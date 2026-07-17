"""Kubernetes risk classification rules — foundation (message 1 of 9).

This module exists ONLY to give ``kubernetes_*`` records a dedicated,
correct classifier so that ``risk_service.classify_change()`` never falls
through to the unrelated Cloudflare DNS default classifier (the generic
fallback at the bottom of that dispatch chain is for un-prefixed record
types and would produce a nonsensical result for a Kubernetes Change).

This is intentionally NOT a full risk classifier. Per the message-1 scope,
no broad Kubernetes Security Findings or exhaustive severity calibration
are built yet — that is message 6 (Security Finding taxonomy) and message 7
(Change classification). The only differentiated case handled here is
Pod Security Admission label weakening on a namespace, since that field is
already emitted and tracked in this message and has an unambiguous
security direction (removing/weakening ``enforce`` reduces the namespace's
baseline protection). Every other Kubernetes field currently tracked
(cluster version/platform, namespace phase) is deliberately generic/low —
those are informational, not risk-bearing, signals.
"""

from __future__ import annotations

from app.connectors.kubernetes_schema import (
    KUBERNETES_API_CAPABILITY,
    KUBERNETES_CLUSTER,
    KUBERNETES_NAMESPACE,
)


def _get(obj: object, field: str) -> object:
    if isinstance(obj, dict):
        return obj.get(field)
    return getattr(obj, field, None)


_PSA_ENFORCEMENT_RANK = {
    None: 0,
    "privileged": 0,
    "baseline": 1,
    "restricted": 2,
}


def _classify_cluster_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    if ct == "added":
        return "low", "A Kubernetes cluster was added to monitoring."
    if ct == "removed":
        return (
            "medium",
            "A Kubernetes cluster is no longer visible to ConfigTrace. "
            "Verify the integration still has valid credentials.",
        )
    fp = (_get(change, "field_path") or "").lower()
    if fp in ("kubernetes_version", "kubernetes_major_minor"):
        return "low", "The Kubernetes cluster version changed."
    if fp == "platform":
        return "low", "The Kubernetes cluster platform category changed."
    if fp == "partial_permission_indicator":
        nv = _get(change, "new_value")
        if nv is True:
            return (
                "medium",
                "ConfigTrace's Kubernetes credentials have only partial "
                "permission to read this cluster's configuration. Some "
                "records may be incomplete. Review the granted RBAC permissions.",
            )
        return "low", "ConfigTrace's Kubernetes collection permission completeness changed."
    return "low", "A Kubernetes cluster configuration field changed."


def _classify_namespace_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    if ct == "added":
        return "low", "A Kubernetes namespace was added to monitoring."
    if ct == "removed":
        return "low", "A Kubernetes namespace is no longer visible to ConfigTrace."

    fp = (_get(change, "field_path") or "").lower()
    if fp == "psa_enforce":
        nv = _get(change, "new_value")
        pv = _get(change, "prev_value")
        if nv is None:
            return (
                "medium",
                "The namespace's Pod Security Admission 'enforce' label was "
                "removed. Pod Security Admission enforcement is no longer "
                "guaranteed for this namespace.",
            )
        new_rank = _PSA_ENFORCEMENT_RANK.get(nv, 0)
        old_rank = _PSA_ENFORCEMENT_RANK.get(pv, 0)
        if new_rank < old_rank:
            return (
                "medium",
                f"The namespace's Pod Security Admission 'enforce' level was "
                f"weakened (from {pv!r} to {nv!r}).",
            )
        return "low", "The namespace's Pod Security Admission 'enforce' level changed."

    if fp in ("psa_audit", "psa_warn"):
        return "low", "The namespace's Pod Security Admission label changed."
    if fp == "phase":
        return "low", "The namespace's phase changed."
    if fp == "terminating":
        return "low", "The namespace's terminating status changed."
    return "low", "A Kubernetes namespace configuration field changed."


def _classify_api_capability_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    if ct == "added":
        return "low", "A Kubernetes API resource type was newly discovered."
    if ct == "removed":
        return (
            "low",
            "A previously discovered Kubernetes API resource type is no "
            "longer available. Verify whether this was an intentional "
            "cluster upgrade or feature-gate change.",
        )
    return "low", "A Kubernetes API capability record changed."


def classify_kubernetes_change(change: object) -> tuple[str, str]:
    """Route a Kubernetes Change to its record-type classifier.

    Unknown/future ``kubernetes_*`` record types (i.e. the message 2-5
    planned taxonomy, before their classifiers exist) fail safely into a
    generic low-severity message rather than raising or falling through to
    an unrelated provider's classifier.
    """
    raw_pm = _get(change, "provider_metadata")
    pm: dict = raw_pm if isinstance(raw_pm, dict) else {}
    record_type = (pm.get("record_type") or "").lower()

    if record_type == KUBERNETES_CLUSTER:
        return _classify_cluster_change(change)
    if record_type == KUBERNETES_NAMESPACE:
        return _classify_namespace_change(change)
    if record_type == KUBERNETES_API_CAPABILITY:
        return _classify_api_capability_change(change)

    return "low", f"A Kubernetes configuration record changed ({record_type or 'unknown record type'})."
