"""Kubernetes risk classification rules — foundation + workloads + RBAC (messages 1-3 of 9).

This module exists to give every ``kubernetes_*`` record type a dedicated,
correct classifier so that ``risk_service.classify_change()`` never falls
through to the unrelated Cloudflare DNS default classifier (the generic
fallback at the bottom of that dispatch chain is for un-prefixed record
types and would produce a nonsensical result for a Kubernetes Change).

This is intentionally NOT the full, final risk classifier. No complete
Kubernetes Security Finding taxonomy or exhaustive severity calibration is
built yet — that is message 6 (Security Finding taxonomy) and message 7
(Change classification's full pass). What IS implemented here is
structural classifier support for every record type through message 3 and
the "obvious high-value transitions" called out for each message:
privileged/root/host-namespace posture, dangerous capabilities, seccomp/
AppArmor, hostPath (including runtime-socket mounts), image mutability,
missing resource controls, host ports, service-account-token automount
(message 2), and RBAC — new cluster-admin subjects, wildcard/bind/escalate/
impersonate permissions, Secret/Pod-exec access grants, anonymous/
unauthenticated meaningful access, and roleRef/privilege-resolution
transitions (message 3). Severity assignments deliberately do NOT claim
compromise, breakout, exploitation, internet exposure, or credential
theft — they describe structural posture only.

Unresolved/unknown privilege (unresolved roleRef, access-denied
collection, malformed rules) is classified as ``"medium"`` — never
``"low"`` (unknown is not safe) and never ``"high"``/``"critical"``
without concrete evidence (unknown is not proof of danger either).
"""

from __future__ import annotations

from app.connectors.kubernetes_schema import (
    CAPABILITY_ALL,
    CATEGORY_BIND,
    CATEGORY_CLUSTER_ROLE_BINDING_WRITE,
    CATEGORY_CRD_WRITE,
    CATEGORY_CSR_APPROVAL,
    CATEGORY_ESCALATE,
    CATEGORY_FULL_WILDCARD,
    CATEGORY_IMPERSONATE,
    CATEGORY_NODE_PROXY,
    CATEGORY_ADMISSION_WEBHOOK_WRITE,
    CATEGORY_SECRET_READ_BROAD_SCOPE,
    CATEGORY_TOKEN_CREATION,
    DANGEROUS_CAPABILITIES,
    HOSTPATH_CATEGORY_CONTAINERD_SOCKET,
    HOSTPATH_CATEGORY_DOCKER_SOCKET,
    IMAGE_TAG_LATEST_EXPLICIT,
    IMAGE_TAG_LATEST_IMPLICIT,
    KUBERNETES_API_CAPABILITY,
    KUBERNETES_CLUSTER,
    KUBERNETES_CLUSTER_ROLE,
    KUBERNETES_CLUSTER_ROLE_BINDING,
    KUBERNETES_CONTAINER_SECURITY_CONTEXT,
    KUBERNETES_CRONJOB,
    KUBERNETES_DAEMONSET,
    KUBERNETES_DEPLOYMENT,
    KUBERNETES_JOB,
    KUBERNETES_NAMESPACE,
    KUBERNETES_POD,
    KUBERNETES_RBAC_PERMISSION_SUMMARY,
    KUBERNETES_RBAC_SUBJECT_BINDING,
    KUBERNETES_ROLE,
    KUBERNETES_ROLE_BINDING,
    KUBERNETES_SERVICE_ACCOUNT,
    KUBERNETES_STATEFULSET,
    KUBERNETES_WORKLOAD_SERVICE_ACCOUNT,
    PROFILE_CATEGORY_UNCONFINED,
    ROLE_RESOLUTION_RESOLVED,
    SECURITY_POSTURE_ELEVATED,
    SECURITY_POSTURE_PRIVILEGED_OR_HOST_ACCESS,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SEVERITY_UNKNOWN,
)

_WORKLOAD_CONTROLLER_RECORD_TYPES = frozenset(
    {
        KUBERNETES_DEPLOYMENT, KUBERNETES_STATEFULSET, KUBERNETES_DAEMONSET,
        KUBERNETES_JOB, KUBERNETES_CRONJOB,
    }
)
_ROLE_RECORD_TYPES = frozenset({KUBERNETES_ROLE, KUBERNETES_CLUSTER_ROLE})
_BINDING_RECORD_TYPES = frozenset({KUBERNETES_ROLE_BINDING, KUBERNETES_CLUSTER_ROLE_BINDING})
_DANGEROUS_HOSTPATH_SOCKET_CATEGORIES = frozenset(
    {HOSTPATH_CATEGORY_DOCKER_SOCKET, HOSTPATH_CATEGORY_CONTAINERD_SOCKET}
)
_MUTABLE_IMAGE_TAG_CATEGORIES = frozenset({IMAGE_TAG_LATEST_EXPLICIT, IMAGE_TAG_LATEST_IMPLICIT})

_CRITICAL_PERMISSION_CATEGORIES = frozenset({
    CATEGORY_FULL_WILDCARD, CATEGORY_BIND, CATEGORY_ESCALATE, CATEGORY_IMPERSONATE,
    CATEGORY_TOKEN_CREATION, CATEGORY_CSR_APPROVAL, CATEGORY_CLUSTER_ROLE_BINDING_WRITE,
    CATEGORY_ADMISSION_WEBHOOK_WRITE, CATEGORY_CRD_WRITE, CATEGORY_NODE_PROXY,
    CATEGORY_SECRET_READ_BROAD_SCOPE,
})

_SEVERITY_RANK: dict[str, int] = {
    SEVERITY_UNKNOWN: -1, SEVERITY_LOW: 0, SEVERITY_MEDIUM: 1,
    SEVERITY_HIGH: 2, SEVERITY_CRITICAL: 3,
}


def _severity_rank(value: object) -> int:
    return _SEVERITY_RANK.get(value, -1) if isinstance(value, str) else -1


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


def _whole_record(change: object, *, added: bool) -> dict:
    value = _get(change, "new_value") if added else _get(change, "prev_value")
    return value if isinstance(value, dict) else {}


def _classify_workload_controller_change(change: object) -> tuple[str, str]:
    """Shared classifier for Deployment/StatefulSet/DaemonSet/Job/CronJob."""
    ct = (_get(change, "change_type") or "").lower()

    if ct == "added":
        record = _whole_record(change, added=True)
        posture = record.get("security_posture_summary")
        if posture == SECURITY_POSTURE_PRIVILEGED_OR_HOST_ACCESS:
            return (
                "high",
                "A Kubernetes workload was added to monitoring that is already "
                "running with privileged or host-access posture.",
            )
        if posture == SECURITY_POSTURE_ELEVATED:
            return (
                "medium",
                "A Kubernetes workload was added to monitoring with elevated "
                "security posture (e.g. root execution or added capabilities).",
            )
        return "low", "A Kubernetes workload was added to monitoring."

    if ct == "removed":
        record = _whole_record(change, added=False)
        posture = record.get("security_posture_summary")
        if posture == SECURITY_POSTURE_PRIVILEGED_OR_HOST_ACCESS:
            return (
                "medium",
                "A Kubernetes workload with privileged or host-access posture "
                "is no longer visible to ConfigTrace. Verify this was an "
                "intentional removal.",
            )
        return "low", "A Kubernetes workload is no longer visible to ConfigTrace."

    fp = (_get(change, "field_path") or "").lower()
    nv = _get(change, "new_value")
    pv = _get(change, "prev_value")

    if fp == "host_network":
        return ("medium", "Host network access was enabled for a Kubernetes workload.") if nv is True else (
            "low", "Host network access was disabled for a Kubernetes workload.",
        )
    if fp == "host_pid":
        return ("high", "Host PID namespace access was enabled for a Kubernetes workload.") if nv is True else (
            "low", "Host PID namespace access was disabled for a Kubernetes workload.",
        )
    if fp == "host_ipc":
        return ("high", "Host IPC namespace access was enabled for a Kubernetes workload.") if nv is True else (
            "low", "Host IPC namespace access was disabled for a Kubernetes workload.",
        )
    if fp == "share_process_namespace":
        return ("medium", "Process namespace sharing was enabled for a Kubernetes Pod.") if nv is True else (
            "low", "Process namespace sharing was disabled for a Kubernetes Pod.",
        )
    if fp == "privileged_container_count":
        if (nv or 0) > (pv or 0):
            return "high", "A privileged container was introduced into a Kubernetes workload."
        return "low", "A privileged container was removed from a Kubernetes workload."
    if fp == "root_container_count":
        if (nv or 0) > (pv or 0):
            return "medium", "A container explicitly configured to run as root was introduced."
        return "low", "A container explicitly configured to run as root was removed."
    if fp == "allow_privilege_escalation_count":
        if (nv or 0) > (pv or 0):
            return "medium", "Privilege escalation was enabled for a container in a Kubernetes workload."
        return "low", "Privilege escalation was disabled for a container in a Kubernetes workload."
    if fp == "dangerous_hostpath_categories":
        return _classify_hostpath_category_transition(nv, pv)
    if fp == "added_capability_categories":
        return _classify_capability_transition(nv, pv)
    if fp == "seccomp_posture_summary":
        return _classify_profile_transition(nv, pv, profile_name="Seccomp")
    if fp == "apparmor_posture_summary":
        return _classify_profile_transition(nv, pv, profile_name="AppArmor", unconfined_severity="medium")
    if fp == "read_only_root_filesystem_coverage":
        return _classify_coverage_regression(
            nv, pv, "Read-only root filesystem coverage decreased for a Kubernetes workload.",
            "Read-only root filesystem coverage improved for a Kubernetes workload.",
        )
    if fp == "resource_limit_coverage":
        return _classify_coverage_regression(
            nv, pv, "A Kubernetes workload no longer has resource limits configured.",
            "Resource limit coverage was restored for a Kubernetes workload.",
        )
    if fp == "image_posture_summary":
        if nv == "mutable" and pv != "mutable":
            return "medium", "A Kubernetes workload now uses a mutable/latest image tag."
        if pv == "mutable" and nv != "mutable":
            return "low", "A Kubernetes workload's image tag is no longer mutable/latest."
        return "low", "A Kubernetes workload's image posture changed."
    if fp == "automount_service_account_token":
        if nv is True and pv is not True:
            return "medium", "Service-account token automount was explicitly enabled for a Kubernetes workload."
        if nv is False and pv is not False:
            return "low", "Service-account token automount was explicitly disabled for a Kubernetes workload."
        return "low", "Service-account token automount setting changed for a Kubernetes workload."
    if fp in ("liveness_probe_coverage", "readiness_probe_coverage", "startup_probe_coverage"):
        return "low", "Probe coverage changed for a Kubernetes workload."
    if fp in ("update_strategy_category", "desired_replica_count", "runtime_class_name"):
        return "low", "A Kubernetes workload's configuration field changed."
    if fp == "collection_completeness_category":
        if nv == "partial":
            return (
                "medium",
                "ConfigTrace's Kubernetes credentials have only partial "
                "permission to read this workload's configuration.",
            )
        return "low", "ConfigTrace's Kubernetes workload collection permission completeness changed."
    return "low", "A Kubernetes workload configuration field changed."


def _classify_container_security_context_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()

    if ct == "added":
        record = _whole_record(change, added=True)
        if record.get("privileged") is True:
            return "high", "A privileged container was added to a Kubernetes workload."
        if record.get("dangerous_added_capability_categories"):
            return "medium", "A container with dangerous added Linux capabilities was added to a Kubernetes workload."
        return "low", "A container was added to a Kubernetes workload."

    if ct == "removed":
        record = _whole_record(change, added=False)
        if record.get("privileged") is True:
            return "low", "A privileged container was removed from a Kubernetes workload."
        return "low", "A container was removed from a Kubernetes workload."

    fp = (_get(change, "field_path") or "").lower()
    nv = _get(change, "new_value")
    pv = _get(change, "prev_value")

    if fp == "privileged":
        return ("high", "A container was explicitly configured as privileged.") if nv is True else (
            "low", "A container is no longer configured as privileged.",
        )
    if fp == "allow_privilege_escalation":
        return ("medium", "Privilege escalation was enabled for a container.") if nv is True else (
            "low", "Privilege escalation was disabled for a container.",
        )
    if fp == "run_as_non_root":
        if nv is False and pv is not False:
            return "high", "A container was explicitly configured to allow running as root."
        if pv is False and nv is not False:
            return "low", "A container's explicit root-execution setting was removed."
        return "low", "A container's runAsNonRoot setting changed."
    if fp == "run_as_uid":
        if nv == 0 and pv != 0:
            return "high", "A container was explicitly configured to run as UID 0 (root)."
        if pv == 0 and nv != 0:
            return "low", "A container is no longer explicitly configured to run as UID 0."
        return "low", "A container's run-as UID changed."
    if fp == "read_only_root_filesystem":
        if nv is False and pv is not False:
            return "medium", "Read-only root filesystem was disabled for a container."
        if pv is False and nv is not False:
            return "low", "Read-only root filesystem was enabled for a container."
        return "low", "A container's read-only root filesystem setting changed."
    if fp == "seccomp_profile_category":
        return _classify_profile_transition(nv, pv, profile_name="Seccomp")
    if fp == "apparmor_profile_category":
        return _classify_profile_transition(nv, pv, profile_name="AppArmor", unconfined_severity="medium")
    if fp in ("capabilities_added", "dangerous_added_capability_categories"):
        return _classify_capability_transition(nv, pv)
    if fp == "image_tag_category":
        if nv in _MUTABLE_IMAGE_TAG_CATEGORIES and pv not in _MUTABLE_IMAGE_TAG_CATEGORIES:
            return "medium", "A container's image tag became mutable/latest."
        if pv in _MUTABLE_IMAGE_TAG_CATEGORIES and nv not in _MUTABLE_IMAGE_TAG_CATEGORIES:
            return "low", "A container's image tag is no longer mutable/latest."
        return "low", "A container's image tag category changed."
    if fp == "any_resource_limit_present":
        return ("medium", "Resource limits were removed from a container.") if nv is False else (
            "low", "Resource limits were added to a container.",
        )
    if fp == "host_port_count":
        return ("medium", "A host port was introduced on a container.") if (nv or 0) > (pv or 0) else (
            "low", "A host port was removed from a container.",
        )
    if fp == "dangerous_host_ports":
        added = set(nv or []) - set(pv or [])
        if added:
            return "medium", f"A sensitive host port was introduced on a container ({sorted(added)})."
        return "low", "A sensitive host port was removed from a container."
    if fp in ("hostpath_mount_count", "writable_hostpath_mount_count"):
        return ("medium", "A writable hostPath mount was introduced on a container.") if (nv or 0) > (pv or 0) else (
            "low", "A hostPath mount was removed from a container.",
        )
    if fp == "service_account_token_explicitly_mounted":
        return ("medium", "A service-account token was explicitly mounted on a container.") if nv is True else (
            "low", "A service-account token mount was removed from a container.",
        )
    if fp == "bidirectional_mount_propagation_present":
        return ("medium", "A bidirectional mount propagation volume mount was introduced on a container.") if nv is True else (
            "low", "A bidirectional mount propagation volume mount was removed from a container.",
        )
    return "low", "A container's configuration field changed."


def _classify_workload_service_account_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    if ct == "added":
        return "low", "A Kubernetes service account is now referenced by a monitored workload."
    if ct == "removed":
        return "low", "A Kubernetes service account is no longer referenced by any monitored workload."

    fp = (_get(change, "field_path") or "").lower()
    nv = _get(change, "new_value")
    pv = _get(change, "prev_value")

    if fp == "effective_automount_state":
        if nv == "kubernetes_default_true" and pv not in ("kubernetes_default_true", None):
            return "medium", "A workload ServiceAccount's effective automount posture became enabled (Kubernetes default)."
        if isinstance(nv, str) and nv.startswith("unknown_"):
            return "medium", "A workload ServiceAccount's effective automount posture could not be resolved."
        return "low", "A workload ServiceAccount's effective automount posture changed."
    if fp == "service_account_privilege_summary":
        if _severity_rank(nv) > _severity_rank(pv) and nv in (SEVERITY_HIGH, SEVERITY_CRITICAL):
            return "high", f"A workload ServiceAccount's bound privilege increased to {nv!r}."
        if _severity_rank(nv) < _severity_rank(pv):
            return "low", "A workload ServiceAccount's bound privilege decreased."
        return "low", "A workload ServiceAccount's bound privilege summary changed."
    if fp == "service_account_found":
        return ("low", "The workload's ServiceAccount is now resolvable.") if nv else (
            "medium", "The workload's ServiceAccount is no longer resolvable (missing or access denied).",
        )
    if fp in ("bound_role_binding_count", "bound_cluster_role_binding_count"):
        return "low", "A workload ServiceAccount's bound-binding count changed."
    if fp == "risky_permission_categories":
        added = set(nv or []) - set(pv or [])
        if added:
            return "high", f"A workload ServiceAccount gained risky permission categories: {sorted(added)}."
        return "low", "A workload ServiceAccount's risky permission categories decreased."
    if fp == "collection_completeness_category":
        return ("medium", "Kubernetes workload ServiceAccount identity resolution is incomplete.") if nv == "partial" else (
            "low", "Kubernetes workload ServiceAccount identity resolution completeness changed.",
        )
    return "low", "A Kubernetes workload service-account rollup field changed."


def _classify_service_account_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()

    if ct == "added":
        record = _whole_record(change, added=True)
        if record.get("cluster_admin_bound"):
            return "critical", "A new Kubernetes ServiceAccount was added already bound to cluster-admin."
        highest = record.get("highest_privilege_category")
        if highest == SEVERITY_CRITICAL:
            return "critical", "A new Kubernetes ServiceAccount was added already holding critical-severity privilege."
        if highest == SEVERITY_HIGH:
            return "high", "A new Kubernetes ServiceAccount was added already holding high-severity privilege."
        return "low", "A Kubernetes ServiceAccount was added to monitoring."

    if ct == "removed":
        record = _whole_record(change, added=False)
        if record.get("cluster_admin_bound"):
            return (
                "medium",
                "A Kubernetes ServiceAccount bound to cluster-admin is no longer visible. "
                "Verify this was an intentional removal.",
            )
        return "low", "A Kubernetes ServiceAccount is no longer visible to ConfigTrace."

    fp = (_get(change, "field_path") or "").lower()
    nv = _get(change, "new_value")
    pv = _get(change, "prev_value")

    if fp == "cluster_admin_bound":
        return ("critical", "A Kubernetes ServiceAccount gained cluster-admin privilege.") if nv else (
            "low", "A Kubernetes ServiceAccount's cluster-admin privilege was removed.",
        )
    if fp == "wildcard_permission_bound":
        return ("high", "A Kubernetes ServiceAccount gained a wildcard permission binding.") if nv else (
            "low", "A Kubernetes ServiceAccount's wildcard permission binding was removed.",
        )
    if fp == "secret_read_permission_bound":
        return ("high", "A Kubernetes ServiceAccount gained Secret-read permission.") if nv else (
            "low", "A Kubernetes ServiceAccount's Secret-read permission was removed.",
        )
    if fp == "pod_exec_permission_bound":
        return ("high", "A Kubernetes ServiceAccount gained Pod-exec permission.") if nv else (
            "low", "A Kubernetes ServiceAccount's Pod-exec permission was removed.",
        )
    if fp == "workload_creation_permission_bound":
        return ("high", "A Kubernetes ServiceAccount gained broad workload-creation permission.") if nv else (
            "low", "A Kubernetes ServiceAccount's workload-creation permission was removed.",
        )
    if fp == "rbac_modification_permission_bound":
        return ("high", "A Kubernetes ServiceAccount gained RBAC-modification permission.") if nv else (
            "low", "A Kubernetes ServiceAccount's RBAC-modification permission was removed.",
        )
    if fp == "impersonation_permission_bound":
        return ("critical", "A Kubernetes ServiceAccount gained impersonation permission.") if nv else (
            "low", "A Kubernetes ServiceAccount's impersonation permission was removed.",
        )
    if fp == "highest_privilege_category":
        if _severity_rank(nv) > _severity_rank(pv) and nv in (SEVERITY_HIGH, SEVERITY_CRITICAL):
            return ("critical" if nv == SEVERITY_CRITICAL else "high"), f"A Kubernetes ServiceAccount's privilege increased to {nv!r}."
        if _severity_rank(nv) < _severity_rank(pv):
            return "low", "A Kubernetes ServiceAccount's privilege decreased."
        return "low", "A Kubernetes ServiceAccount's privilege summary changed."
    if fp == "automount_service_account_token":
        return ("medium", "A Kubernetes ServiceAccount's automount default was explicitly enabled.") if nv is True else (
            "low", "A Kubernetes ServiceAccount's automount default was explicitly disabled.",
        )
    if fp in ("secret_reference_count", "image_pull_secret_count", "bound_role_binding_count", "bound_cluster_role_binding_count"):
        return "low", "A Kubernetes ServiceAccount's reference/binding count changed."
    if fp == "collection_completeness_category":
        return ("medium", "ConfigTrace's Kubernetes credentials have only partial visibility into this ServiceAccount's bindings.") if nv == "partial" else (
            "low", "Kubernetes ServiceAccount collection completeness changed.",
        )
    return "low", "A Kubernetes ServiceAccount configuration field changed."


def _classify_role_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    kind_label = "Role/ClusterRole"

    if ct == "added":
        record = _whole_record(change, added=True)
        kind_label = record.get("kind") or kind_label
        highest = record.get("highest_severity_category")
        if highest == SEVERITY_CRITICAL:
            return "critical", f"A new {kind_label} was added already granting critical-severity permissions."
        if highest == SEVERITY_HIGH:
            return "high", f"A new {kind_label} was added already granting high-severity permissions."
        return "low", f"A Kubernetes {kind_label} was added to monitoring."

    if ct == "removed":
        record = _whole_record(change, added=False)
        kind_label = record.get("kind") or kind_label
        highest = record.get("highest_severity_category")
        if highest in (SEVERITY_CRITICAL, SEVERITY_HIGH):
            return "medium", f"A dangerous {kind_label} was removed. Verify this was an intentional cleanup."
        return "low", f"A Kubernetes {kind_label} is no longer visible to ConfigTrace."

    fp = (_get(change, "field_path") or "").lower()
    nv = _get(change, "new_value")
    pv = _get(change, "prev_value")

    if fp == "high_risk_permission_categories":
        added = set(nv or []) - set(pv or [])
        removed = set(pv or []) - set(nv or [])
        critical_new = added & _CRITICAL_PERMISSION_CATEGORIES
        if critical_new:
            return "critical", f"A {kind_label} gained a critical permission category: {sorted(critical_new)}."
        if added:
            return "high", f"A {kind_label} gained dangerous permission categories: {sorted(added)}."
        if removed:
            return "low", f"A {kind_label}'s dangerous permission categories decreased: {sorted(removed)}."
        return "low", f"A {kind_label}'s permission categories changed."
    if fp in ("wildcard_api_group", "wildcard_resource", "wildcard_verb"):
        return ("high", f"A wildcard permission was introduced on a {kind_label}.") if nv else (
            "low", f"A wildcard permission was removed from a {kind_label}.",
        )
    if fp == "wildcard_non_resource_url":
        return ("medium", f"A wildcard non-resource-URL permission was introduced on a {kind_label}.") if nv else (
            "low", f"A wildcard non-resource-URL permission was removed from a {kind_label}.",
        )
    if fp == "highest_severity_category":
        if _severity_rank(nv) > _severity_rank(pv):
            if nv == SEVERITY_CRITICAL:
                return "critical", f"A {kind_label}'s highest granted severity increased to critical."
            if nv == SEVERITY_HIGH:
                return "high", f"A {kind_label}'s highest granted severity increased to high."
        if _severity_rank(nv) < _severity_rank(pv):
            return "low", f"A {kind_label}'s highest granted severity decreased."
        return "low", f"A {kind_label}'s highest granted severity category changed."
    if fp == "aggregation_rule_present":
        return "low", f"A {kind_label}'s aggregation-rule presence changed."
    if fp in ("rule_count", "permission_fingerprint", "aggregation_selector_count"):
        return "low", f"A {kind_label}'s permission rules changed."
    if fp == "collection_completeness_category":
        return ("medium", f"A {kind_label}'s aggregated permissions could not be fully resolved.") if nv == "partial" else (
            "low", f"A {kind_label}'s collection completeness changed.",
        )
    return "low", f"A Kubernetes {kind_label} configuration field changed."


def _binding_added_removed_severity(record: dict, *, removed: bool) -> tuple[str, str]:
    kind_label = record.get("kind") or "RoleBinding/ClusterRoleBinding"
    if record.get("cluster_admin_binding"):
        if removed:
            return "medium", f"A {kind_label} granting cluster-admin was removed. Verify this was intentional."
        return "critical", f"A new {kind_label} grants cluster-admin."
    priv = record.get("resolved_privilege_category")
    if removed:
        if priv in (SEVERITY_CRITICAL, SEVERITY_HIGH):
            return "medium", f"A dangerous {kind_label} was removed. Verify this was intentional."
        return "low", f"A Kubernetes {kind_label} is no longer visible to ConfigTrace."
    if priv == SEVERITY_CRITICAL:
        return "critical", f"A new {kind_label} was created already granting critical-severity permissions."
    if priv == SEVERITY_HIGH:
        return "high", f"A new {kind_label} was created already granting high-severity permissions."
    if priv == SEVERITY_UNKNOWN:
        return "medium", f"A new {kind_label} references a role that could not be resolved. Review manually."
    return "low", f"A Kubernetes {kind_label} was added to monitoring."


def _classify_role_binding_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()

    if ct == "added":
        return _binding_added_removed_severity(_whole_record(change, added=True), removed=False)
    if ct == "removed":
        return _binding_added_removed_severity(_whole_record(change, added=False), removed=True)

    fp = (_get(change, "field_path") or "").lower()
    nv = _get(change, "new_value")
    pv = _get(change, "prev_value")

    if fp == "cluster_admin_binding":
        return ("critical", "A Kubernetes binding now grants cluster-admin.") if nv else (
            "low", "A Kubernetes binding's cluster-admin grant was removed.",
        )
    if fp == "wildcard_permission_binding":
        return ("high", "A Kubernetes binding now resolves to a wildcard-permission role.") if nv else (
            "low", "A Kubernetes binding no longer resolves to a wildcard-permission role.",
        )
    if fp == "resolved_privilege_category":
        if _severity_rank(nv) > _severity_rank(pv):
            if nv == SEVERITY_CRITICAL:
                return "critical", "A Kubernetes binding's resolved privilege increased to critical."
            if nv == SEVERITY_HIGH:
                return "high", "A Kubernetes binding's resolved privilege increased to high (was lower privilege)."
            if nv == SEVERITY_UNKNOWN:
                return "medium", "A Kubernetes binding's role reference became unresolved."
        if _severity_rank(nv) < _severity_rank(pv):
            return "low", "A Kubernetes binding's resolved privilege decreased."
        return "low", "A Kubernetes binding's resolved privilege category changed."
    if fp == "role_resolution_status":
        if nv != ROLE_RESOLUTION_RESOLVED:
            return "medium", f"A Kubernetes binding's roleRef is {nv!r} — privilege cannot be confirmed. Review manually."
        return "low", "A Kubernetes binding's roleRef became resolvable."
    if fp == "role_ref_name":
        return "medium", f"A Kubernetes binding's roleRef changed from {pv!r} to {nv!r}. Re-evaluate effective privilege."
    if fp in ("subject_count", "user_subject_count", "group_subject_count", "service_account_subject_count"):
        return "low", "A Kubernetes binding's subject count changed."
    if fp == "binding_fingerprint":
        return "low", "A Kubernetes binding's subjects or roleRef changed."
    if fp == "collection_completeness_category":
        return ("medium", "ConfigTrace's Kubernetes credentials have only partial visibility into this binding.") if nv == "partial" else (
            "low", "Kubernetes binding collection completeness changed.",
        )
    return "low", "A Kubernetes RoleBinding/ClusterRoleBinding configuration field changed."


def _subject_binding_added_removed_severity(record: dict, *, removed: bool) -> tuple[str, str]:
    subject_kind = record.get("subject_kind") or "subject"
    priv = record.get("resolved_privilege_category")
    meaningful_access = priv in (SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_UNKNOWN)

    if not removed:
        if record.get("anonymous_subject") and meaningful_access:
            return "critical", "An anonymous subject was granted meaningful permissions via a Kubernetes RBAC binding."
        if record.get("unauthenticated_group") and meaningful_access:
            return "critical", "The system:unauthenticated group was granted meaningful permissions via a Kubernetes RBAC binding."
        if record.get("cluster_admin_binding"):
            return "critical", f"A {subject_kind} subject was added to a cluster-admin binding."
        if priv == SEVERITY_CRITICAL:
            return "critical", f"A {subject_kind} subject was added to a critical-privilege Kubernetes RBAC binding."
        if priv == SEVERITY_HIGH:
            return "high", f"A {subject_kind} subject was added to a high-privilege Kubernetes RBAC binding."
        if priv == SEVERITY_UNKNOWN:
            return "medium", f"A {subject_kind} subject was added to a binding whose role could not be resolved."
        return "low", "A subject was added to a Kubernetes RBAC binding."

    if record.get("cluster_admin_binding"):
        return "medium", f"A {subject_kind} subject was removed from a cluster-admin binding. Verify this was intentional."
    return "low", "A subject was removed from a Kubernetes RBAC binding."


def _classify_rbac_subject_binding_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()

    if ct == "added":
        return _subject_binding_added_removed_severity(_whole_record(change, added=True), removed=False)
    if ct == "removed":
        return _subject_binding_added_removed_severity(_whole_record(change, added=False), removed=True)

    fp = (_get(change, "field_path") or "").lower()
    nv = _get(change, "new_value")
    pv = _get(change, "prev_value")

    if fp == "role_ref_name":
        return "medium", f"A Kubernetes subject binding's roleRef changed from {pv!r} to {nv!r}."
    if fp == "cluster_admin_binding":
        return ("critical", "A Kubernetes subject binding now grants cluster-admin.") if nv else (
            "low", "A Kubernetes subject binding's cluster-admin grant was removed.",
        )
    if fp == "wildcard_permission_binding":
        return ("high", "A Kubernetes subject binding now resolves to a wildcard-permission role.") if nv else (
            "low", "A Kubernetes subject binding no longer resolves to a wildcard-permission role.",
        )
    if fp == "resolved_privilege_category":
        if _severity_rank(nv) > _severity_rank(pv):
            if nv == SEVERITY_CRITICAL:
                return "critical", "A Kubernetes subject binding's resolved privilege increased to critical."
            if nv == SEVERITY_HIGH:
                return "high", "A Kubernetes subject binding's resolved privilege increased to high."
            if nv == SEVERITY_UNKNOWN:
                return "medium", "A Kubernetes subject binding's role reference became unresolved."
        if _severity_rank(nv) < _severity_rank(pv):
            return "low", "A Kubernetes subject binding's resolved privilege decreased."
        return "low", "A Kubernetes subject binding's resolved privilege category changed."
    if fp == "role_resolution_status":
        if nv != ROLE_RESOLUTION_RESOLVED:
            return "medium", f"A Kubernetes subject binding's roleRef is {nv!r} — privilege cannot be confirmed."
        return "low", "A Kubernetes subject binding's roleRef became resolvable."
    if fp == "high_risk_permission_categories":
        added = set(nv or []) - set(pv or [])
        critical_new = added & _CRITICAL_PERMISSION_CATEGORIES
        if critical_new:
            return "critical", f"A Kubernetes subject binding gained a critical permission category: {sorted(critical_new)}."
        if added:
            return "high", f"A Kubernetes subject binding gained dangerous permission categories: {sorted(added)}."
        return "low", "A Kubernetes subject binding's permission categories changed."
    return "low", "A Kubernetes RBAC subject-binding field changed."


def _classify_rbac_permission_summary_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()

    if ct == "added":
        record = _whole_record(change, added=True)
        if record.get("cluster_admin_bound"):
            return "critical", "A new Kubernetes identity was observed with cluster-admin access."
        highest = record.get("highest_privilege_category")
        if highest == SEVERITY_CRITICAL:
            return "critical", "A new Kubernetes identity was observed with critical aggregate privilege."
        if highest == SEVERITY_HIGH:
            return "high", "A new Kubernetes identity was observed with high aggregate privilege."
        return "low", "A new Kubernetes identity permission rollup was observed."
    if ct == "removed":
        record = _whole_record(change, added=False)
        if record.get("cluster_admin_bound"):
            return "medium", "A Kubernetes identity's cluster-admin access rollup is no longer present. Verify this was intentional."
        return "low", "A Kubernetes identity permission rollup is no longer present."

    fp = (_get(change, "field_path") or "").lower()
    nv = _get(change, "new_value")
    pv = _get(change, "prev_value")

    if fp == "cluster_admin_bound":
        return ("critical", "A Kubernetes identity gained cluster-admin access across its bindings.") if nv else (
            "low", "A Kubernetes identity's cluster-admin access was removed.",
        )
    if fp == "highest_privilege_category":
        if _severity_rank(nv) > _severity_rank(pv):
            if nv == SEVERITY_CRITICAL:
                return "critical", "A Kubernetes identity's aggregate privilege increased to critical."
            if nv == SEVERITY_HIGH:
                return "high", "A Kubernetes identity's aggregate privilege increased to high."
        if _severity_rank(nv) < _severity_rank(pv):
            return "low", "A Kubernetes identity's aggregate privilege decreased."
        return "low", "A Kubernetes identity's aggregate privilege summary changed."
    if fp in ("secret_read_bound", "secret_write_bound"):
        return ("high", "A Kubernetes identity gained Secret access across its bindings.") if nv else (
            "low", "A Kubernetes identity's Secret access was removed across its bindings.",
        )
    if fp == "pod_exec_bound":
        return ("high", "A Kubernetes identity gained Pod-exec access across its bindings.") if nv else (
            "low", "A Kubernetes identity's Pod-exec access was removed across its bindings.",
        )
    if fp == "workload_create_bound":
        return ("high", "A Kubernetes identity gained broad workload-creation access across its bindings.") if nv else (
            "low", "A Kubernetes identity's workload-creation access was removed across its bindings.",
        )
    if fp == "rbac_modification_bound":
        return ("high", "A Kubernetes identity gained RBAC-modification access across its bindings.") if nv else (
            "low", "A Kubernetes identity's RBAC-modification access was removed across its bindings.",
        )
    if fp == "impersonation_bound":
        return ("critical", "A Kubernetes identity gained impersonation access across its bindings.") if nv else (
            "low", "A Kubernetes identity's impersonation access was removed across its bindings.",
        )
    if fp == "wildcard_permission_bound":
        return ("high", "A Kubernetes identity gained a wildcard-permission binding.") if nv else (
            "low", "A Kubernetes identity's wildcard-permission binding was removed.",
        )
    if fp in ("role_binding_count", "cluster_role_binding_count"):
        return "low", "A Kubernetes identity's binding count changed."
    return "low", "A Kubernetes identity permission rollup field changed."


def _classify_hostpath_category_transition(nv: object, pv: object) -> tuple[str, str]:
    new_set = set(nv or [])
    prev_set = set(pv or [])
    added = new_set - prev_set
    removed = prev_set - new_set
    if added & _DANGEROUS_HOSTPATH_SOCKET_CATEGORIES:
        return (
            "critical",
            "A writable container-runtime socket (Docker/containerd) was mounted "
            "into a Kubernetes workload.",
        )
    if added:
        return "high", f"A dangerous hostPath mount was introduced ({sorted(added)})."
    if removed:
        return "low", "A dangerous hostPath mount was removed."
    return "low", "A Kubernetes workload's hostPath posture changed."


def _classify_capability_transition(nv: object, pv: object) -> tuple[str, str]:
    new_set = set(nv or [])
    prev_set = set(pv or [])
    added = new_set - prev_set
    removed = prev_set - new_set
    if CAPABILITY_ALL in added:
        return "high", "The 'ALL' Linux capability was added to a Kubernetes container."
    if "SYS_ADMIN" in added:
        return "high", "The SYS_ADMIN Linux capability was added to a Kubernetes container."
    if added & DANGEROUS_CAPABILITIES:
        return "medium", f"A dangerous Linux capability was added to a Kubernetes container ({sorted(added)})."
    if CAPABILITY_ALL in removed or (removed & DANGEROUS_CAPABILITIES):
        return "low", "A dangerous Linux capability was removed from a Kubernetes container."
    return "low", "A Kubernetes container's capability configuration changed."


def _classify_profile_transition(
    nv: object, pv: object, *, profile_name: str, unconfined_severity: str = "high"
) -> tuple[str, str]:
    if nv == PROFILE_CATEGORY_UNCONFINED and pv != PROFILE_CATEGORY_UNCONFINED:
        return unconfined_severity, f"{profile_name} protection was changed to Unconfined."
    if pv == PROFILE_CATEGORY_UNCONFINED and nv != PROFILE_CATEGORY_UNCONFINED:
        return "low", f"{profile_name} protection was restored."
    return "low", f"A Kubernetes {profile_name} profile category changed."


def _classify_coverage_regression(
    nv: object, pv: object, regressed_message: str, restored_message: str
) -> tuple[str, str]:
    if nv == "none" and pv != "none":
        return "medium", regressed_message
    if pv == "none" and nv != "none":
        return "low", restored_message
    return "low", "A Kubernetes workload's coverage posture changed."


def classify_kubernetes_change(change: object) -> tuple[str, str]:
    """Route a Kubernetes Change to its record-type classifier.

    Unknown/future ``kubernetes_*`` record types (i.e. the message 4-5
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
    if record_type in _WORKLOAD_CONTROLLER_RECORD_TYPES or record_type == KUBERNETES_POD:
        return _classify_workload_controller_change(change)
    if record_type == KUBERNETES_CONTAINER_SECURITY_CONTEXT:
        return _classify_container_security_context_change(change)
    if record_type == KUBERNETES_WORKLOAD_SERVICE_ACCOUNT:
        return _classify_workload_service_account_change(change)
    if record_type == KUBERNETES_SERVICE_ACCOUNT:
        return _classify_service_account_change(change)
    if record_type in _ROLE_RECORD_TYPES:
        return _classify_role_change(change)
    if record_type in _BINDING_RECORD_TYPES:
        return _classify_role_binding_change(change)
    if record_type == KUBERNETES_RBAC_SUBJECT_BINDING:
        return _classify_rbac_subject_binding_change(change)
    if record_type == KUBERNETES_RBAC_PERMISSION_SUMMARY:
        return _classify_rbac_permission_summary_change(change)

    return "low", f"A Kubernetes configuration record changed ({record_type or 'unknown record type'})."
