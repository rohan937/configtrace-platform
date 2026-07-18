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

from app.connectors import kubernetes_schema as ks
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
    KUBERNETES_GATEWAY,
    KUBERNETES_GATEWAY_LISTENER,
    KUBERNETES_HTTP_ROUTE,
    KUBERNETES_HTTP_ROUTE_RULE,
    KUBERNETES_INGRESS,
    KUBERNETES_INGRESS_RULE,
    KUBERNETES_JOB,
    KUBERNETES_NAMESPACE,
    KUBERNETES_NAMESPACE_NETWORK_POSTURE,
    KUBERNETES_NETWORK_POLICY,
    KUBERNETES_POD,
    KUBERNETES_RBAC_PERMISSION_SUMMARY,
    KUBERNETES_RBAC_SUBJECT_BINDING,
    KUBERNETES_ROLE,
    KUBERNETES_ROLE_BINDING,
    KUBERNETES_LIMIT_RANGE,
    KUBERNETES_MUTATING_WEBHOOK,
    KUBERNETES_MUTATING_WEBHOOK_CONFIGURATION,
    KUBERNETES_NAMESPACE_GOVERNANCE_POSTURE,
    KUBERNETES_POD_SECURITY_ADMISSION,
    KUBERNETES_RESOURCE_QUOTA,
    KUBERNETES_SERVICE,
    KUBERNETES_SERVICE_ACCOUNT,
    KUBERNETES_SERVICE_PORT,
    KUBERNETES_STATEFULSET,
    KUBERNETES_VALIDATING_WEBHOOK,
    KUBERNETES_VALIDATING_WEBHOOK_CONFIGURATION,
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
_WEBHOOK_CONFIGURATION_RECORD_TYPES = frozenset(
    {KUBERNETES_VALIDATING_WEBHOOK_CONFIGURATION, KUBERNETES_MUTATING_WEBHOOK_CONFIGURATION}
)
_WEBHOOK_RECORD_TYPES = frozenset({KUBERNETES_VALIDATING_WEBHOOK, KUBERNETES_MUTATING_WEBHOOK})
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


def _as_int(value: object) -> "int | None":
    """Return *value* as an int only for genuine integers (bool excluded,
    since bool is an int subclass in Python but never a count here).
    Anything else (None, str, float, malformed) is unknown."""
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return None


def _count_transition(
    nv: object, pv: object, *,
    increased: tuple[str, str], decreased: tuple[str, str],
    unknown_message: str = "A Kubernetes count field changed and could not be safely compared.",
) -> tuple[str, str]:
    """Directional severity for an integer count field.

    Unknown (non-int, e.g. ``None`` from a missing/omitted key) on either
    side is never coerced to 0 — an unknown count must never be misread as
    a decrease (or an increase) relative to the other side. Only fires
    ``increased``/``decreased`` when BOTH values are genuine integers.
    """
    nv_i, pv_i = _as_int(nv), _as_int(pv)
    if nv_i is None or pv_i is None:
        return "low", unknown_message
    if nv_i > pv_i:
        return increased
    return decreased


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


# Mirrors security_rules/kubernetes.py's kubernetes_privileged_host_access
# static Finding's exact trigger, so a newly-added workload matching that
# Critical combination is never under-classified as a fresh Change (Finding
# severity parity — see message 7's audit).
_HIGH_TIER_CAPABILITIES = frozenset({"SYS_ADMIN", "SYS_MODULE", "SYS_RAWIO", "NET_ADMIN", "SYS_PTRACE"})
_SOCKET_HOSTPATH_CATEGORIES = frozenset(
    {HOSTPATH_CATEGORY_DOCKER_SOCKET, HOSTPATH_CATEGORY_CONTAINERD_SOCKET}
)


def _is_privileged_host_access_combo(record: dict) -> bool:
    privileged_count = record.get("privileged_container_count")
    if not (isinstance(privileged_count, int) and not isinstance(privileged_count, bool) and privileged_count > 0):
        return False
    if record.get("host_pid") or record.get("host_ipc"):
        return True
    hostpaths = set(record.get("dangerous_hostpath_categories") or [])
    if hostpaths & _SOCKET_HOSTPATH_CATEGORIES:
        return True
    caps = set(record.get("added_capability_categories") or [])
    return bool(caps & _HIGH_TIER_CAPABILITIES)


def _classify_workload_controller_change(change: object) -> tuple[str, str]:
    """Shared classifier for Deployment/StatefulSet/DaemonSet/Job/CronJob."""
    ct = (_get(change, "change_type") or "").lower()

    if ct == "added":
        record = _whole_record(change, added=True)
        if _is_privileged_host_access_combo(record):
            return (
                "critical",
                "A Kubernetes workload was added to monitoring already combining "
                "a privileged container with host PID/IPC access, a container "
                "runtime socket mount, or a high-risk added Linux capability.",
            )
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
        if _is_privileged_host_access_combo(record):
            return (
                "medium",
                "A Kubernetes workload combining a privileged container with "
                "host-access posture is no longer visible to ConfigTrace. "
                "Verify this was an intentional removal.",
            )
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
        return _count_transition(
            nv, pv,
            increased=("high", "A privileged container was introduced into a Kubernetes workload."),
            decreased=("low", "A privileged container was removed from a Kubernetes workload."),
            unknown_message="A Kubernetes workload's privileged-container count could not be safely compared.",
        )
    if fp == "root_container_count":
        return _count_transition(
            nv, pv,
            increased=("medium", "A container explicitly configured to run as root was introduced."),
            decreased=("low", "A container explicitly configured to run as root was removed."),
            unknown_message="A Kubernetes workload's root-container count could not be safely compared.",
        )
    if fp == "allow_privilege_escalation_count":
        return _count_transition(
            nv, pv,
            increased=("medium", "Privilege escalation was enabled for a container in a Kubernetes workload."),
            decreased=("low", "Privilege escalation was disabled for a container in a Kubernetes workload."),
            unknown_message="A Kubernetes workload's privilege-escalation container count could not be safely compared.",
        )
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
        return _count_transition(
            nv, pv,
            increased=("medium", "A host port was introduced on a container."),
            decreased=("low", "A host port was removed from a container."),
            unknown_message="A container's host-port count could not be safely compared.",
        )
    if fp == "dangerous_host_ports":
        added = set(nv or []) - set(pv or [])
        if added:
            return "medium", f"A sensitive host port was introduced on a container ({sorted(added)})."
        return "low", "A sensitive host port was removed from a container."
    if fp in ("hostpath_mount_count", "writable_hostpath_mount_count"):
        return _count_transition(
            nv, pv,
            increased=("medium", "A writable hostPath mount was introduced on a container."),
            decreased=("low", "A hostPath mount was removed from a container."),
            unknown_message="A container's hostPath mount count could not be safely compared.",
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


# ── Network exposure and isolation classifiers (message 4) ───────────────────
#
# These are structural classifications only: they describe posture
# transitions (internal → external, TLS present/absent, default-deny
# present/absent), never a claim of compromise, exploitation, or verified
# internet reachability. A "confirmed external" category requires actual
# assigned LoadBalancer/status evidence, not just a requested type — see
# kubernetes.py's evidence-hierarchy docstring.

_EXTERNALLY_EXPOSED_CATEGORIES = frozenset(
    {ks.EXPOSURE_EXTERNAL_LOAD_BALANCER, ks.EXPOSURE_EXTERNAL_IP}
)


def _classify_service_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()

    if ct == "added":
        record = _whole_record(change, added=True)
        exposure = record.get("exposure_category")
        if exposure in _EXTERNALLY_EXPOSED_CATEGORIES:
            return "high", "A new Kubernetes Service was added already externally exposed."
        if exposure == ks.EXPOSURE_NODE_PORT:
            return "medium", "A new Kubernetes Service was added using NodePort."
        return "low", "A Kubernetes Service was added to monitoring."

    if ct == "removed":
        record = _whole_record(change, added=False)
        if record.get("exposure_category") in _EXTERNALLY_EXPOSED_CATEGORIES:
            return "low", "An externally exposed Kubernetes Service is no longer visible to ConfigTrace."
        return "low", "A Kubernetes Service is no longer visible to ConfigTrace."

    fp = (_get(change, "field_path") or "").lower()
    nv = _get(change, "new_value")
    pv = _get(change, "prev_value")

    if fp == "exposure_category":
        if nv in _EXTERNALLY_EXPOSED_CATEGORIES and pv not in _EXTERNALLY_EXPOSED_CATEGORIES:
            return "high", "A Kubernetes Service changed from internal to confirmed external exposure."
        if pv in _EXTERNALLY_EXPOSED_CATEGORIES and nv not in _EXTERNALLY_EXPOSED_CATEGORIES:
            return "low", "A Kubernetes Service's external exposure was removed."
        if nv == ks.EXPOSURE_NODE_PORT and pv != ks.EXPOSURE_NODE_PORT:
            return "medium", "A Kubernetes Service changed to NodePort exposure."
        return "low", "A Kubernetes Service's exposure category changed."
    if fp == "load_balancer_ingress_count":
        return _count_transition(
            nv, pv,
            increased=("high", "A public LoadBalancer address was assigned to a Kubernetes Service."),
            decreased=("low", "A Kubernetes Service's LoadBalancer address was unassigned."),
            unknown_message="A Kubernetes Service's LoadBalancer ingress count could not be safely compared.",
        )
    if fp == "external_ip_count":
        return _count_transition(
            nv, pv,
            increased=("high", "An externalIP was added to a Kubernetes Service."),
            decreased=("low", "An externalIP was removed from a Kubernetes Service."),
            unknown_message="A Kubernetes Service's externalIP count could not be safely compared.",
        )
    if fp == "internal_load_balancer_annotation_present":
        if pv is True and nv is not True:
            return "high", "A Kubernetes Service's LoadBalancer is no longer marked internal."
        if nv is True and pv is not True:
            return "low", "A Kubernetes Service's LoadBalancer was marked internal."
        return "low", "A Kubernetes Service's internal-LoadBalancer annotation changed."
    if fp == "external_name_category":
        return ("medium", "A Kubernetes Service was changed to ExternalName.") if nv else (
            "low", "A Kubernetes Service's ExternalName configuration was removed.",
        )
    if fp == "service_type":
        if nv == "NodePort":
            return "medium", "A Kubernetes Service's type changed to NodePort."
        if nv == "ExternalName":
            return "medium", "A Kubernetes Service's type changed to ExternalName."
        return "low", "A Kubernetes Service's type changed."
    if fp in ("external_traffic_policy", "internal_traffic_policy"):
        return "medium", "A Kubernetes Service's traffic policy changed."
    if fp in ("ip_family_categories", "selector_fingerprint"):
        return "low", "A Kubernetes Service's configuration field changed."
    if fp == "mixed_exposure_evidence":
        return "medium", "A Kubernetes Service shows mixed exposure evidence (multiple exposure mechanisms configured)."
    if fp == "collection_completeness_category":
        return ("medium", "ConfigTrace's Kubernetes credentials have only partial visibility into this Service.") if nv == "partial" else (
            "low", "Kubernetes Service collection completeness changed.",
        )
    return "low", "A Kubernetes Service configuration field changed."


def _classify_service_port_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()

    if ct == "added":
        record = _whole_record(change, added=True)
        if record.get("sensitive_port") and record.get("exposure_category") in (
            ks.EXPOSURE_EXTERNAL_LOAD_BALANCER, ks.EXPOSURE_EXTERNAL_IP, ks.EXPOSURE_NODE_PORT,
        ):
            return "high", "A sensitive port was added to an externally reachable Kubernetes Service."
        return "low", "A port was added to a Kubernetes Service."
    if ct == "removed":
        return "low", "A port was removed from a Kubernetes Service."

    fp = (_get(change, "field_path") or "").lower()
    nv = _get(change, "new_value")
    pv = _get(change, "prev_value")

    if fp == "node_port":
        if nv and not pv:
            return "medium", "A NodePort was introduced for a Kubernetes Service port."
        if pv and not nv:
            return "low", "A NodePort was removed from a Kubernetes Service port."
        return "low", "A Kubernetes Service port's NodePort assignment changed."
    if fp == "sensitive_port":
        return ("medium", "A Kubernetes Service port was recategorized as sensitive.") if nv else (
            "low", "A Kubernetes Service port is no longer categorized as sensitive.",
        )
    if fp == "exposure_category":
        if nv in _EXTERNALLY_EXPOSED_CATEGORIES and pv not in _EXTERNALLY_EXPOSED_CATEGORIES:
            return "high", "A Kubernetes Service port's exposure became externally reachable."
        return "low", "A Kubernetes Service port's exposure category changed."
    return "low", "A Kubernetes Service port configuration field changed."


def _classify_ingress_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()

    if ct == "added":
        record = _whole_record(change, added=True)
        if (
            record.get("public_exposure_category") == ks.EXPOSURE_EXTERNAL_LOAD_BALANCER
            and record.get("plaintext_exposure_category") == "plaintext_http_present"
        ):
            return "high", "A new Ingress was added already publicly exposed over plaintext HTTP."
        if record.get("hostless_rule_present"):
            return "medium", "A new Ingress was added with a hostless catch-all rule."
        return "low", "A Kubernetes Ingress was added to monitoring."

    if ct == "removed":
        return "low", "A Kubernetes Ingress is no longer visible to ConfigTrace."

    fp = (_get(change, "field_path") or "").lower()
    nv = _get(change, "new_value")
    pv = _get(change, "prev_value")

    if fp == "plaintext_exposure_category":
        if nv == "plaintext_http_present" and pv == "tls_covered":
            return "high", "TLS coverage was removed from a Kubernetes Ingress; it now serves plaintext HTTP."
        if nv == "tls_covered" and pv == "plaintext_http_present":
            return "low", "TLS coverage was restored for a Kubernetes Ingress."
        return "low", "A Kubernetes Ingress's plaintext-exposure category changed."
    if fp == "tls_host_count":
        nv_i, pv_i = _as_int(nv), _as_int(pv)
        if nv_i is None or pv_i is None:
            return "low", "A Kubernetes Ingress's TLS host count could not be safely compared."
        if nv_i < pv_i and nv_i == 0:
            return "high", "TLS coverage was fully removed from a Kubernetes Ingress."
        if nv_i < pv_i:
            return "medium", "TLS coverage was partially reduced on a Kubernetes Ingress."
        return "low", "A Kubernetes Ingress's TLS host coverage changed."
    if fp == "wildcard_host_count":
        return _count_transition(
            nv, pv,
            increased=("high", "A wildcard host was introduced on a Kubernetes Ingress."),
            decreased=("low", "A wildcard host was removed from a Kubernetes Ingress."),
            unknown_message="A Kubernetes Ingress's wildcard host count could not be safely compared.",
        )
    if fp == "hostless_rule_present":
        return ("high", "A hostless catch-all rule was introduced on a Kubernetes Ingress.") if nv else (
            "low", "A hostless catch-all rule was removed from a Kubernetes Ingress.",
        )
    if fp == "public_exposure_category":
        if nv == ks.EXPOSURE_EXTERNAL_LOAD_BALANCER and pv != ks.EXPOSURE_EXTERNAL_LOAD_BALANCER:
            return "high", "A public LoadBalancer address was assigned to a Kubernetes Ingress."
        return "low", "A Kubernetes Ingress's public-exposure category changed."
    if fp == "load_balancer_ingress_count":
        return _count_transition(
            nv, pv,
            increased=("high", "A public LoadBalancer address was assigned to a Kubernetes Ingress."),
            decreased=("low", "A Kubernetes Ingress's LoadBalancer address was unassigned."),
            unknown_message="A Kubernetes Ingress's LoadBalancer ingress count could not be safely compared.",
        )
    if fp == "ingress_class":
        return "medium", "A Kubernetes Ingress's class changed."
    if fp == "default_backend_present":
        return ("medium", "A default backend was introduced on a Kubernetes Ingress.") if nv else (
            "low", "The default backend was removed from a Kubernetes Ingress.",
        )
    if fp == "backend_service_count":
        return "medium", "A Kubernetes Ingress's backend Service configuration changed."
    if fp == "collection_completeness_category":
        return ("medium", "ConfigTrace's Kubernetes credentials have only partial visibility into this Ingress.") if nv == "partial" else (
            "low", "Kubernetes Ingress collection completeness changed.",
        )
    return "low", "A Kubernetes Ingress configuration field changed."


def _classify_ingress_rule_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()

    if ct == "added":
        record = _whole_record(change, added=True)
        if record.get("catch_all_route") and not record.get("tls_covered"):
            return "high", "A catch-all, plaintext Ingress route was added."
        return "low", "A Kubernetes Ingress route was added."
    if ct == "removed":
        return "low", "A Kubernetes Ingress route was removed."

    fp = (_get(change, "field_path") or "").lower()
    nv = _get(change, "new_value")
    pv = _get(change, "prev_value")

    if fp == "tls_covered":
        return ("low", "TLS coverage was added to a Kubernetes Ingress route.") if nv else (
            "high", "TLS coverage was removed from a Kubernetes Ingress route.",
        )
    if fp == "host_category":
        return ("high", "A Kubernetes Ingress route's host became a wildcard.") if nv == ks.HOST_CATEGORY_WILDCARD else (
            "low", "A Kubernetes Ingress route's host category changed.",
        )
    if fp == "backend_service_name":
        return "medium", "A Kubernetes Ingress route's backend Service changed."
    if fp == "catch_all_route":
        return ("medium", "A Kubernetes Ingress route became a catch-all.") if nv else (
            "low", "A Kubernetes Ingress route is no longer a catch-all.",
        )
    return "low", "A Kubernetes Ingress route field changed."


def _classify_gateway_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()

    if ct == "added":
        record = _whole_record(change, added=True)
        if record.get("public_address_category") == ks.GATEWAY_ADDRESS_EXTERNAL and record.get("http_listener_count", 0) > 0:
            return "high", "A new Gateway was added already externally addressed with an HTTP listener."
        if record.get("allowed_routes_category") == ks.ALLOWED_NAMESPACES_ALL:
            return "medium", "A new Gateway was added allowing routes from all namespaces."
        return "low", "A Kubernetes Gateway was added to monitoring."
    if ct == "removed":
        return "low", "A Kubernetes Gateway is no longer visible to ConfigTrace."

    fp = (_get(change, "field_path") or "").lower()
    nv = _get(change, "new_value")
    pv = _get(change, "prev_value")

    if fp == "allowed_routes_category":
        if nv == ks.ALLOWED_NAMESPACES_ALL and pv != ks.ALLOWED_NAMESPACES_ALL:
            return "high", "A Kubernetes Gateway's allowedRoutes changed to All namespaces."
        if pv == ks.ALLOWED_NAMESPACES_ALL and nv != ks.ALLOWED_NAMESPACES_ALL:
            return "low", "A Kubernetes Gateway's allowedRoutes was narrowed from All namespaces."
        return "low", "A Kubernetes Gateway's allowedRoutes category changed."
    if fp == "cross_namespace_route_allowance":
        return ("high", "A Kubernetes Gateway now allows cross-namespace route attachment.") if nv else (
            "low", "A Kubernetes Gateway's cross-namespace route allowance was removed.",
        )
    if fp == "public_address_category":
        if nv == ks.GATEWAY_ADDRESS_EXTERNAL and pv != ks.GATEWAY_ADDRESS_EXTERNAL:
            return "high", "A Kubernetes Gateway was assigned an external address."
        return "low", "A Kubernetes Gateway's address category changed."
    if fp in ("http_listener_count", "https_listener_count", "tls_listener_count", "listener_protocol_categories"):
        return "medium", "A Kubernetes Gateway's listener configuration changed."
    if fp == "wildcard_hostname_count":
        return _count_transition(
            nv, pv,
            increased=("high", "A wildcard hostname was introduced on a Kubernetes Gateway listener."),
            decreased=("low", "A wildcard hostname was removed from a Kubernetes Gateway listener."),
            unknown_message="A Kubernetes Gateway's wildcard hostname count could not be safely compared.",
        )
    if fp == "status_category":
        return "low", "A Kubernetes Gateway's status category changed."
    if fp == "collection_completeness_category":
        return ("medium", "ConfigTrace's Kubernetes credentials have only partial visibility into this Gateway.") if nv == "partial" else (
            "low", "Kubernetes Gateway collection completeness changed.",
        )
    return "low", "A Kubernetes Gateway configuration field changed."


def _classify_gateway_listener_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()

    if ct == "added":
        record = _whole_record(change, added=True)
        if record.get("tls_mode") == ks.TLS_MODE_NONE and record.get("protocol") == "HTTP":
            return "medium", "A new plaintext HTTP listener was added to a Kubernetes Gateway."
        return "low", "A Kubernetes Gateway listener was added."
    if ct == "removed":
        return "low", "A Kubernetes Gateway listener was removed."

    fp = (_get(change, "field_path") or "").lower()
    nv = _get(change, "new_value")
    pv = _get(change, "prev_value")

    if fp == "tls_mode":
        if nv == ks.TLS_MODE_NONE and pv != ks.TLS_MODE_NONE:
            return "high", "TLS was removed from a Kubernetes Gateway listener."
        if pv == ks.TLS_MODE_NONE and nv != ks.TLS_MODE_NONE:
            return "low", "TLS was added to a Kubernetes Gateway listener."
        return "low", "A Kubernetes Gateway listener's TLS mode changed."
    if fp == "allowed_namespace_policy":
        if nv == ks.ALLOWED_NAMESPACES_ALL and pv != ks.ALLOWED_NAMESPACES_ALL:
            return "high", "A Kubernetes Gateway listener's allowed namespaces changed to All."
        return "low", "A Kubernetes Gateway listener's allowed-namespace policy changed."
    if fp == "public_exposure_category":
        if nv == ks.EXPOSURE_EXTERNAL_LOAD_BALANCER and pv != ks.EXPOSURE_EXTERNAL_LOAD_BALANCER:
            return "high", "A Kubernetes Gateway listener became externally reachable."
        return "low", "A Kubernetes Gateway listener's exposure category changed."
    if fp in ("protocol", "port", "hostname_category"):
        return "medium", "A Kubernetes Gateway listener's configuration changed."
    return "low", "A Kubernetes Gateway listener field changed."


def _classify_http_route_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()

    if ct == "added":
        record = _whole_record(change, added=True)
        if record.get("cross_namespace_backend_count", 0) > 0 and record.get("resolved_refs_status") != ks.ROUTE_REFS_ALL_RESOLVED:
            return "medium", "A new HTTPRoute references a cross-namespace backend with unresolved references."
        return "low", "A Kubernetes HTTPRoute was added to monitoring."
    if ct == "removed":
        return "low", "A Kubernetes HTTPRoute is no longer visible to ConfigTrace."

    fp = (_get(change, "field_path") or "").lower()
    nv = _get(change, "new_value")
    pv = _get(change, "prev_value")

    if fp == "cross_namespace_backend_count":
        return _count_transition(
            nv, pv,
            increased=("high", "A Kubernetes HTTPRoute's cross-namespace backend reference was broadened."),
            decreased=("low", "A Kubernetes HTTPRoute's cross-namespace backend reference was narrowed."),
            unknown_message="A Kubernetes HTTPRoute's cross-namespace backend count could not be safely compared.",
        )
    if fp == "cross_namespace_parent_count":
        return _count_transition(
            nv, pv,
            increased=("medium", "A Kubernetes HTTPRoute gained a cross-namespace parent reference."),
            decreased=("low", "A Kubernetes HTTPRoute's cross-namespace parent reference was removed."),
            unknown_message="A Kubernetes HTTPRoute's cross-namespace parent count could not be safely compared.",
        )
    if fp == "resolved_refs_status":
        if nv == ks.ROUTE_REFS_SOME_UNRESOLVED:
            return "medium", "A Kubernetes HTTPRoute has unresolved backend/parent references."
        return "low", "A Kubernetes HTTPRoute's reference-resolution status changed."
    if fp == "wildcard_hostname_count":
        return _count_transition(
            nv, pv,
            increased=("high", "A wildcard hostname was introduced on a Kubernetes HTTPRoute."),
            decreased=("low", "A wildcard hostname was removed from a Kubernetes HTTPRoute."),
            unknown_message="A Kubernetes HTTPRoute's wildcard hostname count could not be safely compared.",
        )
    if fp in ("redirect_present", "rewrite_present", "filter_categories"):
        return "low", "A Kubernetes HTTPRoute's filter configuration changed."
    if fp == "collection_completeness_category":
        return ("medium", "ConfigTrace's Kubernetes credentials have only partial visibility into this HTTPRoute.") if nv == "partial" else (
            "low", "Kubernetes HTTPRoute collection completeness changed.",
        )
    return "low", "A Kubernetes HTTPRoute configuration field changed."


def _classify_http_route_rule_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()

    if ct == "added":
        record = _whole_record(change, added=True)
        if record.get("cross_namespace_backend"):
            return "medium", "A new HTTPRoute rule references a cross-namespace backend."
        return "low", "A Kubernetes HTTPRoute rule was added."
    if ct == "removed":
        return "low", "A Kubernetes HTTPRoute rule was removed."

    fp = (_get(change, "field_path") or "").lower()
    nv = _get(change, "new_value")

    if fp == "cross_namespace_backend":
        return ("high", "A Kubernetes HTTPRoute rule's backend reference was broadened to another namespace.") if nv else (
            "low", "A Kubernetes HTTPRoute rule's cross-namespace backend reference was removed.",
        )
    if fp == "catch_all_path":
        return ("medium", "A Kubernetes HTTPRoute rule became a catch-all path match.") if nv else (
            "low", "A Kubernetes HTTPRoute rule is no longer a catch-all path match.",
        )
    return "low", "A Kubernetes HTTPRoute rule field changed."


def _classify_network_policy_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()

    if ct == "added":
        record = _whole_record(change, added=True)
        broad_allow = record.get("allows_all_ingress") or record.get("allows_all_egress")
        public_cidr = record.get("public_ipv4_cidr_allowed") or record.get("public_ipv6_cidr_allowed")
        if broad_allow and record.get("pod_selector_empty_all_pods"):
            return "high", "A new NetworkPolicy was added that allows all traffic for all Pods in the namespace."
        if public_cidr:
            return "high", "A new NetworkPolicy was added that permits a public CIDR range."
        return "low", "A Kubernetes NetworkPolicy was added to monitoring."
    if ct == "removed":
        record = _whole_record(change, added=False)
        if record.get("pod_selector_empty_all_pods") and (record.get("empty_ingress_list") or record.get("empty_egress_list")):
            return "high", "A NetworkPolicy providing default-deny coverage for all Pods was removed."
        return "low", "A Kubernetes NetworkPolicy is no longer visible to ConfigTrace."

    fp = (_get(change, "field_path") or "").lower()
    nv = _get(change, "new_value")
    pv = _get(change, "prev_value")

    if fp == "empty_ingress_list":
        return ("low", "A default-deny ingress posture was added to a Kubernetes NetworkPolicy.") if nv else (
            "high", "A default-deny ingress posture was removed from a Kubernetes NetworkPolicy.",
        )
    if fp == "empty_egress_list":
        return ("low", "A default-deny egress posture was added to a Kubernetes NetworkPolicy.") if nv else (
            "high", "A default-deny egress posture was removed from a Kubernetes NetworkPolicy.",
        )
    if fp == "allows_all_ingress":
        return ("critical", "A Kubernetes NetworkPolicy now allows all ingress traffic to all Pods it selects.") if nv else (
            "low", "A Kubernetes NetworkPolicy no longer allows all ingress traffic.",
        )
    if fp == "allows_all_egress":
        return ("critical", "A Kubernetes NetworkPolicy now allows all egress traffic from all Pods it selects.") if nv else (
            "low", "A Kubernetes NetworkPolicy no longer allows all egress traffic.",
        )
    if fp == "public_ipv4_cidr_allowed":
        return ("high", "A Kubernetes NetworkPolicy now permits an unrestricted public IPv4 CIDR (0.0.0.0/0).") if nv else (
            "low", "A Kubernetes NetworkPolicy's public IPv4 CIDR allowance was removed.",
        )
    if fp == "public_ipv6_cidr_allowed":
        return ("high", "A Kubernetes NetworkPolicy now permits an unrestricted public IPv6 CIDR (::/0).") if nv else (
            "low", "A Kubernetes NetworkPolicy's public IPv6 CIDR allowance was removed.",
        )
    if fp == "broad_cidr_count":
        return _count_transition(
            nv, pv,
            increased=("medium", "A Kubernetes NetworkPolicy's broad (non-private) CIDR count increased."),
            decreased=("low", "A Kubernetes NetworkPolicy's broad CIDR count decreased."),
            unknown_message="A Kubernetes NetworkPolicy's broad CIDR count could not be safely compared.",
        )
    if fp in ("namespace_selector_present", "pod_selector_present"):
        return "medium", "A Kubernetes NetworkPolicy's peer-selector configuration changed."
    if fp in ("ingress_isolation_enabled", "egress_isolation_enabled"):
        return ("low", "A Kubernetes NetworkPolicy's isolation posture was strengthened.") if nv else (
            "medium", "A Kubernetes NetworkPolicy's isolation posture was weakened.",
        )
    if fp in ("policy_types", "port_restriction_present", "selector_fingerprint", "policy_fingerprint"):
        return "low", "A Kubernetes NetworkPolicy's configuration changed."
    if fp == "collection_completeness_category":
        return ("medium", "ConfigTrace's Kubernetes credentials have only partial visibility into this NetworkPolicy.") if nv == "partial" else (
            "low", "Kubernetes NetworkPolicy collection completeness changed.",
        )
    return "low", "A Kubernetes NetworkPolicy configuration field changed."


def _classify_namespace_network_posture_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()

    if ct == "added":
        return "low", "A Kubernetes namespace network-posture rollup was observed."
    if ct == "removed":
        return "low", "A Kubernetes namespace network-posture rollup is no longer present."

    fp = (_get(change, "field_path") or "").lower()
    nv = _get(change, "new_value")
    pv = _get(change, "prev_value")

    if fp == "has_any_network_policy":
        return ("low", "A namespace now has at least one NetworkPolicy.") if nv else (
            "medium", "A namespace no longer has any NetworkPolicy.",
        )
    if fp == "all_pod_ingress_default_deny":
        return ("low", "A namespace gained all-Pod ingress default-deny coverage.") if nv else (
            "high", "A namespace lost all-Pod ingress default-deny coverage.",
        )
    if fp == "all_pod_egress_default_deny":
        return ("low", "A namespace gained all-Pod egress default-deny coverage.") if nv else (
            "high", "A namespace lost all-Pod egress default-deny coverage.",
        )
    if fp == "policy_coverage_category":
        if nv == ks.POLICY_COVERAGE_BROAD and pv != ks.POLICY_COVERAGE_BROAD:
            return "low", "A namespace's NetworkPolicy coverage became broad (comprehensive default-deny)."
        if pv == ks.POLICY_COVERAGE_BROAD and nv != ks.POLICY_COVERAGE_BROAD:
            return "high", "A namespace's NetworkPolicy coverage regressed from broad to partial or none."
        if nv == ks.POLICY_COVERAGE_UNKNOWN:
            return "medium", "A namespace's NetworkPolicy coverage could not be fully determined."
        return "low", "A namespace's NetworkPolicy coverage category changed."
    if fp == "public_ingress_allowance_present":
        return ("high", "A namespace now has a NetworkPolicy permitting public ingress.") if nv else (
            "low", "A namespace's public ingress allowance was removed.",
        )
    if fp == "public_egress_allowance_present":
        return ("high", "A namespace now has a NetworkPolicy permitting public egress.") if nv else (
            "low", "A namespace's public egress allowance was removed.",
        )
    if fp in ("policy_count", "ingress_isolation_present", "egress_isolation_present",
              "broad_namespace_selector_allowance", "broad_pod_selector_allowance"):
        return "low", "A namespace's NetworkPolicy posture changed."
    if fp == "collection_completeness_category":
        return ("medium", "ConfigTrace's Kubernetes credentials have only partial visibility into this namespace's NetworkPolicies.") if nv == "partial" else (
            "low", "Kubernetes namespace NetworkPolicy collection completeness changed.",
        )
    return "low", "A Kubernetes namespace network-posture field changed."


# ── Admission control and configuration governance classifiers (message 5) ──
#
# `failurePolicy=Ignore` is not automatically a vulnerability (it is
# fail-open, an availability trade-off); `failurePolicy=Fail` is fail-closed
# but can itself create availability risk. Broad webhook scope may be
# intentional (e.g. a policy engine). Missing CA bundle does not
# necessarily mean no TLS (URL clients may rely on system trust). None of
# these classifiers claim admission bypass, exploitation, or compromise —
# only structural posture transitions.

_PSA_RANK_UNKNOWN = -1


def _psa_rank(value: object) -> int:
    """Rank for directional (weaker/stronger) comparison only. "unset" is
    treated as rank 0 (same as "privileged") here — an *unlabeled*
    namespace behaves exactly like an explicit privileged one for
    enforcement purposes, so introducing baseline/restricted from unset is
    correctly a strengthening. This is separate from — and does not
    override — the explicit "enforcement removed" classification below for
    the reverse transition (labeled -> unset), which is always high
    regardless of rank math."""
    if isinstance(value, str) and value in ks.PSA_LEVEL_RANK:
        return ks.PSA_LEVEL_RANK[value]
    if value == ks.PSA_ENFORCE_CATEGORY_UNSET:
        return 0
    return _PSA_RANK_UNKNOWN


def _classify_webhook_configuration_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    kind_label = "webhook configuration"

    if ct == "added":
        record = _whole_record(change, added=True)
        kind_label = record.get("kind") or kind_label
        posture = record.get("security_posture_summary")
        if posture == ks.WEBHOOK_SECURITY_POSTURE_FAIL_OPEN:
            return "medium", f"A new {kind_label} was added entirely fail-open."
        return "low", f"A Kubernetes {kind_label} was added to monitoring."

    if ct == "removed":
        record = _whole_record(change, added=False)
        kind_label = record.get("kind") or kind_label
        if record.get("fail_closed_webhook_count", 0) > 0:
            return "high", f"A {kind_label} providing fail-closed admission validation was removed."
        return "low", f"A Kubernetes {kind_label} is no longer visible to ConfigTrace."

    fp = (_get(change, "field_path") or "").lower()
    nv = _get(change, "new_value")
    pv = _get(change, "prev_value")

    if fp == "security_posture_summary":
        if nv == ks.WEBHOOK_SECURITY_POSTURE_FAIL_OPEN and pv != ks.WEBHOOK_SECURITY_POSTURE_FAIL_OPEN:
            return "high", f"A {kind_label} changed from fail-closed to fail-open."
        if pv == ks.WEBHOOK_SECURITY_POSTURE_FAIL_OPEN and nv != ks.WEBHOOK_SECURITY_POSTURE_FAIL_OPEN:
            return "low", f"A {kind_label} changed from fail-open to fail-closed."
        return "low", f"A {kind_label}'s security posture summary changed."
    if fp == "fail_open_webhook_count":
        return _count_transition(
            nv, pv,
            increased=("medium", f"A {kind_label} gained a fail-open webhook."),
            decreased=("low", f"A {kind_label}'s fail-open webhook count decreased."),
            unknown_message=f"A {kind_label}'s fail-open webhook count could not be safely compared.",
        )
    if fp == "fail_closed_webhook_count":
        return _count_transition(
            nv, pv,
            increased=("low", f"A {kind_label} gained a fail-closed webhook."),
            decreased=("medium", f"A {kind_label}'s fail-closed webhook count decreased."),
            unknown_message=f"A {kind_label}'s fail-closed webhook count could not be safely compared.",
        )
    if fp == "webhook_count":
        return _count_transition(
            nv, pv,
            increased=("low", f"A {kind_label} gained a webhook."),
            decreased=("medium", f"A webhook was removed from a {kind_label}."),
            unknown_message=f"A {kind_label}'s webhook count could not be safely compared.",
        )
    if fp == "ca_bundle_present_count":
        return _count_transition(
            nv, pv,
            increased=("low", f"A {kind_label}'s CA-bundle coverage increased."),
            decreased=("medium", f"A {kind_label}'s CA-bundle coverage decreased."),
            unknown_message=f"A {kind_label}'s CA-bundle coverage count could not be safely compared.",
        )
    if fp in ("timeout_seconds_min", "timeout_seconds_max"):
        return "medium", f"A {kind_label}'s webhook timeout configuration changed."
    if fp in ("namespace_selector_present_count", "object_selector_present_count"):
        return "medium", f"A {kind_label}'s selector coverage changed."
    if fp in ("external_url_client_count", "in_cluster_service_client_count"):
        return "medium", f"A {kind_label}'s client configuration changed."
    if fp in ("match_policy_categories", "reinvocation_policy_categories",
              "admission_review_version_categories", "configuration_fingerprint"):
        return "low", f"A {kind_label}'s configuration changed."
    if fp == "collection_completeness_category":
        return ("medium", f"ConfigTrace's Kubernetes credentials have only partial visibility into this {kind_label}.") if nv == "partial" else (
            "low", f"Kubernetes {kind_label} collection completeness changed.",
        )
    return "low", f"A Kubernetes {kind_label} field changed."


def _classify_webhook_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()

    if ct == "added":
        record = _whole_record(change, added=True)
        full_wildcard = record.get("wildcard_operation") and record.get("wildcard_api_group") and record.get("wildcard_resource")
        if full_wildcard:
            return "high", "A new admission webhook was added with wildcard operation/API-group/resource scope."
        if record.get("client_type") == ks.CLIENT_TYPE_URL and record.get("plaintext_http_client"):
            return "high", "A new admission webhook was added using an external plaintext HTTP URL."
        if record.get("failure_policy") == ks.FAILURE_POLICY_IGNORE:
            return "medium", "A new admission webhook was added with failurePolicy=Ignore (fail-open)."
        return "low", "An admission webhook was added to monitoring."

    if ct == "removed":
        record = _whole_record(change, added=False)
        webhook_type = record.get("webhook_type") or "admission"
        if webhook_type == "validating" and record.get("failure_policy") == ks.FAILURE_POLICY_FAIL:
            return "high", "A fail-closed validating webhook was removed."
        if webhook_type == "mutating":
            return "medium", "A mutating webhook was removed."
        return "low", "An admission webhook is no longer visible to ConfigTrace."

    fp = (_get(change, "field_path") or "").lower()
    nv = _get(change, "new_value")
    pv = _get(change, "prev_value")

    if fp == "failure_policy":
        if nv == ks.FAILURE_POLICY_IGNORE and pv == ks.FAILURE_POLICY_FAIL:
            return "high", "An admission webhook's failurePolicy changed from Fail to Ignore."
        if nv == ks.FAILURE_POLICY_FAIL and pv == ks.FAILURE_POLICY_IGNORE:
            return "low", "An admission webhook's failurePolicy was restored to Fail (fail-closed)."
        return "low", "An admission webhook's failurePolicy changed."
    if fp in ("wildcard_operation", "wildcard_api_group", "wildcard_resource"):
        return ("high", "An admission webhook's rule scope was broadened to a wildcard.") if nv else (
            "low", "An admission webhook's wildcard rule scope was narrowed.",
        )
    if fp == "wildcard_api_version":
        return ("medium", "An admission webhook's rule API-version scope was broadened to a wildcard.") if nv else (
            "low", "An admission webhook's wildcard API-version scope was narrowed.",
        )
    if fp in ("namespace_selector_category", "object_selector_category"):
        broadened = nv in (ks.SELECTOR_ABSENT, ks.SELECTOR_EMPTY_ALL) and pv == ks.SELECTOR_NARROW
        narrowed = pv in (ks.SELECTOR_ABSENT, ks.SELECTOR_EMPTY_ALL) and nv == ks.SELECTOR_NARROW
        if broadened:
            return "medium", "An admission webhook's selector was broadened to match all resources."
        if narrowed:
            return "low", "An admission webhook's selector was narrowed."
        return "low", "An admission webhook's selector configuration changed."
    if fp == "ca_bundle_present":
        return ("low", "An admission webhook's CA bundle was configured.") if nv else (
            "medium", "An admission webhook's CA-bundle protection was removed.",
        )
    if fp in ("service_namespace", "service_name", "service_port"):
        return "medium", "An admission webhook's client Service destination changed."
    if fp == "external_url_host_category":
        return "medium", "An admission webhook's external URL changed."
    if fp == "plaintext_http_client":
        return ("high", "An admission webhook's external URL changed to plaintext HTTP.") if nv else (
            "low", "An admission webhook's external URL is no longer plaintext HTTP.",
        )
    if fp == "reinvocation_policy":
        return "medium", "A mutating webhook's reinvocation policy changed."
    if fp == "side_effects":
        if nv == ks.SIDE_EFFECTS_UNKNOWN and pv != ks.SIDE_EFFECTS_UNKNOWN:
            return "medium", "An admission webhook's sideEffects became Unknown."
        return "low", "An admission webhook's sideEffects category changed."
    if fp == "timeout_seconds":
        nv_i, pv_i = _as_int(nv), _as_int(pv)
        if nv_i is None or pv_i is None:
            return "low", "An admission webhook's timeout could not be safely compared."
        if nv_i < pv_i:
            return "medium", "An admission webhook's timeout was reduced."
        return "low", "An admission webhook's timeout was increased."
    if fp == "match_policy":
        return "low", "An admission webhook's matchPolicy changed."
    if fp in ("operation_categories", "api_group_categories", "resource_categories", "scope_category",
              "rules_count", "admission_review_versions", "webhook_fingerprint"):
        return "low", "An admission webhook's rule configuration changed."
    if fp == "collection_completeness_category":
        return ("medium", "ConfigTrace's Kubernetes credentials have only partial visibility into this webhook.") if nv == "partial" else (
            "low", "Kubernetes admission webhook collection completeness changed.",
        )
    return "low", "An admission webhook field changed."


def _classify_pod_security_admission_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()

    if ct == "added":
        record = _whole_record(change, added=True)
        enforce = record.get("enforce_level")
        if enforce == ks.PSA_ENFORCE_CATEGORY_INVALID:
            return "high", "A namespace was observed with an invalid Pod Security Admission enforce label."
        if enforce == ks.PSA_ENFORCE_CATEGORY_UNSET:
            return "low", "A namespace was observed with no Pod Security Admission enforce label."
        return "low", "A namespace's Pod Security Admission posture was observed."
    if ct == "removed":
        return "low", "A namespace's Pod Security Admission posture is no longer visible to ConfigTrace."

    fp = (_get(change, "field_path") or "").lower()
    nv = _get(change, "new_value")
    pv = _get(change, "prev_value")

    if fp == "enforce_level":
        if nv == ks.PSA_ENFORCE_CATEGORY_INVALID:
            return "high", "A namespace's Pod Security Admission enforce label became invalid."
        new_rank, old_rank = _psa_rank(nv), _psa_rank(pv)
        if nv == ks.PSA_ENFORCE_CATEGORY_UNSET and pv != ks.PSA_ENFORCE_CATEGORY_UNSET:
            return "high", "A namespace's Pod Security Admission enforcement was removed."
        if new_rank != _PSA_RANK_UNKNOWN and old_rank != _PSA_RANK_UNKNOWN:
            if new_rank < old_rank:
                return "high", f"A namespace's Pod Security Admission enforcement was weakened (from {pv!r} to {nv!r})."
            if new_rank > old_rank:
                return "low", f"A namespace's Pod Security Admission enforcement was strengthened (from {pv!r} to {nv!r})."
        return "medium", "A namespace's Pod Security Admission enforce level changed."
    if fp == "enforce_version_category":
        if nv == ks.PSA_VERSION_PINNED_OLD and pv != ks.PSA_VERSION_PINNED_OLD:
            return "medium", "A namespace's Pod Security Admission enforce version was pinned to an old release."
        return "low", "A namespace's Pod Security Admission enforce version category changed."
    if fp in ("audit_level", "warn_level"):
        if nv == ks.PSA_ENFORCE_CATEGORY_UNSET and pv != ks.PSA_ENFORCE_CATEGORY_UNSET:
            return "medium", "A namespace's Pod Security Admission audit/warn label was removed."
        return "low", "A namespace's Pod Security Admission audit/warn level changed."
    if fp in ("enforcement_weaker_than_audit", "enforcement_weaker_than_warning"):
        return ("medium", "A namespace's Pod Security Admission enforcement is now weaker than its audit/warn level.") if nv else (
            "low", "A namespace's Pod Security Admission enforcement is no longer weaker than its audit/warn level.",
        )
    if fp in ("audit_version_category", "warn_version_category", "effective_posture_category",
              "enforcement_enabled", "audit_enabled", "warning_enabled", "posture_fingerprint"):
        return "low", "A namespace's Pod Security Admission configuration changed."
    if fp == "collection_completeness_category":
        return ("medium", "ConfigTrace's Kubernetes credentials have only partial visibility into this namespace's PSA labels.") if nv == "partial" else (
            "low", "Kubernetes Pod Security Admission collection completeness changed.",
        )
    return "low", "A namespace's Pod Security Admission field changed."


def _classify_resource_quota_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()

    if ct == "added":
        return "low", "A Kubernetes ResourceQuota was added to monitoring."
    if ct == "removed":
        return "medium", "A Kubernetes ResourceQuota is no longer visible to ConfigTrace."

    fp = (_get(change, "field_path") or "").lower()
    nv = _get(change, "new_value")
    pv = _get(change, "prev_value")

    if fp in (
        "hard_cpu_limit_present", "hard_memory_limit_present", "pod_count_limit_present",
        "load_balancer_count_limit_present", "secret_count_limit_present", "configmap_count_limit_present",
    ):
        return ("medium", "A Kubernetes ResourceQuota control was removed.") if pv is True and nv is not True else (
            "low", "A Kubernetes ResourceQuota control was added.",
        )
    if fp == "resource_control_coverage_category":
        if pv == "broad" and nv != "broad":
            return "medium", "A Kubernetes ResourceQuota's control coverage decreased from broad."
        if nv == "broad" and pv != "broad":
            return "low", "A Kubernetes ResourceQuota's control coverage increased to broad."
        return "low", "A Kubernetes ResourceQuota's control coverage category changed."
    if fp in ("hard_cpu_limit_millicores", "hard_memory_limit_bytes", "request_cpu_limit_millicores",
              "request_memory_limit_bytes", "pod_count_limit"):
        return "low", "A Kubernetes ResourceQuota's configured value changed."
    if fp == "collection_completeness_category":
        return ("medium", "ConfigTrace's Kubernetes credentials have only partial visibility into this ResourceQuota.") if nv == "partial" else (
            "low", "Kubernetes ResourceQuota collection completeness changed.",
        )
    return "low", "A Kubernetes ResourceQuota field changed."


def _classify_limit_range_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()

    if ct == "added":
        return "low", "A Kubernetes LimitRange was added to monitoring."
    if ct == "removed":
        record = _whole_record(change, added=False)
        if record.get("container_default_present"):
            return "high", "A LimitRange providing container default resource limits was removed."
        return "medium", "A Kubernetes LimitRange is no longer visible to ConfigTrace."

    fp = (_get(change, "field_path") or "").lower()
    nv = _get(change, "new_value")
    pv = _get(change, "prev_value")

    if fp in ("container_default_present", "container_default_request_present"):
        return ("high", "A LimitRange's default resource limits were removed.") if pv is True and nv is not True else (
            "low", "A LimitRange's default resource limits were added.",
        )
    if fp in ("pod_max_present", "pod_min_present", "container_max_present", "container_min_present",
              "pvc_min_present", "pvc_max_present"):
        return ("medium", "A LimitRange's min/max resource constraint was removed.") if pv is True and nv is not True else (
            "low", "A LimitRange's min/max resource constraint was added.",
        )
    if fp == "defaulting_coverage_category":
        if pv == "broad" and nv != "broad":
            return "medium", "A LimitRange's defaulting coverage decreased from broad."
        return "low", "A LimitRange's defaulting coverage category changed."
    if fp in ("cpu_policy_coverage_category", "memory_policy_coverage_category", "ephemeral_storage_policy_coverage_category"):
        return "low", "A LimitRange's resource policy coverage category changed."
    if fp == "request_to_limit_ratio_present":
        return "low", "A LimitRange's request-to-limit ratio constraint changed."
    if fp == "collection_completeness_category":
        return ("medium", "ConfigTrace's Kubernetes credentials have only partial visibility into this LimitRange.") if nv == "partial" else (
            "low", "Kubernetes LimitRange collection completeness changed.",
        )
    return "low", "A Kubernetes LimitRange field changed."


def _classify_namespace_governance_posture_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()

    if ct == "added":
        return "low", "A Kubernetes namespace governance-posture rollup was observed."
    if ct == "removed":
        return "low", "A Kubernetes namespace governance-posture rollup is no longer present."

    fp = (_get(change, "field_path") or "").lower()
    nv = _get(change, "new_value")
    pv = _get(change, "prev_value")

    if fp == "psa_enforcement_category":
        new_rank, old_rank = _psa_rank(nv), _psa_rank(pv)
        if new_rank != _PSA_RANK_UNKNOWN and old_rank != _PSA_RANK_UNKNOWN and new_rank < old_rank:
            return "high", "A namespace's governance rollup shows Pod Security Admission enforcement weakened."
        return "low", "A namespace's governance rollup PSA enforcement category changed."
    if fp in ("validating_webhook_coverage_category", "mutating_webhook_coverage_category"):
        if pv == "full" and nv != "full":
            return "medium", "A namespace's admission webhook coverage decreased from full."
        return "low", "A namespace's admission webhook coverage category changed."
    if fp == "quota_coverage_category":
        if pv == "broad" and nv == "none":
            return "medium", "A namespace's resource-governance coverage regressed to none."
        return "low", "A namespace's quota coverage category changed."
    if fp == "default_resource_control_category":
        return ("medium", "A namespace lost its default resource-control coverage.") if pv == "present" and nv != "present" else (
            "low", "A namespace's default resource-control category changed.",
        )
    if fp == "network_policy_coverage_category":
        return "low", "A namespace's governance rollup NetworkPolicy coverage category changed."
    if fp in ("privileged_workload_present", "high_privilege_service_account_present"):
        return ("medium", "A namespace's governance rollup now shows a higher-risk identity/workload signal present.") if nv else (
            "low", "A namespace's governance rollup risk signal was removed.",
        )
    if fp == "governance_risk_summary":
        if nv != "standard" and pv == "standard":
            return "high", f"A namespace's governance rollup now shows a structural risk combination: {nv}."
        if nv == "standard" and pv != "standard":
            return "low", "A namespace's governance rollup risk combination was resolved."
        return "low", "A namespace's governance risk summary changed."
    if fp in ("resource_quota_count", "limit_range_count", "governance_completeness_category"):
        return "low", "A namespace's governance rollup field changed."
    return "low", "A Kubernetes namespace governance-posture field changed."


def classify_kubernetes_change(change: object) -> tuple[str, str]:
    """Route a Kubernetes Change to its record-type classifier.

    Unknown/future ``kubernetes_*`` record types (i.e. any later-message
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
    if record_type == KUBERNETES_SERVICE:
        return _classify_service_change(change)
    if record_type == KUBERNETES_SERVICE_PORT:
        return _classify_service_port_change(change)
    if record_type == KUBERNETES_INGRESS:
        return _classify_ingress_change(change)
    if record_type == KUBERNETES_INGRESS_RULE:
        return _classify_ingress_rule_change(change)
    if record_type == KUBERNETES_GATEWAY:
        return _classify_gateway_change(change)
    if record_type == KUBERNETES_GATEWAY_LISTENER:
        return _classify_gateway_listener_change(change)
    if record_type == KUBERNETES_HTTP_ROUTE:
        return _classify_http_route_change(change)
    if record_type == KUBERNETES_HTTP_ROUTE_RULE:
        return _classify_http_route_rule_change(change)
    if record_type == KUBERNETES_NETWORK_POLICY:
        return _classify_network_policy_change(change)
    if record_type == KUBERNETES_NAMESPACE_NETWORK_POSTURE:
        return _classify_namespace_network_posture_change(change)
    if record_type in _WEBHOOK_CONFIGURATION_RECORD_TYPES:
        return _classify_webhook_configuration_change(change)
    if record_type in _WEBHOOK_RECORD_TYPES:
        return _classify_webhook_change(change)
    if record_type == KUBERNETES_POD_SECURITY_ADMISSION:
        return _classify_pod_security_admission_change(change)
    if record_type == KUBERNETES_RESOURCE_QUOTA:
        return _classify_resource_quota_change(change)
    if record_type == KUBERNETES_LIMIT_RANGE:
        return _classify_limit_range_change(change)
    if record_type == KUBERNETES_NAMESPACE_GOVERNANCE_POSTURE:
        return _classify_namespace_governance_posture_change(change)

    return "low", f"A Kubernetes configuration record changed ({record_type or 'unknown record type'})."
