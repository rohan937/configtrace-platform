"""Kubernetes risk classification rules — foundation + workloads (messages 1-2 of 9).

This module exists to give every ``kubernetes_*`` record type a dedicated,
correct classifier so that ``risk_service.classify_change()`` never falls
through to the unrelated Cloudflare DNS default classifier (the generic
fallback at the bottom of that dispatch chain is for un-prefixed record
types and would produce a nonsensical result for a Kubernetes Change).

This is intentionally NOT the full, final risk classifier. Per the
message-2 scope, no complete Kubernetes Security Finding taxonomy or
exhaustive severity calibration is built yet — that is message 6 (Security
Finding taxonomy) and message 7 (Change classification's full pass). What
IS implemented here is structural classifier support for every new
workload/container record type and the "obvious high-value transitions"
called out for message 2: privileged/root/host-namespace posture, dangerous
capabilities, seccomp/AppArmor, hostPath (including runtime-socket
mounts), image mutability, missing resource controls, host ports, and
service-account-token automount. Severity assignments follow the message-2
brief's safe conventions and deliberately do NOT claim compromise,
breakout, exploitation, internet exposure, or secret theft — they describe
structural posture only.
"""

from __future__ import annotations

from app.connectors.kubernetes_schema import (
    CAPABILITY_ALL,
    DANGEROUS_CAPABILITIES,
    HOSTPATH_CATEGORY_CONTAINERD_SOCKET,
    HOSTPATH_CATEGORY_DOCKER_SOCKET,
    IMAGE_TAG_LATEST_EXPLICIT,
    IMAGE_TAG_LATEST_IMPLICIT,
    KUBERNETES_API_CAPABILITY,
    KUBERNETES_CLUSTER,
    KUBERNETES_CONTAINER_SECURITY_CONTEXT,
    KUBERNETES_CRONJOB,
    KUBERNETES_DAEMONSET,
    KUBERNETES_DEPLOYMENT,
    KUBERNETES_JOB,
    KUBERNETES_NAMESPACE,
    KUBERNETES_POD,
    KUBERNETES_STATEFULSET,
    KUBERNETES_WORKLOAD_SERVICE_ACCOUNT,
    PROFILE_CATEGORY_UNCONFINED,
    SECURITY_POSTURE_ELEVATED,
    SECURITY_POSTURE_PRIVILEGED_OR_HOST_ACCESS,
)

_WORKLOAD_CONTROLLER_RECORD_TYPES = frozenset(
    {
        KUBERNETES_DEPLOYMENT, KUBERNETES_STATEFULSET, KUBERNETES_DAEMONSET,
        KUBERNETES_JOB, KUBERNETES_CRONJOB,
    }
)
_DANGEROUS_HOSTPATH_SOCKET_CATEGORIES = frozenset(
    {HOSTPATH_CATEGORY_DOCKER_SOCKET, HOSTPATH_CATEGORY_CONTAINERD_SOCKET}
)
_MUTABLE_IMAGE_TAG_CATEGORIES = frozenset({IMAGE_TAG_LATEST_EXPLICIT, IMAGE_TAG_LATEST_IMPLICIT})


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
    return "low", "A Kubernetes workload service-account rollup field changed."


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

    Unknown/future ``kubernetes_*`` record types (i.e. the message 3-5
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

    return "low", f"A Kubernetes configuration record changed ({record_type or 'unknown record type'})."
