"""Kubernetes security exposure rules — M89F (Kubernetes message 6 of 9).

Every rule fires only on explicit, reliable normalized fields produced by the
Kubernetes connector (app/connectors/kubernetes.py + kubernetes_schema.py).
Evidence is metadata-only: cluster/namespace/workload/container names,
ServiceAccount/Role/binding names, subject type/name, Service/Ingress/Gateway
names, hostnames, ports, CIDRs, and normalized security-posture categories.

Never included in evidence (matches the connector's own boundaries):
Secret values, Secret key names, ConfigMap values, kubeconfig contents,
tokens, private keys, certificate bytes, webhook payloads, arbitrary
annotations/labels, environment values, command/args, application logs,
admission request/response bodies.

Claim discipline
-----------------
These rules describe CONFIGURATION STATE, never a confirmed breach or
exploit. Titles/descriptions use "is configured to / is bound to / allows /
does not establish" language. They never claim "compromised", "attacker has
access", "secrets were stolen", "bypassed", or similar.

Tri-state discipline
---------------------
Every rule that reads an Optional[bool]/Optional[str] field fires ONLY on an
explicit risky value. ``None`` (unknown/not collected) and partial-collection
states never fire a risky finding — they are provider-completeness concerns,
not security findings. Where a namespace/PSA/webhook lookup genuinely could
not resolve, the rule is skipped rather than guessed.

Record types consumed
----------------------
Workload/Pod       : kubernetes_container_security_context,
                      kubernetes_deployment/statefulset/daemonset/job/cronjob,
                      kubernetes_pod
RBAC/identity       : kubernetes_rbac_subject_binding, kubernetes_service_account
Network exposure    : kubernetes_service, kubernetes_service_port,
                      kubernetes_ingress_rule, kubernetes_gateway_listener
NetworkPolicy       : kubernetes_network_policy, kubernetes_namespace_network_posture
Admission webhooks  : kubernetes_validating_webhook, kubernetes_mutating_webhook
Pod Security Admission: kubernetes_pod_security_admission
Governance rollup   : kubernetes_namespace_governance_posture

Deferred Kubernetes rules (intentionally NOT implemented — see message-6 report)
----------------------------------------------------------------------------
* ``kubernetes_validating_webhook_removed`` — static rules evaluate CURRENT
  state, not historical removal; that belongs to Change classification
  (message 7).
* ``kubernetes_admission_webhook_missing_ca`` / ``_unknown_side_effects`` —
  ambiguous for external-URL clients relying on system trust; deferred to
  avoid false positives.
* ``kubernetes_psa_baseline_enforcement`` / ``_audit_missing`` / ``_warn_missing``
  standalone — baseline enforcement and missing audit/warn are common,
  low-signal defaults on their own; only the combined
  ``kubernetes_psa_weak_with_privileged_workloads`` rule fires.
* ``kubernetes_unresolved_privileged_binding`` — role-resolution failure is a
  provider-completeness/visibility concern, not a security finding on its own.
* ``kubernetes_external_ip_service`` / ``kubernetes_external_name_service`` /
  ``kubernetes_wildcard_ingress`` / ``kubernetes_gateway_routes_all_namespaces`` /
  ``kubernetes_cross_namespace_route`` — lower-signal/noisier per-record
  exposure variants; the highest-signal exposure rules
  (public_load_balancer, sensitive_nodeport, public_ingress_without_tls,
  hostless_catchall_ingress, public_gateway_listener) are kept instead.
* ``kubernetes_certificate_approval_permission`` /
  ``kubernetes_default_service_account_privileged`` as standalone RBAC
  rules — the same signal is already captured by
  ``kubernetes_cluster_admin_binding`` / ``kubernetes_wildcard_rbac_permissions``
  at finer per-subject-per-binding granularity.
* Per-key ResourceQuota/LimitRange findings — a single combined
  ``kubernetes_namespace_resource_governance_missing`` rule is used instead
  of one finding per absent quota/limit key (avoids noise; see task
  guidance "do not create separate Findings for every absent quota key").
* Secret/ConfigMap contents, runtime exploit detection, Pod logs, Kubernetes
  audit events, vulnerability/image scanning, runtime syscall detection, CNI
  enforcement verification — permanently out of scope (see
  kubernetes_schema.py module docstring).
"""

from __future__ import annotations

from typing import Any

from app.connectors import kubernetes_schema as ks
from app.services.security_rules.base import (
    FindingCandidate,
    get_str,
    make_finding_key,
)

# ── Rule keys ────────────────────────────────────────────────────────────────

# Workload / Pod (18)
_RULE_PRIVILEGED_CONTAINER = "kubernetes_privileged_container"
_RULE_PRIVILEGED_HOST_ACCESS = "kubernetes_privileged_host_access"
_RULE_ROOT_CONTAINER = "kubernetes_root_container"
_RULE_RUN_AS_NON_ROOT_DISABLED = "kubernetes_run_as_non_root_disabled"
_RULE_PRIVILEGE_ESCALATION_ALLOWED = "kubernetes_privilege_escalation_allowed"
_RULE_DANGEROUS_CAPABILITY = "kubernetes_dangerous_linux_capability"
_RULE_ALL_CAPABILITIES_ADDED = "kubernetes_all_capabilities_added"
_RULE_HOST_PID = "kubernetes_host_pid_enabled"
_RULE_HOST_IPC = "kubernetes_host_ipc_enabled"
_RULE_HOST_NETWORK = "kubernetes_host_network_enabled"
_RULE_DANGEROUS_HOSTPATH = "kubernetes_dangerous_hostpath"
_RULE_RUNTIME_SOCKET_MOUNTED = "kubernetes_container_runtime_socket_mounted"
_RULE_SECCOMP_UNCONFINED = "kubernetes_seccomp_unconfined"
_RULE_APPARMOR_UNCONFINED = "kubernetes_apparmor_unconfined"
_RULE_WRITABLE_ROOT_FILESYSTEM = "kubernetes_writable_root_filesystem"
_RULE_MUTABLE_IMAGE_TAG = "kubernetes_mutable_image_tag"
_RULE_SA_TOKEN_AUTOMOUNT = "kubernetes_service_account_token_automount"
_RULE_SENSITIVE_HOST_PORT = "kubernetes_sensitive_host_port"

# RBAC / identity (17)
_RULE_CLUSTER_ADMIN_BINDING = "kubernetes_cluster_admin_binding"
_RULE_UNAUTHENTICATED_CLUSTER_ADMIN = "kubernetes_unauthenticated_cluster_admin"
_RULE_AUTHENTICATED_GROUP_CLUSTER_ADMIN = "kubernetes_authenticated_group_cluster_admin"
_RULE_ALL_SERVICE_ACCOUNTS_CLUSTER_ADMIN = "kubernetes_all_service_accounts_cluster_admin"
_RULE_WILDCARD_RBAC_PERMISSIONS = "kubernetes_wildcard_rbac_permissions"
_RULE_RBAC_BIND_PERMISSION = "kubernetes_rbac_bind_permission"
_RULE_RBAC_ESCALATE_PERMISSION = "kubernetes_rbac_escalate_permission"
_RULE_RBAC_IMPERSONATE_PERMISSION = "kubernetes_rbac_impersonate_permission"
_RULE_SA_TOKEN_CREATION = "kubernetes_service_account_token_creation"
_RULE_SECRET_READ_PERMISSION = "kubernetes_secret_read_permission"
_RULE_SECRET_WRITE_PERMISSION = "kubernetes_secret_write_permission"
_RULE_POD_EXEC_PERMISSION = "kubernetes_pod_exec_permission"
_RULE_POD_ATTACH_PERMISSION = "kubernetes_pod_attach_permission"
_RULE_BROAD_WORKLOAD_CREATION = "kubernetes_broad_workload_creation"
_RULE_RBAC_MODIFICATION_PERMISSION = "kubernetes_rbac_modification_permission"
_RULE_ADMISSION_WEBHOOK_MODIFICATION_PERMISSION = "kubernetes_admission_webhook_modification_permission"
_RULE_CRD_MODIFICATION_PERMISSION = "kubernetes_crd_modification_permission"

# Network / public exposure (6)
_RULE_PUBLIC_LOAD_BALANCER = "kubernetes_public_load_balancer"
_RULE_SENSITIVE_NODEPORT = "kubernetes_sensitive_nodeport"
_RULE_PUBLIC_INGRESS_WITHOUT_TLS = "kubernetes_public_ingress_without_tls"
_RULE_HOSTLESS_CATCHALL_INGRESS = "kubernetes_hostless_catchall_ingress"
_RULE_PUBLIC_GATEWAY_LISTENER = "kubernetes_public_gateway_listener"

# NetworkPolicy isolation (7)
_RULE_NETPOL_ALLOWS_ALL_INGRESS = "kubernetes_network_policy_allows_all_ingress"
_RULE_NETPOL_ALLOWS_ALL_EGRESS = "kubernetes_network_policy_allows_all_egress"
_RULE_PUBLIC_IPV4_CIDR = "kubernetes_public_ipv4_cidr_allowed"
_RULE_PUBLIC_IPV6_CIDR = "kubernetes_public_ipv6_cidr_allowed"
_RULE_NAMESPACE_NO_NETWORK_POLICY = "kubernetes_namespace_no_network_policy"
_RULE_NAMESPACE_NO_INGRESS_ISOLATION = "kubernetes_namespace_no_ingress_isolation"
_RULE_NAMESPACE_NO_EGRESS_ISOLATION = "kubernetes_namespace_no_egress_isolation"

# Admission webhooks (4)
_RULE_VALIDATING_WEBHOOK_FAIL_OPEN = "kubernetes_validating_webhook_fail_open"
_RULE_MUTATING_WEBHOOK_FAIL_OPEN = "kubernetes_mutating_webhook_fail_open"
_RULE_BROAD_ADMISSION_WEBHOOK = "kubernetes_broad_admission_webhook"
_RULE_ADMISSION_WEBHOOK_EXTERNAL_HTTP = "kubernetes_admission_webhook_external_http"

# Pod Security Admission (4)
_RULE_PSA_PRIVILEGED_ENFORCEMENT = "kubernetes_psa_privileged_enforcement"
_RULE_PSA_ENFORCEMENT_MISSING = "kubernetes_psa_enforcement_missing"
_RULE_PSA_INVALID_ENFORCEMENT = "kubernetes_psa_invalid_enforcement"
_RULE_PSA_WEAK_WITH_PRIVILEGED_WORKLOADS = "kubernetes_psa_weak_with_privileged_workloads"

# Namespace governance / cross-control combinations (4)
_RULE_NAMESPACE_WEAK_GOVERNANCE = "kubernetes_namespace_weak_governance"
_RULE_PRIVILEGED_IDENTITY_IN_WEAK_NAMESPACE = "kubernetes_privileged_identity_in_weak_namespace"
_RULE_PRIVILEGED_WORKLOAD_WITHOUT_ISOLATION = "kubernetes_privileged_workload_without_isolation"
_RULE_NAMESPACE_RESOURCE_GOVERNANCE_MISSING = "kubernetes_namespace_resource_governance_missing"

# ── Fixed vocab used for dynamic-severity capability tiering ────────────────
_HIGH_TIER_CAPABILITIES = frozenset({"SYS_ADMIN", "SYS_MODULE", "SYS_RAWIO", "NET_ADMIN", "SYS_PTRACE"})
_SOCKET_HOSTPATH_CATEGORIES = frozenset(
    {ks.HOSTPATH_CATEGORY_DOCKER_SOCKET, ks.HOSTPATH_CATEGORY_CONTAINERD_SOCKET}
)
_MUTABLE_IMAGE_TAG_CATEGORIES = frozenset({ks.IMAGE_TAG_LATEST_EXPLICIT, ks.IMAGE_TAG_LATEST_IMPLICIT})

_WORKLOAD_SPEC_RECORD_TYPES = ks.KUBERNETES_WORKLOAD_CONTROLLER_RECORD_TYPES | frozenset({ks.KUBERNETES_POD})


def evaluate(record: dict[str, Any]) -> list[FindingCandidate]:
    """Dispatch a normalized Kubernetes record to the relevant rule(s)."""
    if not isinstance(record, dict):
        return []
    rtype = record.get("record_type")
    if rtype == ks.KUBERNETES_CONTAINER_SECURITY_CONTEXT:
        return _eval_container(record)
    if rtype in _WORKLOAD_SPEC_RECORD_TYPES:
        return _eval_workload_spec(record)
    if rtype == ks.KUBERNETES_RBAC_SUBJECT_BINDING:
        return _eval_rbac_subject_binding(record)
    if rtype == ks.KUBERNETES_SERVICE:
        return _eval_service(record)
    if rtype == ks.KUBERNETES_SERVICE_PORT:
        return _eval_service_port(record)
    if rtype == ks.KUBERNETES_INGRESS_RULE:
        return _eval_ingress_rule(record)
    if rtype == ks.KUBERNETES_GATEWAY_LISTENER:
        return _eval_gateway_listener(record)
    if rtype == ks.KUBERNETES_NETWORK_POLICY:
        return _eval_network_policy(record)
    if rtype == ks.KUBERNETES_NAMESPACE_NETWORK_POSTURE:
        return _eval_namespace_network_posture(record)
    if rtype in (ks.KUBERNETES_VALIDATING_WEBHOOK, ks.KUBERNETES_MUTATING_WEBHOOK):
        return _eval_webhook(record)
    if rtype == ks.KUBERNETES_POD_SECURITY_ADMISSION:
        return _eval_pod_security_admission(record)
    if rtype == ks.KUBERNETES_NAMESPACE_GOVERNANCE_POSTURE:
        return _eval_namespace_governance_posture(record)
    return []


def _evidence_base(record: dict[str, Any]) -> dict[str, Any]:
    ev: dict[str, Any] = {"cluster_id": get_str(record, "cluster_id")}
    if record.get("cluster_name"):
        ev["cluster_name"] = get_str(record, "cluster_name")
    if record.get("namespace"):
        ev["namespace"] = get_str(record, "namespace")
    return ev


# ── Workload / container security context ────────────────────────────────────


def _eval_container(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    record_id = get_str(record, "record_id") or None
    container = get_str(record, "container_name")
    parent_record_id = get_str(record, "parent_record_id")
    evidence = _evidence_base(record)
    evidence["container_name"] = container
    evidence["parent_record_id"] = parent_record_id

    if record.get("privileged") is True:
        out.append(FindingCandidate(
            provider="kubernetes",
            rule_key=_RULE_PRIVILEGED_CONTAINER,
            finding_key=make_finding_key(_RULE_PRIVILEGED_CONTAINER, record_id),
            severity="high",
            title="Kubernetes container is configured to run in privileged mode",
            description=(
                f"The container '{container}' is configured with "
                f"securityContext.privileged=true, granting it broad access to "
                f"host devices and kernel capabilities."
            ),
            evidence={**evidence, "privileged": True},
            remediation={
                "summary": "Remove privileged mode; grant only the specific capabilities required.",
                "steps": [
                    "Set securityContext.privileged=false.",
                    "Grant only the specific Linux capabilities the workload needs.",
                    "Use a PodSecurityPolicy/PSA restricted profile to prevent recurrence.",
                ],
            },
            record_id=record_id,
        ))

    if record.get("run_as_user_set") is True and record.get("run_as_uid") == 0:
        out.append(FindingCandidate(
            provider="kubernetes",
            rule_key=_RULE_ROOT_CONTAINER,
            finding_key=make_finding_key(_RULE_ROOT_CONTAINER, record_id),
            severity="medium",
            title="Kubernetes container explicitly runs as root (UID 0)",
            description=f"The container '{container}' explicitly sets runAsUser to 0 (root).",
            evidence={**evidence, "run_as_uid": 0},
            remediation={
                "summary": "Run the container as a non-root UID.",
                "steps": [
                    "Set securityContext.runAsUser to a non-zero UID.",
                    "Set securityContext.runAsNonRoot=true to enforce this at admission time.",
                ],
            },
            record_id=record_id,
        ))

    if record.get("run_as_non_root") is False:
        out.append(FindingCandidate(
            provider="kubernetes",
            rule_key=_RULE_RUN_AS_NON_ROOT_DISABLED,
            finding_key=make_finding_key(_RULE_RUN_AS_NON_ROOT_DISABLED, record_id),
            severity="medium",
            title="Kubernetes container does not require a non-root user",
            description=(
                f"The container '{container}' has securityContext.runAsNonRoot=false, "
                f"allowing it to run as root if the image defaults to root."
            ),
            evidence={**evidence, "run_as_non_root": False},
            remediation={
                "summary": "Set runAsNonRoot=true.",
                "steps": ["Set securityContext.runAsNonRoot=true.", "Verify the image supports a non-root UID."],
            },
            record_id=record_id,
        ))

    if record.get("allow_privilege_escalation") is True:
        out.append(FindingCandidate(
            provider="kubernetes",
            rule_key=_RULE_PRIVILEGE_ESCALATION_ALLOWED,
            finding_key=make_finding_key(_RULE_PRIVILEGE_ESCALATION_ALLOWED, record_id),
            severity="medium",
            title="Kubernetes container allows privilege escalation",
            description=f"The container '{container}' has securityContext.allowPrivilegeEscalation=true.",
            evidence={**evidence, "allow_privilege_escalation": True},
            remediation={
                "summary": "Set allowPrivilegeEscalation=false.",
                "steps": ["Set securityContext.allowPrivilegeEscalation=false unless a specific process requires it."],
            },
            record_id=record_id,
        ))

    dangerous_caps = record.get("dangerous_added_capability_categories") or []
    if isinstance(dangerous_caps, list) and dangerous_caps:
        high_tier = [c for c in dangerous_caps if c in _HIGH_TIER_CAPABILITIES]
        severity = "high" if high_tier else "medium"
        out.append(FindingCandidate(
            provider="kubernetes",
            rule_key=_RULE_DANGEROUS_CAPABILITY,
            finding_key=make_finding_key(_RULE_DANGEROUS_CAPABILITY, record_id),
            severity=severity,
            title="Kubernetes container adds a dangerous Linux capability",
            description=(
                f"The container '{container}' adds the dangerous Linux "
                f"capabilit{'ies' if len(dangerous_caps) > 1 else 'y'}: {', '.join(sorted(dangerous_caps))}."
            ),
            evidence={**evidence, "dangerous_added_capabilities": sorted(dangerous_caps)},
            remediation={
                "summary": "Remove the dangerous capability unless strictly required.",
                "steps": ["Drop the capability from securityContext.capabilities.add.", "Add back only capabilities the process demonstrably needs."],
            },
            record_id=record_id,
        ))

    caps_added = record.get("capabilities_added") or []
    if isinstance(caps_added, list) and ks.CAPABILITY_ALL in caps_added:
        out.append(FindingCandidate(
            provider="kubernetes",
            rule_key=_RULE_ALL_CAPABILITIES_ADDED,
            finding_key=make_finding_key(_RULE_ALL_CAPABILITIES_ADDED, record_id),
            severity="high",
            title="Kubernetes container adds all Linux capabilities",
            description=f"The container '{container}' adds capability 'ALL', granting the full Linux capability set.",
            evidence={**evidence, "capability": "ALL"},
            remediation={
                "summary": "Replace 'ALL' with the specific capabilities required.",
                "steps": ["Remove ALL from securityContext.capabilities.add.", "Add only the specific capabilities needed."],
            },
            record_id=record_id,
        ))

    if record.get("seccomp_profile_category") == ks.PROFILE_CATEGORY_UNCONFINED:
        out.append(FindingCandidate(
            provider="kubernetes",
            rule_key=_RULE_SECCOMP_UNCONFINED,
            finding_key=make_finding_key(_RULE_SECCOMP_UNCONFINED, record_id),
            severity="high",
            title="Kubernetes container seccomp profile is Unconfined",
            description=f"The container '{container}' explicitly sets its seccomp profile to Unconfined.",
            evidence={**evidence, "seccomp_profile_category": "unconfined"},
            remediation={
                "summary": "Use RuntimeDefault or a scoped custom seccomp profile.",
                "steps": ["Set securityContext.seccompProfile.type=RuntimeDefault (or Localhost with a scoped profile)."],
            },
            record_id=record_id,
        ))

    if record.get("apparmor_profile_category") == ks.PROFILE_CATEGORY_UNCONFINED:
        out.append(FindingCandidate(
            provider="kubernetes",
            rule_key=_RULE_APPARMOR_UNCONFINED,
            finding_key=make_finding_key(_RULE_APPARMOR_UNCONFINED, record_id),
            severity="medium",
            title="Kubernetes container AppArmor profile is unconfined",
            description=f"The container '{container}' explicitly disables AppArmor confinement.",
            evidence={**evidence, "apparmor_profile_category": "unconfined"},
            remediation={
                "summary": "Use the runtime default or a scoped custom AppArmor profile.",
                "steps": ["Set the appArmorProfile type to RuntimeDefault or Localhost with a scoped profile."],
            },
            record_id=record_id,
        ))

    if record.get("read_only_root_filesystem") is False:
        out.append(FindingCandidate(
            provider="kubernetes",
            rule_key=_RULE_WRITABLE_ROOT_FILESYSTEM,
            finding_key=make_finding_key(_RULE_WRITABLE_ROOT_FILESYSTEM, record_id),
            severity="medium",
            title="Kubernetes container filesystem is writable",
            description=f"The container '{container}' has securityContext.readOnlyRootFilesystem=false.",
            evidence={**evidence, "read_only_root_filesystem": False},
            remediation={
                "summary": "Set readOnlyRootFilesystem=true and mount writable paths as explicit volumes.",
                "steps": ["Set securityContext.readOnlyRootFilesystem=true.", "Add emptyDir volumes for any paths the process must write to."],
            },
            record_id=record_id,
        ))

    if record.get("image_tag_category") in _MUTABLE_IMAGE_TAG_CATEGORIES:
        out.append(FindingCandidate(
            provider="kubernetes",
            rule_key=_RULE_MUTABLE_IMAGE_TAG,
            finding_key=make_finding_key(_RULE_MUTABLE_IMAGE_TAG, record_id),
            severity="medium",
            title="Kubernetes container uses a mutable image tag",
            description=(
                f"The container '{container}' references an image using the 'latest' tag "
                f"(explicit or implicit), which can change without a corresponding deployment update."
            ),
            evidence={**evidence, "image_tag_category": record.get("image_tag_category")},
            remediation={
                "summary": "Pin the image to a specific tag or digest.",
                "steps": ["Reference the image by an explicit version tag.", "Prefer a content digest (sha256:...) for immutability."],
            },
            record_id=record_id,
        ))

    dangerous_ports = record.get("dangerous_host_ports") or []
    if isinstance(dangerous_ports, list) and dangerous_ports:
        out.append(FindingCandidate(
            provider="kubernetes",
            rule_key=_RULE_SENSITIVE_HOST_PORT,
            finding_key=make_finding_key(_RULE_SENSITIVE_HOST_PORT, record_id),
            severity="medium",
            title="Kubernetes container binds a sensitive host port",
            description=(
                f"The container '{container}' binds a hostPort in the sensitive/infra "
                f"port range: {', '.join(str(p) for p in sorted(dangerous_ports))}."
            ),
            evidence={**evidence, "dangerous_host_ports": sorted(dangerous_ports)},
            remediation={
                "summary": "Remove the hostPort binding or restrict it to a private network.",
                "steps": ["Remove the hostPort field and use a Service instead.", "If a hostPort is required, restrict scheduling to trusted nodes."],
            },
            record_id=record_id,
        ))

    return out


# ── Workload / Pod spec (host namespaces, hostPath, automount) ──────────────


def _eval_workload_spec(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    record_id = get_str(record, "record_id") or None
    name = get_str(record, "name")
    kind = get_str(record, "kind") or record.get("record_type")
    evidence = _evidence_base(record)
    evidence["workload_name"] = name
    evidence["kind"] = kind

    host_pid = record.get("host_pid") is True
    host_ipc = record.get("host_ipc") is True
    host_network = record.get("host_network") is True
    privileged_count = record.get("privileged_container_count") or 0
    dangerous_hostpaths = set(record.get("dangerous_hostpath_categories") or [])
    dangerous_caps = set(record.get("added_capability_categories") or [])

    if isinstance(privileged_count, int) and privileged_count > 0 and (
        host_pid or host_ipc
        or bool(dangerous_hostpaths & _SOCKET_HOSTPATH_CATEGORIES)
        or bool(dangerous_caps & _HIGH_TIER_CAPABILITIES)
    ):
        out.append(FindingCandidate(
            provider="kubernetes",
            rule_key=_RULE_PRIVILEGED_HOST_ACCESS,
            finding_key=make_finding_key(_RULE_PRIVILEGED_HOST_ACCESS, record_id),
            severity="critical",
            title="Kubernetes workload combines a privileged container with host access",
            description=(
                f"The {kind} '{name}' has at least one privileged container AND "
                f"one or more of: a host PID/IPC namespace, a mounted container "
                f"runtime socket, or a high-risk added Linux capability."
            ),
            evidence={
                **evidence,
                "privileged_container_count": privileged_count,
                "host_pid": host_pid,
                "host_ipc": host_ipc,
                "dangerous_hostpath_categories": sorted(dangerous_hostpaths),
                "high_risk_capability_categories": sorted(dangerous_caps & _HIGH_TIER_CAPABILITIES),
            },
            remediation={
                "summary": "Remove privileged mode or the accompanying host-access configuration.",
                "steps": [
                    "Disable securityContext.privileged on the container(s).",
                    "Disable hostPID/hostIPC unless strictly required.",
                    "Remove hostPath mounts of container runtime sockets.",
                ],
            },
            record_id=record_id,
        ))

    if host_pid:
        out.append(FindingCandidate(
            provider="kubernetes",
            rule_key=_RULE_HOST_PID,
            finding_key=make_finding_key(_RULE_HOST_PID, record_id),
            severity="high",
            title="Kubernetes workload shares the host PID namespace",
            description=f"The {kind} '{name}' has hostPID=true, exposing host process information to its containers.",
            evidence={**evidence, "host_pid": True},
            remediation={"summary": "Disable hostPID.", "steps": ["Set hostPID=false unless required for a system-level workload."]},
            record_id=record_id,
        ))

    if host_ipc:
        out.append(FindingCandidate(
            provider="kubernetes",
            rule_key=_RULE_HOST_IPC,
            finding_key=make_finding_key(_RULE_HOST_IPC, record_id),
            severity="high",
            title="Kubernetes workload shares the host IPC namespace",
            description=f"The {kind} '{name}' has hostIPC=true, sharing host inter-process communication resources.",
            evidence={**evidence, "host_ipc": True},
            remediation={"summary": "Disable hostIPC.", "steps": ["Set hostIPC=false unless required for a system-level workload."]},
            record_id=record_id,
        ))

    if host_network:
        out.append(FindingCandidate(
            provider="kubernetes",
            rule_key=_RULE_HOST_NETWORK,
            finding_key=make_finding_key(_RULE_HOST_NETWORK, record_id),
            severity="medium",
            title="Kubernetes workload uses the host network namespace",
            description=f"The {kind} '{name}' has hostNetwork=true, giving its containers direct access to the node's network interfaces.",
            evidence={**evidence, "host_network": True},
            remediation={"summary": "Disable hostNetwork.", "steps": ["Set hostNetwork=false unless required (e.g. a CNI/kube-proxy system component)."]},
            record_id=record_id,
        ))

    socket_categories = dangerous_hostpaths & _SOCKET_HOSTPATH_CATEGORIES
    if socket_categories:
        out.append(FindingCandidate(
            provider="kubernetes",
            rule_key=_RULE_RUNTIME_SOCKET_MOUNTED,
            finding_key=make_finding_key(_RULE_RUNTIME_SOCKET_MOUNTED, record_id),
            severity="high",
            title="Kubernetes workload mounts the container runtime socket",
            description=(
                f"The {kind} '{name}' mounts a hostPath matching the container "
                f"runtime socket ({', '.join(sorted(socket_categories))}), which "
                f"typically grants control over other containers on the node."
            ),
            evidence={**evidence, "hostpath_categories": sorted(socket_categories)},
            remediation={
                "summary": "Remove the runtime socket mount unless the workload is a trusted node agent.",
                "steps": ["Remove the hostPath volume referencing the runtime socket.", "If required, restrict the workload to a dedicated, tightly controlled ServiceAccount and namespace."],
            },
            record_id=record_id,
        ))

    other_dangerous = dangerous_hostpaths - _SOCKET_HOSTPATH_CATEGORIES
    if other_dangerous:
        out.append(FindingCandidate(
            provider="kubernetes",
            rule_key=_RULE_DANGEROUS_HOSTPATH,
            finding_key=make_finding_key(_RULE_DANGEROUS_HOSTPATH, record_id),
            severity="high",
            title="Kubernetes workload mounts a sensitive host path",
            description=(
                f"The {kind} '{name}' mounts a hostPath categorized as "
                f"{', '.join(sorted(other_dangerous))}, a sensitive area of the host filesystem."
            ),
            evidence={**evidence, "hostpath_categories": sorted(other_dangerous)},
            remediation={
                "summary": "Remove the sensitive hostPath mount unless strictly required.",
                "steps": ["Remove the hostPath volume.", "Use a narrower, purpose-built volume type instead (ConfigMap/Secret/PVC/emptyDir)."],
            },
            record_id=record_id,
        ))

    if record.get("automount_service_account_token") is True:
        out.append(FindingCandidate(
            provider="kubernetes",
            rule_key=_RULE_SA_TOKEN_AUTOMOUNT,
            finding_key=make_finding_key(_RULE_SA_TOKEN_AUTOMOUNT, record_id),
            severity="medium",
            title="Kubernetes workload automounts its ServiceAccount token",
            description=(
                f"The {kind} '{name}' has automountServiceAccountToken=true, "
                f"placing a live API token in every Pod's filesystem."
            ),
            evidence={**evidence, "service_account_name": get_str(record, "service_account_name"), "automount_service_account_token": True},
            remediation={
                "summary": "Disable automount unless the workload calls the Kubernetes API.",
                "steps": ["Set automountServiceAccountToken=false at the Pod or ServiceAccount level unless the workload genuinely needs API access."],
            },
            record_id=record_id,
        ))

    return out


# ── RBAC / identity (per subject-per-binding) ────────────────────────────────


def _eval_rbac_subject_binding(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    record_id = get_str(record, "record_id") or None
    subject_kind = get_str(record, "subject_kind")
    subject_identity = get_str(record, "subject_identity")
    binding_name = get_str(record, "binding_name")
    evidence = _evidence_base(record)
    evidence.update({
        "binding_kind": get_str(record, "binding_kind"),
        "binding_name": binding_name,
        "subject_kind": subject_kind,
        "subject_identity": subject_identity,
        "role_ref_name": get_str(record, "role_ref_name"),
    })

    cluster_admin = record.get("cluster_admin_binding") is True
    anonymous = record.get("anonymous_subject") is True
    unauthenticated_group = record.get("unauthenticated_group") is True
    authenticated_group = record.get("authenticated_group") is True
    broad_group = record.get("broad_group") is True
    subject_name = get_str(record, "subject_name")

    if cluster_admin and (anonymous or unauthenticated_group):
        out.append(FindingCandidate(
            provider="kubernetes",
            rule_key=_RULE_UNAUTHENTICATED_CLUSTER_ADMIN,
            finding_key=make_finding_key(_RULE_UNAUTHENTICATED_CLUSTER_ADMIN, record_id),
            severity="critical",
            title="Kubernetes cluster-admin is bound to an unauthenticated identity",
            description=(
                f"The binding '{binding_name}' grants cluster-admin (or equivalent) "
                f"privilege to an anonymous or unauthenticated subject."
            ),
            evidence={**evidence, "anonymous_subject": anonymous, "unauthenticated_group": unauthenticated_group},
            remediation={"summary": "Remove this binding immediately.", "steps": ["Delete the RoleBinding/ClusterRoleBinding.", "Audit for related unintended anonymous access."]},
            record_id=record_id,
        ))
    elif cluster_admin and authenticated_group:
        out.append(FindingCandidate(
            provider="kubernetes",
            rule_key=_RULE_AUTHENTICATED_GROUP_CLUSTER_ADMIN,
            finding_key=make_finding_key(_RULE_AUTHENTICATED_GROUP_CLUSTER_ADMIN, record_id),
            severity="critical",
            title="Kubernetes cluster-admin is bound to the system:authenticated group",
            description=f"The binding '{binding_name}' grants cluster-admin to every authenticated user in the cluster (system:authenticated).",
            evidence=evidence,
            remediation={"summary": "Remove this binding and scope cluster-admin to specific trusted identities.", "steps": ["Delete the ClusterRoleBinding.", "Recreate bindings scoped to individual users/groups/ServiceAccounts as needed."]},
            record_id=record_id,
        ))
    elif cluster_admin and subject_kind == "Group" and subject_name == "system:serviceaccounts":
        out.append(FindingCandidate(
            provider="kubernetes",
            rule_key=_RULE_ALL_SERVICE_ACCOUNTS_CLUSTER_ADMIN,
            finding_key=make_finding_key(_RULE_ALL_SERVICE_ACCOUNTS_CLUSTER_ADMIN, record_id),
            severity="critical",
            title="Kubernetes cluster-admin is bound to all ServiceAccounts",
            description=f"The binding '{binding_name}' grants cluster-admin to the system:serviceaccounts group (every ServiceAccount in every namespace).",
            evidence=evidence,
            remediation={"summary": "Remove this binding and scope cluster-admin to specific ServiceAccounts.", "steps": ["Delete the ClusterRoleBinding.", "Bind cluster-admin only to specific, audited ServiceAccounts if truly required."]},
            record_id=record_id,
        ))
    elif cluster_admin:
        out.append(FindingCandidate(
            provider="kubernetes",
            rule_key=_RULE_CLUSTER_ADMIN_BINDING,
            finding_key=make_finding_key(_RULE_CLUSTER_ADMIN_BINDING, record_id),
            severity="high",
            title="Kubernetes subject is bound to the cluster-admin role",
            description=f"The binding '{binding_name}' grants the {subject_kind.lower()} '{subject_identity}' the cluster-admin role (or equivalent full-wildcard permissions).",
            evidence=evidence,
            remediation={"summary": "Review whether cluster-admin is necessary; scope to least privilege.", "steps": ["Replace cluster-admin with a narrower Role/ClusterRole.", "Reserve cluster-admin for break-glass identities only."]},
            record_id=record_id,
        ))

    if record.get("wildcard_permission_binding") is True and not cluster_admin:
        out.append(FindingCandidate(
            provider="kubernetes",
            rule_key=_RULE_WILDCARD_RBAC_PERMISSIONS,
            finding_key=make_finding_key(_RULE_WILDCARD_RBAC_PERMISSIONS, record_id),
            severity="high",
            title="Kubernetes subject is bound to wildcard RBAC permissions",
            description=f"The binding '{binding_name}' grants the {subject_kind.lower()} '{subject_identity}' a role containing wildcard API groups/resources/verbs.",
            evidence={**evidence, "broad_group": broad_group},
            remediation={"summary": "Replace wildcard rules with an explicit, scoped permission list.", "steps": ["Enumerate the specific apiGroups/resources/verbs the subject needs.", "Remove wildcard ('*') entries from the Role/ClusterRole."]},
            record_id=record_id,
        ))

    categories = set(record.get("high_risk_permission_categories") or [])
    _category_rules: list[tuple[str, str, str, str]] = [
        ("bind", _RULE_RBAC_BIND_PERMISSION, "critical", "bind permissions on Roles/ClusterRoles"),
        ("escalate", _RULE_RBAC_ESCALATE_PERMISSION, "critical", "escalate permissions on Roles/ClusterRoles"),
        ("impersonate", _RULE_RBAC_IMPERSONATE_PERMISSION, "high", "impersonation permissions"),
        ("token_creation", _RULE_SA_TOKEN_CREATION, "high", "serviceaccounts/token creation permission"),
        ("secret_read", _RULE_SECRET_READ_PERMISSION, "high", "Secret read permission"),
        ("secret_read_broad_scope", _RULE_SECRET_READ_PERMISSION, "high", "broad-scope Secret read permission"),
        ("secret_write", _RULE_SECRET_WRITE_PERMISSION, "high", "Secret write permission"),
        ("pod_exec", _RULE_POD_EXEC_PERMISSION, "high", "pod exec permission"),
        ("pod_attach", _RULE_POD_ATTACH_PERMISSION, "high", "pod attach permission"),
        ("workload_write", _RULE_BROAD_WORKLOAD_CREATION, "high", "broad workload creation/modification permission"),
        ("role_or_cluster_role_write", _RULE_RBAC_MODIFICATION_PERMISSION, "high", "Role/ClusterRole modification permission"),
        ("cluster_role_binding_write", _RULE_RBAC_MODIFICATION_PERMISSION, "high", "ClusterRoleBinding modification permission"),
        ("admission_webhook_write", _RULE_ADMISSION_WEBHOOK_MODIFICATION_PERMISSION, "high", "admission webhook modification permission"),
        ("crd_write", _RULE_CRD_MODIFICATION_PERMISSION, "high", "CustomResourceDefinition modification permission"),
    ]
    emitted_rule_keys: set[str] = set()
    for category_key, rule_key, severity, human in _category_rules:
        if category_key not in categories:
            continue
        if rule_key in emitted_rule_keys:
            continue  # secret_read + secret_read_broad_scope, or role_write + crb_write, dedupe to one finding
        emitted_rule_keys.add(rule_key)
        out.append(FindingCandidate(
            provider="kubernetes",
            rule_key=rule_key,
            finding_key=make_finding_key(rule_key, record_id),
            severity=severity,
            title=f"Kubernetes subject holds {human}",
            description=f"The binding '{binding_name}' grants the {subject_kind.lower()} '{subject_identity}' {human}.",
            evidence={**evidence, "permission_category": category_key},
            remediation={"summary": "Review whether this permission is necessary; scope to least privilege.", "steps": [f"Remove the rule granting {human} unless demonstrably required.", "Prefer a narrower Role scoped to specific resource names/namespaces."]},
            record_id=record_id,
        ))

    return out


# ── Public/network exposure ───────────────────────────────────────────────────


def _eval_service(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    record_id = get_str(record, "record_id") or None
    name = get_str(record, "name")
    evidence = _evidence_base(record)
    evidence["service_name"] = name

    if record.get("exposure_category") == ks.EXPOSURE_EXTERNAL_LOAD_BALANCER:
        out.append(FindingCandidate(
            provider="kubernetes",
            rule_key=_RULE_PUBLIC_LOAD_BALANCER,
            finding_key=make_finding_key(_RULE_PUBLIC_LOAD_BALANCER, record_id),
            severity="high",
            title="Kubernetes Service is configured with confirmed external load-balancer ingress",
            description=f"The Service '{name}' has a confirmed external LoadBalancer address assigned (not merely requested/pending).",
            evidence={**evidence, "service_type": get_str(record, "service_type"), "load_balancer_ingress_count": record.get("load_balancer_ingress_count")},
            remediation={"summary": "Confirm this Service is intended to be publicly reachable.", "steps": ["Restrict via an internal-LB annotation if the Service should be private.", "Add a NetworkPolicy or security-group rule to scope reachable clients."]},
            record_id=record_id,
        ))

    return out


def _eval_service_port(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    record_id = get_str(record, "record_id") or None
    evidence = _evidence_base(record)
    evidence["parent_service_record_id"] = get_str(record, "parent_service_record_id")

    if record.get("node_port") is not None and record.get("sensitive_port") is True:
        out.append(FindingCandidate(
            provider="kubernetes",
            rule_key=_RULE_SENSITIVE_NODEPORT,
            finding_key=make_finding_key(_RULE_SENSITIVE_NODEPORT, record_id),
            severity="medium",
            title="Kubernetes NodePort Service exposes a sensitive port",
            description=(
                f"A NodePort Service port (node port {record.get('node_port')}) is "
                f"categorized as sensitive. ConfigTrace observed this NodePort binding; "
                f"it does not claim internet exposure, which depends on node network reachability."
            ),
            evidence={**evidence, "node_port": record.get("node_port"), "port": record.get("port"), "protocol": get_str(record, "protocol")},
            remediation={"summary": "Avoid exposing sensitive ports via NodePort.", "steps": ["Use ClusterIP with an internal-only path, or restrict node network reachability.", "Front the service with an authenticated proxy/ingress instead."]},
            record_id=record_id,
        ))

    return out


def _eval_ingress_rule(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    record_id = get_str(record, "record_id") or None
    evidence = _evidence_base(record)
    evidence["parent_ingress_record_id"] = get_str(record, "parent_ingress_record_id")
    evidence["host_category"] = get_str(record, "host_category")

    public = record.get("public_exposure_category") == ks.EXPOSURE_EXTERNAL_LOAD_BALANCER
    catch_all = record.get("catch_all_route") is True
    hostless = record.get("host_category") == ks.HOST_CATEGORY_HOSTLESS

    if public and record.get("tls_covered") is False:
        out.append(FindingCandidate(
            provider="kubernetes",
            rule_key=_RULE_PUBLIC_INGRESS_WITHOUT_TLS,
            finding_key=make_finding_key(_RULE_PUBLIC_INGRESS_WITHOUT_TLS, record_id),
            severity="high",
            title="Kubernetes public Ingress route is not covered by TLS",
            description="An Ingress rule with confirmed external load-balancer exposure has no matching TLS block.",
            evidence={**evidence, "tls_covered": False, "public_exposure_category": "external_load_balancer"},
            remediation={"summary": "Add a TLS block covering this host.", "steps": ["Add an entry under spec.tls covering this rule's host.", "Reference a valid TLS Secret."]},
            record_id=record_id,
        ))

    if catch_all and hostless:
        out.append(FindingCandidate(
            provider="kubernetes",
            rule_key=_RULE_HOSTLESS_CATCHALL_INGRESS,
            finding_key=make_finding_key(_RULE_HOSTLESS_CATCHALL_INGRESS, record_id),
            severity="high",
            title="Kubernetes Ingress has a hostless catch-all rule",
            description="An Ingress rule has no host restriction and matches all paths, routing any unmatched request to its backend.",
            evidence={**evidence, "catch_all_route": True},
            remediation={"summary": "Scope the rule to a specific host and path.", "steps": ["Add an explicit host to the rule.", "Narrow the path match instead of a catch-all."]},
            record_id=record_id,
        ))

    return out


def _eval_gateway_listener(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    record_id = get_str(record, "record_id") or None
    evidence = _evidence_base(record)
    evidence["parent_gateway_record_id"] = get_str(record, "parent_gateway_record_id")
    evidence["listener_name"] = get_str(record, "listener_name")

    if record.get("public_exposure_category") == ks.EXPOSURE_EXTERNAL_LOAD_BALANCER:
        out.append(FindingCandidate(
            provider="kubernetes",
            rule_key=_RULE_PUBLIC_GATEWAY_LISTENER,
            finding_key=make_finding_key(_RULE_PUBLIC_GATEWAY_LISTENER, record_id),
            severity="high",
            title="Kubernetes Gateway listener is configured with confirmed external exposure",
            description="A Gateway API listener has a confirmed external address and an HTTP/HTTPS/TLS protocol.",
            evidence={**evidence, "protocol": get_str(record, "protocol"), "port": record.get("port")},
            remediation={"summary": "Confirm this listener is intended to be publicly reachable.", "steps": ["Restrict the Gateway's address/service to an internal load balancer if it should be private.", "Add HTTPRoute-level authentication/authorization if publicly reachable."]},
            record_id=record_id,
        ))

    return out


# ── NetworkPolicy isolation ────────────────────────────────────────────────


def _eval_network_policy(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    record_id = get_str(record, "record_id") or None
    name = get_str(record, "name")
    evidence = _evidence_base(record)
    evidence["network_policy_name"] = name

    if record.get("allows_all_ingress") is True:
        out.append(FindingCandidate(
            provider="kubernetes",
            rule_key=_RULE_NETPOL_ALLOWS_ALL_INGRESS,
            finding_key=make_finding_key(_RULE_NETPOL_ALLOWS_ALL_INGRESS, record_id),
            severity="high",
            title="Kubernetes NetworkPolicy allows all ingress traffic",
            description=f"The NetworkPolicy '{name}' has an ingress rule with no 'from' restriction, allowing traffic from any source to its selected Pods.",
            evidence=evidence,
            remediation={"summary": "Scope the ingress rule to specific sources.", "steps": ["Add podSelector/namespaceSelector/ipBlock restrictions to the ingress rule."]},
            record_id=record_id,
        ))

    if record.get("allows_all_egress") is True:
        out.append(FindingCandidate(
            provider="kubernetes",
            rule_key=_RULE_NETPOL_ALLOWS_ALL_EGRESS,
            finding_key=make_finding_key(_RULE_NETPOL_ALLOWS_ALL_EGRESS, record_id),
            severity="medium",
            title="Kubernetes NetworkPolicy allows all egress traffic",
            description=f"The NetworkPolicy '{name}' has an egress rule with no 'to' restriction, allowing its selected Pods to reach any destination.",
            evidence=evidence,
            remediation={"summary": "Scope the egress rule to specific destinations.", "steps": ["Add podSelector/namespaceSelector/ipBlock restrictions to the egress rule."]},
            record_id=record_id,
        ))

    if record.get("public_ipv4_cidr_allowed") is True:
        out.append(FindingCandidate(
            provider="kubernetes",
            rule_key=_RULE_PUBLIC_IPV4_CIDR,
            finding_key=make_finding_key(_RULE_PUBLIC_IPV4_CIDR, record_id),
            severity="high",
            title="Kubernetes NetworkPolicy allows an unrestricted public IPv4 CIDR",
            description=f"The NetworkPolicy '{name}' has an ipBlock rule allowing 0.0.0.0/0 (or an equivalently broad public IPv4 range).",
            evidence=evidence,
            remediation={"summary": "Restrict the ipBlock to specific trusted CIDRs.", "steps": ["Replace 0.0.0.0/0 with the specific CIDR ranges that must be reachable.", "Add an 'except' clause to carve out untrusted sub-ranges."]},
            record_id=record_id,
        ))

    if record.get("public_ipv6_cidr_allowed") is True:
        out.append(FindingCandidate(
            provider="kubernetes",
            rule_key=_RULE_PUBLIC_IPV6_CIDR,
            finding_key=make_finding_key(_RULE_PUBLIC_IPV6_CIDR, record_id),
            severity="high",
            title="Kubernetes NetworkPolicy allows an unrestricted public IPv6 CIDR",
            description=f"The NetworkPolicy '{name}' has an ipBlock rule allowing ::/0 (or an equivalently broad public IPv6 range).",
            evidence=evidence,
            remediation={"summary": "Restrict the ipBlock to specific trusted CIDRs.", "steps": ["Replace ::/0 with the specific IPv6 CIDR ranges that must be reachable.", "Add an 'except' clause to carve out untrusted sub-ranges."]},
            record_id=record_id,
        ))

    return out


def _eval_namespace_network_posture(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    record_id = get_str(record, "record_id") or None
    evidence = _evidence_base(record)

    completeness = record.get("collection_completeness_category")
    if completeness == "partial":
        return out  # never interpret a partial NetworkPolicy collection as "no controls"

    if record.get("has_any_network_policy") is False:
        out.append(FindingCandidate(
            provider="kubernetes",
            rule_key=_RULE_NAMESPACE_NO_NETWORK_POLICY,
            finding_key=make_finding_key(_RULE_NAMESPACE_NO_NETWORK_POLICY, record_id),
            severity="medium",
            title="Kubernetes namespace has no NetworkPolicy",
            description="ConfigTrace observed no Kubernetes NetworkPolicy resources in this namespace.",
            evidence=evidence,
            remediation={"summary": "Add a NetworkPolicy establishing baseline isolation.", "steps": ["Add a default-deny NetworkPolicy for the namespace.", "Add explicit allow rules for required traffic."]},
            record_id=record_id,
        ))
        return out  # the two isolation-specific rules would be redundant with zero policies

    if record.get("ingress_isolation_present") is False:
        out.append(FindingCandidate(
            provider="kubernetes",
            rule_key=_RULE_NAMESPACE_NO_INGRESS_ISOLATION,
            finding_key=make_finding_key(_RULE_NAMESPACE_NO_INGRESS_ISOLATION, record_id),
            severity="medium",
            title="Kubernetes namespace has no ingress isolation",
            description="ConfigTrace observed no Kubernetes NetworkPolicy providing ingress isolation for Pods in this namespace.",
            evidence=evidence,
            remediation={"summary": "Add a NetworkPolicy with an Ingress policy type.", "steps": ["Add a NetworkPolicy selecting the namespace's Pods with policyTypes including Ingress."]},
            record_id=record_id,
        ))

    if record.get("egress_isolation_present") is False:
        out.append(FindingCandidate(
            provider="kubernetes",
            rule_key=_RULE_NAMESPACE_NO_EGRESS_ISOLATION,
            finding_key=make_finding_key(_RULE_NAMESPACE_NO_EGRESS_ISOLATION, record_id),
            severity="medium",
            title="Kubernetes namespace has no egress isolation",
            description="ConfigTrace observed no Kubernetes NetworkPolicy providing egress isolation for Pods in this namespace.",
            evidence=evidence,
            remediation={"summary": "Add a NetworkPolicy with an Egress policy type.", "steps": ["Add a NetworkPolicy selecting the namespace's Pods with policyTypes including Egress."]},
            record_id=record_id,
        ))

    return out


# ── Admission webhooks ────────────────────────────────────────────────────


def _eval_webhook(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    record_id = get_str(record, "record_id") or None
    webhook_type = get_str(record, "webhook_type")
    name = get_str(record, "webhook_name")
    evidence = _evidence_base(record)
    evidence.update({"webhook_name": name, "webhook_type": webhook_type, "parent_configuration_record_id": get_str(record, "parent_configuration_record_id")})

    if record.get("failure_policy") == ks.FAILURE_POLICY_IGNORE:
        if webhook_type == "validating":
            out.append(FindingCandidate(
                provider="kubernetes",
                rule_key=_RULE_VALIDATING_WEBHOOK_FAIL_OPEN,
                finding_key=make_finding_key(_RULE_VALIDATING_WEBHOOK_FAIL_OPEN, record_id),
                severity="high",
                title="Kubernetes validating admission webhook is configured to fail open",
                description=f"The validating webhook '{name}' has failurePolicy=Ignore: admission requests proceed even if the webhook is unreachable.",
                evidence={**evidence, "failure_policy": "Ignore"},
                remediation={"summary": "Set failurePolicy=Fail unless availability strictly requires Ignore.", "steps": ["Set failurePolicy=Fail.", "Ensure the webhook service has adequate availability/SLOs before doing so."]},
                record_id=record_id,
            ))
        else:
            out.append(FindingCandidate(
                provider="kubernetes",
                rule_key=_RULE_MUTATING_WEBHOOK_FAIL_OPEN,
                finding_key=make_finding_key(_RULE_MUTATING_WEBHOOK_FAIL_OPEN, record_id),
                severity="medium",
                title="Kubernetes mutating admission webhook is configured to fail open",
                description=f"The mutating webhook '{name}' has failurePolicy=Ignore: admission requests proceed without the intended mutation if the webhook is unreachable.",
                evidence={**evidence, "failure_policy": "Ignore"},
                remediation={"summary": "Set failurePolicy=Fail unless availability strictly requires Ignore.", "steps": ["Set failurePolicy=Fail.", "Ensure the webhook service has adequate availability/SLOs before doing so."]},
                record_id=record_id,
            ))

    if record.get("wildcard_operation") is True or record.get("wildcard_api_group") is True or record.get("wildcard_resource") is True:
        out.append(FindingCandidate(
            provider="kubernetes",
            rule_key=_RULE_BROAD_ADMISSION_WEBHOOK,
            finding_key=make_finding_key(_RULE_BROAD_ADMISSION_WEBHOOK, record_id),
            severity="medium",
            title="Kubernetes admission webhook has a broad wildcard rule scope",
            description=f"The webhook '{name}' has a rule using a wildcard operation, API group, or resource, applying it to a broad set of admission requests.",
            evidence={**evidence, "wildcard_operation": record.get("wildcard_operation"), "wildcard_api_group": record.get("wildcard_api_group"), "wildcard_resource": record.get("wildcard_resource")},
            remediation={"summary": "Scope the webhook's rules to specific operations/groups/resources.", "steps": ["Replace wildcard entries in spec.rules with the specific resources the webhook needs to evaluate."]},
            record_id=record_id,
        ))

    if record.get("plaintext_http_client") is True:
        out.append(FindingCandidate(
            provider="kubernetes",
            rule_key=_RULE_ADMISSION_WEBHOOK_EXTERNAL_HTTP,
            finding_key=make_finding_key(_RULE_ADMISSION_WEBHOOK_EXTERNAL_HTTP, record_id),
            severity="high",
            title="Kubernetes admission webhook client uses plaintext HTTP",
            description=f"The webhook '{name}' calls an external URL with an http:// scheme instead of https://.",
            evidence={**evidence, "plaintext_http_client": True, "external_url_host_category": record.get("external_url_host_category")},
            remediation={"summary": "Use an https:// endpoint for the webhook client.", "steps": ["Update clientConfig.url to use https://.", "Configure a valid CA bundle for the endpoint."]},
            record_id=record_id,
        ))

    return out


# ── Pod Security Admission ────────────────────────────────────────────────


def _eval_pod_security_admission(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    record_id = get_str(record, "record_id") or None
    namespace = get_str(record, "namespace")
    evidence = _evidence_base(record)

    completeness = record.get("collection_completeness_category")
    if completeness == "partial":
        return out

    enforce_level = record.get("enforce_level")

    if enforce_level == ks.PSA_ENFORCE_CATEGORY_PRIVILEGED:
        out.append(FindingCandidate(
            provider="kubernetes",
            rule_key=_RULE_PSA_PRIVILEGED_ENFORCEMENT,
            finding_key=make_finding_key(_RULE_PSA_PRIVILEGED_ENFORCEMENT, record_id),
            severity="medium",
            title="Kubernetes namespace Pod Security Admission enforcement is set to privileged",
            description=f"Pod Security Admission enforcement for namespace '{namespace}' is explicitly set to the 'privileged' level, which imposes no Pod security restrictions.",
            evidence={**evidence, "enforce_level": "privileged"},
            remediation={"summary": "Raise enforcement to baseline or restricted unless this namespace genuinely requires privileged workloads.", "steps": ["Set the pod-security.kubernetes.io/enforce label to baseline or restricted."]},
            record_id=record_id,
        ))
    elif enforce_level == ks.PSA_ENFORCE_CATEGORY_UNSET:
        out.append(FindingCandidate(
            provider="kubernetes",
            rule_key=_RULE_PSA_ENFORCEMENT_MISSING,
            finding_key=make_finding_key(_RULE_PSA_ENFORCEMENT_MISSING, record_id),
            severity="medium",
            title="Kubernetes namespace has no Pod Security Admission enforcement",
            description=f"Pod Security Admission enforcement is unset for namespace '{namespace}'.",
            evidence={**evidence, "enforce_level": "unset"},
            remediation={"summary": "Set a Pod Security Admission enforcement level.", "steps": ["Add the pod-security.kubernetes.io/enforce label with baseline or restricted."]},
            record_id=record_id,
        ))
    elif enforce_level == ks.PSA_ENFORCE_CATEGORY_INVALID:
        out.append(FindingCandidate(
            provider="kubernetes",
            rule_key=_RULE_PSA_INVALID_ENFORCEMENT,
            finding_key=make_finding_key(_RULE_PSA_INVALID_ENFORCEMENT, record_id),
            severity="medium",
            title="Kubernetes namespace Pod Security Admission enforcement label is invalid",
            description=f"The pod-security.kubernetes.io/enforce label on namespace '{namespace}' is not a recognized level (privileged/baseline/restricted).",
            evidence={**evidence, "enforce_level": "invalid"},
            remediation={"summary": "Set enforce to a valid PSA level.", "steps": ["Correct the pod-security.kubernetes.io/enforce label to privileged, baseline, or restricted."]},
            record_id=record_id,
        ))

    return out


# ── Namespace governance rollup / cross-control combinations ────────────────


def _eval_namespace_governance_posture(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    record_id = get_str(record, "record_id") or None
    namespace = get_str(record, "namespace")
    evidence = _evidence_base(record)

    completeness = record.get("governance_completeness_category")
    if completeness == "partial":
        return out  # a partial rollup never becomes a risky-state claim

    psa_category = record.get("psa_enforcement_category")
    net_coverage = record.get("network_policy_coverage_category")
    privileged_present = record.get("privileged_workload_present") is True
    high_priv_present = record.get("high_privilege_service_account_present") is True
    risk_summary = get_str(record, "governance_risk_summary")
    risk_bits = set(risk_summary.split(",")) if risk_summary else set()

    weak_psa = psa_category in (ks.PSA_ENFORCE_CATEGORY_PRIVILEGED, ks.PSA_ENFORCE_CATEGORY_UNSET, ks.PSA_ENFORCE_CATEGORY_INVALID)
    weak_net = net_coverage in ("none", "partial", ks.POLICY_COVERAGE_NONE, ks.POLICY_COVERAGE_PARTIAL)

    if "privileged_workload_weak_psa" in risk_bits:
        out.append(FindingCandidate(
            provider="kubernetes",
            rule_key=_RULE_PSA_WEAK_WITH_PRIVILEGED_WORKLOADS,
            finding_key=make_finding_key(_RULE_PSA_WEAK_WITH_PRIVILEGED_WORKLOADS, record_id),
            severity="high",
            title="Kubernetes namespace has privileged workloads with weak Pod Security Admission",
            description=(
                f"Namespace '{namespace}' contains at least one privileged/host-access "
                f"workload, and Pod Security Admission enforcement is privileged, unset, or invalid."
            ),
            evidence={**evidence, "psa_enforcement_category": psa_category, "privileged_workload_present": True},
            remediation={"summary": "Raise PSA enforcement for this namespace or remove the privileged workloads.", "steps": ["Set pod-security.kubernetes.io/enforce to baseline or restricted.", "Move privileged workloads to a dedicated, tightly governed namespace."]},
            record_id=record_id,
        ))

    if "high_privilege_identity_weak_governance" in risk_bits:
        out.append(FindingCandidate(
            provider="kubernetes",
            rule_key=_RULE_PRIVILEGED_IDENTITY_IN_WEAK_NAMESPACE,
            finding_key=make_finding_key(_RULE_PRIVILEGED_IDENTITY_IN_WEAK_NAMESPACE, record_id),
            severity="high",
            title="Kubernetes namespace has a high-privilege identity with weak governance",
            description=(
                f"Namespace '{namespace}' contains a high-privilege ServiceAccount, "
                f"and has weak/absent NetworkPolicy isolation and no ResourceQuota."
            ),
            evidence={**evidence, "high_privilege_service_account_present": True, "network_policy_coverage_category": net_coverage},
            remediation={"summary": "Reduce the ServiceAccount's privilege or strengthen namespace isolation and quotas.", "steps": ["Review and narrow the ServiceAccount's bound RBAC permissions.", "Add a NetworkPolicy and a ResourceQuota for the namespace."]},
            record_id=record_id,
        ))

    if privileged_present and weak_net and net_coverage != "unknown" and "privileged_workload_weak_psa" not in risk_bits:
        out.append(FindingCandidate(
            provider="kubernetes",
            rule_key=_RULE_PRIVILEGED_WORKLOAD_WITHOUT_ISOLATION,
            finding_key=make_finding_key(_RULE_PRIVILEGED_WORKLOAD_WITHOUT_ISOLATION, record_id),
            severity="high",
            title="Kubernetes namespace has a privileged workload without network isolation",
            description=(
                f"Namespace '{namespace}' contains a privileged/host-access workload, "
                f"and ConfigTrace observed no (or only partial) NetworkPolicy isolation for the namespace."
            ),
            evidence={**evidence, "network_policy_coverage_category": net_coverage, "privileged_workload_present": True},
            remediation={"summary": "Add NetworkPolicy isolation for this namespace.", "steps": ["Add a default-deny NetworkPolicy selecting the namespace's Pods.", "Add explicit allow rules for required traffic only."]},
            record_id=record_id,
        ))

    ingress_absent = record.get("network_policy_coverage_category") in ("none", ks.POLICY_COVERAGE_NONE)
    quota_coverage_early = record.get("quota_coverage_category")
    weak_signal_count = sum([
        weak_psa,
        ingress_absent,
        quota_coverage_early == "none",
        privileged_present or high_priv_present,
    ])
    if weak_signal_count >= 3 and quota_coverage_early != "unknown" and psa_category != "unknown" and net_coverage != "unknown":
        out.append(FindingCandidate(
            provider="kubernetes",
            rule_key=_RULE_NAMESPACE_WEAK_GOVERNANCE,
            finding_key=make_finding_key(_RULE_NAMESPACE_WEAK_GOVERNANCE, record_id),
            severity="high",
            title="Kubernetes namespace has weak governance across multiple controls",
            description=(
                f"Namespace '{namespace}' shows weak posture across multiple governance "
                f"controls simultaneously (Pod Security Admission, NetworkPolicy isolation, "
                f"resource quotas, and/or privileged workloads or high-privilege identities)."
            ),
            evidence={
                **evidence,
                "psa_enforcement_category": psa_category,
                "network_policy_coverage_category": net_coverage,
                "quota_coverage_category": quota_coverage_early,
                "privileged_workload_present": privileged_present,
                "high_privilege_service_account_present": high_priv_present,
            },
            remediation={
                "summary": "Strengthen PSA enforcement, add NetworkPolicy isolation, and add resource quotas for this namespace.",
                "steps": [
                    "Set pod-security.kubernetes.io/enforce to baseline or restricted.",
                    "Add a NetworkPolicy providing ingress/egress isolation.",
                    "Add a ResourceQuota for the namespace.",
                ],
            },
            record_id=record_id,
        ))

    quota_count = record.get("resource_quota_count") or 0
    limit_count = record.get("limit_range_count") or 0
    quota_coverage = record.get("quota_coverage_category")
    if quota_coverage != "unknown" and quota_count == 0 and limit_count == 0:
        out.append(FindingCandidate(
            provider="kubernetes",
            rule_key=_RULE_NAMESPACE_RESOURCE_GOVERNANCE_MISSING,
            finding_key=make_finding_key(_RULE_NAMESPACE_RESOURCE_GOVERNANCE_MISSING, record_id),
            severity="low",
            title="Kubernetes namespace has no ResourceQuota or LimitRange",
            description=f"ConfigTrace observed no ResourceQuota or LimitRange objects in namespace '{namespace}'.",
            evidence={**evidence, "resource_quota_count": 0, "limit_range_count": 0},
            remediation={"summary": "Add a ResourceQuota and/or LimitRange for the namespace.", "steps": ["Add a ResourceQuota to bound aggregate namespace resource consumption.", "Add a LimitRange to set default container resource requests/limits."]},
            record_id=record_id,
        ))

    return out
