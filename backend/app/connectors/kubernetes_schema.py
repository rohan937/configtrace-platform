"""Kubernetes connector schema — workload security (message 2 of a 9-message arc).

This module defines the full planned record-type taxonomy for the
Kubernetes provider. Message 1 emitted the first three types (cluster,
namespace, API capability). Message 2 adds the workload-controller family,
the standalone-Pod family, per-container security-context records, and a
minimal workload-service-account rollup. The remaining types are reserved
names for later messages so downstream code (diff tracking, risk
classification, Security Findings) can be built incrementally against a
stable taxonomy without renaming record types mid-arc.

Emitted in message 1
---------------------
``kubernetes_cluster``        — one record per connected cluster.
``kubernetes_namespace``      — one record per visible namespace.
``kubernetes_api_capability``  — one record per discovered API resource type.

Emitted in message 2 (workloads and Pod-security posture)
-------------------------------------------------------------
``kubernetes_deployment``, ``kubernetes_statefulset``, ``kubernetes_daemonset``,
``kubernetes_job``, ``kubernetes_cronjob`` — one record per controller object,
carrying safe declarative configuration plus aggregated security-posture
summary fields.
``kubernetes_pod`` — one record per **standalone** Pod only (no owner
reference). Controller-owned Pods are intentionally NOT emitted as separate
records in message 2: their declarative posture is already fully captured by
the owning controller's Pod template, and enumerating every live Pod of a
large ReplicaSet/DaemonSet would duplicate identical template posture N
times without adding security signal. See ``kubernetes.py`` module docstring
for the full Pod-emission policy.
``kubernetes_container_security_context`` — one record per container
(application, init, or ephemeral), for both standalone Pods and workload
controllers' Pod templates, so drift is detectable at container precision.
``kubernetes_workload_service_account`` — one rollup record per
(namespace, service_account_name) pair actually referenced by a collected
workload this sync, with automount-posture counts. A full ServiceAccount
resource (and its own default automount value) is collected starting
message 3.

Planned for later messages (message 3 — RBAC)
-----------------------------------------------
``kubernetes_role``, ``kubernetes_cluster_role``, ``kubernetes_role_binding``,
``kubernetes_cluster_role_binding``, ``kubernetes_service_account``.

Planned for later messages (message 4 — networking)
------------------------------------------------------
``kubernetes_service``, ``kubernetes_ingress``, ``kubernetes_gateway``,
``kubernetes_http_route``, ``kubernetes_network_policy``.

Planned for later messages (message 5 — configuration/admission)
--------------------------------------------------------------------
``kubernetes_secret_metadata``, ``kubernetes_config_map_metadata``,
``kubernetes_validating_webhook``, ``kubernetes_mutating_webhook``,
``kubernetes_resource_quota``, ``kubernetes_limit_range``,
``kubernetes_pod_security_admission``,
``kubernetes_api_server_security_posture`` (only if safely observable).

SENSITIVE-DATA POLICY (mandatory, see kubernetes.py module docstring for the
full contract): this connector NEVER fetches Secret values, ConfigMap
values, service-account token contents, kubeconfig contents, Pod logs, exec
output, or raw annotation/label maps. Message 1 does not fetch Secrets or
ConfigMaps at all — not even metadata. That begins (metadata only, still
never values) in message 5.
"""

from __future__ import annotations

from typing import Optional

from typing_extensions import TypedDict

# ── Record type constants — emitted in message 1 ─────────────────────────────

KUBERNETES_CLUSTER = "kubernetes_cluster"
KUBERNETES_NAMESPACE = "kubernetes_namespace"
KUBERNETES_API_CAPABILITY = "kubernetes_api_capability"

KUBERNETES_FOUNDATION_RECORD_TYPES: frozenset[str] = frozenset(
    {
        KUBERNETES_CLUSTER,
        KUBERNETES_NAMESPACE,
        KUBERNETES_API_CAPABILITY,
    }
)

# ── Record type constants — emitted in message 2 (workloads) ────────────────

KUBERNETES_DEPLOYMENT = "kubernetes_deployment"
KUBERNETES_STATEFULSET = "kubernetes_statefulset"
KUBERNETES_DAEMONSET = "kubernetes_daemonset"
KUBERNETES_JOB = "kubernetes_job"
KUBERNETES_CRONJOB = "kubernetes_cronjob"
KUBERNETES_POD = "kubernetes_pod"
KUBERNETES_CONTAINER_SECURITY_CONTEXT = "kubernetes_container_security_context"
KUBERNETES_WORKLOAD_SERVICE_ACCOUNT = "kubernetes_workload_service_account"

# The controller-family record types, keyed by their canonical "kind" string
# — shared by the connector (dispatch) and tests (parametrization).
KUBERNETES_WORKLOAD_CONTROLLER_RECORD_TYPES: frozenset[str] = frozenset(
    {
        KUBERNETES_DEPLOYMENT,
        KUBERNETES_STATEFULSET,
        KUBERNETES_DAEMONSET,
        KUBERNETES_JOB,
        KUBERNETES_CRONJOB,
    }
)

KUBERNETES_WORKLOAD_RECORD_TYPES: frozenset[str] = (
    KUBERNETES_WORKLOAD_CONTROLLER_RECORD_TYPES
    | frozenset(
        {
            KUBERNETES_POD,
            KUBERNETES_CONTAINER_SECURITY_CONTEXT,
            KUBERNETES_WORKLOAD_SERVICE_ACCOUNT,
        }
    )
)

# ── Record type constants — reserved for later messages (not yet emitted) ───
# These names are fixed now so that later messages never need to rename a
# record type after Changes/Findings have already been built against it.

KUBERNETES_ROLE = "kubernetes_role"
KUBERNETES_CLUSTER_ROLE = "kubernetes_cluster_role"
KUBERNETES_ROLE_BINDING = "kubernetes_role_binding"
KUBERNETES_CLUSTER_ROLE_BINDING = "kubernetes_cluster_role_binding"
KUBERNETES_SERVICE_ACCOUNT = "kubernetes_service_account"

KUBERNETES_SERVICE = "kubernetes_service"
KUBERNETES_INGRESS = "kubernetes_ingress"
KUBERNETES_GATEWAY = "kubernetes_gateway"
KUBERNETES_HTTP_ROUTE = "kubernetes_http_route"
KUBERNETES_NETWORK_POLICY = "kubernetes_network_policy"

KUBERNETES_SECRET_METADATA = "kubernetes_secret_metadata"
KUBERNETES_CONFIG_MAP_METADATA = "kubernetes_config_map_metadata"
KUBERNETES_VALIDATING_WEBHOOK = "kubernetes_validating_webhook"
KUBERNETES_MUTATING_WEBHOOK = "kubernetes_mutating_webhook"
KUBERNETES_RESOURCE_QUOTA = "kubernetes_resource_quota"
KUBERNETES_LIMIT_RANGE = "kubernetes_limit_range"
KUBERNETES_POD_SECURITY_ADMISSION = "kubernetes_pod_security_admission"
KUBERNETES_API_SERVER_SECURITY_POSTURE = "kubernetes_api_server_security_posture"

KUBERNETES_PLANNED_RECORD_TYPES: frozenset[str] = frozenset(
    {
        KUBERNETES_ROLE, KUBERNETES_CLUSTER_ROLE, KUBERNETES_ROLE_BINDING,
        KUBERNETES_CLUSTER_ROLE_BINDING, KUBERNETES_SERVICE_ACCOUNT,
        KUBERNETES_SERVICE, KUBERNETES_INGRESS, KUBERNETES_GATEWAY,
        KUBERNETES_HTTP_ROUTE, KUBERNETES_NETWORK_POLICY,
        KUBERNETES_SECRET_METADATA, KUBERNETES_CONFIG_MAP_METADATA,
        KUBERNETES_VALIDATING_WEBHOOK, KUBERNETES_MUTATING_WEBHOOK,
        KUBERNETES_RESOURCE_QUOTA, KUBERNETES_LIMIT_RANGE,
        KUBERNETES_POD_SECURITY_ADMISSION, KUBERNETES_API_SERVER_SECURITY_POSTURE,
    }
)

# All record types across the full planned taxonomy, whether or not they are
# emitted yet. Used only for documentation/introspection — never assume every
# member of this set is reachable from fetch() today.
KUBERNETES_RECORD_TYPES: frozenset[str] = (
    KUBERNETES_FOUNDATION_RECORD_TYPES
    | KUBERNETES_WORKLOAD_RECORD_TYPES
    | KUBERNETES_PLANNED_RECORD_TYPES
)


# ── Safe-label policy ─────────────────────────────────────────────────────────
# Kubernetes labels/annotations may contain arbitrary business or deployment
# information and must never be persisted wholesale. The only labels this
# connector ever reads are the well-known Pod Security Admission labels,
# which are a fixed, documented Kubernetes API convention (never
# user-defined free text) and are directly relevant to namespace security
# posture. No other label or annotation key is read anywhere in this
# connector.
PSA_LABEL_ENFORCE = "pod-security.kubernetes.io/enforce"
PSA_LABEL_ENFORCE_VERSION = "pod-security.kubernetes.io/enforce-version"
PSA_LABEL_AUDIT = "pod-security.kubernetes.io/audit"
PSA_LABEL_AUDIT_VERSION = "pod-security.kubernetes.io/audit-version"
PSA_LABEL_WARN = "pod-security.kubernetes.io/warn"
PSA_LABEL_WARN_VERSION = "pod-security.kubernetes.io/warn-version"

SAFE_NAMESPACE_LABEL_KEYS: frozenset[str] = frozenset(
    {
        PSA_LABEL_ENFORCE, PSA_LABEL_ENFORCE_VERSION,
        PSA_LABEL_AUDIT, PSA_LABEL_AUDIT_VERSION,
        PSA_LABEL_WARN, PSA_LABEL_WARN_VERSION,
    }
)


# ── TypedDict schemas — message 1 ────────────────────────────────────────────


class KubernetesClusterRecord(TypedDict):
    record_type: str
    record_id: str
    cluster_id: str
    cluster_name: str
    context_name: Optional[str]
    api_server_host_category: str
    kubernetes_version: Optional[str]
    kubernetes_major_minor: Optional[str]
    platform: str
    authentication_mode_category: str
    cluster_scoped_access_available: Optional[bool]
    namespace_count: Optional[int]
    visible_namespace_count: Optional[int]
    selected_namespace_count: Optional[int]
    api_discovery_status: str
    collection_completeness_category: str
    partial_permission_indicator: bool
    server_certificate_verification_enabled: bool


class KubernetesNamespaceRecord(TypedDict):
    record_type: str
    record_id: str
    cluster_id: str
    cluster_name: str
    api_version: str
    kind: str
    name: str
    uid: Optional[str]
    phase: Optional[str]
    terminating: bool
    psa_enforce: Optional[str]
    psa_enforce_version: Optional[str]
    psa_audit: Optional[str]
    psa_audit_version: Optional[str]
    psa_warn: Optional[str]
    psa_warn_version: Optional[str]


class KubernetesApiCapabilityRecord(TypedDict):
    record_type: str
    record_id: str
    cluster_id: str
    cluster_name: str
    api_group: str
    api_version: str
    resource: str
    namespaced: bool
    verbs: list[str]
    available: bool
    preferred_version: bool
    collection_support_status: str


# ── Workload / Pod-security category vocabulary — message 2 ─────────────────
#
# Explicit / effective / unknown semantics
# ------------------------------------------
# Every tri-state security field below is stored as ``True``, ``False``, or
# ``None``. ``None`` ALWAYS means "not explicitly set in the object we read
# (workload template or Pod spec)" — it never means "confirmed disabled" or
# "confirmed enabled". Kubernetes' own default semantics vary by field and
# are documented per-field where the connector normalizes it (see
# ``kubernetes.py``): some omissions have a well-known, safe default
# enforced by the API server itself (``hostNetwork``/``hostPID``/``hostIPC``
# default to ``false`` — this is a real, documented Kubernetes default, so
# these three are stored as concrete booleans, not tri-state), while others
# (``runAsNonRoot``, ``runAsUser``, seccomp/AppArmor profile, automount
# token) have no safe universal default — omission is recorded as ``None``
# and must never be read as either "secure" or "risky" by any downstream
# code.

# Dangerous Linux capabilities (case-normalized to upper snake case, without
# the "CAP_" prefix, matching the Kubernetes API's own capability strings).
DANGEROUS_CAPABILITIES: frozenset[str] = frozenset(
    {
        "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "DAC_READ_SEARCH",
        "DAC_OVERRIDE", "SETUID", "SETGID", "SYS_MODULE", "SYS_RAWIO",
        "MKNOD", "NET_RAW", "AUDIT_CONTROL", "BPF", "PERFMON",
        "CHECKPOINT_RESTORE",
    }
)
CAPABILITY_ALL = "ALL"

# hostPath categories. Only these fixed, security-relevant categories are
# ever persisted — the raw hostPath string is never stored (it could reveal
# internal filesystem layout or embed sensitive naming). Any path not
# matching a known-dangerous category is bucketed as "other" (count only,
# no path).
HOSTPATH_CATEGORY_ROOT = "root_filesystem"  # "/"
HOSTPATH_CATEGORY_ETC = "etc"
HOSTPATH_CATEGORY_PROC = "proc"
HOSTPATH_CATEGORY_SYS = "sys"
HOSTPATH_CATEGORY_VAR_RUN = "var_run"
HOSTPATH_CATEGORY_DOCKER_SOCKET = "docker_socket"
HOSTPATH_CATEGORY_CONTAINERD_SOCKET = "containerd_socket"
HOSTPATH_CATEGORY_KUBELET_DIR = "kubelet_dir"
HOSTPATH_CATEGORY_OTHER = "other"

# (path prefix, category) — evaluated in order, first match wins. Exact
# high-risk paths are checked before generic prefixes so e.g.
# "/var/run/docker.sock" categorizes as docker_socket, not var_run.
_HOSTPATH_CATEGORY_RULES: tuple[tuple[str, str], ...] = (
    ("/var/run/docker.sock", HOSTPATH_CATEGORY_DOCKER_SOCKET),
    ("/run/docker.sock", HOSTPATH_CATEGORY_DOCKER_SOCKET),
    ("/run/containerd", HOSTPATH_CATEGORY_CONTAINERD_SOCKET),
    ("/var/run/containerd", HOSTPATH_CATEGORY_CONTAINERD_SOCKET),
    ("/var/lib/kubelet", HOSTPATH_CATEGORY_KUBELET_DIR),
    ("/var/run", HOSTPATH_CATEGORY_VAR_RUN),
    ("/run", HOSTPATH_CATEGORY_VAR_RUN),
    ("/proc", HOSTPATH_CATEGORY_PROC),
    ("/sys", HOSTPATH_CATEGORY_SYS),
    ("/etc", HOSTPATH_CATEGORY_ETC),
)
HOSTPATH_ROOT_EXACT: frozenset[str] = frozenset({"/", ""})

DANGEROUS_HOSTPATH_CATEGORIES: frozenset[str] = frozenset(
    {
        HOSTPATH_CATEGORY_ROOT, HOSTPATH_CATEGORY_ETC, HOSTPATH_CATEGORY_PROC,
        HOSTPATH_CATEGORY_SYS, HOSTPATH_CATEGORY_VAR_RUN,
        HOSTPATH_CATEGORY_DOCKER_SOCKET, HOSTPATH_CATEGORY_CONTAINERD_SOCKET,
        HOSTPATH_CATEGORY_KUBELET_DIR,
    }
)

# Seccomp / AppArmor profile categories.
PROFILE_CATEGORY_RUNTIME_DEFAULT = "runtime_default"
PROFILE_CATEGORY_LOCALHOST = "localhost"
PROFILE_CATEGORY_UNCONFINED = "unconfined"
PROFILE_CATEGORY_OMITTED = "omitted"

# Legacy AppArmor annotation prefix (Kubernetes < 1.30 style). Only this
# exact, well-known key prefix is ever inspected — never arbitrary
# annotations. Modern clusters use ``securityContext.appArmorProfile``
# instead, which is a structured field, not an annotation.
APPARMOR_ANNOTATION_PREFIX = "container.apparmor.security.beta.kubernetes.io/"

# Image tag categories.
IMAGE_TAG_PINNED_DIGEST = "pinned_digest"
IMAGE_TAG_EXPLICIT = "explicit_tag"
IMAGE_TAG_LATEST_EXPLICIT = "latest_explicit"
IMAGE_TAG_LATEST_IMPLICIT = "latest_implicit"

# Well-known public registry hostname categories (safe to record — these are
# public, well-known service names, not private infrastructure details).
_PUBLIC_REGISTRY_HOSTS: dict[str, str] = {
    "docker.io": "docker_hub",
    "index.docker.io": "docker_hub",
    "registry-1.docker.io": "docker_hub",
    "gcr.io": "gcr",
    "ghcr.io": "ghcr",
    "quay.io": "quay",
    "public.ecr.aws": "ecr_public",
}
REGISTRY_CATEGORY_ECR = "ecr"
REGISTRY_CATEGORY_ACR = "acr"
REGISTRY_CATEGORY_PRIVATE_OR_UNKNOWN = "private_or_unknown"
REGISTRY_CATEGORY_DOCKER_HUB_IMPLICIT = "docker_hub"  # no registry host at all

# Sensitive host ports (well-known control-plane / infra ports). Only ports
# within this curated set are ever categorized as "dangerous" — every
# hostPort value is still counted, but the specific list of dangerous ports
# recorded is bounded to this allowlist rather than persisting arbitrary
# port numbers as "sensitive" without basis.
SENSITIVE_HOST_PORTS: frozenset[int] = frozenset(
    {22, 2379, 2380, 3389, 6443, 10250, 10255, 10256, 8443}
)

# Container categories.
CONTAINER_CATEGORY_APPLICATION = "application"
CONTAINER_CATEGORY_INIT = "init"
CONTAINER_CATEGORY_EPHEMERAL = "ephemeral"

# Volume-mount categories (derived from the Pod's volume source type, never
# from the mount path).
VOLUME_CATEGORY_HOSTPATH = "hostpath"
VOLUME_CATEGORY_CONFIGMAP = "configmap"
VOLUME_CATEGORY_SECRET = "secret"
VOLUME_CATEGORY_EMPTYDIR = "emptydir"
VOLUME_CATEGORY_PVC = "pvc"
VOLUME_CATEGORY_PROJECTED = "projected"
VOLUME_CATEGORY_OTHER = "other"

# Coverage categories used for aggregate workload-level fields (e.g.
# "read_only_root_filesystem_coverage", "resource_limit_coverage").
COVERAGE_FULL = "full"
COVERAGE_PARTIAL = "partial"
COVERAGE_NONE = "none"

# Workload-level security-posture summary categories. Purely descriptive/
# structural — NOT a severity judgement (severity is the risk classifier's
# job; see risk_rules/kubernetes.py and message 7's full calibration pass).
SECURITY_POSTURE_STANDARD = "standard"
SECURITY_POSTURE_ELEVATED = "elevated"
SECURITY_POSTURE_PRIVILEGED_OR_HOST_ACCESS = "privileged_or_host_access"


# ── Categorization helpers ────────────────────────────────────────────────────
# Centralized here (rather than in kubernetes.py) so the categorization logic
# and its vocabulary constants have one source of truth.


def _path_matches(path: str, prefix: str) -> bool:
    prefix = prefix.rstrip("/")
    return path == prefix or path.startswith(prefix + "/")


def categorize_hostpath(path: Optional[str]) -> str:
    """Categorize a hostPath volume's path into a fixed, safe bucket.

    The raw path string is NEVER returned or persisted by the caller — only
    this category. Any path not matching a known-dangerous prefix is
    bucketed as "other" (still counted, never stored as free text).
    """
    if not path:
        return HOSTPATH_CATEGORY_OTHER
    normalized = path.strip()
    if normalized in HOSTPATH_ROOT_EXACT:
        return HOSTPATH_CATEGORY_ROOT
    for prefix, category in _HOSTPATH_CATEGORY_RULES:
        if _path_matches(normalized, prefix):
            return category
    return HOSTPATH_CATEGORY_OTHER


def _parse_image_reference(image: Optional[str]) -> dict:
    """Split an image reference into safe, structural components.

    Returns ``{"registry": str, "tag": str, "digest_pinned": bool,
    "tag_explicit": bool}``. Never returns the repository path or digest
    value itself — only what's needed to categorize registry and tag.
    """
    if not image:
        return {"registry": "", "tag": "", "digest_pinned": False, "tag_explicit": False}
    if "@" in image:
        name_part, _digest = image.split("@", 1)
        registry = _split_registry_host(name_part)
        return {"registry": registry, "tag": "", "digest_pinned": True, "tag_explicit": False}

    name_part = image
    last_slash = name_part.rfind("/")
    last_colon = name_part.rfind(":")
    tag = ""
    tag_explicit = False
    if last_colon > last_slash:
        tag = name_part[last_colon + 1 :]
        name_part = name_part[:last_colon]
        tag_explicit = True
    registry = _split_registry_host(name_part)
    return {
        "registry": registry,
        "tag": tag or "latest",
        "digest_pinned": False,
        "tag_explicit": tag_explicit,
    }


def _split_registry_host(name_part: str) -> str:
    if "/" not in name_part:
        return ""
    first_segment, _rest = name_part.split("/", 1)
    if "." in first_segment or ":" in first_segment or first_segment == "localhost":
        return first_segment.lower()
    return ""


def categorize_image_tag(image: Optional[str]) -> str:
    """Categorize an image reference's tag/digest posture."""
    parsed = _parse_image_reference(image)
    if parsed["digest_pinned"]:
        return IMAGE_TAG_PINNED_DIGEST
    if not parsed["tag_explicit"]:
        return IMAGE_TAG_LATEST_IMPLICIT
    if parsed["tag"] == "latest":
        return IMAGE_TAG_LATEST_EXPLICIT
    return IMAGE_TAG_EXPLICIT


def categorize_image_registry(image: Optional[str]) -> str:
    """Categorize an image reference's registry into a safe bucket.

    Only well-known public registry hostnames (or recognizable
    cloud-provider registry domain suffixes) are named; anything else is
    "private_or_unknown" — the literal registry hostname is never stored,
    since a private registry host can reveal internal infrastructure.
    """
    parsed = _parse_image_reference(image)
    registry = parsed["registry"]
    if not registry:
        return REGISTRY_CATEGORY_DOCKER_HUB_IMPLICIT
    if registry in _PUBLIC_REGISTRY_HOSTS:
        return _PUBLIC_REGISTRY_HOSTS[registry]
    if registry.endswith(".amazonaws.com") and "ecr" in registry:
        return REGISTRY_CATEGORY_ECR
    if registry.endswith(".azurecr.io"):
        return REGISTRY_CATEGORY_ACR
    return REGISTRY_CATEGORY_PRIVATE_OR_UNKNOWN


def seccomp_or_apparmor_profile_category(profile: object) -> str:
    """Categorize a structured ``SeccompProfile``/``AppArmorProfile``-like
    object (has a ``.type`` of ``RuntimeDefault``/``Localhost``/``Unconfined``).

    Shared between seccomp (all Kubernetes versions) and the modern
    structured AppArmor field (Kubernetes 1.30+), since both use the same
    three-value vocabulary.
    """
    if profile is None:
        return PROFILE_CATEGORY_OMITTED
    ptype = getattr(profile, "type", None)
    if ptype == "RuntimeDefault":
        return PROFILE_CATEGORY_RUNTIME_DEFAULT
    if ptype == "Localhost":
        return PROFILE_CATEGORY_LOCALHOST
    if ptype == "Unconfined":
        return PROFILE_CATEGORY_UNCONFINED
    return PROFILE_CATEGORY_OMITTED


def categorize_legacy_apparmor_annotation(value: Optional[str]) -> str:
    """Categorize a legacy AppArmor annotation value
    (``container.apparmor.security.beta.kubernetes.io/<container>``).

    Only ever called with the value of that one exact, well-known
    annotation key — never with arbitrary annotation content.
    """
    if not value:
        return PROFILE_CATEGORY_OMITTED
    normalized = value.strip().lower()
    if normalized.startswith("runtime/default"):
        return PROFILE_CATEGORY_RUNTIME_DEFAULT
    if normalized.startswith("localhost/"):
        return PROFILE_CATEGORY_LOCALHOST
    if normalized == "unconfined":
        return PROFILE_CATEGORY_UNCONFINED
    return PROFILE_CATEGORY_OMITTED


# ── TypedDict schemas — message 2 (workloads) ────────────────────────────────


class KubernetesWorkloadControllerRecord(TypedDict):
    """Shared shape for kubernetes_deployment/statefulset/daemonset/job/cronjob."""

    record_type: str
    record_id: str
    cluster_id: str
    cluster_name: str
    namespace: str
    name: str
    uid: Optional[str]
    api_version: str
    kind: str
    desired_replica_count: Optional[int]
    update_strategy_category: Optional[str]
    service_account_name: str
    automount_service_account_token: Optional[bool]
    host_network: bool
    host_pid: bool
    host_ipc: bool
    dns_policy_category: Optional[str]
    restart_policy: Optional[str]
    runtime_class_name: Optional[str]
    node_selector_key_count: int
    toleration_count: int
    dangerous_toleration_categories: list[str]
    affinity_present: bool
    anti_affinity_present: bool
    topology_spread_constraint_count: int
    image_pull_secret_count: int
    container_count: int
    init_container_count: int
    ephemeral_container_count: int
    hostpath_volume_count: int
    dangerous_hostpath_categories: list[str]
    privileged_container_count: int
    root_container_count: int
    allow_privilege_escalation_count: int
    added_capability_categories: list[str]
    seccomp_posture_summary: str
    apparmor_posture_summary: str
    read_only_root_filesystem_coverage: str
    resource_limit_coverage: str
    liveness_probe_coverage: str
    readiness_probe_coverage: str
    startup_probe_coverage: str
    image_posture_summary: str
    security_posture_summary: str
    collection_completeness_category: str


class KubernetesPodRecord(TypedDict):
    """Standalone Pods only — see module docstring for the Pod-emission policy."""

    record_type: str
    record_id: str
    cluster_id: str
    cluster_name: str
    namespace: str
    name: str
    uid: Optional[str]
    api_version: str
    kind: str
    mirror_pod: bool
    service_account_name: str
    automount_service_account_token: Optional[bool]
    host_network: bool
    host_pid: bool
    host_ipc: bool
    share_process_namespace: Optional[bool]
    dns_policy_category: Optional[str]
    restart_policy: Optional[str]
    runtime_class_name: Optional[str]
    node_selector_key_count: int
    toleration_count: int
    dangerous_toleration_categories: list[str]
    affinity_present: bool
    anti_affinity_present: bool
    image_pull_secret_count: int
    container_count: int
    init_container_count: int
    ephemeral_container_count: int
    hostpath_volume_count: int
    dangerous_hostpath_categories: list[str]
    privileged_container_count: int
    root_container_count: int
    allow_privilege_escalation_count: int
    added_capability_categories: list[str]
    seccomp_posture_summary: str
    apparmor_posture_summary: str
    read_only_root_filesystem_coverage: str
    resource_limit_coverage: str
    liveness_probe_coverage: str
    readiness_probe_coverage: str
    startup_probe_coverage: str
    image_posture_summary: str
    security_posture_summary: str
    collection_completeness_category: str
    # Runtime-only fields (mutable status; excluded from diff tracking).
    phase_category: str
    scheduled: Optional[bool]
    ready: Optional[bool]
    host_ip_present: bool
    pod_ip_count: int
    restart_count_aggregate: int
    container_waiting_reason_category: Optional[str]
    container_terminated_reason_category: Optional[str]


class KubernetesContainerSecurityContextRecord(TypedDict):
    record_type: str
    record_id: str
    cluster_id: str
    cluster_name: str
    namespace: str
    parent_workload_type: str
    parent_workload_uid: Optional[str]
    parent_record_id: str
    container_name: str
    container_category: str
    image: str
    image_registry_category: str
    image_tag_category: str
    image_pull_policy: Optional[str]
    privileged: Optional[bool]
    allow_privilege_escalation: Optional[bool]
    run_as_user_set: bool
    run_as_uid: Optional[int]
    run_as_group_set: bool
    run_as_non_root: Optional[bool]
    read_only_root_filesystem: Optional[bool]
    seccomp_profile_category: str
    apparmor_profile_category: str
    selinux_options_present: bool
    windows_security_context_present: bool
    capabilities_added: list[str]
    capabilities_dropped: list[str]
    dangerous_added_capability_categories: list[str]
    proc_mount_category: Optional[str]
    host_port_count: int
    dangerous_host_ports: list[int]
    cpu_request_present: bool
    memory_request_present: bool
    cpu_limit_present: bool
    memory_limit_present: bool
    any_resource_request_present: bool
    any_resource_limit_present: bool
    liveness_probe_present: bool
    readiness_probe_present: bool
    startup_probe_present: bool
    volume_mount_categories: list[str]
    hostpath_mount_count: int
    writable_hostpath_mount_count: int
    service_account_token_explicitly_mounted: bool
    bidirectional_mount_propagation_present: bool


class KubernetesWorkloadServiceAccountRecord(TypedDict):
    record_type: str
    record_id: str
    cluster_id: str
    cluster_name: str
    namespace: str
    service_account_name: str
    referencing_workload_count: int
    automount_explicit_true_count: int
    automount_explicit_false_count: int
    automount_inherited_count: int
