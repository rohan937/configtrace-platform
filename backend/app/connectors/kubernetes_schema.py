"""Kubernetes connector schema — RBAC and identity (message 3 of a 9-message arc).

This module defines the full planned record-type taxonomy for the
Kubernetes provider. Message 1 emitted the first three types (cluster,
namespace, API capability). Message 2 added the workload-controller family,
the standalone-Pod family, per-container security-context records, and a
minimal workload-service-account rollup. Message 3 (this message) adds
ServiceAccounts, Roles, ClusterRoles, RoleBindings, ClusterRoleBindings, a
per-subject RBAC permission rollup, and a per-binding-subject drift record,
and enriches the message-2 workload-service-account rollup with resolved
automount posture and bound-privilege context. The remaining types are
reserved names for later messages so downstream code (diff tracking, risk
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

Emitted in message 3 (RBAC and identity)
-------------------------------------------
``kubernetes_service_account`` — one record per ServiceAccount, with safe
counts (image-pull secrets, Secret references), resolved automount default,
and a bound-privilege rollup (cluster-admin/wildcard/secret-read/pod-exec/
workload-create/RBAC-modify/impersonation flags) computed after binding
resolution.
``kubernetes_role``, ``kubernetes_cluster_role`` — one record per Role/
ClusterRole, with normalized rule categorization (never raw rule documents):
API-group/resource/verb categories, the full dangerous-permission boolean
taxonomy (secrets, Pod exec/attach/port-forward/logs, workload/RBAC/webhook/
CRD/namespace mutation, bind/escalate/impersonate/token-creation/
CSR-approval), a stable permission fingerprint, and a highest-severity
category.
``kubernetes_role_binding``, ``kubernetes_cluster_role_binding`` — one
record per binding, with subject-category counts, resolved roleRef privilege
(or an explicit unresolved/denied status — never silently downgraded to
"safe"), and a binding fingerprint.
``kubernetes_rbac_subject_binding`` — one record per (binding, subject)
pair, so a single subject being added to or removed from a binding produces
one precise Change (see ``kubernetes.py`` module docstring for why this is
a separate record from the coarser binding record).
``kubernetes_rbac_permission_summary`` — one rollup record per unique
subject identity (User/Group/ServiceAccount) aggregating privilege across
*every* binding that subject appears in — answers "what does this identity
have access to in total", independent of how many individual bindings grant
it.

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

# ── Record type constants — emitted in message 3 (RBAC and identity) ────────

KUBERNETES_ROLE = "kubernetes_role"
KUBERNETES_CLUSTER_ROLE = "kubernetes_cluster_role"
KUBERNETES_ROLE_BINDING = "kubernetes_role_binding"
KUBERNETES_CLUSTER_ROLE_BINDING = "kubernetes_cluster_role_binding"
KUBERNETES_SERVICE_ACCOUNT = "kubernetes_service_account"
KUBERNETES_RBAC_SUBJECT_BINDING = "kubernetes_rbac_subject_binding"
KUBERNETES_RBAC_PERMISSION_SUMMARY = "kubernetes_rbac_permission_summary"

KUBERNETES_RBAC_ROLE_RECORD_TYPES: frozenset[str] = frozenset(
    {KUBERNETES_ROLE, KUBERNETES_CLUSTER_ROLE}
)
KUBERNETES_RBAC_BINDING_RECORD_TYPES: frozenset[str] = frozenset(
    {KUBERNETES_ROLE_BINDING, KUBERNETES_CLUSTER_ROLE_BINDING}
)
KUBERNETES_RBAC_RECORD_TYPES: frozenset[str] = (
    KUBERNETES_RBAC_ROLE_RECORD_TYPES
    | KUBERNETES_RBAC_BINDING_RECORD_TYPES
    | frozenset(
        {
            KUBERNETES_SERVICE_ACCOUNT,
            KUBERNETES_RBAC_SUBJECT_BINDING,
            KUBERNETES_RBAC_PERMISSION_SUMMARY,
        }
    )
)

# ── Record type constants — reserved for later messages (not yet emitted) ───
# These names are fixed now so that later messages never need to rename a
# record type after Changes/Findings have already been built against it.

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
    | KUBERNETES_RBAC_RECORD_TYPES
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
    # Enriched in message 3 (RBAC) — see kubernetes.py's automount
    # resolution logic and module docstring.
    service_account_found: bool
    effective_automount_state: str
    automount_source_category: str
    service_account_privilege_summary: str
    bound_role_binding_count: int
    bound_cluster_role_binding_count: int
    risky_permission_categories: list[str]
    collection_completeness_category: str


# ── RBAC vocabulary — message 3 ───────────────────────────────────────────────

# ServiceAccount / binding automount resolution states. "unknown_*" states
# must never be treated as a confirmed true/false by any downstream code.
AUTOMOUNT_STATE_EXPLICIT_WORKLOAD_TRUE = "explicit_workload_true"
AUTOMOUNT_STATE_EXPLICIT_WORKLOAD_FALSE = "explicit_workload_false"
AUTOMOUNT_STATE_INHERITED_SERVICE_ACCOUNT_TRUE = "inherited_service_account_true"
AUTOMOUNT_STATE_INHERITED_SERVICE_ACCOUNT_FALSE = "inherited_service_account_false"
AUTOMOUNT_STATE_KUBERNETES_DEFAULT_TRUE = "kubernetes_default_true"
AUTOMOUNT_STATE_UNKNOWN_SERVICE_ACCOUNT_MISSING = "unknown_service_account_missing"
AUTOMOUNT_STATE_UNKNOWN_PERMISSION_DENIED = "unknown_permission_denied"

AUTOMOUNT_SOURCE_WORKLOAD_EXPLICIT = "workload_explicit"
AUTOMOUNT_SOURCE_SERVICE_ACCOUNT_EXPLICIT = "service_account_explicit"
AUTOMOUNT_SOURCE_KUBERNETES_DEFAULT = "kubernetes_default"
AUTOMOUNT_SOURCE_UNKNOWN = "unknown"

# Role-resolution status — an unresolved/denied roleRef must never be
# silently treated as low/no privilege.
ROLE_RESOLUTION_RESOLVED = "resolved"
ROLE_RESOLUTION_MISSING = "missing"
ROLE_RESOLUTION_ACCESS_DENIED = "access_denied"
ROLE_RESOLUTION_MALFORMED = "malformed"

# Privilege severity categories shared by Roles/ClusterRoles, bindings,
# subject-bindings, and the permission-summary rollup. "unknown" is
# distinct from "low" — it means privilege could not be determined
# (unresolved roleRef, access-denied collection, malformed rule), never a
# confirmed safe state.
SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"
SEVERITY_UNKNOWN = "unknown"

# Built-in role categories. Recognizing these is NOT a judgement that they
# are safe or unsafe — only the fact of a subject being BOUND to one is
# potentially dangerous (see kubernetes.py module docstring).
BUILTIN_ROLE_CLUSTER_ADMIN = "cluster-admin"
BUILTIN_ROLE_ADMIN = "admin"
BUILTIN_ROLE_EDIT = "edit"
BUILTIN_ROLE_VIEW = "view"
BUILTIN_ROLE_SYSTEM = "system"
BUILTIN_ROLE_AGGREGATE_TO_ADMIN = "aggregate-to-admin"
BUILTIN_ROLE_AGGREGATE_TO_EDIT = "aggregate-to-edit"
BUILTIN_ROLE_AGGREGATE_TO_VIEW = "aggregate-to-view"
BUILTIN_ROLE_NONE = "none"

# Only these explicit, well-known bootstrapping label keys are ever read
# from a Role/ClusterRole — never arbitrary labels.
SAFE_ROLE_LABEL_KEYS: frozenset[str] = frozenset(
    {"kubernetes.io/bootstrapping", "rbac.authorization.k8s.io/aggregate-to-admin",
     "rbac.authorization.k8s.io/aggregate-to-edit", "rbac.authorization.k8s.io/aggregate-to-view"}
)

# API-group categories (never store the raw group string beyond this
# bounded, well-known vocabulary; unrecognized groups — almost always CRD
# groups — are "custom", not persisted verbatim beyond that bucket... note:
# actual K8s API group names are not secret, but categorizing keeps the
# stored vocabulary bounded and consistent with resource/verb handling).
API_GROUP_CORE = "core"
API_GROUP_WILDCARD = "wildcard"
API_GROUP_CUSTOM = "custom"
_KNOWN_API_GROUPS: frozenset[str] = frozenset(
    {
        "apps", "batch", "networking.k8s.io", "rbac.authorization.k8s.io",
        "policy", "admissionregistration.k8s.io", "storage.k8s.io",
        "certificates.k8s.io", "authorization.k8s.io", "authentication.k8s.io",
        "apiextensions.k8s.io", "coordination.k8s.io", "scheduling.k8s.io",
        "discovery.k8s.io", "events.k8s.io", "autoscaling",
    }
)

# Resource categories — the bounded vocabulary a raw RBAC resource string
# (e.g. "pods", "pods/exec", "secrets") is mapped into.
RESOURCE_CATEGORY_SECRETS = "secrets"
RESOURCE_CATEGORY_CONFIGMAPS = "configmaps"
RESOURCE_CATEGORY_PODS = "pods"
RESOURCE_CATEGORY_PODS_EXEC = "pods/exec"
RESOURCE_CATEGORY_PODS_ATTACH = "pods/attach"
RESOURCE_CATEGORY_PODS_PORTFORWARD = "pods/portforward"
RESOURCE_CATEGORY_PODS_LOG = "pods/log"
RESOURCE_CATEGORY_WORKLOADS = "workloads"
RESOURCE_CATEGORY_SERVICES = "services"
RESOURCE_CATEGORY_INGRESSES = "ingresses"
RESOURCE_CATEGORY_NETWORK_POLICIES = "networkpolicies"
RESOURCE_CATEGORY_ROLES = "roles"
RESOURCE_CATEGORY_ROLE_BINDINGS = "rolebindings"
RESOURCE_CATEGORY_CLUSTER_ROLES = "clusterroles"
RESOURCE_CATEGORY_CLUSTER_ROLE_BINDINGS = "clusterrolebindings"
RESOURCE_CATEGORY_SERVICE_ACCOUNTS = "serviceaccounts"
RESOURCE_CATEGORY_SERVICE_ACCOUNTS_TOKEN = "serviceaccounts/token"
RESOURCE_CATEGORY_NODES = "nodes"
RESOURCE_CATEGORY_NODES_PROXY = "nodes/proxy"
RESOURCE_CATEGORY_PERSISTENT_VOLUMES = "persistentvolumes"
RESOURCE_CATEGORY_NAMESPACES = "namespaces"
RESOURCE_CATEGORY_VALIDATING_WEBHOOKS = "validatingwebhookconfigurations"
RESOURCE_CATEGORY_MUTATING_WEBHOOKS = "mutatingwebhookconfigurations"
RESOURCE_CATEGORY_CRDS = "customresourcedefinitions"
RESOURCE_CATEGORY_CSR_APPROVAL = "certificatesigningrequests/approval"
RESOURCE_CATEGORY_SUBJECT_ACCESS_REVIEWS = "subjectaccessreviews"
RESOURCE_CATEGORY_EVENTS = "events"
RESOURCE_CATEGORY_ENDPOINT_SLICES = "endpointslices"
RESOURCE_CATEGORY_WILDCARD = "wildcard"
RESOURCE_CATEGORY_OTHER = "other"

# Raw resource string -> category. Resources not listed here (almost always
# CRDs) fall back to RESOURCE_CATEGORY_OTHER.
_RESOURCE_CATEGORY_MAP: dict[str, str] = {
    "secrets": RESOURCE_CATEGORY_SECRETS,
    "configmaps": RESOURCE_CATEGORY_CONFIGMAPS,
    "pods": RESOURCE_CATEGORY_PODS,
    "pods/exec": RESOURCE_CATEGORY_PODS_EXEC,
    "pods/attach": RESOURCE_CATEGORY_PODS_ATTACH,
    "pods/portforward": RESOURCE_CATEGORY_PODS_PORTFORWARD,
    "pods/log": RESOURCE_CATEGORY_PODS_LOG,
    "deployments": RESOURCE_CATEGORY_WORKLOADS,
    "statefulsets": RESOURCE_CATEGORY_WORKLOADS,
    "daemonsets": RESOURCE_CATEGORY_WORKLOADS,
    "replicasets": RESOURCE_CATEGORY_WORKLOADS,
    "jobs": RESOURCE_CATEGORY_WORKLOADS,
    "cronjobs": RESOURCE_CATEGORY_WORKLOADS,
    "services": RESOURCE_CATEGORY_SERVICES,
    "ingresses": RESOURCE_CATEGORY_INGRESSES,
    "networkpolicies": RESOURCE_CATEGORY_NETWORK_POLICIES,
    "roles": RESOURCE_CATEGORY_ROLES,
    "rolebindings": RESOURCE_CATEGORY_ROLE_BINDINGS,
    "clusterroles": RESOURCE_CATEGORY_CLUSTER_ROLES,
    "clusterrolebindings": RESOURCE_CATEGORY_CLUSTER_ROLE_BINDINGS,
    "serviceaccounts": RESOURCE_CATEGORY_SERVICE_ACCOUNTS,
    "serviceaccounts/token": RESOURCE_CATEGORY_SERVICE_ACCOUNTS_TOKEN,
    "nodes": RESOURCE_CATEGORY_NODES,
    "nodes/proxy": RESOURCE_CATEGORY_NODES_PROXY,
    "persistentvolumes": RESOURCE_CATEGORY_PERSISTENT_VOLUMES,
    "persistentvolumeclaims": RESOURCE_CATEGORY_PERSISTENT_VOLUMES,
    "namespaces": RESOURCE_CATEGORY_NAMESPACES,
    "validatingwebhookconfigurations": RESOURCE_CATEGORY_VALIDATING_WEBHOOKS,
    "mutatingwebhookconfigurations": RESOURCE_CATEGORY_MUTATING_WEBHOOKS,
    "customresourcedefinitions": RESOURCE_CATEGORY_CRDS,
    "certificatesigningrequests/approval": RESOURCE_CATEGORY_CSR_APPROVAL,
    "subjectaccessreviews": RESOURCE_CATEGORY_SUBJECT_ACCESS_REVIEWS,
    "selfsubjectaccessreviews": RESOURCE_CATEGORY_SUBJECT_ACCESS_REVIEWS,
    "events": RESOURCE_CATEGORY_EVENTS,
    "endpointslices": RESOURCE_CATEGORY_ENDPOINT_SLICES,
}

# Verb categories — verbs are already a small, fixed Kubernetes vocabulary,
# so they are normalized (lowercased) but not further bucketed except for
# preserving "*".
READ_VERBS: frozenset[str] = frozenset({"get", "list", "watch"})
WRITE_VERBS: frozenset[str] = frozenset({"create", "update", "patch", "delete", "deletecollection"})
VERB_WILDCARD = "*"
VERB_BIND = "bind"
VERB_ESCALATE = "escalate"
VERB_IMPERSONATE = "impersonate"
VERB_APPROVE = "approve"

# Non-resource URL categories.
NON_RESOURCE_CATEGORY_HEALTH_VERSION = "health_version"
NON_RESOURCE_CATEGORY_METRICS = "metrics"
NON_RESOURCE_CATEGORY_LOGS = "logs"
NON_RESOURCE_CATEGORY_DEBUG = "debug"
NON_RESOURCE_CATEGORY_API_ROOT = "api_root"
NON_RESOURCE_CATEGORY_WILDCARD = "wildcard"
NON_RESOURCE_CATEGORY_OTHER = "other"

_HEALTH_VERSION_PATHS: frozenset[str] = frozenset({"/healthz", "/livez", "/readyz", "/version"})

# Dangerous-permission category tags. Used both for the stored
# ``high_risk_permission_categories`` list and to derive
# ``highest_severity_category`` via _CATEGORY_SEVERITY below.
CATEGORY_FULL_WILDCARD = "full_wildcard"
CATEGORY_BIND = "bind"
CATEGORY_ESCALATE = "escalate"
CATEGORY_IMPERSONATE = "impersonate"
CATEGORY_TOKEN_CREATION = "token_creation"
CATEGORY_CSR_APPROVAL = "csr_approval"
CATEGORY_CLUSTER_ROLE_BINDING_WRITE = "cluster_role_binding_write"
CATEGORY_ADMISSION_WEBHOOK_WRITE = "admission_webhook_write"
CATEGORY_CRD_WRITE = "crd_write"
CATEGORY_NODE_PROXY = "node_proxy"
CATEGORY_SECRET_READ_BROAD_SCOPE = "secret_read_broad_scope"
CATEGORY_SECRET_READ = "secret_read"
CATEGORY_SECRET_WRITE = "secret_write"
CATEGORY_POD_EXEC = "pod_exec"
CATEGORY_POD_ATTACH = "pod_attach"
CATEGORY_POD_PORT_FORWARD = "pod_port_forward"
CATEGORY_POD_WRITE = "pod_write"
CATEGORY_WORKLOAD_WRITE = "workload_write"
CATEGORY_ROLE_OR_CLUSTER_ROLE_WRITE = "role_or_cluster_role_write"
CATEGORY_NAMESPACE_WRITE = "namespace_write"
CATEGORY_NETWORK_MUTATION = "network_mutation"
CATEGORY_PV_ACCESS = "persistent_volume_access"
CATEGORY_NODES_WRITE = "nodes_write"
CATEGORY_WILDCARD_VERB = "wildcard_verb"
CATEGORY_WILDCARD_RESOURCE = "wildcard_resource"
CATEGORY_CONFIGMAP_WRITE = "configmap_write"
CATEGORY_CONFIGMAP_READ_BROAD = "configmap_read_broad"
CATEGORY_POD_LOGS = "pod_logs"
CATEGORY_SERVICE_WRITE = "service_write"
CATEGORY_NODES_READ = "nodes_read"
CATEGORY_NON_RESOURCE_BROAD = "non_resource_broad"

_CATEGORY_SEVERITY: dict[str, str] = {
    CATEGORY_FULL_WILDCARD: SEVERITY_CRITICAL,
    CATEGORY_BIND: SEVERITY_CRITICAL,
    CATEGORY_ESCALATE: SEVERITY_CRITICAL,
    CATEGORY_IMPERSONATE: SEVERITY_CRITICAL,
    CATEGORY_TOKEN_CREATION: SEVERITY_CRITICAL,
    CATEGORY_CSR_APPROVAL: SEVERITY_CRITICAL,
    CATEGORY_CLUSTER_ROLE_BINDING_WRITE: SEVERITY_CRITICAL,
    CATEGORY_ADMISSION_WEBHOOK_WRITE: SEVERITY_CRITICAL,
    CATEGORY_CRD_WRITE: SEVERITY_CRITICAL,
    CATEGORY_NODE_PROXY: SEVERITY_CRITICAL,
    CATEGORY_SECRET_READ_BROAD_SCOPE: SEVERITY_CRITICAL,
    CATEGORY_SECRET_READ: SEVERITY_HIGH,
    CATEGORY_SECRET_WRITE: SEVERITY_HIGH,
    CATEGORY_POD_EXEC: SEVERITY_HIGH,
    CATEGORY_POD_ATTACH: SEVERITY_HIGH,
    CATEGORY_POD_PORT_FORWARD: SEVERITY_HIGH,
    CATEGORY_POD_WRITE: SEVERITY_HIGH,
    CATEGORY_WORKLOAD_WRITE: SEVERITY_HIGH,
    CATEGORY_ROLE_OR_CLUSTER_ROLE_WRITE: SEVERITY_HIGH,
    CATEGORY_NAMESPACE_WRITE: SEVERITY_HIGH,
    CATEGORY_NETWORK_MUTATION: SEVERITY_HIGH,
    CATEGORY_PV_ACCESS: SEVERITY_HIGH,
    CATEGORY_NODES_WRITE: SEVERITY_HIGH,
    CATEGORY_WILDCARD_VERB: SEVERITY_HIGH,
    CATEGORY_WILDCARD_RESOURCE: SEVERITY_HIGH,
    CATEGORY_CONFIGMAP_WRITE: SEVERITY_MEDIUM,
    CATEGORY_CONFIGMAP_READ_BROAD: SEVERITY_MEDIUM,
    CATEGORY_POD_LOGS: SEVERITY_MEDIUM,
    CATEGORY_SERVICE_WRITE: SEVERITY_MEDIUM,
    CATEGORY_NODES_READ: SEVERITY_MEDIUM,
    CATEGORY_NON_RESOURCE_BROAD: SEVERITY_MEDIUM,
}

# Subject-kind and group vocabulary.
SUBJECT_KIND_USER = "User"
SUBJECT_KIND_GROUP = "Group"
SUBJECT_KIND_SERVICE_ACCOUNT = "ServiceAccount"

GROUP_SYSTEM_MASTERS = "system:masters"
GROUP_SYSTEM_AUTHENTICATED = "system:authenticated"
GROUP_SYSTEM_UNAUTHENTICATED = "system:unauthenticated"
GROUP_SYSTEM_SERVICEACCOUNTS_PREFIX = "system:serviceaccounts"
GROUP_SYSTEM_NODES = "system:nodes"
USER_SYSTEM_ANONYMOUS = "system:anonymous"


def categorize_api_group(group: Optional[str]) -> str:
    if group is None:
        return API_GROUP_CORE
    group = group.strip()
    if group == "*":
        return API_GROUP_WILDCARD
    if group == "":
        return API_GROUP_CORE
    if group in _KNOWN_API_GROUPS:
        return group
    return API_GROUP_CUSTOM


def categorize_resource(resource: Optional[str]) -> str:
    if not resource:
        return RESOURCE_CATEGORY_OTHER
    resource = resource.strip().lower()
    if resource == "*":
        return RESOURCE_CATEGORY_WILDCARD
    return _RESOURCE_CATEGORY_MAP.get(resource, RESOURCE_CATEGORY_OTHER)


def categorize_non_resource_url(url: Optional[str]) -> str:
    if not url:
        return NON_RESOURCE_CATEGORY_OTHER
    url = url.strip()
    if url == "*":
        return NON_RESOURCE_CATEGORY_WILDCARD
    trimmed = url.rstrip("/") or "/"
    if trimmed in _HEALTH_VERSION_PATHS:
        return NON_RESOURCE_CATEGORY_HEALTH_VERSION
    if trimmed.startswith("/metrics"):
        return NON_RESOURCE_CATEGORY_METRICS
    if trimmed.startswith("/logs"):
        return NON_RESOURCE_CATEGORY_LOGS
    if trimmed.startswith("/debug"):
        return NON_RESOURCE_CATEGORY_DEBUG
    if trimmed == "/":
        return NON_RESOURCE_CATEGORY_API_ROOT
    return NON_RESOURCE_CATEGORY_OTHER


def categorize_builtin_role(name: Optional[str]) -> str:
    """Categorize a Role/ClusterRole name into a well-known built-in bucket.

    Recognizing a built-in role is NOT a judgement that it is safe or
    unsafe — a binding record's own fields (cluster_admin_binding, etc.)
    carry the actual risk signal. See module + connector docstrings.
    """
    if not name:
        return BUILTIN_ROLE_NONE
    if name == "cluster-admin":
        return BUILTIN_ROLE_CLUSTER_ADMIN
    if name == "admin":
        return BUILTIN_ROLE_ADMIN
    if name == "edit":
        return BUILTIN_ROLE_EDIT
    if name == "view":
        return BUILTIN_ROLE_VIEW
    if name == "system:aggregate-to-admin":
        return BUILTIN_ROLE_AGGREGATE_TO_ADMIN
    if name == "system:aggregate-to-edit":
        return BUILTIN_ROLE_AGGREGATE_TO_EDIT
    if name == "system:aggregate-to-view":
        return BUILTIN_ROLE_AGGREGATE_TO_VIEW
    if name.startswith("system:"):
        return BUILTIN_ROLE_SYSTEM
    return BUILTIN_ROLE_NONE


def canonical_service_account_identity(namespace: str, name: str) -> str:
    return f"system:serviceaccount:{namespace}:{name}"


def categorize_group(name: Optional[str]) -> str:
    if not name:
        return "custom"
    if name == GROUP_SYSTEM_MASTERS:
        return GROUP_SYSTEM_MASTERS
    if name == GROUP_SYSTEM_AUTHENTICATED:
        return GROUP_SYSTEM_AUTHENTICATED
    if name == GROUP_SYSTEM_UNAUTHENTICATED:
        return GROUP_SYSTEM_UNAUTHENTICATED
    if name == GROUP_SYSTEM_NODES:
        return GROUP_SYSTEM_NODES
    if name.startswith(GROUP_SYSTEM_SERVICEACCOUNTS_PREFIX):
        return GROUP_SYSTEM_SERVICEACCOUNTS_PREFIX
    return "custom"


def highest_severity(categories: "set[str] | list[str]") -> str:
    """Return the highest severity among the given category tags, or
    SEVERITY_LOW if the set is empty. Never returns SEVERITY_UNKNOWN —
    callers pass SEVERITY_UNKNOWN explicitly when resolution itself failed."""
    severities = {_CATEGORY_SEVERITY.get(c) for c in categories}
    severities.discard(None)
    for level in (SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW):
        if level in severities:
            return level
    return SEVERITY_LOW


# ── TypedDict schemas — message 3 (RBAC and identity) ────────────────────────


class KubernetesServiceAccountRecord(TypedDict):
    record_type: str
    record_id: str
    cluster_id: str
    cluster_name: str
    namespace: str
    name: str
    uid: Optional[str]
    automount_service_account_token: Optional[bool]
    image_pull_secret_count: int
    secret_reference_count: int
    workload_reference_count: int
    bound_role_binding_count: int
    bound_cluster_role_binding_count: int
    highest_privilege_category: str
    cluster_admin_bound: bool
    wildcard_permission_bound: bool
    secret_read_permission_bound: bool
    pod_exec_permission_bound: bool
    workload_creation_permission_bound: bool
    rbac_modification_permission_bound: bool
    impersonation_permission_bound: bool
    collection_completeness_category: str


class KubernetesRoleRecord(TypedDict):
    """Shared shape for kubernetes_role / kubernetes_cluster_role."""

    record_type: str
    record_id: str
    cluster_id: str
    cluster_name: str
    namespace: Optional[str]
    name: str
    uid: Optional[str]
    kind: str
    built_in_role_category: str
    system_managed: bool
    aggregation_rule_present: bool
    aggregation_selector_count: int
    rule_count: int
    api_group_categories: list[str]
    resource_categories: list[str]
    verb_categories: list[str]
    resource_name_restriction_present: bool
    non_resource_url_categories: list[str]
    non_resource_url_count: int
    wildcard_api_group: bool
    wildcard_resource: bool
    wildcard_verb: bool
    wildcard_non_resource_url: bool
    secret_read: bool
    secret_write: bool
    configmap_read: bool
    configmap_write: bool
    pod_read: bool
    pod_write: bool
    pod_exec: bool
    pod_attach: bool
    pod_port_forward: bool
    pod_logs: bool
    workload_write: bool
    service_write: bool
    network_mutation: bool
    rbac_read: bool
    rbac_write: bool
    cluster_role_binding_write: bool
    bind_permission: bool
    escalate_permission: bool
    impersonate_permission: bool
    csr_approve_permission: bool
    node_proxy_access: bool
    nodes_read: bool
    nodes_write: bool
    persistent_volume_access: bool
    admission_webhook_modification: bool
    crd_modification: bool
    namespace_modification: bool
    service_account_token_creation: bool
    token_request_access: bool
    subject_access_review_creation: bool
    high_risk_permission_categories: list[str]
    highest_severity_category: str
    permission_fingerprint: str
    collection_completeness_category: str


class KubernetesRoleBindingRecord(TypedDict):
    """Shared shape for kubernetes_role_binding / kubernetes_cluster_role_binding."""

    record_type: str
    record_id: str
    cluster_id: str
    cluster_name: str
    namespace: Optional[str]
    name: str
    uid: Optional[str]
    kind: str
    role_ref_kind: str
    role_ref_name: str
    role_ref_api_group: str
    subject_count: int
    user_subject_count: int
    group_subject_count: int
    service_account_subject_count: int
    role_resolved: bool
    role_resolution_status: str
    resolved_privilege_category: str
    cluster_admin_binding: bool
    wildcard_permission_binding: bool
    high_risk_permission_categories: list[str]
    binding_fingerprint: str
    collection_completeness_category: str


class KubernetesRbacSubjectBindingRecord(TypedDict):
    record_type: str
    record_id: str
    cluster_id: str
    cluster_name: str
    binding_kind: str
    binding_namespace: Optional[str]
    binding_name: str
    binding_uid: Optional[str]
    role_ref_kind: str
    role_ref_name: str
    role_ref_api_group: str
    subject_kind: str
    subject_name: str
    subject_namespace: Optional[str]
    subject_identity: str
    anonymous_subject: bool
    unauthenticated_group: bool
    authenticated_group: bool
    system_group: bool
    broad_group: bool
    cross_namespace_service_account: bool
    role_resolved: bool
    role_resolution_status: str
    resolved_privilege_category: str
    cluster_admin_binding: bool
    wildcard_permission_binding: bool
    high_risk_permission_categories: list[str]


class KubernetesRbacPermissionSummaryRecord(TypedDict):
    record_type: str
    record_id: str
    cluster_id: str
    cluster_name: str
    subject_kind: str
    subject_identity: str
    namespace: Optional[str]
    role_binding_count: int
    cluster_role_binding_count: int
    cluster_admin_bound: bool
    wildcard_permission_bound: bool
    secret_read_bound: bool
    secret_write_bound: bool
    pod_exec_bound: bool
    workload_create_bound: bool
    rbac_modification_bound: bool
    impersonation_bound: bool
    high_risk_permission_categories: list[str]
    highest_privilege_category: str
    collection_completeness_category: str
