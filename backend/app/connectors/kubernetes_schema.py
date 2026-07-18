"""Kubernetes connector schema — admission control and configuration governance (message 5 of a 9-message arc).

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

Emitted in message 4 (network exposure and isolation)
----------------------------------------------------------
``kubernetes_service``, ``kubernetes_service_port`` — one record per
Service plus one per declared port, with an evidence-hierarchy exposure
category (never claiming confirmed public reachability without assigned
LoadBalancer/externalIP evidence).
``kubernetes_ingress``, ``kubernetes_ingress_rule`` — one record per
Ingress plus one per host/path rule grouping, with TLS coverage, wildcard/
hostless detection, and public-exposure evidence from `.status` only.
``kubernetes_gateway``, ``kubernetes_gateway_listener`` — one record per
Gateway API `Gateway` plus one per listener. Collected via
`CustomObjectsApi` (no typed client exists for Gateway API); absent
entirely on clusters without the CRDs installed, which is fail-soft
"unsupported", not an error.
``kubernetes_http_route``, ``kubernetes_http_route_rule`` — one record per
Gateway API `HTTPRoute` plus one per rule, with cross-namespace
parent/backend detection. `ReferenceGrant` collection is NOT implemented
this message (GAP, revisit message 8 if needed) — the API server's own
`resolvedRefs` status condition is used as the authoritative signal for
whether a cross-namespace reference is actually authorized, since
Kubernetes itself evaluates ReferenceGrants when populating that
condition.
``kubernetes_network_policy`` — one record per NetworkPolicy, with the
full omitted/empty/allow-all semantic distinction (see `kubernetes.py`
module docstring) and IPv4/IPv6 CIDR categorization.
``kubernetes_namespace_network_posture`` — one rollup record per
namespace, aggregating NetworkPolicy coverage across that namespace.

Emitted in message 5 (admission control and configuration governance)
---------------------------------------------------------------------------
``kubernetes_validating_webhook_configuration``, ``kubernetes_validating_webhook``
— one record per `ValidatingWebhookConfiguration` plus one per contained
webhook, with failure-policy/match-policy/side-effects/selector/rule
categorization (never raw rule dicts, never CA bundle bytes).
``kubernetes_mutating_webhook_configuration``, ``kubernetes_mutating_webhook``
— same shape, plus `reinvocationPolicy`.
``kubernetes_pod_security_admission`` — one record per namespace,
promoting the six PSA labels already read in message 1 into a dedicated
posture record (enforce/audit/warn level + version, effective posture,
weakening detection).
``kubernetes_resource_quota`` — one record per ResourceQuota, with
normalized configured hard-limit quantities (never usage/status values).
``kubernetes_limit_range`` — one record per LimitRange, with
default/default-request/min/max coverage categories.
``kubernetes_namespace_governance_posture`` — one rollup record per
namespace, cross-referencing PSA + webhook coverage + quota/limit
coverage + message-4's NetworkPolicy posture + message-2's privileged-
workload signal + message-3's high-privilege-identity signal. A compact
cross-control summary, not a Finding engine (message 6 owns Findings).

Deliberately NOT implemented (documented safety decisions, not gaps in
disguise — see kubernetes.py module docstring for the full review)
-----------------------------------------------------------------------------
``kubernetes_config_map_metadata`` — ConfigMap API access remains
disabled. The Kubernetes API returns full values alongside metadata for
ConfigMaps (no field-level RBAC exists to request metadata only), and
ConfigTrace's default permission contract does not request ConfigMap read
access. Revisit only if a future message adopts an explicit, customer-
opt-in, fetch-and-immediately-discard architecture with redaction tests —
not attempted here.
``kubernetes_secret_metadata`` — Secret API access remains permanently
disabled, under an even stricter version of the same limitation (see
message-1's contract). This is not a placeholder for a future message;
it is a deliberate, permanent architectural boundary for this connector.

Planned for later messages (beyond message 5)
---------------------------------------------------
``kubernetes_api_server_security_posture`` (only if safely observable —
still under review).

SENSITIVE-DATA POLICY (mandatory, see kubernetes.py module docstring for the
full contract): this connector NEVER fetches Secret values, ConfigMap
values, service-account token contents, kubeconfig contents, Pod logs, exec
output, admission request/response payloads, webhook CA bundle bytes, or
raw annotation/label maps. Message 5 does NOT begin ConfigMap/Secret
metadata collection — see the "deliberately NOT implemented" section above.
"""

from __future__ import annotations

import hashlib
import ipaddress
from decimal import Decimal, InvalidOperation
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

# ── Record type constants — emitted in message 4 (network exposure/isolation) ─

KUBERNETES_SERVICE = "kubernetes_service"
KUBERNETES_SERVICE_PORT = "kubernetes_service_port"
KUBERNETES_INGRESS = "kubernetes_ingress"
KUBERNETES_INGRESS_RULE = "kubernetes_ingress_rule"
KUBERNETES_GATEWAY = "kubernetes_gateway"
KUBERNETES_GATEWAY_LISTENER = "kubernetes_gateway_listener"
KUBERNETES_HTTP_ROUTE = "kubernetes_http_route"
KUBERNETES_HTTP_ROUTE_RULE = "kubernetes_http_route_rule"
KUBERNETES_NETWORK_POLICY = "kubernetes_network_policy"
KUBERNETES_NAMESPACE_NETWORK_POSTURE = "kubernetes_namespace_network_posture"

KUBERNETES_NETWORK_RECORD_TYPES: frozenset[str] = frozenset(
    {
        KUBERNETES_SERVICE, KUBERNETES_SERVICE_PORT,
        KUBERNETES_INGRESS, KUBERNETES_INGRESS_RULE,
        KUBERNETES_GATEWAY, KUBERNETES_GATEWAY_LISTENER,
        KUBERNETES_HTTP_ROUTE, KUBERNETES_HTTP_ROUTE_RULE,
        KUBERNETES_NETWORK_POLICY, KUBERNETES_NAMESPACE_NETWORK_POSTURE,
    }
)

# ── Record type constants — emitted in message 5 (admission/governance) ─────

KUBERNETES_VALIDATING_WEBHOOK_CONFIGURATION = "kubernetes_validating_webhook_configuration"
KUBERNETES_VALIDATING_WEBHOOK = "kubernetes_validating_webhook"
KUBERNETES_MUTATING_WEBHOOK_CONFIGURATION = "kubernetes_mutating_webhook_configuration"
KUBERNETES_MUTATING_WEBHOOK = "kubernetes_mutating_webhook"
KUBERNETES_POD_SECURITY_ADMISSION = "kubernetes_pod_security_admission"
KUBERNETES_RESOURCE_QUOTA = "kubernetes_resource_quota"
KUBERNETES_LIMIT_RANGE = "kubernetes_limit_range"
KUBERNETES_NAMESPACE_GOVERNANCE_POSTURE = "kubernetes_namespace_governance_posture"

KUBERNETES_ADMISSION_CONFIGURATION_RECORD_TYPES: frozenset[str] = frozenset(
    {KUBERNETES_VALIDATING_WEBHOOK_CONFIGURATION, KUBERNETES_MUTATING_WEBHOOK_CONFIGURATION}
)
KUBERNETES_ADMISSION_WEBHOOK_RECORD_TYPES: frozenset[str] = frozenset(
    {KUBERNETES_VALIDATING_WEBHOOK, KUBERNETES_MUTATING_WEBHOOK}
)
KUBERNETES_ADMISSION_RECORD_TYPES: frozenset[str] = (
    KUBERNETES_ADMISSION_CONFIGURATION_RECORD_TYPES
    | KUBERNETES_ADMISSION_WEBHOOK_RECORD_TYPES
    | frozenset(
        {
            KUBERNETES_POD_SECURITY_ADMISSION, KUBERNETES_RESOURCE_QUOTA,
            KUBERNETES_LIMIT_RANGE, KUBERNETES_NAMESPACE_GOVERNANCE_POSTURE,
        }
    )
)

# ── Record type constants — deliberately unsupported (never emitted) ────────
# See kubernetes.py / this module's docstring for the full safety review.
# These are NOT "not yet implemented" placeholders — they document a
# permanent architectural decision not to collect this data.
KUBERNETES_CONFIG_MAP_METADATA = "kubernetes_config_map_metadata"
KUBERNETES_SECRET_METADATA = "kubernetes_secret_metadata"

# ── Record type constants — reserved for later messages (not yet emitted) ───
# These names are fixed now so that later messages never need to rename a
# record type after Changes/Findings have already been built against it.

KUBERNETES_API_SERVER_SECURITY_POSTURE = "kubernetes_api_server_security_posture"

KUBERNETES_PLANNED_RECORD_TYPES: frozenset[str] = frozenset(
    {KUBERNETES_API_SERVER_SECURITY_POSTURE}
)

# All record types across the full planned taxonomy, whether or not they are
# emitted yet. Used only for documentation/introspection — never assume every
# member of this set is reachable from fetch() today. Deliberately excludes
# KUBERNETES_CONFIG_MAP_METADATA/KUBERNETES_SECRET_METADATA — those are
# permanently unsupported, not merely unemitted (see module docstring).
KUBERNETES_RECORD_TYPES: frozenset[str] = (
    KUBERNETES_FOUNDATION_RECORD_TYPES
    | KUBERNETES_WORKLOAD_RECORD_TYPES
    | KUBERNETES_RBAC_RECORD_TYPES
    | KUBERNETES_NETWORK_RECORD_TYPES
    | KUBERNETES_ADMISSION_RECORD_TYPES
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
    family_completeness: dict[str, str]
    configured_namespace_allowlist: Optional[list[str]]


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


# ── Network vocabulary — message 4 ────────────────────────────────────────────
#
# Public-exposure evidence hierarchy (shared across Service/Ingress/Gateway):
# 1. explicit internal/external configuration (e.g. internal-LB annotation)
# 2. assigned external/load-balancer addresses (status, not spec/request)
# 3. service/resource type or route/listener configuration
# 4. unknown
# A resource is never classified as "confirmed public" on spec/request alone
# (e.g. LoadBalancer *type* requested but no `.status.loadBalancer.ingress`
# assigned yet) — that is "requested"/"pending", a distinct, weaker category.

EXPOSURE_CLUSTER_INTERNAL = "cluster_internal"
EXPOSURE_HEADLESS_INTERNAL = "headless_internal"
EXPOSURE_NODE_PORT = "node_port"
EXPOSURE_EXTERNAL_LOAD_BALANCER = "external_load_balancer"
EXPOSURE_EXTERNAL_IP = "external_ip"
EXPOSURE_EXTERNAL_NAME = "external_name"
EXPOSURE_INTERNAL_LOAD_BALANCER = "internal_load_balancer"
EXPOSURE_PENDING_LOAD_BALANCER = "pending_load_balancer"
EXPOSURE_WILDCARD_HOST = "wildcard_host"
EXPOSURE_CATCH_ALL_ROUTE = "catch_all_route"
EXPOSURE_UNKNOWN = "unknown"

# Only these well-known, provider-neutral-but-explicitly-named annotation
# keys are ever read from a Service — never arbitrary annotations. Each
# means "this LoadBalancer is explicitly internal", a security-relevant
# fact that overrides the default "LoadBalancer type -> externally
# reachable" assumption.
SAFE_INTERNAL_LOAD_BALANCER_ANNOTATION_KEYS: frozenset[str] = frozenset(
    {
        "service.beta.kubernetes.io/aws-load-balancer-internal",
        "cloud.google.com/load-balancer-type",  # value "Internal" checked separately
        "service.beta.kubernetes.io/azure-load-balancer-internal",
    }
)

# Well-known sensitive/administrative ports — same convention as
# SENSITIVE_HOST_PORTS (message 2) plus common database/infra ports, since
# Services commonly front databases directly.
SENSITIVE_SERVICE_PORTS: frozenset[int] = frozenset(
    SENSITIVE_HOST_PORTS | {3306, 5432, 6379, 27017, 9200, 9300, 2181, 9092, 11211}
)

HOST_CATEGORY_EXACT = "exact"
HOST_CATEGORY_WILDCARD = "wildcard"
HOST_CATEGORY_HOSTLESS = "hostless"


def categorize_host(host: Optional[str]) -> str:
    if not host:
        return HOST_CATEGORY_HOSTLESS
    if host.startswith("*."):
        return HOST_CATEGORY_WILDCARD
    return HOST_CATEGORY_EXACT


# CIDR categories. The raw CIDR string IS stored (it is non-secret network
# configuration metadata, same policy as hostnames) but always alongside its
# category — never relied upon alone for severity.
CIDR_CATEGORY_PUBLIC_IPV4_UNRESTRICTED = "public_ipv4_unrestricted"
CIDR_CATEGORY_PUBLIC_IPV6_UNRESTRICTED = "public_ipv6_unrestricted"
CIDR_CATEGORY_PRIVATE = "private"
CIDR_CATEGORY_LOOPBACK = "loopback"
CIDR_CATEGORY_LINK_LOCAL = "link_local"
CIDR_CATEGORY_SINGLE_IP = "single_ip"
CIDR_CATEGORY_BROAD_PUBLIC_RANGE = "broad_public_range"
CIDR_CATEGORY_UNKNOWN_MALFORMED = "unknown_malformed"

_UNRESTRICTED_CIDR_CATEGORIES: frozenset[str] = frozenset(
    {CIDR_CATEGORY_PUBLIC_IPV4_UNRESTRICTED, CIDR_CATEGORY_PUBLIC_IPV6_UNRESTRICTED}
)
PUBLIC_CIDR_CATEGORIES: frozenset[str] = _UNRESTRICTED_CIDR_CATEGORIES | frozenset(
    {CIDR_CATEGORY_BROAD_PUBLIC_RANGE}
)


def categorize_cidr(cidr: Optional[str]) -> str:
    """Categorize an IPv4/IPv6 CIDR string using ``ipaddress`` — never
    assumes every non-private network is internet-routable in every
    environment; the wording used downstream is "public-address range" /
    "broad non-private CIDR", not a reachability claim."""
    if not cidr:
        return CIDR_CATEGORY_UNKNOWN_MALFORMED
    try:
        net = ipaddress.ip_network(cidr.strip(), strict=False)
    except ValueError:
        return CIDR_CATEGORY_UNKNOWN_MALFORMED
    if net.version == 4 and str(net) == "0.0.0.0/0":
        return CIDR_CATEGORY_PUBLIC_IPV4_UNRESTRICTED
    if net.version == 6 and str(net) == "::/0":
        return CIDR_CATEGORY_PUBLIC_IPV6_UNRESTRICTED
    if net.is_loopback:
        return CIDR_CATEGORY_LOOPBACK
    if net.is_link_local:
        return CIDR_CATEGORY_LINK_LOCAL
    if net.is_private:
        return CIDR_CATEGORY_PRIVATE
    if (net.version == 4 and net.prefixlen == 32) or (net.version == 6 and net.prefixlen == 128):
        return CIDR_CATEGORY_SINGLE_IP
    return CIDR_CATEGORY_BROAD_PUBLIC_RANGE


def is_public_cidr_category(category: str) -> bool:
    return category in PUBLIC_CIDR_CATEGORIES


def categorize_ip_address(value: Optional[str]) -> str:
    """Categorize a bare IP (e.g. a Gateway status address) — same
    vocabulary as ``categorize_cidr`` by treating it as a /32 or /128."""
    if not value:
        return CIDR_CATEGORY_UNKNOWN_MALFORMED
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        return CIDR_CATEGORY_UNKNOWN_MALFORMED
    if ip.is_loopback:
        return CIDR_CATEGORY_LOOPBACK
    if ip.is_link_local:
        return CIDR_CATEGORY_LINK_LOCAL
    if ip.is_private:
        return CIDR_CATEGORY_PRIVATE
    return CIDR_CATEGORY_BROAD_PUBLIC_RANGE


# Ingress/Gateway path-match categories.
PATH_CATEGORY_ROOT_PREFIX = "root_prefix"
PATH_CATEGORY_SPECIFIC = "specific"
PATH_CATEGORY_IMPLEMENTATION_SPECIFIC_CATCH_ALL = "implementation_specific_catch_all"


_CATCH_ALL_PATH_TYPES: frozenset[str] = frozenset(
    # Ingress (networking.k8s.io/v1): "Prefix", "ImplementationSpecific".
    # Gateway API (gateway.networking.k8s.io): "PathPrefix" — a distinct
    # vocabulary from Ingress's, both handled here since callers pass
    # either API's path type through the same helper.
    {"Prefix", "ImplementationSpecific", "PathPrefix", None}
)


def is_catch_all_path(path: Optional[str], path_type: Optional[str]) -> bool:
    """A Prefix/PathPrefix (or ImplementationSpecific) path of "/" or empty
    matches every request — a catch-all route, regardless of other rules.
    Handles both the Ingress and Gateway API path-type vocabularies."""
    normalized_path = path or "/"
    return normalized_path in ("", "/") and path_type in _CATCH_ALL_PATH_TYPES


def categorize_ingress_path(path: Optional[str], path_type: Optional[str]) -> str:
    if is_catch_all_path(path, path_type) and path_type == "ImplementationSpecific":
        return PATH_CATEGORY_IMPLEMENTATION_SPECIFIC_CATCH_ALL
    if is_catch_all_path(path, path_type):
        return PATH_CATEGORY_ROOT_PREFIX
    return PATH_CATEGORY_SPECIFIC


# Gateway API allowedRoutes / TLS / status categories.
ALLOWED_NAMESPACES_SAME = "Same"
ALLOWED_NAMESPACES_ALL = "All"
ALLOWED_NAMESPACES_SELECTOR = "Selector"
ALLOWED_NAMESPACES_UNKNOWN = "Unknown"

TLS_MODE_TERMINATE = "Terminate"
TLS_MODE_PASSTHROUGH = "Passthrough"
TLS_MODE_NONE = "none"

GATEWAY_API_STATUS_READY = "ready"
GATEWAY_API_STATUS_NOT_READY = "not_ready"
GATEWAY_API_STATUS_UNKNOWN = "unknown"

ROUTE_REFS_ALL_RESOLVED = "all_resolved"
ROUTE_REFS_SOME_UNRESOLVED = "some_unresolved"
ROUTE_REFS_UNKNOWN = "unknown"

GATEWAY_ADDRESS_EXTERNAL = "external"
GATEWAY_ADDRESS_INTERNAL = "internal"
GATEWAY_ADDRESS_UNKNOWN = "unknown"
GATEWAY_ADDRESS_UNASSIGNED = "unassigned"
GATEWAY_ADDRESS_DNS_HOSTNAME = "dns_hostname_unknown"


# NetworkPolicy semantics. "declared" fields distinguish an omitted field
# (attribute is None) from an explicit empty list ([]) — even though both
# currently produce the SAME effective behavior per the Kubernetes API
# (the apiserver treats them identically) — because a schema that erases
# this distinction could never support a future, more precise semantic if
# Kubernetes ever changes this, and it keeps message-4's own test suite
# honest about what was actually observed on the wire.
POLICY_COVERAGE_NONE = "none"
POLICY_COVERAGE_PARTIAL = "partial"
POLICY_COVERAGE_BROAD = "broad"
POLICY_COVERAGE_UNKNOWN = "unknown"


def rule_permits_everything(peers: Optional[list], ports: Optional[list]) -> bool:
    """True if an ingress/egress rule has no ``from``/``to`` peers AND no
    ``ports`` restriction — such a rule matches all sources/destinations on
    all ports, i.e. "allow all", regardless of any other rule present."""
    return not peers and not ports


def stable_fingerprint(*parts: object) -> str:
    """Deterministic, order-independent-where-noted hash used for every
    ``*_fingerprint`` field in this module. Callers pre-sort any
    unordered components before passing them in."""
    source = "|".join(str(p) for p in parts)
    return hashlib.sha256(source.encode("utf-8")).hexdigest()[:16]


# ── TypedDict schemas — message 4 (network exposure and isolation) ──────────


class KubernetesServiceRecord(TypedDict):
    record_type: str
    record_id: str
    cluster_id: str
    cluster_name: str
    namespace: str
    name: str
    uid: Optional[str]
    service_type: str
    cluster_ip_present: bool
    headless: bool
    external_ip_count: int
    load_balancer_ingress_count: int
    external_name_category: Optional[str]
    publish_not_ready_addresses: bool
    external_traffic_policy: Optional[str]
    internal_traffic_policy: Optional[str]
    session_affinity: Optional[str]
    ip_family_categories: list[str]
    ip_family_policy: Optional[str]
    selector_key_count: int
    selector_fingerprint: str
    internal_load_balancer_annotation_present: bool
    port_count: int
    exposure_category: str
    mixed_exposure_evidence: bool
    collection_completeness_category: str


class KubernetesServicePortRecord(TypedDict):
    record_type: str
    record_id: str
    cluster_id: str
    cluster_name: str
    namespace: str
    parent_service_record_id: str
    port_name: Optional[str]
    protocol: str
    port: int
    target_port_category: str
    node_port: Optional[int]
    app_protocol_category: Optional[str]
    sensitive_port: bool
    exposure_category: str


class KubernetesIngressRecord(TypedDict):
    record_type: str
    record_id: str
    cluster_id: str
    cluster_name: str
    namespace: str
    name: str
    uid: Optional[str]
    ingress_class: Optional[str]
    default_backend_present: bool
    rule_count: int
    host_count: int
    wildcard_host_count: int
    hostless_rule_present: bool
    tls_block_count: int
    tls_host_count: int
    tls_secret_reference_count: int
    http_path_count: int
    backend_service_count: int
    cross_namespace_backend_count: int
    path_type_categories: list[str]
    plaintext_exposure_category: str
    public_exposure_category: str
    load_balancer_ingress_count: int
    collection_completeness_category: str


class KubernetesIngressRuleRecord(TypedDict):
    record_type: str
    record_id: str
    cluster_id: str
    cluster_name: str
    namespace: str
    parent_ingress_record_id: str
    host_category: str
    hostname: Optional[str]
    path_category: str
    path_type: Optional[str]
    backend_service_name: Optional[str]
    backend_port: Optional[int]
    tls_covered: bool
    public_exposure_category: str
    catch_all_route: bool
    default_backend: bool
    route_fingerprint: str


class KubernetesGatewayRecord(TypedDict):
    record_type: str
    record_id: str
    cluster_id: str
    cluster_name: str
    namespace: str
    name: str
    uid: Optional[str]
    gateway_class_name: Optional[str]
    listener_count: int
    attached_route_count: Optional[int]
    address_count: int
    public_address_category: str
    listener_protocol_categories: list[str]
    http_listener_count: int
    https_listener_count: int
    tls_listener_count: int
    wildcard_hostname_count: int
    allowed_routes_category: str
    cross_namespace_route_allowance: bool
    tls_certificate_reference_count: int
    status_category: str
    collection_completeness_category: str


class KubernetesGatewayListenerRecord(TypedDict):
    record_type: str
    record_id: str
    cluster_id: str
    cluster_name: str
    namespace: str
    parent_gateway_record_id: str
    listener_name: str
    protocol: str
    port: int
    hostname_category: str
    tls_mode: str
    certificate_reference_count: int
    allowed_namespace_policy: str
    public_exposure_category: str
    listener_fingerprint: str


class KubernetesHttpRouteRecord(TypedDict):
    record_type: str
    record_id: str
    cluster_id: str
    cluster_name: str
    namespace: str
    name: str
    uid: Optional[str]
    parent_ref_count: int
    cross_namespace_parent_count: int
    hostname_count: int
    wildcard_hostname_count: int
    rule_count: int
    backend_ref_count: int
    cross_namespace_backend_count: int
    path_match_categories: list[str]
    method_match_present: bool
    header_match_present: bool
    query_match_present: bool
    filter_categories: list[str]
    redirect_present: bool
    rewrite_present: bool
    timeout_configured_present: bool
    resolved_refs_status: str
    route_fingerprint: str
    collection_completeness_category: str


class KubernetesHttpRouteRuleRecord(TypedDict):
    record_type: str
    record_id: str
    cluster_id: str
    cluster_name: str
    namespace: str
    parent_route_record_id: str
    match_categories: list[str]
    catch_all_path: bool
    backend_count: int
    backend_namespace_count: int
    cross_namespace_backend: bool
    redirect_present: bool
    rewrite_present: bool
    mirror_present: bool
    route_fingerprint: str


class KubernetesNetworkPolicyRecord(TypedDict):
    record_type: str
    record_id: str
    cluster_id: str
    cluster_name: str
    namespace: str
    name: str
    uid: Optional[str]
    pod_selector_empty_all_pods: bool
    selected_label_key_count: int
    policy_types: list[str]
    ingress_rule_count: int
    egress_rule_count: int
    ingress_isolation_enabled: bool
    egress_isolation_enabled: bool
    ingress_rules_declared: bool
    egress_rules_declared: bool
    empty_ingress_list: bool
    empty_egress_list: bool
    allows_all_ingress: bool
    allows_all_egress: bool
    public_ipv4_cidr_allowed: bool
    public_ipv6_cidr_allowed: bool
    broad_cidr_count: int
    namespace_selector_present: bool
    pod_selector_present: bool
    ip_block_present: bool
    except_cidr_count: int
    port_restriction_present: bool
    protocol_categories: list[str]
    selector_fingerprint: str
    policy_fingerprint: str
    collection_completeness_category: str


class KubernetesNamespaceNetworkPostureRecord(TypedDict):
    record_type: str
    record_id: str
    cluster_id: str
    cluster_name: str
    namespace: str
    policy_count: int
    has_any_network_policy: bool
    ingress_isolation_present: bool
    egress_isolation_present: bool
    all_pod_ingress_default_deny: bool
    all_pod_egress_default_deny: bool
    policy_coverage_category: str
    public_ingress_allowance_present: bool
    public_egress_allowance_present: bool
    broad_namespace_selector_allowance: bool
    broad_pod_selector_allowance: bool
    collection_completeness_category: str


# ── Admission control / configuration governance vocabulary — message 5 ─────

FAILURE_POLICY_FAIL = "Fail"
FAILURE_POLICY_IGNORE = "Ignore"
FAILURE_POLICY_UNKNOWN = "unknown"

MATCH_POLICY_EXACT = "Exact"
MATCH_POLICY_EQUIVALENT = "Equivalent"
MATCH_POLICY_UNKNOWN = "unknown"

SIDE_EFFECTS_NONE = "None"
SIDE_EFFECTS_NONE_ON_DRY_RUN = "NoneOnDryRun"
SIDE_EFFECTS_SOME = "Some"
SIDE_EFFECTS_UNKNOWN = "Unknown"

REINVOCATION_NEVER = "Never"
REINVOCATION_IF_NEEDED = "IfNeeded"
REINVOCATION_UNKNOWN = "unknown"

CLIENT_TYPE_SERVICE = "service"
CLIENT_TYPE_URL = "url"
CLIENT_TYPE_UNKNOWN = "unknown"

SCOPE_CLUSTER = "Cluster"
SCOPE_NAMESPACED = "Namespaced"
SCOPE_ALL = "all_scopes"
SCOPE_UNKNOWN = "unknown"

SELECTOR_ABSENT = "absent"
SELECTOR_EMPTY_ALL = "empty_all"
SELECTOR_NARROW = "narrow"
SELECTOR_MALFORMED = "malformed"

WEBHOOK_SECURITY_POSTURE_FAIL_CLOSED_NARROW = "fail_closed_narrow"
WEBHOOK_SECURITY_POSTURE_FAIL_CLOSED_BROAD = "fail_closed_broad"
WEBHOOK_SECURITY_POSTURE_FAIL_OPEN = "fail_open"
WEBHOOK_SECURITY_POSTURE_MIXED = "mixed"
WEBHOOK_SECURITY_POSTURE_UNKNOWN = "unknown"

# Only these well-known, fixed selector label keys are ever inspected on a
# webhook namespaceSelector/objectSelector matchLabels map — never
# arbitrary business labels. Values are never read, only whether the KEY
# is one of these.
SAFE_WEBHOOK_SELECTOR_LABEL_KEYS: frozenset[str] = frozenset(
    {
        "kubernetes.io/metadata.name",
        PSA_LABEL_ENFORCE, PSA_LABEL_ENFORCE_VERSION,
        PSA_LABEL_AUDIT, PSA_LABEL_AUDIT_VERSION,
        PSA_LABEL_WARN, PSA_LABEL_WARN_VERSION,
    }
)


def categorize_failure_policy(value: Optional[str]) -> str:
    return value if value in (FAILURE_POLICY_FAIL, FAILURE_POLICY_IGNORE) else FAILURE_POLICY_UNKNOWN


def categorize_match_policy(value: Optional[str]) -> str:
    return value if value in (MATCH_POLICY_EXACT, MATCH_POLICY_EQUIVALENT) else MATCH_POLICY_UNKNOWN


def categorize_side_effects(value: Optional[str]) -> str:
    return value if value in (SIDE_EFFECTS_NONE, SIDE_EFFECTS_NONE_ON_DRY_RUN, SIDE_EFFECTS_SOME, SIDE_EFFECTS_UNKNOWN) else SIDE_EFFECTS_UNKNOWN


def categorize_reinvocation_policy(value: Optional[str]) -> str:
    return value if value in (REINVOCATION_NEVER, REINVOCATION_IF_NEEDED) else REINVOCATION_UNKNOWN


def categorize_admission_scope(value: Optional[str]) -> str:
    if value == "*":
        return SCOPE_ALL
    if value in (SCOPE_CLUSTER, SCOPE_NAMESPACED):
        return value
    return SCOPE_UNKNOWN


def categorize_selector_presence(
    match_labels: Optional[dict], match_expressions: Optional[list], *, present: bool,
) -> dict:
    """Categorize a namespaceSelector/objectSelector without ever storing
    arbitrary label values. Returns a dict of category/counts/fingerprint/
    allowlisted-key-category — never the label values themselves."""
    if not present:
        return {
            "category": SELECTOR_ABSENT, "match_labels_count": 0, "match_expressions_count": 0,
            "fingerprint": stable_fingerprint("absent"), "allowlisted_key_category": False,
        }
    ml = match_labels or {}
    me = match_expressions or []
    if not ml and not me:
        category = SELECTOR_EMPTY_ALL
    else:
        category = SELECTOR_NARROW
    allowlisted = bool(ml) and all(k in SAFE_WEBHOOK_SELECTOR_LABEL_KEYS for k in ml)
    fingerprint = stable_fingerprint(category, sorted(ml.keys()), len(me))
    return {
        "category": category, "match_labels_count": len(ml), "match_expressions_count": len(me),
        "fingerprint": fingerprint, "allowlisted_key_category": allowlisted,
    }


# PSA posture vocabulary. Reuses the six exact label keys already defined
# above (PSA_LABEL_*) — no new label keys are ever read.
PSA_ENFORCE_CATEGORY_PRIVILEGED = "privileged"
PSA_ENFORCE_CATEGORY_BASELINE = "baseline"
PSA_ENFORCE_CATEGORY_RESTRICTED = "restricted"
PSA_ENFORCE_CATEGORY_UNSET = "unset"
PSA_ENFORCE_CATEGORY_INVALID = "invalid"

PSA_LEVEL_RANK: dict[str, int] = {
    PSA_ENFORCE_CATEGORY_PRIVILEGED: 0,
    PSA_ENFORCE_CATEGORY_BASELINE: 1,
    PSA_ENFORCE_CATEGORY_RESTRICTED: 2,
}

PSA_VERSION_LATEST = "latest"
PSA_VERSION_PINNED_CURRENT = "pinned_current"
PSA_VERSION_PINNED_OLD = "pinned_old"
PSA_VERSION_UNSET = "unset"
PSA_VERSION_INVALID = "invalid"

NAMESPACE_CATEGORY_SYSTEM = "system"
NAMESPACE_CATEGORY_DEFAULT = "default"
NAMESPACE_CATEGORY_USER = "user"

_SYSTEM_NAMESPACES: frozenset[str] = frozenset({"kube-system", "kube-public", "kube-node-lease"})


def categorize_psa_level(value: Optional[str]) -> str:
    if value is None:
        return PSA_ENFORCE_CATEGORY_UNSET
    if value in PSA_LEVEL_RANK:
        return value
    return PSA_ENFORCE_CATEGORY_INVALID


def _parse_minor_version(value: Optional[str]) -> Optional[tuple[int, int]]:
    if not value:
        return None
    stripped = value.strip().lstrip("v")
    parts = stripped.split(".")
    if len(parts) < 2:
        return None
    try:
        return int(parts[0]), int(parts[1])
    except ValueError:
        return None


def categorize_psa_version(value: Optional[str], cluster_major_minor: Optional[str] = None) -> str:
    """Categorize a PSA `*-version` label. "pinned_old" requires the
    cluster's own major.minor version for comparison (>= 3 minor versions
    behind); without that context a pinned version is just "pinned_current"
    — never guessed as old without evidence."""
    if not value:
        return PSA_VERSION_UNSET
    if value == "latest":
        return PSA_VERSION_LATEST
    parsed = _parse_minor_version(value)
    if parsed is None:
        return PSA_VERSION_INVALID
    cluster_parsed = _parse_minor_version(cluster_major_minor) if cluster_major_minor else None
    if cluster_parsed is not None and cluster_parsed[0] == parsed[0] and (cluster_parsed[1] - parsed[1]) >= 3:
        return PSA_VERSION_PINNED_OLD
    return PSA_VERSION_PINNED_CURRENT


def categorize_namespace_context(name: Optional[str]) -> str:
    if name in _SYSTEM_NAMESPACES:
        return NAMESPACE_CATEGORY_SYSTEM
    if name == "default":
        return NAMESPACE_CATEGORY_DEFAULT
    return NAMESPACE_CATEGORY_USER


# ResourceQuota / LimitRange coverage categories reuse the same
# none/partial/broad/unknown vocabulary as NetworkPolicy namespace
# coverage (POLICY_COVERAGE_*) — same meaning, different control family.
LIMIT_RANGE_TYPE_POD = "Pod"
LIMIT_RANGE_TYPE_CONTAINER = "Container"
LIMIT_RANGE_TYPE_PVC = "PersistentVolumeClaim"

# Kubernetes hard-limit keys this connector normalizes into named fields
# (never an arbitrary passthrough dict).
_QUOTA_CPU_KEYS = ("cpu", "limits.cpu")
_QUOTA_CPU_REQUEST_KEYS = ("requests.cpu",)
_QUOTA_MEMORY_KEYS = ("memory", "limits.memory")
_QUOTA_MEMORY_REQUEST_KEYS = ("requests.memory",)


def _quantity_present(hard: dict, keys: tuple[str, ...]) -> bool:
    return any(k in hard for k in keys)


# ── Kubernetes resource-quantity parsing ──────────────────────────────────────
# Deterministic, float-free. CPU normalizes to millicores; memory/storage/
# ephemeral-storage normalize to bytes. Malformed input -> None ("unknown"),
# never coerced to zero. Exact zero ("0") is preserved as 0, distinct from
# None (missing/malformed).

_MEMORY_BINARY_SUFFIXES: dict[str, int] = {
    "Ki": 2**10, "Mi": 2**20, "Gi": 2**30, "Ti": 2**40, "Pi": 2**50, "Ei": 2**60,
}
_MEMORY_DECIMAL_SUFFIXES: dict[str, int] = {
    "k": 10**3, "M": 10**6, "G": 10**9, "T": 10**12, "P": 10**15, "E": 10**18,
}


def parse_cpu_quantity_millicores(value: Optional[str]) -> Optional[int]:
    """Parse a Kubernetes CPU quantity (e.g. "500m", "2", "1.5") into an
    integer millicore count. Returns None for malformed input — never 0."""
    if value is None:
        return None
    s = str(value).strip()
    if not s:
        return None
    try:
        if s.endswith("m"):
            return int(Decimal(s[:-1]))
        return int(Decimal(s) * 1000)
    except (InvalidOperation, ValueError):
        return None


def parse_memory_quantity_bytes(value: Optional[str]) -> Optional[int]:
    """Parse a Kubernetes memory/storage quantity (e.g. "128Mi", "1Gi",
    "500M", "1000000") into an integer byte count. Returns None for
    malformed input — never 0."""
    if value is None:
        return None
    s = str(value).strip()
    if not s:
        return None
    for suffix, multiplier in _MEMORY_BINARY_SUFFIXES.items():
        if s.endswith(suffix):
            try:
                return int(Decimal(s[: -len(suffix)]) * multiplier)
            except (InvalidOperation, ValueError):
                return None
    for suffix, multiplier in _MEMORY_DECIMAL_SUFFIXES.items():
        if s.endswith(suffix):
            try:
                return int(Decimal(s[: -len(suffix)]) * multiplier)
            except (InvalidOperation, ValueError):
                return None
    try:
        return int(Decimal(s))
    except (InvalidOperation, ValueError):
        return None


# ── TypedDict schemas — message 5 (admission control / governance) ──────────


class KubernetesWebhookConfigurationRecord(TypedDict):
    """Shared shape for kubernetes_validating_webhook_configuration /
    kubernetes_mutating_webhook_configuration."""

    record_type: str
    record_id: str
    cluster_id: str
    cluster_name: str
    name: str
    uid: Optional[str]
    kind: str
    webhook_count: int
    admission_review_version_categories: list[str]
    fail_open_webhook_count: int
    fail_closed_webhook_count: int
    no_side_effects_webhook_count: int
    unknown_side_effects_webhook_count: int
    namespace_selector_present_count: int
    object_selector_present_count: int
    external_url_client_count: int
    in_cluster_service_client_count: int
    ca_bundle_present_count: int
    timeout_seconds_min: Optional[int]
    timeout_seconds_max: Optional[int]
    match_policy_categories: list[str]
    reinvocation_policy_categories: list[str]
    security_posture_summary: str
    configuration_fingerprint: str
    collection_completeness_category: str


class KubernetesWebhookRecord(TypedDict):
    """Shared shape for kubernetes_validating_webhook / kubernetes_mutating_webhook."""

    record_type: str
    record_id: str
    cluster_id: str
    cluster_name: str
    parent_configuration_record_id: str
    webhook_name: str
    webhook_type: str
    client_type: str
    service_namespace: Optional[str]
    service_name: Optional[str]
    service_path_category: Optional[str]
    service_port: Optional[int]
    external_url_host_category: Optional[str]
    plaintext_http_client: bool
    failure_policy: str
    match_policy: str
    side_effects: str
    timeout_seconds: Optional[int]
    namespace_selector_category: str
    object_selector_category: str
    rules_count: int
    operation_categories: list[str]
    api_group_categories: list[str]
    api_version_categories: list[str]
    resource_categories: list[str]
    scope_category: str
    admission_review_versions: list[str]
    ca_bundle_present: bool
    reinvocation_policy: Optional[str]
    wildcard_operation: bool
    wildcard_api_group: bool
    wildcard_api_version: bool
    wildcard_resource: bool
    webhook_fingerprint: str
    collection_completeness_category: str


class KubernetesPodSecurityAdmissionRecord(TypedDict):
    record_type: str
    record_id: str
    cluster_id: str
    cluster_name: str
    namespace: str
    enforce_level: str
    enforce_version_category: str
    audit_level: str
    audit_version_category: str
    warn_level: str
    warn_version_category: str
    effective_posture_category: str
    enforcement_enabled: bool
    audit_enabled: bool
    warning_enabled: bool
    enforcement_weaker_than_audit: bool
    enforcement_weaker_than_warning: bool
    namespace_context_category: str
    posture_fingerprint: str
    collection_completeness_category: str


class KubernetesResourceQuotaRecord(TypedDict):
    record_type: str
    record_id: str
    cluster_id: str
    cluster_name: str
    namespace: str
    name: str
    uid: Optional[str]
    hard_limit_key_count: int
    hard_cpu_limit_present: bool
    hard_cpu_limit_millicores: Optional[int]
    hard_memory_limit_present: bool
    hard_memory_limit_bytes: Optional[int]
    request_cpu_limit_present: bool
    request_cpu_limit_millicores: Optional[int]
    request_memory_limit_present: bool
    request_memory_limit_bytes: Optional[int]
    pod_count_limit_present: bool
    pod_count_limit: Optional[int]
    service_count_limit_present: bool
    load_balancer_count_limit_present: bool
    pvc_count_limit_present: bool
    storage_request_limit_present: bool
    ephemeral_storage_limit_present: bool
    secret_count_limit_present: bool
    configmap_count_limit_present: bool
    scope_categories: list[str]
    scope_selector_present: bool
    resource_control_coverage_category: str
    quota_fingerprint: str
    collection_completeness_category: str


class KubernetesLimitRangeRecord(TypedDict):
    record_type: str
    record_id: str
    cluster_id: str
    cluster_name: str
    namespace: str
    name: str
    uid: Optional[str]
    item_count: int
    container_default_present: bool
    container_default_request_present: bool
    pod_max_present: bool
    pod_min_present: bool
    container_max_present: bool
    container_min_present: bool
    pvc_min_present: bool
    pvc_max_present: bool
    request_to_limit_ratio_present: bool
    cpu_policy_coverage_category: str
    memory_policy_coverage_category: str
    ephemeral_storage_policy_coverage_category: str
    defaulting_coverage_category: str
    limit_fingerprint: str
    collection_completeness_category: str


class KubernetesNamespaceGovernancePostureRecord(TypedDict):
    record_type: str
    record_id: str
    cluster_id: str
    cluster_name: str
    namespace: str
    psa_enforcement_category: str
    validating_webhook_coverage_category: str
    mutating_webhook_coverage_category: str
    resource_quota_count: int
    limit_range_count: int
    quota_coverage_category: str
    default_resource_control_category: str
    network_policy_coverage_category: str
    privileged_workload_present: bool
    high_privilege_service_account_present: bool
    governance_completeness_category: str
    governance_risk_summary: str
