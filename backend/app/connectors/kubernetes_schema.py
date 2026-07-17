"""Kubernetes connector schema — foundation (message 1 of a 9-message arc).

This module defines the full planned record-type taxonomy for the
Kubernetes provider, but only the first three types are actually emitted by
``KubernetesConnector.fetch()`` in this message. The remaining types are
reserved names for later messages so downstream code (diff tracking, risk
classification, Security Findings) can be built incrementally against a
stable taxonomy without renaming record types mid-arc.

Emitted in message 1
---------------------
``kubernetes_cluster``        — one record per connected cluster.
``kubernetes_namespace``      — one record per visible namespace.
``kubernetes_api_capability``  — one record per discovered API resource type.

Planned for later messages (message 2 — workloads)
----------------------------------------------------
``kubernetes_deployment``, ``kubernetes_statefulset``, ``kubernetes_daemonset``,
``kubernetes_job``, ``kubernetes_cronjob``, ``kubernetes_pod``,
``kubernetes_container_security_context``, ``kubernetes_workload_service_account``.

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

# ── Record type constants — reserved for later messages (not yet emitted) ───
# These names are fixed now so that later messages never need to rename a
# record type after Changes/Findings have already been built against it.

KUBERNETES_DEPLOYMENT = "kubernetes_deployment"
KUBERNETES_STATEFULSET = "kubernetes_statefulset"
KUBERNETES_DAEMONSET = "kubernetes_daemonset"
KUBERNETES_JOB = "kubernetes_job"
KUBERNETES_CRONJOB = "kubernetes_cronjob"
KUBERNETES_POD = "kubernetes_pod"
KUBERNETES_CONTAINER_SECURITY_CONTEXT = "kubernetes_container_security_context"
KUBERNETES_WORKLOAD_SERVICE_ACCOUNT = "kubernetes_workload_service_account"

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
        KUBERNETES_DEPLOYMENT, KUBERNETES_STATEFULSET, KUBERNETES_DAEMONSET,
        KUBERNETES_JOB, KUBERNETES_CRONJOB, KUBERNETES_POD,
        KUBERNETES_CONTAINER_SECURITY_CONTEXT, KUBERNETES_WORKLOAD_SERVICE_ACCOUNT,
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
    KUBERNETES_FOUNDATION_RECORD_TYPES | KUBERNETES_PLANNED_RECORD_TYPES
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
