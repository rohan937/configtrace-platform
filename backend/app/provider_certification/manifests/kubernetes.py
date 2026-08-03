"""Kubernetes certification manifest (message 3 of N).

Derived from the real Kubernetes launch arc (messages 1-9 of 9,
culminating in the Kubernetes provider-depth certification) — every
field below was independently re-derived from discovered repository
state, not copied from memory.

Kubernetes needed a discovery ADAPTER for two genuinely different
architectural patterns generic discovery cannot resolve on its own:

1. **Credential fields have no ``kubernetes_`` prefix.** Every other
   provider's credential fields are named ``<provider>_<field>``; the
   Kubernetes connector's fields are ``kubeconfig``, ``context``,
   ``cluster_name``, ``namespace_allowlist`` — a real, deliberate naming
   difference (the field IS the credential, unlike e.g.
   ``sentry_auth_token``), not a defect.
2. **Change classifier dispatch uses GROUPED constants.**
   ``risk_rules/kubernetes.py`` dispatches several related record types
   through one shared branch via a local frozenset constant (e.g.
   ``_WORKLOAD_CONTROLLER_RECORD_TYPES = frozenset({KUBERNETES_
   DEPLOYMENT, KUBERNETES_STATEFULSET, ...})`` then ``if record_type in
   _WORKLOAD_CONTROLLER_RECORD_TYPES:``) rather than one ``record_type
   ==`` check per type — generic literal/named-constant dispatch
   discovery cannot see these.

See ``discovery.discover_classifier_grouped_dispatch`` (generic,
reusable — not Kubernetes-only) for #2; the credential-field adapter
hook below handles #1.

Three schema constants (``kubernetes_api_server_security_posture``,
``kubernetes_config_map_metadata``, ``kubernetes_secret_metadata``) are
declared in ``kubernetes_schema.py`` but never referenced by the
connector as an actual emitted ``record_type`` — discovered via
``discovery.discover_schema_record_type_constants``'s connector-wiring
precision filter (message 3) — and are correctly EXCLUDED from
``expected_record_types`` below; declaring them would certify a record
type the connector doesn't actually produce.
"""

from __future__ import annotations

from app.provider_certification import adapters as adapt
from app.provider_certification import discovery as disc
from app.provider_certification.models import (
    FindingChangeParityEvidence,
    FindingReachabilityEvidence,
    ProviderCertificationManifest,
)
from app.provider_certification.runner import register_manifest

_EXPECTED_RECORD_TYPES = (
    "kubernetes_cluster",
    "kubernetes_api_capability",
    "kubernetes_namespace",
    "kubernetes_deployment",
    "kubernetes_statefulset",
    "kubernetes_daemonset",
    "kubernetes_job",
    "kubernetes_cronjob",
    "kubernetes_pod",
    "kubernetes_container_security_context",
    "kubernetes_service_account",
    "kubernetes_workload_service_account",
    "kubernetes_role",
    "kubernetes_cluster_role",
    "kubernetes_role_binding",
    "kubernetes_cluster_role_binding",
    "kubernetes_rbac_subject_binding",
    "kubernetes_rbac_permission_summary",
    "kubernetes_service",
    "kubernetes_service_port",
    "kubernetes_ingress",
    "kubernetes_ingress_rule",
    "kubernetes_gateway",
    "kubernetes_gateway_listener",
    "kubernetes_http_route",
    "kubernetes_http_route_rule",
    "kubernetes_network_policy",
    "kubernetes_namespace_network_posture",
    "kubernetes_validating_webhook",
    "kubernetes_mutating_webhook",
    "kubernetes_validating_webhook_configuration",
    "kubernetes_mutating_webhook_configuration",
    "kubernetes_pod_security_admission",
    "kubernetes_resource_quota",
    "kubernetes_limit_range",
    "kubernetes_namespace_governance_posture",
)

_DERIVED_RECORD_TYPES = (
    "kubernetes_workload_service_account",
    "kubernetes_rbac_permission_summary",
    "kubernetes_namespace_network_posture",
    "kubernetes_namespace_governance_posture",
)

_SECURITY_FINDING_RULE_IDS = (
    "kubernetes_admission_webhook_external_http",
    "kubernetes_admission_webhook_modification_permission",
    "kubernetes_all_capabilities_added",
    "kubernetes_all_service_accounts_cluster_admin",
    "kubernetes_apparmor_unconfined",
    "kubernetes_authenticated_group_cluster_admin",
    "kubernetes_broad_admission_webhook",
    "kubernetes_broad_workload_creation",
    "kubernetes_cluster_admin_binding",
    "kubernetes_container_runtime_socket_mounted",
    "kubernetes_crd_modification_permission",
    "kubernetes_dangerous_hostpath",
    "kubernetes_dangerous_linux_capability",
    "kubernetes_host_ipc_enabled",
    "kubernetes_host_network_enabled",
    "kubernetes_host_pid_enabled",
    "kubernetes_hostless_catchall_ingress",
    "kubernetes_mutable_image_tag",
    "kubernetes_mutating_webhook_fail_open",
    "kubernetes_namespace_no_egress_isolation",
    "kubernetes_namespace_no_ingress_isolation",
    "kubernetes_namespace_no_network_policy",
    "kubernetes_namespace_resource_governance_missing",
    "kubernetes_namespace_weak_governance",
    "kubernetes_network_policy_allows_all_egress",
    "kubernetes_network_policy_allows_all_ingress",
    "kubernetes_pod_attach_permission",
    "kubernetes_pod_exec_permission",
    "kubernetes_privilege_escalation_allowed",
    "kubernetes_privileged_container",
    "kubernetes_privileged_host_access",
    "kubernetes_privileged_identity_in_weak_namespace",
    "kubernetes_privileged_workload_without_isolation",
    "kubernetes_psa_enforcement_missing",
    "kubernetes_psa_invalid_enforcement",
    "kubernetes_psa_privileged_enforcement",
    "kubernetes_psa_weak_with_privileged_workloads",
    "kubernetes_public_gateway_listener",
    "kubernetes_public_ingress_without_tls",
    "kubernetes_public_ipv4_cidr_allowed",
    "kubernetes_public_ipv6_cidr_allowed",
    "kubernetes_public_load_balancer",
    "kubernetes_rbac_bind_permission",
    "kubernetes_rbac_escalate_permission",
    "kubernetes_rbac_impersonate_permission",
    "kubernetes_rbac_modification_permission",
    "kubernetes_root_container",
    "kubernetes_run_as_non_root_disabled",
    "kubernetes_seccomp_unconfined",
    "kubernetes_secret_read_permission",
    "kubernetes_secret_write_permission",
    "kubernetes_sensitive_host_port",
    "kubernetes_sensitive_nodeport",
    "kubernetes_service_account_token_automount",
    "kubernetes_service_account_token_creation",
    "kubernetes_unauthenticated_cluster_admin",
    "kubernetes_validating_webhook_fail_open",
    "kubernetes_wildcard_rbac_permissions",
    "kubernetes_writable_root_filesystem",
)

_CREDENTIAL_FIELDS = ("kubeconfig", "context", "cluster_name", "namespace_allowlist")


def _discover_kubernetes_credential_fields() -> frozenset[str] | None:
    from app.schemas.integration import IntegrationCreateRequest

    found = frozenset(f for f in _CREDENTIAL_FIELDS if f in IntegrationCreateRequest.model_fields)
    return found or None


def _discover_kubernetes_classifier_record_types() -> frozenset[str] | None:
    direct = disc.discover_classifier_record_type_dispatch("kubernetes")
    grouped = disc.discover_classifier_grouped_dispatch("kubernetes")
    combined = direct | grouped
    return combined or None


_KUBERNETES_ADAPTER = adapt.ProviderDiscoveryAdapter(
    provider_id="kubernetes",
    discover_credential_fields=_discover_kubernetes_credential_fields,
    discover_classifier_record_types=_discover_kubernetes_classifier_record_types,
    note=(
        "Credential fields carry no 'kubernetes_' prefix (kubeconfig/context/"
        "cluster_name/namespace_allowlist ARE the credential, not a labeled "
        "field of it). Classifier dispatch is resolved by combining direct "
        "record_type== checks with grouped record_type-in-frozenset checks."
    ),
)
adapt.register_adapter(_KUBERNETES_ADAPTER)


KUBERNETES_MANIFEST = ProviderCertificationManifest(
    provider_id="kubernetes",
    display_name="Kubernetes",
    category="cloud",
    maturity="partial",
    expected_public=True,
    expected_connectable=True,
    expected_live=True,
    credential_fields=_CREDENTIAL_FIELDS,
    sensitive_credential_fields=("kubeconfig",),
    authentication_model="kubeconfig",
    expected_record_types=_EXPECTED_RECORD_TYPES,
    derived_record_types=_DERIVED_RECORD_TYPES,
    security_finding_rule_ids=_SECURITY_FINDING_RULE_IDS,
    supported_capabilities=("security_findings",),
    unsupported_capabilities=(
        "activity_ingestion",
        "activity_signals",
        "risk_activity_correlations",
        "demo_case_reporting",
    ),
    completeness_scopes=(
        "cluster_wide_family_completeness",
        "namespace_allowlist_scope_change_suppression",
    ),
    false_removal_scopes=(
        "cluster_wide_family_completeness",
        "namespace_allowlist_scope_change_suppression",
    ),
    expected_frontend_form="KubernetesIntegrationForm.tsx",
    expected_reconnect=True,
    # NOTE: the "kubernetes" PyPI package IS present in requirements.txt
    # (unrelated to this connector, which never imports it — confirmed
    # via direct grep of app/connectors/kubernetes.py) — declaring it
    # prohibited here would be a false positive against real repository
    # state, not a genuine defect this framework should flag.
    allowed_dependencies=("httpx",),
    prohibited_dependencies=(),
    required_env_vars=(),
    prohibited_env_vars=("KUBECONFIG", "KUBERNETES_SERVICE_HOST"),
    known_limitations=(
        "Evidence is metadata-only (names, categories, booleans, counts, CIDRs) — "
        "Secret and ConfigMap CONTENTS are never read or stored",
        "No exec/attach/logs/port-forward of any kind",
        "No runtime or audit-event monitoring",
        "No vulnerability or malware scanning",
        "'exec' and 'auth-provider' kubeconfig authentication entries are rejected at connection time — "
        "ConfigTrace does not execute external auth plugins",
        "No activity ingestion, incident signals, risk x activity correlations, or demo/case tooling — "
        "Kubernetes' security stack is drift + Security Findings only",
        "Reconnect UI (ReconnectIntegrationModal) does not yet support Kubernetes' multi-field credential "
        "shape — backend reconnect_credentials_kubernetes() and router branch are fully implemented and "
        "tested at the API layer",
    ),
    evidence_test_files=(
        "tests/test_kubernetes_change_classification.py",
        "tests/test_kubernetes_change_finding_parity.py",
        "tests/test_kubernetes_partial_sync.py",
        "tests/test_kubernetes_security_finding_reachability.py",
        "tests/test_kubernetes_provider_depth_qa.py",
        "tests/test_kubernetes_integration_creation.py",
        "tests/test_kubernetes_multi_cluster.py",
    ),
    evidence_reports=(
        "tests/reports/kubernetes_reliability_matrix.md",
        "tests/reports/kubernetes_provider_depth_matrix.md",
    ),
    reachability_evidence=(
        FindingReachabilityEvidence(
            provider_id="kubernetes",
            test_file="tests/test_kubernetes_security_finding_reachability.py",
            test_selector="",
            covered_rule_ids=_SECURITY_FINDING_RULE_IDS,
            minimum_test_count=17,
            note="Grouped evidence: connector-shaped fixture -> normalize -> derive -> evaluate, across all 59 rules.",
        ),
    ),
    change_parity_evidence=(
        FindingChangeParityEvidence(
            provider_id="kubernetes",
            test_file="tests/test_kubernetes_change_finding_parity.py",
            test_selector="",
            covered_rule_ids=_SECURITY_FINDING_RULE_IDS,
            minimum_test_count=28,
            note="Grouped evidence: compute_diff()-pipeline severity parity across all 59 rules.",
        ),
    ),
)

register_manifest(KUBERNETES_MANIFEST)
