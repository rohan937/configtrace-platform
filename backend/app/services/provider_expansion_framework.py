"""Dual-stack provider expansion framework (M76).

Defines the canonical 6-stage template every future ConfigTrace provider
must follow:

  Stage 1 — drift_foundation       Connector + schema + sync + snapshot + diff + risk.
  Stage 2 — security_foundation    Security rules + rule registry + confidence + catalog.
  Stage 3 — activity_ingestion     Activity event ingestion + metadata allowlist.
  Stage 4 — activity_signals       Incident Signals generated from activity events.
  Stage 5 — risk_activity_correlations  Risk × activity evidence correlations.
  Stage 6 — demo_qa                Demo seed/clear/status + case/report/timeline/graph.

This module is READ-ONLY metadata — it never evaluates live state, never
calls external APIs, never changes DB records. Its purpose is to be the
single source of truth for the repeatable onboarding path so copy-paste
drift between providers is minimized.

CLAIM DISCIPLINE: all copy uses "evidence for review", "may require review",
"may affect operations", "does not confirm" — never "secure", "safe",
"breach-free", or "confirmed incident".

Privacy: the framework contains no customer data, no credentials, no secrets,
no API keys, no tokens, and no per-workspace state. Fully static.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


# ── Canonical forbidden claim phrases ────────────────────────────────────────
# Must be enforced in every provider's connector, service, schema, and UI copy.
FORBIDDEN_CLAIM_PHRASES: tuple[str, ...] = (
    "compromise confirmed",
    "secret leaked",
    "data leaked",
    "customer data leaked",
    "payment fraud detected",
    "attacker found",
    "someone has access",
    "unauthorized access confirmed",
    "breach detected",
    "attack detected",
    "orders exposed",
    "card data exposed",
)

# Canonical safe framing phrases every provider must use instead.
REQUIRED_SAFE_PHRASES: tuple[str, ...] = (
    "evidence for review",
    "may require review",
    "may affect operations",
    "does not confirm",
    "review window",
)

# ── Privacy requirements (universal across all stages) ───────────────────────
UNIVERSAL_PRIVACY_REQUIREMENTS: tuple[str, ...] = (
    "no_raw_payloads",
    "no_secrets_or_tokens",
    "no_auth_headers",
    "no_request_response_bodies",
    "no_customer_pii_unless_safe",
    "no_payment_card_bank_data",
    "no_message_or_email_body_content",
    "no_private_staff_identity_unless_safe",
    "strict_metadata_allowlist_per_provider",
    "scalar_only_metadata_where_possible",
    "bounded_pagination",
    "fail_soft_connector",
    "deterministic_idempotency_keys",
)


# ── Stage dataclass ───────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ProviderExpansionStage:
    """One stage in the dual-stack provider expansion template."""

    stage_key: str
    """Machine-readable stage identifier."""
    label: str
    """Human-readable stage label."""
    order: int
    """Position in the ordered 6-stage sequence (1-indexed)."""
    description: str
    """Short description of what this stage delivers."""

    backend_touchpoints: tuple[str, ...]
    """Backend files / patterns that must be created or updated."""
    frontend_touchpoints: tuple[str, ...]
    """Frontend files / patterns that must be created or updated (empty = none yet)."""
    required_tests: tuple[str, ...]
    """Test expectations that must pass before the stage is considered complete."""

    privacy_requirements: tuple[str, ...]
    """Privacy constraints applicable to this stage."""
    claim_discipline_requirements: tuple[str, ...]
    """Claim-discipline constraints applicable to this stage."""
    capability_matrix_update: str
    """Which capability-matrix fields flip to True when this stage ships."""


# ── Stage definitions ─────────────────────────────────────────────────────────

_STAGE_1 = ProviderExpansionStage(
    stage_key="drift_foundation",
    label="Drift Foundation",
    order=1,
    description=(
        "Add a configuration-snapshot connector for the provider. Implement the "
        "sync pipeline so periodic snapshots are stored and diffs are computed. "
        "Snapshots are metadata only — never raw secrets, auth headers, or customer data."
    ),
    backend_touchpoints=(
        "backend/app/connectors/<provider>.py",
        "backend/app/connectors/<provider>_schema.py",
        "backend/app/services/sync_service.py (_SUPPORTED_PROVIDERS tuple)",
        "backend/app/services/snapshot_service.py (schema coverage)",
        "backend/app/services/security_coverage_service.py (PROVIDERS + RULE_RECORD_TYPES)",
    ),
    frontend_touchpoints=(
        "frontend/src/app/(app)/integrations/* (connection form if needed)",
        "frontend/src/app/(app)/resources/* (resource type display if needed)",
    ),
    required_tests=(
        "test_connector_fetches_config_metadata_not_secrets",
        "test_snapshot_stored_with_no_raw_payload",
        "test_diff_computed_from_consecutive_snapshots",
        "test_sync_scheduled_via_supported_providers",
    ),
    privacy_requirements=(
        "no_raw_payloads",
        "no_secrets_or_tokens",
        "no_auth_headers",
        "no_request_response_bodies",
        "no_customer_pii_unless_safe",
        "scalar_only_metadata_where_possible",
        "bounded_pagination",
        "fail_soft_connector",
    ),
    claim_discipline_requirements=(
        "diff_described_as_configuration_change_not_breach",
        "snapshot_described_as_metadata_only_evidence",
    ),
    capability_matrix_update=(
        "drift.drift_snapshots = True, drift.drift_diff = True"
    ),
)

_STAGE_2 = ProviderExpansionStage(
    stage_key="security_foundation",
    label="Security Foundation",
    order=2,
    description=(
        "Add security rules that classify configuration drift as risk findings. "
        "Register rule keys, confidence levels, rule packs, and catalog entries. "
        "Rules emit review-safe evidence dicts — never raw values or secrets."
    ),
    backend_touchpoints=(
        "backend/app/services/security_rules/<provider>.py",
        "backend/app/services/security_rule_registry.py (KNOWN_RULE_KEYS)",
        "backend/app/services/security_rule_confidence.py",
        "backend/app/services/security_rule_pack.py",
        "backend/app/services/security_coverage_service.py (RULE_RECORD_TYPES)",
        "backend/app/services/security_beta_catalog.py if catalog used",
    ),
    frontend_touchpoints=(
        "frontend/src/lib/securityRuleCatalog.ts (rule descriptions)",
    ),
    required_tests=(
        "test_rules_fire_on_risky_config",
        "test_safe_config_does_not_fire",
        "test_malformed_record_ignored",
        "test_evidence_contains_no_secrets",
        "test_rule_keys_registered_in_known_rule_keys",
        "test_descriptions_contain_no_forbidden_claim_wording",
    ),
    privacy_requirements=(
        "no_secrets_or_tokens_in_evidence",
        "no_customer_pii_in_evidence",
        "evidence_is_name_level_identifiers_only",
        "no_raw_config_values",
    ),
    claim_discipline_requirements=(
        "finding_title_says_risk_not_confirmed_breach",
        "description_says_evidence_for_review",
        "description_says_does_not_confirm",
    ),
    capability_matrix_update=(
        "drift.drift_risk_classification = True, drift.drift_review_workflow = True, "
        "security.security_rules = True"
    ),
)

_STAGE_3 = ProviderExpansionStage(
    stage_key="activity_ingestion",
    label="Activity Ingestion",
    order=3,
    description=(
        "Add an activity ingestion service that fetches configuration-change events "
        "from the provider's audit/activity API. Normalize events through the shared "
        "metadata allowlist. Never store raw payloads, customer PII, secrets, or "
        "auth headers. Ingest via a POST /security/<provider>-activity/sync endpoint."
    ),
    backend_touchpoints=(
        "backend/app/connectors/<provider>.py (list_activity_events method)",
        "backend/app/services/<provider>_activity_ingestion_service.py",
        "backend/app/services/security_activity_event_service.py "
        "(ALLOWED_METADATA_KEYS — add provider-specific safe keys only)",
        "backend/app/schemas/security_<provider>_activity.py "
        "(<Provider>ActivitySyncRequest/Response)",
        "backend/app/routers/security.py "
        "(POST /security/<provider>-activity/sync, admin-gated)",
    ),
    frontend_touchpoints=(
        "frontend/src/lib/api.ts (sync<Provider>Activity helper)",
        "frontend/src/types/index.ts (<Provider>ActivitySyncResponse)",
        "frontend/src/app/(app)/security/activity/page.tsx "
        "(Provider union, PROVIDER_LABEL, <PROVIDER>_EVENT_TYPES, SyncBar, EmptyState, Select options)",
    ),
    required_tests=(
        "test_normalizes_and_maps_event_types",
        "test_non_config_events_skipped (defense-in-depth allowlist)",
        "test_malformed_events_skipped",
        "test_permission_failure_non_fatal (permission_limited)",
        "test_idempotent_ingestion",
        "test_idempotent_without_id_via_fingerprint",
        "test_no_secrets_pii_or_raw_payloads",
        "test_workspace_scoping",
        "test_no_forbidden_wording",
        "test_member_cannot_sync",
        "test_owner_can_sync_and_member_can_read_via_endpoint",
        "test_no_active_integration_returns_clean_summary",
        "test_connector_uses_strict_allowlist",
    ),
    privacy_requirements=(
        "no_raw_payloads",
        "no_secrets_or_tokens",
        "no_auth_headers",
        "no_request_response_bodies",
        "no_customer_pii_unless_safe",
        "no_message_or_email_body_content",
        "no_private_staff_identity_unless_safe",
        "strict_metadata_allowlist_per_provider",
        "scalar_only_metadata_where_possible",
        "bounded_pagination",
        "fail_soft_connector",
        "deterministic_idempotency_keys",
    ),
    claim_discipline_requirements=(
        "activity_events_described_as_evidence_for_review",
        "no_claim_of_breach_or_attack_in_event_type_or_metadata",
        "endpoint_docstring_says_does_not_confirm",
        "sync_response_says_permission_limited_not_compromised",
    ),
    capability_matrix_update="security.activity_ingestion = True",
)

_STAGE_4 = ProviderExpansionStage(
    stage_key="activity_signals",
    label="Activity Signals",
    order=4,
    description=(
        "Add an activity signal service that promotes ingested activity events into "
        "review-worthy Incident Signals (evidence_level=activity, confidence=medium). "
        "Group events by provider object identity. Signals are idempotent and never "
        "assert breach, fraud, or confirmed incident — only review priority."
    ),
    backend_touchpoints=(
        "backend/app/services/<provider>_activity_signal_service.py",
        "backend/app/services/security_incident_signal_service.py "
        "(ALLOWED_METADATA_KEYS — add provider-specific safe signal keys)",
        "backend/app/schemas/security_<provider>_activity.py "
        "(<Provider>ActivitySignalGenerateRequest/Response)",
        "backend/app/routers/security.py "
        "(POST /security/<provider>-activity/generate-signals, admin-gated)",
    ),
    frontend_touchpoints=(
        "frontend/src/lib/api.ts (generate<Provider>ActivitySignals helper)",
        "frontend/src/types/index.ts (<Provider>ActivitySignalGenerateResponse)",
        "frontend/src/app/(app)/security/signals/page.tsx "
        "(Provider union, PROVIDER_LABEL, <PROVIDER>_SIGNAL_TYPES, dispatch, SyncBar, EmptyState, Select options)",
    ),
    required_tests=(
        "test_webhook_or_primary_event_creates_signal",
        "test_severity_bumped_on_high_risk_variant",
        "test_idempotent_generation",
        "test_grouping_deduplicates",
        "test_workspace_scoping",
        "test_metadata_privacy (no secrets/pii/raw)",
        "test_no_forbidden_wording",
        "test_member_cannot_generate",
        "test_owner_can_generate_and_member_can_read_via_endpoint",
    ),
    privacy_requirements=(
        "no_secrets_or_tokens_in_signal_metadata",
        "no_customer_pii_in_signal_metadata",
        "signal_metadata_through_sanitize_signal_metadata",
        "no_raw_payloads_or_api_responses",
    ),
    claim_discipline_requirements=(
        "signal_summary_says_evidence_for_review",
        "signal_summary_says_does_not_confirm",
        "severity_reflects_review_priority_not_confirmed_impact",
        "signal_type_is_descriptive_not_alarming",
    ),
    capability_matrix_update="security.activity_signals = True",
)

_STAGE_5 = ProviderExpansionStage(
    stage_key="risk_activity_correlations",
    label="Risk × Activity Correlations",
    order=5,
    description=(
        "Add correlation rules that join active configuration-risk findings with "
        "matching activity events for the same provider object within the review "
        "window (finding.first_detected_at - 24h .. last_seen_at + 24h). "
        "Correlations are object-scoped — never provider-only. Each correlation "
        "auto-creates a linked Incident Signal (evidence_level=correlation)."
    ),
    backend_touchpoints=(
        "backend/app/services/security_signal_correlation_service.py "
        "(<PROVIDER>_CORRELATION_RULES dict, _<p>_event_md helpers, "
        "build_<provider>_correlation, generate_<provider>_correlations, "
        "ALLOWED_METADATA_KEYS — add provider-specific safe correlation keys, "
        "PROVIDER_<PROVIDER> constant)",
        "backend/app/routers/security.py "
        "(dispatch branch in POST /security/correlations/generate)",
        "frontend/src/app/(app)/security/correlations/page.tsx "
        "(PROVIDER_OPTIONS, TYPE_OPTIONS_BY_PROVIDER, blurb, EmptyState scope)",
    ),
    frontend_touchpoints=(
        "frontend/src/app/(app)/security/correlations/page.tsx "
        "(PROVIDER_OPTIONS, TYPE_OPTIONS_BY_PROVIDER.<provider>, blurb, EmptyState)",
    ),
    required_tests=(
        "test_primary_risk_x_matching_activity_creates_correlation",
        "test_different_object_does_not_correlate",
        "test_provider_only_match_does_not_correlate",
        "test_event_outside_window_does_not_correlate",
        "test_idempotent_generation",
        "test_linked_correlation_signal_created",
        "test_metadata_privacy",
        "test_list_endpoint_filters_by_provider_and_type",
        "test_member_cannot_generate",
        "test_deferred_patterns_not_in_rules_map (for unsupported evidence types)",
    ),
    privacy_requirements=(
        "no_secrets_or_tokens_in_correlation_metadata",
        "no_customer_pii_in_correlation_metadata",
        "correlation_metadata_through_sanitize_correlation_metadata",
        "no_raw_payloads_or_api_responses",
        "object_identity_is_safe_identifier_not_secret",
    ),
    claim_discipline_requirements=(
        "correlation_summary_says_evidence_for_review",
        "correlation_summary_says_does_not_confirm",
        "correlation_type_is_descriptive_e_g_risk_activity_not_confirmed_breach",
        "object_label_is_name_only_never_secret_or_token",
    ),
    capability_matrix_update="security.risk_activity_correlations = True",
)

_STAGE_6 = ProviderExpansionStage(
    stage_key="demo_qa",
    label="Demo + QA",
    order=6,
    description=(
        "Add a synthetic, clearly-marked demo incident chain (seed/clear/status) "
        "that showcases the full dual-stack evidence story: configuration risk → "
        "activity events → activity signals → correlations → case. Add a QA test "
        "suite that asserts the full chain, report/timeline/graph correctness, "
        "claim discipline, and demo isolation (clear does not remove non-demo data)."
    ),
    backend_touchpoints=(
        "backend/app/services/security_incident_demo_service.py "
        "(<PROVIDER>_DEMO_INTEGRATION_NAME, <PROVIDER>_DEMO_CASE_SOURCE, "
        "get_<provider>_demo_integration, _existing_<provider>_demo_case, "
        "get_<provider>_status, seed_<provider>, clear_<provider>)",
        "backend/app/services/security_case_report_service.py "
        "(_TIMELINE_PROVIDER_LABELS — add provider label)",
        "backend/app/routers/security.py "
        "(dispatch branches in incident_demo_status/seed/clear)",
        "backend/tests/test_milestone<N><P>_<provider>_demo_qa.py",
    ),
    frontend_touchpoints=(
        "frontend/src/lib/api.ts "
        "(seedIncidentDemo/clearIncidentDemo/getIncidentDemoStatus provider union)",
        "frontend/src/app/(app)/security/cases/page.tsx "
        "(PROVIDER_DEMO_CARDS array — add new entry)",
        "frontend/src/lib/securityDemoScript.ts "
        "(mention provider in talk tracks)",
        "frontend/src/app/(app)/security/demo-script/page.tsx "
        "(PROVIDER_CAPABILITY_TABLE — add new row)",
    ),
    required_tests=(
        "test_seed_creates_full_chain",
        "test_seeded_evidence_shapes",
        "test_correlations_have_linked_signals",
        "test_case_report_provider_label",
        "test_timeline_and_graph_build",
        "test_no_secret_material_in_report",
        "test_clear_removes_only_demo",
        "test_seed_clear_idempotent_and_status",
    ),
    privacy_requirements=(
        "demo_evidence_is_synthetic_and_name_level_only",
        "demo_integration_credentials_are_sentinel_not_real",
        "no_real_api_keys_or_tokens_in_demo",
        "no_customer_pii_in_seeded_data",
        "no_payment_card_bank_data_in_seeded_data",
        "clear_removes_only_demo_integration_evidence",
    ),
    claim_discipline_requirements=(
        "case_summary_says_evidence_for_review",
        "case_summary_says_does_not_confirm",
        "case_title_marked_Demo_explicitly",
        "timeline_label_shows_correct_provider_label",
        "report_does_not_claim_breach_or_compromise",
    ),
    capability_matrix_update=(
        "security.demo_seed_clear = True, security.case_report = True, "
        "security.evidence_timeline = True, security.evidence_graph = True, "
        "maturity = 'complete' (if all prior stages also complete)"
    ),
)


# ── Ordered stage list ───────────────────────────────────────────────────────

EXPANSION_STAGES: list[ProviderExpansionStage] = [
    _STAGE_1,
    _STAGE_2,
    _STAGE_3,
    _STAGE_4,
    _STAGE_5,
    _STAGE_6,
]

STAGE_BY_KEY: dict[str, ProviderExpansionStage] = {
    s.stage_key: s for s in EXPANSION_STAGES
}


# ── Recommended next-provider queue ──────────────────────────────────────────

@dataclass(frozen=True)
class RecommendedProvider:
    """A candidate provider for a future dual-stack arc."""

    provider: str
    label: str
    category: str
    why_high_fit: str
    drift_surfaces: tuple[str, ...]
    security_surfaces: tuple[str, ...]
    sensitive_data_to_avoid: tuple[str, ...]
    first_milestone_name: str
    notes: str


# NOTE: M79A launched Twilio drift foundation; Twilio moved into
# PROVIDER_CAPABILITIES_PARTIAL in provider_capability_matrix_service.py.
# M80A launched SendGrid drift foundation; SendGrid also moved into
# PROVIDER_CAPABILITIES_PARTIAL. M81A launched Auth0 drift foundation;
# Auth0 also moved into PROVIDER_CAPABILITIES_PARTIAL. M82A launched
# Datadog drift foundation; Datadog also moved into
# PROVIDER_CAPABILITIES_PARTIAL. Clerk is now the head of the
# recommended queue.
RECOMMENDED_NEXT_PROVIDERS: list[RecommendedProvider] = [
    RecommendedProvider(
        provider="clerk",
        label="Clerk",
        category="auth",
        why_high_fit=(
            "Clerk is the auth provider used by ConfigTrace itself. Configuration "
            "drift in session settings, allowed redirect URLs, social connection "
            "posture, and email/SMS OTP settings directly affects application security "
            "and makes a compelling internal-dogfood + external demo story."
        ),
        drift_surfaces=(
            "session_timeout_and_token_lifetime",
            "allowed_redirect_urls",
            "social_connection_settings",
            "email_sms_otp_settings",
            "password_policy_settings",
            "mfa_enforcement_posture",
        ),
        security_surfaces=(
            "overly_long_session_lifetime",
            "overly_broad_allowed_redirect_urls",
            "mfa_not_enforced",
            "weak_password_policy",
        ),
        sensitive_data_to_avoid=(
            "user_session_tokens",
            "user_email_addresses",
            "user_phone_numbers",
            "raw_webhook_payloads",
            "jwt_private_keys",
            "publishable_key_value",
        ),
        first_milestone_name="M80A: Clerk Drift Provider Foundation",
        notes=(
            "Use the Clerk Backend API. Focus on instance settings: "
            "/v1/instance (session lifetimes, allowed redirects), "
            "/v1/instance/restrictions, and /v1/instance/organization_settings. "
            "Never store user session tokens, user emails, or JWT private keys."
        ),
    ),
    RecommendedProvider(
        provider="pagerduty",
        label="PagerDuty",
        category="observability",
        why_high_fit=(
            "PagerDuty webhook endpoints and escalation-policy configurations are "
            "critical incident-response infrastructure. Drift in these (HTTP endpoints, "
            "missing acknowledgement timeouts, overly broad API key scopes) can "
            "silently break on-call workflows."
        ),
        drift_surfaces=(
            "webhook_subscriptions",
            "escalation_policy_configuration",
            "service_configuration",
            "api_key_scopes",
            "notification_rules",
        ),
        security_surfaces=(
            "webhook_http_endpoint",
            "escalation_policy_gap",
            "overly_broad_api_key_scope",
        ),
        sensitive_data_to_avoid=(
            "incident_bodies_or_details",
            "user_contact_methods",
            "auth_tokens",
            "raw_webhook_payloads",
            "personally_identifiable_responder_information",
        ),
        first_milestone_name="M81A: PagerDuty Drift Provider Foundation",
        notes=(
            "Use the PagerDuty REST API v2. Focus on /services, "
            "/webhook_subscriptions, /escalation_policies, and /api_keys "
            "(key description + scope only, never value). "
            "Never store incident details, responder identities, or raw alert payloads."
        ),
    ),
    RecommendedProvider(
        provider="linear",
        label="Linear",
        category="devops",
        why_high_fit=(
            "Linear project-management configuration (workspace settings, webhook "
            "endpoints, API key posture, team membership changes) is increasingly "
            "part of the DevSecOps surface for engineering teams. "
            "Drift in webhook URLs or overly permissive team access is reviewable."
        ),
        drift_surfaces=(
            "workspace_settings",
            "webhook_endpoints",
            "api_key_scopes",
            "team_membership_and_permissions",
            "integration_connections",
        ),
        security_surfaces=(
            "webhook_http_endpoint",
            "overly_broad_api_key",
            "team_membership_change",
        ),
        sensitive_data_to_avoid=(
            "issue_titles_or_descriptions",
            "user_emails_unless_safe",
            "auth_tokens",
            "raw_webhook_payloads",
            "comment_content",
        ),
        first_milestone_name="M82A: Linear Drift Provider Foundation",
        notes=(
            "Use the Linear GraphQL API. Focus on workspace webhooks, API key "
            "metadata (name + scope, never value), and team configuration. "
            "Never store issue content, user emails, or comment bodies."
        ),
    ),
    RecommendedProvider(
        provider="jira",
        label="Jira",
        category="devops",
        why_high_fit=(
            "Jira webhook configuration, project permission schemes, and API token "
            "posture are common IT/DevOps configuration surfaces. Permission-scheme "
            "drift that broadens access is a reviewable security signal."
        ),
        drift_surfaces=(
            "webhook_endpoints",
            "project_permission_schemes",
            "issue_security_schemes",
            "api_token_posture",
        ),
        security_surfaces=(
            "webhook_http_endpoint",
            "overly_broad_permission_scheme",
            "issue_security_scheme_missing",
        ),
        sensitive_data_to_avoid=(
            "issue_summaries_or_descriptions",
            "user_emails_unless_safe",
            "auth_tokens_or_api_keys",
            "raw_webhook_payloads",
            "comment_content",
            "attachment_content",
        ),
        first_milestone_name="M83A: Jira Drift Provider Foundation",
        notes=(
            "Use the Jira REST API v3. Focus on /rest/api/3/webhook (webhook "
            "endpoint URLs and schemes), /rest/api/3/permissionscheme (scheme "
            "NAME + grant summary, never raw grants), and API token metadata "
            "(label + status, never value). Never store issue content or user emails."
        ),
    ),
]

RECOMMENDED_NEXT_BY_KEY: dict[str, RecommendedProvider] = {
    p.provider: p for p in RECOMMENDED_NEXT_PROVIDERS
}


# ── Public API ────────────────────────────────────────────────────────────────

def get_provider_stage_checklist(stage_key: str) -> ProviderExpansionStage | None:
    """Return the stage definition for a given stage key, or None."""
    return STAGE_BY_KEY.get(stage_key)


def get_dual_stack_provider_template() -> dict[str, Any]:
    """Return the full dual-stack provider expansion template as a dict."""
    return {
        "stages": [
            {
                "stage_key": s.stage_key,
                "label": s.label,
                "order": s.order,
                "description": s.description,
                "backend_touchpoints": list(s.backend_touchpoints),
                "frontend_touchpoints": list(s.frontend_touchpoints),
                "required_tests": list(s.required_tests),
                "privacy_requirements": list(s.privacy_requirements),
                "claim_discipline_requirements": list(s.claim_discipline_requirements),
                "capability_matrix_update": s.capability_matrix_update,
            }
            for s in EXPANSION_STAGES
        ],
        "universal_privacy_requirements": list(UNIVERSAL_PRIVACY_REQUIREMENTS),
        "forbidden_claim_phrases": list(FORBIDDEN_CLAIM_PHRASES),
        "required_safe_phrases": list(REQUIRED_SAFE_PHRASES),
    }


def get_next_provider_recommendations() -> list[dict[str, Any]]:
    """Return the ordered list of recommended next providers as dicts."""
    return [
        {
            "provider": p.provider,
            "label": p.label,
            "category": p.category,
            "why_high_fit": p.why_high_fit,
            "drift_surfaces": list(p.drift_surfaces),
            "security_surfaces": list(p.security_surfaces),
            "sensitive_data_to_avoid": list(p.sensitive_data_to_avoid),
            "first_milestone_name": p.first_milestone_name,
            "notes": p.notes,
        }
        for p in RECOMMENDED_NEXT_PROVIDERS
    ]


def get_framework() -> dict[str, Any]:
    """Return the complete framework dict ready for JSON serialization."""
    recommendations = get_next_provider_recommendations()
    return {
        "template": get_dual_stack_provider_template(),
        "recommended_next_providers": recommendations,
        "summary": {
            "stage_count": len(EXPANSION_STAGES),
            "recommended_provider_count": len(RECOMMENDED_NEXT_PROVIDERS),
            "next_provider": recommendations[0]["label"] if recommendations else None,
            "next_milestone": (
                recommendations[0]["first_milestone_name"] if recommendations else None
            ),
            "planned_next_stage": "M82E: Datadog Activity Signals",
        },
    }
