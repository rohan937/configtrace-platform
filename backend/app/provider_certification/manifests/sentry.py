"""Sentry certification manifest (pilot provider, message 1 of N).

Derived from the real Sentry launch arc (messages 1-8 of 8, culminating
in ``tests/reports/sentry_provider_certification.md``) — not copied from
that Markdown report. Every field below is independently checked against
discovered repository reality by ``app.provider_certification.gates``.
"""

from __future__ import annotations

from app.provider_certification.models import ProviderCertificationManifest
from app.provider_certification.runner import register_manifest

_EXPECTED_RECORD_TYPES = (
    "sentry_organization",
    "sentry_api_capability",
    "sentry_project",
    "sentry_team",
    "sentry_member",
    "sentry_team_membership",
    "sentry_project_team_assignment",
    "sentry_metric_alert_rule",
    "sentry_metric_alert_trigger",
    "sentry_issue_alert_rule",
    "sentry_alert_action",
    "sentry_organization_integration",
    "sentry_repository",
    "sentry_code_mapping",
    "sentry_ownership_rule",
    "sentry_privileged_member",
    "sentry_privileged_team",
    "sentry_routing_context",
)

_DERIVED_RECORD_TYPES = (
    "sentry_privileged_member",
    "sentry_privileged_team",
    "sentry_routing_context",
)

_SECURITY_FINDING_RULE_IDS = (
    "sentry_active_organization_admin",
    "sentry_active_organization_manager",
    "sentry_active_organization_owner",
    "sentry_alert_references_disabled_integration",
    "sentry_alert_references_inactive_member",
    "sentry_alert_targets_missing_member",
    "sentry_alert_targets_missing_team",
    "sentry_issue_alert_disabled_with_routing_configured",
    "sentry_issue_alert_unrouted",
    "sentry_member_broad_routing_authority",
    "sentry_member_team_admin_without_org_role",
    "sentry_metric_alert_disabled_with_routing_configured",
    "sentry_metric_alert_unrouted",
    "sentry_ownership_targets_inactive_member",
    "sentry_ownership_targets_missing_member",
    "sentry_ownership_targets_missing_team",
    "sentry_pending_privileged_invitation",
    "sentry_repository_pending_deletion",
    "sentry_team_has_broad_routing_authority",
    "sentry_team_has_unresolved_members",
)

SENTRY_MANIFEST = ProviderCertificationManifest(
    provider_id="sentry",
    display_name="Sentry",
    category="observability",
    maturity="partial",
    expected_public=True,
    expected_connectable=True,
    expected_live=True,
    credential_fields=("sentry_organization_slug", "sentry_auth_token"),
    sensitive_credential_fields=("sentry_auth_token",),
    authentication_model="organization_auth_token",
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
        "organization_wide_family_completeness",
        "per_team_membership_completeness",
        "per_project_issue_alert_completeness",
        "per_project_ownership_completeness",
        "derived_privileged_members_teams_routing_contexts",
    ),
    false_removal_scopes=(
        "organization_wide_family_completeness",
        "per_team_membership_completeness",
        "per_project_issue_alert_completeness",
        "per_project_ownership_completeness",
        "derived_privileged_members_teams_routing_contexts",
    ),
    expected_frontend_form="SentryIntegrationForm.tsx",
    expected_reconnect=True,
    allowed_dependencies=("httpx",),
    prohibited_dependencies=("sentry-sdk", "sentry-cli"),
    required_env_vars=(),
    prohibited_env_vars=("SENTRY_AUTH_TOKEN", "SENTRY_DSN", "SENTRY_ORG", "SENTRY_ORGANIZATION"),
    known_limitations=(
        "SaaS only (sentry.io) — no self-hosted Sentry support",
        "No custom base URL / no arbitrary regional host (EU de.sentry.io unsupported)",
        "No issue or event ingestion of any kind (no stack traces, breadcrumbs, session replay, performance spans, profiles)",
        "No DSN, source code, or commit-content ingestion",
        "No release/deployment history ingestion",
        "No activity ingestion, incident signals, risk x activity correlations, or demo/case tooling (dual-stack scope: drift + Security Findings only)",
        "Webhook delivery-content ingestion deferred (private API)",
        "Release-threshold configuration ingestion deferred (experimental API)",
        "Some extended families (metric_alerts, integrations, repositories, releases) may remain Partial for a narrowly-scoped token — expected, not a defect",
    ),
    evidence_test_files=(
        "tests/test_sentry_change_classification.py",
        "tests/test_sentry_change_parity.py",
        "tests/test_sentry_partial_sync.py",
        "tests/test_sentry_http_reliability.py",
        "tests/test_sentry_scale_reliability.py",
        "tests/test_sentry_provider_depth_qa.py",
        "tests/test_sentry_integration_creation.py",
        "tests/test_sentry_reconnect.py",
    ),
    evidence_reports=(
        "tests/reports/sentry_reliability_certification.md",
        "tests/reports/sentry_provider_certification.md",
        "tests/reports/sentry_provider_depth_matrix.md",
        "tests/reports/sentry_access_requirement_matrix.md",
    ),
)

register_manifest(SENTRY_MANIFEST)
