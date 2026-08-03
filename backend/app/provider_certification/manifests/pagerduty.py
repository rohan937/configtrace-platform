"""PagerDuty certification manifest (message 5 of N).

Generic discovery is fully sufficient for PagerDuty — no adapter needed.
PagerDuty is registered in PROVIDER_CAPABILITIES_PARTIAL (maturity='partial'), matching this manifest's declared maturity.
"""

from __future__ import annotations

from app.provider_certification.models import (
    FindingChangeParityEvidence,
    FindingReachabilityEvidence,
    ProviderCertificationManifest,
)
from app.provider_certification.runner import register_manifest

_EXPECTED_RECORD_TYPES = (
    "pagerduty_business_service",
    "pagerduty_escalation_policy",
    "pagerduty_event_orchestration",
    "pagerduty_response_play",
    "pagerduty_schedule",
    "pagerduty_service",
    "pagerduty_service_integration",
    "pagerduty_webhook_subscription",
)

_FINDING_RULE_IDS = (
    "pagerduty_business_service_no_contact",
    "pagerduty_business_service_no_team",
    "pagerduty_escalation_policy_low_target_count",
    "pagerduty_escalation_policy_no_rules",
    "pagerduty_escalation_policy_no_schedule_targets",
    "pagerduty_escalation_policy_no_targets",
    "pagerduty_escalation_policy_no_team_targets",
    "pagerduty_escalation_policy_single_level",
    "pagerduty_event_orchestration_low_route_count",
    "pagerduty_event_orchestration_no_routes",
    "pagerduty_event_orchestration_no_team",
    "pagerduty_response_play_low_responder_count",
    "pagerduty_response_play_manual_only",
    "pagerduty_response_play_no_responders",
    "pagerduty_response_play_no_subscribers",
    "pagerduty_response_play_no_team",
    "pagerduty_response_play_not_runnable",
    "pagerduty_schedule_low_target_count",
    "pagerduty_schedule_no_layers",
    "pagerduty_schedule_no_restrictions",
    "pagerduty_schedule_no_targets",
    "pagerduty_schedule_no_teams",
    "pagerduty_schedule_single_layer",
    "pagerduty_service_ack_timeout_disabled",
    "pagerduty_service_alert_creation_limited",
    "pagerduty_service_auto_resolve_disabled",
    "pagerduty_service_integration_email_type",
    "pagerduty_service_integration_missing_key_indicator",
    "pagerduty_service_integration_routing_key_missing",
    "pagerduty_service_integration_unknown_type",
    "pagerduty_service_no_escalation_policy",
    "pagerduty_service_no_integrations",
    "pagerduty_service_no_teams",
    "pagerduty_webhook_subscription_account_scope",
    "pagerduty_webhook_subscription_broad_event_scope",
    "pagerduty_webhook_subscription_broad_scope_high",
    "pagerduty_webhook_subscription_inactive",
    "pagerduty_webhook_subscription_no_events",
    "pagerduty_webhook_subscription_non_https",
    "pagerduty_webhook_subscription_secret_not_indicated",
)

PAGERDUTY_MANIFEST = ProviderCertificationManifest(
    provider_id="pagerduty",
    display_name="PagerDuty",
    category="incident_management",
    maturity="partial",
    expected_public=True,
    expected_connectable=True,
    expected_live=False,
    credential_fields=("pagerduty_api_token",),
    sensitive_credential_fields=("pagerduty_api_token",),
    authentication_model="api_token",
    expected_record_types=_EXPECTED_RECORD_TYPES,
    security_finding_rule_ids=_FINDING_RULE_IDS,
    supported_capabilities=(
        "security_findings",
        "activity_ingestion",
        "activity_signals",
        "risk_activity_correlations",
        "demo_case_reporting",
    ),
    unsupported_capabilities=(),
    completeness_scopes=(),
    false_removal_scopes=(),
    expected_frontend_form="PagerDutyIntegrationForm.tsx",
    expected_reconnect=False,
    prohibited_dependencies=(),
    known_limitations=(
        "No incident-event ingestion, alert payload ingestion, timeline ingestion, or responder communications are ingested — only service/escalation-policy/schedule/team/integration/event-orchestration CONFIGURATION metadata.",
        "No reconnect function or dispatch is wired for PagerDuty yet.",
        "No false-removal suppression function exists for PagerDuty yet.",
    ),
    evidence_test_files=(
        "tests/test_pagerduty_provider_depth_qa.py",
        "tests/test_pagerduty_provider_depth_qa.py",
    ),
    reachability_evidence=(
        FindingReachabilityEvidence(
            provider_id="pagerduty",
            test_file="tests/test_pagerduty_provider_depth_qa.py",
            test_selector="",
            covered_rule_ids=_FINDING_RULE_IDS,
            minimum_test_count=25,
            quality="direct",
        ),
    ),
    change_parity_evidence=(
        FindingChangeParityEvidence(
            provider_id="pagerduty",
            test_file="tests/test_pagerduty_provider_depth_qa.py",
            test_selector="",
            covered_rule_ids=_FINDING_RULE_IDS,
            minimum_test_count=25,
            quality="direct",
        ),
    ),
)

register_manifest(PAGERDUTY_MANIFEST)
