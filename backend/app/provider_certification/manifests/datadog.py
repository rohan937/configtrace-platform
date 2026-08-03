"""Datadog certification manifest (message 5 of N).

Generic discovery is fully sufficient for Datadog — no adapter needed.
Datadog is registered in PROVIDER_CAPABILITIES_PARTIAL (maturity='partial' in the real capability matrix), matching this manifest's declared maturity.
"""

from __future__ import annotations

from app.provider_certification.models import (
    CapabilityEvidenceDeclaration,
    FindingChangeParityEvidence,
    FindingReachabilityEvidence,
    ProviderCertificationManifest,
)
from app.provider_certification.runner import register_manifest

_EXPECTED_RECORD_TYPES = (
    "datadog_api_key_metadata",
    "datadog_application_key_metadata",
    "datadog_cloud_integration",
    "datadog_dashboard",
    "datadog_monitor",
    "datadog_notification_integration",
    "datadog_role",
    "datadog_slo",
    "datadog_team",
    "datadog_webhook_integration",
)

_FINDING_RULE_IDS = (
    "datadog_api_key_disabled",
    "datadog_application_key_broad_scopes",
    "datadog_cloud_integration_broad_collection",
    "datadog_cloud_integration_log_collection_enabled",
    "datadog_dashboard_public_url_present",
    "datadog_dashboard_unrestricted_roles",
    "datadog_monitor_broad_group_by",
    "datadog_monitor_disabled",
    "datadog_monitor_long_no_data_timeframe",
    "datadog_monitor_long_query",
    "datadog_monitor_message_template_present",
    "datadog_monitor_no_notifications",
    "datadog_monitor_no_recovery_threshold",
    "datadog_monitor_no_warning_threshold",
    "datadog_monitor_notify_audit_disabled",
    "datadog_monitor_notify_no_data_disabled",
    "datadog_monitor_query_wildcard_scope",
    "datadog_monitor_require_full_window_disabled",
    "datadog_monitor_silenced_scopes_present",
    "datadog_monitor_unrestricted_roles",
    "datadog_notification_integration_no_channels",
    "datadog_role_high_permission_count",
    "datadog_slo_low_target",
    "datadog_slo_no_monitors",
    "datadog_team_no_members",
    "datadog_webhook_auth_material_present",
    "datadog_webhook_custom_headers_without_secret_headers",
    "datadog_webhook_large_payload_template",
    "datadog_webhook_non_https_endpoint",
    "datadog_webhook_payload_template_present",
    "datadog_webhook_without_secret_headers",
)

DATADOG_MANIFEST = ProviderCertificationManifest(
    provider_id="datadog",
    display_name="Datadog",
    category="observability",
    maturity="partial",
    expected_public=True,
    expected_connectable=True,
    expected_live=False,
    credential_fields=("datadog_api_key", "datadog_application_key", "datadog_site"),
    sensitive_credential_fields=("datadog_api_key", "datadog_application_key"),
    authentication_model="api_key",
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
    expected_frontend_form="DatadogIntegrationForm.tsx",
    expected_reconnect=False,
    prohibited_dependencies=(),
    known_limitations=(
        "No metrics, logs, traces, spans, RUM events, profiles, or incident timelines are ingested — only monitor/dashboard/SLO/integration/role/team CONFIGURATION metadata.",
        "API/application key metadata records track key existence and scope, never the key material itself.",
        "No reconnect function or dispatch is wired for Datadog yet.",
        "No false-removal suppression function exists for Datadog yet.",
    ),
    evidence_test_files=(
        "tests/test_datadog_provider_depth_qa.py",
        "tests/test_datadog_provider_depth_qa.py",
    ),
    reachability_evidence=(
        FindingReachabilityEvidence(
            provider_id="datadog",
            test_file="tests/test_datadog_provider_depth_qa.py",
            test_selector="",
            covered_rule_ids=_FINDING_RULE_IDS,
            minimum_test_count=25,
            quality="direct",
        ),
    ),
    change_parity_evidence=(
        FindingChangeParityEvidence(
            provider_id="datadog",
            test_file="tests/test_datadog_provider_depth_qa.py",
            test_selector="",
            covered_rule_ids=_FINDING_RULE_IDS,
            minimum_test_count=25,
            quality="direct",
        ),
    ),
    capability_evidence=(
        CapabilityEvidenceDeclaration(
            capability="security_findings",
            supporting_record_types=("datadog_monitor", "datadog_role", "datadog_webhook_integration"),
            supporting_finding_rule_ids=_FINDING_RULE_IDS,
            evidence_tests=("tests/test_datadog_provider_depth_qa.py",),
            limitation_note="Monitor/role/webhook CONFIGURATION metadata only — no metrics, logs, or traces.",
        ),
    ),
)

register_manifest(DATADOG_MANIFEST)
