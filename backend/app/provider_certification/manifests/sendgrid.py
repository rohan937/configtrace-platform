"""SendGrid certification manifest (message 6 of N).

Generic discovery is fully sufficient for SendGrid — no adapter needed.
SendGrid is registered in the capability matrix as maturity='partial'.
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
    "sendgrid_account",
    "sendgrid_api_key",
    "sendgrid_domain_authentication",
    "sendgrid_mail_settings",
    "sendgrid_sender_identity",
    "sendgrid_suppression_settings",
    "sendgrid_tracking_settings",
    "sendgrid_webhook_settings",
)

_FINDING_RULE_IDS = (
    "sendgrid_api_key_broad_scopes",
    "sendgrid_bcc_enabled",
    "sendgrid_bounce_purge_disabled",
    "sendgrid_click_tracking_enabled",
    "sendgrid_default_domain_authentication_invalid",
    "sendgrid_domain_authentication_invalid",
    "sendgrid_domain_authentication_legacy",
    "sendgrid_domain_automatic_security_disabled",
    "sendgrid_domain_dns_records_missing",
    "sendgrid_event_webhook_broad_event_stream",
    "sendgrid_event_webhook_disabled",
    "sendgrid_event_webhook_not_signed",
    "sendgrid_event_webhook_url_missing",
    "sendgrid_footer_disabled",
    "sendgrid_google_analytics_tracking_enabled",
    "sendgrid_inbound_parse_enabled",
    "sendgrid_inbound_parse_raw_email_enabled",
    "sendgrid_inbound_parse_spam_check_disabled",
    "sendgrid_open_tracking_enabled",
    "sendgrid_sandbox_mode_enabled",
    "sendgrid_sender_identity_locked",
    "sendgrid_sender_identity_reply_domain_mismatch",
    "sendgrid_sender_identity_unverified",
    "sendgrid_spam_check_disabled",
    "sendgrid_subscription_tracking_disabled",
    "sendgrid_suppression_settings_empty",
    "sendgrid_template_engine_enabled",
)

SENDGRID_MANIFEST = ProviderCertificationManifest(
    provider_id="sendgrid",
    display_name="SendGrid",
    category="communications",
    maturity="partial",
    expected_public=True,
    expected_connectable=True,
    expected_live=False,
    credential_fields=("sendgrid_api_key",),
    sensitive_credential_fields=("sendgrid_api_key",),
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
    expected_frontend_form="SendGridIntegrationForm.tsx",
    expected_reconnect=False,
    prohibited_dependencies=(),
    known_limitations=(
        "API key metadata is tracked without ever storing the key value itself.",
        "Verified sender identities are tracked by email domain only — full email addresses are never stored.",
        "Event webhook configuration is tracked via boolean flags only — the webhook URL is never stored.",
        "No reconnect function or dispatch is wired for SendGrid yet.",
        "No false-removal suppression function exists for SendGrid yet.",
    ),
    evidence_test_files=(
        "tests/test_sendgrid_provider_depth_qa.py",
        "tests/test_sendgrid_risk_rules.py",
    ),
    reachability_evidence=(
        FindingReachabilityEvidence(
            provider_id="sendgrid",
            test_file="tests/test_sendgrid_provider_depth_qa.py",
            test_selector="",
            covered_rule_ids=_FINDING_RULE_IDS,
            minimum_test_count=44,
            quality="direct",
        ),
    ),
    change_parity_evidence=(
        FindingChangeParityEvidence(
            provider_id="sendgrid",
            test_file="tests/test_sendgrid_risk_rules.py",
            test_selector="",
            covered_rule_ids=_FINDING_RULE_IDS,
            minimum_test_count=34,
            quality="direct",
        ),
    ),
    capability_evidence=(
        CapabilityEvidenceDeclaration(
            capability="security_findings",
            supporting_record_types=("sendgrid_api_key", "sendgrid_sender_identity", "sendgrid_webhook_settings"),
            supporting_finding_rule_ids=_FINDING_RULE_IDS,
            evidence_tests=("tests/test_sendgrid_provider_depth_qa.py",),
            limitation_note="API key VALUES and full email addresses are never stored — only key metadata, sender email domains, and webhook posture booleans.",
        ),
    ),
)

register_manifest(SENDGRID_MANIFEST)
