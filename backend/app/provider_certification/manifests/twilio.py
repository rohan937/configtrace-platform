"""Twilio certification manifest (message 6 of N).

Generic discovery is fully sufficient for Twilio — no adapter needed.
Twilio is registered in the capability matrix as maturity='partial'.
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
    "twilio_account",
    "twilio_api_key_summary",
    "twilio_incoming_phone_number",
    "twilio_messaging_service",
    "twilio_verify_service",
)

_FINDING_RULE_IDS = (
    "twilio_account_suspended",
    "twilio_api_key_stale",
    "twilio_messaging_service_fallback_missing",
    "twilio_messaging_service_inbound_webhook_missing",
    "twilio_messaging_service_long_validity_period",
    "twilio_messaging_service_number_level_inbound_webhook",
    "twilio_messaging_service_observability_gap",
    "twilio_messaging_service_status_callback_missing",
    "twilio_phone_number_messaging_observability_gap",
    "twilio_phone_number_sms_webhook_missing",
    "twilio_phone_number_status_callback_missing",
    "twilio_phone_number_voice_observability_gap",
    "twilio_phone_number_voice_webhook_missing",
    "twilio_verify_lookup_disabled",
    "twilio_verify_psd2_disabled",
    "twilio_verify_short_code_length",
    "twilio_verify_sms_to_landlines_allowed",
    "twilio_webhook_uses_http",
)

TWILIO_MANIFEST = ProviderCertificationManifest(
    provider_id="twilio",
    display_name="Twilio",
    category="communications",
    maturity="partial",
    expected_public=True,
    expected_connectable=True,
    expected_live=False,
    credential_fields=("twilio_account_sid", "twilio_auth_token"),
    sensitive_credential_fields=("twilio_auth_token",),
    authentication_model="basic_auth",
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
    expected_frontend_form="TwilioIntegrationForm.tsx",
    expected_reconnect=False,
    prohibited_dependencies=(),
    known_limitations=(
        "Call and message CONTENT is never stored — only account/phone-number/messaging-service/verify-service configuration metadata.",
        "The auth token is never logged or stored in records.",
        "API key secrets are never stored.",
        "No reconnect function or dispatch is wired for Twilio yet.",
        "No false-removal suppression function exists for Twilio yet.",
    ),
    evidence_test_files=(
        "tests/test_twilio_provider_depth_qa.py",
        "tests/test_twilio_risk_rules.py",
    ),
    reachability_evidence=(
        FindingReachabilityEvidence(
            provider_id="twilio",
            test_file="tests/test_twilio_provider_depth_qa.py",
            test_selector="",
            covered_rule_ids=_FINDING_RULE_IDS,
            minimum_test_count=26,
            quality="direct",
        ),
    ),
    change_parity_evidence=(
        FindingChangeParityEvidence(
            provider_id="twilio",
            test_file="tests/test_twilio_risk_rules.py",
            test_selector="",
            covered_rule_ids=_FINDING_RULE_IDS,
            minimum_test_count=26,
            quality="direct",
        ),
    ),
    capability_evidence=(
        CapabilityEvidenceDeclaration(
            capability="security_findings",
            supporting_record_types=("twilio_incoming_phone_number", "twilio_messaging_service", "twilio_verify_service", "twilio_api_key_summary"),
            supporting_finding_rule_ids=_FINDING_RULE_IDS,
            evidence_tests=("tests/test_twilio_provider_depth_qa.py",),
            limitation_note="Call/message content, phone numbers, and the full request URL are never stored — only posture/count/webhook-scheme metadata.",
        ),
    ),
)

register_manifest(TWILIO_MANIFEST)
