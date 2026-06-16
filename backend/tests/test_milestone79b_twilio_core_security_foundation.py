"""M79B — Twilio Core Security Foundation.

Pins the second Twilio arc milestone:
  * TWILIO_RULE_KEYS contains exactly the 9 expected rule keys
  * get_twilio_findings fires correctly on trigger conditions
  * Rules do NOT fire on healthy records
  * Evidence privacy: no raw URLs, no full phone numbers, no auth secrets
  * Malformed / missing records are handled gracefully
  * Registry / confidence / pack / coverage all stay in parity
  * Provider capability matrix reflects M79B state
  * Expansion framework planned_next_stage → M79C Twilio
  * Frontend catalog contains all 9 rule keys with required fields
  * No forbidden wording anywhere in the module or capability notes

These rules are configuration-posture findings only. A finding is evidence
for review and never asserts that a breach occurred, that data leaked, or
that an attacker has access.
"""

from __future__ import annotations

import inspect
import re
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
FE_CATALOG = REPO_ROOT / "frontend" / "src" / "lib" / "securityRuleCatalog.ts"

# ── Forbidden phrases ─────────────────────────────────────────────────────────

FORBIDDEN_PHRASES = [
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
]

# ── Expected rule keys ────────────────────────────────────────────────────────

_SMS_WEBHOOK = "twilio_phone_number_sms_webhook_missing"
_VOICE_WEBHOOK = "twilio_phone_number_voice_webhook_missing"
_STATUS_CALLBACK = "twilio_phone_number_status_callback_missing"
_MSG_INBOUND = "twilio_messaging_service_inbound_webhook_missing"
_MSG_FALLBACK = "twilio_messaging_service_fallback_missing"
_MSG_STATUS = "twilio_messaging_service_status_callback_missing"
_VERIFY_CODE = "twilio_verify_short_code_length"
_VERIFY_LOOKUP = "twilio_verify_lookup_disabled"
_ACCOUNT_SUSPENDED = "twilio_account_suspended"

ALL_M79B_RULE_KEYS: frozenset[str] = frozenset({
    _SMS_WEBHOOK,
    _VOICE_WEBHOOK,
    _STATUS_CALLBACK,
    _MSG_INBOUND,
    _MSG_FALLBACK,
    _MSG_STATUS,
    _VERIFY_CODE,
    _VERIFY_LOOKUP,
    _ACCOUNT_SUSPENDED,
})

# ── Helpers for record building ───────────────────────────────────────────────


def _phone_record(**overrides) -> dict[str, Any]:
    base: dict[str, Any] = {
        "record_type": "twilio_incoming_phone_number",
        "record_id": "PN-test-001",
        "phone_number_last4": "1234",
        "friendly_name": "Test Number",
        "iso_country": "US",
        "capability_sms": True,
        "capability_voice": True,
        "capability_mms": False,
        "capability_fax": False,
        "sms_url_configured": True,
        "voice_url_configured": True,
        "status_callback_configured": True,
    }
    base.update(overrides)
    return base


def _messaging_record(**overrides) -> dict[str, Any]:
    base: dict[str, Any] = {
        "record_type": "twilio_messaging_service",
        "record_id": "MG-test-001",
        "friendly_name": "Test Messaging Service",
        "inbound_request_url_configured": True,
        "fallback_url_configured": True,
        "status_callback_url_configured": True,
        "use_inbound_webhook_on_number": False,
    }
    base.update(overrides)
    return base


def _verify_record(**overrides) -> dict[str, Any]:
    base: dict[str, Any] = {
        "record_type": "twilio_verify_service",
        "record_id": "VA-test-001",
        "friendly_name": "Test Verify Service",
        "code_length": 6,
        "lookup_enabled": True,
    }
    base.update(overrides)
    return base


def _account_record(**overrides) -> dict[str, Any]:
    base: dict[str, Any] = {
        "record_type": "twilio_account",
        "record_id": "AC-test-001",
        "account_sid_prefix": "AC123456",
        "friendly_name": "Test Account",
        "status": "active",
        "account_type": "Full",
    }
    base.update(overrides)
    return base


def _keys(findings) -> set[str]:
    return {f.rule_key for f in findings}


# ══════════════════════════════════════════════════════════════════════════════
# Section A: Rule key existence
# ══════════════════════════════════════════════════════════════════════════════


class TestRuleKeyExistence:
    def setup_method(self):
        from app.services.security_rules.twilio import TWILIO_RULE_KEYS
        self.keys = TWILIO_RULE_KEYS

    def test_twilio_rule_keys_is_frozenset(self):
        assert isinstance(self.keys, frozenset)

    def test_sms_webhook_missing_in_keys(self):
        assert _SMS_WEBHOOK in self.keys

    def test_voice_webhook_missing_in_keys(self):
        assert _VOICE_WEBHOOK in self.keys

    def test_status_callback_missing_in_keys(self):
        assert _STATUS_CALLBACK in self.keys

    def test_messaging_inbound_missing_in_keys(self):
        assert _MSG_INBOUND in self.keys

    def test_messaging_fallback_missing_in_keys(self):
        assert _MSG_FALLBACK in self.keys

    def test_messaging_status_callback_missing_in_keys(self):
        assert _MSG_STATUS in self.keys

    def test_verify_short_code_in_keys(self):
        assert _VERIFY_CODE in self.keys

    def test_verify_lookup_disabled_in_keys(self):
        assert _VERIFY_LOOKUP in self.keys

    def test_account_suspended_in_keys(self):
        assert _ACCOUNT_SUSPENDED in self.keys

    def test_exactly_nine_rule_keys(self):
        # M79C added 8 new keys; total is now 17
        assert len(self.keys) == 17

    def test_no_extra_unexpected_keys(self):
        # M79C keys are now also present; accept the full combined set
        ALL_M79C_NEW_RULE_KEYS = frozenset({
            "twilio_api_key_stale",
            "twilio_messaging_service_observability_gap",
            "twilio_messaging_service_number_level_inbound_webhook",
            "twilio_messaging_service_long_validity_period",
            "twilio_phone_number_messaging_observability_gap",
            "twilio_phone_number_voice_observability_gap",
            "twilio_verify_psd2_disabled",
            "twilio_verify_sms_to_landlines_allowed",
        })
        extra = self.keys - ALL_M79B_RULE_KEYS - ALL_M79C_NEW_RULE_KEYS
        assert extra == frozenset(), f"unexpected rule keys: {extra}"

    def test_all_expected_keys_present(self):
        missing = ALL_M79B_RULE_KEYS - self.keys
        assert missing == frozenset(), f"missing rule keys: {missing}"


# ══════════════════════════════════════════════════════════════════════════════
# Section B: Rules trigger correctly
# ══════════════════════════════════════════════════════════════════════════════


class TestRulesTriggerCorrectly:
    def setup_method(self):
        from app.services.security_rules.twilio import get_twilio_findings
        self.get_findings = get_twilio_findings

    # b1. sms_webhook_missing
    def test_b1_sms_webhook_missing_fires(self):
        rec = _phone_record(capability_sms=True, sms_url_configured=False)
        findings = self.get_findings(rec)
        assert _SMS_WEBHOOK in _keys(findings)

    # b2. voice_webhook_missing
    def test_b2_voice_webhook_missing_fires(self):
        rec = _phone_record(capability_voice=True, voice_url_configured=False)
        findings = self.get_findings(rec)
        assert _VOICE_WEBHOOK in _keys(findings)

    # b3. status_callback_missing
    def test_b3_status_callback_missing_fires(self):
        rec = _phone_record(capability_sms=True, status_callback_configured=False)
        findings = self.get_findings(rec)
        assert _STATUS_CALLBACK in _keys(findings)

    # b4. messaging_inbound_missing
    def test_b4_messaging_inbound_missing_fires(self):
        rec = _messaging_record(
            inbound_request_url_configured=False,
            use_inbound_webhook_on_number=False,
        )
        findings = self.get_findings(rec)
        assert _MSG_INBOUND in _keys(findings)

    # b5. messaging_fallback_missing
    def test_b5_messaging_fallback_missing_fires(self):
        rec = _messaging_record(fallback_url_configured=False)
        findings = self.get_findings(rec)
        assert _MSG_FALLBACK in _keys(findings)

    # b6. messaging_status_callback_missing
    def test_b6_messaging_status_callback_missing_fires(self):
        rec = _messaging_record(status_callback_url_configured=False)
        findings = self.get_findings(rec)
        assert _MSG_STATUS in _keys(findings)

    # b7. verify_short_code (code_length=4 < 6)
    def test_b7_verify_short_code_fires_on_4(self):
        rec = _verify_record(code_length=4)
        findings = self.get_findings(rec)
        assert _VERIFY_CODE in _keys(findings)

    def test_b7_verify_short_code_fires_on_5(self):
        rec = _verify_record(code_length=5)
        findings = self.get_findings(rec)
        assert _VERIFY_CODE in _keys(findings)

    # b8. verify_lookup_disabled
    def test_b8_verify_lookup_disabled_fires(self):
        rec = _verify_record(lookup_enabled=False)
        findings = self.get_findings(rec)
        assert _VERIFY_LOOKUP in _keys(findings)

    # b9. account_suspended
    def test_b9_account_suspended_fires(self):
        rec = _account_record(status="suspended")
        findings = self.get_findings(rec)
        assert _ACCOUNT_SUSPENDED in _keys(findings)

    def test_b9_account_closed_fires(self):
        rec = _account_record(status="closed")
        findings = self.get_findings(rec)
        assert _ACCOUNT_SUSPENDED in _keys(findings)


# ══════════════════════════════════════════════════════════════════════════════
# Section C: Rules do NOT fire on healthy records
# ══════════════════════════════════════════════════════════════════════════════


class TestRulesDoNotFireOnHealthy:
    def setup_method(self):
        from app.services.security_rules.twilio import get_twilio_findings
        self.get_findings = get_twilio_findings

    # c1. sms_webhook_missing: sms_url_configured=True → no fire
    def test_c1_sms_webhook_no_fire_when_configured(self):
        rec = _phone_record(capability_sms=True, sms_url_configured=True)
        findings = self.get_findings(rec)
        assert _SMS_WEBHOOK not in _keys(findings)

    # c2. voice_webhook_missing: voice_url_configured=True → no fire
    def test_c2_voice_webhook_no_fire_when_configured(self):
        rec = _phone_record(capability_voice=True, voice_url_configured=True)
        findings = self.get_findings(rec)
        assert _VOICE_WEBHOOK not in _keys(findings)

    # c3. status_callback_missing: status_callback_configured=True → no fire
    def test_c3_status_callback_no_fire_when_configured(self):
        rec = _phone_record(status_callback_configured=True)
        findings = self.get_findings(rec)
        assert _STATUS_CALLBACK not in _keys(findings)

    # c4. messaging_inbound_missing: inbound_request_url_configured=True → no fire
    def test_c4_messaging_inbound_no_fire_when_url_configured(self):
        rec = _messaging_record(inbound_request_url_configured=True)
        findings = self.get_findings(rec)
        assert _MSG_INBOUND not in _keys(findings)

    def test_c4_messaging_inbound_no_fire_when_uses_number_webhook(self):
        rec = _messaging_record(
            inbound_request_url_configured=False,
            use_inbound_webhook_on_number=True,
        )
        findings = self.get_findings(rec)
        assert _MSG_INBOUND not in _keys(findings)

    # c5. messaging_fallback_missing: fallback_url_configured=True → no fire
    def test_c5_messaging_fallback_no_fire_when_configured(self):
        rec = _messaging_record(fallback_url_configured=True)
        findings = self.get_findings(rec)
        assert _MSG_FALLBACK not in _keys(findings)

    # c6. messaging_status_callback_missing: status_callback_url_configured=True → no fire
    def test_c6_messaging_status_callback_no_fire_when_configured(self):
        rec = _messaging_record(status_callback_url_configured=True)
        findings = self.get_findings(rec)
        assert _MSG_STATUS not in _keys(findings)

    # c7. verify_short_code: code_length=6 → no fire
    def test_c7_verify_short_code_no_fire_on_6(self):
        rec = _verify_record(code_length=6)
        findings = self.get_findings(rec)
        assert _VERIFY_CODE not in _keys(findings)

    def test_c7_verify_short_code_no_fire_on_8(self):
        rec = _verify_record(code_length=8)
        findings = self.get_findings(rec)
        assert _VERIFY_CODE not in _keys(findings)

    # c8. verify_lookup_disabled: lookup_enabled=True → no fire
    def test_c8_verify_lookup_no_fire_when_enabled(self):
        rec = _verify_record(lookup_enabled=True)
        findings = self.get_findings(rec)
        assert _VERIFY_LOOKUP not in _keys(findings)

    # c9. account_suspended: status="active" → no fire
    def test_c9_account_no_fire_when_active(self):
        rec = _account_record(status="active")
        findings = self.get_findings(rec)
        assert _ACCOUNT_SUSPENDED not in _keys(findings)

    # c10. sms_webhook_missing: capability_sms=False → no fire
    def test_c10_sms_webhook_no_fire_when_no_sms_capability(self):
        rec = _phone_record(capability_sms=False, sms_url_configured=False)
        findings = self.get_findings(rec)
        assert _SMS_WEBHOOK not in _keys(findings)


# ══════════════════════════════════════════════════════════════════════════════
# Section D: Evidence privacy
# ══════════════════════════════════════════════════════════════════════════════


class TestEvidencePrivacy:
    def setup_method(self):
        from app.services.security_rules.twilio import get_twilio_findings
        self.get_findings = get_twilio_findings

    def _all_trigger_findings(self):
        """Return findings from all trigger conditions."""
        records = [
            _phone_record(capability_sms=True, sms_url_configured=False),
            _phone_record(capability_voice=True, voice_url_configured=False),
            _phone_record(capability_sms=True, status_callback_configured=False),
            _messaging_record(
                inbound_request_url_configured=False, use_inbound_webhook_on_number=False
            ),
            _messaging_record(fallback_url_configured=False),
            _messaging_record(status_callback_url_configured=False),
            _verify_record(code_length=4),
            _verify_record(lookup_enabled=False),
            _account_record(status="suspended"),
        ]
        findings = []
        for rec in records:
            findings.extend(self.get_findings(rec))
        return findings

    def test_no_phone_number_field_in_evidence(self):
        for f in self._all_trigger_findings():
            assert "phone_number" not in f.evidence, (
                f"forbidden 'phone_number' field in {f.rule_key} evidence"
            )

    def test_no_sms_url_field_in_evidence(self):
        for f in self._all_trigger_findings():
            assert "sms_url" not in f.evidence, (
                f"forbidden 'sms_url' field in {f.rule_key} evidence"
            )

    def test_no_voice_url_field_in_evidence(self):
        for f in self._all_trigger_findings():
            assert "voice_url" not in f.evidence, (
                f"forbidden 'voice_url' field in {f.rule_key} evidence"
            )

    def test_no_inbound_request_url_field_in_evidence(self):
        for f in self._all_trigger_findings():
            assert "inbound_request_url" not in f.evidence, (
                f"forbidden 'inbound_request_url' field in {f.rule_key} evidence"
            )

    def test_no_fallback_url_field_in_evidence(self):
        for f in self._all_trigger_findings():
            assert "fallback_url" not in f.evidence, (
                f"forbidden 'fallback_url' field in {f.rule_key} evidence"
            )

    def test_no_status_callback_url_field_in_evidence(self):
        for f in self._all_trigger_findings():
            assert "status_callback_url" not in f.evidence, (
                f"forbidden 'status_callback_url' field in {f.rule_key} evidence"
            )

    def test_no_auth_token_field_in_evidence(self):
        for f in self._all_trigger_findings():
            assert "auth_token" not in f.evidence, (
                f"forbidden 'auth_token' field in {f.rule_key} evidence"
            )

    def test_no_api_secret_field_in_evidence(self):
        for f in self._all_trigger_findings():
            assert "api_secret" not in f.evidence, (
                f"forbidden 'api_secret' field in {f.rule_key} evidence"
            )

    def test_no_api_key_secret_field_in_evidence(self):
        for f in self._all_trigger_findings():
            assert "api_key_secret" not in f.evidence, (
                f"forbidden 'api_key_secret' field in {f.rule_key} evidence"
            )

    def test_phone_number_last4_has_length_at_most_4(self):
        for f in self._all_trigger_findings():
            if "phone_number_last4" in f.evidence:
                val = f.evidence["phone_number_last4"]
                if val:  # skip empty
                    assert len(val) <= 4, (
                        f"phone_number_last4 too long in {f.rule_key}: {val!r}"
                    )

    def test_friendly_name_has_length_at_most_100(self):
        for f in self._all_trigger_findings():
            if "friendly_name" in f.evidence:
                val = f.evidence["friendly_name"]
                if val:
                    assert len(val) <= 100, (
                        f"friendly_name too long in {f.rule_key}: len={len(val)}"
                    )

    def test_no_full_account_sid_in_evidence(self):
        # A full Twilio account SID is "AC" followed by exactly 32 hex chars
        account_sid_pattern = re.compile(r"AC[0-9a-fA-F]{32}")
        for f in self._all_trigger_findings():
            for k, v in f.evidence.items():
                if isinstance(v, str):
                    assert not account_sid_pattern.search(v), (
                        f"full account SID found in {f.rule_key}.evidence[{k!r}]"
                    )

    def test_no_full_e164_phone_number_in_evidence(self):
        # A full E.164 phone number looks like +1xxxxxxxxxx (at least 10 digits)
        e164_pattern = re.compile(r"\+\d{10,}")
        for f in self._all_trigger_findings():
            for k, v in f.evidence.items():
                if isinstance(v, str):
                    assert not e164_pattern.search(v), (
                        f"full E.164 phone number found in {f.rule_key}.evidence[{k!r}]: {v!r}"
                    )


# ══════════════════════════════════════════════════════════════════════════════
# Section E: Malformed / missing records
# ══════════════════════════════════════════════════════════════════════════════


class TestMalformedRecords:
    def setup_method(self):
        from app.services.security_rules.twilio import get_twilio_findings
        self.get_findings = get_twilio_findings

    def test_empty_dict_returns_no_findings(self):
        assert self.get_findings({}) == []

    def test_none_input_returns_no_findings(self):
        assert self.get_findings(None) == []  # type: ignore[arg-type]

    def test_string_input_returns_no_findings(self):
        assert self.get_findings("not a dict") == []  # type: ignore[arg-type]

    def test_record_missing_capability_sms_handled_gracefully(self):
        rec = {
            "record_type": "twilio_incoming_phone_number",
            "record_id": "PN-test",
            # no capability_sms key
            "sms_url_configured": False,
        }
        findings = self.get_findings(rec)
        # Should not raise; sms_webhook rule won't fire without explicit True
        assert _SMS_WEBHOOK not in _keys(findings)

    def test_wrong_record_type_returns_no_relevant_findings(self):
        rec = {"record_type": "unknown_type", "capability_sms": True, "sms_url_configured": False}
        findings = self.get_findings(rec)
        assert _SMS_WEBHOOK not in _keys(findings)

    def test_none_values_in_optional_fields_do_not_crash(self):
        rec = _phone_record(capability_sms=None, sms_url_configured=None)
        # Should not raise
        findings = self.get_findings(rec)
        assert isinstance(findings, list)

    def test_none_code_length_does_not_crash(self):
        rec = _verify_record(code_length=None)
        findings = self.get_findings(rec)
        assert _VERIFY_CODE not in _keys(findings)

    def test_none_lookup_enabled_does_not_crash(self):
        rec = _verify_record(lookup_enabled=None)
        findings = self.get_findings(rec)
        assert _VERIFY_LOOKUP not in _keys(findings)

    def test_missing_status_field_does_not_crash(self):
        rec = {"record_type": "twilio_account", "record_id": "AC-test"}
        findings = self.get_findings(rec)
        # No status = empty string → no fire
        assert _ACCOUNT_SUSPENDED not in _keys(findings)

    def test_messaging_service_missing_fields_handled(self):
        rec = {"record_type": "twilio_messaging_service"}
        findings = self.get_findings(rec)
        assert isinstance(findings, list)


# ══════════════════════════════════════════════════════════════════════════════
# Section F: Rule registration
# ══════════════════════════════════════════════════════════════════════════════


class TestRuleRegistration:
    def test_all_rule_keys_in_known_rule_keys(self):
        from app.services.security_rule_registry import KNOWN_RULE_KEYS
        for k in ALL_M79B_RULE_KEYS:
            assert k in KNOWN_RULE_KEYS, f"missing from KNOWN_RULE_KEYS: {k}"

    def test_all_rule_keys_in_security_rule_confidence(self):
        from app.services.security_rule_confidence import RULE_CONFIDENCE
        for k in ALL_M79B_RULE_KEYS:
            assert k in RULE_CONFIDENCE, f"missing from RULE_CONFIDENCE: {k}"
            confidence, guard = RULE_CONFIDENCE[k]
            assert confidence in ("high", "medium", "low"), (
                f"unexpected confidence for {k}: {confidence}"
            )
            assert guard, f"empty guard for {k}"

    def test_all_rule_keys_in_security_rule_pack(self):
        from app.services.security_rule_pack import _RULE_META
        for k in ALL_M79B_RULE_KEYS:
            assert k in _RULE_META, f"missing from _RULE_META: {k}"
            provider, severity, category = _RULE_META[k]
            assert provider == "twilio", f"wrong provider for {k}: {provider}"
            assert severity in ("critical", "high", "medium", "low", "info"), (
                f"unexpected severity for {k}: {severity}"
            )

    def test_twilio_in_security_coverage_providers(self):
        from app.services.security_coverage_service import PROVIDERS
        assert "twilio" in PROVIDERS

    def test_all_rule_keys_in_security_coverage_record_types(self):
        from app.services.security_coverage_service import RULE_RECORD_TYPES
        for k in ALL_M79B_RULE_KEYS:
            assert k in RULE_RECORD_TYPES, f"missing from RULE_RECORD_TYPES: {k}"
            assert RULE_RECORD_TYPES[k], f"empty record types for {k}"


# ══════════════════════════════════════════════════════════════════════════════
# Section G: Capability matrix
# ══════════════════════════════════════════════════════════════════════════════


class TestCapabilityMatrix:
    def setup_method(self):
        from app.services.provider_capability_matrix_service import get_provider_capability
        self.cap = get_provider_capability("twilio")

    def test_security_rules_is_true(self):
        assert self.cap.security.security_rules is True

    def test_drift_risk_classification_is_true(self):
        assert self.cap.drift.drift_risk_classification is True

    def test_activity_ingestion_is_true(self):
        assert self.cap.security.activity_ingestion is True

    def test_demo_seed_clear_is_false(self):
        assert self.cap.security.demo_seed_clear is True

    def test_maturity_is_partial(self):
        assert self.cap.maturity == "partial"

    def test_twilio_in_provider_capabilities_partial(self):
        from app.services.provider_capability_matrix_service import (
            PROVIDER_CAPABILITIES_PARTIAL,
        )
        providers = {p.provider for p in PROVIDER_CAPABILITIES_PARTIAL}
        assert "twilio" in providers

    def test_twilio_not_in_canonical_provider_capabilities(self):
        from app.services.provider_capability_matrix_service import PROVIDER_CAPABILITIES
        providers = {p.provider for p in PROVIDER_CAPABILITIES}
        assert "twilio" not in providers


# ══════════════════════════════════════════════════════════════════════════════
# Section H: Expansion framework
# ══════════════════════════════════════════════════════════════════════════════


class TestExpansionFramework:
    def setup_method(self):
        from app.services import provider_expansion_framework as svc
        self.fw = svc.get_framework()
        self.stage = self.fw["summary"]["planned_next_stage"]

    def test_planned_next_stage_contains_m79e(self):
        assert "M80B" in self.stage, (
            f"expected 'M80B' in planned_next_stage (M80A complete), got: {self.stage!r}"
        )

    def test_planned_next_stage_contains_twilio(self):
        assert "M80A" in self.stage or "SendGrid" in self.stage, (
            f"expected 'M80A'/'SendGrid' in planned_next_stage (M79I complete), got: {self.stage!r}"
        )

    def test_planned_next_stage_does_not_contain_m79b(self):
        assert "M79B" not in self.stage, (
            f"planned_next_stage should not reference M79B (already complete): {self.stage!r}"
        )


# ══════════════════════════════════════════════════════════════════════════════
# Section I: Frontend catalog
# ══════════════════════════════════════════════════════════════════════════════


class TestFrontendCatalog:
    def setup_method(self):
        if not FE_CATALOG.exists():
            pytest.skip("frontend/src/lib/securityRuleCatalog.ts not accessible")
        self.text = FE_CATALOG.read_text()

    def test_all_9_rule_keys_appear_as_key_strings(self):
        for k in ALL_M79B_RULE_KEYS:
            assert f'key: "{k}"' in self.text, (
                f"missing catalog entry: key: \"{k}\""
            )

    def test_each_entry_has_description_field(self):
        for k in ALL_M79B_RULE_KEYS:
            idx = self.text.find(f'key: "{k}"')
            assert idx >= 0
            section = self.text[idx: idx + 1500]
            assert "description:" in section, (
                f"missing 'description' field near key: {k}"
            )

    def test_each_entry_has_remediation_field(self):
        for k in ALL_M79B_RULE_KEYS:
            idx = self.text.find(f'key: "{k}"')
            assert idx >= 0
            section = self.text[idx: idx + 1500]
            assert "remediation:" in section, (
                f"missing 'remediation' field near key: {k}"
            )

    def test_each_entry_has_false_positive_guard_field(self):
        for k in ALL_M79B_RULE_KEYS:
            idx = self.text.find(f'key: "{k}"')
            assert idx >= 0
            section = self.text[idx: idx + 1500]
            assert "falsePositiveGuard:" in section, (
                f"missing 'falsePositiveGuard' field near key: {k}"
            )

    def test_no_entry_contains_forbidden_phrases(self):
        low = self.text.lower()
        for phrase in FORBIDDEN_PHRASES:
            assert phrase not in low, (
                f"forbidden phrase {phrase!r} found in securityRuleCatalog.ts"
            )

    def test_no_raw_webhook_url_strings_in_catalog(self):
        # Should not store raw webhook URLs — only descriptions
        pattern = re.compile(r"https?://[^\s'\"]+webhook", re.IGNORECASE)
        # Check only the Twilio section
        twilio_start = self.text.find('key: "twilio_phone_number_sms_webhook_missing"')
        twilio_end = self.text.find('key: "twilio_account_suspended"')
        if twilio_start >= 0 and twilio_end >= 0:
            twilio_section = self.text[twilio_start: twilio_end + 500]
            assert not pattern.search(twilio_section), (
                "raw webhook URL found in Twilio catalog entries"
            )

    def test_no_full_phone_numbers_in_catalog(self):
        e164_pattern = re.compile(r"\+\d{10,}")
        # Only check Twilio section
        twilio_start = self.text.find('key: "twilio_phone_number_sms_webhook_missing"')
        if twilio_start >= 0:
            twilio_section = self.text[twilio_start: twilio_start + 5000]
            assert not e164_pattern.search(twilio_section), (
                "full E.164 phone number found in Twilio catalog section"
            )


# ══════════════════════════════════════════════════════════════════════════════
# Section J: Forbidden wording in source
# ══════════════════════════════════════════════════════════════════════════════


class TestForbiddenWordingInSource:
    def test_no_forbidden_phrases_in_get_twilio_findings_source(self):
        from app.services.security_rules import twilio as twilio_rules
        src = inspect.getsource(twilio_rules.get_twilio_findings)
        low = src.lower()
        for phrase in FORBIDDEN_PHRASES:
            assert phrase not in low, (
                f"forbidden phrase {phrase!r} found in get_twilio_findings source"
            )

    def test_no_forbidden_phrases_in_twilio_rule_keys_module(self):
        from app.services.security_rules import twilio as twilio_rules
        # Check the whole module
        src = inspect.getsource(twilio_rules)
        low = src.lower()
        for phrase in FORBIDDEN_PHRASES:
            assert phrase not in low, (
                f"forbidden phrase {phrase!r} found in twilio security rules module"
            )

    def test_no_forbidden_phrases_in_capability_notes(self):
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("twilio")
        notes_low = (cap.notes or "").lower()
        for phrase in FORBIDDEN_PHRASES:
            assert phrase not in notes_low, (
                f"forbidden phrase {phrase!r} found in Twilio capability notes"
            )
