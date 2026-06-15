"""M79C — Twilio Messaging/Webhook Risk Expansion.

Pins the third Twilio arc milestone:
  * TWILIO_RULE_KEYS now contains 17 keys (9 from M79B + 8 new from M79C)
  * get_twilio_findings fires correctly for all 8 new M79C rules
  * Rules do NOT fire on healthy/partial records
  * Evidence privacy: no raw URLs, no full phone numbers, no auth secrets
  * API key staleness logic handles tz-aware and tz-naive dates correctly
  * Compound observability-gap rules are distinct from individual M79B rules
  * Registry / confidence / pack / coverage all stay in parity
  * Provider capability matrix reflects M79C state
  * Expansion framework planned_next_stage → M79D / Activity
  * Frontend catalog contains all 8 new rule keys with required fields
  * No forbidden wording anywhere in the module

These rules are configuration-posture findings only. A finding is evidence
for review and never asserts that a breach occurred, that data leaked, or
that an attacker has access.
"""

from __future__ import annotations

import inspect
import re
from datetime import datetime, timedelta, timezone
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

# ── M79B rule keys (still expected to exist) ──────────────────────────────────

_M79B_RULE_KEYS: frozenset[str] = frozenset({
    "twilio_phone_number_sms_webhook_missing",
    "twilio_phone_number_voice_webhook_missing",
    "twilio_phone_number_status_callback_missing",
    "twilio_messaging_service_inbound_webhook_missing",
    "twilio_messaging_service_fallback_missing",
    "twilio_messaging_service_status_callback_missing",
    "twilio_verify_short_code_length",
    "twilio_verify_lookup_disabled",
    "twilio_account_suspended",
})

# ── M79C rule keys (new in this milestone) ────────────────────────────────────

_API_KEY_STALE = "twilio_api_key_stale"
_MSG_OBS_GAP = "twilio_messaging_service_observability_gap"
_MSG_NUMBER_INBOUND = "twilio_messaging_service_number_level_inbound_webhook"
_MSG_LONG_VALIDITY = "twilio_messaging_service_long_validity_period"
_PHONE_MSG_OBS_GAP = "twilio_phone_number_messaging_observability_gap"
_PHONE_VOICE_OBS_GAP = "twilio_phone_number_voice_observability_gap"
_VERIFY_PSD2 = "twilio_verify_psd2_disabled"
_VERIFY_LANDLINES = "twilio_verify_sms_to_landlines_allowed"

ALL_M79C_NEW_RULE_KEYS: frozenset[str] = frozenset({
    _API_KEY_STALE,
    _MSG_OBS_GAP,
    _MSG_NUMBER_INBOUND,
    _MSG_LONG_VALIDITY,
    _PHONE_MSG_OBS_GAP,
    _PHONE_VOICE_OBS_GAP,
    _VERIFY_PSD2,
    _VERIFY_LANDLINES,
})

# ── Helpers ───────────────────────────────────────────────────────────────────


def _keys(findings) -> set[str]:
    return {f.rule_key for f in findings}


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
        "validity_period": 3600,
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
        "psd2_enabled": True,
        "skip_sms_to_landlines": True,
    }
    base.update(overrides)
    return base


def _api_key_record(**overrides) -> dict[str, Any]:
    base: dict[str, Any] = {
        "record_type": "twilio_api_key_summary",
        "record_id": "SK-test-001",
        "api_key_sid": "SK-test-sid",
        "friendly_name": "Test API Key",
        "date_created": None,
        "date_updated": None,
    }
    base.update(overrides)
    return base


def _days_ago_iso(days: int) -> str:
    dt = datetime.now(timezone.utc) - timedelta(days=days)
    return dt.isoformat()


# ══════════════════════════════════════════════════════════════════════════════
# Section A: New rule key existence
# ══════════════════════════════════════════════════════════════════════════════


class TestRuleKeyExistence:
    def setup_method(self):
        from app.services.security_rules.twilio import TWILIO_RULE_KEYS
        self.keys = TWILIO_RULE_KEYS

    def test_total_rule_keys_is_17(self):
        assert len(self.keys) == 17, (
            f"expected 17 total rule keys, got {len(self.keys)}: {sorted(self.keys)}"
        )

    def test_api_key_stale_in_keys(self):
        assert _API_KEY_STALE in self.keys

    def test_msg_observability_gap_in_keys(self):
        assert _MSG_OBS_GAP in self.keys

    def test_msg_number_level_inbound_in_keys(self):
        assert _MSG_NUMBER_INBOUND in self.keys

    def test_msg_long_validity_in_keys(self):
        assert _MSG_LONG_VALIDITY in self.keys

    def test_phone_messaging_observability_gap_in_keys(self):
        assert _PHONE_MSG_OBS_GAP in self.keys

    def test_phone_voice_observability_gap_in_keys(self):
        assert _PHONE_VOICE_OBS_GAP in self.keys

    def test_verify_psd2_disabled_in_keys(self):
        assert _VERIFY_PSD2 in self.keys

    def test_verify_sms_to_landlines_allowed_in_keys(self):
        assert _VERIFY_LANDLINES in self.keys

    def test_all_m79b_keys_still_present(self):
        missing = _M79B_RULE_KEYS - self.keys
        assert missing == frozenset(), f"M79B rules removed from TWILIO_RULE_KEYS: {missing}"

    def test_all_m79c_new_keys_present(self):
        missing = ALL_M79C_NEW_RULE_KEYS - self.keys
        assert missing == frozenset(), f"M79C rule keys missing: {missing}"


# ══════════════════════════════════════════════════════════════════════════════
# Section B: Rules trigger correctly
# ══════════════════════════════════════════════════════════════════════════════


class TestRulesTriggerCorrectly:
    def setup_method(self):
        from app.services.security_rules.twilio import get_twilio_findings
        self.get_findings = get_twilio_findings

    # B1. twilio_api_key_stale ─────────────────────────────────────────────────

    def test_b1_api_key_stale_fires_on_old_date_created(self):
        rec = _api_key_record(date_created="2020-01-01T00:00:00Z")
        findings = self.get_findings(rec)
        assert _API_KEY_STALE in _keys(findings)

    def test_b1_api_key_stale_fires_when_date_updated_200_days_ago(self):
        rec = _api_key_record(date_updated=_days_ago_iso(200))
        findings = self.get_findings(rec)
        assert _API_KEY_STALE in _keys(findings)

    def test_b1_api_key_stale_does_not_fire_when_date_updated_30_days_ago(self):
        rec = _api_key_record(date_updated=_days_ago_iso(30))
        findings = self.get_findings(rec)
        assert _API_KEY_STALE not in _keys(findings)

    def test_b1_api_key_stale_does_not_fire_when_no_dates(self):
        rec = _api_key_record()  # date_created=None, date_updated=None
        findings = self.get_findings(rec)
        assert _API_KEY_STALE not in _keys(findings)

    # B2. twilio_messaging_service_observability_gap ──────────────────────────

    def test_b2_msg_observability_gap_fires_when_both_false(self):
        rec = _messaging_record(
            fallback_url_configured=False,
            status_callback_url_configured=False,
        )
        findings = self.get_findings(rec)
        assert _MSG_OBS_GAP in _keys(findings)

    def test_b2_msg_observability_gap_does_not_fire_when_only_fallback_true(self):
        rec = _messaging_record(
            fallback_url_configured=True,
            status_callback_url_configured=False,
        )
        findings = self.get_findings(rec)
        assert _MSG_OBS_GAP not in _keys(findings)

    def test_b2_msg_observability_gap_does_not_fire_when_only_status_callback_true(self):
        rec = _messaging_record(
            fallback_url_configured=False,
            status_callback_url_configured=True,
        )
        findings = self.get_findings(rec)
        assert _MSG_OBS_GAP not in _keys(findings)

    def test_b2_msg_observability_gap_does_not_fire_when_both_true(self):
        rec = _messaging_record(
            fallback_url_configured=True,
            status_callback_url_configured=True,
        )
        findings = self.get_findings(rec)
        assert _MSG_OBS_GAP not in _keys(findings)

    # B3. twilio_messaging_service_number_level_inbound_webhook ───────────────

    def test_b3_msg_number_level_inbound_fires_when_use_webhook_on_number_and_no_service_url(self):
        rec = _messaging_record(
            use_inbound_webhook_on_number=True,
            inbound_request_url_configured=False,
        )
        findings = self.get_findings(rec)
        assert _MSG_NUMBER_INBOUND in _keys(findings)

    def test_b3_msg_number_level_inbound_does_not_fire_when_use_webhook_false(self):
        rec = _messaging_record(
            use_inbound_webhook_on_number=False,
            inbound_request_url_configured=False,
        )
        findings = self.get_findings(rec)
        assert _MSG_NUMBER_INBOUND not in _keys(findings)

    def test_b3_msg_number_level_inbound_does_not_fire_when_service_url_configured(self):
        rec = _messaging_record(
            use_inbound_webhook_on_number=True,
            inbound_request_url_configured=True,
        )
        findings = self.get_findings(rec)
        assert _MSG_NUMBER_INBOUND not in _keys(findings)

    # B4. twilio_messaging_service_long_validity_period ───────────────────────

    def test_b4_msg_long_validity_fires_on_172800(self):
        rec = _messaging_record(validity_period=172800)
        findings = self.get_findings(rec)
        assert _MSG_LONG_VALIDITY in _keys(findings)

    def test_b4_msg_long_validity_does_not_fire_on_86400(self):
        # threshold is > 86400, not >=
        rec = _messaging_record(validity_period=86400)
        findings = self.get_findings(rec)
        assert _MSG_LONG_VALIDITY not in _keys(findings)

    def test_b4_msg_long_validity_does_not_fire_on_3600(self):
        rec = _messaging_record(validity_period=3600)
        findings = self.get_findings(rec)
        assert _MSG_LONG_VALIDITY not in _keys(findings)

    def test_b4_msg_long_validity_does_not_fire_on_none(self):
        rec = _messaging_record(validity_period=None)
        findings = self.get_findings(rec)
        assert _MSG_LONG_VALIDITY not in _keys(findings)

    def test_b4_msg_long_validity_does_not_fire_when_field_missing(self):
        base = {
            "record_type": "twilio_messaging_service",
            "record_id": "MG-no-vp",
            "friendly_name": "No Validity Period",
            "inbound_request_url_configured": True,
            "fallback_url_configured": True,
            "status_callback_url_configured": True,
            "use_inbound_webhook_on_number": False,
        }
        findings = self.get_findings(base)
        assert _MSG_LONG_VALIDITY not in _keys(findings)

    # B5. twilio_phone_number_messaging_observability_gap ─────────────────────

    def test_b5_phone_msg_obs_gap_fires(self):
        rec = _phone_record(
            capability_sms=True,
            sms_url_configured=False,
            status_callback_configured=False,
        )
        findings = self.get_findings(rec)
        assert _PHONE_MSG_OBS_GAP in _keys(findings)

    def test_b5_phone_msg_obs_gap_does_not_fire_when_sms_url_configured(self):
        rec = _phone_record(
            capability_sms=True,
            sms_url_configured=True,
            status_callback_configured=False,
        )
        findings = self.get_findings(rec)
        assert _PHONE_MSG_OBS_GAP not in _keys(findings)

    def test_b5_phone_msg_obs_gap_does_not_fire_when_no_sms_capability(self):
        rec = _phone_record(
            capability_sms=False,
            sms_url_configured=False,
            status_callback_configured=False,
        )
        findings = self.get_findings(rec)
        assert _PHONE_MSG_OBS_GAP not in _keys(findings)

    # B6. twilio_phone_number_voice_observability_gap ─────────────────────────

    def test_b6_phone_voice_obs_gap_fires(self):
        rec = _phone_record(
            capability_voice=True,
            voice_url_configured=False,
            status_callback_configured=False,
        )
        findings = self.get_findings(rec)
        assert _PHONE_VOICE_OBS_GAP in _keys(findings)

    def test_b6_phone_voice_obs_gap_does_not_fire_when_voice_url_configured(self):
        rec = _phone_record(
            capability_voice=True,
            voice_url_configured=True,
            status_callback_configured=False,
        )
        findings = self.get_findings(rec)
        assert _PHONE_VOICE_OBS_GAP not in _keys(findings)

    def test_b6_phone_voice_obs_gap_does_not_fire_when_no_voice_capability(self):
        rec = _phone_record(
            capability_voice=False,
            voice_url_configured=False,
            status_callback_configured=False,
        )
        findings = self.get_findings(rec)
        assert _PHONE_VOICE_OBS_GAP not in _keys(findings)

    # B7. twilio_verify_psd2_disabled ─────────────────────────────────────────

    def test_b7_verify_psd2_disabled_fires_on_false(self):
        rec = _verify_record(psd2_enabled=False)
        findings = self.get_findings(rec)
        assert _VERIFY_PSD2 in _keys(findings)

    def test_b7_verify_psd2_disabled_does_not_fire_on_true(self):
        rec = _verify_record(psd2_enabled=True)
        findings = self.get_findings(rec)
        assert _VERIFY_PSD2 not in _keys(findings)

    def test_b7_verify_psd2_disabled_does_not_fire_on_none(self):
        rec = _verify_record(psd2_enabled=None)
        findings = self.get_findings(rec)
        assert _VERIFY_PSD2 not in _keys(findings)

    def test_b7_verify_psd2_disabled_does_not_fire_when_field_missing(self):
        base = {
            "record_type": "twilio_verify_service",
            "record_id": "VA-no-psd2",
            "friendly_name": "No PSD2 Field",
            "code_length": 6,
            "lookup_enabled": True,
            "skip_sms_to_landlines": True,
        }
        findings = self.get_findings(base)
        assert _VERIFY_PSD2 not in _keys(findings)

    # B8. twilio_verify_sms_to_landlines_allowed ──────────────────────────────

    def test_b8_verify_sms_to_landlines_fires_on_false(self):
        rec = _verify_record(skip_sms_to_landlines=False)
        findings = self.get_findings(rec)
        assert _VERIFY_LANDLINES in _keys(findings)

    def test_b8_verify_sms_to_landlines_does_not_fire_on_true(self):
        rec = _verify_record(skip_sms_to_landlines=True)
        findings = self.get_findings(rec)
        assert _VERIFY_LANDLINES not in _keys(findings)

    def test_b8_verify_sms_to_landlines_does_not_fire_on_none(self):
        rec = _verify_record(skip_sms_to_landlines=None)
        findings = self.get_findings(rec)
        assert _VERIFY_LANDLINES not in _keys(findings)

    def test_b8_verify_sms_to_landlines_does_not_fire_when_field_missing(self):
        base = {
            "record_type": "twilio_verify_service",
            "record_id": "VA-no-landlines",
            "friendly_name": "No Landlines Field",
            "code_length": 6,
            "lookup_enabled": True,
            "psd2_enabled": True,
        }
        findings = self.get_findings(base)
        assert _VERIFY_LANDLINES not in _keys(findings)


# ══════════════════════════════════════════════════════════════════════════════
# Section C: Evidence privacy
# ══════════════════════════════════════════════════════════════════════════════


class TestEvidencePrivacy:
    def setup_method(self):
        from app.services.security_rules.twilio import get_twilio_findings
        self.get_findings = get_twilio_findings

    def _all_m79c_trigger_findings(self):
        """Return findings from all M79C trigger conditions."""
        records = [
            _api_key_record(date_created="2020-01-01T00:00:00Z"),
            _messaging_record(
                fallback_url_configured=False,
                status_callback_url_configured=False,
            ),
            _messaging_record(
                use_inbound_webhook_on_number=True,
                inbound_request_url_configured=False,
            ),
            _messaging_record(validity_period=172800),
            _phone_record(
                capability_sms=True,
                sms_url_configured=False,
                status_callback_configured=False,
            ),
            _phone_record(
                capability_voice=True,
                voice_url_configured=False,
                status_callback_configured=False,
            ),
            _verify_record(psd2_enabled=False),
            _verify_record(skip_sms_to_landlines=False),
        ]
        findings = []
        for rec in records:
            for f in self.get_findings(rec):
                if f.rule_key in ALL_M79C_NEW_RULE_KEYS:
                    findings.append(f)
        return findings

    def test_no_sms_url_field_in_evidence(self):
        for f in self._all_m79c_trigger_findings():
            assert "sms_url" not in f.evidence, (
                f"forbidden 'sms_url' in {f.rule_key} evidence"
            )

    def test_no_voice_url_field_in_evidence(self):
        for f in self._all_m79c_trigger_findings():
            assert "voice_url" not in f.evidence, (
                f"forbidden 'voice_url' in {f.rule_key} evidence"
            )

    def test_no_inbound_request_url_field_in_evidence(self):
        for f in self._all_m79c_trigger_findings():
            assert "inbound_request_url" not in f.evidence, (
                f"forbidden 'inbound_request_url' in {f.rule_key} evidence"
            )

    def test_no_fallback_url_field_in_evidence(self):
        for f in self._all_m79c_trigger_findings():
            assert "fallback_url" not in f.evidence, (
                f"forbidden 'fallback_url' in {f.rule_key} evidence"
            )

    def test_no_status_callback_url_field_in_evidence(self):
        for f in self._all_m79c_trigger_findings():
            assert "status_callback_url" not in f.evidence, (
                f"forbidden 'status_callback_url' in {f.rule_key} evidence"
            )

    def test_no_auth_token_in_evidence(self):
        for f in self._all_m79c_trigger_findings():
            assert "auth_token" not in f.evidence, (
                f"forbidden 'auth_token' in {f.rule_key} evidence"
            )

    def test_no_api_secret_in_evidence(self):
        for f in self._all_m79c_trigger_findings():
            assert "api_secret" not in f.evidence, (
                f"forbidden 'api_secret' in {f.rule_key} evidence"
            )

    def test_no_api_key_secret_in_evidence(self):
        for f in self._all_m79c_trigger_findings():
            assert "api_key_secret" not in f.evidence, (
                f"forbidden 'api_key_secret' in {f.rule_key} evidence"
            )

    def test_phone_number_last4_is_safe(self):
        for f in self._all_m79c_trigger_findings():
            if "phone_number_last4" in f.evidence:
                val = f.evidence["phone_number_last4"]
                if val:
                    assert len(val) <= 4, (
                        f"phone_number_last4 too long in {f.rule_key}: {val!r}"
                    )

    def test_no_full_e164_phone_number_in_evidence(self):
        e164_pattern = re.compile(r"\+\d{10,}")
        for f in self._all_m79c_trigger_findings():
            for k, v in f.evidence.items():
                if isinstance(v, str):
                    assert not e164_pattern.search(v), (
                        f"full E.164 phone number in {f.rule_key}.evidence[{k!r}]: {v!r}"
                    )

    def test_api_key_evidence_has_no_secret_only_metadata(self):
        rec = _api_key_record(date_created="2020-01-01T00:00:00Z")
        findings = self.get_findings(rec)
        api_key_findings = [f for f in findings if f.rule_key == _API_KEY_STALE]
        assert api_key_findings, "expected twilio_api_key_stale to fire"
        for f in api_key_findings:
            assert "api_secret" not in f.evidence
            assert "api_key_secret" not in f.evidence
            assert "auth_token" not in f.evidence

    def test_api_key_evidence_date_fields_are_safe_timestamps(self):
        """date_created / date_updated are ISO timestamps, not secrets."""
        rec = _api_key_record(date_created="2020-01-01T00:00:00Z")
        findings = self.get_findings(rec)
        api_key_findings = [f for f in findings if f.rule_key == _API_KEY_STALE]
        assert api_key_findings
        f = api_key_findings[0]
        # date fields are permitted — just verify no forbidden secret-like fields
        assert "api_secret" not in f.evidence
        assert "auth_token" not in f.evidence


# ══════════════════════════════════════════════════════════════════════════════
# Section D: Registration checks
# ══════════════════════════════════════════════════════════════════════════════


class TestRegistration:
    def test_all_m79c_rule_keys_in_known_rule_keys(self):
        from app.services.security_rule_registry import KNOWN_RULE_KEYS
        for k in ALL_M79C_NEW_RULE_KEYS:
            assert k in KNOWN_RULE_KEYS, f"missing from KNOWN_RULE_KEYS: {k}"

    def test_all_m79c_rule_keys_in_security_rule_confidence(self):
        from app.services.security_rule_confidence import RULE_CONFIDENCE
        for k in ALL_M79C_NEW_RULE_KEYS:
            assert k in RULE_CONFIDENCE, f"missing from RULE_CONFIDENCE: {k}"
            confidence, guard = RULE_CONFIDENCE[k]
            assert confidence in ("high", "medium", "low"), (
                f"unexpected confidence for {k}: {confidence}"
            )
            assert guard, f"empty guard for {k}"

    def test_all_m79c_rule_keys_in_security_rule_pack(self):
        from app.services.security_rule_pack import _RULE_META
        for k in ALL_M79C_NEW_RULE_KEYS:
            assert k in _RULE_META, f"missing from _RULE_META: {k}"
            provider, severity, category = _RULE_META[k]
            assert provider == "twilio", f"wrong provider for {k}: {provider}"
            assert severity in ("critical", "high", "medium", "low", "info"), (
                f"unexpected severity for {k}: {severity}"
            )

    def test_twilio_in_security_coverage_providers(self):
        from app.services.security_coverage_service import PROVIDERS
        assert "twilio" in PROVIDERS


# ══════════════════════════════════════════════════════════════════════════════
# Section E: Capability matrix + expansion framework
# ══════════════════════════════════════════════════════════════════════════════


class TestCapabilityMatrixAndExpansion:
    def setup_method(self):
        from app.services.provider_capability_matrix_service import get_provider_capability
        self.cap = get_provider_capability("twilio")

    def test_security_rules_is_true(self):
        assert self.cap.security.security_rules is True

    def test_maturity_is_partial(self):
        assert self.cap.maturity == "partial"

    def test_activity_ingestion_is_true(self):
        assert self.cap.security.activity_ingestion is True

    def test_planned_next_stage_contains_m79e(self):
        from app.services import provider_expansion_framework as svc
        fw = svc.get_framework()
        stage = fw["summary"]["planned_next_stage"]
        assert "M79G" in stage, (
            f"expected 'M79G' in planned_next_stage (M79F complete), got: {stage!r}"
        )

    def test_planned_next_stage_contains_twilio_or_signal(self):
        from app.services import provider_expansion_framework as svc
        fw = svc.get_framework()
        stage = fw["summary"]["planned_next_stage"]
        assert "Twilio" in stage or "Signal" in stage, (
            f"expected 'Twilio' or 'Signal' in planned_next_stage, got: {stage!r}"
        )

    def test_planned_next_stage_does_not_contain_m79c(self):
        from app.services import provider_expansion_framework as svc
        fw = svc.get_framework()
        stage = fw["summary"]["planned_next_stage"]
        assert "M79C" not in stage, (
            f"planned_next_stage should not reference M79C (already complete): {stage!r}"
        )


# ══════════════════════════════════════════════════════════════════════════════
# Section F: Frontend catalog
# ══════════════════════════════════════════════════════════════════════════════


class TestFrontendCatalog:
    def setup_method(self):
        if not FE_CATALOG.exists():
            pytest.skip("frontend/src/lib/securityRuleCatalog.ts not accessible")
        self.text = FE_CATALOG.read_text()

    def test_all_8_m79c_rule_keys_appear_as_key_strings(self):
        for k in ALL_M79C_NEW_RULE_KEYS:
            assert f'key: "{k}"' in self.text, (
                f"missing catalog entry: key: \"{k}\""
            )

    def test_each_entry_has_description_field(self):
        for k in ALL_M79C_NEW_RULE_KEYS:
            idx = self.text.find(f'key: "{k}"')
            assert idx >= 0
            section = self.text[idx: idx + 1500]
            assert "description:" in section, (
                f"missing 'description' field near key: {k}"
            )

    def test_each_entry_has_remediation_field(self):
        for k in ALL_M79C_NEW_RULE_KEYS:
            idx = self.text.find(f'key: "{k}"')
            assert idx >= 0
            section = self.text[idx: idx + 1500]
            assert "remediation:" in section, (
                f"missing 'remediation' field near key: {k}"
            )

    def test_each_entry_has_false_positive_guard_field(self):
        for k in ALL_M79C_NEW_RULE_KEYS:
            idx = self.text.find(f'key: "{k}"')
            assert idx >= 0
            section = self.text[idx: idx + 1500]
            assert "falsePositiveGuard:" in section, (
                f"missing 'falsePositiveGuard' field near key: {k}"
            )

    def test_no_forbidden_phrases_in_catalog_entries(self):
        low = self.text.lower()
        for phrase in FORBIDDEN_PHRASES:
            assert phrase not in low, (
                f"forbidden phrase {phrase!r} found in securityRuleCatalog.ts"
            )


# ══════════════════════════════════════════════════════════════════════════════
# Section G: Forbidden wording + privacy
# ══════════════════════════════════════════════════════════════════════════════


class TestForbiddenWording:
    def test_no_forbidden_phrases_in_twilio_rule_keys(self):
        from app.services.security_rules.twilio import TWILIO_RULE_KEYS
        combined = " ".join(sorted(TWILIO_RULE_KEYS)).lower()
        for phrase in FORBIDDEN_PHRASES:
            assert phrase not in combined, (
                f"forbidden phrase {phrase!r} found in TWILIO_RULE_KEYS names"
            )

    def test_no_forbidden_phrases_in_get_twilio_findings_source(self):
        from app.services.security_rules import twilio as twilio_rules
        src = inspect.getsource(twilio_rules.get_twilio_findings)
        low = src.lower()
        for phrase in FORBIDDEN_PHRASES:
            assert phrase not in low, (
                f"forbidden phrase {phrase!r} found in get_twilio_findings source"
            )

    def test_no_forbidden_phrases_in_twilio_module_source(self):
        from app.services.security_rules import twilio as twilio_rules
        src = inspect.getsource(twilio_rules)
        low = src.lower()
        for phrase in FORBIDDEN_PHRASES:
            assert phrase not in low, (
                f"forbidden phrase {phrase!r} found in twilio security rules module"
            )


# ══════════════════════════════════════════════════════════════════════════════
# Section H: No M79B duplication — compound vs individual rules
# ══════════════════════════════════════════════════════════════════════════════


class TestNoM79BDuplication:
    """Verify that the M79C compound observability-gap rules are distinct from
    the individual M79B rules and fire only under the correct conditions."""

    def setup_method(self):
        from app.services.security_rules.twilio import get_twilio_findings
        self.get_findings = get_twilio_findings

    def test_observability_gap_is_different_from_fallback_missing(self):
        """twilio_messaging_service_observability_gap and
        twilio_messaging_service_fallback_missing are different rule keys."""
        assert _MSG_OBS_GAP != "twilio_messaging_service_fallback_missing"

    def test_observability_gap_is_different_from_status_callback_missing(self):
        """twilio_messaging_service_observability_gap and
        twilio_messaging_service_status_callback_missing are different rule keys."""
        assert _MSG_OBS_GAP != "twilio_messaging_service_status_callback_missing"

    def test_partial_gap_fires_individual_m79b_rule_not_compound_m79c(self):
        """When only fallback is missing (status_callback_url_configured=True),
        the M79B individual rule fires but the M79C compound rule does NOT."""
        rec = _messaging_record(
            fallback_url_configured=False,
            status_callback_url_configured=True,
        )
        findings = self.get_findings(rec)
        found_keys = _keys(findings)
        # M79B individual rule should fire
        assert "twilio_messaging_service_fallback_missing" in found_keys, (
            "expected twilio_messaging_service_fallback_missing to fire when "
            "only fallback is missing"
        )
        # M79C compound rule must NOT fire (only partial gap)
        assert _MSG_OBS_GAP not in found_keys, (
            "twilio_messaging_service_observability_gap must NOT fire when "
            "status_callback_url_configured=True (only partial gap)"
        )

    def test_compound_rule_fires_only_when_both_urls_missing(self):
        """The M79C compound rule fires only when BOTH fallback and status
        callback are absent."""
        rec = _messaging_record(
            fallback_url_configured=False,
            status_callback_url_configured=False,
        )
        findings = self.get_findings(rec)
        found_keys = _keys(findings)
        assert _MSG_OBS_GAP in found_keys, (
            "twilio_messaging_service_observability_gap should fire when "
            "both fallback and status callback are missing"
        )

    def test_status_callback_only_gap_fires_m79b_not_compound(self):
        """When only status_callback is missing (fallback_url_configured=True),
        the M79B individual rule fires but the M79C compound rule does NOT."""
        rec = _messaging_record(
            fallback_url_configured=True,
            status_callback_url_configured=False,
        )
        findings = self.get_findings(rec)
        found_keys = _keys(findings)
        assert "twilio_messaging_service_status_callback_missing" in found_keys, (
            "expected twilio_messaging_service_status_callback_missing to fire "
            "when only status callback is missing"
        )
        assert _MSG_OBS_GAP not in found_keys, (
            "twilio_messaging_service_observability_gap must NOT fire when "
            "fallback_url_configured=True (only partial gap)"
        )
