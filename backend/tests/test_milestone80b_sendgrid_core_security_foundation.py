"""M80B — SendGrid Core Security Foundation.

Pins the M80B SendGrid security rules milestone:
  * SENDGRID_RULE_KEYS contains exactly the 15 expected rule keys
  * evaluate() fires correctly on trigger conditions
  * Rules do NOT fire on healthy records
  * Evidence privacy: no API keys, bearer tokens, email addresses, URLs, PII
  * Malformed / missing records are handled gracefully
  * Registry / confidence / pack / coverage all stay in parity
  * Provider capability matrix reflects M80B state
  * Expansion framework planned_next_stage → M80C
  * Frontend catalog contains all 15 rule keys with required fields
  * No forbidden wording in the module or capability notes

These rules are configuration-posture findings only. A finding is evidence
for review and never asserts that a breach occurred, that data leaked, that
keys were compromised, or that an attacker has access.
"""

from __future__ import annotations

import inspect
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

# Sensitive field names that must NEVER appear in rule evidence.
SENSITIVE_EVIDENCE_FIELDS = frozenset({
    "api_key",
    "api_key_value",
    "api_key_secret",
    "secret",
    "bearer",
    "authorization",
    "access_token",
    "email",
    "from_email",
    "reply_to",
    "recipient_email",
    "suppressed_email",
    "url",
    "webhook_url",
    "bcc_address",
    "template_content",
    "subject",
})

# ── Expected rule keys ────────────────────────────────────────────────────────

_API_KEY_BROAD = "sendgrid_api_key_broad_scopes"
_SENDER_UNVERIFIED = "sendgrid_sender_identity_unverified"
_SENDER_LOCKED = "sendgrid_sender_identity_locked"
_DOMAIN_INVALID = "sendgrid_domain_authentication_invalid"
_DOMAIN_AUTO_SEC = "sendgrid_domain_automatic_security_disabled"
_DOMAIN_LEGACY = "sendgrid_domain_authentication_legacy"
_SPAM_CHECK = "sendgrid_spam_check_disabled"
_SANDBOX_MODE = "sendgrid_sandbox_mode_enabled"
_BCC_ENABLED = "sendgrid_bcc_enabled"
_CLICK_TRACK = "sendgrid_click_tracking_enabled"
_OPEN_TRACK = "sendgrid_open_tracking_enabled"
_SUB_TRACK = "sendgrid_subscription_tracking_disabled"
_WEBHOOK_DISABLED = "sendgrid_event_webhook_disabled"
_WEBHOOK_URL_MISSING = "sendgrid_event_webhook_url_missing"
_SUPPRESSION_EMPTY = "sendgrid_suppression_settings_empty"

ALL_M80B_RULE_KEYS: frozenset[str] = frozenset({
    _API_KEY_BROAD,
    _SENDER_UNVERIFIED,
    _SENDER_LOCKED,
    _DOMAIN_INVALID,
    _DOMAIN_AUTO_SEC,
    _DOMAIN_LEGACY,
    _SPAM_CHECK,
    _SANDBOX_MODE,
    _BCC_ENABLED,
    _CLICK_TRACK,
    _OPEN_TRACK,
    _SUB_TRACK,
    _WEBHOOK_DISABLED,
    _WEBHOOK_URL_MISSING,
    _SUPPRESSION_EMPTY,
})

# ── Record builders ───────────────────────────────────────────────────────────


def _api_key_record(**overrides) -> dict[str, Any]:
    base: dict[str, Any] = {
        "record_type": "sendgrid_api_key",
        "record_id": "SENDGRID_TEST_API_KEY_PLACEHOLDER_ID",
        "api_key_id": "SENDGRID_TEST_API_KEY_PLACEHOLDER_ID",
        "name": "Test Key",
        "scopes_count": 2,
        "has_mail_send": True,
        "has_full_access": False,
    }
    base.update(overrides)
    return base


def _sender_record(**overrides) -> dict[str, Any]:
    base: dict[str, Any] = {
        "record_type": "sendgrid_sender_identity",
        "record_id": "SENDGRID_TEST_SENDER_ID",
        "sender_id": "SENDGRID_TEST_SENDER_ID",
        "nickname": "Test Sender",
        "from_email_domain": "example-domain.com",
        "reply_to_domain": "example-domain.com",
        "verified": True,
        "locked": False,
    }
    base.update(overrides)
    return base


def _domain_record(**overrides) -> dict[str, Any]:
    base: dict[str, Any] = {
        "record_type": "sendgrid_domain_authentication",
        "record_id": "SENDGRID_TEST_DOMAIN_ID",
        "domain_id": "SENDGRID_TEST_DOMAIN_ID",
        "domain": "mail.example-domain.com",
        "valid": True,
        "automatic_security": True,
        "default": True,
        "legacy": False,
        "dns_record_count": 3,
    }
    base.update(overrides)
    return base


def _mail_settings_record(**overrides) -> dict[str, Any]:
    base: dict[str, Any] = {
        "record_type": "sendgrid_mail_settings",
        "record_id": "sendgrid_mail_settings_main",
        "bcc_enabled": False,
        "bounce_purge_enabled": True,
        "footer_enabled": True,    # M80C: True = healthy (footer_disabled rule won't fire)
        "forward_bounce_enabled": True,
        "forward_spam_enabled": False,
        "sandbox_mode_enabled": False,
        "spam_check_enabled": True,
        "template_enabled": False,  # M80C: False = healthy (template_engine_enabled won't fire)
    }
    base.update(overrides)
    return base


def _tracking_settings_record(**overrides) -> dict[str, Any]:
    base: dict[str, Any] = {
        "record_type": "sendgrid_tracking_settings",
        "record_id": "sendgrid_tracking_settings_main",
        "click_tracking_enabled": False,
        "open_tracking_enabled": False,
        "subscription_tracking_enabled": True,
        "ganalytics_enabled": False,
    }
    base.update(overrides)
    return base


def _webhook_settings_record(**overrides) -> dict[str, Any]:
    base: dict[str, Any] = {
        "record_type": "sendgrid_webhook_settings",
        "record_id": "sendgrid_webhook_settings_main",
        "event_webhook_enabled": True,
        "event_webhook_has_url": True,
        "event_webhook_signed": True,
        "event_count": 5,
    }
    base.update(overrides)
    return base


def _suppression_record(**overrides) -> dict[str, Any]:
    base: dict[str, Any] = {
        "record_type": "sendgrid_suppression_settings",
        "record_id": "sendgrid_suppression_settings_main",
        "suppression_group_count": 3,
    }
    base.update(overrides)
    return base


# ══════════════════════════════════════════════════════════════════════════════
# A. Rule key existence
# ══════════════════════════════════════════════════════════════════════════════

class TestRuleKeyExistence:
    def test_sendgrid_rule_keys_contains_all_m80b_keys(self):
        from app.services.security_rules.sendgrid import SENDGRID_RULE_KEYS
        assert ALL_M80B_RULE_KEYS.issubset(SENDGRID_RULE_KEYS), (
            f"Missing from SENDGRID_RULE_KEYS: {ALL_M80B_RULE_KEYS - SENDGRID_RULE_KEYS}"
        )

    def test_sendgrid_rule_keys_count_is_15(self):
        """M80C added 11 rules — total is now 26 (15 M80B + 11 M80C)."""
        from app.services.security_rules.sendgrid import SENDGRID_RULE_KEYS
        assert len(SENDGRID_RULE_KEYS) == 26, (
            f"Expected 26 rule keys (15 M80B + 11 M80C), got {len(SENDGRID_RULE_KEYS)}: {sorted(SENDGRID_RULE_KEYS)}"
        )

    def test_all_rule_keys_have_sendgrid_prefix(self):
        from app.services.security_rules.sendgrid import SENDGRID_RULE_KEYS
        for k in SENDGRID_RULE_KEYS:
            assert k.startswith("sendgrid_"), f"Rule key {k!r} missing sendgrid_ prefix"

    @pytest.mark.parametrize("rule_key", sorted(ALL_M80B_RULE_KEYS))
    def test_individual_rule_key_present(self, rule_key: str):
        from app.services.security_rules.sendgrid import SENDGRID_RULE_KEYS
        assert rule_key in SENDGRID_RULE_KEYS


# ══════════════════════════════════════════════════════════════════════════════
# B. Rules FIRE on trigger conditions
# ══════════════════════════════════════════════════════════════════════════════

class TestRulesFire:
    def _eval(self, record: dict) -> list:
        from app.services.security_rules.sendgrid import evaluate
        return evaluate(record)

    def _keys(self, record: dict) -> set:
        return {f.rule_key for f in self._eval(record)}

    # API key
    def test_api_key_broad_scopes_fires(self):
        assert _API_KEY_BROAD in self._keys(_api_key_record(has_full_access=True))

    # Sender identity
    def test_sender_unverified_fires(self):
        assert _SENDER_UNVERIFIED in self._keys(_sender_record(verified=False))

    def test_sender_locked_fires(self):
        assert _SENDER_LOCKED in self._keys(_sender_record(locked=True))

    # Domain authentication
    def test_domain_invalid_fires(self):
        assert _DOMAIN_INVALID in self._keys(_domain_record(valid=False))

    def test_domain_auto_security_disabled_fires(self):
        assert _DOMAIN_AUTO_SEC in self._keys(_domain_record(automatic_security=False))

    def test_domain_legacy_fires(self):
        assert _DOMAIN_LEGACY in self._keys(_domain_record(legacy=True))

    # Mail settings
    def test_spam_check_disabled_fires(self):
        assert _SPAM_CHECK in self._keys(_mail_settings_record(spam_check_enabled=False))

    def test_sandbox_mode_fires(self):
        assert _SANDBOX_MODE in self._keys(_mail_settings_record(sandbox_mode_enabled=True))

    def test_bcc_enabled_fires(self):
        assert _BCC_ENABLED in self._keys(_mail_settings_record(bcc_enabled=True))

    # Tracking settings
    def test_click_tracking_fires(self):
        assert _CLICK_TRACK in self._keys(_tracking_settings_record(click_tracking_enabled=True))

    def test_open_tracking_fires(self):
        assert _OPEN_TRACK in self._keys(_tracking_settings_record(open_tracking_enabled=True))

    def test_subscription_tracking_disabled_fires(self):
        assert _SUB_TRACK in self._keys(
            _tracking_settings_record(subscription_tracking_enabled=False)
        )

    # Webhook settings
    def test_event_webhook_disabled_fires(self):
        assert _WEBHOOK_DISABLED in self._keys(
            _webhook_settings_record(event_webhook_enabled=False)
        )

    def test_event_webhook_url_missing_fires(self):
        assert _WEBHOOK_URL_MISSING in self._keys(
            _webhook_settings_record(event_webhook_enabled=True, event_webhook_has_url=False)
        )

    # Suppression settings
    def test_suppression_settings_empty_fires(self):
        assert _SUPPRESSION_EMPTY in self._keys(
            _suppression_record(suppression_group_count=0)
        )


# ══════════════════════════════════════════════════════════════════════════════
# C. Rules do NOT fire on healthy records
# ══════════════════════════════════════════════════════════════════════════════

class TestRulesDoNotFireOnHealthy:
    def _eval(self, record: dict) -> list:
        from app.services.security_rules.sendgrid import evaluate
        return evaluate(record)

    def _keys(self, record: dict) -> set:
        return {f.rule_key for f in self._eval(record)}

    def test_healthy_api_key_no_findings(self):
        assert self._eval(_api_key_record()) == []

    def test_api_key_has_mail_send_only_no_broad(self):
        rec = _api_key_record(has_full_access=False, has_mail_send=True)
        assert _API_KEY_BROAD not in self._keys(rec)

    def test_verified_sender_no_findings(self):
        assert self._eval(_sender_record()) == []

    def test_sender_unverified_false_does_not_fire_locked(self):
        assert _SENDER_LOCKED not in self._keys(_sender_record(locked=False))

    def test_healthy_domain_no_findings(self):
        assert self._eval(_domain_record()) == []

    def test_domain_valid_true_does_not_fire(self):
        assert _DOMAIN_INVALID not in self._keys(_domain_record(valid=True))

    def test_domain_auto_security_true_does_not_fire(self):
        assert _DOMAIN_AUTO_SEC not in self._keys(_domain_record(automatic_security=True))

    def test_domain_not_legacy_does_not_fire(self):
        assert _DOMAIN_LEGACY not in self._keys(_domain_record(legacy=False))

    def test_healthy_mail_settings_no_findings(self):
        assert self._eval(_mail_settings_record()) == []

    def test_spam_check_enabled_does_not_fire(self):
        assert _SPAM_CHECK not in self._keys(_mail_settings_record(spam_check_enabled=True))

    def test_sandbox_mode_disabled_does_not_fire(self):
        assert _SANDBOX_MODE not in self._keys(_mail_settings_record(sandbox_mode_enabled=False))

    def test_bcc_disabled_does_not_fire(self):
        assert _BCC_ENABLED not in self._keys(_mail_settings_record(bcc_enabled=False))

    def test_healthy_tracking_settings_no_findings(self):
        assert self._eval(_tracking_settings_record()) == []

    def test_click_tracking_disabled_does_not_fire(self):
        assert _CLICK_TRACK not in self._keys(_tracking_settings_record(click_tracking_enabled=False))

    def test_open_tracking_disabled_does_not_fire(self):
        assert _OPEN_TRACK not in self._keys(_tracking_settings_record(open_tracking_enabled=False))

    def test_subscription_tracking_enabled_does_not_fire(self):
        assert _SUB_TRACK not in self._keys(
            _tracking_settings_record(subscription_tracking_enabled=True)
        )

    def test_healthy_webhook_settings_no_findings(self):
        assert self._eval(_webhook_settings_record()) == []

    def test_webhook_enabled_with_url_does_not_fire_url_missing(self):
        assert _WEBHOOK_URL_MISSING not in self._keys(
            _webhook_settings_record(event_webhook_enabled=True, event_webhook_has_url=True)
        )

    def test_webhook_disabled_does_not_fire_url_missing(self):
        """URL missing rule requires enabled=True — disabled webhook should not trigger it."""
        assert _WEBHOOK_URL_MISSING not in self._keys(
            _webhook_settings_record(event_webhook_enabled=False, event_webhook_has_url=False)
        )

    def test_suppression_groups_present_does_not_fire(self):
        assert _SUPPRESSION_EMPTY not in self._keys(_suppression_record(suppression_group_count=3))

    def test_unknown_record_type_returns_empty(self):
        from app.services.security_rules.sendgrid import evaluate
        assert evaluate({"record_type": "sendgrid_account"}) == []
        assert evaluate({"record_type": "unknown_type"}) == []
        assert evaluate({}) == []
        assert evaluate(None) == []  # type: ignore


# ══════════════════════════════════════════════════════════════════════════════
# D. Evidence privacy — no sensitive fields in any finding
# ══════════════════════════════════════════════════════════════════════════════

class TestEvidencePrivacy:
    def _all_findings(self) -> list:
        from app.services.security_rules.sendgrid import evaluate
        trigger_records = [
            _api_key_record(has_full_access=True),
            _sender_record(verified=False),
            _sender_record(locked=True),
            _domain_record(valid=False),
            _domain_record(automatic_security=False),
            _domain_record(legacy=True),
            _mail_settings_record(spam_check_enabled=False),
            _mail_settings_record(sandbox_mode_enabled=True),
            _mail_settings_record(bcc_enabled=True),
            _tracking_settings_record(click_tracking_enabled=True),
            _tracking_settings_record(open_tracking_enabled=True),
            _tracking_settings_record(subscription_tracking_enabled=False),
            _webhook_settings_record(event_webhook_enabled=False),
            _webhook_settings_record(event_webhook_enabled=True, event_webhook_has_url=False),
            _suppression_record(suppression_group_count=0),
        ]
        findings = []
        for rec in trigger_records:
            findings.extend(evaluate(rec))
        return findings

    def test_all_15_rules_produce_findings(self):
        findings = self._all_findings()
        keys = {f.rule_key for f in findings}
        missing = ALL_M80B_RULE_KEYS - keys
        assert missing == set(), f"Rules did not fire: {missing}"

    def test_no_sensitive_field_in_any_evidence(self):
        findings = self._all_findings()
        for f in findings:
            for field in SENSITIVE_EVIDENCE_FIELDS:
                assert field not in f.evidence, (
                    f"Sensitive field '{field}' found in evidence of rule {f.rule_key}"
                )

    def test_api_key_value_not_in_any_evidence(self):
        findings = self._all_findings()
        for f in findings:
            evidence_str = str(f.evidence)
            assert "SG." not in evidence_str, (
                f"SG.-shaped API key found in evidence of {f.rule_key}"
            )

    def test_full_email_not_in_any_evidence(self):
        findings = self._all_findings()
        for f in findings:
            evidence_str = str(f.evidence)
            assert "@example-domain.com" not in evidence_str, (
                f"Full email address in evidence of {f.rule_key}"
            )

    def test_bcc_address_not_in_evidence(self):
        from app.services.security_rules.sendgrid import evaluate
        findings = evaluate(_mail_settings_record(bcc_enabled=True))
        bcc_findings = [f for f in findings if f.rule_key == _BCC_ENABLED]
        assert len(bcc_findings) == 1
        assert "bcc_address" not in bcc_findings[0].evidence
        assert "bcc_email" not in bcc_findings[0].evidence

    def test_webhook_url_not_in_evidence(self):
        from app.services.security_rules.sendgrid import evaluate
        for rec in [
            _webhook_settings_record(event_webhook_enabled=False),
            _webhook_settings_record(event_webhook_enabled=True, event_webhook_has_url=False),
        ]:
            findings = evaluate(rec)
            for f in findings:
                assert "url" not in f.evidence, (
                    f"'url' field in evidence of {f.rule_key}"
                )

    def test_suppression_email_not_in_evidence(self):
        from app.services.security_rules.sendgrid import evaluate
        findings = evaluate(_suppression_record(suppression_group_count=0))
        supp_findings = [f for f in findings if f.rule_key == _SUPPRESSION_EMPTY]
        assert len(supp_findings) == 1
        ev = supp_findings[0].evidence
        assert "email" not in str(ev).lower() or "email" not in ev

    def test_all_findings_have_provider_sendgrid(self):
        findings = self._all_findings()
        for f in findings:
            assert f.provider == "sendgrid", (
                f"Rule {f.rule_key} has provider {f.provider!r} — must be 'sendgrid'"
            )

    def test_all_findings_have_severity(self):
        findings = self._all_findings()
        valid_severities = {"critical", "high", "medium", "low", "info"}
        for f in findings:
            assert f.severity in valid_severities, (
                f"Rule {f.rule_key} has invalid severity {f.severity!r}"
            )


# ══════════════════════════════════════════════════════════════════════════════
# E. Malformed records handled gracefully
# ══════════════════════════════════════════════════════════════════════════════

class TestMalformedRecordsGraceful:
    def _eval(self, record: dict) -> list:
        from app.services.security_rules.sendgrid import evaluate
        return evaluate(record)

    def test_missing_required_fields_returns_no_findings(self):
        # Partially complete records should not crash or produce stray findings.
        assert self._eval({"record_type": "sendgrid_api_key"}) == []
        assert self._eval({"record_type": "sendgrid_sender_identity"}) == []
        assert self._eval({"record_type": "sendgrid_domain_authentication"}) == []

    def test_none_field_values_skipped(self):
        # None values should not trigger rules (only explicit False/True).
        assert self._eval(_api_key_record(has_full_access=None)) == []
        assert self._eval(_domain_record(valid=None)) == []
        assert self._eval(_domain_record(automatic_security=None)) == []
        assert self._eval(_mail_settings_record(spam_check_enabled=None)) == []
        assert self._eval(_suppression_record(suppression_group_count=None)) == []

    def test_non_boolean_values_skipped(self):
        # String or int values should not trigger boolean-flag rules.
        assert self._eval(_sender_record(verified="false")) == []
        assert self._eval(_sender_record(locked="true")) == []

    def test_non_integer_suppression_count_skipped(self):
        assert self._eval(_suppression_record(suppression_group_count="0")) == []
        assert self._eval(_suppression_record(suppression_group_count=None)) == []

    def test_empty_dict_returns_empty(self):
        assert self._eval({}) == []

    def test_non_sendgrid_record_type_returns_empty(self):
        assert self._eval({"record_type": "twilio_account"}) == []
        assert self._eval({"record_type": "azure_storage_account"}) == []


# ══════════════════════════════════════════════════════════════════════════════
# F. Registry / confidence / pack / coverage parity
# ══════════════════════════════════════════════════════════════════════════════

class TestRegistryParity:
    def test_all_m80b_keys_in_registry(self):
        from app.services.security_rule_registry import KNOWN_RULE_KEYS
        missing = ALL_M80B_RULE_KEYS - KNOWN_RULE_KEYS
        assert missing == set(), f"Keys missing from registry: {missing}"

    def test_all_m80b_keys_in_confidence(self):
        from app.services.security_rule_confidence import RULE_CONFIDENCE
        missing = ALL_M80B_RULE_KEYS - set(RULE_CONFIDENCE)
        assert missing == set(), f"Keys missing from RULE_CONFIDENCE: {missing}"

    def test_all_m80b_keys_have_high_or_medium_confidence(self):
        from app.services.security_rule_confidence import RULE_CONFIDENCE
        for key in ALL_M80B_RULE_KEYS:
            confidence, _ = RULE_CONFIDENCE[key]
            assert confidence in ("high", "medium"), (
                f"{key} has confidence {confidence!r} — must be high or medium"
            )

    def test_all_m80b_keys_in_rule_pack(self):
        from app.services.security_rule_pack import _RULE_META
        missing = ALL_M80B_RULE_KEYS - set(_RULE_META)
        assert missing == set(), f"Keys missing from _RULE_META: {missing}"

    def test_all_m80b_pack_entries_have_sendgrid_provider(self):
        from app.services.security_rule_pack import _RULE_META
        for key in ALL_M80B_RULE_KEYS:
            provider, _, _ = _RULE_META[key]
            assert provider == "sendgrid", (
                f"{key} has provider {provider!r} in rule pack — must be 'sendgrid'"
            )

    def test_all_m80b_keys_in_coverage_rule_record_types(self):
        from app.services.security_coverage_service import RULE_RECORD_TYPES
        missing = ALL_M80B_RULE_KEYS - set(RULE_RECORD_TYPES)
        assert missing == set(), f"Keys missing from RULE_RECORD_TYPES: {missing}"

    def test_coverage_record_types_are_sendgrid_types(self):
        from app.services.security_coverage_service import RULE_RECORD_TYPES
        for key in ALL_M80B_RULE_KEYS:
            rtypes = RULE_RECORD_TYPES[key]
            for rt in rtypes:
                assert rt.startswith("sendgrid_"), (
                    f"{key} maps to non-sendgrid record type {rt!r}"
                )

    def test_sendgrid_in_coverage_providers(self):
        from app.services.security_coverage_service import PROVIDERS
        assert "sendgrid" in PROVIDERS

    def test_sendgrid_coverage_surfaces_exist(self):
        from app.services.security_coverage_service import PROVIDER_SURFACES
        assert "sendgrid" in PROVIDER_SURFACES
        surfaces = PROVIDER_SURFACES["sendgrid"]
        assert len(surfaces) >= 5, "SendGrid should have at least 5 coverage surfaces"


# ══════════════════════════════════════════════════════════════════════════════
# G. Capability matrix
# ══════════════════════════════════════════════════════════════════════════════

class TestCapabilityMatrix:
    def test_sendgrid_security_rules_true(self):
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("sendgrid")
        assert cap is not None
        assert cap.security.security_rules is True

    def test_sendgrid_drift_risk_classification_true(self):
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("sendgrid")
        assert cap is not None
        assert cap.drift.drift_risk_classification is True

    def test_sendgrid_activity_flags_still_false(self):
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("sendgrid")
        assert cap is not None
        # M80D rolled activity_ingestion forward to True.
        assert cap.security.activity_ingestion is True
        assert cap.security.activity_signals is False
        assert cap.security.risk_activity_correlations is False
        assert cap.security.demo_seed_clear is False

    def test_sendgrid_maturity_still_partial(self):
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("sendgrid")
        assert cap is not None
        assert cap.maturity == "partial"

    def test_sendgrid_notes_mention_m80b(self):
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("sendgrid")
        notes = cap.notes or ""
        assert "M80B" in notes

    def test_sendgrid_notes_no_forbidden_phrases(self):
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("sendgrid")
        low = (cap.notes or "").lower()
        for phrase in FORBIDDEN_PHRASES:
            assert phrase not in low, (
                f"Forbidden phrase {phrase!r} in SendGrid capability notes"
            )


# ══════════════════════════════════════════════════════════════════════════════
# H. Expansion framework
# ══════════════════════════════════════════════════════════════════════════════

class TestExpansionFramework:
    def test_planned_next_stage_is_m80c(self):
        """M80C complete — planned_next_stage rolls to M80D."""
        from app.services.provider_expansion_framework import get_framework
        fw = get_framework()
        stage = fw["summary"]["planned_next_stage"]
        assert "M80E" in stage, (
            f"planned_next_stage should point to M80E after M80D; got: {stage!r}"
        )
        assert "SendGrid" in stage

    def test_m80b_not_in_planned_next_stage(self):
        from app.services.provider_expansion_framework import get_framework
        fw = get_framework()
        stage = fw["summary"]["planned_next_stage"]
        assert "M80B" not in stage, (
            f"M80B is done; planned_next_stage must advance past it (got: {stage!r})"
        )

    def test_sendgrid_not_in_recommended_queue(self):
        from app.services.provider_expansion_framework import get_framework
        recs = get_framework()["recommended_next_providers"]
        providers = [r["provider"] for r in recs]
        assert "sendgrid" not in providers


# ══════════════════════════════════════════════════════════════════════════════
# I. Frontend rule catalog
# ══════════════════════════════════════════════════════════════════════════════

class TestFrontendRuleCatalog:
    def _catalog_text(self) -> str:
        if not FE_CATALOG.exists():
            pytest.skip("securityRuleCatalog.ts not found")
        return FE_CATALOG.read_text(encoding="utf-8")

    def test_all_15_keys_present_in_catalog(self):
        text = self._catalog_text()
        for key in ALL_M80B_RULE_KEYS:
            assert f'key: "{key}"' in text, (
                f"securityRuleCatalog.ts missing key {key!r}"
            )

    def test_all_catalog_entries_have_description(self):
        import re
        text = self._catalog_text()
        for key in ALL_M80B_RULE_KEYS:
            # Find the key and check description follows within a reasonable window.
            idx = text.find(f'key: "{key}"')
            assert idx != -1, f"Key {key!r} not found"
            block = text[idx: idx + 2000]
            assert "description:" in block, f"No description for {key!r}"

    def test_all_catalog_entries_have_remediation(self):
        text = self._catalog_text()
        for key in ALL_M80B_RULE_KEYS:
            idx = text.find(f'key: "{key}"')
            assert idx != -1
            block = text[idx: idx + 2000]
            assert "remediation:" in block, f"No remediation for {key!r}"

    def test_all_catalog_entries_have_false_positive_guard(self):
        text = self._catalog_text()
        for key in ALL_M80B_RULE_KEYS:
            idx = text.find(f'key: "{key}"')
            assert idx != -1
            block = text[idx: idx + 2000]
            assert "falsePositiveGuard:" in block, f"No falsePositiveGuard for {key!r}"

    def test_all_catalog_entries_have_provider_sendgrid(self):
        text = self._catalog_text()
        for key in ALL_M80B_RULE_KEYS:
            idx = text.find(f'key: "{key}"')
            assert idx != -1
            block = text[idx: idx + 500]
            assert 'provider: "sendgrid"' in block, (
                f"Rule {key!r} missing provider: \"sendgrid\" in catalog"
            )

    def test_all_catalog_entries_have_metadata_only_true(self):
        text = self._catalog_text()
        for key in ALL_M80B_RULE_KEYS:
            idx = text.find(f'key: "{key}"')
            assert idx != -1
            block = text[idx: idx + 500]
            assert "metadataOnly: true" in block, (
                f"Rule {key!r} missing metadataOnly: true"
            )

    def test_sendgrid_catalog_section_no_forbidden_phrases(self):
        text = self._catalog_text()
        start = text.find('"sendgrid_api_key_broad_scopes"')
        assert start != -1, "SendGrid section not found in rule catalog"
        sendgrid_section = text[start:].lower()
        for phrase in FORBIDDEN_PHRASES:
            assert phrase not in sendgrid_section, (
                f"securityRuleCatalog.ts SendGrid section contains forbidden phrase {phrase!r}"
            )

    def test_sendgrid_coverage_section_present(self):
        text = self._catalog_text()
        assert 'provider: "sendgrid"' in text
        assert "Sender identities" in text or "Verified sender" in text
        assert "Domain authentication" in text


# ══════════════════════════════════════════════════════════════════════════════
# J. Claim discipline — no forbidden phrases in module
# ══════════════════════════════════════════════════════════════════════════════

class TestClaimDiscipline:
    def _strip_negation_contexts(self, src: str) -> str:
        out = []
        for line in src.splitlines():
            low = line.lower()
            if any(
                tok in low for tok in (
                    "does not confirm", "never assert", "never claim",
                    "do not claim", "forbidden", "not confirm",
                    "claim discipline", "review-safe", "without overclaim",
                    "evidence for review", "deferred",
                )
            ):
                continue
            out.append(line)
        return "\n".join(out)

    def test_sendgrid_rules_module_no_forbidden_claims(self):
        import app.services.security_rules.sendgrid as mod
        src = inspect.getsource(mod)
        stripped = self._strip_negation_contexts(src).lower()
        for phrase in FORBIDDEN_PHRASES:
            assert phrase not in stripped, (
                f"Forbidden phrase {phrase!r} in sendgrid.py security rules"
            )
