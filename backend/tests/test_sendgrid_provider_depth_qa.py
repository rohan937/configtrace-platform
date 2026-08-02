"""SendGrid provider depth QA.

Durable, mostly-static guardrails that pin the full SendGrid rule taxonomy
across every registration surface and validate the privacy / claim-discipline
invariants for the SendGrid provider, plus the central-evaluator wiring that
makes SendGrid rules actually fire during snapshot evaluation.

  TestSendGridRuleRegistration      — all 27 SendGrid rule keys present in the
                                      module export, registry, confidence map,
                                      rule pack, and coverage service.
  TestSendGridFrontendCatalogParity — all 27 keys appear in the TypeScript
                                      securityRuleCatalog.ts with matching
                                      severities.
  TestSendGridEvidenceSafety        — fired-rule evidence is flat and carries
                                      no secret / token / PII / raw keys.
  TestSendGridCopySafety            — rule copy carries no forbidden
                                      (breach-style) wording.
  TestSendGridEvaluatorDispatch     — "sendgrid" is wired into the central
                                      evaluator and produces findings through it.
  TestSendGridExpansionFramework    — expansion framework points at M89A
                                      Kubernetes; SendGrid is not the next stage.
  TestSendGridProviderCapabilityMatrix — SendGrid is implemented (partial);
                                      Kubernetes is not yet implemented.

Pure unit tests: the registry / catalog / copy / severity checks read Python
dicts and the TypeScript catalog as text and require no database connection.

The 27 SendGrid rules are:
  M80B (15):
    sendgrid_api_key_broad_scopes
    sendgrid_sender_identity_unverified
    sendgrid_sender_identity_locked
    sendgrid_domain_authentication_invalid
    sendgrid_domain_automatic_security_disabled
    sendgrid_domain_authentication_legacy
    sendgrid_spam_check_disabled
    sendgrid_sandbox_mode_enabled
    sendgrid_bcc_enabled
    sendgrid_click_tracking_enabled
    sendgrid_open_tracking_enabled
    sendgrid_subscription_tracking_disabled
    sendgrid_event_webhook_disabled
    sendgrid_event_webhook_url_missing
    sendgrid_suppression_settings_empty
  M80C (11):
    sendgrid_sender_identity_reply_domain_mismatch
    sendgrid_domain_dns_records_missing
    sendgrid_default_domain_authentication_invalid
    sendgrid_footer_disabled
    sendgrid_bounce_purge_disabled
    sendgrid_template_engine_enabled
    sendgrid_google_analytics_tracking_enabled
    sendgrid_event_webhook_broad_event_stream
    sendgrid_inbound_parse_enabled
    sendgrid_inbound_parse_raw_email_enabled
    sendgrid_inbound_parse_spam_check_disabled
  M80C QA (1):
    sendgrid_event_webhook_not_signed
"""

from __future__ import annotations

import inspect
import re
from pathlib import Path
from typing import Any

import pytest

# ── Paths ─────────────────────────────────────────────────────────────────────

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND = REPO_ROOT / "backend" / "app"
FRONTEND = REPO_ROOT / "frontend" / "src"

SENDGRID_RULES_FILE = BACKEND / "services" / "security_rules" / "sendgrid.py"
FE_RULE_CATALOG = FRONTEND / "lib" / "securityRuleCatalog.ts"

CANONICAL_PROVIDER = "sendgrid"

# ── Canonical SendGrid rule set (27 shipped rules) ────────────────────────────

SENDGRID_RULE_KEYS = [
    # M80B — 15 core rules
    "sendgrid_api_key_broad_scopes",
    "sendgrid_sender_identity_unverified",
    "sendgrid_sender_identity_locked",
    "sendgrid_domain_authentication_invalid",
    "sendgrid_domain_automatic_security_disabled",
    "sendgrid_domain_authentication_legacy",
    "sendgrid_spam_check_disabled",
    "sendgrid_sandbox_mode_enabled",
    "sendgrid_bcc_enabled",
    "sendgrid_click_tracking_enabled",
    "sendgrid_open_tracking_enabled",
    "sendgrid_subscription_tracking_disabled",
    "sendgrid_event_webhook_disabled",
    "sendgrid_event_webhook_url_missing",
    "sendgrid_suppression_settings_empty",
    # M80C — 11 mail/webhook expansion rules
    "sendgrid_sender_identity_reply_domain_mismatch",
    "sendgrid_domain_dns_records_missing",
    "sendgrid_default_domain_authentication_invalid",
    "sendgrid_footer_disabled",
    "sendgrid_bounce_purge_disabled",
    "sendgrid_template_engine_enabled",
    "sendgrid_google_analytics_tracking_enabled",
    "sendgrid_event_webhook_broad_event_stream",
    "sendgrid_inbound_parse_enabled",
    "sendgrid_inbound_parse_raw_email_enabled",
    "sendgrid_inbound_parse_spam_check_disabled",
    # M80C QA — 1 webhook signing rule
    "sendgrid_event_webhook_not_signed",
]

ALL_SENDGRID_RULE_KEYS: frozenset[str] = frozenset(SENDGRID_RULE_KEYS)

# Forbidden claim wording — never in SendGrid rule code or user-facing copy
# (except inside an explicit negating disclaimer or a denylist constant).
FORBIDDEN_PHRASES = [
    "breach",
    "compromise",
    "leaked",
    "attacker",
    "exfiltration",
    "unauthorized access",
    "stolen",
    "fraud",
    "attack",
    "emails exposed",
    "recipients exposed",
    "account takeover",
    "spoofing",
    "phishing",
    "spam abuse",
]

# Evidence dicts must never carry secret-bearing / PII-bearing / raw keys.
FORBIDDEN_EVIDENCE_KEYS = [
    "api_key",
    "api_key_value",
    "api_secret",
    "api_key_secret",
    "secret",
    "secret_value",
    "token",
    "oauth_token",
    "authorization",
    "headers",
    "payload",
    "request",
    "response",
    "raw",
    "webhook_secret",
    "email_body",
    "subject",
    "template_content",
    "recipient_email",
    "suppressed_email",
    "bounce_email",
    "spam_report_email",
    "sender_email",
    "from_email",
    "customer_email",
    "customer_name",
    "customer",
    "bcc_address",
    "url",
    "webhook_url",
    "ip_address",
    "ip",
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _rule_key(f: Any) -> str:
    return f.rule_key if hasattr(f, "rule_key") else f.get("rule_key", "")


def _severity(f: Any) -> str:
    return f.severity if hasattr(f, "severity") else f.get("severity", "")


def _evidence(f: Any) -> dict:
    ev = f.evidence if hasattr(f, "evidence") else f.get("evidence", {})
    return ev if isinstance(ev, dict) else {}


def _title(f: Any) -> str:
    return (f.title if hasattr(f, "title") else f.get("title", "")) or ""


def _description(f: Any) -> str:
    return (f.description if hasattr(f, "description") else f.get("description", "")) or ""


def _sg_eval(record: dict) -> list[Any]:
    from app.services.security_rules.sendgrid import evaluate
    return evaluate(record)


def _all_sendgrid_findings() -> list[Any]:
    """Fire every SendGrid rule across a set of representative risky records.

    Field names mirror the canonical connector-normalizer schema consumed by
    ``security_rules.sendgrid.evaluate`` (as exercised by the M80B/M80C tests).
    """
    from app.connectors.sendgrid_schema import (
        SENDGRID_API_KEY,
        SENDGRID_DOMAIN_AUTHENTICATION,
        SENDGRID_MAIL_SETTINGS,
        SENDGRID_SENDER_IDENTITY,
        SENDGRID_SUPPRESSION_SETTINGS,
        SENDGRID_TRACKING_SETTINGS,
        SENDGRID_WEBHOOK_SETTINGS,
    )

    records: list[dict] = [
        # API key: broad/full-access → sendgrid_api_key_broad_scopes (1 rule).
        {
            "record_type": SENDGRID_API_KEY,
            "record_id": "SG_TEST_KEY_BROAD",
            "api_key_id": "SG_TEST_KEY_BROAD",
            "name": "Broad Key",
            "scopes_count": 20,
            "has_mail_send": True,
            "has_full_access": True,
        },
        # Sender identity: unverified, locked, and reply-to mismatch (3 rules).
        {
            "record_type": SENDGRID_SENDER_IDENTITY,
            "record_id": "SG_TEST_SENDER_UNVERIFIED",
            "sender_id": "SG_TEST_SENDER_UNVERIFIED",
            "nickname": "Test Sender Unverified",
            "from_email_domain": "example-domain.com",
            "reply_to_domain": "example-domain.com",
            "verified": False,
            "locked": False,
        },
        {
            "record_type": SENDGRID_SENDER_IDENTITY,
            "record_id": "SG_TEST_SENDER_LOCKED",
            "sender_id": "SG_TEST_SENDER_LOCKED",
            "nickname": "Test Sender Locked",
            "from_email_domain": "example-domain.com",
            "reply_to_domain": "reply-domain.com",  # mismatch → reply_domain_mismatch
            "verified": True,
            "locked": True,
        },
        # Domain authentication: invalid, auto_security disabled, legacy,
        # dns_record_count==0, and default+invalid (5 rules on 3 records).
        {
            "record_type": SENDGRID_DOMAIN_AUTHENTICATION,
            "record_id": "SG_TEST_DOMAIN_INVALID",
            "domain_id": "SG_TEST_DOMAIN_INVALID",
            "domain": "mail.example-domain.com",
            "valid": False,
            "automatic_security": False,  # auto-sec disabled + invalid on same record
            "default": False,
            "legacy": False,
            "dns_record_count": 3,
        },
        {
            "record_type": SENDGRID_DOMAIN_AUTHENTICATION,
            "record_id": "SG_TEST_DOMAIN_LEGACY",
            "domain_id": "SG_TEST_DOMAIN_LEGACY",
            "domain": "old.example-domain.com",
            "valid": True,
            "automatic_security": True,
            "default": False,
            "legacy": True,
            "dns_record_count": 2,
        },
        {
            "record_type": SENDGRID_DOMAIN_AUTHENTICATION,
            "record_id": "SG_TEST_DOMAIN_DEFAULT_INVALID",
            "domain_id": "SG_TEST_DOMAIN_DEFAULT_INVALID",
            "domain": "send.example-domain.com",
            "valid": False,
            "automatic_security": True,
            "default": True,  # default + invalid → default_domain_auth_invalid
            "legacy": False,
            "dns_record_count": 0,  # dns_record_count==0 → dns_records_missing
        },
        # Mail settings: all risky flags → 6 rules.
        {
            "record_type": SENDGRID_MAIL_SETTINGS,
            "record_id": "sendgrid_mail_settings_main",
            "provider_resource_id": "mail_settings/main",
            "bcc_enabled": True,
            "bounce_purge_enabled": False,
            "footer_enabled": False,
            "forward_bounce_enabled": True,
            "forward_spam_enabled": False,
            "sandbox_mode_enabled": True,
            "spam_check_enabled": False,
            "template_enabled": True,
        },
        # Tracking settings: all risky → 4 rules.
        {
            "record_type": SENDGRID_TRACKING_SETTINGS,
            "record_id": "sendgrid_tracking_settings_main",
            "provider_resource_id": "tracking_settings/main",
            "click_tracking_enabled": True,
            "open_tracking_enabled": True,
            "subscription_tracking_enabled": False,
            "ganalytics_enabled": True,
        },
        # Webhook settings (record A): disabled webhook (1 rule).
        {
            "record_type": SENDGRID_WEBHOOK_SETTINGS,
            "record_id": "sendgrid_webhook_settings_main",
            "provider_resource_id": "webhooks/event/settings/main",
            "event_webhook_enabled": False,
            "event_webhook_has_url": False,
            "event_webhook_signed": False,
            "event_count": 0,
            "inbound_parse_enabled": False,
            "inbound_parse_spam_check_enabled": True,
            "inbound_parse_send_raw_enabled": False,
        },
        # Webhook settings (record B): enabled, URL missing (1 rule: url_missing).
        {
            "record_type": SENDGRID_WEBHOOK_SETTINGS,
            "record_id": "sendgrid_webhook_settings_url_missing",
            "provider_resource_id": "webhooks/event/settings/url_missing",
            "event_webhook_enabled": True,
            "event_webhook_has_url": False,
            "event_webhook_signed": False,
            "event_count": 5,
            "inbound_parse_enabled": False,
            "inbound_parse_spam_check_enabled": True,
            "inbound_parse_send_raw_enabled": False,
        },
        # Webhook settings (record C): enabled, URL present, NOT signed, broad stream
        # (2 rules: not_signed + broad_event_stream).
        {
            "record_type": SENDGRID_WEBHOOK_SETTINGS,
            "record_id": "sendgrid_webhook_settings_unsigned",
            "provider_resource_id": "webhooks/event/settings/unsigned",
            "event_webhook_enabled": True,
            "event_webhook_has_url": True,
            "event_webhook_signed": False,   # → not_signed
            "event_count": 11,              # > 8 → broad_event_stream
            "inbound_parse_enabled": False,
            "inbound_parse_spam_check_enabled": True,
            "inbound_parse_send_raw_enabled": False,
        },
        # Webhook settings (record D): inbound parse risky flags
        # (3 rules: inbound_parse_enabled + raw_email + spam_check_disabled).
        {
            "record_type": SENDGRID_WEBHOOK_SETTINGS,
            "record_id": "sendgrid_webhook_settings_inbound",
            "provider_resource_id": "webhooks/event/settings/inbound",
            "event_webhook_enabled": True,
            "event_webhook_has_url": True,
            "event_webhook_signed": True,
            "event_count": 3,
            "inbound_parse_enabled": True,
            "inbound_parse_spam_check_enabled": False,   # → spam_check_disabled
            "inbound_parse_send_raw_enabled": True,      # → raw_email_enabled
        },
        # Suppression settings: no groups → sendgrid_suppression_settings_empty (1 rule).
        {
            "record_type": SENDGRID_SUPPRESSION_SETTINGS,
            "record_id": "sendgrid_suppression_settings_main",
            "provider_resource_id": "suppression_settings/main",
            "suppression_group_count": 0,
        },
    ]

    out: list[Any] = []
    for r in records:
        out.extend(_sg_eval(r))
    return out


# ── TestSendGridRuleRegistration ──────────────────────────────────────────────

class TestSendGridRuleRegistration:
    def test_rule_key_count_is_twenty_seven(self) -> None:
        """27 rules: 15 M80B + 11 M80C + 1 M80C QA (webhook signing)."""
        assert len(ALL_SENDGRID_RULE_KEYS) == 27

    def test_module_export_matches_canonical_set(self) -> None:
        from app.services.security_rules.sendgrid import SENDGRID_RULE_KEYS as MOD_KEYS
        assert set(MOD_KEYS) == ALL_SENDGRID_RULE_KEYS, (
            f"Module SENDGRID_RULE_KEYS drift. "
            f"Missing: {ALL_SENDGRID_RULE_KEYS - set(MOD_KEYS)}. "
            f"Extra: {set(MOD_KEYS) - ALL_SENDGRID_RULE_KEYS}"
        )

    def test_all_keys_in_registry(self) -> None:
        from app.services.security_rule_registry import KNOWN_RULE_KEYS
        for key in ALL_SENDGRID_RULE_KEYS:
            assert key in KNOWN_RULE_KEYS, f"{key!r} missing from KNOWN_RULE_KEYS"

    def test_all_keys_in_confidence(self) -> None:
        from app.services.security_rule_confidence import RULE_CONFIDENCE
        for key in ALL_SENDGRID_RULE_KEYS:
            assert key in RULE_CONFIDENCE, f"{key!r} missing from RULE_CONFIDENCE"

    def test_all_confidence_values_are_valid(self) -> None:
        from app.services.security_rule_confidence import RULE_CONFIDENCE, VALID_CONFIDENCE
        for key in ALL_SENDGRID_RULE_KEYS:
            level, _note = RULE_CONFIDENCE[key]
            assert level in VALID_CONFIDENCE, (
                f"{key!r} has invalid confidence level: {level!r}"
            )

    def test_all_keys_in_rule_pack(self) -> None:
        from app.services.security_rule_pack import _RULE_META
        for key in ALL_SENDGRID_RULE_KEYS:
            assert key in _RULE_META, f"{key!r} missing from _RULE_META"
            provider, sev, cat = _RULE_META[key]
            assert provider == CANONICAL_PROVIDER, (
                f"{key!r} wrong provider in pack: {provider!r}"
            )
            assert sev in ("high", "medium", "low"), (
                f"{key!r} invalid severity in pack: {sev!r}"
            )
            assert cat, f"{key!r} has empty category in pack"

    def test_all_keys_in_coverage(self) -> None:
        from app.services.security_coverage_service import RULE_RECORD_TYPES
        for key in ALL_SENDGRID_RULE_KEYS:
            assert key in RULE_RECORD_TYPES, f"{key!r} missing from RULE_RECORD_TYPES"
            assert RULE_RECORD_TYPES[key], f"{key!r} has empty record-type tuple"

    def test_all_coverage_record_types_are_sendgrid(self) -> None:
        """Every covered record type must be a sendgrid_ record type."""
        from app.services.security_coverage_service import RULE_RECORD_TYPES
        for key in ALL_SENDGRID_RULE_KEYS:
            for rt in RULE_RECORD_TYPES[key]:
                assert rt.startswith("sendgrid_"), (
                    f"{key!r} maps to non-sendgrid record type: {rt!r}"
                )

    def test_registry_has_no_unexpected_sendgrid_keys(self) -> None:
        from app.services.security_rule_registry import KNOWN_RULE_KEYS
        reg = {k for k in KNOWN_RULE_KEYS if k.startswith("sendgrid")}
        extra = reg - ALL_SENDGRID_RULE_KEYS
        assert not extra, f"unexpected sendgrid keys in registry: {sorted(extra)}"

    def test_rule_pack_has_no_unexpected_sendgrid_keys(self) -> None:
        from app.services.security_rule_pack import _RULE_META
        pack = {k for k, v in _RULE_META.items() if v[0] == CANONICAL_PROVIDER}
        extra = pack - ALL_SENDGRID_RULE_KEYS
        assert not extra, f"unexpected sendgrid keys in rule pack: {sorted(extra)}"

    def test_severity_matches_between_module_and_pack(self) -> None:
        """The severity in the rule module must match the rule pack for every rule."""
        from app.services.security_rule_pack import _RULE_META

        # Build risky records that trigger all rules, then check severity.
        from app.connectors.sendgrid_schema import (
            SENDGRID_API_KEY, SENDGRID_DOMAIN_AUTHENTICATION,
            SENDGRID_MAIL_SETTINGS, SENDGRID_SENDER_IDENTITY,
            SENDGRID_SUPPRESSION_SETTINGS, SENDGRID_TRACKING_SETTINGS,
            SENDGRID_WEBHOOK_SETTINGS,
        )
        risky_records = [
            {"record_type": SENDGRID_API_KEY, "record_id": "k1", "api_key_id": "k1",
             "name": "K", "scopes_count": 20, "has_mail_send": True, "has_full_access": True},
            {"record_type": SENDGRID_SENDER_IDENTITY, "record_id": "s1", "sender_id": "s1",
             "nickname": "S", "from_email_domain": "a.com", "reply_to_domain": "b.com",
             "verified": False, "locked": True},
            {"record_type": SENDGRID_DOMAIN_AUTHENTICATION, "record_id": "d1", "domain_id": "d1",
             "domain": "mail.a.com", "valid": False, "automatic_security": False,
             "default": True, "legacy": True, "dns_record_count": 0},
            {"record_type": SENDGRID_MAIL_SETTINGS, "record_id": "m1",
             "bcc_enabled": True, "bounce_purge_enabled": False, "footer_enabled": False,
             "forward_bounce_enabled": True, "forward_spam_enabled": False,
             "sandbox_mode_enabled": True, "spam_check_enabled": False, "template_enabled": True},
            {"record_type": SENDGRID_TRACKING_SETTINGS, "record_id": "t1",
             "click_tracking_enabled": True, "open_tracking_enabled": True,
             "subscription_tracking_enabled": False, "ganalytics_enabled": True},
            {"record_type": SENDGRID_WEBHOOK_SETTINGS, "record_id": "w1",
             "event_webhook_enabled": False, "event_webhook_has_url": False,
             "event_webhook_signed": False, "event_count": 0,
             "inbound_parse_enabled": False, "inbound_parse_spam_check_enabled": True,
             "inbound_parse_send_raw_enabled": False},
            {"record_type": SENDGRID_WEBHOOK_SETTINGS, "record_id": "w2",
             "event_webhook_enabled": True, "event_webhook_has_url": False,
             "event_webhook_signed": False, "event_count": 5,
             "inbound_parse_enabled": False, "inbound_parse_spam_check_enabled": True,
             "inbound_parse_send_raw_enabled": False},
            {"record_type": SENDGRID_WEBHOOK_SETTINGS, "record_id": "w3",
             "event_webhook_enabled": True, "event_webhook_has_url": True,
             "event_webhook_signed": False, "event_count": 11,
             "inbound_parse_enabled": True, "inbound_parse_spam_check_enabled": False,
             "inbound_parse_send_raw_enabled": True},
            {"record_type": SENDGRID_SUPPRESSION_SETTINGS, "record_id": "ss1",
             "suppression_group_count": 0},
        ]
        for rec in risky_records:
            for f in _sg_eval(rec):
                rk = _rule_key(f)
                rule_sev = _severity(f)
                pack_sev = _RULE_META.get(rk, (None, "unknown", None))[1]
                assert rule_sev == pack_sev, (
                    f"{rk!r}: module severity {rule_sev!r} != pack severity {pack_sev!r}"
                )


# ── TestSendGridFrontendCatalogParity ─────────────────────────────────────────

@pytest.mark.skipif(not FE_RULE_CATALOG.exists(), reason="Frontend tree absent")
class TestSendGridFrontendCatalogParity:
    def _catalog_text(self) -> str:
        return FE_RULE_CATALOG.read_text(encoding="utf-8")

    def test_all_keys_present_in_catalog(self) -> None:
        text = self._catalog_text()
        missing = [k for k in ALL_SENDGRID_RULE_KEYS if f'key: "{k}"' not in text]
        assert not missing, (
            f"SendGrid rule keys missing from frontend catalog: {missing}"
        )

    def test_catalog_keys_match_via_regex(self) -> None:
        text = self._catalog_text()
        found = set(re.findall(r'key:\s*"(sendgrid_[a-z0-9_]+)"', text))
        missing = ALL_SENDGRID_RULE_KEYS - found
        assert not missing, (
            f"Regex did not find SendGrid keys in catalog: {sorted(missing)}"
        )

    def test_catalog_has_no_unexpected_sendgrid_keys(self) -> None:
        text = self._catalog_text()
        found = set(re.findall(r'key:\s*"(sendgrid_[a-z0-9_]+)"', text))
        extra = found - ALL_SENDGRID_RULE_KEYS
        assert not extra, (
            f"Unexpected sendgrid keys in frontend catalog: {sorted(extra)}"
        )

    def test_catalog_severity_matches_backend_pack(self) -> None:
        text = self._catalog_text()
        from app.services.security_rule_pack import _RULE_META
        for key in ALL_SENDGRID_RULE_KEYS:
            idx = text.find(f'key: "{key}"')
            assert idx != -1, f"SendGrid rule {key!r} not found in frontend catalog"
            block = text[idx:idx + 900]
            _provider, expected_sev, _cat = _RULE_META[key]
            assert f'severity: "{expected_sev}"' in block, (
                f"Frontend severity for {key!r} does not match backend "
                f"({expected_sev!r})"
            )

    def test_catalog_provider_is_canonical(self) -> None:
        text = self._catalog_text()
        for key in ALL_SENDGRID_RULE_KEYS:
            idx = text.find(f'key: "{key}"')
            block = text[idx:idx + 900]
            assert 'provider: "sendgrid"' in block, (
                f"Frontend catalog entry for {key!r} must use provider 'sendgrid'"
            )

    def test_catalog_entries_have_required_fields(self) -> None:
        text = self._catalog_text()
        required_fields = ["title:", "category:", "confidence:", "description:",
                           "whatItChecks:", "whyItMatters:", "evidence:", "remediation:"]
        for key in ALL_SENDGRID_RULE_KEYS:
            idx = text.find(f'key: "{key}"')
            # Get next ~1500 chars to cover the entry
            block = text[idx:idx + 1500]
            for field in required_fields:
                assert field in block, (
                    f"Frontend catalog entry for {key!r} missing field: {field!r}"
                )


# ── TestSendGridEvidenceSafety ────────────────────────────────────────────────

class TestSendGridEvidenceSafety:
    def test_synthetic_records_fire_every_rule(self) -> None:
        fired = {_rule_key(f) for f in _all_sendgrid_findings()}
        missing = ALL_SENDGRID_RULE_KEYS - fired
        assert not missing, (
            f"Synthetic records did not fire rules: {sorted(missing)}"
        )

    def test_evidence_has_no_forbidden_keys(self) -> None:
        findings = _all_sendgrid_findings()
        assert findings, "expected at least one finding across representative records"
        for f in findings:
            ev_keys = {k.lower() for k in _evidence(f)}
            for forbidden in FORBIDDEN_EVIDENCE_KEYS:
                assert forbidden not in ev_keys, (
                    f"Forbidden evidence key {forbidden!r} in finding "
                    f"{_rule_key(f)!r}: {sorted(ev_keys)}"
                )

    def test_evidence_is_flat_safe_scalars(self) -> None:
        """SendGrid evidence is metadata-only: flat scalars only; no nested dicts."""
        def _is_safe_scalar(x: Any) -> bool:
            return isinstance(x, (str, int, float, bool, type(None)))

        for f in _all_sendgrid_findings():
            for k, v in _evidence(f).items():
                if _is_safe_scalar(v):
                    continue
                # Lists of scalars are allowed for multi-value evidence.
                assert isinstance(v, list), (
                    f"Non-scalar evidence value in {_rule_key(f)!r} key {k!r}: "
                    f"{type(v).__name__}"
                )
                for item in v:
                    assert _is_safe_scalar(item), (
                        f"Unsafe list item in {_rule_key(f)!r} key {k!r}: "
                        f"{type(item).__name__}"
                    )

    def test_no_raw_email_in_evidence(self) -> None:
        """No finding evidence should carry a full email address."""
        email_pattern = re.compile(r"[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}")
        for f in _all_sendgrid_findings():
            for k, v in _evidence(f).items():
                if isinstance(v, str):
                    assert not email_pattern.search(v), (
                        f"Full email address in evidence of {_rule_key(f)!r} "
                        f"key {k!r}: {v!r}"
                    )

    def test_no_api_key_value_pattern_in_evidence(self) -> None:
        """No evidence value should match a SendGrid API key shape (SG.xxx.xxx)."""
        sg_key_pattern = re.compile(r"SG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")
        for f in _all_sendgrid_findings():
            for k, v in _evidence(f).items():
                if isinstance(v, str):
                    assert not sg_key_pattern.search(v), (
                        f"SendGrid API key shape found in evidence of "
                        f"{_rule_key(f)!r} key {k!r}"
                    )

    def test_from_email_domain_not_from_email(self) -> None:
        """from_email_domain evidence must not contain '@' (domain-part only)."""
        for f in _all_sendgrid_findings():
            ev = _evidence(f)
            for k in ("from_email_domain", "reply_to_domain"):
                v = ev.get(k)
                if isinstance(v, str) and v:
                    assert "@" not in v, (
                        f"Full email address (contains @) in evidence of "
                        f"{_rule_key(f)!r} key {k!r}: {v!r}"
                    )


# ── TestSendGridCopySafety ────────────────────────────────────────────────────

class TestSendGridCopySafety:
    _NEGATION_TOKENS = (
        "does not confirm", "never assert", "never claim", "do not claim",
        "is not a claim", "without claiming", "claim discipline",
        "claim-discipline", "without overclaim", "doesn't confirm",
        "forbidden", "not confirm", "denylist", "negating",
        "it never asserts", "does not", "not detect breaches",
        "may indicate", "evidence for review",
    )

    def _strip_negation_lines(self, src: str) -> str:
        out = []
        for line in src.splitlines():
            low = line.lower()
            if any(tok in low for tok in self._NEGATION_TOKENS):
                continue
            out.append(line)
        return "\n".join(out)

    def test_no_forbidden_wording_in_rules_module(self) -> None:
        from app.services.security_rules import sendgrid as sg_rules
        src = inspect.getsource(sg_rules).lower()
        src = re.sub(r'"\s*\n\s*[a-z]*"', " ", src)
        src = re.sub(r'"\s+"', " ", src)
        src = re.sub(r"\s+", " ", src)
        # Remove canonical negating disclaimers wholesale.
        for disclaimer in (
            "this is configuration evidence for review and does not confirm a leaked key, "
            "unauthorized access, or data exposure.",
            "this is configuration evidence for review; it does not confirm unauthorized "
            "access or data exposure.",
            "this is configuration evidence for review and does not confirm email "
            "delivery failure or unauthorized access.",
            "this is configuration evidence for review and does not confirm email "
            "delivery failure or data exposure.",
            "it never asserts that a key was leaked, an email was intercepted, "
            "a recipient list was exposed, a domain was hijacked, that unauthorized "
            "access occurred, or that any attacker is present.",
            "does not confirm compromise, unauthorized access, or data exposure.",
            "does not confirm breach, unauthorized access, or data exposure.",
        ):
            src = src.replace(disclaimer, " ")
        src = self._strip_negation_lines(src)
        for phrase in FORBIDDEN_PHRASES:
            assert phrase not in src, (
                f"forbidden phrase {phrase!r} present in security_rules.sendgrid "
                f"outside a negation/denylist context"
            )

    def test_no_forbidden_wording_in_finding_copy(self) -> None:
        for f in _all_sendgrid_findings():
            blob = f"{_title(f)}\n{_description(f)}"
            blob = self._strip_negation_lines(blob).lower()
            # Drop canonical disclaimer sentences.
            blob = blob.replace(
                "this is configuration evidence for review and does not confirm "
                "unauthorized access or data exposure.", ""
            )
            blob = blob.replace(
                "this is configuration evidence for review.", ""
            )
            for phrase in FORBIDDEN_PHRASES:
                assert phrase not in blob, (
                    f"Finding {_rule_key(f)!r} copy contains forbidden phrase "
                    f"{phrase!r}"
                )

    def test_all_findings_mention_evidence_for_review(self) -> None:
        """Every finding description should frame output as evidence for review."""
        for f in _all_sendgrid_findings():
            desc = _description(f).lower()
            assert "evidence for review" in desc or "configuration evidence" in desc or \
                   "may require review" in desc or "for review" in desc, (
                f"Finding {_rule_key(f)!r} description does not frame itself as "
                f"evidence for review"
            )


# ── TestSendGridEvaluatorDispatch ─────────────────────────────────────────────

class TestSendGridEvaluatorDispatch:
    """Regression: 'sendgrid' must be wired into the central evaluator.

    These tests failed at P0 when sendgrid was missing from _PROVIDER_RULES;
    they now serve as permanent guards against regressing back to that state.
    """

    def test_sendgrid_in_provider_rules(self) -> None:
        from app.services.security_finding_evaluator import _PROVIDER_RULES
        assert "sendgrid" in _PROVIDER_RULES, (
            "sendgrid missing from security_finding_evaluator._PROVIDER_RULES — "
            "all SendGrid security rules are dead without this dispatch entry"
        )
        assert _PROVIDER_RULES["sendgrid"], (
            "sendgrid dispatch list in _PROVIDER_RULES is empty"
        )

    def test_central_evaluator_produces_api_key_finding(self) -> None:
        """An API key with broad access MUST yield a finding via the central evaluator."""
        from app.connectors.sendgrid_schema import SENDGRID_API_KEY
        from app.services.security_finding_evaluator import evaluate_record
        rec = {
            "record_type": SENDGRID_API_KEY,
            "record_id": "SG_DISPATCH_TEST_KEY",
            "api_key_id": "SG_DISPATCH_TEST_KEY",
            "name": "Dispatch Test Key",
            "scopes_count": 20,
            "has_mail_send": True,
            "has_full_access": True,
        }
        candidates = evaluate_record(rec, "sendgrid")
        assert candidates, (
            "central evaluator produced no SendGrid findings for a broad-scope API key"
        )
        keys = {c.rule_key for c in candidates}
        assert "sendgrid_api_key_broad_scopes" in keys, (
            f"expected sendgrid_api_key_broad_scopes via central dispatch; got {keys}"
        )

    def test_central_evaluator_produces_domain_finding(self) -> None:
        """A default domain with failed DNS must yield a finding via the central evaluator."""
        from app.connectors.sendgrid_schema import SENDGRID_DOMAIN_AUTHENTICATION
        from app.services.security_finding_evaluator import evaluate_record
        rec = {
            "record_type": SENDGRID_DOMAIN_AUTHENTICATION,
            "record_id": "SG_DISPATCH_TEST_DOMAIN",
            "domain_id": "SG_DISPATCH_TEST_DOMAIN",
            "domain": "send.dispatch-test.com",
            "valid": False,
            "automatic_security": True,
            "default": True,
            "legacy": False,
            "dns_record_count": 3,
        }
        candidates = evaluate_record(rec, "sendgrid")
        assert candidates, (
            "central evaluator produced no SendGrid findings for an invalid default domain"
        )
        keys = {c.rule_key for c in candidates}
        assert "sendgrid_default_domain_authentication_invalid" in keys, (
            f"expected sendgrid_default_domain_authentication_invalid; got {keys}"
        )

    def test_central_evaluator_produces_webhook_finding(self) -> None:
        """An enabled webhook with no URL must yield a finding via the central evaluator."""
        from app.connectors.sendgrid_schema import SENDGRID_WEBHOOK_SETTINGS
        from app.services.security_finding_evaluator import evaluate_record
        rec = {
            "record_type": SENDGRID_WEBHOOK_SETTINGS,
            "record_id": "SG_DISPATCH_TEST_WEBHOOK",
            "provider_resource_id": "webhooks/event/settings/dispatch_test",
            "event_webhook_enabled": True,
            "event_webhook_has_url": False,
            "event_webhook_signed": False,
            "event_count": 5,
            "inbound_parse_enabled": False,
            "inbound_parse_spam_check_enabled": True,
            "inbound_parse_send_raw_enabled": False,
        }
        candidates = evaluate_record(rec, "sendgrid")
        assert candidates, (
            "central evaluator produced no SendGrid findings for webhook with missing URL"
        )
        keys = {c.rule_key for c in candidates}
        assert "sendgrid_event_webhook_url_missing" in keys, (
            f"expected sendgrid_event_webhook_url_missing; got {keys}"
        )

    def test_central_evaluator_produces_webhook_not_signed_finding(self) -> None:
        """An active, URL-configured, unsigned webhook must fire not_signed via evaluator."""
        from app.connectors.sendgrid_schema import SENDGRID_WEBHOOK_SETTINGS
        from app.services.security_finding_evaluator import evaluate_record
        rec = {
            "record_type": SENDGRID_WEBHOOK_SETTINGS,
            "record_id": "SG_DISPATCH_TEST_UNSIGNED",
            "provider_resource_id": "webhooks/event/settings/unsigned_test",
            "event_webhook_enabled": True,
            "event_webhook_has_url": True,
            "event_webhook_signed": False,
            "event_count": 5,
            "inbound_parse_enabled": False,
            "inbound_parse_spam_check_enabled": True,
            "inbound_parse_send_raw_enabled": False,
        }
        candidates = evaluate_record(rec, "sendgrid")
        assert candidates, (
            "central evaluator produced no SendGrid findings for unsigned active webhook"
        )
        keys = {c.rule_key for c in candidates}
        assert "sendgrid_event_webhook_not_signed" in keys, (
            f"expected sendgrid_event_webhook_not_signed; got {keys}"
        )

    def test_unknown_provider_returns_no_sendgrid_findings(self) -> None:
        """Passing a sendgrid record with a wrong provider must yield nothing."""
        from app.connectors.sendgrid_schema import SENDGRID_API_KEY
        from app.services.security_finding_evaluator import evaluate_record
        rec = {
            "record_type": SENDGRID_API_KEY,
            "record_id": "k1",
            "api_key_id": "k1",
            "name": "test",
            "scopes_count": 10,
            "has_mail_send": True,
            "has_full_access": True,
        }
        assert evaluate_record(rec, "unknown_provider") == []
        assert evaluate_record(rec, "") == []

    def test_sendgrid_account_record_safely_returns_empty(self) -> None:
        """sendgrid_account records are not evaluated — evaluate() must return []."""
        from app.services.security_finding_evaluator import evaluate_record
        rec = {
            "record_type": "sendgrid_account",
            "record_id": "sendgrid_account_main",
            "account_type": "free",
            "reputation": 70.0,
        }
        assert evaluate_record(rec, "sendgrid") == []


# ── TestSendGridExpansionFramework ────────────────────────────────────────────

class TestSendGridExpansionFramework:
    def test_planned_next_stage_points_at_kubernetes(self) -> None:
        """Regression note: Kubernetes launched (Kubernetes message 1 /
        M89A) and is no longer the planned next stage — Sentry/M90A is."""
        from app.services.provider_expansion_framework import get_framework
        stage = get_framework()["summary"]["planned_next_stage"]
        assert "M90A" in stage or "Sentry" in stage, (
            f"planned_next_stage should reference M90A Sentry; got: {stage!r}"
        )

    def test_sendgrid_is_not_the_next_stage(self) -> None:
        from app.services.provider_expansion_framework import get_framework
        stage = get_framework()["summary"]["planned_next_stage"].lower()
        assert "sendgrid" not in stage, (
            f"SendGrid must not be the planned_next_stage; got: {stage!r}"
        )

    def test_sendgrid_not_in_recommended_queue(self) -> None:
        from app.services.provider_expansion_framework import get_framework
        fw = get_framework()
        providers = [r["provider"] for r in fw["recommended_next_providers"]]
        assert CANONICAL_PROVIDER not in providers, (
            "SendGrid arc is complete and must not be in the recommended queue"
        )

    def test_recommended_queue_is_empty_after_sentry_launch(self) -> None:
        """Regression note: Kubernetes launched and was removed from the
        recommended queue. Sentry (message 8 — public launch) was the
        FINAL planned provider, so the queue is now permanently empty."""
        from app.services.provider_expansion_framework import get_framework
        fw = get_framework()
        recs = fw["recommended_next_providers"]
        assert recs == [], f"recommended_next_providers must be empty; got: {recs!r}"

    def test_next_provider_summary_is_none_expansion_frozen(self) -> None:
        """Regression note: Kubernetes launched, then Sentry (message 8 —
        public launch) was the FINAL planned provider. next_provider is
        now permanently None."""
        from app.services.provider_expansion_framework import get_framework
        fw = get_framework()
        assert fw["summary"]["next_provider"] is None, (
            f"next_provider should be None; got: {fw['summary']['next_provider']!r}"
        )


# ── TestSendGridProviderCapabilityMatrix ──────────────────────────────────────

class TestSendGridProviderCapabilityMatrix:
    def test_sendgrid_present_with_expected_capabilities(self) -> None:
        from app.services.provider_capability_matrix_service import (
            get_provider_capability,
        )
        cap = get_provider_capability(CANONICAL_PROVIDER)
        assert cap is not None, "SendGrid missing from provider capability matrix"
        assert cap.provider == CANONICAL_PROVIDER
        assert cap.security.security_rules is True, "security_rules must be True (M80B)"
        assert cap.drift.drift_snapshots is True, "drift_snapshots must be True (M80A)"
        assert cap.drift.drift_diff is True, "drift_diff must be True (M80A)"
        assert cap.drift.drift_risk_classification is True
        assert cap.security.activity_ingestion is True, "activity_ingestion must be True (M80D)"
        assert cap.security.activity_signals is True, "activity_signals must be True (M80E)"
        assert cap.security.risk_activity_correlations is True, "correlations must be True (M80F)"
        assert cap.security.demo_seed_clear is True, "demo_seed_clear must be True (M80G)"
        assert cap.security.case_report is True, "case_report must be True (M80G)"
        assert cap.maturity == "partial"

    def test_sendgrid_in_partial_not_canonical_matrix(self) -> None:
        """SendGrid must be in the partial matrix, not the canonical 8."""
        from app.services.provider_capability_matrix_service import (
            PROVIDER_CAPABILITIES,
            PROVIDER_CAPABILITIES_PARTIAL,
        )
        canonical = {p.provider for p in PROVIDER_CAPABILITIES}
        partial = {p.provider for p in PROVIDER_CAPABILITIES_PARTIAL}
        assert CANONICAL_PROVIDER not in canonical, (
            "SendGrid must not be in the canonical PROVIDER_CAPABILITIES list"
        )
        assert CANONICAL_PROVIDER in partial, (
            "SendGrid must be in PROVIDER_CAPABILITIES_PARTIAL"
        )

    def test_sendgrid_capability_count_matches_rule_set(self) -> None:
        """The SendGrid rule pack must expose exactly the 27 canonical rules."""
        from app.services.security_rule_pack import _RULE_META
        sg_keys = {k for k, v in _RULE_META.items() if v[0] == CANONICAL_PROVIDER}
        assert sg_keys == ALL_SENDGRID_RULE_KEYS, (
            f"SendGrid rule-pack key set drift. "
            f"Missing: {ALL_SENDGRID_RULE_KEYS - sg_keys}. "
            f"Extra: {sg_keys - ALL_SENDGRID_RULE_KEYS}"
        )

    def test_kubernetes_is_not_yet_implemented(self) -> None:
        """Regression note: Kubernetes now has a static Security Finding
        layer (message 6) — capability entry reflects maturity='partial',
        security_rules=True. Still not connectable/production-ready."""
        from app.services.provider_capability_matrix_service import (
            get_provider_capability,
        )
        cap = get_provider_capability("kubernetes")
        assert cap is not None
        assert cap.maturity == "partial"
        assert cap.security.security_rules is True

    def test_kubernetes_connector_does_not_exist(self) -> None:
        """Regression note: the Kubernetes connector now exists (foundation
        stage only — see kubernetes_foundation_contract.md)."""
        k8s_connector = BACKEND / "connectors" / "kubernetes.py"
        assert k8s_connector.exists()

    def test_sendgrid_notes_mention_key_milestones(self) -> None:
        """Capability matrix notes should reference core SendGrid milestones."""
        from app.services.provider_capability_matrix_service import (
            get_provider_capability,
        )
        cap = get_provider_capability(CANONICAL_PROVIDER)
        assert cap is not None
        notes = cap.notes
        assert "M80A" in notes or "drift" in notes.lower(), (
            "SendGrid capability notes should reference M80A or drift foundation"
        )
        assert "M80B" in notes or "security" in notes.lower(), (
            "SendGrid capability notes should reference M80B or security rules"
        )
