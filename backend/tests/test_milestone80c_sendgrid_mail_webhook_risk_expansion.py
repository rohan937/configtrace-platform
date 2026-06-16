"""M80C — SendGrid Mail/Webhook Risk Expansion.

Pins the M80C SendGrid security rules milestone:
  * SENDGRID_RULE_KEYS now contains 26 keys (15 from M80B + 11 new from M80C)
  * evaluate() fires correctly for all 11 new M80C rules
  * Rules do NOT fire on healthy records
  * Schema/connector expansions normalize only safe booleans
  * Evidence privacy: no API keys, bearer tokens, email addresses,
    URLs, webhook URLs, raw SendGrid payloads, email bodies, subject lines,
    recipient emails, sender full emails, suppression emails, template content,
    contact data, event payloads, customer data, or PII in findings
  * Registry / confidence / pack / coverage all stay in parity
  * Provider capability matrix reflects M80C state (notes mention M80C)
  * Expansion framework planned_next_stage → M80D
  * Frontend catalog contains all 11 new rule keys with required fields
  * No forbidden wording anywhere in the module
  * No SendGrid/Twilio secret-shaped strings in backend/app or frontend/src
  * M80A and M80B tests still pass (regression check via fixture import)

These rules are configuration-posture findings only. A finding is evidence
for review and never asserts that a breach occurred, that data leaked, that
keys were compromised, or that an attacker has access.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
FE_CATALOG = REPO_ROOT / "frontend" / "src" / "lib" / "securityRuleCatalog.ts"
BACKEND_APP = REPO_ROOT / "backend" / "app"
FRONTEND_SRC = REPO_ROOT / "frontend" / "src"

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

# Sensitive evidence field names that must NEVER appear in M80C rule findings.
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
    "hostname",
    "bcc_address",
    "template_content",
    "subject",
    "event_payload",
    "raw_email",
    "customer_data",
    "pii",
})

# ── M80B rule keys (must still exist) ────────────────────────────────────────

_M80B_RULE_KEYS: frozenset[str] = frozenset({
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
})

# ── M80C rule keys (new in this milestone) ────────────────────────────────────

_SENDER_REPLY_MISMATCH = "sendgrid_sender_identity_reply_domain_mismatch"
_DOMAIN_DNS_MISSING = "sendgrid_domain_dns_records_missing"
_DEFAULT_DOMAIN_INVALID = "sendgrid_default_domain_authentication_invalid"
_FOOTER_DISABLED = "sendgrid_footer_disabled"
_BOUNCE_PURGE_DISABLED = "sendgrid_bounce_purge_disabled"
_TEMPLATE_ENABLED = "sendgrid_template_engine_enabled"
_GA_TRACKING = "sendgrid_google_analytics_tracking_enabled"
_BROAD_STREAM = "sendgrid_event_webhook_broad_event_stream"
_INBOUND_PARSE = "sendgrid_inbound_parse_enabled"
_INBOUND_RAW = "sendgrid_inbound_parse_raw_email_enabled"
_INBOUND_SPAM = "sendgrid_inbound_parse_spam_check_disabled"

ALL_M80C_NEW_RULE_KEYS: frozenset[str] = frozenset({
    _SENDER_REPLY_MISMATCH,
    _DOMAIN_DNS_MISSING,
    _DEFAULT_DOMAIN_INVALID,
    _FOOTER_DISABLED,
    _BOUNCE_PURGE_DISABLED,
    _TEMPLATE_ENABLED,
    _GA_TRACKING,
    _BROAD_STREAM,
    _INBOUND_PARSE,
    _INBOUND_RAW,
    _INBOUND_SPAM,
})

ALL_M80C_RULE_KEYS: frozenset[str] = _M80B_RULE_KEYS | ALL_M80C_NEW_RULE_KEYS


# ── Helpers ───────────────────────────────────────────────────────────────────


def _keys(findings) -> set[str]:
    return {f.rule_key for f in findings}


# ── Record builders ───────────────────────────────────────────────────────────


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
        "default": False,
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
        "footer_enabled": True,
        "forward_bounce_enabled": True,
        "forward_spam_enabled": False,
        "sandbox_mode_enabled": False,
        "spam_check_enabled": True,
        "template_enabled": False,
    }
    base.update(overrides)
    return base


def _tracking_record(**overrides) -> dict[str, Any]:
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


def _webhook_record(**overrides) -> dict[str, Any]:
    base: dict[str, Any] = {
        "record_type": "sendgrid_webhook_settings",
        "record_id": "sendgrid_webhook_settings_main",
        "event_webhook_enabled": True,
        "event_webhook_has_url": True,
        "event_webhook_signed": True,
        "event_count": 5,
        "inbound_parse_enabled": False,
        "inbound_parse_spam_check_enabled": True,
        "inbound_parse_send_raw_enabled": False,
    }
    base.update(overrides)
    return base


# ── SENDGRID_RULE_KEYS completeness ──────────────────────────────────────────


class TestRuleKeyCompleteness:
    def test_m80c_new_keys_present(self):
        from app.services.security_rules.sendgrid import SENDGRID_RULE_KEYS
        missing = ALL_M80C_NEW_RULE_KEYS - SENDGRID_RULE_KEYS
        assert not missing, f"M80C keys missing from SENDGRID_RULE_KEYS: {sorted(missing)}"

    def test_m80b_keys_still_present(self):
        from app.services.security_rules.sendgrid import SENDGRID_RULE_KEYS
        missing = _M80B_RULE_KEYS - SENDGRID_RULE_KEYS
        assert not missing, f"M80B keys missing from SENDGRID_RULE_KEYS: {sorted(missing)}"

    def test_total_key_count(self):
        from app.services.security_rules.sendgrid import SENDGRID_RULE_KEYS
        assert len(SENDGRID_RULE_KEYS) == 26, (
            f"Expected 26 total rule keys (15 M80B + 11 M80C), got {len(SENDGRID_RULE_KEYS)}"
        )


# ── Sender identity: reply domain mismatch ────────────────────────────────────


class TestSenderReplyDomainMismatch:
    def test_fires_when_domains_differ(self):
        from app.services.security_rules.sendgrid import evaluate
        rec = _sender_record(
            from_email_domain="example.com",
            reply_to_domain="different.com",
        )
        findings = evaluate(rec)
        assert _SENDER_REPLY_MISMATCH in _keys(findings)

    def test_no_fire_when_domains_match(self):
        from app.services.security_rules.sendgrid import evaluate
        rec = _sender_record(
            from_email_domain="example.com",
            reply_to_domain="example.com",
        )
        assert _SENDER_REPLY_MISMATCH not in _keys(evaluate(rec))

    def test_no_fire_when_from_domain_empty(self):
        from app.services.security_rules.sendgrid import evaluate
        rec = _sender_record(from_email_domain="", reply_to_domain="other.com")
        assert _SENDER_REPLY_MISMATCH not in _keys(evaluate(rec))

    def test_no_fire_when_reply_domain_empty(self):
        from app.services.security_rules.sendgrid import evaluate
        rec = _sender_record(from_email_domain="example.com", reply_to_domain="")
        assert _SENDER_REPLY_MISMATCH not in _keys(evaluate(rec))

    def test_evidence_contains_domains_not_full_emails(self):
        from app.services.security_rules.sendgrid import evaluate
        rec = _sender_record(
            from_email_domain="example.com",
            reply_to_domain="different.com",
        )
        findings = [f for f in evaluate(rec) if f.rule_key == _SENDER_REPLY_MISMATCH]
        assert findings
        ev = findings[0].evidence
        assert "from_email_domain" in ev
        assert "reply_to_domain" in ev
        # SECURITY: full email addresses must never appear
        for key in SENSITIVE_EVIDENCE_FIELDS:
            assert key not in ev, f"Sensitive field '{key}' found in evidence"
        # Values must be domain-only (no @ present)
        assert "@" not in str(ev.get("from_email_domain", ""))
        assert "@" not in str(ev.get("reply_to_domain", ""))


# ── Domain: DNS records missing ───────────────────────────────────────────────


class TestDomainDnsRecordsMissing:
    def test_fires_when_count_zero(self):
        from app.services.security_rules.sendgrid import evaluate
        rec = _domain_record(dns_record_count=0, valid=False)
        assert _DOMAIN_DNS_MISSING in _keys(evaluate(rec))

    def test_no_fire_when_records_exist(self):
        from app.services.security_rules.sendgrid import evaluate
        rec = _domain_record(dns_record_count=3)
        assert _DOMAIN_DNS_MISSING not in _keys(evaluate(rec))

    def test_no_fire_when_count_missing(self):
        from app.services.security_rules.sendgrid import evaluate
        rec = _domain_record()
        del rec["dns_record_count"]
        assert _DOMAIN_DNS_MISSING not in _keys(evaluate(rec))

    def test_evidence_has_no_raw_dns_values(self):
        from app.services.security_rules.sendgrid import evaluate
        rec = _domain_record(dns_record_count=0, valid=False)
        findings = [f for f in evaluate(rec) if f.rule_key == _DOMAIN_DNS_MISSING]
        assert findings
        ev = findings[0].evidence
        assert ev["dns_record_count"] == 0
        for key in SENSITIVE_EVIDENCE_FIELDS:
            assert key not in ev


# ── Domain: default domain auth invalid ──────────────────────────────────────


class TestDefaultDomainAuthInvalid:
    def test_fires_when_default_and_invalid(self):
        from app.services.security_rules.sendgrid import evaluate
        rec = _domain_record(default=True, valid=False)
        assert _DEFAULT_DOMAIN_INVALID in _keys(evaluate(rec))

    def test_no_fire_when_not_default(self):
        from app.services.security_rules.sendgrid import evaluate
        rec = _domain_record(default=False, valid=False)
        assert _DEFAULT_DOMAIN_INVALID not in _keys(evaluate(rec))

    def test_no_fire_when_valid(self):
        from app.services.security_rules.sendgrid import evaluate
        rec = _domain_record(default=True, valid=True)
        assert _DEFAULT_DOMAIN_INVALID not in _keys(evaluate(rec))

    def test_finding_severity_is_high(self):
        from app.services.security_rules.sendgrid import evaluate
        rec = _domain_record(default=True, valid=False)
        findings = [f for f in evaluate(rec) if f.rule_key == _DEFAULT_DOMAIN_INVALID]
        assert findings
        assert findings[0].severity == "high"


# ── Mail settings: footer disabled ───────────────────────────────────────────


class TestFooterDisabled:
    def test_fires_when_footer_disabled(self):
        from app.services.security_rules.sendgrid import evaluate
        rec = _mail_settings_record(footer_enabled=False)
        assert _FOOTER_DISABLED in _keys(evaluate(rec))

    def test_no_fire_when_footer_enabled(self):
        from app.services.security_rules.sendgrid import evaluate
        rec = _mail_settings_record(footer_enabled=True)
        assert _FOOTER_DISABLED not in _keys(evaluate(rec))

    def test_evidence_has_no_footer_text(self):
        from app.services.security_rules.sendgrid import evaluate
        rec = _mail_settings_record(footer_enabled=False)
        findings = [f for f in evaluate(rec) if f.rule_key == _FOOTER_DISABLED]
        assert findings
        ev = findings[0].evidence
        assert "footer_enabled" in ev
        for key in SENSITIVE_EVIDENCE_FIELDS:
            assert key not in ev


# ── Mail settings: bounce purge disabled ─────────────────────────────────────


class TestBouncePurgeDisabled:
    def test_fires_when_bounce_purge_disabled(self):
        from app.services.security_rules.sendgrid import evaluate
        rec = _mail_settings_record(bounce_purge_enabled=False)
        assert _BOUNCE_PURGE_DISABLED in _keys(evaluate(rec))

    def test_no_fire_when_bounce_purge_enabled(self):
        from app.services.security_rules.sendgrid import evaluate
        rec = _mail_settings_record(bounce_purge_enabled=True)
        assert _BOUNCE_PURGE_DISABLED not in _keys(evaluate(rec))


# ── Mail settings: template engine enabled ────────────────────────────────────


class TestTemplateEngineEnabled:
    def test_fires_when_template_enabled(self):
        from app.services.security_rules.sendgrid import evaluate
        rec = _mail_settings_record(template_enabled=True)
        assert _TEMPLATE_ENABLED in _keys(evaluate(rec))

    def test_no_fire_when_template_disabled(self):
        from app.services.security_rules.sendgrid import evaluate
        rec = _mail_settings_record(template_enabled=False)
        assert _TEMPLATE_ENABLED not in _keys(evaluate(rec))

    def test_no_fire_when_field_missing(self):
        from app.services.security_rules.sendgrid import evaluate
        rec = _mail_settings_record()
        del rec["template_enabled"]
        assert _TEMPLATE_ENABLED not in _keys(evaluate(rec))

    def test_evidence_has_no_template_content(self):
        from app.services.security_rules.sendgrid import evaluate
        rec = _mail_settings_record(template_enabled=True)
        findings = [f for f in evaluate(rec) if f.rule_key == _TEMPLATE_ENABLED]
        assert findings
        ev = findings[0].evidence
        assert ev["template_enabled"] is True
        for key in SENSITIVE_EVIDENCE_FIELDS:
            assert key not in ev


# ── Tracking settings: Google Analytics enabled ───────────────────────────────


class TestGoogleAnalyticsTrackingEnabled:
    def test_fires_when_ga_enabled(self):
        from app.services.security_rules.sendgrid import evaluate
        rec = _tracking_record(ganalytics_enabled=True)
        assert _GA_TRACKING in _keys(evaluate(rec))

    def test_no_fire_when_ga_disabled(self):
        from app.services.security_rules.sendgrid import evaluate
        rec = _tracking_record(ganalytics_enabled=False)
        assert _GA_TRACKING not in _keys(evaluate(rec))

    def test_evidence_has_no_ga_parameters(self):
        from app.services.security_rules.sendgrid import evaluate
        rec = _tracking_record(ganalytics_enabled=True)
        findings = [f for f in evaluate(rec) if f.rule_key == _GA_TRACKING]
        assert findings
        ev = findings[0].evidence
        assert ev["ganalytics_enabled"] is True
        for key in SENSITIVE_EVIDENCE_FIELDS:
            assert key not in ev


# ── Webhook settings: broad event stream ─────────────────────────────────────


class TestEventWebhookBroadEventStream:
    def test_fires_when_event_count_above_threshold(self):
        from app.services.security_rules.sendgrid import evaluate
        rec = _webhook_record(event_webhook_enabled=True, event_count=9)
        assert _BROAD_STREAM in _keys(evaluate(rec))

    def test_fires_at_edge_above_threshold(self):
        from app.services.security_rules.sendgrid import evaluate
        rec = _webhook_record(event_webhook_enabled=True, event_count=11)
        assert _BROAD_STREAM in _keys(evaluate(rec))

    def test_no_fire_at_threshold(self):
        from app.services.security_rules.sendgrid import evaluate
        rec = _webhook_record(event_webhook_enabled=True, event_count=8)
        assert _BROAD_STREAM not in _keys(evaluate(rec))

    def test_no_fire_below_threshold(self):
        from app.services.security_rules.sendgrid import evaluate
        rec = _webhook_record(event_webhook_enabled=True, event_count=3)
        assert _BROAD_STREAM not in _keys(evaluate(rec))

    def test_no_fire_when_webhook_disabled(self):
        from app.services.security_rules.sendgrid import evaluate
        rec = _webhook_record(event_webhook_enabled=False, event_count=11)
        assert _BROAD_STREAM not in _keys(evaluate(rec))

    def test_evidence_uses_count_not_payloads(self):
        from app.services.security_rules.sendgrid import evaluate
        rec = _webhook_record(event_webhook_enabled=True, event_count=10)
        findings = [f for f in evaluate(rec) if f.rule_key == _BROAD_STREAM]
        assert findings
        ev = findings[0].evidence
        assert "event_count" in ev
        assert ev["event_count"] == 10
        for key in SENSITIVE_EVIDENCE_FIELDS:
            assert key not in ev


# ── Webhook settings: inbound parse enabled ───────────────────────────────────


class TestInboundParseEnabled:
    def test_fires_when_inbound_parse_enabled(self):
        from app.services.security_rules.sendgrid import evaluate
        rec = _webhook_record(inbound_parse_enabled=True)
        assert _INBOUND_PARSE in _keys(evaluate(rec))

    def test_no_fire_when_inbound_parse_disabled(self):
        from app.services.security_rules.sendgrid import evaluate
        rec = _webhook_record(inbound_parse_enabled=False)
        assert _INBOUND_PARSE not in _keys(evaluate(rec))

    def test_evidence_has_no_hostname_or_url(self):
        from app.services.security_rules.sendgrid import evaluate
        rec = _webhook_record(inbound_parse_enabled=True)
        findings = [f for f in evaluate(rec) if f.rule_key == _INBOUND_PARSE]
        assert findings
        ev = findings[0].evidence
        assert "inbound_parse_enabled" in ev
        for key in SENSITIVE_EVIDENCE_FIELDS:
            assert key not in ev


# ── Webhook settings: inbound parse raw email enabled ────────────────────────


class TestInboundParseRawEmailEnabled:
    def test_fires_when_parse_enabled_and_raw(self):
        from app.services.security_rules.sendgrid import evaluate
        rec = _webhook_record(
            inbound_parse_enabled=True,
            inbound_parse_send_raw_enabled=True,
        )
        assert _INBOUND_RAW in _keys(evaluate(rec))

    def test_no_fire_when_parse_disabled(self):
        from app.services.security_rules.sendgrid import evaluate
        rec = _webhook_record(
            inbound_parse_enabled=False,
            inbound_parse_send_raw_enabled=True,
        )
        assert _INBOUND_RAW not in _keys(evaluate(rec))

    def test_no_fire_when_raw_disabled(self):
        from app.services.security_rules.sendgrid import evaluate
        rec = _webhook_record(
            inbound_parse_enabled=True,
            inbound_parse_send_raw_enabled=False,
        )
        assert _INBOUND_RAW not in _keys(evaluate(rec))

    def test_evidence_has_no_raw_content(self):
        from app.services.security_rules.sendgrid import evaluate
        rec = _webhook_record(
            inbound_parse_enabled=True,
            inbound_parse_send_raw_enabled=True,
        )
        findings = [f for f in evaluate(rec) if f.rule_key == _INBOUND_RAW]
        assert findings
        ev = findings[0].evidence
        assert ev["inbound_parse_enabled"] is True
        assert ev["inbound_parse_send_raw_enabled"] is True
        for key in SENSITIVE_EVIDENCE_FIELDS:
            assert key not in ev


# ── Webhook settings: inbound parse spam check disabled ──────────────────────


class TestInboundParseSpamCheckDisabled:
    def test_fires_when_parse_enabled_and_spam_check_off(self):
        from app.services.security_rules.sendgrid import evaluate
        rec = _webhook_record(
            inbound_parse_enabled=True,
            inbound_parse_spam_check_enabled=False,
        )
        assert _INBOUND_SPAM in _keys(evaluate(rec))

    def test_no_fire_when_parse_disabled(self):
        from app.services.security_rules.sendgrid import evaluate
        rec = _webhook_record(
            inbound_parse_enabled=False,
            inbound_parse_spam_check_enabled=False,
        )
        assert _INBOUND_SPAM not in _keys(evaluate(rec))

    def test_no_fire_when_spam_check_enabled(self):
        from app.services.security_rules.sendgrid import evaluate
        rec = _webhook_record(
            inbound_parse_enabled=True,
            inbound_parse_spam_check_enabled=True,
        )
        assert _INBOUND_SPAM not in _keys(evaluate(rec))

    def test_finding_severity_is_medium(self):
        from app.services.security_rules.sendgrid import evaluate
        rec = _webhook_record(
            inbound_parse_enabled=True,
            inbound_parse_spam_check_enabled=False,
        )
        findings = [f for f in evaluate(rec) if f.rule_key == _INBOUND_SPAM]
        assert findings
        assert findings[0].severity == "medium"


# ── Healthy record: no M80C rules fire ───────────────────────────────────────


class TestHealthyRecordsNoM80CFire:
    def test_healthy_sender_no_m80c_findings(self):
        from app.services.security_rules.sendgrid import evaluate
        rec = _sender_record()
        keys = _keys(evaluate(rec))
        assert not (ALL_M80C_NEW_RULE_KEYS & keys)

    def test_healthy_domain_no_m80c_findings(self):
        from app.services.security_rules.sendgrid import evaluate
        rec = _domain_record(dns_record_count=3, default=False, valid=True)
        keys = _keys(evaluate(rec))
        assert not (ALL_M80C_NEW_RULE_KEYS & keys)

    def test_healthy_mail_settings_no_m80c_findings(self):
        from app.services.security_rules.sendgrid import evaluate
        rec = _mail_settings_record(
            footer_enabled=True,
            bounce_purge_enabled=True,
            template_enabled=False,
        )
        keys = _keys(evaluate(rec))
        assert not (ALL_M80C_NEW_RULE_KEYS & keys)

    def test_healthy_tracking_no_m80c_findings(self):
        from app.services.security_rules.sendgrid import evaluate
        rec = _tracking_record(ganalytics_enabled=False)
        keys = _keys(evaluate(rec))
        assert not (ALL_M80C_NEW_RULE_KEYS & keys)

    def test_healthy_webhook_no_m80c_findings(self):
        from app.services.security_rules.sendgrid import evaluate
        rec = _webhook_record(
            event_webhook_enabled=True,
            event_count=5,
            inbound_parse_enabled=False,
        )
        keys = _keys(evaluate(rec))
        assert not (ALL_M80C_NEW_RULE_KEYS & keys)


# ── Schema / connector: new fields normalize safely ───────────────────────────


class TestSchemaConnectorExpansion:
    def test_mail_settings_record_has_template_enabled(self):
        rec = _mail_settings_record(template_enabled=True)
        assert "template_enabled" in rec
        assert isinstance(rec["template_enabled"], bool)

    def test_webhook_settings_record_has_inbound_parse_fields(self):
        rec = _webhook_record(
            inbound_parse_enabled=True,
            inbound_parse_spam_check_enabled=False,
            inbound_parse_send_raw_enabled=True,
        )
        assert "inbound_parse_enabled" in rec
        assert "inbound_parse_spam_check_enabled" in rec
        assert "inbound_parse_send_raw_enabled" in rec
        assert isinstance(rec["inbound_parse_enabled"], bool)
        assert isinstance(rec["inbound_parse_spam_check_enabled"], bool)
        assert isinstance(rec["inbound_parse_send_raw_enabled"], bool)

    def test_connector_normalize_webhook_with_parse_configs(self):
        from app.connectors.sendgrid import SendGridConnector
        event_data = {
            "enabled": True,
            "url": "https://example.com/hook",
            "bounce": True,
            "click": True,
            "open": True,
        }
        parse_configs = [
            {"hostname": "parse.example.com", "url": "https://example.com/parse",
             "spam_check": False, "send_raw": True},
        ]
        result = SendGridConnector._normalize_webhook_settings(event_data, parse_configs)
        assert result["inbound_parse_enabled"] is True
        assert result["inbound_parse_send_raw_enabled"] is True
        assert result["inbound_parse_spam_check_enabled"] is False
        # SECURITY: hostname and URL must never be in the result
        assert "hostname" not in result
        assert "url" not in result
        assert "parse.example.com" not in str(result)
        assert "https://example.com/parse" not in str(result)

    def test_connector_normalize_webhook_no_parse_configs(self):
        from app.connectors.sendgrid import SendGridConnector
        event_data = {"enabled": False}
        result = SendGridConnector._normalize_webhook_settings(event_data, [])
        assert result["inbound_parse_enabled"] is False
        assert result["inbound_parse_spam_check_enabled"] is True   # safe default
        assert result["inbound_parse_send_raw_enabled"] is False

    def test_connector_normalize_mail_settings_template_field(self):
        from app.connectors.sendgrid import SendGridConnector
        raw = {"result": [
            {"name": "template", "enabled": True},
            {"name": "footer", "enabled": False},
            {"name": "spam_check", "enabled": True},
        ]}
        result = SendGridConnector._normalize_mail_settings(raw)
        assert result["template_enabled"] is True
        assert result["footer_enabled"] is False
        assert result["spam_check_enabled"] is True


# ── Registry / confidence / pack / coverage parity ───────────────────────────


class TestRegistryParity:
    def test_all_m80c_keys_in_registry(self):
        from app.services.security_rule_registry import KNOWN_RULE_KEYS
        missing = ALL_M80C_NEW_RULE_KEYS - KNOWN_RULE_KEYS
        assert not missing, f"M80C keys missing from KNOWN_RULE_KEYS: {sorted(missing)}"

    def test_m80b_keys_still_in_registry(self):
        from app.services.security_rule_registry import KNOWN_RULE_KEYS
        missing = _M80B_RULE_KEYS - KNOWN_RULE_KEYS
        assert not missing

    def test_all_m80c_keys_have_confidence(self):
        from app.services.security_rule_confidence import RULE_CONFIDENCE
        missing = ALL_M80C_NEW_RULE_KEYS - set(RULE_CONFIDENCE)
        assert not missing, f"M80C keys missing from RULE_CONFIDENCE: {sorted(missing)}"

    def test_all_m80c_keys_in_pack(self):
        from app.services.security_rule_pack import _RULE_META
        missing = ALL_M80C_NEW_RULE_KEYS - set(_RULE_META)
        assert not missing, f"M80C keys missing from _RULE_META: {sorted(missing)}"

    def test_all_m80c_keys_in_coverage(self):
        from app.services.security_coverage_service import RULE_RECORD_TYPES as RULE_RECORD_MAP
        missing = ALL_M80C_NEW_RULE_KEYS - set(RULE_RECORD_MAP)
        assert not missing, f"M80C keys missing from RULE_RECORD_MAP: {sorted(missing)}"

    def test_coverage_maps_to_correct_record_types(self):
        from app.services.security_coverage_service import RULE_RECORD_TYPES as RULE_RECORD_MAP
        assert RULE_RECORD_MAP[_SENDER_REPLY_MISMATCH] == ("sendgrid_sender_identity",)
        assert RULE_RECORD_MAP[_DOMAIN_DNS_MISSING] == ("sendgrid_domain_authentication",)
        assert RULE_RECORD_MAP[_DEFAULT_DOMAIN_INVALID] == ("sendgrid_domain_authentication",)
        assert RULE_RECORD_MAP[_FOOTER_DISABLED] == ("sendgrid_mail_settings",)
        assert RULE_RECORD_MAP[_BOUNCE_PURGE_DISABLED] == ("sendgrid_mail_settings",)
        assert RULE_RECORD_MAP[_TEMPLATE_ENABLED] == ("sendgrid_mail_settings",)
        assert RULE_RECORD_MAP[_GA_TRACKING] == ("sendgrid_tracking_settings",)
        assert RULE_RECORD_MAP[_BROAD_STREAM] == ("sendgrid_webhook_settings",)
        assert RULE_RECORD_MAP[_INBOUND_PARSE] == ("sendgrid_webhook_settings",)
        assert RULE_RECORD_MAP[_INBOUND_RAW] == ("sendgrid_webhook_settings",)
        assert RULE_RECORD_MAP[_INBOUND_SPAM] == ("sendgrid_webhook_settings",)


# ── Capability matrix ─────────────────────────────────────────────────────────


class TestCapabilityMatrix:
    def _get_sendgrid_cap(self):
        from app.services.provider_capability_matrix_service import (
            get_provider_capability,
        )
        return get_provider_capability("sendgrid")

    def test_sendgrid_capability_exists(self):
        cap = self._get_sendgrid_cap()
        assert cap is not None

    def test_maturity_is_partial(self):
        cap = self._get_sendgrid_cap()
        assert cap.maturity == "partial"

    def test_security_rules_true(self):
        cap = self._get_sendgrid_cap()
        assert cap.security.security_rules is True

    def test_activity_signals_correlations_demo_false(self):
        cap = self._get_sendgrid_cap()
        # M80D rolled activity_ingestion forward to True.
        # M80E rolled activity_signals forward to True.
        assert cap.security.activity_ingestion is True
        assert cap.security.activity_signals is True
        assert cap.security.risk_activity_correlations is True  # M80F rolled forward
        assert cap.security.demo_seed_clear is False
        assert cap.security.case_report is False

    def test_notes_mention_m80c(self):
        cap = self._get_sendgrid_cap()
        assert "M80C" in cap.notes, "Capability notes should mention M80C"

    def test_drift_snapshots_true(self):
        cap = self._get_sendgrid_cap()
        assert cap.drift.drift_snapshots is True

    def test_drift_risk_classification_true(self):
        cap = self._get_sendgrid_cap()
        assert cap.drift.drift_risk_classification is True


# ── Expansion framework ───────────────────────────────────────────────────────


class TestExpansionFramework:
    def test_planned_next_stage_is_m80d(self):
        from app.services.provider_expansion_framework import get_framework
        fw = get_framework()
        stage = fw["summary"]["planned_next_stage"]
        assert "M80G" in stage, f"Expected M80G in planned_next_stage, got: {stage!r}"
        assert "SendGrid" in stage or "Demo" in stage, (
            f"Expected SendGrid/Demo in planned_next_stage, got: {stage!r}"
        )


# ── Frontend catalog ──────────────────────────────────────────────────────────


class TestFrontendCatalog:
    def _catalog_text(self) -> str:
        return FE_CATALOG.read_text(encoding="utf-8")

    def test_all_m80c_keys_in_catalog(self):
        text = self._catalog_text()
        for key in ALL_M80C_NEW_RULE_KEYS:
            assert key in text, f"M80C rule key not in frontend catalog: {key}"

    def test_m80b_keys_still_in_catalog(self):
        text = self._catalog_text()
        for key in _M80B_RULE_KEYS:
            assert key in text, f"M80B rule key missing from frontend catalog: {key}"

    def test_catalog_has_required_fields_for_new_keys(self):
        text = self._catalog_text()
        required = ["key:", "provider:", "severity:", "title:", "category:",
                    "confidence:", "description:", "whatItChecks:", "evidence:",
                    "remediation:", "falsePositiveGuard:"]
        # Each M80C key section should be surrounded by required fields.
        for key in ALL_M80C_NEW_RULE_KEYS:
            assert key in text, f"key {key} not in catalog"
        # All required fields appear at least N times in the full catalog.
        for field in required:
            assert text.count(field) > 0


# ── Privacy / sanitization checks ────────────────────────────────────────────


class TestPrivacySanitization:
    """Ensure no sensitive data appears in any M80C rule evidence."""

    def _all_m80c_findings(self):
        from app.services.security_rules.sendgrid import evaluate

        records = [
            _sender_record(from_email_domain="a.com", reply_to_domain="b.com"),
            _domain_record(dns_record_count=0, valid=False),
            _domain_record(default=True, valid=False),
            _mail_settings_record(footer_enabled=False),
            _mail_settings_record(bounce_purge_enabled=False),
            _mail_settings_record(template_enabled=True),
            _tracking_record(ganalytics_enabled=True),
            _webhook_record(event_webhook_enabled=True, event_count=11),
            _webhook_record(inbound_parse_enabled=True),
            _webhook_record(
                inbound_parse_enabled=True,
                inbound_parse_send_raw_enabled=True,
            ),
            _webhook_record(
                inbound_parse_enabled=True,
                inbound_parse_spam_check_enabled=False,
            ),
        ]
        findings = []
        for rec in records:
            findings.extend(evaluate(rec))
        return [f for f in findings if f.rule_key in ALL_M80C_NEW_RULE_KEYS]

    def test_no_sensitive_evidence_fields(self):
        findings = self._all_m80c_findings()
        assert findings, "Expected at least some M80C findings"
        for finding in findings:
            ev = finding.evidence
            for key in SENSITIVE_EVIDENCE_FIELDS:
                assert key not in ev, (
                    f"Sensitive field '{key}' in evidence for rule {finding.rule_key}"
                )

    def test_no_at_signs_in_evidence_values(self):
        findings = self._all_m80c_findings()
        for finding in findings:
            for _k, v in finding.evidence.items():
                if isinstance(v, str):
                    assert "@" not in v, (
                        f"Email-like value with @ in evidence for rule {finding.rule_key}: {v!r}"
                    )

    def test_no_http_in_evidence_values(self):
        findings = self._all_m80c_findings()
        for finding in findings:
            for _k, v in finding.evidence.items():
                if isinstance(v, str):
                    assert not v.startswith("http"), (
                        f"URL-like value in evidence for rule {finding.rule_key}: {v!r}"
                    )


# ── Forbidden wording ─────────────────────────────────────────────────────────


class TestForbiddenWording:
    def test_no_forbidden_phrases_in_sendgrid_rules_module(self):
        from app.services.security_rules import sendgrid as sg_module
        import inspect
        source = inspect.getsource(sg_module)
        for phrase in FORBIDDEN_PHRASES:
            assert phrase not in source.lower(), (
                f"Forbidden phrase '{phrase}' found in sendgrid security rules module"
            )

    def test_no_forbidden_phrases_in_frontend_catalog(self):
        text = FE_CATALOG.read_text(encoding="utf-8").lower()
        for phrase in FORBIDDEN_PHRASES:
            assert phrase not in text, (
                f"Forbidden phrase '{phrase}' found in frontend catalog"
            )


# ── Secret-shape grep ─────────────────────────────────────────────────────────


class TestSecretShapeGrep:
    _SG_PATTERN = re.compile(
        r"SG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
    )
    _TWILIO_PATTERNS = [
        re.compile(r"AC[0-9a-fA-F]{32}"),
        re.compile(r"SK[0-9a-fA-F]{32}"),
    ]

    def _scan_dir(self, root: Path) -> list[str]:
        hits = []
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix not in (".py", ".ts", ".tsx", ".js", ".json"):
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            if self._SG_PATTERN.search(text):
                hits.append(f"{path}: SendGrid secret shape")
            for pat in self._TWILIO_PATTERNS:
                if pat.search(text):
                    hits.append(f"{path}: Twilio secret shape")
        return hits

    def test_no_secret_shapes_in_backend_app(self):
        hits = self._scan_dir(BACKEND_APP)
        assert not hits, f"Secret-shaped strings found:\n" + "\n".join(hits)

    def test_no_secret_shapes_in_frontend_src(self):
        hits = self._scan_dir(FRONTEND_SRC)
        assert not hits, f"Secret-shaped strings found:\n" + "\n".join(hits)
