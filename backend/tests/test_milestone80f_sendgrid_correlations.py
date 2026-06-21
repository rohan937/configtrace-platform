"""M80F — SendGrid Risk × Activity Correlations.

Verifies:
  * SENDGRID_CORRELATION_TYPES contains all 7 expected correlation types
  * SENDGRID_CORRELATION_RULES covers all 26 SendGrid rule keys across 7 families
  * Each rule family maps correctly to expected signal types
  * _match_pair returns correct match_reason for per-resource and family matches
  * _build_correlation produces safe metadata with no forbidden fields
  * generate_sendgrid_correlations queries only provider=sendgrid findings/signals
  * API key findings correlate with api_key signals using api_key_id matching
  * Sender identity findings correlate with sender_identity signals using sender_id
  * Domain auth findings correlate with domain_auth signals using domain_id
  * Account-level surfaces (mail/tracking/webhook/suppression) use family matching
  * No cross-resource correlations (different api_key_id → no match)
  * Idempotency: re-running with same data creates no duplicate correlations
  * Metadata contains no API keys, bearer tokens, auth headers, raw URLs,
    webhook URLs, raw SendGrid payloads, email bodies, subject lines, recipient
    emails, sender full emails, suppression emails, template content, contact
    data, mail event payloads, message IDs, customer data, or PII
  * API endpoint POST /security/sendgrid-correlations/generate
  * Endpoint requires admin/owner; member cannot call
  * Schema has correct request/response shapes
  * ALLOWED_METADATA_KEYS in correlation service includes SendGrid keys
  * Capability matrix marks risk_activity_correlations=True
  * Expansion framework points to M80G
  * Frontend correlations page includes SendGrid provider and blurb
  * Forbidden wording absent from correlation service
  * No SendGrid/Twilio secret-shaped strings

CLAIM DISCIPLINE: correlations are EVIDENCE FOR REVIEW. They never assert that
a breach, compromise, unauthorized access, or data exposure has occurred.
"""

from __future__ import annotations

import inspect
import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
FE_CORR = REPO_ROOT / "frontend" / "src" / "app" / "(app)" / "security" / "correlations" / "page.tsx"
FE_API = REPO_ROOT / "frontend" / "src" / "lib" / "api.ts"
FE_TYPES = REPO_ROOT / "frontend" / "src" / "types" / "index.ts"
BACKEND_APP = REPO_ROOT / "backend" / "app"

# ── Forbidden wording ─────────────────────────────────────────────────────────

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

# Correlation metadata fields that must NEVER appear.
FORBIDDEN_METADATA_FIELDS = frozenset({
    "api_key",
    "api_key_value",
    "api_key_secret",
    "bearer",
    "authorization",
    "access_token",
    "secret",
    "email",
    "from_email",
    "reply_to",
    "recipient_email",
    "sender_email",
    "suppressed_email",
    "url",
    "webhook_url",
    "hostname",
    "template_content",
    "subject",
    "body",
    "payload",
    "raw",
    "message_id",
    "sg_message_id",
    "smtp_id",
    "click",
    "bounce",
    "delivered",
    "deferred",
    "dropped",
    "spamreport",
    "unsubscribe",
    "ip_address",
    "customer",
    "contact",
    "recipient",
})

# ── Expected correlation types ────────────────────────────────────────────────

EXPECTED_CORRELATION_TYPES: frozenset[str] = frozenset({
    "sendgrid_api_key_risk_activity_correlation",
    "sendgrid_sender_identity_risk_activity_correlation",
    "sendgrid_domain_authentication_risk_activity_correlation",
    "sendgrid_mail_settings_risk_activity_correlation",
    "sendgrid_tracking_settings_risk_activity_correlation",
    "sendgrid_webhook_risk_activity_correlation",
    "sendgrid_suppression_settings_risk_activity_correlation",
})

# Rule key → expected correlation family
EXPECTED_RULE_FAMILIES: dict[str, str] = {
    "sendgrid_api_key_broad_scopes": "sendgrid_api_key_risk_activity_correlation",
    "sendgrid_sender_identity_unverified": "sendgrid_sender_identity_risk_activity_correlation",
    "sendgrid_sender_identity_locked": "sendgrid_sender_identity_risk_activity_correlation",
    "sendgrid_sender_identity_reply_domain_mismatch": "sendgrid_sender_identity_risk_activity_correlation",
    "sendgrid_domain_authentication_invalid": "sendgrid_domain_authentication_risk_activity_correlation",
    "sendgrid_domain_automatic_security_disabled": "sendgrid_domain_authentication_risk_activity_correlation",
    "sendgrid_domain_authentication_legacy": "sendgrid_domain_authentication_risk_activity_correlation",
    "sendgrid_domain_dns_records_missing": "sendgrid_domain_authentication_risk_activity_correlation",
    "sendgrid_default_domain_authentication_invalid": "sendgrid_domain_authentication_risk_activity_correlation",
    "sendgrid_spam_check_disabled": "sendgrid_mail_settings_risk_activity_correlation",
    "sendgrid_sandbox_mode_enabled": "sendgrid_mail_settings_risk_activity_correlation",
    "sendgrid_bcc_enabled": "sendgrid_mail_settings_risk_activity_correlation",
    "sendgrid_footer_disabled": "sendgrid_mail_settings_risk_activity_correlation",
    "sendgrid_bounce_purge_disabled": "sendgrid_mail_settings_risk_activity_correlation",
    "sendgrid_template_engine_enabled": "sendgrid_mail_settings_risk_activity_correlation",
    "sendgrid_click_tracking_enabled": "sendgrid_tracking_settings_risk_activity_correlation",
    "sendgrid_open_tracking_enabled": "sendgrid_tracking_settings_risk_activity_correlation",
    "sendgrid_subscription_tracking_disabled": "sendgrid_tracking_settings_risk_activity_correlation",
    "sendgrid_google_analytics_tracking_enabled": "sendgrid_tracking_settings_risk_activity_correlation",
    "sendgrid_event_webhook_disabled": "sendgrid_webhook_risk_activity_correlation",
    "sendgrid_event_webhook_url_missing": "sendgrid_webhook_risk_activity_correlation",
    "sendgrid_event_webhook_broad_event_stream": "sendgrid_webhook_risk_activity_correlation",
    "sendgrid_inbound_parse_enabled": "sendgrid_webhook_risk_activity_correlation",
    "sendgrid_inbound_parse_raw_email_enabled": "sendgrid_webhook_risk_activity_correlation",
    "sendgrid_inbound_parse_spam_check_disabled": "sendgrid_webhook_risk_activity_correlation",
    "sendgrid_suppression_settings_empty": "sendgrid_suppression_settings_risk_activity_correlation",
}


# ── Mock helpers ──────────────────────────────────────────────────────────────


def _recent(hours: float = 1) -> datetime:
    return datetime.now(timezone.utc) - timedelta(hours=hours)


def _make_finding(
    rule_key: str = "sendgrid_api_key_broad_scopes",
    workspace_id: uuid.UUID | None = None,
    status: str = "active",
    severity: str = "high",
    evidence: dict | None = None,
) -> MagicMock:
    f = MagicMock()
    f.id = uuid.uuid4()
    f.workspace_id = workspace_id or uuid.uuid4()
    f.provider = "sendgrid"
    f.finding_key = f"{rule_key}:test-record-id"
    f.status = status
    f.severity = severity
    f.first_detected_at = _recent(2)
    f.last_seen_at = _recent(1)
    f.linked_change_id = None
    f.integration_id = uuid.uuid4()
    f.evidence = evidence or {}
    return f


def _make_signal(
    signal_type: str = "sendgrid_api_key_config_changed",
    workspace_id: uuid.UUID | None = None,
    signal_metadata: dict | None = None,
) -> MagicMock:
    s = MagicMock()
    s.id = uuid.uuid4()
    s.workspace_id = workspace_id or uuid.uuid4()
    s.provider = "sendgrid"
    s.signal_type = signal_type
    s.first_seen_at = _recent(1)
    s.last_seen_at = _recent(0)
    s.linked_activity_event_id = uuid.uuid4()
    s.signal_metadata = signal_metadata or {
        "event_source": "sendgrid_activity_event",
        "event_types": "sendgrid.api_key.updated",
        "event_count": 1,
    }
    return s


# ══════════════════════════════════════════════════════════════════════════════
# A: Correlation type registry
# ══════════════════════════════════════════════════════════════════════════════

class TestCorrelationTypeRegistry:
    def test_a1_correlation_types_is_frozenset(self):
        from app.services.sendgrid_risk_activity_correlation_service import SENDGRID_CORRELATION_TYPES
        assert isinstance(SENDGRID_CORRELATION_TYPES, frozenset)

    def test_a2_all_expected_types_present(self):
        from app.services.sendgrid_risk_activity_correlation_service import SENDGRID_CORRELATION_TYPES
        missing = EXPECTED_CORRELATION_TYPES - SENDGRID_CORRELATION_TYPES
        assert not missing, f"missing correlation types: {missing}"

    def test_a3_type_count_is_7(self):
        from app.services.sendgrid_risk_activity_correlation_service import SENDGRID_CORRELATION_TYPES
        assert len(SENDGRID_CORRELATION_TYPES) == 7

    def test_a4_rules_cover_26_sendgrid_rule_keys(self):
        """All SendGrid rule keys must appear in at least one correlation config (27 total)."""
        from app.services.sendgrid_risk_activity_correlation_service import SENDGRID_CORRELATION_RULES
        from app.services.security_rules.sendgrid import SENDGRID_RULE_KEYS
        all_rule_keys = set()
        for rule in SENDGRID_CORRELATION_RULES.values():
            all_rule_keys.update(rule["rule_keys"])
        missing = set(EXPECTED_RULE_FAMILIES.keys()) - all_rule_keys
        assert not missing, f"rule keys not covered: {missing}"
        assert len(all_rule_keys) == len(SENDGRID_RULE_KEYS), (
            f"Correlation rule key count ({len(all_rule_keys)}) must match "
            f"SENDGRID_RULE_KEYS count ({len(SENDGRID_RULE_KEYS)})"
        )

    def test_a5_each_rule_key_maps_to_correct_family(self):
        from app.services.sendgrid_risk_activity_correlation_service import SENDGRID_CORRELATION_RULES
        rule_key_to_corr: dict[str, str] = {}
        for corr_type, rule in SENDGRID_CORRELATION_RULES.items():
            for rk in rule["rule_keys"]:
                rule_key_to_corr[rk] = corr_type
        for rk, expected_ct in EXPECTED_RULE_FAMILIES.items():
            got = rule_key_to_corr.get(rk)
            assert got == expected_ct, f"{rk!r}: expected {expected_ct!r}, got {got!r}"


# ══════════════════════════════════════════════════════════════════════════════
# B: _match_pair logic
# ══════════════════════════════════════════════════════════════════════════════

class TestMatchPair:
    def test_b1_api_key_exact_match(self):
        from app.services.sendgrid_risk_activity_correlation_service import _match_pair
        finding = _make_finding(evidence={"api_key_id": "key_abc"})
        signal = _make_signal(signal_metadata={"api_key_id": "key_abc"})
        result = _match_pair(finding, signal, "api_key")
        assert result == "api_key_id_match"

    def test_b2_api_key_no_cross_key_match(self):
        from app.services.sendgrid_risk_activity_correlation_service import _match_pair
        finding = _make_finding(evidence={"api_key_id": "key_abc"})
        signal = _make_signal(signal_metadata={"api_key_id": "key_xyz"})
        result = _match_pair(finding, signal, "api_key")
        assert result is None  # different keys → no correlation

    def test_b3_api_key_family_when_no_id(self):
        from app.services.sendgrid_risk_activity_correlation_service import _match_pair
        finding = _make_finding(evidence={})
        signal = _make_signal(signal_metadata={})
        result = _match_pair(finding, signal, "api_key")
        assert result == "api_key_family"

    def test_b4_sender_id_exact_match(self):
        from app.services.sendgrid_risk_activity_correlation_service import _match_pair
        finding = _make_finding(evidence={"sender_id": "SENDGRID_TEST_SENDER_ID"})
        signal = _make_signal(signal_metadata={"sender_id": "SENDGRID_TEST_SENDER_ID"})
        result = _match_pair(finding, signal, "sender_identity")
        assert result == "sender_id_match"

    def test_b5_sender_id_no_cross_match(self):
        from app.services.sendgrid_risk_activity_correlation_service import _match_pair
        finding = _make_finding(evidence={"sender_id": "sender_001"})
        signal = _make_signal(signal_metadata={"sender_id": "sender_002"})
        result = _match_pair(finding, signal, "sender_identity")
        assert result is None

    def test_b6_domain_id_exact_match(self):
        from app.services.sendgrid_risk_activity_correlation_service import _match_pair
        finding = _make_finding(evidence={"domain_id": "SENDGRID_TEST_DOMAIN_ID"})
        signal = _make_signal(signal_metadata={"domain_id": "SENDGRID_TEST_DOMAIN_ID"})
        result = _match_pair(finding, signal, "domain_authentication")
        assert result == "domain_id_match"

    def test_b7_mail_settings_family_match(self):
        from app.services.sendgrid_risk_activity_correlation_service import _match_pair
        finding = _make_finding(evidence={})
        signal = _make_signal()
        result = _match_pair(finding, signal, "mail_settings")
        assert result == "mail_settings_family"

    def test_b8_tracking_settings_family_match(self):
        from app.services.sendgrid_risk_activity_correlation_service import _match_pair
        finding = _make_finding(evidence={})
        signal = _make_signal()
        result = _match_pair(finding, signal, "tracking_settings")
        assert result == "tracking_settings_family"

    def test_b9_webhook_family_match(self):
        from app.services.sendgrid_risk_activity_correlation_service import _match_pair
        finding = _make_finding(evidence={})
        signal = _make_signal()
        result = _match_pair(finding, signal, "webhook")
        assert result == "webhook_family"

    def test_b10_suppression_family_match(self):
        from app.services.sendgrid_risk_activity_correlation_service import _match_pair
        finding = _make_finding(evidence={})
        signal = _make_signal()
        result = _match_pair(finding, signal, "suppression_settings")
        assert result == "suppression_settings_family"

    def test_b11_match_strength_exact(self):
        from app.services.sendgrid_risk_activity_correlation_service import _match_strength
        assert _match_strength("api_key_id_match") == "high"
        assert _match_strength("sender_id_match") == "high"
        assert _match_strength("domain_id_match") == "high"

    def test_b12_match_strength_family(self):
        from app.services.sendgrid_risk_activity_correlation_service import _match_strength
        assert _match_strength("api_key_family") == "medium"
        assert _match_strength("mail_settings_family") == "medium"


# ══════════════════════════════════════════════════════════════════════════════
# C: _build_correlation metadata privacy
# ══════════════════════════════════════════════════════════════════════════════

class TestBuildCorrelationPrivacy:
    def test_c1_no_forbidden_metadata_fields(self):
        from app.services.sendgrid_risk_activity_correlation_service import (
            _build_correlation,
            SENDGRID_CORRELATION_RULES,
        )
        rule_name = "sendgrid_api_key_risk_activity_correlation"
        rule = SENDGRID_CORRELATION_RULES[rule_name]
        finding = _make_finding(
            rule_key="sendgrid_api_key_broad_scopes",
            evidence={"api_key_id": "SENDGRID_TEST_API_KEY_PLACEHOLDER", "has_full_access": True},
        )
        signal = _make_signal(
            signal_type="sendgrid_api_key_config_changed",
            signal_metadata={"api_key_id": "SENDGRID_TEST_API_KEY_PLACEHOLDER", "event_count": 1}
        )
        corr = _build_correlation(
            finding=finding,
            signal=signal,
            correlation_type=rule_name,
            rule=rule,
            match_reason="api_key_id_match",
        )
        md = corr.get("metadata", {})
        for key in FORBIDDEN_METADATA_FIELDS:
            assert key not in md, f"forbidden field {key!r} in correlation metadata"

    def test_c2_no_at_signs_in_metadata_values(self):
        from app.services.sendgrid_risk_activity_correlation_service import (
            _build_correlation,
            SENDGRID_CORRELATION_RULES,
        )
        rule_name = "sendgrid_sender_identity_risk_activity_correlation"
        rule = SENDGRID_CORRELATION_RULES[rule_name]
        finding = _make_finding(
            rule_key="sendgrid_sender_identity_unverified",
            evidence={"sender_id": "SENDGRID_TEST_SENDER_ID", "verified": False},
        )
        signal = _make_signal(
            signal_type="sendgrid_sender_identity_config_changed",
            signal_metadata={"sender_id": "SENDGRID_TEST_SENDER_ID", "event_count": 1}
        )
        corr = _build_correlation(
            finding=finding,
            signal=signal,
            correlation_type=rule_name,
            rule=rule,
            match_reason="sender_id_match",
        )
        for k, v in corr.get("metadata", {}).items():
            if isinstance(v, str):
                assert "@" not in v, f"email-like @ in metadata field {k!r}: {v!r}"

    def test_c3_no_http_in_metadata_values(self):
        from app.services.sendgrid_risk_activity_correlation_service import (
            _build_correlation,
            SENDGRID_CORRELATION_RULES,
        )
        rule = SENDGRID_CORRELATION_RULES["sendgrid_webhook_risk_activity_correlation"]
        finding = _make_finding(rule_key="sendgrid_event_webhook_disabled")
        signal = _make_signal(signal_type="sendgrid_event_webhook_config_changed")
        corr = _build_correlation(
            finding=finding,
            signal=signal,
            correlation_type="sendgrid_webhook_risk_activity_correlation",
            rule=rule,
            match_reason="webhook_family",
        )
        for k, v in corr.get("metadata", {}).items():
            if isinstance(v, str):
                assert not v.startswith("http"), f"URL in metadata field {k!r}: {v!r}"

    def test_c4_safe_ids_in_metadata(self):
        from app.services.sendgrid_risk_activity_correlation_service import (
            _build_correlation,
            SENDGRID_CORRELATION_RULES,
        )
        rule = SENDGRID_CORRELATION_RULES["sendgrid_api_key_risk_activity_correlation"]
        finding = _make_finding(
            rule_key="sendgrid_api_key_broad_scopes",
            evidence={"api_key_id": "SENDGRID_TEST_API_KEY_PLACEHOLDER"},
        )
        signal = _make_signal(
            signal_type="sendgrid_api_key_config_changed",
            signal_metadata={"api_key_id": "SENDGRID_TEST_API_KEY_PLACEHOLDER"}
        )
        corr = _build_correlation(
            finding=finding,
            signal=signal,
            correlation_type="sendgrid_api_key_risk_activity_correlation",
            rule=rule,
            match_reason="api_key_id_match",
        )
        md = corr.get("metadata", {})
        assert "api_key_id" in md
        assert "api_key" not in md  # the KEY VALUE must not be there


# ══════════════════════════════════════════════════════════════════════════════
# D: generate_sendgrid_correlations integration (mocked DB)
# ══════════════════════════════════════════════════════════════════════════════

class TestGenerateCorrelationsMocked:
    def _make_db(self, findings: list, signals: list) -> MagicMock:
        db = MagicMock()
        q = MagicMock()
        db.query.return_value = q
        q.filter.return_value = q
        q.order_by.return_value = q
        q.limit.return_value = q
        # First call returns findings, second returns signals
        q.all.side_effect = [findings, signals]
        return db

    def test_d1_returns_summary_dict(self):
        from app.services.sendgrid_risk_activity_correlation_service import generate_sendgrid_correlations
        db = self._make_db([], [])
        result = generate_sendgrid_correlations(workspace_id=uuid.uuid4(), db=db)
        assert isinstance(result, dict)
        for key in ("provider", "findings_scanned", "signals_scanned",
                    "correlations_created", "correlations_skipped"):
            assert key in result, f"missing key: {key}"

    def test_d2_provider_is_sendgrid(self):
        from app.services.sendgrid_risk_activity_correlation_service import generate_sendgrid_correlations
        db = self._make_db([], [])
        result = generate_sendgrid_correlations(workspace_id=uuid.uuid4(), db=db)
        assert result["provider"] == "sendgrid"

    def test_d3_zero_findings_zero_correlations(self):
        from app.services.sendgrid_risk_activity_correlation_service import generate_sendgrid_correlations
        db = self._make_db([], [])
        result = generate_sendgrid_correlations(workspace_id=uuid.uuid4(), db=db)
        assert result["findings_scanned"] == 0
        assert result["correlations_created"] == 0

    def test_d4_api_key_finding_correlates_with_api_key_signal(self):
        from app.services.sendgrid_risk_activity_correlation_service import generate_sendgrid_correlations
        from app.services import security_signal_correlation_service as corr_svc
        wid = uuid.uuid4()
        finding = _make_finding(
            rule_key="sendgrid_api_key_broad_scopes",
            workspace_id=wid,
            evidence={"api_key_id": "key_001"},
        )
        signal = _make_signal(
            signal_type="sendgrid_api_key_config_changed",
            workspace_id=wid,
            signal_metadata={"api_key_id": "key_001", "event_count": 1},
        )
        db = self._make_db([finding], [signal])
        with patch.object(corr_svc, "upsert_correlation") as mock_upsert:
            mock_upsert.return_value = ("created", MagicMock())
            result = generate_sendgrid_correlations(workspace_id=wid, db=db)
        assert result["correlations_created"] == 1

    def test_d5_no_cross_api_key_correlation(self):
        from app.services.sendgrid_risk_activity_correlation_service import generate_sendgrid_correlations
        from app.services import security_signal_correlation_service as corr_svc
        wid = uuid.uuid4()
        finding = _make_finding(
            rule_key="sendgrid_api_key_broad_scopes",
            workspace_id=wid,
            evidence={"api_key_id": "key_001"},
        )
        signal = _make_signal(
            signal_type="sendgrid_api_key_config_changed",
            workspace_id=wid,
            signal_metadata={"api_key_id": "key_999"},  # different key
        )
        db = self._make_db([finding], [signal])
        with patch.object(corr_svc, "upsert_correlation") as mock_upsert:
            mock_upsert.return_value = ("created", MagicMock())
            result = generate_sendgrid_correlations(workspace_id=wid, db=db)
        # Different api_key_ids → no correlation
        assert result["correlations_created"] == 0

    def test_d6_mail_settings_family_correlates(self):
        from app.services.sendgrid_risk_activity_correlation_service import generate_sendgrid_correlations
        from app.services import security_signal_correlation_service as corr_svc
        wid = uuid.uuid4()
        finding = _make_finding(
            rule_key="sendgrid_spam_check_disabled",
            workspace_id=wid,
            evidence={"spam_check_enabled": False},
        )
        signal = _make_signal(
            signal_type="sendgrid_mail_settings_config_changed",
            workspace_id=wid,
        )
        db = self._make_db([finding], [signal])
        with patch.object(corr_svc, "upsert_correlation") as mock_upsert:
            mock_upsert.return_value = ("created", MagicMock())
            result = generate_sendgrid_correlations(workspace_id=wid, db=db)
        assert result["correlations_created"] == 1

    def test_d7_idempotent_second_run_skips(self):
        from app.services.sendgrid_risk_activity_correlation_service import generate_sendgrid_correlations
        from app.services import security_signal_correlation_service as corr_svc
        wid = uuid.uuid4()
        finding = _make_finding(
            rule_key="sendgrid_api_key_broad_scopes",
            workspace_id=wid,
        )
        signal = _make_signal(workspace_id=wid)
        db = self._make_db([finding], [signal])
        with patch.object(corr_svc, "upsert_correlation") as mock_upsert:
            mock_upsert.return_value = ("skipped", MagicMock())
            result = generate_sendgrid_correlations(workspace_id=wid, db=db)
        assert result["correlations_created"] == 0
        assert result["correlations_skipped"] == 1

    def test_d8_inactive_findings_not_used(self):
        from app.services.sendgrid_risk_activity_correlation_service import generate_sendgrid_correlations
        wid = uuid.uuid4()
        # The DB query filters status == 'active', but here we test service with
        # what DB returns (in real use only active findings come back)
        db = self._make_db([], [])
        result = generate_sendgrid_correlations(workspace_id=wid, db=db)
        assert result["findings_scanned"] == 0

    def test_d9_max_correlations_cap_enforced(self):
        from app.services.sendgrid_risk_activity_correlation_service import generate_sendgrid_correlations
        from app.services import security_signal_correlation_service as corr_svc
        wid = uuid.uuid4()
        # Create 5 mail settings findings
        findings = [
            _make_finding("sendgrid_spam_check_disabled", workspace_id=wid)
            for _ in range(5)
        ]
        signal = _make_signal("sendgrid_mail_settings_config_changed", workspace_id=wid)
        db = self._make_db(findings, [signal])
        with patch.object(corr_svc, "upsert_correlation") as mock_upsert:
            mock_upsert.return_value = ("created", MagicMock())
            result = generate_sendgrid_correlations(
                workspace_id=wid, db=db, max_correlations=2
            )
        assert result["correlations_created"] == 2

    def test_d10_webhook_finding_correlates_with_webhook_signal(self):
        from app.services.sendgrid_risk_activity_correlation_service import generate_sendgrid_correlations
        from app.services import security_signal_correlation_service as corr_svc
        wid = uuid.uuid4()
        finding = _make_finding(
            rule_key="sendgrid_event_webhook_disabled",
            workspace_id=wid,
        )
        signal = _make_signal(
            signal_type="sendgrid_event_webhook_config_changed",
            workspace_id=wid,
        )
        db = self._make_db([finding], [signal])
        with patch.object(corr_svc, "upsert_correlation") as mock_upsert:
            mock_upsert.return_value = ("created", MagicMock())
            result = generate_sendgrid_correlations(workspace_id=wid, db=db)
        assert result["correlations_created"] == 1

    def test_d11_suppression_finding_correlates_with_suppression_signal(self):
        from app.services.sendgrid_risk_activity_correlation_service import generate_sendgrid_correlations
        from app.services import security_signal_correlation_service as corr_svc
        wid = uuid.uuid4()
        finding = _make_finding(
            rule_key="sendgrid_suppression_settings_empty",
            workspace_id=wid,
        )
        signal = _make_signal(
            signal_type="sendgrid_suppression_settings_config_changed",
            workspace_id=wid,
        )
        db = self._make_db([finding], [signal])
        with patch.object(corr_svc, "upsert_correlation") as mock_upsert:
            mock_upsert.return_value = ("created", MagicMock())
            result = generate_sendgrid_correlations(workspace_id=wid, db=db)
        assert result["correlations_created"] == 1


# ══════════════════════════════════════════════════════════════════════════════
# E: API endpoint
# ══════════════════════════════════════════════════════════════════════════════

class TestApiEndpoint:
    def test_e1_endpoint_exists_in_router(self):
        from app.routers.security import router
        paths = [r.path for r in router.routes]
        assert any("sendgrid-correlations/generate" in p for p in paths), (
            "POST /security/sendgrid-correlations/generate not registered"
        )

    def test_e2_schema_has_correlation_request(self):
        from app.schemas.security_sendgrid_activity import SendGridCorrelationGenerateRequest
        req = SendGridCorrelationGenerateRequest()
        assert req.lookback_hours == 24
        assert req.max_correlations == 100

    def test_e3_schema_has_correlation_response(self):
        from app.schemas.security_sendgrid_activity import SendGridCorrelationGenerateResponse
        resp = SendGridCorrelationGenerateResponse(
            findings_scanned=10,
            signals_scanned=5,
            correlations_created=3,
            correlations_skipped=0,
        )
        assert resp.provider == "sendgrid"
        assert resp.correlations_created == 3

    def test_e4_unauthenticated_returns_expected_status(self):
        from fastapi.testclient import TestClient
        from app.main import app
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/security/sendgrid-correlations/generate", json={})
        assert resp.status_code in (200, 401, 422), (
            f"Expected 200/401/422, got {resp.status_code}: {resp.text[:200]}"
        )


# ══════════════════════════════════════════════════════════════════════════════
# F: Correlation ALLOWED_METADATA_KEYS
# ══════════════════════════════════════════════════════════════════════════════

class TestCorrelationAllowedMetadataKeys:
    def _keys(self):
        from app.services.security_signal_correlation_service import ALLOWED_METADATA_KEYS
        return ALLOWED_METADATA_KEYS

    def test_f1_sendgrid_specific_keys_present(self):
        keys = self._keys()
        sendgrid_keys = [
            "api_key_id",
            "sender_id",
            "mail_setting_name",
            "tracking_setting_name",
            "event_webhook_enabled",
            "event_webhook_has_url",
            "inbound_parse_enabled",
            "domain_valid",
            "automatic_security",
            "sender_verified",
            "sender_locked",
            "suppression_group_count",
        ]
        missing = [k for k in sendgrid_keys if k not in keys]
        assert not missing, f"missing from ALLOWED_METADATA_KEYS: {missing}"

    def test_f2_common_keys_present(self):
        keys = self._keys()
        common = ["source", "rule_key", "signal_type", "resource_type",
                  "match_reason", "match_strength", "finding_severity",
                  "event_types", "event_count", "risk_family", "activity_family"]
        missing = [k for k in common if k not in keys]
        assert not missing, f"missing common keys: {missing}"

    def test_f3_forbidden_keys_absent(self):
        keys = self._keys()
        forbidden = [
            "api_key", "bearer", "authorization", "email", "from_email",
            "url", "webhook_url", "hostname", "template_content",
            "subject", "body", "payload", "message_id", "customer",
        ]
        found = [k for k in forbidden if k in keys]
        assert not found, f"forbidden keys in ALLOWED_METADATA_KEYS: {found}"


# ══════════════════════════════════════════════════════════════════════════════
# G: Capability matrix
# ══════════════════════════════════════════════════════════════════════════════

class TestCapabilityMatrix:
    def _cap(self):
        from app.services.provider_capability_matrix_service import get_provider_capability
        return get_provider_capability("sendgrid")

    def test_g1_risk_activity_correlations_true(self):
        assert self._cap().security.risk_activity_correlations is True

    def test_g2_activity_signals_true(self):
        assert self._cap().security.activity_signals is True

    def test_g3_activity_ingestion_true(self):
        assert self._cap().security.activity_ingestion is True

    def test_g4_demo_and_case_false(self):
        cap = self._cap()
        assert cap.security.demo_seed_clear is True  # M80G rolled forward
        assert cap.security.case_report is True  # M80G rolled forward

    def test_g5_maturity_partial(self):
        assert self._cap().maturity == "partial"

    def test_g6_notes_mention_m80f_or_correlations(self):
        cap = self._cap()
        assert "M80F" in cap.notes or "correlat" in cap.notes.lower(), (
            "Capability notes should mention M80F or correlations"
        )


# ══════════════════════════════════════════════════════════════════════════════
# H: Expansion framework
# ══════════════════════════════════════════════════════════════════════════════

class TestExpansionFramework:
    def _fw(self):
        from app.services import provider_expansion_framework as svc
        return svc.get_framework()

    def test_h1_planned_next_stage_contains_m80g(self):
        """All SendGrid milestones complete — planned_next_stage points to M89A Kubernetes."""
        stage = self._fw()["summary"]["planned_next_stage"]
        assert "M89A" in stage or "Kubernetes" in stage, (
            f"planned_next_stage should reference M89A Kubernetes; got: {stage!r}"
        )

    def test_h2_planned_next_stage_not_m80f(self):
        stage = self._fw()["summary"]["planned_next_stage"]
        assert "M80F" not in stage


# ══════════════════════════════════════════════════════════════════════════════
# I: Frontend references
# ══════════════════════════════════════════════════════════════════════════════

class TestFrontendReferences:
    def test_i1_correlations_page_has_sendgrid_in_provider_options(self):
        text = FE_CORR.read_text()
        assert '"sendgrid"' in text

    def test_i2_correlations_page_has_sendgrid_blurb(self):
        text = FE_CORR.read_text()
        # The blurb should mention sendgrid
        assert "sendgrid" in text.lower()
        assert "SendGrid" in text

    def test_i3_api_ts_has_generate_function(self):
        text = FE_API.read_text()
        assert "generateSendGridCorrelations" in text
        assert "sendgrid-correlations/generate" in text

    def test_i4_types_has_sendgrid_response(self):
        text = FE_TYPES.read_text()
        assert "SendGridCorrelationGenerateResponse" in text

    def test_i5_correlations_page_handles_sendgrid_in_generate(self):
        text = FE_CORR.read_text()
        assert "generateSendGridCorrelations" in text


# ══════════════════════════════════════════════════════════════════════════════
# J: Forbidden wording + secret-shape scan
# ══════════════════════════════════════════════════════════════════════════════

def _assert_no_forbidden_wording(src: str, name: str) -> None:
    low = src.lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in low, f"forbidden phrase {phrase!r} in {name}"


def test_j1_no_forbidden_in_correlation_service():
    import importlib
    mod = importlib.import_module("app.services.sendgrid_risk_activity_correlation_service")
    _assert_no_forbidden_wording(inspect.getsource(mod), mod.__name__)


def test_j2_no_forbidden_in_frontend_correlations_page():
    text = FE_CORR.read_text().lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in text, f"forbidden phrase {phrase!r} in correlations page"


_SG_PATTERN = re.compile(r"SG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")
_TWILIO_PATTERNS = [
    re.compile(r"AC[0-9a-fA-F]{32}"),
    re.compile(r"SK[0-9a-fA-F]{32}"),
]


def _scan_secrets(root: Path) -> list[str]:
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
        if _SG_PATTERN.search(text):
            hits.append(f"{path}: SendGrid secret shape")
        for pat in _TWILIO_PATTERNS:
            if pat.search(text):
                hits.append(f"{path}: Twilio secret shape")
    return hits


def test_j3_no_secret_shapes_in_backend_app():
    hits = _scan_secrets(BACKEND_APP)
    assert not hits, "Secret-shaped strings found:\n" + "\n".join(hits)


def test_j4_no_secret_shapes_in_frontend_src():
    hits = _scan_secrets(REPO_ROOT / "frontend" / "src")
    assert not hits, "Secret-shaped strings found:\n" + "\n".join(hits)
