"""Twilio webhook URL scheme detection — end-to-end tests.

Covers the scheme-only extraction feature added to the Twilio connector,
diff tracking, Change classification, and Security Findings:

  * ``TwilioConnector._url_scheme`` never returns or leaks anything beyond
    a bare "http"/"https" string.
  * The connector's phone-number and Messaging Service normalizers populate
    the new scheme fields correctly from https/http/missing/invalid URLs.
  * ``_TWILIO_TRACKED_FIELDS_BY_TYPE`` tracks the new scheme fields so
    ``compute_diff`` detects a scheme transition.
  * ``classify_twilio_change`` classifies scheme transitions with the
    correct severity and safe wording.
  * ``security_rules.twilio.evaluate`` fires ``twilio_webhook_uses_http``
    only on an explicit "http" scheme, never on unknown/https.

Privacy contract under test: only the scheme ("http"/"https"/None) is ever
read from a webhook URL. Host, path, query string, and the full URL string
are never stored, logged, or returned anywhere in this pipeline.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from app.connectors.twilio import TwilioConnector, _url_scheme


# ── _url_scheme() — the extractor itself ──────────────────────────────────────


@pytest.mark.parametrize(
    "raw_url,expected_scheme",
    [
        ("https://example.com/path?token=x", "https"),
        ("http://example.com/path", "http"),
        ("HTTPS://Example.Com/Path", "https"),  # case-insensitive
        ("HTTP://example.com", "http"),
        ("", None),
        (None, None),
        ("not a url", None),
        ("ftp://example.com/file", None),  # non-http(s) scheme -> unknown
        (123, None),  # non-string input
        ({"not": "a string"}, None),
    ],
)
def test_url_scheme_extraction(raw_url, expected_scheme):
    assert _url_scheme(raw_url) == expected_scheme


def test_url_scheme_never_returns_the_full_url_or_host():
    """The extractor's return value must never contain anything beyond the
    bare scheme word — no host, path, query string, or token."""
    result = _url_scheme("https://attacker.example.com/webhook?token=SECRET123")
    assert result == "https"
    assert "attacker" not in result
    assert "SECRET123" not in result
    assert "example.com" not in result
    assert len(result) <= len("https")


# ── Connector normalization: phone number ─────────────────────────────────────


def _raw_phone_number(sms_url="https://example.com/sms", voice_url="https://example.com/voice",
                       status_callback="https://example.com/status") -> dict:
    return {
        "sid": "PNabcdef1234567890abcdef1234567890",
        "friendly_name": "Test Number",
        "phone_number": "+15105551234",
        "iso_country": "US",
        "capabilities": {"voice": True, "sms": True, "mms": False, "fax": False},
        "sms_url": sms_url,
        "voice_url": voice_url,
        "status_callback": status_callback,
        "address_requirements": "none",
        "emergency_status": "Active",
    }


class TestPhoneNumberSchemeNormalization:
    def test_https_urls_normalize_to_https_scheme(self):
        record = TwilioConnector._normalize_incoming_phone_number(_raw_phone_number())
        assert record["sms_url_scheme"] == "https"
        assert record["voice_url_scheme"] == "https"
        assert record["status_callback_scheme"] == "https"
        # Boolean presence fields are unaffected.
        assert record["sms_url_configured"] is True
        assert record["voice_url_configured"] is True
        assert record["status_callback_configured"] is True

    def test_http_urls_normalize_to_http_scheme(self):
        raw = _raw_phone_number(
            sms_url="http://example.com/sms",
            voice_url="http://example.com/voice",
            status_callback="http://example.com/status",
        )
        record = TwilioConnector._normalize_incoming_phone_number(raw)
        assert record["sms_url_scheme"] == "http"
        assert record["voice_url_scheme"] == "http"
        assert record["status_callback_scheme"] == "http"

    def test_missing_urls_normalize_to_none_scheme(self):
        raw = _raw_phone_number(sms_url="", voice_url="", status_callback="")
        record = TwilioConnector._normalize_incoming_phone_number(raw)
        assert record["sms_url_scheme"] is None
        assert record["voice_url_scheme"] is None
        assert record["status_callback_scheme"] is None
        assert record["sms_url_configured"] is False

    def test_no_full_url_host_or_path_in_normalized_record(self):
        """The normalized record must contain neither the raw URL string nor
        any substring of its host/path — only the bare scheme word."""
        raw = _raw_phone_number(
            sms_url="https://attacker.example.com/webhook?token=SECRET123"
        )
        record = TwilioConnector._normalize_incoming_phone_number(raw)
        blob = str(record)
        assert "attacker" not in blob
        assert "example.com" not in blob
        assert "SECRET123" not in blob
        assert "webhook" not in blob
        assert record["sms_url_scheme"] == "https"


# ── Connector normalization: messaging service ────────────────────────────────


def _raw_messaging_service(
    inbound_request_url="https://example.com/inbound",
    fallback_url="https://example.com/fallback",
    status_callback_url="https://example.com/status",
) -> dict:
    return {
        "sid": "MGabcdef1234567890abcdef1234567890",
        "friendly_name": "Test Messaging Service",
        "inbound_request_url": inbound_request_url,
        "fallback_url": fallback_url,
        "status_callback_url": status_callback_url,
        "smart_encoding": True,
        "validity_period": 14400,
        "area_code_geomatch": True,
        "sticky_sender": True,
        "mms_converter": True,
        "use_inbound_webhook_on_number": False,
        "numbers_count": 3,
    }


class TestMessagingServiceSchemeNormalization:
    def test_https_urls_normalize_to_https_scheme(self):
        record = TwilioConnector._normalize_messaging_service(_raw_messaging_service())
        assert record["inbound_request_url_scheme"] == "https"
        assert record["fallback_url_scheme"] == "https"
        assert record["status_callback_url_scheme"] == "https"

    def test_http_urls_normalize_to_http_scheme(self):
        raw = _raw_messaging_service(
            inbound_request_url="http://example.com/inbound",
            fallback_url="http://example.com/fallback",
            status_callback_url="http://example.com/status",
        )
        record = TwilioConnector._normalize_messaging_service(raw)
        assert record["inbound_request_url_scheme"] == "http"
        assert record["fallback_url_scheme"] == "http"
        assert record["status_callback_url_scheme"] == "http"

    def test_missing_urls_normalize_to_none_scheme(self):
        raw = _raw_messaging_service(
            inbound_request_url="", fallback_url="", status_callback_url=""
        )
        record = TwilioConnector._normalize_messaging_service(raw)
        assert record["inbound_request_url_scheme"] is None
        assert record["fallback_url_scheme"] is None
        assert record["status_callback_url_scheme"] is None

    def test_no_full_url_host_or_path_in_normalized_record(self):
        raw = _raw_messaging_service(
            inbound_request_url="https://internal.example.org/webhook-path?key=TOPSECRET"
        )
        record = TwilioConnector._normalize_messaging_service(raw)
        blob = str(record)
        assert "internal" not in blob
        assert "example.org" not in blob
        assert "TOPSECRET" not in blob
        assert "webhook-path" not in blob
        assert record["inbound_request_url_scheme"] == "https"


# ── Diff tracking: compute_diff detects scheme transitions ───────────────────


def _mock_snapshot(state: list[dict]) -> MagicMock:
    from app.models.snapshot import Snapshot

    snap = MagicMock(spec=Snapshot)
    snap.state = state
    return snap


def _phone_record(sms_scheme) -> dict:
    return {
        "record_id": "PN123",
        "record_type": "twilio_incoming_phone_number",
        "provider_resource_id": "incoming_phone_numbers/PN123",
        "phone_number_sid": "PN123",
        "friendly_name": "Main line",
        "phone_number_last4": "1234",
        "iso_country": "US",
        "capability_voice": True,
        "capability_sms": True,
        "capability_mms": False,
        "capability_fax": False,
        "sms_url_configured": True,
        "voice_url_configured": True,
        "status_callback_configured": False,
        "sms_url_scheme": sms_scheme,
        "voice_url_scheme": "https",
        "status_callback_scheme": None,
        "address_requirements": "none",
        "emergency_status": "Active",
    }


class TestSchemeDiffTracking:
    def test_diff_tracked_fields_include_scheme_fields(self):
        from app.services.diff_service import _TWILIO_TRACKED_FIELDS_BY_TYPE

        phone_fields = _TWILIO_TRACKED_FIELDS_BY_TYPE["twilio_incoming_phone_number"]
        assert "sms_url_scheme" in phone_fields
        assert "voice_url_scheme" in phone_fields
        assert "status_callback_scheme" in phone_fields

        msg_fields = _TWILIO_TRACKED_FIELDS_BY_TYPE["twilio_messaging_service"]
        assert "inbound_request_url_scheme" in msg_fields
        assert "fallback_url_scheme" in msg_fields
        assert "status_callback_url_scheme" in msg_fields

    def test_https_to_http_creates_a_change(self):
        from app.services.diff_service import compute_diff

        prev = _mock_snapshot([_phone_record("https")])
        new = _mock_snapshot([_phone_record("http")])

        changes = compute_diff(prev, new)
        scheme_changes = [c for c in changes if c["field_path"] == "sms_url_scheme"]

        assert len(scheme_changes) == 1
        assert scheme_changes[0]["change_type"] == "modified"
        assert scheme_changes[0]["prev_value"] == "https"
        assert scheme_changes[0]["new_value"] == "http"

    def test_http_to_https_creates_a_change(self):
        from app.services.diff_service import compute_diff

        prev = _mock_snapshot([_phone_record("http")])
        new = _mock_snapshot([_phone_record("https")])

        changes = compute_diff(prev, new)
        scheme_changes = [c for c in changes if c["field_path"] == "sms_url_scheme"]

        assert len(scheme_changes) == 1
        assert scheme_changes[0]["prev_value"] == "http"
        assert scheme_changes[0]["new_value"] == "https"

    def test_same_scheme_different_host_produces_no_change(self):
        """Only the scheme is normalized/tracked — a host or path change on an
        otherwise-identical scheme must NOT be visible to compute_diff, since
        the connector never even stores host/path in the first place."""
        from app.services.diff_service import compute_diff

        # Both records have identical normalized fields (the connector would
        # produce the same output for "https://old-host.example.com/webhook"
        # and "https://new-host.example.com/webhook" — both are scheme "https").
        record = _phone_record("https")
        prev = _mock_snapshot([dict(record)])
        new = _mock_snapshot([dict(record)])

        assert compute_diff(prev, new) == []


# ── Change classification: classify_twilio_change ────────────────────────────


class TestSchemeChangeClassification:
    def _change(self, *, field_path, prev_value, new_value, record_type="twilio_incoming_phone_number"):
        return {
            "change_type": "modified",
            "field_path": field_path,
            "prev_value": prev_value,
            "new_value": new_value,
            "provider_metadata": {"record_type": record_type, "record_name": "PN123"},
        }

    def test_https_to_http_is_high(self):
        from app.services.risk_rules.twilio import classify_twilio_change

        change = self._change(field_path="sms_url_scheme", prev_value="https", new_value="http")
        level, reason = classify_twilio_change(change)
        assert level == "high"
        assert "http" in reason.lower()
        assert "weakened" in reason.lower()

    def test_unknown_to_http_is_medium_not_high(self):
        """First observation of an http scheme (no prior known value) is a
        weaker signal than a confirmed https-to-http regression."""
        from app.services.risk_rules.twilio import classify_twilio_change

        change = self._change(field_path="sms_url_scheme", prev_value=None, new_value="http")
        level, _ = classify_twilio_change(change)
        assert level == "medium"

    def test_http_to_https_is_medium_improvement(self):
        from app.services.risk_rules.twilio import classify_twilio_change

        change = self._change(field_path="voice_url_scheme", prev_value="http", new_value="https")
        level, reason = classify_twilio_change(change)
        assert level == "medium"
        assert "restored" in reason.lower() or "https" in reason.lower()

    def test_unknown_to_https_is_low(self):
        from app.services.risk_rules.twilio import classify_twilio_change

        change = self._change(field_path="status_callback_scheme", prev_value=None, new_value="https")
        level, _ = classify_twilio_change(change)
        assert level == "low"

    def test_to_unknown_scheme_is_low_never_escalated(self):
        from app.services.risk_rules.twilio import classify_twilio_change

        change = self._change(field_path="sms_url_scheme", prev_value="https", new_value=None)
        level, _ = classify_twilio_change(change)
        assert level == "low"

    def test_messaging_service_inbound_https_to_http_is_high(self):
        from app.services.risk_rules.twilio import classify_twilio_change

        change = self._change(
            record_type="twilio_messaging_service",
            field_path="inbound_request_url_scheme",
            prev_value="https",
            new_value="http",
        )
        level, reason = classify_twilio_change(change)
        assert level == "high"
        assert "inbound" in reason.lower()

    def test_safe_wording_no_forbidden_phrases(self):
        from app.services.risk_rules.twilio import classify_twilio_change

        forbidden = (
            "breach",
            "attacker",
            "fraud",
            "message interception confirmed",
            "unauthorized access confirmed",
            "secret leaked",
            "data leaked",
        )
        for field_path, prev, new in (
            ("sms_url_scheme", "https", "http"),
            ("voice_url_scheme", None, "http"),
            ("status_callback_scheme", "http", "https"),
        ):
            change = self._change(field_path=field_path, prev_value=prev, new_value=new)
            _, reason = classify_twilio_change(change)
            lowered = reason.lower()
            for word in forbidden:
                assert word not in lowered, f"Forbidden wording {word!r} in: {reason!r}"


# ── Security Findings: twilio_webhook_uses_http ──────────────────────────────


class TestWebhookUsesHttpFinding:
    def test_fires_on_explicit_http_phone_number(self):
        from app.services.security_rules.twilio import evaluate

        record = {
            "record_type": "twilio_incoming_phone_number",
            "record_id": "PN999",
            "phone_number_sid": "PN999",
            "friendly_name": "Risky Number",
            "sms_url_scheme": "http",
        }
        findings = evaluate(record)
        assert any(f.rule_key == "twilio_webhook_uses_http" for f in findings)
        finding = next(f for f in findings if f.rule_key == "twilio_webhook_uses_http")
        assert finding.severity == "high"

    def test_does_not_fire_on_https_phone_number(self):
        from app.services.security_rules.twilio import evaluate

        record = {
            "record_type": "twilio_incoming_phone_number",
            "record_id": "PN999",
            "sms_url_scheme": "https",
            "voice_url_scheme": "https",
            "status_callback_scheme": "https",
        }
        findings = evaluate(record)
        assert not any(f.rule_key == "twilio_webhook_uses_http" for f in findings)

    def test_does_not_fire_on_unknown_missing_scheme(self):
        from app.services.security_rules.twilio import evaluate

        record = {
            "record_type": "twilio_incoming_phone_number",
            "record_id": "PN999",
            # No scheme fields present at all — unknown, not risky.
        }
        findings = evaluate(record)
        assert not any(f.rule_key == "twilio_webhook_uses_http" for f in findings)

    def test_fires_on_explicit_http_messaging_service(self):
        from app.services.security_rules.twilio import evaluate

        record = {
            "record_type": "twilio_messaging_service",
            "record_id": "MG999",
            "messaging_service_sid": "MG999",
            "friendly_name": "Risky Service",
            "inbound_request_url_scheme": "http",
        }
        findings = evaluate(record)
        assert any(f.rule_key == "twilio_webhook_uses_http" for f in findings)

    def test_does_not_fire_on_https_messaging_service(self):
        from app.services.security_rules.twilio import evaluate

        record = {
            "record_type": "twilio_messaging_service",
            "record_id": "MG999",
            "inbound_request_url_scheme": "https",
            "fallback_url_scheme": "https",
            "status_callback_url_scheme": "https",
        }
        findings = evaluate(record)
        assert not any(f.rule_key == "twilio_webhook_uses_http" for f in findings)

    def test_fires_once_per_http_field_not_once_per_record(self):
        """Two independently-risky webhook fields on the same phone number
        must produce two distinct findings (discriminated by field name)."""
        from app.services.security_rules.twilio import evaluate

        record = {
            "record_type": "twilio_incoming_phone_number",
            "record_id": "PN999",
            "sms_url_scheme": "http",
            "voice_url_scheme": "http",
        }
        findings = [f for f in evaluate(record) if f.rule_key == "twilio_webhook_uses_http"]
        assert len(findings) == 2
        assert len({f.finding_key for f in findings}) == 2

    def test_evidence_contains_no_host_path_or_full_url(self):
        from app.services.security_rules.twilio import evaluate

        record = {
            "record_type": "twilio_incoming_phone_number",
            "record_id": "PN999",
            "friendly_name": "Risky Number",
            "sms_url_scheme": "http",
        }
        findings = evaluate(record)
        finding = next(f for f in findings if f.rule_key == "twilio_webhook_uses_http")
        blob = str(finding.evidence)
        assert "http://" not in blob
        assert "https://" not in blob
        # Only the bare scheme word should appear as a value.
        assert finding.evidence.get("scheme") == "http"

    def test_finding_copy_has_no_forbidden_wording(self):
        from app.services.security_rules.twilio import evaluate

        forbidden = (
            "breach",
            "attacker",
            "fraud",
            "message interception confirmed",
            "unauthorized access confirmed",
            "secret leaked",
            "data leaked",
            "messages exposed",
        )
        record = {
            "record_type": "twilio_incoming_phone_number",
            "record_id": "PN999",
            "sms_url_scheme": "http",
        }
        findings = evaluate(record)
        finding = next(f for f in findings if f.rule_key == "twilio_webhook_uses_http")
        combined = (finding.title + " " + finding.description).lower()
        for word in forbidden:
            assert word not in combined, f"Forbidden wording {word!r} in finding copy"
