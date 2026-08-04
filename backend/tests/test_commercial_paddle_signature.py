"""Paddle webhook signature verification tests (Commercial Infrastructure message 2)."""

from __future__ import annotations

import hashlib
import hmac
import json
import time

import pytest

from app.billing.paddle_webhooks import PaddleSignatureError, verify_paddle_signature

_SECRET = "test_webhook_secret_not_real"


def _sign(body: bytes, ts: int | None = None, secret: str = _SECRET) -> str:
    ts = ts if ts is not None else int(time.time())
    signed_payload = f"{ts}:{body.decode()}"
    sig = hmac.new(secret.encode(), signed_payload.encode(), hashlib.sha256).hexdigest()
    return f"ts={ts};h1={sig}"


class TestValidSignature:
    def test_valid_signature_returns_parsed_event(self):
        body = json.dumps({"event_id": "evt_1", "event_type": "customer.updated"}).encode()
        header = _sign(body)
        event = verify_paddle_signature(body, header, _SECRET)
        assert event["event_id"] == "evt_1"


class TestInvalidHmac:
    def test_wrong_hmac_rejected(self):
        body = json.dumps({"event_id": "evt_1"}).encode()
        ts = int(time.time())
        header = f"ts={ts};h1=deadbeef" * 4
        with pytest.raises(PaddleSignatureError):
            verify_paddle_signature(body, header, _SECRET)


class TestModifiedBody:
    def test_modified_body_after_signing_rejected(self):
        body = json.dumps({"event_id": "evt_1"}).encode()
        header = _sign(body)
        modified_body = json.dumps({"event_id": "evt_1_modified"}).encode()
        with pytest.raises(PaddleSignatureError):
            verify_paddle_signature(modified_body, header, _SECRET)


class TestWrongSecret:
    def test_wrong_secret_rejected(self):
        body = json.dumps({"event_id": "evt_1"}).encode()
        header = _sign(body, secret="a_different_secret")
        with pytest.raises(PaddleSignatureError):
            verify_paddle_signature(body, header, _SECRET)


class TestMissingHeader:
    def test_empty_header_rejected(self):
        with pytest.raises(PaddleSignatureError):
            verify_paddle_signature(b"{}", "", _SECRET)


class TestMalformedHeader:
    def test_header_without_ts_rejected(self):
        with pytest.raises(PaddleSignatureError):
            verify_paddle_signature(b"{}", "h1=abcdef", _SECRET)

    def test_header_without_h1_rejected(self):
        with pytest.raises(PaddleSignatureError):
            verify_paddle_signature(b"{}", f"ts={int(time.time())}", _SECRET)

    def test_non_integer_timestamp_rejected(self):
        with pytest.raises(PaddleSignatureError):
            verify_paddle_signature(b"{}", "ts=notanumber;h1=abcdef", _SECRET)

    def test_completely_malformed_header_rejected(self):
        with pytest.raises(PaddleSignatureError):
            verify_paddle_signature(b"{}", "garbage-not-a-real-header", _SECRET)


class TestStaleTimestamp:
    def test_timestamp_too_old_rejected(self):
        body = json.dumps({"event_id": "evt_1"}).encode()
        old_ts = int(time.time()) - 600
        header = _sign(body, ts=old_ts)
        with pytest.raises(PaddleSignatureError):
            verify_paddle_signature(body, header, _SECRET)

    def test_timestamp_too_far_in_future_rejected(self):
        body = json.dumps({"event_id": "evt_1"}).encode()
        future_ts = int(time.time()) + 600
        header = _sign(body, ts=future_ts)
        with pytest.raises(PaddleSignatureError):
            verify_paddle_signature(body, header, _SECRET)

    def test_custom_tolerance_respected(self):
        body = json.dumps({"event_id": "evt_1"}).encode()
        ts = int(time.time()) - 200
        header = _sign(body, ts=ts)
        # Default tolerance (300s) accepts it...
        verify_paddle_signature(body, header, _SECRET)
        # ...but a tighter tolerance rejects it.
        with pytest.raises(PaddleSignatureError):
            verify_paddle_signature(body, header, _SECRET, tolerance_seconds=60)


class TestMultipleSignatures:
    def test_multiple_h1_values_accepted_if_any_matches(self):
        body = json.dumps({"event_id": "evt_1"}).encode()
        ts = int(time.time())
        real_sig = _sign(body, ts=ts).split("h1=")[1]
        header = f"ts={ts};h1=deadbeefdeadbeef;h1={real_sig}"
        event = verify_paddle_signature(body, header, _SECRET)
        assert event["event_id"] == "evt_1"

    def test_multiple_h1_values_rejected_if_none_matches(self):
        body = json.dumps({"event_id": "evt_1"}).encode()
        ts = int(time.time())
        header = f"ts={ts};h1=deadbeef1;h1=deadbeef2"
        with pytest.raises(PaddleSignatureError):
            verify_paddle_signature(body, header, _SECRET)


class TestExactRawBodyPreservation:
    def test_whitespace_difference_breaks_signature(self):
        """Proves verification is byte-exact — a re-serialized (even
        semantically identical) JSON body must NOT verify against a
        signature computed over the original bytes."""
        original_body = b'{"event_id":"evt_1","event_type":"customer.updated"}'
        header = _sign(original_body)
        # Re-serialize with different whitespace — semantically identical,
        # byte-different.
        reserialized = json.dumps(json.loads(original_body)).encode()
        assert reserialized != original_body
        with pytest.raises(PaddleSignatureError):
            verify_paddle_signature(reserialized, header, _SECRET)

    def test_exact_original_bytes_verify(self):
        original_body = b'{"event_id":"evt_1","event_type":"customer.updated"}'
        header = _sign(original_body)
        event = verify_paddle_signature(original_body, header, _SECRET)
        assert event["event_id"] == "evt_1"


class TestNoBodyLogging:
    def test_signature_error_message_never_contains_body_content(self):
        body = json.dumps({"event_id": "evt_1", "secret_looking_field": "should-not-leak"}).encode()
        header = "ts=123;h1=deadbeef"
        try:
            verify_paddle_signature(body, header, _SECRET)
            assert False, "expected PaddleSignatureError"
        except PaddleSignatureError as exc:
            assert "should-not-leak" not in str(exc)

    def test_signature_error_never_contains_secret(self):
        body = json.dumps({"event_id": "evt_1"}).encode()
        header = "ts=123;h1=deadbeef"
        try:
            verify_paddle_signature(body, header, _SECRET)
            assert False, "expected PaddleSignatureError"
        except PaddleSignatureError as exc:
            assert _SECRET not in str(exc)


class TestMissingWebhookSecret:
    def test_empty_secret_rejected(self):
        with pytest.raises(PaddleSignatureError):
            verify_paddle_signature(b"{}", "ts=123;h1=abc", "")
