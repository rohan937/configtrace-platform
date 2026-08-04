"""Dodo webhook signature verification tests (Dodo Payments message 1).

Verifies the Standard Webhooks scheme Dodo documents itself as following:
signed_content = f"{webhook-id}.{webhook-timestamp}.{raw_body}",
HMAC-SHA256, base64-encoded, secret prefixed "whsec_" and base64-decoded
before use, header value "v1,<sig>" (space-delimited for rotation).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import time

import pytest

from app.billing.dodo_webhooks import DodoSignatureError, verify_dodo_signature

_SECRET = "whsec_" + base64.b64encode(b"a-test-signing-secret-32-bytes!!").decode()


def _sign(webhook_id: str, timestamp: str, body: bytes, secret: str = _SECRET) -> str:
    raw = secret[len("whsec_"):]
    key = base64.b64decode(raw)
    signed_content = f"{webhook_id}.{timestamp}.{body.decode()}"
    digest = hmac.new(key, signed_content.encode(), hashlib.sha256).digest()
    return "v1," + base64.b64encode(digest).decode()


def _headers(webhook_id="msg_test1", timestamp=None, signature=None, body=b'{"type":"subscription.active"}'):
    ts = timestamp or str(int(time.time()))
    sig = signature if signature is not None else _sign(webhook_id, ts, body)
    return {"webhook-id": webhook_id, "webhook-timestamp": ts, "webhook-signature": sig}


class TestValidSignature:
    def test_valid_signature_returns_parsed_event(self):
        body = b'{"type":"subscription.active","data":{}}'
        headers = _headers(body=body)
        event = verify_dodo_signature(body, headers, _SECRET)
        assert event["type"] == "subscription.active"


class TestInvalidHmac:
    def test_wrong_signature_rejected(self):
        body = b'{"type":"subscription.active"}'
        headers = _headers(body=body, signature="v1,bm90dGhlcmlnaHRzaWc=")
        with pytest.raises(DodoSignatureError):
            verify_dodo_signature(body, headers, _SECRET)


class TestTamperedBody:
    def test_modified_body_after_signing_rejected(self):
        original = b'{"type":"subscription.active"}'
        headers = _headers(body=original)
        tampered = b'{"type":"subscription.active","extra":"injected"}'
        with pytest.raises(DodoSignatureError):
            verify_dodo_signature(tampered, headers, _SECRET)


class TestWrongSecret:
    def test_wrong_secret_rejected(self):
        body = b'{"type":"subscription.active"}'
        headers = _headers(body=body)
        other_secret = "whsec_" + base64.b64encode(b"a-different-secret-of-32-bytes!!").decode()
        with pytest.raises(DodoSignatureError):
            verify_dodo_signature(body, headers, other_secret)


class TestMissingHeaders:
    def test_missing_webhook_id_rejected(self):
        body = b"{}"
        headers = _headers(body=body)
        del headers["webhook-id"]
        with pytest.raises(DodoSignatureError):
            verify_dodo_signature(body, headers, _SECRET)

    def test_missing_webhook_timestamp_rejected(self):
        body = b"{}"
        headers = _headers(body=body)
        del headers["webhook-timestamp"]
        with pytest.raises(DodoSignatureError):
            verify_dodo_signature(body, headers, _SECRET)

    def test_missing_webhook_signature_rejected(self):
        body = b"{}"
        headers = _headers(body=body)
        del headers["webhook-signature"]
        with pytest.raises(DodoSignatureError):
            verify_dodo_signature(body, headers, _SECRET)


class TestStaleTimestamp:
    def test_timestamp_too_old_rejected(self):
        body = b'{"type":"subscription.active"}'
        old_ts = str(int(time.time()) - 3600)
        headers = _headers(body=body, timestamp=old_ts)
        with pytest.raises(DodoSignatureError):
            verify_dodo_signature(body, headers, _SECRET)

    def test_timestamp_too_far_in_future_rejected(self):
        body = b'{"type":"subscription.active"}'
        future_ts = str(int(time.time()) + 3600)
        headers = _headers(body=body, timestamp=future_ts)
        with pytest.raises(DodoSignatureError):
            verify_dodo_signature(body, headers, _SECRET)

    def test_custom_tolerance_respected(self):
        body = b'{"type":"subscription.active"}'
        ts = str(int(time.time()) - 250)
        headers = _headers(body=body, timestamp=ts)
        # Default tolerance (300s) accepts it...
        verify_dodo_signature(body, headers, _SECRET)
        # ...a narrower tolerance rejects the same delivery.
        with pytest.raises(DodoSignatureError):
            verify_dodo_signature(body, headers, _SECRET, tolerance_seconds=60)

    def test_non_integer_timestamp_rejected(self):
        body = b"{}"
        headers = _headers(body=body, timestamp="not-a-number")
        headers["webhook-signature"] = "v1,irrelevant"
        with pytest.raises(DodoSignatureError):
            verify_dodo_signature(body, headers, _SECRET)


class TestSecretRotation:
    def test_multiple_signatures_accepted_if_any_matches(self):
        body = b'{"type":"subscription.active"}'
        ts = str(int(time.time()))
        correct_sig = _sign("msg_1", ts, body)
        wrong_sig = "v1,d3JvbmdzaWduYXR1cmU="
        headers = {"webhook-id": "msg_1", "webhook-timestamp": ts, "webhook-signature": f"{wrong_sig} {correct_sig}"}
        event = verify_dodo_signature(body, headers, _SECRET)
        assert event["type"] == "subscription.active"

    def test_multiple_signatures_rejected_if_none_matches(self):
        body = b'{"type":"subscription.active"}'
        ts = str(int(time.time()))
        headers = {
            "webhook-id": "msg_1", "webhook-timestamp": ts,
            "webhook-signature": "v1,d3Jvbmcx v1,d3Jvbmcy",
        }
        with pytest.raises(DodoSignatureError):
            verify_dodo_signature(body, headers, _SECRET)


class TestExactRawBodyPreservation:
    def test_whitespace_difference_breaks_signature(self):
        original = b'{"type": "subscription.active"}'
        reserialized = b'{"type":"subscription.active"}'
        headers = _headers(body=original)
        with pytest.raises(DodoSignatureError):
            verify_dodo_signature(reserialized, headers, _SECRET)

    def test_exact_original_bytes_verify(self):
        body = b'{"type":"subscription.active","data":{"foo":"bar"}}'
        headers = _headers(body=body)
        verify_dodo_signature(body, headers, _SECRET)  # must not raise


class TestNoSecretOrBodyLeakedInErrors:
    def test_signature_error_never_contains_secret(self):
        body = b'{"type":"subscription.active"}'
        headers = _headers(body=body, signature="v1,d3Jvbmc=")
        try:
            verify_dodo_signature(body, headers, _SECRET)
            assert False, "expected DodoSignatureError"
        except DodoSignatureError as exc:
            assert _SECRET not in str(exc)
            assert _SECRET[len("whsec_"):] not in str(exc)

    def test_signature_error_never_contains_body_content(self):
        body = b'{"type":"subscription.active","data":{"sensitive":"value123"}}'
        headers = _headers(body=body, signature="v1,d3Jvbmc=")
        try:
            verify_dodo_signature(body, headers, _SECRET)
            assert False, "expected DodoSignatureError"
        except DodoSignatureError as exc:
            assert "value123" not in str(exc)


class TestEmptySecretRejected:
    def test_empty_secret_rejected(self):
        body = b"{}"
        headers = _headers(body=body)
        with pytest.raises(DodoSignatureError):
            verify_dodo_signature(body, headers, "")
