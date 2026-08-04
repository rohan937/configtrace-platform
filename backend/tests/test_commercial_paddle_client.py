"""Paddle API client tests (Commercial Infrastructure message 2).

All HTTP is mocked via ``httpx.MockTransport`` — zero real network calls.
"""

from __future__ import annotations

import httpx
import pytest

from app.billing.paddle_client import (
    PaddleAPIClient,
    PaddleAuthenticationError,
    PaddleClientConfig,
    PaddleNetworkError,
    PaddleRateLimitedError,
    PaddleRequest,
    PaddleServerError,
    PaddleValidationError,
)


def _client(handler, environment="sandbox", max_retries=3) -> PaddleAPIClient:
    transport = httpx.MockTransport(handler)
    config = PaddleClientConfig(environment=environment, api_key="test_key_not_real", max_retries=max_retries)
    return PaddleAPIClient(config, transport=transport)


class TestCorrectUrlsPerEnvironment:
    def test_sandbox_base_url(self):
        seen = {}

        def handler(request):
            seen["url"] = str(request.url)
            return httpx.Response(200, json={"data": {}})

        client = _client(handler, environment="sandbox")
        client.get_subscription("sub_1")
        assert seen["url"].startswith("https://sandbox-api.paddle.com")

    def test_production_base_url(self):
        seen = {}

        def handler(request):
            seen["url"] = str(request.url)
            return httpx.Response(200, json={"data": {}})

        client = _client(handler, environment="production")
        client.get_subscription("sub_1")
        assert seen["url"].startswith("https://api.paddle.com")

    def test_unknown_environment_rejected(self):
        with pytest.raises(ValueError):
            PaddleClientConfig(environment="staging", api_key="x").base_url


class TestAuthorizationHeader:
    def test_bearer_token_sent(self):
        seen = {}

        def handler(request):
            seen["auth"] = request.headers.get("authorization")
            return httpx.Response(200, json={"data": {}})

        client = _client(handler)
        client.get_subscription("sub_1")
        assert seen["auth"] == "Bearer test_key_not_real"


class TestSanitizedErrors:
    def test_401_raises_authentication_error_without_key_in_message(self):
        def handler(request):
            return httpx.Response(401, json={"error": {"code": "invalid_token"}})

        client = _client(handler)
        with pytest.raises(PaddleAuthenticationError) as exc_info:
            client.get_subscription("sub_1")
        assert "test_key_not_real" not in str(exc_info.value)

    def test_422_raises_validation_error(self):
        def handler(request):
            return httpx.Response(422, json={"error": {"code": "bad_request"}})

        client = _client(handler)
        with pytest.raises(PaddleValidationError):
            client.get_subscription("sub_1")

    def test_error_carries_sanitized_request_id(self):
        def handler(request):
            return httpx.Response(401, headers={"paddle-request-id": "req_abc"}, json={"error": {"code": "x"}})

        client = _client(handler)
        with pytest.raises(PaddleAuthenticationError) as exc_info:
            client.get_subscription("sub_1")
        assert exc_info.value.request_id == "req_abc"

    def test_error_dict_never_contains_full_body(self):
        def handler(request):
            return httpx.Response(422, json={"error": {"code": "x", "detail": "some huge internal detail"}})

        client = _client(handler)
        with pytest.raises(PaddleValidationError) as exc_info:
            client.get_subscription("sub_1")
        assert "some huge internal detail" not in str(exc_info.value.as_dict())


class TestTimeouts:
    def test_timeout_raises_network_error(self):
        def handler(request):
            raise httpx.TimeoutException("timed out")

        client = _client(handler, max_retries=1)
        with pytest.raises(PaddleNetworkError):
            client.get_subscription("sub_1")


class TestRetries:
    def test_500_retried_then_succeeds(self):
        calls = {"n": 0}

        def handler(request):
            calls["n"] += 1
            if calls["n"] < 2:
                return httpx.Response(500)
            return httpx.Response(200, json={"data": {"id": "sub_1"}})

        client = _client(handler, max_retries=3)
        result = client.get_subscription("sub_1")
        assert result["data"]["id"] == "sub_1"
        assert calls["n"] == 2

    def test_401_never_retried(self):
        calls = {"n": 0}

        def handler(request):
            calls["n"] += 1
            return httpx.Response(401)

        client = _client(handler, max_retries=3)
        with pytest.raises(PaddleAuthenticationError):
            client.get_subscription("sub_1")
        assert calls["n"] == 1

    def test_429_retried_with_retry_after(self):
        calls = {"n": 0}

        def handler(request):
            calls["n"] += 1
            if calls["n"] < 2:
                return httpx.Response(429, headers={"Retry-After": "0"})
            return httpx.Response(200, json={"data": {}})

        client = _client(handler, max_retries=3)
        client.get_subscription("sub_1")
        assert calls["n"] == 2

    def test_non_idempotent_request_never_retried(self):
        calls = {"n": 0}

        def handler(request):
            calls["n"] += 1
            return httpx.Response(500)

        client = _client(handler, max_retries=3)
        with pytest.raises(PaddleServerError):
            client.create_checkout(items=[{"price_id": "pri_1", "quantity": 1}], custom_data={})
        assert calls["n"] == 1


class TestJSONEncodingDecoding:
    def test_request_body_is_json_encoded(self):
        seen = {}

        def handler(request):
            seen["content_type"] = request.headers.get("content-type")
            return httpx.Response(200, json={"data": {}})

        client = _client(handler)
        client.create_checkout(items=[{"price_id": "pri_1", "quantity": 1}], custom_data={"a": 1})
        assert seen["content_type"] == "application/json"

    def test_empty_response_body_returns_empty_dict(self):
        def handler(request):
            return httpx.Response(204)

        client = _client(handler)
        result = client.cancel_subscription("sub_1", effective_from="next_billing_period")
        assert result == {}


class TestCorrelationId:
    def test_correlation_id_sent_as_header_not_secret(self):
        seen = {}

        def handler(request):
            seen["header"] = request.headers.get("x-configtrace-correlation-id")
            return httpx.Response(200, json={"data": {}})

        client = _client(handler)
        client.request(PaddleRequest(method="GET", path="/subscriptions/sub_1", correlation_id="corr-123"))
        assert seen["header"] == "corr-123"
