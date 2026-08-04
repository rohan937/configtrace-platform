"""Dodo API client tests (Dodo Payments message 1).

No live Dodo API call is made anywhere in this file — every request goes
through ``httpx.MockTransport``.
"""

from __future__ import annotations

import httpx
import pytest

from app.billing.dodo_client import (
    DodoAPIClient,
    DodoAuthenticationError,
    DodoClientConfig,
    DodoNetworkError,
    DodoRateLimitedError,
    DodoRequest,
    DodoServerError,
    DodoValidationError,
)


def _client(handler, *, environment="test", api_key="apikey_test_dummy", max_retries=3) -> DodoAPIClient:
    transport = httpx.MockTransport(handler)
    config = DodoClientConfig(environment=environment, api_key=api_key, max_retries=max_retries)
    return DodoAPIClient(config, transport=transport)


class TestCorrectUrlsPerEnvironment:
    def test_test_base_url(self):
        seen = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["url"] = str(request.url)
            return httpx.Response(200, json={})

        client = _client(handler, environment="test")
        client.get_customer("cus_1")
        assert seen["url"].startswith("https://test.dodopayments.com")

    def test_live_base_url(self):
        seen = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["url"] = str(request.url)
            return httpx.Response(200, json={})

        client = _client(handler, environment="live")
        client.get_customer("cus_1")
        assert seen["url"].startswith("https://live.dodopayments.com")

    def test_unknown_environment_rejected(self):
        client = _client(lambda r: httpx.Response(200), environment="sandbox")
        with pytest.raises(ValueError):
            client.get_customer("cus_1")


class TestAuthorizationHeader:
    def test_bearer_token_sent(self):
        seen = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["auth"] = request.headers.get("authorization")
            return httpx.Response(200, json={})

        client = _client(handler, api_key="apikey_test_secretvalue")
        client.get_customer("cus_1")
        assert seen["auth"] == "Bearer apikey_test_secretvalue"


class TestSanitizedErrors:
    def test_401_raises_authentication_error_without_key_in_message(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(401, json={"code": "unauthorized", "message": "nope"})

        client = _client(handler, api_key="apikey_test_supersecret")
        with pytest.raises(DodoAuthenticationError) as exc_info:
            client.get_customer("cus_1")
        assert "apikey_test_supersecret" not in str(exc_info.value)

    def test_422_raises_validation_error(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(422, json={"code": "invalid_request"})

        client = _client(handler)
        with pytest.raises(DodoValidationError):
            client.create_checkout_session(body={})

    def test_error_carries_sanitized_code_no_full_body(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(400, json={"code": "bad_thing", "message": "some sensitive detail"})

        client = _client(handler)
        with pytest.raises(DodoValidationError) as exc_info:
            client.get_customer("cus_1")
        err = exc_info.value
        assert err.error_code == "bad_thing"
        assert err.as_dict()["message"] != "some sensitive detail"


class TestTimeouts:
    def test_network_error_raises_dodo_network_error(self):
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("boom", request=request)

        client = _client(handler, max_retries=1)
        with pytest.raises(DodoNetworkError):
            client.get_customer("cus_1")


class TestRetries:
    def test_500_retried_then_succeeds(self):
        calls = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            if calls["n"] < 2:
                return httpx.Response(500, json={"code": "server_error"})
            return httpx.Response(200, json={"customer_id": "cus_1"})

        client = _client(handler, max_retries=3)
        result = client.get_customer("cus_1")
        assert result["customer_id"] == "cus_1"
        assert calls["n"] == 2

    def test_401_never_retried(self):
        calls = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            return httpx.Response(401, json={"code": "unauthorized"})

        client = _client(handler, max_retries=3)
        with pytest.raises(DodoAuthenticationError):
            client.get_customer("cus_1")
        assert calls["n"] == 1

    def test_429_retried_with_retry_after(self):
        calls = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            if calls["n"] < 2:
                return httpx.Response(429, headers={"Retry-After": "0"}, json={"code": "rate_limited"})
            return httpx.Response(200, json={})

        client = _client(handler, max_retries=3)
        client.get_customer("cus_1")
        assert calls["n"] == 2

    def test_non_idempotent_request_never_retried(self):
        calls = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            return httpx.Response(500, json={"code": "server_error"})

        client = _client(handler, max_retries=3)
        with pytest.raises(DodoServerError):
            client.create_checkout_session(body={"product_cart": []})
        assert calls["n"] == 1  # non-idempotent — never retried


class TestJSONEncodingDecoding:
    def test_request_body_is_json_encoded(self):
        seen = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["content_type"] = request.headers.get("content-type")
            return httpx.Response(200, json={"checkout_url": "https://test.checkout.dodopayments.com/x"})

        client = _client(handler)
        client.create_checkout_session(body={"product_cart": [{"product_id": "p", "quantity": 1}]})
        assert seen["content_type"] == "application/json"

    def test_empty_response_body_returns_empty_dict(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=b"")

        client = _client(handler)
        result = client.get_customer("cus_1")
        assert result == {}


class TestCorrelationId:
    def test_correlation_id_sent_as_header_not_secret(self):
        seen = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["header"] = request.headers.get("x-configtrace-correlation-id")
            return httpx.Response(200, json={})

        client = _client(handler)
        client.get_customer("cus_1", correlation_id="corr-123")
        assert seen["header"] == "corr-123"


class TestTypedConveniencePaths:
    """Verify each convenience method hits the exact documented path/verb."""

    def test_create_checkout_session_posts_to_checkouts(self):
        seen = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["method"] = request.method
            seen["path"] = request.url.path
            return httpx.Response(200, json={"session_id": "cks_1", "checkout_url": "https://x"})

        client = _client(handler)
        client.create_checkout_session(body={"product_cart": []})
        assert seen["method"] == "POST"
        assert seen["path"] == "/checkouts"

    def test_get_subscription_gets_subscriptions_id(self):
        seen = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["method"] = request.method
            seen["path"] = request.url.path
            return httpx.Response(200, json={"subscription_id": "sub_1"})

        client = _client(handler)
        client.get_subscription("sub_1")
        assert seen["method"] == "GET"
        assert seen["path"] == "/subscriptions/sub_1"

    def test_change_plan_posts_to_change_plan(self):
        seen = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["method"] = request.method
            seen["path"] = request.url.path
            return httpx.Response(200, json={})

        client = _client(handler)
        client.change_plan("sub_1", body={"product_id": "p", "quantity": 1, "proration_billing_mode": "prorated_immediately"})
        assert seen["method"] == "POST"
        assert seen["path"] == "/subscriptions/sub_1/change-plan"

    def test_update_subscription_patches_subscriptions_id(self):
        seen = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["method"] = request.method
            seen["path"] = request.url.path
            return httpx.Response(200, json={})

        client = _client(handler)
        client.update_subscription("sub_1", body={"cancel_at_next_billing_date": True})
        assert seen["method"] == "PATCH"
        assert seen["path"] == "/subscriptions/sub_1"

    def test_create_customer_portal_session_posts_correct_path(self):
        seen = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["method"] = request.method
            seen["path"] = request.url.path
            return httpx.Response(200, json={"link": "https://customer.dodopayments.com/x"})

        client = _client(handler)
        client.create_customer_portal_session("cus_1")
        assert seen["method"] == "POST"
        assert seen["path"] == "/customers/cus_1/customer-portal/session"
