"""Bounded Dodo Payments API HTTP client (Dodo Payments message 1).

Uses raw ``httpx`` (already installed — same pattern as the existing
Stripe and Paddle integrations) rather than a Dodo SDK. No Dodo SDK is
added.

Base URLs verified against official Dodo Payments documentation
(docs.dodopayments.com/api-reference/introduction, fetched during this
message's research):

    Test Mode: https://test.dodopayments.com
    Live Mode: https://live.dodopayments.com

Authentication: ``Authorization: Bearer <DODO_API_KEY>`` (Bearer token,
confirmed from the same page).

Safety
------
* Explicit base URL per environment — test and live are never reachable
  through the same base URL by accident.
* Bounded timeout on every request.
* Bounded retry ONLY for safe, idempotent, read-only GET requests, only on
  network errors and 429/5xx — never on 4xx (invalid credentials/bad
  request are never retried). Every mutating call in this client
  (checkout-session creation, change-plan, cancel, portal-session
  creation) is explicitly marked non-idempotent and is never retried,
  since Dodo's documentation does not describe any of these as safe to
  retry automatically.
* ``Retry-After`` is honored when present (Dodo documents 429 responses
  with standard rate-limit headers — X-RateLimit-Limit/Remaining/Reset;
  ``Retry-After`` itself was not documented, so it's honored defensively
  when present and a backoff schedule is used otherwise).
* No API key, webhook secret, or full response body ever appears in a
  raised exception's message — only a sanitized summary (status code, a
  request-tracing ID header if present, an error "code" field from Dodo's
  documented error envelope: ``{"code": ..., "message": ...}``).
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import httpx

_TEST_BASE_URL = "https://test.dodopayments.com"
_LIVE_BASE_URL = "https://live.dodopayments.com"

_DEFAULT_TIMEOUT_SECONDS = 15.0
_MAX_RETRIES = 3
_RETRY_BACKOFF_SECONDS = 0.5

# Status codes safe to retry — transient server-side or rate-limit
# conditions only. Never 4xx auth/validation errors.
_RETRYABLE_STATUS_CODES = frozenset({429, 500, 502, 503, 504})


class DodoAPIError(Exception):
    """Base class for all Dodo API client errors. Never carries a secret
    or a full raw response body — only sanitized diagnostics."""

    def __init__(self, message: str, *, status_code: int | None = None, request_id: str | None = None, error_code: str | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.request_id = request_id
        self.error_code = error_code

    def as_dict(self) -> dict:
        return {
            "message": str(self),
            "status_code": self.status_code,
            "request_id": self.request_id,
            "error_code": self.error_code,
        }


class DodoAuthenticationError(DodoAPIError):
    """401/403 — never retried."""


class DodoValidationError(DodoAPIError):
    """400/422 — never retried."""


class DodoRateLimitedError(DodoAPIError):
    """429 — retried with backoff / Retry-After."""


class DodoServerError(DodoAPIError):
    """5xx — retried with backoff."""


class DodoNetworkError(DodoAPIError):
    """Connection/timeout failure — retried with backoff."""


def _base_url_for_environment(environment: str) -> str:
    if environment == "test":
        return _TEST_BASE_URL
    if environment == "live":
        return _LIVE_BASE_URL
    raise ValueError(f"Unknown Dodo environment {environment!r}; must be 'test' or 'live'")


@dataclass(frozen=True)
class DodoClientConfig:
    environment: str  # "test" | "live"
    api_key: str
    timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS
    max_retries: int = _MAX_RETRIES

    @property
    def base_url(self) -> str:
        return _base_url_for_environment(self.environment)


def _sanitize_error(exc: httpx.HTTPStatusError) -> tuple[str | None, str | None]:
    """Extract a request-tracing header and Dodo's documented error `code`
    field WITHOUT ever surfacing the full response body."""
    request_id = exc.response.headers.get("x-request-id") or exc.response.headers.get("request-id")
    error_code = None
    try:
        body = exc.response.json()
        error_code = body.get("code")
    except Exception:
        pass
    return request_id, error_code


def _raise_for_status(exc: httpx.HTTPStatusError) -> None:
    status = exc.response.status_code
    request_id, error_code = _sanitize_error(exc)
    if status in (401, 403):
        raise DodoAuthenticationError(
            "Dodo authentication failed.", status_code=status, request_id=request_id, error_code=error_code
        ) from exc
    if status in (400, 422):
        raise DodoValidationError(
            "Dodo rejected the request as invalid.", status_code=status, request_id=request_id, error_code=error_code
        ) from exc
    if status == 429:
        raise DodoRateLimitedError(
            "Dodo rate limit exceeded.", status_code=status, request_id=request_id, error_code=error_code
        ) from exc
    if status >= 500:
        raise DodoServerError(
            "Dodo server error.", status_code=status, request_id=request_id, error_code=error_code
        ) from exc
    raise DodoAPIError(
        "Dodo API error.", status_code=status, request_id=request_id, error_code=error_code
    ) from exc


@dataclass(frozen=True)
class DodoRequest:
    method: str
    path: str
    json_body: dict | None = None
    params: dict | None = None
    idempotent: bool = True  # safe to retry on transient failure
    correlation_id: str | None = None  # never logged with secrets; safe request tracing


class DodoAPIClient:
    """Thin, bounded Dodo REST client. One instance per request/adapter
    call — no shared mutable state, no connection pool assumptions beyond
    what ``httpx`` already provides safely per-call."""

    def __init__(self, config: DodoClientConfig, *, transport: httpx.BaseTransport | None = None):
        self._config = config
        self._transport = transport

    def _headers(self, correlation_id: str | None) -> dict:
        headers = {
            "Authorization": f"Bearer {self._config.api_key}",
            "Content-Type": "application/json",
        }
        if correlation_id:
            headers["X-ConfigTrace-Correlation-Id"] = correlation_id
        return headers

    def request(self, req: DodoRequest) -> dict:
        url = f"{self._config.base_url}{req.path}"
        headers = self._headers(req.correlation_id)
        attempts = self._config.max_retries if req.idempotent else 1

        last_exc: Exception | None = None
        for attempt in range(attempts):
            try:
                with httpx.Client(timeout=self._config.timeout_seconds, transport=self._transport) as client:
                    response = client.request(
                        req.method, url, headers=headers, json=req.json_body, params=req.params
                    )
                    response.raise_for_status()
                    if not response.content:
                        return {}
                    return response.json()
            except httpx.HTTPStatusError as exc:
                status = exc.response.status_code
                if status not in _RETRYABLE_STATUS_CODES or attempt == attempts - 1:
                    _raise_for_status(exc)
                retry_after = exc.response.headers.get("Retry-After")
                delay = float(retry_after) if retry_after else _RETRY_BACKOFF_SECONDS * (2**attempt)
                time.sleep(delay)
                last_exc = exc
            except (httpx.ConnectError, httpx.TimeoutException) as exc:
                if attempt == attempts - 1:
                    raise DodoNetworkError(f"Dodo network error: {type(exc).__name__}") from exc
                time.sleep(_RETRY_BACKOFF_SECONDS * (2**attempt))
                last_exc = exc

        raise DodoNetworkError("Dodo request exhausted retries with no response.") from last_exc

    # ── Typed convenience methods ────────────────────────────────────────
    #
    # Every path/verb below is verified against official Dodo Payments
    # documentation fetched during this message's research (see the Dodo
    # feasibility audit + this message's implementation report for exact
    # source pages). None is guessed.

    def create_checkout_session(self, *, body: dict, correlation_id: str | None = None) -> dict:
        """POST /checkouts — creates a hosted Checkout Session. Non-
        idempotent: creates a real (test-mode) session object; never
        blindly retried."""
        return self.request(
            DodoRequest(method="POST", path="/checkouts", json_body=body, idempotent=False, correlation_id=correlation_id)
        )

    def get_subscription(self, subscription_id: str, *, correlation_id: str | None = None) -> dict:
        """GET /subscriptions/{id} — standard REST detail fetch, safe to
        retry. Path pattern verified consistent with every other Dodo
        resource (products, payments); exact response-field documentation
        for this specific endpoint was not directly confirmed in this
        message's research — flagged in the implementation report as a
        Test Mode verification item."""
        return self.request(
            DodoRequest(method="GET", path=f"/subscriptions/{subscription_id}", correlation_id=correlation_id)
        )

    def update_subscription(self, subscription_id: str, *, body: dict, correlation_id: str | None = None) -> dict:
        """PATCH /subscriptions/{id} — used for cancellation
        (``cancel_at_next_billing_date`` / ``status``) and other field
        updates. Non-idempotent."""
        return self.request(
            DodoRequest(
                method="PATCH", path=f"/subscriptions/{subscription_id}", json_body=body,
                idempotent=False, correlation_id=correlation_id,
            )
        )

    def change_plan(self, subscription_id: str, *, body: dict, correlation_id: str | None = None) -> dict:
        """POST /subscriptions/{id}/change-plan — the documented endpoint
        for changing a subscription's product/quantity/addons with an
        explicit proration mode. Non-idempotent (mutates real subscription
        state)."""
        return self.request(
            DodoRequest(
                method="POST", path=f"/subscriptions/{subscription_id}/change-plan", json_body=body,
                idempotent=False, correlation_id=correlation_id,
            )
        )

    def get_customer(self, customer_id: str, *, correlation_id: str | None = None) -> dict:
        """GET /customers/{id} — standard REST detail fetch, safe to
        retry."""
        return self.request(
            DodoRequest(method="GET", path=f"/customers/{customer_id}", correlation_id=correlation_id)
        )

    def create_customer_portal_session(
        self, customer_id: str, *, return_url: str | None = None, correlation_id: str | None = None
    ) -> dict:
        """POST /customers/{id}/customer-portal/session — creates a
        Customer Portal session. Non-idempotent."""
        body: dict[str, Any] = {}
        if return_url:
            body["return_url"] = return_url
        return self.request(
            DodoRequest(
                method="POST", path=f"/customers/{customer_id}/customer-portal/session",
                json_body=body or None, idempotent=False, correlation_id=correlation_id,
            )
        )

    def get_product(self, product_id: str, *, correlation_id: str | None = None) -> dict:
        """GET /products/{id} — used only by the opt-in sandbox catalog
        verification test, never in the normal checkout/webhook path."""
        return self.request(
            DodoRequest(method="GET", path=f"/products/{product_id}", correlation_id=correlation_id)
        )
