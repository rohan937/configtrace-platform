"""Bounded Paddle API HTTP client (Commercial Infrastructure message 2).

Uses raw ``httpx`` (already installed — same pattern as the existing
Stripe integration in ``app/services/billing_service.py``) rather than a
Paddle SDK. No Paddle SDK is added: the API surface this integration
needs (checkout/customers/subscriptions/transactions, a handful of GET/
POST/PATCH calls) is small enough that raw HTTP is simpler to audit than
a full SDK dependency, matching this repo's existing convention.

Safety
------
* Explicit base URL per environment — sandbox and live are never
  reachable through the same base URL by accident.
* Bounded timeout on every request.
* Bounded retry ONLY for safe (idempotent, read-only or explicitly
  idempotency-keyed) requests, only on network errors and 429/5xx —
  never on 4xx (invalid credentials/bad request are never retried).
* ``Retry-After`` is honored when present.
* No API key, webhook secret, or full response body ever appears in a
  raised exception's message — only a sanitized summary (status code,
  Paddle's own request ID if present, an error "type"/"code" field if
  Paddle's error envelope includes one).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Optional

import httpx

_SANDBOX_BASE_URL = "https://sandbox-api.paddle.com"
_PRODUCTION_BASE_URL = "https://api.paddle.com"

_DEFAULT_TIMEOUT_SECONDS = 15.0
_MAX_RETRIES = 3
_RETRY_BACKOFF_SECONDS = 0.5

# Status codes safe to retry — transient server-side or rate-limit
# conditions only. Never 4xx auth/validation errors.
_RETRYABLE_STATUS_CODES = frozenset({429, 500, 502, 503, 504})


class PaddleAPIError(Exception):
    """Base class for all Paddle API client errors. Never carries a
    secret or a full raw response body — only sanitized diagnostics."""

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


class PaddleAuthenticationError(PaddleAPIError):
    """401/403 — never retried."""


class PaddleValidationError(PaddleAPIError):
    """400/422 — never retried."""


class PaddleRateLimitedError(PaddleAPIError):
    """429 — retried with backoff / Retry-After."""


class PaddleServerError(PaddleAPIError):
    """5xx — retried with backoff."""


class PaddleNetworkError(PaddleAPIError):
    """Connection/timeout failure — retried with backoff."""


def _base_url_for_environment(environment: str) -> str:
    if environment == "sandbox":
        return _SANDBOX_BASE_URL
    if environment == "production":
        return _PRODUCTION_BASE_URL
    raise ValueError(f"Unknown Paddle environment {environment!r}; must be 'sandbox' or 'production'")


@dataclass(frozen=True)
class PaddleClientConfig:
    environment: str  # "sandbox" | "production"
    api_key: str
    timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS
    max_retries: int = _MAX_RETRIES

    @property
    def base_url(self) -> str:
        return _base_url_for_environment(self.environment)


def _sanitize_error(exc: httpx.HTTPStatusError) -> tuple[str | None, str | None]:
    """Extract a Paddle request ID and error code from a response WITHOUT
    ever surfacing the full body (which could, in principle, echo request
    data back)."""
    request_id = exc.response.headers.get("paddle-request-id")
    error_code = None
    try:
        body = exc.response.json()
        error_code = (body.get("error") or {}).get("code")
    except Exception:
        pass
    return request_id, error_code


def _raise_for_status(exc: httpx.HTTPStatusError) -> None:
    status = exc.response.status_code
    request_id, error_code = _sanitize_error(exc)
    if status in (401, 403):
        raise PaddleAuthenticationError(
            "Paddle authentication failed.", status_code=status, request_id=request_id, error_code=error_code
        ) from exc
    if status in (400, 422):
        raise PaddleValidationError(
            "Paddle rejected the request as invalid.", status_code=status, request_id=request_id, error_code=error_code
        ) from exc
    if status == 429:
        raise PaddleRateLimitedError(
            "Paddle rate limit exceeded.", status_code=status, request_id=request_id, error_code=error_code
        ) from exc
    if status >= 500:
        raise PaddleServerError(
            "Paddle server error.", status_code=status, request_id=request_id, error_code=error_code
        ) from exc
    raise PaddleAPIError(
        "Paddle API error.", status_code=status, request_id=request_id, error_code=error_code
    ) from exc


@dataclass(frozen=True)
class PaddleRequest:
    method: str
    path: str
    json_body: dict | None = None
    params: dict | None = None
    idempotent: bool = True  # safe to retry on transient failure
    correlation_id: str | None = None  # never logged with secrets; safe request tracing


class PaddleAPIClient:
    """Thin, bounded Paddle REST client. One instance per request/adapter
    call — no shared mutable state, no connection pool assumptions beyond
    what ``httpx`` already provides safely per-call."""

    def __init__(self, config: PaddleClientConfig, *, transport: httpx.BaseTransport | None = None):
        self._config = config
        self._transport = transport

    def _headers(self, correlation_id: str | None) -> dict:
        headers = {
            "Authorization": f"Bearer {self._config.api_key}",
            "Content-Type": "application/json",
        }
        if correlation_id:
            # Safe to include — an internal, non-secret trace identifier,
            # never a credential.
            headers["X-ConfigTrace-Correlation-Id"] = correlation_id
        return headers

    def request(self, req: PaddleRequest) -> dict:
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
                    raise PaddleNetworkError(f"Paddle network error: {type(exc).__name__}") from exc
                time.sleep(_RETRY_BACKOFF_SECONDS * (2**attempt))
                last_exc = exc

        # Unreachable in practice (loop always returns or raises), but
        # keeps type checkers happy and fails loudly if it ever is reached.
        raise PaddleNetworkError("Paddle request exhausted retries with no response.") from last_exc

    # ── Typed convenience methods ────────────────────────────────────────

    def create_checkout(self, *, items: list[dict], custom_data: dict, correlation_id: str | None = None) -> dict:
        return self.request(
            PaddleRequest(
                method="POST", path="/transactions",
                json_body={"items": items, "custom_data": custom_data},
                idempotent=False,  # creates a real transaction — never blindly retried
                correlation_id=correlation_id,
            )
        )

    def get_subscription(self, subscription_id: str, *, correlation_id: str | None = None) -> dict:
        return self.request(
            PaddleRequest(method="GET", path=f"/subscriptions/{subscription_id}", correlation_id=correlation_id)
        )

    def update_subscription_items(
        self, subscription_id: str, *, items: list[dict], proration_billing_mode: str, correlation_id: str | None = None
    ) -> dict:
        return self.request(
            PaddleRequest(
                method="PATCH", path=f"/subscriptions/{subscription_id}",
                json_body={"items": items, "proration_billing_mode": proration_billing_mode},
                idempotent=False,  # mutates real subscription state — never blindly retried
                correlation_id=correlation_id,
            )
        )

    def cancel_subscription(self, subscription_id: str, *, effective_from: str, correlation_id: str | None = None) -> dict:
        return self.request(
            PaddleRequest(
                method="POST", path=f"/subscriptions/{subscription_id}/cancel",
                json_body={"effective_from": effective_from},
                idempotent=False,
                correlation_id=correlation_id,
            )
        )

    def get_customer(self, customer_id: str, *, correlation_id: str | None = None) -> dict:
        return self.request(
            PaddleRequest(method="GET", path=f"/customers/{customer_id}", correlation_id=correlation_id)
        )

    def get_customer_portal_session(self, customer_id: str, *, correlation_id: str | None = None) -> dict:
        return self.request(
            PaddleRequest(
                method="POST", path=f"/customers/{customer_id}/portal-sessions",
                idempotent=False,
                correlation_id=correlation_id,
            )
        )

    def get_price(self, price_id: str, *, correlation_id: str | None = None) -> dict:
        return self.request(PaddleRequest(method="GET", path=f"/prices/{price_id}", correlation_id=correlation_id))
