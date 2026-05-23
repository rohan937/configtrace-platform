"""Stripe connector — M35.

Fetches read-only configuration data from the Stripe API.  Customer PII,
payment data, and secrets are NEVER fetched or stored.

Resources fetched
-----------------
stripe_account_settings
    GET /v1/account — account-level settings only.

stripe_webhook_endpoint
    GET /v1/webhook_endpoints — all endpoints.
    Signing secrets are NEVER fetched (endpoint.secret is not requested).

stripe_payment_method_configuration
    GET /v1/payment_method_configurations — all PM configs.

stripe_payment_method_domain
    GET /v1/payment_method_domains — all PM domains.

SECURITY
--------
- The stripe_api_key is NEVER logged (not even partially).
- The stripe_api_key is NEVER returned to the frontend.
- Webhook signing secrets are NEVER fetched or included in any snapshot.
- Customer PII is NEVER fetched (no /v1/customers, /v1/charges, etc.).
- The connector is stateless and DB-independent.
"""

from __future__ import annotations

import logging
import time
from typing import Any

import httpx

from app.connectors.base import BaseConnector
from app.connectors.exceptions import (
    AuthenticationError,
    ConnectorError,
    NetworkError,
    RateLimitError,
)
from app.connectors.stripe_schema import (
    STRIPE_ACCOUNT_SETTINGS,
    STRIPE_PAYMENT_METHOD_CONFIGURATION,
    STRIPE_PAYMENT_METHOD_DOMAIN,
    STRIPE_WEBHOOK_ENDPOINT,
)

logger = logging.getLogger(__name__)

_BASE_URL = "https://api.stripe.com"
_TIMEOUT = 20.0  # seconds
_MAX_RETRIES = 3
_RETRY_BACKOFF = (1.0, 2.0, 4.0)


class StripeConnector(BaseConnector):
    """Read-only Stripe configuration connector.

    SECURITY: The API key is passed in credentials["stripe_api_key"].
    It is NEVER logged, NEVER returned to the frontend, and NEVER stored
    except in encrypted form in the database.
    """

    def _get(
        self,
        credentials: dict,
        path: str,
        params: dict | None = None,
    ) -> Any:
        """Make an authenticated GET to the Stripe API with retry/back-off.

        Raises
        ------
        AuthenticationError  — 401 / 403
        ConnectorError       — 4xx (other than 401/403/429)
        RateLimitError       — 429
        NetworkError         — connection / timeout failures

        SECURITY: The API key is used as HTTP Basic Auth username (Stripe's
        bearer auth scheme).  It is NEVER written to any log line.
        """
        # SECURITY: do not log the API key value.
        logger.debug("stripe._get path=%s", path)

        url = f"{_BASE_URL}{path}"
        last_exc: Exception | None = None

        for attempt in range(_MAX_RETRIES):
            try:
                resp = httpx.get(
                    url,
                    params=params,
                    auth=(credentials["stripe_api_key"], ""),
                    timeout=_TIMEOUT,
                    headers={"Stripe-Version": "2024-06-20"},
                )
            except httpx.TimeoutException as exc:
                last_exc = exc
                if attempt < _MAX_RETRIES - 1:
                    time.sleep(_RETRY_BACKOFF[attempt])
                    continue
                raise NetworkError(
                    f"Stripe API timed out after {_TIMEOUT}s for {path}"
                ) from exc
            except httpx.RequestError as exc:
                last_exc = exc
                if attempt < _MAX_RETRIES - 1:
                    time.sleep(_RETRY_BACKOFF[attempt])
                    continue
                raise NetworkError(
                    f"Network error reaching Stripe API: {exc}"
                ) from exc

            if resp.status_code == 429:
                retry_after = float(resp.headers.get("Retry-After", _RETRY_BACKOFF[attempt]))
                logger.warning(
                    "stripe._get: rate limited  path=%s  retry_after=%.1fs",
                    path,
                    retry_after,
                )
                if attempt < _MAX_RETRIES - 1:
                    time.sleep(retry_after)
                    continue
                raise RateLimitError(
                    f"Stripe API rate limit hit for {path}. Retry after {retry_after}s."
                )

            if resp.status_code in (401, 403):
                raise AuthenticationError(
                    f"Stripe API authentication failed (HTTP {resp.status_code}). "
                    "Check that the API key is valid and has the required permissions."
                )

            if resp.status_code >= 500:
                logger.warning(
                    "stripe._get: server error  path=%s  status=%d  attempt=%d",
                    path,
                    resp.status_code,
                    attempt + 1,
                )
                if attempt < _MAX_RETRIES - 1:
                    time.sleep(_RETRY_BACKOFF[attempt])
                    continue
                raise ConnectorError(
                    f"Stripe API returned HTTP {resp.status_code} for {path} "
                    f"after {_MAX_RETRIES} attempts."
                )

            if not resp.is_success:
                try:
                    body = resp.json()
                    detail = body.get("error", {}).get("message", resp.text)
                except Exception:
                    detail = resp.text
                raise ConnectorError(
                    f"Stripe API returned HTTP {resp.status_code} for {path}: {detail}"
                )

            return resp.json()

        # Should not reach here, but satisfy type checker.
        raise NetworkError(f"Stripe API request failed after {_MAX_RETRIES} retries.")

    def _get_list(self, credentials: dict, path: str, limit: int = 100) -> list[dict]:
        """Fetch a paginated Stripe list endpoint, returning all items.

        Uses Stripe's cursor-based pagination (starting_after).
        """
        items: list[dict] = []
        params: dict = {"limit": limit}

        while True:
            data = self._get(credentials, path, params=params)
            page: list[dict] = data.get("data", [])
            items.extend(page)

            if not data.get("has_more", False):
                break

            # Cursor: ID of the last item on this page.
            if page:
                params["starting_after"] = page[-1]["id"]
            else:
                break

        return items

    # ── Fetch helpers ──────────────────────────────────────────────────────────

    def _fetch_account_settings(self, credentials: dict) -> dict:
        """Fetch GET /v1/account and normalise into a stripe_account_settings record."""
        data = self._get(credentials, "/v1/account")

        # Capabilities: extract names of requested+active capabilities.
        capabilities = data.get("capabilities") or {}
        enabled_caps = sorted(
            name for name, status in capabilities.items() if status == "active"
        )

        # Payout schedule
        payout_settings = (data.get("settings") or {}).get("payouts") or {}
        schedule = payout_settings.get("schedule") or {}

        # Branding
        branding = (data.get("settings") or {}).get("branding") or {}

        # Dashboard
        dashboard = (data.get("settings") or {}).get("dashboard") or {}

        # Business profile
        bp = data.get("business_profile") or {}

        account_id = data.get("id", "")

        return {
            "record_type": STRIPE_ACCOUNT_SETTINGS,
            "record_id":   account_id,
            "name":        account_id,
            # Business profile
            "account_id":          account_id,
            "business_name":       bp.get("name"),
            "support_email":       bp.get("support_email"),
            "support_url":         bp.get("support_url"),
            "business_url":        bp.get("url"),
            "country":             data.get("country"),
            # Operational
            "default_currency":          data.get("default_currency"),
            "payout_schedule_interval":  schedule.get("interval"),
            "payout_schedule_delay_days": schedule.get("delay_days"),
            # Dashboard
            "display_name": dashboard.get("display_name"),
            # Branding (file IDs are safe — not secrets)
            "branding_icon":          branding.get("icon"),
            "branding_logo":          branding.get("logo"),
            "branding_primary_color": branding.get("primary_color"),
            # Capabilities
            "enabled_payment_methods": enabled_caps,
            # Operational flags
            "charges_enabled": bool(data.get("charges_enabled", False)),
            "payouts_enabled": bool(data.get("payouts_enabled", False)),
            # Platform controller
            "controller_type": (data.get("controller") or {}).get("type"),
        }

    def _fetch_webhook_endpoints(self, credentials: dict) -> list[dict]:
        """Fetch GET /v1/webhook_endpoints and normalise records.

        SECURITY: The ``secret`` field in Stripe's API response is NEVER
        accessed, stored, or included in the returned records.
        """
        raw = self._get_list(credentials, "/v1/webhook_endpoints")
        records = []
        for ep in raw:
            # SECURITY: do NOT access ep["secret"] — signing secrets must
            # never be fetched, logged, or stored.
            endpoint_id = ep.get("id", "")
            url = ep.get("url", "")
            enabled_events: list[str] = sorted(ep.get("enabled_events") or [])
            records.append(
                {
                    "record_type":     STRIPE_WEBHOOK_ENDPOINT,
                    "record_id":       endpoint_id,
                    "name":            url,
                    "endpoint_id":     endpoint_id,
                    "url":             url,
                    "status":          ep.get("status", ""),
                    "api_version":     ep.get("api_version"),
                    "enabled_events":  enabled_events,
                    "description":     ep.get("description"),
                }
            )
        return records

    def _fetch_payment_method_configurations(self, credentials: dict) -> list[dict]:
        """Fetch GET /v1/payment_method_configurations and normalise records."""
        try:
            raw = self._get_list(credentials, "/v1/payment_method_configurations")
        except ConnectorError as exc:
            # Endpoint not available on all account types — treat as empty.
            logger.info(
                "stripe: payment_method_configurations unavailable (%s) — skipping",
                exc,
            )
            return []

        # Payment method type names to inspect for enabled status.
        _PM_TYPES = [
            "acss_debit", "affirm", "afterpay_clearpay", "alipay", "amazon_pay",
            "au_becs_debit", "bacs_debit", "bancontact", "blik", "boleto",
            "card", "cashapp", "customer_balance", "eps", "fpx", "giropay",
            "google_pay", "gopay", "grabpay", "ideal", "jcb", "klarna",
            "konbini", "link", "multibanco", "naver_pay", "oxxo", "p24",
            "paynow", "paypal", "pix", "promptpay", "revolut_pay", "sepa_debit",
            "sofort", "swish", "twint", "us_bank_account", "wechat_pay", "zip",
        ]

        records = []
        for cfg in raw:
            config_id = cfg.get("id", "")
            enabled_pm: dict[str, bool] = {}
            for pm_type in _PM_TYPES:
                pm_data = cfg.get(pm_type) or {}
                if pm_data:
                    display_preference = pm_data.get("display_preference") or {}
                    value = display_preference.get("value", "off")
                    enabled_pm[pm_type] = value == "on"

            records.append(
                {
                    "record_type": STRIPE_PAYMENT_METHOD_CONFIGURATION,
                    "record_id":   config_id,
                    "name":        cfg.get("name") or config_id,
                    "config_id":   config_id,
                    "config_name": cfg.get("name"),
                    "is_default":  bool(cfg.get("is_default", False)),
                    "parent_id":   cfg.get("parent"),
                    "enabled_payment_methods": enabled_pm,
                }
            )
        return records

    def _fetch_payment_method_domains(self, credentials: dict) -> list[dict]:
        """Fetch GET /v1/payment_method_domains and normalise records."""
        try:
            raw = self._get_list(credentials, "/v1/payment_method_domains")
        except ConnectorError as exc:
            # Not available on all account types — treat as empty.
            logger.info(
                "stripe: payment_method_domains unavailable (%s) — skipping",
                exc,
            )
            return []

        records = []
        for dom in raw:
            domain_id = dom.get("id", "")
            domain_name = dom.get("domain_name", "")

            # Determine per-method status.
            apple_enabled  = (dom.get("apple_pay")   or {}).get("status") == "active"
            google_enabled = (dom.get("google_pay")  or {}).get("status") == "active"
            link_enabled   = (dom.get("link")         or {}).get("status") == "active"

            records.append(
                {
                    "record_type":      STRIPE_PAYMENT_METHOD_DOMAIN,
                    "record_id":        domain_id,
                    "name":             domain_name,
                    "domain_id":        domain_id,
                    "domain_name":      domain_name,
                    "enabled":          dom.get("enabled", True),
                    "apple_pay_enabled":  apple_enabled,
                    "google_pay_enabled": google_enabled,
                    "link_enabled":       link_enabled,
                }
            )
        return records

    # ── Public interface ───────────────────────────────────────────────────────

    def fetch(self, credentials: dict) -> list[dict]:
        """Fetch all Stripe configuration records.

        Returns a flat list of normalised records across all four resource
        types.  Records are safe to snapshot — they contain no PII, no
        payment data, and no secrets.

        Raises
        ------
        AuthenticationError  — invalid or revoked API key.
        ConnectorError       — unexpected API error.
        RateLimitError       — Stripe rate limit hit.
        NetworkError         — network / timeout failure.
        """
        # SECURITY: do not log credentials["stripe_api_key"].
        logger.info("StripeConnector.fetch: starting")

        records: list[dict] = []

        # 1. Account settings (always present — one record per integration).
        account_record = self._fetch_account_settings(credentials)
        records.append(account_record)
        logger.info("StripeConnector.fetch: account_settings fetched")

        # 2. Webhook endpoints.
        webhook_records = self._fetch_webhook_endpoints(credentials)
        records.extend(webhook_records)
        logger.info(
            "StripeConnector.fetch: webhook_endpoints fetched count=%d",
            len(webhook_records),
        )

        # 3. Payment method configurations.
        pm_config_records = self._fetch_payment_method_configurations(credentials)
        records.extend(pm_config_records)
        logger.info(
            "StripeConnector.fetch: payment_method_configurations fetched count=%d",
            len(pm_config_records),
        )

        # 4. Payment method domains.
        pm_domain_records = self._fetch_payment_method_domains(credentials)
        records.extend(pm_domain_records)
        logger.info(
            "StripeConnector.fetch: payment_method_domains fetched count=%d",
            len(pm_domain_records),
        )

        logger.info(
            "StripeConnector.fetch: complete total_records=%d",
            len(records),
        )
        return records

    def validate_credentials(self, credentials: dict) -> bool:
        """Validate the Stripe API key by calling GET /v1/account.

        Returns True on success.  Raises AuthenticationError, ConnectorError,
        or NetworkError on failure.

        SECURITY: The API key is NEVER logged.
        """
        # SECURITY: do not log credentials["stripe_api_key"].
        logger.info("StripeConnector.validate_credentials: calling /v1/account")
        self._get(credentials, "/v1/account")
        logger.info("StripeConnector.validate_credentials: success")
        return True
