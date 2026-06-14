"""Stripe connector — M35 (restricted key support fix).

Fetches read-only configuration data from the Stripe API.  Customer PII,
payment data, and secrets are NEVER fetched or stored.

Resources fetched
-----------------
stripe_account_settings
    GET /v1/account — account-level settings only.
    OPTIONAL: restricted keys without the "Account" permission will skip
    this resource gracefully.  All other resources remain functional.

stripe_webhook_endpoint
    GET /v1/webhook_endpoints — all endpoints.
    Signing secrets are NEVER fetched (endpoint.secret is not requested).

stripe_payment_method_configuration
    GET /v1/payment_method_configurations — all PM configs.
    OPTIONAL: skipped on 403.

stripe_payment_method_domain
    GET /v1/payment_method_domains — all PM domains.
    OPTIONAL: skipped on 403.

Restricted key support (rk_test_... / rk_live_...)
---------------------------------------------------
Restricted keys are the PREFERRED auth method for least-privilege access.
They may not have the "Account" permission (GET /v1/account returns 403);
that is fine — account settings will be omitted but all other resources
remain fully functional.

Validation uses a multi-probe strategy: it tries resource-specific endpoints
(webhook_endpoints, pm_configurations, pm_domains, events) before /v1/account.
The first endpoint returning 200 confirms the key is valid.

Standard secret keys (sk_test_... / sk_live_...) continue to work.

SECURITY
--------
- The stripe_api_key is NEVER logged (not even partially).
- The stripe_api_key is NEVER returned to the frontend.
- Webhook signing secrets are NEVER fetched or included in any snapshot.
- Customer PII is NEVER fetched (no /v1/customers, /v1/charges, etc.).
- The connector is stateless and DB-independent.
- The fingerprint used as resource ID when /v1/account is inaccessible is a
  SHA-256 hash — non-reversible, does not leak the key.
"""

from __future__ import annotations

import hashlib
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
    STRIPE_BILLING_PORTAL_CONFIG,
    STRIPE_PAYMENT_LINK,
    STRIPE_PAYMENT_METHOD_CONFIGURATION,
    STRIPE_PAYMENT_METHOD_DOMAIN,
    STRIPE_WEBHOOK_ENDPOINT,
)

logger = logging.getLogger(__name__)

_BASE_URL = "https://api.stripe.com"
_TIMEOUT = 20.0  # seconds
_MAX_RETRIES = 3
_RETRY_BACKOFF = (1.0, 2.0, 4.0)

# Ordered probe endpoints for validate_credentials().
# Resource-specific endpoints (require only targeted read permission) are tried
# before /v1/account (requires broad Account permission not available to most
# restricted keys).  The first 200 response confirms the key is valid.
_VALIDATE_PROBE_ENDPOINTS = [
    "/v1/webhook_endpoints",
    "/v1/payment_method_configurations",
    "/v1/payment_method_domains",
    "/v1/events",
    "/v1/account",
]


def _url_origin(url: Any) -> str | None:
    """Reduce a URL to its scheme+host (origin) form — M73A.

    SECURITY: query strings and path segments may carry tokens or customer
    identifiers; only ``scheme://netloc`` is ever retained. Returns None when
    the input is empty or unparseable.
    """
    if not url or not isinstance(url, str):
        return None
    try:
        from urllib.parse import urlparse

        parsed = urlparse(url)
        if parsed.scheme and parsed.netloc:
            return f"{parsed.scheme}://{parsed.netloc}"
    except Exception:
        return None
    return None


class StripeConnector(BaseConnector):
    """Read-only Stripe configuration connector.

    Supports both restricted keys (rk_test_... / rk_live_..., recommended)
    and standard secret keys (sk_test_... / sk_live_...).

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

        HTTP status distinction
        ----------------------
        - 401  → ``AuthenticationError`` (invalid or revoked key — re-auth needed).
        - 403  → ``ConnectorError(status_code=403)`` (valid key, lacks permission
                 for THIS endpoint — callers may try a different endpoint or skip).
        - 429  → ``RateLimitError``
        - 5xx  → ``ConnectorError`` (transient server error, retried)
        - net  → ``NetworkError``

        The 401/403 split is crucial for restricted key support:
        - 401 means the key itself is invalid → fail hard.
        - 403 means the key is valid but this specific endpoint is not
          permitted → the caller can skip this endpoint and try another.

        SECURITY: The API key is NEVER written to any log line.
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

            # ── 401: key is invalid or revoked ────────────────────────────────
            if resp.status_code == 401:
                raise AuthenticationError(
                    "Stripe API authentication failed: the API key is invalid, "
                    "revoked, or has no permissions at all. "
                    "Check that the key value is correct.",
                    status_code=401,
                )

            # ── 403: key is valid but lacks permission for THIS endpoint ──────
            # This is expected for restricted keys on endpoints they haven't
            # been granted access to.  Callers handle 403 ConnectorError by
            # skipping the endpoint or trying an alternative.
            if resp.status_code == 403:
                raise ConnectorError(
                    f"Stripe API returned 403 for {path}: the key lacks "
                    "permission for this endpoint. If using a restricted key "
                    "(rk_...), ensure read access is granted for this resource.",
                    status_code=403,
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
                    f"after {_MAX_RETRIES} attempts.",
                    status_code=resp.status_code,
                )

            if not resp.is_success:
                try:
                    body = resp.json()
                    detail = body.get("error", {}).get("message", resp.text)
                except Exception:
                    detail = resp.text
                raise ConnectorError(
                    f"Stripe API returned HTTP {resp.status_code} for {path}: {detail}",
                    status_code=resp.status_code,
                )

            return resp.json()

        # Should not reach here, but satisfy type checker.
        raise NetworkError(f"Stripe API request failed after {_MAX_RETRIES} retries.")

    def _get_list(self, credentials: dict, path: str, limit: int = 100) -> list[dict]:
        """Fetch a paginated Stripe list endpoint, returning all items.

        Uses Stripe's cursor-based pagination (starting_after).
        Raises ConnectorError(status_code=403) if the key lacks permission.
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

    def _resolve_account_id(self, credentials: dict) -> tuple[str, bool]:
        """Return a stable identifier for the connected Stripe account.

        Tries GET /v1/account first (returns the real account ID).
        If the key lacks permission (HTTP 403, common for restricted keys),
        falls back to a SHA-256 fingerprint of the API key — non-reversible,
        stable across sessions, safe to store.

        Returns
        -------
        (identifier, is_real_account_id)
            is_real_account_id = True  → ``identifier`` is a real Stripe
                account ID (``acct_xxx``).
            is_real_account_id = False → ``identifier`` is a key fingerprint
                (``fp_<24-hex-chars>``).

        SECURITY: The fingerprint is SHA-256(key) — non-reversible.  The full
        API key is never stored, logged, or embedded in the identifier.
        """
        try:
            data = self._get(credentials, "/v1/account")
            account_id: str = data.get("id", "")
            logger.debug("stripe: resolved real account_id=%s", account_id)
            return account_id, True
        except ConnectorError as exc:
            if exc.status_code == 403:
                # Restricted key without Account permission — use fingerprint.
                # SECURITY: SHA-256 of the full key; non-reversible.
                fingerprint = hashlib.sha256(
                    credentials["stripe_api_key"].encode()
                ).hexdigest()[:24]
                fake_id = f"fp_{fingerprint}"
                logger.info(
                    "stripe: /v1/account not accessible (restricted key without "
                    "Account permission) — using key fingerprint as stable identifier"
                )
                return fake_id, False
            raise

    # ── Fetch helpers ──────────────────────────────────────────────────────────

    def _fetch_account_settings(self, credentials: dict) -> dict | None:
        """Fetch GET /v1/account and normalise into a stripe_account_settings record.

        Returns
        -------
        dict    — normalised record on success.
        None    — when the key lacks permission (HTTP 403, common for restricted
                  keys).  The caller should skip this record silently.

        SECURITY: No PII, payment data, or secrets are included.
        """
        try:
            data = self._get(credentials, "/v1/account")
        except ConnectorError as exc:
            if exc.status_code == 403:
                logger.info(
                    "stripe: /v1/account not accessible (restricted key without "
                    "Account permission) — stripe_account_settings omitted"
                )
                return None
            raise

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
            # Onboarding completeness — whether the account finished Stripe's
            # required-information submission (M73A). A boolean only.
            "details_submitted": bool(data.get("details_submitted", False)),
            # Platform controller
            "controller_type": (data.get("controller") or {}).get("type"),
        }

    def _fetch_webhook_endpoints(self, credentials: dict) -> list[dict]:
        """Fetch GET /v1/webhook_endpoints and normalise records.

        Returns an empty list if the key lacks permission (HTTP 403).

        SECURITY: The ``secret`` field in Stripe's API response is NEVER
        accessed, stored, or included in the returned records.
        """
        try:
            raw = self._get_list(credentials, "/v1/webhook_endpoints")
        except ConnectorError as exc:
            if exc.status_code == 403:
                logger.info(
                    "stripe: /v1/webhook_endpoints not accessible "
                    "(restricted key without Webhook Endpoints permission) — skipping"
                )
                return []
            raise

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
        """Fetch GET /v1/payment_method_configurations and normalise records.

        Returns an empty list if the endpoint is inaccessible (403 or other error).
        """
        try:
            raw = self._get_list(credentials, "/v1/payment_method_configurations")
        except ConnectorError as exc:
            # Endpoint not available on all account types or key lacks permission.
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
        """Fetch GET /v1/payment_method_domains and normalise records.

        Returns an empty list if the endpoint is inaccessible (403 or other error).
        """
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

    def _fetch_billing_portal_configs(self, credentials: dict) -> list[dict]:
        """Fetch GET /v1/billing_portal/configurations — M57.9.

        Returns one ``stripe_billing_portal_config`` record per configuration.
        Returns an empty list when the endpoint is inaccessible (403) or the
        Billing Portal product is not enabled on the account.

        SECURITY
        --------
        - No customer PII, subscription data, or invoice data is fetched.
        - ``default_return_url`` — only the domain component is stored; the
          full URL may contain path tokens.
        - ``business_profile`` URLs are skipped (internal privacy/ToS pages).
        """
        try:
            raw = self._get_list(credentials, "/v1/billing_portal/configurations")
        except AuthenticationError:
            # 401 = key is invalid — propagate so the caller surfaces an auth error.
            raise
        except Exception as exc:
            # 403 = key lacks permission (expected for most restricted keys).
            # Other errors (404, 5xx, network, or test-mock exhaustion) are
            # treated as "surface unavailable" and skipped gracefully.
            logger.info(
                "stripe: billing_portal/configurations unavailable (%s) — skipping",
                type(exc).__name__,
            )
            return []

        records = []
        for cfg in raw:
            config_id = cfg.get("id", "")

            # Login page
            login_page = cfg.get("login_page") or {}
            login_page_enabled = bool(login_page.get("enabled", False))

            # Return URL — domain only (full URL may contain sensitive path segments)
            default_return_url: str | None = cfg.get("default_return_url")
            return_url_domain: str | None = None
            if default_return_url:
                try:
                    from urllib.parse import urlparse
                    parsed = urlparse(default_return_url)
                    return_url_domain = parsed.netloc or None
                except Exception:
                    pass

            # Feature flags
            features = cfg.get("features") or {}

            cu = features.get("customer_update") or {}
            customer_update_enabled = bool(cu.get("enabled", False))
            customer_update_allowed: list[str] = sorted(
                cu.get("allowed_updates") or []
            )

            ih = features.get("invoice_history") or {}
            invoice_history_enabled = bool(ih.get("enabled", False))

            pmu = features.get("payment_method_update") or {}
            payment_method_update_enabled = bool(pmu.get("enabled", False))

            sc = features.get("subscription_cancel") or {}
            subscription_cancel_enabled = bool(sc.get("enabled", False))
            subscription_cancel_mode: str | None = sc.get("mode")
            cancellation_reason = sc.get("cancellation_reason") or {}
            subscription_cancel_reason_enabled = bool(
                cancellation_reason.get("enabled", False)
            )

            su = features.get("subscription_update") or {}
            subscription_update_enabled = bool(su.get("enabled", False))
            subscription_update_allowed: list[str] = sorted(
                su.get("default_allowed_updates") or []
            )

            sp = features.get("subscription_pause") or {}
            subscription_pause_enabled = bool(sp.get("enabled", False))

            records.append(
                {
                    "record_type":   STRIPE_BILLING_PORTAL_CONFIG,
                    "record_id":     config_id,
                    "name":          "default billing portal" if cfg.get("is_default") else f"billing portal {config_id}",
                    "config_id":     config_id,
                    "active":        bool(cfg.get("active", False)),
                    "is_default":    bool(cfg.get("is_default", False)),
                    "login_page_enabled": login_page_enabled,
                    "return_url_domain":  return_url_domain,
                    "customer_update_enabled":         customer_update_enabled,
                    "customer_update_allowed_updates": customer_update_allowed,
                    "invoice_history_enabled":         invoice_history_enabled,
                    "payment_method_update_enabled":   payment_method_update_enabled,
                    "subscription_cancel_enabled":     subscription_cancel_enabled,
                    "subscription_cancel_mode":        subscription_cancel_mode,
                    "subscription_cancel_reason_enabled": subscription_cancel_reason_enabled,
                    "subscription_update_enabled":     subscription_update_enabled,
                    "subscription_update_allowed_updates": subscription_update_allowed,
                    "subscription_pause_enabled":      subscription_pause_enabled,
                }
            )
        return records

    def _fetch_payment_links(self, credentials: dict) -> list[dict]:
        """Fetch GET /v1/payment_links and normalise records — M73A.

        Returns one ``stripe_payment_link`` record per payment link. Returns an
        empty list when the endpoint is inaccessible (403, common for restricted
        keys without Payment Links read access) or the surface is unavailable.

        SECURITY / DATA MINIMISATION
        ----------------------------
        - No customer PII, card data, charges, or checkout-session data is
          fetched. A payment link object is account configuration, not customer
          data.
        - ``url`` / ``after_completion`` redirect URLs are reduced to their
          scheme+host (origin) form; query strings (which may carry
          ``{CHECKOUT_SESSION_ID}`` or customer-supplied tokens) are never stored.
        - Line-item details and price amounts are not fetched (line_items are not
          expanded); only safe configuration booleans + counts are kept.
        """
        try:
            raw = self._get_list(credentials, "/v1/payment_links")
        except AuthenticationError:
            # 401 = key is invalid — propagate so the caller surfaces an auth error.
            raise
        except Exception as exc:
            # 403 = key lacks permission (expected for most restricted keys).
            # Other errors (404, 5xx, network, or test-mock exhaustion) are
            # treated as "surface unavailable" and skipped gracefully.
            logger.info(
                "stripe: payment_links unavailable (%s) — skipping",
                type(exc).__name__,
            )
            return []

        records: list[dict] = []
        for link in raw:
            link_id = link.get("id", "")
            automatic_tax = link.get("automatic_tax") or {}
            after_completion = link.get("after_completion") or {}
            pm_types = link.get("payment_method_types") or []
            metadata = link.get("metadata") or {}

            records.append(
                {
                    "record_type": STRIPE_PAYMENT_LINK,
                    "record_id":   link_id,
                    "name":        link_id,
                    "active":      bool(link.get("active", False)),
                    "allow_promotion_codes": bool(link.get("allow_promotion_codes", False)),
                    "automatic_tax_enabled": bool(automatic_tax.get("enabled", False)),
                    "after_completion_type": after_completion.get("type"),
                    "after_completion_redirect_origin": _url_origin(
                        (after_completion.get("redirect") or {}).get("url")
                    ),
                    "success_url_origin": _url_origin(link.get("url")),
                    "customer_creation": link.get("customer_creation"),
                    "payment_method_collection": link.get("payment_method_collection"),
                    "payment_method_types_count": len(pm_types) if isinstance(pm_types, list) else 0,
                    "application_fee_amount": link.get("application_fee_amount"),
                    "application_fee_percent": link.get("application_fee_percent"),
                    "metadata_key_count": len(metadata) if isinstance(metadata, dict) else 0,
                    "livemode": bool(link.get("livemode", False)),
                }
            )
        return records

    # ── Public interface ───────────────────────────────────────────────────────

    def fetch(self, credentials: dict) -> list[dict]:
        """Fetch all accessible Stripe configuration records.

        All four resource types are attempted.  Resources for which the key
        lacks permission (HTTP 403) are skipped gracefully — the remaining
        resources are still returned.  This ensures restricted keys (rk_...)
        that don't have the "Account" permission can still monitor webhooks,
        PM configurations, and PM domains.

        Returns
        -------
        Flat list of normalised records.  May be empty if the key has no
        useful permissions (but validation would have caught that earlier).

        Raises
        ------
        AuthenticationError  — key is invalid or revoked (HTTP 401).
        ConnectorError       — unexpected non-permission API error.
        RateLimitError       — Stripe rate limit hit after all retries.
        NetworkError         — network / timeout failure.
        """
        # SECURITY: do not log credentials["stripe_api_key"].
        logger.info("StripeConnector.fetch: starting")

        records: list[dict] = []

        # 1. Account settings — optional (requires "Account" permission).
        #    Restricted keys without this permission return None; skip silently.
        account_record = self._fetch_account_settings(credentials)
        if account_record is not None:
            records.append(account_record)
            logger.info("StripeConnector.fetch: account_settings fetched")
        else:
            logger.info(
                "StripeConnector.fetch: account_settings skipped "
                "(restricted key without Account permission)"
            )

        # 2. Webhook endpoints — skipped on 403.
        webhook_records = self._fetch_webhook_endpoints(credentials)
        records.extend(webhook_records)
        logger.info(
            "StripeConnector.fetch: webhook_endpoints fetched count=%d",
            len(webhook_records),
        )

        # 3. Payment method configurations — skipped on 403 or unavailable.
        pm_config_records = self._fetch_payment_method_configurations(credentials)
        records.extend(pm_config_records)
        logger.info(
            "StripeConnector.fetch: payment_method_configurations fetched count=%d",
            len(pm_config_records),
        )

        # 4. Payment method domains — skipped on 403 or unavailable.
        pm_domain_records = self._fetch_payment_method_domains(credentials)
        records.extend(pm_domain_records)
        logger.info(
            "StripeConnector.fetch: payment_method_domains fetched count=%d",
            len(pm_domain_records),
        )

        # 5. Billing portal configurations — skipped on 403 or unavailable (M57.9).
        bp_config_records = self._fetch_billing_portal_configs(credentials)
        records.extend(bp_config_records)
        logger.info(
            "StripeConnector.fetch: billing_portal_configs fetched count=%d",
            len(bp_config_records),
        )

        # 6. Payment links — skipped on 403 or unavailable (M73A).
        payment_link_records = self._fetch_payment_links(credentials)
        records.extend(payment_link_records)
        logger.info(
            "StripeConnector.fetch: payment_links fetched count=%d",
            len(payment_link_records),
        )

        logger.info(
            "StripeConnector.fetch: complete total_records=%d",
            len(records),
        )
        return records

    # ── Activity / Events API surface (M73B) ──────────────────────────────────
    #
    # Stripe surfaces account-config change activity through the public
    # ``/v1/events`` API. ConfigTrace ingests ONLY a strict allowlist of
    # configuration-oriented event types — never customer/payment/charge/invoice
    # lifecycle events (which carry PII / payment data). When a restricted key
    # lacks the "Events" permission this fails soft and the ingestion layer
    # reports ``permission_limited`` (the existing Stripe configuration sync is
    # NEVER broken). The connector itself stores nothing; the ingestion layer
    # keeps only allowlisted, flat fields and NEVER raw event payloads, raw API
    # responses, customer PII / emails, payment method data, card data, signing
    # secrets, tokens, headers, request/response bodies, or bank-account details.

    # Strict configuration-event allowlist. Customer/payment/charge/invoice
    # lifecycle events are deliberately EXCLUDED.
    _ALLOWED_EVENT_TYPES: tuple[str, ...] = (
        "webhook_endpoint.created",
        "webhook_endpoint.updated",
        "webhook_endpoint.deleted",
        "payment_link.created",
        "payment_link.updated",
        "billing_portal.configuration.created",
        "billing_portal.configuration.updated",
        "account.updated",
        "capability.updated",
    )

    # Bounded pagination guard for the Stripe Events API.
    _MAX_ACTIVITY_PAGES = 10

    def list_activity_events(
        self,
        credentials: dict,
        *,
        max_events: int = 100,
        lookback_hours: int = 24,
    ) -> list[dict]:
        """Fetch Stripe configuration-change events — metadata only (M73B).

        Strict event-type allowlist (configuration changes only). Customer /
        payment / charge / invoice / refund / dispute lifecycle events are
        deliberately EXCLUDED at the API level — they are never requested,
        scraped, or inferred from any other surface.

        SECURITY: returns raw event dicts for the ingestion layer to normalize
        through the metadata allowlist. The connector stores nothing; the
        ingestion layer keeps only allowlisted, flat fields and NEVER customer
        PII / emails, payment method data, card data, charges/payment intents/
        invoices/customer records, raw event payloads, raw API responses,
        OAuth tokens, signing secrets, headers, request/response bodies,
        bank-account details, or tax IDs.

        Raises ``AuthenticationError`` for an invalid key; ``ConnectorError`` for
        permission or API errors so the ingestion layer can fail soft.
        """
        cap = max(1, min(int(max_events), 1000))
        hours = max(1, min(int(lookback_hours or 24), 168))
        # Lookback window: ``created[gte]`` is a Unix epoch in seconds. We pass a
        # safe bounded floor; the upper bound is implicit (now).
        try:
            created_floor = int(time.time()) - hours * 3600
        except Exception:
            created_floor = 0

        # The /v1/events API accepts repeated ``types[]=...`` query params to
        # filter at the source — no client-side fan-in needed. Stripe caps
        # ``limit`` at 100 per page; bound page-count via _MAX_ACTIVITY_PAGES.
        per_page = min(cap, 100)
        params: dict[str, Any] = {
            "limit": per_page,
            "created[gte]": created_floor,
        }
        # ``httpx`` encodes a list of values for a key as repeated query params.
        params["types[]"] = list(self._ALLOWED_EVENT_TYPES)

        events: list[dict] = []
        for _page in range(self._MAX_ACTIVITY_PAGES):
            data = self._get(credentials, "/v1/events", params=params)
            batch = data.get("data") if isinstance(data, dict) else None
            if not isinstance(batch, list):
                break
            for ev in batch:
                events.append(ev)
                if len(events) >= cap:
                    return events[:cap]
            if not data.get("has_more", False) or not batch:
                break
            last_id = batch[-1].get("id") if isinstance(batch[-1], dict) else None
            if not last_id:
                break
            params = {**params, "starting_after": last_id}
        return events[:cap]

    def validate_credentials(self, credentials: dict) -> bool:
        """Validate the Stripe API key using a least-privilege probe strategy.

        Tries endpoints in order of preference (most-targeted permissions first,
        broad account access last).  The first endpoint returning HTTP 200
        confirms the key is valid.  This design supports restricted keys that
        don't have the "Account" permission.

        Probe order
        -----------
        1. GET /v1/webhook_endpoints       — requires Webhook Endpoints:Read
        2. GET /v1/payment_method_configurations — requires PM Configs:Read
        3. GET /v1/payment_method_domains  — requires PM Domains:Read
        4. GET /v1/events                  — requires Events:Read
        5. GET /v1/account                 — requires broad Account permission
                                             (standard sk_* keys or accounts with
                                             full access)

        Failure semantics
        -----------------
        - HTTP 401 on ANY probe → ``AuthenticationError`` (key is invalid; no retry).
        - HTTP 403 on a probe   → not counted as a failure; try the next probe.
        - All probes return 403 → ``ConnectorError(status_code=403)`` with a
          message listing the required permissions.
        - HTTP 4xx (other)      → ``ConnectorError`` raised immediately.
        - Network/rate limit    → ``NetworkError`` / ``RateLimitError``.

        SECURITY: The API key is NEVER logged.
        """
        # SECURITY: do not log credentials["stripe_api_key"].
        logger.info("StripeConnector.validate_credentials: probing endpoints")

        forbidden_count = 0
        last_403_exc: ConnectorError | None = None

        for endpoint in _VALIDATE_PROBE_ENDPOINTS:
            try:
                self._get(credentials, endpoint, params={"limit": 1})
                logger.info(
                    "StripeConnector.validate_credentials: success via %s",
                    endpoint,
                )
                return True
            except AuthenticationError:
                # 401 = key is invalid — fail hard and immediately.
                # Do NOT try other endpoints; a bad key is a bad key.
                raise
            except ConnectorError as exc:
                if exc.status_code == 403:
                    # 403 = key is valid but doesn't have permission for THIS
                    # endpoint.  Try the next probe.
                    forbidden_count += 1
                    last_403_exc = exc
                    logger.debug(
                        "stripe.validate: 403 on %s — trying next probe",
                        endpoint,
                    )
                    continue
                # Other ConnectorError (4xx, 5xx) — surface immediately.
                raise
            except (NetworkError, RateLimitError):
                raise

        # Every probe returned 403.  The key is technically valid but has no
        # permissions for any resource we monitor.
        raise ConnectorError(
            "The Stripe API key has no read access to any monitored resource. "
            "Grant read-only access to at least one of: "
            "Webhook Endpoints, Payment Method Configurations, "
            "Payment Method Domains, or Events. "
            f"(All {forbidden_count} probe endpoints returned HTTP 403.)",
            status_code=403,
        )
