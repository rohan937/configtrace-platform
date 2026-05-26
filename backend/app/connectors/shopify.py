"""Shopify connector — M57.5.

Fetches read-only configuration metadata from the Shopify Admin REST API.
Customer PII, order data, payment data, and financial records are NEVER
fetched or stored.

Resources fetched
-----------------
shopify_shop_metadata
    GET /admin/api/{version}/shop.json — store configuration metadata.
    Excludes: owner email, phone, address, billing/payment details.

shopify_webhook_subscription
    GET /admin/api/{version}/webhooks.json — all webhook subscriptions.
    Full URL is decomposed: only domain + path hash stored.

shopify_store_policy
    GET /admin/api/{version}/policies.json — store policy metadata.
    Only policy type, presence flag, and body hash stored.
    Raw policy text is NEVER stored.

FORBIDDEN endpoints (never called by this connector)
------------------------------------------------------
The following Shopify Admin API endpoint categories are strictly
off-limits and will never be called by this connector:
  orders, customers, transactions, checkouts, draft_orders,
  theme assets, gift_cards, payouts, disputes, balance.

SECURITY
--------
- The shopify_access_token is NEVER logged (not even partially).
- The shopify_access_token is NEVER returned to the frontend.
- Customer PII (email, phone, address) is NEVER fetched or stored.
- Order, transaction, payment, checkout, and gift card data are NEVER
  fetched.
- Full webhook delivery URLs are decomposed: domain + SHA-256 path hash
  only, to avoid storing URLs that may contain embedded secrets.
- Policy body text is hashed only — raw text is never stored.
- The connector is stateless and DB-independent.
"""

from __future__ import annotations

import hashlib
import logging
import re
import time
from urllib.parse import urlparse
from typing import Any

import httpx

from app.connectors.base import BaseConnector
from app.connectors.exceptions import (
    AuthenticationError,
    ConnectorError,
    NetworkError,
    RateLimitError,
)
from app.connectors.shopify_schema import (
    SENSITIVE_SHOPIFY_SCOPES,
    SHOPIFY_APP_SCOPE_SUMMARY,
    SHOPIFY_SHOP_METADATA,
    SHOPIFY_STORE_POLICY,
    SHOPIFY_WEBHOOK_SUBSCRIPTION,
)

logger = logging.getLogger(__name__)

_API_VERSION = "2024-01"
_TIMEOUT = 20.0
_MAX_RETRIES = 3
_RETRY_BACKOFF = (1.0, 2.0, 4.0)

# ── Domain validation ──────────────────────────────────────────────────────────

# Regex: <1+ label chars>.<optional more labels>.myshopify.com
# OR a general valid custom domain (no IP addresses)
_MYSHOPIFY_RE = re.compile(
    r"^[a-z0-9][a-z0-9\-]{1,}\.myshopify\.com$"
)
_CUSTOM_DOMAIN_RE = re.compile(
    r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)+$"
)

# Substrings that must never appear anywhere in a shop domain (IPs, localhost).
_BLOCKED_DOMAIN_SUBSTRINGS = (
    "localhost",
    "127.",
    "0.0.0.0",
    "::1",
    "10.",
    "172.16.",
    "172.17.",
    "172.18.",
    "172.19.",
    "172.20.",
    "172.21.",
    "172.22.",
    "172.23.",
    "172.24.",
    "172.25.",
    "172.26.",
    "172.27.",
    "172.28.",
    "172.29.",
    "172.30.",
    "172.31.",
    "192.168.",
)

# Suffixes (TLD-like) that must not end a shop domain (private/reserved TLDs).
# Checked with endswith() so "shop.example.com" is NOT blocked by ".example".
_BLOCKED_DOMAIN_SUFFIXES = (
    ".local",
    ".internal",
    ".corp",
    ".example",
    ".test",
    ".invalid",
    ".localhost",
    ".lan",
    ".intranet",
    ".private",
)


def normalize_shop_domain(raw: str) -> str:
    """Normalise a raw shop domain input to a clean lowercase hostname.

    Strips ``https://``, ``http://``, trailing slashes, and leading/
    trailing whitespace.  Converts to lowercase.  Does NOT validate
    format — call :func:`validate_shop_domain` for that.

    Args:
        raw: Raw user input, e.g. ``"https://mystore.myshopify.com/"``

    Returns:
        Normalised domain string, e.g. ``"mystore.myshopify.com"``
    """
    domain = raw.strip().lower()
    for prefix in ("https://", "http://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    domain = domain.rstrip("/")
    return domain


def validate_shop_domain(domain: str) -> None:
    """Validate a normalised shop domain for use as a Shopify Admin API host.

    Raises:
        ValueError: If the domain is invalid, private, or blocked.
    """
    if not domain:
        raise ValueError("shop_domain must not be empty.")

    # Block private/local/reserved IP-range substrings.
    for blocked in _BLOCKED_DOMAIN_SUBSTRINGS:
        if blocked in domain:
            raise ValueError(
                f"shop_domain {domain!r} is not a valid public Shopify domain. "
                "Private, local, and internal addresses are not allowed."
            )

    # Block private/reserved TLD suffixes (endswith so that e.g.
    # "shop.example.com" is NOT blocked by the ".example" suffix rule).
    for suffix in _BLOCKED_DOMAIN_SUFFIXES:
        if domain.endswith(suffix):
            raise ValueError(
                f"shop_domain {domain!r} is not a valid public Shopify domain. "
                "Private, local, and internal addresses are not allowed."
            )

    # Accept *.myshopify.com or a general valid custom domain.
    if _MYSHOPIFY_RE.match(domain) or _CUSTOM_DOMAIN_RE.match(domain):
        return

    raise ValueError(
        f"shop_domain {domain!r} does not appear to be a valid Shopify store domain. "
        "Expected format: 'mystore.myshopify.com' or a valid custom domain."
    )


class ShopifyConnector(BaseConnector):
    """Read-only Shopify configuration connector.

    Authenticates using a Shopify Admin API access token (private/custom app).

    SECURITY:
        - The access token is passed in credentials["shopify_access_token"].
        - It is NEVER logged, NEVER returned to the frontend, and NEVER
          stored except in encrypted form in the database.
        - Customer data, orders, transactions, and payment data are NEVER
          fetched.
    """

    def _base_url(self, credentials: dict) -> str:
        """Construct the Admin API base URL from credentials."""
        domain = normalize_shop_domain(credentials.get("shop_domain", ""))
        return f"https://{domain}/admin/api/{_API_VERSION}"

    def _auth_headers(self, credentials: dict) -> dict:
        """Build authentication headers.

        SECURITY: The access token is NEVER logged.
        """
        return {
            "X-Shopify-Access-Token": credentials["shopify_access_token"],
            "Content-Type": "application/json",
        }

    def _get(self, credentials: dict, path: str, params: dict | None = None) -> Any:
        """Make an authenticated GET to the Shopify Admin API with retry/back-off.

        HTTP status handling
        --------------------
        - 401  → ``AuthenticationError`` (token revoked or invalid)
        - 402  → ``ConnectorError`` (shop requires payment — suspended/frozen)
        - 403  → ``ConnectorError(status_code=403)`` (insufficient permissions)
        - 423  → ``ConnectorError`` (shop is locked)
        - 429  → ``RateLimitError`` with Retry-After honoured
        - 5xx  → ``ConnectorError`` (retried)
        - net  → ``NetworkError``

        SECURITY: The access token is NEVER written to any log line.
        """
        logger.debug("shopify._get path=%s", path)

        base = self._base_url(credentials)
        url = f"{base}{path}"
        headers = self._auth_headers(credentials)
        last_exc: Exception | None = None

        for attempt in range(_MAX_RETRIES):
            try:
                resp = httpx.get(
                    url,
                    params=params,
                    headers=headers,
                    timeout=_TIMEOUT,
                )
            except httpx.TimeoutException as exc:
                last_exc = exc
                if attempt < _MAX_RETRIES - 1:
                    time.sleep(_RETRY_BACKOFF[attempt])
                    continue
                raise NetworkError(
                    f"Shopify API timed out after {_TIMEOUT}s for {path}"
                ) from exc
            except httpx.RequestError as exc:
                last_exc = exc
                if attempt < _MAX_RETRIES - 1:
                    time.sleep(_RETRY_BACKOFF[attempt])
                    continue
                raise NetworkError(
                    f"Network error reaching Shopify API: {exc}"
                ) from exc

            # ── 429: rate limited ─────────────────────────────────────────────
            if resp.status_code == 429:
                retry_after = float(resp.headers.get("Retry-After", _RETRY_BACKOFF[attempt]))
                logger.warning(
                    "shopify._get: rate limited  path=%s  retry_after=%.1fs",
                    path,
                    retry_after,
                )
                if attempt < _MAX_RETRIES - 1:
                    time.sleep(retry_after)
                    continue
                raise RateLimitError(
                    f"Shopify API rate limit hit for {path}. Retry after {retry_after}s."
                )

            # ── 401: token invalid or revoked ─────────────────────────────────
            if resp.status_code == 401:
                raise AuthenticationError(
                    "Shopify Admin API authentication failed: the access token is "
                    "invalid, revoked, or was issued for a different shop. "
                    "Check that the token value is correct and belongs to this store.",
                    status_code=401,
                )

            # ── 402: shop requires payment (suspended/frozen) ─────────────────
            if resp.status_code == 402:
                raise ConnectorError(
                    "Shopify returned 402: the shop requires payment or is frozen. "
                    "Restore the shop subscription to resume syncing.",
                    status_code=402,
                )

            # ── 403: insufficient scopes ──────────────────────────────────────
            if resp.status_code == 403:
                raise ConnectorError(
                    f"Shopify returned 403 for {path}: the access token lacks the "
                    "required permission for this endpoint. "
                    "Ensure the custom app has the necessary read-only scopes.",
                    status_code=403,
                )

            # ── 404: shop not found (custom domain mismatch, etc.) ────────────
            if resp.status_code == 404:
                raise ConnectorError(
                    f"Shopify returned 404 for {path}: the resource was not found. "
                    "Verify the shop domain is correct.",
                    status_code=404,
                )

            # ── 423: shop locked ──────────────────────────────────────────────
            if resp.status_code == 423:
                raise ConnectorError(
                    "Shopify returned 423: the shop is locked. "
                    "The shop may have violated Shopify's Terms of Service.",
                    status_code=423,
                )

            # ── 5xx: server error ─────────────────────────────────────────────
            if resp.status_code >= 500:
                logger.warning(
                    "shopify._get: server error  path=%s  status=%d  attempt=%d",
                    path,
                    resp.status_code,
                    attempt + 1,
                )
                if attempt < _MAX_RETRIES - 1:
                    time.sleep(_RETRY_BACKOFF[attempt])
                    continue
                raise ConnectorError(
                    f"Shopify API returned HTTP {resp.status_code} for {path} "
                    f"after {_MAX_RETRIES} attempts.",
                    status_code=resp.status_code,
                )

            if not resp.is_success:
                try:
                    body = resp.json()
                    errors = body.get("errors") or body.get("error") or resp.text
                    detail = str(errors)
                except Exception:
                    detail = resp.text
                raise ConnectorError(
                    f"Shopify API returned HTTP {resp.status_code} for {path}: {detail}",
                    status_code=resp.status_code,
                )

            try:
                return resp.json()
            except Exception as exc:
                raise ConnectorError(
                    f"Shopify API returned non-JSON for {path}: {exc}",
                    status_code=resp.status_code,
                ) from exc

        raise NetworkError(f"Shopify API request failed after {_MAX_RETRIES} retries.")

    # ── Helpers ────────────────────────────────────────────────────────────────

    @staticmethod
    def _hash(value: str, length: int = 16) -> str:
        """Return a hex-encoded SHA-256 hash prefix of *value*."""
        return hashlib.sha256(value.encode("utf-8")).hexdigest()[:length]

    @staticmethod
    def _decompose_webhook_url(url: str) -> dict:
        """Decompose a webhook delivery URL into safe components.

        The full URL is intentionally NOT returned.  Only the domain,
        scheme, and a non-reversible path hash are exposed.

        SECURITY: Full webhook URLs may contain embedded secrets or tokens
        in the path.  We store only the domain and a hash.

        Returns:
            dict with keys: endpoint_domain, endpoint_scheme,
                            endpoint_path_hash, endpoint_path_length, is_https
        """
        try:
            parsed = urlparse(url)
            domain = parsed.hostname or ""
            scheme = parsed.scheme or "https"
            path = parsed.path or "/"
            path_hash = hashlib.sha256(url.encode("utf-8")).hexdigest()[:24]
            path_length = len(path.encode("utf-8"))
        except Exception:
            domain = ""
            scheme = "https"
            path_hash = ShopifyConnector._hash(url)
            path_length = len(url.encode("utf-8"))

        return {
            "endpoint_domain":      domain,
            "endpoint_scheme":      scheme,
            "endpoint_path_hash":   path_hash,
            "endpoint_path_length": path_length,
            "is_https":             scheme.lower() == "https",
        }

    # ── Fetch helpers ──────────────────────────────────────────────────────────

    def _fetch_access_scopes(self, credentials: dict) -> dict | None:
        """Fetch GET /admin/oauth/access_scopes.json — M57.9.

        Returns a single ``shopify_app_scope_summary`` aggregate record
        summarising the OAuth scopes granted to the access token.

        Returns None when the endpoint is inaccessible (403) — the token
        may be a legacy private-app token that does not expose this endpoint.

        SECURITY
        --------
        - Scope names (e.g. "read_orders", "write_products") are permission
          labels — they are NOT customer data, order data, or payment data.
        - No customer PII, order data, or financial data is fetched.
        - The access token itself is NEVER read or stored.
        """
        # Note: access_scopes endpoint is relative to the shop root, not the
        # versioned API path, so we build the URL directly.
        base_domain = normalize_shop_domain(credentials.get("shop_domain", ""))
        url_path = "/oauth/access_scopes.json"
        url = f"https://{base_domain}/admin{url_path}"
        headers = self._auth_headers(credentials)

        try:
            resp = httpx.get(url, headers=headers, timeout=_TIMEOUT)
        except Exception as exc:
            logger.info(
                "shopify: access_scopes fetch failed (%s) — skipping",
                type(exc).__name__,
            )
            return None

        if resp.status_code == 403:
            logger.info(
                "shopify: /admin/oauth/access_scopes.json returned 403 "
                "(legacy token or insufficient scope) — skipping"
            )
            return None

        if not resp.is_success:
            logger.info(
                "shopify: /admin/oauth/access_scopes.json returned %d — skipping",
                resp.status_code,
            )
            return None

        try:
            data = resp.json()
        except Exception:
            return None

        raw_scopes: list[dict] = data.get("access_scopes") or []
        if not isinstance(raw_scopes, list):
            raw_scopes = []

        # Extract scope handle strings
        scope_names: list[str] = sorted(
            s["handle"]
            for s in raw_scopes
            if isinstance(s, dict) and s.get("handle")
        )

        scope_count = len(scope_names)
        write_scope_count = sum(1 for s in scope_names if s.startswith("write_"))
        sensitive_scope_count = sum(1 for s in scope_names if s in SENSITIVE_SHOPIFY_SCOPES)

        customer_scope_present = any("customer" in s for s in scope_names)
        order_scope_present = any("order" in s for s in scope_names)
        payment_scope_present = any(
            kw in s for s in scope_names
            for kw in ("payment", "financial", "shopify_payments")
        )

        scope_hash = self._hash(",".join(scope_names))

        shop_domain = base_domain

        return {
            "record_type": SHOPIFY_APP_SCOPE_SUMMARY,
            "record_id":   f"{shop_domain}:app_scopes",
            "name":        f"app scopes ({shop_domain})",
            "scope_count":            scope_count,
            "write_scope_count":      write_scope_count,
            "sensitive_scope_count":  sensitive_scope_count,
            "customer_scope_present": customer_scope_present,
            "order_scope_present":    order_scope_present,
            "payment_scope_present":  payment_scope_present,
            "scope_hash":             scope_hash,
            "scope_names":            scope_names,
        }

    def _fetch_shop_metadata(self, credentials: dict) -> dict | None:
        """Fetch GET /admin/api/{version}/shop.json and normalise.

        Returns None on 403 (missing read_config or equivalent scope).

        SECURITY: Owner email, phone, billing details, and address are
        intentionally excluded even if present in the API response.
        """
        try:
            data = self._get(credentials, "/shop.json")
        except ConnectorError as exc:
            if exc.status_code == 403:
                logger.info(
                    "shopify: /shop.json not accessible (token lacks read scope) — "
                    "shopify_shop_metadata omitted"
                )
                return None
            raise

        shop = data.get("shop") or {}
        domain = shop.get("domain") or shop.get("myshopify_domain") or credentials.get("shop_domain", "")
        shop_id = shop.get("id")
        shop_id_hash = self._hash(str(shop_id)) if shop_id else domain

        return {
            "record_type": SHOPIFY_SHOP_METADATA,
            "record_id":   shop_id_hash,
            "name":        domain,
            # Identity
            "shop_domain":  domain,
            "shop_name":    shop.get("name"),
            # Plan
            "plan_name":         shop.get("plan_name"),
            "plan_display_name": shop.get("plan_display_name"),
            # Regional
            "timezone":       shop.get("timezone"),
            "iana_timezone":  shop.get("iana_timezone"),
            "currency":       shop.get("currency"),
            "primary_locale": shop.get("primary_locale"),
            "country_code":   shop.get("country_code"),
            # Flags
            "password_enabled":                    shop.get("password_enabled"),
            "checkout_api_supported":              shop.get("checkout_api_supported"),
            "has_storefront":                      shop.get("has_storefront"),
            "eligible_for_payments":               shop.get("eligible_for_payments"),
            "requires_extra_payments_agreement":   shop.get("requires_extra_payments_agreement"),
            "taxes_included":                      shop.get("taxes_included"),
            "tax_shipping":                        shop.get("tax_shipping"),
            # SECURITY: the following fields are intentionally EXCLUDED:
            #   email, customer_email, phone, address1, address2, city,
            #   zip, province, country, owner, billing_* fields, money_format
        }

    def _fetch_webhook_subscriptions(self, credentials: dict) -> list[dict]:
        """Fetch GET /admin/api/{version}/webhooks.json and normalise.

        Returns an empty list if the token lacks permission (403).

        SECURITY: Full delivery URLs are decomposed into domain + path hash.
        The raw URL is intentionally NOT stored.
        """
        try:
            data = self._get(credentials, "/webhooks.json", params={"limit": 250})
        except ConnectorError as exc:
            if exc.status_code == 403:
                logger.info(
                    "shopify: /webhooks.json not accessible (token lacks scope) — "
                    "shopify_webhook_subscription records omitted"
                )
                return []
            raise

        webhooks = data.get("webhooks") or []
        records = []
        for wh in webhooks:
            wh_id = wh.get("id")
            wh_id_hash = self._hash(str(wh_id)) if wh_id else self._hash(str(wh))
            topic = wh.get("topic", "")
            # SECURITY: decompose URL, do not store raw
            url = wh.get("address", "")
            url_parts = self._decompose_webhook_url(url)
            display = f"{topic} → {url_parts['endpoint_domain']}"
            records.append(
                {
                    "record_type":    SHOPIFY_WEBHOOK_SUBSCRIPTION,
                    "record_id":      wh_id_hash,
                    "name":           display,
                    "webhook_id_hash": wh_id_hash,
                    "topic":          topic,
                    **url_parts,
                    "format":      wh.get("format"),
                    "api_version": wh.get("api_version"),
                    "created_at":  wh.get("created_at"),
                    "updated_at":  wh.get("updated_at"),
                }
            )
        return records

    def _fetch_store_policies(self, credentials: dict) -> list[dict]:
        """Fetch GET /admin/api/{version}/policies.json and normalise.

        Returns an empty list if the endpoint is inaccessible (403).

        SECURITY: Raw policy body text is NEVER stored.  Only the policy
        type, presence flag, and a SHA-256 hash of the body are kept.
        """
        try:
            data = self._get(credentials, "/policies.json")
        except ConnectorError as exc:
            if exc.status_code in (403, 404):
                logger.info(
                    "shopify: /policies.json not accessible (status=%d) — "
                    "shopify_store_policy records omitted",
                    exc.status_code,
                )
                return []
            raise

        policies = data.get("policies") or []
        shop_domain = credentials.get("shop_domain", "")
        records = []
        for policy in policies:
            policy_type = policy.get("handle") or policy.get("title", "").lower().replace(" ", "_")
            body = policy.get("body") or ""
            body_bytes = body.encode("utf-8")
            body_hash = hashlib.sha256(body_bytes).hexdigest() if body else None
            record_id = self._hash(f"{shop_domain}:{policy_type}")
            records.append(
                {
                    "record_type":  SHOPIFY_STORE_POLICY,
                    "record_id":    record_id,
                    "name":         f"{policy_type} policy",
                    "policy_type":  policy_type,
                    "present":      bool(body.strip()),
                    "body_hash":    body_hash,
                    "body_length":  len(body_bytes),
                    "updated_at":   policy.get("updated_at"),
                    # SECURITY: raw body text is intentionally NOT stored
                }
            )
        return records

    # ── Public interface ───────────────────────────────────────────────────────

    def fetch(self, credentials: dict) -> list[dict]:
        """Fetch all accessible Shopify configuration records.

        Surfaces that are inaccessible due to missing token scopes are
        skipped gracefully — remaining surfaces are still returned.

        Returns
        -------
        Flat list of normalised records.

        Raises
        ------
        AuthenticationError  — token is invalid or revoked (HTTP 401).
        ConnectorError       — unexpected API error.
        RateLimitError       — rate limit hit after all retries.
        NetworkError         — network / timeout failure.

        SECURITY: credentials["shopify_access_token"] is NEVER logged.
        """
        # SECURITY: do not log credentials["shopify_access_token"].
        logger.info("ShopifyConnector.fetch: starting")

        records: list[dict] = []

        # 1. Shop metadata — core surface.
        shop_record = self._fetch_shop_metadata(credentials)
        if shop_record is not None:
            records.append(shop_record)
            logger.info("ShopifyConnector.fetch: shop_metadata fetched")
        else:
            logger.info("ShopifyConnector.fetch: shop_metadata skipped")

        # 2. Webhook subscriptions.
        webhook_records = self._fetch_webhook_subscriptions(credentials)
        records.extend(webhook_records)
        logger.info(
            "ShopifyConnector.fetch: webhook_subscriptions fetched count=%d",
            len(webhook_records),
        )

        # 3. Store policies.
        policy_records = self._fetch_store_policies(credentials)
        records.extend(policy_records)
        logger.info(
            "ShopifyConnector.fetch: store_policies fetched count=%d",
            len(policy_records),
        )

        # 4. App scope summary — M57.9 (optional: skipped on 403 or legacy token).
        scope_record = self._fetch_access_scopes(credentials)
        if scope_record is not None:
            records.append(scope_record)
            logger.info("ShopifyConnector.fetch: app_scope_summary fetched")
        else:
            logger.info("ShopifyConnector.fetch: app_scope_summary skipped")

        logger.info(
            "ShopifyConnector.fetch: complete total_records=%d",
            len(records),
        )
        return records

    def validate_credentials(self, credentials: dict) -> bool:
        """Validate Shopify credentials via GET /admin/api/{version}/shop.json.

        Returns True on success.

        Raises
        ------
        ValueError           — shop_domain is invalid or blocked.
        AuthenticationError  — access token is invalid (HTTP 401).
        ConnectorError       — API error (403 = insufficient scopes).
        NetworkError         — network / timeout failure.

        SECURITY: The access token is NEVER logged.
        """
        # SECURITY: do not log credentials["shopify_access_token"].
        domain = normalize_shop_domain(credentials.get("shop_domain", ""))
        validate_shop_domain(domain)

        logger.info(
            "ShopifyConnector.validate_credentials: probing shop=%s",
            domain,
        )

        # Probe with the shop metadata endpoint (safe, low-privilege).
        self._get(credentials, "/shop.json")
        logger.info("ShopifyConnector.validate_credentials: success shop=%s", domain)
        return None
