"""SendGrid drift connector — M80A.

Snapshots safe configuration metadata from the SendGrid v3 REST API:
  - Account type and reputation
  - API key metadata (never the key value)
  - Verified sender identities (email domain only — never full addresses)
  - Domain authentication status and DNS record count
  - Mail settings (boolean flags only)
  - Tracking settings (boolean flags only)
  - Event webhook configuration (boolean flags only — never the URL)
  - Suppression group count

Authentication: Bearer token (api_key) via Authorization header.

PRIVACY / SECURITY — what is NEVER stored or logged
-----------------------------------------------------
- API key value or secret — only the api_key_id identifier is stored.
- Authorization headers or bearer tokens of any kind.
- Full email addresses — only the domain part (after @) is stored.
- Recipient email addresses, suppression lists, or contact data.
- Template HTML, plaintext, subject lines, or any email content.
- Webhook URL strings — stored as a boolean presence flag only.
- Raw DNS record values (CNAME targets, DKIM keys) — count only.
- Mail event payloads, click/open event data, or tracking data at
  the individual-recipient level.
- Marketing contact data, campaign content, or list membership.
- Raw SendGrid API response dicts.
- Raw HTTP request or response bodies.
- Customer PII of any kind.

Records fetched (M80A)
-----------------------
SENDGRID_ACCOUNT
    Safe fields: account_type, reputation.

SENDGRID_API_KEY
    Safe fields: api_key_id, name (truncated), scopes_count,
    has_mail_send, has_full_access. Key value NEVER stored.

SENDGRID_SENDER_IDENTITY
    Safe fields: sender_id, nickname, from_email_domain, reply_to_domain,
    verified, locked. Full email addresses NEVER stored.

SENDGRID_DOMAIN_AUTHENTICATION
    Safe fields: domain_id, domain, valid, automatic_security, default,
    legacy, dns_record_count. Raw DNS values NEVER stored.

SENDGRID_MAIL_SETTINGS
    Safe fields: boolean flag per mail feature.

SENDGRID_TRACKING_SETTINGS
    Safe fields: boolean flag per tracking feature.

SENDGRID_WEBHOOK_SETTINGS
    Safe fields: event_webhook_enabled, event_webhook_has_url (bool),
    event_webhook_signed, event_count. URL NEVER stored.

SENDGRID_SUPPRESSION_SETTINGS
    Safe fields: suppression_group_count. No recipient data stored.

Auth / credentials dict
-----------------------
    api_key : str — SendGrid API key. NEVER logged, stored in records,
                    or included in error messages.

The api_key is used only as the HTTP Bearer token for in-flight API
requests via the Authorization header. It is never written to any
normalised record, never passed to log statements, and never stored on
the connector instance.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

import httpx

from app.connectors.base import BaseConnector
from app.connectors.exceptions import (
    AuthenticationError,
    ConnectorError,
    NetworkError,
    RateLimitError,
)
from app.connectors.sendgrid_schema import (
    SENDGRID_ACCOUNT,
    SENDGRID_API_KEY,
    SENDGRID_DOMAIN_AUTHENTICATION,
    SENDGRID_MAIL_SETTINGS,
    SENDGRID_SENDER_IDENTITY,
    SENDGRID_SUPPRESSION_SETTINGS,
    SENDGRID_TRACKING_SETTINGS,
    SENDGRID_WEBHOOK_SETTINGS,
)

logger = logging.getLogger(__name__)

# ── Module-level constants ─────────────────────────────────────────────────────

_SENDGRID_BASE = "https://api.sendgrid.com"
_TIMEOUT = 30.0
_MAX_PAGES = 10
_PAGE_SIZE = 100
_MAX_STR_LEN = 100

# Per-surface record caps.
_MAX_API_KEYS = 200
_MAX_SENDERS = 200
_MAX_DOMAINS = 100


# ── String safety helpers ──────────────────────────────────────────────────────


def _trunc(value: Any, length: int = _MAX_STR_LEN) -> str:
    if isinstance(value, str):
        return value[:length]
    return ""


def _bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return bool(value)
    if isinstance(value, str):
        return value.lower() in ("true", "1", "yes")
    return False


def _email_domain(email: Any) -> str:
    """Extract the domain part from an email address.

    Returns the portion after @ (lowercased), or "" if the input is not a
    valid email-shaped string. Full email addresses are NEVER returned.
    """
    if not isinstance(email, str):
        return ""
    at = email.rfind("@")
    if at < 0:
        return ""
    return email[at + 1:].lower().strip()[:253]


# ── Config event type allowlist (M80D) ──────────────────────────────────────────
#
# Only safe configuration/control-plane types. Mail-delivery events
# (bounce/click/open/delivered/dropped/deferred/spamreport/unsubscribe/
# group_unsubscribe/processed/etc.) are NEVER in this set and are NEVER called
# or returned.
_SENDGRID_CONFIG_EVENT_TYPES: frozenset[str] = frozenset({
    "sendgrid.account.updated",
    "sendgrid.api_key.created",
    "sendgrid.api_key.updated",
    "sendgrid.api_key.deleted",
    "sendgrid.sender_identity.created",
    "sendgrid.sender_identity.updated",
    "sendgrid.sender_identity.verified",
    "sendgrid.sender_identity.deleted",
    "sendgrid.domain_authentication.created",
    "sendgrid.domain_authentication.updated",
    "sendgrid.domain_authentication.deleted",
    "sendgrid.mail_settings.updated",
    "sendgrid.tracking_settings.updated",
    "sendgrid.event_webhook.updated",
    "sendgrid.inbound_parse.updated",
    "sendgrid.suppression_settings.updated",
    "sendgrid.config.event",
})


# ── Connector ──────────────────────────────────────────────────────────────────


class SendGridConnector(BaseConnector):
    """SendGrid v3 REST connector for ConfigTrace drift tracking (M80A).

    Stateless: credentials are passed at call time; nothing is stored on
    the instance between calls. An httpx.Client is constructed per call
    with Bearer auth and torn down after the call completes.

    SECURITY: api_key is NEVER stored as an instance attribute, NEVER
    logged, NEVER included in error messages, and NEVER written to any
    normalised record.
    """

    # ── HTTP client helpers ────────────────────────────────────────────────────

    @staticmethod
    def _make_client(api_key: str) -> httpx.Client:
        """Construct an httpx.Client with Bearer auth for SendGrid.

        SECURITY: api_key is placed in the Authorization header only.
        It is never stored on the connector instance or logged.
        """
        return httpx.Client(
            base_url=_SENDGRID_BASE,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            timeout=_TIMEOUT,
        )

    @staticmethod
    def _raise_for_status(resp: httpx.Response, context: str = "") -> None:
        """Map SendGrid HTTP error codes to connector exceptions.

        Raises:
            AuthenticationError: HTTP 401.
            ConnectorError: HTTP 403, 404, 422, other 4xx, or 5xx.
            RateLimitError: HTTP 429 (Retry-After surfaced when present).
        """
        if resp.status_code < 400:
            return
        if resp.status_code == 401:
            raise AuthenticationError(
                f"sendgrid: 401 Unauthorized{' — ' + context if context else ''}",
                status_code=401,
            )
        if resp.status_code == 429:
            retry_after: Optional[float] = None
            try:
                retry_after = float(resp.headers.get("Retry-After", ""))
            except (ValueError, TypeError):
                retry_after = None
            raise RateLimitError(
                "sendgrid: rate limit hit (429)",
                retry_after=retry_after,
            )
        if resp.status_code in (403, 404, 422):
            raise ConnectorError(
                f"sendgrid: HTTP {resp.status_code}"
                f"{' — ' + context if context else ''}",
                status_code=resp.status_code,
            )
        if resp.status_code >= 500:
            raise ConnectorError(
                f"sendgrid: server error HTTP {resp.status_code}"
                f"{' — ' + context if context else ''}",
                status_code=resp.status_code,
            )
        if resp.status_code >= 400:
            raise ConnectorError(
                f"sendgrid: HTTP {resp.status_code}"
                f"{' — ' + context if context else ''}",
                status_code=resp.status_code,
            )

    @staticmethod
    def _get(
        client: httpx.Client,
        path: str,
        params: Optional[dict] = None,
    ) -> Any:
        """Perform a single authenticated GET and return parsed JSON.

        Raises:
            AuthenticationError: HTTP 401.
            ConnectorError: HTTP 4xx/5xx or JSON parse error.
            RateLimitError: HTTP 429.
            NetworkError: Transport-level failure.
        """
        try:
            resp = client.get(path, params=params)
        except httpx.ConnectError as exc:
            raise NetworkError(
                f"sendgrid: GET network error for {path[:200]}: {exc}"
            ) from exc
        except httpx.TimeoutException as exc:
            raise NetworkError(
                f"sendgrid: GET timed out for {path[:200]}"
            ) from exc
        except httpx.HTTPError as exc:
            raise NetworkError(f"sendgrid: GET request error: {exc}") from exc

        SendGridConnector._raise_for_status(resp, context=path[:200])

        try:
            return resp.json()
        except ValueError as exc:
            raise ConnectorError(
                "sendgrid: response was not valid JSON"
            ) from exc

    # ── Paginated list helper ──────────────────────────────────────────────────

    @staticmethod
    def _paginate_offset(
        client: httpx.Client,
        path: str,
        items_key: Optional[str],
        max_records: int,
        page_size: int = _PAGE_SIZE,
    ) -> list[Any]:
        """Fetch all pages using limit+offset pagination, bounded to _MAX_PAGES.

        Handles both array-root responses (items_key=None) and object
        responses with a named result list (items_key="result"|"results").
        """
        items: list[Any] = []
        offset = 0
        page = 0

        while page < _MAX_PAGES and len(items) < max_records:
            params = {"limit": page_size, "offset": offset}
            data = SendGridConnector._get(client, path, params=params)
            page += 1

            if items_key:
                batch = data.get(items_key, []) if isinstance(data, dict) else []
            else:
                batch = data if isinstance(data, list) else []

            if not isinstance(batch, list) or not batch:
                break

            items.extend(batch)
            if len(batch) < page_size:
                break
            offset += len(batch)

        if page >= _MAX_PAGES:
            logger.info(
                "sendgrid: pagination cap (%d pages) reached for %s; "
                "remaining pages skipped",
                _MAX_PAGES,
                path[:200],
            )

        return items[:max_records]

    # ── Credential validation ──────────────────────────────────────────────────

    def validate_credentials(self, credentials: dict) -> bool:
        """Validate credentials with a lightweight account check.

        Makes a single GET to /v3/user/account to confirm the API key is
        valid. Returns True on success.

        Raises:
            AuthenticationError: API key is invalid.
            ConnectorError: Unexpected API error.
            RateLimitError: Rate limit hit.
            NetworkError: Transport failure.
        """
        api_key = credentials.get("api_key", "")
        if not isinstance(api_key, str) or not api_key:
            raise AuthenticationError(
                "sendgrid: 'api_key' credential is required"
            )
        with self._make_client(api_key) as client:
            self._get(client, "/v3/user/account")
        return True

    # ── Surface normalizers ────────────────────────────────────────────────────

    @staticmethod
    def _normalize_account(
        account_data: dict,
    ) -> dict:
        """Normalise SendGrid account data into a safe record.

        SECURITY: owner email, billing info, and all PII are NEVER stored.
        Only account_type and reputation (metadata fields) are kept.
        """
        account_type = _trunc(account_data.get("type") or "unknown")
        if account_type not in ("free", "paid", "trusted"):
            account_type = account_type or "unknown"

        reputation = account_data.get("reputation")
        if isinstance(reputation, (int, float)):
            reputation = float(reputation)
        else:
            reputation = None

        return {
            "record_type": SENDGRID_ACCOUNT,
            "record_id": "sendgrid_account_main",
            "provider_resource_id": "accounts/main",
            "account_type": account_type,
            "reputation": reputation,
        }

    @staticmethod
    def _normalize_api_key(raw: dict) -> Optional[dict]:
        """Normalise a single API key entry into a safe record.

        SECURITY: the API key value/secret is NEVER stored — only the
        opaque api_key_id, human-readable name, and scope metadata.
        """
        api_key_id = _trunc(raw.get("api_key_id") or "", length=200)
        if not api_key_id:
            return None

        name = _trunc(raw.get("name") or "")
        scopes = raw.get("scopes") or []
        if not isinstance(scopes, list):
            scopes = []

        scopes_count = len(scopes)
        has_mail_send = "mail.send" in scopes

        # Broad admin scope detection — "2022-02-01" style or legacy names
        _BROAD_SCOPE_PATTERNS = (
            "admin", "full", "sender_verification_eligible",
        )
        has_full_access = any(
            any(pat in str(s).lower() for pat in _BROAD_SCOPE_PATTERNS)
            for s in scopes
        )

        return {
            "record_type": SENDGRID_API_KEY,
            "record_id": api_key_id,
            "provider_resource_id": f"api_keys/{api_key_id}",
            "api_key_id": api_key_id,
            "name": name,
            "scopes_count": scopes_count,
            "has_mail_send": has_mail_send,
            "has_full_access": has_full_access,
        }

    @staticmethod
    def _normalize_sender_identity(raw: dict) -> Optional[dict]:
        """Normalise a verified sender identity into a safe record.

        SECURITY: full email addresses, names, postal addresses, city,
        state, country, zip, and phone are NEVER stored. Only the domain
        part of email fields is stored.
        """
        sender_id = raw.get("id")
        if sender_id is None:
            return None
        sender_id_str = str(sender_id)

        nickname = _trunc(raw.get("nickname") or "")
        from_email_domain = _email_domain(raw.get("from_email") or "")
        reply_to_domain = _email_domain(raw.get("reply_to") or "")
        verified = _bool(raw.get("verified"))
        locked = _bool(raw.get("locked"))

        return {
            "record_type": SENDGRID_SENDER_IDENTITY,
            "record_id": sender_id_str,
            "provider_resource_id": f"verified_senders/{sender_id_str}",
            "sender_id": sender_id_str,
            "nickname": nickname,
            "from_email_domain": from_email_domain,
            "reply_to_domain": reply_to_domain,
            "verified": verified,
            "locked": locked,
        }

    @staticmethod
    def _normalize_domain_auth(raw: dict) -> Optional[dict]:
        """Normalise a domain authentication entry into a safe record.

        SECURITY: raw DNS record values (CNAME targets, DKIM public keys),
        usernames, and subdomain strings are NEVER stored. Only the domain
        name, validity, and DNS record count are kept.
        """
        domain_id = raw.get("id")
        if domain_id is None:
            return None
        domain_id_str = str(domain_id)

        domain = _trunc(raw.get("domain") or "", length=253)
        valid = _bool(raw.get("valid"))
        automatic_security = _bool(raw.get("automatic_security"))
        default = _bool(raw.get("default"))
        legacy = _bool(raw.get("legacy"))

        # Count DNS records without storing values.
        dns = raw.get("dns") or {}
        if isinstance(dns, dict):
            dns_record_count = len(dns)
        else:
            dns_record_count = 0

        return {
            "record_type": SENDGRID_DOMAIN_AUTHENTICATION,
            "record_id": domain_id_str,
            "provider_resource_id": f"whitelabel/domains/{domain_id_str}",
            "domain_id": domain_id_str,
            "domain": domain,
            "valid": valid,
            "automatic_security": automatic_security,
            "default": default,
            "legacy": legacy,
            "dns_record_count": dns_record_count,
        }

    @staticmethod
    def _normalize_mail_settings(raw: Any) -> dict:
        """Normalise mail settings into safe boolean flags.

        SECURITY: BCC email addresses, footer text, address whitelist
        entries, and all email-content fields are NEVER stored.
        """
        # SendGrid returns a list or a dict with a "result" list.
        settings: dict[str, bool] = {}
        items = (
            raw.get("result", []) if isinstance(raw, dict)
            else raw if isinstance(raw, list)
            else []
        )
        for item in items:
            if not isinstance(item, dict):
                continue
            name = item.get("name") or ""
            enabled = _bool(item.get("enabled"))
            if isinstance(name, str) and name:
                settings[name] = enabled

        return {
            "record_type": SENDGRID_MAIL_SETTINGS,
            "record_id": "sendgrid_mail_settings_main",
            "provider_resource_id": "mail_settings/main",
            "bcc_enabled": settings.get("bcc", False),
            "bounce_purge_enabled": settings.get("bounce_purge", False),
            "footer_enabled": settings.get("footer", False),
            "forward_bounce_enabled": settings.get("forward_bounce", False),
            "forward_spam_enabled": settings.get("forward_spam", False),
            "sandbox_mode_enabled": settings.get("sandbox_mode", False),
            "spam_check_enabled": settings.get("spam_check", False),
            # M80C: template engine feature flag (boolean only — no template content).
            "template_enabled": settings.get("template", False),
        }

    @staticmethod
    def _normalize_tracking_settings(raw: Any) -> dict:
        """Normalise tracking settings into safe boolean flags.

        SECURITY: unsubscribe URLs, Google Analytics parameters, and
        all recipient-level tracking data are NEVER stored.
        """
        settings: dict[str, bool] = {}
        items = (
            raw.get("result", []) if isinstance(raw, dict)
            else raw if isinstance(raw, list)
            else []
        )
        for item in items:
            if not isinstance(item, dict):
                continue
            name = item.get("name") or ""
            enabled = _bool(item.get("enabled"))
            if isinstance(name, str) and name:
                settings[name] = enabled

        return {
            "record_type": SENDGRID_TRACKING_SETTINGS,
            "record_id": "sendgrid_tracking_settings_main",
            "provider_resource_id": "tracking_settings/main",
            "click_tracking_enabled": settings.get("click_tracking", False),
            "open_tracking_enabled": settings.get("open_tracking", False),
            "subscription_tracking_enabled": settings.get(
                "subscription_tracking", False
            ),
            "ganalytics_enabled": settings.get("ganalytics", False),
        }

    @staticmethod
    def _normalize_webhook_settings(raw: dict, parse_configs: Optional[list] = None) -> dict:
        """Normalise event webhook + inbound parse settings into safe boolean flags.

        SECURITY: the webhook URL string is NEVER stored — only a boolean
        indicating whether a URL is configured. Webhook signing secrets and
        OAuth credentials are NEVER stored. Raw event payloads are NEVER stored.
        Inbound parse hostnames, URLs, email bodies, and payload content are
        NEVER stored — only safe booleans are extracted.

        Args:
            raw: event webhook settings dict from /v3/user/webhooks/event/settings.
            parse_configs: list of dicts from /v3/user/webhooks/parse/settings result.
        """
        if not isinstance(raw, dict):
            raw = {}

        enabled = _bool(raw.get("enabled"))
        url = raw.get("url") or ""
        event_webhook_has_url = isinstance(url, str) and bool(url.strip())

        # signed: OAuth client id present → signed webhooks enabled
        oauth_client_id = raw.get("oauth_client_id") or ""
        signed = bool(oauth_client_id)

        # Count enabled event types.
        _EVENT_KEYS = (
            "bounce", "click", "deferred", "delivered", "drop",
            "group_resubscribe", "group_unsubscribe", "open",
            "processed", "spam_report", "unsubscribe",
        )
        event_count = sum(1 for k in _EVENT_KEYS if _bool(raw.get(k)))

        # M80C: inbound parse — boolean extraction only.
        # SECURITY: hostname and url strings are NEVER stored.
        if parse_configs is None:
            parse_configs = []
        if not isinstance(parse_configs, list):
            parse_configs = []
        valid_configs = [c for c in parse_configs if isinstance(c, dict)]
        inbound_parse_enabled = len(valid_configs) > 0
        if valid_configs:
            first = valid_configs[0]
            inbound_parse_spam_check_enabled = _bool(first.get("spam_check", True))
            inbound_parse_send_raw_enabled = any(
                _bool(c.get("send_raw", False)) for c in valid_configs
            )
        else:
            inbound_parse_spam_check_enabled = True  # safe default when not in use
            inbound_parse_send_raw_enabled = False

        return {
            "record_type": SENDGRID_WEBHOOK_SETTINGS,
            "record_id": "sendgrid_webhook_settings_main",
            "provider_resource_id": "webhooks/event/settings/main",
            "event_webhook_enabled": enabled,
            "event_webhook_has_url": event_webhook_has_url,
            "event_webhook_signed": signed,
            "event_count": event_count,
            "inbound_parse_enabled": inbound_parse_enabled,
            "inbound_parse_spam_check_enabled": inbound_parse_spam_check_enabled,
            "inbound_parse_send_raw_enabled": inbound_parse_send_raw_enabled,
        }

    @staticmethod
    def _normalize_suppression_settings(groups: Any) -> dict:
        """Normalise suppression group data into a safe count-only record.

        SECURITY: suppressed email addresses, recipient identities, and
        suppression list contents are NEVER stored — only the group count.
        """
        if isinstance(groups, list):
            suppression_group_count = len(groups)
        elif isinstance(groups, dict):
            result = groups.get("result") or groups.get("groups") or []
            suppression_group_count = len(result) if isinstance(result, list) else 0
        else:
            suppression_group_count = 0

        return {
            "record_type": SENDGRID_SUPPRESSION_SETTINGS,
            "record_id": "sendgrid_suppression_settings_main",
            "provider_resource_id": "suppression_settings/main",
            "suppression_group_count": suppression_group_count,
        }

    # ── Surface fetchers ───────────────────────────────────────────────────────

    @staticmethod
    def _fetch_account(client: httpx.Client) -> dict:
        data = SendGridConnector._get(client, "/v3/user/account")
        if not isinstance(data, dict):
            data = {}
        return SendGridConnector._normalize_account(data)

    @staticmethod
    def _fetch_api_keys(client: httpx.Client) -> list[dict]:
        try:
            data = SendGridConnector._get(
                client, "/v3/api_keys", params={"limit": _MAX_API_KEYS}
            )
        except ConnectorError as exc:
            if exc.status_code in (403, 404):
                logger.info("sendgrid: api_keys endpoint not accessible (HTTP %s)", exc.status_code)
                return []
            raise
        keys_raw = data.get("result", []) if isinstance(data, dict) else []
        if not isinstance(keys_raw, list):
            return []
        records = []
        for raw in keys_raw[:_MAX_API_KEYS]:
            rec = SendGridConnector._normalize_api_key(raw)
            if rec is not None:
                records.append(rec)
        return records

    @staticmethod
    def _fetch_sender_identities(client: httpx.Client) -> list[dict]:
        try:
            data = SendGridConnector._get(
                client, "/v3/verified_senders", params={"limit": _PAGE_SIZE}
            )
        except ConnectorError as exc:
            if exc.status_code in (403, 404):
                logger.info("sendgrid: verified_senders not accessible (HTTP %s)", exc.status_code)
                return []
            raise
        senders_raw = (
            data.get("results") or data.get("result") or []
            if isinstance(data, dict) else
            data if isinstance(data, list) else []
        )
        if not isinstance(senders_raw, list):
            return []
        records = []
        for raw in senders_raw[:_MAX_SENDERS]:
            rec = SendGridConnector._normalize_sender_identity(raw)
            if rec is not None:
                records.append(rec)
        return records

    @staticmethod
    def _fetch_domain_authentications(client: httpx.Client) -> list[dict]:
        try:
            domains_raw = SendGridConnector._paginate_offset(
                client,
                "/v3/whitelabel/domains",
                items_key=None,
                max_records=_MAX_DOMAINS,
            )
        except ConnectorError as exc:
            if exc.status_code in (403, 404):
                logger.info("sendgrid: whitelabel/domains not accessible (HTTP %s)", exc.status_code)
                return []
            raise
        records = []
        for raw in domains_raw:
            rec = SendGridConnector._normalize_domain_auth(raw)
            if rec is not None:
                records.append(rec)
        return records

    @staticmethod
    def _fetch_mail_settings(client: httpx.Client) -> Optional[dict]:
        try:
            data = SendGridConnector._get(client, "/v3/mail_settings")
        except ConnectorError as exc:
            if exc.status_code in (403, 404):
                logger.info("sendgrid: mail_settings not accessible (HTTP %s)", exc.status_code)
                return None
            raise
        return SendGridConnector._normalize_mail_settings(data)

    @staticmethod
    def _fetch_tracking_settings(client: httpx.Client) -> Optional[dict]:
        try:
            data = SendGridConnector._get(client, "/v3/tracking_settings")
        except ConnectorError as exc:
            if exc.status_code in (403, 404):
                logger.info("sendgrid: tracking_settings not accessible (HTTP %s)", exc.status_code)
                return None
            raise
        return SendGridConnector._normalize_tracking_settings(data)

    @staticmethod
    def _fetch_webhook_settings(client: httpx.Client) -> Optional[dict]:
        try:
            data = SendGridConnector._get(
                client, "/v3/user/webhooks/event/settings"
            )
        except ConnectorError as exc:
            if exc.status_code in (403, 404):
                logger.info("sendgrid: event webhook settings not accessible (HTTP %s)", exc.status_code)
                return None
            raise

        # M80C: also fetch inbound parse settings — boolean fields only.
        # SECURITY: hostname and URL strings from parse configs NEVER stored.
        parse_configs: list = []
        try:
            parse_data = SendGridConnector._get(
                client, "/v3/user/webhooks/parse/settings"
            )
            if isinstance(parse_data, dict):
                result = parse_data.get("result") or []
                parse_configs = result if isinstance(result, list) else []
            elif isinstance(parse_data, list):
                parse_configs = parse_data
        except ConnectorError as exc:
            if exc.status_code in (403, 404):
                logger.info(
                    "sendgrid: inbound parse settings not accessible (HTTP %s)", exc.status_code
                )
            else:
                raise

        return SendGridConnector._normalize_webhook_settings(
            data if isinstance(data, dict) else {},
            parse_configs,
        )

    @staticmethod
    def _fetch_suppression_settings(client: httpx.Client) -> Optional[dict]:
        try:
            data = SendGridConnector._get(client, "/v3/asm/groups")
        except ConnectorError as exc:
            if exc.status_code in (403, 404):
                logger.info("sendgrid: asm/groups not accessible (HTTP %s)", exc.status_code)
                return None
            raise
        return SendGridConnector._normalize_suppression_settings(data)

    # ── Activity events (M80D) ──────────────────────────────────────────────────

    def list_activity_events(
        self,
        credentials: dict,
        *,
        max_events: int = 100,
        lookback_hours: int = 24,
    ) -> list[dict]:
        """Synthesize review-safe SendGrid configuration-state activity events.

        SendGrid has NO native audit/event API for configuration changes. These
        events are config-state observations synthesized from the same safe
        configuration surfaces the drift connector reads (account, API keys,
        sender identities, domain authentication, mail settings, tracking
        settings, event webhook, inbound parse, and suppression settings).

        Each event represents configuration state observed at poll time. Events
        are date-scoped (day-level) for idempotency: re-polling the same
        configuration on the same UTC day yields the same provider_event_id and
        is a safe no-op.

        CLAIM DISCIPLINE: events are configuration-state evidence for review.
        This does NOT confirm a breach, unauthorized access, or data exposure.

        PRIVACY — what is NEVER returned:
        - API key values, bearer tokens, or authorization headers.
        - Email bodies, subject lines, template content, recipient emails,
          sender personal emails, or suppression recipient emails.
        - Raw webhook URL strings, raw inbound-parse hostnames, or message IDs.
        - Mail event payloads (bounce/click/open/delivered/deferred/dropped/
          spamreport/unsubscribe/processed) — these are NEVER fetched.
        - Raw DNS record values or any customer data / PII.

        Returns only safe booleans, counts, opaque IDs, and domain names.

        Raises:
            AuthenticationError: API key is missing or invalid (HTTP 401).
            RateLimitError: Rate limit hit (HTTP 429).
            NetworkError: Transport-level failure.
        """
        from datetime import datetime, timezone

        api_key = credentials.get("api_key", "")
        if not isinstance(api_key, str) or not api_key:
            raise AuthenticationError(
                "sendgrid: 'api_key' credential is required"
            )

        max_events = min(max(1, max_events), 1000)
        lookback_hours = min(max(1, lookback_hours), 168)

        day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        events: list[dict] = []

        with self._make_client(api_key) as client:
            self._collect_account_event(client, events, day)
            self._collect_api_key_events(client, events, day)
            self._collect_sender_identity_events(client, events, day)
            self._collect_domain_auth_events(client, events, day)
            self._collect_mail_settings_event(client, events, day)
            self._collect_tracking_settings_event(client, events, day)
            self._collect_webhook_settings_event(client, events, day)
            self._collect_suppression_settings_event(client, events, day)

        return events[:max_events]

    # ── Activity surface collectors (M80D) ──────────────────────────────────────
    #
    # Each collector reuses the existing safe drift fetchers/normalizers and
    # emits at most a small, capped number of config-state events. Each fails
    # soft on 403/404 (missing permission for that surface) so one inaccessible
    # surface never aborts the whole poll. Authentication / rate-limit / network
    # errors propagate so the ingestion service can report them honestly.

    @staticmethod
    def _activity_event(event_type: str, provider_event_id: str, metadata: dict) -> dict:
        """Build one synthesized config-state activity event envelope."""
        meta = dict(metadata)
        meta.setdefault("event_source", "sendgrid_activity_event")
        meta.setdefault("event_action", event_type)
        return {
            "event_type": event_type,
            "provider": "sendgrid",
            "source": "sendgrid_activity_event",
            "event_source": "sendgrid_activity_event",
            "provider_event_id": provider_event_id,
            "metadata": meta,
        }

    def _collect_account_event(self, client: httpx.Client, events: list, day: str) -> None:
        try:
            rec = self._fetch_account(client)
        except ConnectorError as exc:
            if exc.status_code in (403, 404):
                return
            raise
        if not isinstance(rec, dict):
            return
        meta = {
            "resource_type": "account",
            "event_action": "sendgrid.account.updated",
            "operation_name": "SendGrid account configuration observed",
            "category": "account",
            "status": "observed",
        }
        events.append(
            self._activity_event(
                "sendgrid.account.updated",
                f"sg:account:main:{day}",
                meta,
            )
        )

    def _collect_api_key_events(self, client: httpx.Client, events: list, day: str) -> None:
        try:
            recs = self._fetch_api_keys(client)
        except ConnectorError as exc:
            if exc.status_code in (403, 404):
                return
            raise
        for rec in recs[:10]:
            if not isinstance(rec, dict):
                continue
            api_key_id = rec.get("api_key_id") or ""
            if not api_key_id:
                continue
            meta = {
                "resource_type": "api_key",
                "api_key_id": api_key_id,
                "resource_id": api_key_id,
                "resource_name": _trunc(rec.get("name") or ""),
                "event_action": "sendgrid.api_key.updated",
                "category": "api_key",
                "status": "observed",
            }
            events.append(
                self._activity_event(
                    "sendgrid.api_key.updated",
                    f"sg:api_key:{api_key_id}:{day}",
                    meta,
                )
            )

    def _collect_sender_identity_events(self, client: httpx.Client, events: list, day: str) -> None:
        try:
            recs = self._fetch_sender_identities(client)
        except ConnectorError as exc:
            if exc.status_code in (403, 404):
                return
            raise
        for rec in recs[:10]:
            if not isinstance(rec, dict):
                continue
            sender_id = rec.get("sender_id") or ""
            if not sender_id:
                continue
            meta = {
                "resource_type": "sender_identity",
                "sender_id": sender_id,
                "resource_id": sender_id,
                "sender_verified": bool(rec.get("verified")),
                "sender_locked": bool(rec.get("locked")),
                "event_action": "sendgrid.sender_identity.updated",
                "category": "sender_identity",
                "status": "observed",
            }
            events.append(
                self._activity_event(
                    "sendgrid.sender_identity.updated",
                    f"sg:sender_identity:{sender_id}:{day}",
                    meta,
                )
            )

    def _collect_domain_auth_events(self, client: httpx.Client, events: list, day: str) -> None:
        try:
            recs = self._fetch_domain_authentications(client)
        except ConnectorError as exc:
            if exc.status_code in (403, 404):
                return
            raise
        for rec in recs[:10]:
            if not isinstance(rec, dict):
                continue
            domain_id = rec.get("domain_id") or ""
            if not domain_id:
                continue
            meta = {
                "resource_type": "domain_authentication",
                "domain_id": domain_id,
                "resource_id": domain_id,
                "resource_name": _trunc(rec.get("domain") or "", length=253),
                "domain_valid": bool(rec.get("valid")),
                "automatic_security": bool(rec.get("automatic_security")),
                "dns_record_count": int(rec.get("dns_record_count") or 0),
                "event_action": "sendgrid.domain_authentication.updated",
                "category": "domain_authentication",
                "status": "observed",
            }
            events.append(
                self._activity_event(
                    "sendgrid.domain_authentication.updated",
                    f"sg:domain_authentication:{domain_id}:{day}",
                    meta,
                )
            )

    def _collect_mail_settings_event(self, client: httpx.Client, events: list, day: str) -> None:
        try:
            rec = self._fetch_mail_settings(client)
        except ConnectorError as exc:
            if exc.status_code in (403, 404):
                return
            raise
        if not isinstance(rec, dict):
            return
        meta = {
            "resource_type": "mail_settings",
            "mail_setting_name": "mail_settings_config",
            "event_action": "sendgrid.mail_settings.updated",
            "category": "mail_settings",
            "status": "observed",
        }
        for k in (
            "bcc_enabled", "bounce_purge_enabled", "footer_enabled",
            "forward_bounce_enabled", "forward_spam_enabled",
            "sandbox_mode_enabled", "spam_check_enabled", "template_enabled",
        ):
            if k in rec:
                # These keys are not on the activity allowlist; carry only the
                # generic mail_setting_name. Booleans are summarized via status.
                pass
        events.append(
            self._activity_event(
                "sendgrid.mail_settings.updated",
                f"sg:mail_settings:main:{day}",
                meta,
            )
        )

    def _collect_tracking_settings_event(self, client: httpx.Client, events: list, day: str) -> None:
        try:
            rec = self._fetch_tracking_settings(client)
        except ConnectorError as exc:
            if exc.status_code in (403, 404):
                return
            raise
        if not isinstance(rec, dict):
            return
        meta = {
            "resource_type": "tracking_settings",
            "tracking_setting_name": "tracking_settings_config",
            "event_action": "sendgrid.tracking_settings.updated",
            "category": "tracking_settings",
            "status": "observed",
        }
        events.append(
            self._activity_event(
                "sendgrid.tracking_settings.updated",
                f"sg:tracking_settings:main:{day}",
                meta,
            )
        )

    def _collect_webhook_settings_event(self, client: httpx.Client, events: list, day: str) -> None:
        try:
            rec = self._fetch_webhook_settings(client)
        except ConnectorError as exc:
            if exc.status_code in (403, 404):
                return
            raise
        if not isinstance(rec, dict):
            return
        meta = {
            "resource_type": "event_webhook",
            "event_webhook_enabled": bool(rec.get("event_webhook_enabled")),
            "event_webhook_has_url": bool(rec.get("event_webhook_has_url")),
            "webhook_configured": bool(rec.get("event_webhook_has_url")),
            "event_webhook_event_count": int(rec.get("event_count") or 0),
            "inbound_parse_enabled": bool(rec.get("inbound_parse_enabled")),
            "inbound_parse_spam_check_enabled": bool(
                rec.get("inbound_parse_spam_check_enabled")
            ),
            "inbound_parse_send_raw_enabled": bool(
                rec.get("inbound_parse_send_raw_enabled")
            ),
            "event_action": "sendgrid.event_webhook.updated",
            "category": "event_webhook",
            "status": "observed",
        }
        events.append(
            self._activity_event(
                "sendgrid.event_webhook.updated",
                f"sg:event_webhook:main:{day}",
                meta,
            )
        )

    def _collect_suppression_settings_event(self, client: httpx.Client, events: list, day: str) -> None:
        try:
            rec = self._fetch_suppression_settings(client)
        except ConnectorError as exc:
            if exc.status_code in (403, 404):
                return
            raise
        if not isinstance(rec, dict):
            return
        meta = {
            "resource_type": "suppression_settings",
            "suppression_group_count": int(rec.get("suppression_group_count") or 0),
            "event_action": "sendgrid.suppression_settings.updated",
            "category": "suppression_settings",
            "status": "observed",
        }
        events.append(
            self._activity_event(
                "sendgrid.suppression_settings.updated",
                f"sg:suppression_settings:main:{day}",
                meta,
            )
        )

    # ── Main fetch ─────────────────────────────────────────────────────────────

    def fetch(self, credentials: dict) -> list[dict]:
        """Fetch all SendGrid configuration surfaces and return safe records.

        SECURITY: api_key is extracted from credentials for in-flight use
        only. It is never stored on the instance, never logged, and never
        written to any returned record.

        Args:
            credentials: dict with key ``api_key`` (str).

        Returns:
            List of normalised record dicts covering all implemented surfaces.

        Raises:
            AuthenticationError: API key is missing or invalid (HTTP 401).
            ConnectorError: Unexpected API error (non-403/404 4xx or 5xx).
            RateLimitError: Rate limit hit (HTTP 429).
            NetworkError: Transport-level failure.
        """
        api_key = credentials.get("api_key", "")
        if not isinstance(api_key, str) or not api_key:
            raise AuthenticationError(
                "sendgrid: 'api_key' credential is required"
            )

        records: list[dict] = []

        with self._make_client(api_key) as client:
            # Account — required; AuthenticationError / RateLimitError re-raise.
            records.append(self._fetch_account(client))

            # Optional surfaces — each fails soft on 403/404.
            for fetch_fn in (
                self._fetch_api_keys,
                self._fetch_sender_identities,
                self._fetch_domain_authentications,
                self._fetch_mail_settings,
                self._fetch_tracking_settings,
                self._fetch_webhook_settings,
                self._fetch_suppression_settings,
            ):
                try:
                    result = fetch_fn(client)
                    if isinstance(result, list):
                        records.extend(result)
                    elif result is not None:
                        records.append(result)
                except (AuthenticationError, RateLimitError, NetworkError):
                    raise
                except ConnectorError:
                    raise
                except Exception:
                    logger.warning(
                        "sendgrid: unexpected error in %s; skipping surface",
                        getattr(fetch_fn, "__name__", repr(fetch_fn)),
                    )

        return records
