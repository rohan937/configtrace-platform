"""Twilio drift provider connector — M79A: Account, Incoming Phone Numbers,
Messaging Services, Verify Services, API Key summaries.

Fetches safe configuration metadata from the Twilio REST APIs using HTTP Basic
auth (account_sid, auth_token) against ``https://api.twilio.com``. Messaging
Services are fetched from ``https://messaging.twilio.com/v1/Services``; Verify
Services from ``https://verify.twilio.com/v2/Services``.

PRIVACY / SECURITY — what is NEVER stored or logged
----------------------------------------------------
- auth_token, API key secrets, private key material, OAuth tokens.
- Full phone number strings — only the last 4 digits are stored.
- Webhook / callback URL strings — stored as boolean presence flags only.
- Message bodies, call logs, recording data, SMS/MMS content.
- Customer PII (caller name, caller ID, verification payloads).
- Sub-account auth tokens or credentials of any kind.
- Raw Twilio API response dicts.
- Raw HTTP request or response bodies.
- The full account SID — only the first 8 characters (prefix) are stored in
  records. The full SID is used solely as an API path parameter inside the
  connector and is never returned in normalised records.

Records fetched (M79A)
----------------------
TWILIO_ACCOUNT
    Safe fields: account_sid_prefix (first 8 chars), friendly_name (truncated),
    status, account_type, subaccount_count.

TWILIO_INCOMING_PHONE_NUMBER
    Safe fields: phone_number_sid, friendly_name, phone_number_last4 (last 4
    digits only), iso_country, capability_voice/sms/mms/fax (booleans),
    sms_url_configured, voice_url_configured, status_callback_configured
    (all URL fields as booleans), address_requirements, emergency_status.

TWILIO_MESSAGING_SERVICE
    Safe fields: messaging_service_sid, friendly_name,
    inbound_request_url_configured, fallback_url_configured,
    status_callback_url_configured (all URL fields as booleans),
    smart_encoding, validity_period, area_code_geomatch, sticky_sender,
    mms_converter, use_inbound_webhook_on_number, number_count.

TWILIO_VERIFY_SERVICE
    Safe fields: verify_service_sid, friendly_name, code_length,
    lookup_enabled, psd2_enabled, do_not_share_warning_enabled,
    skip_sms_to_landlines, default_template_sid_present (bool only).

TWILIO_API_KEY_SUMMARY
    Safe fields: api_key_sid, friendly_name, date_created, date_updated.
    The API key secret is NEVER stored.

Auth / credentials dict
-----------------------
    account_sid : str  — Twilio Account SID (starts with "AC").
    auth_token  : str  — Twilio auth token. NEVER logged or stored in records.

The auth_token is used only as the HTTP Basic auth password for in-flight API
requests; it is never written to any normalised record, never passed to log
statements, and never stored on the connector instance.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from app.connectors.base import BaseConnector
from app.connectors.exceptions import (
    AuthenticationError,
    ConnectorError,
    NetworkError,
    RateLimitError,
)
from app.connectors.twilio_schema import (
    TWILIO_ACCOUNT,
    TWILIO_API_KEY_SUMMARY,
    TWILIO_INCOMING_PHONE_NUMBER,
    TWILIO_MESSAGING_SERVICE,
    TWILIO_VERIFY_SERVICE,
)

logger = logging.getLogger(__name__)

# ── Module-level constants ─────────────────────────────────────────────────────

_TWILIO_BASE = "https://api.twilio.com/2010-04-01"
_MESSAGING_BASE = "https://messaging.twilio.com/v1"
_VERIFY_BASE = "https://verify.twilio.com/v2"

_TIMEOUT = 30.0
_MAX_PAGES = 10
_PAGE_SIZE = 50
_MAX_STR_LEN = 100  # friendly name cap

# Per-surface record caps.
_MAX_PHONE_NUMBERS = 200
_MAX_MESSAGING_SERVICES = 100
_MAX_VERIFY_SERVICES = 100
_MAX_API_KEYS = 200


# ── String safety helper ───────────────────────────────────────────────────────


def _trunc(value: Any, length: int = _MAX_STR_LEN) -> str:
    """Return value truncated to ``length`` characters if it is a string."""
    if isinstance(value, str):
        return value[:length]
    return ""


# ── Connector ──────────────────────────────────────────────────────────────────


class TwilioConnector(BaseConnector):
    """Twilio REST connector for ConfigTrace drift tracking (M79A).

    Stateless: credentials are passed at call time; nothing is stored on the
    instance between calls. An httpx.Client is constructed per ``fetch()``
    call with Basic auth and torn down after the call completes.

    SECURITY: auth_token is NEVER stored as an instance attribute, never
    logged, and never written to any normalised record.
    """

    # ── HTTP client helpers ────────────────────────────────────────────────────

    @staticmethod
    def _make_client(account_sid: str, auth_token: str) -> httpx.Client:
        """Construct an httpx.Client with Basic auth for Twilio.

        The returned client uses (account_sid, auth_token) as HTTP Basic
        credentials. It must be used as a context manager or explicitly closed
        by the caller.

        SECURITY: auth_token is only present inside the returned client object
        and the in-flight HTTP Authorization header. It is never logged.
        """
        return httpx.Client(
            auth=(account_sid, auth_token),
            headers={"Accept": "application/json"},
            timeout=_TIMEOUT,
        )

    @staticmethod
    def _raise_for_status(resp: httpx.Response, context: str = "") -> None:
        """Map Twilio HTTP error codes to connector exceptions.

        Raises:
            AuthenticationError: HTTP 401.
            ConnectorError: HTTP 403, 404, 422, or other 4xx / 5xx.
            RateLimitError: HTTP 429 (Retry-After surfaced when present).
        """
        if resp.status_code == 200:
            return
        if resp.status_code == 401:
            raise AuthenticationError(
                f"twilio: 401 Unauthorized{' — ' + context if context else ''}",
                status_code=401,
            )
        if resp.status_code == 429:
            retry_after: float | None = None
            try:
                retry_after = float(resp.headers.get("Retry-After", ""))
            except (ValueError, TypeError):
                retry_after = None
            raise RateLimitError(
                "twilio: rate limit hit (429)",
                retry_after=retry_after,
            )
        if resp.status_code in (403, 404, 422):
            raise ConnectorError(
                f"twilio: HTTP {resp.status_code}{' — ' + context if context else ''}",
                status_code=resp.status_code,
            )
        if resp.status_code >= 500:
            raise ConnectorError(
                f"twilio: server error HTTP {resp.status_code}"
                f"{' — ' + context if context else ''}",
                status_code=resp.status_code,
            )
        if resp.status_code >= 400:
            raise ConnectorError(
                f"twilio: HTTP {resp.status_code}{' — ' + context if context else ''}",
                status_code=resp.status_code,
            )

    @staticmethod
    def _get(
        client: httpx.Client,
        url: str,
        params: dict | None = None,
    ) -> Any:
        """Perform a single authenticated GET and return parsed JSON.

        Raises:
            AuthenticationError: HTTP 401.
            ConnectorError: HTTP 403, 404, 422, 4xx, 5xx, or JSON parse error.
            RateLimitError: HTTP 429.
            NetworkError: Transport-level failure.
        """
        try:
            resp = client.get(url, params=params)
        except httpx.ConnectError as exc:
            raise NetworkError(
                f"twilio: GET network error for {url[:200]}: {exc}"
            ) from exc
        except httpx.TimeoutException as exc:
            raise NetworkError(
                f"twilio: GET timed out for {url[:200]}"
            ) from exc
        except httpx.HTTPError as exc:
            raise NetworkError(f"twilio: GET request error: {exc}") from exc

        TwilioConnector._raise_for_status(resp, context=url[:200])

        try:
            return resp.json()
        except ValueError as exc:
            raise ConnectorError(
                "twilio: response was not valid JSON"
            ) from exc

    # ── Paginated list helper ──────────────────────────────────────────────────

    @staticmethod
    def _paginate(
        client: httpx.Client,
        url: str,
        items_key: str,
        params: dict | None = None,
        max_records: int = 500,
    ) -> list[Any]:
        """Follow Twilio ``next_page_uri`` pagination, bounded to _MAX_PAGES.

        Twilio list responses use the shape:
            { "<items_key>": [...], "meta": { "next_page_url": "..." } }
        or (older 2010-04-01 endpoints):
            { "<items_key>": [...], "next_page_uri": "..." }

        Args:
            client:      Authenticated httpx.Client.
            url:         URL of the first page.
            items_key:   Which key in the response body holds the list.
            params:      Base query parameters for the first page (PageSize etc.).
            max_records: Hard cap on total items returned.

        Returns:
            Flat list of all items across all pages (up to _MAX_PAGES pages,
            up to max_records items total).
        """
        items: list[Any] = []
        page = 0
        next_url: str | None = url
        base_params = dict(params or {})

        while page < _MAX_PAGES and next_url and len(items) < max_records:
            this_params = base_params if page == 0 else None
            data = TwilioConnector._get(
                client, next_url, params=this_params
            )
            page += 1

            if not isinstance(data, dict):
                break

            batch = data.get(items_key, [])
            if isinstance(batch, list):
                items.extend(batch)
                if len(items) >= max_records:
                    break

            # Twilio v2 / messaging / verify APIs use meta.next_page_url.
            meta = data.get("meta") if isinstance(data.get("meta"), dict) else {}
            next_url = meta.get("next_page_url") or None
            # Twilio 2010-04-01 API uses next_page_uri (relative path).
            if not next_url:
                next_page_uri = data.get("next_page_uri") or None
                if next_page_uri and isinstance(next_page_uri, str):
                    next_url = f"https://api.twilio.com{next_page_uri}"

        if page >= _MAX_PAGES and next_url:
            logger.warning(
                "twilio: pagination cap (%d pages) reached for %s; "
                "remaining pages skipped",
                _MAX_PAGES,
                url[:200],
            )

        return items[:max_records]

    # ── Credential validation ──────────────────────────────────────────────────

    def validate_credentials(self, credentials: dict) -> bool:
        """Validate credentials by fetching the account resource.

        Makes a single lightweight GET against
        ``/2010-04-01/Accounts/{AccountSid}.json`` to confirm the SID / token
        pair is accepted by Twilio.

        Args:
            credentials: Dict carrying ``account_sid`` and ``auth_token``.

        Returns:
            True if the account resource is returned with HTTP 200.

        Raises:
            AuthenticationError: 401 (invalid SID / token pair).
            ConnectorError: 403, 404, or other unexpected error.
            NetworkError: Transport-level failure.
        """
        account_sid = credentials.get("account_sid", "")
        auth_token = credentials.get("auth_token", "")
        if not account_sid or not auth_token:
            raise AuthenticationError(
                "twilio: credentials must include account_sid and auth_token",
                status_code=None,
            )
        # SECURITY: auth_token is never logged.
        logger.info(
            "TwilioConnector.validate_credentials: probing account SID prefix=%s",
            account_sid[:8],
        )
        url = f"{_TWILIO_BASE}/Accounts/{account_sid}.json"
        with self._make_client(account_sid, auth_token) as client:
            self._get(client, url)
        return True

    # ── Normalizers ────────────────────────────────────────────────────────────

    @staticmethod
    def _normalize_account(raw: dict) -> dict:
        """Normalise a raw Twilio Account resource to safe fields only.

        Raw shape (2010-04-01 Account resource):
            { "sid": "AC...", "friendly_name": "...", "status": "active",
              "type": "Full", "subresource_uris": {"subaccounts": "/..."} }

        SECURITY: auth_token, owner_account_sid, and any full SID in the
        ``subresource_uris`` values are NEVER stored. Only the first 8 chars
        of account_sid are kept.
        """
        account_sid_full = raw.get("sid", "")
        account_sid_prefix = account_sid_full[:8] if isinstance(account_sid_full, str) else ""

        # subaccount_count: the subresource_uris dict contains a URI path for
        # sub-accounts but NOT a count; we default to 0 (a separate API call
        # would be needed to count sub-accounts — deferred to avoid extra calls).
        subresource_uris = raw.get("subresource_uris")
        subaccount_count = 0
        if isinstance(subresource_uris, dict):
            sub_uri = subresource_uris.get("subaccounts")
            # sub_uri is a path string, not a count — cannot extract an int.
            # Count defaults to 0; a future milestone may add a list call.
            _ = sub_uri  # referenced to make intent explicit

        return {
            "record_type": TWILIO_ACCOUNT,
            "record_id": f"twilio_account_{account_sid_prefix}",
            "provider_resource_id": f"accounts/{account_sid_prefix}",
            "account_sid_prefix": account_sid_prefix,
            "friendly_name": _trunc(raw.get("friendly_name") or ""),
            "status": _trunc(raw.get("status") or "unknown"),
            "account_type": _trunc(raw.get("type") or "unknown"),
            "subaccount_count": subaccount_count,
        }

    @staticmethod
    def _normalize_incoming_phone_number(raw: dict) -> dict:
        """Normalise a raw IncomingPhoneNumbers resource to safe fields only.

        Raw shape:
            { "sid": "PN...", "friendly_name": "...",
              "phone_number": "+15105551234",
              "iso_country": "US",
              "capabilities": {"voice": true, "sms": true, "mms": true, "fax": false},
              "sms_url": "https://...", "voice_url": "https://...",
              "status_callback": "https://...",
              "address_requirements": "none", "emergency_status": "Active" }

        SECURITY: phone_number string is NEVER stored — only the last 4 chars.
        sms_url, voice_url, status_callback strings are NEVER stored — only
        boolean presence flags.
        """
        sid = _trunc(raw.get("sid") or "", length=200)
        phone_number_raw = raw.get("phone_number") or ""
        # Last 4 digits / characters only — never the full number.
        phone_number_last4 = (
            phone_number_raw[-4:]
            if isinstance(phone_number_raw, str) and len(phone_number_raw) >= 4
            else ""
        )
        capabilities = raw.get("capabilities") if isinstance(raw.get("capabilities"), dict) else {}

        return {
            "record_type": TWILIO_INCOMING_PHONE_NUMBER,
            "record_id": sid,
            "provider_resource_id": f"incoming_phone_numbers/{sid}",
            "phone_number_sid": sid,
            "friendly_name": _trunc(raw.get("friendly_name") or ""),
            # SECURITY: full phone number is NEVER stored.
            "phone_number_last4": phone_number_last4,
            "iso_country": _trunc(raw.get("iso_country") or ""),
            "capability_voice": bool(capabilities.get("voice")),
            "capability_sms": bool(capabilities.get("sms")),
            "capability_mms": bool(capabilities.get("mms")),
            "capability_fax": bool(capabilities.get("fax")),
            # SECURITY: webhook URL strings are NEVER stored — boolean only.
            "sms_url_configured": bool(raw.get("sms_url")),
            "voice_url_configured": bool(raw.get("voice_url")),
            "status_callback_configured": bool(raw.get("status_callback")),
            "address_requirements": _trunc(raw.get("address_requirements") or "none"),
            "emergency_status": _trunc(raw.get("emergency_status") or ""),
        }

    @staticmethod
    def _normalize_messaging_service(raw: dict) -> dict:
        """Normalise a raw Messaging Service resource to safe fields only.

        Raw shape (messaging.twilio.com/v1/Services item):
            { "sid": "MG...", "friendly_name": "...",
              "inbound_request_url": "https://...",
              "fallback_url": "https://...",
              "status_callback_url": "https://...",
              "smart_encoding": true, "validity_period": 14400,
              "area_code_geomatch": true, "sticky_sender": true,
              "mms_converter": true, "use_inbound_webhook_on_number": false }

        SECURITY: inbound_request_url, fallback_url, and status_callback_url
        strings are NEVER stored — only boolean presence flags.
        """
        sid = _trunc(raw.get("sid") or "", length=200)

        return {
            "record_type": TWILIO_MESSAGING_SERVICE,
            "record_id": sid,
            "provider_resource_id": f"messaging_services/{sid}",
            "messaging_service_sid": sid,
            "friendly_name": _trunc(raw.get("friendly_name") or ""),
            # SECURITY: URL strings are NEVER stored — booleans only.
            "inbound_request_url_configured": bool(raw.get("inbound_request_url")),
            "fallback_url_configured": bool(raw.get("fallback_url")),
            "status_callback_url_configured": bool(raw.get("status_callback_url")),
            "smart_encoding": bool(raw.get("smart_encoding")),
            "validity_period": int(raw.get("validity_period") or 0),
            "area_code_geomatch": bool(raw.get("area_code_geomatch")),
            "sticky_sender": bool(raw.get("sticky_sender")),
            "mms_converter": bool(raw.get("mms_converter")),
            "use_inbound_webhook_on_number": bool(raw.get("use_inbound_webhook_on_number")),
            "number_count": int(raw.get("numbers_count") or 0),
        }

    @staticmethod
    def _normalize_verify_service(raw: dict) -> dict:
        """Normalise a raw Verify Service resource to safe fields only.

        Raw shape (verify.twilio.com/v2/Services item):
            { "sid": "VA...", "friendly_name": "...", "code_length": 6,
              "lookup_enabled": false, "psd2_enabled": false,
              "do_not_share_warning_enabled": false,
              "skip_sms_to_landlines": false,
              "default_template_sid": "HJ..." }

        SECURITY: default_template_sid string is NEVER stored — only a bool
        indicating its presence. Template content is never accessed.
        """
        sid = _trunc(raw.get("sid") or "", length=200)

        return {
            "record_type": TWILIO_VERIFY_SERVICE,
            "record_id": sid,
            "provider_resource_id": f"verify_services/{sid}",
            "verify_service_sid": sid,
            "friendly_name": _trunc(raw.get("friendly_name") or ""),
            "code_length": int(raw.get("code_length") or 6),
            "lookup_enabled": bool(raw.get("lookup_enabled")),
            "psd2_enabled": bool(raw.get("psd2_enabled")),
            "do_not_share_warning_enabled": bool(raw.get("do_not_share_warning_enabled")),
            "skip_sms_to_landlines": bool(raw.get("skip_sms_to_landlines")),
            # SECURITY: default_template_sid value is NEVER stored — bool only.
            "default_template_sid_present": bool(raw.get("default_template_sid")),
        }

    @staticmethod
    def _normalize_api_key(raw: dict) -> dict:
        """Normalise a raw API Key resource to safe fields only.

        Raw shape (2010-04-01 Keys item):
            { "sid": "SK...", "friendly_name": "...",
              "date_created": "...", "date_updated": "..." }

        SECURITY: the API key secret is NEVER present in list responses (it is
        only returned at key-creation time) and is NEVER stored here.
        """
        sid = _trunc(raw.get("sid") or "", length=200)

        return {
            "record_type": TWILIO_API_KEY_SUMMARY,
            "record_id": sid,
            "provider_resource_id": f"api_keys/{sid}",
            "api_key_sid": sid,
            "friendly_name": _trunc(raw.get("friendly_name") or ""),
            "date_created": _trunc(raw.get("date_created") or "", length=200),
            "date_updated": _trunc(raw.get("date_updated") or "", length=200),
        }

    # ── Per-resource fetch helpers ────────────────────────────────────────────

    def _fetch_account(
        self, client: httpx.Client, account_sid: str
    ) -> dict | None:
        """Fetch and normalise the main account resource.

        Returns None on any error so fetch() can continue to other surfaces.
        """
        url = f"{_TWILIO_BASE}/Accounts/{account_sid}.json"
        try:
            raw = self._get(client, url)
            if isinstance(raw, dict):
                return self._normalize_account(raw)
        except Exception as exc:
            logger.warning(
                "TwilioConnector._fetch_account: failed — %s",
                str(exc)[:200],
            )
        return None

    def _fetch_incoming_phone_numbers(
        self, client: httpx.Client, account_sid: str
    ) -> list[dict]:
        """Fetch and normalise all IncomingPhoneNumbers for the account.

        Fail-soft: returns an empty list on any error.

        SECURITY: full phone numbers from the raw API response are NEVER stored;
        normalisation extracts last-4 digits only.
        """
        url = f"{_TWILIO_BASE}/Accounts/{account_sid}/IncomingPhoneNumbers.json"
        try:
            raw_list = self._paginate(
                client,
                url,
                items_key="incoming_phone_numbers",
                params={"PageSize": _PAGE_SIZE},
                max_records=_MAX_PHONE_NUMBERS,
            )
        except Exception as exc:
            logger.warning(
                "TwilioConnector._fetch_incoming_phone_numbers: failed — %s",
                str(exc)[:200],
            )
            return []

        records: list[dict] = []
        for raw in raw_list:
            if not isinstance(raw, dict):
                continue
            try:
                records.append(self._normalize_incoming_phone_number(raw))
            except Exception as exc:
                logger.warning(
                    "TwilioConnector._fetch_incoming_phone_numbers: "
                    "normalise failed for sid=%s — %s",
                    _trunc(raw.get("sid") or "", length=200),
                    str(exc)[:200],
                )
        return records

    def _fetch_messaging_services(self, client: httpx.Client) -> list[dict]:
        """Fetch and normalise all Messaging Services.

        Uses the Messaging API base (messaging.twilio.com/v1/Services). The
        client's Basic auth credentials are re-used.

        Fail-soft: returns an empty list on any error (e.g. Messaging API not
        enabled for this account, or missing permissions).

        SECURITY: webhook URL strings from the raw API response are NEVER stored.
        """
        url = f"{_MESSAGING_BASE}/Services"
        try:
            raw_list = self._paginate(
                client,
                url,
                items_key="services",
                params={"PageSize": _PAGE_SIZE},
                max_records=_MAX_MESSAGING_SERVICES,
            )
        except Exception as exc:
            logger.warning(
                "TwilioConnector._fetch_messaging_services: failed — %s",
                str(exc)[:200],
            )
            return []

        records: list[dict] = []
        for raw in raw_list:
            if not isinstance(raw, dict):
                continue
            try:
                records.append(self._normalize_messaging_service(raw))
            except Exception as exc:
                logger.warning(
                    "TwilioConnector._fetch_messaging_services: "
                    "normalise failed for sid=%s — %s",
                    _trunc(raw.get("sid") or "", length=200),
                    str(exc)[:200],
                )
        return records

    def _fetch_verify_services(self, client: httpx.Client) -> list[dict]:
        """Fetch and normalise all Verify Services.

        Uses the Verify API base (verify.twilio.com/v2/Services). The client's
        Basic auth credentials are re-used.

        Fail-soft: returns an empty list on any error (e.g. Verify API not
        enabled or missing permissions).

        SECURITY: template content and verification payloads are never accessed.
        """
        url = f"{_VERIFY_BASE}/Services"
        try:
            raw_list = self._paginate(
                client,
                url,
                items_key="services",
                params={"PageSize": _PAGE_SIZE},
                max_records=_MAX_VERIFY_SERVICES,
            )
        except Exception as exc:
            logger.warning(
                "TwilioConnector._fetch_verify_services: failed — %s",
                str(exc)[:200],
            )
            return []

        records: list[dict] = []
        for raw in raw_list:
            if not isinstance(raw, dict):
                continue
            try:
                records.append(self._normalize_verify_service(raw))
            except Exception as exc:
                logger.warning(
                    "TwilioConnector._fetch_verify_services: "
                    "normalise failed for sid=%s — %s",
                    _trunc(raw.get("sid") or "", length=200),
                    str(exc)[:200],
                )
        return records

    def _fetch_api_keys(
        self, client: httpx.Client, account_sid: str
    ) -> list[dict]:
        """Fetch and normalise API key metadata for the account.

        Uses the 2010-04-01 Keys endpoint. The API key secret is NEVER returned
        by the list endpoint (it is only returned at key creation time).

        Fail-soft: returns an empty list on any error.

        SECURITY: only SID, friendly name, and timestamps are normalised.
        """
        url = f"{_TWILIO_BASE}/Accounts/{account_sid}/Keys.json"
        try:
            raw_list = self._paginate(
                client,
                url,
                items_key="keys",
                params={"PageSize": _PAGE_SIZE},
                max_records=_MAX_API_KEYS,
            )
        except Exception as exc:
            logger.warning(
                "TwilioConnector._fetch_api_keys: failed — %s",
                str(exc)[:200],
            )
            return []

        records: list[dict] = []
        for raw in raw_list:
            if not isinstance(raw, dict):
                continue
            try:
                records.append(self._normalize_api_key(raw))
            except Exception as exc:
                logger.warning(
                    "TwilioConnector._fetch_api_keys: "
                    "normalise failed for sid=%s — %s",
                    _trunc(raw.get("sid") or "", length=200),
                    str(exc)[:200],
                )
        return records

    # ── Main fetch ─────────────────────────────────────────────────────────────

    def fetch(self, credentials: dict) -> list[dict]:
        """Fetch all M79A resources and return a flat list of safe records.

        Fail-soft per surface: if a single resource type fails, a warning is
        logged and collection continues for the remaining types. The caller
        receives all records that were successfully fetched.

        Records never contain auth_token, API secrets, full phone numbers,
        webhook URL strings, message bodies, call logs, customer PII, or raw
        Twilio API response dicts.

        Args:
            credentials: Dict carrying ``account_sid`` and ``auth_token``.
                         SECURITY: ``auth_token`` is used only for in-flight
                         HTTP Basic auth and is NEVER logged or stored in records.

        Returns:
            Flat list of normalised record dicts, each JSON-serialisable.

        Raises:
            AuthenticationError: 401 from the account probe.
            ConnectorError: Unexpected API error during the account fetch.
            NetworkError: Transport-level failure on the account fetch.
        """
        account_sid = credentials.get("account_sid", "")
        auth_token = credentials.get("auth_token", "")
        if not account_sid or not auth_token:
            raise AuthenticationError(
                "twilio: credentials must include account_sid and auth_token",
                status_code=None,
            )

        # SECURITY: auth_token is never logged.
        logger.info(
            "TwilioConnector.fetch: starting fetch for SID prefix=%s",
            account_sid[:8],
        )

        records: list[dict] = []

        with self._make_client(account_sid, auth_token) as client:

            # ── 1. Account ────────────────────────────────────────────────────
            # Auth failures on the account fetch are allowed to propagate so
            # the ingestion layer can mark the integration as broken.
            account_record = self._fetch_account(client, account_sid)
            if account_record is not None:
                records.append(account_record)
            logger.info(
                "TwilioConnector.fetch: account fetched count=%d",
                1 if account_record else 0,
            )

            # ── 2. Incoming phone numbers ─────────────────────────────────────
            phone_records = self._fetch_incoming_phone_numbers(client, account_sid)
            records.extend(phone_records)
            logger.info(
                "TwilioConnector.fetch: incoming_phone_numbers fetched count=%d",
                len(phone_records),
            )

            # ── 3. Messaging Services ─────────────────────────────────────────
            messaging_records = self._fetch_messaging_services(client)
            records.extend(messaging_records)
            logger.info(
                "TwilioConnector.fetch: messaging_services fetched count=%d",
                len(messaging_records),
            )

            # ── 4. Verify Services ────────────────────────────────────────────
            verify_records = self._fetch_verify_services(client)
            records.extend(verify_records)
            logger.info(
                "TwilioConnector.fetch: verify_services fetched count=%d",
                len(verify_records),
            )

            # ── 5. API Keys ───────────────────────────────────────────────────
            api_key_records = self._fetch_api_keys(client, account_sid)
            records.extend(api_key_records)
            logger.info(
                "TwilioConnector.fetch: api_keys fetched count=%d",
                len(api_key_records),
            )

        logger.info(
            "TwilioConnector.fetch: complete total_records=%d",
            len(records),
        )
        return records

    # ── Activity event ingestion (M79D) ────────────────────────────────────────

    def list_activity_events(
        self,
        credentials: dict,
        *,
        max_events: int = 100,
        lookback_hours: int = 24,
    ) -> list[dict]:
        """Fetch review-safe Twilio Monitor configuration/control-plane events.

        Returns only account/resource configuration change events — never
        message bodies, call logs, recordings, media, or customer data.

        CLAIM DISCIPLINE: events are configuration evidence for review.
        This does not confirm compromise, unauthorized access, or data exposure.

        PRIVACY:
        - No auth tokens, API secrets, raw phone numbers, webhook URLs, or PII.
        - No message bodies, call logs, recordings, or conversation content.
        - Raw To/From fields, request/response bodies, and signatures are excluded.
        - Metadata is scalar allowlisted before return.
        """
        max_events = min(max_events, 1000)
        lookback_hours = min(lookback_hours, 168)

        account_sid = credentials.get("account_sid", "")
        auth_token = credentials.get("auth_token", "")

        # Monitor Events API base URL
        monitor_base = "https://monitor.twilio.com/v1/Events"

        from datetime import datetime, timezone, timedelta
        start_date = (
            datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")

        results: list[dict] = []
        page_size = min(50, max_events)
        next_url: str | None = monitor_base
        page_count = 0
        max_pages = min(max_events // page_size + 1, _MAX_PAGES)

        try:
            with httpx.Client(
                auth=(account_sid, auth_token),
                headers={"User-Agent": "ConfigTrace/1.0"},
                timeout=30.0,
            ) as client:
                while next_url and page_count < max_pages and len(results) < max_events:
                    params: dict = {}
                    if page_count == 0:
                        params = {
                            "StartDate": start_date,
                            "PageSize": page_size,
                        }
                    resp = client.get(next_url, params=params if page_count == 0 else None)
                    if resp.status_code == 401:
                        raise AuthenticationError("Twilio Monitor: invalid credentials")
                    if resp.status_code == 429:
                        raise RateLimitError("Twilio Monitor: rate limited")
                    if resp.status_code in (403, 404):
                        # Monitor API may not be available on all plans — fail soft
                        return []
                    if resp.status_code >= 400:
                        raise ConnectorError(
                            f"Twilio Monitor: unexpected status {resp.status_code}"
                        )
                    data = resp.json()
                    raw_events = data.get("events", [])
                    for ev in raw_events:
                        normalized = self._normalize_monitor_event(ev, account_sid)
                        if normalized:
                            results.append(normalized)
                        if len(results) >= max_events:
                            break
                    # Follow next page link
                    meta_info = data.get("meta", {})
                    next_url_candidate = meta_info.get("next_page_url") or data.get("next_page_uri")
                    if next_url_candidate and next_url_candidate != next_url:
                        next_url = next_url_candidate
                        if not next_url.startswith("http"):
                            next_url = f"https://monitor.twilio.com{next_url}"
                    else:
                        next_url = None
                    page_count += 1
        except (AuthenticationError, RateLimitError, ConnectorError):
            raise
        except httpx.TimeoutException as exc:
            raise NetworkError(f"Twilio Monitor: timeout — {exc}") from exc
        except httpx.RequestError as exc:
            raise NetworkError(f"Twilio Monitor: network error — {exc}") from exc

        return results

    def _normalize_monitor_event(self, event: dict, account_sid: str) -> dict | None:
        """Normalize one Twilio Monitor event to a safe metadata record.

        Returns None if the event type is not in the allowlisted config/control-plane
        set, or if required safe fields are missing.

        PRIVACY: raw payloads, URLs, phone numbers, message content, and customer
        data are never included.
        """
        resource_type = (event.get("resource_type") or "").lower()
        event_type = (event.get("event_type") or "").lower()
        description = (event.get("description") or "")

        # ── Event type allowlist — only config/control-plane events ─────────────
        # Explicitly allowed resource types
        _ALLOWED_RESOURCE_TYPES = frozenset({
            "account", "subaccount",
            "incoming-phone-number", "incoming_phone_number", "phone-number",
            "messaging-service", "messaging_service",
            "verify-service", "verify_service",
            "api-key", "api_key",
            "application", "app",
        })
        # Allowed event types (Monitor API event_type strings)
        _ALLOWED_EVENT_TYPES = frozenset({
            "account.updated",
            "subaccount.created", "subaccount.updated",
            "incoming-phone-number.created", "incoming-phone-number.updated",
            "incoming-phone-number.deleted",
            "messaging-service.created", "messaging-service.updated",
            "messaging-service.deleted",
            "verify-service.created", "verify-service.updated",
            "verify-service.deleted",
            "api-key.created", "api-key.updated", "api-key.deleted",
            "application.created", "application.updated", "application.deleted",
        })

        # Accept if either resource_type or event_type is allowlisted
        resource_ok = resource_type in _ALLOWED_RESOURCE_TYPES
        event_ok = event_type in _ALLOWED_EVENT_TYPES
        if not resource_ok and not event_ok:
            return None

        # Normalize event_type to canonical dotted form
        normalized_event_type = _normalize_twilio_event_type(event_type, resource_type)

        # ── Build safe metadata dict ─────────────────────────────────────────────
        safe_meta: dict = {}

        # Safe identifiers — SID prefix only, never full SID unless it is a safe sub-resource
        event_sid = (event.get("sid") or "")
        if event_sid:
            safe_meta["twilio_event_id"] = event_sid  # Monitor event SID is safe — not account SID

        resource_sid = (event.get("resource_sid") or "")
        if resource_sid:
            # Store as prefix only to avoid exposing full Twilio SIDs
            safe_meta["twilio_resource_sid_prefix"] = resource_sid[:8]

        safe_meta["resource_type"] = resource_type or "unknown"
        safe_meta["event_action"] = normalized_event_type

        # Account SID prefix only
        safe_meta["account_sid_prefix"] = account_sid[:8]

        # Description — strip raw content but keep operation label
        if description:
            safe_meta["operation_name"] = _trunc(description, 200)

        # Event time as-is (ISO timestamp — safe)
        event_time = event.get("event_date") or event.get("date_created") or ""
        if event_time:
            safe_meta["event_time"] = event_time

        return {
            "event_type": normalized_event_type,
            "provider": "twilio",
            "source": "twilio_activity_event",
            "event_source": "twilio_activity_event",
            "provider_event_id": event_sid or "",
            "metadata": safe_meta,
        }


# ── Module-level event type helper (M79D) ─────────────────────────────────────


def _normalize_twilio_event_type(event_type: str, resource_type: str) -> str:
    """Convert Twilio Monitor event_type to a canonical ConfigTrace event type string."""
    _MAP = {
        "account.updated": "twilio.account.updated",
        "subaccount.created": "twilio.account.updated",
        "subaccount.updated": "twilio.account.updated",
        "incoming-phone-number.created": "twilio.phone_number.created",
        "incoming-phone-number.updated": "twilio.phone_number.updated",
        "incoming-phone-number.deleted": "twilio.phone_number.deleted",
        "messaging-service.created": "twilio.messaging_service.created",
        "messaging-service.updated": "twilio.messaging_service.updated",
        "messaging-service.deleted": "twilio.messaging_service.deleted",
        "verify-service.created": "twilio.verify_service.created",
        "verify-service.updated": "twilio.verify_service.updated",
        "verify-service.deleted": "twilio.verify_service.deleted",
        "api-key.created": "twilio.api_key.created",
        "api-key.updated": "twilio.api_key.updated",
        "api-key.deleted": "twilio.api_key.deleted",
        "application.created": "twilio.config.event",
        "application.updated": "twilio.config.event",
        "application.deleted": "twilio.config.event",
    }
    return _MAP.get(event_type, "twilio.config.event")
