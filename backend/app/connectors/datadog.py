"""Datadog drift connector — M82A.

Snapshots safe configuration metadata from the Datadog API:
  - Monitors (type, status, counts — never raw query or message)
  - SLOs (type, target categories, counts — never raw description)
  - Dashboards (layout, widget/variable counts — never raw JSON or queries)
  - Webhook integrations (presence booleans — never URL, headers, payload, or secrets)
  - Notification integrations (type, counts — never handles, channels, or service keys)
  - API key metadata (ID, name, created/modified presence — never key value)
  - Application key metadata (ID, name, scope count — never key value)
  - Roles (name, permission/user counts — never user identities)
  - Teams (name, member count — never member identities or handles)
  - Cloud integrations (type, collection flags — never account IDs)

Authentication: DD-API-KEY + DD-APPLICATION-KEY headers.

PRIVACY / SECURITY — what is NEVER stored or logged
----------------------------------------------------
- api_key value — NEVER stored on instance, NEVER logged
- application_key value — NEVER stored on instance, NEVER logged
- DD-API-KEY header value — NEVER in logs or records
- DD-APPLICATION-KEY header value — NEVER in logs or records
- Raw Datadog API response dicts — NEVER stored
- Monitor query strings — NEVER stored (query_present boolean only)
- Monitor message text — NEVER stored (message_present boolean + length category)
- Dashboard JSON — NEVER stored (widget_count / template_variable_count only)
- Widget query strings or formulas — NEVER stored
- Webhook URLs — NEVER stored (url_present boolean only)
- Webhook custom headers — NEVER stored (custom_headers_present boolean only)
- Webhook payload templates — NEVER stored (payload_template_present boolean only)
- Notification handles (Slack channels, PagerDuty service IDs, etc.) — NEVER stored
- Email addresses, user IDs, user names — NEVER stored
- Team handles — NEVER stored (handle_present boolean only)
- AWS account IDs, GCP project IDs, Azure subscription/tenant IDs — NEVER stored
- API key last4 digits — NEVER stored (last4_present boolean only)
- Logs, traces, metric values, incident content — NEVER fetched or stored

Credentials dict
----------------
    api_key         : str — Datadog API key (NEVER logged or stored)
    application_key : str — Datadog Application key (NEVER logged or stored)
    site            : str — Datadog site, e.g. "datadoghq.com" (optional, defaults to "datadoghq.com")
"""

from __future__ import annotations

import json as _json
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
from app.connectors.datadog_schema import (
    DATADOG_API_KEY_METADATA,
    DATADOG_APPLICATION_KEY_METADATA,
    DATADOG_CLOUD_INTEGRATION,
    DATADOG_DASHBOARD,
    DATADOG_MONITOR,
    DATADOG_NOTIFICATION_INTEGRATION,
    DATADOG_ROLE,
    DATADOG_SLO,
    DATADOG_TEAM,
    DATADOG_WEBHOOK_INTEGRATION,
)

logger = logging.getLogger(__name__)

# ── Module-level constants ─────────────────────────────────────────────────────

_TIMEOUT = 30.0
_PAGE_SIZE = 100
_MAX_PAGES = 5

# Per-surface record caps — conservative to avoid overwhelming snapshot storage.
_MAX_MONITORS = 300
_MAX_SLOS = 200
_MAX_DASHBOARDS = 200
_MAX_WEBHOOKS = 100
_MAX_API_KEYS = 200
_MAX_APP_KEYS = 200
_MAX_ROLES = 100
_MAX_TEAMS = 200
_MAX_CLOUD_INTEGRATIONS = 50

_MAX_STR_LEN = 100

# Known Datadog sites — used for validation hint; free-text site is also accepted.
_KNOWN_SITES: frozenset[str] = frozenset({
    "datadoghq.com",
    "datadoghq.eu",
    "us3.datadoghq.com",
    "us5.datadoghq.com",
    "ap1.datadoghq.com",
    "ap2.datadoghq.com",
    "ddog-gov.com",
})

# Notification integration types we attempt to probe.
_NOTIFICATION_INTEGRATION_TYPES: tuple[str, ...] = (
    "pagerduty",
    "opsgenie",
    "slack",
)


# ── Helper functions ───────────────────────────────────────────────────────────


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
        return value.lower() in ("true", "1", "yes", "enabled")
    return False


def _int(value: Any, default: int = 0) -> int:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            pass
    return default


def _length_category(text: Any) -> str:
    """Return a safe length category for a text field.

    The content itself is NEVER stored.
    """
    if not isinstance(text, str) or not text:
        return "absent"
    length = len(text)
    if length < 200:
        return "short"
    if length < 1000:
        return "medium"
    return "long"


def _sanitize_site(site: Any) -> str:
    """Validate and normalise a Datadog site credential.

    Returns a cleaned lowercase site string (e.g. 'datadoghq.com').
    Defaults to 'datadoghq.com' if the value is absent or clearly invalid.

    SECURITY: this result is used to build API base URLs only, never stored
    in normalised records.
    """
    if not isinstance(site, str):
        return "datadoghq.com"
    cleaned = site.strip().lower()
    if not cleaned or " " in cleaned or "://" in cleaned or len(cleaned) > 253:
        return "datadoghq.com"
    return cleaned


def _priority_category(priority: Any) -> str:
    """Map a Datadog monitor priority integer (1–5) to a safe category label."""
    if not isinstance(priority, int) or isinstance(priority, bool):
        return "none"
    return {1: "critical", 2: "high", 3: "medium", 4: "low", 5: "info"}.get(
        priority, "none"
    )


def _target_category(target: Any) -> str:
    """Map an SLO target percentage (0–100) to a safe category label."""
    if not isinstance(target, (int, float)):
        return "none"
    if target >= 99.9:
        return "99.9_plus"
    if target >= 99.0:
        return "99_plus"
    if target >= 95.0:
        return "95_plus"
    return "below_95"


def _eval_delay_category(delay_seconds: Any) -> str:
    """Categorise an evaluation delay in seconds."""
    if not isinstance(delay_seconds, (int, float)):
        return "none"
    s = int(delay_seconds)
    if s <= 0:
        return "none"
    if s < 60:
        return "short"
    if s < 300:
        return "medium"
    return "long"


# ── M82C helper functions ──────────────────────────────────────────────────────


def _renotify_interval_category(interval_minutes: Any) -> str:
    """Categorise a monitor renotify_interval (in minutes).

    Returns "disabled" when the interval is absent or zero.
    SECURITY: the raw interval value is categorised and discarded.
    """
    if not isinstance(interval_minutes, (int, float)):
        return "disabled"
    m = int(interval_minutes)
    if m <= 0:
        return "disabled"
    if m < 60:
        return "short"     # < 1 hour
    if m < 240:
        return "medium"    # 1–4 hours
    return "long"          # >= 4 hours


def _no_data_timeframe_category(timeframe_minutes: Any) -> str:
    """Categorise a monitor no_data_timeframe (in minutes).

    Returns "none" when absent or zero.
    SECURITY: the raw value is categorised and discarded.
    """
    if not isinstance(timeframe_minutes, (int, float)):
        return "none"
    m = int(timeframe_minutes)
    if m <= 0:
        return "none"
    if m < 30:
        return "short"      # < 30 min
    if m < 120:
        return "medium"     # 30–120 min
    return "extended"       # >= 2 hours


def _count_notification_mentions(message: Any) -> int:
    """Count the number of @ characters in a monitor message.

    This gives an approximation of notification handles without storing
    any of the actual handles, channel names, or user references.
    SECURITY: the raw message is NEVER stored. Only the count is returned.
    Capped at 50 to avoid outsized values.
    """
    if not isinstance(message, str):
        return 0
    return min(message.count("@"), 50)


def _detect_webhook_auth_material(raw_headers_str: Any) -> bool:
    """Check whether custom_headers contains any auth-like header names.

    Parses the custom_headers JSON string to inspect key names only. Neither
    header names nor header values are returned or stored — only a boolean.
    SECURITY: header names are matched against a fixed pattern list and then
    discarded. Header values are NEVER read or stored.
    """
    if not isinstance(raw_headers_str, str) or not raw_headers_str.strip():
        return False
    try:
        headers_dict = _json.loads(raw_headers_str)
    except (ValueError, TypeError):
        return False
    if not isinstance(headers_dict, dict):
        return False
    # Pattern list of auth-suggestive header name substrings.
    # SECURITY: these patterns are used for detection only — never stored.
    _AUTH_PATTERNS = frozenset({
        "authorization", "x-api-key", "x-auth-token", "apikey", "api-key",
        "x-dd-api-key", "x-datadog-api-key", "token", "api_key",
        "x-token", "auth", "bearer",
    })
    for key in headers_dict:
        if not isinstance(key, str):
            continue
        key_lower = key.lower()
        if any(p in key_lower for p in _AUTH_PATTERNS):
            return True
    return False


def _count_headers(raw_headers_str: Any) -> int:
    """Count the number of keys in a JSON-encoded headers dict.

    SECURITY: header names and values are NEVER stored — only the count.
    Returns 0 on parse error.
    """
    if not isinstance(raw_headers_str, str) or not raw_headers_str.strip():
        return 0
    try:
        headers_dict = _json.loads(raw_headers_str)
    except (ValueError, TypeError):
        return 0
    return len(headers_dict) if isinstance(headers_dict, dict) else 0


def _url_scheme_category(url: Any) -> str:
    """Extract the URL scheme category without storing the URL.

    SECURITY: the full URL string is NEVER stored or returned. Only a safe
    categorical label ("https"/"http"/"absent"/"unknown") is returned.
    """
    if not isinstance(url, str) or not url.strip():
        return "absent"
    url_lower = url.lower().strip()
    if url_lower.startswith("https://"):
        return "https"
    if url_lower.startswith("http://"):
        return "http"
    return "unknown"


# ── Connector ──────────────────────────────────────────────────────────────────


class DatadogConnector(BaseConnector):
    """Datadog API connector for ConfigTrace drift tracking (M82A).

    Stateless: credentials are passed at call time; nothing is stored on the
    instance between calls.

    SECURITY: api_key and application_key are NEVER stored as instance
    attributes, NEVER logged, NEVER included in error messages, and NEVER
    written to any normalised record. They are placed only in request headers
    within the scope of each method and discarded immediately after.
    """

    # ── HTTP client helpers ───────────────────────────────────────────────────

    @staticmethod
    def _make_client(site: str, api_key: str, application_key: str) -> httpx.Client:
        """Build an httpx.Client for the Datadog API.

        SECURITY: api_key and application_key are placed in HTTP headers only.
        They are never stored on the connector instance or logged.
        """
        base_url = f"https://api.{site}"
        return httpx.Client(
            base_url=base_url,
            headers={
                "DD-API-KEY": api_key,
                "DD-APPLICATION-KEY": application_key,
                "Accept": "application/json",
            },
            timeout=_TIMEOUT,
        )

    @staticmethod
    def _raise_for_status(resp: httpx.Response, context: str = "") -> None:
        """Map Datadog API HTTP error codes to connector exceptions."""
        if resp.status_code < 400:
            return
        if resp.status_code in (401, 403):
            raise AuthenticationError(
                f"datadog: HTTP {resp.status_code} — "
                f"check api_key and application_key permissions"
                f"{' (' + context + ')' if context else ''}",
                status_code=resp.status_code,
            )
        if resp.status_code == 429:
            retry_after: Optional[float] = None
            try:
                retry_after = float(resp.headers.get("Retry-After", ""))
            except (ValueError, TypeError):
                pass
            raise RateLimitError(
                "datadog: rate limit hit (429)",
                retry_after=retry_after,
            )
        if resp.status_code >= 500:
            raise ConnectorError(
                f"datadog: server error HTTP {resp.status_code}"
                f"{' — ' + context if context else ''}",
                status_code=resp.status_code,
            )
        raise ConnectorError(
            f"datadog: HTTP {resp.status_code}"
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
            AuthenticationError: HTTP 401/403.
            ConnectorError: HTTP 4xx/5xx or JSON parse error.
            RateLimitError: HTTP 429.
            NetworkError: Transport-level failure.
        """
        try:
            resp = client.get(path, params=params)
        except httpx.ConnectError as exc:
            raise NetworkError(
                f"datadog: GET connection error for {path[:200]}: {exc}"
            ) from exc
        except httpx.TimeoutException:
            raise NetworkError(f"datadog: GET timed out for {path[:200]}")
        except httpx.HTTPError as exc:
            raise NetworkError(f"datadog: GET request error: {exc}") from exc

        DatadogConnector._raise_for_status(resp, context=path[:200])
        try:
            return resp.json()
        except ValueError as exc:
            raise ConnectorError("datadog: response was not valid JSON") from exc

    # ── Record normalizers ────────────────────────────────────────────────────

    @staticmethod
    def _normalize_monitor(raw: dict) -> Optional[dict]:
        """Normalize one Datadog monitor record.

        SECURITY: raw query string and raw message text are NEVER stored.
        Notification handles embedded in the message are NEVER stored.
        Query and message are read transiently to compute safe derived booleans
        and counts (M82C), then discarded immediately.
        """
        mid = raw.get("id")
        if mid is None:
            return None

        options = raw.get("options") if isinstance(raw.get("options"), dict) else {}
        thresholds = options.get("thresholds") if isinstance(options.get("thresholds"), dict) else {}
        restricted_roles = raw.get("restricted_roles") or []
        tags = raw.get("tags") or []

        # query is NEVER stored — compute derived fields then discard
        query = raw.get("query", "")
        # message is NEVER stored — compute derived fields then discard
        message = raw.get("message", "")

        # enabled: False if monitor is currently silenced (dict with timestamps)
        silenced = options.get("silenced")
        enabled = not bool(silenced and isinstance(silenced, dict) and silenced)

        eval_delay = options.get("evaluation_delay")

        # ── M82C: safe derived fields from query (query NEVER stored) ─────────
        # query_uses_wildcard_scope: monitor covers all hosts/metrics via {*}
        query_uses_wildcard_scope = bool(
            isinstance(query, str) and "{*}" in query
        )
        # query_group_by_count: count of group-by clauses (raw query discarded)
        query_group_by_count = (
            min(query.lower().count("by {"), 20)
            if isinstance(query, str) else 0
        )

        # ── M82C: safe derived fields from message (message NEVER stored) ─────
        # notification_routing_present: any @ mention in the message
        notification_routing_present = bool(
            isinstance(message, str) and "@" in message
        )
        # notification_count: count of @ characters (handles NEVER stored)
        notification_count = _count_notification_mentions(message)
        # message_template_present: message uses {{ template variables
        message_template_present = bool(
            isinstance(message, str) and "{{" in message
        )

        # ── M82C: individual threshold fields ─────────────────────────────────
        threshold_critical_present = (
            isinstance(thresholds, dict) and thresholds.get("critical") is not None
        )
        threshold_warning_present = (
            isinstance(thresholds, dict) and thresholds.get("warning") is not None
        )
        threshold_recovery_present = (
            isinstance(thresholds, dict) and (
                thresholds.get("critical_recovery") is not None
                or thresholds.get("warning_recovery") is not None
            )
        )

        # ── M82C: silenced scope count (from silenced dict) ───────────────────
        silenced_scope_count = (
            len(silenced) if isinstance(silenced, dict) else 0
        )

        return {
            "record_type": DATADOG_MONITOR,
            "provider": "datadog",
            "record_id": str(mid),
            "resource_id": str(mid),
            "resource_name": _trunc(raw.get("name") or "", _MAX_STR_LEN),
            "monitor_type": _trunc(raw.get("type") or "", 50),
            "enabled": enabled,
            "status": _trunc(raw.get("status") or "", 30),
            "priority_category": _priority_category(raw.get("priority")),
            # query NEVER stored — presence and complexity only
            "query_present": bool(isinstance(query, str) and query),
            "query_complexity_category": _length_category(query),
            # M82C: safe derivations from query (query discarded)
            "query_uses_wildcard_scope": query_uses_wildcard_scope,
            "query_group_by_count": query_group_by_count,
            # message NEVER stored — presence and length only
            "message_present": bool(isinstance(message, str) and message),
            "message_length_category": _length_category(message),
            # M82C: safe derivations from message (message discarded)
            "notification_routing_present": notification_routing_present,
            "notification_count": notification_count,
            "message_template_present": message_template_present,
            "tag_count": len(tags) if isinstance(tags, list) else 0,
            "threshold_count": len(thresholds) if isinstance(thresholds, dict) else 0,
            # M82C: individual threshold presence booleans
            "threshold_critical_present": threshold_critical_present,
            "threshold_warning_present": threshold_warning_present,
            "threshold_recovery_present": threshold_recovery_present,
            "renotify_enabled": bool(options.get("renotify_interval")),
            "renotify_interval_category": _renotify_interval_category(
                options.get("renotify_interval")
            ),
            "restricted_roles_count": len(restricted_roles) if isinstance(restricted_roles, list) else 0,
            "notify_no_data": _bool(options.get("notify_no_data", False)),
            "include_tags": _bool(options.get("include_tags", True)),
            # M82C: additional option booleans
            "notify_audit": _bool(options.get("notify_audit", False)),
            "require_full_window": _bool(options.get("require_full_window", True)),
            "evaluation_delay_category": _eval_delay_category(eval_delay),
            # M82C: derived silenced scope count and no-data timeframe category
            "silenced_scope_count": silenced_scope_count,
            "no_data_timeframe_category": _no_data_timeframe_category(
                options.get("no_data_timeframe")
            ),
        }

    @staticmethod
    def _normalize_slo(raw: dict) -> Optional[dict]:
        """Normalize one Datadog SLO record.

        SECURITY: raw SLO description, raw query strings (metric SLOs), and
        all raw SLO API response payload are NEVER stored.
        """
        slo_id = raw.get("id", "")
        if not isinstance(slo_id, str) or not slo_id.strip():
            return None

        thresholds = raw.get("thresholds") or []
        monitor_ids = raw.get("monitor_ids") or []
        groups = raw.get("groups") or []
        tags = raw.get("tags") or []
        # description NEVER stored
        description = raw.get("description", "")

        # Extract primary and warning targets from thresholds list
        primary_target: Any = None
        warning_target: Any = None
        for t in (thresholds if isinstance(thresholds, list) else []):
            if not isinstance(t, dict):
                continue
            tv = t.get("target")
            wv = t.get("warning")
            if tv is not None and primary_target is None:
                primary_target = tv
            if wv is not None and warning_target is None:
                warning_target = wv

        return {
            "record_type": DATADOG_SLO,
            "provider": "datadog",
            "record_id": _trunc(slo_id, 100),
            "resource_id": _trunc(slo_id, 100),
            "resource_name": _trunc(raw.get("name") or "", _MAX_STR_LEN),
            "slo_type": _trunc(raw.get("type") or "", 30),
            "target_category": _target_category(primary_target),
            "warning_target_category": _target_category(warning_target),
            "timeframe_count": len(thresholds) if isinstance(thresholds, list) else 0,
            "monitor_count": len(monitor_ids) if isinstance(monitor_ids, list) else 0,
            "group_count": len(groups) if isinstance(groups, list) else 0,
            "tag_count": len(tags) if isinstance(tags, list) else 0,
            # description NEVER stored — presence and length only
            "description_present": bool(isinstance(description, str) and description),
            "description_length_category": _length_category(description),
        }

    @staticmethod
    def _normalize_dashboard(raw: dict) -> Optional[dict]:
        """Normalize one Datadog dashboard record.

        SECURITY: raw dashboard JSON, widget queries, widget formulas,
        template variable defaults, public URL strings, and all raw dashboard
        API response payload are NEVER stored.
        """
        dash_id = raw.get("id", "")
        if not isinstance(dash_id, str) or not dash_id.strip():
            return None

        widgets = raw.get("widgets") or []
        template_variables = raw.get("template_variables") or []
        restricted_roles = raw.get("restricted_roles") or []
        # description NEVER stored
        description = raw.get("description", "")

        return {
            "record_type": DATADOG_DASHBOARD,
            "provider": "datadog",
            "record_id": _trunc(dash_id, 100),
            "resource_id": _trunc(dash_id, 100),
            "resource_name": _trunc(raw.get("title") or "", _MAX_STR_LEN),
            "layout_type": _trunc(raw.get("layout_type") or "", 30),
            "widget_count": len(widgets) if isinstance(widgets, list) else 0,
            "template_variable_count": len(template_variables) if isinstance(template_variables, list) else 0,
            "restricted_roles_count": len(restricted_roles) if isinstance(restricted_roles, list) else 0,
            # public URL NEVER stored — presence boolean only
            "public_url_present": bool(raw.get("url")),
            # description NEVER stored — presence and length only
            "description_present": bool(isinstance(description, str) and description),
            "description_length_category": _length_category(description),
        }

    @staticmethod
    def _normalize_webhook(raw: dict) -> Optional[dict]:
        """Normalize one Datadog webhook integration record.

        SECURITY: webhook URL (full string), custom HTTP header names/values,
        payload template body, and signing secrets are NEVER stored. The URL is
        read transiently to derive only the scheme category, then discarded.
        Custom header keys are scanned for auth patterns only (boolean result),
        then discarded. Neither header names nor values are retained.
        M82C expands with additional safe derived fields.
        """
        name = raw.get("name", "")
        if not isinstance(name, str) or not name.strip():
            return None

        # ── M82C: safe URL scheme category (URL string NEVER stored) ──────────
        url_str = raw.get("url", "")
        url_scheme_cat = _url_scheme_category(url_str)

        # ── M82C: custom header count and auth detection (names NEVER stored) ──
        raw_custom_headers = raw.get("custom_headers", "")
        custom_header_count = _count_headers(raw_custom_headers)
        auth_material_present = _detect_webhook_auth_material(raw_custom_headers)

        # ── M82C: secret headers count (secret values NEVER stored) ──────────
        raw_secret_headers = raw.get("secret_headers", "")
        secret_headers_count = _count_headers(raw_secret_headers)

        # ── M82C: payload template length category (content NEVER stored) ─────
        payload_str = raw.get("payload", "")
        payload_template_length_cat = _length_category(payload_str)

        # ── M82C: encode_as safe category ─────────────────────────────────────
        encode_as = raw.get("encode_as", "")
        if encode_as == "json":
            encode_as_category = "json"
        elif encode_as == "form":
            encode_as_category = "form"
        else:
            encode_as_category = "unknown"

        return {
            "record_type": DATADOG_WEBHOOK_INTEGRATION,
            "provider": "datadog",
            "record_id": _trunc(name, 100),
            "resource_id": _trunc(name, 100),
            "resource_name": _trunc(name, 100),
            # URL NEVER stored — presence boolean + scheme category only (M82C)
            "url_present": bool(url_str),
            "url_scheme_category": url_scheme_cat,
            # custom_headers NEVER stored — presence boolean + count + auth detection (M82C)
            "custom_headers_present": bool(raw_custom_headers),
            "custom_header_count": custom_header_count,
            "auth_material_present": auth_material_present,
            # payload_template NEVER stored — presence boolean + length category (M82C)
            "payload_template_present": bool(payload_str),
            "payload_template_length_category": payload_template_length_cat,
            # secret_headers NEVER stored — presence boolean + count (M82C)
            "secret_headers_present": bool(raw_secret_headers),
            "secret_headers_count": secret_headers_count,
            # encode_as: safe category label (M82C)
            "encode_as_category": encode_as_category,
        }

    @staticmethod
    def _normalize_notification_integration(
        integration_type: str,
        raw: Any,
    ) -> Optional[dict]:
        """Normalize one Datadog notification integration record.

        SECURITY: service API keys, subdomain strings, PagerDuty service
        keys, Slack channel names/IDs, OpsGenie API keys, email addresses,
        webhook URLs, and all destination handle values are NEVER stored.
        """
        if raw is None:
            return None

        enabled = True  # presence of a response means it's configured
        handle_count = 0
        channel_count = 0
        restricted_roles_count = 0

        if isinstance(raw, dict):
            # PagerDuty: services list
            if integration_type == "pagerduty":
                services = raw.get("services") or []
                handle_count = len(services) if isinstance(services, list) else 0
            # Slack: channels list
            elif integration_type == "slack":
                channels = raw.get("channels") or []
                channel_count = len(channels) if isinstance(channels, list) else 0
            # OpsGenie: services list
            elif integration_type == "opsgenie":
                services = raw.get("services") or []
                handle_count = len(services) if isinstance(services, list) else 0

        rec_id = f"datadog_notif_{integration_type}"
        return {
            "record_type": DATADOG_NOTIFICATION_INTEGRATION,
            "provider": "datadog",
            "record_id": rec_id,
            "resource_id": rec_id,
            "resource_name": integration_type.capitalize(),
            "integration_type": integration_type,
            "enabled": enabled,
            "handle_count": handle_count,
            "channel_count": channel_count,
            "restricted_roles_count": restricted_roles_count,
        }

    @staticmethod
    def _normalize_api_key(raw: dict) -> Optional[dict]:
        """Normalize one Datadog API key metadata record.

        SECURITY: the API key value is NEVER stored. last4 digits are stored
        as a boolean presence flag only. created_by identity is NEVER stored.
        """
        if not isinstance(raw, dict):
            return None

        # v2 API: data is under "attributes"
        attrs = raw.get("attributes") if isinstance(raw.get("attributes"), dict) else raw
        key_id = raw.get("id", "") or attrs.get("id", "")
        if not key_id:
            return None

        name = attrs.get("name", "")
        last4 = attrs.get("last4", "")
        created_by = attrs.get("created_by") or attrs.get("created_by_uuid")

        return {
            "record_type": DATADOG_API_KEY_METADATA,
            "provider": "datadog",
            "record_id": _trunc(str(key_id), 100),
            "resource_id": _trunc(str(key_id), 100),
            "resource_name": _trunc(str(name), _MAX_STR_LEN),
            "created_present": bool(attrs.get("created_at") or attrs.get("created")),
            "modified_present": bool(attrs.get("modified_at") or attrs.get("last_modified")),
            # last4 NEVER stored — presence only
            "last4_present": bool(isinstance(last4, str) and last4),
            # created_by identity NEVER stored — presence only
            "created_by_present": bool(created_by),
            "disabled": _bool(attrs.get("disabled") or attrs.get("blocked", False)),
        }

    @staticmethod
    def _normalize_app_key(raw: dict) -> Optional[dict]:
        """Normalize one Datadog application key metadata record.

        SECURITY: the application key value and hash are NEVER stored.
        owned_by identity (user info) is NEVER stored.
        """
        if not isinstance(raw, dict):
            return None

        attrs = raw.get("attributes") if isinstance(raw.get("attributes"), dict) else raw
        key_id = raw.get("id", "") or attrs.get("id", "")
        if not key_id:
            return None

        name = attrs.get("name", "")
        scopes = attrs.get("scopes") or []
        owned_by = attrs.get("owned_by")

        return {
            "record_type": DATADOG_APPLICATION_KEY_METADATA,
            "provider": "datadog",
            "record_id": _trunc(str(key_id), 100),
            "resource_id": _trunc(str(key_id), 100),
            "resource_name": _trunc(str(name), _MAX_STR_LEN),
            "created_present": bool(attrs.get("created_at") or attrs.get("created")),
            "modified_present": bool(attrs.get("modified_at") or attrs.get("last_modified")),
            # scope names NEVER stored — count only
            "scopes_count": len(scopes) if isinstance(scopes, list) else 0,
            # owned_by identity NEVER stored — presence only
            "owned_by_present": bool(owned_by),
        }

    @staticmethod
    def _normalize_role(raw: dict) -> Optional[dict]:
        """Normalize one Datadog role record.

        SECURITY: user identities, user IDs, user emails, user names, and
        team member lists are NEVER stored.
        """
        if not isinstance(raw, dict):
            return None

        attrs = raw.get("attributes") if isinstance(raw.get("attributes"), dict) else raw
        role_id = raw.get("id", "") or attrs.get("id", "")
        if not role_id:
            return None

        name = attrs.get("name", "")
        # Permission count from relationship or attribute
        rels = raw.get("relationships") if isinstance(raw.get("relationships"), dict) else {}
        perms_data = rels.get("permissions", {}) if isinstance(rels.get("permissions"), dict) else {}
        perms_list = perms_data.get("data") or []
        permission_count = len(perms_list) if isinstance(perms_list, list) else _int(attrs.get("user_count"), 0)

        user_count = _int(attrs.get("user_count"), 0)
        team_count = _int(attrs.get("group_count") or attrs.get("team_count"), 0)

        return {
            "record_type": DATADOG_ROLE,
            "provider": "datadog",
            "record_id": _trunc(str(role_id), 100),
            "resource_id": _trunc(str(role_id), 100),
            "resource_name": _trunc(str(name), _MAX_STR_LEN),
            "permission_count": permission_count,
            # user identities NEVER stored — count only
            "user_count": user_count,
            # team identities NEVER stored — count only
            "team_count": team_count,
        }

    @staticmethod
    def _normalize_team(raw: dict) -> Optional[dict]:
        """Normalize one Datadog team record.

        SECURITY: member names, member emails, member IDs, and team handles
        are NEVER stored. handle_present is a boolean only.
        """
        if not isinstance(raw, dict):
            return None

        attrs = raw.get("attributes") if isinstance(raw.get("attributes"), dict) else raw
        team_id = raw.get("id", "") or attrs.get("id", "")
        if not team_id:
            return None

        name = attrs.get("name", "")
        # handle NEVER stored — presence only
        handle = attrs.get("handle", "")
        member_count = _int(attrs.get("user_count") or attrs.get("member_count"), 0)
        links = attrs.get("links") or []
        link_count = len(links) if isinstance(links, list) else 0

        return {
            "record_type": DATADOG_TEAM,
            "provider": "datadog",
            "record_id": _trunc(str(team_id), 100),
            "resource_id": _trunc(str(team_id), 100),
            "resource_name": _trunc(str(name), _MAX_STR_LEN),
            # member identities NEVER stored — count only
            "member_count": member_count,
            # handle NEVER stored — presence only
            "handle_present": bool(isinstance(handle, str) and handle),
            "link_count": link_count,
        }

    @staticmethod
    def _normalize_cloud_integration(
        cloud_provider: str,
        raw: Any,
        index: int,
    ) -> Optional[dict]:
        """Normalize one Datadog cloud integration record.

        SECURITY: AWS account IDs, GCP project IDs, Azure tenant/subscription
        IDs, IAM role ARNs, service account email addresses, and all raw
        credential fields are NEVER stored. account_id_present is a boolean only.
        """
        if not isinstance(raw, dict):
            return None

        # RECORD_ID STABILITY TRADEOFF (deferred — M82 QA):
        # The only stable, non-secret identifier Datadog exposes for a cloud
        # integration is the account ID (AWS account_id / GCP project_id /
        # Azure tenant). ConfigTrace deliberately treats those as sensitive and
        # NEVER stores them (account_id_present is a boolean only), so they are
        # not available to seed a deterministic record_id. cloud_provider is the
        # only stable category field, but there can be multiple integrations per
        # provider, so a positional index is unavoidable here. The index is
        # stable only as long as the Datadog API returns accounts in a stable
        # order within a single sync; a reordered account list could reassign
        # record_ids. A deterministic-hash approach is deferred because every
        # candidate stable input (account_id, ARN, project_id, tenant) is on the
        # never-store list. Keeping the index keeps this surface privacy-safe at
        # the cost of perfect cross-sync record_id stability.
        rec_id = f"datadog_cloud_{cloud_provider}_{index}"
        resource_name = f"{cloud_provider.upper()} integration"

        # Determine account_id presence without storing the value
        account_id: Any = None
        if cloud_provider == "aws":
            account_id = raw.get("account_id") or raw.get("id")
        elif cloud_provider == "gcp":
            account_id = raw.get("project_id") or raw.get("id")
        elif cloud_provider == "azure":
            account_id = raw.get("tenant_name") or raw.get("id")

        # Tags count — tag keys are configuration-level, tag values may be sensitive
        account_tags = raw.get("account_specific_namespace_rules") or raw.get("host_tags") or []
        account_tags_count = len(account_tags) if isinstance(account_tags, list) else 0

        # Namespace count (metric namespaces)
        excluded_regions = raw.get("excluded_regions") or []
        namespace_count = len(excluded_regions) if isinstance(excluded_regions, list) else 0

        return {
            "record_type": DATADOG_CLOUD_INTEGRATION,
            "provider": "datadog",
            "record_id": rec_id,
            "resource_id": rec_id,
            "resource_name": resource_name,
            "cloud_provider": cloud_provider,
            # account ID NEVER stored — presence only
            "account_id_present": bool(account_id),
            "resource_collection_enabled": _bool(
                raw.get("resource_collection_enabled", False)
            ),
            "metric_collection_enabled": _bool(
                raw.get("metrics_collection_enabled")
                if raw.get("metrics_collection_enabled") is not None
                else raw.get("metric_collection_enabled", True)
            ),
            "log_collection_enabled": _bool(
                raw.get("logs_enabled") or raw.get("log_analytics_enabled", False)
            ),
            "account_tags_count": account_tags_count,
            "namespace_count": namespace_count,
        }

    # ── Per-surface fetch helpers ─────────────────────────────────────────────

    def _fetch_monitors(self, client: httpx.Client) -> list[dict]:
        """Fetch Datadog monitors. Never stores raw query or message."""
        try:
            # Datadog v1 monitors: GET /api/v1/monitor with pagination
            records: list[dict] = []
            for page_num in range(_MAX_PAGES):
                start = page_num * _PAGE_SIZE
                data = self._get(
                    client,
                    "/api/v1/monitor",
                    params={"page_size": _PAGE_SIZE, "page": page_num},
                )
                if not isinstance(data, list):
                    break
                for raw in data:
                    if not isinstance(raw, dict):
                        continue
                    rec = self._normalize_monitor(raw)
                    if rec is not None:
                        records.append(rec)
                if len(data) < _PAGE_SIZE:
                    break
                if len(records) >= _MAX_MONITORS:
                    break
            return records[:_MAX_MONITORS]
        except ConnectorError as exc:
            if getattr(exc, "status_code", None) in (403, 404):
                logger.debug("datadog: monitors not accessible (%d); skipping", getattr(exc, "status_code", 0))
                return []
            raise

    def _fetch_slos(self, client: httpx.Client) -> list[dict]:
        """Fetch Datadog SLOs. Never stores raw description or queries."""
        try:
            records: list[dict] = []
            for page_num in range(_MAX_PAGES):
                data = self._get(
                    client,
                    "/api/v1/slo",
                    params={"limit": _PAGE_SIZE, "offset": page_num * _PAGE_SIZE},
                )
                raws: list = []
                if isinstance(data, list):
                    raws = data
                elif isinstance(data, dict):
                    raws = data.get("data") or []
                if not raws:
                    break
                for raw in raws:
                    if not isinstance(raw, dict):
                        continue
                    rec = self._normalize_slo(raw)
                    if rec is not None:
                        records.append(rec)
                if len(raws) < _PAGE_SIZE:
                    break
                if len(records) >= _MAX_SLOS:
                    break
            return records[:_MAX_SLOS]
        except ConnectorError as exc:
            if getattr(exc, "status_code", None) in (403, 404):
                logger.debug("datadog: SLOs not accessible; skipping")
                return []
            raise

    def _fetch_dashboards(self, client: httpx.Client) -> list[dict]:
        """Fetch Datadog dashboards. Never stores raw JSON or widget queries."""
        try:
            data = self._get(client, "/api/v1/dashboard")
            raws: list = []
            if isinstance(data, list):
                raws = data
            elif isinstance(data, dict):
                raws = data.get("dashboards") or []
            records = []
            for raw in raws[:_MAX_DASHBOARDS]:
                if not isinstance(raw, dict):
                    continue
                rec = self._normalize_dashboard(raw)
                if rec is not None:
                    records.append(rec)
            return records
        except ConnectorError as exc:
            if getattr(exc, "status_code", None) in (403, 404):
                logger.debug("datadog: dashboards not accessible; skipping")
                return []
            raise

    def _fetch_webhook_integrations(self, client: httpx.Client) -> list[dict]:
        """Fetch Datadog webhook integrations. Never stores URL, headers, payload, or secrets."""
        try:
            data = self._get(client, "/api/v1/integration/webhooks/configuration/webhooks")
            # Response: {"webhook_names": ["name1", ...]} or a list
            webhook_names: list = []
            if isinstance(data, dict):
                webhook_names = data.get("webhook_names") or []
            elif isinstance(data, list):
                webhook_names = data

            records = []
            for name in webhook_names[:_MAX_WEBHOOKS]:
                if not isinstance(name, str) or not name.strip():
                    continue
                try:
                    raw = self._get(
                        client,
                        f"/api/v1/integration/webhooks/configuration/webhooks/{name}",
                    )
                    if isinstance(raw, dict):
                        rec = self._normalize_webhook(raw)
                        if rec is not None:
                            records.append(rec)
                except ConnectorError:
                    # Per-webhook fetch failure is non-fatal
                    records.append({
                        "record_type": DATADOG_WEBHOOK_INTEGRATION,
                        "provider": "datadog",
                        "record_id": _trunc(name, 100),
                        "resource_id": _trunc(name, 100),
                        "resource_name": _trunc(name, 100),
                        "url_present": True,  # it exists but we can't read details
                        "custom_headers_present": False,
                        "payload_template_present": False,
                        "secret_headers_present": False,
                        # M82C derived fields — safe defaults matching TypedDict schema
                        "url_scheme_category": "unknown",
                        "custom_header_count": 0,
                        "auth_material_present": False,
                        "payload_template_length_category": "absent",
                        "secret_headers_count": 0,
                        "encode_as_category": "unknown",
                    })
            return records
        except ConnectorError as exc:
            if getattr(exc, "status_code", None) in (403, 404):
                logger.debug("datadog: webhook integrations not accessible; skipping")
                return []
            raise

    def _fetch_notification_integrations(self, client: httpx.Client) -> list[dict]:
        """Fetch Datadog notification integrations. Never stores handles, channels, or service keys."""
        records: list[dict] = []
        for itype in _NOTIFICATION_INTEGRATION_TYPES:
            try:
                path = f"/api/v1/integration/{itype}"
                data = self._get(client, path)
                rec = self._normalize_notification_integration(itype, data)
                if rec is not None:
                    records.append(rec)
            except ConnectorError as exc:
                if getattr(exc, "status_code", None) in (403, 404, 400):
                    # Not configured or not accessible — not an error
                    logger.debug("datadog: %s integration not accessible; skipping", itype)
                    continue
                logger.debug("datadog: %s integration fetch error (%s); skipping", itype, exc)
                continue
        return records

    def _fetch_api_keys(self, client: httpx.Client) -> list[dict]:
        """Fetch Datadog API key metadata. Never stores key value or last4 digits."""
        try:
            records: list[dict] = []
            for page_num in range(_MAX_PAGES):
                data = self._get(
                    client,
                    "/api/v2/api_keys",
                    params={"page[number]": page_num, "page[size]": _PAGE_SIZE},
                )
                raws: list = []
                if isinstance(data, dict):
                    raws = data.get("data") or []
                elif isinstance(data, list):
                    raws = data
                if not raws:
                    break
                for raw in raws:
                    rec = self._normalize_api_key(raw)
                    if rec is not None:
                        records.append(rec)
                if len(raws) < _PAGE_SIZE:
                    break
                if len(records) >= _MAX_API_KEYS:
                    break
            return records[:_MAX_API_KEYS]
        except ConnectorError as exc:
            if getattr(exc, "status_code", None) in (403, 404):
                logger.debug("datadog: API keys not accessible; skipping")
                return []
            raise

    def _fetch_application_keys(self, client: httpx.Client) -> list[dict]:
        """Fetch Datadog application key metadata. Never stores key value."""
        try:
            records: list[dict] = []
            for page_num in range(_MAX_PAGES):
                data = self._get(
                    client,
                    "/api/v2/application_keys",
                    params={"page[number]": page_num, "page[size]": _PAGE_SIZE},
                )
                raws: list = []
                if isinstance(data, dict):
                    raws = data.get("data") or []
                elif isinstance(data, list):
                    raws = data
                if not raws:
                    break
                for raw in raws:
                    rec = self._normalize_app_key(raw)
                    if rec is not None:
                        records.append(rec)
                if len(raws) < _PAGE_SIZE:
                    break
                if len(records) >= _MAX_APP_KEYS:
                    break
            return records[:_MAX_APP_KEYS]
        except ConnectorError as exc:
            if getattr(exc, "status_code", None) in (403, 404):
                logger.debug("datadog: application keys not accessible; skipping")
                return []
            raise

    def _fetch_roles(self, client: httpx.Client) -> list[dict]:
        """Fetch Datadog roles. Never stores user identities."""
        try:
            records: list[dict] = []
            for page_num in range(_MAX_PAGES):
                data = self._get(
                    client,
                    "/api/v2/roles",
                    params={"page[number]": page_num, "page[size]": _PAGE_SIZE},
                )
                raws: list = []
                if isinstance(data, dict):
                    raws = data.get("data") or []
                elif isinstance(data, list):
                    raws = data
                if not raws:
                    break
                for raw in raws:
                    rec = self._normalize_role(raw)
                    if rec is not None:
                        records.append(rec)
                if len(raws) < _PAGE_SIZE:
                    break
                if len(records) >= _MAX_ROLES:
                    break
            return records[:_MAX_ROLES]
        except ConnectorError as exc:
            if getattr(exc, "status_code", None) in (403, 404):
                logger.debug("datadog: roles not accessible; skipping")
                return []
            raise

    def _fetch_teams(self, client: httpx.Client) -> list[dict]:
        """Fetch Datadog teams. Never stores member identities or handles."""
        try:
            records: list[dict] = []
            for page_num in range(_MAX_PAGES):
                data = self._get(
                    client,
                    "/api/v2/teams",
                    params={"page[number]": page_num, "page[size]": _PAGE_SIZE},
                )
                raws: list = []
                if isinstance(data, dict):
                    raws = data.get("data") or []
                elif isinstance(data, list):
                    raws = data
                if not raws:
                    break
                for raw in raws:
                    rec = self._normalize_team(raw)
                    if rec is not None:
                        records.append(rec)
                if len(raws) < _PAGE_SIZE:
                    break
                if len(records) >= _MAX_TEAMS:
                    break
            return records[:_MAX_TEAMS]
        except ConnectorError as exc:
            if getattr(exc, "status_code", None) in (403, 404):
                logger.debug("datadog: teams not accessible; skipping")
                return []
            raise

    def _fetch_cloud_integrations(self, client: httpx.Client) -> list[dict]:
        """Fetch Datadog cloud integration posture. Never stores account IDs."""
        records: list[dict] = []

        # AWS integrations
        try:
            data = self._get(client, "/api/v1/integration/aws")
            accounts: list = []
            if isinstance(data, dict):
                accounts = data.get("accounts") or []
            elif isinstance(data, list):
                accounts = data
            for idx, raw in enumerate(accounts[:_MAX_CLOUD_INTEGRATIONS]):
                rec = self._normalize_cloud_integration("aws", raw, idx)
                if rec is not None:
                    records.append(rec)
        except ConnectorError as exc:
            if getattr(exc, "status_code", None) in (403, 404):
                logger.debug("datadog: AWS cloud integration not accessible; skipping")
            else:
                logger.debug("datadog: AWS cloud integration fetch error; skipping")

        # GCP integrations
        try:
            data = self._get(client, "/api/v1/integration/gcp")
            accounts_gcp: list = []
            if isinstance(data, dict):
                accounts_gcp = data.get("accounts") or []
            elif isinstance(data, list):
                accounts_gcp = data
            base_idx = len(records)
            for idx, raw in enumerate(accounts_gcp[:_MAX_CLOUD_INTEGRATIONS]):
                rec = self._normalize_cloud_integration("gcp", raw, base_idx + idx)
                if rec is not None:
                    records.append(rec)
        except ConnectorError as exc:
            if getattr(exc, "status_code", None) in (403, 404):
                logger.debug("datadog: GCP cloud integration not accessible; skipping")
            else:
                logger.debug("datadog: GCP cloud integration fetch error; skipping")

        # Azure integrations
        try:
            data = self._get(client, "/api/v1/integration/azure")
            accounts_az: list = []
            if isinstance(data, dict):
                accounts_az = data.get("accounts") or []
            elif isinstance(data, list):
                accounts_az = data
            base_idx = len(records)
            for idx, raw in enumerate(accounts_az[:_MAX_CLOUD_INTEGRATIONS]):
                rec = self._normalize_cloud_integration("azure", raw, base_idx + idx)
                if rec is not None:
                    records.append(rec)
        except ConnectorError as exc:
            if getattr(exc, "status_code", None) in (403, 404):
                logger.debug("datadog: Azure cloud integration not accessible; skipping")
            else:
                logger.debug("datadog: Azure cloud integration fetch error; skipping")

        return records

    # ── Activity event helpers (M82D) ────────────────────────────────────────

    @staticmethod
    def _activity_event(
        event_type: str,
        provider_event_id: str,
        metadata: dict,
    ) -> dict:
        """Build one synthesized config-state activity event envelope.

        PRIVACY: metadata must contain only safe scalar fields from the
        normalized drift record. Raw Datadog API payloads, audit actor
        identities, IP addresses, user agents, and credential material
        are NEVER included.
        """
        meta = dict(metadata)
        meta.setdefault("event_source", "datadog_activity_event")
        meta.setdefault("event_action", event_type)
        return {
            "event_type": event_type,
            "provider": "datadog",
            "source": "datadog_activity_event",
            "event_source": "datadog_activity_event",
            "provider_event_id": provider_event_id,
            "metadata": meta,
        }

    def _collect_monitor_activity_events(
        self, client: httpx.Client, events: list, day: str
    ) -> None:
        """Emit one config-state event per monitor found (never raw query/message)."""
        try:
            recs = self._fetch_monitors(client)
        except ConnectorError as exc:
            if getattr(exc, "status_code", None) in (403, 404):
                logger.debug("datadog_activity: monitors surface not accessible; skipping")
                return
            raise
        except Exception:  # noqa: BLE001
            logger.debug("datadog_activity: monitors surface skipped (unexpected error)")
            return
        for rec in recs:
            rid = rec.get("record_id", "")
            if not rid:
                continue
            event_type = (
                "datadog.api_key_metadata.disabled"
                if rec.get("record_type") == "datadog_api_key_metadata" and rec.get("disabled")
                else "datadog.monitor.updated"
            )
            meta: dict = {
                "resource_type": "monitor",
                "monitor_id": rid,
                "monitor_type": rec.get("monitor_type", ""),
                "enabled": rec.get("enabled", True),
                "status": rec.get("status", ""),
                "priority_category": rec.get("priority_category", "none"),
                "query_present": rec.get("query_present", False),
                "query_complexity_category": rec.get("query_complexity_category", "absent"),
                "query_uses_wildcard_scope": rec.get("query_uses_wildcard_scope", False),
                "query_group_by_count": rec.get("query_group_by_count", 0),
                "message_present": rec.get("message_present", False),
                "message_length_category": rec.get("message_length_category", "absent"),
                "notification_routing_present": rec.get("notification_routing_present", False),
                "notification_count": rec.get("notification_count", 0),
                "message_template_present": rec.get("message_template_present", False),
                "threshold_critical_present": rec.get("threshold_critical_present", False),
                "threshold_warning_present": rec.get("threshold_warning_present", False),
                "threshold_recovery_present": rec.get("threshold_recovery_present", False),
                "threshold_count": rec.get("threshold_count", 0),
                "renotify_enabled": rec.get("renotify_enabled", False),
                "renotify_interval_category": rec.get("renotify_interval_category", "disabled"),
                "restricted_roles_count": rec.get("restricted_roles_count", 0),
                "notify_audit": rec.get("notify_audit", False),
                "require_full_window": rec.get("require_full_window", True),
                "silenced_scope_count": rec.get("silenced_scope_count", 0),
                "no_data_timeframe_category": rec.get("no_data_timeframe_category", "none"),
                "tag_count": rec.get("tag_count", 0),
                "category": "datadog_configuration",
                "status_category": "observed",
                "operation_name": "datadog.monitor.observe",
                "operation_family": "datadog.monitor",
                "operation_action": "observe",
            }
            eid = f"datadog.monitor.updated:{rid}:{day}"
            events.append(self._activity_event("datadog.monitor.updated", eid, meta))

    def _collect_slo_activity_events(
        self, client: httpx.Client, events: list, day: str
    ) -> None:
        """Emit one config-state event per SLO found (never raw description)."""
        try:
            recs = self._fetch_slos(client)
        except ConnectorError as exc:
            if getattr(exc, "status_code", None) in (403, 404):
                logger.debug("datadog_activity: SLOs surface not accessible; skipping")
                return
            raise
        except Exception:  # noqa: BLE001
            logger.debug("datadog_activity: SLOs surface skipped (unexpected error)")
            return
        for rec in recs:
            rid = rec.get("record_id", "")
            if not rid:
                continue
            meta: dict = {
                "resource_type": "slo",
                "slo_id": rid,
                "slo_type": rec.get("slo_type", ""),
                "target_category": rec.get("target_category", "none"),
                "warning_target_category": rec.get("warning_target_category", "none"),
                "timeframe_count": rec.get("timeframe_count", 0),
                "monitor_count": rec.get("monitor_count", 0),
                "group_count": rec.get("group_count", 0),
                "tag_count": rec.get("tag_count", 0),
                "category": "datadog_configuration",
                "status_category": "observed",
                "operation_name": "datadog.slo.observe",
                "operation_family": "datadog.slo",
                "operation_action": "observe",
            }
            eid = f"datadog.slo.updated:{rid}:{day}"
            events.append(self._activity_event("datadog.slo.updated", eid, meta))

    def _collect_dashboard_activity_events(
        self, client: httpx.Client, events: list, day: str
    ) -> None:
        """Emit one config-state event per dashboard found (never raw JSON)."""
        try:
            recs = self._fetch_dashboards(client)
        except ConnectorError as exc:
            if getattr(exc, "status_code", None) in (403, 404):
                logger.debug("datadog_activity: dashboards surface not accessible; skipping")
                return
            raise
        except Exception:  # noqa: BLE001
            logger.debug("datadog_activity: dashboards surface skipped (unexpected error)")
            return
        for rec in recs:
            rid = rec.get("record_id", "")
            if not rid:
                continue
            meta: dict = {
                "resource_type": "dashboard",
                "dashboard_id": rid,
                "layout_type": rec.get("layout_type", ""),
                "widget_count": rec.get("widget_count", 0),
                "template_variable_count": rec.get("template_variable_count", 0),
                "restricted_roles_count": rec.get("restricted_roles_count", 0),
                "public_url_present": rec.get("public_url_present", False),
                "category": "datadog_configuration",
                "status_category": "observed",
                "operation_name": "datadog.dashboard.observe",
                "operation_family": "datadog.dashboard",
                "operation_action": "observe",
            }
            eid = f"datadog.dashboard.updated:{rid}:{day}"
            events.append(self._activity_event("datadog.dashboard.updated", eid, meta))

    def _collect_webhook_activity_events(
        self, client: httpx.Client, events: list, day: str
    ) -> None:
        """Emit one config-state event per webhook (never URL, headers, payload, secrets)."""
        try:
            recs = self._fetch_webhook_integrations(client)
        except ConnectorError as exc:
            if getattr(exc, "status_code", None) in (403, 404):
                logger.debug("datadog_activity: webhook integrations surface not accessible; skipping")
                return
            raise
        except Exception:  # noqa: BLE001
            logger.debug("datadog_activity: webhook integrations surface skipped (unexpected error)")
            return
        for rec in recs:
            rid = rec.get("record_id", "")
            if not rid:
                continue
            meta: dict = {
                "resource_type": "webhook_integration",
                "webhook_id": rid,
                "url_present": rec.get("url_present", False),
                "url_scheme_category": rec.get("url_scheme_category", "absent"),
                "custom_headers_present": rec.get("custom_headers_present", False),
                "custom_header_count": rec.get("custom_header_count", 0),
                "auth_material_present": rec.get("auth_material_present", False),
                "payload_template_present": rec.get("payload_template_present", False),
                "payload_template_length_category": rec.get("payload_template_length_category", "absent"),
                "secret_headers_present": rec.get("secret_headers_present", False),
                "secret_headers_count": rec.get("secret_headers_count", 0),
                "encode_as_category": rec.get("encode_as_category", "unknown"),
                "category": "datadog_configuration",
                "status_category": "observed",
                "operation_name": "datadog.webhook_integration.observe",
                "operation_family": "datadog.webhook_integration",
                "operation_action": "observe",
            }
            eid = f"datadog.webhook_integration.updated:{rid}:{day}"
            events.append(
                self._activity_event("datadog.webhook_integration.updated", eid, meta)
            )

    def _collect_notification_activity_events(
        self, client: httpx.Client, events: list, day: str
    ) -> None:
        """Emit one config-state event per notification integration (never handles/channels)."""
        try:
            recs = self._fetch_notification_integrations(client)
        except ConnectorError as exc:
            if getattr(exc, "status_code", None) in (403, 404):
                logger.debug("datadog_activity: notification integrations surface not accessible; skipping")
                return
            raise
        except Exception:  # noqa: BLE001
            logger.debug("datadog_activity: notification integrations surface skipped (unexpected error)")
            return
        for rec in recs:
            rid = rec.get("record_id", "")
            if not rid:
                continue
            meta: dict = {
                "resource_type": "notification_integration",
                "notification_integration_id": rid,
                "integration_type": rec.get("integration_type", ""),
                "enabled": rec.get("enabled", True),
                "handle_count": rec.get("handle_count", 0),
                "channel_count": rec.get("channel_count", 0),
                "category": "datadog_configuration",
                "status_category": "observed",
                "operation_name": "datadog.notification_integration.observe",
                "operation_family": "datadog.notification_integration",
                "operation_action": "observe",
            }
            eid = f"datadog.notification_integration.updated:{rid}:{day}"
            events.append(
                self._activity_event("datadog.notification_integration.updated", eid, meta)
            )

    def _collect_api_key_activity_events(
        self, client: httpx.Client, events: list, day: str
    ) -> None:
        """Emit one config-state event per API key metadata (never key value or last4)."""
        try:
            recs = self._fetch_api_keys(client)
        except ConnectorError as exc:
            if getattr(exc, "status_code", None) in (403, 404):
                logger.debug("datadog_activity: API keys surface not accessible; skipping")
                return
            raise
        except Exception:  # noqa: BLE001
            logger.debug("datadog_activity: API keys surface skipped (unexpected error)")
            return
        for rec in recs:
            rid = rec.get("record_id", "")
            if not rid:
                continue
            disabled = rec.get("disabled", False)
            event_type = (
                "datadog.api_key_metadata.disabled" if disabled
                else "datadog.api_key_metadata.updated"
            )
            meta: dict = {
                "resource_type": "api_key_metadata",
                "api_key_id": rid,
                "created_present": rec.get("created_present", False),
                "modified_present": rec.get("modified_present", False),
                "created_by_present": rec.get("created_by_present", False),
                "enabled": not disabled,
                "category": "datadog_configuration",
                "status_category": "observed",
                "operation_name": "datadog.api_key_metadata.observe",
                "operation_family": "datadog.api_key_metadata",
                "operation_action": "observe",
            }
            eid = f"{event_type}:{rid}:{day}"
            events.append(self._activity_event(event_type, eid, meta))

    def _collect_app_key_activity_events(
        self, client: httpx.Client, events: list, day: str
    ) -> None:
        """Emit one config-state event per application key metadata (never key value)."""
        try:
            recs = self._fetch_application_keys(client)
        except ConnectorError as exc:
            if getattr(exc, "status_code", None) in (403, 404):
                logger.debug("datadog_activity: application keys surface not accessible; skipping")
                return
            raise
        except Exception:  # noqa: BLE001
            logger.debug("datadog_activity: application keys surface skipped (unexpected error)")
            return
        for rec in recs:
            rid = rec.get("record_id", "")
            if not rid:
                continue
            meta: dict = {
                "resource_type": "application_key_metadata",
                "application_key_id": rid,
                "created_present": rec.get("created_present", False),
                "modified_present": rec.get("modified_present", False),
                "scopes_count": rec.get("scopes_count", 0),
                "owned_by_present": rec.get("owned_by_present", False),
                "category": "datadog_configuration",
                "status_category": "observed",
                "operation_name": "datadog.application_key_metadata.observe",
                "operation_family": "datadog.application_key_metadata",
                "operation_action": "observe",
            }
            eid = f"datadog.application_key_metadata.updated:{rid}:{day}"
            events.append(
                self._activity_event("datadog.application_key_metadata.updated", eid, meta)
            )

    def _collect_role_activity_events(
        self, client: httpx.Client, events: list, day: str
    ) -> None:
        """Emit one config-state event per role (never user identities)."""
        try:
            recs = self._fetch_roles(client)
        except ConnectorError as exc:
            if getattr(exc, "status_code", None) in (403, 404):
                logger.debug("datadog_activity: roles surface not accessible; skipping")
                return
            raise
        except Exception:  # noqa: BLE001
            logger.debug("datadog_activity: roles surface skipped (unexpected error)")
            return
        for rec in recs:
            rid = rec.get("record_id", "")
            if not rid:
                continue
            meta: dict = {
                "resource_type": "role",
                "role_id": rid,
                "permission_count": rec.get("permission_count", 0),
                "user_count": rec.get("user_count", 0),
                "team_count": rec.get("team_count", 0),
                "category": "datadog_configuration",
                "status_category": "observed",
                "operation_name": "datadog.role.observe",
                "operation_family": "datadog.role",
                "operation_action": "observe",
            }
            eid = f"datadog.role.updated:{rid}:{day}"
            events.append(self._activity_event("datadog.role.updated", eid, meta))

    def _collect_team_activity_events(
        self, client: httpx.Client, events: list, day: str
    ) -> None:
        """Emit one config-state event per team (never member identities or handles)."""
        try:
            recs = self._fetch_teams(client)
        except ConnectorError as exc:
            if getattr(exc, "status_code", None) in (403, 404):
                logger.debug("datadog_activity: teams surface not accessible; skipping")
                return
            raise
        except Exception:  # noqa: BLE001
            logger.debug("datadog_activity: teams surface skipped (unexpected error)")
            return
        for rec in recs:
            rid = rec.get("record_id", "")
            if not rid:
                continue
            meta: dict = {
                "resource_type": "team",
                "team_id": rid,
                "member_count": rec.get("member_count", 0),
                "handle_present": rec.get("handle_present", False),
                "link_count": rec.get("link_count", 0),
                "category": "datadog_configuration",
                "status_category": "observed",
                "operation_name": "datadog.team.observe",
                "operation_family": "datadog.team",
                "operation_action": "observe",
            }
            eid = f"datadog.team.updated:{rid}:{day}"
            events.append(self._activity_event("datadog.team.updated", eid, meta))

    def _collect_cloud_integration_activity_events(
        self, client: httpx.Client, events: list, day: str
    ) -> None:
        """Emit one config-state event per cloud integration (never account IDs)."""
        try:
            recs = self._fetch_cloud_integrations(client)
        except ConnectorError as exc:
            if getattr(exc, "status_code", None) in (403, 404):
                logger.debug("datadog_activity: cloud integrations surface not accessible; skipping")
                return
            raise
        except Exception:  # noqa: BLE001
            logger.debug("datadog_activity: cloud integrations surface skipped (unexpected error)")
            return
        for rec in recs:
            rid = rec.get("record_id", "")
            if not rid:
                continue
            meta: dict = {
                "resource_type": "cloud_integration",
                "cloud_integration_id": rid,
                "cloud_provider": rec.get("cloud_provider", ""),
                "account_id_present": rec.get("account_id_present", False),
                "resource_collection_enabled": rec.get("resource_collection_enabled", False),
                "metric_collection_enabled": rec.get("metric_collection_enabled", True),
                "log_collection_enabled": rec.get("log_collection_enabled", False),
                "account_tags_count": rec.get("account_tags_count", 0),
                "namespace_count": rec.get("namespace_count", 0),
                "category": "datadog_configuration",
                "status_category": "observed",
                "operation_name": "datadog.cloud_integration.observe",
                "operation_family": "datadog.cloud_integration",
                "operation_action": "observe",
            }
            eid = f"datadog.cloud_integration.updated:{rid}:{day}"
            events.append(
                self._activity_event("datadog.cloud_integration.updated", eid, meta)
            )

    def list_activity_events(
        self,
        credentials: dict,
        *,
        max_events: int = 100,
        lookback_hours: int = 24,
    ) -> list[dict]:
        """Synthesize review-safe Datadog configuration-state activity events (M82D).

        Datadog's audit/audit-trail API is identity-heavy: every entry
        includes actor email, actor UUID, and IP-level request metadata.
        Storing these fields would violate ConfigTrace's privacy contract.

        Instead, activity events are synthesized from the same 10 safe drift
        surfaces the drift connector already reads (monitors, SLOs, dashboards,
        webhook integrations, notification integrations, API key metadata,
        application key metadata, roles, teams, and cloud integrations).

        Each event represents configuration state observed at poll time.
        Events are day-scoped (UTC day-level) for idempotency: re-polling on
        the same UTC day yields the same provider_event_id and is a no-op.

        SOURCES THAT ARE NEVER INGESTED:
        - Datadog audit API (actor identity, IP, user agent, raw payload)
        - Datadog log data, trace data, metric values, incident content
        - Monitor raw query strings, monitor raw message text
        - Dashboard JSON, widget queries/formulas
        - Webhook URLs, headers, payload templates, signing secrets
        - Notification handles (Slack channels, PagerDuty service IDs)
        - User emails, user IDs, user names, IP addresses
        - API key values, application key values, OAuth tokens

        CLAIM DISCIPLINE: events are configuration-state evidence for review.
        This method does NOT confirm breach, compromise, unauthorized access,
        data exposure, or leaked credentials.

        Args:
            credentials: Dict with 'api_key', 'application_key', optional 'site'.
            max_events:  Maximum events to return (1–1000, default 100).
            lookback_hours: Lookback window hint (1–168, default 24).
                           Used for parameter validation only — synthesized
                           events are always day-scoped regardless of this value.

        Returns:
            List of safe, synthesized config-state event dicts.

        Raises:
            AuthenticationError: 401/403 from the Datadog API.
            RateLimitError: 429 rate limit hit.
            NetworkError: Transport-level failure.
            ConnectorError: Unexpected API error.
        """
        from datetime import datetime, timezone

        max_events = min(max(1, max_events), 1000)
        lookback_hours = min(max(1, lookback_hours), 168)  # noqa: F841

        day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        events: list[dict] = []

        site = _sanitize_site(credentials.get("site", "datadoghq.com"))
        api_key = credentials.get("api_key", "")
        application_key = credentials.get("application_key", "")

        with self._make_client(site, api_key, application_key) as client:
            self._collect_monitor_activity_events(client, events, day)
            self._collect_slo_activity_events(client, events, day)
            self._collect_dashboard_activity_events(client, events, day)
            self._collect_api_key_activity_events(client, events, day)
            self._collect_app_key_activity_events(client, events, day)
            try:
                self._collect_webhook_activity_events(client, events, day)
            except Exception:  # noqa: BLE001
                logger.debug("datadog_activity: webhook surface failed; skipping")
            try:
                self._collect_notification_activity_events(client, events, day)
            except Exception:  # noqa: BLE001
                logger.debug("datadog_activity: notification integration surface failed; skipping")
            try:
                self._collect_role_activity_events(client, events, day)
            except Exception:  # noqa: BLE001
                logger.debug("datadog_activity: roles surface failed; skipping")
            try:
                self._collect_team_activity_events(client, events, day)
            except Exception:  # noqa: BLE001
                logger.debug("datadog_activity: teams surface failed; skipping")
            try:
                self._collect_cloud_integration_activity_events(client, events, day)
            except Exception:  # noqa: BLE001
                logger.debug("datadog_activity: cloud integrations surface failed; skipping")

        return events[:max_events]

    # ── Public connector interface ─────────────────────────────────────────────

    def validate_credentials(self, credentials: dict) -> bool:
        """Verify Datadog credentials with a single lightweight API call.

        Uses GET /api/v2/api_keys?page[number]=0&page[size]=1 which requires
        both api_key and application_key. Returns True on success.

        SECURITY: api_key and application_key are NEVER stored on the instance.

        Raises:
            AuthenticationError: Credentials are invalid or lack permissions.
            ConnectorError: API returned an unexpected error.
            NetworkError: Transport-level failure.
        """
        site = _sanitize_site(credentials.get("site", "datadoghq.com"))
        api_key = credentials.get("api_key", "")
        application_key = credentials.get("application_key", "")

        if not api_key:
            raise AuthenticationError(
                "datadog: api_key is required",
                status_code=401,
            )
        if not application_key:
            raise AuthenticationError(
                "datadog: application_key is required",
                status_code=401,
            )

        with self._make_client(site, api_key, application_key) as client:
            self._get(
                client,
                "/api/v2/api_keys",
                params={"page[number]": 0, "page[size]": 1},
            )
        return True

    def fetch(self, credentials: dict) -> list[dict]:
        """Fetch all Datadog drift surfaces and return normalised records.

        Calls each surface fetcher in sequence. Soft-failure surfaces
        (notification integrations, cloud integrations) skip gracefully when
        permissions are absent, so partial permission sets still produce
        useful drift records.

        SECURITY: api_key and application_key are placed only in request
        headers, never stored on the connector instance, never logged, and
        discarded when the httpx.Client context manager exits.

        Logs, traces, metric values, and incident content are NEVER fetched.

        Args:
            credentials: Dict with 'api_key', 'application_key', and optional 'site'.

        Returns:
            Flat list of safe, normalised record dicts.

        Raises:
            AuthenticationError: 401/403 from the Datadog API.
            ConnectorError: Unexpected API error.
            RateLimitError: Rate limits exceeded.
            NetworkError: Transport-level failure.
        """
        site = _sanitize_site(credentials.get("site", "datadoghq.com"))
        api_key = credentials.get("api_key", "")
        application_key = credentials.get("application_key", "")

        records: list[dict] = []

        with self._make_client(site, api_key, application_key) as client:
            # Core surfaces — raise on hard errors
            records.extend(self._fetch_monitors(client))
            records.extend(self._fetch_slos(client))
            records.extend(self._fetch_dashboards(client))
            records.extend(self._fetch_api_keys(client))
            records.extend(self._fetch_application_keys(client))

            # Secondary surfaces — soft-fail on permission/availability errors
            try:
                records.extend(self._fetch_webhook_integrations(client))
            except Exception:  # noqa: BLE001
                logger.debug("datadog: webhook integrations fetch failed; skipping surface")
            try:
                records.extend(self._fetch_notification_integrations(client))
            except Exception:  # noqa: BLE001
                logger.debug("datadog: notification integrations fetch failed; skipping surface")
            try:
                records.extend(self._fetch_roles(client))
            except Exception:  # noqa: BLE001
                logger.debug("datadog: roles fetch failed; skipping surface")
            try:
                records.extend(self._fetch_teams(client))
            except Exception:  # noqa: BLE001
                logger.debug("datadog: teams fetch failed; skipping surface")
            try:
                records.extend(self._fetch_cloud_integrations(client))
            except Exception:  # noqa: BLE001
                logger.debug("datadog: cloud integrations fetch failed; skipping surface")

        return records
