"""Cloudflare DNS + WAF connector — M57.7 (rulesets).

Fetches DNS records and WAF ruleset metadata for a given zone, handles
pagination and rate-limit backoff, and returns a combined list of normalised
records.

Surfaces
--------
* **DNS records** (existing) — one ``CloudflareDNSRecord`` per DNS entry.
* **WAF rulesets** (M57.7) — one ``CloudflareRuleset`` per ruleset returned by
  ``GET /zones/{zone_id}/rulesets``.  Only aggregate metadata is stored; raw
  rule expressions are NEVER fetched or stored (data-minimisation constraint).

Usage
-----
    from app.connectors.cloudflare import CloudflareConnector

    connector = CloudflareConnector()
    records = connector.fetch({"api_token": "...", "zone_id": "..."})
    # records → [{"record_id": "abc123", "record_type": "A", ...},
    #            {"record_id": "...", "record_type": "cloudflare_ruleset", ...}]

Credentials dict
----------------
    api_token : str
        A Cloudflare API token with **Zone:Read** (or **Zone.DNS:Read** +
        **Zone.Firewall:Read**) permission scoped to the target zone.
        Never use a Global API Key here.
    zone_id : str
        The 32-character hexadecimal Zone ID found on the Cloudflare dashboard
        overview page for the domain.

SECURITY (M57.7)
----------------
- Rule expressions (``rule.expression`` field) are NEVER fetched or stored.
  They may contain sensitive path/hostname patterns.
- Only action counts and rule counts are stored — no raw statement content.
"""

from __future__ import annotations

import hashlib
import logging
import re
import time
from urllib.parse import urlparse

import httpx

from app.connectors.base import BaseConnector
from app.connectors.cloudflare_schema import (
    CLOUDFLARE_ACCESS_APPLICATION,
    CLOUDFLARE_ACCESS_POLICY,
    CLOUDFLARE_PAGE_RULE,
    CLOUDFLARE_RULESET,
    CLOUDFLARE_WAF_RULE,
    CLOUDFLARE_WORKER_ROUTE,
    CLOUDFLARE_WORKER_SCRIPT,
    CLOUDFLARE_ZONE_SETTING,
    CloudflareDNSRecord,
    CloudflareRuleset,
)
from app.connectors.exceptions import (
    AuthenticationError,
    ConnectorError,
    NetworkError,
    RateLimitError,
)

logger = logging.getLogger(__name__)

# ── Module-level constants ───────────────────────────────────────────────────

# Cloudflare Zones REST API base URL (no trailing slash)
_BASE_URL = "https://api.cloudflare.com/client/v4"

# Maximum number of records per page (Cloudflare cap)
_PER_PAGE = 100

# Number of 429-retry attempts before giving up.  The first request is
# attempt 0; the last allowed retry is attempt _MAX_RETRIES.
_MAX_RETRIES = 3

# Per-request HTTP timeout in seconds
_TIMEOUT = 30.0


# ── Normalisation helper ─────────────────────────────────────────────────────

def _normalize(raw: dict) -> CloudflareDNSRecord:
    """Map a raw Cloudflare API record dict to a ``CloudflareDNSRecord``.

    Only the fields defined in ``CloudflareDNSRecord`` are kept; all other
    Cloudflare-specific fields (zone_id, zone_name, locked, meta, etc.) are
    discarded to keep the stored state compact and provider-agnostic.
    """
    return {
        "record_id":   raw["id"],
        "record_type": raw["type"],
        "name":        raw["name"],
        "content":     raw["content"],
        "ttl":         raw["ttl"],
        "proxied":     raw.get("proxied", False),
        "priority":    raw.get("priority"),    # int for MX/SRV; None otherwise
        "comment":     raw.get("comment"),     # str or None
        "modified_on": raw.get("modified_on", ""),
    }


# ── Ruleset normalisation helper ─────────────────────────────────────────────

def _normalize_ruleset(raw: dict) -> CloudflareRuleset:
    """Map a raw Cloudflare rulesets API entry to a ``CloudflareRuleset``.

    SECURITY: ``rule.expression`` fields are explicitly skipped — they may
    contain sensitive path/hostname patterns.  Only aggregate counts and
    action-type summaries are stored.
    """
    # Count rules and their actions.  The ``rules`` list may be absent for
    # rulesets that have no rules configured yet.
    rules: list[dict] = raw.get("rules") or []
    rule_count = len(rules)
    enabled_rule_count = 0
    block_count = 0
    log_count = 0
    skip_count = 0
    challenge_count = 0
    managed_challenge_count = 0
    execute_count = 0

    for rule in rules:
        if rule.get("enabled", True):  # rules default to enabled
            enabled_rule_count += 1
        action = (rule.get("action") or "").lower()
        if action == "block":
            block_count += 1
        elif action == "log":
            log_count += 1
        elif action == "skip":
            skip_count += 1
        elif action in ("challenge", "js_challenge"):
            challenge_count += 1
        elif action == "managed_challenge":
            managed_challenge_count += 1
        elif action == "execute":
            execute_count += 1

    return {
        "record_type":            CLOUDFLARE_RULESET,
        "record_id":              raw.get("id") or "",
        "name":                   raw.get("name") or "",
        "kind":                   raw.get("kind") or "unknown",
        "phase":                  raw.get("phase") or "unknown",
        "version":                str(raw.get("version") or ""),
        "rule_count":             rule_count,
        "enabled_rule_count":     enabled_rule_count,
        "block_count":            block_count,
        "log_count":              log_count,
        "skip_count":             skip_count,
        "challenge_count":        challenge_count,
        "managed_challenge_count": managed_challenge_count,
        "execute_count":          execute_count,
        "last_updated":           raw.get("last_updated"),
    }


# ── Connector class ──────────────────────────────────────────────────────────

class CloudflareConnector(BaseConnector):
    """Connector for Cloudflare DNS records via the Zones API.

    This class is stateless.  Create a new instance per fetch operation or
    reuse a single instance freely — there is no shared mutable state.
    """

    # ── Public API ───────────────────────────────────────────────────────────

    def fetch(self, credentials: dict) -> list[dict]:
        """Fetch all DNS records for the zone and return normalised dicts.

        Paginates through every page of results using the ``result_info``
        envelope until ``total_count`` records have been retrieved.

        Rate-limit responses (HTTP 429) are retried up to ``_MAX_RETRIES``
        times.  The delay between retries is read from the ``Retry-After``
        response header; if the header is absent, 60 seconds is used as a
        conservative default.

        Args:
            credentials: Must contain ``api_token`` and ``zone_id``.

        Returns:
            A list of ``CloudflareDNSRecord`` dicts (plain dicts, not TypedDict
            instances — they are directly JSON-serialisable into
            ``Snapshot.state``).

        Raises:
            ConnectorError:      Missing or malformed credentials, or the
                                 Cloudflare API returned ``success=false``.
            AuthenticationError: HTTP 401 or 403.
            RateLimitError:      HTTP 429 after all retries are exhausted.
            NetworkError:        Timeout or transport-level failure.
        """
        api_token, zone_id = self._extract_credentials(credentials)
        headers = self._auth_headers(api_token)
        url = f"{_BASE_URL}/zones/{zone_id}/dns_records"

        records: list[dict] = []
        page = 1

        with httpx.Client(timeout=_TIMEOUT) as client:
            while True:
                response = self._get(
                    client,
                    url,
                    headers,
                    params={"page": page, "per_page": _PER_PAGE},
                )
                body = response.json()

                if not body.get("success"):
                    errors = body.get("errors", [])
                    raise ConnectorError(
                        f"Cloudflare API returned success=false: {errors}",
                        status_code=response.status_code,
                    )

                for raw in body.get("result", []):
                    records.append(_normalize(raw))

                result_info: dict = body.get("result_info", {})
                total_count: int = result_info.get("total_count", 0)
                per_page: int = result_info.get("per_page", _PER_PAGE)

                logger.debug(
                    "cloudflare_connector zone=%s page=%d fetched=%d total=%d",
                    zone_id,
                    page,
                    len(records),
                    total_count,
                )

                # Stop when we have retrieved at least total_count records.
                # Using page * per_page rather than len(records) so that a
                # partially-filled last page also terminates the loop.
                if page * per_page >= total_count:
                    break
                page += 1

            # M57.7: fetch WAF ruleset metadata (fail-soft).
            # If the token lacks Firewall:Read scope or the endpoint is not
            # available for the plan tier, we log a warning and continue — the
            # DNS records are still returned.
            ruleset_records = self._fetch_rulesets(client, zone_id, headers)
            records.extend(ruleset_records)

            # ── M59.7: zone settings, page rules, worker routes, granular WAF
            # rules, Access applications/policies, worker scripts.  Each
            # surface is fetched with the same fail-soft pattern: if the
            # token lacks the relevant scope (401/403) or the endpoint is
            # unavailable for the plan (404/422), a safe warning is logged
            # and an empty list is returned.  DNS sync is never blocked
            # by a missing optional permission.
            records.extend(self._fetch_zone_settings(client, zone_id, headers))
            records.extend(self._fetch_page_rules(client, zone_id, headers))
            records.extend(self._fetch_worker_routes(client, zone_id, headers))
            records.extend(self._fetch_waf_rules(client, zone_id, headers))

            # Account-scoped surfaces — resolve the parent account_id first.
            account_id = self._resolve_account_id(client, zone_id, headers)
            if account_id:
                records.extend(
                    self._fetch_worker_scripts(client, account_id, headers)
                )
                app_records = self._fetch_access_applications(
                    client, account_id, headers
                )
                records.extend(app_records)
                # Policies require an application id; iterate the apps
                # already fetched above.
                for app in app_records:
                    app_id = app.get("record_id")
                    if not app_id:
                        continue
                    records.extend(
                        self._fetch_access_policies(
                            client, account_id, app_id, headers
                        )
                    )

        return records

    # ── M57.7: WAF ruleset helpers ───────────────────────────────────────────

    def _fetch_rulesets(
        self,
        client: httpx.Client,
        zone_id: str,
        headers: dict[str, str],
    ) -> list[dict]:
        """Fetch WAF ruleset metadata for the zone.

        Calls ``GET /zones/{zone_id}/rulesets`` once (the response is not
        paginated by Cloudflare — all rulesets are returned in a single reply).

        Returns one ``cloudflare_ruleset`` record per ruleset.

        Fail-soft: if the token lacks Firewall:Read permission (HTTP 403) or
        the account plan does not support the Rulesets API (HTTP 404/422), a
        warning is logged and an empty list is returned.  DNS records are not
        affected.

        SECURITY:
        - Rule expressions (``rule.expression``) are NEVER read or stored.
          They may contain sensitive host/path pattern strings.
        - Only action counts and summary flags are kept.
        """
        url = f"{_BASE_URL}/zones/{zone_id}/rulesets"
        try:
            response = client.get(url, headers=headers)
        except httpx.TimeoutException as exc:
            logger.warning(
                "cloudflare: ruleset fetch timed out  zone=%s  error=%s",
                zone_id, exc,
            )
            return []
        except httpx.RequestError as exc:
            logger.warning(
                "cloudflare: ruleset fetch network error  zone=%s  error=%s",
                zone_id, exc,
            )
            return []

        if response.status_code in (401, 403):
            logger.warning(
                "cloudflare: token lacks Firewall:Read — "
                "skipping ruleset monitoring for this sync  zone=%s  http=%d",
                zone_id, response.status_code,
            )
            return []

        if response.status_code in (404, 422):
            logger.warning(
                "cloudflare: rulesets endpoint not available  "
                "zone=%s  http=%d  (plan may not include WAF API)",
                zone_id, response.status_code,
            )
            return []

        if not response.is_success:
            logger.warning(
                "cloudflare: ruleset fetch failed  zone=%s  http=%d",
                zone_id, response.status_code,
            )
            return []

        try:
            body = response.json()
        except Exception:
            logger.warning(
                "cloudflare: ruleset response is not valid JSON  zone=%s",
                zone_id,
            )
            return []

        if not body.get("success"):
            errors = body.get("errors", [])
            logger.warning(
                "cloudflare: rulesets API returned success=false  "
                "zone=%s  errors=%s",
                zone_id, errors,
            )
            return []

        records: list[dict] = []
        for raw in body.get("result") or []:
            ruleset_id: str = raw.get("id") or ""
            if not ruleset_id:
                continue
            rec = _normalize_ruleset(raw)
            records.append(rec)

        logger.debug(
            "cloudflare_connector zone=%s rulesets fetched=%d",
            zone_id, len(records),
        )
        return records

    def validate_credentials(self, credentials: dict) -> bool:
        """Verify that the token has Zone.DNS:Read access to the zone.

        Issues a single ``GET /zones/{zone_id}/dns_records?per_page=1`` call
        — the lightest possible probe that exercises both authentication and
        zone-scoped permission.

        Args:
            credentials: Must contain ``api_token`` and ``zone_id``.

        Returns:
            ``True`` if the credentials are valid.

        Raises:
            AuthenticationError: HTTP 401 or 403 response.
            ConnectorError:      Any other API error.
            NetworkError:        Timeout or transport failure.
        """
        api_token, zone_id = self._extract_credentials(credentials)
        headers = self._auth_headers(api_token)
        url = f"{_BASE_URL}/zones/{zone_id}/dns_records"

        with httpx.Client(timeout=_TIMEOUT) as client:
            self._get(client, url, headers, params={"page": 1, "per_page": 1})

        return True

    # ── Private helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _extract_credentials(credentials: dict) -> tuple[str, str]:
        """Return ``(api_token, zone_id)`` or raise ``ConnectorError``."""
        api_token = credentials.get("api_token", "")
        zone_id = credentials.get("zone_id", "")
        if not api_token or not zone_id:
            raise ConnectorError(
                "Cloudflare credentials must include 'api_token' and 'zone_id'"
            )
        return api_token, zone_id

    @staticmethod
    def _auth_headers(api_token: str) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json",
        }

    def _get(
        self,
        client: httpx.Client,
        url: str,
        headers: dict[str, str],
        params: dict,
    ) -> httpx.Response:
        """Issue a GET request with 429 retry-backoff logic.

        Retries up to ``_MAX_RETRIES`` times on HTTP 429.  The inter-retry
        delay is taken from the ``Retry-After`` response header (defaults to
        60 s if the header is absent or non-numeric).

        Raises:
            AuthenticationError: HTTP 401 or 403.
            RateLimitError:      HTTP 429 after retries are exhausted.
            ConnectorError:      Any other non-2xx response.
            NetworkError:        ``httpx.TimeoutException`` or
                                 ``httpx.RequestError``.
        """
        for attempt in range(_MAX_RETRIES + 1):
            try:
                response = client.get(url, headers=headers, params=params)
            except httpx.TimeoutException as exc:
                raise NetworkError(f"Request timed out: {exc}") from exc
            except httpx.RequestError as exc:
                raise NetworkError(f"Network error: {exc}") from exc

            if response.status_code == 429:
                if attempt >= _MAX_RETRIES:
                    raise RateLimitError(
                        f"Cloudflare rate limit exceeded after {_MAX_RETRIES} "
                        "retries. Try again later."
                    )
                try:
                    retry_after = float(response.headers.get("Retry-After", "60"))
                except ValueError:
                    retry_after = 60.0

                logger.warning(
                    "Rate limited by Cloudflare (attempt %d/%d). "
                    "Sleeping %.1f s before retry.",
                    attempt + 1,
                    _MAX_RETRIES,
                    retry_after,
                )
                time.sleep(retry_after)
                continue  # retry

            if response.status_code in (401, 403):
                raise AuthenticationError(
                    f"Cloudflare authentication failed (HTTP {response.status_code}). "
                    "Verify that the API token has Zone.DNS:Read permission and "
                    "is scoped to the correct zone.",
                    status_code=response.status_code,
                )

            if not response.is_success:
                raise ConnectorError(
                    f"Cloudflare API error (HTTP {response.status_code}): "
                    f"{response.text[:500]}",
                    status_code=response.status_code,
                )

            return response

        # The loop always raises or returns — this line is unreachable.
        raise ConnectorError("Unexpected end of retry loop")  # pragma: no cover


# ═════════════════════════════════════════════════════════════════════════════
# M59.7 — Additional Cloudflare surface fetchers
# ═════════════════════════════════════════════════════════════════════════════
#
# Security stance shared by every helper below
# ---------------------------------------------
# * The Cloudflare API token is NEVER logged.  Logs use only ``zone_id``,
#   ``account_id``, the HTTP status code, and surface-name short labels.
# * Authorization / Bearer headers are NEVER echoed (the response.text is
#   not interpolated into any log line that crosses a permission boundary).
# * Raw WAF rule expressions are NEVER stored — only their sha256 hash.
# * Page Rule redirect targets are reduced to scheme+host before storage
#   so query-string tokens cannot leak into ``Snapshot.state``.
# * Worker secrets, env-var values, Access rules' raw email/IP/group lists,
#   IdP client secrets, and service tokens are NEVER fetched or stored.
#
# Fail-soft pattern
# -----------------
# Every helper returns ``list[dict]`` and degrades to ``[]`` on:
#   - httpx.TimeoutException / httpx.RequestError
#   - HTTP 401/403 (missing scope)
#   - HTTP 404/422 (endpoint unavailable for plan tier)
#   - response body parse failure or success=false
# DNS sync continues unaffected when an optional surface is denied.


# ── Settings we monitor (security-relevant, safe to read) ────────────────────

_ZONE_SETTING_IDS: tuple[str, ...] = (
    "ssl",
    "always_use_https",
    "min_tls_version",
    "security_level",
    "browser_check",
    "development_mode",
    "automatic_https_rewrites",
    "security_header",   # HSTS — value is a dict
)


# Page-rule actions whose targets must be redacted (no query strings).
_REDIRECT_ACTION_IDS: frozenset[str] = frozenset(
    {"forwarding_url"}
)


def _safe_redirect_target(url: str) -> str:
    """Return scheme+host for a URL, stripping path/query so tokens cannot
    leak via ``actions_summary`` storage.
    """
    if not url:
        return ""
    try:
        parsed = urlparse(url)
    except Exception:
        return ""
    if not parsed.scheme or not parsed.hostname:
        # Not a URL-shape — return empty rather than store the raw blob.
        return ""
    return f"{parsed.scheme}://{parsed.hostname}"


def _hash_expression(expr: str) -> str:
    """Deterministic sha256 of a WAF rule expression.

    The raw expression itself is NEVER stored — only this hash, which lets
    the diff service detect a change without leaking the expression text.
    """
    return hashlib.sha256((expr or "").encode("utf-8")).hexdigest()


def _normalize_zone_setting(raw: dict) -> dict:
    """Map a raw Cloudflare zone-setting response to a snapshot dict."""
    setting_id = raw.get("id") or ""
    return {
        "record_type": CLOUDFLARE_ZONE_SETTING,
        "record_id":   setting_id,
        "setting_id":  setting_id,
        "value":       raw.get("value"),
        "editable":    bool(raw.get("editable", True)),
        "modified_on": raw.get("modified_on"),
    }


def _summarize_page_rule_actions(actions: list[dict]) -> str:
    """Build a compact, redacted ``actions_summary`` string for a Page Rule.

    Format examples:
      ``"forwarding_url:to=https://new.example.com,302"``
      ``"cache_level:cache_everything"``
      ``"always_use_https"``

    Any redirect target is reduced to scheme+host (no path/query) so an
    embedded ``?token=...`` cannot land in ``Snapshot.state``.
    """
    parts: list[str] = []
    for a in actions or []:
        aid = (a.get("id") or "").lower()
        if not aid:
            continue
        if aid in _REDIRECT_ACTION_IDS:
            v = a.get("value") or {}
            if isinstance(v, dict):
                target = _safe_redirect_target(str(v.get("url") or ""))
                status = v.get("status_code")
                if target and status is not None:
                    parts.append(f"{aid}:to={target},{status}")
                elif target:
                    parts.append(f"{aid}:to={target}")
                else:
                    parts.append(aid)  # do not echo a malformed/risky URL
            else:
                parts.append(aid)
        elif aid in ("cache_level", "browser_cache_ttl", "edge_cache_ttl"):
            v = a.get("value")
            parts.append(f"{aid}:{v}")
        else:
            # All other action ids: store id alone (no value bodies that
            # could carry sensitive substrings).
            parts.append(aid)
    return ",".join(parts)


def _detect_page_rule_kind(actions_summary: str) -> str:
    s = actions_summary.lower()
    if "forwarding_url" in s:
        return "redirect"
    if "cache_level" in s or "cache_everything" in s or "_cache_ttl" in s:
        return "cache_rule"
    return "page_rule"


def _normalize_page_rule(raw: dict) -> dict:
    actions = raw.get("actions") or []
    # Pull the URL pattern from the first matching target (Cloudflare's shape).
    targets = raw.get("targets") or []
    target_pattern = ""
    for t in targets:
        if (t.get("target") or "").lower() == "url":
            v = t.get("constraint") or {}
            target_pattern = str(v.get("value") or "")
            break
    actions_summary = _summarize_page_rule_actions(actions)
    return {
        "record_type":        CLOUDFLARE_PAGE_RULE,
        "record_id":          raw.get("id") or "",
        "target_url_pattern": target_pattern,
        "actions_summary":    actions_summary,
        "rule_kind":          _detect_page_rule_kind(actions_summary),
        "priority":           int(raw.get("priority") or 0),
        "status":             str(raw.get("status") or "active").lower(),
        "modified_on":        raw.get("modified_on"),
    }


def _normalize_worker_route(raw: dict) -> dict:
    return {
        "record_type": CLOUDFLARE_WORKER_ROUTE,
        "record_id":   raw.get("id") or "",
        "pattern":     str(raw.get("pattern") or ""),
        "script_name": str(raw.get("script") or ""),
        # Worker routes are active when configured — Cloudflare's API does
        # not expose a separate ``enabled`` flag, so we treat presence as
        # enabled.
        "enabled":     True,
        "modified_on": raw.get("modified_on"),
    }


def _normalize_worker_script(raw: dict) -> dict:
    """Worker script METADATA only — source code is never fetched/stored.

    Cloudflare's ``GET /accounts/{aid}/workers/scripts`` returns a list of
    script metadata entries (script_name, etag, created_on, modified_on,
    optional bindings array).  We never call the ``content`` endpoint
    which would return source code.
    """
    bindings = raw.get("bindings") or []
    # Count env var bindings WITHOUT inspecting their values.
    env_var_count = sum(
        1 for b in bindings
        if (b.get("type") or "").lower() in ("plain_text", "secret_text")
    )
    return {
        "record_type":    CLOUDFLARE_WORKER_SCRIPT,
        "record_id":      raw.get("id") or raw.get("name") or "",
        "script_name":    raw.get("id") or raw.get("name") or "",
        "script_etag":    str(raw.get("etag") or raw.get("script_etag") or ""),
        "env_var_count":  env_var_count,
        "binding_count":  len(bindings),
        "modified_on":    raw.get("modified_on"),
    }


def _normalize_access_application(raw: dict) -> dict:
    allowed_idps = raw.get("allowed_idps") or []
    return {
        "record_type":         CLOUDFLARE_ACCESS_APPLICATION,
        "record_id":           raw.get("id") or "",
        "name":                str(raw.get("name") or ""),
        "type":                str(raw.get("type") or "self_hosted"),
        "domain":              str(raw.get("domain") or ""),
        "visibility":          "private" if not bool(raw.get("app_launcher_visible", True)) else "public",
        "enabled":             bool(raw.get("enabled", True)),
        "session_duration":    str(raw.get("session_duration") or ""),
        "allowed_idps_count":  len(allowed_idps),
        "modified_on":         raw.get("updated_at") or raw.get("modified_on"),
    }


def _normalize_access_policy(raw: dict, app_id: str) -> dict:
    """Access policy snapshot — INCLUDE/EXCLUDE/REQUIRE stored as COUNTS only.

    SECURITY: the raw include/exclude/require lists contain emails, group
    IDs, service-token references, and IP ranges.  None of these are
    persisted — only their counts.  This prevents PII (email allowlists)
    and operational secrets (service tokens) from landing in snapshots.
    """
    return {
        "record_type":      CLOUDFLARE_ACCESS_POLICY,
        "record_id":        raw.get("id") or "",
        "application_id":   app_id,
        "name":             str(raw.get("name") or ""),
        "decision":         str(raw.get("decision") or "allow").lower(),
        "enabled":          bool(raw.get("enabled", True)),
        "precedence":       int(raw.get("precedence") or 0),
        "include_count":    len(raw.get("include") or []),
        "exclude_count":    len(raw.get("exclude") or []),
        "require_count":    len(raw.get("require") or []),
        "modified_on":      raw.get("updated_at") or raw.get("modified_on"),
    }


def _normalize_waf_rule(raw: dict, ruleset_id: str) -> dict:
    """Per-rule WAF snapshot — expression is HASHED, never stored.

    SECURITY: ``raw["expression"]`` is read only to compute the hash and
    is immediately discarded.  The ``description`` field is stored because
    it is human-supplied and intentionally non-sensitive (e.g. "block SQLi").
    """
    expr = str(raw.get("expression") or "")
    action = (raw.get("action") or "").lower()
    return {
        "record_type":      CLOUDFLARE_WAF_RULE,
        "record_id":        raw.get("id") or "",
        "ruleset_id":       ruleset_id,
        "description":      str(raw.get("description") or ""),
        "action":           action,
        "enabled":          bool(raw.get("enabled", True)),
        "expression_hash":  _hash_expression(expr),
        "modified_on":      raw.get("last_updated"),
    }


# ── Connector-class method extensions ────────────────────────────────────────


def _is_skip_status(code: int) -> bool:
    """True if the HTTP status indicates a missing scope or unsupported
    endpoint that should be silently skipped."""
    return code in (401, 403, 404, 422)


def _safe_get(
    client: httpx.Client,
    url: str,
    headers: dict[str, str],
    *,
    surface: str,
    zone_id: str = "",
    account_id: str = "",
) -> dict | None:
    """Issue a GET that fail-softs on missing scope / network errors.

    Returns the parsed JSON body on success, ``None`` on any error path.
    NEVER logs the Authorization header, response.text, or token material.
    """
    try:
        response = client.get(url, headers=headers)
    except httpx.TimeoutException:
        logger.warning(
            "cloudflare: %s fetch timed out  zone=%s  account=%s",
            surface, zone_id or "-", account_id or "-",
        )
        return None
    except httpx.RequestError as exc:
        # Only the exception TYPE is logged — the message may contain the URL.
        logger.warning(
            "cloudflare: %s fetch network error  zone=%s  account=%s  error_type=%s",
            surface, zone_id or "-", account_id or "-", type(exc).__name__,
        )
        return None

    if _is_skip_status(response.status_code):
        logger.warning(
            "cloudflare: %s skipped — token lacks scope or endpoint "
            "unavailable  zone=%s  account=%s  http=%d",
            surface, zone_id or "-", account_id or "-", response.status_code,
        )
        return None

    if not response.is_success:
        logger.warning(
            "cloudflare: %s fetch failed  zone=%s  account=%s  http=%d",
            surface, zone_id or "-", account_id or "-", response.status_code,
        )
        return None

    try:
        body = response.json()
    except Exception:
        logger.warning(
            "cloudflare: %s response is not valid JSON  zone=%s",
            surface, zone_id or "-",
        )
        return None

    if not body.get("success", True):
        # Some Access endpoints return an envelope-less body; tolerate that.
        # When ``success`` is explicitly false, log the error CODES only.
        errors = body.get("errors") or []
        # Pull only Cloudflare-supplied error code numbers; the messages
        # may contain echoed input.
        codes = sorted({e.get("code") for e in errors if isinstance(e, dict)})
        logger.warning(
            "cloudflare: %s API returned success=false  zone=%s  codes=%s",
            surface, zone_id or "-", codes,
        )
        return None

    return body


def _fetch_zone_settings_impl(
    self,
    client: httpx.Client,
    zone_id: str,
    headers: dict[str, str],
) -> list[dict]:
    """Fetch the security-relevant subset of ``/zones/{id}/settings``.

    Each setting is fetched individually so that a 403 on one setting (e.g.
    ``security_header`` on a plan that doesn't support it) does not stop
    the others from being recorded.
    """
    out: list[dict] = []
    base = f"{_BASE_URL}/zones/{zone_id}/settings"
    for setting_id in _ZONE_SETTING_IDS:
        body = _safe_get(
            client, f"{base}/{setting_id}", headers,
            surface=f"zone_setting:{setting_id}", zone_id=zone_id,
        )
        if body is None:
            continue
        result = body.get("result")
        if not isinstance(result, dict):
            continue
        out.append(_normalize_zone_setting(result))
    return out


def _fetch_page_rules_impl(
    self,
    client: httpx.Client,
    zone_id: str,
    headers: dict[str, str],
) -> list[dict]:
    body = _safe_get(
        client, f"{_BASE_URL}/zones/{zone_id}/pagerules", headers,
        surface="page_rules", zone_id=zone_id,
    )
    if body is None:
        return []
    out: list[dict] = []
    for raw in body.get("result") or []:
        rid = raw.get("id")
        if not rid:
            continue
        out.append(_normalize_page_rule(raw))
    return out


def _fetch_worker_routes_impl(
    self,
    client: httpx.Client,
    zone_id: str,
    headers: dict[str, str],
) -> list[dict]:
    body = _safe_get(
        client, f"{_BASE_URL}/zones/{zone_id}/workers/routes", headers,
        surface="worker_routes", zone_id=zone_id,
    )
    if body is None:
        return []
    out: list[dict] = []
    for raw in body.get("result") or []:
        rid = raw.get("id")
        if not rid:
            continue
        out.append(_normalize_worker_route(raw))
    return out


def _fetch_waf_rules_impl(
    self,
    client: httpx.Client,
    zone_id: str,
    headers: dict[str, str],
) -> list[dict]:
    """Per-rule WAF records (granular).

    Distinct from ``_fetch_rulesets`` which emits aggregate counts.  This
    helper iterates each ruleset and emits one ``cloudflare_waf_rule``
    record per rule with the expression HASHED.
    """
    list_body = _safe_get(
        client, f"{_BASE_URL}/zones/{zone_id}/rulesets", headers,
        surface="waf_rules:list", zone_id=zone_id,
    )
    if list_body is None:
        return []
    out: list[dict] = []
    for ruleset in list_body.get("result") or []:
        ruleset_id = ruleset.get("id") or ""
        if not ruleset_id:
            continue
        # The list endpoint sometimes returns the inline ``rules`` array,
        # sometimes not.  If absent, follow up with the detail endpoint —
        # also fail-softly.
        rules = ruleset.get("rules")
        if not isinstance(rules, list):
            detail = _safe_get(
                client,
                f"{_BASE_URL}/zones/{zone_id}/rulesets/{ruleset_id}",
                headers,
                surface=f"waf_rules:detail:{ruleset_id[:8]}",
                zone_id=zone_id,
            )
            if detail is None:
                continue
            result = detail.get("result") or {}
            rules = result.get("rules") if isinstance(result, dict) else None
            if not isinstance(rules, list):
                continue
        for rule in rules:
            rid = rule.get("id")
            if not rid:
                continue
            out.append(_normalize_waf_rule(rule, ruleset_id))
    return out


def _resolve_account_id_impl(
    self,
    client: httpx.Client,
    zone_id: str,
    headers: dict[str, str],
) -> str | None:
    """Look up the parent account id for *zone_id*.

    Returns ``None`` (and logs a safe warning) if the token cannot read the
    zone's account context — account-scoped surfaces are then skipped.
    """
    body = _safe_get(
        client, f"{_BASE_URL}/zones/{zone_id}", headers,
        surface="account_id_lookup", zone_id=zone_id,
    )
    if body is None:
        return None
    result = body.get("result") or {}
    account = result.get("account") or {}
    account_id = str(account.get("id") or "")
    return account_id or None


def _fetch_worker_scripts_impl(
    self,
    client: httpx.Client,
    account_id: str,
    headers: dict[str, str],
) -> list[dict]:
    body = _safe_get(
        client, f"{_BASE_URL}/accounts/{account_id}/workers/scripts", headers,
        surface="worker_scripts", account_id=account_id,
    )
    if body is None:
        return []
    out: list[dict] = []
    for raw in body.get("result") or []:
        name = raw.get("id") or raw.get("name")
        if not name:
            continue
        out.append(_normalize_worker_script(raw))
    return out


def _fetch_access_applications_impl(
    self,
    client: httpx.Client,
    account_id: str,
    headers: dict[str, str],
) -> list[dict]:
    body = _safe_get(
        client, f"{_BASE_URL}/accounts/{account_id}/access/apps", headers,
        surface="access_apps", account_id=account_id,
    )
    if body is None:
        return []
    out: list[dict] = []
    for raw in body.get("result") or []:
        aid = raw.get("id")
        if not aid:
            continue
        out.append(_normalize_access_application(raw))
    return out


def _fetch_access_policies_impl(
    self,
    client: httpx.Client,
    account_id: str,
    app_id: str,
    headers: dict[str, str],
) -> list[dict]:
    body = _safe_get(
        client,
        f"{_BASE_URL}/accounts/{account_id}/access/apps/{app_id}/policies",
        headers,
        surface=f"access_policies:{app_id[:8]}",
        account_id=account_id,
    )
    if body is None:
        return []
    out: list[dict] = []
    for raw in body.get("result") or []:
        pid = raw.get("id")
        if not pid:
            continue
        out.append(_normalize_access_policy(raw, app_id))
    return out


# Bind the impl functions as methods on ``CloudflareConnector``.  This keeps
# the file readable (no 600-line class body) without changing the public
# surface — the connector still has the same class name and call sites.
CloudflareConnector._fetch_zone_settings = _fetch_zone_settings_impl       # type: ignore[attr-defined]
CloudflareConnector._fetch_page_rules = _fetch_page_rules_impl             # type: ignore[attr-defined]
CloudflareConnector._fetch_worker_routes = _fetch_worker_routes_impl       # type: ignore[attr-defined]
CloudflareConnector._fetch_waf_rules = _fetch_waf_rules_impl               # type: ignore[attr-defined]
CloudflareConnector._resolve_account_id = _resolve_account_id_impl         # type: ignore[attr-defined]
CloudflareConnector._fetch_worker_scripts = _fetch_worker_scripts_impl     # type: ignore[attr-defined]
CloudflareConnector._fetch_access_applications = _fetch_access_applications_impl  # type: ignore[attr-defined]
CloudflareConnector._fetch_access_policies = _fetch_access_policies_impl   # type: ignore[attr-defined]
