"""Auth0 drift connector — M81A.

Snapshots safe configuration metadata from the Auth0 Management API v2:
  - Tenant settings (boolean flags and categories — never raw payload)
  - Applications / clients (counts and safe fields — never client_secret,
    raw callback URLs, JWKS, or certificates)
  - Connections (strategy and safe posture — never credentials or user data)
  - APIs / resource servers (signing alg and scope count — never audience URI)
  - Rules (name, enabled, script_present — never script content)
  - Actions (name, status, runtime — never code or secrets)
  - MFA / Guardian factors (name, enabled — never enrollment data)
  - Custom domains (status, type — never domain names or verification tokens)

Authentication: OAuth2 client_credentials flow to the Auth0 Management API v2,
or a direct management_api_token if provided.

PRIVACY / SECURITY — what is NEVER stored or logged
----------------------------------------------------
- client_secret — NEVER stored on instance, NEVER logged
- management_api_token — NEVER stored on instance, NEVER logged
- access_token minted from client_credentials — NEVER stored on instance,
  used only within the scope of fetch() and discarded immediately after
- Authorization headers or bearer tokens — NEVER in logs or records
- Raw Auth0 API response dicts — NEVER stored
- Callback URLs, logout URLs, allowed origins, web origins — integer counts only
- Resource server identifier (audience URI) — boolean presence flag only
- Custom domain name string — boolean presence flag only; domain_present=True
- Rule or action script/code content — boolean + length category only
- Action secret names or values — integer count only
- Connection credentials (database passwords, social tokens, certs, keys)
- User emails, user names, user IDs, profile data, identities, login history
- MFA enrollment data, recovery codes, phone numbers
- IP addresses, device fingerprints, session data
- SAML certificates, JWKS, private keys
- Verification tokens, DNS record values, CNAME targets

Credentials dict
----------------
    domain              : str — Auth0 tenant domain (e.g. "myapp.auth0.com")
    client_id           : str — M2M application client ID (omit if management_api_token provided)
    client_secret       : str — M2M application client secret (NEVER logged or stored)
    management_api_token: str — direct token (NEVER logged or stored; optional)

If management_api_token is present it is used directly; otherwise a token is
minted via the client_credentials grant using client_id + client_secret.
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
from app.connectors.auth0_schema import (
    AUTH0_ACTION,
    AUTH0_APPLICATION,
    AUTH0_CONNECTION,
    AUTH0_CUSTOM_DOMAIN,
    AUTH0_MFA_FACTOR,
    AUTH0_RESOURCE_SERVER,
    AUTH0_RULE,
    AUTH0_TENANT_SETTINGS,
)

logger = logging.getLogger(__name__)

# ── Module-level constants ─────────────────────────────────────────────────────

_TIMEOUT = 30.0
_PAGE_SIZE = 50
_MAX_PAGES = 10
_MAX_STR_LEN = 100

# Per-surface record caps
_MAX_APPLICATIONS = 200
_MAX_CONNECTIONS = 200
_MAX_RESOURCE_SERVERS = 100
_MAX_RULES = 200
_MAX_ACTIONS = 200
_MAX_CUSTOM_DOMAINS = 20

# ── Activity event type allowlist (M81D) ──────────────────────────────────────
#
# Auth0 Management API logs (/api/v2/logs) are highly user-centric: every
# entry includes user_id, email, IP address, and device data — which must
# NEVER be stored. Instead, activity events are synthesized from the same
# safe drift surfaces the drift connector already reads, using the same
# privacy-safe normalized records. This mirrors the SendGrid approach.
#
# Login / authentication / session / token-exchange / password-reset /
# MFA-enrollment / profile / organization-member events are NEVER in
# this set and are NEVER fetched or returned.
_AUTH0_CONFIG_EVENT_TYPES: frozenset[str] = frozenset({
    "auth0.tenant.updated",
    "auth0.application.created",
    "auth0.application.updated",
    "auth0.application.deleted",
    "auth0.connection.created",
    "auth0.connection.updated",
    "auth0.connection.deleted",
    "auth0.resource_server.created",
    "auth0.resource_server.updated",
    "auth0.resource_server.deleted",
    "auth0.rule.created",
    "auth0.rule.updated",
    "auth0.rule.deleted",
    "auth0.action.created",
    "auth0.action.updated",
    "auth0.action.deployed",
    "auth0.action.deleted",
    "auth0.mfa_factor.updated",
    "auth0.custom_domain.created",
    "auth0.custom_domain.updated",
    "auth0.custom_domain.verified",
    "auth0.custom_domain.deleted",
    "auth0.config.event",
})

# Session lifetime category thresholds (hours — Auth0 uses hours for session_lifetime)
_SESSION_CATEGORIES = [
    (1, "very_short"),     # < 1h
    (24, "short"),         # 1–24h
    (168, "standard"),     # 24h–7d
]

# Token lifetime category thresholds (seconds — Auth0 uses seconds for token_lifetime).
# Upper bound is exclusive (value < threshold); using 86401 so exactly 86400s (24h)
# — the Auth0 default token_lifetime — lands in "standard", not "extended".
_TOKEN_CATEGORIES = [
    (900, "very_short"),    # < 15m
    (3600, "short"),        # 15m–1h
    (86401, "standard"),    # 1h–24h (inclusive of the 86400s Auth0 default)
]


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
        return value.lower() in ("true", "1", "yes")
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
    return email[at + 1:].lower().strip()[:100]


def _session_category(hours: Any) -> str:
    """Categorise an Auth0 session_lifetime / idle_session_lifetime (in hours)."""
    h = _int(hours, 0)
    for threshold, cat in _SESSION_CATEGORIES:
        if h < threshold:
            return cat
    return "extended"


def _token_category(seconds: Any) -> str:
    """Categorise an Auth0 resource server token_lifetime (in seconds)."""
    s = _int(seconds, 0)
    for threshold, cat in _TOKEN_CATEGORIES:
        if s < threshold:
            return cat
    return "extended"


def _has_wildcard(urls: list) -> bool:
    """Return True if any URL in the list contains a wildcard character.

    Used for M81C posture booleans. Raw URL strings are NEVER stored.
    """
    return any("*" in u for u in urls if isinstance(u, str))


def _has_localhost(urls: list) -> bool:
    """Return True if any URL starts with a localhost / loopback origin.

    Matches http(s)://localhost, http(s)://127.0.0.1, http(s)://[::1].
    Raw URL strings are NEVER stored.
    """
    _LOCALHOST_PREFIXES = (
        "http://localhost", "https://localhost",
        "http://127.0.0.1", "https://127.0.0.1",
        "http://[::1]", "https://[::1]",
    )
    return any(
        isinstance(u, str) and any(u.startswith(p) for p in _LOCALHOST_PREFIXES)
        for u in urls
    )


def _has_http_non_localhost(urls: list) -> bool:
    """Return True if any URL uses http:// for a non-localhost origin.

    Raw URL strings are NEVER stored.
    """
    _LOCALHOST_HTTP_PREFIXES = ("http://localhost", "http://127.0.0.1", "http://[::1]")
    return any(
        isinstance(u, str)
        and u.startswith("http://")
        and not any(u.startswith(p) for p in _LOCALHOST_HTTP_PREFIXES)
        for u in urls
    )


def _code_length_category(code: Any) -> str:
    """Return a safe length category for rule script or action code.

    The content itself is NEVER stored.
    """
    if not isinstance(code, str) or not code:
        return "absent"
    length = len(code)
    if length < 500:
        return "short"
    if length < 2000:
        return "medium"
    return "long"


def _categorize_factor(name: str) -> str:
    """Return a broad category label for a Guardian/MFA factor name."""
    return {
        "sms": "sms",
        "push-notification": "push",
        "email": "email",
        "otp": "totp",
        "webauthn-roaming": "webauthn",
        "webauthn-platform": "webauthn",
        "recovery-code": "recovery",
        "duo": "third_party",
    }.get(name, "other")


def _sanitize_domain(domain: Any) -> str:
    """Validate and lightly sanitize an Auth0 tenant domain string.

    Returns a cleaned domain string (e.g. 'myapp.auth0.com') or raises
    ValueError if the input is clearly malformed.

    SECURITY: this result is used to build API URLs only, never stored
    in normalised records.
    """
    if not isinstance(domain, str):
        raise ValueError("auth0: domain credential must be a string")
    cleaned = domain.strip().lower()
    if not cleaned:
        raise ValueError("auth0: domain credential must not be empty")
    if " " in cleaned or "://" in cleaned or len(cleaned) > 253:
        raise ValueError(f"auth0: domain has invalid format: {cleaned[:60]!r}")
    return cleaned


# ── Connector ──────────────────────────────────────────────────────────────────


class Auth0Connector(BaseConnector):
    """Auth0 Management API v2 connector for ConfigTrace drift tracking (M81A).

    Stateless: credentials are passed at call time; nothing is stored on the
    instance between calls. Management tokens (whether supplied directly or
    minted via client_credentials) are never stored as instance attributes.

    SECURITY: client_secret and management_api_token are NEVER stored as
    instance attributes, NEVER logged, NEVER included in error messages, and
    NEVER written to any normalised record. Access tokens minted via the
    client_credentials flow are used only within the scope of fetch() and
    discarded immediately after the httpx.Client context exits.
    """

    # ── Token acquisition ─────────────────────────────────────────────────────

    @staticmethod
    def _acquire_token(domain: str, credentials: dict) -> str:
        """Return a Management API bearer token.

        If 'management_api_token' is present in credentials it is returned
        directly. Otherwise a token is minted via OAuth2 client_credentials
        using 'client_id' and 'client_secret'.

        SECURITY: client_secret is NEVER logged. The returned token is used
        only within the caller's fetch() scope; it is never stored on the
        connector instance.

        Raises:
            AuthenticationError: Invalid credentials or 401/403 from token endpoint.
            ConnectorError: Token endpoint returned an unexpected error.
            NetworkError: Transport-level failure contacting the token endpoint.
        """
        # Direct token path — token itself is never logged
        if credentials.get("management_api_token"):
            return credentials["management_api_token"]

        client_id = credentials.get("client_id", "")
        client_secret = credentials.get("client_secret", "")
        if not client_id or not client_secret:
            raise AuthenticationError(
                "auth0: credentials must contain either 'management_api_token' "
                "or both 'client_id' and 'client_secret'",
                status_code=401,
            )

        audience = f"https://{domain}/api/v2/"
        # SECURITY: client_secret is passed in the JSON body and never logged
        try:
            resp = httpx.post(
                f"https://{domain}/oauth/token",
                json={
                    "grant_type": "client_credentials",
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "audience": audience,
                },
                timeout=_TIMEOUT,
            )
        except httpx.ConnectError as exc:
            raise NetworkError(
                f"auth0: token endpoint connection failed: {exc}"
            ) from exc
        except httpx.TimeoutException:
            raise NetworkError("auth0: token endpoint request timed out")
        except httpx.HTTPError as exc:
            raise NetworkError(
                f"auth0: token endpoint request error: {exc}"
            ) from exc

        if resp.status_code in (401, 403):
            raise AuthenticationError(
                f"auth0: token endpoint returned HTTP {resp.status_code} — "
                "check client_id, client_secret, and Management API audience",
                status_code=resp.status_code,
            )
        if resp.status_code == 429:
            retry_after: Optional[float] = None
            try:
                retry_after = float(resp.headers.get("Retry-After", ""))
            except (ValueError, TypeError):
                pass
            raise RateLimitError(
                "auth0: token endpoint rate limited (429)",
                retry_after=retry_after,
            )
        if resp.status_code >= 400:
            raise ConnectorError(
                f"auth0: token endpoint returned HTTP {resp.status_code}",
                status_code=resp.status_code,
            )

        try:
            data = resp.json()
        except ValueError as exc:
            raise ConnectorError(
                "auth0: token endpoint response was not valid JSON"
            ) from exc

        token = data.get("access_token", "")
        if not isinstance(token, str) or not token:
            raise AuthenticationError(
                "auth0: token endpoint returned no access_token",
                status_code=401,
            )
        return token

    # ── HTTP client helpers ───────────────────────────────────────────────────

    @staticmethod
    def _make_management_client(domain: str, token: str) -> httpx.Client:
        """Build an httpx.Client for the Auth0 Management API v2.

        SECURITY: token is placed in the Authorization header only.
        It is never stored on the connector instance or logged.
        """
        return httpx.Client(
            base_url=f"https://{domain}/api/v2",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
            },
            timeout=_TIMEOUT,
        )

    @staticmethod
    def _raise_for_status(resp: httpx.Response, context: str = "") -> None:
        """Map Auth0 Management API HTTP error codes to connector exceptions."""
        if resp.status_code < 400:
            return
        if resp.status_code == 401:
            raise AuthenticationError(
                f"auth0: 401 Unauthorized{' — ' + context if context else ''}",
                status_code=401,
            )
        if resp.status_code == 429:
            retry_after: Optional[float] = None
            try:
                retry_after = float(resp.headers.get("Retry-After", ""))
            except (ValueError, TypeError):
                pass
            raise RateLimitError(
                "auth0: rate limit hit (429)",
                retry_after=retry_after,
            )
        if resp.status_code in (403, 404, 422):
            raise ConnectorError(
                f"auth0: HTTP {resp.status_code}"
                f"{' — ' + context if context else ''}",
                status_code=resp.status_code,
            )
        if resp.status_code >= 500:
            raise ConnectorError(
                f"auth0: server error HTTP {resp.status_code}"
                f"{' — ' + context if context else ''}",
                status_code=resp.status_code,
            )
        raise ConnectorError(
            f"auth0: HTTP {resp.status_code}"
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
                f"auth0: GET connection error for {path[:200]}: {exc}"
            ) from exc
        except httpx.TimeoutException:
            raise NetworkError(f"auth0: GET timed out for {path[:200]}")
        except httpx.HTTPError as exc:
            raise NetworkError(f"auth0: GET request error: {exc}") from exc

        Auth0Connector._raise_for_status(resp, context=path[:200])
        try:
            return resp.json()
        except ValueError as exc:
            raise ConnectorError("auth0: response was not valid JSON") from exc

    # ── Pagination helper ─────────────────────────────────────────────────────

    @staticmethod
    def _get_pages(
        client: httpx.Client,
        path: str,
        items_key: Optional[str],
        max_records: int,
        extra_params: Optional[dict] = None,
    ) -> list[Any]:
        """Paginate an Auth0 Management API list endpoint (page/per_page style).

        Bounded to _MAX_PAGES pages and max_records total items. Handles both
        plain array responses and paginated-object responses.
        """
        items: list[Any] = []
        for page in range(_MAX_PAGES):
            params: dict = {"per_page": _PAGE_SIZE, "page": page}
            if extra_params:
                params.update(extra_params)
            try:
                data = Auth0Connector._get(client, path, params=params)
            except ConnectorError:
                break

            page_items: list = []
            if isinstance(data, list):
                page_items = data
            elif isinstance(data, dict):
                if items_key and items_key in data and isinstance(data[items_key], list):
                    page_items = data[items_key]
                else:
                    # Try common Auth0 response envelope keys in preference order
                    for key in (items_key or "", "result", "clients", "connections",
                                "resource_servers", "rules"):
                        if key and isinstance(data.get(key), list):
                            page_items = data[key]
                            break

            if not page_items:
                break
            items.extend(page_items)
            if len(items) >= max_records:
                items = items[:max_records]
                break
            if len(page_items) < _PAGE_SIZE:
                break

        return items

    # ── Record normalizers ────────────────────────────────────────────────────

    @staticmethod
    def _normalize_tenant_settings(raw: dict) -> dict:
        """Normalize Auth0 tenant settings into a safe record.

        SECURITY: support_email (full address), support_url, management API JWT,
        error_page HTML, device_flow config, custom_login_page HTML,
        sandbox_version, default_audience, change_password HTML, and all raw
        tenant settings payload are NEVER stored.
        """
        flags = raw.get("flags") if isinstance(raw.get("flags"), dict) else {}
        return {
            "record_type": AUTH0_TENANT_SETTINGS,
            "record_id": "auth0_tenant_settings_main",
            "provider_resource_id": "tenants/settings",
            "friendly_name_present": bool(raw.get("friendly_name")),
            # support_email: domain part only — full email NEVER stored
            "support_email_domain": _email_domain(raw.get("support_email", "")),
            "default_directory_present": bool(raw.get("default_directory")),
            # session_lifetime is in hours in the Auth0 API
            "session_lifetime_category": _session_category(raw.get("session_lifetime")),
            "idle_session_lifetime_category": _session_category(
                raw.get("idle_session_lifetime")
            ),
            "enabled_locales_count": len(
                raw.get("enabled_locales", []) or []
            ),
            # Safe boolean flags from the flags dict
            "flag_change_pwd_on_first_login": _bool(
                flags.get("change_pwd_on_first_login")
            ),
            "flag_enable_client_connections": _bool(
                flags.get("enable_client_connections")
            ),
            "flag_enable_apis_section": _bool(flags.get("enable_apis_section")),
            "flag_enable_pipeline2": _bool(flags.get("enable_pipeline2")),
            "flag_enable_dynamic_client_registration": _bool(
                flags.get("enable_dynamic_client_registration")
            ),
            "flag_enable_custom_domain_in_emails": _bool(
                flags.get("enable_custom_domain_in_emails")
            ),
            "flag_universal_login": _bool(flags.get("universal_login")),
            "flag_enable_legacy_logs_search_v2": _bool(
                flags.get("enable_legacy_logs_search_v2")
            ),
            "flag_no_disclose_enterprise_connections": _bool(
                flags.get("no_disclose_enterprise_connections")
            ),
            "flag_disable_management_api_sms_obfuscation": _bool(
                flags.get("disable_management_api_sms_obfuscation")
            ),
            "flag_enable_adfs_waad_email_verification": _bool(
                flags.get("enable_adfs_waad_email_verification")
            ),
            "flag_revoke_refresh_token_grant": _bool(
                flags.get("revoke_refresh_token_grant")
            ),
        }

    @staticmethod
    def _normalize_application(raw: dict) -> Optional[dict]:
        """Normalize one Auth0 application/client record.

        SECURITY: client_secret, JWKS, raw callback_urls, raw allowed_logout_urls,
        raw allowed_origins, raw web_origins, encryption_key, initiate_login_uri,
        signing_keys, and all raw client configuration are NEVER stored.
        URL lists are stored as integer counts only.
        """
        client_id = raw.get("client_id", "")
        if not isinstance(client_id, str) or not client_id.strip():
            return None

        grant_types = raw.get("grant_types") or []
        grant_types_summary = ",".join(
            sorted(_trunc(g, 50) for g in grant_types if isinstance(g, str))
        )[:200]

        rt_config = raw.get("refresh_token") if isinstance(raw.get("refresh_token"), dict) else {}
        rt_rotation = _bool(
            isinstance(rt_config.get("rotation_type"), str)
            and rt_config["rotation_type"] == "rotating"
        )
        rt_lifetime = rt_config.get("token_lifetime")
        rt_lifetime_cat = (
            _token_category(rt_lifetime) if isinstance(rt_lifetime, (int, float))
            else "not_configured"
        )

        jwt_cfg = raw.get("jwt_configuration")
        jwt_alg = (
            _trunc(jwt_cfg.get("alg", "RS256"), 20)
            if isinstance(jwt_cfg, dict)
            else "RS256"
        )

        # M81C: grant type booleans — derived from grant_types list only
        _gt_set = frozenset(g for g in grant_types if isinstance(g, str))
        grant_mfa = bool(
            "http://auth0.com/oauth/grant-type/mfa-otp" in _gt_set
            or "http://auth0.com/oauth/grant-type/mfa-bearer" in _gt_set
        )

        # M81C: URL posture booleans — compute before discarding URL lists
        _callbacks = raw.get("callbacks") or []
        _logout_urls = raw.get("allowed_logout_urls") or []
        _allowed_origins = raw.get("allowed_origins") or []

        return {
            "record_type": AUTH0_APPLICATION,
            "record_id": _trunc(client_id, 100),
            "provider_resource_id": f"clients/{_trunc(client_id, 100)}",
            "client_id": _trunc(client_id, 100),
            "name": _trunc(raw.get("name", ""), _MAX_STR_LEN),
            "app_type": _trunc(raw.get("app_type") or "unknown", 50),
            "is_first_party": _bool(raw.get("is_first_party", True)),
            "grant_types_summary": grant_types_summary,
            # URL lists stored as COUNTS ONLY — raw URL strings NEVER stored
            "callbacks_count": len(_callbacks),
            "allowed_logout_urls_count": len(_logout_urls),
            "allowed_origins_count": len(_allowed_origins),
            "web_origins_count": len(raw.get("web_origins") or []),
            "jwt_alg": jwt_alg,
            "oidc_conformant": _bool(raw.get("oidc_conformant", True)),
            "token_endpoint_auth_method": _trunc(
                raw.get("token_endpoint_auth_method") or "client_secret_basic", 50
            ),
            "refresh_token_rotation_enabled": rt_rotation,
            "refresh_token_lifetime_category": rt_lifetime_cat,
            # ── M81C: grant type booleans ──────────────────────────────────────
            "grant_types_count": len(_gt_set),
            "grant_password_enabled": "password" in _gt_set,
            "grant_implicit_enabled": "implicit" in _gt_set,
            "grant_client_credentials_enabled": "client_credentials" in _gt_set,
            "grant_authorization_code_enabled": "authorization_code" in _gt_set,
            "grant_refresh_token_enabled": "refresh_token" in _gt_set,
            "grant_device_code_enabled": (
                "urn:ietf:params:oauth:grant-type:device_code" in _gt_set
            ),
            "grant_mfa_enabled": grant_mfa,
            # ── M81C: URL posture booleans — raw URLs discarded after this ─────
            "wildcard_callback_present": _has_wildcard(_callbacks),
            "wildcard_logout_url_present": _has_wildcard(_logout_urls),
            "wildcard_allowed_origin_present": _has_wildcard(_allowed_origins),
            "localhost_callback_present": _has_localhost(_callbacks),
            "localhost_origin_present": _has_localhost(_allowed_origins),
            "callbacks_missing_https": _has_http_non_localhost(_callbacks),
            "allowed_origins_missing_https": _has_http_non_localhost(_allowed_origins),
        }

    @staticmethod
    def _normalize_connection(raw: dict) -> Optional[dict]:
        """Normalize one Auth0 connection record.

        SECURITY: connection options dict (containing credentials, passwords,
        social provider tokens, API keys, SAML certs, private keys), raw user
        data, raw domain lists, and all raw connection payload are NEVER stored.
        """
        connection_id = raw.get("id", "")
        if not isinstance(connection_id, str) or not connection_id.strip():
            return None

        strategy = _trunc(raw.get("strategy") or "", 50)
        options = raw.get("options") if isinstance(raw.get("options"), dict) else {}

        # Password policy category — only for auth0 (database) connections
        pw_policy: Optional[str] = None
        if strategy == "auth0":
            pw = options.get("password_policy")
            if isinstance(pw, str) and pw:
                pw_policy = _trunc(pw, 20)

        # MFA enabled flag — only for auth0 (database) connections
        mfa_enabled: Optional[bool] = None
        if strategy == "auth0":
            mfa_cfg = options.get("mfa")
            if isinstance(mfa_cfg, dict):
                mfa_enabled = _bool(mfa_cfg.get("active"))

        return {
            "record_type": AUTH0_CONNECTION,
            "record_id": _trunc(connection_id, 100),
            "provider_resource_id": f"connections/{_trunc(connection_id, 100)}",
            "connection_id": _trunc(connection_id, 100),
            "name": _trunc(raw.get("name") or "", _MAX_STR_LEN),
            "strategy": strategy,
            "enabled_clients_count": len(raw.get("enabled_clients") or []),
            "is_domain_connection": _bool(raw.get("is_domain_connection", False)),
            "password_policy_category": pw_policy,
            "mfa_enabled": mfa_enabled,
        }

    @staticmethod
    def _normalize_resource_server(raw: dict) -> Optional[dict]:
        """Normalize one Auth0 API / resource server record.

        SECURITY: identifier (audience URI string), signing_secret, raw scope
        definitions with descriptions, and all raw resource server payload are
        NEVER stored. identifier is stored as identifier_present boolean only.
        """
        rs_id = raw.get("id", "")
        if not isinstance(rs_id, str) or not rs_id.strip():
            return None

        scopes = raw.get("scopes") or []
        token_lifetime = raw.get("token_lifetime")

        return {
            "record_type": AUTH0_RESOURCE_SERVER,
            "record_id": _trunc(rs_id, 100),
            "provider_resource_id": f"resource-servers/{_trunc(rs_id, 100)}",
            "resource_server_id": _trunc(rs_id, 100),
            "name": _trunc(raw.get("name") or "", _MAX_STR_LEN),
            # identifier (audience URI) stored as boolean only — never the URI string
            "identifier_present": bool(raw.get("identifier")),
            "signing_alg": _trunc(raw.get("signing_alg") or "RS256", 20),
            "token_lifetime_category": (
                _token_category(token_lifetime)
                if isinstance(token_lifetime, (int, float))
                else "default"
            ),
            "allow_offline_access": _bool(raw.get("allow_offline_access", False)),
            "skip_consent_for_verifiable_first_party_clients": _bool(
                raw.get("skip_consent_for_verifiable_first_party_clients", False)
            ),
            "rbac_enabled": _bool(raw.get("enforce_policies", False)),
            "scopes_count": len(scopes) if isinstance(scopes, list) else 0,
        }

    @staticmethod
    def _normalize_rule(raw: dict) -> Optional[dict]:
        """Normalize one Auth0 rule record.

        SECURITY: rule script content, any URLs or tokens in the script,
        and all raw rule payload are NEVER stored. script_present is a
        boolean; script content is never returned or stored.
        """
        rule_id = raw.get("id", "")
        if not isinstance(rule_id, str) or not rule_id.strip():
            return None

        script = raw.get("script", "")

        return {
            "record_type": AUTH0_RULE,
            "record_id": _trunc(rule_id, 100),
            "provider_resource_id": f"rules/{_trunc(rule_id, 100)}",
            "rule_id": _trunc(rule_id, 100),
            "name": _trunc(raw.get("name") or "", _MAX_STR_LEN),
            "enabled": _bool(raw.get("enabled", True)),
            "order": _int(raw.get("order"), 0),
            # Script: presence boolean and length category only — content NEVER stored
            "script_present": bool(isinstance(script, str) and script),
            "script_length_category": _code_length_category(script),
            "stage": _trunc(raw.get("stage") or "login_success", 30),
        }

    @staticmethod
    def _normalize_action(raw: dict) -> Optional[dict]:
        """Normalize one Auth0 action record.

        SECURITY: action code content, action secret names or values,
        dependency package versions or names, and all raw action payload are
        NEVER stored. code_present is a boolean. secrets_count is an integer;
        secret values are never stored.
        """
        action_id = raw.get("id", "")
        if not isinstance(action_id, str) or not action_id.strip():
            return None

        code = raw.get("code", "")
        secrets = raw.get("secrets") or []
        dependencies = raw.get("dependencies") or []
        supported_triggers = raw.get("supported_triggers") or []
        trigger_id = ""
        if supported_triggers and isinstance(supported_triggers[0], dict):
            trigger_id = _trunc(supported_triggers[0].get("id") or "", 50)

        return {
            "record_type": AUTH0_ACTION,
            "record_id": _trunc(action_id, 100),
            "provider_resource_id": f"actions/actions/{_trunc(action_id, 100)}",
            "action_id": _trunc(action_id, 100),
            "name": _trunc(raw.get("name") or "", _MAX_STR_LEN),
            "status": _trunc(raw.get("status") or "", 30),
            "runtime": _trunc(raw.get("runtime") or "", 30),
            "trigger_id": trigger_id,
            # Code: presence boolean + length category — content NEVER stored
            "code_present": bool(isinstance(code, str) and code),
            "code_length_category": _code_length_category(code),
            "deployed_version_present": bool(raw.get("deployed_version")),
            # Dependency and secret counts — names and values NEVER stored
            "dependencies_count": len(dependencies) if isinstance(dependencies, list) else 0,
            "secrets_count": len(secrets) if isinstance(secrets, list) else 0,
        }

    @staticmethod
    def _normalize_mfa_factor(raw: dict) -> Optional[dict]:
        """Normalize one Auth0 Guardian / MFA factor record.

        SECURITY: enrollment data, phone numbers, email addresses, recovery
        codes, user-level factor status, raw provider configs, OTP seeds,
        push device tokens, and all raw factor payload are NEVER stored.
        """
        name = _trunc(raw.get("name") or "", 50)
        if not name:
            return None

        trial_expired: Optional[bool] = None
        if "trial_expired" in raw:
            trial_expired = _bool(raw["trial_expired"])

        return {
            "record_type": AUTH0_MFA_FACTOR,
            "record_id": f"auth0_mfa_factor_{name}",
            "provider_resource_id": f"guardian/factors/{name}",
            "factor_name": name,
            "enabled": _bool(raw.get("enabled", False)),
            "trial_expired": trial_expired,
            "provider_category": _categorize_factor(name),
        }

    @staticmethod
    def _normalize_custom_domain(raw: dict) -> Optional[dict]:
        """Normalize one Auth0 custom domain record.

        SECURITY: raw domain name string (customer-identifying), verification
        tokens, DNS record values (CNAME targets), certificate material, private
        keys, and all raw custom domain payload are NEVER stored.
        domain_present is always True (by definition if we have a record);
        the actual domain string is never stored.
        """
        domain_id = raw.get("custom_domain_id", "")
        if not isinstance(domain_id, str) or not domain_id.strip():
            return None

        verification = raw.get("verification")
        verification_method = ""
        if isinstance(verification, dict):
            methods = verification.get("methods") or []
            if methods and isinstance(methods[0], dict):
                verification_method = _trunc(methods[0].get("name") or "", 30)

        return {
            "record_type": AUTH0_CUSTOM_DOMAIN,
            "record_id": _trunc(domain_id, 100),
            "provider_resource_id": f"custom-domains/{_trunc(domain_id, 100)}",
            "custom_domain_id": _trunc(domain_id, 100),
            # domain name is customer-identifying and NEVER stored
            "domain_present": True,
            "status": _trunc(raw.get("status") or "", 30),
            "type": _trunc(raw.get("type") or "", 50),
            "primary": _bool(raw.get("primary", False)),
            # Verification method category — never the verification token
            "verification_method_category": verification_method,
            "tls_policy_category": _trunc(raw.get("tls_policy") or "", 20),
        }

    # ── Per-surface fetch helpers ─────────────────────────────────────────────

    @staticmethod
    def _fetch_tenant_settings(client: httpx.Client) -> list[dict]:
        """Fetch Auth0 tenant settings. Returns a single-element list."""
        try:
            raw = Auth0Connector._get(client, "/tenants/settings")
        except ConnectorError as exc:
            if getattr(exc, "status_code", None) in (403, 404):
                logger.debug("auth0: tenants/settings not accessible (403/404); skipping")
                return []
            raise
        if not isinstance(raw, dict):
            return []
        return [Auth0Connector._normalize_tenant_settings(raw)]

    @staticmethod
    def _fetch_applications(client: httpx.Client) -> list[dict]:
        """Fetch Auth0 applications / clients.

        Uses the 'fields' parameter to explicitly exclude client_secret and
        other sensitive fields from the response, as an extra safety layer.
        """
        safe_fields = (
            "client_id,name,app_type,is_first_party,grant_types,"
            "callbacks,allowed_logout_urls,allowed_origins,web_origins,"
            "jwt_configuration,oidc_conformant,token_endpoint_auth_method,"
            "refresh_token"
        )
        try:
            raws = Auth0Connector._get_pages(
                client, "/clients", "clients", _MAX_APPLICATIONS,
                extra_params={"fields": safe_fields, "include_fields": "true"},
            )
        except ConnectorError as exc:
            if getattr(exc, "status_code", None) in (403, 404):
                logger.debug("auth0: clients not accessible (403/404); skipping")
                return []
            raise
        records = []
        for raw in raws:
            rec = Auth0Connector._normalize_application(raw)
            if rec is not None:
                records.append(rec)
        return records

    @staticmethod
    def _fetch_connections(client: httpx.Client) -> list[dict]:
        """Fetch Auth0 connections."""
        safe_fields = "id,name,strategy,enabled_clients,is_domain_connection,options"
        try:
            raws = Auth0Connector._get_pages(
                client, "/connections", "result", _MAX_CONNECTIONS,
                extra_params={"fields": safe_fields, "include_fields": "true"},
            )
        except ConnectorError as exc:
            if getattr(exc, "status_code", None) in (403, 404):
                logger.debug("auth0: connections not accessible (403/404); skipping")
                return []
            raise
        records = []
        for raw in raws:
            rec = Auth0Connector._normalize_connection(raw)
            if rec is not None:
                records.append(rec)
        return records

    @staticmethod
    def _fetch_resource_servers(client: httpx.Client) -> list[dict]:
        """Fetch Auth0 APIs / resource servers."""
        safe_fields = (
            "id,name,identifier,signing_alg,token_lifetime,"
            "allow_offline_access,skip_consent_for_verifiable_first_party_clients,"
            "enforce_policies,scopes"
        )
        try:
            raws = Auth0Connector._get_pages(
                client, "/resource-servers", "resource_servers",
                _MAX_RESOURCE_SERVERS,
                extra_params={"fields": safe_fields, "include_fields": "true"},
            )
        except ConnectorError as exc:
            if getattr(exc, "status_code", None) in (403, 404):
                logger.debug("auth0: resource-servers not accessible (403/404); skipping")
                return []
            raise
        records = []
        for raw in raws:
            rec = Auth0Connector._normalize_resource_server(raw)
            if rec is not None:
                records.append(rec)
        return records

    @staticmethod
    def _fetch_rules(client: httpx.Client) -> list[dict]:
        """Fetch Auth0 rules (legacy pipeline).

        Rules are deprecated in favor of Actions but remain available on
        tenants still using the classic pipeline.
        """
        safe_fields = "id,name,enabled,order,script,stage"
        try:
            raws = Auth0Connector._get_pages(
                client, "/rules", "rules", _MAX_RULES,
                extra_params={"fields": safe_fields, "include_fields": "true"},
            )
        except ConnectorError as exc:
            if getattr(exc, "status_code", None) in (403, 404):
                logger.debug("auth0: rules not accessible (403/404); skipping")
                return []
            raise
        records = []
        for raw in raws:
            rec = Auth0Connector._normalize_rule(raw)
            if rec is not None:
                records.append(rec)
        return records

    @staticmethod
    def _fetch_actions(client: httpx.Client) -> list[dict]:
        """Fetch Auth0 actions (Actions pipeline)."""
        try:
            data = Auth0Connector._get(
                client, "/actions/actions",
                params={"per_page": _PAGE_SIZE, "page": 0},
            )
        except ConnectorError as exc:
            if getattr(exc, "status_code", None) in (403, 404):
                logger.debug("auth0: actions not accessible (403/404); skipping")
                return []
            raise

        raws: list = []
        if isinstance(data, list):
            raws = data
        elif isinstance(data, dict):
            raws = data.get("actions") or []

        records = []
        for raw in raws[:_MAX_ACTIONS]:
            rec = Auth0Connector._normalize_action(raw)
            if rec is not None:
                records.append(rec)
        return records

    @staticmethod
    def _fetch_mfa_factors(client: httpx.Client) -> list[dict]:
        """Fetch Auth0 MFA / Guardian factor configuration."""
        try:
            data = Auth0Connector._get(client, "/guardian/factors")
        except ConnectorError as exc:
            if getattr(exc, "status_code", None) in (403, 404):
                logger.debug("auth0: guardian/factors not accessible (403/404); skipping")
                return []
            raise

        raws: list = data if isinstance(data, list) else []
        records = []
        for raw in raws:
            rec = Auth0Connector._normalize_mfa_factor(raw)
            if rec is not None:
                records.append(rec)
        return records

    @staticmethod
    def _fetch_custom_domains(client: httpx.Client) -> list[dict]:
        """Fetch Auth0 custom domain configuration."""
        try:
            data = Auth0Connector._get(client, "/custom-domains")
        except ConnectorError as exc:
            if getattr(exc, "status_code", None) in (403, 404):
                logger.debug("auth0: custom-domains not accessible (403/404); skipping")
                return []
            raise

        raws: list = data if isinstance(data, list) else []
        records = []
        for raw in raws[:_MAX_CUSTOM_DOMAINS]:
            rec = Auth0Connector._normalize_custom_domain(raw)
            if rec is not None:
                records.append(rec)
        return records

    # ── Public connector interface ─────────────────────────────────────────────

    def validate_credentials(self, credentials: dict) -> bool:
        """Verify Auth0 credentials with a single lightweight Management API call.

        Acquires a Management API token (direct or via client_credentials) and
        makes one GET /api/v2/clients?per_page=1 to confirm read access.

        SECURITY: the acquired token is never stored on the instance.

        Raises:
            AuthenticationError: Credentials are invalid or token acquisition failed.
            ConnectorError: API returned an unexpected error.
            NetworkError: Transport-level failure.
        """
        domain = _sanitize_domain(credentials.get("domain", ""))
        token = self._acquire_token(domain, credentials)
        with self._make_management_client(domain, token) as client:
            self._get(
                client, "/clients",
                params={"per_page": "1", "include_totals": "false"},
            )
        return True

    def fetch(self, credentials: dict) -> list[dict]:
        """Fetch all Auth0 drift surfaces and return normalised records.

        Acquires a Management API token from credentials, then calls each
        surface-specific fetcher. Soft-failure surfaces (rules, actions, MFA
        factors, custom domains) skip gracefully when permissions are absent,
        so partial permission sets still produce useful drift records.

        SECURITY: the acquired Management API token is used only within this
        method's scope, placed only in Authorization headers, never stored on
        the connector instance, never logged, and discarded when the httpx.Client
        context manager exits.

        Args:
            credentials: Dict with 'domain' and either 'management_api_token'
                or 'client_id' + 'client_secret'.

        Returns:
            Flat list of safe, normalised record dicts.

        Raises:
            AuthenticationError: Token acquisition failed or 401 returned.
            ConnectorError: A required API surface returned an unexpected error.
            RateLimitError: Rate limits exceeded.
            NetworkError: Transport-level failure.
        """
        domain = _sanitize_domain(credentials.get("domain", ""))

        # SECURITY: token is acquired here, used within the context manager scope,
        # and never stored on self. client_secret is never logged.
        token = self._acquire_token(domain, credentials)

        records: list[dict] = []
        with self._make_management_client(domain, token) as client:
            # Core surfaces — raise on hard errors
            records.extend(self._fetch_tenant_settings(client))
            records.extend(self._fetch_applications(client))
            records.extend(self._fetch_connections(client))
            records.extend(self._fetch_resource_servers(client))
            # Soft-failure surfaces — skip gracefully on any exception
            try:
                records.extend(self._fetch_rules(client))
            except Exception:  # noqa: BLE001
                logger.debug("auth0: rules fetch failed; skipping surface")
            try:
                records.extend(self._fetch_actions(client))
            except Exception:  # noqa: BLE001
                logger.debug("auth0: actions fetch failed; skipping surface")
            try:
                records.extend(self._fetch_mfa_factors(client))
            except Exception:  # noqa: BLE001
                logger.debug("auth0: mfa factors fetch failed; skipping surface")
            try:
                records.extend(self._fetch_custom_domains(client))
            except Exception:  # noqa: BLE001
                logger.debug("auth0: custom domains fetch failed; skipping surface")

        return records

    # ── Activity event synthesis (M81D) ───────────────────────────────────────

    @staticmethod
    def _activity_event(
        event_type: str,
        provider_event_id: str,
        metadata: dict,
    ) -> dict:
        """Build one synthesized config-state activity event envelope.

        Mirrors the SendGrid connector's _activity_event pattern.
        """
        meta = dict(metadata)
        meta.setdefault("event_source", "auth0_activity_event")
        meta.setdefault("event_action", event_type)
        return {
            "event_type": event_type,
            "provider": "auth0",
            "source": "auth0_activity_event",
            "event_source": "auth0_activity_event",
            "provider_event_id": provider_event_id,
            "metadata": meta,
        }

    def list_activity_events(
        self,
        credentials: dict,
        *,
        max_events: int = 100,
        lookback_hours: int = 24,
    ) -> list[dict]:
        """Synthesize review-safe Auth0 configuration-state activity events.

        Auth0 Management API logs (/api/v2/logs) include user_id, email,
        IP address, and device data in every log entry — storing these
        would violate ConfigTrace's privacy contract. Instead, activity
        events are synthesized from the same safe drift surfaces the drift
        connector already reads (tenant_settings, applications, connections,
        resource_servers, rules, actions, mfa_factors, and custom_domains).

        Each event represents configuration state observed at poll time.
        Events are date-scoped (day-level) for idempotency: re-polling on
        the same UTC day yields the same provider_event_id and is a no-op.

        Login, authentication, session, token-exchange, password-reset,
        MFA enrollment, user profile, and organization-member events are
        NEVER fetched, returned, or stored.

        PRIVACY — what is NEVER returned:
        - client_secret, management_api_token, access tokens, JWTs, keys.
        - Raw callback URLs, logout URLs, allowed origins, audience URIs.
        - Custom domain name strings, rule/action script content.
        - Action secret names or values.
        - User emails, user IDs, user names, profile data.
        - IP addresses, device fingerprints, session data.
        - MFA enrollment data, recovery codes.
        - Connection credentials (passwords, tokens, certs, keys).
        - Any raw Auth0 API response dicts or log entries.

        Raises:
            AuthenticationError: Token acquisition or 401 from Management API.
            RateLimitError: 429 rate limit hit.
            NetworkError: Transport-level failure.
            ConnectorError: Unexpected 4xx/5xx.
        """
        from datetime import datetime, timezone

        max_events = min(max(1, max_events), 1000)
        lookback_hours = min(max(1, lookback_hours), 168)  # noqa: F841 — context only

        day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        events: list[dict] = []

        domain = _sanitize_domain(credentials.get("domain", ""))
        token = self._acquire_token(domain, credentials)

        with self._make_management_client(domain, token) as client:
            self._collect_tenant_event(client, events, day)
            self._collect_application_events(client, events, day)
            self._collect_connection_events(client, events, day)
            self._collect_resource_server_events(client, events, day)
            try:
                self._collect_rule_events(client, events, day)
            except Exception:  # noqa: BLE001
                logger.debug("auth0_activity: rules surface skipped")
            try:
                self._collect_action_events(client, events, day)
            except Exception:  # noqa: BLE001
                logger.debug("auth0_activity: actions surface skipped")
            try:
                self._collect_mfa_factor_events(client, events, day)
            except Exception:  # noqa: BLE001
                logger.debug("auth0_activity: mfa_factors surface skipped")
            try:
                self._collect_custom_domain_events(client, events, day)
            except Exception:  # noqa: BLE001
                logger.debug("auth0_activity: custom_domains surface skipped")

        return events[:max_events]

    # ── Activity surface collectors (M81D) ────────────────────────────────────
    #
    # Each collector reuses the existing safe drift fetchers/normalizers and
    # emits at most a small, capped set of config-state events. Each fails
    # soft on 403/404 (missing permission) so one inaccessible surface
    # never aborts the whole poll. Auth/rate-limit/network errors propagate.

    def _collect_tenant_event(
        self, client: "httpx.Client", events: list, day: str
    ) -> None:
        try:
            recs = self._fetch_tenant_settings(client)
        except ConnectorError as exc:
            if getattr(exc, "status_code", None) in (403, 404):
                return
            raise
        if not recs:
            return
        rec = recs[0]
        meta = {
            "resource_type": "tenant_settings",
            "event_action": "auth0.tenant.updated",
            "category": "auth0_configuration",
            "status": "observed",
            "operation_name": "auth0.tenant.settings.observe",
            "operation_family": "auth0.tenant",
            "operation_action": "observe",
        }
        # Include safe scalar fields from the normalized record.
        for key in (
            "session_lifetime_category",
            "idle_session_lifetime_category",
            "enabled_locales_count",
            "flag_enable_dynamic_client_registration",
            "flag_revoke_refresh_token_grant",
            "flag_universal_login",
        ):
            if key in rec:
                meta[key] = rec[key]
        eid = f"auth0.tenant.updated:{day}"
        events.append(self._activity_event("auth0.tenant.updated", eid, meta))

    def _collect_application_events(
        self, client: "httpx.Client", events: list, day: str
    ) -> None:
        try:
            recs = self._fetch_applications(client)
        except ConnectorError as exc:
            if getattr(exc, "status_code", None) in (403, 404):
                return
            raise
        for rec in recs:
            cid = rec.get("client_id") or ""
            if not cid:
                continue
            meta = {
                "resource_type": "application",
                "event_action": "auth0.application.updated",
                "category": "auth0_configuration",
                "status": "observed",
                "operation_name": "auth0.application.observe",
                "operation_family": "auth0.application",
                "operation_action": "observe",
                "client_id": _trunc(cid, 100),
                "resource_id": _trunc(cid, 100),
                "resource_name": _trunc(rec.get("name") or "", _MAX_STR_LEN),
            }
            for key in (
                "app_type", "is_first_party", "jwt_alg", "oidc_conformant",
                "token_endpoint_auth_method", "refresh_token_rotation_enabled",
                "refresh_token_lifetime_category",
                "grant_types_count", "grant_password_enabled",
                "grant_implicit_enabled", "grant_client_credentials_enabled",
                "grant_refresh_token_enabled", "grant_device_code_enabled",
                "callbacks_count", "allowed_logout_urls_count",
                "allowed_origins_count", "web_origins_count",
                "wildcard_callback_present", "wildcard_allowed_origin_present",
                "wildcard_logout_url_present",
                "localhost_callback_present", "localhost_origin_present",
                "callbacks_missing_https", "allowed_origins_missing_https",
            ):
                if key in rec:
                    meta[key] = rec[key]
            eid = f"auth0.application.updated:{cid}:{day}"
            events.append(self._activity_event("auth0.application.updated", eid, meta))

    def _collect_connection_events(
        self, client: "httpx.Client", events: list, day: str
    ) -> None:
        try:
            recs = self._fetch_connections(client)
        except ConnectorError as exc:
            if getattr(exc, "status_code", None) in (403, 404):
                return
            raise
        for rec in recs:
            conn_id = rec.get("connection_id") or ""
            if not conn_id:
                continue
            meta = {
                "resource_type": "connection",
                "event_action": "auth0.connection.updated",
                "category": "auth0_configuration",
                "status": "observed",
                "operation_name": "auth0.connection.observe",
                "operation_family": "auth0.connection",
                "operation_action": "observe",
                "connection_id": _trunc(conn_id, 100),
                "resource_id": _trunc(conn_id, 100),
                "resource_name": _trunc(rec.get("name") or "", _MAX_STR_LEN),
            }
            for key in (
                "enabled_clients_count", "is_domain_connection",
                "password_policy_category",
            ):
                if key in rec:
                    meta[key] = rec[key]
            eid = f"auth0.connection.updated:{conn_id}:{day}"
            events.append(self._activity_event("auth0.connection.updated", eid, meta))

    def _collect_resource_server_events(
        self, client: "httpx.Client", events: list, day: str
    ) -> None:
        try:
            recs = self._fetch_resource_servers(client)
        except ConnectorError as exc:
            if getattr(exc, "status_code", None) in (403, 404):
                return
            raise
        for rec in recs:
            rs_id = rec.get("resource_server_id") or ""
            if not rs_id:
                continue
            meta = {
                "resource_type": "resource_server",
                "event_action": "auth0.resource_server.updated",
                "category": "auth0_configuration",
                "status": "observed",
                "operation_name": "auth0.resource_server.observe",
                "operation_family": "auth0.resource_server",
                "operation_action": "observe",
                "resource_server_id": _trunc(rs_id, 100),
                "resource_id": _trunc(rs_id, 100),
                "resource_name": _trunc(rec.get("name") or "", _MAX_STR_LEN),
            }
            for key in (
                "signing_alg", "token_lifetime_category",
                "allow_offline_access", "rbac_enabled", "scopes_count",
            ):
                if key in rec:
                    meta[key] = rec[key]
            eid = f"auth0.resource_server.updated:{rs_id}:{day}"
            events.append(
                self._activity_event("auth0.resource_server.updated", eid, meta)
            )

    def _collect_rule_events(
        self, client: "httpx.Client", events: list, day: str
    ) -> None:
        try:
            recs = self._fetch_rules(client)
        except ConnectorError as exc:
            if getattr(exc, "status_code", None) in (403, 404):
                return
            raise
        for rec in recs:
            rule_id = rec.get("rule_id") or ""
            if not rule_id:
                continue
            meta = {
                "resource_type": "rule",
                "event_action": "auth0.rule.updated",
                "category": "auth0_configuration",
                "status": "observed",
                "operation_name": "auth0.rule.observe",
                "operation_family": "auth0.rule",
                "operation_action": "observe",
                "rule_id": _trunc(rule_id, 100),
                "resource_id": _trunc(rule_id, 100),
                "resource_name": _trunc(rec.get("name") or "", _MAX_STR_LEN),
            }
            for key in ("enabled", "script_present", "script_length_category"):
                if key in rec:
                    meta[key] = rec[key]
            eid = f"auth0.rule.updated:{rule_id}:{day}"
            events.append(self._activity_event("auth0.rule.updated", eid, meta))

    def _collect_action_events(
        self, client: "httpx.Client", events: list, day: str
    ) -> None:
        try:
            recs = self._fetch_actions(client)
        except ConnectorError as exc:
            if getattr(exc, "status_code", None) in (403, 404):
                return
            raise
        for rec in recs:
            action_id = rec.get("action_id") or ""
            if not action_id:
                continue
            is_deployed = rec.get("deployed_version_present", False)
            event_type = (
                "auth0.action.deployed" if is_deployed
                else "auth0.action.updated"
            )
            meta = {
                "resource_type": "action",
                "event_action": event_type,
                "category": "auth0_configuration",
                "status": "observed",
                "operation_name": "auth0.action.observe",
                "operation_family": "auth0.action",
                "operation_action": "observe",
                "action_id": _trunc(action_id, 100),
                "resource_id": _trunc(action_id, 100),
                "resource_name": _trunc(rec.get("name") or "", _MAX_STR_LEN),
            }
            for key in (
                "code_present", "code_length_category",
                "deployed_version_present", "secrets_count",
            ):
                if key in rec:
                    meta[key] = rec[key]
            eid = f"{event_type}:{action_id}:{day}"
            events.append(self._activity_event(event_type, eid, meta))

    def _collect_mfa_factor_events(
        self, client: "httpx.Client", events: list, day: str
    ) -> None:
        try:
            recs = self._fetch_mfa_factors(client)
        except ConnectorError as exc:
            if getattr(exc, "status_code", None) in (403, 404):
                return
            raise
        for rec in recs:
            factor_name = rec.get("factor_name") or ""
            if not factor_name:
                continue
            meta = {
                "resource_type": "mfa_factor",
                "event_action": "auth0.mfa_factor.updated",
                "category": "auth0_configuration",
                "status": "observed",
                "operation_name": "auth0.mfa_factor.observe",
                "operation_family": "auth0.mfa_factor",
                "operation_action": "observe",
                "factor_name": _trunc(factor_name, 50),
                "resource_id": _trunc(factor_name, 50),
                "resource_name": _trunc(factor_name, 50),
            }
            for key in ("enabled", "provider_category"):
                if key in rec:
                    meta[key] = rec[key]
            eid = f"auth0.mfa_factor.updated:{factor_name}:{day}"
            events.append(self._activity_event("auth0.mfa_factor.updated", eid, meta))

    def _collect_custom_domain_events(
        self, client: "httpx.Client", events: list, day: str
    ) -> None:
        try:
            recs = self._fetch_custom_domains(client)
        except ConnectorError as exc:
            if getattr(exc, "status_code", None) in (403, 404):
                return
            raise
        for rec in recs:
            domain_id = rec.get("custom_domain_id") or ""
            if not domain_id:
                continue
            domain_status = rec.get("status") or ""
            event_type = (
                "auth0.custom_domain.verified"
                if domain_status == "ready"
                else "auth0.custom_domain.updated"
            )
            meta = {
                "resource_type": "custom_domain",
                "event_action": event_type,
                "category": "auth0_configuration",
                "status": "observed",
                "operation_name": "auth0.custom_domain.observe",
                "operation_family": "auth0.custom_domain",
                "operation_action": "observe",
                "custom_domain_id": _trunc(domain_id, 100),
                "resource_id": _trunc(domain_id, 100),
            }
            for key in ("tls_policy_category", "status_category"):
                if key in rec:
                    meta[key] = rec[key]
            # Include domain status as status_category (safe label).
            if "status" in rec and isinstance(rec["status"], str):
                meta["status_category"] = _trunc(rec["status"], 30)
            eid = f"{event_type}:{domain_id}:{day}"
            events.append(self._activity_event(event_type, eid, meta))
