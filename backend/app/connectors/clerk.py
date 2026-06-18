"""Clerk drift connector — M83A.

Snapshots safe configuration metadata from the Clerk Backend API v1:
  - Instance settings (feature flags, restrictions, session/sign-up posture)
  - Domains (status, verified, primary, SSL — never raw domain names)
  - Redirect URLs (scheme/posture booleans — never raw URL strings)
  - JWT templates (name, claims count, lifetime — never template body)
  - Webhook endpoints (scheme/posture booleans — never URL, secret, or events)
  - Email/SMS settings (enabled flags, custom-sender presence)
  - Auth strategy (enabled auth methods — never credentials or secrets)
  - Organization settings (enabled flags, membership posture)
  - Session policy (lifetime categories — never session tokens or IDs)

Authentication: Clerk Backend API v1 uses a secret key (sk_live_* or
sk_test_*) passed as a Bearer token in the Authorization header.

PRIVACY / SECURITY — what is NEVER stored or logged
----------------------------------------------------
- Clerk secret key — NEVER stored on instance, NEVER logged
- Publishable key or Frontend API URL — NEVER stored on instance or in records
- Session tokens — NEVER fetched, NEVER stored
- JWTs / OAuth tokens / bearer tokens — NEVER stored in records
- Webhook URLs, signing secrets — presence booleans only; values NEVER stored
- Raw redirect URLs, callback URLs, allowed origins — posture booleans only
- JWT template body, custom claims, audience URIs, issuer strings — counts and
  presence booleans only; values NEVER stored
- User emails, user IDs, user names, phone numbers — NEVER fetched or stored
- Organization names (customer-identifying) — NEVER stored
- Member identities, invitation lists — NEVER fetched or stored
- Session history, login history, IP addresses, user agents — NEVER fetched
- Password data, MFA secrets, backup codes — NEVER stored
- Raw Clerk API response dicts — NEVER stored in records
- Customer data, PII of any kind — NEVER stored

Credentials dict
----------------
    secret_key       : str — Clerk Backend API secret key (sk_live_* or
                             sk_test_*). NEVER logged or stored in plaintext.
    frontend_api_url : str — optional, used to build the Clerk FAPI base URL
                             if needed. Not currently used for drift snapshots.
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
from app.connectors.clerk_schema import (
    CLERK_APPLICATION,
    CLERK_AUTH_STRATEGY,
    CLERK_DOMAIN,
    CLERK_EMAIL_SMS_SETTINGS,
    CLERK_INSTANCE_SETTINGS,
    CLERK_JWT_TEMPLATE,
    CLERK_ORGANIZATION_SETTINGS,
    CLERK_REDIRECT_URL_CONFIG,
    CLERK_SESSION_POLICY,
    CLERK_WEBHOOK_ENDPOINT,
)

logger = logging.getLogger(__name__)

# ── Module-level constants ─────────────────────────────────────────────────────

_BASE_URL = "https://api.clerk.com/v1"
_TIMEOUT = 30.0
_MAX_STR_LEN = 100

# Per-surface record caps
_MAX_DOMAINS = 20
_MAX_REDIRECT_URLS = 100
_MAX_JWT_TEMPLATES = 50
_MAX_WEBHOOKS = 50

# Session lifetime category thresholds (minutes).
_SESSION_CATEGORIES = [
    (60, "very_short"),       # < 1 hour
    (1440, "short"),          # 1h – 24h
    (10080, "standard"),      # 24h – 7 days
    (43200, "extended"),      # 7d – 30 days
]

# JWT template lifetime category thresholds (seconds).
_JWT_LIFETIME_CATEGORIES = [
    (300, "very_short"),      # < 5 minutes
    (3600, "short"),          # 5m – 1h
    (86400, "standard"),      # 1h – 24h
]


# ── Helper functions ───────────────────────────────────────────────────────────


def _trunc(value: Any, length: int = _MAX_STR_LEN) -> str:
    if isinstance(value, str):
        return value[:length]
    return ""


def _bool_field(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return bool(value)
    if isinstance(value, str):
        return value.lower() in ("true", "1", "yes", "enabled")
    return default


def _int_field(value: Any, default: int = 0) -> int:
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


def _len_list(value: Any) -> int:
    if isinstance(value, list):
        return len(value)
    if isinstance(value, dict):
        return len(value)
    return 0


def _session_category(minutes: Any) -> str:
    m = _int_field(minutes, 0)
    for threshold, cat in _SESSION_CATEGORIES:
        if m < threshold:
            return cat
    return "very_long"


def _jwt_lifetime_category(seconds: Any) -> str:
    s = _int_field(seconds, 0)
    for threshold, cat in _JWT_LIFETIME_CATEGORIES:
        if s < threshold:
            return cat
    return "extended"


def _url_scheme_category(url: Any) -> str:
    """Derive a safe scheme category from a URL string.

    SECURITY: the raw URL is NEVER stored or logged — only the category label
    is kept.
    """
    if not isinstance(url, str) or not url:
        return "unknown"
    u = url.strip().lower()
    if u.startswith("https://"):
        return "https"
    if u.startswith("http://"):
        return "http"
    return "custom"


def _has_wildcard_url(url: Any) -> bool:
    """Return True if the URL contains a wildcard character.

    SECURITY: the raw URL string is NEVER stored.
    """
    return isinstance(url, str) and "*" in url


def _is_localhost_url(url: Any) -> bool:
    """Return True if the URL targets a localhost/loopback origin.

    SECURITY: the raw URL string is NEVER stored.
    """
    if not isinstance(url, str):
        return False
    u = url.strip().lower()
    for prefix in ("http://localhost", "https://localhost",
                   "http://127.0.0.1", "https://127.0.0.1",
                   "http://[::1]", "https://[::1]"):
        if u.startswith(prefix):
            return True
    return False


def _is_custom_scheme_url(url: Any) -> bool:
    """Return True if the URL uses a non-http(s) scheme (e.g. custom deep link).

    SECURITY: the raw URL string is NEVER stored.
    """
    if not isinstance(url, str):
        return False
    u = url.strip().lower()
    return not (u.startswith("http://") or u.startswith("https://"))


def _sanitize_secret_key(secret_key: Any) -> str:
    """Validate the Clerk secret key credential.

    Returns the stripped secret key string or raises ValueError for
    clearly malformed input. SECURITY: the value is never logged.
    """
    if not isinstance(secret_key, str):
        raise ValueError("clerk: secret_key credential must be a string")
    cleaned = secret_key.strip()
    if not cleaned:
        raise ValueError("clerk: secret_key must not be empty")
    if len(cleaned) > 500:
        raise ValueError("clerk: secret_key is unexpectedly long")
    return cleaned


# ── Connector ──────────────────────────────────────────────────────────────────


class ClerkConnector(BaseConnector):
    """Clerk Backend API v1 connector for ConfigTrace drift tracking (M83A).

    Stateless: the secret key is accepted at call time and is never stored
    as an instance attribute. It is placed only in the Authorization header
    and is discarded when the httpx.Client context exits.

    SECURITY: the secret key is NEVER stored as an instance attribute,
    NEVER logged, NEVER included in error messages, and NEVER written to
    any normalised record. User data, session data, and raw Clerk API
    responses are NEVER stored in any record.
    """

    # ── HTTP client ───────────────────────────────────────────────────────────

    @staticmethod
    def _make_client(secret_key: str) -> httpx.Client:
        """Build an httpx.Client for the Clerk Backend API v1.

        SECURITY: secret_key is placed in the Authorization header only.
        It is never stored on the connector instance or logged.
        """
        return httpx.Client(
            base_url=_BASE_URL,
            headers={
                "Authorization": f"Bearer {secret_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            timeout=_TIMEOUT,
        )

    @staticmethod
    def _raise_for_status(resp: httpx.Response, context: str = "") -> None:
        """Map Clerk API HTTP error codes to connector exceptions."""
        if resp.status_code < 400:
            return
        if resp.status_code == 401:
            raise AuthenticationError(
                f"clerk: 401 Unauthorized{' — ' + context if context else ''} "
                "— check the secret_key credential",
                status_code=401,
            )
        if resp.status_code == 403:
            raise ConnectorError(
                f"clerk: 403 Forbidden{' — ' + context if context else ''}",
                status_code=403,
            )
        if resp.status_code == 429:
            retry_after: Optional[float] = None
            try:
                retry_after = float(resp.headers.get("Retry-After", ""))
            except (ValueError, TypeError):
                pass
            raise RateLimitError(
                "clerk: rate limit hit (429)",
                retry_after=retry_after,
            )
        if resp.status_code >= 500:
            raise ConnectorError(
                f"clerk: server error HTTP {resp.status_code}"
                + (f" — {context}" if context else ""),
                status_code=resp.status_code,
            )
        if resp.status_code >= 400:
            raise ConnectorError(
                f"clerk: HTTP {resp.status_code}"
                + (f" — {context}" if context else ""),
                status_code=resp.status_code,
            )

    @staticmethod
    def _get_json(client: httpx.Client, path: str, params: dict | None = None) -> Any:
        """GET a Clerk API path and return the parsed JSON body."""
        try:
            resp = client.get(path, params=params or {})
        except httpx.ConnectError as exc:
            raise NetworkError(f"clerk: connection failed to {path}: {exc}") from exc
        except httpx.TimeoutException:
            raise NetworkError(f"clerk: request timed out for {path}")
        except httpx.HTTPError as exc:
            raise NetworkError(f"clerk: HTTP error for {path}: {exc}") from exc

        ClerkConnector._raise_for_status(resp, context=path)
        try:
            return resp.json()
        except ValueError as exc:
            raise ConnectorError(
                f"clerk: response for {path} was not valid JSON"
            ) from exc

    # ── validate_credentials ──────────────────────────────────────────────────

    def validate_credentials(self, credentials: dict) -> bool:
        """Validate Clerk Backend API credentials by calling GET /v1/instance.

        SECURITY: the secret_key is used only for the Authorization header
        and is discarded immediately after. It is never stored on the
        instance or logged.

        Returns True on success; raises AuthenticationError / ConnectorError
        / NetworkError / RateLimitError on failure (following the existing
        connector convention where exceptions signal failure).
        """
        secret_key = _sanitize_secret_key(credentials.get("secret_key", ""))
        with self._make_client(secret_key) as client:
            self._get_json(client, "/instance")
        return True

    # ── Normalizers ───────────────────────────────────────────────────────────

    def _normalize_instance(self, raw: dict) -> dict:
        """Normalise a Clerk instance object into a safe flat record.

        SECURITY: raw domain names, support email addresses, raw theme data,
        and all customer-identifying fields are NEVER stored.
        """
        instance_id = _trunc(raw.get("id") or "clerk_instance_main", 60)

        # Extract sign-up / sign-in attribute flags
        attrs = raw.get("user_settings", {}) or {}
        social_connections = attrs.get("social", {}) or {}
        social_count = sum(
            1 for k, v in social_connections.items()
            if isinstance(v, dict) and _bool_field(v.get("enabled"))
        ) if isinstance(social_connections, dict) else _int_field(social_connections)

        # MFA settings
        mfa = attrs.get("mfa", {}) or {}
        mfa_policy = mfa.get("user_settings", {}) or {} if isinstance(mfa, dict) else {}
        mfa_enabled = _bool_field((mfa or {}).get("enabled") if isinstance(mfa, dict) else False)
        mfa_supported = mfa.get("supported_factors", []) or [] if isinstance(mfa, dict) else []
        mfa_factor_count = len(mfa_supported) if isinstance(mfa_supported, list) else 0

        # Attribute flags
        email_enabled = _bool_field(
            (attrs.get("email_address") or {}).get("enabled")
            if isinstance(attrs.get("email_address"), dict) else attrs.get("email_enabled")
        )
        phone_enabled = _bool_field(
            (attrs.get("phone_number") or {}).get("enabled")
            if isinstance(attrs.get("phone_number"), dict) else attrs.get("phone_enabled")
        )
        username_enabled = _bool_field(
            (attrs.get("username") or {}).get("enabled")
            if isinstance(attrs.get("username"), dict) else attrs.get("username_enabled")
        )
        password_enabled = _bool_field(
            (attrs.get("password") or {}).get("enabled")
            if isinstance(attrs.get("password"), dict) else attrs.get("password_enabled")
        )

        # Session settings
        session_settings = raw.get("session_settings", {}) or {}
        token_ttl_mins = _int_field(
            session_settings.get("token_lifetime_minutes")
            or session_settings.get("session_lifetime_minutes"), 60
        )
        session_cat = _session_category(token_ttl_mins)

        # Organization settings
        org_settings = raw.get("organization_settings", {}) or {}

        # Restrictions
        restrictions = raw.get("restrictions", {}) or {}
        allowlist = _bool_field(restrictions.get("allowlist", {}).get("enabled") if isinstance(restrictions.get("allowlist"), dict) else restrictions.get("allowlist_enabled"))
        blocklist = _bool_field(restrictions.get("blocklist", {}).get("enabled") if isinstance(restrictions.get("blocklist"), dict) else restrictions.get("blocklist_enabled"))
        sign_in_mode = _trunc(restrictions.get("sign_in_mode") or "public", 50)

        return {
            "record_type": CLERK_INSTANCE_SETTINGS,
            "record_id": instance_id,
            "provider_resource_id": "instance/settings",
            "provider": "clerk",
            "environment_type": _trunc(raw.get("environment_type") or "unknown", 50),
            "sign_up_enabled": _bool_field(raw.get("sign_up_enabled", True)),
            "sign_in_enabled": _bool_field(raw.get("sign_in_enabled", True)),
            "email_enabled": email_enabled,
            "phone_enabled": phone_enabled,
            "username_enabled": username_enabled,
            "password_enabled": password_enabled,
            "social_provider_count": social_count,
            "mfa_enabled": mfa_enabled,
            "mfa_factor_count": mfa_factor_count,
            "session_lifetime_category": session_cat,
            # These are derived at full-fetch time from domain/redirect/webhook lists
            "allowed_redirect_count": _int_field(raw.get("redirect_url_count") or raw.get("allowed_redirect_count"), 0),
            "domain_count": _int_field(raw.get("domain_count"), 0),
            "webhook_count": _int_field(raw.get("webhook_count"), 0),
            "allowlist_enabled": allowlist,
            "blocklist_enabled": blocklist,
            "sign_in_mode": sign_in_mode,
        }

    def _normalize_auth_strategy(self, raw: dict) -> dict:
        """Derive auth strategy record from instance user_settings.

        SECURITY: social provider secrets, SAML certs, and raw strategy
        config are NEVER stored.
        """
        attrs = raw.get("user_settings", {}) or {}
        social = attrs.get("social", {}) or {}
        social_count = sum(
            1 for v in (social.values() if isinstance(social, dict) else [])
            if isinstance(v, dict) and _bool_field(v.get("enabled"))
        )
        mfa = attrs.get("mfa", {}) or {}
        mfa_enabled = _bool_field(mfa.get("enabled") if isinstance(mfa, dict) else False)
        mfa_supported = mfa.get("supported_factors", []) or [] if isinstance(mfa, dict) else []
        mfa_required = _bool_field(mfa.get("user_settings", {}).get("mfa_required") if isinstance(mfa, dict) else False)

        password_enabled = _bool_field(
            (attrs.get("password") or {}).get("enabled")
            if isinstance(attrs.get("password"), dict) else attrs.get("password_enabled")
        )
        saml_enabled = _bool_field(attrs.get("saml_enabled") or raw.get("saml_enabled"))
        passkey_enabled = _bool_field(attrs.get("passkeys", {}).get("enabled") if isinstance(attrs.get("passkeys"), dict) else attrs.get("passkey_enabled"))
        magic_link_enabled = _bool_field(
            (attrs.get("magic_link") or {}).get("enabled")
            if isinstance(attrs.get("magic_link"), dict) else attrs.get("magic_link_enabled")
        )
        email_otp_enabled = _bool_field(
            (attrs.get("email_otp") or {}).get("enabled")
            if isinstance(attrs.get("email_otp"), dict) else attrs.get("email_otp_enabled")
        )
        phone_otp_enabled = _bool_field(
            (attrs.get("phone_otp") or {}).get("enabled")
            if isinstance(attrs.get("phone_otp"), dict) else attrs.get("phone_otp_enabled")
        )
        return {
            "record_type": CLERK_AUTH_STRATEGY,
            "record_id": "clerk_auth_strategy_main",
            "provider_resource_id": "instance/auth_strategy",
            "provider": "clerk",
            "password_enabled": password_enabled,
            "oauth_enabled": social_count > 0,
            "social_provider_count": social_count,
            "saml_enabled": saml_enabled,
            "mfa_enabled": mfa_enabled,
            "mfa_required": mfa_required,
            "passkey_enabled": passkey_enabled,
            "magic_link_enabled": magic_link_enabled,
            "email_otp_enabled": email_otp_enabled,
            "phone_otp_enabled": phone_otp_enabled,
        }

    def _normalize_email_sms_settings(self, raw: dict) -> dict:
        """Derive email/SMS settings record from instance user_settings.

        SECURITY: sender addresses, template content are NEVER stored.
        """
        attrs = raw.get("user_settings", {}) or {}
        email_enabled = _bool_field(
            (attrs.get("email_address") or {}).get("enabled")
            if isinstance(attrs.get("email_address"), dict) else attrs.get("email_enabled")
        )
        phone_enabled = _bool_field(
            (attrs.get("phone_number") or {}).get("enabled")
            if isinstance(attrs.get("phone_number"), dict) else attrs.get("phone_enabled")
        )
        # Custom sender domain presence — boolean only, never the address
        comm_settings = raw.get("communication_settings", {}) or {}
        custom_sender = _bool_field(comm_settings.get("custom_sender_present") or comm_settings.get("sender_custom", False))
        template_customization = _bool_field(comm_settings.get("template_customization_present") or comm_settings.get("has_custom_templates", False))
        return {
            "record_type": CLERK_EMAIL_SMS_SETTINGS,
            "record_id": "clerk_email_sms_settings_main",
            "provider_resource_id": "instance/email_sms",
            "provider": "clerk",
            "email_enabled": email_enabled,
            "sms_enabled": phone_enabled,
            "custom_sender_present": custom_sender,
            "template_customization_present": template_customization,
        }

    def _normalize_organization_settings(self, raw: dict) -> dict:
        """Derive organization settings record from instance org_settings.

        SECURITY: org names, member emails/IDs, invitation lists are NEVER stored.
        """
        org = raw.get("organization_settings", {}) or {}
        orgs_enabled = _bool_field(org.get("enabled") if isinstance(org, dict) else False)
        max_memberships = _int_field(org.get("max_allowed_memberships", 0) if isinstance(org, dict) else 0)
        if max_memberships == 0:
            membership_cat = "unlimited"
        elif max_memberships <= 10:
            membership_cat = "small"
        elif max_memberships <= 100:
            membership_cat = "medium"
        else:
            membership_cat = "large"
        admin_delete = _bool_field(org.get("admin_delete_enabled", True) if isinstance(org, dict) else True)
        domains_enabled = _bool_field(org.get("domains", {}).get("enabled") if isinstance(org.get("domains"), dict) else org.get("domains_enabled"))
        domains_enrollment_mode = _trunc(
            (org.get("domains") or {}).get("enrollment_mode") if isinstance(org.get("domains"), dict)
            else org.get("domains_enrollment_mode") or "manual", 50
        )
        return {
            "record_type": CLERK_ORGANIZATION_SETTINGS,
            "record_id": "clerk_organization_settings_main",
            "provider_resource_id": "instance/organization",
            "provider": "clerk",
            "organizations_enabled": orgs_enabled,
            "max_allowed_memberships_category": membership_cat,
            "admin_delete_enabled": admin_delete,
            "domains_enabled": domains_enabled,
            "domains_enrollment_mode_category": domains_enrollment_mode,
            "verified_domains_required": _bool_field(
                (org.get("domains") or {}).get("verified_required")
                if isinstance(org.get("domains"), dict)
                else org.get("verified_domains_required", False)
            ),
            "invitation_enabled": _bool_field(
                org.get("invitation_enabled", True)
                if isinstance(org, dict) else True
            ),
            "admin_role_present": _bool_field(
                org.get("admin_role_present", True)
                if isinstance(org, dict) else True
            ),
            "role_count": _int_field(org.get("role_count") or org.get("roles_count") if isinstance(org, dict) else 0),
            "permission_count": _int_field(org.get("permission_count") or org.get("permissions_count") if isinstance(org, dict) else 0),
        }

    def _normalize_session_policy(self, raw: dict) -> dict:
        """Derive session policy record from instance session_settings.

        SECURITY: active tokens, session IDs, session content are NEVER stored.
        """
        sess = raw.get("session_settings", {}) or {}
        token_ttl = _int_field(sess.get("token_lifetime_minutes") or sess.get("session_lifetime_minutes"), 60)
        inactivity_mins = _int_field(sess.get("inactivity_timeout_minutes") or sess.get("idle_session_lifetime_minutes"), 0)
        if inactivity_mins == 0:
            inactivity_cat = "none"
        elif inactivity_mins < 60:
            inactivity_cat = "short"
        elif inactivity_mins < 1440:
            inactivity_cat = "standard"
        else:
            inactivity_cat = "extended"
        single_session = _bool_field(sess.get("single_session_mode") or sess.get("single_session", False))
        url_syncing = _bool_field(sess.get("url_based_session_syncing", False))
        token_rotation = None
        if "token_rotation_enabled" in sess:
            token_rotation = _bool_field(sess["token_rotation_enabled"])
        return {
            "record_type": CLERK_SESSION_POLICY,
            "record_id": "clerk_session_policy_main",
            "provider_resource_id": "instance/session",
            "provider": "clerk",
            "session_lifetime_category": _session_category(token_ttl),
            "inactivity_timeout_category": inactivity_cat,
            "single_session_mode": single_session,
            "url_based_session_syncing": url_syncing,
            "token_rotation_enabled": token_rotation,
            "device_tracking_enabled": (
                _bool_field(sess.get("device_tracking_enabled"))
                if "device_tracking_enabled" in sess else None
            ),
            "reverification_required": (
                _bool_field(sess.get("reverification_required"))
                if "reverification_required" in sess else None
            ),
        }

    def _normalize_application(self, raw: dict) -> dict:
        """Normalise a Clerk application object into a safe flat record.

        SECURITY: client_id, client_secret, raw URLs/origins are NEVER stored.
        """
        app_id = _trunc(raw.get("id") or "unknown", 60)
        return {
            "record_type": CLERK_APPLICATION,
            "record_id": app_id,
            "provider_resource_id": f"applications/{app_id}",
            "provider": "clerk",
            "name": _trunc(raw.get("name") or "Clerk Application"),
            "application_type": _trunc(raw.get("type") or raw.get("application_type") or "unknown", 50),
            "enabled": _bool_field(raw.get("enabled", True)),
            "oauth_provider_count": _int_field(raw.get("oauth_provider_count") or _len_list(raw.get("oauth_strategies"))),
            "redirect_url_count": _int_field(raw.get("redirect_url_count") or _len_list(raw.get("redirect_urls"))),
            "allowed_origin_count": _int_field(raw.get("allowed_origin_count") or _len_list(raw.get("allowed_origins"))),
            "jwt_template_count": _int_field(raw.get("jwt_template_count") or _len_list(raw.get("jwt_templates"))),
            "organization_enabled": _bool_field(raw.get("organization_enabled") or raw.get("organizations_enabled")),
            "mfa_required": _bool_field(raw.get("mfa_required")),
            "sign_up_enabled": _bool_field(raw.get("sign_up_enabled"), default=True),
            "sign_in_enabled": _bool_field(raw.get("sign_in_enabled"), default=True),
            "password_enabled": _bool_field(raw.get("password_enabled") or (raw.get("user_settings") or {}).get("password", {}).get("enabled") if isinstance((raw.get("user_settings") or {}), dict) else False),
            "saml_enabled": _bool_field(raw.get("saml_enabled") or (raw.get("user_settings") or {}).get("saml_enabled")),
        }

    def _normalize_domain(self, raw: dict) -> dict:
        """Normalise a Clerk domain object into a safe flat record.

        SECURITY: the raw domain name string is customer-identifying and is
        NEVER stored. domain_present is always True.
        """
        domain_id = _trunc(raw.get("id") or "unknown", 60)
        is_primary = _bool_field(raw.get("is_primary") or raw.get("primary"))
        domain_type_val = "primary" if is_primary else "satellite"
        dns_status = _trunc(raw.get("dns_records_status") or raw.get("verification_status") or raw.get("status") or "unknown", 50)
        dns_cat = dns_status if dns_status in ("verified", "pending", "failed") else "unknown"
        return {
            "record_type": CLERK_DOMAIN,
            "record_id": domain_id,
            "provider_resource_id": f"domains/{domain_id}",
            "provider": "clerk",
            "domain_present": True,
            "domain_type": domain_type_val,
            "verified": _bool_field(raw.get("verified") or raw.get("is_verified")),
            "primary": is_primary,
            "ssl_enabled": _bool_field(raw.get("ssl_enabled") or raw.get("has_ssl", True)),
            "dns_status_category": dns_cat,
            "proxy_enabled": _bool_field(raw.get("proxy_url") is not None or raw.get("proxy_enabled")),
        }

    def _normalize_redirect_url(self, raw: dict) -> dict:
        """Normalise a Clerk redirect URL entry into a safe flat record.

        SECURITY: the raw URL string is NEVER stored — only posture booleans
        derived from it are kept. The URL is discarded immediately after.
        """
        url_id = _trunc(raw.get("id") or "unknown", 60)
        raw_url = raw.get("url") or ""
        scheme_cat = _url_scheme_category(raw_url)
        has_wildcard = _has_wildcard_url(raw_url)
        has_localhost = _is_localhost_url(raw_url)
        has_custom_scheme = _is_custom_scheme_url(raw_url)
        return {
            "record_type": CLERK_REDIRECT_URL_CONFIG,
            "record_id": url_id,
            "provider_resource_id": f"redirect_urls/{url_id}",
            "provider": "clerk",
            "url_present": True,
            "url_scheme_category": scheme_cat,
            "wildcard_present": has_wildcard,
            "localhost_present": has_localhost,
            "custom_scheme_present": has_custom_scheme,
        }

    def _normalize_jwt_template(self, raw: dict) -> dict:
        """Normalise a Clerk JWT template into a safe flat record.

        SECURITY: template body, custom claims, audience, issuer, and signing
        key are NEVER stored. claims_count is derived from the claims dict.
        """
        tmpl_id = _trunc(raw.get("id") or "unknown", 60)
        claims = raw.get("claims") or {}
        claims_count = len(claims) if isinstance(claims, dict) else 0
        custom_claims = claims_count > 0
        audience_present = bool(raw.get("audience") or raw.get("aud"))
        lifetime_secs = _int_field(raw.get("lifetime") or raw.get("token_lifetime"), 60)
        algorithm = _trunc(raw.get("signing_algorithm") or raw.get("algorithm") or "RS256", 20)
        return {
            "record_type": CLERK_JWT_TEMPLATE,
            "record_id": tmpl_id,
            "provider_resource_id": f"jwt_templates/{tmpl_id}",
            "provider": "clerk",
            "name": _trunc(raw.get("name") or "JWT Template"),
            "enabled": _bool_field(raw.get("enabled", True)),
            "claims_count": claims_count,
            "custom_claims_present": custom_claims,
            "audience_present": audience_present,
            "lifetime_category": _jwt_lifetime_category(lifetime_secs),
            "algorithm": algorithm,
            "issuer_present": bool(raw.get("issuer") or raw.get("iss")),
        }

    def _normalize_webhook(self, raw: dict) -> dict:
        """Normalise a Clerk webhook endpoint into a safe flat record.

        SECURITY: webhook URL, signing secret, event names, and all raw
        webhook payload are NEVER stored. url_scheme_category is derived
        from the URL before it is discarded.
        """
        wh_id = _trunc(raw.get("id") or raw.get("svix_id") or "unknown", 60)
        raw_url = raw.get("url") or ""
        scheme_cat = _url_scheme_category(raw_url)
        enabled = _bool_field(raw.get("enabled") or raw.get("active", True))
        events = raw.get("filter_types") or raw.get("event_types") or []
        event_count = len(events) if isinstance(events, list) else 0
        secret_present = bool(raw.get("secret") or raw.get("signing_secret") or raw.get("secret_present"))
        description = raw.get("description") or raw.get("metadata") or ""
        return {
            "record_type": CLERK_WEBHOOK_ENDPOINT,
            "record_id": wh_id,
            "provider_resource_id": f"webhooks/{wh_id}",
            "provider": "clerk",
            "enabled": enabled,
            "url_present": bool(raw_url),
            "url_scheme_category": scheme_cat,
            "event_count": event_count,
            "secret_present": secret_present,
            "description_present": bool(description),
        }

    # ── Per-surface fetch helpers ─────────────────────────────────────────────

    def _fetch_instance(self, client: httpx.Client) -> list[dict]:
        """Fetch Clerk instance settings (single record).

        Produces:
        - One clerk_instance_settings record
        - One clerk_auth_strategy record (derived from user_settings)
        - One clerk_email_sms_settings record
        - One clerk_organization_settings record
        - One clerk_session_policy record
        """
        try:
            raw = self._get_json(client, "/instance")
        except (ConnectorError, AuthenticationError, RateLimitError, NetworkError):
            raise
        if not isinstance(raw, dict):
            return []
        records: list[dict] = [
            self._normalize_instance(raw),
            self._normalize_auth_strategy(raw),
            self._normalize_email_sms_settings(raw),
            self._normalize_organization_settings(raw),
            self._normalize_session_policy(raw),
        ]
        return records

    def _fetch_domains(self, client: httpx.Client) -> list[dict]:
        """Fetch Clerk domain list. Fail-soft on 403/404 (optional surface)."""
        try:
            raw = self._get_json(client, "/domains")
        except ConnectorError as exc:
            if getattr(exc, "status_code", None) in (403, 404):
                logger.debug("clerk: domains not accessible — skipping")
                return []
            raise
        items = raw if isinstance(raw, list) else raw.get("data", []) or []
        records = []
        for item in items[:_MAX_DOMAINS]:
            if not isinstance(item, dict):
                continue
            try:
                records.append(self._normalize_domain(item))
            except Exception:
                logger.debug("clerk: failed to normalize domain record — skipping")
        return records

    def _fetch_redirect_urls(self, client: httpx.Client) -> list[dict]:
        """Fetch Clerk redirect URL entries. Fail-soft on 403/404."""
        try:
            raw = self._get_json(client, "/redirect_urls")
        except ConnectorError as exc:
            if getattr(exc, "status_code", None) in (403, 404):
                logger.debug("clerk: redirect_urls not accessible — skipping")
                return []
            raise
        items = raw if isinstance(raw, list) else raw.get("data", []) or []
        records = []
        for item in items[:_MAX_REDIRECT_URLS]:
            if not isinstance(item, dict):
                continue
            try:
                records.append(self._normalize_redirect_url(item))
            except Exception:
                logger.debug("clerk: failed to normalize redirect_url record — skipping")
        return records

    def _fetch_jwt_templates(self, client: httpx.Client) -> list[dict]:
        """Fetch Clerk JWT templates. Fail-soft on 403/404."""
        try:
            raw = self._get_json(client, "/jwt_templates")
        except ConnectorError as exc:
            if getattr(exc, "status_code", None) in (403, 404):
                logger.debug("clerk: jwt_templates not accessible — skipping")
                return []
            raise
        items = raw if isinstance(raw, list) else raw.get("data", []) or []
        records = []
        for item in items[:_MAX_JWT_TEMPLATES]:
            if not isinstance(item, dict):
                continue
            try:
                records.append(self._normalize_jwt_template(item))
            except Exception:
                logger.debug("clerk: failed to normalize jwt_template record — skipping")
        return records

    def _fetch_webhooks(self, client: httpx.Client) -> list[dict]:
        """Fetch Clerk Svix webhook subscriptions. Fail-soft on 403/404."""
        # Clerk uses Svix for webhooks; endpoint may be /webhooks/svix
        # or /webhook_endpoints depending on the API version.
        for path in ("/webhooks/svix", "/webhook_endpoints"):
            try:
                raw = self._get_json(client, path)
                items = raw if isinstance(raw, list) else raw.get("data", []) or []
                records = []
                for item in items[:_MAX_WEBHOOKS]:
                    if not isinstance(item, dict):
                        continue
                    try:
                        records.append(self._normalize_webhook(item))
                    except Exception:
                        logger.debug("clerk: failed to normalize webhook record — skipping")
                return records
            except ConnectorError as exc:
                if getattr(exc, "status_code", None) in (403, 404):
                    continue
                raise
        logger.debug("clerk: webhook endpoints not accessible — skipping")
        return []

    # ── Public API ────────────────────────────────────────────────────────────

    def fetch(self, credentials: dict) -> list[dict]:
        """Fetch all safe Clerk configuration drift surfaces (M83A).

        Returns a flat list of normalised record dicts. Each record contains
        only safe boolean/count/category/opaque-ID fields — never raw URLs,
        secrets, tokens, user data, or customer PII.

        SECURITY: the secret_key credential is placed only in the
        Authorization header; it is never stored on the instance or logged.
        The httpx.Client context is exited (and the header discarded) before
        this method returns.

        Never fetches or stores:
        - User data (/v1/users, session tokens, user emails, phone numbers)
        - Organization member lists or invitations
        - Audit log entries
        - Raw Clerk API response dicts beyond safe field extraction
        """
        secret_key = _sanitize_secret_key(credentials.get("secret_key", ""))
        records: list[dict] = []
        with self._make_client(secret_key) as client:
            # Instance settings produces 5 records (instance + auth_strategy +
            # email_sms + org_settings + session_policy). Must not fail-soft —
            # if we can't read the instance we have no useful data.
            records.extend(self._fetch_instance(client))

            # Optional surfaces — fail-soft on 403/404 for permission-limited
            # environments.
            records.extend(self._fetch_domains(client))
            records.extend(self._fetch_redirect_urls(client))
            records.extend(self._fetch_jwt_templates(client))
            records.extend(self._fetch_webhooks(client))

        return records
