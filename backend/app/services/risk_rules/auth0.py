"""Auth0 drift risk classification rules.

Entry point: ``classify_auth0_change(change)``

Classifies drift changes for Auth0 identity infrastructure configuration
records. Built during the Auth0 detection QA pass — this module previously
did not exist, so every Auth0 change silently fell through to the
Cloudflare DNS classifier fallback in ``risk_service.py``, despite the
provider capability matrix already (incorrectly) advertising
``drift_risk_classification=True``.

Risk levels
-----------
high   — password/implicit OAuth grants enabled; a public/client-side app
         gains the client_credentials grant; a wildcard callback or
         allowed-origin is present; a weak (symmetric) JWT signing
         algorithm is configured; dynamic client registration is enabled
         tenant-wide; a database connection's password policy is weak or
         unconfigured.

medium — OIDC conformance disabled; callback/origin counts cross the
         "many" review threshold; a broad grant-type surface; a wildcard
         logout URL; callbacks/origins missing HTTPS; refresh token
         rotation disabled; refresh token or access token lifetime
         extended; token endpoint auth method is "none"; a public client
         gains the refresh_token grant; API offline access enabled; API
         RBAC disabled; tenant session lifetime extended; custom domain
         not in a ready state.

low    — device code grant; localhost callback/origin; idle session
         lifetime extended; connection with no enabled clients; rule
         disabled/large script; action not deployed / has secrets; custom
         domain weak TLS policy; count-only changes with unclear impact;
         metadata-only drift; unknown/missing category fields; safe
         restoration/improvement transitions.

Claim discipline
-----------------
All reason strings use safe review-framing:
  "Auth0 authentication posture changed"
  "Auth0 MFA posture was weakened"
  "Auth0 token policy changed"
  "Auth0 application OAuth posture changed"
  "Auth0 attack protection posture changed"
  "This may require review"
  "Configuration evidence does not confirm compromise, unauthorized access,
  credential exposure, token exposure, or data exposure."
Forbidden phrases: breach, compromise, attacker, leaked, unauthorized access,
account takeover, credential exposed, token exposed, secret exposed, user
data exposed, data exposed.
"""

from __future__ import annotations

from typing import Optional

from app.models.change import Change

# Thresholds mirrored from security_rules/auth0.py so Change severities stay
# aligned with the corresponding Security Findings.
_MANY_CALLBACKS_THRESHOLD = 10
_MANY_ORIGINS_THRESHOLD = 10
_MANY_GRANT_TYPES_THRESHOLD = 4

_WEAK_JWT_ALGS = frozenset({"HS256", "HS384", "HS512", "none"})
_WEAK_PASSWORD_POLICIES = frozenset({"none", "low", "fair"})
_STRONG_MFA_FACTORS = frozenset({"otp", "webauthn-roaming", "push-notification"})
_NOT_READY_STATUSES = frozenset({"pending_verification", "provisioning", "disabled"})
_WEAK_TLS_POLICIES = frozenset({"compatible"})


def _get(obj: object, field: str) -> object:
    """Safely retrieve a field from a Change object or dict."""
    if isinstance(obj, dict):
        return obj.get(field)
    return getattr(obj, field, None)


def _is_truthy(val: object) -> bool:
    if val is True or val == "true" or val == 1:
        return True
    return False


def _is_falsy_explicit(val: object) -> bool:
    if val is False or val == "false" or val == 0:
        return True
    return False


def _int_or_none(val: object) -> Optional[int]:
    """Coerce to int, but return None (not 0) for missing/unparseable values.

    A count that is genuinely unknown/missing must never be silently
    treated as an explicit ``0`` or as crossing a threshold — doing so
    would let an unknown transition falsely trigger a finding.
    """
    if isinstance(val, bool) or val is None:
        return None
    try:
        return int(val)
    except (TypeError, ValueError):
        return None


def _crossed_threshold_increase(
    prev_v: object, new_v: object, threshold: int
) -> Optional[bool]:
    """Return True if *new_v* is over *threshold* and higher than *prev_v*.

    Fires on ANY increase while over the threshold, not just the exact
    moment of crossing it. Returns None (caller should treat as unknown)
    when the new value cannot be parsed as an int.
    """
    n_new = _int_or_none(new_v)
    if n_new is None:
        return None
    n_old = _int_or_none(prev_v)
    return n_new > threshold and n_new > (n_old or 0)


# ── auth0_tenant_settings ─────────────────────────────────────────────────────


def _classify_tenant_settings_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    prev_v = _get(change, "prev_value")
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return ("low", "Auth0 tenant configuration record was added or removed during sync.")

    if fp == "session_lifetime_category":
        if new_v == "extended":
            return (
                "medium",
                "Auth0 token policy changed — tenant login session lifetime was "
                "extended. This may require review.",
            )
        if new_v is not None and prev_v == "extended":
            return ("low", "Auth0 tenant login session lifetime was shortened.")
        return ("low", "Auth0 tenant login session lifetime category changed.")

    if fp == "idle_session_lifetime_category":
        if new_v == "extended":
            return (
                "low",
                "Auth0 token policy changed — tenant idle session lifetime was "
                "extended. This may require review.",
            )
        if new_v is not None and prev_v == "extended":
            return ("low", "Auth0 tenant idle session lifetime was shortened.")
        return ("low", "Auth0 tenant idle session lifetime category changed.")

    if fp == "flag_enable_dynamic_client_registration":
        if _is_truthy(new_v):
            return (
                "high",
                "Auth0 authentication posture changed — dynamic client "
                "registration was enabled tenant-wide. This may require review.",
            )
        if _is_falsy_explicit(new_v):
            return ("low", "Auth0 tenant dynamic client registration was disabled.")
        return ("low", "Auth0 tenant dynamic client registration state is now unknown or missing.")

    if fp in (
        "friendly_name_present", "support_email_domain",
        "default_directory_present", "enabled_locales_count",
        "flag_change_pwd_on_first_login", "flag_enable_client_connections",
        "flag_enable_apis_section", "flag_enable_pipeline2",
        "flag_enable_custom_domain_in_emails", "flag_universal_login",
        "flag_enable_legacy_logs_search_v2",
        "flag_no_disclose_enterprise_connections",
        "flag_disable_management_api_sms_obfuscation",
        "flag_enable_adfs_waad_email_verification",
        "flag_revoke_refresh_token_grant",
    ):
        return ("low", f"Auth0 tenant {fp.replace('_', ' ')} changed.")

    return ("low", f"Auth0 tenant configuration field '{fp}' changed.")


# ── auth0_application ────────────────────────────────────────────────────────


def _classify_application_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    prev_v = _get(change, "prev_value")
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return ("low", "Auth0 application configuration record was added or removed during sync.")

    if fp == "oidc_conformant":
        if _is_falsy_explicit(new_v):
            return (
                "medium",
                "Auth0 application OAuth posture changed — OIDC conformance was "
                "disabled. This may require review.",
            )
        if _is_truthy(new_v):
            return ("low", "Auth0 application OIDC conformance was enabled.")
        return ("low", "Auth0 application OIDC conformance state is now unknown or missing.")

    if fp == "jwt_alg":
        if new_v in _WEAK_JWT_ALGS:
            return (
                "high",
                f"Auth0 application OAuth posture changed — JWT signing algorithm "
                f"changed to {new_v}, a symmetric algorithm. This may require review.",
            )
        if new_v is not None and prev_v in _WEAK_JWT_ALGS:
            return ("low", "Auth0 application JWT signing algorithm was strengthened to an asymmetric algorithm.")
        return ("low", "Auth0 application JWT signing algorithm changed.")

    if fp == "refresh_token_rotation_enabled":
        if _is_falsy_explicit(new_v):
            return (
                "medium",
                "Auth0 token policy changed — refresh token rotation was "
                "disabled. This may require review.",
            )
        if _is_truthy(new_v):
            return ("low", "Auth0 application refresh token rotation was enabled.")
        return ("low", "Auth0 application refresh token rotation state is now unknown or missing.")

    if fp == "refresh_token_lifetime_category":
        if new_v == "extended":
            return (
                "medium",
                "Auth0 token policy changed — refresh token lifetime was "
                "extended. This may require review.",
            )
        if new_v is not None and prev_v == "extended":
            return ("low", "Auth0 application refresh token lifetime was shortened.")
        return ("low", "Auth0 application refresh token lifetime category changed.")

    if fp == "callbacks_count":
        crossed = _crossed_threshold_increase(prev_v, new_v, _MANY_CALLBACKS_THRESHOLD)
        if crossed:
            return (
                "medium",
                f"Auth0 application OAuth posture changed — callback URL count "
                f"increased to {new_v}, exceeding the review threshold. This may require review.",
            )
        if crossed is None:
            return ("low", "Auth0 application callback URL count is now unknown or missing.")
        if _int_or_none(new_v) == 0:
            return ("low", "Auth0 application callback URL count changed to 0.")
        return ("low", f"Auth0 application callback URL count changed to {new_v}.")

    if fp in ("allowed_origins_count", "web_origins_count"):
        crossed = _crossed_threshold_increase(prev_v, new_v, _MANY_ORIGINS_THRESHOLD)
        if crossed:
            return (
                "medium",
                f"Auth0 application OAuth posture changed — {fp.replace('_', ' ')} "
                f"increased to {new_v}, exceeding the review threshold. This may require review.",
            )
        if crossed is None:
            return ("low", f"Auth0 application {fp.replace('_', ' ')} is now unknown or missing.")
        return ("low", f"Auth0 application {fp.replace('_', ' ')} changed to {new_v}.")

    if fp == "grant_types_count":
        crossed = _crossed_threshold_increase(prev_v, new_v, _MANY_GRANT_TYPES_THRESHOLD)
        if crossed:
            return (
                "medium",
                f"Auth0 application OAuth posture changed — grant type count "
                f"increased to {new_v}, exceeding the review threshold. This may require review.",
            )
        if crossed is None:
            return ("low", "Auth0 application grant type count is now unknown or missing.")
        return ("low", f"Auth0 application grant type count changed to {new_v}.")

    if fp == "grant_password_enabled":
        if _is_truthy(new_v):
            return (
                "high",
                "Auth0 application OAuth posture changed — the password grant "
                "was enabled. This may require review.",
            )
        if _is_falsy_explicit(new_v):
            return ("low", "Auth0 application password grant was disabled.")
        return ("low", "Auth0 application password grant state is now unknown or missing.")

    if fp == "grant_implicit_enabled":
        if _is_truthy(new_v):
            return (
                "high",
                "Auth0 application OAuth posture changed — the implicit grant "
                "was enabled. This may require review.",
            )
        if _is_falsy_explicit(new_v):
            return ("low", "Auth0 application implicit grant was disabled.")
        return ("low", "Auth0 application implicit grant state is now unknown or missing.")

    if fp == "grant_client_credentials_enabled":
        if _is_truthy(new_v):
            return (
                "medium",
                "Auth0 application OAuth posture changed — the client "
                "credentials grant was enabled. This may require review.",
            )
        if _is_falsy_explicit(new_v):
            return ("low", "Auth0 application client credentials grant was disabled.")
        return ("low", "Auth0 application client credentials grant state is now unknown or missing.")

    if fp == "grant_device_code_enabled":
        if _is_truthy(new_v):
            return ("low", "Auth0 application device code grant was enabled. This may require review.")
        return ("low", "Auth0 application device code grant state changed.")

    if fp == "wildcard_callback_present":
        if _is_truthy(new_v):
            return (
                "high",
                "Auth0 application OAuth posture changed — a wildcard callback "
                "URL is now present. This may require review.",
            )
        if _is_falsy_explicit(new_v):
            return ("low", "Auth0 application wildcard callback URL was removed.")
        return ("low", "Auth0 application wildcard callback presence is now unknown or missing.")

    if fp == "wildcard_allowed_origin_present":
        if _is_truthy(new_v):
            return (
                "high",
                "Auth0 application OAuth posture changed — a wildcard allowed "
                "origin is now present. This may require review.",
            )
        if _is_falsy_explicit(new_v):
            return ("low", "Auth0 application wildcard allowed origin was removed.")
        return ("low", "Auth0 application wildcard allowed origin presence is now unknown or missing.")

    if fp == "wildcard_logout_url_present":
        if _is_truthy(new_v):
            return (
                "medium",
                "Auth0 application OAuth posture changed — a wildcard logout "
                "URL is now present. This may require review.",
            )
        if _is_falsy_explicit(new_v):
            return ("low", "Auth0 application wildcard logout URL was removed.")
        return ("low", "Auth0 application wildcard logout URL presence is now unknown or missing.")

    if fp in ("localhost_callback_present", "localhost_origin_present"):
        if _is_truthy(new_v):
            return ("low", f"Auth0 application {fp.replace('_', ' ')} is now present. This may require review.")
        return ("low", f"Auth0 application {fp.replace('_', ' ')} changed.")

    if fp == "callbacks_missing_https":
        if _is_truthy(new_v):
            return (
                "medium",
                "Auth0 application OAuth posture changed — a callback URL is "
                "now missing HTTPS. This may require review.",
            )
        if _is_falsy_explicit(new_v):
            return ("low", "Auth0 application callback URLs no longer miss HTTPS.")
        return ("low", "Auth0 application callback HTTPS posture is now unknown or missing.")

    if fp == "allowed_origins_missing_https":
        if _is_truthy(new_v):
            return (
                "medium",
                "Auth0 application OAuth posture changed — an allowed origin is "
                "now missing HTTPS. This may require review.",
            )
        if _is_falsy_explicit(new_v):
            return ("low", "Auth0 application allowed origins no longer miss HTTPS.")
        return ("low", "Auth0 application origin HTTPS posture is now unknown or missing.")

    if fp == "token_endpoint_auth_method":
        if new_v == "none":
            return (
                "medium",
                "Auth0 application OAuth posture changed — token endpoint "
                "authentication method changed to 'none'. This may require review.",
            )
        if new_v is not None and prev_v == "none":
            return ("low", "Auth0 application token endpoint authentication method now requires a client secret or assertion.")
        return ("low", "Auth0 application token endpoint authentication method changed.")

    if fp in (
        "name", "app_type", "is_first_party", "grant_types_summary",
        "grant_authorization_code_enabled", "grant_refresh_token_enabled",
        "grant_mfa_enabled",
    ):
        return ("low", f"Auth0 application {fp.replace('_', ' ')} changed.")

    return ("low", f"Auth0 application configuration field '{fp}' changed.")


# ── auth0_connection ─────────────────────────────────────────────────────────


def _classify_connection_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    prev_v = _get(change, "prev_value")
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return ("low", "Auth0 connection configuration record was added or removed during sync.")

    if fp == "enabled_clients_count":
        n_new = _int_or_none(new_v)
        if n_new is None:
            return ("low", "Auth0 connection enabled clients count is now unknown or missing.")
        n_old = _int_or_none(prev_v)
        if n_new == 0:
            return ("low", "Auth0 connection now has no enabled client applications.")
        if n_old == 0 and n_new > 0:
            return ("low", "Auth0 connection now has enabled client applications.")
        return ("low", f"Auth0 connection enabled clients count changed to {n_new}.")

    if fp == "password_policy_category":
        # Matches security_rules/auth0.py's explicit unknown-posture rule:
        # a database connection's password policy being unset (None) is
        # itself treated as "not configured" and rated the same as a weak
        # policy — this is an intentional exception to the general
        # "unknown must never overstate certainty" rule, mirroring the
        # existing Security Finding's own explicit design.
        if new_v is None or (isinstance(new_v, str) and new_v.lower() in _WEAK_PASSWORD_POLICIES):
            return (
                "high",
                "Auth0 authentication posture changed — database connection "
                "password policy is weak or not configured. This may require review.",
            )
        return ("low", "Auth0 connection password policy was strengthened.")

    if fp == "mfa_enabled":
        # Change-only signal: no dedicated Security Finding exists yet for
        # connection-level mfa_enabled (see auth0_detection_matrix.md,
        # category S) — classified per this task's MFA severity convention.
        if _is_falsy_explicit(new_v):
            return (
                "high",
                "Auth0 MFA posture was weakened — this database connection no "
                "longer has MFA enabled. This may require review.",
            )
        if _is_truthy(new_v):
            return ("low", "Auth0 connection MFA was enabled.")
        return ("low", "Auth0 connection MFA enabled state is now unknown or missing.")

    if fp in ("name", "strategy", "is_domain_connection"):
        return ("low", f"Auth0 connection {fp.replace('_', ' ')} changed.")

    return ("low", f"Auth0 connection configuration field '{fp}' changed.")


# ── auth0_resource_server ────────────────────────────────────────────────────


def _classify_resource_server_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    prev_v = _get(change, "prev_value")
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return ("low", "Auth0 API configuration record was added or removed during sync.")

    if fp == "allow_offline_access":
        if _is_truthy(new_v):
            return (
                "medium",
                "Auth0 token policy changed — this API now allows offline "
                "access (refresh tokens). This may require review.",
            )
        if _is_falsy_explicit(new_v):
            return ("low", "Auth0 API offline access was disabled.")
        return ("low", "Auth0 API offline access state is now unknown or missing.")

    if fp == "token_lifetime_category":
        if new_v == "extended":
            return (
                "medium",
                "Auth0 token policy changed — this API's access token "
                "lifetime was extended. This may require review.",
            )
        if new_v is not None and prev_v == "extended":
            return ("low", "Auth0 API access token lifetime was shortened.")
        return ("low", "Auth0 API access token lifetime category changed.")

    if fp == "rbac_enabled":
        if _is_falsy_explicit(new_v):
            return (
                "medium",
                "Auth0 authentication posture changed — RBAC enforcement was "
                "disabled for this API. This may require review.",
            )
        if _is_truthy(new_v):
            return ("low", "Auth0 API RBAC enforcement was enabled.")
        return ("low", "Auth0 API RBAC enforcement state is now unknown or missing.")

    if fp == "signing_alg":
        # Change-only signal: security_rules/auth0.py only evaluates
        # jwt_alg weakness at the auth0_application record type, not on
        # auth0_resource_server — see auth0_detection_matrix.md, category S.
        if new_v in _WEAK_JWT_ALGS:
            return (
                "high",
                f"Auth0 token policy changed — API signing algorithm changed "
                f"to {new_v}, a symmetric algorithm. This may require review.",
            )
        if new_v is not None and prev_v in _WEAK_JWT_ALGS:
            return ("low", "Auth0 API signing algorithm was strengthened to an asymmetric algorithm.")
        return ("low", "Auth0 API signing algorithm changed.")

    if fp in (
        "name", "identifier_present", "scopes_count",
        "skip_consent_for_verifiable_first_party_clients",
    ):
        return ("low", f"Auth0 API {fp.replace('_', ' ')} changed.")

    return ("low", f"Auth0 API configuration field '{fp}' changed.")


# ── auth0_rule ────────────────────────────────────────────────────────────────


def _classify_rule_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return ("low", "Auth0 rule configuration record was added or removed during sync.")

    if fp == "enabled":
        if _is_falsy_explicit(new_v):
            return ("low", "Auth0 rule was disabled. This may require review.")
        if _is_truthy(new_v):
            return ("low", "Auth0 rule was enabled.")
        return ("low", "Auth0 rule enabled state is now unknown or missing.")

    if fp == "script_length_category":
        if new_v == "long":
            return ("low", "Auth0 rule script is now classified as long. This may require review.")
        return ("low", "Auth0 rule script length category changed.")

    if fp in ("name", "order", "script_present", "stage"):
        return ("low", f"Auth0 rule {fp.replace('_', ' ')} changed.")

    return ("low", f"Auth0 rule configuration field '{fp}' changed.")


# ── auth0_action ──────────────────────────────────────────────────────────────


def _classify_action_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return ("low", "Auth0 action configuration record was added or removed during sync.")

    if fp == "deployed_version_present":
        if _is_falsy_explicit(new_v):
            return ("low", "Auth0 action no longer has a deployed version.")
        if _is_truthy(new_v):
            return ("low", "Auth0 action was deployed.")
        return ("low", "Auth0 action deployed-version state is now unknown or missing.")

    if fp == "secrets_count":
        n_new = _int_or_none(new_v)
        if n_new is None:
            return ("low", "Auth0 action secrets count is now unknown or missing.")
        if n_new > 0:
            return ("low", f"Auth0 action now has {n_new} secret(s) configured. This may require review.")
        return ("low", "Auth0 action secrets count changed to 0.")

    if fp in (
        "name", "status", "runtime", "trigger_id", "code_present",
        "code_length_category", "dependencies_count",
    ):
        return ("low", f"Auth0 action {fp.replace('_', ' ')} changed.")

    return ("low", f"Auth0 action configuration field '{fp}' changed.")


# ── auth0_mfa_factor ──────────────────────────────────────────────────────────


def _classify_mfa_factor_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return ("low", "Auth0 MFA factor configuration record was added or removed during sync.")

    if fp == "enabled":
        pm = _get(change, "provider_metadata") or {}
        record_id = str(pm.get("record_id") or "") if isinstance(pm, dict) else ""
        factor_name = record_id[len("auth0_mfa_factor_"):] if record_id.startswith("auth0_mfa_factor_") else ""
        is_strong = factor_name in _STRONG_MFA_FACTORS

        if _is_falsy_explicit(new_v):
            if is_strong:
                return (
                    "medium",
                    "Auth0 MFA posture was weakened — a strong second-factor "
                    "option was disabled. This may require review.",
                )
            return ("low", "Auth0 MFA factor was disabled.")
        if _is_truthy(new_v):
            return ("low", "Auth0 MFA factor was enabled.")
        return ("low", "Auth0 MFA factor enabled state is now unknown or missing.")

    if fp in ("trial_expired", "provider_category"):
        return ("low", f"Auth0 MFA factor {fp.replace('_', ' ')} changed.")

    return ("low", f"Auth0 MFA factor configuration field '{fp}' changed.")


# ── auth0_custom_domain ───────────────────────────────────────────────────────


def _classify_custom_domain_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return ("low", "Auth0 custom domain configuration record was added or removed during sync.")

    if fp == "status":
        if new_v in _NOT_READY_STATUSES:
            return (
                "medium",
                f"Auth0 authentication posture changed — custom domain status "
                f"changed to '{new_v}'. This may require review.",
            )
        if new_v == "ready":
            return ("low", "Auth0 custom domain reached the ready state.")
        return ("low", "Auth0 custom domain status changed.")

    if fp == "tls_policy_category":
        if new_v in _WEAK_TLS_POLICIES:
            return ("low", "Auth0 custom domain TLS policy changed to 'compatible'. This may require review.")
        return ("low", "Auth0 custom domain TLS policy category changed.")

    if fp in ("domain_present", "type", "primary", "verification_method_category"):
        return ("low", f"Auth0 custom domain {fp.replace('_', ' ')} changed.")

    return ("low", f"Auth0 custom domain configuration field '{fp}' changed.")


# ── Main dispatcher ───────────────────────────────────────────────────────────


def classify_auth0_change(change: Change) -> tuple[str, str]:
    """Return ``(risk_level, risk_reason)`` for an Auth0 configuration change.

    Dispatches on ``provider_metadata["record_type"]``:
      * ``auth0_tenant_settings``  → tenant session/flag posture rules
      * ``auth0_application``     → OAuth/client posture rules
      * ``auth0_connection``      → connection/password-policy/MFA rules
      * ``auth0_resource_server`` → API signing/token/RBAC rules
      * ``auth0_rule``            → legacy rule pipeline posture rules
      * ``auth0_action``          → Actions pipeline posture rules
      * ``auth0_mfa_factor``      → Guardian/MFA factor posture rules
      * ``auth0_custom_domain``   → custom domain posture rules

    Configuration evidence does not confirm compromise, unauthorized access,
    credential exposure, token exposure, or data exposure. Auth0
    configuration evidence may require review.
    """
    pm = _get(change, "provider_metadata") or {}
    if isinstance(pm, dict):
        record_type = (pm.get("record_type") or "").lower()
    else:
        record_type = ""

    if record_type == "auth0_tenant_settings":
        return _classify_tenant_settings_change(change)
    if record_type == "auth0_application":
        return _classify_application_change(change)
    if record_type == "auth0_connection":
        return _classify_connection_change(change)
    if record_type == "auth0_resource_server":
        return _classify_resource_server_change(change)
    if record_type == "auth0_rule":
        return _classify_rule_change(change)
    if record_type == "auth0_action":
        return _classify_action_change(change)
    if record_type == "auth0_mfa_factor":
        return _classify_mfa_factor_change(change)
    if record_type == "auth0_custom_domain":
        return _classify_custom_domain_change(change)

    # Fallback for unknown auth0_ subtypes
    return (
        "low",
        f"Auth0 configuration changed (record type: {record_type or 'unknown'}). "
        "This may require review.",
    )
