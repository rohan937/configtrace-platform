"""Clerk drift risk classification rules.

Entry point: ``classify_clerk_change(change)``

Classifies drift changes for Clerk authentication configuration records.
Built during the Clerk detection QA pass — this module previously did not
exist, so every Clerk change silently fell through to the Cloudflare DNS
classifier fallback in ``risk_service.py``.

Risk levels
-----------
high   — MFA/second-factor capability disabled at instance or auth-strategy
         level; a domain's SSL is disabled; a redirect URL or webhook uses a
         plaintext HTTP (or otherwise non-HTTPS) scheme; a webhook loses its
         signing secret indicator.

medium — MFA no longer required (instance app / application / auth
         strategy); a domain becomes unverified; a redirect URL gains a
         wildcard or custom scheme; a JWT template's lifetime is extended or
         loses its audience; SAML/enterprise SSO enabled; an organization's
         verified-domains or admin-role requirement is dropped; permission
         count crosses the review threshold; session lifetime is extended;
         token rotation or reverification is disabled; an extended session
         lifetime combines with single-session mode being disabled.

low    — sign-up broadened; count-only changes crossing "many" thresholds;
         localhost redirect URLs present; safe restoration/improvement
         transitions (e.g. MFA re-enabled, HTTPS restored, a webhook secret
         restored); metadata-only drift; unknown/missing category fields.

Claim discipline
-----------------
All reason strings use safe review-framing:
  "Clerk authentication posture changed"
  "Clerk MFA posture was weakened"
  "Clerk verification requirements changed"
  "Clerk session policy changed"
  "Clerk webhook posture may require review"
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

# Thresholds mirrored from security_rules/clerk.py so Change severities stay
# aligned with the corresponding Security Findings.
_MANY_REDIRECT_URLS_THRESHOLD = 10
_MANY_ALLOWED_ORIGINS_THRESHOLD = 10
_MANY_CLAIMS_THRESHOLD = 15
_BROAD_WEBHOOK_EVENTS_THRESHOLD = 10
_HIGH_ROLE_COUNT_THRESHOLD = 20
_HIGH_PERMISSION_COUNT_THRESHOLD = 50

_LONG_LIFETIME_CATEGORIES = frozenset({"extended", "long"})
_EXTENDED_SESSION_LIFETIME_CATEGORIES = frozenset({"extended", "very_long"})


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
    moment of crossing it — an increase from 15 to 20 with a threshold of
    10 must still be flagged. Returns None (caller should treat as unknown)
    when the new value cannot be parsed as an int.
    """
    n_new = _int_or_none(new_v)
    if n_new is None:
        return None
    n_old = _int_or_none(prev_v)
    return n_new > threshold and n_new > (n_old or 0)


# ── clerk_instance_settings ──────────────────────────────────────────────────


def _classify_instance_settings_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    prev_v = _get(change, "prev_value")
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return ("low", "Clerk instance configuration record was added or removed during sync.")

    if fp == "mfa_enabled":
        if _is_falsy_explicit(new_v):
            return (
                "high",
                "Clerk MFA posture was weakened — multi-factor authentication is "
                "no longer enabled at the instance level. This may require review.",
            )
        if _is_truthy(new_v):
            return ("low", "Clerk instance MFA was enabled.")
        return ("low", "Clerk instance MFA enabled state is now unknown or missing.")

    if fp == "sign_up_enabled":
        if _is_truthy(new_v):
            return (
                "low",
                "Clerk authentication posture changed — instance sign-up was "
                "enabled. This may require review.",
            )
        if _is_falsy_explicit(new_v):
            return ("low", "Clerk instance sign-up was disabled.")
        return ("low", "Clerk instance sign-up enabled state is now unknown or missing.")

    if fp == "sign_in_mode":
        if new_v == "public" and prev_v == "restricted":
            return (
                "medium",
                "Clerk authentication posture changed — instance sign-in mode was "
                "broadened from restricted to public. This may require review.",
            )
        if new_v == "restricted":
            return ("low", "Clerk instance sign-in mode was restricted.")
        return ("low", "Clerk instance sign-in mode changed.")

    if fp == "session_lifetime_category":
        if new_v in _EXTENDED_SESSION_LIFETIME_CATEGORIES:
            return (
                "medium",
                "Clerk session policy changed — instance session lifetime was "
                "extended. This may require review.",
            )
        if new_v is not None and prev_v in _EXTENDED_SESSION_LIFETIME_CATEGORIES:
            return ("low", "Clerk instance session lifetime was shortened.")
        return ("low", "Clerk instance session lifetime category changed.")

    if fp in (
        "email_enabled", "phone_enabled", "username_enabled",
        "password_enabled", "allowlist_enabled", "blocklist_enabled",
    ):
        return ("low", f"Clerk instance {fp.replace('_', ' ')} changed.")

    if fp in (
        "social_provider_count", "mfa_factor_count", "allowed_redirect_count",
        "domain_count", "webhook_count",
    ):
        return ("low", f"Clerk instance {fp.replace('_', ' ')} changed.")

    if fp == "environment_type":
        return ("low", "Clerk instance environment type changed.")

    return ("low", f"Clerk instance configuration field '{fp}' changed.")


# ── clerk_application ────────────────────────────────────────────────────────


def _classify_application_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    prev_v = _get(change, "prev_value")
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return ("low", "Clerk application configuration record was added or removed during sync.")

    if fp == "mfa_required":
        if _is_falsy_explicit(new_v):
            return (
                "medium",
                "Clerk MFA posture was weakened — this application no longer "
                "requires multi-factor authentication. This may require review.",
            )
        if _is_truthy(new_v):
            return ("low", "Clerk application MFA requirement was enabled.")
        return ("low", "Clerk application MFA requirement is now unknown or missing.")

    if fp == "sign_up_enabled":
        if _is_truthy(new_v):
            return (
                "low",
                "Clerk authentication posture changed — application sign-up was "
                "enabled. This may require review.",
            )
        if _is_falsy_explicit(new_v):
            return ("low", "Clerk application sign-up was disabled.")
        return ("low", "Clerk application sign-up enabled state is now unknown or missing.")

    if fp == "saml_enabled":
        if _is_truthy(new_v):
            return (
                "medium",
                "Clerk authentication posture changed — SAML/enterprise SSO was "
                "enabled for this application. This may require review.",
            )
        if _is_falsy_explicit(new_v):
            return ("low", "Clerk application SAML/enterprise SSO was disabled.")
        return ("low", "Clerk application SAML enabled state is now unknown or missing.")

    if fp == "redirect_url_count":
        crossed = _crossed_threshold_increase(prev_v, new_v, _MANY_REDIRECT_URLS_THRESHOLD)
        if crossed:
            return (
                "low",
                f"Clerk application redirect URL count increased to {new_v}, "
                "exceeding the review threshold. This may require review.",
            )
        if crossed is None:
            return ("low", "Clerk application redirect URL count is now unknown or missing.")
        return ("low", f"Clerk application redirect URL count changed to {new_v}.")

    if fp == "allowed_origin_count":
        crossed = _crossed_threshold_increase(prev_v, new_v, _MANY_ALLOWED_ORIGINS_THRESHOLD)
        if crossed:
            return (
                "low",
                f"Clerk application allowed origin count increased to {new_v}, "
                "exceeding the review threshold. This may require review.",
            )
        if crossed is None:
            return ("low", "Clerk application allowed origin count is now unknown or missing.")
        return ("low", f"Clerk application allowed origin count changed to {new_v}.")

    if fp == "oauth_provider_count":
        n_old = _int_or_none(prev_v)
        n_new = _int_or_none(new_v)
        if n_new is None:
            return ("low", "Clerk application OAuth provider count is now unknown or missing.")
        if n_new > (n_old or 0):
            return (
                "low",
                f"Clerk application OAuth/social provider count increased from "
                f"{n_old} to {n_new}. This may require review.",
            )
        return ("low", f"Clerk application OAuth/social provider count changed from {n_old} to {n_new}.")

    if fp in ("password_enabled", "sign_in_enabled", "enabled", "organization_enabled"):
        return ("low", f"Clerk application {fp.replace('_', ' ')} changed.")

    if fp in ("name", "application_type", "jwt_template_count"):
        return ("low", f"Clerk application {fp.replace('_', ' ')} changed.")

    return ("low", f"Clerk application configuration field '{fp}' changed.")


# ── clerk_domain ─────────────────────────────────────────────────────────────


def _classify_domain_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return ("low", "Clerk domain configuration record was added or removed during sync.")

    if fp == "verified":
        if _is_falsy_explicit(new_v):
            return (
                "medium",
                "Clerk authentication posture changed — a domain became "
                "unverified. This may require review.",
            )
        if _is_truthy(new_v):
            return ("low", "Clerk domain was verified.")
        return ("low", "Clerk domain verified state is now unknown or missing.")

    if fp == "ssl_enabled":
        if _is_falsy_explicit(new_v):
            return (
                "high",
                "Clerk domain SSL was disabled. This may require review.",
            )
        if _is_truthy(new_v):
            return ("low", "Clerk domain SSL was enabled.")
        return ("low", "Clerk domain SSL enabled state is now unknown or missing.")

    if fp in ("primary", "domain_type", "dns_status_category", "proxy_enabled", "domain_present"):
        return ("low", f"Clerk domain {fp.replace('_', ' ')} changed.")

    return ("low", f"Clerk domain configuration field '{fp}' changed.")


# ── clerk_redirect_url_config ────────────────────────────────────────────────


def _classify_redirect_url_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    prev_v = _get(change, "prev_value")
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return ("low", "Clerk redirect URL configuration record was added or removed during sync.")

    if fp == "url_scheme_category":
        if new_v == "http":
            return (
                "high",
                "Clerk redirect URL scheme changed to plaintext HTTP. "
                "This may require review.",
            )
        if new_v == "https" and prev_v != "https":
            return ("low", "Clerk redirect URL scheme was restored to HTTPS.")
        return ("low", "Clerk redirect URL scheme category changed.")

    if fp == "wildcard_present":
        if _is_truthy(new_v):
            return (
                "medium",
                "Clerk authentication posture changed — a redirect URL now "
                "contains a wildcard. This may require review.",
            )
        if _is_falsy_explicit(new_v):
            return ("low", "Clerk redirect URL wildcard was removed.")
        return ("low", "Clerk redirect URL wildcard presence is now unknown or missing.")

    if fp == "custom_scheme_present":
        if _is_truthy(new_v):
            return (
                "medium",
                "Clerk authentication posture changed — a redirect URL now uses "
                "a custom/deep-link scheme. This may require review.",
            )
        if _is_falsy_explicit(new_v):
            return ("low", "Clerk redirect URL custom scheme was removed.")
        return ("low", "Clerk redirect URL custom scheme presence is now unknown or missing.")

    if fp == "localhost_present":
        if _is_truthy(new_v):
            return ("low", "Clerk redirect URL now targets localhost. This may require review.")
        return ("low", "Clerk redirect URL localhost presence changed.")

    if fp == "url_present":
        return ("low", "Clerk redirect URL presence changed.")

    return ("low", f"Clerk redirect URL configuration field '{fp}' changed.")


# ── clerk_jwt_template ───────────────────────────────────────────────────────


def _classify_jwt_template_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    prev_v = _get(change, "prev_value")
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return ("low", "Clerk JWT template configuration record was added or removed during sync.")

    if fp == "lifetime_category":
        if new_v in _LONG_LIFETIME_CATEGORIES:
            return (
                "medium",
                "Clerk JWT template lifetime was extended. This may require review.",
            )
        if new_v is not None and prev_v in _LONG_LIFETIME_CATEGORIES:
            return ("low", "Clerk JWT template lifetime was shortened.")
        return ("low", "Clerk JWT template lifetime category changed.")

    if fp == "audience_present":
        if _is_falsy_explicit(new_v):
            return (
                "medium",
                "Clerk JWT template no longer has an audience configured. "
                "This may require review.",
            )
        if _is_truthy(new_v):
            return ("low", "Clerk JWT template audience was configured.")
        return ("low", "Clerk JWT template audience presence is now unknown or missing.")

    if fp == "issuer_present":
        if _is_falsy_explicit(new_v):
            return ("low", "Clerk JWT template no longer has an issuer configured.")
        if _is_truthy(new_v):
            return ("low", "Clerk JWT template issuer was configured.")
        return ("low", "Clerk JWT template issuer presence is now unknown or missing.")

    if fp == "custom_claims_present":
        if _is_truthy(new_v):
            return ("low", "Clerk JWT template now includes custom claims. This may require review.")
        return ("low", "Clerk JWT template custom claims presence changed.")

    if fp == "claims_count":
        crossed = _crossed_threshold_increase(prev_v, new_v, _MANY_CLAIMS_THRESHOLD)
        if crossed:
            return (
                "low",
                f"Clerk JWT template claims count increased to {new_v}, exceeding "
                "the review threshold. This may require review.",
            )
        if crossed is None:
            return ("low", "Clerk JWT template claims count is now unknown or missing.")
        return ("low", f"Clerk JWT template claims count changed to {new_v}.")

    if fp in ("enabled", "algorithm", "name"):
        return ("low", f"Clerk JWT template {fp} changed.")

    return ("low", f"Clerk JWT template configuration field '{fp}' changed.")


# ── clerk_webhook_endpoint ───────────────────────────────────────────────────


def _classify_webhook_endpoint_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    prev_v = _get(change, "prev_value")
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return ("low", "Clerk webhook endpoint configuration record was added or removed during sync.")

    if fp == "secret_present":
        if _is_falsy_explicit(new_v):
            return (
                "high",
                "Clerk webhook posture may require review — the webhook signing "
                "secret indicator was removed.",
            )
        if _is_truthy(new_v):
            return ("low", "Clerk webhook signing secret was configured.")
        return ("low", "Clerk webhook signing secret presence is now unknown or missing.")

    if fp == "url_scheme_category":
        if new_v is not None and new_v != "https":
            return (
                "high",
                "Clerk webhook posture may require review — the webhook URL "
                "scheme is not HTTPS.",
            )
        if new_v == "https" and prev_v != "https":
            return ("low", "Clerk webhook URL scheme was restored to HTTPS.")
        return ("low", "Clerk webhook URL scheme category changed.")

    if fp == "enabled":
        if _is_falsy_explicit(new_v):
            return ("low", "Clerk webhook endpoint was disabled.")
        if _is_truthy(new_v):
            return ("low", "Clerk webhook endpoint was enabled.")
        return ("low", "Clerk webhook endpoint enabled state is now unknown or missing.")

    if fp == "event_count":
        crossed = _crossed_threshold_increase(prev_v, new_v, _BROAD_WEBHOOK_EVENTS_THRESHOLD)
        if crossed:
            return (
                "low",
                f"Clerk webhook event count increased to {new_v}, exceeding the "
                "review threshold. This may require review.",
            )
        if crossed is None:
            return ("low", "Clerk webhook event count is now unknown or missing.")
        return ("low", f"Clerk webhook event count changed to {new_v}.")

    if fp in ("url_present", "description_present"):
        return ("low", f"Clerk webhook endpoint {fp.replace('_', ' ')} changed.")

    return ("low", f"Clerk webhook endpoint configuration field '{fp}' changed.")


# ── clerk_email_sms_settings ─────────────────────────────────────────────────


def _classify_email_sms_settings_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return ("low", "Clerk email/SMS settings configuration record was added or removed during sync.")

    if fp == "custom_sender_present":
        if _is_truthy(new_v):
            return ("low", "Clerk email/SMS custom sender was configured. This may require review.")
        return ("low", "Clerk email/SMS custom sender presence changed.")

    if fp in ("email_enabled", "sms_enabled", "template_customization_present"):
        return ("low", f"Clerk email/SMS {fp.replace('_', ' ')} changed.")

    return ("low", f"Clerk email/SMS settings field '{fp}' changed.")


# ── clerk_auth_strategy ──────────────────────────────────────────────────────


def _classify_auth_strategy_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return ("low", "Clerk auth strategy configuration record was added or removed during sync.")

    if fp == "mfa_enabled":
        if _is_falsy_explicit(new_v):
            return (
                "high",
                "Clerk MFA posture was weakened — multi-factor authentication "
                "capability was disabled. This may require review.",
            )
        if _is_truthy(new_v):
            return ("low", "Clerk auth strategy MFA capability was enabled.")
        return ("low", "Clerk auth strategy MFA enabled state is now unknown or missing.")

    if fp == "mfa_required":
        if _is_falsy_explicit(new_v):
            return (
                "medium",
                "Clerk MFA posture was weakened — multi-factor authentication "
                "is no longer required. This may require review.",
            )
        if _is_truthy(new_v):
            return ("low", "Clerk auth strategy MFA requirement was enabled.")
        return ("low", "Clerk auth strategy MFA requirement is now unknown or missing.")

    if fp == "saml_enabled":
        if _is_truthy(new_v):
            return (
                "medium",
                "Clerk authentication posture changed — SAML/enterprise SSO was "
                "enabled. This may require review.",
            )
        return ("low", "Clerk auth strategy SAML enabled state changed.")

    if fp in (
        "password_enabled", "oauth_enabled", "social_provider_count",
        "passkey_enabled", "magic_link_enabled", "email_otp_enabled",
        "phone_otp_enabled",
    ):
        return ("low", f"Clerk auth strategy {fp.replace('_', ' ')} changed.")

    return ("low", f"Clerk auth strategy configuration field '{fp}' changed.")


# ── clerk_organization_settings ──────────────────────────────────────────────


def _classify_organization_settings_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    prev_v = _get(change, "prev_value")
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return ("low", "Clerk organization settings configuration record was added or removed during sync.")

    if fp == "verified_domains_required":
        if _is_falsy_explicit(new_v):
            return (
                "medium",
                "Clerk authentication posture changed — organizations no longer "
                "require verified domains. This may require review.",
            )
        if _is_truthy(new_v):
            return ("low", "Clerk organization verified-domains requirement was enabled.")
        return ("low", "Clerk organization verified-domains requirement is now unknown or missing.")

    if fp == "admin_role_present":
        if _is_falsy_explicit(new_v):
            return (
                "medium",
                "Clerk authentication posture changed — the organization admin "
                "role is no longer present. This may require review.",
            )
        if _is_truthy(new_v):
            return ("low", "Clerk organization admin role was configured.")
        return ("low", "Clerk organization admin role presence is now unknown or missing.")

    if fp == "invitation_enabled":
        if _is_truthy(new_v):
            return ("low", "Clerk organization invitations were enabled. This may require review.")
        return ("low", "Clerk organization invitation enabled state changed.")

    if fp == "role_count":
        crossed = _crossed_threshold_increase(prev_v, new_v, _HIGH_ROLE_COUNT_THRESHOLD)
        if crossed:
            return (
                "low",
                f"Clerk organization role count increased to {new_v}, exceeding "
                "the review threshold. This may require review.",
            )
        if crossed is None:
            return ("low", "Clerk organization role count is now unknown or missing.")
        return ("low", f"Clerk organization role count changed to {new_v}.")

    if fp == "permission_count":
        crossed = _crossed_threshold_increase(prev_v, new_v, _HIGH_PERMISSION_COUNT_THRESHOLD)
        if crossed:
            return (
                "medium",
                f"Clerk organization permission count increased to {new_v}, "
                "exceeding the review threshold. This may require review.",
            )
        if crossed is None:
            return ("low", "Clerk organization permission count is now unknown or missing.")
        return ("low", f"Clerk organization permission count changed to {new_v}.")

    if fp in (
        "organizations_enabled", "max_allowed_memberships_category",
        "admin_delete_enabled", "domains_enabled",
        "domains_enrollment_mode_category",
    ):
        return ("low", f"Clerk organization {fp.replace('_', ' ')} changed.")

    return ("low", f"Clerk organization settings field '{fp}' changed.")


# ── clerk_session_policy ─────────────────────────────────────────────────────


def _classify_session_policy_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    prev_v = _get(change, "prev_value")
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return ("low", "Clerk session policy configuration record was added or removed during sync.")

    if fp == "session_lifetime_category":
        if new_v in _EXTENDED_SESSION_LIFETIME_CATEGORIES:
            return (
                "medium",
                "Clerk session policy changed — session lifetime was extended. "
                "This may require review.",
            )
        if new_v is not None and prev_v in _EXTENDED_SESSION_LIFETIME_CATEGORIES:
            return ("low", "Clerk session lifetime was shortened.")
        return ("low", "Clerk session lifetime category changed.")

    if fp == "inactivity_timeout_category":
        if new_v == "extended":
            return (
                "low",
                "Clerk session policy changed — inactivity timeout was extended. "
                "This may require review.",
            )
        return ("low", "Clerk session inactivity timeout category changed.")

    if fp == "single_session_mode":
        if _is_falsy_explicit(new_v):
            return ("low", "Clerk session policy changed — single-session mode was disabled.")
        if _is_truthy(new_v):
            return ("low", "Clerk session single-session mode was enabled.")
        return ("low", "Clerk session single-session mode is now unknown or missing.")

    if fp == "token_rotation_enabled":
        if _is_falsy_explicit(new_v):
            return (
                "medium",
                "Clerk session policy changed — token rotation was disabled. "
                "This may require review.",
            )
        if _is_truthy(new_v):
            return ("low", "Clerk session token rotation was enabled.")
        return ("low", "Clerk session token rotation state is now unknown or missing.")

    if fp == "device_tracking_enabled":
        if _is_falsy_explicit(new_v):
            return ("low", "Clerk session policy changed — device tracking was disabled.")
        if _is_truthy(new_v):
            return ("low", "Clerk session device tracking was enabled.")
        return ("low", "Clerk session device tracking state is now unknown or missing.")

    if fp == "reverification_required":
        if _is_falsy_explicit(new_v):
            return (
                "medium",
                "Clerk session policy changed — reverification is no longer "
                "required. This may require review.",
            )
        if _is_truthy(new_v):
            return ("low", "Clerk session reverification requirement was enabled.")
        return ("low", "Clerk session reverification requirement is now unknown or missing.")

    if fp == "url_based_session_syncing":
        return ("low", "Clerk session URL-based syncing setting changed.")

    return ("low", f"Clerk session policy field '{fp}' changed.")


# ── Main dispatcher ───────────────────────────────────────────────────────────


def classify_clerk_change(change: Change) -> tuple[str, str]:
    """Return ``(risk_level, risk_reason)`` for a Clerk configuration change.

    Dispatches on ``provider_metadata["record_type"]``:
      * ``clerk_instance_settings``     → instance-level auth posture rules
      * ``clerk_application``           → per-application auth posture rules
      * ``clerk_domain``                → domain verification/SSL rules
      * ``clerk_redirect_url_config``   → redirect URL scheme/shape rules
      * ``clerk_jwt_template``          → JWT template posture rules
      * ``clerk_webhook_endpoint``      → webhook transport/signing rules
      * ``clerk_email_sms_settings``    → email/SMS delivery posture rules
      * ``clerk_auth_strategy``         → authentication strategy rules
      * ``clerk_organization_settings`` → organization posture rules
      * ``clerk_session_policy``        → session lifetime/policy rules

    Configuration evidence does not confirm compromise, unauthorized access,
    credential exposure, token exposure, or data exposure. Clerk
    configuration evidence may require review.
    """
    pm = _get(change, "provider_metadata") or {}
    if isinstance(pm, dict):
        record_type = (pm.get("record_type") or "").lower()
    else:
        record_type = ""

    if record_type == "clerk_instance_settings":
        return _classify_instance_settings_change(change)
    if record_type == "clerk_application":
        return _classify_application_change(change)
    if record_type == "clerk_domain":
        return _classify_domain_change(change)
    if record_type == "clerk_redirect_url_config":
        return _classify_redirect_url_change(change)
    if record_type == "clerk_jwt_template":
        return _classify_jwt_template_change(change)
    if record_type == "clerk_webhook_endpoint":
        return _classify_webhook_endpoint_change(change)
    if record_type == "clerk_email_sms_settings":
        return _classify_email_sms_settings_change(change)
    if record_type == "clerk_auth_strategy":
        return _classify_auth_strategy_change(change)
    if record_type == "clerk_organization_settings":
        return _classify_organization_settings_change(change)
    if record_type == "clerk_session_policy":
        return _classify_session_policy_change(change)

    # Fallback for unknown clerk_ subtypes
    return (
        "low",
        f"Clerk configuration changed (record type: {record_type or 'unknown'}). "
        "This may require review.",
    )
