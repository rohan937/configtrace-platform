"""Clerk configuration-risk security rules — M83B.

Every rule fires only on explicit, reliable normalized fields produced by the
Clerk connector (app/connectors/clerk.py + clerk_schema.py, M83A). Evidence is
metadata-only: booleans, counts, categories, opaque identifiers, and safe
string labels. No Clerk secret key values, publishable key values, session
tokens, JWTs, OAuth tokens, bearer tokens, webhook secrets, raw webhook URLs,
raw redirect URLs, raw callback URLs, raw domain names, raw JWT template bodies,
raw claims, raw audience values, raw issuer values, user emails, user IDs, phone
numbers, names, organization member identities, session history, login history,
password data, MFA secrets, backup codes, verification codes, IP addresses,
user agents, raw audit payloads, request/response payloads, customer data, or
PII are ever read, stored, or surfaced.

CLAIM DISCIPLINE
----------------
These are configuration posture findings that may require review. A finding is
evidence for review only. It never asserts that a credential was leaked, a
token was compromised, that unauthorized access occurred, or that any attacker
is present. Severity reflects review priority, not confirmed impact.

Record types consumed (M83A)
----------------------------
- ``clerk_instance_settings``   → sign_up_enabled, password_enabled, mfa_enabled,
                                  session_lifetime_category, sign_in_mode
- ``clerk_application``         → mfa_required, organization_enabled
- ``clerk_domain``              → verified, ssl_enabled, domain_type
- ``clerk_redirect_url_config`` → url_present, url_scheme_category, wildcard_present,
                                  localhost_present
- ``clerk_jwt_template``        → custom_claims_present, lifetime_category
- ``clerk_webhook_endpoint``    → enabled, url_present, url_scheme_category,
                                  secret_present
- ``clerk_email_sms_settings``  → custom_sender_present
- ``clerk_auth_strategy``       → password_enabled, mfa_enabled, mfa_required
- ``clerk_session_policy``      → session_lifetime_category,
                                  inactivity_timeout_category, single_session_mode,
                                  token_rotation_enabled

Rules deferred from M83B
-------------------------
- ``clerk_application_sign_up_enabled`` — M83A ClerkApplicationRecord has no
  sign_up_enabled field. The connector aggregates application-level sign-up
  posture via instance settings. Deferred until a safe application-level
  sign_up_enabled field is added to the schema.
- ``clerk_domain_wildcard_enabled`` — M83A ClerkDomainRecord has no
  wildcard_enabled field. Deferred until the field is added.
- ``clerk_org_verified_domains_not_required`` — M83A
  ClerkOrganizationSettingsRecord has no verified_domains_required field.
  Deferred until the field is added.
- ``clerk_org_invitations_enabled`` — M83A ClerkOrganizationSettingsRecord has
  no invitation_enabled field. Deferred until the field is added.
- ``clerk_org_admin_role_missing`` — M83A ClerkOrganizationSettingsRecord has
  no admin_role_present field. Deferred until the field is added.
- ``clerk_session_device_tracking_disabled`` — M83A ClerkSessionPolicyRecord
  has no device_tracking_enabled field. Deferred until the field is added.
- ``clerk_session_reverification_disabled`` — M83A ClerkSessionPolicyRecord has
  no reverification_required field. Deferred until the field is added.
"""

from __future__ import annotations

from typing import Any

from app.connectors.clerk_schema import (
    CLERK_APPLICATION,
    CLERK_AUTH_STRATEGY,
    CLERK_DOMAIN,
    CLERK_EMAIL_SMS_SETTINGS,
    CLERK_INSTANCE_SETTINGS,
    CLERK_JWT_TEMPLATE,
    CLERK_REDIRECT_URL_CONFIG,
    CLERK_SESSION_POLICY,
    CLERK_WEBHOOK_ENDPOINT,
)
from app.services.security_rules.base import (
    FindingCandidate,
    get_str,
    make_finding_key,
)

# ── Rule key constants ─────────────────────────────────────────────────────────

# Instance settings
_RULE_INSTANCE_MFA_DISABLED = "clerk_instance_mfa_disabled"
_RULE_INSTANCE_PASSWORD_WITHOUT_MFA = "clerk_instance_password_without_mfa"
_RULE_INSTANCE_SIGN_UP_ENABLED = "clerk_instance_sign_up_enabled"

# Application
_RULE_APP_MFA_NOT_REQUIRED = "clerk_application_mfa_not_required"

# Domain
_RULE_DOMAIN_UNVERIFIED = "clerk_domain_unverified"
_RULE_DOMAIN_SSL_DISABLED = "clerk_domain_ssl_disabled"

# Redirect URL
_RULE_REDIRECT_URL_NON_HTTPS = "clerk_redirect_url_non_https"
_RULE_REDIRECT_URL_WILDCARD = "clerk_redirect_url_wildcard_present"
_RULE_REDIRECT_URL_LOCALHOST = "clerk_redirect_url_localhost_present"

# JWT template
_RULE_JWT_CUSTOM_CLAIMS = "clerk_jwt_template_custom_claims_present"
_RULE_JWT_LONG_LIFETIME = "clerk_jwt_template_long_lifetime"

# Webhook
_RULE_WEBHOOK_DISABLED = "clerk_webhook_endpoint_disabled"
_RULE_WEBHOOK_WITHOUT_SIGNING = "clerk_webhook_without_signing"
_RULE_WEBHOOK_NON_HTTPS = "clerk_webhook_non_https"

# Email/SMS
_RULE_EMAIL_SMS_CUSTOM_SENDER = "clerk_email_sms_custom_sender_present"

# Auth strategy
_RULE_AUTH_STRATEGY_MFA_NOT_REQUIRED = "clerk_auth_strategy_mfa_not_required"
_RULE_AUTH_STRATEGY_PASSWORD_WITHOUT_MFA = "clerk_auth_strategy_password_without_mfa"

# Session policy
_RULE_SESSION_LIFETIME_EXTENDED = "clerk_session_lifetime_extended"
_RULE_SESSION_INACTIVITY_EXTENDED = "clerk_session_inactivity_timeout_extended"
_RULE_SESSION_SINGLE_SESSION_DISABLED = "clerk_session_single_session_disabled"
_RULE_SESSION_TOKEN_ROTATION_DISABLED = "clerk_session_token_rotation_disabled"

CLERK_RULE_KEYS: frozenset[str] = frozenset({
    # Instance settings
    _RULE_INSTANCE_MFA_DISABLED,
    _RULE_INSTANCE_PASSWORD_WITHOUT_MFA,
    _RULE_INSTANCE_SIGN_UP_ENABLED,
    # Application
    _RULE_APP_MFA_NOT_REQUIRED,
    # Domain
    _RULE_DOMAIN_UNVERIFIED,
    _RULE_DOMAIN_SSL_DISABLED,
    # Redirect URL
    _RULE_REDIRECT_URL_NON_HTTPS,
    _RULE_REDIRECT_URL_WILDCARD,
    _RULE_REDIRECT_URL_LOCALHOST,
    # JWT template
    _RULE_JWT_CUSTOM_CLAIMS,
    _RULE_JWT_LONG_LIFETIME,
    # Webhook
    _RULE_WEBHOOK_DISABLED,
    _RULE_WEBHOOK_WITHOUT_SIGNING,
    _RULE_WEBHOOK_NON_HTTPS,
    # Email/SMS
    _RULE_EMAIL_SMS_CUSTOM_SENDER,
    # Auth strategy
    _RULE_AUTH_STRATEGY_MFA_NOT_REQUIRED,
    _RULE_AUTH_STRATEGY_PASSWORD_WITHOUT_MFA,
    # Session policy
    _RULE_SESSION_LIFETIME_EXTENDED,
    _RULE_SESSION_INACTIVITY_EXTENDED,
    _RULE_SESSION_SINGLE_SESSION_DISABLED,
    _RULE_SESSION_TOKEN_ROTATION_DISABLED,
})

# JWT lifetime categories that indicate a long/extended token lifetime.
_LONG_JWT_LIFETIME_CATEGORIES = frozenset({"extended", "long"})

# Session lifetime categories that indicate an extended session.
_EXTENDED_SESSION_LIFETIME_CATEGORIES = frozenset({"extended", "very_long"})


# ── Helpers ────────────────────────────────────────────────────────────────────


def _bool_field(record: dict[str, Any], key: str) -> bool:
    val = record.get(key)
    return bool(val) if isinstance(val, bool) else False


# ── Instance settings evaluator ────────────────────────────────────────────────


def _eval_instance_settings(record: dict[str, Any]) -> list[FindingCandidate]:
    """Evaluate one clerk_instance_settings record.

    SECURITY: raw instance ID strings beyond the opaque record_id, support
    email addresses, domain names, theme data, and all raw API payload
    are NEVER read or stored.
    """
    record_id = get_str(record, "record_id") or "clerk_instance_settings_main"
    findings: list[FindingCandidate] = []

    mfa_enabled = _bool_field(record, "mfa_enabled")
    password_enabled = _bool_field(record, "password_enabled")
    sign_up_enabled = _bool_field(record, "sign_up_enabled")

    # ── clerk_instance_mfa_disabled ───────────────────────────────────────────
    if not mfa_enabled:
        findings.append(FindingCandidate(
            provider="clerk",
            rule_key=_RULE_INSTANCE_MFA_DISABLED,
            finding_key=make_finding_key(_RULE_INSTANCE_MFA_DISABLED, record_id),
            severity="medium",
            title="Clerk instance has MFA disabled",
            description=(
                "The Clerk instance does not have multi-factor authentication (MFA) "
                "enabled at the instance level. Without MFA, users authenticate with "
                "a single factor, which may increase exposure to credential-based "
                "account access. This configuration posture may require review. "
                "This is configuration evidence — it does not confirm unauthorized access."
            ),
            evidence={
                "rule": _RULE_INSTANCE_MFA_DISABLED,
                "record_id": record_id,
                "mfa_enabled": False,
            },
            remediation={
                "summary": "Enable MFA in the Clerk Dashboard for the instance.",
                "steps": [
                    "Sign in to the Clerk Dashboard.",
                    "Navigate to User & Authentication > Multi-factor.",
                    "Enable at least one MFA factor (TOTP, SMS OTP, or hardware key).",
                    "Review your authentication policy to confirm MFA is required for "
                    "production accounts.",
                ],
            },
            record_id=record_id,
        ))

    # ── clerk_instance_password_without_mfa ──────────────────────────────────
    if password_enabled and not mfa_enabled:
        findings.append(FindingCandidate(
            provider="clerk",
            rule_key=_RULE_INSTANCE_PASSWORD_WITHOUT_MFA,
            finding_key=make_finding_key(_RULE_INSTANCE_PASSWORD_WITHOUT_MFA, record_id),
            severity="medium",
            title="Clerk instance has password authentication enabled without MFA",
            description=(
                "The Clerk instance has password-based authentication enabled but "
                "multi-factor authentication (MFA) is not enabled. Password-only "
                "authentication provides a single authentication barrier. Enabling "
                "MFA adds a second factor that may reduce the impact of credential "
                "compromise. This configuration posture may require review. "
                "This is configuration evidence — it does not confirm unauthorized access."
            ),
            evidence={
                "rule": _RULE_INSTANCE_PASSWORD_WITHOUT_MFA,
                "record_id": record_id,
                "password_enabled": True,
                "mfa_enabled": False,
            },
            remediation={
                "summary": "Enable MFA alongside password authentication in the Clerk Dashboard.",
                "steps": [
                    "Sign in to the Clerk Dashboard.",
                    "Navigate to User & Authentication > Multi-factor.",
                    "Enable at least one MFA factor.",
                    "Consider making MFA required for users with password-based accounts.",
                ],
            },
            record_id=record_id,
        ))

    # ── clerk_instance_sign_up_enabled ────────────────────────────────────────
    if sign_up_enabled:
        findings.append(FindingCandidate(
            provider="clerk",
            rule_key=_RULE_INSTANCE_SIGN_UP_ENABLED,
            finding_key=make_finding_key(_RULE_INSTANCE_SIGN_UP_ENABLED, record_id),
            severity="low",
            title="Clerk instance has public sign-up enabled",
            description=(
                "The Clerk instance has sign-up enabled, allowing new users to "
                "register. Public sign-up posture may require review to confirm "
                "this is the intended access model for all environments, particularly "
                "production. If unrestricted registration is not intended, consider "
                "enabling allowlists or invitation-only mode. "
                "This is configuration evidence — it does not confirm unauthorized access."
            ),
            evidence={
                "rule": _RULE_INSTANCE_SIGN_UP_ENABLED,
                "record_id": record_id,
                "sign_up_enabled": True,
                "sign_in_mode": get_str(record, "sign_in_mode"),
            },
            remediation={
                "summary": "Review the sign-up configuration for this Clerk instance.",
                "steps": [
                    "Sign in to the Clerk Dashboard.",
                    "Navigate to User & Authentication > Email, Phone, Username.",
                    "Review whether sign-up should be open, invitation-only, or "
                    "restricted by an allowlist.",
                    "Enable Restrictions > Allowlist if only specific email domains "
                    "should be permitted to register.",
                ],
            },
            record_id=record_id,
        ))

    return findings


# ── Application evaluator ──────────────────────────────────────────────────────


def _eval_application(record: dict[str, Any]) -> list[FindingCandidate]:
    """Evaluate one clerk_application record.

    SECURITY: client_id, OAuth client secrets, raw redirect URL lists, raw
    allowed origins, and all raw application payload are NEVER stored.
    """
    record_id = get_str(record, "record_id") or "clerk_application_main"
    app_name = get_str(record, "name") or "unknown"
    findings: list[FindingCandidate] = []

    # ── clerk_application_mfa_not_required ────────────────────────────────────
    if record.get("mfa_required") is False:
        findings.append(FindingCandidate(
            provider="clerk",
            rule_key=_RULE_APP_MFA_NOT_REQUIRED,
            finding_key=make_finding_key(_RULE_APP_MFA_NOT_REQUIRED, record_id),
            severity="medium",
            title="Clerk application does not require MFA",
            description=(
                f"The Clerk application '{app_name}' does not have MFA required at "
                "the application level. Without mandatory MFA, users may authenticate "
                "with only a single factor. This configuration posture may require "
                "review for applications handling sensitive operations. "
                "This is configuration evidence — it does not confirm unauthorized access."
            ),
            evidence={
                "rule": _RULE_APP_MFA_NOT_REQUIRED,
                "record_id": record_id,
                "name": app_name,
                "mfa_required": False,
            },
            remediation={
                "summary": "Enable MFA as a requirement for this Clerk application.",
                "steps": [
                    "Sign in to the Clerk Dashboard.",
                    "Navigate to the application configuration.",
                    "Review the MFA policy and enable required MFA for users "
                    "of this application.",
                ],
            },
            record_id=record_id,
        ))

    return findings


# ── Domain evaluator ───────────────────────────────────────────────────────────


def _eval_domain(record: dict[str, Any]) -> list[FindingCandidate]:
    """Evaluate one clerk_domain record.

    SECURITY: the raw domain name string is customer-identifying and is NEVER
    stored. Evidence uses only domain_type, verified, ssl_enabled, and the
    opaque record_id.
    """
    record_id = get_str(record, "record_id") or "clerk_domain_unknown"
    domain_type = get_str(record, "domain_type") or "unknown"
    findings: list[FindingCandidate] = []

    # ── clerk_domain_unverified ───────────────────────────────────────────────
    if record.get("verified") is False:
        findings.append(FindingCandidate(
            provider="clerk",
            rule_key=_RULE_DOMAIN_UNVERIFIED,
            finding_key=make_finding_key(_RULE_DOMAIN_UNVERIFIED, record_id),
            severity="medium",
            title="Clerk domain is not verified",
            description=(
                "A Clerk domain is not in a verified state. An unverified domain "
                "may indicate a pending DNS configuration or a setup that has not "
                "been completed. Unverified domains may affect authentication "
                "routing and may require review. "
                "Raw domain name strings are never stored by ConfigTrace."
            ),
            evidence={
                "rule": _RULE_DOMAIN_UNVERIFIED,
                "record_id": record_id,
                "domain_type": domain_type,
                "verified": False,
            },
            remediation={
                "summary": "Complete domain verification in the Clerk Dashboard.",
                "steps": [
                    "Sign in to the Clerk Dashboard.",
                    "Navigate to Domains.",
                    "Locate the unverified domain and complete the required DNS "
                    "verification steps.",
                    "If the domain is no longer needed, remove it to keep configuration clean.",
                ],
            },
            record_id=record_id,
        ))

    # ── clerk_domain_ssl_disabled ─────────────────────────────────────────────
    if record.get("ssl_enabled") is False:
        findings.append(FindingCandidate(
            provider="clerk",
            rule_key=_RULE_DOMAIN_SSL_DISABLED,
            finding_key=make_finding_key(_RULE_DOMAIN_SSL_DISABLED, record_id),
            severity="high",
            title="Clerk domain has SSL disabled",
            description=(
                "A Clerk domain has SSL disabled. Without SSL, authentication "
                "traffic for this domain may be transmitted without transport-layer "
                "encryption, which may expose credentials and tokens in transit. "
                "This configuration posture may require review. "
                "Raw domain name strings are never stored by ConfigTrace."
            ),
            evidence={
                "rule": _RULE_DOMAIN_SSL_DISABLED,
                "record_id": record_id,
                "domain_type": domain_type,
                "ssl_enabled": False,
            },
            remediation={
                "summary": "Enable SSL for this Clerk domain.",
                "steps": [
                    "Sign in to the Clerk Dashboard.",
                    "Navigate to Domains.",
                    "Review the SSL configuration for the affected domain.",
                    "Enable SSL and verify that a valid TLS certificate is provisioned.",
                ],
            },
            record_id=record_id,
        ))

    return findings


# ── Redirect URL evaluator ─────────────────────────────────────────────────────


def _eval_redirect_url(record: dict[str, Any]) -> list[FindingCandidate]:
    """Evaluate one clerk_redirect_url_config record.

    SECURITY: the raw URL string is NEVER stored. url_scheme_category,
    wildcard_present, and localhost_present are booleans/categories derived
    from the URL before it is discarded.
    """
    record_id = get_str(record, "record_id") or "clerk_redirect_url_unknown"
    findings: list[FindingCandidate] = []

    url_present = _bool_field(record, "url_present")
    url_scheme_cat = get_str(record, "url_scheme_category")

    # ── clerk_redirect_url_non_https ──────────────────────────────────────────
    if url_present and url_scheme_cat and url_scheme_cat != "https":
        findings.append(FindingCandidate(
            provider="clerk",
            rule_key=_RULE_REDIRECT_URL_NON_HTTPS,
            finding_key=make_finding_key(_RULE_REDIRECT_URL_NON_HTTPS, record_id),
            severity="high",
            title="Clerk redirect URL uses a non-HTTPS scheme",
            description=(
                "A Clerk redirect URL is configured with a scheme other than HTTPS. "
                "Redirect URLs that use plain HTTP may expose authorization codes "
                "or tokens in transit. Custom schemes (deep links) may also require "
                "review depending on the application's security model. "
                "This configuration posture may require review. "
                "Raw redirect URL strings are never stored by ConfigTrace."
            ),
            evidence={
                "rule": _RULE_REDIRECT_URL_NON_HTTPS,
                "record_id": record_id,
                "url_present": True,
                "url_scheme_category": url_scheme_cat,
            },
            remediation={
                "summary": "Review redirect URLs and update non-HTTPS entries to use HTTPS.",
                "steps": [
                    "Sign in to the Clerk Dashboard.",
                    "Navigate to the application settings.",
                    "Review the configured redirect URLs.",
                    "Replace any http:// entries with https:// equivalents.",
                    "For custom schemes, confirm the scheme is intentional and "
                    "the receiving application handles tokens securely.",
                ],
            },
            record_id=record_id,
        ))

    # ── clerk_redirect_url_wildcard_present ───────────────────────────────────
    if _bool_field(record, "wildcard_present"):
        findings.append(FindingCandidate(
            provider="clerk",
            rule_key=_RULE_REDIRECT_URL_WILDCARD,
            finding_key=make_finding_key(_RULE_REDIRECT_URL_WILDCARD, record_id),
            severity="medium",
            title="Clerk redirect URL contains a wildcard",
            description=(
                "A Clerk redirect URL contains a wildcard character. Wildcard "
                "redirect URLs may allow authorization codes to be redirected to "
                "unexpected destinations and may broaden the redirect surface "
                "beyond what is intended. This configuration posture may require "
                "review. Raw redirect URL strings are never stored by ConfigTrace."
            ),
            evidence={
                "rule": _RULE_REDIRECT_URL_WILDCARD,
                "record_id": record_id,
                "wildcard_present": True,
            },
            remediation={
                "summary": "Replace wildcard redirect URLs with explicit, fully-qualified URLs.",
                "steps": [
                    "Sign in to the Clerk Dashboard.",
                    "Navigate to the application settings and review redirect URLs.",
                    "Replace any wildcard entries with specific, fully-qualified URLs.",
                ],
            },
            record_id=record_id,
        ))

    # ── clerk_redirect_url_localhost_present ──────────────────────────────────
    if _bool_field(record, "localhost_present"):
        findings.append(FindingCandidate(
            provider="clerk",
            rule_key=_RULE_REDIRECT_URL_LOCALHOST,
            finding_key=make_finding_key(_RULE_REDIRECT_URL_LOCALHOST, record_id),
            severity="low",
            title="Clerk redirect URL points to localhost",
            description=(
                "A Clerk redirect URL is configured to redirect to localhost or a "
                "loopback address. Localhost redirect URLs are common during local "
                "development but may indicate development configuration left in a "
                "production instance and may require review. "
                "Raw redirect URL strings are never stored by ConfigTrace."
            ),
            evidence={
                "rule": _RULE_REDIRECT_URL_LOCALHOST,
                "record_id": record_id,
                "localhost_present": True,
            },
            remediation={
                "summary": "Review whether localhost redirect URLs are appropriate for this environment.",
                "steps": [
                    "Sign in to the Clerk Dashboard.",
                    "Navigate to the application settings and review redirect URLs.",
                    "Remove localhost entries if this is a production instance.",
                ],
            },
            record_id=record_id,
        ))

    return findings


# ── JWT template evaluator ─────────────────────────────────────────────────────


def _eval_jwt_template(record: dict[str, Any]) -> list[FindingCandidate]:
    """Evaluate one clerk_jwt_template record.

    SECURITY: template body, custom claims, audience URI, issuer string,
    signing key material, and all raw template content are NEVER stored.
    """
    record_id = get_str(record, "record_id") or "clerk_jwt_template_unknown"
    template_name = get_str(record, "name") or "unknown"
    findings: list[FindingCandidate] = []

    # ── clerk_jwt_template_custom_claims_present ──────────────────────────────
    if _bool_field(record, "custom_claims_present"):
        claims_count = record.get("claims_count", 0)
        findings.append(FindingCandidate(
            provider="clerk",
            rule_key=_RULE_JWT_CUSTOM_CLAIMS,
            finding_key=make_finding_key(_RULE_JWT_CUSTOM_CLAIMS, record_id),
            severity="low",
            title="Clerk JWT template has custom claims configured",
            description=(
                f"The Clerk JWT template '{template_name}' has custom claims "
                "configured. Custom claims embed additional data in JWTs issued "
                "by this template. The claim count and presence are tracked as "
                "configuration evidence for periodic review — claim names, values, "
                "audience URIs, and template body are never stored by ConfigTrace."
            ),
            evidence={
                "rule": _RULE_JWT_CUSTOM_CLAIMS,
                "record_id": record_id,
                "name": template_name,
                "custom_claims_present": True,
                "claims_count": claims_count if isinstance(claims_count, int) else 0,
            },
            remediation={
                "summary": "Review custom claims in this JWT template periodically.",
                "steps": [
                    "Sign in to the Clerk Dashboard.",
                    "Navigate to JWT Templates and open the template.",
                    "Review the configured custom claims to confirm they are "
                    "current, minimal, and appropriate for the template's audience.",
                ],
            },
            record_id=record_id,
        ))

    # ── clerk_jwt_template_long_lifetime ──────────────────────────────────────
    lifetime_cat = get_str(record, "lifetime_category")
    if lifetime_cat and lifetime_cat in _LONG_JWT_LIFETIME_CATEGORIES:
        findings.append(FindingCandidate(
            provider="clerk",
            rule_key=_RULE_JWT_LONG_LIFETIME,
            finding_key=make_finding_key(_RULE_JWT_LONG_LIFETIME, record_id),
            severity="medium",
            title="Clerk JWT template has an extended token lifetime",
            description=(
                f"The Clerk JWT template '{template_name}' has a token lifetime "
                "classified as extended. Long-lived JWTs increase the window "
                "during which a token remains valid and may require review for "
                "alignment with your token lifecycle policy. "
                "This is configuration evidence — no token values are stored."
            ),
            evidence={
                "rule": _RULE_JWT_LONG_LIFETIME,
                "record_id": record_id,
                "name": template_name,
                "lifetime_category": lifetime_cat,
            },
            remediation={
                "summary": "Review and reduce the token lifetime for this JWT template.",
                "steps": [
                    "Sign in to the Clerk Dashboard.",
                    "Navigate to JWT Templates and open the template.",
                    "Reduce the token lifetime to match your security policy.",
                    "Short-lived tokens (minutes to a few hours) limit the impact "
                    "window if a token requires review.",
                ],
            },
            record_id=record_id,
        ))

    return findings


# ── Webhook endpoint evaluator ─────────────────────────────────────────────────


def _eval_webhook_endpoint(record: dict[str, Any]) -> list[FindingCandidate]:
    """Evaluate one clerk_webhook_endpoint record.

    SECURITY: webhook URL, signing secret, raw event names, and all raw
    webhook payload are NEVER stored. url_scheme_category is derived from
    the URL before discarding it.
    """
    record_id = get_str(record, "record_id") or "clerk_webhook_endpoint_unknown"
    findings: list[FindingCandidate] = []

    enabled = _bool_field(record, "enabled")
    url_present = _bool_field(record, "url_present")
    secret_present = _bool_field(record, "secret_present")
    url_scheme_cat = get_str(record, "url_scheme_category")

    # ── clerk_webhook_endpoint_disabled ──────────────────────────────────────
    if not enabled:
        findings.append(FindingCandidate(
            provider="clerk",
            rule_key=_RULE_WEBHOOK_DISABLED,
            finding_key=make_finding_key(_RULE_WEBHOOK_DISABLED, record_id),
            severity="low",
            title="Clerk webhook endpoint is disabled",
            description=(
                "A Clerk webhook endpoint is currently disabled. A disabled "
                "webhook endpoint will not deliver events, which may indicate "
                "an integration that was intentionally or unintentionally paused. "
                "This is an integration reliability posture item for review — "
                "it does not confirm a security incident."
            ),
            evidence={
                "rule": _RULE_WEBHOOK_DISABLED,
                "record_id": record_id,
                "enabled": False,
            },
            remediation={
                "summary": "Review whether this webhook endpoint should be re-enabled.",
                "steps": [
                    "Sign in to the Clerk Dashboard.",
                    "Navigate to Webhooks.",
                    "Locate the disabled endpoint and review its configuration.",
                    "Re-enable it if the integration should receive events, or "
                    "remove it if it is no longer needed.",
                ],
            },
            record_id=record_id,
        ))

    # ── clerk_webhook_without_signing ─────────────────────────────────────────
    if url_present and not secret_present:
        findings.append(FindingCandidate(
            provider="clerk",
            rule_key=_RULE_WEBHOOK_WITHOUT_SIGNING,
            finding_key=make_finding_key(_RULE_WEBHOOK_WITHOUT_SIGNING, record_id),
            severity="high",
            title="Clerk webhook endpoint has no signing secret configured",
            description=(
                "A Clerk webhook endpoint has a URL configured but no signing "
                "secret present. Without a signing secret, the receiving endpoint "
                "cannot verify that incoming webhook deliveries originate from "
                "Clerk. This configuration posture may require review. "
                "Webhook URLs and secret values are never stored by ConfigTrace."
            ),
            evidence={
                "rule": _RULE_WEBHOOK_WITHOUT_SIGNING,
                "record_id": record_id,
                "url_present": True,
                "secret_present": False,
            },
            remediation={
                "summary": "Add a signing secret to verify the origin of Clerk webhook deliveries.",
                "steps": [
                    "Sign in to the Clerk Dashboard.",
                    "Navigate to Webhooks and open the endpoint configuration.",
                    "Copy the signing secret and configure the receiving endpoint "
                    "to validate the svix-signature header on each delivery.",
                    "Reject deliveries that fail signature verification.",
                ],
            },
            record_id=record_id,
        ))

    # ── clerk_webhook_non_https ───────────────────────────────────────────────
    if url_present and url_scheme_cat and url_scheme_cat != "https":
        findings.append(FindingCandidate(
            provider="clerk",
            rule_key=_RULE_WEBHOOK_NON_HTTPS,
            finding_key=make_finding_key(_RULE_WEBHOOK_NON_HTTPS, record_id),
            severity="high",
            title="Clerk webhook endpoint uses a non-HTTPS URL",
            description=(
                "A Clerk webhook endpoint is configured with a URL that does not "
                "use HTTPS. Webhook payloads delivered over unencrypted connections "
                "may expose event content in transit. This configuration posture "
                "may require review. Webhook URL strings are never stored by "
                "ConfigTrace."
            ),
            evidence={
                "rule": _RULE_WEBHOOK_NON_HTTPS,
                "record_id": record_id,
                "url_present": True,
                "url_scheme_category": url_scheme_cat,
            },
            remediation={
                "summary": "Update the webhook endpoint URL to use HTTPS.",
                "steps": [
                    "Sign in to the Clerk Dashboard.",
                    "Navigate to Webhooks and open the endpoint configuration.",
                    "Update the endpoint URL to use HTTPS.",
                    "Verify the endpoint has a valid TLS certificate.",
                ],
            },
            record_id=record_id,
        ))

    return findings


# ── Email/SMS settings evaluator ───────────────────────────────────────────────


def _eval_email_sms_settings(record: dict[str, Any]) -> list[FindingCandidate]:
    """Evaluate one clerk_email_sms_settings record.

    SECURITY: sender email addresses, sender phone numbers, template content,
    and raw settings payload are NEVER stored.
    """
    record_id = get_str(record, "record_id") or "clerk_email_sms_settings_main"
    findings: list[FindingCandidate] = []

    # ── clerk_email_sms_custom_sender_present ─────────────────────────────────
    if _bool_field(record, "custom_sender_present"):
        findings.append(FindingCandidate(
            provider="clerk",
            rule_key=_RULE_EMAIL_SMS_CUSTOM_SENDER,
            finding_key=make_finding_key(_RULE_EMAIL_SMS_CUSTOM_SENDER, record_id),
            severity="low",
            title="Clerk email/SMS settings include a custom sender",
            description=(
                "The Clerk instance has a custom sender domain or address "
                "configured for email or SMS delivery. Custom senders affect "
                "deliverability and email authentication (SPF/DKIM) posture and "
                "may require periodic review to confirm ownership and delivery "
                "health. Sender addresses are never stored by ConfigTrace."
            ),
            evidence={
                "rule": _RULE_EMAIL_SMS_CUSTOM_SENDER,
                "record_id": record_id,
                "custom_sender_present": True,
            },
            remediation={
                "summary": "Review custom sender configuration for deliverability and ownership.",
                "steps": [
                    "Sign in to the Clerk Dashboard.",
                    "Navigate to Email, Phone, Username > Email settings.",
                    "Confirm the custom sender domain has valid SPF, DKIM, and DMARC "
                    "records configured.",
                    "Verify the sender domain is actively monitored for bounce and "
                    "deliverability signals.",
                ],
            },
            record_id=record_id,
        ))

    return findings


# ── Auth strategy evaluator ────────────────────────────────────────────────────


def _eval_auth_strategy(record: dict[str, Any]) -> list[FindingCandidate]:
    """Evaluate one clerk_auth_strategy record.

    SECURITY: social provider secrets, SAML certificates, private keys,
    connection credentials, and raw strategy configuration are NEVER stored.
    """
    record_id = get_str(record, "record_id") or "clerk_auth_strategy_main"
    findings: list[FindingCandidate] = []

    mfa_enabled = _bool_field(record, "mfa_enabled")
    mfa_required = _bool_field(record, "mfa_required")
    password_enabled = _bool_field(record, "password_enabled")

    # ── clerk_auth_strategy_mfa_not_required ──────────────────────────────────
    if mfa_enabled and not mfa_required:
        findings.append(FindingCandidate(
            provider="clerk",
            rule_key=_RULE_AUTH_STRATEGY_MFA_NOT_REQUIRED,
            finding_key=make_finding_key(_RULE_AUTH_STRATEGY_MFA_NOT_REQUIRED, record_id),
            severity="medium",
            title="Clerk authentication strategy supports MFA but does not require it",
            description=(
                "The Clerk instance has MFA available as an authentication method "
                "but does not require it. When MFA is optional, users may skip "
                "enrollment, leaving accounts protected by a single factor. "
                "This configuration posture may require review to confirm whether "
                "MFA enforcement aligns with your security policy. "
                "This is configuration evidence — it does not confirm unauthorized access."
            ),
            evidence={
                "rule": _RULE_AUTH_STRATEGY_MFA_NOT_REQUIRED,
                "record_id": record_id,
                "mfa_enabled": True,
                "mfa_required": False,
            },
            remediation={
                "summary": "Consider making MFA required for all users in the Clerk Dashboard.",
                "steps": [
                    "Sign in to the Clerk Dashboard.",
                    "Navigate to User & Authentication > Multi-factor.",
                    "Review whether MFA should be set as required rather than optional.",
                    "If not all user types require MFA, consider applying MFA requirements "
                    "selectively via organizations or application-level policies.",
                ],
            },
            record_id=record_id,
        ))

    # ── clerk_auth_strategy_password_without_mfa ─────────────────────────────
    if password_enabled and not mfa_required:
        findings.append(FindingCandidate(
            provider="clerk",
            rule_key=_RULE_AUTH_STRATEGY_PASSWORD_WITHOUT_MFA,
            finding_key=make_finding_key(
                _RULE_AUTH_STRATEGY_PASSWORD_WITHOUT_MFA, record_id
            ),
            severity="medium",
            title="Clerk authentication strategy has password enabled without required MFA",
            description=(
                "The Clerk instance has password-based authentication enabled as "
                "a strategy but MFA is not required. Password-only authentication "
                "may be strengthened by requiring a second factor. This configuration "
                "posture may require review. "
                "This is configuration evidence — it does not confirm unauthorized access."
            ),
            evidence={
                "rule": _RULE_AUTH_STRATEGY_PASSWORD_WITHOUT_MFA,
                "record_id": record_id,
                "password_enabled": True,
                "mfa_required": False,
            },
            remediation={
                "summary": "Enable required MFA alongside password authentication.",
                "steps": [
                    "Sign in to the Clerk Dashboard.",
                    "Navigate to User & Authentication > Multi-factor.",
                    "Enable and require at least one MFA factor for users with "
                    "password-based accounts.",
                ],
            },
            record_id=record_id,
        ))

    return findings


# ── Session policy evaluator ───────────────────────────────────────────────────


def _eval_session_policy(record: dict[str, Any]) -> list[FindingCandidate]:
    """Evaluate one clerk_session_policy record.

    SECURITY: active session tokens, session IDs, session content, and all
    user-level session data are NEVER stored. Evidence uses only categories,
    booleans, and the opaque record_id.
    """
    record_id = get_str(record, "record_id") or "clerk_session_policy_main"
    findings: list[FindingCandidate] = []

    session_lifetime_cat = get_str(record, "session_lifetime_category")
    inactivity_cat = get_str(record, "inactivity_timeout_category")
    single_session_mode = record.get("single_session_mode")
    token_rotation_enabled = record.get("token_rotation_enabled")

    # ── clerk_session_lifetime_extended ───────────────────────────────────────
    if session_lifetime_cat and session_lifetime_cat in _EXTENDED_SESSION_LIFETIME_CATEGORIES:
        findings.append(FindingCandidate(
            provider="clerk",
            rule_key=_RULE_SESSION_LIFETIME_EXTENDED,
            finding_key=make_finding_key(_RULE_SESSION_LIFETIME_EXTENDED, record_id),
            severity="medium",
            title="Clerk session lifetime is extended",
            description=(
                "The Clerk session policy is configured with an extended session "
                "lifetime. Extended sessions increase the window during which a "
                "session token remains valid without re-authentication, which may "
                "warrant review for alignment with your access-management policy. "
                "This is configuration evidence — no session token values are stored."
            ),
            evidence={
                "rule": _RULE_SESSION_LIFETIME_EXTENDED,
                "record_id": record_id,
                "session_lifetime_category": session_lifetime_cat,
            },
            remediation={
                "summary": "Review and reduce the session lifetime in the Clerk Dashboard.",
                "steps": [
                    "Sign in to the Clerk Dashboard.",
                    "Navigate to Sessions.",
                    "Review the session token lifetime and reduce it to match "
                    "your access-management policy.",
                ],
            },
            record_id=record_id,
        ))

    # ── clerk_session_inactivity_timeout_extended ─────────────────────────────
    if inactivity_cat and inactivity_cat == "extended":
        findings.append(FindingCandidate(
            provider="clerk",
            rule_key=_RULE_SESSION_INACTIVITY_EXTENDED,
            finding_key=make_finding_key(_RULE_SESSION_INACTIVITY_EXTENDED, record_id),
            severity="low",
            title="Clerk session inactivity timeout is extended",
            description=(
                "The Clerk session policy has an extended inactivity timeout. "
                "Sessions that persist for an extended period without activity "
                "may warrant review for alignment with your access-management "
                "policy. This is configuration evidence — no session token "
                "values are stored."
            ),
            evidence={
                "rule": _RULE_SESSION_INACTIVITY_EXTENDED,
                "record_id": record_id,
                "inactivity_timeout_category": inactivity_cat,
            },
            remediation={
                "summary": "Review and reduce the inactivity timeout in the Clerk Dashboard.",
                "steps": [
                    "Sign in to the Clerk Dashboard.",
                    "Navigate to Sessions.",
                    "Review the inactivity timeout setting and reduce it as appropriate.",
                ],
            },
            record_id=record_id,
        ))

    # ── clerk_session_single_session_disabled ─────────────────────────────────
    if single_session_mode is False:
        findings.append(FindingCandidate(
            provider="clerk",
            rule_key=_RULE_SESSION_SINGLE_SESSION_DISABLED,
            finding_key=make_finding_key(_RULE_SESSION_SINGLE_SESSION_DISABLED, record_id),
            severity="low",
            title="Clerk single-session mode is disabled",
            description=(
                "The Clerk session policy does not enforce single-session mode. "
                "Without single-session enforcement, a user can maintain concurrent "
                "active sessions on multiple devices or browsers. This may be "
                "intentional but may require review for high-security applications. "
                "This is configuration evidence — no session data is stored."
            ),
            evidence={
                "rule": _RULE_SESSION_SINGLE_SESSION_DISABLED,
                "record_id": record_id,
                "single_session_mode": False,
            },
            remediation={
                "summary": "Review whether single-session mode should be enabled.",
                "steps": [
                    "Sign in to the Clerk Dashboard.",
                    "Navigate to Sessions.",
                    "Review the single-session mode setting.",
                    "Enable it if your application requires that a user can only "
                    "have one active session at a time.",
                ],
            },
            record_id=record_id,
        ))

    # ── clerk_session_token_rotation_disabled ─────────────────────────────────
    if token_rotation_enabled is False:
        findings.append(FindingCandidate(
            provider="clerk",
            rule_key=_RULE_SESSION_TOKEN_ROTATION_DISABLED,
            finding_key=make_finding_key(_RULE_SESSION_TOKEN_ROTATION_DISABLED, record_id),
            severity="medium",
            title="Clerk session token rotation is disabled",
            description=(
                "The Clerk session policy does not have token rotation enabled. "
                "Without token rotation, session tokens remain valid until they "
                "expire or are explicitly revoked. Enabling token rotation issues "
                "a new session token periodically, limiting the validity window of "
                "any token that may require review. "
                "This is configuration evidence — no token values are stored."
            ),
            evidence={
                "rule": _RULE_SESSION_TOKEN_ROTATION_DISABLED,
                "record_id": record_id,
                "token_rotation_enabled": False,
            },
            remediation={
                "summary": "Enable session token rotation in the Clerk Dashboard.",
                "steps": [
                    "Sign in to the Clerk Dashboard.",
                    "Navigate to Sessions.",
                    "Enable token rotation to reduce the validity window of "
                    "individual session tokens.",
                ],
            },
            record_id=record_id,
        ))

    return findings


# ── Public evaluate entry point ────────────────────────────────────────────────


def evaluate(record: dict[str, Any]) -> list[FindingCandidate]:
    """Evaluate one normalized Clerk drift record and return any findings.

    Accepts any dict. Unknown record_type values return an empty list — never
    raises. Each evaluator is self-contained and never mutates the record.

    SECURITY: no rule reads or stores Clerk secret key values, publishable key
    values, session tokens, JWTs, OAuth tokens, bearer tokens, webhook secrets,
    raw webhook URLs, raw redirect URLs, raw callback URLs, raw domain names, raw
    JWT template bodies, raw claims, raw audience values, raw issuer values, user
    emails, user IDs, phone numbers, names, organization member identities,
    session history, login history, password data, MFA secrets, backup codes,
    verification codes, IP addresses, user agents, raw audit payloads, request or
    response payloads, customer data, or PII.
    """
    if not isinstance(record, dict):
        return []

    rtype = record.get("record_type")

    if rtype == CLERK_INSTANCE_SETTINGS:
        return _eval_instance_settings(record)
    if rtype == CLERK_APPLICATION:
        return _eval_application(record)
    if rtype == CLERK_DOMAIN:
        return _eval_domain(record)
    if rtype == CLERK_REDIRECT_URL_CONFIG:
        return _eval_redirect_url(record)
    if rtype == CLERK_JWT_TEMPLATE:
        return _eval_jwt_template(record)
    if rtype == CLERK_WEBHOOK_ENDPOINT:
        return _eval_webhook_endpoint(record)
    if rtype == CLERK_EMAIL_SMS_SETTINGS:
        return _eval_email_sms_settings(record)
    if rtype == CLERK_AUTH_STRATEGY:
        return _eval_auth_strategy(record)
    if rtype == CLERK_SESSION_POLICY:
        return _eval_session_policy(record)

    return []
