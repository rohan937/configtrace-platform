"""Auth0 configuration-risk security rules — M81B.

Every rule fires only on explicit, reliable normalized fields produced by the
Auth0 connector (app/connectors/auth0.py + auth0_schema.py, M81A). Evidence
is metadata-only: booleans, counts, categories, opaque identifiers, and safe
string labels. No client secrets, management tokens, access tokens, JWTs,
private keys, authorization headers, raw callback URLs, audience URIs, domain
names, script/code content, action secret values, connection credentials,
user emails, user IDs, or any customer data are ever read, stored, or surfaced.

CLAIM DISCIPLINE
----------------
These are configuration posture findings that may require review. A finding is
evidence for review only. It never asserts that a credential was leaked, a
token was compromised, that unauthorized access occurred, or that any attacker
is present. Severity reflects review priority, not confirmed impact.

Record types consumed (M81A)
----------------------------
- ``auth0_tenant_settings``     → session lifetime, flags
- ``auth0_application``         → app type, grant types, URL counts, JWT alg,
                                   token_endpoint_auth_method, OIDC conformance,
                                   refresh token configuration
- ``auth0_connection``          → strategy, enabled clients count, password policy
- ``auth0_resource_server``     → signing alg, token lifetime, offline access, RBAC
- ``auth0_rule``                → enabled status, script presence/length
- ``auth0_action``              → deployed status, secrets count
- ``auth0_mfa_factor``          → factor name, enabled status
- ``auth0_custom_domain``       → status, TLS policy

Rules deferred from M81B
--------------------------
- ``auth0_tenant_mfa_policy_weak`` — M81A schema has no mfa_policy_category field
  in auth0_tenant_settings. Auth0 tenant-level MFA enforcement posture is not
  surfaced through /api/v2/tenants/settings in a form captured by M81A. Deferred
  until a safe endpoint (e.g. /api/v2/guardian/factors aggregated) is wired.
- ``auth0_application_stale_client`` — Auth0 Management API does not expose
  application last-used or last-synced timestamps in the safe client fields
  captured in M81A. Deferred.
"""

from __future__ import annotations

from typing import Any

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
from app.services.security_rules.base import (
    FindingCandidate,
    get_str,
    make_finding_key,
)

# ── Rule keys — M81B ──────────────────────────────────────────────────────────

# Tenant settings
_RULE_TENANT_SESSION_LIFETIME_EXTENDED = "auth0_tenant_session_lifetime_extended"
_RULE_TENANT_IDLE_SESSION_LIFETIME_EXTENDED = "auth0_tenant_idle_session_lifetime_extended"
_RULE_TENANT_DYNAMIC_CLIENT_REGISTRATION_ENABLED = "auth0_tenant_dynamic_client_registration_enabled"

# Application
_RULE_APP_NO_CALLBACKS = "auth0_application_no_callbacks"
_RULE_APP_MANY_CALLBACKS = "auth0_application_many_callbacks"
_RULE_APP_MANY_ALLOWED_ORIGINS = "auth0_application_many_allowed_origins"
_RULE_APP_OIDC_NON_CONFORMANT = "auth0_application_oidc_non_conformant"
_RULE_APP_WEAK_JWT_ALGORITHM = "auth0_application_weak_jwt_algorithm"
_RULE_REFRESH_TOKEN_ROTATION_DISABLED = "auth0_refresh_token_rotation_disabled"
_RULE_REFRESH_TOKEN_LIFETIME_EXTENDED = "auth0_refresh_token_lifetime_extended"

# Connection
_RULE_CONNECTION_NO_ENABLED_CLIENTS = "auth0_connection_no_enabled_clients"
_RULE_CONNECTION_WEAK_PASSWORD_POLICY = "auth0_connection_weak_password_policy"

# Resource server
_RULE_RS_OFFLINE_ACCESS_ENABLED = "auth0_resource_server_offline_access_enabled"
_RULE_RS_TOKEN_LIFETIME_EXTENDED = "auth0_resource_server_token_lifetime_extended"
_RULE_RS_RBAC_DISABLED = "auth0_resource_server_rbac_disabled"

# Rule
_RULE_RULE_DISABLED = "auth0_rule_disabled"
_RULE_RULE_LARGE_SCRIPT = "auth0_rule_large_script"

# Action
_RULE_ACTION_NOT_DEPLOYED = "auth0_action_not_deployed"
_RULE_ACTION_SECRETS_PRESENT = "auth0_action_secrets_present"

# MFA factor
_RULE_MFA_FACTOR_DISABLED = "auth0_mfa_factor_disabled"

# Custom domain
_RULE_CUSTOM_DOMAIN_NOT_READY = "auth0_custom_domain_not_ready"
_RULE_CUSTOM_DOMAIN_WEAK_TLS_POLICY = "auth0_custom_domain_weak_tls_policy"

AUTH0_RULE_KEYS: frozenset[str] = frozenset({
    # Tenant settings (M81B)
    _RULE_TENANT_SESSION_LIFETIME_EXTENDED,
    _RULE_TENANT_IDLE_SESSION_LIFETIME_EXTENDED,
    _RULE_TENANT_DYNAMIC_CLIENT_REGISTRATION_ENABLED,
    # Application (M81B)
    _RULE_APP_NO_CALLBACKS,
    _RULE_APP_MANY_CALLBACKS,
    _RULE_APP_MANY_ALLOWED_ORIGINS,
    _RULE_APP_OIDC_NON_CONFORMANT,
    _RULE_APP_WEAK_JWT_ALGORITHM,
    _RULE_REFRESH_TOKEN_ROTATION_DISABLED,
    _RULE_REFRESH_TOKEN_LIFETIME_EXTENDED,
    # Connection (M81B)
    _RULE_CONNECTION_NO_ENABLED_CLIENTS,
    _RULE_CONNECTION_WEAK_PASSWORD_POLICY,
    # Resource server (M81B)
    _RULE_RS_OFFLINE_ACCESS_ENABLED,
    _RULE_RS_TOKEN_LIFETIME_EXTENDED,
    _RULE_RS_RBAC_DISABLED,
    # Rule (M81B)
    _RULE_RULE_DISABLED,
    _RULE_RULE_LARGE_SCRIPT,
    # Action (M81B)
    _RULE_ACTION_NOT_DEPLOYED,
    _RULE_ACTION_SECRETS_PRESENT,
    # MFA factor (M81B)
    _RULE_MFA_FACTOR_DISABLED,
    # Custom domain (M81B)
    _RULE_CUSTOM_DOMAIN_NOT_READY,
    _RULE_CUSTOM_DOMAIN_WEAK_TLS_POLICY,
})

# Web-based application types for which missing callbacks are noteworthy.
_WEB_APP_TYPES = frozenset({"spa", "regular_web"})

# Callback count threshold above which the surface is considered broad.
_MANY_CALLBACKS_THRESHOLD = 10

# Origins count threshold (allowed_origins_count + web_origins_count).
_MANY_ORIGINS_THRESHOLD = 10

# JWT algorithms that use symmetric signing (client must share the secret).
_WEAK_JWT_ALGS = frozenset({"HS256", "HS384", "HS512", "none"})

# Password policy categories considered weak for database connections.
_WEAK_PASSWORD_POLICIES = frozenset({"none", "low", "fair"})

# MFA factor names considered strong second factors worth monitoring.
_STRONG_MFA_FACTORS = frozenset({"otp", "webauthn-roaming", "push-notification"})

# Custom domain statuses that indicate the domain is not yet operational.
_NOT_READY_STATUSES = frozenset({"pending_verification", "provisioning", "disabled"})

# TLS policy categories that indicate legacy/weaker TLS configuration.
_WEAK_TLS_POLICIES = frozenset({"compatible"})

# Action statuses that indicate the action has never been successfully built/deployed.
_NOT_BUILT_STATUSES = frozenset({"failed", "building", "retrying", "waiting", "packaged"})


# ── Helpers ────────────────────────────────────────────────────────────────────


def _int(record: dict[str, Any], key: str, default: int = 0) -> int:
    val = record.get(key)
    if isinstance(val, int) and not isinstance(val, bool):
        return val
    return default


def _bool_field(record: dict[str, Any], key: str) -> bool:
    """Read a boolean field from a normalized record (False if missing or not bool)."""
    val = record.get(key)
    return bool(val) if isinstance(val, bool) else False


# ── Tenant settings evaluator ─────────────────────────────────────────────────


def _eval_tenant_settings(record: dict[str, Any]) -> list[FindingCandidate]:
    record_id = get_str(record, "record_id") or "auth0_tenant_settings_main"
    findings: list[FindingCandidate] = []

    # ── auth0_tenant_session_lifetime_extended ────────────────────────────────
    session_cat = get_str(record, "session_lifetime_category")
    if session_cat == "extended":
        findings.append(FindingCandidate(
            provider="auth0",
            rule_key=_RULE_TENANT_SESSION_LIFETIME_EXTENDED,
            finding_key=make_finding_key(_RULE_TENANT_SESSION_LIFETIME_EXTENDED, record_id),
            severity="medium",
            title="Auth0 tenant login session lifetime is extended",
            description=(
                "The Auth0 tenant is configured with an extended login session lifetime "
                "(greater than 7 days). Extended session lifetimes may increase the window "
                "during which a session can be used without re-authentication and may "
                "require review for your organization's access-management policy. "
                "This is configuration metadata — it does not confirm unauthorized access."
            ),
            evidence={
                "rule": _RULE_TENANT_SESSION_LIFETIME_EXTENDED,
                "session_lifetime_category": session_cat,
            },
            remediation={
                "summary": "Review and reduce the login session lifetime in the Auth0 Dashboard.",
                "steps": [
                    "Sign in to the Auth0 Dashboard.",
                    "Navigate to Settings > Tenant Settings > Advanced.",
                    "Review the Login Session Lifetime and reduce it to match your "
                    "organization's access-management policy (e.g. 1–7 days).",
                ],
            },
            record_id=record_id,
        ))

    # ── auth0_tenant_idle_session_lifetime_extended ───────────────────────────
    idle_cat = get_str(record, "idle_session_lifetime_category")
    if idle_cat == "extended":
        findings.append(FindingCandidate(
            provider="auth0",
            rule_key=_RULE_TENANT_IDLE_SESSION_LIFETIME_EXTENDED,
            finding_key=make_finding_key(_RULE_TENANT_IDLE_SESSION_LIFETIME_EXTENDED, record_id),
            severity="low",
            title="Auth0 tenant idle session lifetime is extended",
            description=(
                "The Auth0 tenant is configured with an extended idle session lifetime "
                "(greater than 7 days). Idle sessions that persist for an extended period "
                "without activity may warrant review for alignment with your access-management "
                "policy. This is configuration metadata — it does not confirm unauthorized access."
            ),
            evidence={
                "rule": _RULE_TENANT_IDLE_SESSION_LIFETIME_EXTENDED,
                "idle_session_lifetime_category": idle_cat,
            },
            remediation={
                "summary": "Review and reduce the idle session lifetime in the Auth0 Dashboard.",
                "steps": [
                    "Sign in to the Auth0 Dashboard.",
                    "Navigate to Settings > Tenant Settings > Advanced.",
                    "Review the Idle Session Lifetime and reduce it to match your "
                    "organization's policy (e.g. 1–3 days idle timeout).",
                ],
            },
            record_id=record_id,
        ))

    # ── auth0_tenant_dynamic_client_registration_enabled ─────────────────────
    if _bool_field(record, "flag_enable_dynamic_client_registration"):
        findings.append(FindingCandidate(
            provider="auth0",
            rule_key=_RULE_TENANT_DYNAMIC_CLIENT_REGISTRATION_ENABLED,
            finding_key=make_finding_key(
                _RULE_TENANT_DYNAMIC_CLIENT_REGISTRATION_ENABLED, record_id
            ),
            severity="high",
            title="Auth0 tenant has dynamic client registration enabled",
            description=(
                "The Auth0 tenant has the dynamic client registration flag enabled. Dynamic "
                "client registration (RFC 7591) allows external parties to register OAuth "
                "clients programmatically without pre-approval. This capability may broaden "
                "the tenant's OAuth client surface and may require review to confirm the "
                "configuration is intentional and access is appropriately restricted. "
                "This is configuration metadata — it does not confirm misuse or unauthorized access."
            ),
            evidence={
                "rule": _RULE_TENANT_DYNAMIC_CLIENT_REGISTRATION_ENABLED,
                "flag_enable_dynamic_client_registration": True,
            },
            remediation={
                "summary": "Review the dynamic client registration setting in the Auth0 Dashboard.",
                "steps": [
                    "Sign in to the Auth0 Dashboard.",
                    "Navigate to Settings > Advanced.",
                    "Review whether dynamic client registration is required for your use case.",
                    "If not required, disable this flag to prevent unapproved client registrations.",
                ],
            },
            record_id=record_id,
        ))

    return findings


# ── Application evaluator ─────────────────────────────────────────────────────


def _eval_application(record: dict[str, Any]) -> list[FindingCandidate]:
    record_id = get_str(record, "client_id") or get_str(record, "record_id")
    app_name = get_str(record, "name")
    app_type = get_str(record, "app_type")
    findings: list[FindingCandidate] = []

    callbacks_count = _int(record, "callbacks_count")
    allowed_origins_count = _int(record, "allowed_origins_count")
    web_origins_count = _int(record, "web_origins_count")
    jwt_alg = get_str(record, "jwt_alg")
    grant_types_summary = get_str(record, "grant_types_summary")
    refresh_token_lifetime_cat = get_str(record, "refresh_token_lifetime_category")

    # ── auth0_application_no_callbacks ────────────────────────────────────────
    # Only flag web-based apps where missing callbacks is notable.
    if app_type in _WEB_APP_TYPES and callbacks_count == 0:
        findings.append(FindingCandidate(
            provider="auth0",
            rule_key=_RULE_APP_NO_CALLBACKS,
            finding_key=make_finding_key(_RULE_APP_NO_CALLBACKS, record_id),
            severity="low",
            title="Auth0 application has no configured callback URLs",
            description=(
                f"The Auth0 application '{app_name}' (type: {app_type}) has no callback "
                "URLs configured. Web-based applications typically require at least one "
                "callback URL for the OAuth authorization flow to redirect authenticated "
                "users. This configuration may require review. Callback URL count is "
                "stored as a number — raw URLs are never stored."
            ),
            evidence={
                "rule": _RULE_APP_NO_CALLBACKS,
                "client_id": record_id,
                "name": app_name,
                "app_type": app_type,
                "callbacks_count": callbacks_count,
            },
            remediation={
                "summary": "Configure at least one callback URL for this application.",
                "steps": [
                    "Sign in to the Auth0 Dashboard.",
                    "Navigate to Applications > Applications and select the application.",
                    "Under Settings, add the appropriate Allowed Callback URLs for your deployment.",
                ],
            },
            record_id=record_id,
        ))

    # ── auth0_application_many_callbacks ─────────────────────────────────────
    if callbacks_count > _MANY_CALLBACKS_THRESHOLD:
        findings.append(FindingCandidate(
            provider="auth0",
            rule_key=_RULE_APP_MANY_CALLBACKS,
            finding_key=make_finding_key(_RULE_APP_MANY_CALLBACKS, record_id),
            severity="medium",
            title="Auth0 application has a large number of callback URLs",
            description=(
                f"The Auth0 application '{app_name}' has {callbacks_count} callback URLs "
                f"configured (threshold: {_MANY_CALLBACKS_THRESHOLD}). A large callback "
                "surface increases the set of redirect destinations that Auth0 will accept "
                "after authentication and may require review for any stale or unintended "
                "entries. Callback URL count is stored as a number — raw URLs are never stored."
            ),
            evidence={
                "rule": _RULE_APP_MANY_CALLBACKS,
                "client_id": record_id,
                "name": app_name,
                "app_type": app_type,
                "callbacks_count": callbacks_count,
            },
            remediation={
                "summary": "Review and prune stale or unintended callback URLs.",
                "steps": [
                    "Sign in to the Auth0 Dashboard.",
                    "Navigate to Applications > Applications and select the application.",
                    "Review the Allowed Callback URLs list and remove any stale, "
                    "test, or non-production entries.",
                ],
            },
            record_id=record_id,
        ))

    # ── auth0_application_many_allowed_origins ────────────────────────────────
    total_origins = allowed_origins_count + web_origins_count
    if total_origins > _MANY_ORIGINS_THRESHOLD:
        findings.append(FindingCandidate(
            provider="auth0",
            rule_key=_RULE_APP_MANY_ALLOWED_ORIGINS,
            finding_key=make_finding_key(_RULE_APP_MANY_ALLOWED_ORIGINS, record_id),
            severity="medium",
            title="Auth0 application has a large number of allowed origins",
            description=(
                f"The Auth0 application '{app_name}' has {total_origins} allowed/web origins "
                f"configured (allowed_origins: {allowed_origins_count}, web_origins: "
                f"{web_origins_count}; threshold: {_MANY_ORIGINS_THRESHOLD}). A large origin "
                "surface increases the set of domains permitted to make cross-origin requests "
                "and may require review. Origin counts are stored as numbers — raw origin "
                "URLs are never stored."
            ),
            evidence={
                "rule": _RULE_APP_MANY_ALLOWED_ORIGINS,
                "client_id": record_id,
                "name": app_name,
                "allowed_origins_count": allowed_origins_count,
                "web_origins_count": web_origins_count,
            },
            remediation={
                "summary": "Review and prune stale or unintended allowed/web origins.",
                "steps": [
                    "Sign in to the Auth0 Dashboard.",
                    "Navigate to Applications > Applications and select the application.",
                    "Review the Allowed Web Origins and Allowed Origins lists.",
                    "Remove stale, test, or non-production entries.",
                ],
            },
            record_id=record_id,
        ))

    # ── auth0_application_oidc_non_conformant ─────────────────────────────────
    if record.get("oidc_conformant") is False:
        findings.append(FindingCandidate(
            provider="auth0",
            rule_key=_RULE_APP_OIDC_NON_CONFORMANT,
            finding_key=make_finding_key(_RULE_APP_OIDC_NON_CONFORMANT, record_id),
            severity="medium",
            title="Auth0 application is not OIDC conformant",
            description=(
                f"The Auth0 application '{app_name}' has OIDC conformance disabled. "
                "Non-OIDC-conformant applications use a legacy Auth0 authentication pipeline "
                "that may not support the latest OAuth 2.0 / OpenID Connect features and "
                "security improvements. Migration to OIDC-conformant mode may require review."
            ),
            evidence={
                "rule": _RULE_APP_OIDC_NON_CONFORMANT,
                "client_id": record_id,
                "name": app_name,
                "app_type": app_type,
                "oidc_conformant": False,
            },
            remediation={
                "summary": "Enable OIDC conformance for this application.",
                "steps": [
                    "Sign in to the Auth0 Dashboard.",
                    "Navigate to Applications > Applications and select the application.",
                    "Under Settings > Advanced Settings > OAuth, enable OIDC Conformant.",
                    "Test your integration after enabling, as token format and flows may change.",
                ],
            },
            record_id=record_id,
        ))

    # ── auth0_application_weak_jwt_algorithm ──────────────────────────────────
    if jwt_alg and jwt_alg in _WEAK_JWT_ALGS:
        findings.append(FindingCandidate(
            provider="auth0",
            rule_key=_RULE_APP_WEAK_JWT_ALGORITHM,
            finding_key=make_finding_key(_RULE_APP_WEAK_JWT_ALGORITHM, record_id),
            severity="high",
            title="Auth0 application uses a symmetric JWT signing algorithm",
            description=(
                f"The Auth0 application '{app_name}' is configured to use {jwt_alg} for "
                "JWT signing. Symmetric HMAC algorithms require the signing secret to be "
                "shared with the application for token verification, broadening the secret "
                "surface compared to asymmetric algorithms (RS256, PS256). Consider "
                "migrating to RS256 or PS256 to reduce signing-secret exposure. "
                "No signing keys are ever stored by ConfigTrace."
            ),
            evidence={
                "rule": _RULE_APP_WEAK_JWT_ALGORITHM,
                "client_id": record_id,
                "name": app_name,
                "jwt_alg": jwt_alg,
            },
            remediation={
                "summary": "Switch this application's JWT signing algorithm to RS256 or PS256.",
                "steps": [
                    "Sign in to the Auth0 Dashboard.",
                    "Navigate to Applications > Applications and select the application.",
                    "Under Settings > Advanced Settings > OAuth, change the JsonWebToken "
                    "Signature Algorithm to RS256.",
                    "Update your application's token verification to use Auth0's public key "
                    "(available from .well-known/jwks.json) instead of the shared client secret.",
                ],
            },
            record_id=record_id,
        ))

    # ── auth0_refresh_token_rotation_disabled ─────────────────────────────────
    # Only relevant when the application has refresh-token capability.
    has_refresh_token_grant = "refresh_token" in grant_types_summary.lower()
    if has_refresh_token_grant and record.get("refresh_token_rotation_enabled") is False:
        findings.append(FindingCandidate(
            provider="auth0",
            rule_key=_RULE_REFRESH_TOKEN_ROTATION_DISABLED,
            finding_key=make_finding_key(_RULE_REFRESH_TOKEN_ROTATION_DISABLED, record_id),
            severity="medium",
            title="Auth0 application has refresh token rotation disabled",
            description=(
                f"The Auth0 application '{app_name}' issues refresh tokens (grant_types "
                f"includes refresh_token) but does not have refresh token rotation enabled. "
                "Without rotation, a compromised refresh token remains valid indefinitely "
                "until explicitly revoked. Rotating refresh tokens on use limits the "
                "validity window of any leaked token. "
                "This is configuration metadata — it does not confirm any token was exposed."
            ),
            evidence={
                "rule": _RULE_REFRESH_TOKEN_ROTATION_DISABLED,
                "client_id": record_id,
                "name": app_name,
                "refresh_token_rotation_enabled": False,
                "grant_types_summary": grant_types_summary,
            },
            remediation={
                "summary": "Enable refresh token rotation for this application.",
                "steps": [
                    "Sign in to the Auth0 Dashboard.",
                    "Navigate to Applications > Applications and select the application.",
                    "Under Settings > Refresh Token Rotation, enable rotation.",
                    "Set an appropriate rotation interval and reuse interval for your use case.",
                ],
            },
            record_id=record_id,
        ))

    # ── auth0_refresh_token_lifetime_extended ─────────────────────────────────
    if refresh_token_lifetime_cat == "extended":
        findings.append(FindingCandidate(
            provider="auth0",
            rule_key=_RULE_REFRESH_TOKEN_LIFETIME_EXTENDED,
            finding_key=make_finding_key(_RULE_REFRESH_TOKEN_LIFETIME_EXTENDED, record_id),
            severity="medium",
            title="Auth0 application refresh token lifetime is extended",
            description=(
                f"The Auth0 application '{app_name}' has an extended refresh token "
                "lifetime (greater than 24 hours). Long-lived refresh tokens extend the "
                "window during which a token could be used if obtained by an unauthorized "
                "party and may require review for alignment with your token lifecycle policy. "
                "This is configuration metadata — it does not confirm any token was exposed."
            ),
            evidence={
                "rule": _RULE_REFRESH_TOKEN_LIFETIME_EXTENDED,
                "client_id": record_id,
                "name": app_name,
                "refresh_token_lifetime_category": refresh_token_lifetime_cat,
            },
            remediation={
                "summary": "Review and reduce the refresh token lifetime for this application.",
                "steps": [
                    "Sign in to the Auth0 Dashboard.",
                    "Navigate to Applications > Applications and select the application.",
                    "Under Settings > Refresh Token Expiration, review the absolute lifetime.",
                    "Reduce to match your token lifecycle policy (typically ≤ 24 hours for "
                    "sensitive contexts).",
                ],
            },
            record_id=record_id,
        ))

    return findings


# ── Connection evaluator ──────────────────────────────────────────────────────


def _eval_connection(record: dict[str, Any]) -> list[FindingCandidate]:
    record_id = get_str(record, "connection_id") or get_str(record, "record_id")
    conn_name = get_str(record, "name")
    strategy = get_str(record, "strategy")
    findings: list[FindingCandidate] = []

    enabled_clients_count = _int(record, "enabled_clients_count")

    # ── auth0_connection_no_enabled_clients ───────────────────────────────────
    if enabled_clients_count == 0:
        findings.append(FindingCandidate(
            provider="auth0",
            rule_key=_RULE_CONNECTION_NO_ENABLED_CLIENTS,
            finding_key=make_finding_key(_RULE_CONNECTION_NO_ENABLED_CLIENTS, record_id),
            severity="low",
            title="Auth0 connection has no enabled client applications",
            description=(
                f"The Auth0 connection '{conn_name}' (strategy: {strategy}) has no enabled "
                "client applications. A connection without enabled clients cannot be used for "
                "authentication. This may indicate a stale or inactive connection that may "
                "warrant review or cleanup."
            ),
            evidence={
                "rule": _RULE_CONNECTION_NO_ENABLED_CLIENTS,
                "connection_id": record_id,
                "name": conn_name,
                "strategy": strategy,
                "enabled_clients_count": enabled_clients_count,
            },
            remediation={
                "summary": "Review whether this connection is still needed.",
                "steps": [
                    "Sign in to the Auth0 Dashboard.",
                    "Navigate to Authentication > Database (or Social/Enterprise) and "
                    "select the connection.",
                    "Check if the connection is intentionally disabled or is stale.",
                    "Either enable it for the appropriate applications or remove it if unused.",
                ],
            },
            record_id=record_id,
        ))

    # ── auth0_connection_weak_password_policy ─────────────────────────────────
    # Only applies to Auth0 database connections (strategy == "auth0").
    if strategy == "auth0":
        pw_policy = record.get("password_policy_category")
        # Fire on weak categories, or when policy is None (unset/unconfigured)
        if pw_policy is None or (isinstance(pw_policy, str) and pw_policy.lower() in _WEAK_PASSWORD_POLICIES):
            policy_display = pw_policy if pw_policy else "not configured"
            findings.append(FindingCandidate(
                provider="auth0",
                rule_key=_RULE_CONNECTION_WEAK_PASSWORD_POLICY,
                finding_key=make_finding_key(_RULE_CONNECTION_WEAK_PASSWORD_POLICY, record_id),
                severity="high",
                title="Auth0 database connection has a weak or unconfigured password policy",
                description=(
                    f"The Auth0 database connection '{conn_name}' has a password policy "
                    f"category of '{policy_display}'. Weak or unconfigured password policies "
                    "may allow low-complexity passwords that are easier to guess or brute-force. "
                    "A 'good' or 'excellent' policy is recommended for production database "
                    "connections. This is configuration metadata only."
                ),
                evidence={
                    "rule": _RULE_CONNECTION_WEAK_PASSWORD_POLICY,
                    "connection_id": record_id,
                    "name": conn_name,
                    "strategy": strategy,
                    "password_policy_category": pw_policy,
                },
                remediation={
                    "summary": "Upgrade the password policy to 'good' or 'excellent'.",
                    "steps": [
                        "Sign in to the Auth0 Dashboard.",
                        "Navigate to Authentication > Database and select the connection.",
                        "Under Password Policy, set the policy to 'Good' or 'Excellent'.",
                        "Review the policy requirements and communicate changes to users "
                        "if a password reset is required.",
                    ],
                },
                record_id=record_id,
            ))

    return findings


# ── Resource server evaluator ─────────────────────────────────────────────────


def _eval_resource_server(record: dict[str, Any]) -> list[FindingCandidate]:
    record_id = get_str(record, "resource_server_id") or get_str(record, "record_id")
    rs_name = get_str(record, "name")
    findings: list[FindingCandidate] = []

    # ── auth0_resource_server_offline_access_enabled ──────────────────────────
    if _bool_field(record, "allow_offline_access"):
        findings.append(FindingCandidate(
            provider="auth0",
            rule_key=_RULE_RS_OFFLINE_ACCESS_ENABLED,
            finding_key=make_finding_key(_RULE_RS_OFFLINE_ACCESS_ENABLED, record_id),
            severity="medium",
            title="Auth0 API allows offline access (refresh tokens)",
            description=(
                f"The Auth0 resource server '{rs_name}' has offline access enabled, "
                "meaning applications can request refresh tokens (the offline_access scope) "
                "that persist beyond the active session. Offline access broadens the token "
                "footprint and may require review to confirm it is needed for all consumers "
                "of this API. This is configuration metadata only."
            ),
            evidence={
                "rule": _RULE_RS_OFFLINE_ACCESS_ENABLED,
                "resource_server_id": record_id,
                "name": rs_name,
                "allow_offline_access": True,
            },
            remediation={
                "summary": "Review whether offline access is required for this API.",
                "steps": [
                    "Sign in to the Auth0 Dashboard.",
                    "Navigate to Applications > APIs and select the resource server.",
                    "Under Settings, review the Allow Offline Access toggle.",
                    "Disable offline access if refresh tokens are not required for this API.",
                ],
            },
            record_id=record_id,
        ))

    # ── auth0_resource_server_token_lifetime_extended ─────────────────────────
    token_cat = get_str(record, "token_lifetime_category")
    if token_cat == "extended":
        findings.append(FindingCandidate(
            provider="auth0",
            rule_key=_RULE_RS_TOKEN_LIFETIME_EXTENDED,
            finding_key=make_finding_key(_RULE_RS_TOKEN_LIFETIME_EXTENDED, record_id),
            severity="medium",
            title="Auth0 API access token lifetime is extended",
            description=(
                f"The Auth0 resource server '{rs_name}' has an extended access token "
                "lifetime (greater than 24 hours). Long-lived access tokens extend the "
                "period during which a token is valid and increase the impact window "
                "if the token requires review or rotation. Short-lived tokens (15 minutes "
                "to 1 hour) are recommended for production APIs. "
                "This is configuration metadata only."
            ),
            evidence={
                "rule": _RULE_RS_TOKEN_LIFETIME_EXTENDED,
                "resource_server_id": record_id,
                "name": rs_name,
                "token_lifetime_category": token_cat,
            },
            remediation={
                "summary": "Reduce the access token lifetime for this API.",
                "steps": [
                    "Sign in to the Auth0 Dashboard.",
                    "Navigate to Applications > APIs and select the resource server.",
                    "Under Settings, reduce the Token Expiration to ≤ 3600 seconds (1 hour) "
                    "for sensitive APIs or to match your security policy.",
                ],
            },
            record_id=record_id,
        ))

    # ── auth0_resource_server_rbac_disabled ───────────────────────────────────
    if record.get("rbac_enabled") is False:
        findings.append(FindingCandidate(
            provider="auth0",
            rule_key=_RULE_RS_RBAC_DISABLED,
            finding_key=make_finding_key(_RULE_RS_RBAC_DISABLED, record_id),
            severity="medium",
            title="Auth0 API does not enforce RBAC policies",
            description=(
                f"The Auth0 resource server '{rs_name}' does not enforce RBAC policies "
                "(enforce_policies is disabled). Without RBAC enforcement, access control "
                "based on permissions and roles is not applied to tokens for this API, "
                "which may broaden the access surface beyond what individual callers require. "
                "This is configuration metadata only."
            ),
            evidence={
                "rule": _RULE_RS_RBAC_DISABLED,
                "resource_server_id": record_id,
                "name": rs_name,
                "rbac_enabled": False,
            },
            remediation={
                "summary": "Enable RBAC enforcement for this API.",
                "steps": [
                    "Sign in to the Auth0 Dashboard.",
                    "Navigate to Applications > APIs and select the resource server.",
                    "Under Settings > RBAC Settings, enable 'Enable RBAC' and "
                    "'Add Permissions in the Access Token'.",
                    "Define permissions for the API and assign them to roles as appropriate.",
                ],
            },
            record_id=record_id,
        ))

    return findings


# ── Rule evaluator ────────────────────────────────────────────────────────────


def _eval_rule(record: dict[str, Any]) -> list[FindingCandidate]:
    record_id = get_str(record, "rule_id") or get_str(record, "record_id")
    rule_name = get_str(record, "name")
    findings: list[FindingCandidate] = []

    # ── auth0_rule_disabled ───────────────────────────────────────────────────
    # Only flag when a rule has script content but is not enabled.
    if record.get("enabled") is False and _bool_field(record, "script_present"):
        findings.append(FindingCandidate(
            provider="auth0",
            rule_key=_RULE_RULE_DISABLED,
            finding_key=make_finding_key(_RULE_RULE_DISABLED, record_id),
            severity="low",
            title="Auth0 rule has a script but is disabled",
            description=(
                f"The Auth0 rule '{rule_name}' has script content configured but the rule "
                "is currently disabled and will not execute during the authentication pipeline. "
                "A disabled rule with an existing script may indicate automation that was "
                "intentionally or unintentionally paused and may warrant review. "
                "Rule script content is never stored by ConfigTrace."
            ),
            evidence={
                "rule": _RULE_RULE_DISABLED,
                "rule_id": record_id,
                "name": rule_name,
                "enabled": False,
                "script_present": True,
                "stage": get_str(record, "stage"),
            },
            remediation={
                "summary": "Review whether this rule should remain disabled.",
                "steps": [
                    "Sign in to the Auth0 Dashboard.",
                    "Navigate to Auth Pipeline > Rules and select the rule.",
                    "Determine whether the rule should be re-enabled or permanently removed.",
                    "Remove unused rules to reduce the attack surface of the pipeline.",
                ],
            },
            record_id=record_id,
        ))

    # ── auth0_rule_large_script ───────────────────────────────────────────────
    script_len_cat = get_str(record, "script_length_category")
    if script_len_cat == "long":
        findings.append(FindingCandidate(
            provider="auth0",
            rule_key=_RULE_RULE_LARGE_SCRIPT,
            finding_key=make_finding_key(_RULE_RULE_LARGE_SCRIPT, record_id),
            severity="low",
            title="Auth0 rule has a large script",
            description=(
                f"The Auth0 rule '{rule_name}' has a large script (greater than 2,000 "
                "characters). Large rule scripts can be harder to review, audit, and "
                "maintain. Consider refactoring into smaller rules or migrating to "
                "Auth0 Actions. Rule script content is never stored by ConfigTrace."
            ),
            evidence={
                "rule": _RULE_RULE_LARGE_SCRIPT,
                "rule_id": record_id,
                "name": rule_name,
                "script_length_category": script_len_cat,
                "stage": get_str(record, "stage"),
            },
            remediation={
                "summary": "Refactor large rules for maintainability.",
                "steps": [
                    "Sign in to the Auth0 Dashboard.",
                    "Navigate to Auth Pipeline > Rules and review the rule's script.",
                    "Consider breaking the logic into multiple focused rules or migrating "
                    "to Auth0 Actions (the modern replacement for Rules).",
                ],
            },
            record_id=record_id,
        ))

    return findings


# ── Action evaluator ──────────────────────────────────────────────────────────


def _eval_action(record: dict[str, Any]) -> list[FindingCandidate]:
    record_id = get_str(record, "action_id") or get_str(record, "record_id")
    action_name = get_str(record, "name")
    action_status = get_str(record, "status")
    findings: list[FindingCandidate] = []

    # ── auth0_action_not_deployed ─────────────────────────────────────────────
    if not _bool_field(record, "deployed_version_present"):
        findings.append(FindingCandidate(
            provider="auth0",
            rule_key=_RULE_ACTION_NOT_DEPLOYED,
            finding_key=make_finding_key(_RULE_ACTION_NOT_DEPLOYED, record_id),
            severity="low",
            title="Auth0 action has no deployed version",
            description=(
                f"The Auth0 action '{action_name}' has no deployed version. Actions must "
                "be deployed to be active in the authentication pipeline. An action without "
                "a deployed version is not currently executing and may indicate an action "
                "that was created but never deployed, or was undeployed."
            ),
            evidence={
                "rule": _RULE_ACTION_NOT_DEPLOYED,
                "action_id": record_id,
                "name": action_name,
                "status": action_status,
                "deployed_version_present": False,
                "trigger_id": get_str(record, "trigger_id"),
            },
            remediation={
                "summary": "Deploy this action or remove it if it is no longer needed.",
                "steps": [
                    "Sign in to the Auth0 Dashboard.",
                    "Navigate to Auth Pipeline > Actions > Library and select the action.",
                    "Deploy the action if it is ready, or delete it if it is no longer "
                    "needed to keep the action library clean.",
                ],
            },
            record_id=record_id,
        ))

    # ── auth0_action_secrets_present ──────────────────────────────────────────
    secrets_count = _int(record, "secrets_count")
    if secrets_count > 0:
        findings.append(FindingCandidate(
            provider="auth0",
            rule_key=_RULE_ACTION_SECRETS_PRESENT,
            finding_key=make_finding_key(_RULE_ACTION_SECRETS_PRESENT, record_id),
            severity="low",
            title="Auth0 action has secrets configured",
            description=(
                f"The Auth0 action '{action_name}' has {secrets_count} secret(s) configured. "
                "Action secrets are credentials (such as API keys or tokens) stored in Auth0 "
                "for use within the action's code. These secrets represent a credential surface "
                "that may require periodic review, rotation, and access-control validation. "
                "Secret names and values are never stored by ConfigTrace."
            ),
            evidence={
                "rule": _RULE_ACTION_SECRETS_PRESENT,
                "action_id": record_id,
                "name": action_name,
                "secrets_count": secrets_count,
            },
            remediation={
                "summary": "Review and rotate action secrets periodically.",
                "steps": [
                    "Sign in to the Auth0 Dashboard.",
                    "Navigate to Auth Pipeline > Actions > Library and select the action.",
                    "Review the configured secrets. Remove any that are no longer needed.",
                    "Rotate secrets according to your organization's credential rotation policy.",
                ],
            },
            record_id=record_id,
        ))

    return findings


# ── MFA factor evaluator ──────────────────────────────────────────────────────


def _eval_mfa_factor(record: dict[str, Any]) -> list[FindingCandidate]:
    record_id = get_str(record, "record_id") or f"auth0_mfa_factor_{get_str(record, 'factor_name')}"
    factor_name = get_str(record, "factor_name")
    findings: list[FindingCandidate] = []

    # ── auth0_mfa_factor_disabled ─────────────────────────────────────────────
    # Only flag strong second factors that are disabled.
    if factor_name in _STRONG_MFA_FACTORS and record.get("enabled") is False:
        friendly = {
            "otp": "TOTP (authenticator app)",
            "webauthn-roaming": "WebAuthn / hardware security key",
            "push-notification": "Push notification",
        }.get(factor_name, factor_name)

        findings.append(FindingCandidate(
            provider="auth0",
            rule_key=_RULE_MFA_FACTOR_DISABLED,
            finding_key=make_finding_key(_RULE_MFA_FACTOR_DISABLED, record_id),
            severity="medium",
            title=f"Auth0 strong MFA factor is disabled: {friendly}",
            description=(
                f"The Auth0 Guardian / MFA factor '{factor_name}' ({friendly}) is currently "
                "disabled. This factor is a strong second-factor option that provides "
                "phishing-resistant or time-based authentication. Disabling strong factors "
                "may limit users' ability to enroll in robust MFA and may warrant review "
                "if other strong factors are also unavailable. "
                "No enrollment data, recovery codes, or user-level factor status is stored."
            ),
            evidence={
                "rule": _RULE_MFA_FACTOR_DISABLED,
                "factor_name": factor_name,
                "enabled": False,
                "provider_category": get_str(record, "provider_category"),
            },
            remediation={
                "summary": f"Enable the {friendly} MFA factor if it is appropriate for your tenant.",
                "steps": [
                    "Sign in to the Auth0 Dashboard.",
                    "Navigate to Security > Multi-factor Auth.",
                    f"Enable the {friendly} factor.",
                    "Review your MFA policy to ensure users are prompted at appropriate points "
                    "in the authentication flow.",
                ],
            },
            record_id=record_id,
        ))

    return findings


# ── Custom domain evaluator ───────────────────────────────────────────────────


def _eval_custom_domain(record: dict[str, Any]) -> list[FindingCandidate]:
    record_id = get_str(record, "custom_domain_id") or get_str(record, "record_id")
    findings: list[FindingCandidate] = []

    # ── auth0_custom_domain_not_ready ─────────────────────────────────────────
    domain_status = get_str(record, "status")
    if domain_status and domain_status in _NOT_READY_STATUSES:
        findings.append(FindingCandidate(
            provider="auth0",
            rule_key=_RULE_CUSTOM_DOMAIN_NOT_READY,
            finding_key=make_finding_key(_RULE_CUSTOM_DOMAIN_NOT_READY, record_id),
            severity="medium",
            title="Auth0 custom domain is not in a ready state",
            description=(
                f"An Auth0 custom domain is in the '{domain_status}' state rather than "
                "'ready'. A non-ready custom domain may indicate pending DNS verification, "
                "a provisioning issue, or a disabled state. Users may be redirected to the "
                "default Auth0 domain for authentication if the custom domain is not "
                "operational. Custom domain name strings are never stored by ConfigTrace."
            ),
            evidence={
                "rule": _RULE_CUSTOM_DOMAIN_NOT_READY,
                "custom_domain_id": record_id,
                "status": domain_status,
                "type": get_str(record, "type"),
                "primary": _bool_field(record, "primary"),
            },
            remediation={
                "summary": "Resolve the custom domain configuration issue.",
                "steps": [
                    "Sign in to the Auth0 Dashboard.",
                    "Navigate to Branding > Custom Domains.",
                    "Check the domain status and complete any pending DNS verification steps.",
                    "If the domain should be removed, delete it to avoid confusion.",
                ],
            },
            record_id=record_id,
        ))

    # ── auth0_custom_domain_weak_tls_policy ───────────────────────────────────
    tls_policy = get_str(record, "tls_policy_category")
    if tls_policy in _WEAK_TLS_POLICIES:
        findings.append(FindingCandidate(
            provider="auth0",
            rule_key=_RULE_CUSTOM_DOMAIN_WEAK_TLS_POLICY,
            finding_key=make_finding_key(_RULE_CUSTOM_DOMAIN_WEAK_TLS_POLICY, record_id),
            severity="low",
            title="Auth0 custom domain uses a compatible (non-recommended) TLS policy",
            description=(
                "An Auth0 custom domain is configured with the 'compatible' TLS policy "
                "rather than the 'recommended' policy. The compatible policy supports older "
                "TLS versions and cipher suites, which may allow connections from legacy "
                "clients but may also allow weaker cipher negotiations. The 'recommended' "
                "policy enforces current TLS best practices. "
                "Custom domain name strings are never stored by ConfigTrace."
            ),
            evidence={
                "rule": _RULE_CUSTOM_DOMAIN_WEAK_TLS_POLICY,
                "custom_domain_id": record_id,
                "tls_policy_category": tls_policy,
                "status": domain_status,
            },
            remediation={
                "summary": "Switch this custom domain's TLS policy to 'Recommended'.",
                "steps": [
                    "Sign in to the Auth0 Dashboard.",
                    "Navigate to Branding > Custom Domains and select the domain.",
                    "Change the TLS policy to 'Recommended' to enforce current TLS standards.",
                    "Verify that any legacy clients or integrations still work after the change.",
                ],
            },
            record_id=record_id,
        ))

    return findings


# ── Main dispatch ─────────────────────────────────────────────────────────────


def evaluate(record: dict[str, Any]) -> list[FindingCandidate]:
    """Evaluate one normalized Auth0 drift record and return any findings.

    Accepts any dict. Unknown record_type values return an empty list — never
    raises. Each evaluator is self-contained and never mutates the record.
    """
    if not isinstance(record, dict):
        return []

    rtype = record.get("record_type")

    if rtype == AUTH0_TENANT_SETTINGS:
        return _eval_tenant_settings(record)
    if rtype == AUTH0_APPLICATION:
        return _eval_application(record)
    if rtype == AUTH0_CONNECTION:
        return _eval_connection(record)
    if rtype == AUTH0_RESOURCE_SERVER:
        return _eval_resource_server(record)
    if rtype == AUTH0_RULE:
        return _eval_rule(record)
    if rtype == AUTH0_ACTION:
        return _eval_action(record)
    if rtype == AUTH0_MFA_FACTOR:
        return _eval_mfa_factor(record)
    if rtype == AUTH0_CUSTOM_DOMAIN:
        return _eval_custom_domain(record)

    return []
