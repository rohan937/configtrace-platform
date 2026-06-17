"""Auth0 connector record type constants — M81A.

M81A scope (drift foundation)
------------------------------
Eight safe drift surfaces from the Auth0 Management API v2:

    auth0_tenant_settings   — tenant-level boolean flags and categories
    auth0_application       — application/client metadata (counts and safe fields)
    auth0_connection        — connection strategy and safe posture metadata
    auth0_resource_server   — API/resource server metadata (never audience URI)
    auth0_rule              — rule metadata (never script content)
    auth0_action            — action metadata (never code or secrets)
    auth0_mfa_factor        — Guardian/MFA factor enabled status
    auth0_custom_domain     — custom domain posture (never domain name)

Privacy contract
----------------
SECURITY: in M81A no client_secret, management_api_token, access_token,
refresh_token, ID token, JWT or JWKS material, signing private keys,
authorization headers, raw Auth0 API response, raw callback URLs,
raw logout URLs, raw allowed origins, raw web origins, resource server
identifier (audience URI), custom domain name string, rule or action
script/code content, action secret values, connection credentials,
database passwords, social provider secrets, SAML certificates, private
keys, user emails, user names, user IDs, profile data, identities arrays,
login history, IP addresses, device fingerprints, session data, MFA
enrollment data, MFA recovery codes, or customer PII is ever stored in a
normalised record.

URL fields (callback URLs, logout URLs, allowed origins, web origins) are
stored as integer counts only.  The resource server identifier (audience URI)
is stored as a boolean presence flag only.  Custom domain names are stored as
a boolean presence flag only.  Rule and action script/code are stored as a
boolean presence flag and a length category only — never the content itself.
"""
from __future__ import annotations

from typing import Optional, TypedDict

# ── M81A record type string constants ─────────────────────────────────────────

# Tenant-level configuration posture.
# SECURITY: support_email (full address), support_url, management API JWT,
# error page HTML, device flow config, custom login page HTML, sandbox
# version, and all raw tenant payload fields are NEVER stored.
AUTH0_TENANT_SETTINGS = "auth0_tenant_settings"

# One per Auth0 application / client.
# SECURITY: client_secret, JWKS, raw callback_urls, raw allowed_logout_urls,
# raw allowed_origins, raw web_origins, encryption_key, signing_keys, and
# all raw client config payload are NEVER stored.
AUTH0_APPLICATION = "auth0_application"

# One per Auth0 connection.
# SECURITY: connection credentials (passwords, social provider tokens,
# API keys, SAML certs, private keys), raw options payload, user profile
# data, user emails, user IDs, and domain lists are NEVER stored.
AUTH0_CONNECTION = "auth0_connection"

# One per Auth0 resource server / API.
# SECURITY: identifier (audience URI string), signing_secret, raw scope
# definitions, and all raw resource server payload are NEVER stored.
# identifier_present is a boolean only.
AUTH0_RESOURCE_SERVER = "auth0_resource_server"

# One per Auth0 rule (legacy pipeline).
# SECURITY: rule script content, any URLs or tokens in the script,
# and all raw rule payload are NEVER stored.
# script_present is a boolean; script content is never stored.
AUTH0_RULE = "auth0_rule"

# One per Auth0 action.
# SECURITY: action code, action secret names or values, dependency
# package versions, and all raw action payload are NEVER stored.
# code_present is a boolean; code is never stored.
# secrets_count is an integer count; secret values are never stored.
AUTH0_ACTION = "auth0_action"

# One per Guardian / MFA factor type.
# SECURITY: enrollment data, phone numbers, email addresses, recovery
# codes, user-level factor status, raw provider configs, and trial/billing
# details beyond the trial_expired boolean are NEVER stored.
AUTH0_MFA_FACTOR = "auth0_mfa_factor"

# One per Auth0 custom domain.
# SECURITY: raw domain name string (customer-identifying), verification
# tokens, DNS record values, certificate material, private keys, and
# CNAME targets are NEVER stored. domain_present is a boolean only.
AUTH0_CUSTOM_DOMAIN = "auth0_custom_domain"

# ── Aggregate set ─────────────────────────────────────────────────────────────

AUTH0_RECORD_TYPES: frozenset[str] = frozenset({
    AUTH0_TENANT_SETTINGS,
    AUTH0_APPLICATION,
    AUTH0_CONNECTION,
    AUTH0_RESOURCE_SERVER,
    AUTH0_RULE,
    AUTH0_ACTION,
    AUTH0_MFA_FACTOR,
    AUTH0_CUSTOM_DOMAIN,
})


# ── TypedDicts ────────────────────────────────────────────────────────────────


class Auth0TenantSettingsRecord(TypedDict):
    """Safe normalised record for Auth0 tenant settings (M81A).

    SECURITY: support_email (full), support_url, management API JWT,
    error_page HTML, device_flow, custom_login_page, sandbox_version,
    and all raw settings payload are NEVER stored.
    """

    record_type: str           # always "auth0_tenant_settings"
    record_id: str             # always "auth0_tenant_settings_main"
    provider_resource_id: str  # always "tenants/settings"
    friendly_name_present: bool
    support_email_domain: str   # domain part after @ only — full email NEVER stored
    default_directory_present: bool
    session_lifetime_category: str   # "very_short"/"short"/"standard"/"extended"
    idle_session_lifetime_category: str
    enabled_locales_count: int
    # Safe boolean flags from tenant flags dict
    flag_change_pwd_on_first_login: bool
    flag_enable_client_connections: bool
    flag_enable_apis_section: bool
    flag_enable_pipeline2: bool
    flag_enable_dynamic_client_registration: bool
    flag_enable_custom_domain_in_emails: bool
    flag_universal_login: bool
    flag_enable_legacy_logs_search_v2: bool
    flag_no_disclose_enterprise_connections: bool
    flag_disable_management_api_sms_obfuscation: bool
    flag_enable_adfs_waad_email_verification: bool
    flag_revoke_refresh_token_grant: bool


class Auth0ApplicationRecord(TypedDict):
    """Safe normalised record for an Auth0 application/client (M81A).

    SECURITY: client_secret, JWKS, raw callback_urls, raw allowed_logout_urls,
    raw allowed_origins, raw web_origins, encryption_key, initiate_login_uri,
    and all raw client payload are NEVER stored.
    URLs are stored as integer COUNTS only.
    """

    record_type: str           # always "auth0_application"
    record_id: str             # client_id (opaque Auth0 identifier)
    provider_resource_id: str  # f"clients/{client_id}"
    client_id: str             # opaque Auth0 client identifier
    name: str                  # truncated to 100 chars
    app_type: str              # "spa"/"native"/"regular_web"/"non_interactive"/etc.
    is_first_party: bool
    grant_types_summary: str   # comma-joined grant type names (safe string labels)
    # URL counts only — raw URL strings NEVER stored
    callbacks_count: int
    allowed_logout_urls_count: int
    allowed_origins_count: int
    web_origins_count: int
    jwt_alg: str               # "RS256"/"HS256"/etc. from jwt_configuration
    oidc_conformant: bool
    token_endpoint_auth_method: str  # "client_secret_basic"/"none"/etc.
    refresh_token_rotation_enabled: bool
    refresh_token_lifetime_category: str  # or "not_configured"


class Auth0ConnectionRecord(TypedDict):
    """Safe normalised record for an Auth0 connection (M81A).

    SECURITY: connection options dict (passwords, provider tokens, certs,
    private keys, API keys), raw user data, raw domain lists, and all raw
    connection payload are NEVER stored.
    """

    record_type: str           # always "auth0_connection"
    record_id: str             # connection_id (opaque Auth0 identifier)
    provider_resource_id: str  # f"connections/{connection_id}"
    connection_id: str         # opaque Auth0 connection identifier
    name: str                  # truncated to 100 chars
    strategy: str              # "auth0"/"google-oauth2"/"github"/etc. (safe label)
    enabled_clients_count: int  # number of clients using this connection
    is_domain_connection: bool
    password_policy_category: Optional[str]  # only for auth0 strategy; never raw policy
    mfa_enabled: Optional[bool]              # only for auth0 strategy


class Auth0ResourceServerRecord(TypedDict):
    """Safe normalised record for an Auth0 API / resource server (M81A).

    SECURITY: identifier (audience URI string), signing_secret, raw scope
    definitions with descriptions, and all raw resource server payload are
    NEVER stored. identifier is stored as identifier_present boolean only.
    """

    record_type: str           # always "auth0_resource_server"
    record_id: str             # resource_server_id (opaque Auth0 identifier)
    provider_resource_id: str  # f"resource-servers/{resource_server_id}"
    resource_server_id: str    # opaque Auth0 resource server identifier
    name: str                  # truncated to 100 chars
    identifier_present: bool   # audience URI presence — NEVER the URI string itself
    signing_alg: str           # "RS256"/"HS256"/etc.
    token_lifetime_category: str  # based on token_lifetime seconds
    allow_offline_access: bool
    skip_consent_for_verifiable_first_party_clients: bool
    rbac_enabled: bool         # from enforce_policies
    scopes_count: int


class Auth0RuleRecord(TypedDict):
    """Safe normalised record for an Auth0 rule (M81A).

    SECURITY: rule script content, any URLs or tokens in the script,
    and all raw rule payload are NEVER stored. script_present is a boolean
    only; script content is never returned or stored.
    """

    record_type: str           # always "auth0_rule"
    record_id: str             # rule_id (opaque Auth0 identifier)
    provider_resource_id: str  # f"rules/{rule_id}"
    rule_id: str               # opaque Auth0 rule identifier
    name: str                  # truncated to 100 chars
    enabled: bool
    order: int                 # execution order
    script_present: bool       # whether a script is configured — content NEVER stored
    script_length_category: str  # "absent"/"short"/"medium"/"long"
    stage: str                 # "login_success"/"login_failure"/"pre_authorize"


class Auth0ActionRecord(TypedDict):
    """Safe normalised record for an Auth0 action (M81A).

    SECURITY: action code content, action secret names or values, dependency
    package names/versions, and all raw action payload are NEVER stored.
    code_present is a boolean. secrets_count is an integer count; secret
    names or values are never stored.
    """

    record_type: str           # always "auth0_action"
    record_id: str             # action_id (opaque Auth0 identifier)
    provider_resource_id: str  # f"actions/actions/{action_id}"
    action_id: str             # opaque Auth0 action identifier
    name: str                  # truncated to 100 chars
    status: str                # "built"/"building"/"packaged"/"waiting"/"failed"/"retrying"
    runtime: str               # "node12"/"node18-actions"/etc.
    trigger_id: str            # "post-login"/"credentials-exchange"/etc.
    code_present: bool         # whether code is configured — content NEVER stored
    code_length_category: str  # "absent"/"short"/"medium"/"long"
    deployed_version_present: bool
    dependencies_count: int    # count only — dependency names/versions NEVER stored
    secrets_count: int         # count only — secret names/values NEVER stored


class Auth0MfaFactorRecord(TypedDict):
    """Safe normalised record for an Auth0 Guardian / MFA factor (M81A).

    SECURITY: enrollment data, phone numbers, email addresses, recovery codes,
    user-level factor status, raw provider configs, OTP seeds, push device
    tokens, and all raw factor payload are NEVER stored.
    """

    record_type: str           # always "auth0_mfa_factor"
    record_id: str             # f"auth0_mfa_factor_{factor_name}"
    provider_resource_id: str  # f"guardian/factors/{factor_name}"
    factor_name: str           # "sms"/"push-notification"/"email"/"otp"/"webauthn-roaming"/etc.
    enabled: bool
    trial_expired: Optional[bool]
    provider_category: str     # "sms"/"push"/"email"/"totp"/"webauthn"/"recovery"/"third_party"


class Auth0CustomDomainRecord(TypedDict):
    """Safe normalised record for an Auth0 custom domain (M81A).

    SECURITY: raw domain name string (customer-identifying), verification
    tokens, DNS record values (CNAME targets), certificate material, private
    keys, and all raw custom domain payload are NEVER stored.
    domain_present is always True (by definition if we have a record).
    """

    record_type: str           # always "auth0_custom_domain"
    record_id: str             # custom_domain_id (opaque Auth0 identifier)
    provider_resource_id: str  # f"custom-domains/{custom_domain_id}"
    custom_domain_id: str      # opaque Auth0 custom domain identifier
    domain_present: bool       # always True — raw domain string NEVER stored
    status: str                # "ready"/"pending_verification"/"provisioning"/"disabled"
    type: str                  # "auth0_managed_certs"/"self_managed_certs"
    primary: bool
    verification_method_category: str  # "txt"/"cname" etc. — never the token
    tls_policy_category: str   # "recommended"/"compatible"
