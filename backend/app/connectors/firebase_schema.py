"""Firebase record type constants and TypedDicts — M53.

Record types
------------
firebase_project
    Top-level Firebase project metadata: display name, state, enabled surfaces.
    One record per integration.

firebase_auth_config
    Firebase Authentication configuration: enabled sign-in methods, anonymous
    auth, MFA state, authorized domain count, SAML/OIDC provider counts.
    Auth user data is NEVER fetched.

firebase_auth_provider
    Individual OAuth/SAML/OIDC provider configuration.  Provider-specific
    client_secret values are NEVER fetched.

firebase_authorized_domain
    Domain authorised for Firebase Auth redirect flows.  No customer data.

firebase_firestore_ruleset
    Active Firestore Security Rules deployment: ruleset name hash, rules hash,
    and conservative public-access analysis.
    Firestore documents and collection data are NEVER read.

firebase_storage_bucket
    Google Cloud Storage bucket metadata: location, storage class, access
    controls.  Storage object names and contents are NEVER read.

firebase_storage_ruleset
    Active Firebase Storage Security Rules deployment: ruleset name hash, rules
    hash, and conservative public-access analysis.
    Storage object contents are NEVER read.

firebase_hosting_site
    Firebase Hosting site configuration: site ID, default URL, custom domain
    count, release status.

firebase_hosting_domain
    Custom domain attached to a Firebase Hosting site.

firebase_function_metadata
    Cloud Functions configuration metadata: name, region, runtime, trigger type,
    status.  Environment variable VALUES are NEVER stored.

SECURITY
--------
- Service account private key is encrypted via the existing credential store;
  it is NEVER logged, returned in API responses, or embedded in snapshots.
- The private key is only used to sign a short-lived OAuth2 JWT.
- Firebase project numbers are stored only in hashed form (SHA-256 prefix).
- Firestore ruleset names are stored only in hashed form.
- Storage ruleset names are stored only in hashed form.
- Raw rules source is NEVER stored; only its SHA-256 hash.
- Firestore documents are NEVER read.
- Storage objects are NEVER listed or read.
- Firebase Auth user data is NEVER exported or read.
- Cloud Function environment variable VALUES are NEVER stored.
- Secret Manager secret values are NEVER read.
"""

from __future__ import annotations

from typing import Optional, TypedDict

# ── Record type constants ──────────────────────────────────────────────────────

FIREBASE_PROJECT                 = "firebase_project"
FIREBASE_AUTH_CONFIG             = "firebase_auth_config"
FIREBASE_AUTH_PROVIDER           = "firebase_auth_provider"
FIREBASE_AUTHORIZED_DOMAIN       = "firebase_authorized_domain"
FIREBASE_FIRESTORE_RULESET       = "firebase_firestore_ruleset"
FIREBASE_STORAGE_BUCKET          = "firebase_storage_bucket"
FIREBASE_STORAGE_RULESET         = "firebase_storage_ruleset"
FIREBASE_HOSTING_SITE            = "firebase_hosting_site"
FIREBASE_HOSTING_DOMAIN          = "firebase_hosting_domain"
FIREBASE_FUNCTION_METADATA       = "firebase_function_metadata"

# ── M57.8 record types ────────────────────────────────────────────────────────

# One per Firebase project — Remote Config template structural metadata.
# Parameter values, condition expressions, and user info are NEVER stored.
FIREBASE_REMOTE_CONFIG_TEMPLATE  = "firebase_remote_config_template"

# One per Firebase project — App Check service enforcement aggregate.
# Debug tokens, attestation data, and device/user data are NEVER stored.
FIREBASE_APP_CHECK_CONFIG        = "firebase_app_check_config"

FIREBASE_RECORD_TYPES: frozenset[str] = frozenset(
    {
        FIREBASE_PROJECT,
        FIREBASE_AUTH_CONFIG,
        FIREBASE_AUTH_PROVIDER,
        FIREBASE_AUTHORIZED_DOMAIN,
        FIREBASE_FIRESTORE_RULESET,
        FIREBASE_STORAGE_BUCKET,
        FIREBASE_STORAGE_RULESET,
        FIREBASE_HOSTING_SITE,
        FIREBASE_HOSTING_DOMAIN,
        FIREBASE_FUNCTION_METADATA,
        # M57.8
        FIREBASE_REMOTE_CONFIG_TEMPLATE,
        FIREBASE_APP_CHECK_CONFIG,
    }
)

# ── Required service account credential fields ─────────────────────────────────

REQUIRED_SA_FIELDS: tuple[str, ...] = (
    "type",
    "project_id",
    "private_key_id",
    "private_key",
    "client_email",
)

# Optional fields validated if present
OPTIONAL_SA_FIELDS: tuple[str, ...] = (
    "client_id",
    "token_uri",
)


# ── TypedDicts ─────────────────────────────────────────────────────────────────


class FirebaseProjectRecord(TypedDict, total=False):
    """Normalised firebase_project record."""

    record_type: str        # "firebase_project"
    record_id: str          # project_id
    name: str               # project_id (display identifier)

    project_id: str
    display_name: Optional[str]
    project_number_hash: str    # SHA-256[:16] of project number — not reversible
    lifecycle_state: Optional[str]
    # Which Firebase surfaces are enabled
    hosting_site: Optional[str]         # default hosting site name
    has_realtime_db: bool
    has_storage: bool
    config_fetch_warnings: list[str]


class FirebaseAuthConfigRecord(TypedDict, total=False):
    """Normalised firebase_auth_config record."""

    record_type: str        # "firebase_auth_config"
    record_id: str          # "{project_id}/auth_config"
    name: str               # "{project_id}/auth_config"

    project_id: str
    sign_in_email_enabled: bool
    sign_in_phone_enabled: bool
    anonymous_enabled: bool
    mfa_enabled: bool
    mfa_state: Optional[str]
    authorized_domain_count: int
    saml_provider_count: int
    oidc_provider_count: int
    config_fetch_warnings: list[str]


class FirebaseAuthProviderRecord(TypedDict, total=False):
    """Normalised firebase_auth_provider record."""

    record_type: str        # "firebase_auth_provider"
    record_id: str          # "{project_id}/{provider_id}"
    name: str               # provider display name

    project_id: str
    provider_id: str
    provider_type: str      # "saml" | "oidc"
    enabled: bool
    # client_secret is NEVER stored
    config_fetch_warnings: list[str]


class FirebaseAuthorizedDomainRecord(TypedDict, total=False):
    """Normalised firebase_authorized_domain record."""

    record_type: str        # "firebase_authorized_domain"
    record_id: str          # "{project_id}/{domain}"
    name: str               # domain

    project_id: str
    domain: str
    is_localhost: bool
    is_default_firebase_domain: bool    # e.g. *.firebaseapp.com, *.web.app
    config_fetch_warnings: list[str]


class FirebaseFirestoreRulesetRecord(TypedDict, total=False):
    """Normalised firebase_firestore_ruleset record.

    Raw rules source is NEVER stored — only its SHA-256 hash.
    """

    record_type: str        # "firebase_firestore_ruleset"
    record_id: str          # "{project_id}/firestore/{release_name}"
    name: str               # release name

    project_id: str
    release_name: str
    ruleset_name_hash: str          # SHA-256[:16] of fully-qualified ruleset resource name
    rules_hash: Optional[str]       # SHA-256[:16] of raw rules source
    public_read_detected: bool
    public_write_detected: bool
    authenticated_only_detected: bool
    rule_summary: str
    parser_confidence: str          # "high" | "medium" | "low"
    config_fetch_warnings: list[str]


class FirebaseStorageBucketRecord(TypedDict, total=False):
    """Normalised firebase_storage_bucket record.

    Storage object names and contents are NEVER read.
    """

    record_type: str        # "firebase_storage_bucket"
    record_id: str          # "{project_id}/{bucket_name}"
    name: str               # bucket name

    project_id: str
    bucket_name: str
    bucket_name_hash: str   # SHA-256[:16] of bucket name
    location: Optional[str]
    storage_class: Optional[str]
    uniform_bucket_level_access: Optional[bool]
    public_access_prevention: Optional[str]
    versioning_enabled: Optional[bool]
    config_fetch_warnings: list[str]


class FirebaseStorageRulesetRecord(TypedDict, total=False):
    """Normalised firebase_storage_ruleset record.

    Raw rules source is NEVER stored — only its SHA-256 hash.
    """

    record_type: str        # "firebase_storage_ruleset"
    record_id: str          # "{project_id}/storage/{release_name}"
    name: str               # release name

    project_id: str
    release_name: str
    bucket_name_hash: Optional[str]     # SHA-256[:16] of bucket name if derivable
    ruleset_name_hash: str              # SHA-256[:16] of ruleset resource name
    rules_hash: Optional[str]           # SHA-256[:16] of raw rules source
    public_read_detected: bool
    public_write_detected: bool
    authenticated_only_detected: bool
    rule_summary: str
    parser_confidence: str              # "high" | "medium" | "low"
    config_fetch_warnings: list[str]


class FirebaseHostingSiteRecord(TypedDict, total=False):
    """Normalised firebase_hosting_site record."""

    record_type: str        # "firebase_hosting_site"
    record_id: str          # "{project_id}/{site_id}"
    name: str               # site_id

    project_id: str
    site_id: str
    default_url: Optional[str]
    app_id: Optional[str]
    custom_domain_count: int
    config_fetch_warnings: list[str]


class FirebaseHostingDomainRecord(TypedDict, total=False):
    """Normalised firebase_hosting_domain record."""

    record_type: str        # "firebase_hosting_domain"
    record_id: str          # "{project_id}/{site_id}/{domain}"
    name: str               # domain

    project_id: str
    site_id: str
    domain: str
    domain_type: str        # "FIREBASE_SERVING_DOMAIN" | "CUSTOM"
    status: Optional[str]
    config_fetch_warnings: list[str]


class FirebaseFunctionMetadataRecord(TypedDict, total=False):
    """Normalised firebase_function_metadata record.

    Environment variable VALUES are NEVER stored — only the count of keys.
    """

    record_type: str        # "firebase_function_metadata"
    record_id: str          # "{project_id}/{region}/{function_name}"
    name: str               # function_name

    project_id: str
    function_name: str
    region: str
    runtime: Optional[str]
    trigger_type: str       # "HTTP" | "EVENT" | "SCHEDULED" | "OTHER"
    status: Optional[str]
    env_var_key_count: int              # count of env var KEYS only, no values
    config_fetch_warnings: list[str]


# ── M57.8 TypedDicts ──────────────────────────────────────────────────────────


class FirebaseRemoteConfigTemplateRecord(TypedDict, total=False):
    """Normalised firebase_remote_config_template record — M57.8.

    Tracks Firebase Remote Config template structural metadata.

    SECURITY / DATA MINIMISATION:
    - Parameter VALUES are NEVER stored (default or conditional).
    - Condition expressions are NEVER stored.
    - ``updateUser`` (email/display name) is NEVER stored.
    - ``parameterGroups`` descriptions are NEVER stored.
    - Only counts, hashes, and version metadata are kept.

    ``parameter_keys_hash`` and ``condition_names_hash`` change when
    parameters/conditions are added or removed; they are SHA-256[:16]
    digests of the sorted key/name lists.
    """

    record_type: str        # "firebase_remote_config_template"
    record_id: str          # "{project_id}/remote_config"
    name: str               # "{project_id}/remote_config"

    project_id: str
    version_number: Optional[str]       # template version as a string (e.g. "42")
    update_origin: Optional[str]        # "CONSOLE", "REST_API", "ADMIN_SDK_NODE", etc.
    update_type: Optional[str]          # "INCREMENTAL_UPDATE", "FORCED_UPDATE", "ROLLBACK"
    parameter_count: int                # number of top-level parameters
    condition_count: int                # number of conditions
    parameter_group_count: int          # number of parameter groups
    parameter_keys_hash: Optional[str]  # SHA-256[:16] of sorted parameter key names
    condition_names_hash: Optional[str] # SHA-256[:16] of sorted condition names
    config_fetch_warnings: list[str]


class FirebaseAppCheckConfigRecord(TypedDict, total=False):
    """Normalised firebase_app_check_config record — M57.8.

    Tracks Firebase App Check enforcement posture across protected services.

    SECURITY / DATA MINIMISATION:
    - Debug tokens are NEVER stored.
    - App attestation data, device data, and user data are NEVER stored.
    - Raw app IDs are NOT stored; only aggregate counts and service names
      (which are Google API endpoint strings, not secrets) are kept.

    ``enforced_service_names`` holds the list of Firebase service API names
    (e.g. "firestore.googleapis.com") for which enforcement is active.
    These are infrastructure identifiers, not customer data.
    """

    record_type: str        # "firebase_app_check_config"
    record_id: str          # "{project_id}/app_check"
    name: str               # "{project_id}/app_check"

    project_id: str
    service_count: int              # total services monitored by App Check
    enforced_service_count: int     # services with enforcement active
    unenforced_service_count: int   # services with enforcement off/unspecified
    enforced_service_names: Optional[list[str]]  # service API names (not secrets)
    config_fetch_warnings: list[str]
