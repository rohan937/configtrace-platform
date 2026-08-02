"""Pydantic schemas for integration endpoints.

Response schemas deliberately omit every credential field:
``encrypted_credentials``, ``credential_iv``, and any raw provider tokens
or IDs are never present in any API response.  This is enforced at the schema
level, not by runtime filtering.

Supported providers
-------------------
``cloudflare``
    Credentials: ``api_token`` + ``zone_id``.
``github``
    Credentials: ``github_token`` + ``repo_owner`` + ``repo_name``.
``vercel``
    Credentials: ``vercel_token`` + ``vercel_project_id``.
``stripe``
    Credentials: ``stripe_api_key``.
``azure``  (M82-pre.1)
    Credentials: ``azure_tenant_id`` + ``azure_client_id`` + ``azure_client_secret``
                 + ``azure_subscription_id``.
``google_cloud``  (M82-pre.1)
    Credentials: ``google_cloud_project_id`` + ``google_cloud_service_account_json``.
``twilio``  (M82-pre.1)
    Credentials: ``twilio_account_sid`` + ``twilio_auth_token``.
``sendgrid``  (M82-pre.1)
    Credentials: ``sendgrid_api_key``.
``auth0``  (M82-pre.1)
    Credentials: ``auth0_domain`` + ``auth0_client_id`` + ``auth0_client_secret``
                 (or ``auth0_management_api_token`` for direct-token mode).
``datadog``  (M82A)
    Credentials: ``datadog_api_key`` + ``datadog_application_key`` + optional ``datadog_site``.
``kubernetes``  (Kubernetes message 1 — provider foundation)
    Credentials: ``kubeconfig`` + optional ``context`` + optional ``cluster_name``
                 + optional ``namespace_allowlist``.
``okta``  (Okta message 1 — provider foundation)
    Credentials: ``okta_org_url`` + ``okta_api_token``.
    Foundation stage — not yet publicly connectable.

Provider-specific fields are made optional at the Pydantic level and
cross-validated by ``validate_provider_fields`` to produce clear error
messages when a required field is missing for the selected provider.

SECURITY: credential fields for M82-pre.1 and M82A providers follow the same
invariants as existing providers — stored encrypted, never returned,
never logged.  azure_client_secret, twilio_auth_token, sendgrid_api_key,
auth0_client_secret, auth0_management_api_token,
google_cloud_service_account_json (which embeds a private_key),
datadog_api_key, and datadog_application_key are NEVER present in any
API response or log output.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal, Optional

from pydantic import UUID4, BaseModel, Field, model_validator

# Allowed per-integration sync intervals (minutes).  Must stay in sync with
# ``sync_service._ALLOWED_INTERVALS``.
_ALLOWED_SYNC_INTERVALS = frozenset({5, 10, 15, 30, 60})


class IntegrationCreateRequest(BaseModel):
    """Request body for ``POST /integrations``.

    All credential fields are optional at the type level; the
    ``validate_provider_fields`` validator enforces that the correct subset
    is present for the chosen provider.
    """

    provider: Literal[
        "cloudflare", "github", "vercel", "stripe", "aws", "firebase",
        "supabase", "shopify",
        # M82-pre.1 — credential-connect parity for completed security providers.
        "azure", "google_cloud", "twilio", "sendgrid", "auth0",
        # M82A — Datadog drift provider foundation.
        "datadog",
        # M83A — Clerk drift provider foundation.
        "clerk",
        # M84A — PagerDuty drift provider foundation.
        "pagerduty",
        # M85A — Linear drift provider foundation.
        "linear",
        # M86A — Jira drift provider foundation.
        "jira",
        # M87A — GitLab drift provider foundation.
        "gitlab",
        # M88A — Terraform Cloud drift provider foundation.
        "terraform_cloud",
        # Kubernetes message 1 — provider architecture foundation.
        "kubernetes",
        # Okta message 1 — provider architecture foundation.
        "okta",
        # Microsoft Entra ID message 1 — provider architecture foundation.
        "entra",
        # Snowflake message 1 — provider architecture foundation.
        "snowflake",
        # Sentry message 1 — provider architecture foundation.
        "sentry",
    ] = Field(
        ...,
        description=(
            "Provider identifier. "
            "Supported values: 'cloudflare', 'github', 'vercel', 'stripe', "
            "'aws', 'firebase', 'supabase', 'shopify', 'azure', "
            "'google_cloud', 'twilio', 'sendgrid', 'auth0', 'datadog'."
        ),
    )
    display_name: str = Field(
        ...,
        min_length=1,
        max_length=200,
        description="Human-readable label for this integration (shown in the UI).",
    )

    # ── Cloudflare fields ─────────────────────────────────────────────────────
    api_token: Optional[str] = Field(
        None,
        min_length=1,
        description=(
            "Cloudflare API token with Zone.DNS:Read permission. "
            "Required when provider='cloudflare'. "
            "Stored encrypted — never returned in API responses."
        ),
    )
    zone_id: Optional[str] = Field(
        None,
        min_length=1,
        description=(
            "Cloudflare Zone ID (32-char hex string from the dashboard). "
            "Required when provider='cloudflare'."
        ),
    )

    # ── GitHub fields ─────────────────────────────────────────────────────────
    github_token: Optional[str] = Field(
        None,
        min_length=1,
        description=(
            "Fine-grained GitHub PAT with Metadata:Read, Administration:Read, "
            "Secrets:Read, and Variables:Read repository permissions. "
            "Required when provider='github'. "
            "Stored encrypted — never returned in API responses."
        ),
    )
    repo_owner: Optional[str] = Field(
        None,
        min_length=1,
        description=(
            "GitHub username or organisation that owns the repository. "
            "Required when provider='github'."
        ),
    )
    repo_name: Optional[str] = Field(
        None,
        min_length=1,
        description=(
            "Repository name (without the owner prefix). "
            "Required when provider='github'."
        ),
    )

    # ── Vercel fields ─────────────────────────────────────────────────────────
    vercel_token: Optional[str] = Field(
        None,
        min_length=1,
        description=(
            "Vercel personal access token with read access to the project. "
            "Generated at vercel.com → Settings → Tokens. "
            "Required when provider='vercel'. "
            "Stored encrypted — never returned in API responses."
        ),
    )
    vercel_project_id: Optional[str] = Field(
        None,
        min_length=1,
        description=(
            "Vercel project ID (prj_xxx) or project slug name. "
            "Found at vercel.com → <project> → Settings → General → Project ID. "
            "Required when provider='vercel'."
        ),
    )

    # ── Stripe fields ─────────────────────────────────────────────────────────
    stripe_api_key: Optional[str] = Field(
        None,
        min_length=1,
        description=(
            "Stripe restricted API key with read-only permissions. "
            "Create at dashboard.stripe.com → Developers → API keys → "
            "Create restricted key. "
            "Required when provider='stripe'. "
            "Stored encrypted — never returned in API responses."
        ),
    )

    # ── AWS fields ────────────────────────────────────────────────────────────
    aws_access_key_id: Optional[str] = Field(
        None,
        min_length=1,
        description=(
            "AWS IAM access key ID (starts with AKIA or ASIA). "
            "Required when provider='aws'. "
            "Stored encrypted — never returned in API responses. "
            "Use a dedicated read-only IAM user for ConfigTrace."
        ),
    )
    aws_secret_access_key: Optional[str] = Field(
        None,
        min_length=1,
        description=(
            "AWS IAM secret access key. "
            "Required when provider='aws'. "
            "Stored encrypted — never returned in API responses. "
            "SECURITY: never logged or returned to the frontend."
        ),
    )
    aws_default_region: Optional[str] = Field(
        None,
        description=(
            "Default AWS region for API calls (e.g. 'us-east-1'). "
            "Optional when provider='aws' — defaults to 'us-east-1' if not set."
        ),
    )
    aws_selected_regions: Optional[list[str]] = Field(
        None,
        description=(
            "List of AWS regions to monitor (e.g. ['us-east-1', 'eu-west-1']). "
            "Optional when provider='aws' — defaults to [aws_default_region] if not set."
        ),
    )

    # ── Firebase fields ───────────────────────────────────────────────────────
    firebase_service_account_json: Optional[str] = Field(
        None,
        min_length=1,
        description=(
            "Firebase service account JSON (the full contents of the key file "
            "downloaded from Firebase Console → Project settings → Service accounts). "
            "Required when provider='firebase'. "
            "Stored encrypted — never returned in API responses. "
            "SECURITY: The private_key embedded in this JSON is encrypted at rest "
            "and is NEVER logged, returned to the frontend, or stored in plaintext."
        ),
    )

    # ── Supabase fields ───────────────────────────────────────────────────────
    supabase_access_token: Optional[str] = Field(
        None,
        min_length=1,
        description=(
            "Supabase Management API personal access token (starts with sbp_). "
            "Generated at supabase.com/dashboard/account/tokens. "
            "Required when provider='supabase'. "
            "Stored encrypted — never returned in API responses. "
            "SECURITY: Never logged, never returned to the frontend, stored in plaintext."
        ),
    )
    supabase_project_ref: Optional[str] = Field(
        None,
        min_length=1,
        description=(
            "Supabase project reference string (20-char alphanumeric, shown in the project URL). "
            "Required when provider='supabase'."
        ),
    )

    # ── Shopify fields ────────────────────────────────────────────────────────
    shopify_shop_domain: Optional[str] = Field(
        None,
        min_length=1,
        description=(
            "Shopify shop domain, e.g. 'mystore.myshopify.com' or a custom domain. "
            "Required when provider='shopify'. "
            "Do not include 'https://' — the backend normalises the value."
        ),
    )
    shopify_access_token: Optional[str] = Field(
        None,
        min_length=1,
        description=(
            "Shopify Admin API access token (starts with 'shpat_' for custom apps). "
            "Required when provider='shopify'. "
            "Stored encrypted — NEVER returned in API responses. "
            "SECURITY: Never logged, never returned to the frontend, stored in plaintext."
        ),
    )

    # ── Azure fields (M82-pre.1) ──────────────────────────────────────────────
    azure_tenant_id: Optional[str] = Field(
        None,
        min_length=1,
        description=(
            "Azure AD / Entra ID tenant GUID. Required when provider='azure'. "
            "Used as the OAuth2 token-endpoint tenant for the service principal."
        ),
    )
    azure_client_id: Optional[str] = Field(
        None,
        min_length=1,
        description=(
            "Azure service principal application (client) ID. "
            "Required when provider='azure'."
        ),
    )
    azure_client_secret: Optional[str] = Field(
        None,
        min_length=1,
        description=(
            "Azure service principal client secret. "
            "Required when provider='azure'. "
            "Stored encrypted — NEVER returned in API responses or logged."
        ),
    )
    azure_subscription_id: Optional[str] = Field(
        None,
        min_length=1,
        description=(
            "Azure subscription GUID to monitor. "
            "Required when provider='azure'."
        ),
    )

    # ── Google Cloud fields (M82-pre.1) ───────────────────────────────────────
    google_cloud_project_id: Optional[str] = Field(
        None,
        min_length=1,
        description=(
            "Google Cloud project ID to monitor (e.g. 'my-project-12345'). "
            "Required when provider='google_cloud'. If absent, the backend "
            "attempts to read it from the service account JSON."
        ),
    )
    google_cloud_service_account_json: Optional[str] = Field(
        None,
        min_length=1,
        description=(
            "Google Cloud service account JSON key file contents (full JSON "
            "downloaded from console.cloud.google.com → IAM & Admin → "
            "Service Accounts → Keys → Create new key → JSON). "
            "Required when provider='google_cloud'. "
            "Stored encrypted — NEVER returned in API responses or logged. "
            "SECURITY: the embedded private_key is encrypted at rest and is "
            "NEVER logged, returned to the frontend, or stored in plaintext."
        ),
    )

    # ── Twilio fields (M82-pre.1) ─────────────────────────────────────────────
    twilio_account_sid: Optional[str] = Field(
        None,
        min_length=1,
        description=(
            "Twilio Account SID. "
            "Required when provider='twilio'. "
            "Used as the HTTP Basic auth username for read-only Twilio "
            "configuration API calls."
        ),
    )
    twilio_auth_token: Optional[str] = Field(
        None,
        min_length=1,
        description=(
            "Twilio auth token. "
            "Required when provider='twilio'. "
            "Stored encrypted — NEVER returned in API responses or logged. "
            "SECURITY: never appears in error messages or sync diagnostics."
        ),
    )

    # ── SendGrid fields (M82-pre.1) ───────────────────────────────────────────
    sendgrid_api_key: Optional[str] = Field(
        None,
        min_length=1,
        description=(
            "SendGrid API key with read-only access to account configuration "
            "(API keys list, sender authentication, mail settings, tracking "
            "settings, event webhook, inbound parse, suppression settings). "
            "Required when provider='sendgrid'. "
            "Stored encrypted — NEVER returned in API responses or logged."
        ),
    )

    # ── Auth0 fields (M82-pre.1) ──────────────────────────────────────────────
    auth0_domain: Optional[str] = Field(
        None,
        min_length=1,
        description=(
            "Auth0 tenant domain, e.g. 'mytenant.auth0.com'. "
            "Required when provider='auth0'."
        ),
    )
    auth0_client_id: Optional[str] = Field(
        None,
        min_length=1,
        description=(
            "Auth0 M2M application client ID. "
            "Required when provider='auth0' and using the OAuth2 "
            "client_credentials flow (omit when supplying "
            "auth0_management_api_token directly)."
        ),
    )
    auth0_client_secret: Optional[str] = Field(
        None,
        min_length=1,
        description=(
            "Auth0 M2M application client secret. "
            "Required when provider='auth0' and using the OAuth2 "
            "client_credentials flow. "
            "Stored encrypted — NEVER returned in API responses or logged."
        ),
    )
    auth0_management_api_token: Optional[str] = Field(
        None,
        min_length=1,
        description=(
            "Auth0 Management API token (direct-token mode — used instead of "
            "client_id + client_secret). Optional when provider='auth0'. "
            "Stored encrypted — NEVER returned in API responses or logged."
        ),
    )

    # ── Datadog fields (M82A) ─────────────────────────────────────────────────
    datadog_api_key: Optional[str] = Field(
        None,
        min_length=1,
        description=(
            "Datadog API key. "
            "Required when provider='datadog'. "
            "Stored encrypted — NEVER returned in API responses or logged."
        ),
    )
    datadog_application_key: Optional[str] = Field(
        None,
        min_length=1,
        description=(
            "Datadog Application key. "
            "Required when provider='datadog'. "
            "Stored encrypted — NEVER returned in API responses or logged."
        ),
    )
    datadog_site: Optional[str] = Field(
        None,
        description=(
            "Datadog site to connect to (e.g. 'datadoghq.com', 'datadoghq.eu', "
            "'us3.datadoghq.com'). Optional — defaults to 'datadoghq.com'. "
            "Not a secret; stored in resource metadata."
        ),
    )

    # ── Clerk fields (M83A) ───────────────────────────────────────────────────
    clerk_secret_key: Optional[str] = Field(
        None,
        min_length=1,
        description=(
            "Clerk Backend API secret key (sk_live_* or sk_test_*). "
            "Required when provider='clerk'. "
            "Stored encrypted — NEVER returned in API responses or logged. "
            "SECURITY: never logged, never returned to the frontend, "
            "never stored in plaintext or resource metadata."
        ),
    )
    clerk_frontend_api_url: Optional[str] = Field(
        None,
        min_length=1,
        description=(
            "Clerk Frontend API URL (e.g. 'https://<instance>.clerk.accounts.dev'). "
            "Optional when provider='clerk' — not required for Backend API drift "
            "snapshots. If provided, stored encrypted. Not a secret but kept "
            "encrypted alongside the secret key for consistency."
        ),
    )

    # ── PagerDuty fields (M84A) ───────────────────────────────────────────────
    pagerduty_api_token: Optional[str] = Field(
        None,
        min_length=1,
        description=(
            "PagerDuty API token (read-only). "
            "Required when provider='pagerduty'. "
            "Stored encrypted — NEVER returned in API responses or logged. "
            "SECURITY: never logged, never returned to the frontend, "
            "never stored in plaintext or resource metadata."
        ),
    )

    # ── Linear fields (M85A) ─────────────────────────────────────────────────
    linear_api_key: Optional[str] = Field(
        None,
        min_length=1,
        description=(
            "Linear API key (read-only). "
            "Required when provider='linear'. "
            "Stored encrypted — NEVER returned in API responses or logged. "
            "SECURITY: never logged, never returned to the frontend, "
            "never stored in plaintext or resource metadata."
        ),
    )

    # ── Jira fields (M86A) ───────────────────────────────────────────────────
    jira_site_url: Optional[str] = Field(
        None,
        description=(
            "Required when provider='jira'. "
            "Jira Cloud site URL (e.g. myco.atlassian.net). "
            "Never returned in API responses. Never logged."
        ),
    )
    jira_email: Optional[str] = Field(
        None,
        description=(
            "Required when provider='jira'. "
            "Jira account email for API authentication. "
            "Never returned in API responses. Never logged."
        ),
    )
    jira_api_token: Optional[str] = Field(
        None,
        description=(
            "Required when provider='jira'. "
            "Jira API token. Stored encrypted. "
            "Never returned in any response. Never logged."
        ),
    )

    # ── GitLab fields (M87A) ────────────────────────────────────────────────
    gitlab_access_token: Optional[str] = Field(
        None,
        description=(
            "Required when provider='gitlab'. "
            "GitLab personal access token with read_api or api scope. "
            "Stored encrypted — NEVER returned in API responses or logged. "
            "SECURITY: never logged, never returned to the frontend, "
            "never stored in plaintext or resource metadata."
        ),
    )
    gitlab_base_url: Optional[str] = Field(
        None,
        description=(
            "Optional when provider='gitlab'. "
            "Base URL for self-managed GitLab instances (e.g. https://gitlab.example.com). "
            "Defaults to https://gitlab.com if omitted. "
            "Never stored as a raw URL in resource metadata."
        ),
    )

    # ── Terraform Cloud fields (M88A) ──────────────────────────────────────────
    terraform_cloud_api_token: Optional[str] = Field(
        None,
        description=(
            "Required when provider='terraform_cloud'. "
            "Terraform Cloud team or user API token. "
            "Stored encrypted — NEVER returned in API responses or logged. "
            "SECURITY: never logged, never returned to the frontend, "
            "never stored in plaintext or resource metadata."
        ),
    )
    terraform_cloud_organization: Optional[str] = Field(
        None,
        description=(
            "Required when provider='terraform_cloud'. "
            "Terraform Cloud organization name slug. "
            "Used as an API path parameter — never stored in normalized records."
        ),
    )
    terraform_cloud_base_url: Optional[str] = Field(
        None,
        description=(
            "Optional when provider='terraform_cloud'. "
            "Base URL for Terraform Enterprise or self-managed Terraform Cloud. "
            "Defaults to https://app.terraform.io if omitted. "
            "Never stored as a raw URL in resource metadata."
        ),
    )

    # ── Kubernetes fields (message 1 — provider foundation) ────────────────────
    kubeconfig: Optional[str] = Field(
        None,
        description=(
            "Required when provider='kubernetes'. "
            "Full kubeconfig YAML content for the cluster to monitor. "
            "Stored encrypted — NEVER returned in API responses or logged. "
            "'exec' and 'auth-provider' authentication entries in the "
            "selected context are rejected at connection time; ConfigTrace "
            "does not execute external auth plugins."
        ),
    )
    context: Optional[str] = Field(
        None,
        description=(
            "Optional when provider='kubernetes'. "
            "The kubeconfig context to use. Defaults to the kubeconfig's "
            "current-context if omitted."
        ),
    )
    cluster_name: Optional[str] = Field(
        None,
        description=(
            "Optional when provider='kubernetes'. "
            "User-supplied display name for the cluster. Non-authoritative — "
            "the stable cluster identity is derived from cluster metadata, "
            "not this name."
        ),
    )
    namespace_allowlist: Optional[list[str]] = Field(
        None,
        description=(
            "Optional when provider='kubernetes'. "
            "If supplied, only these namespaces are collected. Omitted means "
            "all visible namespaces are collected — ConfigTrace does not "
            "silently exclude 'kube-system', 'kube-public', or "
            "'kube-node-lease'."
        ),
    )

    # ── Okta fields (message 1 — provider foundation) ──────────────────────────
    okta_org_url: Optional[str] = Field(
        None,
        description=(
            "Required when provider='okta'. "
            "Okta org base URL, e.g. 'https://example.okta.com'. Custom "
            "Okta domains are supported. Must use https://, no embedded "
            "credentials, no query string or path."
        ),
    )
    okta_api_token: Optional[str] = Field(
        None,
        description=(
            "Required when provider='okta'. "
            "Okta API token (sent as 'Authorization: SSWS <token>'). "
            "Stored encrypted — NEVER returned in API responses or logged."
        ),
    )

    # ── Microsoft Entra ID fields (message 1 — provider foundation) ────────────
    entra_tenant_id: Optional[str] = Field(
        None,
        description=(
            "Required when provider='entra'. "
            "Microsoft Entra tenant GUID, e.g. "
            "'11111111-1111-1111-1111-111111111111'. Must be a concrete "
            "tenant GUID — 'common'/'organizations'/'consumers' are rejected."
        ),
    )
    entra_client_id: Optional[str] = Field(
        None,
        description=(
            "Required when provider='entra'. "
            "Microsoft Entra app registration (client) GUID."
        ),
    )
    entra_client_secret: Optional[str] = Field(
        None,
        description=(
            "Required when provider='entra'. "
            "Microsoft Entra app registration client secret. "
            "Stored encrypted — NEVER returned in API responses or logged."
        ),
    )

    # ── Snowflake fields (message 1 — provider foundation) ─────────────────────
    snowflake_account_identifier: Optional[str] = Field(
        None,
        description=(
            "Required when provider='snowflake'. "
            "Snowflake account identifier, preferred 'orgname-accountname' form "
            "(or the legacy account-locator form). Used only to construct the "
            "request hostname — never a full URL."
        ),
    )
    snowflake_username: Optional[str] = Field(
        None,
        description=(
            "Required when provider='snowflake'. "
            "The dedicated service user's Snowflake login name."
        ),
    )
    snowflake_programmatic_access_token: Optional[str] = Field(
        None,
        description=(
            "Required when provider='snowflake'. "
            "Snowflake Programmatic Access Token (PAT) for the service user. "
            "Stored encrypted — NEVER returned in API responses or logged."
        ),
    )
    snowflake_role: Optional[str] = Field(
        None,
        description=(
            "Required when provider='snowflake'. "
            "Explicit least-privileged monitoring role. ConfigTrace never "
            "defaults to ACCOUNTADMIN or SECURITYADMIN."
        ),
    )

    # ── Sentry fields (message 1 — provider foundation) ─────────────────────────
    sentry_organization_slug: Optional[str] = Field(
        None,
        description=(
            "Required when provider='sentry'. "
            "Sentry organization slug (e.g. 'my-organization'). Used only as a "
            "path segment on the fixed https://sentry.io API origin — never a "
            "full URL."
        ),
    )
    sentry_auth_token: Optional[str] = Field(
        None,
        description=(
            "Required when provider='sentry'. "
            "Sentry organization auth token. Stored encrypted — NEVER "
            "returned in API responses or logged."
        ),
    )

    # ── M50: workspace assignment ─────────────────────────────────────────────
    workspace_id: Optional[UUID4] = Field(
        None,
        description=(
            "M50: workspace to create this integration in. "
            "If omitted, the user's default workspace is used. "
            "Caller must be a member of the workspace."
        ),
    )

    @model_validator(mode="after")
    def validate_provider_fields(self) -> "IntegrationCreateRequest":
        """Ensure the correct credential fields are present for the provider."""
        if self.provider == "cloudflare":
            if not self.api_token:
                raise ValueError(
                    "api_token is required for Cloudflare integrations."
                )
            if not self.zone_id:
                raise ValueError(
                    "zone_id is required for Cloudflare integrations."
                )
        elif self.provider == "github":
            if not self.github_token:
                raise ValueError(
                    "github_token is required for GitHub integrations."
                )
            if not self.repo_owner:
                raise ValueError(
                    "repo_owner is required for GitHub integrations."
                )
            if not self.repo_name:
                raise ValueError(
                    "repo_name is required for GitHub integrations."
                )
        elif self.provider == "vercel":
            if not self.vercel_token:
                raise ValueError(
                    "vercel_token is required for Vercel integrations."
                )
            if not self.vercel_project_id:
                raise ValueError(
                    "vercel_project_id is required for Vercel integrations."
                )
        elif self.provider == "stripe":
            if not self.stripe_api_key:
                raise ValueError(
                    "stripe_api_key is required for Stripe integrations."
                )
        elif self.provider == "aws":
            if not self.aws_access_key_id:
                raise ValueError(
                    "aws_access_key_id is required for AWS integrations."
                )
            if not self.aws_secret_access_key:
                raise ValueError(
                    "aws_secret_access_key is required for AWS integrations."
                )
        elif self.provider == "firebase":
            if not self.firebase_service_account_json:
                raise ValueError(
                    "firebase_service_account_json is required for Firebase integrations."
                )
        elif self.provider == "supabase":
            if not self.supabase_access_token:
                raise ValueError(
                    "supabase_access_token is required for Supabase integrations."
                )
            if not self.supabase_project_ref:
                raise ValueError(
                    "supabase_project_ref is required for Supabase integrations."
                )
        elif self.provider == "shopify":
            if not self.shopify_shop_domain:
                raise ValueError(
                    "shopify_shop_domain is required for Shopify integrations."
                )
            if not self.shopify_access_token:
                raise ValueError(
                    "shopify_access_token is required for Shopify integrations."
                )
        # ── M82-pre.1 — credential presence validation ──────────────────────────
        # New connectable providers: presence and basic shape only. Live
        # validation against the provider API happens on first sync, not at
        # create time. This avoids tight coupling to network availability
        # during integration creation and keeps secret values from appearing
        # in synchronous error messages.
        elif self.provider == "azure":
            if not self.azure_tenant_id:
                raise ValueError(
                    "azure_tenant_id is required for Azure integrations."
                )
            if not self.azure_client_id:
                raise ValueError(
                    "azure_client_id is required for Azure integrations."
                )
            if not self.azure_client_secret:
                raise ValueError(
                    "azure_client_secret is required for Azure integrations."
                )
            if not self.azure_subscription_id:
                raise ValueError(
                    "azure_subscription_id is required for Azure integrations."
                )
        elif self.provider == "google_cloud":
            if not self.google_cloud_service_account_json:
                raise ValueError(
                    "google_cloud_service_account_json is required for "
                    "Google Cloud integrations."
                )
            # project_id is recommended but may be derived from the service
            # account JSON's project_id field; we accept either here.
        elif self.provider == "twilio":
            if not self.twilio_account_sid:
                raise ValueError(
                    "twilio_account_sid is required for Twilio integrations."
                )
            if not self.twilio_auth_token:
                raise ValueError(
                    "twilio_auth_token is required for Twilio integrations."
                )
        elif self.provider == "sendgrid":
            if not self.sendgrid_api_key:
                raise ValueError(
                    "sendgrid_api_key is required for SendGrid integrations."
                )
        elif self.provider == "auth0":
            if not self.auth0_domain:
                raise ValueError(
                    "auth0_domain is required for Auth0 integrations."
                )
            # Either client_credentials (client_id + client_secret) OR a
            # direct management_api_token must be provided. The connector
            # supports both modes.
            has_client_creds = bool(self.auth0_client_id) and bool(
                self.auth0_client_secret
            )
            has_mgmt_token = bool(self.auth0_management_api_token)
            if not (has_client_creds or has_mgmt_token):
                raise ValueError(
                    "Auth0 integrations require either auth0_client_id + "
                    "auth0_client_secret OR auth0_management_api_token."
                )
        # ── M82A — Datadog drift provider ────────────────────────────────────
        elif self.provider == "datadog":
            if not self.datadog_api_key:
                raise ValueError(
                    "datadog_api_key is required for Datadog integrations."
                )
            if not self.datadog_application_key:
                raise ValueError(
                    "datadog_application_key is required for Datadog integrations."
                )
        # ── M83A — Clerk drift provider ──────────────────────────────────────
        elif self.provider == "clerk":
            if not self.clerk_secret_key:
                raise ValueError(
                    "clerk_secret_key is required for Clerk integrations."
                )
        # ── M84A — PagerDuty drift provider ──────────────────────────────────
        elif self.provider == "pagerduty":
            if not self.pagerduty_api_token:
                raise ValueError(
                    "pagerduty_api_token is required for PagerDuty integrations."
                )
        # ── M85A — Linear drift provider ─────────────────────────────────────
        elif self.provider == "linear":
            if not self.linear_api_key:
                raise ValueError(
                    "linear_api_key is required for Linear integrations."
                )
        # ── M86A — Jira drift provider ────────────────────────────────────────
        elif self.provider == "jira":
            if not self.jira_site_url:
                raise ValueError(
                    "jira_site_url is required for Jira integrations."
                )
            if not self.jira_email:
                raise ValueError(
                    "jira_email is required for Jira integrations."
                )
            if not self.jira_api_token:
                raise ValueError(
                    "jira_api_token is required for Jira integrations."
                )
        elif self.provider == "gitlab":
            if not self.gitlab_access_token:
                raise ValueError(
                    "gitlab_access_token is required for GitLab integrations."
                )
        # ── M88A — Terraform Cloud drift provider ─────────────────────────────
        elif self.provider == "terraform_cloud":
            if not self.terraform_cloud_api_token:
                raise ValueError(
                    "terraform_cloud_api_token is required for Terraform Cloud integrations."
                )
            if not self.terraform_cloud_organization:
                raise ValueError(
                    "terraform_cloud_organization is required for Terraform Cloud integrations."
                )
        # ── Kubernetes message 1 — provider foundation ────────────────────────
        elif self.provider == "kubernetes":
            if not self.kubeconfig:
                raise ValueError(
                    "kubeconfig is required for Kubernetes integrations."
                )
        # ── Okta message 1 — provider foundation ───────────────────────────────
        elif self.provider == "okta":
            if not self.okta_org_url:
                raise ValueError(
                    "okta_org_url is required for Okta integrations."
                )
            if not self.okta_api_token:
                raise ValueError(
                    "okta_api_token is required for Okta integrations."
                )
        # ── Microsoft Entra ID message 1 — provider foundation ────────────────
        elif self.provider == "entra":
            if not self.entra_tenant_id:
                raise ValueError(
                    "entra_tenant_id is required for Microsoft Entra ID integrations."
                )
            if not self.entra_client_id:
                raise ValueError(
                    "entra_client_id is required for Microsoft Entra ID integrations."
                )
            if not self.entra_client_secret:
                raise ValueError(
                    "entra_client_secret is required for Microsoft Entra ID integrations."
                )
        # ── Snowflake message 1 — provider foundation ─────────────────────────
        elif self.provider == "snowflake":
            if not self.snowflake_account_identifier:
                raise ValueError(
                    "snowflake_account_identifier is required for Snowflake integrations."
                )
            if not self.snowflake_username:
                raise ValueError(
                    "snowflake_username is required for Snowflake integrations."
                )
            if not self.snowflake_programmatic_access_token:
                raise ValueError(
                    "snowflake_programmatic_access_token is required for Snowflake integrations."
                )
            if not self.snowflake_role:
                raise ValueError(
                    "snowflake_role is required for Snowflake integrations."
                )
        # ── Sentry message 1 — provider foundation ────────────────────────────
        elif self.provider == "sentry":
            if not self.sentry_organization_slug:
                raise ValueError(
                    "sentry_organization_slug is required for Sentry integrations."
                )
            if not self.sentry_auth_token:
                raise ValueError(
                    "sentry_auth_token is required for Sentry integrations."
                )
        return self


class IntegrationUpdateRequest(BaseModel):
    """Request body for ``PATCH /integrations/{id}``.

    All fields are optional — only the provided fields are updated.
    At least one field must be present.

    Constraints:
    - ``status`` may only be set to ``"active"`` or ``"paused"`` via this
      endpoint.  Soft-delete is performed via ``DELETE /integrations/{id}``.
    - ``sync_interval_minutes`` must be one of: 5, 10, 15, 30, 60.
    """

    display_name: Optional[str] = Field(
        None,
        min_length=1,
        max_length=200,
        description="New display name for the integration.",
    )
    sync_interval_minutes: Optional[int] = Field(
        None,
        description=(
            "Scheduled sync cadence in minutes. "
            "Allowed values: 5, 10, 15, 30, 60. "
            "Default (when null): 60."
        ),
    )
    status: Optional[Literal["active", "paused"]] = Field(
        None,
        description=(
            "Integration status. Use 'paused' to suspend scheduled syncs "
            "and block manual Sync Now requests. Use 'active' to re-enable."
        ),
    )

    @model_validator(mode="after")
    def validate_at_least_one_field(self) -> "IntegrationUpdateRequest":
        if (
            self.display_name is None
            and self.sync_interval_minutes is None
            and self.status is None
        ):
            raise ValueError(
                "At least one field (display_name, sync_interval_minutes, "
                "or status) must be provided."
            )
        if (
            self.sync_interval_minutes is not None
            and self.sync_interval_minutes not in _ALLOWED_SYNC_INTERVALS
        ):
            raise ValueError(
                f"sync_interval_minutes must be one of: "
                f"{sorted(_ALLOWED_SYNC_INTERVALS)}."
            )
        return self


class IntegrationReconnectRequest(BaseModel):
    """Request body for ``POST /integrations/{id}/reconnect``.

    Token-only reconnect — the integration's underlying resource (Cloudflare
    zone_id or GitHub owner/repo) cannot be changed via this endpoint.

    Provide ``api_token`` for Cloudflare integrations.
    Provide ``github_token`` for GitHub integrations.
    The backend uses the integration's existing provider to determine which
    field is required.  The token is validated against the live provider API
    before saving.  Tokens are never logged or returned.
    """

    api_token: Optional[str] = Field(
        None,
        min_length=1,
        description=(
            "New Cloudflare API token. Required for Cloudflare integrations."
        ),
    )
    github_token: Optional[str] = Field(
        None,
        min_length=1,
        description=(
            "New GitHub Personal Access Token. Required for GitHub integrations."
        ),
    )
    vercel_token: Optional[str] = Field(
        None,
        min_length=1,
        description=(
            "New Vercel personal access token. Required for Vercel integrations."
        ),
    )
    stripe_api_key: Optional[str] = Field(
        None,
        min_length=1,
        description=(
            "New Stripe restricted API key. Required for Stripe integrations."
        ),
    )
    aws_access_key_id: Optional[str] = Field(
        None,
        min_length=1,
        description=(
            "New AWS access key ID. Required for AWS integrations."
        ),
    )
    aws_secret_access_key: Optional[str] = Field(
        None,
        min_length=1,
        description=(
            "New AWS secret access key. Required for AWS integrations."
        ),
    )
    firebase_service_account_json: Optional[str] = Field(
        None,
        min_length=1,
        description=(
            "New Firebase service account JSON. Required for Firebase integrations. "
            "Stored encrypted — never returned in API responses."
        ),
    )
    supabase_access_token: Optional[str] = Field(
        None,
        min_length=1,
        description=(
            "New Supabase Management API access token (sbp_...). "
            "Required for Supabase integrations. "
            "Stored encrypted — never returned in API responses."
        ),
    )
    shopify_access_token: Optional[str] = Field(
        None,
        min_length=1,
        description=(
            "New Shopify Admin API access token. "
            "Required for Shopify integrations. "
            "Stored encrypted — never returned in API responses."
        ),
    )
    kubeconfig: Optional[str] = Field(
        None,
        min_length=1,
        description=(
            "New kubeconfig YAML content. Required for Kubernetes integrations. "
            "A kubeconfig for the SAME cluster (including a rotated credential) "
            "is accepted; a kubeconfig for a genuinely different cluster is "
            "rejected. Stored encrypted — never returned in API responses."
        ),
    )
    context: Optional[str] = Field(
        None,
        description=(
            "Optional kubeconfig context to use. Defaults to the kubeconfig's "
            "current-context if omitted. Kubernetes integrations only."
        ),
    )
    cluster_name: Optional[str] = Field(
        None,
        description="Optional display name update. Kubernetes integrations only.",
    )
    namespace_allowlist: Optional[list[str]] = Field(
        None,
        description="Optional namespace allowlist update. Kubernetes integrations only.",
    )
    okta_org_url: Optional[str] = Field(
        None,
        min_length=1,
        description=(
            "Optional new Okta org base URL. Okta integrations only. Only "
            "needed when rotating to a token from a different Okta org URL "
            "for the SAME tenant (e.g. a custom-domain migration) — a token "
            "rotation with no org URL change may omit this field. A URL "
            "that resolves to a genuinely different Okta tenant is rejected."
        ),
    )
    okta_api_token: Optional[str] = Field(
        None,
        min_length=1,
        description=(
            "New Okta API token. Required for Okta integrations. A rotated "
            "token for the SAME tenant is accepted; a token for a different "
            "tenant is rejected. Stored encrypted — never returned in API "
            "responses."
        ),
    )
    entra_tenant_id: Optional[str] = Field(
        None,
        min_length=1,
        description=(
            "Optional new Microsoft Entra tenant ID. Entra integrations "
            "only. Only needed when rotating credentials for a different "
            "tenant GUID — a secret rotation with no tenant change may "
            "omit this field. A tenant ID that resolves to a genuinely "
            "different tenant than the one this integration is connected "
            "to is rejected."
        ),
    )
    entra_client_id: Optional[str] = Field(
        None,
        min_length=1,
        description=(
            "Optional new Microsoft Entra application (client) ID. Entra "
            "integrations only. Only needed when rotating to a different "
            "app registration for the SAME tenant — a secret rotation "
            "with no client change may omit this field."
        ),
    )
    entra_client_secret: Optional[str] = Field(
        None,
        min_length=1,
        description=(
            "New Microsoft Entra application client secret. Required for "
            "Entra integrations. A rotated secret for the SAME tenant is "
            "accepted; credentials resolving to a different tenant are "
            "rejected. Stored encrypted — never returned in API responses."
        ),
    )
    snowflake_account_identifier: Optional[str] = Field(
        None,
        min_length=1,
        description=(
            "Optional new Snowflake account identifier. Snowflake "
            "integrations only. Only needed when rotating to a different "
            "identifier string for the SAME underlying account — a PAT "
            "rotation with no identifier change may omit this field. An "
            "identifier that resolves to a genuinely different Snowflake "
            "account is rejected."
        ),
    )
    snowflake_username: Optional[str] = Field(
        None,
        min_length=1,
        description=(
            "Optional new Snowflake username. Snowflake integrations only. "
            "Only needed when rotating to a new service user for the SAME "
            "account — a PAT rotation with no username change may omit "
            "this field."
        ),
    )
    snowflake_programmatic_access_token: Optional[str] = Field(
        None,
        min_length=1,
        description=(
            "New Snowflake Programmatic Access Token. Required for "
            "Snowflake integrations. A rotated PAT for the SAME account is "
            "accepted; credentials resolving to a different account are "
            "rejected. Stored encrypted — never returned in API responses."
        ),
    )
    snowflake_role: Optional[str] = Field(
        None,
        min_length=1,
        description=(
            "Optional new Snowflake monitoring role. Snowflake integrations "
            "only. Only needed when rotating to a different role for the "
            "SAME account — accepted after validation; coverage "
            "diagnostics are recomputed against the new role."
        ),
    )
    sentry_organization_slug: Optional[str] = Field(
        None,
        min_length=1,
        description=(
            "Optional new Sentry organization slug. Sentry integrations "
            "only. Only needed when the organization was renamed in "
            "Sentry — a token rotation with no slug change may omit this "
            "field. A slug that resolves to a genuinely different "
            "organization (different stable organization ID) is rejected."
        ),
    )
    sentry_auth_token: Optional[str] = Field(
        None,
        min_length=1,
        description=(
            "New Sentry organization auth token. Required for Sentry "
            "integrations. A rotated token for the SAME organization is "
            "accepted; credentials resolving to a different organization "
            "are rejected. Stored encrypted — never returned in API "
            "responses."
        ),
    )


class IntegrationResponse(BaseModel):
    """Safe representation of a single integration — no credentials."""

    id: UUID4
    provider: str
    display_name: str
    status: str
    last_synced_at: Optional[datetime]
    created_at: datetime
    # Populated from the ``Integration.resource_count`` property.  The
    # ``resources`` relationship is loaded eagerly (selectin) so this incurs
    # no additional query.
    resource_count: int = 0

    # ── M29 additions ─────────────────────────────────────────────────────────
    # ``sync_interval_minutes`` comes from the Integration column (dormant in
    # prior milestones).  ``last_sync_status`` and ``last_sync_error`` are
    # populated from the most recent SyncRun by the router helper
    # ``_build_response`` — they are not ORM attributes.
    sync_interval_minutes: Optional[int] = None
    last_sync_status: Optional[str] = None
    last_sync_error: Optional[str] = None

    # ── M59.15 addition ───────────────────────────────────────────────────────
    # ``last_sync_failure_category`` — stable, machine-readable category from
    # the M32 failure classifier on the most recent SyncRun.  Values match
    # ``SyncRun.failure_category``: ``authentication``, ``resource_missing``,
    # ``provider_unavailable``, ``rate_limited``, ``network``, ``config_error``,
    # ``internal_error``, ``unknown``, or null when no failed run exists.
    #
    # Exposed so the frontend can derive a display status (Active / Needs
    # attention / Degraded) without string-matching on the free-text
    # ``last_sync_error`` message.  Backend ``status`` is unchanged — this is
    # purely a UI-derivation hint that's safe to expose (no secrets, no PII,
    # just a category label).
    last_sync_failure_category: Optional[str] = None

    # ── M31 addition ──────────────────────────────────────────────────────────
    # Derived without credential decryption — read from resource_metadata.
    # Values: "github_app" | "pat" (GitHub only) | None (non-GitHub providers).
    # This field is safe to expose — it conveys the auth method, not a secret.
    connection_method: Optional[str] = None

    # ── M32 additions ─────────────────────────────────────────────────────────
    # consecutive_failure_count: number of consecutive *scheduled* sync failures
    #   since the last success.  Reset to 0 on any successful sync.
    # needs_attention: True when consecutive_failure_count >= 3.  Populated by
    #   the router helper so the frontend can show a warning badge without
    #   knowing the threshold.
    consecutive_failure_count: int = 0
    needs_attention: bool = False

    # ── M57.6 additions ───────────────────────────────────────────────────────
    # scheduled_sync_enabled: whether automated scheduled syncing is turned on.
    #   False → manual-only integration (syncs only when user triggers explicitly).
    #   Exposed so the frontend can show honest cadence copy:
    #   "Manual sync only" vs. "Monitoring cadence: every N min".
    # last_failure_at: UTC timestamp of the most recent sync failure of any type.
    #   Used for time-since-failure display and stale-sync warnings.
    scheduled_sync_enabled: bool = False
    last_failure_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class IntegrationListResponse(BaseModel):
    """Response body for ``GET /integrations``."""

    integrations: list[IntegrationResponse]
    total: int
