"""Vercel connector schema — M33.

TypedDict definitions for each record type the Vercel connector produces.

SECURITY CONSTRAINT (M33)
--------------------------
``VercelEnvVarRecord`` deliberately omits the ``value`` field.  Vercel
environment variable values are NEVER stored in snapshots, timelines,
emails, logs, or tests.  Only metadata (key name, target environments, type)
is recorded so operators can detect when secrets are rotated or reassigned
without ever exposing what the secret actually contains.

Record types
------------
vercel_project   — project-level settings (framework, build config)
vercel_env_var   — environment variable metadata (name + target, NOT value)
vercel_domain    — custom domain configuration
"""

from __future__ import annotations

from typing import List, Optional

from typing_extensions import TypedDict

# ── Record type constants ─────────────────────────────────────────────────────

VERCEL_PROJECT: str = "vercel_project"
VERCEL_ENV_VAR: str = "vercel_env_var"
VERCEL_DOMAIN: str = "vercel_domain"
VERCEL_DEPLOY_HOOK_METADATA: str = "vercel_deploy_hook_metadata"  # M57.9

# ── M59.12 — Vercel expansion: deployments / access / config / runtime ────────

# One per Vercel deployment.  Production aliasing and rollback are surfaced
# via field_paths on this record.
VERCEL_DEPLOYMENT: str = "vercel_deployment"

# One per team / project member.  Captures role + outside-collaborator
# status — never PII beyond the Vercel username/email already public on
# the team's member list.
VERCEL_TEAM_MEMBER: str = "vercel_team_member"

# One per Edge Config item / feature flag.  SECURITY: raw values are NEVER
# stored — only the key name, content hash, value type, and target/env.
VERCEL_EDGE_CONFIG_ITEM: str = "vercel_edge_config_item"

# One per Vercel cron job.
VERCEL_CRON_JOB: str = "vercel_cron_job"

# Per-project deployment-protection posture.  Separate from
# vercel_project so granular toggles diff cleanly.
VERCEL_DEPLOYMENT_PROTECTION: str = "vercel_deployment_protection"

# One per installed integration.
VERCEL_INTEGRATION_INSTALLATION: str = "vercel_integration_installation"

# Per-project function / runtime metadata (one record per project — covers
# the project-wide defaults for serverless / edge functions).
VERCEL_FUNCTION_RUNTIME: str = "vercel_function_runtime"

# One per Vercel firewall (Web Application Firewall) rule.  SECURITY: raw
# rule expressions are NEVER stored — only their sha256 hash.
VERCEL_FIREWALL_RULE: str = "vercel_firewall_rule"

VERCEL_RECORD_TYPES: frozenset[str] = frozenset({
    VERCEL_PROJECT,
    VERCEL_ENV_VAR,
    VERCEL_DOMAIN,
    VERCEL_DEPLOY_HOOK_METADATA,
    # M59.12 expansion
    VERCEL_DEPLOYMENT,
    VERCEL_TEAM_MEMBER,
    VERCEL_EDGE_CONFIG_ITEM,
    VERCEL_CRON_JOB,
    VERCEL_DEPLOYMENT_PROTECTION,
    VERCEL_INTEGRATION_INSTALLATION,
    VERCEL_FUNCTION_RUNTIME,
    VERCEL_FIREWALL_RULE,
})


# ── TypedDicts ────────────────────────────────────────────────────────────────


class VercelProjectRecord(TypedDict):
    """Project-level settings snapshot."""

    record_id: str           # Vercel project ID (prj_xxx) or slug
    record_type: str         # "vercel_project"
    name: str                # project slug name
    framework: Optional[str]          # "nextjs", "create-react-app", etc.
    build_command: Optional[str]      # custom build command or None
    install_command: Optional[str]    # custom install command or None
    output_directory: Optional[str]   # custom output directory or None
    root_directory: Optional[str]     # monorepo root directory or None
    node_version: Optional[str]       # "20.x", "18.x", etc.
    # Git connection
    git_repository: Optional[str]     # connected repo, e.g. "owner/repo"
    git_branch: Optional[str]         # production branch, e.g. "main"
    # Deployment protection (normalized to deploymentType string or None)
    sso_protection: Optional[str]     # None = disabled; "all" / "preview" = enabled
    password_protection: Optional[str]  # None = disabled; "all" / "preview" = enabled


class VercelEnvVarRecord(TypedDict):
    """Environment variable metadata.

    SECURITY: ``value`` is intentionally omitted — values must NEVER be stored.
    Only the key name, target environments, and type are recorded.  A change
    in ``updated_at`` signals a credential rotation without revealing the new
    secret value.
    """

    record_id: str           # Vercel env var ID
    record_type: str         # "vercel_env_var"
    name: str                # env var key name (same as ``key``)
    key: str                 # env var key name (e.g. "DATABASE_URL")
    env_type: Optional[str]  # "encrypted", "plain", "secret", "system"
    target: List[str]        # sorted: ["production"], ["preview", "development"], etc.
    git_branch: Optional[str]    # branch-scoped env var (preview only)
    created_at: Optional[int]    # Unix ms timestamp (immutable after creation)
    updated_at: Optional[int]    # Unix ms timestamp — change signals value rotation
    # NOTE: "value" is deliberately NOT present here (M33 security constraint)


class VercelDomainRecord(TypedDict):
    """Custom domain configuration."""

    record_id: str           # domain name used as stable ID
    record_type: str         # "vercel_domain"
    name: str                # domain name (e.g. "app.example.com")
    verified: bool           # whether Vercel has verified domain ownership
    git_branch: Optional[str]    # branch-specific domain (preview only)
    redirect: Optional[str]      # redirect target if this domain redirects
    created_at: Optional[int]    # Unix ms timestamp
    updated_at: Optional[int]    # Unix ms timestamp


class VercelDeployHookMetadataRecord(TypedDict):
    """Deploy hook metadata — M57.9.

    One record per deploy hook on the project.  Deploy hooks trigger
    deployments via a unique URL; that URL is NOT stored because it acts as an
    auth token.  Only the hook's stable ID, user-visible name, and target git
    ref are recorded so operators can detect when hooks are added or removed.

    Fields
    ------
    record_id
        ``"{project_id}#deploy_hook#{hook_id}"``
    record_type
        ``VERCEL_DEPLOY_HOOK_METADATA``
    name
        User-defined hook name (e.g. ``"nightly-rebuild"``).
    hook_id
        The hook's stable UUID assigned by Vercel.
    hook_name
        Duplicate of ``name`` — explicit tracked field.
    hook_ref
        Git branch or tag this hook deploys (e.g. ``"main"``).

    SECURITY
    --------
    The hook ``url`` field is NEVER stored — it functions as an auth token
    and its exposure would allow unauthorized deployments.
    """

    record_id: str           # "{project_id}#deploy_hook#{hook_id}"
    record_type: str         # "vercel_deploy_hook_metadata"
    name: str                # user-defined hook name
    hook_id: str             # stable hook UUID
    hook_name: str           # same as name — explicit tracked field
    hook_ref: Optional[str]  # target git ref/branch, e.g. "main"


# ── M59.12 Vercel expansion — TypedDicts ─────────────────────────────────────


class VercelDeploymentRecord(TypedDict, total=False):
    """One per Vercel deployment.

    SECURITY: deploy hook URLs, signed preview URLs, and Authorization
    headers are NEVER stored.  Deployment URLs ARE persisted (they are
    intentionally public per Vercel's design — a deployment URL alone
    cannot be used to authenticate).
    """

    record_id: str               # Vercel deployment id (dpl_xxx)
    record_type: str             # always "vercel_deployment"
    name: str                    # short display label
    project_id: str
    target: str                  # "production" | "preview" | "staging"
    state: str                   # "BUILDING"|"READY"|"ERROR"|"CANCELED"|"QUEUED"
    is_current_production_alias: bool
    source_branch: str | None
    source_commit_sha: str | None
    creator_username: str | None
    created_at: int              # epoch seconds
    deployment_url: str | None   # public Vercel-supplied URL


class VercelTeamMemberRecord(TypedDict, total=False):
    """One per team or project member.

    SECURITY: only role + outside-collaborator flag are stored.  No emails
    or PII beyond what's already public in Vercel's member list.
    """

    record_id: str               # Vercel user id or team-member id
    record_type: str             # always "vercel_team_member"
    name: str                    # username/slug
    role: str                    # "OWNER"|"ADMIN"|"DEVELOPER"|"MEMBER"|"VIEWER"
    is_outside_collaborator: bool
    project_scope: list[str]     # list of project ids the member has access to


class VercelEdgeConfigItemRecord(TypedDict, total=False):
    """One per Edge Config item / feature flag.

    SECURITY: the value itself is NEVER persisted — only the key name,
    a sha256 ``value_hash``, the value type, and the target environment.
    Operators sometimes store secrets in Edge Config (against best practice);
    storing only the hash defends against that misconfiguration.
    """

    record_id: str               # config-id + key
    record_type: str             # always "vercel_edge_config_item"
    name: str                    # key name
    config_id: str
    key: str
    value_hash: str              # sha256 of the value
    value_type: str              # "string"|"number"|"boolean"|"array"|"object"
    target: str                  # "production"|"preview"|"development"|"all"


class VercelCronJobRecord(TypedDict, total=False):
    """One per Vercel cron job."""

    record_id: str               # cron id
    record_type: str             # always "vercel_cron_job"
    name: str
    project_id: str
    schedule: str                # cron expression
    path: str                    # target route within the deployment
    enabled: bool
    target_env: str              # "production"|"preview"|"all"
    region: str | None


class VercelDeploymentProtectionRecord(TypedDict, total=False):
    """Per-project deployment-protection posture (singleton per project)."""

    record_id: str               # project id
    record_type: str             # always "vercel_deployment_protection"
    name: str                    # project name
    sso_enabled: bool            # Vercel Authentication
    password_enabled: bool
    protection_bypass_for_automation: bool
    trusted_ips_count: int
    trusted_ips_cidr_hash: str   # sha256 of sorted CIDR list — never raw list
    preview_comments_public: bool
    preview_deployments_protected: bool


class VercelIntegrationInstallationRecord(TypedDict, total=False):
    """One per installed integration."""

    record_id: str               # integration installation id
    record_type: str             # always "vercel_integration_installation"
    name: str                    # short integration name/slug
    scope_type: str              # "team"|"user"
    project_count: int           # number of projects this integration covers
    has_env_access: bool
    has_deployment_access: bool
    has_domain_access: bool
    has_admin_access: bool
    installed_by_user_id: str | None
    installed_at: int            # epoch seconds


class VercelFunctionRuntimeRecord(TypedDict, total=False):
    """Per-project function / runtime metadata (singleton per project)."""

    record_id: str               # project id
    record_type: str             # always "vercel_function_runtime"
    name: str
    default_runtime: str         # "nodejs20.x"|"nodejs18.x"|"edge"|"python3.12"|…
    default_region: str          # e.g. "iad1"
    default_max_duration_seconds: int
    default_memory_mb: int
    edge_function_count: int
    serverless_function_count: int
    public_function_route_count: int  # number of routes exposed publicly


class VercelFirewallRuleRecord(TypedDict, total=False):
    """One per Vercel firewall (WAF) rule.

    SECURITY: raw rule expressions are NEVER stored — only their sha256
    ``expression_hash``.  Expressions can encode sensitive customer
    paths, attacker fingerprints, and detection logic.
    """

    record_id: str               # firewall rule id
    record_type: str             # always "vercel_firewall_rule"
    name: str                    # short label
    description: str | None      # short label, user-supplied
    action: str                  # "block"|"challenge"|"allow"|"log"|"bypass"
    enabled: bool
    expression_hash: str         # sha256 of the rule expression
    targets_production: bool
