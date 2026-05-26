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

VERCEL_RECORD_TYPES: frozenset[str] = frozenset({
    VERCEL_PROJECT,
    VERCEL_ENV_VAR,
    VERCEL_DOMAIN,
    VERCEL_DEPLOY_HOOK_METADATA,
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
