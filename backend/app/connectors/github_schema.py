"""Normalised schema for GitHub repository configuration records.

Seven categories of repository configuration are monitored and stored as
plain dicts inside ``Snapshot.state``.  Each dict contains ``record_id``
(the stable join key used by the diff service) and ``record_type`` (used by
the diff service and risk service for field-set dispatch and rule routing).

Record-type string constants
-----------------------------
``GITHUB_REPO_SETTINGS``       — overall repository settings
``GITHUB_BRANCH_PROTECTION``   — branch-level protection rules
``GITHUB_ACTIONS_SECRET``      — Actions secret metadata (name + timestamps only)
``GITHUB_ACTIONS_VARIABLE``    — Actions variable (name + value)
``GITHUB_WEBHOOK``             — repository webhook configuration
``GITHUB_ACTIONS_PERMISSIONS`` — Actions permissions for the repository
``GITHUB_DEPLOY_KEY``          — deploy key (title, read_only, verified)

Design notes
------------
* Secret *values* are intentionally absent — only the name and last-updated
  timestamp are stored.  Detecting ``last_updated_at`` changes is sufficient
  to surface credential rotation events without persisting the actual secret.
* ``record_id`` uses a composite string of the form
  ``"{owner}/{repo}#{category}#{discriminator}"`` so records from the same
  repository never collide even if multiple categories are mixed in a single
  snapshot state list.
* All TypedDicts use ``from __future__ import annotations`` compatible
  Optional (not ``X | Y`` syntax) for Python 3.9 compatibility.
"""

from __future__ import annotations

from typing import List, Optional

try:
    from typing import TypedDict
except ImportError:  # Python < 3.8 — not expected in this project
    from typing_extensions import TypedDict  # type: ignore[assignment]


# ── Record type identifier constants ────────────────────────────────────────

GITHUB_REPO_SETTINGS = "github_repo_settings"
GITHUB_BRANCH_PROTECTION = "github_branch_protection"
GITHUB_ACTIONS_SECRET = "github_actions_secret"
GITHUB_ACTIONS_VARIABLE = "github_actions_variable"
GITHUB_WEBHOOK = "github_webhook"
GITHUB_ACTIONS_PERMISSIONS = "github_actions_permissions"
GITHUB_DEPLOY_KEY = "github_deploy_key"
GITHUB_ENVIRONMENT_PROTECTION = "github_environment_protection"  # M57.9

# ── M59.6 — Additional GitHub surfaces ───────────────────────────────────────
# Modern branch/tag rulesets (replacement for legacy branch protection).
GITHUB_RULESET = "github_ruleset"

# CODEOWNERS file ownership snapshot.  Stores hash + critical-path coverage —
# the full file contents are NOT persisted.
GITHUB_CODEOWNERS = "github_codeowners"

# Individual Actions workflow file (one record per ``.github/workflows/*.yml``).
# Stores path + content hash + safe permissions/triggers summary — raw YAML
# is NEVER persisted.
GITHUB_WORKFLOW_FILE = "github_workflow_file"

# OIDC trust signal — a cloud-side role's trust policy that references a
# GitHub OIDC subject pattern.  Stored conservatively (hashes + flags); raw
# IAM/ARN strings or OIDC tokens are NEVER persisted.
GITHUB_OIDC_TRUST = "github_oidc_trust"

# Repository collaborator (user or team) with a permission level.  One record
# per actor.  No PII beyond the GitHub login/team slug.
GITHUB_COLLABORATOR = "github_collaborator"

# GitHub App installation on a repo or org, including its current permission
# scope.  App private keys / installation tokens are NEVER stored.
GITHUB_APP_INSTALLATION = "github_app_installation"

# Repository security-feature posture: secret scanning, push protection,
# code scanning, Dependabot, vulnerability alerts.
GITHUB_SECURITY_FEATURES = "github_security_features"

# Automation credential / token permission posture (M69.5B). One record per
# repository describing the authenticated credential's repo permission level and
# (for classic PATs) its OAuth scope NAMES — never the token, headers, or
# secrets. Used to surface broad automation blast radius.
GITHUB_AUTOMATION_PERMISSIONS = "github_automation_permissions"

# GitHub Pages configuration for the repository (one record when Pages is
# enabled; a disabled/unknown record otherwise). Never stores the CNAME
# domain itself or any certificate material — presence/posture booleans only.
GITHUB_PAGES = "github_pages"

#: Set of all GitHub record type strings — used for fast membership checks.
GITHUB_RECORD_TYPES: frozenset[str] = frozenset({
    GITHUB_REPO_SETTINGS,
    GITHUB_BRANCH_PROTECTION,
    GITHUB_ACTIONS_SECRET,
    GITHUB_ACTIONS_VARIABLE,
    GITHUB_WEBHOOK,
    GITHUB_ACTIONS_PERMISSIONS,
    GITHUB_DEPLOY_KEY,
    GITHUB_ENVIRONMENT_PROTECTION,
    GITHUB_RULESET,
    GITHUB_CODEOWNERS,
    GITHUB_WORKFLOW_FILE,
    GITHUB_OIDC_TRUST,
    GITHUB_COLLABORATOR,
    GITHUB_APP_INSTALLATION,
    GITHUB_SECURITY_FEATURES,
    GITHUB_AUTOMATION_PERMISSIONS,
    GITHUB_PAGES,
})


# ── TypedDicts ────────────────────────────────────────────────────────────────

class GitHubRepoSettings(TypedDict):
    """Overall repository settings.

    Fields
    ------
    record_id
        ``"{owner}/{repo}#settings"``
    record_type
        ``GITHUB_REPO_SETTINGS``
    name
        ``"{owner}/{repo}"`` — used by ``format_record_identifier``.
    visibility
        ``"public"``, ``"private"``, or ``"internal"``.
    default_branch
        Name of the default branch (e.g. ``"main"``).
    has_issues, has_projects, has_wiki
        Feature flags for built-in GitHub features.
    allow_merge_commit, allow_squash_merge, allow_rebase_merge
        Which merge strategies are permitted on pull requests.
    delete_branch_on_merge
        Whether GitHub automatically deletes head branches after merge.
    archived
        Whether the repository is archived (read-only).
    """
    record_id: str
    record_type: str
    name: str
    visibility: str
    default_branch: str
    has_issues: bool
    has_projects: bool
    has_wiki: bool
    allow_merge_commit: bool
    allow_squash_merge: bool
    allow_rebase_merge: bool
    delete_branch_on_merge: bool
    archived: bool


class GitHubBranchProtection(TypedDict):
    """Branch-level protection rule snapshot.

    When no protection rule is configured for a branch, all boolean fields
    are ``False`` and ``required_approving_review_count`` is ``None``.

    Fields
    ------
    record_id
        ``"{owner}/{repo}#branch_protection#{branch}"``
    record_type
        ``GITHUB_BRANCH_PROTECTION``
    name
        ``"{branch} branch"`` — used by ``format_record_identifier``.
    branch
        Branch name (e.g. ``"main"``).
    protection_enabled
        ``False`` when no rule is configured (404 from GitHub).
    required_status_checks_enabled
        Whether required status checks are configured.
    required_pull_request_reviews_enabled
        Whether PR review requirements are configured.
    required_approving_review_count
        Minimum number of approving reviews required.  ``None`` when
        ``required_pull_request_reviews_enabled`` is ``False``.
    dismiss_stale_reviews
        Whether approvals are dismissed when new commits are pushed.
    enforce_admins
        Whether admins are also subject to branch protection rules.
    required_linear_history
        Whether force-pushes creating non-linear history are blocked.
    allow_force_pushes
        Whether force-pushes to this branch are permitted.
    allow_deletions
        Whether branch deletion is permitted.
    """
    record_id: str
    record_type: str
    name: str
    branch: str
    protection_enabled: bool
    required_status_checks_enabled: bool
    required_pull_request_reviews_enabled: bool
    required_approving_review_count: Optional[int]
    dismiss_stale_reviews: bool
    enforce_admins: bool
    required_linear_history: bool
    allow_force_pushes: bool
    allow_deletions: bool


class GitHubActionsSecret(TypedDict):
    """Actions secret metadata — name and rotation timestamp only.

    Secret *values* are intentionally never fetched or stored.
    Changes to ``last_updated_at`` indicate a rotation event.

    Fields
    ------
    record_id
        ``"{owner}/{repo}#secret#{name}"``
    record_type
        ``GITHUB_ACTIONS_SECRET``
    name
        Secret name (also the display label for ``format_record_identifier``).
    secret_name
        Duplicate of ``name`` — kept as an explicit tracked field so the
        diff service can detect name-level changes if a secret is deleted
        and recreated with a different name.
    last_updated_at
        ISO 8601 timestamp of the last secret update.  A change in this
        field indicates a secret rotation.
    """
    record_id: str
    record_type: str
    name: str
    secret_name: str
    last_updated_at: str


class GitHubActionsVariable(TypedDict):
    """Actions variable (name + value).

    Variables are not secrets and their values are stored.

    Fields
    ------
    record_id
        ``"{owner}/{repo}#variable#{name}"``
    record_type
        ``GITHUB_ACTIONS_VARIABLE``
    name
        Variable name (display label).
    variable_name
        Duplicate of ``name`` — explicit tracked field.
    value
        Variable value string.
    """
    record_id: str
    record_type: str
    name: str
    variable_name: str
    value: str


class GitHubWebhook(TypedDict):
    """Repository webhook configuration.

    Fields
    ------
    record_id
        ``"{owner}/{repo}#webhook#{id}"``
    record_type
        ``GITHUB_WEBHOOK``
    name
        ``"hook #{id}"`` — display label.
    hook_id
        GitHub's numeric ID for the webhook.
    url
        Delivery URL (from ``config.url``).
    active
        Whether the webhook is currently active.
    events
        Sorted list of subscribed event strings (e.g. ``["push", "pull_request"]``).
    content_type
        Delivery content-type: ``"json"`` or ``"form"``.
    webhook_secret_configured
        Whether a signing secret is configured (boolean presence only — the
        secret value itself is never stored).
    insecure_ssl_enabled
        Normalized from ``config.insecure_ssl``. ``True`` means SSL
        verification is disabled for deliveries; ``False`` means it's
        enabled; ``None`` means the field was absent or unrecognised.
    ssl_verification_enabled
        Inverse of ``insecure_ssl_enabled`` (``None`` stays ``None``).
    """
    record_id: str
    record_type: str
    name: str
    hook_id: int
    url: str
    active: bool
    events: List[str]
    content_type: str
    webhook_secret_configured: bool
    insecure_ssl_enabled: Optional[bool]
    ssl_verification_enabled: Optional[bool]


class GitHubActionsPermissions(TypedDict):
    """Actions permissions for the repository.

    Fields
    ------
    record_id
        ``"{owner}/{repo}#actions_permissions"``
    record_type
        ``GITHUB_ACTIONS_PERMISSIONS``
    name
        ``"{owner}/{repo}"`` — display label.
    enabled
        Whether GitHub Actions is enabled for this repository.
    allowed_actions
        Which actions can run: ``"all"``, ``"local_only"``, or ``"selected"``.
        Empty string when Actions is disabled.
    default_workflow_permissions
        Normalized default GITHUB_TOKEN permission scope: ``"read"`` or
        ``"write"``. ``None`` when the workflow-permissions sub-endpoint
        wasn't accessible (insufficient token scope) — never defaulted.
    can_approve_pull_request_reviews
        Whether GitHub Actions workflows may approve pull request reviews.
        ``None`` when unknown (same soft-fail as above).
    """
    record_id: str
    record_type: str
    name: str
    enabled: bool
    allowed_actions: str
    default_workflow_permissions: Optional[str]
    can_approve_pull_request_reviews: Optional[bool]


class GitHubDeployKey(TypedDict):
    """Repository deploy key.

    Fields
    ------
    record_id
        ``"{owner}/{repo}#deploy_key#{id}"``
    record_type
        ``GITHUB_DEPLOY_KEY``
    name
        Key title (display label).
    key_id
        GitHub's numeric ID for the deploy key.
    title
        Human-readable title of the key.
    read_only
        ``True`` if the key has read-only access; ``False`` for read-write.
    verified
        Whether the key has been verified by GitHub.
    """
    record_id: str
    record_type: str
    name: str
    key_id: int
    title: str
    read_only: bool
    verified: bool


class GitHubEnvironmentProtection(TypedDict):
    """Deployment environment protection rules — M57.9.

    One record per environment per repository.  Captures deployment guard rails
    (required reviewers, wait timers, branch policies) without reading source
    code, secret values, workflow files, or reviewer identities.

    Fields
    ------
    record_id
        ``"{owner}/{repo}#environment#{name}"``
    record_type
        ``GITHUB_ENVIRONMENT_PROTECTION``
    name
        Environment name (e.g. ``"production"``, ``"staging"``).
    environment_name
        Duplicate of ``name`` — explicit tracked field.
    wait_timer
        Required wait time in minutes before allowing deployments.  ``0`` when
        no wait timer protection rule is configured.
    reviewers_count
        Number of required reviewers before deployments are allowed.  ``0``
        when no reviewer requirement is configured.
    prevent_self_review
        Whether the actor who triggered the deployment is blocked from
        approving it.
    protected_branches
        ``True`` when only protected branches may deploy to this environment.
        ``None`` when no deployment branch policy is configured.
    custom_branch_policies
        ``True`` when custom branch name patterns control which branches can
        deploy.  ``None`` when no deployment branch policy is configured.

    SECURITY
    --------
    - Reviewer identities (user names / team names) are NEVER stored.
    - Secret names and values are NEVER read.
    - Workflow file contents are NEVER accessed.
    """
    record_id: str
    record_type: str
    name: str
    environment_name: str
    wait_timer: int
    reviewers_count: int
    prevent_self_review: bool
    protected_branches: Optional[bool]
    custom_branch_policies: Optional[bool]


# ── M59.6 — TypedDicts for new GitHub surfaces ────────────────────────────────


class GitHubRuleset(TypedDict, total=False):
    """Modern GitHub branch/tag ruleset.

    Replaces legacy branch protection on newer repos.  Stored fields are the
    aggregate posture — branch patterns and bypass-actor entries are stored as
    COUNTS only, not the raw lists.

    Security
    --------
    No actor logins, team slugs, or branch glob strings are persisted in
    this snapshot — only their counts.  See ``GitHubCollaborator`` for the
    per-actor record type used elsewhere.
    """

    record_type: str                    # always "github_ruleset"
    record_id: str                      # GitHub ruleset id
    name: str                           # human-readable name
    target: str                         # "branch" | "tag"
    enforcement: str                    # "active" | "evaluate" | "disabled"
    branch_patterns_count: int          # number of include/exclude patterns
    targets_protected_branch: bool      # heuristic: covers main/master/release/etc.
    bypass_actor_count: int
    required_status_checks_count: int
    required_pr_reviews_required: bool
    require_signed_commits: bool
    restrict_force_pushes: bool         # when False, force-push is ALLOWED
    restrict_deletions: bool            # when False, branch deletion is ALLOWED


class GitHubCodeowners(TypedDict, total=False):
    """CODEOWNERS file posture.

    Security
    --------
    The full file content is NEVER stored — only:
      * its sha256 content_hash (so diffs are detectable)
      * the count of rule lines
      * whether each critical path is covered (per-path bool map)
      * whether a wildcard owner exists.
    """

    record_type: str                    # always "github_codeowners"
    record_id: str                      # always "CODEOWNERS"
    path: str                           # ".github/CODEOWNERS" | "docs/CODEOWNERS" | …
    exists: bool
    content_hash: str
    rule_count: int
    wildcard_owner_present: bool
    # Map of critical-path → has_owners.  Keys are short labels:
    # ``"workflows"``, ``"infra"``, ``"terraform"``, ``"auth"``, ``"billing"``,
    # ``"security"``, ``"config"``.
    critical_paths_with_owners: dict


class GitHubWorkflowFile(TypedDict, total=False):
    """Single ``.github/workflows/*.yml`` workflow file posture.

    Security
    --------
    The raw YAML is NEVER stored.  Persisted fields are:
      * path + content_hash
      * a flat ``permissions_summary`` string (e.g. ``"write-all"`` /
        ``"contents:write,id-token:write"`` / ``"default"``)
      * a flat ``triggers_summary`` string (e.g. ``"push,pull_request"``)
      * boolean flags for high-signal triggers (``pull_request_target``)
      * job count + secret-reference count
      * a deploy heuristic flag.
    """

    record_type: str                    # always "github_workflow_file"
    record_id: str                      # workflow filename (e.g. "deploy.yml")
    path: str                           # ".github/workflows/deploy.yml"
    content_hash: str
    permissions_summary: str
    triggers_summary: str
    has_pull_request_target: bool
    job_count: int
    secret_reference_count: int
    is_deploy_workflow: bool            # heuristic from name/path/jobs
    enabled: bool


class GitHubOIDCTrust(TypedDict, total=False):
    """OIDC trust signal — a cloud-side role bound to a GitHub OIDC subject
    pattern.

    Security
    --------
    The role ARN / GCP resource path / Azure subscription id is HASHED (not
    stored verbatim).  No OIDC tokens, JWTs, or client secrets are ever
    persisted.  Subject/audience strings are stored because they ARE the
    trust policy, but they contain no credential material.
    """

    record_type: str                    # always "github_oidc_trust"
    record_id: str                      # opaque id (cloud-provided)
    cloud_provider: str                 # "aws" | "gcp" | "azure" | "other"
    cloud_role_hash: str                # sha256 of the role ARN/path
    audience: str                       # configured aud claim
    repo_pattern: str                   # e.g. "octocat/repo:ref:refs/heads/main"
    repo_wildcard: bool
    branch_wildcard: bool
    environment_restricted: bool        # True when sub claim pins :environment:
    # Whether the trust permits ANY repo in an org or org-wide wildcard.
    org_wildcard: bool


class GitHubCollaborator(TypedDict, total=False):
    """One repository collaborator (user or team) with their permission level.

    Security
    --------
    No PII is stored beyond the GitHub login / team slug, which is already
    public on GitHub.  No emails, tokens, or session info.
    """

    record_type: str                    # always "github_collaborator"
    record_id: str                      # "user:<login>" or "team:<slug>"
    actor_type: str                     # "user" | "team"
    actor_login: str                    # login or team slug
    is_outside_collaborator: bool       # user-only; teams are False
    permission: str                     # "read"|"triage"|"write"|"maintain"|"admin"


class GitHubAppInstallation(TypedDict, total=False):
    """GitHub App installation on a repo/org with its permission scope.

    Security
    --------
    No app private key, installation token, or JWT is ever stored.  Only the
    app slug + permission summary + repo-selection mode.
    """

    record_type: str                    # always "github_app_installation"
    record_id: str                      # installation id
    app_slug: str
    account_type: str                   # "user" | "organization"
    repository_selection: str           # "selected" | "all"
    repositories_count: int
    events_count: int
    permissions_summary: dict           # {"contents": "write", "actions": "read", …}
    has_admin_access: bool
    has_secrets_access: bool
    has_contents_write: bool
    has_workflows_write: bool


class GitHubSecurityFeatures(TypedDict, total=False):
    """Repo-level security-feature posture.

    Each field is a tri-state because GitHub's API can return ``None`` when a
    feature is not applicable (e.g. ``secret_scanning_push_protection`` is
    only available on private repos in some plans).
    """

    record_type: str                    # always "github_security_features"
    record_id: str                      # always "security"
    private_repo: bool
    secret_scanning_enabled: Optional[bool]
    secret_scanning_push_protection: Optional[bool]
    code_scanning_enabled: Optional[bool]
    dependabot_alerts_enabled: Optional[bool]
    dependabot_security_updates_enabled: Optional[bool]
    vulnerability_alerts_enabled: Optional[bool]


class GitHubPages(TypedDict, total=False):
    """GitHub Pages configuration for the repository.

    Fields
    ------
    record_id
        ``"{owner}/{repo}#pages"``
    record_type
        ``GITHUB_PAGES``
    name
        ``"{owner}/{repo}"`` — display label.
    pages_enabled
        Whether GitHub Pages is enabled (the ``/pages`` endpoint returned 200).
    pages_source_branch
        Source branch for the Pages build, or ``None`` when unknown/disabled.
    pages_source_path
        Source path within the branch (e.g. ``"/"`` or ``"/docs"``), or
        ``None`` when unknown/disabled.
    pages_build_type
        ``"legacy"`` or ``"workflow"`` (GitHub Actions-based build), or
        ``None`` when unknown/disabled.
    pages_cname_configured
        Whether a custom domain (CNAME) is configured. The domain string
        itself is never stored — presence boolean only.
    pages_https_enforced
        Whether HTTPS is enforced for the Pages site. ``None`` when unknown.
    pages_visibility
        ``"public"`` or ``"private"`` (private Pages sites are a GitHub
        Enterprise feature), or ``None`` when unknown/disabled.

    Security
    --------
    No certificate material, raw CNAME domain, or credentials are ever
    stored — only presence/posture booleans and safe enum strings.
    """

    record_id: str
    record_type: str
    name: str
    pages_enabled: bool
    pages_source_branch: Optional[str]
    pages_source_path: Optional[str]
    pages_build_type: Optional[str]
    pages_cname_configured: Optional[bool]
    pages_https_enforced: Optional[bool]
    pages_visibility: Optional[str]
