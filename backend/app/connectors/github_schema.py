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
    """
    record_id: str
    record_type: str
    name: str
    hook_id: int
    url: str
    active: bool
    events: List[str]
    content_type: str


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
    """
    record_id: str
    record_type: str
    name: str
    enabled: bool
    allowed_actions: str


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
