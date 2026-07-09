"""Unit tests for the GitHub connector — Milestone 26.

All HTTP calls are intercepted by ``respx`` — no real network calls are made.
GitHub tokens are NEVER logged in these tests (assertions are on response data
only, never on credential values).

Run with:
    docker compose run --rm api pytest backend/tests/test_github_connector.py -v
"""

from __future__ import annotations

import pytest
import respx
import httpx

from app.connectors.github import GitHubConnector
from app.connectors.exceptions import (
    AuthenticationError,
    ConnectorError,
    NetworkError,
    RateLimitError,
)
from app.connectors.github_schema import (
    GITHUB_ACTIONS_PERMISSIONS,
    GITHUB_ACTIONS_SECRET,
    GITHUB_ACTIONS_VARIABLE,
    GITHUB_BRANCH_PROTECTION,
    GITHUB_DEPLOY_KEY,
    GITHUB_REPO_SETTINGS,
    GITHUB_WEBHOOK,
)

# ── Constants ────────────────────────────────────────────────────────────────

VALID_CREDS = {
    "github_token": "github_pat_test_token",
    "repo_owner": "acme",
    "repo_name": "myapp",
}
SLUG = "acme/myapp"
GH_BASE = "https://api.github.com"
REPO_URL = f"{GH_BASE}/repos/{SLUG}"
PROTECTION_URL = f"{REPO_URL}/branches/main/protection"
SECRETS_URL = f"{REPO_URL}/actions/secrets"
VARIABLES_URL = f"{REPO_URL}/actions/variables"
HOOKS_URL = f"{REPO_URL}/hooks"
PERMISSIONS_URL = f"{REPO_URL}/actions/permissions"
WORKFLOW_PERMISSIONS_URL = f"{REPO_URL}/actions/permissions/workflow"
KEYS_URL = f"{REPO_URL}/keys"


# ── Fixture ───────────────────────────────────────────────────────────────────

@pytest.fixture
def connector() -> GitHubConnector:
    return GitHubConnector()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _repo_raw(
    visibility: str = "private",
    default_branch: str = "main",
    archived: bool = False,
) -> dict:
    return {
        "visibility": visibility,
        "default_branch": default_branch,
        "has_issues": True,
        "has_projects": True,
        "has_wiki": False,
        "allow_merge_commit": True,
        "allow_squash_merge": True,
        "allow_rebase_merge": False,
        "delete_branch_on_merge": True,
        "archived": archived,
    }


def _protection_raw() -> dict:
    return {
        "required_pull_request_reviews": {
            "required_approving_review_count": 2,
            "dismiss_stale_reviews": True,
        },
        "required_status_checks": {
            "strict": True,
            "contexts": ["ci/build"],
        },
        "enforce_admins": {"enabled": True},
        "required_linear_history": {"enabled": False},
        "allow_force_pushes": {"enabled": False},
        "allow_deletions": {"enabled": False},
    }


def _secrets_envelope(secrets: list[dict]) -> dict:
    return {"total_count": len(secrets), "secrets": secrets}


def _variables_envelope(variables: list[dict]) -> dict:
    return {"total_count": len(variables), "variables": variables}


def _full_mock(
    *,
    repo_raw=None,
    protection_raw=None,
    protection_status: int = 200,
    secrets=None,
    variables=None,
    hooks=None,
    permissions=None,
    workflow_permissions=None,
    workflow_permissions_status: int = 200,
    deploy_keys=None,
):
    """Set up respx routes for all seven GitHub API endpoints."""
    if repo_raw is None:
        repo_raw = _repo_raw()
    if secrets is None:
        secrets = []
    if variables is None:
        variables = []
    if hooks is None:
        hooks = []
    if permissions is None:
        permissions = {"enabled": True, "allowed_actions": "all"}
    if workflow_permissions is None:
        workflow_permissions = {
            "default_workflow_permissions": "read",
            "can_approve_pull_request_reviews": False,
        }
    if deploy_keys is None:
        deploy_keys = []

    # Repo settings
    respx.get(REPO_URL).mock(return_value=httpx.Response(200, json=repo_raw))

    # Branch protection
    if protection_raw is None:
        if protection_status == 404:
            respx.get(PROTECTION_URL).mock(return_value=httpx.Response(404, json={"message": "Branch not protected"}))
        else:
            respx.get(PROTECTION_URL).mock(return_value=httpx.Response(200, json=_protection_raw()))
    else:
        respx.get(PROTECTION_URL).mock(return_value=httpx.Response(protection_status, json=protection_raw))

    # Secrets
    respx.get(SECRETS_URL).mock(return_value=httpx.Response(200, json=_secrets_envelope(secrets)))

    # Variables
    respx.get(VARIABLES_URL).mock(return_value=httpx.Response(200, json=_variables_envelope(variables)))

    # Hooks
    respx.get(HOOKS_URL).mock(return_value=httpx.Response(200, json=hooks))

    # Permissions
    respx.get(PERMISSIONS_URL).mock(return_value=httpx.Response(200, json=permissions))

    # Workflow permissions (default token permission + PR-approval posture)
    if workflow_permissions_status == 200:
        respx.get(WORKFLOW_PERMISSIONS_URL).mock(
            return_value=httpx.Response(200, json=workflow_permissions)
        )
    else:
        respx.get(WORKFLOW_PERMISSIONS_URL).mock(
            return_value=httpx.Response(workflow_permissions_status, json={"message": "Forbidden"})
        )

    # Deploy keys
    respx.get(KEYS_URL).mock(return_value=httpx.Response(200, json=deploy_keys))


# ── validate_credentials ──────────────────────────────────────────────────────

@respx.mock
def test_validate_credentials_success(connector: GitHubConnector) -> None:
    """validate_credentials returns True when the repo endpoint returns 200."""
    respx.get(REPO_URL).mock(return_value=httpx.Response(200, json=_repo_raw()))
    assert connector.validate_credentials(VALID_CREDS) is True


@respx.mock
def test_validate_credentials_401(connector: GitHubConnector) -> None:
    respx.get(REPO_URL).mock(return_value=httpx.Response(401, json={"message": "Bad credentials"}))
    with pytest.raises(AuthenticationError):
        connector.validate_credentials(VALID_CREDS)


@respx.mock
def test_validate_credentials_403(connector: GitHubConnector) -> None:
    respx.get(REPO_URL).mock(return_value=httpx.Response(403, json={"message": "Forbidden"}))
    with pytest.raises(AuthenticationError):
        connector.validate_credentials(VALID_CREDS)


@respx.mock
def test_validate_credentials_404(connector: GitHubConnector) -> None:
    """404 → ConnectorError (repo not found or no Metadata:Read access)."""
    respx.get(REPO_URL).mock(return_value=httpx.Response(404, json={"message": "Not Found"}))
    with pytest.raises(ConnectorError) as exc_info:
        connector.validate_credentials(VALID_CREDS)
    assert exc_info.value.status_code == 404


def test_validate_credentials_missing_fields(connector: GitHubConnector) -> None:
    with pytest.raises(ConnectorError, match="must include"):
        connector.validate_credentials({"github_token": "tok"})  # missing owner + repo


# ── fetch(): repo settings ────────────────────────────────────────────────────

@respx.mock
def test_fetch_repo_settings_fields(connector: GitHubConnector) -> None:
    """Repo settings record has correct record_id, record_type, and all fields."""
    raw = _repo_raw(visibility="public", default_branch="main")
    _full_mock(repo_raw=raw)

    records = connector.fetch(VALID_CREDS)
    settings = next(r for r in records if r["record_type"] == GITHUB_REPO_SETTINGS)

    assert settings["record_id"] == f"{SLUG}#settings"
    assert settings["name"] == SLUG
    assert settings["visibility"] == "public"
    assert settings["default_branch"] == "main"
    assert settings["has_issues"] is True
    assert settings["has_wiki"] is False
    assert settings["archived"] is False
    assert settings["delete_branch_on_merge"] is True


# ── fetch(): branch protection ────────────────────────────────────────────────

@respx.mock
def test_fetch_branch_protection_enabled(connector: GitHubConnector) -> None:
    """Branch protection fields are correctly normalised when a rule exists."""
    _full_mock(protection_raw=_protection_raw(), protection_status=200)
    records = connector.fetch(VALID_CREDS)
    bp = next(r for r in records if r["record_type"] == GITHUB_BRANCH_PROTECTION)

    assert bp["record_id"] == f"{SLUG}#branch_protection#main"
    assert bp["name"] == "main branch"
    assert bp["branch"] == "main"
    assert bp["protection_enabled"] is True
    assert bp["required_pull_request_reviews_enabled"] is True
    assert bp["required_approving_review_count"] == 2
    assert bp["dismiss_stale_reviews"] is True
    assert bp["enforce_admins"] is True
    assert bp["allow_force_pushes"] is False
    assert bp["allow_deletions"] is False


@respx.mock
def test_fetch_branch_protection_404_normalised(connector: GitHubConnector) -> None:
    """404 from branch protection API is normalised to a 'disabled' record."""
    _full_mock(protection_status=404)
    records = connector.fetch(VALID_CREDS)
    bp = next(r for r in records if r["record_type"] == GITHUB_BRANCH_PROTECTION)

    assert bp["protection_enabled"] is False
    assert bp["allow_force_pushes"] is False
    assert bp["required_approving_review_count"] is None


# ── fetch(): secrets ──────────────────────────────────────────────────────────

@respx.mock
def test_fetch_secrets_metadata_only(connector: GitHubConnector) -> None:
    """Secrets records contain name + last_updated_at only (no values)."""
    secrets = [
        {"name": "PROD_DB_PASSWORD", "created_at": "2024-01-01T00:00:00Z", "updated_at": "2024-06-01T12:00:00Z"},
        {"name": "API_KEY", "created_at": "2024-02-01T00:00:00Z", "updated_at": "2024-06-02T09:00:00Z"},
    ]
    _full_mock(secrets=secrets)
    records = connector.fetch(VALID_CREDS)
    secret_records = [r for r in records if r["record_type"] == GITHUB_ACTIONS_SECRET]

    assert len(secret_records) == 2
    names = {r["name"] for r in secret_records}
    assert names == {"PROD_DB_PASSWORD", "API_KEY"}

    prod_rec = next(r for r in secret_records if r["name"] == "PROD_DB_PASSWORD")
    assert prod_rec["record_id"] == f"{SLUG}#secret#PROD_DB_PASSWORD"
    assert prod_rec["last_updated_at"] == "2024-06-01T12:00:00Z"
    # Ensure no "value" field exists — values must NEVER be stored
    assert "value" not in prod_rec


# ── fetch(): variables ────────────────────────────────────────────────────────

@respx.mock
def test_fetch_variables(connector: GitHubConnector) -> None:
    """Variable records include name and value."""
    variables = [
        {"name": "REGION", "value": "us-east-1", "created_at": "2024-01-01T00:00:00Z", "updated_at": "2024-01-01T00:00:00Z"},
    ]
    _full_mock(variables=variables)
    records = connector.fetch(VALID_CREDS)
    var_records = [r for r in records if r["record_type"] == GITHUB_ACTIONS_VARIABLE]

    assert len(var_records) == 1
    assert var_records[0]["record_id"] == f"{SLUG}#variable#REGION"
    assert var_records[0]["value"] == "us-east-1"
    assert var_records[0]["variable_name"] == "REGION"


# ── fetch(): webhooks ─────────────────────────────────────────────────────────

@respx.mock
def test_fetch_webhooks(connector: GitHubConnector) -> None:
    """Webhook records include URL (from config), active, events, content_type."""
    hooks = [
        {
            "id": 1001,
            "active": True,
            "events": ["push", "pull_request"],
            "config": {
                "url": "https://ci.example.com/hook",
                "content_type": "json",
            },
        }
    ]
    _full_mock(hooks=hooks)
    records = connector.fetch(VALID_CREDS)
    hook_records = [r for r in records if r["record_type"] == GITHUB_WEBHOOK]

    assert len(hook_records) == 1
    hook = hook_records[0]
    assert hook["record_id"] == f"{SLUG}#webhook#1001"
    assert hook["name"] == "hook #1001"
    assert hook["url"] == "https://ci.example.com/hook"
    assert hook["active"] is True
    assert hook["events"] == ["pull_request", "push"]  # sorted
    assert hook["content_type"] == "json"
    assert hook["hook_id"] == 1001
    # No insecure_ssl in the raw config → unknown, not defaulted to "verified".
    assert hook["insecure_ssl_enabled"] is None
    assert hook["ssl_verification_enabled"] is None


@respx.mock
def test_fetch_webhooks_insecure_ssl_string_one_means_disabled(connector: GitHubConnector) -> None:
    """config.insecure_ssl == "1" => insecure_ssl_enabled=True, ssl_verification_enabled=False."""
    hooks = [
        {
            "id": 2001,
            "active": True,
            "events": ["push"],
            "config": {
                "url": "https://ci.example.com/hook",
                "content_type": "json",
                "insecure_ssl": "1",
            },
        }
    ]
    _full_mock(hooks=hooks)
    records = connector.fetch(VALID_CREDS)
    hook = next(r for r in records if r["record_type"] == GITHUB_WEBHOOK)

    assert hook["insecure_ssl_enabled"] is True
    assert hook["ssl_verification_enabled"] is False


@respx.mock
def test_fetch_webhooks_insecure_ssl_string_zero_means_enabled(connector: GitHubConnector) -> None:
    """config.insecure_ssl == "0" => insecure_ssl_enabled=False, ssl_verification_enabled=True."""
    hooks = [
        {
            "id": 2002,
            "active": True,
            "events": ["push"],
            "config": {
                "url": "https://ci.example.com/hook",
                "content_type": "json",
                "insecure_ssl": "0",
            },
        }
    ]
    _full_mock(hooks=hooks)
    records = connector.fetch(VALID_CREDS)
    hook = next(r for r in records if r["record_type"] == GITHUB_WEBHOOK)

    assert hook["insecure_ssl_enabled"] is False
    assert hook["ssl_verification_enabled"] is True


@respx.mock
@pytest.mark.parametrize(
    "raw_value,expected_insecure",
    [
        ("1", True),
        ("0", False),
        (1, True),
        (0, False),
        (True, True),
        (False, False),
    ],
)
def test_fetch_webhooks_insecure_ssl_handles_string_and_int_and_bool(
    connector: GitHubConnector, raw_value, expected_insecure
) -> None:
    """insecure_ssl normalization is robust across string/int/bool shapes GitHub may return."""
    hooks = [
        {
            "id": 2003,
            "active": True,
            "events": ["push"],
            "config": {
                "url": "https://ci.example.com/hook",
                "content_type": "json",
                "insecure_ssl": raw_value,
            },
        }
    ]
    _full_mock(hooks=hooks)
    records = connector.fetch(VALID_CREDS)
    hook = next(r for r in records if r["record_type"] == GITHUB_WEBHOOK)

    assert hook["insecure_ssl_enabled"] is expected_insecure
    assert hook["ssl_verification_enabled"] is (not expected_insecure)


# ── fetch(): actions permissions ──────────────────────────────────────────────

@respx.mock
def test_fetch_actions_permissions(connector: GitHubConnector) -> None:
    perms = {"enabled": True, "allowed_actions": "selected"}
    _full_mock(permissions=perms)
    records = connector.fetch(VALID_CREDS)
    perm_records = [r for r in records if r["record_type"] == GITHUB_ACTIONS_PERMISSIONS]

    assert len(perm_records) == 1
    assert perm_records[0]["record_id"] == f"{SLUG}#actions_permissions"
    assert perm_records[0]["enabled"] is True
    assert perm_records[0]["allowed_actions"] == "selected"
    # Default _full_mock workflow-permissions fixture: read / no PR approval.
    assert perm_records[0]["default_workflow_permissions"] == "read"
    assert perm_records[0]["can_approve_pull_request_reviews"] is False


@respx.mock
def test_fetch_actions_permissions_404_normalised(connector: GitHubConnector) -> None:
    """404 on actions/permissions returns a disabled record instead of raising."""
    _full_mock()
    # Override the permissions URL with a 404
    respx.get(PERMISSIONS_URL).mock(return_value=httpx.Response(404))
    records = connector.fetch(VALID_CREDS)
    perm_records = [r for r in records if r["record_type"] == GITHUB_ACTIONS_PERMISSIONS]

    assert len(perm_records) == 1
    assert perm_records[0]["enabled"] is False


@respx.mock
def test_fetch_workflow_permissions_write_and_pr_approval_true(connector: GitHubConnector) -> None:
    """default_workflow_permissions='write' and can_approve_pull_request_reviews=True normalize as-is."""
    _full_mock(
        workflow_permissions={
            "default_workflow_permissions": "write",
            "can_approve_pull_request_reviews": True,
        }
    )
    records = connector.fetch(VALID_CREDS)
    perm = next(r for r in records if r["record_type"] == GITHUB_ACTIONS_PERMISSIONS)

    assert perm["default_workflow_permissions"] == "write"
    assert perm["can_approve_pull_request_reviews"] is True


@respx.mock
def test_fetch_workflow_permissions_read_and_pr_approval_false(connector: GitHubConnector) -> None:
    """default_workflow_permissions='read' and can_approve_pull_request_reviews=False normalize as-is."""
    _full_mock(
        workflow_permissions={
            "default_workflow_permissions": "read",
            "can_approve_pull_request_reviews": False,
        }
    )
    records = connector.fetch(VALID_CREDS)
    perm = next(r for r in records if r["record_type"] == GITHUB_ACTIONS_PERMISSIONS)

    assert perm["default_workflow_permissions"] == "read"
    assert perm["can_approve_pull_request_reviews"] is False


@respx.mock
def test_fetch_workflow_permissions_403_is_soft_fail_unknown(connector: GitHubConnector) -> None:
    """A 403 on the workflow-permissions sub-endpoint must NOT fail the whole sync.

    The fields become unknown (None), and every other record type still comes
    back normally — this is the same fail-soft contract as _fetch_environments.
    """
    _full_mock(workflow_permissions_status=403)
    records = connector.fetch(VALID_CREDS)  # must not raise

    perm = next(r for r in records if r["record_type"] == GITHUB_ACTIONS_PERMISSIONS)
    assert perm["default_workflow_permissions"] is None
    assert perm["can_approve_pull_request_reviews"] is None
    # Other record types still synced normally.
    assert any(r["record_type"] == GITHUB_REPO_SETTINGS for r in records)


@respx.mock
def test_fetch_workflow_permissions_404_is_soft_fail_unknown(connector: GitHubConnector) -> None:
    """A 404 on the workflow-permissions sub-endpoint is also a soft, unknown-posture fail."""
    _full_mock(workflow_permissions_status=404)
    records = connector.fetch(VALID_CREDS)  # must not raise

    perm = next(r for r in records if r["record_type"] == GITHUB_ACTIONS_PERMISSIONS)
    assert perm["default_workflow_permissions"] is None
    assert perm["can_approve_pull_request_reviews"] is None


@respx.mock
@pytest.mark.parametrize(
    "raw_value,expected",
    [
        ("read", "read"),
        ("write", "write"),
        ("read-all", "read"),
        ("write-all", "write"),
        ("read_repository", "read"),
        ("write_repository", "write"),
        ("something_unrecognised", None),
        (None, None),
    ],
)
def test_fetch_workflow_permissions_normalization_variants(
    connector: GitHubConnector, raw_value, expected
) -> None:
    """default_workflow_permissions normalization is robust across GitHub's naming variants."""
    _full_mock(
        workflow_permissions={
            "default_workflow_permissions": raw_value,
            "can_approve_pull_request_reviews": False,
        }
    )
    records = connector.fetch(VALID_CREDS)
    perm = next(r for r in records if r["record_type"] == GITHUB_ACTIONS_PERMISSIONS)

    assert perm["default_workflow_permissions"] == expected


# ── fetch(): deploy keys ──────────────────────────────────────────────────────

@respx.mock
def test_fetch_deploy_keys(connector: GitHubConnector) -> None:
    keys = [
        {"id": 42, "title": "CI Deploy Key", "read_only": True, "verified": True},
        {"id": 43, "title": "Staging Key", "read_only": False, "verified": False},
    ]
    _full_mock(deploy_keys=keys)
    records = connector.fetch(VALID_CREDS)
    key_records = [r for r in records if r["record_type"] == GITHUB_DEPLOY_KEY]

    assert len(key_records) == 2
    ci_key = next(r for r in key_records if r["key_id"] == 42)
    assert ci_key["record_id"] == f"{SLUG}#deploy_key#42"
    assert ci_key["title"] == "CI Deploy Key"
    assert ci_key["read_only"] is True
    assert ci_key["verified"] is True

    staging_key = next(r for r in key_records if r["key_id"] == 43)
    assert staging_key["read_only"] is False
    assert staging_key["verified"] is False


# ── fetch(): all categories present ───────────────────────────────────────────

@respx.mock
def test_fetch_returns_all_seven_categories(connector: GitHubConnector) -> None:
    """A full fetch always produces at least one record from every category."""
    secrets = [{"name": "DB_PASS", "created_at": "2024-01-01T00:00:00Z", "updated_at": "2024-01-01T00:00:00Z"}]
    variables = [{"name": "ENV", "value": "prod", "created_at": "2024-01-01T00:00:00Z", "updated_at": "2024-01-01T00:00:00Z"}]
    hooks = [{"id": 1, "active": True, "events": ["push"], "config": {"url": "https://example.com", "content_type": "json"}}]
    keys = [{"id": 10, "title": "CI", "read_only": True, "verified": True}]
    _full_mock(secrets=secrets, variables=variables, hooks=hooks, deploy_keys=keys)

    records = connector.fetch(VALID_CREDS)
    record_types = {r["record_type"] for r in records}

    assert GITHUB_REPO_SETTINGS in record_types
    assert GITHUB_BRANCH_PROTECTION in record_types
    assert GITHUB_ACTIONS_SECRET in record_types
    assert GITHUB_ACTIONS_VARIABLE in record_types
    assert GITHUB_WEBHOOK in record_types
    assert GITHUB_ACTIONS_PERMISSIONS in record_types
    assert GITHUB_DEPLOY_KEY in record_types


# ── fetch(): empty collections ────────────────────────────────────────────────

@respx.mock
def test_fetch_empty_collections(connector: GitHubConnector) -> None:
    """fetch() succeeds when all paginated collections are empty."""
    _full_mock()
    records = connector.fetch(VALID_CREDS)

    # Exactly the two singleton records (settings + protection) when nothing else exists
    singleton_types = {GITHUB_REPO_SETTINGS, GITHUB_BRANCH_PROTECTION, GITHUB_ACTIONS_PERMISSIONS}
    returned_types = {r["record_type"] for r in records}
    assert singleton_types.issubset(returned_types)
    # No secret / variable / hook / key records
    for rt in (GITHUB_ACTIONS_SECRET, GITHUB_ACTIONS_VARIABLE, GITHUB_WEBHOOK, GITHUB_DEPLOY_KEY):
        assert rt not in returned_types


# ── HTTP error handling ───────────────────────────────────────────────────────

@respx.mock
def test_auth_error_401_propagates(connector: GitHubConnector) -> None:
    """401 on any endpoint raises AuthenticationError."""
    respx.get(REPO_URL).mock(return_value=httpx.Response(401))
    with pytest.raises(AuthenticationError):
        connector.fetch(VALID_CREDS)


@respx.mock
def test_auth_error_403_propagates(connector: GitHubConnector) -> None:
    respx.get(REPO_URL).mock(return_value=httpx.Response(403))
    with pytest.raises(AuthenticationError):
        connector.fetch(VALID_CREDS)


@respx.mock
def test_rate_limit_exhausted_raises(connector: GitHubConnector) -> None:
    """After _MAX_RETRIES 429s, RateLimitError is raised."""
    respx.get(REPO_URL).mock(
        return_value=httpx.Response(429, headers={"Retry-After": "0"})
    )
    with pytest.raises(RateLimitError):
        connector.fetch(VALID_CREDS)


def test_network_timeout_raises(connector: GitHubConnector) -> None:
    """httpx.TimeoutException is wrapped as NetworkError."""
    with respx.mock:
        respx.get(REPO_URL).mock(side_effect=httpx.TimeoutException("timed out"))
        with pytest.raises(NetworkError):
            connector.fetch(VALID_CREDS)


# ── _extract_credentials ──────────────────────────────────────────────────────

def test_extract_credentials_empty_token_raises(connector: GitHubConnector) -> None:
    with pytest.raises(ConnectorError, match="must include"):
        connector._extract_credentials({"github_token": "", "repo_owner": "a", "repo_name": "b"})


def test_extract_credentials_missing_owner_raises(connector: GitHubConnector) -> None:
    with pytest.raises(ConnectorError, match="must include"):
        connector._extract_credentials({"github_token": "tok", "repo_owner": "", "repo_name": "b"})


def test_extract_credentials_missing_repo_raises(connector: GitHubConnector) -> None:
    with pytest.raises(ConnectorError, match="must include"):
        connector._extract_credentials({"github_token": "tok", "repo_owner": "a", "repo_name": ""})


# ── record_id format ──────────────────────────────────────────────────────────

@respx.mock
def test_record_ids_use_slug_prefix(connector: GitHubConnector) -> None:
    """All record IDs start with the {owner}/{repo}# prefix."""
    secrets = [{"name": "MY_SECRET", "created_at": "2024-01-01T00:00:00Z", "updated_at": "2024-01-01T00:00:00Z"}]
    _full_mock(secrets=secrets)
    records = connector.fetch(VALID_CREDS)

    for record in records:
        assert record["record_id"].startswith(SLUG), (
            f"record_id {record['record_id']!r} does not start with {SLUG!r}"
        )
