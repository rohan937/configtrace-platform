"""GitHub risk-rule tests — Milestone 26 (revised model).

The risk model weighs five signals per change:
    1. Category (record_type)
    2. Direction of change (weakening vs. strengthening protection)
    3. Security / production impact
    4. Name sensitivity (secrets and variables)
    5. Change type (added / removed / modified)

Keyword matching is one of these five inputs, not the sole determinant.

Run with:
    docker compose exec api pytest backend/tests/test_milestone26_risk_rules.py -v
"""

from __future__ import annotations

import pytest

from app.services.risk_rules.github import (
    _is_sensitive_secret,
    classify_github_change,
)
from app.services.risk_service import classify_change


# ── Test-change builder ───────────────────────────────────────────────────────

def _change(
    *,
    change_type: str = "modified",
    field_path: str | None = None,
    prev_value=None,
    new_value=None,
    record_type: str = "github_repo_settings",
    record_name: str = "acme/myapp",
) -> dict:
    """Build a minimal change dict that mirrors a diff-service output."""
    return {
        "change_type": change_type,
        "field_path": field_path,
        "prev_value": prev_value,
        "new_value": new_value,
        "provider_metadata": {
            "record_type": record_type,
            "record_name": record_name,
        },
    }


# ── Provider dispatch ─────────────────────────────────────────────────────────

def test_classify_change_dispatches_to_github_for_github_record_type():
    """risk_service.classify_change routes github_ records to GitHub rules."""
    change = _change(
        record_type="github_repo_settings",
        field_path="visibility",
        new_value="public",
    )
    level, reason = classify_change(change)
    assert level == "critical"
    assert "public" in reason.lower()


def test_classify_change_dispatches_to_cloudflare_for_non_github_record_type():
    """risk_service.classify_change routes non-github_ records to Cloudflare rules."""
    change = {
        "change_type": "modified",
        "field_path": "comment",
        "prev_value": "old",
        "new_value": "new",
        "provider_metadata": {
            "record_type": "A",
            "record_name": "api.example.com",
        },
    }
    level, reason = classify_change(change)
    # Cloudflare comment change is low risk
    assert level == "low"


# ── Sensitive name detection ──────────────────────────────────────────────────

@pytest.mark.parametrize("name", [
    # Original patterns
    "PROD_SECRET",
    "DATABASE_PASSWORD",
    "STRIPE_SECRET_KEY",
    "AWS_ACCESS_KEY",
    "MY_API_KEY",
    "VERCEL_TOKEN",
    "CLOUDFLARE_TOKEN",
    "PRIVATE_KEY_RSA",
    "APP_SECRET",
    "DEPLOY_KEY",
    # New patterns added in revised model
    "SUPABASE_URL",
    "FIREBASE_TOKEN",
    "OPENAI_API_KEY",
    "CLERK_SECRET_KEY",
    "RESEND_API_KEY",
    "WEBHOOK_SECRET",
    "DB_PASSWORD",
    "PROD_TEST_TOKEN",           # the reported false-Low case
    "PRODUCTION_DATABASE_URL",
])
def test_sensitive_patterns_detected(name: str):
    assert _is_sensitive_secret(name), f"Expected '{name}' to be sensitive"


@pytest.mark.parametrize("name", [
    "REGION",
    "ENVIRONMENT",
    "NODE_ENV",
    "LOG_LEVEL",
    "PORT",
    "BUILD_NUMBER",
    "CACHE_SIZE",
    "RETRY_LIMIT",
])
def test_non_sensitive_names_not_detected(name: str):
    assert not _is_sensitive_secret(name), f"Expected '{name}' NOT to be sensitive"


# ── Repository settings ───────────────────────────────────────────────────────

def test_visibility_private_to_public_is_critical():
    change = _change(field_path="visibility", new_value="public")
    level, reason = classify_github_change(change)
    assert level == "critical"
    assert "public" in reason.lower()


def test_visibility_public_to_private_is_medium():
    change = _change(field_path="visibility", new_value="private", prev_value="public")
    level, reason = classify_github_change(change)
    assert level == "medium"


def test_default_branch_change_is_high():
    change = _change(
        field_path="default_branch",
        prev_value="master",
        new_value="main",
    )
    level, reason = classify_github_change(change)
    assert level == "high"
    assert "default branch" in reason.lower()


def test_archived_to_true_is_medium():
    """Repository archival is notable but reversible — Medium (not High)."""
    change = _change(field_path="archived", new_value=True, prev_value=False)
    level, reason = classify_github_change(change)
    assert level == "medium"
    assert "archiv" in reason.lower()


def test_merge_setting_change_is_medium():
    for field in (
        "allow_merge_commit",
        "allow_squash_merge",
        "allow_rebase_merge",
        "delete_branch_on_merge",
    ):
        change = _change(field_path=field, prev_value=True, new_value=False)
        level, _ = classify_github_change(change)
        assert level == "medium", f"Expected medium for {field}"


def test_has_wiki_enabled_is_low():
    """Wiki enabled is an additional collaboration surface — Low, not the generic Medium fallback."""
    change = _change(field_path="has_wiki", prev_value=False, new_value=True)
    level, reason = classify_github_change(change)
    assert level == "low"
    assert "wiki is enabled" in reason.lower()
    for forbidden in ("breach", "leak", "exploit", "attacker"):
        assert forbidden not in reason.lower()


def test_has_wiki_disabled_is_low():
    change = _change(field_path="has_wiki", prev_value=True, new_value=False)
    level, reason = classify_github_change(change)
    assert level == "low"
    assert "disabled" in reason.lower()


# ── Branch protection — Critical (gates removed entirely) ─────────────────────

def test_protection_disabled_is_critical():
    change = _change(
        record_type="github_branch_protection",
        record_name="main branch",
        field_path="protection_enabled",
        prev_value=True,
        new_value=False,
    )
    level, reason = classify_github_change(change)
    assert level == "critical"
    assert "unprotect" in reason.lower() or "disabled" in reason.lower()


def test_protection_rule_removed_is_critical():
    change = _change(
        change_type="removed",
        record_type="github_branch_protection",
        record_name="main branch",
    )
    level, _ = classify_github_change(change)
    assert level == "critical"


def test_allow_force_pushes_enabled_is_critical():
    """Force-pushes rewrite history — Critical (was High in previous model)."""
    change = _change(
        record_type="github_branch_protection",
        field_path="allow_force_pushes",
        prev_value=False,
        new_value=True,
    )
    level, reason = classify_github_change(change)
    assert level == "critical"
    assert "force" in reason.lower()


def test_allow_deletions_enabled_is_critical():
    """Branch can be permanently deleted — Critical (was High in previous model)."""
    change = _change(
        record_type="github_branch_protection",
        field_path="allow_deletions",
        prev_value=False,
        new_value=True,
    )
    level, _ = classify_github_change(change)
    assert level == "critical"


def test_required_status_checks_removed_is_critical():
    """Removing CI gates lets unvalidated code merge — Critical."""
    change = _change(
        record_type="github_branch_protection",
        field_path="required_status_checks_enabled",
        prev_value=True,
        new_value=False,
    )
    level, reason = classify_github_change(change)
    assert level == "critical"
    assert "status check" in reason.lower()


def test_pr_reviews_disabled_is_critical():
    """Disabling required reviews removes the last human gate — Critical."""
    change = _change(
        record_type="github_branch_protection",
        field_path="required_pull_request_reviews_enabled",
        prev_value=True,
        new_value=False,
    )
    level, _ = classify_github_change(change)
    assert level == "critical"


# ── Branch protection — High (weakening, gates still present) ─────────────────

def test_enforce_admins_disabled_is_high():
    """Admins exempted from protection — High (was Medium in previous model)."""
    change = _change(
        record_type="github_branch_protection",
        field_path="enforce_admins",
        prev_value=True,
        new_value=False,
    )
    level, reason = classify_github_change(change)
    assert level == "high"
    assert "admin" in reason.lower()


def test_required_linear_history_disabled_is_high():
    """Merge commits now allowed — history harder to audit."""
    change = _change(
        record_type="github_branch_protection",
        field_path="required_linear_history",
        prev_value=True,
        new_value=False,
    )
    level, reason = classify_github_change(change)
    assert level == "high"
    assert "linear" in reason.lower()


def test_required_approvals_reduced_is_high():
    """Fewer required reviewers — High (was Medium in previous model)."""
    change = _change(
        record_type="github_branch_protection",
        field_path="required_approving_review_count",
        prev_value=2,
        new_value=1,
    )
    level, reason = classify_github_change(change)
    assert level == "high"
    assert "reduced" in reason.lower()


# ── Branch protection — Medium and Low ───────────────────────────────────────

def test_required_approvals_increased_is_medium():
    """More required reviewers — strengthening, Medium."""
    change = _change(
        record_type="github_branch_protection",
        field_path="required_approving_review_count",
        prev_value=1,
        new_value=2,
    )
    level, reason = classify_github_change(change)
    assert level == "medium"
    assert "increased" in reason.lower()


def test_protection_added_is_low():
    """New protection rule on previously unprotected branch — Low."""
    change = _change(
        change_type="added",
        record_type="github_branch_protection",
    )
    level, _ = classify_github_change(change)
    assert level == "low"


def test_protection_enabled_from_disabled_is_low():
    """Re-enabling protection is a strengthening change — Low."""
    change = _change(
        record_type="github_branch_protection",
        field_path="protection_enabled",
        prev_value=False,
        new_value=True,
    )
    level, _ = classify_github_change(change)
    assert level == "low"


def test_status_checks_enabled_is_not_high_or_critical():
    """Enabling status checks strengthens protection — not High or Critical."""
    change = _change(
        record_type="github_branch_protection",
        field_path="required_status_checks_enabled",
        prev_value=False,
        new_value=True,
    )
    level, _ = classify_github_change(change)
    assert level not in ("high", "critical")


# ── Actions secrets ───────────────────────────────────────────────────────────

def test_sensitive_secret_added_is_medium():
    """PROD_TEST_TOKEN (production-sensitive name) added → Medium, not Low."""
    change = _change(
        change_type="added",
        record_type="github_actions_secret",
        record_name="PROD_TEST_TOKEN",
    )
    level, reason = classify_github_change(change)
    assert level == "medium"
    assert "sensitive" in reason.lower()


def test_nonsensitive_secret_added_is_low():
    """Non-sensitive secret name added → Low."""
    change = _change(
        change_type="added",
        record_type="github_actions_secret",
        record_name="BUILD_NUMBER",
    )
    level, _ = classify_github_change(change)
    assert level == "low"


def test_sensitive_secret_removed_is_high():
    """Sensitive secret deleted — workflows break and credential is gone."""
    change = _change(
        change_type="removed",
        record_type="github_actions_secret",
        record_name="PROD_DB_PASSWORD",
    )
    level, reason = classify_github_change(change)
    assert level == "high"
    assert "deleted" in reason.lower() or "removed" in reason.lower()


def test_nonsensitive_secret_removed_is_medium():
    """Non-sensitive secret deleted — workflows break but no credential risk."""
    change = _change(
        change_type="removed",
        record_type="github_actions_secret",
        record_name="CACHE_SIZE",
    )
    level, _ = classify_github_change(change)
    assert level == "medium"


def test_secret_rotated_sensitive_is_high():
    change = _change(
        record_type="github_actions_secret",
        record_name="PROD_DB_PASSWORD",
        field_path="last_updated_at",
        prev_value="2024-01-01T00:00:00Z",
        new_value="2024-06-01T00:00:00Z",
    )
    level, reason = classify_github_change(change)
    assert level == "high"
    assert "rotated" in reason.lower() or "sensitive" in reason.lower()


def test_secret_rotated_non_sensitive_is_medium():
    change = _change(
        record_type="github_actions_secret",
        record_name="REGION",
        field_path="last_updated_at",
        prev_value="2024-01-01T00:00:00Z",
        new_value="2024-06-01T00:00:00Z",
    )
    level, reason = classify_github_change(change)
    assert level == "medium"
    assert "rotated" in reason.lower()


def test_secret_rotated_with_api_key_in_name_is_high():
    change = _change(
        record_type="github_actions_secret",
        record_name="EXTERNAL_API_KEY",
        field_path="last_updated_at",
        prev_value="2024-01-01T00:00:00Z",
        new_value="2024-07-01T00:00:00Z",
    )
    level, _ = classify_github_change(change)
    assert level == "high"


# ── Actions variables ─────────────────────────────────────────────────────────

def test_sensitive_variable_changed_is_high():
    """Variable with a production-sensitive name modified → High."""
    change = _change(
        record_type="github_actions_variable",
        record_name="API_KEY",
        field_path="value",
        prev_value="old_val",
        new_value="new_val",
    )
    level, reason = classify_github_change(change)
    assert level == "high"
    assert "sensitive" in reason.lower()


def test_nonsensitive_variable_changed_is_low():
    change = _change(
        record_type="github_actions_variable",
        record_name="REGION",
        field_path="value",
        prev_value="us-east-1",
        new_value="eu-west-1",
    )
    level, _ = classify_github_change(change)
    assert level == "low"


def test_variable_changed_to_url_is_high():
    """Variable changed to an external URL is High even without sensitive name."""
    change = _change(
        record_type="github_actions_variable",
        record_name="BASE_ENDPOINT",
        field_path="value",
        prev_value="internal-service:8080",
        new_value="https://api.external.com/v1",
    )
    level, reason = classify_github_change(change)
    assert level == "high"
    assert "url" in reason.lower() or "endpoint" in reason.lower()


def test_sensitive_variable_added_is_medium():
    """Variable with a production-sensitive name added → Medium."""
    change = _change(
        change_type="added",
        record_type="github_actions_variable",
        record_name="PROD_API_URL",
    )
    level, reason = classify_github_change(change)
    assert level == "medium"
    assert "sensitive" in reason.lower()


def test_nonsensitive_variable_added_is_low():
    change = _change(
        change_type="added",
        record_type="github_actions_variable",
        record_name="NEW_VAR",
    )
    level, _ = classify_github_change(change)
    assert level == "low"


def test_nonsensitive_variable_removed_is_low():
    """Non-sensitive variable removed → Low (was Medium in previous model)."""
    change = _change(
        change_type="removed",
        record_type="github_actions_variable",
        record_name="REGION",
    )
    level, _ = classify_github_change(change)
    assert level == "low"


def test_sensitive_variable_removed_is_medium():
    """Sensitive variable removed → Medium."""
    change = _change(
        change_type="removed",
        record_type="github_actions_variable",
        record_name="DB_HOST",
    )
    level, _ = classify_github_change(change)
    assert level == "medium"


# ── Webhooks ──────────────────────────────────────────────────────────────────

def test_webhook_removed_is_high():
    change = _change(
        change_type="removed",
        record_type="github_webhook",
        record_name="hook #42",
    )
    level, reason = classify_github_change(change)
    assert level == "high"
    assert "deleted" in reason.lower() or "removed" in reason.lower()


def test_webhook_url_changed_is_high():
    """Any webhook URL change → High (locked policy decision)."""
    change = _change(
        record_type="github_webhook",
        record_name="hook #42",
        field_path="url",
        prev_value="https://old.example.com/hook",
        new_value="https://new.example.com/hook",
    )
    level, reason = classify_github_change(change)
    assert level == "high"
    assert "url" in reason.lower()


def test_webhook_disabled_is_high():
    """Webhook deactivated (active → False) stops event delivery — High."""
    change = _change(
        record_type="github_webhook",
        field_path="active",
        prev_value=True,
        new_value=False,
    )
    level, reason = classify_github_change(change)
    assert level == "high"
    assert "disabled" in reason.lower()


def test_webhook_enabled_is_medium():
    """Webhook re-enabled (active → True) — Medium."""
    change = _change(
        record_type="github_webhook",
        field_path="active",
        prev_value=False,
        new_value=True,
    )
    level, _ = classify_github_change(change)
    assert level == "medium"


def test_webhook_added_is_medium():
    change = _change(
        change_type="added",
        record_type="github_webhook",
        record_name="hook #99",
    )
    level, _ = classify_github_change(change)
    assert level == "medium"


def test_webhook_events_changed_is_medium():
    change = _change(
        record_type="github_webhook",
        field_path="events",
        prev_value=["push"],
        new_value=["push", "pull_request"],
    )
    level, _ = classify_github_change(change)
    assert level == "medium"


def test_webhook_content_type_changed_is_low():
    change = _change(
        record_type="github_webhook",
        field_path="content_type",
        prev_value="form",
        new_value="json",
    )
    level, _ = classify_github_change(change)
    assert level == "low"


def test_webhook_ssl_verification_disabled_is_high():
    """SSL verification turned off (insecure_ssl_enabled False → True) — High."""
    change = _change(
        record_type="github_webhook",
        field_path="insecure_ssl_enabled",
        prev_value=False,
        new_value=True,
    )
    level, reason = classify_github_change(change)
    assert level == "high"
    assert "ssl verification is disabled" in reason.lower()
    # Safety wording: no breach/compromise/leak/exploit/attacker claims. The
    # rule's own disclaimer legitimately says "does not confirm ... data
    # exposure", so "exposure" itself is not forbidden here.
    for forbidden in ("breach", "leak", "exploit", "attacker"):
        assert forbidden not in reason.lower()


def test_webhook_ssl_verification_restored_is_medium():
    """SSL verification turned back on (insecure_ssl_enabled True → False) — Medium."""
    change = _change(
        record_type="github_webhook",
        field_path="insecure_ssl_enabled",
        prev_value=True,
        new_value=False,
    )
    level, reason = classify_github_change(change)
    assert level == "medium"
    assert "re-enabled" in reason.lower() or "restored" in reason.lower()


# ── Actions permissions ───────────────────────────────────────────────────────

def test_actions_disabled_is_high():
    change = _change(
        record_type="github_actions_permissions",
        field_path="enabled",
        prev_value=True,
        new_value=False,
    )
    level, reason = classify_github_change(change)
    assert level == "high"
    assert "disabled" in reason.lower()


def test_actions_enabled_is_medium():
    change = _change(
        record_type="github_actions_permissions",
        field_path="enabled",
        prev_value=False,
        new_value=True,
    )
    level, _ = classify_github_change(change)
    assert level == "medium"


def test_actions_allowed_changed_to_all_is_high():
    """GitHub change-classification QA (message 2): bumped from medium to
    high so the transition is never rated below the equivalent static
    github_actions_broad_permissions Security Finding, which is severity
    'high'."""
    change = _change(
        record_type="github_actions_permissions",
        field_path="allowed_actions",
        prev_value="selected",
        new_value="all",
    )
    level, reason = classify_github_change(change)
    assert level == "high"
    assert "all" in reason.lower()


def test_actions_workflow_token_permission_read_to_write_is_high():
    """Workflow token permission widened to write — High."""
    change = _change(
        record_type="github_actions_permissions",
        field_path="default_workflow_permissions",
        prev_value="read",
        new_value="write",
    )
    level, reason = classify_github_change(change)
    assert level == "high"
    assert "write permissions" in reason.lower()
    for forbidden in ("breach", "leak", "exploit", "attacker"):
        assert forbidden not in reason.lower()


def test_actions_workflow_token_permission_write_to_read_is_medium():
    """Workflow token permission restored to read-only — Medium."""
    change = _change(
        record_type="github_actions_permissions",
        field_path="default_workflow_permissions",
        prev_value="write",
        new_value="read",
    )
    level, reason = classify_github_change(change)
    assert level == "medium"
    assert "read-only" in reason.lower()


def test_actions_can_approve_pull_requests_enabled_is_high():
    """Actions PR approval enabled — High."""
    change = _change(
        record_type="github_actions_permissions",
        field_path="can_approve_pull_request_reviews",
        prev_value=False,
        new_value=True,
    )
    level, reason = classify_github_change(change)
    assert level == "high"
    assert "pull request approval is enabled" in reason.lower()
    for forbidden in ("breach", "leak", "exploit", "attacker"):
        assert forbidden not in reason.lower()


def test_actions_can_approve_pull_requests_disabled_is_medium():
    """Actions PR approval disabled again — Medium."""
    change = _change(
        record_type="github_actions_permissions",
        field_path="can_approve_pull_request_reviews",
        prev_value=True,
        new_value=False,
    )
    level, reason = classify_github_change(change)
    assert level == "medium"
    assert "disabled" in reason.lower()


# ── GitHub Pages ──────────────────────────────────────────────────────────────

def test_pages_enabled_is_low():
    change = _change(
        record_type="github_pages",
        field_path="pages_enabled",
        prev_value=False,
        new_value=True,
    )
    level, reason = classify_github_change(change)
    assert level == "low"
    assert "pages is enabled" in reason.lower()
    for forbidden in ("breach", "leak", "exploit", "attacker"):
        assert forbidden not in reason.lower()


def test_pages_disabled_is_low():
    change = _change(
        record_type="github_pages",
        field_path="pages_enabled",
        prev_value=True,
        new_value=False,
    )
    level, reason = classify_github_change(change)
    assert level == "low"
    assert "disabled" in reason.lower()


def test_pages_source_branch_changed_is_low():
    change = _change(
        record_type="github_pages",
        field_path="pages_source_branch",
        prev_value="main",
        new_value="gh-pages",
    )
    level, reason = classify_github_change(change)
    assert level == "low"
    assert "gh-pages" in reason.lower()


def test_pages_https_enforcement_disabled_is_medium():
    change = _change(
        record_type="github_pages",
        field_path="pages_https_enforced",
        prev_value=True,
        new_value=False,
    )
    level, reason = classify_github_change(change)
    assert level == "medium"
    assert "https" in reason.lower()


# ── Deploy keys ───────────────────────────────────────────────────────────────

def test_write_enabled_deploy_key_added_is_critical():
    """Adding a write-enabled key grants push access — Critical."""
    change = _change(
        change_type="added",
        record_type="github_deploy_key",
        record_name="CI Deploy Key",
        new_value={"read_only": False, "title": "CI Deploy Key"},
    )
    level, reason = classify_github_change(change)
    assert level == "critical"
    assert "write" in reason.lower()


def test_readonly_deploy_key_added_is_medium():
    """Read-only deploy key added — Medium."""
    change = _change(
        change_type="added",
        record_type="github_deploy_key",
        record_name="CI Deploy Key",
        new_value={"read_only": True, "title": "CI Deploy Key"},
    )
    level, reason = classify_github_change(change)
    assert level == "medium"
    assert "read-only" in reason.lower()


def test_deploy_key_added_unknown_access_defaults_to_medium():
    """Deploy key added with no record dict — defaults to Medium (read-only assumption)."""
    change = _change(
        change_type="added",
        record_type="github_deploy_key",
        record_name="New Key",
        new_value=None,
    )
    level, _ = classify_github_change(change)
    assert level == "medium"


def test_deploy_key_removed_is_high():
    """Deploy key removed — automated system loses access — High."""
    change = _change(
        change_type="removed",
        record_type="github_deploy_key",
        record_name="CI Deploy Key",
    )
    level, _ = classify_github_change(change)
    assert level == "high"


def test_deploy_key_read_only_false_is_high():
    """Existing deploy key gains write access via field change — High."""
    change = _change(
        record_type="github_deploy_key",
        record_name="CI Deploy Key",
        field_path="read_only",
        prev_value=True,
        new_value=False,
    )
    level, reason = classify_github_change(change)
    assert level == "high"
    assert "write" in reason.lower()


# ── Unknown record type ───────────────────────────────────────────────────────

def test_unknown_github_record_type_is_low():
    change = _change(record_type="github_future_feature")
    level, _ = classify_github_change(change)
    assert level == "low"
