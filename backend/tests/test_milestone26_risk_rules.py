"""Risk rule tests for GitHub provider — Milestone 26.

Tests cover every rule branch in app.services.risk_rules.github and also
verify that risk_service.classify_change dispatches correctly to the GitHub
rule set (not the Cloudflare DNS rules) when provider_metadata["record_type"]
starts with "github_".

Run with:
    docker compose run --rm api pytest backend/tests/test_milestone26_risk_rules.py -v
"""

from __future__ import annotations

import pytest

from app.services.risk_rules.github import (
    classify_github_change,
    _is_sensitive_secret,
)
from app.services.risk_service import classify_change


# ── Helpers ───────────────────────────────────────────────────────────────────

def _change(
    *,
    change_type: str = "modified",
    field_path: str | None = None,
    prev_value=None,
    new_value=None,
    record_type: str = "github_repo_settings",
    record_name: str = "acme/myapp",
) -> dict:
    """Build a minimal change dict for testing."""
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


# ── classify_change dispatch ──────────────────────────────────────────────────

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


def test_classify_change_dispatches_to_cloudflare_for_cloudflare_record_type():
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
    # Cloudflare comment change → low
    assert level == "low"


# ── Repo settings rules ───────────────────────────────────────────────────────

def test_visibility_private_to_public_is_critical():
    change = _change(field_path="visibility", new_value="public")
    level, reason = classify_github_change(change)
    assert level == "critical"
    assert "public" in reason.lower()


def test_visibility_public_to_private_is_medium():
    change = _change(field_path="visibility", new_value="private", prev_value="public")
    level, reason = classify_github_change(change)
    assert level == "medium"


def test_archived_to_true_is_high():
    change = _change(field_path="archived", new_value=True, prev_value=False)
    level, reason = classify_github_change(change)
    assert level == "high"
    assert "archiv" in reason.lower()


def test_default_branch_change_is_high():
    change = _change(
        field_path="default_branch",
        prev_value="master",
        new_value="main",
    )
    level, reason = classify_github_change(change)
    assert level == "high"
    assert "default branch" in reason.lower()


def test_merge_setting_change_is_medium():
    for field in ("allow_merge_commit", "allow_squash_merge", "allow_rebase_merge", "delete_branch_on_merge"):
        change = _change(field_path=field, prev_value=True, new_value=False)
        level, _ = classify_github_change(change)
        assert level == "medium", f"Expected medium for {field}"


# ── Branch protection rules ───────────────────────────────────────────────────

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
    assert "unprotected" in reason.lower()


def test_protection_rule_removed_is_critical():
    change = _change(
        change_type="removed",
        record_type="github_branch_protection",
        record_name="main branch",
    )
    level, reason = classify_github_change(change)
    assert level == "critical"


def test_allow_force_pushes_enabled_is_high():
    change = _change(
        record_type="github_branch_protection",
        field_path="allow_force_pushes",
        prev_value=False,
        new_value=True,
    )
    level, reason = classify_github_change(change)
    assert level == "high"
    assert "force" in reason.lower()


def test_allow_deletions_enabled_is_high():
    change = _change(
        record_type="github_branch_protection",
        field_path="allow_deletions",
        prev_value=False,
        new_value=True,
    )
    level, _ = classify_github_change(change)
    assert level == "high"


def test_pr_reviews_disabled_is_high():
    change = _change(
        record_type="github_branch_protection",
        field_path="required_pull_request_reviews_enabled",
        prev_value=True,
        new_value=False,
    )
    level, _ = classify_github_change(change)
    assert level == "high"


def test_enforce_admins_disabled_is_medium():
    change = _change(
        record_type="github_branch_protection",
        field_path="enforce_admins",
        prev_value=True,
        new_value=False,
    )
    level, _ = classify_github_change(change)
    assert level == "medium"


def test_required_approvals_reduced_is_medium():
    change = _change(
        record_type="github_branch_protection",
        field_path="required_approving_review_count",
        prev_value=2,
        new_value=1,
    )
    level, reason = classify_github_change(change)
    assert level == "medium"
    assert "reduced" in reason.lower()


def test_protection_added_is_low():
    change = _change(
        change_type="added",
        record_type="github_branch_protection",
    )
    level, _ = classify_github_change(change)
    assert level == "low"


def test_protection_enabled_from_disabled_is_low():
    change = _change(
        record_type="github_branch_protection",
        field_path="protection_enabled",
        prev_value=False,
        new_value=True,
    )
    level, _ = classify_github_change(change)
    assert level == "low"


# ── Sensitive secret pattern matching ─────────────────────────────────────────

@pytest.mark.parametrize("name", [
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
])
def test_sensitive_patterns_detected(name: str):
    assert _is_sensitive_secret(name), f"Expected {name!r} to be sensitive"


@pytest.mark.parametrize("name", [
    "REGION",
    "ENVIRONMENT",
    "NODE_ENV",
    "LOG_LEVEL",
    "PORT",
])
def test_non_sensitive_names_not_detected(name: str):
    assert not _is_sensitive_secret(name), f"Expected {name!r} to NOT be sensitive"


# ── Secret rules ──────────────────────────────────────────────────────────────

def test_secret_deleted_is_high():
    change = _change(
        change_type="removed",
        record_type="github_actions_secret",
        record_name="MY_SECRET",
    )
    level, reason = classify_github_change(change)
    assert level == "high"
    assert "deleted" in reason.lower()


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
    assert "sensitive" in reason.lower() or "rotated" in reason.lower()


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


def test_secret_added_is_low():
    change = _change(
        change_type="added",
        record_type="github_actions_secret",
        record_name="NEW_SECRET",
    )
    level, _ = classify_github_change(change)
    assert level == "low"


# ── Variable rules ────────────────────────────────────────────────────────────

def test_variable_removed_is_medium():
    change = _change(
        change_type="removed",
        record_type="github_actions_variable",
        record_name="REGION",
    )
    level, _ = classify_github_change(change)
    assert level == "medium"


def test_variable_modified_is_low():
    change = _change(
        record_type="github_actions_variable",
        record_name="REGION",
        field_path="value",
        prev_value="us-east-1",
        new_value="eu-west-1",
    )
    level, _ = classify_github_change(change)
    assert level == "low"


def test_variable_added_is_low():
    change = _change(
        change_type="added",
        record_type="github_actions_variable",
        record_name="NEW_VAR",
    )
    level, _ = classify_github_change(change)
    assert level == "low"


# ── Webhook rules ─────────────────────────────────────────────────────────────

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
    """Per locked decision: any webhook URL change = High."""
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


def test_webhook_added_is_medium():
    change = _change(
        change_type="added",
        record_type="github_webhook",
        record_name="hook #99",
    )
    level, _ = classify_github_change(change)
    assert level == "medium"


def test_webhook_active_changed_is_medium():
    change = _change(
        record_type="github_webhook",
        field_path="active",
        prev_value=True,
        new_value=False,
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


# ── Actions permissions rules ─────────────────────────────────────────────────

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


def test_actions_allowed_changed_to_all_is_medium():
    change = _change(
        record_type="github_actions_permissions",
        field_path="allowed_actions",
        prev_value="selected",
        new_value="all",
    )
    level, reason = classify_github_change(change)
    assert level == "medium"
    assert "all" in reason.lower()


# ── Deploy key rules ──────────────────────────────────────────────────────────

def test_deploy_key_read_only_false_is_high():
    """Key gaining write access → High."""
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


def test_deploy_key_removed_is_medium():
    change = _change(
        change_type="removed",
        record_type="github_deploy_key",
        record_name="CI Deploy Key",
    )
    level, _ = classify_github_change(change)
    assert level == "medium"


def test_deploy_key_added_is_low():
    change = _change(
        change_type="added",
        record_type="github_deploy_key",
        record_name="New Key",
    )
    level, _ = classify_github_change(change)
    assert level == "low"


# ── Unknown record type fallback ──────────────────────────────────────────────

def test_unknown_github_record_type_is_low():
    change = _change(record_type="github_future_feature")
    level, _ = classify_github_change(change)
    assert level == "low"
