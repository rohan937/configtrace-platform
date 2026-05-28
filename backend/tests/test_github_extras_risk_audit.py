"""GitHub extras risk-rule audit — rulesets, CODEOWNERS, workflow files,
OIDC trust, collaborators, App installations, security features.

Mirrors the audit pattern used for the core GitHub classifier
(``tests/test_github_risk_audit.py``).  No GitHub APIs are called; all
fixtures are mock-built ``Change``-shaped MagicMocks.

Scope
-----
* github_ruleset           — A1–A12
* github_codeowners        — B1–B8
* github_workflow_file     — C1–C9
* github_oidc_trust        — D1–D7
* github_collaborator      — E1–E8
* github_app_installation  — F1–F9
* github_security_features — G1–G9
* Dispatcher + safety      — H1–H3
* Secret-safety tripwires  — S1–S4
"""

from __future__ import annotations

import re
from unittest.mock import MagicMock

import pytest

from app.services.risk_rules.github import classify_github_change


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _ch(
    *,
    record_type: str,
    change_type: str = "modified",
    field_path: str | None = None,
    prev_value=None,
    new_value=None,
    pm_extra: dict | None = None,
):
    c = MagicMock(name="Change")
    c.change_type = change_type
    c.field_path = field_path
    c.prev_value = prev_value
    c.new_value = new_value
    pm = {"record_type": record_type}
    if pm_extra:
        pm.update(pm_extra)
    c.provider_metadata = pm
    return c


# ═════════════════════════════════════════════════════════════════════════════
# A. github_ruleset
# ═════════════════════════════════════════════════════════════════════════════


class TestRuleset:

    def test_A1_ruleset_removed_on_main_is_critical(self):
        c = _ch(
            record_type="github_ruleset",
            change_type="removed",
            pm_extra={"name": "main protection", "targets_protected_branch": True},
        )
        level, reason = classify_github_change(c)
        assert level == "critical"
        assert "removed" in reason.lower()

    def test_A2_ruleset_removed_on_non_prod_is_high(self):
        c = _ch(
            record_type="github_ruleset",
            change_type="removed",
            pm_extra={"name": "docs", "targets_protected_branch": False},
        )
        level, _ = classify_github_change(c)
        assert level == "high"

    def test_A3_enforcement_disabled_on_main_is_critical(self):
        c = _ch(
            record_type="github_ruleset", field_path="enforcement",
            prev_value="active", new_value="disabled",
            pm_extra={"name": "main", "targets_protected_branch": True},
        )
        level, _ = classify_github_change(c)
        assert level == "critical"

    def test_A4_enforcement_to_evaluate_is_high(self):
        c = _ch(
            record_type="github_ruleset", field_path="enforcement",
            prev_value="active", new_value="evaluate",
            pm_extra={"name": "main", "targets_protected_branch": True},
        )
        level, _ = classify_github_change(c)
        assert level == "high"

    def test_A5_bypass_actor_added_on_main_is_critical(self):
        c = _ch(
            record_type="github_ruleset", field_path="bypass_actor_count",
            prev_value=0, new_value=2,
            pm_extra={"name": "main", "targets_protected_branch": True},
        )
        level, reason = classify_github_change(c)
        assert level == "critical"
        assert "bypass" in reason.lower()

    def test_A6_bypass_actor_added_on_non_prod_is_high(self):
        c = _ch(
            record_type="github_ruleset", field_path="bypass_actor_count",
            prev_value=0, new_value=1,
            pm_extra={"name": "docs", "targets_protected_branch": False},
        )
        level, _ = classify_github_change(c)
        assert level == "high"

    def test_A7_required_status_checks_lowered_is_high(self):
        c = _ch(
            record_type="github_ruleset",
            field_path="required_status_checks_count",
            prev_value=5, new_value=0,
            pm_extra={"name": "main", "targets_protected_branch": True},
        )
        level, _ = classify_github_change(c)
        assert level == "high"

    def test_A8_required_pr_reviews_disabled_is_high(self):
        c = _ch(
            record_type="github_ruleset",
            field_path="required_pr_reviews_required",
            prev_value=True, new_value=False,
            pm_extra={"name": "main", "targets_protected_branch": True},
        )
        level, _ = classify_github_change(c)
        assert level == "high"

    def test_A9_force_pushes_unrestricted_on_main_is_critical(self):
        c = _ch(
            record_type="github_ruleset", field_path="restrict_force_pushes",
            prev_value=True, new_value=False,
            pm_extra={"name": "main", "targets_protected_branch": True},
        )
        level, reason = classify_github_change(c)
        assert level == "critical"
        assert "force" in reason.lower()

    def test_A10_deletions_unrestricted_on_main_is_critical(self):
        c = _ch(
            record_type="github_ruleset", field_path="restrict_deletions",
            prev_value=True, new_value=False,
            pm_extra={"name": "main", "targets_protected_branch": True},
        )
        level, _ = classify_github_change(c)
        assert level == "critical"

    def test_A11_branch_patterns_broadened_is_medium(self):
        c = _ch(
            record_type="github_ruleset", field_path="branch_patterns_count",
            prev_value=1, new_value=4,
            pm_extra={"name": "main", "targets_protected_branch": True},
        )
        level, _ = classify_github_change(c)
        assert level == "medium"

    def test_A12_ruleset_strengthened_is_low(self):
        c = _ch(
            record_type="github_ruleset", field_path="enforcement",
            prev_value="disabled", new_value="active",
            pm_extra={"name": "main", "targets_protected_branch": True},
        )
        level, _ = classify_github_change(c)
        assert level == "low"


# ═════════════════════════════════════════════════════════════════════════════
# B. github_codeowners
# ═════════════════════════════════════════════════════════════════════════════


class TestCodeowners:

    def test_B1_codeowners_removed_is_high(self):
        c = _ch(record_type="github_codeowners", change_type="removed")
        level, reason = classify_github_change(c)
        assert level == "high"
        assert "codeowners" in reason.lower()

    def test_B2_codeowners_added_is_low(self):
        c = _ch(record_type="github_codeowners", change_type="added")
        level, _ = classify_github_change(c)
        assert level == "low"

    def test_B3_exists_false_is_high(self):
        c = _ch(
            record_type="github_codeowners", field_path="exists",
            prev_value=True, new_value=False,
        )
        level, _ = classify_github_change(c)
        assert level == "high"

    def test_B4_critical_path_owners_removed_is_high(self):
        c = _ch(
            record_type="github_codeowners",
            field_path="critical_paths_with_owners",
            prev_value={"workflows": True, "infra": True, "terraform": True,
                        "auth": True, "billing": True, "security": True,
                        "config": True},
            new_value={"workflows": False, "infra": False, "terraform": True,
                       "auth": True, "billing": True, "security": True,
                       "config": True},
        )
        level, reason = classify_github_change(c)
        assert level == "high"
        assert "workflows" in reason.lower() or "infra" in reason.lower()

    def test_B5_critical_path_owners_added_is_low(self):
        c = _ch(
            record_type="github_codeowners",
            field_path="critical_paths_with_owners",
            prev_value={"workflows": False},
            new_value={"workflows": True},
        )
        level, _ = classify_github_change(c)
        assert level == "low"

    def test_B6_wildcard_owner_removed_is_medium(self):
        c = _ch(
            record_type="github_codeowners",
            field_path="wildcard_owner_present",
            prev_value=True, new_value=False,
        )
        level, _ = classify_github_change(c)
        assert level == "medium"

    def test_B7_content_hash_changed_is_medium(self):
        c = _ch(
            record_type="github_codeowners", field_path="content_hash",
            prev_value="hash_a", new_value="hash_b",
        )
        level, _ = classify_github_change(c)
        assert level == "medium"

    def test_B8_rule_count_decreased_is_medium(self):
        c = _ch(
            record_type="github_codeowners", field_path="rule_count",
            prev_value=10, new_value=5,
        )
        level, _ = classify_github_change(c)
        assert level == "medium"


# ═════════════════════════════════════════════════════════════════════════════
# C. github_workflow_file
# ═════════════════════════════════════════════════════════════════════════════


class TestWorkflowFile:

    def test_C1_workflow_added_with_pr_target_is_high(self):
        c = _ch(
            record_type="github_workflow_file",
            change_type="added",
            pm_extra={
                "path": ".github/workflows/ci.yml",
                "has_pull_request_target": True,
            },
        )
        level, reason = classify_github_change(c)
        assert level == "high"
        assert "pull_request_target" in reason.lower()

    def test_C2_workflow_added_normal_is_medium(self):
        c = _ch(
            record_type="github_workflow_file",
            change_type="added",
            pm_extra={
                "path": ".github/workflows/ci.yml",
                "has_pull_request_target": False,
            },
        )
        level, _ = classify_github_change(c)
        assert level == "medium"

    def test_C3_deploy_workflow_removed_is_high(self):
        c = _ch(
            record_type="github_workflow_file",
            change_type="removed",
            pm_extra={
                "path": ".github/workflows/deploy.yml",
                "is_deploy_workflow": True,
            },
        )
        level, _ = classify_github_change(c)
        assert level == "high"

    def test_C4_write_all_permissions_on_deploy_is_critical(self):
        c = _ch(
            record_type="github_workflow_file",
            field_path="permissions_summary",
            prev_value="default",
            new_value="write-all",
            pm_extra={
                "path": ".github/workflows/deploy.yml",
                "is_deploy_workflow": True,
            },
        )
        level, reason = classify_github_change(c)
        assert level == "critical"
        assert "write-all" in reason.lower()

    def test_C5_contents_write_gained_is_high(self):
        c = _ch(
            record_type="github_workflow_file",
            field_path="permissions_summary",
            prev_value="contents:read",
            new_value="contents:write,id-token:write",
            pm_extra={
                "path": ".github/workflows/ci.yml",
                "is_deploy_workflow": False,
            },
        )
        level, _ = classify_github_change(c)
        assert level == "high"

    def test_C6_pull_request_target_added_is_high(self):
        c = _ch(
            record_type="github_workflow_file",
            field_path="has_pull_request_target",
            prev_value=False, new_value=True,
            pm_extra={"path": ".github/workflows/ci.yml"},
        )
        level, _ = classify_github_change(c)
        assert level == "high"

    def test_C7_deploy_workflow_content_changed_is_high(self):
        c = _ch(
            record_type="github_workflow_file", field_path="content_hash",
            prev_value="a", new_value="b",
            pm_extra={
                "path": ".github/workflows/deploy.yml",
                "is_deploy_workflow": True,
            },
        )
        level, _ = classify_github_change(c)
        assert level == "high"

    def test_C8_workflow_disabled_is_high_when_deploy(self):
        c = _ch(
            record_type="github_workflow_file", field_path="enabled",
            prev_value=True, new_value=False,
            pm_extra={
                "path": ".github/workflows/deploy.yml",
                "is_deploy_workflow": True,
            },
        )
        level, _ = classify_github_change(c)
        assert level == "high"

    def test_C9_permissions_tightened_is_low(self):
        c = _ch(
            record_type="github_workflow_file",
            field_path="permissions_summary",
            prev_value="write-all", new_value="contents:read",
            pm_extra={"path": ".github/workflows/ci.yml"},
        )
        level, _ = classify_github_change(c)
        assert level == "low"


# ═════════════════════════════════════════════════════════════════════════════
# D. github_oidc_trust
# ═════════════════════════════════════════════════════════════════════════════


class TestOIDCTrust:

    def test_D1_repo_wildcard_added_is_critical(self):
        c = _ch(
            record_type="github_oidc_trust", field_path="repo_wildcard",
            prev_value=False, new_value=True,
            pm_extra={"cloud_provider": "aws", "audience": "sts.amazonaws.com"},
        )
        level, reason = classify_github_change(c)
        assert level == "critical"
        assert "wildcard" in reason.lower()

    def test_D2_org_wildcard_added_is_critical(self):
        c = _ch(
            record_type="github_oidc_trust", field_path="org_wildcard",
            prev_value=False, new_value=True,
            pm_extra={"cloud_provider": "aws"},
        )
        level, _ = classify_github_change(c)
        assert level == "critical"

    def test_D3_branch_wildcard_added_is_high(self):
        c = _ch(
            record_type="github_oidc_trust", field_path="branch_wildcard",
            prev_value=False, new_value=True,
            pm_extra={"cloud_provider": "aws"},
        )
        level, _ = classify_github_change(c)
        assert level == "high"

    def test_D4_environment_restriction_removed_is_high(self):
        c = _ch(
            record_type="github_oidc_trust",
            field_path="environment_restricted",
            prev_value=True, new_value=False,
            pm_extra={"cloud_provider": "aws"},
        )
        level, _ = classify_github_change(c)
        assert level == "high"

    def test_D5_oidc_trust_added_is_medium(self):
        c = _ch(
            record_type="github_oidc_trust", change_type="added",
            pm_extra={"cloud_provider": "aws", "audience": "sts.amazonaws.com"},
        )
        level, _ = classify_github_change(c)
        assert level == "medium"

    def test_D6_audience_changed_is_medium(self):
        c = _ch(
            record_type="github_oidc_trust", field_path="audience",
            prev_value="sts.amazonaws.com", new_value="custom-aud",
            pm_extra={"cloud_provider": "aws"},
        )
        level, _ = classify_github_change(c)
        assert level == "medium"

    def test_D7_trust_narrowed_is_low(self):
        c = _ch(
            record_type="github_oidc_trust", field_path="repo_wildcard",
            prev_value=True, new_value=False,
            pm_extra={"cloud_provider": "aws"},
        )
        level, _ = classify_github_change(c)
        assert level == "low"


# ═════════════════════════════════════════════════════════════════════════════
# E. github_collaborator
# ═════════════════════════════════════════════════════════════════════════════


class TestCollaborator:

    def test_E1_outside_collaborator_admin_added_is_critical(self):
        c = _ch(
            record_type="github_collaborator", change_type="added",
            new_value="admin",
            pm_extra={
                "actor_login": "external-user", "actor_type": "user",
                "is_outside_collaborator": True, "permission": "admin",
            },
        )
        level, reason = classify_github_change(c)
        assert level == "critical"
        assert "admin" in reason.lower()

    def test_E2_internal_admin_added_is_high(self):
        c = _ch(
            record_type="github_collaborator", change_type="added",
            new_value="admin",
            pm_extra={
                "actor_login": "alice", "actor_type": "user",
                "is_outside_collaborator": False, "permission": "admin",
            },
        )
        level, _ = classify_github_change(c)
        assert level == "high"

    def test_E3_outside_write_added_is_high(self):
        c = _ch(
            record_type="github_collaborator", change_type="added",
            new_value="write",
            pm_extra={
                "actor_login": "ext", "actor_type": "user",
                "is_outside_collaborator": True, "permission": "write",
            },
        )
        level, _ = classify_github_change(c)
        assert level == "high"

    def test_E4_team_write_added_is_medium(self):
        c = _ch(
            record_type="github_collaborator", change_type="added",
            new_value="write",
            pm_extra={
                "actor_login": "platform-team", "actor_type": "team",
                "is_outside_collaborator": False, "permission": "write",
            },
        )
        level, _ = classify_github_change(c)
        assert level == "medium"

    def test_E5_permission_upgraded_read_to_admin_is_high_internal(self):
        c = _ch(
            record_type="github_collaborator", field_path="permission",
            prev_value="read", new_value="admin",
            pm_extra={
                "actor_login": "alice", "actor_type": "user",
                "is_outside_collaborator": False,
            },
        )
        level, _ = classify_github_change(c)
        assert level == "high"

    def test_E6_permission_upgraded_to_admin_outside_is_critical(self):
        c = _ch(
            record_type="github_collaborator", field_path="permission",
            prev_value="read", new_value="admin",
            pm_extra={
                "actor_login": "ext", "actor_type": "user",
                "is_outside_collaborator": True,
            },
        )
        level, _ = classify_github_change(c)
        assert level == "critical"

    def test_E7_collaborator_removed_is_medium(self):
        c = _ch(
            record_type="github_collaborator", change_type="removed",
            pm_extra={"actor_login": "alice", "actor_type": "user"},
        )
        level, _ = classify_github_change(c)
        assert level == "medium"

    def test_E8_permission_lowered_is_low(self):
        c = _ch(
            record_type="github_collaborator", field_path="permission",
            prev_value="admin", new_value="read",
            pm_extra={"actor_login": "alice", "actor_type": "user"},
        )
        level, _ = classify_github_change(c)
        assert level == "low"


# ═════════════════════════════════════════════════════════════════════════════
# F. github_app_installation
# ═════════════════════════════════════════════════════════════════════════════


class TestAppInstallation:

    def test_F1_app_installed_with_admin_is_critical(self):
        c = _ch(
            record_type="github_app_installation", change_type="added",
            pm_extra={"app_slug": "spooky-app", "has_admin_access": True},
        )
        level, reason = classify_github_change(c)
        assert level == "critical"
        assert "admin" in reason.lower()

    def test_F2_app_installed_with_secrets_is_high(self):
        c = _ch(
            record_type="github_app_installation", change_type="added",
            pm_extra={"app_slug": "secrets-reader", "has_secrets_access": True},
        )
        level, _ = classify_github_change(c)
        assert level == "high"

    def test_F3_app_installed_with_contents_write_is_high(self):
        c = _ch(
            record_type="github_app_installation", change_type="added",
            pm_extra={"app_slug": "code-mover", "has_contents_write": True},
        )
        level, _ = classify_github_change(c)
        assert level == "high"

    def test_F4_app_installed_no_elevated_perms_is_medium(self):
        c = _ch(
            record_type="github_app_installation", change_type="added",
            pm_extra={"app_slug": "metadata-only"},
        )
        level, _ = classify_github_change(c)
        assert level == "medium"

    def test_F5_admin_access_granted_later_is_critical(self):
        c = _ch(
            record_type="github_app_installation", field_path="has_admin_access",
            prev_value=False, new_value=True,
            pm_extra={"app_slug": "spooky-app"},
        )
        level, _ = classify_github_change(c)
        assert level == "critical"

    def test_F6_secrets_access_granted_later_is_high(self):
        c = _ch(
            record_type="github_app_installation",
            field_path="has_secrets_access",
            prev_value=False, new_value=True,
            pm_extra={"app_slug": "spooky-app"},
        )
        level, _ = classify_github_change(c)
        assert level == "high"

    def test_F7_repo_selection_broadened_to_all_is_high(self):
        c = _ch(
            record_type="github_app_installation",
            field_path="repository_selection",
            prev_value="selected", new_value="all",
            pm_extra={"app_slug": "scope-creep"},
        )
        level, reason = classify_github_change(c)
        assert level == "high"
        assert "all" in reason.lower()

    def test_F8_app_removed_is_medium(self):
        c = _ch(
            record_type="github_app_installation", change_type="removed",
            pm_extra={"app_slug": "old-app"},
        )
        level, _ = classify_github_change(c)
        assert level == "medium"

    def test_F9_repo_selection_narrowed_is_low(self):
        c = _ch(
            record_type="github_app_installation",
            field_path="repository_selection",
            prev_value="all", new_value="selected",
            pm_extra={"app_slug": "scope-creep"},
        )
        level, _ = classify_github_change(c)
        assert level == "low"


# ═════════════════════════════════════════════════════════════════════════════
# G. github_security_features
# ═════════════════════════════════════════════════════════════════════════════


class TestSecurityFeatures:

    def test_G1_secret_scanning_disabled_is_high(self):
        c = _ch(
            record_type="github_security_features",
            field_path="secret_scanning_enabled",
            prev_value=True, new_value=False,
            pm_extra={"private_repo": True},
        )
        level, _ = classify_github_change(c)
        assert level == "high"

    def test_G2_push_protection_disabled_is_high(self):
        c = _ch(
            record_type="github_security_features",
            field_path="secret_scanning_push_protection",
            prev_value=True, new_value=False,
            pm_extra={"private_repo": True},
        )
        level, _ = classify_github_change(c)
        assert level == "high"

    def test_G3_code_scanning_disabled_is_high(self):
        c = _ch(
            record_type="github_security_features",
            field_path="code_scanning_enabled",
            prev_value=True, new_value=False,
            pm_extra={"private_repo": True},
        )
        level, _ = classify_github_change(c)
        assert level == "high"

    def test_G4_dependabot_alerts_disabled_is_medium(self):
        c = _ch(
            record_type="github_security_features",
            field_path="dependabot_alerts_enabled",
            prev_value=True, new_value=False,
            pm_extra={"private_repo": True},
        )
        level, _ = classify_github_change(c)
        assert level == "medium"

    def test_G5_dependabot_updates_disabled_is_medium(self):
        c = _ch(
            record_type="github_security_features",
            field_path="dependabot_security_updates_enabled",
            prev_value=True, new_value=False,
            pm_extra={"private_repo": True},
        )
        level, _ = classify_github_change(c)
        assert level == "medium"

    def test_G6_vulnerability_alerts_disabled_is_medium(self):
        c = _ch(
            record_type="github_security_features",
            field_path="vulnerability_alerts_enabled",
            prev_value=True, new_value=False,
            pm_extra={"private_repo": True},
        )
        level, _ = classify_github_change(c)
        assert level == "medium"

    def test_G7_secret_scanning_enabled_is_low(self):
        c = _ch(
            record_type="github_security_features",
            field_path="secret_scanning_enabled",
            prev_value=False, new_value=True,
            pm_extra={"private_repo": True},
        )
        level, _ = classify_github_change(c)
        assert level == "low"

    def test_G8_code_scanning_enabled_is_low(self):
        c = _ch(
            record_type="github_security_features",
            field_path="code_scanning_enabled",
            prev_value=False, new_value=True,
            pm_extra={"private_repo": True},
        )
        level, _ = classify_github_change(c)
        assert level == "low"

    def test_G9_unknown_field_falls_back_low(self):
        c = _ch(
            record_type="github_security_features",
            field_path="some_unknown_attribute",
            prev_value=True, new_value=False,
        )
        level, _ = classify_github_change(c)
        assert level == "low"


# ═════════════════════════════════════════════════════════════════════════════
# H. Dispatcher + safety
# ═════════════════════════════════════════════════════════════════════════════


class TestDispatcherSafety:

    def test_H1_unknown_github_subtype_falls_back_safely(self):
        c = _ch(
            record_type="github_does_not_exist",
            field_path="x", prev_value="a", new_value="b",
        )
        level, reason = classify_github_change(c)
        assert level == "low"
        assert "unrecognised" in reason.lower() or "unrecognized" in reason.lower()

    @pytest.mark.parametrize("bad_pm", [None, "not a dict", 42, [], ()])
    def test_H2_malformed_provider_metadata_does_not_crash(self, bad_pm):
        c = MagicMock(name="Change")
        c.change_type = "modified"
        c.field_path = "x"
        c.prev_value = "a"
        c.new_value = "b"
        c.provider_metadata = bad_pm
        level, _ = classify_github_change(c)
        assert level in ("critical", "high", "medium", "low")

    def test_H3_existing_record_types_still_dispatch(self):
        """Regression: legacy record types still work after the new branches
        were inserted."""
        c = _ch(
            record_type="github_repo_settings", field_path="visibility",
            prev_value="private", new_value="public",
        )
        level, _ = classify_github_change(c)
        # Legacy classifier returns critical for private → public.
        assert level == "critical"


# ═════════════════════════════════════════════════════════════════════════════
# S. Secret-safety tripwires
# ═════════════════════════════════════════════════════════════════════════════


# Realistic credential-shaped fixtures.  No reason from ANY classifier path
# should ever echo these substrings.
_SECRET_FIXTURES: dict[str, str] = {
    "github_pat": "ghp_" + ("G" * 36),
    "github_oauth": "gho_" + ("H" * 36),
    "github_app_pat": "github_pat_11A" + ("I" * 80),
    "stripe_sk_live": "sk_live_" + ("A" * 99),
    "stripe_whsec": "whsec_" + ("C" * 80),
    "aws_akia": "AKIA" + ("K" * 16),
    "bearer_jwt": "Bearer eyJhbGciOi" + ("N" * 80),
    "private_key_pem": (
        "-----BEGIN PRIVATE KEY-----\n"
        + ("O" * 60) + "\n"
        + ("P" * 60) + "\n"
        "-----END PRIVATE KEY-----"
    ),
    "ssh_rsa_pub": "ssh-rsa AAAA" + ("Q" * 200),
    "webhook_url_with_token": "https://hooks.example.com/intake?token=" + ("Z" * 48),
}


_FORBIDDEN_PATTERNS = (
    re.compile(r"\bBearer\s+[A-Za-z0-9._\-]{6,}", re.IGNORECASE),
    re.compile(r"\bAuthorization:\s*Bearer", re.IGNORECASE),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bsk_live_[A-Za-z0-9]{32,}"),
    re.compile(r"\bghp_[A-Za-z0-9]{30,}"),
    re.compile(r"\bAKIA[A-Z0-9]{16}"),
    re.compile(r"\bwhsec_[A-Za-z0-9]{32,}"),
    re.compile(r"\bssh-rsa\s+[A-Za-z0-9+/=]{50,}"),
)


def _assert_safe(reason: str, secret: str) -> None:
    assert secret not in reason, f"Reason leaked secret substring: {reason!r}"
    for p in _FORBIDDEN_PATTERNS:
        assert not p.search(reason), (
            f"Reason matched forbidden pattern {p.pattern!r}: {reason!r}"
        )


class TestSecretSafety:

    @pytest.mark.parametrize("name,secret", list(_SECRET_FIXTURES.items()))
    def test_S1_codeowners_content_hash_change_does_not_echo_secret(self, name, secret):
        """A naïve diff might place CODEOWNERS file content into prev_value/new_value.
        The classifier must NEVER echo that content into the risk reason."""
        c = _ch(
            record_type="github_codeowners", field_path="content_hash",
            prev_value=secret, new_value=secret,
        )
        _, reason = classify_github_change(c)
        _assert_safe(reason, secret)

    @pytest.mark.parametrize("name,secret", list(_SECRET_FIXTURES.items()))
    def test_S2_workflow_content_change_does_not_echo_secret(self, name, secret):
        c = _ch(
            record_type="github_workflow_file", field_path="content_hash",
            prev_value="hash_a", new_value=secret,
            pm_extra={"path": ".github/workflows/deploy.yml",
                      "is_deploy_workflow": True},
        )
        _, reason = classify_github_change(c)
        _assert_safe(reason, secret)

    @pytest.mark.parametrize("name,secret", list(_SECRET_FIXTURES.items()))
    def test_S3_oidc_audience_change_does_not_echo_secret(self, name, secret):
        c = _ch(
            record_type="github_oidc_trust", field_path="audience",
            prev_value="sts.amazonaws.com", new_value=secret,
            pm_extra={"cloud_provider": "aws"},
        )
        _, reason = classify_github_change(c)
        _assert_safe(reason, secret)

    def test_S4_no_forbidden_phrases_in_severe_scenarios(self):
        bad_phrases = (
            "compromised", "hacked", "definitely down", "guaranteed outage",
            "site is down", "auto-fix", "auto fix",
        )
        scenarios = [
            _ch(record_type="github_ruleset", change_type="removed",
                pm_extra={"name": "main", "targets_protected_branch": True}),
            _ch(record_type="github_codeowners", change_type="removed"),
            _ch(record_type="github_workflow_file",
                field_path="permissions_summary",
                prev_value="default", new_value="write-all",
                pm_extra={"path": ".github/workflows/deploy.yml",
                          "is_deploy_workflow": True}),
            _ch(record_type="github_oidc_trust", field_path="repo_wildcard",
                prev_value=False, new_value=True,
                pm_extra={"cloud_provider": "aws"}),
            _ch(record_type="github_collaborator", change_type="added",
                new_value="admin",
                pm_extra={"actor_login": "ext", "actor_type": "user",
                          "is_outside_collaborator": True, "permission": "admin"}),
            _ch(record_type="github_app_installation", change_type="added",
                pm_extra={"app_slug": "spooky-app", "has_admin_access": True}),
            _ch(record_type="github_security_features",
                field_path="secret_scanning_enabled",
                prev_value=True, new_value=False),
        ]
        for c in scenarios:
            _, reason = classify_github_change(c)
            r = reason.lower()
            for bad in bad_phrases:
                assert bad not in r, (
                    f"Forbidden phrase {bad!r} in: {reason!r}"
                )
