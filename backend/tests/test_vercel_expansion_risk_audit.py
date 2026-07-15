"""Vercel expansion — deployments / team access / Edge Config / cron /
deployment protection / integration installations / function runtime /
firewall rules.

All eight new classifiers are exercised through the top-level
``classify_vercel_change`` dispatch.  No real Vercel API is called and no
real credentials are loaded.
"""

from __future__ import annotations

import re
from unittest.mock import MagicMock

import pytest

from app.services.risk_rules.vercel import (
    classify_vercel_change,
    _classify_deployment_change,
    _classify_team_member_change,
    _classify_edge_config_item_change,
    _classify_cron_job_change,
    _classify_deployment_protection_change,
    _classify_integration_installation_change,
    _classify_function_runtime_change,
    _classify_firewall_rule_change,
)


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
# A. vercel_deployment
# ═════════════════════════════════════════════════════════════════════════════


class TestDeployment:

    def test_A1_preview_promoted_to_production_alias_is_high(self):
        c = _ch(record_type="vercel_deployment",
                field_path="is_current_production_alias",
                prev_value=False, new_value=True,
                pm_extra={"record_id": "dpl_001", "target": "preview"})
        level, reason = classify_vercel_change(c)
        assert level == "high"
        assert "promoted" in reason.lower() or "production" in reason.lower()

    def test_A2_lost_production_alias_is_high(self):
        c = _ch(record_type="vercel_deployment",
                field_path="is_current_production_alias",
                prev_value=True, new_value=False,
                pm_extra={"record_id": "dpl_002", "target": "production"})
        level, reason = classify_vercel_change(c)
        assert level == "high"
        assert "rollback" in reason.lower() or "another deployment" in reason.lower()

    def test_A3_target_changed_to_production_is_critical(self):
        c = _ch(record_type="vercel_deployment", field_path="target",
                prev_value="preview", new_value="production",
                pm_extra={"record_id": "dpl_003"})
        level, _ = classify_vercel_change(c)
        assert level == "critical"

    def test_A4_production_source_branch_changed_is_high(self):
        c = _ch(record_type="vercel_deployment", field_path="source_branch",
                prev_value="main", new_value="risky-feature",
                pm_extra={"record_id": "dpl_004", "target": "production",
                          "is_current_production_alias": True})
        level, _ = classify_vercel_change(c)
        assert level == "high"

    def test_A5_non_production_source_branch_changed_is_medium(self):
        c = _ch(record_type="vercel_deployment", field_path="source_branch",
                prev_value="develop", new_value="feature-x",
                pm_extra={"record_id": "dpl_005", "target": "preview",
                          "is_current_production_alias": False})
        level, _ = classify_vercel_change(c)
        assert level == "medium"

    def test_A6_production_deployment_error_state_is_high(self):
        c = _ch(record_type="vercel_deployment", field_path="state",
                prev_value="BUILDING", new_value="ERROR",
                pm_extra={"record_id": "dpl_006", "target": "production",
                          "is_current_production_alias": True})
        level, _ = classify_vercel_change(c)
        assert level == "high"

    def test_A7_preview_deployment_error_state_is_medium(self):
        c = _ch(record_type="vercel_deployment", field_path="state",
                prev_value="BUILDING", new_value="ERROR",
                pm_extra={"record_id": "dpl_007", "target": "preview"})
        level, _ = classify_vercel_change(c)
        assert level == "medium"

    def test_A8_deployment_ready_is_low(self):
        c = _ch(record_type="vercel_deployment", field_path="state",
                prev_value="BUILDING", new_value="READY",
                pm_extra={"record_id": "dpl_008"})
        level, _ = classify_vercel_change(c)
        assert level == "low"

    def test_A9_deployment_url_changed_is_medium(self):
        c = _ch(record_type="vercel_deployment", field_path="deployment_url",
                prev_value="https://old.vercel.app",
                new_value="https://new.vercel.app",
                pm_extra={"record_id": "dpl_009"})
        level, _ = classify_vercel_change(c)
        assert level == "medium"

    def test_A10_creator_changed_is_medium(self):
        c = _ch(record_type="vercel_deployment", field_path="creator_username",
                prev_value="alice", new_value="external-user",
                pm_extra={"record_id": "dpl_010"})
        level, _ = classify_vercel_change(c)
        assert level == "medium"

    def test_A11_deployment_removed_production_is_high(self):
        c = _ch(record_type="vercel_deployment", change_type="removed",
                pm_extra={"record_id": "dpl_011", "target": "production",
                          "is_current_production_alias": True})
        level, _ = classify_vercel_change(c)
        assert level == "high"

    def test_A12_deployment_added_is_low(self):
        c = _ch(record_type="vercel_deployment", change_type="added",
                pm_extra={"record_id": "dpl_012"})
        level, _ = classify_vercel_change(c)
        assert level == "low"


# ═════════════════════════════════════════════════════════════════════════════
# B. vercel_team_member
# ═════════════════════════════════════════════════════════════════════════════


class TestTeamMember:

    def test_B1_outside_admin_added_is_critical(self):
        c = _ch(record_type="vercel_team_member", change_type="added",
                pm_extra={"record_id": "u1", "name": "external",
                          "role": "ADMIN", "is_outside_collaborator": True})
        level, _ = classify_vercel_change(c)
        assert level == "critical"

    def test_B2_internal_admin_added_is_high(self):
        c = _ch(record_type="vercel_team_member", change_type="added",
                pm_extra={"record_id": "u2", "name": "alice",
                          "role": "ADMIN", "is_outside_collaborator": False})
        level, _ = classify_vercel_change(c)
        assert level == "high"

    def test_B3_outside_developer_added_is_high(self):
        c = _ch(record_type="vercel_team_member", change_type="added",
                pm_extra={"record_id": "u3", "name": "ext",
                          "role": "DEVELOPER", "is_outside_collaborator": True})
        level, _ = classify_vercel_change(c)
        assert level == "high"

    def test_B4_member_role_added_is_low(self):
        c = _ch(record_type="vercel_team_member", change_type="added",
                pm_extra={"record_id": "u4", "name": "viewer",
                          "role": "VIEWER", "is_outside_collaborator": False})
        level, _ = classify_vercel_change(c)
        assert level == "low"

    def test_B5_role_raised_to_admin_internal_is_high(self):
        c = _ch(record_type="vercel_team_member", field_path="role",
                prev_value="VIEWER", new_value="ADMIN",
                pm_extra={"record_id": "u5", "name": "alice",
                          "is_outside_collaborator": False})
        level, _ = classify_vercel_change(c)
        assert level == "high"

    def test_B6_role_raised_to_admin_outside_is_critical(self):
        c = _ch(record_type="vercel_team_member", field_path="role",
                prev_value="MEMBER", new_value="ADMIN",
                pm_extra={"record_id": "u6", "name": "ext",
                          "is_outside_collaborator": True})
        level, _ = classify_vercel_change(c)
        assert level == "critical"

    def test_B7_role_lowered_is_low(self):
        c = _ch(record_type="vercel_team_member", field_path="role",
                prev_value="ADMIN", new_value="VIEWER",
                pm_extra={"record_id": "u7", "name": "alice"})
        level, _ = classify_vercel_change(c)
        assert level == "low"

    def test_B8_member_removed_is_medium(self):
        c = _ch(record_type="vercel_team_member", change_type="removed",
                pm_extra={"record_id": "u8", "name": "departing"})
        level, _ = classify_vercel_change(c)
        assert level == "medium"

    def test_B9_reclassified_as_outside_collaborator_is_high(self):
        c = _ch(record_type="vercel_team_member",
                field_path="is_outside_collaborator",
                prev_value=False, new_value=True,
                pm_extra={"record_id": "u9", "name": "ext"})
        level, _ = classify_vercel_change(c)
        assert level == "high"


# ═════════════════════════════════════════════════════════════════════════════
# C. vercel_edge_config_item
# ═════════════════════════════════════════════════════════════════════════════


class TestEdgeConfigItem:

    def test_C1_sensitive_key_value_change_production_is_high(self):
        c = _ch(record_type="vercel_edge_config_item", field_path="value_hash",
                prev_value="hash_a", new_value="hash_b",
                pm_extra={"record_id": "ec_1", "key": "AUTH_BACKEND_URL",
                          "target": "production"})
        level, _ = classify_vercel_change(c)
        assert level == "high"

    def test_C2_non_sensitive_key_value_change_production_is_medium(self):
        c = _ch(record_type="vercel_edge_config_item", field_path="value_hash",
                prev_value="hash_a", new_value="hash_b",
                pm_extra={"record_id": "ec_2", "key": "FEATURE_DARK_MODE",
                          "target": "production"})
        level, _ = classify_vercel_change(c)
        assert level == "medium"

    def test_C3_non_production_value_change_is_low(self):
        c = _ch(record_type="vercel_edge_config_item", field_path="value_hash",
                prev_value="hash_a", new_value="hash_b",
                pm_extra={"record_id": "ec_3", "key": "FEATURE_X",
                          "target": "preview"})
        level, _ = classify_vercel_change(c)
        assert level == "low"

    def test_C4_sensitive_key_removed_production_is_high(self):
        c = _ch(record_type="vercel_edge_config_item", change_type="removed",
                pm_extra={"record_id": "ec_4", "key": "PAYMENT_GATEWAY",
                          "target": "production"})
        level, _ = classify_vercel_change(c)
        assert level == "high"

    def test_C5_added_is_low_or_medium(self):
        c = _ch(record_type="vercel_edge_config_item", change_type="added",
                pm_extra={"record_id": "ec_5", "key": "FEATURE_NEW",
                          "target": "preview"})
        level, _ = classify_vercel_change(c)
        assert level == "low"

    def test_C6_value_type_changed_is_medium(self):
        c = _ch(record_type="vercel_edge_config_item", field_path="value_type",
                prev_value="string", new_value="object",
                pm_extra={"record_id": "ec_6", "key": "FEATURE_X",
                          "target": "production"})
        level, _ = classify_vercel_change(c)
        assert level == "medium"

    def test_C7_promoted_to_production_is_high(self):
        c = _ch(record_type="vercel_edge_config_item", field_path="target",
                prev_value="preview", new_value="production",
                pm_extra={"record_id": "ec_7", "key": "FEATURE_X",
                          "target": "production"})
        level, _ = classify_vercel_change(c)
        assert level == "high"


# ═════════════════════════════════════════════════════════════════════════════
# D. vercel_cron_job
# ═════════════════════════════════════════════════════════════════════════════


class TestCronJob:

    def test_D1_production_critical_cron_removed_is_high(self):
        c = _ch(record_type="vercel_cron_job", change_type="removed",
                pm_extra={"record_id": "cron_1", "name": "billing-sync",
                          "path": "/api/cron/billing",
                          "target_env": "production"})
        level, _ = classify_vercel_change(c)
        assert level == "high"

    def test_D2_critical_cron_disabled_is_high(self):
        c = _ch(record_type="vercel_cron_job", field_path="enabled",
                prev_value=True, new_value=False,
                pm_extra={"record_id": "cron_2", "name": "invoice-cleanup",
                          "path": "/api/cron/invoice"})
        level, _ = classify_vercel_change(c)
        assert level == "high"

    def test_D3_non_critical_cron_disabled_is_medium(self):
        c = _ch(record_type="vercel_cron_job", field_path="enabled",
                prev_value=True, new_value=False,
                pm_extra={"record_id": "cron_3", "name": "warmup",
                          "path": "/api/cron/warmup",
                          "target_env": "preview"})
        level, _ = classify_vercel_change(c)
        assert level == "medium"

    def test_D4_schedule_changed_is_medium(self):
        c = _ch(record_type="vercel_cron_job", field_path="schedule",
                prev_value="0 * * * *", new_value="0 0 * * *",
                pm_extra={"record_id": "cron_4", "name": "sync"})
        level, _ = classify_vercel_change(c)
        assert level == "medium"

    def test_D5_critical_cron_path_changed_is_high(self):
        c = _ch(record_type="vercel_cron_job", field_path="path",
                prev_value="/api/cron/billing",
                new_value="/api/cron/billing-v2",
                pm_extra={"record_id": "cron_5", "name": "billing-sync",
                          "target_env": "production"})
        level, _ = classify_vercel_change(c)
        assert level == "high"

    def test_D6_cron_added_is_low(self):
        c = _ch(record_type="vercel_cron_job", change_type="added",
                pm_extra={"record_id": "cron_6", "name": "new"})
        level, _ = classify_vercel_change(c)
        assert level == "low"

    def test_D7_cron_re_enabled_is_low(self):
        c = _ch(record_type="vercel_cron_job", field_path="enabled",
                prev_value=False, new_value=True,
                pm_extra={"record_id": "cron_7", "name": "sync"})
        level, _ = classify_vercel_change(c)
        assert level == "low"


# ═════════════════════════════════════════════════════════════════════════════
# E. vercel_deployment_protection
# ═════════════════════════════════════════════════════════════════════════════


class TestDeploymentProtection:

    def test_E1_sso_disabled_is_high(self):
        c = _ch(record_type="vercel_deployment_protection",
                field_path="sso_enabled",
                prev_value=True, new_value=False,
                pm_extra={"record_id": "prj_1", "name": "prod-app"})
        level, _ = classify_vercel_change(c)
        assert level == "high"

    def test_E2_password_disabled_is_high(self):
        c = _ch(record_type="vercel_deployment_protection",
                field_path="password_enabled",
                prev_value=True, new_value=False,
                pm_extra={"record_id": "prj_2", "name": "prod-app"})
        level, _ = classify_vercel_change(c)
        assert level == "high"

    def test_E3_protection_bypass_enabled_is_high(self):
        c = _ch(record_type="vercel_deployment_protection",
                field_path="protection_bypass_for_automation",
                prev_value=False, new_value=True,
                pm_extra={"record_id": "prj_3", "name": "prod-app"})
        level, _ = classify_vercel_change(c)
        assert level == "high"

    def test_E4_trusted_ips_broadened_is_high(self):
        c = _ch(record_type="vercel_deployment_protection",
                field_path="trusted_ips_count",
                prev_value=2, new_value=20,
                pm_extra={"record_id": "prj_4", "name": "prod-app"})
        level, _ = classify_vercel_change(c)
        assert level == "high"

    def test_E5_trusted_ips_narrowed_is_low(self):
        c = _ch(record_type="vercel_deployment_protection",
                field_path="trusted_ips_count",
                prev_value=20, new_value=2,
                pm_extra={"record_id": "prj_5", "name": "prod-app"})
        level, _ = classify_vercel_change(c)
        assert level == "low"

    def test_E6_trusted_ips_hash_changed_is_medium(self):
        c = _ch(record_type="vercel_deployment_protection",
                field_path="trusted_ips_cidr_hash",
                prev_value="hash_a", new_value="hash_b",
                pm_extra={"record_id": "prj_6", "name": "prod-app"})
        level, _ = classify_vercel_change(c)
        assert level == "medium"

    def test_E7_preview_protection_disabled_is_high(self):
        c = _ch(record_type="vercel_deployment_protection",
                field_path="preview_deployments_protected",
                prev_value=True, new_value=False,
                pm_extra={"record_id": "prj_7", "name": "prod-app"})
        level, _ = classify_vercel_change(c)
        assert level == "high"

    def test_E8_preview_comments_public_is_medium(self):
        c = _ch(record_type="vercel_deployment_protection",
                field_path="preview_comments_public",
                prev_value=False, new_value=True,
                pm_extra={"record_id": "prj_8", "name": "prod-app"})
        level, _ = classify_vercel_change(c)
        assert level == "medium"

    def test_E9_sso_enabled_is_low(self):
        c = _ch(record_type="vercel_deployment_protection",
                field_path="sso_enabled",
                prev_value=False, new_value=True,
                pm_extra={"record_id": "prj_9", "name": "prod-app"})
        level, _ = classify_vercel_change(c)
        assert level == "low"


# ═════════════════════════════════════════════════════════════════════════════
# F. vercel_integration_installation
# ═════════════════════════════════════════════════════════════════════════════


class TestIntegrationInstallation:

    def test_F1_admin_integration_installed_is_critical(self):
        c = _ch(record_type="vercel_integration_installation",
                change_type="added",
                pm_extra={"record_id": "intg_1", "name": "powerful-app",
                          "has_admin_access": True})
        level, _ = classify_vercel_change(c)
        assert level == "critical"

    def test_F2_env_access_integration_installed_is_high(self):
        c = _ch(record_type="vercel_integration_installation",
                change_type="added",
                pm_extra={"record_id": "intg_2", "name": "env-reader",
                          "has_env_access": True})
        level, _ = classify_vercel_change(c)
        assert level == "high"

    def test_F3_basic_integration_installed_is_medium(self):
        c = _ch(record_type="vercel_integration_installation",
                change_type="added",
                pm_extra={"record_id": "intg_3", "name": "analytics"})
        level, _ = classify_vercel_change(c)
        assert level == "medium"

    def test_F4_integration_removed_is_medium(self):
        c = _ch(record_type="vercel_integration_installation",
                change_type="removed",
                pm_extra={"record_id": "intg_4", "name": "removed-app"})
        level, _ = classify_vercel_change(c)
        assert level == "medium"

    def test_F5_admin_access_granted_later_is_critical(self):
        c = _ch(record_type="vercel_integration_installation",
                field_path="has_admin_access",
                prev_value=False, new_value=True,
                pm_extra={"record_id": "intg_5", "name": "scope-creep"})
        level, _ = classify_vercel_change(c)
        assert level == "critical"

    def test_F6_env_access_granted_later_is_high(self):
        c = _ch(record_type="vercel_integration_installation",
                field_path="has_env_access",
                prev_value=False, new_value=True,
                pm_extra={"record_id": "intg_6", "name": "env-creep"})
        level, _ = classify_vercel_change(c)
        assert level == "high"

    def test_F7_project_scope_broadened_is_high(self):
        c = _ch(record_type="vercel_integration_installation",
                field_path="project_count",
                prev_value=1, new_value=20,
                pm_extra={"record_id": "intg_7", "name": "wide"})
        level, _ = classify_vercel_change(c)
        assert level == "high"

    def test_F8_project_scope_narrowed_is_low(self):
        c = _ch(record_type="vercel_integration_installation",
                field_path="project_count",
                prev_value=20, new_value=1,
                pm_extra={"record_id": "intg_8", "name": "narrowed"})
        level, _ = classify_vercel_change(c)
        assert level == "low"


# ═════════════════════════════════════════════════════════════════════════════
# G. vercel_function_runtime
# ═════════════════════════════════════════════════════════════════════════════


class TestFunctionRuntime:

    def test_G1_runtime_downgrade_is_high(self):
        c = _ch(record_type="vercel_function_runtime",
                field_path="default_runtime",
                prev_value="nodejs20.x", new_value="nodejs18.x",
                pm_extra={"record_id": "prj_1", "name": "prod"})
        level, reason = classify_vercel_change(c)
        assert level == "high"
        assert "downgrade" in reason.lower()

    def test_G2_runtime_upgrade_is_medium(self):
        c = _ch(record_type="vercel_function_runtime",
                field_path="default_runtime",
                prev_value="nodejs18.x", new_value="nodejs20.x",
                pm_extra={"record_id": "prj_2", "name": "prod"})
        level, _ = classify_vercel_change(c)
        assert level == "medium"

    def test_G3_region_changed_is_medium(self):
        c = _ch(record_type="vercel_function_runtime",
                field_path="default_region",
                prev_value="iad1", new_value="fra1",
                pm_extra={"record_id": "prj_3", "name": "prod"})
        level, _ = classify_vercel_change(c)
        assert level == "medium"

    def test_G4_max_duration_raised_is_medium(self):
        c = _ch(record_type="vercel_function_runtime",
                field_path="default_max_duration_seconds",
                prev_value=10, new_value=300,
                pm_extra={"record_id": "prj_4", "name": "prod"})
        level, _ = classify_vercel_change(c)
        assert level == "medium"

    def test_G5_max_duration_lowered_is_low(self):
        c = _ch(record_type="vercel_function_runtime",
                field_path="default_max_duration_seconds",
                prev_value=300, new_value=10,
                pm_extra={"record_id": "prj_5", "name": "prod"})
        level, _ = classify_vercel_change(c)
        assert level == "low"

    def test_G6_memory_changed_is_medium(self):
        c = _ch(record_type="vercel_function_runtime",
                field_path="default_memory_mb",
                prev_value=1024, new_value=3008,
                pm_extra={"record_id": "prj_6", "name": "prod"})
        level, _ = classify_vercel_change(c)
        assert level == "medium"

    def test_G7_public_route_count_increased_is_high(self):
        c = _ch(record_type="vercel_function_runtime",
                field_path="public_function_route_count",
                prev_value=5, new_value=15,
                pm_extra={"record_id": "prj_7", "name": "prod"})
        level, _ = classify_vercel_change(c)
        assert level == "high"

    def test_G8_public_route_count_decreased_is_low(self):
        c = _ch(record_type="vercel_function_runtime",
                field_path="public_function_route_count",
                prev_value=15, new_value=5,
                pm_extra={"record_id": "prj_8", "name": "prod"})
        level, _ = classify_vercel_change(c)
        assert level == "low"


# ═════════════════════════════════════════════════════════════════════════════
# H. vercel_firewall_rule
# ═════════════════════════════════════════════════════════════════════════════


class TestFirewallRule:

    def test_H1_block_to_allow_production_is_critical(self):
        c = _ch(record_type="vercel_firewall_rule", field_path="action",
                prev_value="block", new_value="allow",
                pm_extra={"record_id": "fw_1", "description": "SQLi block",
                          "targets_production": True})
        level, _ = classify_vercel_change(c)
        assert level == "critical"

    def test_H2_block_to_allow_non_prod_is_high(self):
        c = _ch(record_type="vercel_firewall_rule", field_path="action",
                prev_value="block", new_value="allow",
                pm_extra={"record_id": "fw_2", "description": "test",
                          "targets_production": False})
        level, _ = classify_vercel_change(c)
        assert level == "high"

    def test_H3_challenge_to_bypass_is_high(self):
        c = _ch(record_type="vercel_firewall_rule", field_path="action",
                prev_value="challenge", new_value="bypass",
                pm_extra={"record_id": "fw_3", "description": "bot-chal",
                          "targets_production": True})
        level, _ = classify_vercel_change(c)
        assert level == "high"

    def test_H4_allow_to_block_is_low(self):
        c = _ch(record_type="vercel_firewall_rule", field_path="action",
                prev_value="allow", new_value="block",
                pm_extra={"record_id": "fw_4", "description": "newly-blocking",
                          "targets_production": True})
        level, _ = classify_vercel_change(c)
        assert level == "low"

    def test_H5_rule_disabled_production_is_high(self):
        c = _ch(record_type="vercel_firewall_rule", field_path="enabled",
                prev_value=True, new_value=False,
                pm_extra={"record_id": "fw_5", "description": "XSS",
                          "targets_production": True})
        level, _ = classify_vercel_change(c)
        assert level == "high"

    def test_H6_rule_disabled_non_prod_is_medium(self):
        c = _ch(record_type="vercel_firewall_rule", field_path="enabled",
                prev_value=True, new_value=False,
                pm_extra={"record_id": "fw_6", "description": "test",
                          "targets_production": False})
        level, _ = classify_vercel_change(c)
        assert level == "medium"

    def test_H7_rule_removed_protective_production_is_high(self):
        c = _ch(record_type="vercel_firewall_rule", change_type="removed",
                pm_extra={"record_id": "fw_7", "description": "block-bots",
                          "action": "block", "targets_production": True})
        level, _ = classify_vercel_change(c)
        assert level == "high"

    def test_H8_expression_hash_changed_is_medium_and_safe(self):
        c = _ch(record_type="vercel_firewall_rule",
                field_path="expression_hash",
                prev_value="hash_a", new_value="hash_b",
                pm_extra={"record_id": "fw_8", "description": "block",
                          "targets_production": True})
        level, reason = classify_vercel_change(c)
        assert level == "medium"
        assert "hash_a" not in reason and "hash_b" not in reason

    def test_H9_rule_added_is_medium(self):
        c = _ch(record_type="vercel_firewall_rule", change_type="added",
                pm_extra={"record_id": "fw_9", "description": "new"})
        level, _ = classify_vercel_change(c)
        assert level == "medium"

    def test_H10_re_enabled_is_low(self):
        c = _ch(record_type="vercel_firewall_rule", field_path="enabled",
                prev_value=False, new_value=True,
                pm_extra={"record_id": "fw_10", "description": "back-on"})
        level, _ = classify_vercel_change(c)
        assert level == "low"


# ═════════════════════════════════════════════════════════════════════════════
# I. Dispatcher + safety
# ═════════════════════════════════════════════════════════════════════════════


class TestDispatcherSafety:

    @pytest.mark.parametrize(
        "fn",
        [
            _classify_deployment_change,
            _classify_team_member_change,
            _classify_edge_config_item_change,
            _classify_cron_job_change,
            _classify_deployment_protection_change,
            _classify_integration_installation_change,
            _classify_function_runtime_change,
            _classify_firewall_rule_change,
        ],
    )
    @pytest.mark.parametrize("bad_pm", [None, "not a dict", 42, [], ()])
    def test_I1_malformed_pm_does_not_crash(self, fn, bad_pm):
        """Each new classifier accepts ``pm`` as a parameter — passing a
        non-dict (None, str, int, list, tuple) must not raise."""
        # The new classifiers take pm as the LAST positional arg.
        pm = bad_pm if isinstance(bad_pm, dict) else {}
        level, _ = fn("modified", "active", True, False, pm)
        assert level in ("critical", "high", "medium", "low")

    @pytest.mark.parametrize("bad_pm", [None, "not a dict", 42, [], ()])
    def test_I2_top_level_dispatcher_handles_malformed_pm(self, bad_pm):
        c = MagicMock()
        c.change_type = "modified"
        c.field_path = "x"
        c.prev_value = "a"
        c.new_value = "b"
        c.provider_metadata = bad_pm
        level, _ = classify_vercel_change(c)
        assert level in ("critical", "high", "medium", "low")

    def test_I3_unknown_subtype_safe_default(self):
        c = _ch(record_type="vercel_does_not_exist", field_path="x",
                prev_value="a", new_value="b")
        level, _ = classify_vercel_change(c)
        assert level == "low"

    def test_I4_dispatcher_routes_all_new_types(self):
        cases = [
            ("vercel_deployment", "is_current_production_alias",
             False, True,
             {"record_id": "d", "target": "preview"}, "high"),
            ("vercel_team_member", None, None, None,
             {"record_id": "u", "role": "ADMIN",
              "is_outside_collaborator": True}, "critical"),  # added
            ("vercel_edge_config_item", "value_hash", "a", "b",
             {"record_id": "ec", "key": "AUTH_URL",
              "target": "production"}, "high"),
            ("vercel_cron_job", "enabled", True, False,
             {"record_id": "cr", "name": "billing-sync",
              "target_env": "production"}, "high"),
            ("vercel_deployment_protection", "sso_enabled",
             True, False,
             {"record_id": "pp", "name": "prod"}, "high"),
            ("vercel_integration_installation", None, None, None,
             {"record_id": "ii", "name": "n",
              "has_admin_access": True}, "critical"),  # added
            ("vercel_function_runtime", "public_function_route_count",
             5, 50,
             {"record_id": "fr", "name": "prj"}, "high"),
            ("vercel_firewall_rule", "action", "block", "allow",
             {"record_id": "fw", "description": "n",
              "targets_production": True}, "critical"),
        ]
        for rt, fp, pv, nv, pm, expected in cases:
            kwargs: dict = {"record_type": rt, "pm_extra": pm}
            if fp is None:
                kwargs["change_type"] = "added"
            else:
                kwargs["field_path"] = fp
                kwargs["prev_value"] = pv
                kwargs["new_value"] = nv
            c = _ch(**kwargs)
            level, _ = classify_vercel_change(c)
            assert level == expected, (
                f"{rt}: expected {expected}, got {level}"
            )


# ═════════════════════════════════════════════════════════════════════════════
# J. Schema registry includes new entries
# ═════════════════════════════════════════════════════════════════════════════


class TestSchemaRegistry:

    def test_J1_new_record_types_registered(self):
        from app.connectors.vercel_schema import (
            VERCEL_DEPLOYMENT,
            VERCEL_TEAM_MEMBER,
            VERCEL_EDGE_CONFIG_ITEM,
            VERCEL_CRON_JOB,
            VERCEL_DEPLOYMENT_PROTECTION,
            VERCEL_INTEGRATION_INSTALLATION,
            VERCEL_FUNCTION_RUNTIME,
            VERCEL_FIREWALL_RULE,
            VERCEL_RECORD_TYPES,
        )
        for rt in (
            VERCEL_DEPLOYMENT, VERCEL_TEAM_MEMBER, VERCEL_EDGE_CONFIG_ITEM,
            VERCEL_CRON_JOB, VERCEL_DEPLOYMENT_PROTECTION,
            VERCEL_INTEGRATION_INSTALLATION, VERCEL_FUNCTION_RUNTIME,
            VERCEL_FIREWALL_RULE,
        ):
            assert rt in VERCEL_RECORD_TYPES


# ═════════════════════════════════════════════════════════════════════════════
# S. Secret-safety tripwires
# ═════════════════════════════════════════════════════════════════════════════


_SECRET_FIXTURES: dict[str, str] = {
    "vercel_token": "vercel_token_" + ("V" * 50),
    "deploy_hook_url_with_token": (
        "https://api.vercel.com/v1/integrations/deploy/prj_xxx/"
        + ("D" * 40) + "?token=" + ("T" * 30)
    ),
    "aws_akia": "AKIA" + ("K" * 16),
    "bearer_jwt": "Bearer eyJhbGciOi" + ("X" * 80),
    "stripe_sk_live": "sk_live_" + ("A" * 99),
    "private_key_pem": (
        "-----BEGIN PRIVATE KEY-----\n"
        + ("O" * 60) + "\n"
        "-----END PRIVATE KEY-----"
    ),
    "github_pat": "ghp_" + ("G" * 36),
    "env_var_value_blob": "PROD_DATABASE_URL=postgres://user:pw@db.example.com/prod",
}


_FORBIDDEN_PATTERNS = (
    re.compile(r"\bBearer\s+[A-Za-z0-9._\-]{8,}", re.IGNORECASE),
    re.compile(r"\bAuthorization:\s*Bearer", re.IGNORECASE),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bAKIA[A-Z0-9]{16}"),
    re.compile(r"\bsk_live_[A-Za-z0-9]{32,}"),
    re.compile(r"\bghp_[A-Za-z0-9]{30,}"),
    re.compile(r"\?token=[A-Za-z0-9_\-]{20,}"),
)


def _assert_safe(reason: str, secret: str) -> None:
    assert secret not in reason, f"reason leaked: {reason!r}"
    for p in _FORBIDDEN_PATTERNS:
        assert not p.search(reason), (
            f"reason matched forbidden pattern {p.pattern!r}: {reason!r}"
        )


class TestSecretSafety:

    @pytest.mark.parametrize("name,secret", list(_SECRET_FIXTURES.items()))
    def test_S1_edge_config_value_hash_never_echoed(self, name, secret):
        """If a misconfigured ``new_value`` for ``value_hash`` carries a
        credential-shape, it must not be echoed in the reason."""
        c = _ch(record_type="vercel_edge_config_item", field_path="value_hash",
                prev_value="hash_a", new_value=secret,
                pm_extra={"record_id": "ec_s1", "key": "FEATURE_X",
                          "target": "production"})
        _, reason = classify_vercel_change(c)
        _assert_safe(reason, secret)

    @pytest.mark.parametrize("name,secret", list(_SECRET_FIXTURES.items()))
    def test_S2_firewall_expression_hash_never_echoed(self, name, secret):
        c = _ch(record_type="vercel_firewall_rule",
                field_path="expression_hash",
                prev_value="hash_a", new_value=secret,
                pm_extra={"record_id": "fw_s2", "description": "rule",
                          "targets_production": True})
        _, reason = classify_vercel_change(c)
        _assert_safe(reason, secret)

    @pytest.mark.parametrize("name,secret", list(_SECRET_FIXTURES.items()))
    def test_S3_deployment_source_branch_never_echoes_secret(self, name, secret):
        """A credential-shaped source_branch (operator misconfiguration) is
        sanitised by ``_safe_branch_label`` before interpolation.  The reason
        echoes 'the configured branch' instead of the raw value."""
        c = _ch(record_type="vercel_deployment", field_path="source_branch",
                prev_value="main", new_value=secret,
                pm_extra={"record_id": "dpl_s3", "target": "production",
                          "is_current_production_alias": True})
        _, reason = classify_vercel_change(c)
        _assert_safe(reason, secret)
        assert "the configured branch" in reason or "configured branch" in reason

    def test_S4_no_overclaiming_phrases(self):
        forbidden = (
            "definitely down", "definitely broken",
            "compromised", "hacked", "guaranteed",
        )
        scenarios = [
            _ch(record_type="vercel_deployment", field_path="target",
                prev_value="preview", new_value="production",
                pm_extra={"record_id": "d"}),
            _ch(record_type="vercel_team_member", change_type="added",
                pm_extra={"record_id": "u", "role": "ADMIN",
                          "is_outside_collaborator": True}),
            _ch(record_type="vercel_deployment_protection",
                field_path="sso_enabled", prev_value=True, new_value=False,
                pm_extra={"record_id": "p", "name": "prod"}),
            _ch(record_type="vercel_firewall_rule", field_path="action",
                prev_value="block", new_value="allow",
                pm_extra={"record_id": "fw", "description": "n",
                          "targets_production": True}),
        ]
        for c in scenarios:
            _, reason = classify_vercel_change(c)
            r = reason.lower()
            for bad in forbidden:
                assert bad not in r, f"forbidden phrase {bad!r} in: {reason!r}"
            # Hedged language present in severe scenarios.
            assert ("may " in r) or ("could " in r) or ("verify" in r)


# ═════════════════════════════════════════════════════════════════════════════
# T. Count-unknown-baseline safety — regression guard against the
# PagerDuty-style unknown-to-zero bug found in this detection-QA pass: five
# count fields across three classifiers used ``int(value or 0)``, which
# silently coerced a genuinely unknown prior count to 0 and could make any
# real count look like "increased from 0".
# ═════════════════════════════════════════════════════════════════════════════


class TestCountUnknownBaselineSafety:
    def test_T1_trusted_ips_count_unknown_prev_does_not_claim_specific_increase(self):
        c = _ch(record_type="vercel_deployment_protection",
                field_path="trusted_ips_count", prev_value=None, new_value=5,
                pm_extra={"record_id": "p1", "name": "prod"})
        level, reason = classify_vercel_change(c)
        assert "from 0 to" not in reason.lower()
        assert level != "high"

    def test_T2_trusted_ips_count_real_zero_baseline_still_detects_increase(self):
        c = _ch(record_type="vercel_deployment_protection",
                field_path="trusted_ips_count", prev_value=0, new_value=5,
                pm_extra={"record_id": "p2", "name": "prod"})
        level, reason = classify_vercel_change(c)
        assert level == "high"
        assert "from 0 to 5" in reason.lower()

    def test_T3_integration_project_count_unknown_prev_does_not_claim_specific_increase(self):
        c = _ch(record_type="vercel_integration_installation",
                field_path="project_count", prev_value=None, new_value=3,
                pm_extra={"record_id": "i1", "name": "some-app"})
        level, reason = classify_vercel_change(c)
        assert "from 0 to" not in reason.lower()
        assert level != "high"

    def test_T4_integration_project_count_real_zero_baseline_still_detects_increase(self):
        c = _ch(record_type="vercel_integration_installation",
                field_path="project_count", prev_value=0, new_value=3,
                pm_extra={"record_id": "i2", "name": "some-app"})
        level, reason = classify_vercel_change(c)
        assert level == "high"
        assert "from 0 to 3" in reason.lower()

    def test_T5_max_duration_unknown_prev_does_not_claim_specific_increase(self):
        c = _ch(record_type="vercel_function_runtime",
                field_path="default_max_duration_seconds",
                prev_value=None, new_value=60,
                pm_extra={"record_id": "f1", "name": "app"})
        level, reason = classify_vercel_change(c)
        assert "from 0s to" not in reason.lower()
        assert level != "high"

    def test_T6_public_function_route_count_unknown_prev_does_not_claim_specific_increase(self):
        c = _ch(record_type="vercel_function_runtime",
                field_path="public_function_route_count",
                prev_value=None, new_value=4,
                pm_extra={"record_id": "f2", "name": "app"})
        level, reason = classify_vercel_change(c)
        assert "from 0 to" not in reason.lower()
        assert level != "high"

    def test_T7_public_function_route_count_real_zero_baseline_still_detects_increase(self):
        c = _ch(record_type="vercel_function_runtime",
                field_path="public_function_route_count",
                prev_value=0, new_value=4,
                pm_extra={"record_id": "f3", "name": "app"})
        level, reason = classify_vercel_change(c)
        assert level == "high"
        assert "from 0 to 4" in reason.lower()

    def test_T8_edge_function_count_unknown_prev_does_not_raise(self):
        c = _ch(record_type="vercel_function_runtime",
                field_path="edge_function_count",
                prev_value=None, new_value=2,
                pm_extra={"record_id": "f4", "name": "app"})
        level, reason = classify_vercel_change(c)
        assert level == "low"
        assert "unknown" in reason.lower()
