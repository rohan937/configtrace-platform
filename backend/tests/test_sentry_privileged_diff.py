"""Sentry effective-access derivation diff/risk-classification tests
(Sentry message 5 of 8).

Uses the REAL ``compute_diff()`` and ``classify_sentry_change()`` — never
hand-built Change objects standing in for the diff pipeline — to verify
privilege-tier escalation/reduction, organization-wide-access gained/
lost, effective-project-count broadening, ownership/alert routing
targets flipping resolved<->unresolved, integration-target enabled<->
disabled, provider metadata, and reordered-input stability.
"""

from __future__ import annotations

from types import SimpleNamespace as NS

from app.services.diff_service import compute_diff
from app.services.risk_rules.sentry import classify_sentry_change

_ORG = "id:999"


def _snap(records: list[dict]) -> NS:
    return NS(state=records)


def _privileged_member(mid: str, **overrides) -> dict:
    base = {
        "record_type": "sentry_privileged_member",
        "record_id": f"{_ORG}/privileged_member/{mid}",
        "provider_resource_id": f"privileged-members/{mid}",
        "organization_id": _ORG,
        "member_id": mid,
        "org_role_category": "member",
        "member_status_category": "active",
        "privilege_tier": "low",
        "organization_wide_project_access": False,
        "direct_team_count": 1,
        "team_admin_team_count": 0,
        "effective_project_count": 1,
        "project_access_source_categories": ["team_membership"],
        "alert_routing_target_count": 0,
        "ownership_rule_target_count": 0,
        "integration_control_context": "none",
        "repository_control_context": "add_only",
        "privilege_completeness": "complete",
    }
    base.update(overrides)
    return base


def _privileged_team(tid: str, **overrides) -> dict:
    base = {
        "record_type": "sentry_privileged_team",
        "record_id": f"{_ORG}/privileged_team/{tid}",
        "provider_resource_id": f"privileged-teams/{tid}",
        "organization_id": _ORG,
        "team_id": tid,
        "project_count": 1,
        "ownership_rule_target_count": 0,
        "alert_action_target_count": 0,
        "privileged_member_count": 0,
        "unresolved_member_count": 0,
        "access_completeness": "complete",
    }
    base.update(overrides)
    return base


def _routing_context(key: str, **overrides) -> dict:
    base = {
        "record_type": "sentry_routing_context",
        "record_id": f"{_ORG}/routing_context/alert_action/{key}",
        "provider_resource_id": f"routing-context/alert_action/{key}",
        "organization_id": _ORG,
        "context_type": "alert_action",
        "source_record_id": f"{_ORG}/alert_action/metric/{key}",
        "project_id": None,
        "rule_type": "metric",
        "rule_id": "r1",
        "target_type_category": "user",
        "target_id": "m1",
        "target_resolved": True,
        "target_active": True,
        "target_privilege_tier": "low",
        "integration_status_category": None,
        "context_enabled": True,
        "completeness": "complete",
    }
    base.update(overrides)
    return base


def _diff(prev: list[dict], new: list[dict]):
    return compute_diff(_snap(prev), _snap(new))


def _find(changes, *, field_path=None, change_type=None):
    for c in changes:
        if change_type is not None and c["change_type"] != change_type:
            continue
        if field_path is not None and c.get("field_path") != field_path:
            continue
        return c
    raise AssertionError(f"no change matched field_path={field_path!r} change_type={change_type!r} in {changes}")


# ════════════════════════════════════════════════════════════════════════════
# Privileged member
# ════════════════════════════════════════════════════════════════════════════


class TestPrivilegedMemberDiff:
    def test_member_to_owner_is_high(self):
        changes = _diff(
            [_privileged_member("m1", privilege_tier="low")],
            [_privileged_member("m1", privilege_tier="critical")],
        )
        c = _find(changes, field_path="privilege_tier")
        assert classify_sentry_change(c)[0] == "high"

    def test_member_to_admin_is_medium(self):
        changes = _diff(
            [_privileged_member("m1", privilege_tier="low")],
            [_privileged_member("m1", privilege_tier="medium")],
        )
        c = _find(changes, field_path="privilege_tier")
        assert classify_sentry_change(c)[0] == "medium"

    def test_owner_to_member_is_low(self):
        changes = _diff(
            [_privileged_member("m1", privilege_tier="critical")],
            [_privileged_member("m1", privilege_tier="low")],
        )
        c = _find(changes, field_path="privilege_tier")
        assert classify_sentry_change(c)[0] == "low"

    def test_organization_wide_access_gained_is_high(self):
        changes = _diff(
            [_privileged_member("m1", organization_wide_project_access=False)],
            [_privileged_member("m1", organization_wide_project_access=True)],
        )
        c = _find(changes, field_path="organization_wide_project_access")
        assert classify_sentry_change(c)[0] == "high"

    def test_organization_wide_access_lost_is_low(self):
        changes = _diff(
            [_privileged_member("m1", organization_wide_project_access=True)],
            [_privileged_member("m1", organization_wide_project_access=False)],
        )
        c = _find(changes, field_path="organization_wide_project_access")
        assert classify_sentry_change(c)[0] == "low"

    def test_effective_project_count_broadened_is_medium(self):
        changes = _diff(
            [_privileged_member("m1", effective_project_count=1)],
            [_privileged_member("m1", effective_project_count=5)],
        )
        c = _find(changes, field_path="effective_project_count")
        assert classify_sentry_change(c)[0] == "medium"

    def test_added_critical_tier_is_high(self):
        changes = _diff([], [_privileged_member("m1", privilege_tier="critical")])
        c = _find(changes, change_type="added")
        assert classify_sentry_change(c)[0] == "high"

    def test_removed_is_low(self):
        changes = _diff([_privileged_member("m1", privilege_tier="critical")], [])
        c = _find(changes, change_type="removed")
        assert classify_sentry_change(c)[0] == "low"

    def test_provider_metadata_carries_context(self):
        changes = _diff([], [_privileged_member("m1", privilege_tier="high")])
        c = _find(changes, change_type="added")
        assert c["provider_metadata"]["member_id"] == "m1"
        assert c["provider_metadata"]["privilege_tier"] == "high"

    def test_never_includes_email_in_provider_metadata(self):
        changes = _diff([], [_privileged_member("m1")])
        c = _find(changes, change_type="added")
        assert "email" not in str(c["provider_metadata"]).lower()


# ════════════════════════════════════════════════════════════════════════════
# Privileged team
# ════════════════════════════════════════════════════════════════════════════


class TestPrivilegedTeamDiff:
    def test_added_is_low(self):
        changes = _diff([], [_privileged_team("t1")])
        c = _find(changes, change_type="added")
        assert classify_sentry_change(c)[0] == "low"

    def test_gains_admin_member_is_medium(self):
        changes = _diff(
            [_privileged_team("t1", privileged_member_count=0)],
            [_privileged_team("t1", privileged_member_count=1)],
        )
        c = _find(changes, field_path="privileged_member_count")
        assert classify_sentry_change(c)[0] == "medium"

    def test_unresolved_member_count_increase_is_medium(self):
        changes = _diff(
            [_privileged_team("t1", unresolved_member_count=0)],
            [_privileged_team("t1", unresolved_member_count=1)],
        )
        c = _find(changes, field_path="unresolved_member_count")
        assert classify_sentry_change(c)[0] == "medium"


# ════════════════════════════════════════════════════════════════════════════
# Routing context
# ════════════════════════════════════════════════════════════════════════════


class TestRoutingContextDiff:
    def test_resolved_to_missing_enabled_rule_is_high(self):
        changes = _diff(
            [_routing_context("x", target_resolved=True, context_enabled=True)],
            [_routing_context("x", target_resolved=False, context_enabled=True)],
        )
        c = _find(changes, field_path="target_resolved")
        assert classify_sentry_change(c)[0] == "high"

    def test_resolved_to_missing_disabled_rule_is_medium(self):
        changes = _diff(
            [_routing_context("x", target_resolved=True, context_enabled=False)],
            [_routing_context("x", target_resolved=False, context_enabled=False)],
        )
        c = _find(changes, field_path="target_resolved")
        assert classify_sentry_change(c)[0] == "medium"

    def test_missing_to_resolved_is_low(self):
        changes = _diff(
            [_routing_context("x", target_resolved=False)],
            [_routing_context("x", target_resolved=True)],
        )
        c = _find(changes, field_path="target_resolved")
        assert classify_sentry_change(c)[0] == "low"

    def test_integration_enabled_to_disabled_while_targeted_is_high(self):
        changes = _diff(
            [_routing_context("x", integration_status_category="active", context_enabled=True)],
            [_routing_context("x", integration_status_category="disabled", context_enabled=True)],
        )
        c = _find(changes, field_path="integration_status_category")
        assert classify_sentry_change(c)[0] == "high"

    def test_integration_disabled_on_inactive_rule_is_medium(self):
        changes = _diff(
            [_routing_context("x", integration_status_category="active", context_enabled=False)],
            [_routing_context("x", integration_status_category="disabled", context_enabled=False)],
        )
        c = _find(changes, field_path="integration_status_category")
        assert classify_sentry_change(c)[0] == "medium"

    def test_target_restored_active_is_low(self):
        changes = _diff(
            [_routing_context("x", target_active=False)],
            [_routing_context("x", target_active=True)],
        )
        c = _find(changes, field_path="target_active")
        assert classify_sentry_change(c)[0] == "low"

    def test_target_changed_is_medium(self):
        changes = _diff(
            [_routing_context("x", target_id="m1")],
            [_routing_context("x", target_id="m2")],
        )
        c = _find(changes, field_path="target_id")
        assert classify_sentry_change(c)[0] == "medium"

    def test_provider_metadata_carries_context(self):
        changes = _diff([], [_routing_context("x")])
        c = _find(changes, change_type="added")
        assert c["provider_metadata"]["context_type"] == "alert_action"
        assert c["provider_metadata"]["target_resolved"] is True

    def test_reordered_input_produces_no_diff(self):
        a = _routing_context("a")
        b = _routing_context("b")
        assert _diff([a, b], [b, a]) == []
