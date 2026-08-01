"""Sentry effective-access derivation normalization tests (Sentry
message 5 of 8).

Covers the pure ``SentryConnector._derive_effective_access`` helper and
the ``sentry_schema`` privilege-tier/control-context taxonomies directly
(no HTTP mocking — these are pure-function unit tests over hand-built
message-1-4 record lists): tier calculation, org-wide-access mapping,
emission criteria (ordinary members/teams excluded), routing-target
resolution, deterministic ordering, and the sensitive-data boundary.
Collection-level (fetch()) behavior is covered in
``test_sentry_privileged_collection.py``; diff/risk behavior in
``test_sentry_privileged_diff.py``.
"""

from __future__ import annotations

from app.connectors.sentry import SentryConnector
from app.connectors.sentry_schema import (
    CONTROL_CONTEXT_ADD_ONLY,
    CONTROL_CONTEXT_FULL,
    CONTROL_CONTEXT_NONE,
    CONTROL_CONTEXT_UNKNOWN,
    FAMILY_COMPLETE,
    FAMILY_PARTIAL,
    PRIVILEGE_TIER_CRITICAL,
    PRIVILEGE_TIER_HIGH,
    PRIVILEGE_TIER_LOW,
    PRIVILEGE_TIER_MEDIUM,
    PRIVILEGE_TIER_UNKNOWN,
    categorize_integration_control,
    categorize_repository_control,
    highest_privilege_tier,
    organization_wide_access_for_org_role,
    privilege_tier_for_org_role,
)

_ORG = "id:999"


def _project(pid, slug=None):
    return {"project_id": pid, "slug": slug or f"proj-{pid}", "record_type": "sentry_project"}


def _team(tid, slug=None):
    return {"team_id": tid, "slug": slug or f"team-{tid}", "record_type": "sentry_team"}


def _member(mid, org_role="member", status="active"):
    return {"member_id": mid, "org_role_category": org_role, "member_status_category": status, "record_type": "sentry_member"}


def _membership(tid, mid, role="contributor"):
    return {"team_id": tid, "member_id": mid, "team_role_category": role, "record_type": "sentry_team_membership"}


def _assignment(pid, tid):
    return {"project_id": pid, "team_id": tid, "record_type": "sentry_project_team_assignment"}


def _ownership_rule(pid, rule_index, owner_index, owner_type, owner_id, *, record_id=None, is_active=True):
    return {
        "record_id": record_id or f"{_ORG}/ownership_rule/{pid}/{rule_index}/{owner_index}",
        "project_id": pid, "owner_type_category": owner_type, "owner_id": owner_id, "is_active": is_active,
        "record_type": "sentry_ownership_rule",
    }


def _alert_action(action_id, target_type, target_id, *, rule_type="metric", rule_id="r1", integration_id=None, record_id=None):
    return {
        "record_id": record_id or f"{_ORG}/alert_action/{rule_type}/x/{action_id}",
        "rule_type": rule_type, "rule_id": rule_id, "target_type_category": target_type,
        "target_id": target_id, "integration_id": integration_id, "record_type": "sentry_alert_action",
    }


def _derive(**overrides):
    kwargs = dict(
        project_records=[], team_records=[], member_records=[], membership_records=[],
        assignment_records=[], metric_rule_records=[], issue_rule_records=[],
        metric_action_records=[], issue_action_records=[], ownership_records=[],
        integration_records=[], member_completeness=FAMILY_COMPLETE, team_completeness=FAMILY_COMPLETE,
        membership_completeness=FAMILY_COMPLETE, assignment_completeness=FAMILY_COMPLETE,
        ownership_completeness=FAMILY_COMPLETE, action_completeness=FAMILY_COMPLETE,
        integration_completeness=FAMILY_COMPLETE,
    )
    kwargs.update(overrides)
    return SentryConnector._derive_effective_access(_ORG, **kwargs)


class TestPrivilegeTierTaxonomy:
    def test_owner_is_critical(self):
        assert privilege_tier_for_org_role("owner") == PRIVILEGE_TIER_CRITICAL

    def test_manager_is_high(self):
        assert privilege_tier_for_org_role("manager") == PRIVILEGE_TIER_HIGH

    def test_admin_is_medium(self):
        assert privilege_tier_for_org_role("admin") == PRIVILEGE_TIER_MEDIUM

    def test_member_and_billing_are_low(self):
        assert privilege_tier_for_org_role("member") == PRIVILEGE_TIER_LOW
        assert privilege_tier_for_org_role("billing") == PRIVILEGE_TIER_LOW

    def test_unknown_is_unknown_never_low(self):
        assert privilege_tier_for_org_role("unknown") == PRIVILEGE_TIER_UNKNOWN
        assert privilege_tier_for_org_role(None) == PRIVILEGE_TIER_UNKNOWN
        assert privilege_tier_for_org_role("totally-new-role") == PRIVILEGE_TIER_UNKNOWN

    def test_highest_privilege_tier_prefers_known_over_unknown(self):
        assert highest_privilege_tier(["unknown", "high"]) == PRIVILEGE_TIER_HIGH
        assert highest_privilege_tier([]) == PRIVILEGE_TIER_UNKNOWN
        assert highest_privilege_tier(["low", "medium", "critical"]) == PRIVILEGE_TIER_CRITICAL


class TestOrganizationWideAccessMapping:
    def test_owner_and_manager_are_org_wide(self):
        assert organization_wide_access_for_org_role("owner") is True
        assert organization_wide_access_for_org_role("manager") is True

    def test_admin_member_billing_are_not_org_wide(self):
        assert organization_wide_access_for_org_role("admin") is False
        assert organization_wide_access_for_org_role("member") is False
        assert organization_wide_access_for_org_role("billing") is False

    def test_unknown_is_none_never_false(self):
        assert organization_wide_access_for_org_role("unknown") is None
        assert organization_wide_access_for_org_role(None) is None


class TestControlContextTaxonomy:
    def test_owner_manager_full_control(self):
        assert categorize_integration_control("owner") == CONTROL_CONTEXT_FULL
        assert categorize_repository_control("manager") == CONTROL_CONTEXT_FULL

    def test_member_add_only_repository(self):
        assert categorize_repository_control("member") == CONTROL_CONTEXT_ADD_ONLY

    def test_billing_has_no_control(self):
        assert categorize_integration_control("billing") == CONTROL_CONTEXT_NONE
        assert categorize_repository_control("billing") == CONTROL_CONTEXT_NONE

    def test_unknown_role_is_unknown_control(self):
        assert categorize_integration_control("unknown") == CONTROL_CONTEXT_UNKNOWN
        assert categorize_integration_control(None) == CONTROL_CONTEXT_UNKNOWN


class TestPrivilegedMemberEmission:
    def test_ordinary_member_excluded(self):
        pms, _, _ = _derive(member_records=[_member("m1", "member")])
        assert pms == []

    def test_billing_only_excluded(self):
        pms, _, _ = _derive(member_records=[_member("m1", "billing")])
        assert pms == []

    def test_owner_included(self):
        pms, _, _ = _derive(member_records=[_member("m1", "owner")])
        assert len(pms) == 1
        assert pms[0]["member_id"] == "m1"

    def test_admin_included(self):
        pms, _, _ = _derive(member_records=[_member("m1", "admin")])
        assert len(pms) == 1

    def test_unknown_role_included(self):
        pms, _, _ = _derive(member_records=[_member("m1", "unknown")])
        assert len(pms) == 1
        assert pms[0]["privilege_tier"] == PRIVILEGE_TIER_UNKNOWN

    def test_ordinary_member_with_alert_target_included(self):
        pms, _, _ = _derive(
            member_records=[_member("m1", "member")],
            metric_action_records=[_alert_action("a1", "user", "m1")],
        )
        assert len(pms) == 1
        assert pms[0]["alert_routing_target_count"] == 1

    def test_ordinary_member_with_ownership_target_included(self):
        pms, _, _ = _derive(
            member_records=[_member("m1", "member")],
            ownership_records=[_ownership_rule("p1", 0, 0, "user", "m1")],
        )
        assert len(pms) == 1
        assert pms[0]["ownership_rule_target_count"] == 1

    def test_deterministic_ordering(self):
        pms, _, _ = _derive(member_records=[_member("m3", "owner"), _member("m1", "owner"), _member("m2", "owner")])
        assert [p["member_id"] for p in pms] == ["m1", "m2", "m3"]


class TestPrivilegedTeamEmission:
    def test_ordinary_team_excluded(self):
        _, pts, _ = _derive(team_records=[_team("t1")])
        assert pts == []

    def test_team_with_project_assignment_included(self):
        _, pts, _ = _derive(team_records=[_team("t1")], assignment_records=[_assignment("p1", "t1")])
        assert len(pts) == 1
        assert pts[0]["project_count"] == 1

    def test_team_with_ownership_target_included(self):
        _, pts, _ = _derive(
            team_records=[_team("t1")],
            ownership_records=[_ownership_rule("p1", 0, 0, "team", "t1")],
        )
        assert len(pts) == 1
        assert pts[0]["ownership_rule_target_count"] == 1

    def test_unresolved_member_count(self):
        _, pts, _ = _derive(
            team_records=[_team("t1")],
            membership_records=[_membership("t1", "ghost-member")],
        )
        assert len(pts) == 1
        assert pts[0]["unresolved_member_count"] == 1


class TestRoutingContextResolution:
    def test_ownership_team_target_resolved(self):
        _, _, routing = _derive(
            team_records=[_team("t1")],
            ownership_records=[_ownership_rule("p1", 0, 0, "team", "t1")],
        )
        assert len(routing) == 1
        assert routing[0]["target_resolved"] is True
        assert routing[0]["target_active"] is True

    def test_ownership_unresolved_member_target(self):
        _, _, routing = _derive(
            member_records=[],
            ownership_records=[_ownership_rule("p1", 0, 0, "user", "ghost")],
        )
        assert len(routing) == 1
        assert routing[0]["target_resolved"] is False
        assert routing[0]["target_active"] is None
        # source family (members) was COMPLETE -> a confirmed orphan
        assert routing[0]["completeness"] == FAMILY_COMPLETE

    def test_unresolved_target_with_incomplete_source_is_uncertain(self):
        _, _, routing = _derive(
            member_records=[], member_completeness=FAMILY_PARTIAL,
            ownership_records=[_ownership_rule("p1", 0, 0, "user", "ghost")],
        )
        assert routing[0]["target_resolved"] is False
        assert routing[0]["completeness"] == FAMILY_PARTIAL

    def test_alert_action_user_target_resolved_active(self):
        _, _, routing = _derive(
            member_records=[_member("m1", "member")],
            metric_action_records=[_alert_action("a1", "user", "m1")],
        )
        assert len(routing) == 1
        assert routing[0]["target_resolved"] is True
        assert routing[0]["target_active"] is True

    def test_alert_action_specific_target_never_resolved(self):
        _, _, routing = _derive(metric_action_records=[_alert_action("a1", "specific", None)])
        assert routing[0]["target_resolved"] is False
        assert routing[0]["target_id"] is None

    def test_alert_action_integration_status_resolved(self):
        integration = {"integration_id": "i1", "status_category": "disabled", "record_type": "sentry_organization_integration"}
        _, _, routing = _derive(
            integration_records=[integration],
            metric_action_records=[_alert_action("a1", "team", None, integration_id="i1")],
        )
        assert routing[0]["integration_status_category"] == "disabled"

    def test_alert_action_context_enabled_from_owning_rule(self):
        rule = {"rule_id": "r1", "status_category": "enabled", "record_type": "sentry_metric_alert_rule"}
        _, _, routing = _derive(
            metric_rule_records=[rule],
            metric_action_records=[_alert_action("a1", "team", "t1", rule_id="r1")],
        )
        assert routing[0]["context_enabled"] is True

    def test_deterministic_ordering(self):
        _, _, routing = _derive(
            ownership_records=[
                _ownership_rule("p1", 1, 0, "team", "t1", record_id=f"{_ORG}/ownership_rule/p1/1/0"),
                _ownership_rule("p1", 0, 0, "team", "t1", record_id=f"{_ORG}/ownership_rule/p1/0/0"),
            ],
        )
        assert [r["record_id"] for r in routing] == sorted(r["record_id"] for r in routing)


class TestSensitiveDataExclusion:
    def test_privileged_member_never_includes_email_or_display_name(self):
        pms, _, _ = _derive(member_records=[_member("m1", "owner")])
        blob = str(pms)
        assert "email" not in blob.lower()
        assert "@" not in blob

    def test_no_new_field_leaks_raw_ownership_text_or_secrets(self):
        pms, pts, routing = _derive(
            member_records=[_member("m1", "owner")],
            team_records=[_team("t1")],
            ownership_records=[_ownership_rule("p1", 0, 0, "team", "t1")],
        )
        blob = str(pms) + str(pts) + str(routing)
        for forbidden in ("auth_token", "Authorization", "webhook", "dsn", "secret"):
            assert forbidden not in blob
