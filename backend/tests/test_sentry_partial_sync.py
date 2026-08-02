"""Sentry partial-sync / false-removal prevention tests (Sentry message 7
of 8).

Uses the REAL ``compute_diff()`` (never a hand-rolled removal-detection
stand-in) to verify:

* a denied/unavailable organization-wide family never produces fabricated
  "removed" Changes for the records that would have belonged to it;
* an unrelated COMPLETE family still reports real removals normally;
* per-team completeness (team-membership walk) scopes suppression to just
  the failed team, never every team;
* per-project completeness (issue-alert walk, ownership-rule walk) scopes
  suppression to just the failed project, never every project;
* alert-action detail completeness is preserved even when the owning rule
  collected fine;
* derived records (privileged member/team, routing context) are suppressed
  using the correct underlying upstream family keys;
* first-sync / recovery-after-partial-sync semantics.
"""

from __future__ import annotations

from types import SimpleNamespace as NS

from app.services.diff_service import compute_diff

_ORG = "id:999"

_ALL_COMPLETE = {k: "complete" for k in (
    "members", "teams", "team_memberships", "projects", "project_team_assignments",
    "metric_alert_rules", "issue_alert_rules", "alert_actions",
    "organization_integrations", "repositories", "code_mappings", "ownership_rules",
)}


def _snap(records: list[dict]) -> NS:
    return NS(state=records)


def _diff(prev: list[dict], new: list[dict]) -> list[dict]:
    return compute_diff(_snap(prev), _snap(new))


def _org(**family_overrides) -> dict:
    fc = dict(_ALL_COMPLETE)
    fc.update(family_overrides)
    return {
        "record_type": "sentry_organization", "record_id": _ORG, "organization_id": _ORG,
        "slug": "acme", "name": "Acme", "status_category": "active", "family_completeness": fc,
    }


def _member(mid: str) -> dict:
    return {
        "record_type": "sentry_member", "record_id": f"{_ORG}/member/{mid}", "organization_id": _ORG,
        "member_id": mid, "org_role_category": "member", "member_status_category": "active",
    }


def _team(tid: str, *, membership_status: str = "complete") -> dict:
    return {
        "record_type": "sentry_team", "record_id": f"{_ORG}/team/{tid}", "organization_id": _ORG,
        "team_id": tid, "slug": f"team-{tid}", "name": f"Team {tid}",
        "membership_collection_status": membership_status,
    }


def _project(pid: str, *, issue_alert_status: str = "complete", ownership_status: str = "complete") -> dict:
    return {
        "record_type": "sentry_project", "record_id": f"{_ORG}/project/{pid}", "organization_id": _ORG,
        "project_id": pid, "slug": f"proj-{pid}", "name": f"Project {pid}",
        "platform_category": "python", "status_category": "active",
        "issue_alert_collection_status": issue_alert_status,
        "ownership_collection_status": ownership_status,
    }


def _team_membership(tid: str, mid: str) -> dict:
    return {
        "record_type": "sentry_team_membership", "record_id": f"{_ORG}/team_membership/{tid}/{mid}",
        "organization_id": _ORG, "team_id": tid, "member_id": mid, "team_role_category": "contributor",
    }


def _issue_rule(rid: str, pid: str) -> dict:
    return {
        "record_type": "sentry_issue_alert_rule", "record_id": f"{_ORG}/issue_alert_rule/{rid}",
        "organization_id": _ORG, "project_id": pid, "rule_id": rid, "name": "IR",
        "status_category": "enabled", "environment_category": "all", "action_match_category": "any",
        "filter_match_category": "all", "frequency_minutes": 30, "condition_count": 1, "filter_count": 0,
        "action_count": 1, "owner_type_category": "unknown", "owner_id": None, "date_created": None,
    }


def _ownership_rule(pid: str, idx: int) -> dict:
    return {
        "record_type": "sentry_ownership_rule", "record_id": f"{_ORG}/ownership_rule/{pid}/{idx}/0",
        "organization_id": _ORG, "project_id": pid, "rule_index": idx, "owner_index": 0,
        "matcher_category": "path", "owner_type_category": "team", "owner_id": "t1",
        "is_active": True, "fallthrough": True, "auto_assignment_category": "off",
    }


def _privileged_member(mid: str) -> dict:
    return {
        "record_type": "sentry_privileged_member", "record_id": f"{_ORG}/privileged_member/{mid}",
        "organization_id": _ORG, "member_id": mid, "org_role_category": "owner",
        "member_status_category": "active", "privilege_tier": "critical",
        "organization_wide_project_access": True, "direct_team_count": 0, "team_admin_team_count": 0,
        "effective_project_count": 1, "project_access_source_categories": ["organization_wide"],
        "alert_routing_target_count": 0, "ownership_rule_target_count": 0,
        "integration_control_context": "full", "repository_control_context": "full",
        "privilege_completeness": "complete",
    }


def _privileged_team(tid: str) -> dict:
    return {
        "record_type": "sentry_privileged_team", "record_id": f"{_ORG}/privileged_team/{tid}",
        "organization_id": _ORG, "team_id": tid, "project_count": 1, "ownership_rule_target_count": 0,
        "alert_action_target_count": 0, "privileged_member_count": 0, "unresolved_member_count": 0,
        "access_completeness": "complete",
    }


def _routing_context(key: str) -> dict:
    return {
        "record_type": "sentry_routing_context", "record_id": f"{_ORG}/routing_context/alert_action/{key}",
        "organization_id": _ORG, "context_type": "alert_action",
        "source_record_id": f"{_ORG}/alert_action/metric/{key}", "project_id": None,
        "rule_type": "metric", "rule_id": "r1", "target_type_category": "user", "target_id": "m1",
        "target_resolved": True, "target_active": True, "target_privilege_tier": "low",
        "integration_status_category": None, "context_enabled": True, "completeness": "complete",
    }


def _removed_ids(changes: list[dict]) -> set[str]:
    return {c["provider_metadata"].get("member_id") or c["record_identifier"] for c in changes if c["change_type"] == "removed"}


class TestOrganizationWideFalseRemoval:
    def test_members_denied_suppresses_member_removals(self):
        prev = [_org(), _member("m1"), _member("m2")]
        new = [_org(members="denied")]
        changes = _diff(prev, new)
        removed_members = [c for c in changes if c["change_type"] == "removed" and c["prev_value"].get("record_type") == "sentry_member"]
        assert removed_members == []

    def test_members_denied_projects_complete_still_diffs_projects(self):
        prev = [_org(), _member("m1"), _project("p1")]
        new = [_org(members="denied"), _project("p2")]
        changes = _diff(prev, new)
        removed_projects = [c for c in changes if c["change_type"] == "removed" and c["prev_value"].get("record_type") == "sentry_project"]
        added_projects = [c for c in changes if c["change_type"] == "added" and c["new_value"].get("record_type") == "sentry_project"]
        assert len(removed_projects) == 1
        assert len(added_projects) == 1

    def test_members_complete_real_removal_still_reported(self):
        prev = [_org(), _member("m1"), _member("m2")]
        new = [_org()]
        changes = _diff(prev, new)
        removed_members = [c for c in changes if c["change_type"] == "removed" and c["prev_value"].get("record_type") == "sentry_member"]
        assert len(removed_members) == 2

    def test_teams_denied_suppresses_team_and_assignment_removals(self):
        prev = [_org(), _team("t1"), {"record_type": "sentry_project_team_assignment", "record_id": f"{_ORG}/assignment/t1/p1", "organization_id": _ORG, "team_id": "t1", "project_id": "p1"}]
        new = [_org(teams="denied", project_team_assignments="denied")]
        changes = _diff(prev, new)
        removed = [c for c in changes if c["change_type"] == "removed"]
        assert removed == []

    def test_integrations_denied_suppresses_integration_removals(self):
        prev = [_org(), {"record_type": "sentry_organization_integration", "record_id": f"{_ORG}/organization_integration/i1", "organization_id": _ORG, "integration_id": "i1", "name": "Slack", "provider_category": "slack", "status_category": "active", "external_id": None, "feature_categories": None, "out_of_date": None}]
        new = [_org(organization_integrations="denied")]
        changes = _diff(prev, new)
        removed = [c for c in changes if c["change_type"] == "removed"]
        assert removed == []

    def test_no_organization_record_in_new_falls_back_unsuppressed(self):
        prev = [_org(), _member("m1")]
        new = []
        changes = _diff(prev, new)
        removed_members = [c for c in changes if c["change_type"] == "removed" and c["prev_value"].get("record_type") == "sentry_member"]
        assert len(removed_members) == 1

    def test_organization_record_itself_never_suppressed(self):
        prev = [_org()]
        new = []
        changes = _diff(prev, new)
        removed_orgs = [c for c in changes if c["change_type"] == "removed" and c["prev_value"].get("record_type") == "sentry_organization"]
        assert len(removed_orgs) == 1


class TestPerTeamCompleteness:
    def test_team_a_and_c_memberships_still_removed_when_team_b_denied(self):
        prev = [
            _org(), _team("a"), _team("b"), _team("c"),
            _team_membership("a", "m1"), _team_membership("b", "m2"), _team_membership("c", "m3"),
        ]
        new = [
            _org(), _team("a", membership_status="complete"),
            _team("b", membership_status="denied"), _team("c", membership_status="complete"),
        ]
        changes = _diff(prev, new)
        removed_memberships = [
            c for c in changes if c["change_type"] == "removed" and c["prev_value"].get("record_type") == "sentry_team_membership"
        ]
        removed_team_ids = {c["prev_value"]["team_id"] for c in removed_memberships}
        assert removed_team_ids == {"a", "c"}


class TestPerProjectIssueAlertCompleteness:
    def test_project_b_denied_suppresses_only_project_b_issue_alerts(self):
        prev = [
            _org(), _project("a"), _project("b"), _project("c"),
            _issue_rule("ir_a", "a"), _issue_rule("ir_b", "b"), _issue_rule("ir_c", "c"),
        ]
        new = [
            _org(), _project("a", issue_alert_status="complete"),
            _project("b", issue_alert_status="denied"), _project("c", issue_alert_status="complete"),
        ]
        changes = _diff(prev, new)
        removed_rules = [
            c for c in changes if c["change_type"] == "removed" and c["prev_value"].get("record_type") == "sentry_issue_alert_rule"
        ]
        removed_project_ids = {c["prev_value"]["project_id"] for c in removed_rules}
        assert removed_project_ids == {"a", "c"}


class TestPerProjectOwnershipCompleteness:
    def test_project_b_denied_suppresses_only_project_b_ownership_rules(self):
        prev = [
            _org(), _project("a"), _project("b"), _project("c"),
            _ownership_rule("a", 0), _ownership_rule("b", 0), _ownership_rule("c", 0),
        ]
        new = [
            _org(), _project("a", ownership_status="complete"),
            _project("b", ownership_status="denied"), _project("c", ownership_status="complete"),
        ]
        changes = _diff(prev, new)
        removed_rules = [
            c for c in changes if c["change_type"] == "removed" and c["prev_value"].get("record_type") == "sentry_ownership_rule"
        ]
        removed_project_ids = {c["prev_value"]["project_id"] for c in removed_rules}
        assert removed_project_ids == {"a", "c"}


class TestAlertActionCompleteness:
    def test_alert_actions_denied_suppresses_action_removals(self):
        prev = [
            _org(),
            {"record_type": "sentry_alert_action", "record_id": f"{_ORG}/alert_action/metric/tr1/a1", "organization_id": _ORG, "rule_type": "metric", "rule_id": "r1", "trigger_id": "tr1", "action_category": "email", "target_type_category": "user", "target_id": "m1", "integration_id": None},
        ]
        new = [_org(alert_actions="denied")]
        changes = _diff(prev, new)
        removed = [c for c in changes if c["change_type"] == "removed"]
        assert removed == []


class TestDerivedRecordFalseRemovals:
    def test_member_family_denied_suppresses_privileged_member_removal(self):
        prev = [_org(), _privileged_member("m1")]
        new = [_org(members="denied")]
        changes = _diff(prev, new)
        removed = [c for c in changes if c["change_type"] == "removed" and c["prev_value"].get("record_type") == "sentry_privileged_member"]
        assert removed == []

    def test_team_membership_denied_suppresses_privileged_team_removal(self):
        prev = [_org(), _privileged_team("t1")]
        new = [_org(team_memberships="denied")]
        changes = _diff(prev, new)
        removed = [c for c in changes if c["change_type"] == "removed" and c["prev_value"].get("record_type") == "sentry_privileged_team"]
        assert removed == []

    def test_integration_family_denied_suppresses_routing_context_removal(self):
        prev = [_org(), _routing_context("x")]
        new = [_org(organization_integrations="denied")]
        changes = _diff(prev, new)
        removed = [c for c in changes if c["change_type"] == "removed" and c["prev_value"].get("record_type") == "sentry_routing_context"]
        assert removed == []

    def test_all_families_complete_derived_removal_is_real(self):
        prev = [_org(), _privileged_member("m1"), _privileged_team("t1"), _routing_context("x")]
        new = [_org()]
        changes = _diff(prev, new)
        removed_types = {c["prev_value"].get("record_type") for c in changes if c["change_type"] == "removed"}
        assert removed_types == {"sentry_privileged_member", "sentry_privileged_team", "sentry_routing_context"}


class TestRecoveryAfterPartialSync:
    def test_sync1_complete_sync2_partial_sync3_partial_sync4_complete(self):
        sync1 = [_org(), _member("m1"), _member("m2")]
        sync2 = [_org(members="denied")]  # partial — m1/m2 suppressed
        sync3 = [_org(members="denied")]  # still partial — no new info
        sync4 = [_org(), _member("m1")]   # complete again — m2 genuinely gone

        changes_1_2 = _diff(sync1, sync2)
        assert [c for c in changes_1_2 if c["change_type"] == "removed"] == []

        changes_2_3 = _diff(sync2, sync3)
        assert changes_2_3 == []

        changes_3_4 = _diff(sync3, sync4)
        # sync3 had zero member records (suppressed absence), sync4 has m1
        # only -> m1 appears as "added" relative to sync3's snapshot state
        # (this is the documented re-baselining behavior: comparisons are
        # always against the literal previous snapshot's stored state, not
        # a synthesized "last known complete" state).
        added_members = [c for c in changes_3_4 if c["change_type"] == "added" and c["new_value"].get("record_type") == "sentry_member"]
        assert len(added_members) == 1


class TestFirstSyncBehavior:
    def test_first_sync_owner_produces_added_change_not_modified(self):
        changes = _diff([], [_org(), _privileged_member("m1")])
        assert all(c["change_type"] == "added" for c in changes)

    def test_first_sync_unrouted_alert_is_added(self):
        rule = {
            "record_type": "sentry_metric_alert_rule", "record_id": f"{_ORG}/metric_alert_rule/r1",
            "organization_id": _ORG, "project_id": "p1", "rule_id": "r1", "name": "R",
            "status_category": "enabled", "dataset_category": "transactions", "aggregate_category": "percentile",
            "has_query": True, "time_window_minutes": 10, "environment_category": "all",
            "threshold_type_category": "above", "resolve_threshold": None, "detection_type_category": "static",
            "comparison_delta_minutes": None, "owner_type_category": "unknown", "owner_id": None,
            "trigger_count": 0, "action_count": 0, "date_created": None,
        }
        changes = _diff([], [_org(), rule])
        c = [c for c in changes if c["new_value"] and c["new_value"].get("record_type") == "sentry_metric_alert_rule"][0]
        assert c["change_type"] == "added"

    def test_first_sync_disabled_integration_referenced_is_added(self):
        changes = _diff([], [_org(), _routing_context("x")])
        c = [c for c in changes if c["new_value"] and c["new_value"].get("record_type") == "sentry_routing_context"][0]
        assert c["change_type"] == "added"
