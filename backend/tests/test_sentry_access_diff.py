"""Sentry project/team/member/access diff/risk-classification tests
(Sentry message 2 of 8).

Uses the REAL ``compute_diff()`` and ``classify_sentry_change()`` — never
hand-built Change objects standing in for the diff pipeline — to verify
project/team/member/team-membership/project-team-assignment Change
classification, provider_metadata context, and privilege-escalation
severity (member -> owner is High; the reverse and routine lifecycle
events are Low).
"""

from __future__ import annotations

from types import SimpleNamespace as NS

from app.services.diff_service import compute_diff
from app.services.risk_rules.sentry import classify_sentry_change

_ORG_ID = "id:999"


def _snap(records: list[dict]) -> NS:
    return NS(state=records)


def _project(pid: str, **overrides) -> dict:
    base = {
        "record_type": "sentry_project",
        "record_id": f"{_ORG_ID}/project/{pid}",
        "provider_resource_id": f"projects/{pid}",
        "organization_id": _ORG_ID,
        "project_id": pid,
        "slug": f"proj-{pid}",
        "name": f"Project {pid}",
        "platform_category": "python",
        "status_category": "active",
        "date_created": "2020-01-01T00:00:00Z",
    }
    base.update(overrides)
    return base


def _team(tid: str, **overrides) -> dict:
    base = {
        "record_type": "sentry_team",
        "record_id": f"{_ORG_ID}/team/{tid}",
        "provider_resource_id": f"teams/{tid}",
        "organization_id": _ORG_ID,
        "team_id": tid,
        "slug": f"team-{tid}",
        "name": f"Team {tid}",
        "member_count": 1,
        "date_created": "2020-01-01T00:00:00Z",
    }
    base.update(overrides)
    return base


def _member(mid: str, **overrides) -> dict:
    base = {
        "record_type": "sentry_member",
        "record_id": f"{_ORG_ID}/member/{mid}",
        "provider_resource_id": f"members/{mid}",
        "organization_id": _ORG_ID,
        "member_id": mid,
        "org_role_category": "member",
        "member_status_category": "active",
        "date_created": "2020-01-01T00:00:00Z",
    }
    base.update(overrides)
    return base


def _team_membership(tid: str, mid: str, **overrides) -> dict:
    base = {
        "record_type": "sentry_team_membership",
        "record_id": f"{_ORG_ID}/team_membership/{tid}/{mid}",
        "provider_resource_id": f"teams/{tid}/members/{mid}",
        "organization_id": _ORG_ID,
        "team_id": tid,
        "member_id": mid,
        "team_role_category": "contributor",
    }
    base.update(overrides)
    return base


def _assignment(pid: str, tid: str) -> dict:
    return {
        "record_type": "sentry_project_team_assignment",
        "record_id": f"{_ORG_ID}/project_team_assignment/{pid}/{tid}",
        "provider_resource_id": f"projects/{pid}/teams/{tid}",
        "organization_id": _ORG_ID,
        "project_id": pid,
        "team_id": tid,
    }


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
# Project
# ════════════════════════════════════════════════════════════════════════════


class TestProjectDiff:
    def test_added_is_low(self):
        changes = _diff([], [_project("p1")])
        c = _find(changes, change_type="added")
        severity, _ = classify_sentry_change(c)
        assert severity == "low"

    def test_removed_is_medium(self):
        changes = _diff([_project("p1")], [])
        c = _find(changes, change_type="removed")
        severity, _ = classify_sentry_change(c)
        assert severity == "medium"

    def test_rename_is_low(self):
        changes = _diff([_project("p1", slug="old-slug")], [_project("p1", slug="new-slug")])
        c = _find(changes, field_path="slug")
        severity, _ = classify_sentry_change(c)
        assert severity == "low"

    def test_status_toward_disabled_is_medium(self):
        changes = _diff(
            [_project("p1", status_category="active")],
            [_project("p1", status_category="disabled")],
        )
        c = _find(changes, field_path="status_category")
        severity, _ = classify_sentry_change(c)
        assert severity == "medium"

    def test_status_toward_active_is_low(self):
        changes = _diff(
            [_project("p1", status_category="disabled")],
            [_project("p1", status_category="active")],
        )
        c = _find(changes, field_path="status_category")
        severity, _ = classify_sentry_change(c)
        assert severity == "low"

    def test_provider_metadata_carries_project_context(self):
        changes = _diff([], [_project("p1", platform_category="javascript")])
        c = _find(changes, change_type="added")
        assert c["provider_metadata"]["project_id"] == "p1"
        assert c["provider_metadata"]["platform_category"] == "javascript"

    def test_member_count_not_tracked(self):
        changes = _diff([_project("p1")], [_project("p1")])
        assert changes == []

    def test_platform_change_is_low(self):
        changes = _diff(
            [_project("p1", platform_category="python")],
            [_project("p1", platform_category="javascript")],
        )
        c = _find(changes, field_path="platform_category")
        severity, _ = classify_sentry_change(c)
        assert severity == "low"


# ════════════════════════════════════════════════════════════════════════════
# Team
# ════════════════════════════════════════════════════════════════════════════


class TestTeamDiff:
    def test_added_is_low(self):
        changes = _diff([], [_team("t1")])
        c = _find(changes, change_type="added")
        severity, _ = classify_sentry_change(c)
        assert severity == "low"

    def test_removed_is_medium(self):
        changes = _diff([_team("t1")], [])
        c = _find(changes, change_type="removed")
        severity, _ = classify_sentry_change(c)
        assert severity == "medium"

    def test_rename_is_low(self):
        changes = _diff([_team("t1", name="Old")], [_team("t1", name="New")])
        c = _find(changes, field_path="name")
        severity, _ = classify_sentry_change(c)
        assert severity == "low"

    def test_member_count_not_tracked(self):
        changes = _diff([_team("t1", member_count=1)], [_team("t1", member_count=99)])
        assert changes == []


# ════════════════════════════════════════════════════════════════════════════
# Member — the privilege-escalation core
# ════════════════════════════════════════════════════════════════════════════


class TestMemberDiff:
    def test_added_ordinary_member_is_low(self):
        changes = _diff([], [_member("m1", org_role_category="member")])
        c = _find(changes, change_type="added")
        severity, _ = classify_sentry_change(c)
        assert severity == "low"

    def test_added_owner_is_high(self):
        changes = _diff([], [_member("m1", org_role_category="owner")])
        c = _find(changes, change_type="added")
        severity, _ = classify_sentry_change(c)
        assert severity == "high"

    def test_added_manager_is_high(self):
        changes = _diff([], [_member("m1", org_role_category="manager")])
        c = _find(changes, change_type="added")
        severity, _ = classify_sentry_change(c)
        assert severity == "high"

    def test_removed_is_low(self):
        changes = _diff([_member("m1", org_role_category="owner")], [])
        c = _find(changes, change_type="removed")
        severity, _ = classify_sentry_change(c)
        assert severity == "low"

    def test_promoted_member_to_owner_is_high(self):
        changes = _diff(
            [_member("m1", org_role_category="member")],
            [_member("m1", org_role_category="owner")],
        )
        c = _find(changes, field_path="org_role_category")
        severity, msg = classify_sentry_change(c)
        assert severity == "high"
        assert "owner" in msg

    def test_demoted_owner_to_member_is_low(self):
        changes = _diff(
            [_member("m1", org_role_category="owner")],
            [_member("m1", org_role_category="member")],
        )
        c = _find(changes, field_path="org_role_category")
        severity, _ = classify_sentry_change(c)
        assert severity == "low"

    def test_lateral_role_change_is_low(self):
        changes = _diff(
            [_member("m1", org_role_category="billing")],
            [_member("m1", org_role_category="member")],
        )
        c = _find(changes, field_path="org_role_category")
        severity, _ = classify_sentry_change(c)
        assert severity == "low"

    def test_status_becomes_unknown_is_medium(self):
        changes = _diff(
            [_member("m1", member_status_category="active")],
            [_member("m1", member_status_category="unknown")],
        )
        c = _find(changes, field_path="member_status_category")
        severity, _ = classify_sentry_change(c)
        assert severity == "medium"

    def test_pending_to_active_is_low(self):
        changes = _diff(
            [_member("m1", member_status_category="pending")],
            [_member("m1", member_status_category="active")],
        )
        c = _find(changes, field_path="member_status_category")
        severity, _ = classify_sentry_change(c)
        assert severity == "low"

    def test_never_includes_email_in_provider_metadata(self):
        changes = _diff([], [_member("m1")])
        c = _find(changes, change_type="added")
        assert "email" not in str(c["provider_metadata"]).lower()


# ════════════════════════════════════════════════════════════════════════════
# Team membership
# ════════════════════════════════════════════════════════════════════════════


class TestTeamMembershipDiff:
    def test_added_is_low(self):
        changes = _diff([], [_team_membership("t1", "m1")])
        c = _find(changes, change_type="added")
        severity, _ = classify_sentry_change(c)
        assert severity == "low"

    def test_removed_is_low(self):
        changes = _diff([_team_membership("t1", "m1")], [])
        c = _find(changes, change_type="removed")
        severity, _ = classify_sentry_change(c)
        assert severity == "low"

    def test_promoted_to_team_admin_is_medium(self):
        changes = _diff(
            [_team_membership("t1", "m1", team_role_category="contributor")],
            [_team_membership("t1", "m1", team_role_category="admin")],
        )
        c = _find(changes, field_path="team_role_category")
        severity, _ = classify_sentry_change(c)
        assert severity == "medium"

    def test_demoted_from_team_admin_is_low(self):
        changes = _diff(
            [_team_membership("t1", "m1", team_role_category="admin")],
            [_team_membership("t1", "m1", team_role_category="contributor")],
        )
        c = _find(changes, field_path="team_role_category")
        severity, _ = classify_sentry_change(c)
        assert severity == "low"


# ════════════════════════════════════════════════════════════════════════════
# Project-team assignment
# ════════════════════════════════════════════════════════════════════════════


class TestProjectTeamAssignmentDiff:
    def test_added_is_low(self):
        changes = _diff([], [_assignment("p1", "t1")])
        c = _find(changes, change_type="added")
        severity, _ = classify_sentry_change(c)
        assert severity == "low"

    def test_removed_is_low(self):
        changes = _diff([_assignment("p1", "t1")], [])
        c = _find(changes, change_type="removed")
        severity, _ = classify_sentry_change(c)
        assert severity == "low"

    def test_no_mutable_fields_no_modified_changes(self):
        changes = _diff([_assignment("p1", "t1")], [_assignment("p1", "t1")])
        assert changes == []

    def test_provider_metadata_preserves_direction(self):
        changes = _diff([], [_assignment("p1", "t1")])
        c = _find(changes, change_type="added")
        assert c["provider_metadata"]["project_id"] == "p1"
        assert c["provider_metadata"]["team_id"] == "t1"
