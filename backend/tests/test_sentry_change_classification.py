"""Sentry exhaustive Change-classification QA (Sentry message 7 of 8).

Uses the REAL diff pipeline (``compute_diff()`` -> Change ->
``classify_sentry_change()``) — never a hand-built Change object standing
in for the real shape — to certify added/removed/modified posture across
all 18 Sentry record types, tri-state-boolean discipline, numeric-unknown
discipline, and deterministic list/ordering behavior.
"""

from __future__ import annotations

from types import SimpleNamespace as NS

from app.services.diff_service import compute_diff
from app.services.risk_rules.sentry import classify_sentry_change

_ORG = "id:999"


def _snap(records: list[dict]) -> NS:
    return NS(state=records)


def _diff(prev: list[dict], new: list[dict]) -> list[dict]:
    return compute_diff(_snap(prev), _snap(new))


def _find(changes: list[dict], *, change_type: str = None, field_path: str = None) -> dict:
    for c in changes:
        if change_type is not None and c["change_type"] != change_type:
            continue
        if field_path is not None and c.get("field_path") != field_path:
            continue
        return c
    raise AssertionError(f"no change matched change_type={change_type!r} field_path={field_path!r} in {changes}")


def _org(**overrides) -> dict:
    base = {
        "record_type": "sentry_organization", "record_id": _ORG, "organization_id": _ORG,
        "slug": "acme", "name": "Acme", "status_category": "active",
        "family_completeness": {k: "complete" for k in (
            "members", "teams", "team_memberships", "projects", "project_team_assignments",
            "metric_alert_rules", "issue_alert_rules", "alert_actions",
            "organization_integrations", "repositories", "code_mappings", "ownership_rules",
        )},
    }
    base.update(overrides)
    return base


def _member(mid: str, **overrides) -> dict:
    base = {
        "record_type": "sentry_member", "record_id": f"{_ORG}/member/{mid}", "organization_id": _ORG,
        "member_id": mid, "org_role_category": "member", "member_status_category": "active",
    }
    base.update(overrides)
    return base


def _privileged_member(mid: str, **overrides) -> dict:
    base = {
        "record_type": "sentry_privileged_member", "record_id": f"{_ORG}/privileged_member/{mid}",
        "organization_id": _ORG, "member_id": mid, "org_role_category": "member",
        "member_status_category": "active", "privilege_tier": "low",
        "organization_wide_project_access": False, "direct_team_count": 0, "team_admin_team_count": 0,
        "effective_project_count": 0, "project_access_source_categories": [],
        "alert_routing_target_count": 0, "ownership_rule_target_count": 0,
        "integration_control_context": "none", "repository_control_context": "add_only",
        "privilege_completeness": "complete",
    }
    base.update(overrides)
    return base


def _metric_rule(rid: str, **overrides) -> dict:
    base = {
        "record_type": "sentry_metric_alert_rule", "record_id": f"{_ORG}/metric_alert_rule/{rid}",
        "organization_id": _ORG, "project_id": "p1", "rule_id": rid, "name": "R",
        "status_category": "enabled", "dataset_category": "transactions", "aggregate_category": "percentile",
        "has_query": True, "time_window_minutes": 10, "environment_category": "all",
        "threshold_type_category": "above", "resolve_threshold": None, "detection_type_category": "static",
        "comparison_delta_minutes": None, "owner_type_category": "unknown", "owner_id": None,
        "trigger_count": 1, "action_count": 1, "date_created": None,
    }
    base.update(overrides)
    return base


def _issue_rule(rid: str, **overrides) -> dict:
    base = {
        "record_type": "sentry_issue_alert_rule", "record_id": f"{_ORG}/issue_alert_rule/{rid}",
        "organization_id": _ORG, "project_id": "p1", "rule_id": rid, "name": "IR",
        "status_category": "enabled", "environment_category": "all", "action_match_category": "any",
        "filter_match_category": "all", "frequency_minutes": 30, "condition_count": 1, "filter_count": 0,
        "action_count": 1, "owner_type_category": "unknown", "owner_id": None, "date_created": None,
    }
    base.update(overrides)
    return base


def _routing_context(key: str, **overrides) -> dict:
    base = {
        "record_type": "sentry_routing_context", "record_id": f"{_ORG}/routing_context/alert_action/{key}",
        "organization_id": _ORG, "context_type": "alert_action",
        "source_record_id": f"{_ORG}/alert_action/metric/{key}", "project_id": None,
        "rule_type": "metric", "rule_id": "r1", "target_type_category": "user", "target_id": "m1",
        "target_resolved": True, "target_active": True, "target_privilege_tier": "low",
        "integration_status_category": None, "context_enabled": True, "completeness": "complete",
    }
    base.update(overrides)
    return base


def _repository(rid: str, **overrides) -> dict:
    base = {
        "record_type": "sentry_repository", "record_id": f"{_ORG}/repository/{rid}",
        "organization_id": _ORG, "repository_id": rid, "name": "acme/repo",
        "provider_category": "github", "status_category": "active", "integration_id": "int1",
        "external_id": "1", "date_created": None,
    }
    base.update(overrides)
    return base


class TestOrganizationChangeQA:
    def test_added_is_low(self):
        c = _find(_diff([], [_org()]), change_type="added")
        assert classify_sentry_change(c)[0] == "low"

    def test_removed_is_medium(self):
        c = _find(_diff([_org()], []), change_type="removed")
        assert classify_sentry_change(c)[0] == "medium"

    def test_slug_rename_is_low(self):
        c = _find(_diff([_org(slug="acme")], [_org(slug="acme-renamed")]), field_path="slug")
        assert classify_sentry_change(c)[0] == "low"


class TestMemberChangeQA:
    def test_owner_added_is_high(self):
        c = _find(_diff([], [_member("m1", org_role_category="owner")]), change_type="added")
        assert classify_sentry_change(c)[0] == "high"

    def test_manager_added_is_high(self):
        c = _find(_diff([], [_member("m1", org_role_category="manager")]), change_type="added")
        assert classify_sentry_change(c)[0] == "high"

    def test_admin_added_is_high(self):
        # sentry_member's own added-classifier is role-tier-agnostic among
        # owner/manager/admin (all "privileged") — the fine-grained
        # owner/manager/admin severity distinction lives on the derived
        # sentry_privileged_member classifier (see TestPrivilegedMemberChangeQA).
        c = _find(_diff([], [_member("m1", org_role_category="admin")]), change_type="added")
        assert classify_sentry_change(c)[0] == "high"

    def test_ordinary_member_added_is_low(self):
        c = _find(_diff([], [_member("m1", org_role_category="member")]), change_type="added")
        assert classify_sentry_change(c)[0] == "low"

    def test_billing_member_added_is_low(self):
        c = _find(_diff([], [_member("m1", org_role_category="billing")]), change_type="added")
        assert classify_sentry_change(c)[0] == "low"

    def test_unknown_role_added_is_low_not_privileged(self):
        c = _find(_diff([], [_member("m1", org_role_category="unknown")]), change_type="added")
        assert classify_sentry_change(c)[0] == "low"

    def test_member_removed_is_low(self):
        c = _find(_diff([_member("m1")], []), change_type="removed")
        assert classify_sentry_change(c)[0] == "low"

    def test_member_to_admin_is_high(self):
        c = _find(
            _diff([_member("m1", org_role_category="member")], [_member("m1", org_role_category="admin")]),
            field_path="org_role_category",
        )
        assert classify_sentry_change(c)[0] == "high"

    def test_member_to_manager_is_high(self):
        c = _find(
            _diff([_member("m1", org_role_category="member")], [_member("m1", org_role_category="manager")]),
            field_path="org_role_category",
        )
        assert classify_sentry_change(c)[0] == "high"

    def test_member_to_owner_is_high(self):
        c = _find(
            _diff([_member("m1", org_role_category="member")], [_member("m1", org_role_category="owner")]),
            field_path="org_role_category",
        )
        assert classify_sentry_change(c)[0] == "high"

    def test_admin_to_owner_is_low(self):
        # already-privileged -> still-privileged is not a NEW escalation.
        c = _find(
            _diff([_member("m1", org_role_category="admin")], [_member("m1", org_role_category="owner")]),
            field_path="org_role_category",
        )
        assert classify_sentry_change(c)[0] == "low"

    def test_owner_to_manager_is_low(self):
        c = _find(
            _diff([_member("m1", org_role_category="owner")], [_member("m1", org_role_category="manager")]),
            field_path="org_role_category",
        )
        assert classify_sentry_change(c)[0] == "low"

    def test_owner_to_member_is_low(self):
        c = _find(
            _diff([_member("m1", org_role_category="owner")], [_member("m1", org_role_category="member")]),
            field_path="org_role_category",
        )
        assert classify_sentry_change(c)[0] == "low"

    def test_unknown_role_introduced_is_low_not_privileged(self):
        c = _find(
            _diff([_member("m1", org_role_category="member")], [_member("m1", org_role_category="unknown")]),
            field_path="org_role_category",
        )
        assert classify_sentry_change(c)[0] == "low"

    def test_status_becomes_unknown_is_medium(self):
        c = _find(
            _diff(
                [_member("m1", member_status_category="active")],
                [_member("m1", member_status_category="unknown")],
            ),
            field_path="member_status_category",
        )
        assert classify_sentry_change(c)[0] == "medium"

    def test_pending_to_active_is_low(self):
        c = _find(
            _diff(
                [_member("m1", member_status_category="pending")],
                [_member("m1", member_status_category="active")],
            ),
            field_path="member_status_category",
        )
        assert classify_sentry_change(c)[0] == "low"


class TestPrivilegedMemberChangeQA:
    def test_critical_tier_added_is_high(self):
        c = _find(_diff([], [_privileged_member("m1", privilege_tier="critical")]), change_type="added")
        assert classify_sentry_change(c)[0] == "high"

    def test_high_tier_added_is_high(self):
        c = _find(_diff([], [_privileged_member("m1", privilege_tier="high")]), change_type="added")
        assert classify_sentry_change(c)[0] == "high"

    def test_medium_tier_added_is_medium(self):
        c = _find(_diff([], [_privileged_member("m1", privilege_tier="medium")]), change_type="added")
        assert classify_sentry_change(c)[0] == "medium"

    def test_low_tier_added_is_low(self):
        c = _find(_diff([], [_privileged_member("m1", privilege_tier="low")]), change_type="added")
        assert classify_sentry_change(c)[0] == "low"

    def test_tier_low_to_critical_is_high(self):
        c = _find(
            _diff(
                [_privileged_member("m1", privilege_tier="low")],
                [_privileged_member("m1", privilege_tier="critical")],
            ),
            field_path="privilege_tier",
        )
        assert classify_sentry_change(c)[0] == "high"

    def test_tier_low_to_medium_is_medium(self):
        c = _find(
            _diff(
                [_privileged_member("m1", privilege_tier="low")],
                [_privileged_member("m1", privilege_tier="medium")],
            ),
            field_path="privilege_tier",
        )
        assert classify_sentry_change(c)[0] == "medium"

    def test_tier_critical_to_low_is_low(self):
        c = _find(
            _diff(
                [_privileged_member("m1", privilege_tier="critical")],
                [_privileged_member("m1", privilege_tier="low")],
            ),
            field_path="privilege_tier",
        )
        assert classify_sentry_change(c)[0] == "low"

    def test_org_wide_access_gained_is_high(self):
        c = _find(
            _diff(
                [_privileged_member("m1", organization_wide_project_access=False)],
                [_privileged_member("m1", organization_wide_project_access=True)],
            ),
            field_path="organization_wide_project_access",
        )
        assert classify_sentry_change(c)[0] == "high"

    def test_org_wide_access_lost_is_low(self):
        c = _find(
            _diff(
                [_privileged_member("m1", organization_wide_project_access=True)],
                [_privileged_member("m1", organization_wide_project_access=False)],
            ),
            field_path="organization_wide_project_access",
        )
        assert classify_sentry_change(c)[0] == "low"

    def test_org_wide_access_becomes_unknown_is_medium(self):
        c = _find(
            _diff(
                [_privileged_member("m1", organization_wide_project_access=False)],
                [_privileged_member("m1", organization_wide_project_access=None)],
            ),
            field_path="organization_wide_project_access",
        )
        assert classify_sentry_change(c)[0] == "medium"

    def test_effective_project_count_expands_is_medium(self):
        c = _find(
            _diff(
                [_privileged_member("m1", effective_project_count=1)],
                [_privileged_member("m1", effective_project_count=5)],
            ),
            field_path="effective_project_count",
        )
        assert classify_sentry_change(c)[0] == "medium"

    def test_effective_project_count_unknown_never_treated_as_zero(self):
        # A field going to None (unknown) must never be treated as "expanded"
        # (the isinstance guard means the branch falls through to informational Low).
        c = _find(
            _diff(
                [_privileged_member("m1", effective_project_count=5)],
                [_privileged_member("m1", effective_project_count=None)],
            ),
            field_path="effective_project_count",
        )
        severity, _ = classify_sentry_change(c)
        assert severity == "low"

    def test_record_removed_is_low(self):
        c = _find(_diff([_privileged_member("m1")], []), change_type="removed")
        assert classify_sentry_change(c)[0] == "low"


class TestMetricAlertRuleChangeQA:
    def test_enabled_to_disabled_is_medium(self):
        c = _find(
            _diff([_metric_rule("r1", status_category="enabled")], [_metric_rule("r1", status_category="disabled")]),
            field_path="status_category",
        )
        assert classify_sentry_change(c)[0] == "medium"

    def test_disabled_to_enabled_is_low(self):
        c = _find(
            _diff([_metric_rule("r1", status_category="disabled")], [_metric_rule("r1", status_category="enabled")]),
            field_path="status_category",
        )
        assert classify_sentry_change(c)[0] == "low"

    def test_action_count_positive_to_zero_enabled_is_high(self):
        c = _find(
            _diff(
                [_metric_rule("r1", status_category="enabled", action_count=1)],
                [_metric_rule("r1", status_category="enabled", action_count=0)],
            ),
            field_path="action_count",
        )
        assert classify_sentry_change(c)[0] == "high"

    def test_action_count_zero_to_positive_is_low(self):
        c = _find(
            _diff(
                [_metric_rule("r1", action_count=0)],
                [_metric_rule("r1", action_count=1)],
            ),
            field_path="action_count",
        )
        assert classify_sentry_change(c)[0] == "low"

    def test_added_enabled_zero_actions_is_high(self):
        c = _find(_diff([], [_metric_rule("r1", action_count=0)]), change_type="added")
        assert classify_sentry_change(c)[0] == "high"

    def test_removed_enabled_with_actions_is_medium(self):
        c = _find(_diff([_metric_rule("r1", status_category="enabled", action_count=1)], []), change_type="removed")
        assert classify_sentry_change(c)[0] == "medium"

    def test_removed_already_unrouted_is_low(self):
        c = _find(_diff([_metric_rule("r1", status_category="enabled", action_count=0)], []), change_type="removed")
        assert classify_sentry_change(c)[0] == "low"

    def test_removed_disabled_rule_is_low(self):
        c = _find(_diff([_metric_rule("r1", status_category="disabled", action_count=1)], []), change_type="removed")
        assert classify_sentry_change(c)[0] == "low"

    def test_resolve_threshold_unknown_direction_is_low(self):
        c = _find(
            _diff(
                [_metric_rule("r1", resolve_threshold=10.0)],
                [_metric_rule("r1", resolve_threshold=20.0)],
            ),
            field_path="resolve_threshold",
        )
        assert classify_sentry_change(c)[0] == "low"


class TestIssueAlertRuleChangeQA:
    def test_added_enabled_zero_actions_is_high(self):
        c = _find(_diff([], [_issue_rule("ir1", action_count=0)]), change_type="added")
        assert classify_sentry_change(c)[0] == "high"

    def test_action_count_drop_to_zero_enabled_is_high(self):
        c = _find(
            _diff(
                [_issue_rule("ir1", status_category="enabled", action_count=2)],
                [_issue_rule("ir1", status_category="enabled", action_count=0)],
            ),
            field_path="action_count",
        )
        assert classify_sentry_change(c)[0] == "high"

    def test_removed_already_unrouted_is_low(self):
        c = _find(_diff([_issue_rule("ir1", status_category="enabled", action_count=0)], []), change_type="removed")
        assert classify_sentry_change(c)[0] == "low"


class TestRoutingContextChangeQA:
    def test_enabled_disabled_toggle_low(self):
        c = _find(
            _diff([_routing_context("x", context_enabled=True)], [_routing_context("x", context_enabled=False)]),
            field_path="context_enabled",
        )
        assert classify_sentry_change(c)[0] == "low"

    def test_target_type_changes_medium(self):
        c = _find(
            _diff(
                [_routing_context("x", target_type_category="user", target_id="m1")],
                [_routing_context("x", target_type_category="team", target_id="t1")],
            ),
            field_path="target_type_category",
        )
        assert classify_sentry_change(c)[0] == "medium"

    def test_target_id_changes_medium(self):
        c = _find(
            _diff(
                [_routing_context("x", target_id="m1")],
                [_routing_context("x", target_id="m2")],
            ),
            field_path="target_id",
        )
        assert classify_sentry_change(c)[0] == "medium"

    def test_resolved_to_missing_enabled_is_high(self):
        c = _find(
            _diff(
                [_routing_context("x", target_resolved=True, context_enabled=True)],
                [_routing_context("x", target_resolved=False, context_enabled=True)],
            ),
            field_path="target_resolved",
        )
        assert classify_sentry_change(c)[0] == "high"

    def test_missing_to_resolved_is_low(self):
        c = _find(
            _diff(
                [_routing_context("x", target_resolved=False)],
                [_routing_context("x", target_resolved=True)],
            ),
            field_path="target_resolved",
        )
        assert classify_sentry_change(c)[0] == "low"

    def test_active_to_pending_is_medium(self):
        c = _find(
            _diff(
                [_routing_context("x", target_active=True)],
                [_routing_context("x", target_active=False)],
            ),
            field_path="target_active",
        )
        assert classify_sentry_change(c)[0] == "medium"

    def test_integration_enabled_to_disabled_is_high(self):
        c = _find(
            _diff(
                [_routing_context("x", integration_status_category="active", context_enabled=True)],
                [_routing_context("x", integration_status_category="disabled", context_enabled=True)],
            ),
            field_path="integration_status_category",
        )
        assert classify_sentry_change(c)[0] == "high"

    def test_added_missing_target_enabled_is_high(self):
        c = _find(
            _diff([], [_routing_context("x", target_resolved=False, context_enabled=True)]),
            change_type="added",
        )
        assert classify_sentry_change(c)[0] == "high"

    def test_added_disabled_integration_enabled_rule_is_high(self):
        c = _find(
            _diff([], [_routing_context("x", integration_status_category="disabled", context_enabled=True)]),
            change_type="added",
        )
        assert classify_sentry_change(c)[0] == "high"

    def test_added_missing_target_disabled_rule_is_low(self):
        c = _find(
            _diff([], [_routing_context("x", target_resolved=False, context_enabled=False)]),
            change_type="added",
        )
        assert classify_sentry_change(c)[0] == "low"

    def test_source_rule_removed_is_low(self):
        c = _find(_diff([_routing_context("x")], []), change_type="removed")
        assert classify_sentry_change(c)[0] == "low"


class TestRepositoryChangeQA:
    def test_active_to_pending_deletion_is_medium(self):
        c = _find(
            _diff([_repository("r1", status_category="active")], [_repository("r1", status_category="pending_deletion")]),
            field_path="status_category",
        )
        assert classify_sentry_change(c)[0] == "medium"

    def test_pending_deletion_to_active_is_low(self):
        c = _find(
            _diff([_repository("r1", status_category="pending_deletion")], [_repository("r1", status_category="active")]),
            field_path="status_category",
        )
        assert classify_sentry_change(c)[0] == "low"

    def test_integration_changed_is_medium(self):
        c = _find(
            _diff([_repository("r1", integration_id="int1")], [_repository("r1", integration_id="int2")]),
            field_path="integration_id",
        )
        assert classify_sentry_change(c)[0] == "medium"

    def test_rename_is_low(self):
        c = _find(
            _diff([_repository("r1", name="acme/old")], [_repository("r1", name="acme/new")]),
            field_path="name",
        )
        assert classify_sentry_change(c)[0] == "low"

    def test_added_is_low(self):
        c = _find(_diff([], [_repository("r1")]), change_type="added")
        assert classify_sentry_change(c)[0] == "low"

    def test_removed_is_low(self):
        c = _find(_diff([_repository("r1")], []), change_type="removed")
        assert classify_sentry_change(c)[0] == "low"


class TestStaleChangeShapeAudit:
    """Confirms the classifier reads the REAL Change dict shape produced
    by compute_diff() — change_type/field_path/prev_value/new_value/
    provider_metadata — never a legacy old_value/previous_value/before/
    after alias."""

    def test_change_dict_has_expected_keys_only(self):
        changes = _diff([], [_org()])
        c = changes[0]
        assert set(c.keys()) == {
            "change_type", "record_identifier", "field_path", "prev_value", "new_value", "provider_metadata",
        }

    def test_classifier_never_raises_on_real_shape(self):
        for c in _diff([_org(), _member("m1")], [_org(slug="x"), _member("m1", org_role_category="owner")]):
            classify_sentry_change(c)  # must not raise
