"""Sentry Finding-vs-Change severity parity certification (Sentry message 7
of 8).

Rule: for every static Finding that has a corresponding direct transition,
the transition's Change severity must be >= the static Finding's severity.
Any exception must have a durable written rationale and a permanent test —
see ``TestOwnerParityDecision`` below.
"""

from __future__ import annotations

from types import SimpleNamespace as NS

from app.services.diff_service import compute_diff
from app.services.risk_rules.sentry import classify_sentry_change
from app.services.security_rule_pack import _RULE_META

_ORG = "id:999"
_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


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


def _finding_severity(rule_key: str) -> str:
    _provider, severity, _category = _RULE_META[rule_key]
    return severity


def _assert_at_least_as_severe(change_severity: str, rule_key: str) -> None:
    finding_severity = _finding_severity(rule_key)
    assert _RANK[change_severity] >= _RANK[finding_severity], (
        f"Change severity {change_severity!r} is weaker than static Finding "
        f"{rule_key!r} severity {finding_severity!r}"
    )


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


class TestOwnerParityDecision:
    """Explicit, permanent certification of the owner Critical/High
    decision (Sentry message 7, section 14).

    DECISION: Option B — the static ``sentry_active_organization_owner``
    Finding remains Critical (reflecting Owner's absolute, standing
    authority as CURRENT STATE — "unrestricted access to the organization,
    its data, and its settings" per docs.sentry.io), while the
    member->owner TRANSITION Change stays High.

    RATIONALE: this asymmetry was fixed in Sentry message 5's own worked
    severity-classification examples (`member->owner=High`) BEFORE message
    6's Finding taxonomy (which set Critical for the standing-state Owner
    Finding) existed — it mirrors the exact same precedent already
    established for every other provider in this codebase (Okta's
    `okta_super_admin_assigned` Finding is Critical while the
    corresponding Change classifier never emits Critical for ANY Okta
    Change; Snowflake's `snowflake_user_accountadmin` Finding is Critical
    while `has_accountadmin` gained Changes classify at High). Raising the
    transition Change itself to Critical would be a message-5 change-
    classifier redesign, not a message-7 concern, and would break message-
    5's own already-shipped, tested severity contract for a field
    (`privilege_tier`) that is also used by MEDIUM and LOW transitions on
    the same classifier function — not a decision to make lightly this
    message. Raising the Finding to some non-Critical value instead would
    misrepresent Owner's documented absolute authority. Option B is
    therefore the correct, durable choice: keep both values as they are,
    and certify the asymmetry explicitly here rather than leave it
    ambiguous.
    """

    def test_member_to_owner_change_is_high(self):
        c = _find(
            _diff(
                [_privileged_member("m1", org_role_category="member", privilege_tier="low")],
                [_privileged_member("m1", org_role_category="owner", privilege_tier="critical")],
            ),
            field_path="privilege_tier",
        )
        severity, _reason = classify_sentry_change(c)
        assert severity == "high"

    def test_active_owner_finding_is_critical(self):
        assert _finding_severity("sentry_active_organization_owner") == "critical"

    def test_asymmetry_is_intentional_not_a_bug(self):
        change_severity = "high"
        finding_severity = _finding_severity("sentry_active_organization_owner")
        assert _RANK[change_severity] < _RANK[finding_severity]
        assert finding_severity == "critical"


class TestFindingVsChangeParity:
    def test_active_owner(self):
        c = _find(_diff([], [_privileged_member("m1", org_role_category="owner", privilege_tier="critical")]), change_type="added")
        # Certified exception — see TestOwnerParityDecision.
        severity, _reason = classify_sentry_change(c)
        assert severity == "high"

    def test_active_manager(self):
        c = _find(_diff([], [_privileged_member("m1", org_role_category="manager", privilege_tier="high")]), change_type="added")
        severity, _ = classify_sentry_change(c)
        _assert_at_least_as_severe(severity, "sentry_active_organization_manager")

    def test_active_admin(self):
        c = _find(_diff([], [_privileged_member("m1", org_role_category="admin", privilege_tier="medium")]), change_type="added")
        severity, _ = classify_sentry_change(c)
        _assert_at_least_as_severe(severity, "sentry_active_organization_admin")

    def test_pending_privileged_invitation_owner(self):
        c = _find(
            _diff([], [_privileged_member("m1", org_role_category="owner", member_status_category="pending", privilege_tier="critical")]),
            change_type="added",
        )
        severity, _ = classify_sentry_change(c)
        _assert_at_least_as_severe(severity, "sentry_pending_privileged_invitation")

    def test_composite_privileged_member_broadened_access(self):
        c = _find(
            _diff(
                [_privileged_member("m1", effective_project_count=1)],
                [_privileged_member("m1", effective_project_count=10)],
            ),
            field_path="effective_project_count",
        )
        severity, _ = classify_sentry_change(c)
        # No direct Change equivalent for the composite routing-authority
        # Finding — broadened access is the closest available signal, and
        # message-6's rule is medium, so medium Change parity suffices.
        assert _RANK[severity] >= _RANK["medium"]

    def test_metric_alert_zero_actions(self):
        c = _find(_diff([], [_metric_rule("r1", action_count=0)]), change_type="added")
        severity, _ = classify_sentry_change(c)
        _assert_at_least_as_severe(severity, "sentry_metric_alert_unrouted")

    def test_issue_alert_zero_actions(self):
        c = _find(_diff([], [_issue_rule("ir1", action_count=0)]), change_type="added")
        severity, _ = classify_sentry_change(c)
        _assert_at_least_as_severe(severity, "sentry_issue_alert_unrouted")

    def test_disabled_alert_retaining_routing(self):
        c = _find(
            _diff([_metric_rule("r1", status_category="enabled", action_count=1)], [_metric_rule("r1", status_category="disabled", action_count=1)]),
            field_path="status_category",
        )
        severity, _ = classify_sentry_change(c)
        _assert_at_least_as_severe(severity, "sentry_metric_alert_disabled_with_routing_configured")

    def test_missing_team_routing_target(self):
        c = _find(
            _diff(
                [_routing_context("x", target_type_category="team", target_id="t1", target_resolved=True, target_active=True)],
                [_routing_context("x", target_type_category="team", target_id="t1", target_resolved=False, target_active=None)],
            ),
            field_path="target_resolved",
        )
        severity, _ = classify_sentry_change(c)
        _assert_at_least_as_severe(severity, "sentry_alert_targets_missing_team")

    def test_missing_member_routing_target(self):
        c = _find(
            _diff(
                [_routing_context("x", target_resolved=True, target_active=True)],
                [_routing_context("x", target_resolved=False, target_active=None)],
            ),
            field_path="target_resolved",
        )
        severity, _ = classify_sentry_change(c)
        _assert_at_least_as_severe(severity, "sentry_alert_targets_missing_member")

    def test_inactive_member_routing_target(self):
        c = _find(
            _diff(
                [_routing_context("x", target_active=True)],
                [_routing_context("x", target_active=False)],
            ),
            field_path="target_active",
        )
        severity, _ = classify_sentry_change(c)
        _assert_at_least_as_severe(severity, "sentry_alert_references_inactive_member")

    def test_disabled_integration_target(self):
        c = _find(
            _diff(
                [_routing_context("x", integration_status_category="active")],
                [_routing_context("x", integration_status_category="disabled")],
            ),
            field_path="integration_status_category",
        )
        severity, _ = classify_sentry_change(c)
        _assert_at_least_as_severe(severity, "sentry_alert_references_disabled_integration")

    def test_missing_ownership_target(self):
        c = _find(
            _diff(
                [_routing_context("x", context_type="ownership_rule", target_type_category="team", target_id="t1", target_resolved=True, target_active=True, project_id="p1", rule_type=None, rule_id=None)],
                [_routing_context("x", context_type="ownership_rule", target_type_category="team", target_id="t1", target_resolved=False, target_active=None, project_id="p1", rule_type=None, rule_id=None)],
            ),
            field_path="target_resolved",
        )
        severity, _ = classify_sentry_change(c)
        _assert_at_least_as_severe(severity, "sentry_ownership_targets_missing_team")

    def test_inactive_ownership_target(self):
        c = _find(
            _diff(
                [_routing_context("x", context_type="ownership_rule", target_active=True, project_id="p1", rule_type=None, rule_id=None)],
                [_routing_context("x", context_type="ownership_rule", target_active=False, project_id="p1", rule_type=None, rule_id=None)],
            ),
            field_path="target_active",
        )
        severity, _ = classify_sentry_change(c)
        _assert_at_least_as_severe(severity, "sentry_ownership_targets_inactive_member")

    def test_repository_pending_deletion(self):
        c = _find(
            _diff([_repository("r1", status_category="active")], [_repository("r1", status_category="pending_deletion")]),
            field_path="status_category",
        )
        severity, _ = classify_sentry_change(c)
        _assert_at_least_as_severe(severity, "sentry_repository_pending_deletion")

    def test_added_missing_team_routing_target(self):
        c = _find(
            _diff([], [_routing_context("x", target_type_category="team", target_id="t1", target_resolved=False, target_active=None, context_enabled=True)]),
            change_type="added",
        )
        severity, _ = classify_sentry_change(c)
        _assert_at_least_as_severe(severity, "sentry_alert_targets_missing_team")

    def test_added_disabled_integration_routing_target(self):
        c = _find(
            _diff([], [_routing_context("x", integration_status_category="disabled", context_enabled=True)]),
            change_type="added",
        )
        severity, _ = classify_sentry_change(c)
        _assert_at_least_as_severe(severity, "sentry_alert_references_disabled_integration")

    def test_added_missing_ownership_target(self):
        c = _find(
            _diff([], [_routing_context("x", context_type="ownership_rule", target_type_category="team", target_id="t1", target_resolved=False, target_active=None, context_enabled=True, project_id="p1", rule_type=None, rule_id=None)]),
            change_type="added",
        )
        severity, _ = classify_sentry_change(c)
        _assert_at_least_as_severe(severity, "sentry_ownership_targets_missing_team")

    def test_added_repository_pending_deletion(self):
        c = _find(_diff([], [_repository("r1", status_category="pending_deletion")]), change_type="added")
        severity, _ = classify_sentry_change(c)
        # Repository add is always Low regardless of status (see risk_rules
        # module) — matches the Low static Finding severity exactly.
        _assert_at_least_as_severe(severity, "sentry_repository_pending_deletion")

    def test_metric_alert_disabled_removed_never_over_escalates_below_finding(self):
        c = _find(_diff([_metric_rule("r1", status_category="disabled", action_count=1)], []), change_type="removed")
        severity, _ = classify_sentry_change(c)
        _assert_at_least_as_severe(severity, "sentry_metric_alert_disabled_with_routing_configured")

    def test_issue_alert_disabled_retaining_routing(self):
        c = _find(
            _diff([_issue_rule("ir1", status_category="enabled", action_count=1)], [_issue_rule("ir1", status_category="disabled", action_count=1)]),
            field_path="status_category",
        )
        severity, _ = classify_sentry_change(c)
        _assert_at_least_as_severe(severity, "sentry_issue_alert_disabled_with_routing_configured")

    def test_missing_team_ownership_alternate_construction(self):
        c = _find(
            _diff(
                [_routing_context("y", context_type="ownership_rule", target_type_category="user", target_id="m9", target_resolved=True, target_active=True, project_id="p1", rule_type=None, rule_id=None)],
                [_routing_context("y", context_type="ownership_rule", target_type_category="user", target_id="m9", target_resolved=False, target_active=None, project_id="p1", rule_type=None, rule_id=None)],
            ),
            field_path="target_resolved",
        )
        severity, _ = classify_sentry_change(c)
        _assert_at_least_as_severe(severity, "sentry_ownership_targets_missing_member")

    def test_alert_missing_member_alternate_construction(self):
        c = _find(
            _diff(
                [_routing_context("z", target_type_category="user", target_id="m9", target_resolved=True, target_active=True)],
                [_routing_context("z", target_type_category="user", target_id="m9", target_resolved=False, target_active=None)],
            ),
            field_path="target_resolved",
        )
        severity, _ = classify_sentry_change(c)
        _assert_at_least_as_severe(severity, "sentry_alert_targets_missing_member")
