"""Sentry Security Finding predicate tests (Sentry message 6 of 8).

For every implemented rule: a positive-trigger case and at least one
adjacent non-trigger case (unknown/missing/gated-condition/completeness
gap/etc. that must never fire). Uses ``evaluate()`` directly against
hand-built normalized/derived records — connector-shape reachability is
covered separately in ``test_sentry_security_findings_reachability.py``.
"""

from __future__ import annotations

from app.services.security_rules.sentry import evaluate

_ORG = "id:999"


def _keys(record: dict) -> set[str]:
    return {f.rule_key for f in evaluate(record)}


def _privileged_member(**overrides) -> dict:
    base = {
        "record_type": "sentry_privileged_member",
        "record_id": f"{_ORG}/privileged_member/m1",
        "organization_id": _ORG,
        "member_id": "m1",
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


def _privileged_team(**overrides) -> dict:
    base = {
        "record_type": "sentry_privileged_team",
        "record_id": f"{_ORG}/privileged_team/t1",
        "organization_id": _ORG,
        "team_id": "t1",
        "project_count": 1,
        "ownership_rule_target_count": 0,
        "alert_action_target_count": 0,
        "privileged_member_count": 0,
        "unresolved_member_count": 0,
        "access_completeness": "complete",
    }
    base.update(overrides)
    return base


def _metric_alert_rule(**overrides) -> dict:
    base = {
        "record_type": "sentry_metric_alert_rule",
        "record_id": f"{_ORG}/metric_alert_rule/r1",
        "organization_id": _ORG,
        "project_id": "p1",
        "rule_id": "r1",
        "name": "Prod error volume",
        "status_category": "enabled",
        "action_count": 1,
    }
    base.update(overrides)
    return base


def _issue_alert_rule(**overrides) -> dict:
    base = {
        "record_type": "sentry_issue_alert_rule",
        "record_id": f"{_ORG}/issue_alert_rule/r2",
        "organization_id": _ORG,
        "project_id": "p1",
        "rule_id": "r2",
        "name": "New issue notify",
        "status_category": "enabled",
        "action_count": 1,
    }
    base.update(overrides)
    return base


def _routing_context(**overrides) -> dict:
    base = {
        "record_type": "sentry_routing_context",
        "record_id": f"{_ORG}/routing_context/alert_action/metric/r1/tr1/a1",
        "organization_id": _ORG,
        "context_type": "alert_action",
        "source_record_id": f"{_ORG}/alert_action/metric/tr1/a1",
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


def _repository(**overrides) -> dict:
    base = {
        "record_type": "sentry_repository",
        "record_id": f"{_ORG}/repository/repo1",
        "organization_id": _ORG,
        "repository_id": "repo1",
        "name": "acme/webapp",
        "provider_category": "github",
        "status_category": "active",
        "integration_id": "int1",
        "external_id": "12345",
        "date_created": None,
    }
    base.update(overrides)
    return base


# ════════════════════════════════════════════════════════════════════════════
# Privileged organization members
# ════════════════════════════════════════════════════════════════════════════


class TestActiveOwner:
    def test_active_owner_fires(self):
        keys = _keys(_privileged_member(org_role_category="owner", member_status_category="active"))
        assert "sentry_active_organization_owner" in keys

    def test_pending_owner_does_not_fire_active_rule(self):
        keys = _keys(_privileged_member(org_role_category="owner", member_status_category="pending"))
        assert "sentry_active_organization_owner" not in keys
        assert "sentry_pending_privileged_invitation" in keys

    def test_owner_and_admin_mutually_exclusive(self):
        keys = _keys(_privileged_member(org_role_category="owner", member_status_category="active"))
        assert "sentry_active_organization_admin" not in keys
        assert "sentry_active_organization_manager" not in keys


class TestActiveManager:
    def test_active_manager_fires(self):
        keys = _keys(_privileged_member(org_role_category="manager", member_status_category="active"))
        assert "sentry_active_organization_manager" in keys

    def test_ordinary_member_does_not_fire(self):
        keys = _keys(_privileged_member(org_role_category="member", member_status_category="active"))
        assert "sentry_active_organization_manager" not in keys
        assert "sentry_active_organization_owner" not in keys
        assert "sentry_active_organization_admin" not in keys


class TestActiveAdmin:
    def test_active_admin_fires(self):
        keys = _keys(_privileged_member(org_role_category="admin", member_status_category="active"))
        assert "sentry_active_organization_admin" in keys

    def test_billing_role_never_fires(self):
        keys = _keys(_privileged_member(org_role_category="billing", member_status_category="active"))
        assert not (keys & {"sentry_active_organization_owner", "sentry_active_organization_manager", "sentry_active_organization_admin"})

    def test_unknown_role_never_fires_role_rule(self):
        keys = _keys(_privileged_member(org_role_category="unknown", member_status_category="active"))
        assert not (keys & {"sentry_active_organization_owner", "sentry_active_organization_manager", "sentry_active_organization_admin"})


class TestPendingPrivilegedInvitation:
    def test_pending_owner_is_high(self):
        cands = evaluate(_privileged_member(org_role_category="owner", member_status_category="pending"))
        f = next(c for c in cands if c.rule_key == "sentry_pending_privileged_invitation")
        assert f.severity == "high"

    def test_pending_admin_is_medium(self):
        cands = evaluate(_privileged_member(org_role_category="admin", member_status_category="pending"))
        f = next(c for c in cands if c.rule_key == "sentry_pending_privileged_invitation")
        assert f.severity == "medium"

    def test_pending_ordinary_member_does_not_fire(self):
        keys = _keys(_privileged_member(org_role_category="member", member_status_category="pending"))
        assert "sentry_pending_privileged_invitation" not in keys

    def test_expired_privileged_invitation_does_not_fire(self):
        keys = _keys(_privileged_member(org_role_category="owner", member_status_category="expired"))
        assert "sentry_pending_privileged_invitation" not in keys

    def test_pending_unknown_role_does_not_fire(self):
        keys = _keys(_privileged_member(org_role_category="unknown", member_status_category="pending"))
        assert "sentry_pending_privileged_invitation" not in keys


class TestMemberBroadRoutingAuthority:
    def test_combined_targets_fires(self):
        keys = _keys(_privileged_member(org_role_category="member", alert_routing_target_count=1, ownership_rule_target_count=1))
        assert "sentry_member_broad_routing_authority" in keys

    def test_only_alert_target_does_not_fire(self):
        keys = _keys(_privileged_member(org_role_category="member", alert_routing_target_count=1, ownership_rule_target_count=0))
        assert "sentry_member_broad_routing_authority" not in keys

    def test_owner_with_combined_targets_does_not_double_fire(self):
        keys = _keys(_privileged_member(org_role_category="owner", alert_routing_target_count=1, ownership_rule_target_count=1))
        assert "sentry_member_broad_routing_authority" not in keys


class TestMemberTeamAdminWithoutOrgRole:
    def test_team_admin_ordinary_member_fires(self):
        keys = _keys(_privileged_member(org_role_category="member", team_admin_team_count=1))
        assert "sentry_member_team_admin_without_org_role" in keys

    def test_zero_team_admin_count_does_not_fire(self):
        keys = _keys(_privileged_member(org_role_category="member", team_admin_team_count=0))
        assert "sentry_member_team_admin_without_org_role" not in keys

    def test_admin_role_does_not_also_fire_team_admin_rule(self):
        keys = _keys(_privileged_member(org_role_category="admin", team_admin_team_count=1))
        assert "sentry_member_team_admin_without_org_role" not in keys


# ════════════════════════════════════════════════════════════════════════════
# Privileged teams
# ════════════════════════════════════════════════════════════════════════════


class TestTeamBroadRoutingAuthority:
    def test_both_targets_fires(self):
        keys = _keys(_privileged_team(ownership_rule_target_count=1, alert_action_target_count=1))
        assert "sentry_team_has_broad_routing_authority" in keys

    def test_only_ownership_target_does_not_fire(self):
        keys = _keys(_privileged_team(ownership_rule_target_count=1, alert_action_target_count=0))
        assert "sentry_team_has_broad_routing_authority" not in keys


class TestTeamHasUnresolvedMembers:
    def test_unresolved_members_fires(self):
        keys = _keys(_privileged_team(unresolved_member_count=1))
        assert "sentry_team_has_unresolved_members" in keys

    def test_zero_unresolved_does_not_fire(self):
        keys = _keys(_privileged_team(unresolved_member_count=0))
        assert "sentry_team_has_unresolved_members" not in keys


# ════════════════════════════════════════════════════════════════════════════
# Alert coverage
# ════════════════════════════════════════════════════════════════════════════


class TestMetricAlertUnrouted:
    def test_enabled_zero_actions_fires(self):
        keys = _keys(_metric_alert_rule(status_category="enabled", action_count=0))
        assert "sentry_metric_alert_unrouted" in keys

    def test_disabled_zero_actions_does_not_fire_unrouted(self):
        keys = _keys(_metric_alert_rule(status_category="disabled", action_count=0))
        assert "sentry_metric_alert_unrouted" not in keys

    def test_unknown_status_does_not_fire(self):
        keys = _keys(_metric_alert_rule(status_category="unknown", action_count=0))
        assert "sentry_metric_alert_unrouted" not in keys

    def test_action_count_none_does_not_fire(self):
        keys = _keys(_metric_alert_rule(status_category="enabled", action_count=None))
        assert "sentry_metric_alert_unrouted" not in keys

    def test_enabled_with_actions_does_not_fire(self):
        keys = _keys(_metric_alert_rule(status_category="enabled", action_count=2))
        assert "sentry_metric_alert_unrouted" not in keys


class TestIssueAlertUnrouted:
    def test_enabled_zero_actions_fires(self):
        keys = _keys(_issue_alert_rule(status_category="enabled", action_count=0))
        assert "sentry_issue_alert_unrouted" in keys

    def test_disabled_does_not_fire(self):
        keys = _keys(_issue_alert_rule(status_category="disabled", action_count=0))
        assert "sentry_issue_alert_unrouted" not in keys


class TestAlertDisabledWithRoutingConfigured:
    def test_metric_disabled_with_actions_fires_low(self):
        cands = evaluate(_metric_alert_rule(status_category="disabled", action_count=2))
        f = next(c for c in cands if c.rule_key == "sentry_metric_alert_disabled_with_routing_configured")
        assert f.severity == "low"

    def test_metric_disabled_zero_actions_does_not_fire_advisory(self):
        keys = _keys(_metric_alert_rule(status_category="disabled", action_count=0))
        assert "sentry_metric_alert_disabled_with_routing_configured" not in keys

    def test_issue_disabled_with_actions_fires_low(self):
        cands = evaluate(_issue_alert_rule(status_category="disabled", action_count=3))
        f = next(c for c in cands if c.rule_key == "sentry_issue_alert_disabled_with_routing_configured")
        assert f.severity == "low"


# ════════════════════════════════════════════════════════════════════════════
# Alert notification routing
# ════════════════════════════════════════════════════════════════════════════


class TestAlertTargetsMissingTeam:
    def test_missing_team_on_enabled_rule_fires(self):
        keys = _keys(_routing_context(
            target_type_category="team", target_resolved=False, target_active=None,
            completeness="complete", context_enabled=True,
        ))
        assert "sentry_alert_targets_missing_team" in keys

    def test_missing_team_on_disabled_rule_does_not_fire(self):
        keys = _keys(_routing_context(
            target_type_category="team", target_resolved=False, target_active=None,
            completeness="complete", context_enabled=False,
        ))
        assert "sentry_alert_targets_missing_team" not in keys

    def test_missing_team_with_partial_completeness_does_not_fire(self):
        keys = _keys(_routing_context(
            target_type_category="team", target_resolved=False, target_active=None,
            completeness="partial", context_enabled=True,
        ))
        assert "sentry_alert_targets_missing_team" not in keys

    def test_resolved_team_does_not_fire(self):
        keys = _keys(_routing_context(
            target_type_category="team", target_resolved=True, target_active=True,
            completeness="complete", context_enabled=True,
        ))
        assert "sentry_alert_targets_missing_team" not in keys


class TestAlertTargetsMissingMember:
    def test_missing_member_on_enabled_rule_fires(self):
        keys = _keys(_routing_context(
            target_type_category="user", target_resolved=False, target_active=None,
            completeness="complete", context_enabled=True,
        ))
        assert "sentry_alert_targets_missing_member" in keys

    def test_specific_target_type_never_resolves_and_never_fires_missing_member(self):
        keys = _keys(_routing_context(
            target_type_category="specific", target_resolved=False, target_active=None,
            completeness="complete", context_enabled=True,
        ))
        assert "sentry_alert_targets_missing_member" not in keys
        assert "sentry_alert_targets_missing_team" not in keys


class TestAlertReferencesInactiveMember:
    def test_resolved_inactive_member_fires(self):
        keys = _keys(_routing_context(
            target_type_category="user", target_resolved=True, target_active=False,
            completeness="complete", context_enabled=True,
        ))
        assert "sentry_alert_references_inactive_member" in keys

    def test_resolved_active_member_does_not_fire(self):
        keys = _keys(_routing_context(
            target_type_category="user", target_resolved=True, target_active=True,
            completeness="complete", context_enabled=True,
        ))
        assert "sentry_alert_references_inactive_member" not in keys

    def test_disabled_rule_does_not_fire(self):
        keys = _keys(_routing_context(
            target_type_category="user", target_resolved=True, target_active=False,
            completeness="complete", context_enabled=False,
        ))
        assert "sentry_alert_references_inactive_member" not in keys


class TestAlertReferencesDisabledIntegration:
    def test_disabled_integration_on_enabled_rule_fires(self):
        keys = _keys(_routing_context(
            target_type_category="specific", target_resolved=False,
            integration_status_category="disabled", context_enabled=True,
        ))
        assert "sentry_alert_references_disabled_integration" in keys

    def test_active_integration_does_not_fire(self):
        keys = _keys(_routing_context(
            target_type_category="specific", target_resolved=False,
            integration_status_category="active", context_enabled=True,
        ))
        assert "sentry_alert_references_disabled_integration" not in keys

    def test_unknown_integration_status_does_not_fire(self):
        keys = _keys(_routing_context(
            target_type_category="specific", target_resolved=False,
            integration_status_category=None, context_enabled=True,
        ))
        assert "sentry_alert_references_disabled_integration" not in keys


# ════════════════════════════════════════════════════════════════════════════
# Ownership routing
# ════════════════════════════════════════════════════════════════════════════


class TestOwnershipTargetsMissingTeam:
    def test_missing_team_fires(self):
        keys = _keys(_routing_context(
            context_type="ownership_rule", target_type_category="team", target_resolved=False,
            target_active=None, completeness="complete", context_enabled=True,
            rule_type=None, rule_id=None, project_id="p1",
        ))
        assert "sentry_ownership_targets_missing_team" in keys

    def test_valid_team_does_not_fire(self):
        keys = _keys(_routing_context(
            context_type="ownership_rule", target_type_category="team", target_resolved=True,
            target_active=True, completeness="complete", context_enabled=True,
            rule_type=None, rule_id=None, project_id="p1",
        ))
        assert "sentry_ownership_targets_missing_team" not in keys

    def test_partial_inventory_does_not_fire(self):
        keys = _keys(_routing_context(
            context_type="ownership_rule", target_type_category="team", target_resolved=False,
            target_active=None, completeness="partial", context_enabled=True,
            rule_type=None, rule_id=None, project_id="p1",
        ))
        assert "sentry_ownership_targets_missing_team" not in keys


class TestOwnershipTargetsMissingMember:
    def test_missing_member_fires(self):
        keys = _keys(_routing_context(
            context_type="ownership_rule", target_type_category="user", target_resolved=False,
            target_active=None, completeness="complete", context_enabled=True,
            rule_type=None, rule_id=None, project_id="p1",
        ))
        assert "sentry_ownership_targets_missing_member" in keys

    def test_inactive_ownership_config_does_not_fire(self):
        keys = _keys(_routing_context(
            context_type="ownership_rule", target_type_category="user", target_resolved=False,
            target_active=None, completeness="complete", context_enabled=False,
            rule_type=None, rule_id=None, project_id="p1",
        ))
        assert "sentry_ownership_targets_missing_member" not in keys

    def test_unknown_enabled_state_does_not_fire(self):
        keys = _keys(_routing_context(
            context_type="ownership_rule", target_type_category="user", target_resolved=False,
            target_active=None, completeness="complete", context_enabled=None,
            rule_type=None, rule_id=None, project_id="p1",
        ))
        assert "sentry_ownership_targets_missing_member" not in keys


class TestOwnershipTargetsInactiveMember:
    def test_inactive_target_fires(self):
        keys = _keys(_routing_context(
            context_type="ownership_rule", target_type_category="user", target_resolved=True,
            target_active=False, completeness="complete", context_enabled=True,
            rule_type=None, rule_id=None, project_id="p1",
        ))
        assert "sentry_ownership_targets_inactive_member" in keys

    def test_active_target_does_not_fire(self):
        keys = _keys(_routing_context(
            context_type="ownership_rule", target_type_category="user", target_resolved=True,
            target_active=True, completeness="complete", context_enabled=True,
            rule_type=None, rule_id=None, project_id="p1",
        ))
        assert "sentry_ownership_targets_inactive_member" not in keys

    def test_never_stores_raw_email_in_evidence(self):
        cands = evaluate(_routing_context(
            context_type="ownership_rule", target_type_category="user", target_resolved=False,
            target_active=None, completeness="complete", context_enabled=True,
            rule_type=None, rule_id=None, project_id="p1",
        ))
        assert cands
        blob = str(cands[0].evidence).lower()
        assert "@" not in blob
        assert "email" not in blob


# ════════════════════════════════════════════════════════════════════════════
# Repository configuration integrity
# ════════════════════════════════════════════════════════════════════════════


class TestRepositoryPendingDeletion:
    def test_pending_deletion_fires(self):
        keys = _keys(_repository(status_category="pending_deletion"))
        assert "sentry_repository_pending_deletion" in keys

    def test_deletion_in_progress_fires(self):
        keys = _keys(_repository(status_category="deletion_in_progress"))
        assert "sentry_repository_pending_deletion" in keys

    def test_active_repository_does_not_fire(self):
        keys = _keys(_repository(status_category="active"))
        assert "sentry_repository_pending_deletion" not in keys

    def test_disabled_repository_alone_does_not_fire(self):
        keys = _keys(_repository(status_category="disabled"))
        assert "sentry_repository_pending_deletion" not in keys

    def test_unknown_status_does_not_fire(self):
        keys = _keys(_repository(status_category="unknown"))
        assert "sentry_repository_pending_deletion" not in keys


# ════════════════════════════════════════════════════════════════════════════
# Sensitive-data boundary (cross-cutting)
# ════════════════════════════════════════════════════════════════════════════


class TestSensitiveDataExclusion:
    def test_privileged_member_evidence_never_includes_email_or_token(self):
        cands = evaluate(_privileged_member(org_role_category="owner", member_status_category="active"))
        blob = str(cands[0].evidence).lower()
        for forbidden in ("email", "auth_token", "authorization", "webhook", "dsn", "@"):
            assert forbidden not in blob

    def test_unrouted_alert_evidence_never_includes_dsn_or_event_data(self):
        cands = evaluate(_metric_alert_rule(status_category="enabled", action_count=0))
        blob = str(cands[0].evidence).lower()
        for forbidden in ("dsn", "event", "stacktrace", "breadcrumbs"):
            assert forbidden not in blob

    def test_unknown_record_type_returns_empty(self):
        assert evaluate({"record_type": "sentry_organization"}) == []

    def test_non_dict_input_returns_empty(self):
        assert evaluate(None) == []
        assert evaluate("not a dict") == []
