"""Okta authentication policy diff/risk-classification tests (Okta message 4 of 8).

Uses the REAL ``compute_diff()`` and ``classify_okta_change()`` — never
hand-built Change objects standing in for the diff pipeline — to verify
MFA-requirement weakening/strengthening, phishing-resistance
removal/addition, password posture weakening/strengthening, policy
activation/deactivation, priority changes, authenticator
activation/deactivation, added/removed policies/rules/authenticators,
provider metadata, and the ignored-timestamp discipline.
"""

from __future__ import annotations

from types import SimpleNamespace as NS

from app.services.diff_service import _tracked_fields_for, compute_diff
from app.services.risk_rules.okta import classify_okta_change


def _snap(records: list[dict]) -> NS:
    return NS(state=records)


def _policy_record(**overrides) -> dict:
    base = {
        "record_type": "okta_policy",
        "record_id": "id:t1/policy/p1",
        "provider_resource_id": "policies/p1",
        "tenant_id": "id:t1",
        "policy_id": "p1",
        "policy_name": "Default Sign-On Policy",
        "policy_type": "okta_sign_on",
        "status": "ACTIVE",
        "active": True,
        "priority": 1,
        "system": True,
        "scope_category": "all_users",
        "rule_count": 1,
    }
    base.update(overrides)
    return base


def _password_policy_record(**overrides) -> dict:
    base = {
        "record_type": "okta_policy",
        "record_id": "id:t1/policy/pw1",
        "provider_resource_id": "policies/pw1",
        "tenant_id": "id:t1",
        "policy_id": "pw1",
        "policy_name": "Password Policy",
        "policy_type": "password",
        "status": "ACTIVE",
        "active": True,
        "priority": 1,
        "system": False,
        "scope_category": "all_users",
        "rule_count": 1,
        "password_min_length": 12,
        "password_min_length_category": "baseline",
        "password_complexity_required": True,
        "password_history_present": True,
        "password_lifetime_bounded": True,
        "password_lockout_present": True,
        "password_lockout_max_attempts": 5,
    }
    base.update(overrides)
    return base


def _rule_record(**overrides) -> dict:
    base = {
        "record_type": "okta_policy_rule",
        "record_id": "id:t1/policy_rule/p1/r1",
        "provider_resource_id": "policies/p1/rules/r1",
        "tenant_id": "id:t1",
        "policy_id": "p1",
        "policy_name": "Default Sign-On Policy",
        "policy_type": "okta_sign_on",
        "rule_id": "r1",
        "rule_name": "Catch-all",
        "status": "ACTIVE",
        "active": True,
        "priority": 1,
        "scope_category": "all_users",
        "access_category": "ALLOW",
        "mfa_requirement_category": "required",
        "required_factor_count": 2,
        "possession_required": True,
        "knowledge_required": True,
        "phishing_resistant_category": "unknown",
        "hardware_protected_category": "unknown",
        "device_bound": None,
        "session_lifetime_category": "standard",
        "re_authentication_category": "unknown",
    }
    base.update(overrides)
    return base


def _authenticator_record(**overrides) -> dict:
    base = {
        "record_type": "okta_authenticator",
        "record_id": "id:t1/authenticator/a1",
        "provider_resource_id": "authenticators/a1",
        "tenant_id": "id:t1",
        "authenticator_id": "a1",
        "key": "okta_verify",
        "type": "app",
        "status": "ACTIVE",
        "active": True,
        "phishing_resistant_category": "not_phishing_resistant",
        "possession_factor": True,
        "knowledge_factor": False,
        "hardware_backed_category": "unknown",
    }
    base.update(overrides)
    return base


def _find_field_change(changes: list[dict], field_path: str) -> dict:
    match = [c for c in changes if c["field_path"] == field_path]
    assert match, f"no change found for field_path={field_path!r} in {changes}"
    return match[0]


# ════════════════════════════════════════════════════════════════════════════
# Policy activation/deactivation/priority
# ════════════════════════════════════════════════════════════════════════════


class TestPolicyActivation:
    def test_active_to_inactive_is_medium(self):
        prev = [_policy_record(status="ACTIVE", active=True)]
        new = [_policy_record(status="INACTIVE", active=False)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "status")
        level, reason = classify_okta_change(NS(**change))
        assert level == "medium"
        assert "deactivat" in reason.lower()

    def test_inactive_to_active_is_medium(self):
        prev = [_policy_record(status="INACTIVE", active=False)]
        new = [_policy_record(status="ACTIVE", active=True)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "status")
        level, reason = classify_okta_change(NS(**change))
        assert level == "medium"

    def test_unknown_new_status_is_medium(self):
        prev = [_policy_record(status="ACTIVE")]
        new = [_policy_record(status="SOME_FUTURE_STATUS")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "status")
        level, reason = classify_okta_change(NS(**change))
        assert level == "medium"
        assert "unrecognized" in reason.lower()

    def test_priority_change_is_medium(self):
        prev = [_policy_record(priority=3)]
        new = [_policy_record(priority=1)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "priority")
        level, _ = classify_okta_change(NS(**change))
        assert level == "medium"

    def test_policy_renamed_same_id_is_modification(self):
        prev = [_policy_record(policy_name="Old")]
        new = [_policy_record(policy_name="New")]
        changes = compute_diff(_snap(prev), _snap(new))
        change_types = {c["change_type"] for c in changes}
        assert change_types == {"modified"}


class TestPolicyAddedRemoved:
    def test_policy_added(self):
        changes = compute_diff(_snap([]), _snap([_policy_record()]))
        assert changes[0]["change_type"] == "added"
        level, _ = classify_okta_change(NS(**changes[0]))
        assert level == "low"

    def test_policy_removed(self):
        changes = compute_diff(_snap([_policy_record()]), _snap([]))
        assert changes[0]["change_type"] == "removed"
        level, reason = classify_okta_change(NS(**changes[0]))
        assert level == "medium"
        assert "does not by itself confirm" in reason.lower()


# ════════════════════════════════════════════════════════════════════════════
# MFA requirement weakening/strengthening
# ════════════════════════════════════════════════════════════════════════════


class TestMfaRequirementTransitions:
    def test_required_to_none_is_high(self):
        prev = [_rule_record(mfa_requirement_category="required")]
        new = [_rule_record(mfa_requirement_category="none")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "mfa_requirement_category")
        level, reason = classify_okta_change(NS(**change))
        assert level == "high"
        assert "no longer required" in reason.lower() or "removed" in reason.lower()

    def test_required_every_signin_to_none_is_high(self):
        prev = [_rule_record(mfa_requirement_category="required_every_signin")]
        new = [_rule_record(mfa_requirement_category="none")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "mfa_requirement_category")
        level, _ = classify_okta_change(NS(**change))
        assert level == "high"

    def test_required_to_optional_is_medium(self):
        prev = [_rule_record(mfa_requirement_category="required")]
        new = [_rule_record(mfa_requirement_category="optional")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "mfa_requirement_category")
        level, _ = classify_okta_change(NS(**change))
        assert level == "medium"

    def test_optional_to_required_is_low(self):
        prev = [_rule_record(mfa_requirement_category="optional")]
        new = [_rule_record(mfa_requirement_category="required")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "mfa_requirement_category")
        level, _ = classify_okta_change(NS(**change))
        assert level == "low"

    def test_none_to_required_is_low(self):
        prev = [_rule_record(mfa_requirement_category="none")]
        new = [_rule_record(mfa_requirement_category="required")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "mfa_requirement_category")
        level, _ = classify_okta_change(NS(**change))
        assert level == "low"

    def test_unknown_new_value_is_medium_not_ignored(self):
        prev = [_rule_record(mfa_requirement_category="required")]
        new = [_rule_record(mfa_requirement_category="unknown")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "mfa_requirement_category")
        level, _ = classify_okta_change(NS(**change))
        assert level == "medium"

    def test_required_per_session_to_step_up_is_low(self):
        prev = [_rule_record(mfa_requirement_category="required_per_session")]
        new = [_rule_record(mfa_requirement_category="step_up")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "mfa_requirement_category")
        level, _ = classify_okta_change(NS(**change))
        assert level == "low"


class TestAccessCategoryTransitions:
    def test_deny_to_allow_is_high(self):
        prev = [_rule_record(access_category="DENY")]
        new = [_rule_record(access_category="ALLOW")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "access_category")
        level, reason = classify_okta_change(NS(**change))
        assert level == "high"
        assert "deny" in reason.lower() and "allow" in reason.lower()

    def test_allow_to_deny_is_low(self):
        prev = [_rule_record(access_category="ALLOW")]
        new = [_rule_record(access_category="DENY")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "access_category")
        level, _ = classify_okta_change(NS(**change))
        assert level == "low"

    def test_unknown_access_transition_is_medium(self):
        prev = [_rule_record(access_category="ALLOW")]
        new = [_rule_record(access_category="unknown")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "access_category")
        level, _ = classify_okta_change(NS(**change))
        assert level == "medium"


# ════════════════════════════════════════════════════════════════════════════
# Phishing-resistance and factor-count transitions
# ════════════════════════════════════════════════════════════════════════════


class TestPhishingResistanceTransitions:
    def test_required_removed_is_high(self):
        prev = [_rule_record(phishing_resistant_category="phishing_resistant")]
        new = [_rule_record(phishing_resistant_category="not_phishing_resistant")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "phishing_resistant_category")
        level, reason = classify_okta_change(NS(**change))
        assert level == "high"
        assert "removed" in reason.lower() or "no longer" in reason.lower()

    def test_added_is_low(self):
        prev = [_rule_record(phishing_resistant_category="not_phishing_resistant")]
        new = [_rule_record(phishing_resistant_category="phishing_resistant")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "phishing_resistant_category")
        level, _ = classify_okta_change(NS(**change))
        assert level == "low"

    def test_to_unknown_is_medium_not_ignored(self):
        prev = [_rule_record(phishing_resistant_category="phishing_resistant")]
        new = [_rule_record(phishing_resistant_category="unknown")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "phishing_resistant_category")
        level, _ = classify_okta_change(NS(**change))
        assert level == "medium"


class TestFactorCountAndAssuranceTransitions:
    def test_factor_count_decrease_is_medium(self):
        prev = [_rule_record(required_factor_count=2)]
        new = [_rule_record(required_factor_count=1)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "required_factor_count")
        level, _ = classify_okta_change(NS(**change))
        assert level == "medium"

    def test_factor_count_increase_is_low(self):
        prev = [_rule_record(required_factor_count=1)]
        new = [_rule_record(required_factor_count=2)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "required_factor_count")
        level, _ = classify_okta_change(NS(**change))
        assert level == "low"

    def test_possession_required_removed_is_medium(self):
        prev = [_rule_record(possession_required=True)]
        new = [_rule_record(possession_required=False)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "possession_required")
        level, _ = classify_okta_change(NS(**change))
        assert level == "medium"

    def test_possession_required_to_unknown_is_low_not_high(self):
        prev = [_rule_record(possession_required=True)]
        new = [_rule_record(possession_required=None)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "possession_required")
        level, _ = classify_okta_change(NS(**change))
        assert level == "low"

    def test_knowledge_required_removed_is_medium(self):
        prev = [_rule_record(knowledge_required=True)]
        new = [_rule_record(knowledge_required=False)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "knowledge_required")
        level, _ = classify_okta_change(NS(**change))
        assert level == "medium"

    def test_device_bound_removed_is_medium(self):
        prev = [_rule_record(device_bound=True)]
        new = [_rule_record(device_bound=False)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "device_bound")
        level, _ = classify_okta_change(NS(**change))
        assert level == "medium"


class TestRuleAddedRemoved:
    def test_rule_added_is_low(self):
        changes = compute_diff(_snap([]), _snap([_rule_record()]))
        assert changes[0]["change_type"] == "added"
        level, _ = classify_okta_change(NS(**changes[0]))
        assert level == "low"

    def test_rule_removed_is_medium(self):
        changes = compute_diff(_snap([_rule_record()]), _snap([]))
        assert changes[0]["change_type"] == "removed"
        level, _ = classify_okta_change(NS(**changes[0]))
        assert level == "medium"

    def test_rule_status_deactivated_is_medium(self):
        prev = [_rule_record(status="ACTIVE", active=True)]
        new = [_rule_record(status="INACTIVE", active=False)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "status")
        level, _ = classify_okta_change(NS(**change))
        assert level == "medium"

    def test_rule_priority_change_is_medium(self):
        prev = [_rule_record(priority=5)]
        new = [_rule_record(priority=1)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "priority")
        level, _ = classify_okta_change(NS(**change))
        assert level == "medium"


# ════════════════════════════════════════════════════════════════════════════
# Password posture weakening/strengthening
# ════════════════════════════════════════════════════════════════════════════


class TestPasswordPostureTransitions:
    def test_min_length_reduced_is_medium(self):
        prev = [_password_policy_record(password_min_length=14)]
        new = [_password_policy_record(password_min_length=8)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "password_min_length")
        level, _ = classify_okta_change(NS(**change))
        assert level == "medium"

    def test_min_length_increased_is_low(self):
        prev = [_password_policy_record(password_min_length=8)]
        new = [_password_policy_record(password_min_length=14)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "password_min_length")
        level, _ = classify_okta_change(NS(**change))
        assert level == "low"

    def test_complexity_removed_is_medium(self):
        prev = [_password_policy_record(password_complexity_required=True)]
        new = [_password_policy_record(password_complexity_required=False)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "password_complexity_required")
        level, _ = classify_okta_change(NS(**change))
        assert level == "medium"

    def test_complexity_added_is_low(self):
        prev = [_password_policy_record(password_complexity_required=False)]
        new = [_password_policy_record(password_complexity_required=True)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "password_complexity_required")
        level, _ = classify_okta_change(NS(**change))
        assert level == "low"

    def test_history_removed_is_medium(self):
        prev = [_password_policy_record(password_history_present=True)]
        new = [_password_policy_record(password_history_present=False)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "password_history_present")
        level, _ = classify_okta_change(NS(**change))
        assert level == "medium"

    def test_lockout_removed_is_medium(self):
        prev = [_password_policy_record(password_lockout_present=True)]
        new = [_password_policy_record(password_lockout_present=False)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "password_lockout_present")
        level, _ = classify_okta_change(NS(**change))
        assert level == "medium"

    def test_lockout_max_attempts_loosened_is_medium(self):
        prev = [_password_policy_record(password_lockout_max_attempts=3)]
        new = [_password_policy_record(password_lockout_max_attempts=10)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "password_lockout_max_attempts")
        level, _ = classify_okta_change(NS(**change))
        assert level == "medium"

    def test_lockout_max_attempts_tightened_is_low(self):
        prev = [_password_policy_record(password_lockout_max_attempts=10)]
        new = [_password_policy_record(password_lockout_max_attempts=3)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "password_lockout_max_attempts")
        level, _ = classify_okta_change(NS(**change))
        assert level == "low"

    def test_lifetime_unbounded_is_medium(self):
        prev = [_password_policy_record(password_lifetime_bounded=True)]
        new = [_password_policy_record(password_lifetime_bounded=False)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "password_lifetime_bounded")
        level, _ = classify_okta_change(NS(**change))
        assert level == "medium"


# ════════════════════════════════════════════════════════════════════════════
# Authenticator activation/deactivation/added/removed
# ════════════════════════════════════════════════════════════════════════════


class TestAuthenticatorTransitions:
    def test_authenticator_added_is_low(self):
        changes = compute_diff(_snap([]), _snap([_authenticator_record()]))
        assert changes[0]["change_type"] == "added"
        level, _ = classify_okta_change(NS(**changes[0]))
        assert level == "low"

    def test_authenticator_removed_is_medium(self):
        changes = compute_diff(_snap([_authenticator_record()]), _snap([]))
        assert changes[0]["change_type"] == "removed"
        level, reason = classify_okta_change(NS(**changes[0]))
        assert level == "medium"
        assert "does not by itself confirm" in reason.lower()

    def test_ordinary_authenticator_deactivated_is_low(self):
        prev = [_authenticator_record(status="ACTIVE", active=True, phishing_resistant_category="not_phishing_resistant")]
        new = [_authenticator_record(status="INACTIVE", active=False, phishing_resistant_category="not_phishing_resistant")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "status")
        level, _ = classify_okta_change(NS(**change))
        assert level == "low"

    def test_phishing_resistant_authenticator_deactivated_is_medium(self):
        prev = [_authenticator_record(status="ACTIVE", active=True, phishing_resistant_category="phishing_resistant")]
        new = [_authenticator_record(status="INACTIVE", active=False, phishing_resistant_category="phishing_resistant")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "status")
        level, _ = classify_okta_change(NS(**change))
        assert level == "medium"

    def test_authenticator_activated_is_low(self):
        prev = [_authenticator_record(status="INACTIVE", active=False)]
        new = [_authenticator_record(status="ACTIVE", active=True)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "status")
        level, _ = classify_okta_change(NS(**change))
        assert level == "low"

    def test_authenticator_phishing_resistance_lost_is_medium(self):
        prev = [_authenticator_record(phishing_resistant_category="phishing_resistant")]
        new = [_authenticator_record(phishing_resistant_category="not_phishing_resistant")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "phishing_resistant_category")
        level, reason = classify_okta_change(NS(**change))
        assert level == "medium"
        assert "lost" in reason.lower()


# ════════════════════════════════════════════════════════════════════════════
# Provider metadata
# ════════════════════════════════════════════════════════════════════════════


class TestProviderMetadata:
    def test_policy_provider_metadata(self):
        changes = compute_diff(
            _snap([_policy_record(status="ACTIVE")]),
            _snap([_policy_record(status="INACTIVE")]),
        )
        change = _find_field_change(changes, "status")
        pm = change["provider_metadata"]
        assert pm["record_type"] == "okta_policy"
        assert pm["tenant_id"] == "id:t1"
        assert pm["policy_id"] == "p1"
        assert pm["policy_name"] == "Default Sign-On Policy"
        assert pm["policy_type"] == "okta_sign_on"

    def test_rule_provider_metadata(self):
        changes = compute_diff(_snap([]), _snap([_rule_record()]))
        pm = changes[0]["provider_metadata"]
        assert pm["record_type"] == "okta_policy_rule"
        assert pm["policy_id"] == "p1"
        assert pm["rule_id"] == "r1"
        assert pm["rule_name"] == "Catch-all"

    def test_authenticator_provider_metadata(self):
        changes = compute_diff(_snap([]), _snap([_authenticator_record()]))
        pm = changes[0]["provider_metadata"]
        assert pm["record_type"] == "okta_authenticator"
        assert pm["authenticator_id"] == "a1"
        assert pm["key"] == "okta_verify"

    def test_provider_metadata_never_includes_secrets(self):
        changes = compute_diff(_snap([]), _snap([_authenticator_record()]))
        pm = changes[0]["provider_metadata"]
        assert "settings" not in pm
        assert "otp" not in pm
        assert "sharedSecret" not in pm


# ════════════════════════════════════════════════════════════════════════════
# Ignored timestamps / untracked fields
# ════════════════════════════════════════════════════════════════════════════


class TestIgnoredTimestamps:
    def test_creation_timestamp_not_tracked_for_policy(self):
        fields = _tracked_fields_for({"record_type": "okta_policy"})
        assert "created" not in fields
        assert "lastUpdated" not in fields

    def test_targeting_detail_counts_not_tracked_for_rule(self):
        fields = _tracked_fields_for({"record_type": "okta_policy_rule"})
        assert "network_zone_category" not in fields
        assert "group_include_count" not in fields
        assert "group_exclude_count" not in fields
        assert "user_include_count" not in fields

    def test_inherence_factor_not_tracked_for_authenticator(self):
        fields = _tracked_fields_for({"record_type": "okta_authenticator"})
        assert "inherence_factor" not in fields

    def test_no_change_from_untracked_fields_alone(self):
        prev = [_policy_record()]
        prev[0]["created"] = "2020-01-01T00:00:00.000Z"
        new = [_policy_record()]
        new[0]["created"] = "2024-01-01T00:00:00.000Z"
        changes = compute_diff(_snap(prev), _snap(new))
        assert changes == []

    def test_unmapped_policy_subtype_returns_empty(self):
        fields = _tracked_fields_for({"record_type": "okta_policy_totally_unknown_future_subtype"})
        assert fields == ()
