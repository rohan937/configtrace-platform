"""Microsoft Entra ID authentication policy diff/risk-classification tests
(Entra message 4 of 8).

Uses the REAL ``compute_diff()`` and ``classify_entra_change()`` — never
hand-built Change objects standing in for the diff pipeline — to verify
Conditional Access enable/disable/report-only transitions, block-access
removal/addition, MFA weakening/strengthening, phishing-resistant
weakening/strengthening, device requirement changes, legacy-auth block,
exclusions, session controls, authentication-method changes,
authentication-strength changes, and provider metadata.
"""

from __future__ import annotations

from types import SimpleNamespace as NS

from app.services.diff_service import compute_diff
from app.services.risk_rules.entra import classify_entra_change

_TENANT = "id:t1"


def _snap(records: list[dict]) -> NS:
    return NS(state=records)


def _find_field_change(changes: list[dict], field_path: str) -> dict:
    match = [c for c in changes if c["field_path"] == field_path]
    assert match, f"no change found for field_path={field_path!r} in {changes}"
    return match[0]


def _ca_record(**overrides) -> dict:
    base = {
        "record_type": "entra_conditional_access_policy",
        "record_id": f"{_TENANT}/conditional_access_policy/p1",
        "provider_resource_id": "identity/conditionalAccess/policies/p1",
        "tenant_id": _TENANT,
        "policy_id": "p1",
        "display_name": "Require MFA",
        "state_category": "enabled",
        "user_target_category": "all_users",
        "include_user_count": 0,
        "include_group_count": 0,
        "include_role_count": 0,
        "exclude_user_count": 0,
        "exclude_group_count": 0,
        "exclude_role_count": 0,
        "guests_included": False,
        "guests_excluded": False,
        "app_target_category": "all_cloud_apps",
        "include_app_count": 0,
        "exclude_app_count": 0,
        "coverage_category": "all_users_all_apps",
        "location_target_category": "unknown",
        "device_platform_categories": ["unknown"],
        "client_app_type_categories": ["unknown"],
        "legacy_auth_targeted": False,
        "user_risk_level_categories": ["unknown"],
        "sign_in_risk_level_categories": ["unknown"],
        "grant_operator_category": "AND",
        "grant_control_categories": ["mfa"],
        "mfa_requirement_category": "required",
        "block_access": False,
        "compliant_device_required": False,
        "hybrid_joined_device_required": False,
        "approved_application_required": False,
        "compliant_application_required": False,
        "authentication_strength_id": None,
        "authentication_strength_referenced": False,
        "sign_in_frequency_enabled": False,
        "sign_in_frequency_category": "unknown",
        "persistent_browser_category": "unknown",
        "continuous_access_evaluation_category": "unknown",
        "app_enforced_restrictions_enabled": None,
    }
    base.update(overrides)
    return base


def _strength_record(**overrides) -> dict:
    base = {
        "record_type": "entra_authentication_strength",
        "record_id": f"{_TENANT}/authentication_strength/s1",
        "provider_resource_id": "policies/authenticationStrengthPolicies/s1",
        "tenant_id": _TENANT,
        "strength_id": "s1",
        "display_name": "Phishing-resistant MFA",
        "kind_category": "built_in",
        "allowed_combination_count": 2,
        "phishing_resistance_category": "phishing_resistant",
        "passwordless_category": "passwordless",
        "mfa_capability_category": "mfa_capable",
    }
    base.update(overrides)
    return base


def _method_record(**overrides) -> dict:
    base = {
        "record_type": "entra_authentication_method",
        "record_id": f"{_TENANT}/authentication_method/Fido2",
        "provider_resource_id": "policies/authenticationMethodsPolicy/authenticationMethodConfigurations/Fido2",
        "tenant_id": _TENANT,
        "method_config_id": "Fido2",
        "method_type_category": "fido2",
        "state_category": "enabled",
        "phishing_resistance_category": "phishing_resistant",
        "target_category": "all_users",
        "include_target_count": 1,
        "exclude_target_count": 0,
    }
    base.update(overrides)
    return base


# ════════════════════════════════════════════════════════════════════════════
# No spurious changes
# ════════════════════════════════════════════════════════════════════════════


class TestNoSpuriousChangeWhenIdentical:
    def test_identical_ca_policy_produces_no_change(self):
        rec = _ca_record()
        changes = compute_diff(_snap([rec]), _snap([dict(rec)]))
        assert changes == []

    def test_identical_strength_produces_no_change(self):
        rec = _strength_record()
        changes = compute_diff(_snap([rec]), _snap([dict(rec)]))
        assert changes == []

    def test_identical_method_produces_no_change(self):
        rec = _method_record()
        changes = compute_diff(_snap([rec]), _snap([dict(rec)]))
        assert changes == []


# ════════════════════════════════════════════════════════════════════════════
# Conditional Access enable/disable/report-only transitions
# ════════════════════════════════════════════════════════════════════════════


class TestConditionalAccessStateTransitions:
    def test_enabled_to_report_only_is_medium(self):
        prev = [_ca_record(state_category="enabled")]
        new = [_ca_record(state_category="report_only")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "state_category")
        level, reason = classify_entra_change(change)
        assert level == "medium"
        assert "report-only" in reason.lower() or "no longer enforces" in reason.lower()

    def test_report_only_to_enabled_is_low(self):
        prev = [_ca_record(state_category="report_only")]
        new = [_ca_record(state_category="enabled")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "state_category")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_enabled_to_disabled_is_medium(self):
        prev = [_ca_record(state_category="enabled")]
        new = [_ca_record(state_category="disabled")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "state_category")
        level, _ = classify_entra_change(change)
        assert level == "medium"

    def test_disabled_to_enabled_is_low(self):
        prev = [_ca_record(state_category="disabled")]
        new = [_ca_record(state_category="enabled")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "state_category")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_unknown_state_transition_never_ranked_high(self):
        prev = [_ca_record(state_category="enabled")]
        new = [_ca_record(state_category="unknown")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "state_category")
        level, _ = classify_entra_change(change)
        assert level in ("low", "medium")

    def test_policy_added_enabled_broad_no_mfa_is_high(self):
        changes = compute_diff(
            _snap([]),
            _snap([_ca_record(state_category="enabled", coverage_category="all_users_all_apps", mfa_requirement_category="not_required", block_access=False)]),
        )
        change = next(c for c in changes if c["change_type"] == "added")
        level, _ = classify_entra_change(change)
        assert level == "high"

    def test_policy_added_enforced_mfa_is_low(self):
        changes = compute_diff(_snap([]), _snap([_ca_record(state_category="enabled", mfa_requirement_category="required")]))
        change = next(c for c in changes if c["change_type"] == "added")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_policy_added_report_only_is_low(self):
        changes = compute_diff(_snap([]), _snap([_ca_record(state_category="report_only")]))
        change = next(c for c in changes if c["change_type"] == "added")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_enforced_policy_removed_is_high_or_medium(self):
        changes = compute_diff(_snap([_ca_record(state_category="enabled", mfa_requirement_category="required")]), _snap([]))
        change = next(c for c in changes if c["change_type"] == "removed")
        level, _ = classify_entra_change(change)
        assert level in ("high", "medium")

    def test_report_only_policy_removed_is_low(self):
        changes = compute_diff(_snap([_ca_record(state_category="report_only")]), _snap([]))
        change = next(c for c in changes if c["change_type"] == "removed")
        level, _ = classify_entra_change(change)
        assert level == "low"


# ════════════════════════════════════════════════════════════════════════════
# Block access removed/added
# ════════════════════════════════════════════════════════════════════════════


class TestBlockAccessChanges:
    def test_enforced_block_removed_is_high(self):
        prev = [_ca_record(state_category="enabled", block_access=True)]
        new = [_ca_record(state_category="enabled", block_access=False)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "block_access")
        level, _ = classify_entra_change(change)
        assert level == "high"

    def test_block_added_is_low(self):
        prev = [_ca_record(block_access=False)]
        new = [_ca_record(block_access=True)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "block_access")
        level, _ = classify_entra_change(change)
        assert level == "low"


# ════════════════════════════════════════════════════════════════════════════
# MFA requirement weakening/strengthening (AND/OR aware)
# ════════════════════════════════════════════════════════════════════════════


class TestMfaRequirementChanges:
    def test_required_to_not_required_on_enforced_policy_is_high(self):
        prev = [_ca_record(state_category="enabled", mfa_requirement_category="required")]
        new = [_ca_record(state_category="enabled", mfa_requirement_category="not_required")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "mfa_requirement_category")
        level, _ = classify_entra_change(change)
        assert level == "high"

    def test_required_to_one_of_multiple_is_medium(self):
        prev = [_ca_record(state_category="enabled", mfa_requirement_category="required")]
        new = [_ca_record(state_category="enabled", mfa_requirement_category="one_of_multiple_controls")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "mfa_requirement_category")
        level, _ = classify_entra_change(change)
        assert level == "medium"

    def test_not_required_to_required_is_low(self):
        prev = [_ca_record(mfa_requirement_category="not_required")]
        new = [_ca_record(mfa_requirement_category="required")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "mfa_requirement_category")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_unknown_mfa_transition_never_high(self):
        prev = [_ca_record(mfa_requirement_category="required")]
        new = [_ca_record(mfa_requirement_category="unknown")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "mfa_requirement_category")
        level, _ = classify_entra_change(change)
        assert level != "high"


# ════════════════════════════════════════════════════════════════════════════
# Device requirement changes
# ════════════════════════════════════════════════════════════════════════════


class TestDeviceRequirementChanges:
    def test_compliant_device_requirement_removed_is_medium(self):
        prev = [_ca_record(compliant_device_required=True)]
        new = [_ca_record(compliant_device_required=False)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "compliant_device_required")
        level, _ = classify_entra_change(change)
        assert level == "medium"

    def test_compliant_device_requirement_added_is_low(self):
        prev = [_ca_record(compliant_device_required=False)]
        new = [_ca_record(compliant_device_required=True)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "compliant_device_required")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_hybrid_joined_requirement_removed_is_medium(self):
        prev = [_ca_record(hybrid_joined_device_required=True)]
        new = [_ca_record(hybrid_joined_device_required=False)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "hybrid_joined_device_required")
        level, _ = classify_entra_change(change)
        assert level == "medium"


# ════════════════════════════════════════════════════════════════════════════
# Legacy authentication block
# ════════════════════════════════════════════════════════════════════════════


class TestLegacyAuthBlock:
    def test_legacy_auth_targeting_removed_from_enforced_block_policy_is_high(self):
        prev = [_ca_record(legacy_auth_targeted=True, block_access=True)]
        new = [_ca_record(legacy_auth_targeted=False, block_access=True)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "legacy_auth_targeted")
        level, _ = classify_entra_change(change)
        assert level == "high"

    def test_legacy_auth_targeting_added_is_low(self):
        prev = [_ca_record(legacy_auth_targeted=False)]
        new = [_ca_record(legacy_auth_targeted=True)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "legacy_auth_targeted")
        level, _ = classify_entra_change(change)
        assert level == "low"


# ════════════════════════════════════════════════════════════════════════════
# Exclusions
# ════════════════════════════════════════════════════════════════════════════


class TestExclusionChanges:
    def test_exclusions_broadened_is_medium(self):
        prev = [_ca_record(exclude_user_count=1)]
        new = [_ca_record(exclude_user_count=10)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "exclude_user_count")
        level, _ = classify_entra_change(change)
        assert level == "medium"

    def test_exclusions_narrowed_is_low(self):
        prev = [_ca_record(exclude_user_count=10)]
        new = [_ca_record(exclude_user_count=1)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "exclude_user_count")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_guests_exclusion_removed_is_medium(self):
        prev = [_ca_record(guests_excluded=True)]
        new = [_ca_record(guests_excluded=False)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "guests_excluded")
        level, _ = classify_entra_change(change)
        assert level == "medium"


# ════════════════════════════════════════════════════════════════════════════
# Session controls
# ════════════════════════════════════════════════════════════════════════════


class TestSessionControlChanges:
    def test_sign_in_frequency_loosened_is_medium(self):
        prev = [_ca_record(sign_in_frequency_category="short")]
        new = [_ca_record(sign_in_frequency_category="extended")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "sign_in_frequency_category")
        level, _ = classify_entra_change(change)
        assert level == "medium"

    def test_sign_in_frequency_tightened_is_low(self):
        prev = [_ca_record(sign_in_frequency_category="extended")]
        new = [_ca_record(sign_in_frequency_category="short")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "sign_in_frequency_category")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_unknown_sign_in_frequency_transition_never_high(self):
        prev = [_ca_record(sign_in_frequency_category="short")]
        new = [_ca_record(sign_in_frequency_category="unknown")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "sign_in_frequency_category")
        level, _ = classify_entra_change(change)
        assert level != "high"

    def test_cae_loosened_is_medium(self):
        prev = [_ca_record(continuous_access_evaluation_category="strict_enforcement")]
        new = [_ca_record(continuous_access_evaluation_category="disabled")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "continuous_access_evaluation_category")
        level, _ = classify_entra_change(change)
        assert level == "medium"


# ════════════════════════════════════════════════════════════════════════════
# Authentication strength changes
# ════════════════════════════════════════════════════════════════════════════


class TestAuthenticationStrengthChanges:
    def test_phishing_resistant_to_ordinary_mfa_is_high(self):
        prev = [_strength_record(phishing_resistance_category="phishing_resistant")]
        new = [_strength_record(phishing_resistance_category="not_phishing_resistant")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "phishing_resistance_category")
        level, _ = classify_entra_change(change)
        assert level == "high"

    def test_ordinary_mfa_to_phishing_resistant_is_low(self):
        prev = [_strength_record(phishing_resistance_category="not_phishing_resistant")]
        new = [_strength_record(phishing_resistance_category="phishing_resistant")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "phishing_resistance_category")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_passwordless_to_ordinary_mfa_is_medium(self):
        prev = [_strength_record(passwordless_category="passwordless")]
        new = [_strength_record(passwordless_category="not_passwordless")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "passwordless_category")
        level, _ = classify_entra_change(change)
        assert level == "medium"

    def test_combination_count_change_is_low(self):
        prev = [_strength_record(allowed_combination_count=2)]
        new = [_strength_record(allowed_combination_count=3)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "allowed_combination_count")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_renamed_same_id_is_low(self):
        prev = [_strength_record(display_name="Old Name")]
        new = [_strength_record(display_name="New Name")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "display_name")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_custom_strength_added_is_low(self):
        changes = compute_diff(_snap([]), _snap([_strength_record(kind_category="custom")]))
        change = next(c for c in changes if c["change_type"] == "added")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_phishing_resistant_strength_removed_is_medium(self):
        changes = compute_diff(_snap([_strength_record(phishing_resistance_category="phishing_resistant")]), _snap([]))
        change = next(c for c in changes if c["change_type"] == "removed")
        level, _ = classify_entra_change(change)
        assert level == "medium"

    def test_unknown_phishing_resistance_transition_never_high(self):
        prev = [_strength_record(phishing_resistance_category="phishing_resistant")]
        new = [_strength_record(phishing_resistance_category="unknown")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "phishing_resistance_category")
        level, _ = classify_entra_change(change)
        assert level != "high"


# ════════════════════════════════════════════════════════════════════════════
# Authentication method changes
# ════════════════════════════════════════════════════════════════════════════


class TestAuthenticationMethodChanges:
    def test_fido2_disabled_is_medium(self):
        prev = [_method_record(method_type_category="fido2", state_category="enabled")]
        new = [_method_record(method_type_category="fido2", state_category="disabled")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "state_category")
        level, reason = classify_entra_change(change)
        assert level == "medium"
        assert "does not by itself" in reason.lower() or "other methods" in reason.lower()

    def test_fido2_enabled_is_low(self):
        prev = [_method_record(method_type_category="fido2", state_category="disabled")]
        new = [_method_record(method_type_category="fido2", state_category="enabled")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "state_category")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_sms_enabled_is_medium(self):
        prev = [_method_record(method_type_category="sms", state_category="disabled")]
        new = [_method_record(method_type_category="sms", state_category="enabled")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "state_category")
        level, _ = classify_entra_change(change)
        assert level == "medium"

    def test_sms_disabled_is_low(self):
        prev = [_method_record(method_type_category="sms", state_category="enabled")]
        new = [_method_record(method_type_category="sms", state_category="disabled")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "state_category")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_voice_enabled_is_medium(self):
        prev = [_method_record(method_type_category="voice", state_category="disabled")]
        new = [_method_record(method_type_category="voice", state_category="enabled")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "state_category")
        level, _ = classify_entra_change(change)
        assert level == "medium"

    def test_microsoft_authenticator_enabled_is_medium(self):
        prev = [_method_record(method_type_category="microsoft_authenticator", state_category="disabled")]
        new = [_method_record(method_type_category="microsoft_authenticator", state_category="enabled")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "state_category")
        level, _ = classify_entra_change(change)
        assert level == "medium"

    def test_temporary_access_pass_enabled_is_medium(self):
        prev = [_method_record(method_type_category="temporary_access_pass", state_category="disabled")]
        new = [_method_record(method_type_category="temporary_access_pass", state_category="enabled")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "state_category")
        level, _ = classify_entra_change(change)
        assert level == "medium"

    def test_certificate_based_auth_disabled_is_medium(self):
        prev = [_method_record(method_type_category="certificate_based_auth", state_category="enabled")]
        new = [_method_record(method_type_category="certificate_based_auth", state_category="disabled")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "state_category")
        level, _ = classify_entra_change(change)
        assert level == "medium"

    def test_unknown_method_state_is_medium_never_high(self):
        prev = [_method_record(method_type_category="fido2", state_category="enabled")]
        new = [_method_record(method_type_category="fido2", state_category="unknown")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "state_category")
        level, _ = classify_entra_change(change)
        assert level == "medium"

    def test_method_targeting_broadened_is_medium(self):
        prev = [_method_record(target_category="selected_groups")]
        new = [_method_record(target_category="all_users")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "target_category")
        level, _ = classify_entra_change(change)
        assert level == "medium"

    def test_method_targeting_narrowed_is_low(self):
        prev = [_method_record(target_category="all_users")]
        new = [_method_record(target_category="selected_groups")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "target_category")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_single_method_disabled_never_claims_no_mfa_tenant_wide(self):
        """The classifier's reasoning text for a strong method being
        disabled must never claim the tenant overall lost MFA — only that
        this one method was disabled."""
        prev = [_method_record(method_type_category="fido2", state_category="enabled")]
        new = [_method_record(method_type_category="fido2", state_category="disabled")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "state_category")
        _, reason = classify_entra_change(change)
        assert "tenant has no mfa" not in reason.lower()
        assert "no mfa" not in reason.lower()

    def test_method_added_is_low(self):
        changes = compute_diff(_snap([]), _snap([_method_record()]))
        change = next(c for c in changes if c["change_type"] == "added")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_method_removed_is_low(self):
        changes = compute_diff(_snap([_method_record()]), _snap([]))
        change = next(c for c in changes if c["change_type"] == "removed")
        level, _ = classify_entra_change(change)
        assert level == "low"


# ════════════════════════════════════════════════════════════════════════════
# Provider metadata
# ════════════════════════════════════════════════════════════════════════════


class TestProviderMetadata:
    def test_ca_policy_metadata_has_tenant_and_policy_id(self):
        prev = [_ca_record(state_category="enabled")]
        new = [_ca_record(state_category="disabled")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "state_category")
        pm = change["provider_metadata"]
        assert pm["record_type"] == "entra_conditional_access_policy"
        assert pm["policy_id"] == "p1"
        assert pm["tenant_id"] == _TENANT

    def test_strength_metadata_has_strength_id(self):
        prev = [_strength_record(display_name="A")]
        new = [_strength_record(display_name="B")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "display_name")
        pm = change["provider_metadata"]
        assert pm["strength_id"] == "s1"

    def test_method_metadata_has_method_config_id_and_type(self):
        prev = [_method_record(state_category="enabled")]
        new = [_method_record(state_category="disabled")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "state_category")
        pm = change["provider_metadata"]
        assert pm["method_config_id"] == "Fido2"
        assert pm["method_type_category"] == "fido2"

    def test_provider_metadata_never_contains_raw_conditions(self):
        prev = [_ca_record(state_category="enabled")]
        new = [_ca_record(state_category="disabled")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "state_category")
        pm = change["provider_metadata"]
        assert "grantControls" not in pm
        assert "conditions" not in pm
