"""Microsoft Entra ID authentication policy normalization tests (Entra
message 4 of 8).

Covers ``EntraConnector._normalize_conditional_access_policy``,
``_normalize_authentication_strength``, and
``_normalize_authentication_method`` directly: policy state, targeting,
exclusions, grant controls, MFA AND/OR semantics, block posture, legacy
auth, authentication strength phishing-resistance, authentication method
taxonomy, session controls, unknown-state discipline, and sensitive-data
exclusion.
"""

from __future__ import annotations

from app.connectors.entra import EntraConnector
from app.connectors.entra_schema import (
    CA_STATE_DISABLED,
    CA_STATE_ENABLED,
    CA_STATE_REPORT_ONLY,
    CA_STATE_UNKNOWN,
    MFA_REQUIREMENT_BLOCKED,
    MFA_REQUIREMENT_NOT_REQUIRED,
    MFA_REQUIREMENT_ONE_OF_MULTIPLE,
    MFA_REQUIREMENT_REQUIRED,
    MFA_REQUIREMENT_UNKNOWN,
    NOT_PHISHING_RESISTANT,
    PHISHING_RESISTANCE_UNKNOWN,
    PHISHING_RESISTANT,
)

_TENANT = "id:t1"


# ════════════════════════════════════════════════════════════════════════════
# Conditional Access policy state
# ════════════════════════════════════════════════════════════════════════════


class TestConditionalAccessState:
    def test_enabled_state(self):
        rec = EntraConnector._normalize_conditional_access_policy(_TENANT, {"id": "p1", "state": "enabled"})
        assert rec["state_category"] == CA_STATE_ENABLED

    def test_disabled_state(self):
        rec = EntraConnector._normalize_conditional_access_policy(_TENANT, {"id": "p1", "state": "disabled"})
        assert rec["state_category"] == CA_STATE_DISABLED

    def test_report_only_state_never_treated_as_enforced(self):
        rec = EntraConnector._normalize_conditional_access_policy(
            _TENANT, {"id": "p1", "state": "enabledForReportingButNotEnforced"},
        )
        assert rec["state_category"] == CA_STATE_REPORT_ONLY
        assert rec["state_category"] != CA_STATE_ENABLED

    def test_missing_state_is_unknown(self):
        rec = EntraConnector._normalize_conditional_access_policy(_TENANT, {"id": "p1"})
        assert rec["state_category"] == CA_STATE_UNKNOWN

    def test_malformed_state_is_unknown(self):
        rec = EntraConnector._normalize_conditional_access_policy(_TENANT, {"id": "p1", "state": 12345})
        assert rec["state_category"] == CA_STATE_UNKNOWN

    def test_unrecognized_state_string_is_unknown(self):
        rec = EntraConnector._normalize_conditional_access_policy(_TENANT, {"id": "p1", "state": "somethingNew"})
        assert rec["state_category"] == CA_STATE_UNKNOWN

    def test_stable_record_id_uses_tenant_and_policy_id(self):
        rec = EntraConnector._normalize_conditional_access_policy(_TENANT, {"id": "p1", "displayName": "X"})
        assert rec["record_id"] == f"{_TENANT}/conditional_access_policy/p1"
        assert rec["provider_resource_id"] == "identity/conditionalAccess/policies/p1"

    def test_missing_id_returns_none(self):
        assert EntraConnector._normalize_conditional_access_policy(_TENANT, {"displayName": "X"}) is None

    def test_rename_preserves_stable_id(self):
        rec1 = EntraConnector._normalize_conditional_access_policy(_TENANT, {"id": "p1", "displayName": "Old Name"})
        rec2 = EntraConnector._normalize_conditional_access_policy(_TENANT, {"id": "p1", "displayName": "New Name"})
        assert rec1["record_id"] == rec2["record_id"]
        assert rec1["display_name"] != rec2["display_name"]


# ════════════════════════════════════════════════════════════════════════════
# Targeting
# ════════════════════════════════════════════════════════════════════════════


class TestConditionalAccessTargeting:
    def test_all_users_targeting(self):
        rec = EntraConnector._normalize_conditional_access_policy(
            _TENANT, {"id": "p1", "conditions": {"users": {"includeUsers": ["All"]}}},
        )
        assert rec["user_target_category"] == "all_users"

    def test_selected_users_targeting(self):
        rec = EntraConnector._normalize_conditional_access_policy(
            _TENANT, {"id": "p1", "conditions": {"users": {"includeUsers": ["u1", "u2"]}}},
        )
        assert rec["user_target_category"] == "selected_users"
        assert rec["include_user_count"] == 2

    def test_selected_groups_targeting(self):
        rec = EntraConnector._normalize_conditional_access_policy(
            _TENANT, {"id": "p1", "conditions": {"users": {"includeGroups": ["g1"]}}},
        )
        assert rec["user_target_category"] == "selected_groups"
        assert rec["include_group_count"] == 1

    def test_directory_roles_targeting(self):
        rec = EntraConnector._normalize_conditional_access_policy(
            _TENANT, {"id": "p1", "conditions": {"users": {"includeRoles": ["r1"]}}},
        )
        assert rec["user_target_category"] == "directory_roles"

    def test_guests_targeting(self):
        rec = EntraConnector._normalize_conditional_access_policy(
            _TENANT, {"id": "p1", "conditions": {"users": {"includeGuestsOrExternalUsers": {"guestOrExternalUserTypes": "b2b"}}}},
        )
        assert rec["user_target_category"] == "guests_external_users"

    def test_missing_users_block_is_unknown_not_all_users(self):
        rec = EntraConnector._normalize_conditional_access_policy(_TENANT, {"id": "p1", "conditions": {}})
        assert rec["user_target_category"] == "unknown"

    def test_exclusions_counted(self):
        rec = EntraConnector._normalize_conditional_access_policy(
            _TENANT,
            {
                "id": "p1",
                "conditions": {"users": {"includeUsers": ["All"], "excludeUsers": ["u1", "u2"], "excludeGroups": ["g1"]}},
            },
        )
        assert rec["exclude_user_count"] == 2
        assert rec["exclude_group_count"] == 1

    def test_guests_excluded_flag(self):
        rec = EntraConnector._normalize_conditional_access_policy(
            _TENANT, {"id": "p1", "conditions": {"users": {"excludeGuestsOrExternalUsers": {"guestOrExternalUserTypes": "b2b"}}}},
        )
        assert rec["guests_excluded"] is True

    def test_break_glass_naming_not_inferred_as_safe(self):
        """Exclusion presence is never treated as unsafe or safe based on
        naming — this connector never even reads display names of excluded
        principals (only counts), so there is nothing to infer from."""
        rec = EntraConnector._normalize_conditional_access_policy(
            _TENANT,
            {"id": "p1", "conditions": {"users": {"includeUsers": ["All"], "excludeUsers": ["emergency-access-1"]}}},
        )
        assert rec["exclude_user_count"] == 1
        assert "emergency-access-1" not in str(rec)

    def test_app_targeting_all_cloud_apps(self):
        rec = EntraConnector._normalize_conditional_access_policy(
            _TENANT, {"id": "p1", "conditions": {"applications": {"includeApplications": ["All"]}}},
        )
        assert rec["app_target_category"] == "all_cloud_apps"

    def test_app_targeting_selected_apps(self):
        rec = EntraConnector._normalize_conditional_access_policy(
            _TENANT, {"id": "p1", "conditions": {"applications": {"includeApplications": ["app1"]}}},
        )
        assert rec["app_target_category"] == "selected_apps"
        assert rec["include_app_count"] == 1

    def test_app_targeting_user_actions(self):
        rec = EntraConnector._normalize_conditional_access_policy(
            _TENANT, {"id": "p1", "conditions": {"applications": {"includeUserActions": ["urn:user:registersecurityinfo"]}}},
        )
        assert rec["app_target_category"] == "user_actions"

    def test_app_targeting_authentication_context(self):
        rec = EntraConnector._normalize_conditional_access_policy(
            _TENANT, {"id": "p1", "conditions": {"applications": {"includeAuthenticationContextClassReferences": ["c1"]}}},
        )
        assert rec["app_target_category"] == "authentication_context"

    def test_coverage_all_users_all_apps(self):
        rec = EntraConnector._normalize_conditional_access_policy(
            _TENANT,
            {
                "id": "p1",
                "conditions": {"users": {"includeUsers": ["All"]}, "applications": {"includeApplications": ["All"]}},
            },
        )
        assert rec["coverage_category"] == "all_users_all_apps"

    def test_coverage_selected_principals_selected_apps(self):
        rec = EntraConnector._normalize_conditional_access_policy(
            _TENANT,
            {
                "id": "p1",
                "conditions": {"users": {"includeGroups": ["g1"]}, "applications": {"includeApplications": ["app1"]}},
            },
        )
        assert rec["coverage_category"] == "selected_principals_selected_apps"

    def test_coverage_guests_category(self):
        rec = EntraConnector._normalize_conditional_access_policy(
            _TENANT,
            {"id": "p1", "conditions": {"users": {"includeGuestsOrExternalUsers": {"guestOrExternalUserTypes": "b2b"}}}},
        )
        assert rec["coverage_category"] == "guests"

    def test_device_platform_categories(self):
        rec = EntraConnector._normalize_conditional_access_policy(
            _TENANT, {"id": "p1", "conditions": {"platforms": {"includePlatforms": ["android", "iOS"]}}},
        )
        assert rec["device_platform_categories"] == ["android", "iOS"]

    def test_missing_platforms_is_unknown(self):
        rec = EntraConnector._normalize_conditional_access_policy(_TENANT, {"id": "p1"})
        assert rec["device_platform_categories"] == ["unknown"]

    def test_location_targeting_all(self):
        rec = EntraConnector._normalize_conditional_access_policy(
            _TENANT, {"id": "p1", "conditions": {"locations": {"includeLocations": ["All"]}}},
        )
        assert rec["location_target_category"] == "all"

    def test_location_targeting_all_trusted(self):
        rec = EntraConnector._normalize_conditional_access_policy(
            _TENANT, {"id": "p1", "conditions": {"locations": {"includeLocations": ["AllTrusted"]}}},
        )
        assert rec["location_target_category"] == "all_trusted"

    def test_location_targeting_never_exposes_ip_ranges(self):
        """Named-location targeting is categorized without ever reading or
        persisting IP range data — this connector never fetches named
        location objects, only the CA policy's location ID references."""
        rec = EntraConnector._normalize_conditional_access_policy(
            _TENANT, {"id": "p1", "conditions": {"locations": {"includeLocations": ["loc-guid-1"]}}},
        )
        assert rec["location_target_category"] == "selected"
        assert "loc-guid-1" not in str(rec)


# ════════════════════════════════════════════════════════════════════════════
# Client app types / legacy auth
# ════════════════════════════════════════════════════════════════════════════


class TestClientAppTypesAndLegacyAuth:
    def test_legacy_auth_targeted_via_exchange_activesync(self):
        rec = EntraConnector._normalize_conditional_access_policy(
            _TENANT, {"id": "p1", "conditions": {"clientAppTypes": ["exchangeActiveSync"]}},
        )
        assert rec["legacy_auth_targeted"] is True

    def test_legacy_auth_targeted_via_other(self):
        rec = EntraConnector._normalize_conditional_access_policy(
            _TENANT, {"id": "p1", "conditions": {"clientAppTypes": ["other"]}},
        )
        assert rec["legacy_auth_targeted"] is True

    def test_browser_only_is_not_legacy_auth_targeted(self):
        rec = EntraConnector._normalize_conditional_access_policy(
            _TENANT, {"id": "p1", "conditions": {"clientAppTypes": ["browser"]}},
        )
        assert rec["legacy_auth_targeted"] is False

    def test_missing_client_app_types_never_inferred_as_legacy_targeted(self):
        """An absent clientAppTypes condition means 'all client app types'
        (a superset including but not limited to legacy auth) — this must
        never be reported as EXPLICITLY targeting legacy auth."""
        rec = EntraConnector._normalize_conditional_access_policy(_TENANT, {"id": "p1"})
        assert rec["legacy_auth_targeted"] is False
        assert rec["client_app_type_categories"] == ["unknown"]


# ════════════════════════════════════════════════════════════════════════════
# Grant controls / MFA semantics
# ════════════════════════════════════════════════════════════════════════════


class TestGrantControlsAndMfaSemantics:
    def test_mfa_required_with_and_operator(self):
        rec = EntraConnector._normalize_conditional_access_policy(
            _TENANT, {"id": "p1", "grantControls": {"operator": "AND", "builtInControls": ["mfa", "compliantDevice"]}},
        )
        assert rec["mfa_requirement_category"] == MFA_REQUIREMENT_REQUIRED
        assert rec["compliant_device_required"] is True

    def test_mfa_one_of_multiple_with_or_operator_never_flattened_to_required(self):
        rec = EntraConnector._normalize_conditional_access_policy(
            _TENANT, {"id": "p1", "grantControls": {"operator": "OR", "builtInControls": ["mfa", "compliantDevice"]}},
        )
        assert rec["mfa_requirement_category"] == MFA_REQUIREMENT_ONE_OF_MULTIPLE
        assert rec["mfa_requirement_category"] != MFA_REQUIREMENT_REQUIRED

    def test_mfa_required_single_control(self):
        rec = EntraConnector._normalize_conditional_access_policy(
            _TENANT, {"id": "p1", "grantControls": {"operator": "OR", "builtInControls": ["mfa"]}},
        )
        assert rec["mfa_requirement_category"] == MFA_REQUIREMENT_REQUIRED

    def test_mfa_not_required_when_absent(self):
        rec = EntraConnector._normalize_conditional_access_policy(
            _TENANT, {"id": "p1", "grantControls": {"operator": "AND", "builtInControls": ["compliantDevice"]}},
        )
        assert rec["mfa_requirement_category"] == MFA_REQUIREMENT_NOT_REQUIRED

    def test_mfa_unknown_when_operator_unknown_and_multiple_controls(self):
        rec = EntraConnector._normalize_conditional_access_policy(
            _TENANT, {"id": "p1", "grantControls": {"builtInControls": ["mfa", "compliantDevice"]}},
        )
        assert rec["mfa_requirement_category"] == MFA_REQUIREMENT_UNKNOWN

    def test_mfa_unknown_when_grant_controls_missing(self):
        rec = EntraConnector._normalize_conditional_access_policy(_TENANT, {"id": "p1"})
        assert rec["mfa_requirement_category"] == MFA_REQUIREMENT_UNKNOWN

    def test_block_access_true(self):
        rec = EntraConnector._normalize_conditional_access_policy(
            _TENANT, {"id": "p1", "grantControls": {"operator": "OR", "builtInControls": ["block"]}},
        )
        assert rec["block_access"] is True
        assert rec["mfa_requirement_category"] == MFA_REQUIREMENT_BLOCKED

    def test_authentication_strength_reference_captured(self):
        rec = EntraConnector._normalize_conditional_access_policy(
            _TENANT,
            {"id": "p1", "grantControls": {"operator": "AND", "builtInControls": ["authenticationStrength"], "authenticationStrength": {"id": "s1"}}},
        )
        assert rec["authentication_strength_id"] == "s1"
        assert rec["authentication_strength_referenced"] is True

    def test_no_authentication_strength_reference(self):
        rec = EntraConnector._normalize_conditional_access_policy(_TENANT, {"id": "p1"})
        assert rec["authentication_strength_id"] is None
        assert rec["authentication_strength_referenced"] is False

    def test_hybrid_joined_device_required(self):
        rec = EntraConnector._normalize_conditional_access_policy(
            _TENANT, {"id": "p1", "grantControls": {"operator": "AND", "builtInControls": ["domainJoinedDevice"]}},
        )
        assert rec["hybrid_joined_device_required"] is True

    def test_approved_and_compliant_application_required(self):
        rec = EntraConnector._normalize_conditional_access_policy(
            _TENANT, {"id": "p1", "grantControls": {"operator": "OR", "builtInControls": ["approvedApplication", "compliantApplication"]}},
        )
        assert rec["approved_application_required"] is True
        assert rec["compliant_application_required"] is True

    def test_raw_grant_controls_never_persisted(self):
        rec = EntraConnector._normalize_conditional_access_policy(
            _TENANT, {"id": "p1", "grantControls": {"operator": "AND", "builtInControls": ["mfa"], "customAuthenticationFactors": ["secret-thing"]}},
        )
        assert "customAuthenticationFactors" not in str(rec)
        assert "grantControls" not in rec


# ════════════════════════════════════════════════════════════════════════════
# Risk levels
# ════════════════════════════════════════════════════════════════════════════


class TestRiskLevels:
    def test_user_risk_levels_normalized(self):
        rec = EntraConnector._normalize_conditional_access_policy(
            _TENANT, {"id": "p1", "conditions": {"userRiskLevels": ["high", "medium"]}},
        )
        assert rec["user_risk_level_categories"] == ["high", "medium"]

    def test_missing_risk_levels_is_unknown(self):
        rec = EntraConnector._normalize_conditional_access_policy(_TENANT, {"id": "p1"})
        assert rec["sign_in_risk_level_categories"] == ["unknown"]

    def test_unrecognized_risk_value_stays_unknown(self):
        rec = EntraConnector._normalize_conditional_access_policy(
            _TENANT, {"id": "p1", "conditions": {"userRiskLevels": ["totallyNewValue"]}},
        )
        assert rec["user_risk_level_categories"] == ["unknown"]


# ════════════════════════════════════════════════════════════════════════════
# Session controls
# ════════════════════════════════════════════════════════════════════════════


class TestSessionControls:
    def test_sign_in_frequency_hours(self):
        rec = EntraConnector._normalize_conditional_access_policy(
            _TENANT, {"id": "p1", "sessionControls": {"signInFrequency": {"isEnabled": True, "type": "hours", "value": 4}}},
        )
        assert rec["sign_in_frequency_enabled"] is True
        assert rec["sign_in_frequency_category"] == "short"

    def test_sign_in_frequency_every_time(self):
        rec = EntraConnector._normalize_conditional_access_policy(
            _TENANT,
            {"id": "p1", "sessionControls": {"signInFrequency": {"isEnabled": True, "frequencyInterval": "everyTime"}}},
        )
        assert rec["sign_in_frequency_category"] == "every_time"

    def test_sign_in_frequency_disabled_is_unknown(self):
        rec = EntraConnector._normalize_conditional_access_policy(
            _TENANT, {"id": "p1", "sessionControls": {"signInFrequency": {"isEnabled": False}}},
        )
        assert rec["sign_in_frequency_category"] == "unknown"
        assert rec["sign_in_frequency_enabled"] is False

    def test_persistent_browser_always(self):
        rec = EntraConnector._normalize_conditional_access_policy(
            _TENANT, {"id": "p1", "sessionControls": {"persistentBrowser": {"isEnabled": True, "mode": "always"}}},
        )
        assert rec["persistent_browser_category"] == "always"

    def test_persistent_browser_missing_is_unknown(self):
        rec = EntraConnector._normalize_conditional_access_policy(_TENANT, {"id": "p1"})
        assert rec["persistent_browser_category"] == "unknown"

    def test_cae_strict_enforcement(self):
        rec = EntraConnector._normalize_conditional_access_policy(
            _TENANT, {"id": "p1", "sessionControls": {"continuousAccessEvaluation": {"mode": "strictEnforcement"}}},
        )
        assert rec["continuous_access_evaluation_category"] == "strict_enforcement"

    def test_app_enforced_restrictions_missing_is_none(self):
        rec = EntraConnector._normalize_conditional_access_policy(_TENANT, {"id": "p1"})
        assert rec["app_enforced_restrictions_enabled"] is None

    def test_app_enforced_restrictions_true(self):
        rec = EntraConnector._normalize_conditional_access_policy(
            _TENANT, {"id": "p1", "sessionControls": {"applicationEnforcedRestrictions": {"isEnabled": True}}},
        )
        assert rec["app_enforced_restrictions_enabled"] is True

    def test_raw_session_controls_never_persisted(self):
        rec = EntraConnector._normalize_conditional_access_policy(
            _TENANT, {"id": "p1", "sessionControls": {"signInFrequency": {"isEnabled": True, "type": "hours", "value": 1}}},
        )
        assert "sessionControls" not in rec


# ════════════════════════════════════════════════════════════════════════════
# Authentication strength normalization
# ════════════════════════════════════════════════════════════════════════════


class TestAuthenticationStrengthNormalization:
    def test_built_in_via_policy_type(self):
        rec = EntraConnector._normalize_authentication_strength(_TENANT, {"id": "s1", "policyType": "builtIn"})
        assert rec["kind_category"] == "built_in"

    def test_custom_via_policy_type(self):
        rec = EntraConnector._normalize_authentication_strength(_TENANT, {"id": "s1", "policyType": "custom"})
        assert rec["kind_category"] == "custom"

    def test_built_in_via_well_known_id_fallback(self):
        rec = EntraConnector._normalize_authentication_strength(
            _TENANT, {"id": "00000000-0000-0000-0000-000000000004"},
        )
        assert rec["kind_category"] == "built_in"

    def test_missing_policy_type_and_unknown_id_is_unknown(self):
        rec = EntraConnector._normalize_authentication_strength(_TENANT, {"id": "s1"})
        assert rec["kind_category"] == "unknown"

    def test_phishing_resistant_when_all_combos_qualify(self):
        rec = EntraConnector._normalize_authentication_strength(
            _TENANT, {"id": "s1", "allowedCombinations": ["fido2", "windowsHelloForBusiness"]},
        )
        assert rec["phishing_resistance_category"] == PHISHING_RESISTANT

    def test_not_phishing_resistant_when_any_combo_is_weak(self):
        rec = EntraConnector._normalize_authentication_strength(
            _TENANT, {"id": "s1", "allowedCombinations": ["fido2", "password,sms"]},
        )
        assert rec["phishing_resistance_category"] == NOT_PHISHING_RESISTANT

    def test_phishing_resistance_unknown_when_combos_missing(self):
        rec = EntraConnector._normalize_authentication_strength(_TENANT, {"id": "s1"})
        assert rec["phishing_resistance_category"] == PHISHING_RESISTANCE_UNKNOWN

    def test_sms_never_classified_phishing_resistant(self):
        rec = EntraConnector._normalize_authentication_strength(
            _TENANT, {"id": "s1", "allowedCombinations": ["sms"]},
        )
        assert rec["phishing_resistance_category"] == NOT_PHISHING_RESISTANT

    def test_passwordless_category(self):
        rec = EntraConnector._normalize_authentication_strength(
            _TENANT, {"id": "s1", "allowedCombinations": ["fido2"]},
        )
        assert rec["passwordless_category"] == "passwordless"

    def test_combination_count_bounded(self):
        rec = EntraConnector._normalize_authentication_strength(
            _TENANT, {"id": "s1", "allowedCombinations": ["fido2", "windowsHelloForBusiness", "sms"]},
        )
        assert rec["allowed_combination_count"] == 3

    def test_raw_combinations_never_persisted(self):
        rec = EntraConnector._normalize_authentication_strength(
            _TENANT, {"id": "s1", "allowedCombinations": ["fido2"]},
        )
        assert "allowedCombinations" not in rec
        assert "allowed_combinations" not in rec

    def test_mfa_capability_category(self):
        rec = EntraConnector._normalize_authentication_strength(
            _TENANT, {"id": "s1", "allowedCombinations": ["password,sms"]},
        )
        assert rec["mfa_capability_category"] == "mfa_capable"

    def test_missing_id_returns_none(self):
        assert EntraConnector._normalize_authentication_strength(_TENANT, {"displayName": "X"}) is None

    def test_stable_record_id(self):
        rec = EntraConnector._normalize_authentication_strength(_TENANT, {"id": "s1"})
        assert rec["record_id"] == f"{_TENANT}/authentication_strength/s1"


# ════════════════════════════════════════════════════════════════════════════
# Authentication method normalization
# ════════════════════════════════════════════════════════════════════════════


class TestAuthenticationMethodNormalization:
    def test_fido2_type_and_phishing_resistant(self):
        rec = EntraConnector._normalize_authentication_method(_TENANT, {"id": "Fido2", "state": "enabled"})
        assert rec["method_type_category"] == "fido2"
        assert rec["phishing_resistance_category"] == PHISHING_RESISTANT

    def test_sms_type_never_phishing_resistant(self):
        rec = EntraConnector._normalize_authentication_method(_TENANT, {"id": "Sms", "state": "enabled"})
        assert rec["method_type_category"] == "sms"
        assert rec["phishing_resistance_category"] == NOT_PHISHING_RESISTANT

    def test_voice_type(self):
        rec = EntraConnector._normalize_authentication_method(_TENANT, {"id": "Voice"})
        assert rec["method_type_category"] == "voice"

    def test_microsoft_authenticator_type(self):
        rec = EntraConnector._normalize_authentication_method(_TENANT, {"id": "MicrosoftAuthenticator"})
        assert rec["method_type_category"] == "microsoft_authenticator"

    def test_temporary_access_pass_type(self):
        rec = EntraConnector._normalize_authentication_method(_TENANT, {"id": "TemporaryAccessPass"})
        assert rec["method_type_category"] == "temporary_access_pass"

    def test_software_oath_type(self):
        rec = EntraConnector._normalize_authentication_method(_TENANT, {"id": "SoftwareOath"})
        assert rec["method_type_category"] == "software_oath"

    def test_certificate_based_auth_type_is_phishing_resistant(self):
        rec = EntraConnector._normalize_authentication_method(_TENANT, {"id": "X509Certificate"})
        assert rec["method_type_category"] == "certificate_based_auth"
        assert rec["phishing_resistance_category"] == PHISHING_RESISTANT

    def test_email_otp_type(self):
        rec = EntraConnector._normalize_authentication_method(_TENANT, {"id": "Email"})
        assert rec["method_type_category"] == "email_otp"

    def test_unrecognized_config_id_is_unknown(self):
        rec = EntraConnector._normalize_authentication_method(_TENANT, {"id": "SomeFutureMethod"})
        assert rec["method_type_category"] == "unknown"
        assert rec["phishing_resistance_category"] == PHISHING_RESISTANCE_UNKNOWN

    def test_state_enabled(self):
        rec = EntraConnector._normalize_authentication_method(_TENANT, {"id": "Fido2", "state": "enabled"})
        assert rec["state_category"] == "enabled"

    def test_state_disabled(self):
        rec = EntraConnector._normalize_authentication_method(_TENANT, {"id": "Fido2", "state": "disabled"})
        assert rec["state_category"] == "disabled"

    def test_state_missing_is_unknown_not_disabled(self):
        rec = EntraConnector._normalize_authentication_method(_TENANT, {"id": "Fido2"})
        assert rec["state_category"] == "unknown"

    def test_targeting_all_users(self):
        rec = EntraConnector._normalize_authentication_method(
            _TENANT, {"id": "Fido2", "includeTargets": [{"id": "all_users"}]},
        )
        assert rec["target_category"] == "all_users"
        assert rec["include_target_count"] == 1

    def test_targeting_selected_groups(self):
        rec = EntraConnector._normalize_authentication_method(
            _TENANT, {"id": "Fido2", "includeTargets": [{"id": "group-guid-1"}]},
        )
        assert rec["target_category"] == "selected_groups"

    def test_targeting_missing_is_unknown(self):
        rec = EntraConnector._normalize_authentication_method(_TENANT, {"id": "Fido2"})
        assert rec["target_category"] == "unknown"

    def test_target_ids_never_persisted_raw(self):
        rec = EntraConnector._normalize_authentication_method(
            _TENANT, {"id": "Fido2", "includeTargets": [{"id": "group-guid-1"}], "excludeTargets": [{"id": "group-guid-2"}]},
        )
        assert "group-guid-1" not in str(rec)
        assert "group-guid-2" not in str(rec)
        assert rec["include_target_count"] == 1
        assert rec["exclude_target_count"] == 1

    def test_missing_id_returns_none(self):
        assert EntraConnector._normalize_authentication_method(_TENANT, {"state": "enabled"}) is None

    def test_stable_record_id(self):
        rec = EntraConnector._normalize_authentication_method(_TENANT, {"id": "Fido2"})
        assert rec["record_id"] == f"{_TENANT}/authentication_method/Fido2"


# ════════════════════════════════════════════════════════════════════════════
# Sensitive-data exclusion (cross-cutting)
# ════════════════════════════════════════════════════════════════════════════


class TestSensitiveDataExclusion:
    def test_ca_policy_never_persists_secrets_or_tokens(self):
        rec = EntraConnector._normalize_conditional_access_policy(
            _TENANT,
            {
                "id": "p1",
                "displayName": "X",
                "grantControls": {"operator": "AND", "builtInControls": ["mfa"]},
            },
        )
        blob = str(rec).lower()
        for forbidden in ("secret", "private_key", "certificate", "phonenumber", "access_token", "temporaryaccesspass"):
            assert forbidden not in blob

    def test_authentication_method_never_persists_secrets(self):
        rec = EntraConnector._normalize_authentication_method(_TENANT, {"id": "TemporaryAccessPass", "state": "enabled"})
        blob = str(rec).lower()
        for forbidden in ("defaultlifetimeinminutes", "onetimetantoken", "secret"):
            assert forbidden not in blob
