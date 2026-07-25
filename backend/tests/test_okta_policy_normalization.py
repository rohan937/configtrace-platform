"""Okta authentication policy normalization tests (Okta message 4 of 8).

Covers ``OktaConnector._normalize_policy`` / ``_normalize_policy_rule`` /
``_normalize_authenticator`` in isolation: every policy type, MFA
requirement taxonomy, assurance/phishing-resistance posture, password
posture, authenticator taxonomy, unknown-state discipline, and the
sensitive-data exclusion boundary.
"""

from __future__ import annotations

import pytest

from app.connectors.okta import OktaConnector
from app.connectors.okta_schema import (
    ACCESS_CATEGORY_ALLOW,
    ACCESS_CATEGORY_DENY,
    ACCESS_CATEGORY_UNKNOWN,
    AUTHENTICATOR_KEY_EMAIL,
    AUTHENTICATOR_KEY_OKTA_VERIFY,
    AUTHENTICATOR_KEY_PASSWORD,
    AUTHENTICATOR_KEY_PHONE_NUMBER,
    AUTHENTICATOR_KEY_SECURITY_QUESTION,
    AUTHENTICATOR_KEY_SMART_CARD_IDP,
    AUTHENTICATOR_KEY_UNKNOWN,
    AUTHENTICATOR_KEY_WEBAUTHN,
    MFA_REQUIREMENT_NONE,
    MFA_REQUIREMENT_REQUIRED,
    MFA_REQUIREMENT_REQUIRED_EVERY_SIGNIN,
    MFA_REQUIREMENT_REQUIRED_PER_SESSION,
    MFA_REQUIREMENT_UNKNOWN,
    NOT_PHISHING_RESISTANT,
    PASSWORD_STRENGTH_BASELINE,
    PASSWORD_STRENGTH_STRONG,
    PASSWORD_STRENGTH_UNKNOWN,
    PASSWORD_STRENGTH_WEAK,
    PHISHING_RESISTANCE_UNKNOWN,
    PHISHING_RESISTANT,
    POLICY_TYPE_ACCESS_POLICY,
    POLICY_TYPE_IDP_DISCOVERY,
    POLICY_TYPE_MFA_ENROLL,
    POLICY_TYPE_OKTA_SIGN_ON,
    POLICY_TYPE_PASSWORD,
    POLICY_TYPE_PROFILE_ENROLLMENT,
    POLICY_TYPE_UNKNOWN,
    SCOPE_ALL_USERS,
    SCOPE_SCOPED_GROUPS,
    SCOPE_SCOPED_USERS,
    SCOPE_UNKNOWN,
    SESSION_LIFETIME_EXTENDED,
    SESSION_LIFETIME_SHORT,
    SESSION_LIFETIME_STANDARD,
    SESSION_LIFETIME_UNKNOWN,
    SESSION_LIFETIME_VERY_SHORT,
    categorize_access,
    categorize_authenticator_key,
    categorize_password_min_length,
    categorize_policy_type,
    categorize_scope,
    categorize_session_lifetime_minutes,
    is_knowledge_authenticator,
    is_possession_authenticator,
    mfa_requirement_from_signon_actions,
    mfa_requirement_from_verification_method,
    parse_iso8601_duration_to_minutes,
    phishing_resistance_for_authenticator_key,
    phishing_resistance_from_possession_constraint,
)

_TENANT = "id:t1"


def _policy(**overrides) -> dict:
    base = {"id": "p1", "name": "Default Policy", "type": "OKTA_SIGN_ON", "status": "ACTIVE", "priority": 1}
    base.update(overrides)
    return base


def _password_policy(**overrides) -> dict:
    base = {
        "id": "pw1", "name": "Password Policy", "type": "PASSWORD", "status": "ACTIVE", "priority": 1,
        "settings": {"password": {
            "complexity": {"minLength": 12, "minLowerCase": 1, "minUpperCase": 1, "minNumber": 1, "minSymbol": 0,
                           "excludeUsername": True, "dictionary": {"common": {"exclude": True}}},
            "age": {"maxAgeDays": 90, "minAgeMinutes": 0, "historyCount": 4},
            "lockout": {"maxAttempts": 5},
        }},
    }
    base.update(overrides)
    return base


def _rule(**overrides) -> dict:
    base = {
        "id": "r1", "name": "Catch-all", "status": "ACTIVE", "priority": 1,
        "conditions": {"people": {"groups": {"include": []}}},
        "actions": {"signon": {"access": "ALLOW", "requireFactor": True}},
    }
    base.update(overrides)
    return base


def _authenticator(**overrides) -> dict:
    base = {"id": "a1", "key": "okta_verify", "type": "app", "name": "Okta Verify", "status": "ACTIVE"}
    base.update(overrides)
    return base


_POLICY_REC = OktaConnector._normalize_policy(_TENANT, _policy(), rule_count=0)


# ════════════════════════════════════════════════════════════════════════════
# Policy type taxonomy
# ════════════════════════════════════════════════════════════════════════════


class TestPolicyTypeTaxonomy:
    @pytest.mark.parametrize("raw_type,expected", [
        ("OKTA_SIGN_ON", POLICY_TYPE_OKTA_SIGN_ON),
        ("PASSWORD", POLICY_TYPE_PASSWORD),
        ("MFA_ENROLL", POLICY_TYPE_MFA_ENROLL),
        ("ACCESS_POLICY", POLICY_TYPE_ACCESS_POLICY),
        ("PROFILE_ENROLLMENT", POLICY_TYPE_PROFILE_ENROLLMENT),
        ("IDP_DISCOVERY", POLICY_TYPE_IDP_DISCOVERY),
    ])
    def test_every_known_type(self, raw_type, expected):
        assert categorize_policy_type(raw_type) == expected

    def test_unknown_policy_type(self):
        assert categorize_policy_type("SOME_FUTURE_TYPE") == POLICY_TYPE_UNKNOWN

    def test_none_policy_type(self):
        assert categorize_policy_type(None) == POLICY_TYPE_UNKNOWN

    def test_unknown_type_not_fabricated_password_fields(self):
        rec = OktaConnector._normalize_policy(_TENANT, _policy(type="SOME_FUTURE_TYPE"), rule_count=0)
        assert rec["policy_type"] == POLICY_TYPE_UNKNOWN
        assert "password_min_length" not in rec


class TestPolicyRename:
    def test_policy_renamed_same_id(self):
        rec1 = OktaConnector._normalize_policy(_TENANT, _policy(name="Old"), rule_count=0)
        rec2 = OktaConnector._normalize_policy(_TENANT, _policy(name="New"), rule_count=0)
        assert rec1["record_id"] == rec2["record_id"]
        assert rec1["policy_name"] != rec2["policy_name"]

    def test_policy_activated(self):
        rec = OktaConnector._normalize_policy(_TENANT, _policy(status="ACTIVE"), rule_count=0)
        assert rec["active"] is True

    def test_policy_deactivated(self):
        rec = OktaConnector._normalize_policy(_TENANT, _policy(status="INACTIVE"), rule_count=0)
        assert rec["active"] is False

    def test_missing_policy_id_returns_none(self):
        assert OktaConnector._normalize_policy(_TENANT, {"status": "ACTIVE"}, rule_count=0) is None


# ════════════════════════════════════════════════════════════════════════════
# Sign-on rule access / MFA taxonomy
# ════════════════════════════════════════════════════════════════════════════


class TestAccessCategory:
    def test_allow(self):
        assert categorize_access("ALLOW") == ACCESS_CATEGORY_ALLOW

    def test_deny(self):
        assert categorize_access("DENY") == ACCESS_CATEGORY_DENY

    def test_unknown(self):
        assert categorize_access("SOMETHING_NEW") == ACCESS_CATEGORY_UNKNOWN

    def test_none(self):
        assert categorize_access(None) == ACCESS_CATEGORY_UNKNOWN


class TestMfaRequirementTaxonomy:
    def test_mfa_required_every_signin(self):
        actions = {"signon": {"requireFactor": True, "factorPromptMode": "ALWAYS"}}
        assert mfa_requirement_from_signon_actions(actions) == MFA_REQUIREMENT_REQUIRED_EVERY_SIGNIN

    def test_mfa_required_per_session(self):
        actions = {"signon": {"requireFactor": True, "factorPromptMode": "SESSION"}}
        assert mfa_requirement_from_signon_actions(actions) == MFA_REQUIREMENT_REQUIRED_PER_SESSION

    def test_mfa_required_per_device(self):
        actions = {"signon": {"requireFactor": True, "factorPromptMode": "DEVICE"}}
        assert mfa_requirement_from_signon_actions(actions) == MFA_REQUIREMENT_REQUIRED_PER_SESSION

    def test_mfa_required_no_prompt_mode(self):
        actions = {"signon": {"requireFactor": True}}
        assert mfa_requirement_from_signon_actions(actions) == MFA_REQUIREMENT_REQUIRED

    def test_mfa_none(self):
        actions = {"signon": {"requireFactor": False}}
        assert mfa_requirement_from_signon_actions(actions) == MFA_REQUIREMENT_NONE

    def test_mfa_unknown_when_require_factor_absent(self):
        assert mfa_requirement_from_signon_actions({"signon": {}}) == MFA_REQUIREMENT_UNKNOWN

    def test_mfa_unknown_when_signon_absent(self):
        assert mfa_requirement_from_signon_actions({}) == MFA_REQUIREMENT_UNKNOWN

    def test_mfa_unknown_when_require_factor_not_bool(self):
        assert mfa_requirement_from_signon_actions({"signon": {"requireFactor": "yes"}}) == MFA_REQUIREMENT_UNKNOWN

    def test_verification_method_2fa(self):
        assert mfa_requirement_from_verification_method({"factorMode": "2FA"}) == MFA_REQUIREMENT_REQUIRED

    def test_verification_method_1fa(self):
        assert mfa_requirement_from_verification_method({"factorMode": "1FA"}) == MFA_REQUIREMENT_NONE

    def test_verification_method_unknown(self):
        assert mfa_requirement_from_verification_method({"factorMode": "3FA"}) == MFA_REQUIREMENT_UNKNOWN
        assert mfa_requirement_from_verification_method({}) == MFA_REQUIREMENT_UNKNOWN


class TestSignOnRuleFullNormalization:
    def test_allow(self):
        rec = OktaConnector._normalize_policy_rule(_TENANT, _POLICY_REC, _rule(
            actions={"signon": {"access": "ALLOW", "requireFactor": True}}
        ))
        assert rec["access_category"] == ACCESS_CATEGORY_ALLOW

    def test_deny(self):
        rec = OktaConnector._normalize_policy_rule(_TENANT, _POLICY_REC, _rule(
            actions={"signon": {"access": "DENY"}}
        ))
        assert rec["access_category"] == ACCESS_CATEGORY_DENY

    def test_mfa_required(self):
        rec = OktaConnector._normalize_policy_rule(_TENANT, _POLICY_REC, _rule(
            actions={"signon": {"access": "ALLOW", "requireFactor": True}}
        ))
        assert rec["mfa_requirement_category"] == MFA_REQUIREMENT_REQUIRED

    def test_mfa_none(self):
        rec = OktaConnector._normalize_policy_rule(_TENANT, _POLICY_REC, _rule(
            actions={"signon": {"access": "ALLOW", "requireFactor": False}}
        ))
        assert rec["mfa_requirement_category"] == MFA_REQUIREMENT_NONE

    def test_possession_and_knowledge_from_verification_method(self):
        rec = OktaConnector._normalize_policy_rule(_TENANT, _POLICY_REC, _rule(actions={
            "appSignOn": {
                "access": "ALLOW",
                "verificationMethod": {
                    "type": "ASSURANCE", "factorMode": "2FA",
                    "constraints": [{
                        "knowledge": {"types": ["password"]},
                        "possession": {"phishingResistant": "REQUIRED", "hardwareProtection": "REQUIRED", "deviceBound": True},
                    }],
                },
            },
        }))
        assert rec["possession_required"] is True
        assert rec["knowledge_required"] is True
        assert rec["phishing_resistant_category"] == PHISHING_RESISTANT
        assert rec["hardware_protected_category"] == "REQUIRED"
        assert rec["device_bound"] is True
        assert rec["required_factor_count"] == 2

    def test_phishing_resistant_required(self):
        rec = OktaConnector._normalize_policy_rule(_TENANT, _POLICY_REC, _rule(actions={
            "appSignOn": {"verificationMethod": {"factorMode": "2FA", "constraints": [
                {"possession": {"phishingResistant": "REQUIRED"}},
            ]}},
        }))
        assert rec["phishing_resistant_category"] == PHISHING_RESISTANT


# ════════════════════════════════════════════════════════════════════════════
# Session/re-authentication categorization
# ════════════════════════════════════════════════════════════════════════════


class TestSessionLifetimeCategorization:
    def test_very_short(self):
        assert categorize_session_lifetime_minutes(30) == SESSION_LIFETIME_VERY_SHORT

    def test_short(self):
        assert categorize_session_lifetime_minutes(120) == SESSION_LIFETIME_SHORT

    def test_standard(self):
        assert categorize_session_lifetime_minutes(48 * 60) == SESSION_LIFETIME_STANDARD

    def test_extended(self):
        assert categorize_session_lifetime_minutes(365 * 24 * 60) == SESSION_LIFETIME_EXTENDED

    def test_unknown_when_none(self):
        assert categorize_session_lifetime_minutes(None) == SESSION_LIFETIME_UNKNOWN

    def test_unknown_when_negative(self):
        assert categorize_session_lifetime_minutes(-1) == SESSION_LIFETIME_UNKNOWN

    def test_unknown_when_bool(self):
        assert categorize_session_lifetime_minutes(True) == SESSION_LIFETIME_UNKNOWN


class TestIso8601DurationParsing:
    def test_hours(self):
        assert parse_iso8601_duration_to_minutes("PT2H") == 120

    def test_minutes(self):
        assert parse_iso8601_duration_to_minutes("PT30M") == 30

    def test_days(self):
        assert parse_iso8601_duration_to_minutes("P1D") == 1440

    def test_unparseable(self):
        assert parse_iso8601_duration_to_minutes("garbage") is None

    def test_none(self):
        assert parse_iso8601_duration_to_minutes(None) is None

    def test_empty_string(self):
        assert parse_iso8601_duration_to_minutes("") is None


# ════════════════════════════════════════════════════════════════════════════
# Policy/rule targeting scope
# ════════════════════════════════════════════════════════════════════════════


class TestScopeCategorization:
    def test_all_users(self):
        assert categorize_scope(group_include_count=0, user_include_count=0) == SCOPE_ALL_USERS

    def test_scoped_groups(self):
        assert categorize_scope(group_include_count=3, user_include_count=0) == SCOPE_SCOPED_GROUPS

    def test_scoped_users(self):
        assert categorize_scope(group_include_count=0, user_include_count=2) == SCOPE_SCOPED_USERS

    def test_unknown_when_both_none(self):
        assert categorize_scope(group_include_count=None, user_include_count=None) == SCOPE_UNKNOWN

    def test_broad_target_full_normalization(self):
        rec = OktaConnector._normalize_policy_rule(_TENANT, _POLICY_REC, _rule(
            conditions={"people": {"groups": {"include": []}}},
        ))
        assert rec["scope_category"] == SCOPE_ALL_USERS

    def test_scoped_group_target_full_normalization(self):
        rec = OktaConnector._normalize_policy_rule(_TENANT, _POLICY_REC, _rule(
            conditions={"people": {"groups": {"include": ["g1", "g2"]}}},
        ))
        assert rec["scope_category"] == SCOPE_SCOPED_GROUPS
        assert rec["group_include_count"] == 2

    def test_exclusion_target(self):
        rec = OktaConnector._normalize_policy_rule(_TENANT, _POLICY_REC, _rule(
            conditions={"people": {"groups": {"include": ["g1"], "exclude": ["g2", "g3"]}}},
        ))
        assert rec["group_exclude_count"] == 2

    def test_group_ids_never_stored_only_counts(self):
        rec = OktaConnector._normalize_policy_rule(_TENANT, _POLICY_REC, _rule(
            conditions={"people": {"groups": {"include": ["super-secret-group-id"]}}},
        ))
        assert "super-secret-group-id" not in str(rec)


# ════════════════════════════════════════════════════════════════════════════
# Password policy posture
# ════════════════════════════════════════════════════════════════════════════


class TestPasswordPosture:
    def test_minimum_length_strong(self):
        rec = OktaConnector._normalize_policy(_TENANT, _password_policy(), rule_count=0)
        rec["settings"] = None  # ensure no leakage check below doesn't choke
        assert categorize_password_min_length(14) == PASSWORD_STRENGTH_STRONG

    def test_minimum_length_weak(self):
        assert categorize_password_min_length(6) == PASSWORD_STRENGTH_WEAK

    def test_minimum_reduced(self):
        # boundary: exactly at the weak threshold (8) is baseline, 7 is weak
        assert categorize_password_min_length(7) == PASSWORD_STRENGTH_WEAK
        assert categorize_password_min_length(8) == PASSWORD_STRENGTH_BASELINE

    def test_minimum_increased_boundary(self):
        # boundary: 13 is baseline, 14 is strong
        assert categorize_password_min_length(13) == PASSWORD_STRENGTH_BASELINE
        assert categorize_password_min_length(14) == PASSWORD_STRENGTH_STRONG

    def test_history_present(self):
        raw = _password_policy()
        rec = OktaConnector._normalize_policy(_TENANT, raw, rule_count=0)
        assert rec["password_history_present"] is True
        assert rec["password_history_count"] == 4

    def test_history_absent(self):
        raw = _password_policy()
        raw["settings"]["password"]["age"]["historyCount"] = 0
        rec = OktaConnector._normalize_policy(_TENANT, raw, rule_count=0)
        assert rec["password_history_present"] is False

    def test_lockout_present(self):
        rec = OktaConnector._normalize_policy(_TENANT, _password_policy(), rule_count=0)
        assert rec["password_lockout_present"] is True
        assert rec["password_lockout_max_attempts"] == 5

    def test_lockout_absent(self):
        raw = _password_policy()
        raw["settings"]["password"]["lockout"]["maxAttempts"] = 0
        rec = OktaConnector._normalize_policy(_TENANT, raw, rule_count=0)
        assert rec["password_lockout_present"] is False

    def test_complexity_present(self):
        rec = OktaConnector._normalize_policy(_TENANT, _password_policy(), rule_count=0)
        assert rec["password_complexity_required"] is True

    def test_complexity_missing(self):
        raw = _password_policy()
        raw["settings"]["password"]["complexity"] = {
            "minLength": 8, "minLowerCase": 0, "minUpperCase": 0, "minNumber": 0, "minSymbol": 0,
        }
        rec = OktaConnector._normalize_policy(_TENANT, raw, rule_count=0)
        assert rec["password_complexity_required"] is False

    def test_password_lifetime_bounded(self):
        rec = OktaConnector._normalize_policy(_TENANT, _password_policy(), rule_count=0)
        assert rec["password_lifetime_bounded"] is True

    def test_password_lifetime_broad_unknown(self):
        raw = _password_policy()
        raw["settings"]["password"]["age"]["maxAgeDays"] = 0
        rec = OktaConnector._normalize_policy(_TENANT, raw, rule_count=0)
        assert rec["password_lifetime_bounded"] is False

    def test_malformed_numeric_setting(self):
        raw = _password_policy()
        raw["settings"]["password"]["complexity"]["minLength"] = "eight"
        rec = OktaConnector._normalize_policy(_TENANT, raw, rule_count=0)
        assert rec["password_min_length"] is None
        assert rec["password_min_length_category"] == PASSWORD_STRENGTH_UNKNOWN

    def test_only_applies_to_password_type_policies(self):
        rec = OktaConnector._normalize_policy(_TENANT, _policy(type="OKTA_SIGN_ON"), rule_count=0)
        assert "password_min_length" not in rec


# ════════════════════════════════════════════════════════════════════════════
# Authenticator taxonomy
# ════════════════════════════════════════════════════════════════════════════


class TestAuthenticatorTaxonomy:
    @pytest.mark.parametrize("key,expected", [
        ("password", AUTHENTICATOR_KEY_PASSWORD),
        ("security_question", AUTHENTICATOR_KEY_SECURITY_QUESTION),
        ("email", AUTHENTICATOR_KEY_EMAIL),
        ("phone_number", AUTHENTICATOR_KEY_PHONE_NUMBER),
        ("okta_verify", AUTHENTICATOR_KEY_OKTA_VERIFY),
        ("webauthn", AUTHENTICATOR_KEY_WEBAUTHN),
        ("smart_card_idp", AUTHENTICATOR_KEY_SMART_CARD_IDP),
    ])
    def test_every_known_key(self, key, expected):
        assert categorize_authenticator_key(key) == expected

    def test_unknown_authenticator(self):
        assert categorize_authenticator_key("some_future_authenticator") == AUTHENTICATOR_KEY_UNKNOWN

    def test_security_key_type(self):
        rec = OktaConnector._normalize_authenticator(_TENANT, _authenticator(key="webauthn", type="security_key"))
        assert rec["hardware_backed_category"] == "hardware_backed"


class TestPhishingResistance:
    def test_webauthn_true(self):
        assert phishing_resistance_for_authenticator_key(AUTHENTICATOR_KEY_WEBAUTHN) == PHISHING_RESISTANT

    def test_smart_card_true(self):
        assert phishing_resistance_for_authenticator_key(AUTHENTICATOR_KEY_SMART_CARD_IDP) == PHISHING_RESISTANT

    def test_sms_false(self):
        assert phishing_resistance_for_authenticator_key(AUTHENTICATOR_KEY_PHONE_NUMBER) == NOT_PHISHING_RESISTANT

    def test_email_false(self):
        assert phishing_resistance_for_authenticator_key(AUTHENTICATOR_KEY_EMAIL) == NOT_PHISHING_RESISTANT

    def test_totp_like_false(self):
        assert phishing_resistance_for_authenticator_key(AUTHENTICATOR_KEY_OKTA_VERIFY) == NOT_PHISHING_RESISTANT

    def test_unknown_authenticator_unknown_resistance(self):
        assert phishing_resistance_for_authenticator_key(AUTHENTICATOR_KEY_UNKNOWN) == PHISHING_RESISTANCE_UNKNOWN

    def test_never_treats_unknown_as_false(self):
        assert phishing_resistance_for_authenticator_key("custom_app") != NOT_PHISHING_RESISTANT

    def test_from_possession_constraint_required(self):
        assert phishing_resistance_from_possession_constraint({"phishingResistant": "REQUIRED"}) == PHISHING_RESISTANT

    def test_from_possession_constraint_disallowed(self):
        assert phishing_resistance_from_possession_constraint({"phishingResistant": "DISALLOWED"}) == NOT_PHISHING_RESISTANT

    def test_from_possession_constraint_absent(self):
        assert phishing_resistance_from_possession_constraint(None) == PHISHING_RESISTANCE_UNKNOWN
        assert phishing_resistance_from_possession_constraint({}) == PHISHING_RESISTANCE_UNKNOWN


class TestFactorCategories:
    def test_password_is_knowledge(self):
        assert is_knowledge_authenticator(AUTHENTICATOR_KEY_PASSWORD) is True
        assert is_possession_authenticator(AUTHENTICATOR_KEY_PASSWORD) is False

    def test_email_is_possession(self):
        assert is_possession_authenticator(AUTHENTICATOR_KEY_EMAIL) is True
        assert is_knowledge_authenticator(AUTHENTICATOR_KEY_EMAIL) is False

    def test_unknown_authenticator_both_none(self):
        assert is_knowledge_authenticator(AUTHENTICATOR_KEY_UNKNOWN) is None
        assert is_possession_authenticator(AUTHENTICATOR_KEY_UNKNOWN) is None

    def test_inherence_always_none_never_fabricated(self):
        rec = OktaConnector._normalize_authenticator(_TENANT, _authenticator(key="webauthn"))
        assert rec["inherence_factor"] is None


class TestAuthenticatorStatus:
    def test_active(self):
        rec = OktaConnector._normalize_authenticator(_TENANT, _authenticator(status="ACTIVE"))
        assert rec["active"] is True

    def test_inactive(self):
        rec = OktaConnector._normalize_authenticator(_TENANT, _authenticator(status="INACTIVE"))
        assert rec["active"] is False

    def test_unknown_status(self):
        rec = OktaConnector._normalize_authenticator(_TENANT, _authenticator(status="WEIRD"))
        assert rec["status"] == "UNKNOWN"
        assert rec["active"] is False

    def test_missing_authenticator_id_returns_none(self):
        assert OktaConnector._normalize_authenticator(_TENANT, {"key": "password"}) is None


# ════════════════════════════════════════════════════════════════════════════
# Sensitive-data exclusion
# ════════════════════════════════════════════════════════════════════════════


class TestSensitiveDataExclusion:
    def test_otp_seed_excluded(self):
        raw = _authenticator()
        raw["settings"] = {"otpSeed": "SHOULD_NEVER_APPEAR_SEED"}
        rec = OktaConnector._normalize_authenticator(_TENANT, raw)
        assert "SHOULD_NEVER_APPEAR_SEED" not in str(rec)
        assert "settings" not in rec

    def test_password_excluded(self):
        raw = _rule()
        raw["conditions"]["people"]["password"] = "SHOULD_NEVER_APPEAR"
        rec = OktaConnector._normalize_policy_rule(_TENANT, _POLICY_REC, raw)
        assert "SHOULD_NEVER_APPEAR" not in str(rec)

    def test_recovery_code_excluded(self):
        raw = _authenticator()
        raw["settings"] = {"recoveryCodes": ["CODE1", "CODE2"]}
        rec = OktaConnector._normalize_authenticator(_TENANT, raw)
        assert "CODE1" not in str(rec)

    def test_private_key_excluded(self):
        raw = _authenticator()
        raw["settings"] = {"privateKey": "-----BEGIN PRIVATE KEY-----FAKE-----END PRIVATE KEY-----"}
        rec = OktaConnector._normalize_authenticator(_TENANT, raw)
        assert "PRIVATE KEY" not in str(rec)

    def test_challenge_data_excluded(self):
        raw = _rule()
        raw["actions"]["signon"]["challenge"] = {"nonce": "SHOULD_NEVER_APPEAR_NONCE"}
        rec = OktaConnector._normalize_policy_rule(_TENANT, _POLICY_REC, raw)
        assert "SHOULD_NEVER_APPEAR_NONCE" not in str(rec)

    def test_raw_condition_map_excluded(self):
        raw = _rule()
        raw["conditions"]["network"] = {"connection": "ZONE", "include": ["nz_secret_zone_id"]}
        rec = OktaConnector._normalize_policy_rule(_TENANT, _POLICY_REC, raw)
        assert "nz_secret_zone_id" not in str(rec)
        assert "conditions" not in rec

    def test_raw_action_map_excluded(self):
        raw = _rule()
        raw["actions"]["signon"]["extraSecretField"] = "SHOULD_NEVER_APPEAR_ACTION"
        rec = OktaConnector._normalize_policy_rule(_TENANT, _POLICY_REC, raw)
        assert "SHOULD_NEVER_APPEAR_ACTION" not in str(rec)
        assert "actions" not in rec

    def test_phone_excluded(self):
        raw = _authenticator(key="phone_number")
        raw["settings"] = {"phoneNumber": "+15555550100"}
        rec = OktaConnector._normalize_authenticator(_TENANT, raw)
        assert "+15555550100" not in str(rec)

    def test_shared_secret_excluded(self):
        raw = _authenticator()
        raw["settings"] = {"sharedSecret": "SHOULD_NEVER_APPEAR_SHARED"}
        rec = OktaConnector._normalize_authenticator(_TENANT, raw)
        assert "SHOULD_NEVER_APPEAR_SHARED" not in str(rec)

    def test_factor_secret_excluded(self):
        raw = _authenticator()
        raw["factorSecret"] = "SHOULD_NEVER_APPEAR_FACTOR_SECRET"
        rec = OktaConnector._normalize_authenticator(_TENANT, raw)
        assert "SHOULD_NEVER_APPEAR_FACTOR_SECRET" not in str(rec)

    def test_password_policy_never_stores_password_values(self):
        raw = _password_policy()
        raw["settings"]["recovery"] = {"factors": {"okta_email": {"status": "ACTIVE"}}}
        rec = OktaConnector._normalize_policy(_TENANT, raw, rule_count=0)
        assert "recovery" not in rec
        assert "settings" not in rec
