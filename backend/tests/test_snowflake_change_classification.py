"""Snowflake exhaustive Change-classification QA (Snowflake message 7 of
8).

Uses the REAL ``compute_diff()`` -> ``classify_change()`` pipeline for
every case (never a hand-built Change dict standing in for the real
pipeline). Complements the per-message diff test files
(test_snowflake_identity_diff.py, test_snowflake_data_diff.py,
test_snowflake_policy_diff.py, test_snowflake_privileged_diff.py) with
cross-cutting QA: user lifecycle/type transitions, added/removed-record
posture, PUBLIC semantics regression, and MFA-mode transitions this
message specifically targets.
"""

from __future__ import annotations

from types import SimpleNamespace

from app.services.diff_service import compute_diff
from app.services.risk_service import classify_change

_ACCOUNT = "id:acme-prod"


def _diff(prev_records, new_records):
    return compute_diff(SimpleNamespace(state=prev_records), SimpleNamespace(state=new_records))


def _only(changes):
    assert len(changes) == 1, f"expected exactly 1 change, got {len(changes)}: {changes}"
    return changes[0]


def _user(name="ALICE", **overrides):
    r = {
        "record_type": "snowflake_user", "record_id": f"{_ACCOUNT}/user/{name.lower()}", "account_id": _ACCOUNT,
        "user_name": name, "user_type": "person", "disabled": "enabled", "default_role": None,
        "default_secondary_roles": "all", "rsa_key_configured": "false", "password_configured": "true",
        "programmatic_access_token_configured": "false",
    }
    r.update(overrides)
    return r


def _account_role(name="CUSTOM_ADMIN", **overrides):
    r = {"record_type": "snowflake_account_role", "record_id": f"{_ACCOUNT}/account_role/{name.lower()}", "account_id": _ACCOUNT, "role_name": name, "role_category": "custom", "owner": "SYSADMIN"}
    r.update(overrides)
    return r


def _privileged_user(name="ALICE", **overrides):
    r = {
        "record_type": "snowflake_privileged_user", "record_id": f"{_ACCOUNT}/privileged_user/{name.lower()}", "account_id": _ACCOUNT,
        "user_name": name, "user_type": "person", "disabled": "enabled", "highest_known_privilege_tier": "medium",
        "has_accountadmin": False, "has_securityadmin": False, "has_sysadmin": False, "has_useradmin": False,
        "has_manage_grants": False, "high_risk_future_grant_count": 0, "privilege_completeness": "complete",
    }
    r.update(overrides)
    return r


def _network_policy(name="OPEN", **overrides):
    r = {
        "record_type": "snowflake_network_policy", "record_id": f"{_ACCOUNT}/network_policy/{name.lower()}", "account_id": _ACCOUNT,
        "policy_name": name, "owner": "SECURITYADMIN", "allowed_ipv4_count": 1, "blocked_ipv4_count": 0,
        "allowed_network_rule_count": 0, "blocked_network_rule_count": 0, "has_allowlist": True, "has_blocklist": False,
        "allows_anywhere_ipv4": "false", "allows_anywhere_ipv6": "false", "detail_collection_status": "complete",
    }
    r.update(overrides)
    return r


def _auth_policy(name="STRICT", **overrides):
    r = {
        "record_type": "snowflake_authentication_policy", "record_id": f"{_ACCOUNT}/authentication_policy/{name.lower()}", "account_id": _ACCOUNT,
        "policy_name": name, "owner": "SECURITYADMIN", "set_on": "ACCOUNT", "authentication_methods": ["saml"],
        "mfa_enrollment": "required", "client_types": "all", "detail_collection_status": "complete",
    }
    r.update(overrides)
    return r


def _object_grant(grantee="ANALYST", grantee_type="account_role", **overrides):
    r = {
        "record_type": "snowflake_object_grant",
        "record_id": f"{_ACCOUNT}/object_grant/{grantee_type}:{grantee.lower()}/select/table/future=False/x",
        "account_id": _ACCOUNT, "grantee_name": grantee, "grantee_type": grantee_type,
        "privilege": "SELECT", "privilege_category": "data_read", "object_type": "table",
        "object_fqn": "MYDB.PUBLIC.T1", "grant_option": "false", "future_grant": False, "ownership": False,
    }
    r.update(overrides)
    return r


# ── User Change QA (section 12) ──────────────────────────────────────────────


class TestUserLifecycleQA:
    def test_enabled_to_disabled_is_low(self):
        prev, new = _user(disabled="enabled"), _user(disabled="disabled")
        severity, _ = classify_change(_only(_diff([prev], [new])))
        assert severity == "low"

    def test_disabled_to_enabled_is_medium(self):
        prev, new = _user(disabled="disabled"), _user(disabled="enabled")
        severity, _ = classify_change(_only(_diff([prev], [new])))
        assert severity == "medium"

    def test_person_to_service_is_low(self):
        prev, new = _user(user_type="person"), _user(user_type="service")
        severity, _ = classify_change(_only(_diff([prev], [new])))
        assert severity == "low"

    def test_service_to_person_is_low(self):
        prev, new = _user(user_type="service"), _user(user_type="person")
        severity, _ = classify_change(_only(_diff([prev], [new])))
        assert severity == "low"

    def test_service_to_legacy_service_is_medium(self):
        prev, new = _user(user_type="service"), _user(user_type="legacy_service")
        severity, message = classify_change(_only(_diff([prev], [new])))
        assert severity == "medium"
        assert "LEGACY_SERVICE" in message

    def test_legacy_service_to_service_is_low(self):
        prev, new = _user(user_type="legacy_service"), _user(user_type="service")
        severity, _ = classify_change(_only(_diff([prev], [new])))
        assert severity == "low"

    def test_default_role_changed_to_accountadmin_is_medium(self):
        prev, new = _user(default_role="ANALYST"), _user(default_role="ACCOUNTADMIN")
        severity, _ = classify_change(_only(_diff([prev], [new])))
        assert severity == "medium"

    def test_added_ordinary_user_is_low(self):
        severity, _ = classify_change(_only(_diff([], [_user()])))
        assert severity == "low"

    def test_removed_user_is_low(self):
        severity, _ = classify_change(_only(_diff([_user()], [])))
        assert severity == "low"

    def test_secondary_role_posture_change_falls_to_generic_low(self):
        prev, new = _user(default_secondary_roles="all"), _user(default_secondary_roles="none")
        severity, _ = classify_change(_only(_diff([prev], [new])))
        assert severity == "low"

    def test_rsa_key_presence_change_falls_to_generic_low(self):
        prev, new = _user(rsa_key_configured="false"), _user(rsa_key_configured="true")
        severity, _ = classify_change(_only(_diff([prev], [new])))
        assert severity == "low"

    def test_pat_posture_change_falls_to_generic_low(self):
        prev, new = _user(programmatic_access_token_configured="false"), _user(programmatic_access_token_configured="true")
        severity, _ = classify_change(_only(_diff([prev], [new])))
        assert severity == "low"


# ── Privileged-user Change QA (section 26) — real pipeline ──────────────────


class TestPrivilegedUserChangeQA:
    def test_ordinary_to_medium(self):
        severity, _ = classify_change(_only(_diff([], [_privileged_user(highest_known_privilege_tier="medium")])))
        assert severity == "medium"

    def test_medium_to_high(self):
        prev = _privileged_user(highest_known_privilege_tier="medium")
        new = _privileged_user(highest_known_privilege_tier="high", has_securityadmin=True)
        changes = _diff([prev], [new])
        assert any(classify_change(c)[0] == "high" for c in changes)

    def test_high_to_critical(self):
        prev = _privileged_user(highest_known_privilege_tier="high", has_securityadmin=True)
        new = _privileged_user(highest_known_privilege_tier="critical", has_securityadmin=True, has_accountadmin=True)
        changes = _diff([prev], [new])
        assert any(classify_change(c)[0] == "critical" for c in changes)

    def test_critical_to_high_is_reduction(self):
        prev = _privileged_user(highest_known_privilege_tier="critical", has_accountadmin=True)
        new = _privileged_user(highest_known_privilege_tier="high", has_accountadmin=False, has_securityadmin=True)
        changes = _diff([prev], [new])
        assert all(classify_change(c)[0] != "critical" for c in changes)

    def test_has_accountadmin_false_to_true_is_critical(self):
        prev = _privileged_user(has_accountadmin=False, highest_known_privilege_tier="high")
        new = _privileged_user(has_accountadmin=True, highest_known_privilege_tier="critical")
        changes = _diff([prev], [new])
        for c in changes:
            severity, _ = classify_change(c)
            assert severity == "critical"

    def test_has_securityadmin_false_to_true_is_high(self):
        prev = _privileged_user(has_securityadmin=False)
        new = _privileged_user(has_securityadmin=True, highest_known_privilege_tier="high")
        changes = _diff([prev], [new])
        assert any(classify_change(c)[0] == "high" for c in changes)

    def test_has_manage_grants_false_to_true_is_high(self):
        prev = _privileged_user(has_manage_grants=False)
        new = _privileged_user(has_manage_grants=True, highest_known_privilege_tier="high")
        changes = _diff([prev], [new])
        assert any(classify_change(c)[0] == "high" for c in changes)

    def test_disabled_critical_user_enabled_is_critical(self):
        prev = _privileged_user(disabled="disabled", highest_known_privilege_tier="critical", has_accountadmin=True)
        new = _privileged_user(disabled="enabled", highest_known_privilege_tier="critical", has_accountadmin=True)
        severity, _ = classify_change(_only(_diff([prev], [new])))
        assert severity == "critical"

    def test_enabled_critical_user_disabled_is_low(self):
        prev = _privileged_user(disabled="enabled", highest_known_privilege_tier="critical", has_accountadmin=True)
        new = _privileged_user(disabled="disabled", highest_known_privilege_tier="critical", has_accountadmin=True)
        severity, _ = classify_change(_only(_diff([prev], [new])))
        assert severity == "low"

    def test_service_critical_user_added_is_critical(self):
        severity, _ = classify_change(_only(_diff(
            [], [_privileged_user(name="SVC1", user_type="service", highest_known_privilege_tier="critical", has_accountadmin=True)],
        )))
        assert severity == "critical"

    def test_direct_vs_inherited_privilege_both_classify_by_tier(self):
        """The Change classifier reads only the tier/boolean fields on
        the derived record — it cannot distinguish direct vs inherited
        privilege (that distinction lives upstream in message 5's
        derivation), so both must classify identically for the same
        tier/flags."""
        direct = _privileged_user(name="DIRECT", has_accountadmin=True, highest_known_privilege_tier="critical")
        inherited = _privileged_user(name="INHERITED", has_accountadmin=True, highest_known_privilege_tier="critical")
        sev_direct, _ = classify_change(_only(_diff([], [direct])))
        sev_inherited, _ = classify_change(_only(_diff([], [inherited])))
        assert sev_direct == sev_inherited == "critical"

    def test_unknown_hierarchy_tier_never_classified_as_critical(self):
        severity, _ = classify_change(_only(_diff([], [_privileged_user(highest_known_privilege_tier="unknown", has_accountadmin=None)])))
        assert severity != "critical"


# ── PUBLIC semantics regression (section 19, MANDATORY) ──────────────────────


class TestPublicSemanticsRegression:
    def test_future_select_to_public_never_says_internet(self):
        change = _only(_diff([], [_object_grant("PUBLIC", future_grant=True)]))
        severity, message = classify_change(change)
        assert "internet" not in message.lower()

    def test_future_usage_to_public_categorized_correctly(self):
        grant = _object_grant("PUBLIC", future_grant=True, privilege="USAGE", privilege_category="usage", object_type="schema")
        change = _only(_diff([], [grant]))
        _severity, message = classify_change(change)
        assert "internet" not in message.lower()

    def test_future_write_to_public_never_says_internet(self):
        grant = _object_grant("PUBLIC", future_grant=True, privilege="INSERT", privilege_category="data_write")
        change = _only(_diff([], [grant]))
        _severity, message = classify_change(change)
        assert "internet" not in message.lower()

    def test_public_grant_removal_is_low(self):
        severity, _ = classify_change(_only(_diff([_object_grant("PUBLIC", future_grant=True)], [])))
        assert severity == "low"

    def test_ordinary_role_grant_does_not_trigger_public_logic(self):
        change = _only(_diff([], [_object_grant("ANALYST", future_grant=False)]))
        severity, message = classify_change(change)
        assert "PUBLIC" not in message

    def test_no_classifier_output_ever_says_internet_exposed(self):
        """Sweep every PUBLIC-adjacent Change this file constructs and
        confirm none ever produces internet-exposure wording."""
        grants = [
            _object_grant("PUBLIC", future_grant=True, privilege="SELECT", privilege_category="data_read"),
            _object_grant("PUBLIC", future_grant=True, privilege="OWNERSHIP", ownership=True),
            _object_grant("PUBLIC", future_grant=False, privilege="SELECT", privilege_category="data_read"),
        ]
        for g in grants:
            for change in _diff([], [g]):
                _sev, msg = classify_change(change)
                assert "internet" not in msg.lower()
                assert "anonymous" not in msg.lower()


# ── Account-role Change QA (section 13) ──────────────────────────────────────


class TestAccountRoleChangeQA:
    def test_added_role_is_low(self):
        severity, _ = classify_change(_only(_diff([], [_account_role()])))
        assert severity == "low"

    def test_removed_role_is_low(self):
        severity, _ = classify_change(_only(_diff([_account_role()], [])))
        assert severity == "low"

    def test_owner_change_falls_to_generic_low(self):
        prev, new = _account_role(owner="SYSADMIN"), _account_role(owner="SECURITYADMIN")
        severity, _ = classify_change(_only(_diff([prev], [new])))
        assert severity == "low"


# ── Network-policy anywhere QA (section 20) ──────────────────────────────────


class TestNetworkPolicyChangeQA:
    def test_ipv4_anywhere_introduced_is_high(self):
        prev, new = _network_policy(allows_anywhere_ipv4="false"), _network_policy(allows_anywhere_ipv4="true")
        severity, _ = classify_change(_only(_diff([prev], [new])))
        assert severity == "high"

    def test_ipv4_anywhere_removed_is_low(self):
        prev, new = _network_policy(allows_anywhere_ipv4="true"), _network_policy(allows_anywhere_ipv4="false")
        severity, _ = classify_change(_only(_diff([prev], [new])))
        assert severity == "low"

    def test_ipv6_anywhere_introduced_is_high(self):
        prev, new = _network_policy(allows_anywhere_ipv6="false"), _network_policy(allows_anywhere_ipv6="true")
        severity, _ = classify_change(_only(_diff([prev], [new])))
        assert severity == "high"

    def test_policy_added_with_broad_access_is_high(self):
        severity, _ = classify_change(_only(_diff([], [_network_policy(allows_anywhere_ipv4="true")])))
        assert severity == "high"

    def test_restricted_policy_added_is_low(self):
        severity, _ = classify_change(_only(_diff([], [_network_policy()])))
        assert severity == "low"

    def test_policy_removed_is_medium(self):
        severity, _ = classify_change(_only(_diff([_network_policy()], [])))
        assert severity == "medium"

    def test_unknown_broadness_never_treated_as_broad(self):
        prev = _network_policy(allows_anywhere_ipv4="false")
        new = _network_policy(allows_anywhere_ipv4="unknown")
        severity, _ = classify_change(_only(_diff([prev], [new])))
        assert severity != "high"


# ── Authentication-policy MFA-mode QA (section 22) ───────────────────────────


class TestAuthenticationPolicyMfaModeQA:
    def test_required_to_optional_is_high(self):
        prev, new = _auth_policy(mfa_enrollment="required"), _auth_policy(mfa_enrollment="optional")
        severity, _ = classify_change(_only(_diff([prev], [new])))
        assert severity == "high"

    def test_optional_to_required_is_low(self):
        prev, new = _auth_policy(mfa_enrollment="optional"), _auth_policy(mfa_enrollment="required")
        severity, _ = classify_change(_only(_diff([prev], [new])))
        assert severity == "low"

    def test_required_to_required_password_only_is_high(self):
        """REQUIRED covers password+SSO; REQUIRED_PASSWORD_ONLY exempts
        SSO users — a narrowing of MFA coverage, ranked as a weakening."""
        prev, new = _auth_policy(mfa_enrollment="required"), _auth_policy(mfa_enrollment="required_password_only")
        severity, _ = classify_change(_only(_diff([prev], [new])))
        assert severity == "high"

    def test_required_password_only_to_required_is_low(self):
        prev, new = _auth_policy(mfa_enrollment="required_password_only"), _auth_policy(mfa_enrollment="required")
        severity, _ = classify_change(_only(_diff([prev], [new])))
        assert severity == "low"

    def test_unknown_mfa_state_transition_is_never_high(self):
        prev, new = _auth_policy(mfa_enrollment="required"), _auth_policy(mfa_enrollment="unknown")
        severity, _ = classify_change(_only(_diff([prev], [new])))
        assert severity != "high"

    def test_authentication_methods_broadened_is_medium(self):
        prev = _auth_policy(authentication_methods=["saml"])
        new = _auth_policy(authentication_methods=["saml", "password"])
        severity, _ = classify_change(_only(_diff([prev], [new])))
        assert severity == "medium"

    def test_authentication_methods_narrowed_is_low(self):
        prev = _auth_policy(authentication_methods=["saml", "password"])
        new = _auth_policy(authentication_methods=["saml"])
        severity, _ = classify_change(_only(_diff([prev], [new])))
        assert severity == "low"

    def test_policy_removed_is_medium(self):
        severity, _ = classify_change(_only(_diff([_auth_policy()], [])))
        assert severity == "medium"
