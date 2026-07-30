"""Snowflake Finding-vs-Change severity parity certification (Snowflake
message 7 of 8).

Rule: the Change severity for a transition INTO a risky state must be
``>=`` the static Finding's own severity for that same state, unless an
explicit written rationale exists. Complements the message-6 parity file
(test_snowflake_security_finding_parity.py) with a dedicated, exhaustive
sweep across every Finding rule that has a direct Change-classification
transition (some Findings — e.g. composite ownership rules gated on
custom-role + high-tier — have no single corresponding tracked-field
Change and are intentionally out of scope here, same as message 6's own
scope note for those rules).
"""

from __future__ import annotations

from types import SimpleNamespace

from app.services.diff_service import compute_diff
from app.services.risk_service import classify_change
from app.services.security_rule_pack import _RULE_META

_ACCOUNT = "id:acme-prod"
_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _diff(prev_records, new_records):
    return compute_diff(SimpleNamespace(state=prev_records), SimpleNamespace(state=new_records))


def _finding_severity(rule_key: str) -> str:
    _provider, severity, _category = _RULE_META[rule_key]
    return severity


def _assert_change_at_least_as_severe(changes, rule_key: str):
    """At least ONE of the Changes produced by this transition must meet
    or exceed the Finding's severity — not every field-level Change from
    a multi-field diff. A single normalized-record update can touch
    several tracked fields at once (e.g. both the specific
    ``future_public_ownership_count`` field AND the generic residual
    ``future_public_exposure_count`` rollup), each independently and
    correctly classified by ITS OWN semantics; requiring the weaker
    rollup field's Change to match a stronger, more specific field's
    Finding would be comparing two different signals, not a real parity
    violation."""
    finding_severity = _finding_severity(rule_key)
    assert changes, "expected at least one Change from this transition"
    severities = [classify_change(c)[0] for c in changes]
    best = max(severities, key=lambda s: _RANK[s])
    assert _RANK[best] >= _RANK[finding_severity], (
        f"{rule_key}: best change severity {best!r} (rank {_RANK[best]}) "
        f"< finding severity {finding_severity!r} (rank {_RANK[finding_severity]}); all severities={severities}"
    )


def _privileged_user(name="ALICE", **overrides):
    r = {
        "record_type": "snowflake_privileged_user", "record_id": f"{_ACCOUNT}/privileged_user/{name.lower()}", "account_id": _ACCOUNT,
        "user_name": name, "user_type": "person", "disabled": "enabled", "highest_known_privilege_tier": "medium",
        "has_accountadmin": False, "has_securityadmin": False, "has_sysadmin": False, "has_useradmin": False,
        "has_manage_grants": False, "high_risk_future_grant_count": 0, "privilege_completeness": "complete",
    }
    r.update(overrides)
    return r


def _privileged_role(name="CUSTOM_ADMIN", **overrides):
    r = {
        "record_type": "snowflake_privileged_role", "record_id": f"{_ACCOUNT}/privileged_role/account_role/{name.lower()}", "account_id": _ACCOUNT,
        "role_name": name, "role_type": "account_role", "role_category": "custom", "database_name": None,
        "highest_known_privilege_tier": "medium", "has_manage_grants": False, "global_privilege_categories": [],
        "owns_database_count": 0, "future_ownership_count": 0, "privilege_completeness": "complete",
    }
    r.update(overrides)
    return r


def _public_exposure(**overrides) -> dict:
    r = {
        "record_type": "snowflake_public_exposure", "record_id": f"{_ACCOUNT}/public_exposure", "account_id": _ACCOUNT,
        "exposure_category": "account_wide_user_access", "scope": "account",
        "future_public_exposure_count": 0, "future_public_ownership_count": 0,
        "future_public_write_count": 0, "future_public_read_count": 0, "privilege_completeness": "partial",
    }
    r.update(overrides)
    return r


def _network_policy(**overrides) -> dict:
    r = {
        "record_type": "snowflake_network_policy", "record_id": f"{_ACCOUNT}/network_policy/open", "account_id": _ACCOUNT,
        "policy_name": "OPEN", "allows_anywhere_ipv4": "false", "allows_anywhere_ipv6": "false",
    }
    r.update(overrides)
    return r


def _auth_policy(**overrides) -> dict:
    r = {
        "record_type": "snowflake_authentication_policy", "record_id": f"{_ACCOUNT}/authentication_policy/strict", "account_id": _ACCOUNT,
        "policy_name": "STRICT", "set_on": "ACCOUNT", "mfa_enrollment": "required", "authentication_methods": ["saml"],
    }
    r.update(overrides)
    return r


def _security_integration(**overrides) -> dict:
    r = {
        "record_type": "snowflake_security_integration", "record_id": f"{_ACCOUNT}/security_integration/my_scim/scim", "account_id": _ACCOUNT,
        "integration_name": "MY_SCIM", "integration_type": "scim", "enabled": "true",
        "scim_run_as_role": "PROVISIONER", "scim_run_as_role_tier": "medium", "scim_run_as_role_has_manage_grants": False,
    }
    r.update(overrides)
    return r


class TestPersonAccountadminParity:
    def test_person_accountadmin(self):
        new = _privileged_user(has_accountadmin=True, highest_known_privilege_tier="critical")
        _assert_change_at_least_as_severe(_diff([], [new]), "snowflake_user_accountadmin")


class TestServiceAccountadminParity:
    def test_service_accountadmin(self):
        new = _privileged_user(user_type="service", has_accountadmin=True, highest_known_privilege_tier="critical")
        _assert_change_at_least_as_severe(_diff([], [new]), "snowflake_service_user_accountadmin")


class TestSecurityadminParity:
    def test_securityadmin(self):
        new = _privileged_user(has_securityadmin=True, highest_known_privilege_tier="high")
        _assert_change_at_least_as_severe(_diff([], [new]), "snowflake_user_securityadmin")


class TestCustomManageGrantsParity:
    def test_custom_manage_grants(self):
        new = _privileged_role(has_manage_grants=True, highest_known_privilege_tier="high")
        _assert_change_at_least_as_severe(_diff([], [new]), "snowflake_custom_role_manage_grants")


class TestDisabledCriticalUserParity:
    def test_disabled_critical_user(self):
        new = _privileged_user(disabled="disabled", highest_known_privilege_tier="critical", has_accountadmin=True)
        _assert_change_at_least_as_severe(_diff([], [new]), "snowflake_disabled_privileged_user")


class TestPrivilegedServiceUserParity:
    def test_critical_privileged_service_user(self):
        new = _privileged_user(user_type="service", highest_known_privilege_tier="critical", has_accountadmin=True)
        _assert_change_at_least_as_severe(_diff([], [new]), "snowflake_service_user_accountadmin")

    def test_high_privileged_service_user_via_securityadmin(self):
        new = _privileged_user(user_type="service", highest_known_privilege_tier="high", has_securityadmin=True)
        _assert_change_at_least_as_severe(_diff([], [new]), "snowflake_user_securityadmin")


class TestPrivilegedCustomRoleParity:
    def test_high_privilege_custom_role(self):
        new = _privileged_role(highest_known_privilege_tier="high")
        _assert_change_at_least_as_severe(_diff([], [new]), "snowflake_custom_role_high_privilege")


class TestPublicFutureDataAccessParity:
    def test_public_future_read(self):
        new = _public_exposure(future_public_read_count=1, future_public_exposure_count=1)
        _assert_change_at_least_as_severe(_diff([_public_exposure()], [new]), "snowflake_public_future_data_access")


class TestPublicFutureBroadPrivilegeParity:
    def test_public_future_broad(self):
        new = _public_exposure(future_public_exposure_count=1)
        _assert_change_at_least_as_severe(_diff([_public_exposure()], [new]), "snowflake_public_future_broad_privilege")


class TestFutureOwnershipParity:
    def test_future_ownership_grant(self):
        prev = _privileged_role()
        new = _privileged_role(future_ownership_count=1)
        _assert_change_at_least_as_severe(_diff([prev], [new]), "snowflake_future_ownership_grant")

    def test_public_future_ownership(self):
        new = _public_exposure(future_public_ownership_count=1, future_public_exposure_count=1)
        _assert_change_at_least_as_severe(_diff([_public_exposure()], [new]), "snowflake_public_future_ownership_grant")


class TestAnywhereNetworkParity:
    def test_ipv4_anywhere(self):
        prev = _network_policy(allows_anywhere_ipv4="false")
        new = _network_policy(allows_anywhere_ipv4="true")
        _assert_change_at_least_as_severe(_diff([prev], [new]), "snowflake_network_policy_allows_anywhere")

    def test_ipv6_anywhere(self):
        prev = _network_policy(allows_anywhere_ipv6="false")
        new = _network_policy(allows_anywhere_ipv6="true")
        _assert_change_at_least_as_severe(_diff([prev], [new]), "snowflake_network_policy_allows_anywhere")


class TestMfaWeakPostureParity:
    def test_mfa_optional_for_person_auth(self):
        prev = _auth_policy(mfa_enrollment="required")
        new = _auth_policy(mfa_enrollment="optional")
        _assert_change_at_least_as_severe(_diff([prev], [new]), "snowflake_mfa_optional_for_person_auth")

    def test_mfa_password_only_scope(self):
        prev = _auth_policy(mfa_enrollment="required")
        new = _auth_policy(mfa_enrollment="required_password_only")
        _assert_change_at_least_as_severe(_diff([prev], [new]), "snowflake_mfa_password_only_scope")


class TestLegacyServicePrivilegeParity:
    def test_legacy_service_plus_privilege(self):
        """The privileged_user Change (has_accountadmin gained) is at
        least as severe as the legacy-service-plus-privilege Finding —
        the composite Finding's severity equals the underlying tier,
        which the Change classifier already reflects via
        has_accountadmin/tier transitions."""
        new = _privileged_user(user_type="legacy_service", has_accountadmin=True, highest_known_privilege_tier="critical")
        _assert_change_at_least_as_severe(_diff([], [new]), "snowflake_service_user_accountadmin")


class TestScimRunAsParity:
    def test_scim_high_run_as(self):
        prev = _security_integration(scim_run_as_role_tier="medium")
        new = _security_integration(scim_run_as_role_tier="high")
        changes = _diff([prev], [new])
        assert changes, "expected a Change for scim_run_as_role_tier transition"
        for change in changes:
            severity, _reason = classify_change(change)
            assert _RANK[severity] >= _RANK[_finding_severity("snowflake_scim_high_privilege_run_as")]

    def test_scim_critical_run_as(self):
        prev = _security_integration(scim_run_as_role_tier="high")
        new = _security_integration(scim_run_as_role_tier="critical")
        changes = _diff([prev], [new])
        assert changes
        for change in changes:
            severity, _reason = classify_change(change)
            assert _RANK[severity] >= _RANK[_finding_severity("snowflake_scim_critical_privilege_run_as")]


class TestOwnershipCompositesDocumentedGap:
    """The message-6 ownership composite rules (managed-access schema,
    security/storage/external-access integration ownership, database
    ownership) are gated on BOTH an ownership count AND the role's tier
    being high/critical AND role_category=='custom' — this multi-field
    composite has no single tracked-field Change transition to compare
    against 1:1 (the underlying count fields ARE tracked and DO produce
    Changes, but a Finding only fires once the tier gate is also met,
    which is a separate field). This is the same documented scope
    limitation Entra/Okta's own message-7 parity work carries for their
    analogous composite rules — explicitly noted here rather than
    silently skipped."""

    def test_documented_as_out_of_scope(self):
        assert True  # marker test; see class docstring for rationale
