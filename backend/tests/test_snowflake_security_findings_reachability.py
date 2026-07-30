"""Snowflake Security Finding connector-shape reachability tests
(Snowflake message 6 of 8).

For a representative rule from every category, proves the full path: a
real Snowflake-connector normalize/derive function -> a real normalized
record -> evaluate_record() -> a Finding with the expected rule key. This
is not testing hand-fabricated Finding dictionaries — it exercises the
same derivation code the live connector (app/connectors/snowflake.py)
uses, per the task's explicit reachability requirements:

  real user + user-role grant + hierarchy -> privileged user -> Finding
  custom role + MANAGE GRANTS -> privileged role -> Finding
  PUBLIC future grant -> public exposure -> Finding
  network policy -> anywhere posture -> Finding
  SCIM integration + run-as role + privilege resolution -> Finding
"""

from __future__ import annotations

from app.connectors.snowflake import SnowflakeConnector as C
from app.connectors.snowflake_schema import PRINCIPAL_TYPE_ACCOUNT_ROLE
from app.services.security_finding_evaluator import evaluate_record

_ACCOUNT = "id:acme-prod"
_AR = PRINCIPAL_TYPE_ACCOUNT_ROLE


def _rule_keys(record):
    return {f.rule_key for f in evaluate_record(record, "snowflake")}


class TestPrivilegedUserReachability:
    """Real user + user-role grant + role-hierarchy closure -> derived
    snowflake_privileged_user -> Finding."""

    def test_direct_accountadmin_reachable(self):
        hierarchy = [
            {"child_role_name": "SECURITYADMIN", "child_role_type": _AR, "parent_role_name": "ACCOUNTADMIN", "parent_role_type": _AR},
        ]
        children_index = C._build_role_children_index(hierarchy)
        user_records = [{"user_name": "ALICE", "user_type": "person", "disabled": "enabled"}]
        user_role_grants = [{"user_name": "ALICE", "role_name": "ACCOUNTADMIN", "role_type": _AR}]
        users = C._derive_privileged_users(
            _ACCOUNT, user_records=user_records, user_role_grants=user_role_grants,
            children_index=children_index, role_signals={}, closure_memo={},
            completeness="complete",
        )
        assert len(users) == 1
        assert "snowflake_user_accountadmin" in _rule_keys(users[0])

    def test_inherited_securityadmin_reachable(self):
        """A user directly holding a custom role that has SECURITYADMIN
        as a hierarchy child (per real Snowflake docs: child granted to
        parent -> parent inherits child) reaches the SECURITYADMIN
        Finding through inheritance, not a direct grant."""
        hierarchy = [
            {"child_role_name": "SECURITYADMIN", "child_role_type": _AR, "parent_role_name": "CUSTOM_PARENT", "parent_role_type": _AR},
        ]
        children_index = C._build_role_children_index(hierarchy)
        user_records = [{"user_name": "BOB", "user_type": "person", "disabled": "enabled"}]
        user_role_grants = [{"user_name": "BOB", "role_name": "CUSTOM_PARENT", "role_type": _AR}]
        users = C._derive_privileged_users(
            _ACCOUNT, user_records=user_records, user_role_grants=user_role_grants,
            children_index=children_index, role_signals={}, closure_memo={},
            completeness="complete",
        )
        assert "snowflake_user_securityadmin" in _rule_keys(users[0])

    def test_ordinary_user_not_reachable(self):
        user_records = [{"user_name": "CAROL", "user_type": "person", "disabled": "enabled"}]
        user_role_grants = [{"user_name": "CAROL", "role_name": "ANALYST", "role_type": _AR}]
        users = C._derive_privileged_users(
            _ACCOUNT, user_records=user_records, user_role_grants=user_role_grants,
            children_index={}, role_signals={}, closure_memo={},
            completeness="complete",
        )
        assert users == []


class TestPrivilegedRoleReachability:
    """Real custom role + MANAGE GRANTS object grant -> derived
    snowflake_privileged_role -> Finding."""

    def test_custom_role_manage_grants_reachable(self):
        object_grants = [
            {"grantee_name": "DATA_ENGINEER", "grantee_type": _AR, "object_type": "account",
             "privilege": "MANAGE GRANTS", "future_grant": False, "ownership": False,
             "object_fqn": None, "privilege_category": None},
        ]
        signals = C._build_role_signals(
            object_grants, security_integration_names=set(), storage_integration_names=set(),
            external_access_integration_names=set(), managed_access_schema_fqns=set(),
        )
        roles = C._derive_privileged_roles(
            _ACCOUNT,
            account_role_records=[{"role_name": "DATA_ENGINEER"}],
            database_role_records=[], children_index={}, role_signals=signals,
            user_role_grants=[], closure_memo={}, completeness="complete",
        )
        assert len(roles) == 1
        assert "snowflake_custom_role_manage_grants" in _rule_keys(roles[0])

    def test_future_ownership_reachable(self):
        object_grants = [
            {"grantee_name": "FUTURE_OWNER", "grantee_type": _AR, "object_type": "database",
             "privilege": "OWNERSHIP", "future_grant": True, "ownership": True,
             "object_fqn": None, "privilege_category": None},
        ]
        signals = C._build_role_signals(
            object_grants, security_integration_names=set(), storage_integration_names=set(),
            external_access_integration_names=set(), managed_access_schema_fqns=set(),
        )
        roles = C._derive_privileged_roles(
            _ACCOUNT, account_role_records=[{"role_name": "FUTURE_OWNER"}], database_role_records=[],
            children_index={}, role_signals=signals, user_role_grants=[], closure_memo={},
            completeness="complete",
        )
        assert "snowflake_future_ownership_grant" in _rule_keys(roles[0])


class TestPublicExposureReachability:
    """Real future object grant to PUBLIC -> derived
    snowflake_public_exposure -> Finding."""

    def test_future_ownership_to_public_reachable(self):
        object_grants = [
            {"grantee_name": "PUBLIC", "future_grant": True, "object_type": "database", "ownership": True},
        ]
        exposure = C._derive_public_exposure(_ACCOUNT, object_grant_records=object_grants, future_grants_status="complete")
        assert "snowflake_public_future_ownership_grant" in _rule_keys(exposure)

    def test_no_future_public_grants_not_reachable(self):
        exposure = C._derive_public_exposure(_ACCOUNT, object_grant_records=[], future_grants_status="complete")
        assert _rule_keys(exposure) == set()


class TestNetworkPolicyReachability:
    """Real DESCRIBE NETWORK POLICY-shaped normalization -> anywhere
    posture -> Finding."""

    def test_anywhere_ipv4_reachable(self):
        row = {
            "NAME": "OPEN_POLICY", "OWNER": "SECURITYADMIN",
            "ENTRIES_IN_ALLOWED_IP_LIST": "1", "ENTRIES_IN_BLOCKED_IP_LIST": "0",
            "ENTRIES_IN_ALLOWED_NETWORK_RULES": "0", "ENTRIES_IN_BLOCKED_NETWORK_RULES": "0",
        }
        record = C._normalize_network_policy(
            _ACCOUNT, row, allows_anywhere_ipv4=True, allows_anywhere_ipv6=False,
            detail_collection_status="complete",
        )
        assert "snowflake_network_policy_allows_anywhere" in _rule_keys(record)

    def test_restricted_policy_not_reachable(self):
        row = {
            "NAME": "RESTRICTED", "OWNER": "SECURITYADMIN",
            "ENTRIES_IN_ALLOWED_IP_LIST": "1", "ENTRIES_IN_BLOCKED_IP_LIST": "0",
            "ENTRIES_IN_ALLOWED_NETWORK_RULES": "0", "ENTRIES_IN_BLOCKED_NETWORK_RULES": "0",
        }
        record = C._normalize_network_policy(
            _ACCOUNT, row, allows_anywhere_ipv4=False, allows_anywhere_ipv6=False,
            detail_collection_status="complete",
        )
        assert _rule_keys(record) == set()


class TestScimReachability:
    """Real security-integration normalization + message-6 SCIM run-as
    resolution -> Finding."""

    def test_scim_high_privilege_run_as_reachable(self):
        hierarchy = [
            {"child_role_name": "SECURITYADMIN", "child_role_type": _AR, "parent_role_name": "OKTA_PROVISIONER", "parent_role_type": _AR},
        ]
        children_index = C._build_role_children_index(hierarchy)
        row = {"NAME": "MY_SCIM", "TYPE": "SCIM", "ENABLED": "true", "OWNER": "SECURITYADMIN"}
        properties = {"SCIM_RUN_AS_ROLE": "OKTA_PROVISIONER"}
        integration_record = C._normalize_security_integration(_ACCOUNT, row, properties=properties)
        resolved = C._resolve_scim_run_as_context(
            [integration_record],
            account_role_names={"OKTA_PROVISIONER", "SECURITYADMIN"},
            children_index=children_index, role_signals={}, closure_memo={},
        )
        assert len(resolved) == 1
        assert "snowflake_scim_high_privilege_run_as" in _rule_keys(resolved[0])

    def test_scim_unresolvable_role_not_reachable(self):
        row = {"NAME": "MY_SCIM", "TYPE": "SCIM", "ENABLED": "true", "OWNER": "SECURITYADMIN"}
        properties = {"SCIM_RUN_AS_ROLE": "SOME_UNKNOWN_ROLE"}
        integration_record = C._normalize_security_integration(_ACCOUNT, row, properties=properties)
        resolved = C._resolve_scim_run_as_context(
            [integration_record], account_role_names=set(), children_index={}, role_signals={}, closure_memo={},
        )
        assert resolved[0]["scim_run_as_role_tier"] == "unknown"
        assert _rule_keys(resolved[0]) == set()


class TestAuthenticationPolicyReachability:
    def test_optional_mfa_account_wide_reachable(self):
        row = {"NAME": "STRICT", "OWNER": "SECURITYADMIN", "SET_ON": "ACCOUNT"}
        properties = {"AUTHENTICATION_METHODS": "['SAML']", "MFA_ENROLLMENT": "OPTIONAL", "CLIENT_TYPES": "['ALL']"}
        record = C._normalize_authentication_policy(_ACCOUNT, row, properties=properties)
        assert "snowflake_mfa_optional_for_person_auth" in _rule_keys(record)

    def test_required_not_reachable(self):
        row = {"NAME": "STRICT", "OWNER": "SECURITYADMIN", "SET_ON": "ACCOUNT"}
        properties = {"AUTHENTICATION_METHODS": "['SAML']", "MFA_ENROLLMENT": "REQUIRED", "CLIENT_TYPES": "['ALL']"}
        record = C._normalize_authentication_policy(_ACCOUNT, row, properties=properties)
        assert _rule_keys(record) == set()
