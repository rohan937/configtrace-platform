"""Snowflake effective-privilege normalization tests (Snowflake message 5
of 8).

Covers ``SnowflakeConnector._derive_privileged_users`` /
``._derive_privileged_roles`` / ``._derive_public_exposure`` and the
supporting tier/category helpers in ``snowflake_schema.py``: system-role
tiers, unknown-is-not-low ranking, custom-role privilege derivation from
actual grants (never from name), MANAGE GRANTS handling, ownership
rollups (including managed-access-schema and integration cross-
referencing), PUBLIC wording/exposure discipline, and completeness
propagation. Unit-level only — calls the connector's derivation functions
directly with synthetic already-collected records, no HTTP mocking.
"""

from __future__ import annotations

from app.connectors.snowflake import SnowflakeConnector as C
from app.connectors.snowflake_schema import (
    PRINCIPAL_TYPE_ACCOUNT_ROLE,
    PRINCIPAL_TYPE_DATABASE_ROLE,
    PRIVILEGE_COMPLETENESS_COMPLETE,
    PRIVILEGE_COMPLETENESS_PARTIAL,
    PRIVILEGE_COMPLETENESS_UNKNOWN,
    PRIVILEGE_TIER_CRITICAL,
    PRIVILEGE_TIER_HIGH,
    PRIVILEGE_TIER_LOW,
    PRIVILEGE_TIER_MEDIUM,
    PRIVILEGE_TIER_READ_ONLY,
    PRIVILEGE_TIER_UNKNOWN,
    PUBLIC_EXPOSURE_CATEGORY_ACCOUNT_WIDE,
    ROLE_PRIVILEGE_CATEGORY_GRANT_MANAGEMENT,
    ROLE_PRIVILEGE_CATEGORY_IDENTITY_ADMINISTRATION,
    ROLE_PRIVILEGE_CATEGORY_UNKNOWN,
    ROLE_PRIVILEGE_CATEGORY_WAREHOUSE_CONTROL,
    categorize_global_privilege,
    highest_privilege_tier,
    privilege_completeness_for_families,
    privilege_tier_for_custom_role_signals,
    privilege_tier_for_role_category,
)

_AR = PRINCIPAL_TYPE_ACCOUNT_ROLE
_DR = PRINCIPAL_TYPE_DATABASE_ROLE
_ACCOUNT = "acme-prod"


def _hierarchy_edge(child_name, child_type, parent_name, parent_type):
    return {
        "child_role_name": child_name, "child_role_type": child_type,
        "parent_role_name": parent_name, "parent_role_type": parent_type,
    }


def _user_role_grant(user_name, role_name, role_type=_AR):
    return {"user_name": user_name, "role_name": role_name, "role_type": role_type}


def _object_grant(grantee_name, grantee_type=_AR, *, object_type="account", privilege="",
                   future_grant=False, ownership=False, object_fqn=None, privilege_category=None):
    return {
        "grantee_name": grantee_name, "grantee_type": grantee_type,
        "object_type": object_type, "privilege": privilege,
        "future_grant": future_grant, "ownership": ownership,
        "object_fqn": object_fqn, "privilege_category": privilege_category,
    }


def _account_role(name):
    return {"role_name": name}


def _database_role(name, database_name="MYDB"):
    return {"role_name": name, "database_name": database_name}


def _user(name, user_type="person", disabled="enabled"):
    return {"user_name": name, "user_type": user_type, "disabled": disabled}


# ── Privilege-tier taxonomy ──────────────────────────────────────────────────


class TestPrivilegeTierTaxonomy:
    def test_unknown_ranks_below_every_known_tier(self):
        for tier in (PRIVILEGE_TIER_READ_ONLY, PRIVILEGE_TIER_LOW, PRIVILEGE_TIER_MEDIUM,
                     PRIVILEGE_TIER_HIGH, PRIVILEGE_TIER_CRITICAL):
            assert highest_privilege_tier([PRIVILEGE_TIER_UNKNOWN, tier]) == tier

    def test_unknown_alone_is_unknown(self):
        assert highest_privilege_tier([PRIVILEGE_TIER_UNKNOWN]) == PRIVILEGE_TIER_UNKNOWN

    def test_empty_list_is_unknown(self):
        assert highest_privilege_tier([]) == PRIVILEGE_TIER_UNKNOWN

    def test_critical_beats_high(self):
        assert highest_privilege_tier([PRIVILEGE_TIER_HIGH, PRIVILEGE_TIER_CRITICAL]) == PRIVILEGE_TIER_CRITICAL

    def test_accountadmin_is_critical(self):
        """Case A."""
        assert privilege_tier_for_role_category("accountadmin") == PRIVILEGE_TIER_CRITICAL

    def test_securityadmin_is_high(self):
        """Case B."""
        assert privilege_tier_for_role_category("securityadmin") == PRIVILEGE_TIER_HIGH

    def test_sysadmin_is_medium(self):
        """Case C."""
        assert privilege_tier_for_role_category("sysadmin") == PRIVILEGE_TIER_MEDIUM

    def test_useradmin_is_medium(self):
        """Case D."""
        assert privilege_tier_for_role_category("useradmin") == PRIVILEGE_TIER_MEDIUM

    def test_public_role_itself_is_read_only(self):
        """Case E: PUBLIC's own intrinsic tier is read_only — what matters
        is what has been granted TO it (see TestPublicExposure below)."""
        assert privilege_tier_for_role_category("public") == PRIVILEGE_TIER_READ_ONLY

    def test_orgadmin_is_high(self):
        """Case F/G: ORGADMIN/GLOBALORGADMIN both map to role_category
        'orgadmin' upstream (message 2) and are classified High here."""
        assert privilege_tier_for_role_category("orgadmin") == PRIVILEGE_TIER_HIGH

    def test_custom_role_unknown_category_returns_unknown(self):
        assert privilege_tier_for_role_category("custom") == PRIVILEGE_TIER_UNKNOWN
        assert privilege_tier_for_role_category("unknown") == PRIVILEGE_TIER_UNKNOWN


class TestCustomRoleDerivation:
    def test_manage_grants_plus_identity_admin_is_critical(self):
        """Case J+K combined -> Critical, matching the task's own
        DATA_ENGINEER worked example (MANAGE GRANTS + CREATE USER/ROLE)."""
        tier = privilege_tier_for_custom_role_signals(
            has_manage_grants=True, has_identity_admin_privilege=True,
            has_object_creation_privilege=False, has_broad_ownership=False,
        )
        assert tier == PRIVILEGE_TIER_CRITICAL

    def test_manage_grants_alone_is_high(self):
        """Case J."""
        tier = privilege_tier_for_custom_role_signals(
            has_manage_grants=True, has_identity_admin_privilege=False,
            has_object_creation_privilege=False, has_broad_ownership=False,
        )
        assert tier == PRIVILEGE_TIER_HIGH

    def test_broad_ownership_alone_is_high(self):
        tier = privilege_tier_for_custom_role_signals(
            has_manage_grants=False, has_identity_admin_privilege=False,
            has_object_creation_privilege=False, has_broad_ownership=True,
        )
        assert tier == PRIVILEGE_TIER_HIGH

    def test_identity_admin_alone_is_medium(self):
        """Case K."""
        tier = privilege_tier_for_custom_role_signals(
            has_manage_grants=False, has_identity_admin_privilege=True,
            has_object_creation_privilege=False, has_broad_ownership=False,
        )
        assert tier == PRIVILEGE_TIER_MEDIUM

    def test_no_signals_is_low_not_unknown(self):
        """An observed-but-unremarkable custom role (no signals found) is
        'low', not 'unknown' — the absence of powerful grants IS known
        information, distinct from never having collected grants at all."""
        tier = privilege_tier_for_custom_role_signals(
            has_manage_grants=False, has_identity_admin_privilege=False,
            has_object_creation_privilege=False, has_broad_ownership=False,
        )
        assert tier == PRIVILEGE_TIER_LOW

    def test_classified_from_grants_never_from_name(self):
        """Case H/I/O worked example: a role literally named
        'INNOCENT_LOOKING_ROLE' with MANAGE GRANTS + CREATE USER is
        Critical regardless of its display name."""
        tier = privilege_tier_for_custom_role_signals(
            has_manage_grants=True, has_identity_admin_privilege=True,
            has_object_creation_privilege=True, has_broad_ownership=True,
        )
        assert tier == PRIVILEGE_TIER_CRITICAL


class TestGlobalPrivilegeCategorization:
    def test_manage_grants_categorized(self):
        assert categorize_global_privilege("MANAGE GRANTS") == ROLE_PRIVILEGE_CATEGORY_GRANT_MANAGEMENT

    def test_create_user_categorized_identity_administration(self):
        assert categorize_global_privilege("CREATE USER") == ROLE_PRIVILEGE_CATEGORY_IDENTITY_ADMINISTRATION

    def test_create_warehouse_categorized(self):
        """Case L: warehouse-admin custom role."""
        assert categorize_global_privilege("CREATE WAREHOUSE") == ROLE_PRIVILEGE_CATEGORY_WAREHOUSE_CONTROL

    def test_unrecognized_create_falls_back_to_object_creation(self):
        from app.connectors.snowflake_schema import ROLE_PRIVILEGE_CATEGORY_OBJECT_CREATION
        assert categorize_global_privilege("CREATE FUTURE THING") == ROLE_PRIVILEGE_CATEGORY_OBJECT_CREATION

    def test_never_invents_a_category_for_unrecognized_privilege(self):
        """Case O: an unrecognized/future privilege string must map to
        unknown, never a guessed category."""
        assert categorize_global_privilege("SOME_FUTURE_PRIVILEGE") == ROLE_PRIVILEGE_CATEGORY_UNKNOWN

    def test_empty_and_non_string_are_unknown(self):
        assert categorize_global_privilege("") == ROLE_PRIVILEGE_CATEGORY_UNKNOWN
        assert categorize_global_privilege(None) == ROLE_PRIVILEGE_CATEGORY_UNKNOWN


class TestCompleteness:
    def test_all_families_complete_is_complete(self):
        fc = {f: "complete" for f in ("users", "account_roles")}
        assert privilege_completeness_for_families(fc, ("users", "account_roles")) == PRIVILEGE_COMPLETENESS_COMPLETE

    def test_one_family_denied_is_partial(self):
        """Case BJ/BK/BL/BM."""
        fc = {"users": "complete", "account_roles": "denied"}
        assert privilege_completeness_for_families(fc, ("users", "account_roles")) == PRIVILEGE_COMPLETENESS_PARTIAL

    def test_all_families_missing_is_unknown(self):
        assert privilege_completeness_for_families({}, ("users", "account_roles")) == PRIVILEGE_COMPLETENESS_UNKNOWN


# ── End-to-end derivation (privileged users) ─────────────────────────────────


class TestDerivePrivilegedUsers:
    def _base(self):
        hierarchy = [
            _hierarchy_edge("SECURITYADMIN", _AR, "ACCOUNTADMIN", _AR),
            _hierarchy_edge("SYSADMIN", _AR, "ACCOUNTADMIN", _AR),
            _hierarchy_edge("USERADMIN", _AR, "SECURITYADMIN", _AR),
        ]
        children_index = C._build_role_children_index(hierarchy)
        return children_index

    def test_direct_accountadmin_is_critical(self):
        """Case Y."""
        children_index = self._base()
        grants = [_user_role_grant("ALICE", "ACCOUNTADMIN")]
        users = C._derive_privileged_users(
            _ACCOUNT, user_records=[_user("ALICE")], user_role_grants=grants,
            children_index=children_index, role_signals={}, closure_memo={},
            completeness=PRIVILEGE_COMPLETENESS_COMPLETE,
        )
        assert len(users) == 1
        assert users[0]["highest_known_privilege_tier"] == PRIVILEGE_TIER_CRITICAL
        assert users[0]["has_accountadmin"] is True

    def test_inherited_accountadmin_via_custom_role(self):
        """Case Z: a custom role granted AS A CHILD of ACCOUNTADMIN
        (ACCOUNTADMIN inherits the custom role's privileges, and — per
        this connector's downward closure semantics — a user directly
        holding ACCOUNTADMIN inherits everything below it). This test
        instead verifies the more common "inherited built-in tier"
        shape: a user holding a role that has SECURITYADMIN as a
        descendant effectively has SECURITYADMIN."""
        hierarchy = [_hierarchy_edge("SECURITYADMIN", _AR, "CUSTOM_PARENT", _AR)]
        children_index = C._build_role_children_index(hierarchy)
        grants = [_user_role_grant("BOB", "CUSTOM_PARENT")]
        users = C._derive_privileged_users(
            _ACCOUNT, user_records=[_user("BOB")], user_role_grants=grants,
            children_index=children_index, role_signals={}, closure_memo={},
            completeness=PRIVILEGE_COMPLETENESS_COMPLETE,
        )
        assert users[0]["has_securityadmin"] is True
        assert users[0]["highest_known_privilege_tier"] == PRIVILEGE_TIER_HIGH

    def test_securityadmin_direct(self):
        """Case AA."""
        children_index = self._base()
        grants = [_user_role_grant("CAROL", "SECURITYADMIN")]
        users = C._derive_privileged_users(
            _ACCOUNT, user_records=[_user("CAROL")], user_role_grants=grants,
            children_index=children_index, role_signals={}, closure_memo={},
            completeness=PRIVILEGE_COMPLETENESS_COMPLETE,
        )
        assert users[0]["has_securityadmin"] is True
        assert users[0]["highest_known_privilege_tier"] == PRIVILEGE_TIER_HIGH

    def test_manage_grants_custom_role(self):
        """Case AB: DATA_ENGINEER-style custom role with MANAGE GRANTS +
        CREATE USER."""
        grants = [_user_role_grant("DAVE", "DATA_ENGINEER")]
        signals = C._build_role_signals(
            [
                _object_grant("DATA_ENGINEER", privilege="MANAGE GRANTS"),
                _object_grant("DATA_ENGINEER", privilege="CREATE USER"),
            ],
            security_integration_names=set(), storage_integration_names=set(),
            external_access_integration_names=set(), managed_access_schema_fqns=set(),
        )
        users = C._derive_privileged_users(
            _ACCOUNT, user_records=[_user("DAVE", user_type="service")], user_role_grants=grants,
            children_index={}, role_signals=signals, closure_memo={},
            completeness=PRIVILEGE_COMPLETENESS_COMPLETE,
        )
        assert users[0]["highest_known_privilege_tier"] == PRIVILEGE_TIER_CRITICAL
        assert users[0]["has_manage_grants"] is True

    def test_sysadmin_direct(self):
        """Case AC."""
        children_index = self._base()
        grants = [_user_role_grant("ERIN", "SYSADMIN")]
        users = C._derive_privileged_users(
            _ACCOUNT, user_records=[_user("ERIN")], user_role_grants=grants,
            children_index=children_index, role_signals={}, closure_memo={},
            completeness=PRIVILEGE_COMPLETENESS_COMPLETE,
        )
        assert users[0]["has_sysadmin"] is True

    def test_useradmin_direct(self):
        """Case AD."""
        children_index = self._base()
        grants = [_user_role_grant("FRANK", "USERADMIN")]
        users = C._derive_privileged_users(
            _ACCOUNT, user_records=[_user("FRANK")], user_role_grants=grants,
            children_index=children_index, role_signals={}, closure_memo={},
            completeness=PRIVILEGE_COMPLETENESS_COMPLETE,
        )
        assert users[0]["has_useradmin"] is True

    def test_disabled_critical_user_still_emitted(self):
        """Case AE: a disabled ACCOUNTADMIN entitlement is kept visible —
        privilege may return if re-enabled."""
        children_index = self._base()
        grants = [_user_role_grant("GRACE", "ACCOUNTADMIN")]
        users = C._derive_privileged_users(
            _ACCOUNT, user_records=[_user("GRACE", disabled="disabled")], user_role_grants=grants,
            children_index=children_index, role_signals={}, closure_memo={},
            completeness=PRIVILEGE_COMPLETENESS_COMPLETE,
        )
        assert len(users) == 1
        assert users[0]["disabled"] == "disabled"
        assert users[0]["highest_known_privilege_tier"] == PRIVILEGE_TIER_CRITICAL

    def test_service_user_with_critical_privilege(self):
        """Case AF: a service user is NOT called risky solely by type —
        but its privilege tier is preserved structurally alongside its
        user_type."""
        children_index = self._base()
        grants = [_user_role_grant("SVC_PIPE", "ACCOUNTADMIN")]
        users = C._derive_privileged_users(
            _ACCOUNT, user_records=[_user("SVC_PIPE", user_type="service")], user_role_grants=grants,
            children_index=children_index, role_signals={}, closure_memo={},
            completeness=PRIVILEGE_COMPLETENESS_COMPLETE,
        )
        assert users[0]["user_type"] == "service"
        assert users[0]["highest_known_privilege_tier"] == PRIVILEGE_TIER_CRITICAL

    def test_ordinary_service_user_excluded(self):
        """Case AG: an ordinary service user with only a low-privilege
        custom role gets no privileged_user record at all."""
        grants = [_user_role_grant("SVC_READER", "READ_ONLY_ROLE")]
        users = C._derive_privileged_users(
            _ACCOUNT, user_records=[_user("SVC_READER", user_type="service")], user_role_grants=grants,
            children_index={}, role_signals={}, closure_memo={},
            completeness=PRIVILEGE_COMPLETENESS_COMPLETE,
        )
        assert users == []

    def test_ordinary_user_excluded(self):
        grants = [_user_role_grant("HEIDI", "ANALYST")]
        users = C._derive_privileged_users(
            _ACCOUNT, user_records=[_user("HEIDI")], user_role_grants=grants,
            children_index={}, role_signals={}, closure_memo={},
            completeness=PRIVILEGE_COMPLETENESS_COMPLETE,
        )
        assert users == []

    def test_highest_tier_deterministic_regardless_of_role_order(self):
        """Case AH: a user holding two directly-granted roles in
        different orders must resolve to the same highest tier."""
        children_index = self._base()
        grants_a = [_user_role_grant("IVAN", "SYSADMIN"), _user_role_grant("IVAN", "ACCOUNTADMIN")]
        grants_b = list(reversed(grants_a))
        users_a = C._derive_privileged_users(
            _ACCOUNT, user_records=[_user("IVAN")], user_role_grants=grants_a,
            children_index=children_index, role_signals={}, closure_memo={},
            completeness=PRIVILEGE_COMPLETENESS_COMPLETE,
        )
        users_b = C._derive_privileged_users(
            _ACCOUNT, user_records=[_user("IVAN")], user_role_grants=grants_b,
            children_index=children_index, role_signals={}, closure_memo={},
            completeness=PRIVILEGE_COMPLETENESS_COMPLETE,
        )
        assert users_a[0]["highest_known_privilege_tier"] == users_b[0]["highest_known_privilege_tier"] == PRIVILEGE_TIER_CRITICAL

    def test_unknown_hierarchy_never_falsely_denies_accountadmin(self):
        """Section BP: with an empty/incomplete children_index, a user
        directly holding ACCOUNTADMIN must still show has_accountadmin
        True from the direct grant alone — hierarchy incompleteness only
        affects INHERITED evidence, never a direct grant already known."""
        users = C._derive_privileged_users(
            _ACCOUNT, user_records=[_user("JUDY")], user_role_grants=[_user_role_grant("JUDY", "ACCOUNTADMIN")],
            children_index={}, role_signals={}, closure_memo={},
            completeness=PRIVILEGE_COMPLETENESS_UNKNOWN,
        )
        assert users[0]["has_accountadmin"] is True
        assert users[0]["privilege_completeness"] == PRIVILEGE_COMPLETENESS_UNKNOWN


# ── End-to-end derivation (privileged roles) ─────────────────────────────────


class TestDerivePrivilegedRoles:
    def test_accountadmin_role_dedupes_hierarchy_descendants(self):
        """Section 30: ACCOUNTADMIN's own record reports inherited counts,
        never duplicate records for SYSADMIN/SECURITYADMIN separately
        counted twice."""
        hierarchy = [
            _hierarchy_edge("SECURITYADMIN", _AR, "ACCOUNTADMIN", _AR),
            _hierarchy_edge("SYSADMIN", _AR, "ACCOUNTADMIN", _AR),
        ]
        children_index = C._build_role_children_index(hierarchy)
        roles = C._derive_privileged_roles(
            _ACCOUNT,
            account_role_records=[_account_role("ACCOUNTADMIN"), _account_role("SECURITYADMIN"), _account_role("SYSADMIN")],
            database_role_records=[], children_index=children_index, role_signals={},
            user_role_grants=[], closure_memo={}, completeness=PRIVILEGE_COMPLETENESS_COMPLETE,
        )
        accountadmin = next(r for r in roles if r["role_name"] == "ACCOUNTADMIN")
        assert accountadmin["inherited_child_role_count"] == 2
        assert accountadmin["highest_known_privilege_tier"] == PRIVILEGE_TIER_CRITICAL

    def test_ordinary_readonly_role_excluded(self):
        roles = C._derive_privileged_roles(
            _ACCOUNT, account_role_records=[_account_role("READ_ONLY_ROLE")], database_role_records=[],
            children_index={}, role_signals={}, user_role_grants=[], closure_memo={},
            completeness=PRIVILEGE_COMPLETENESS_COMPLETE,
        )
        assert roles == []

    def test_database_role_included_when_owns_database_object(self):
        """Case AI-equivalent at the role level, and section 76: a
        database role with OWNERSHIP is included, an ordinary data-access
        database role is not."""
        signals = C._build_role_signals(
            [_object_grant("DB_OWNER_ROLE", grantee_type=_DR, object_type="database", ownership=True)],
            security_integration_names=set(), storage_integration_names=set(),
            external_access_integration_names=set(), managed_access_schema_fqns=set(),
        )
        roles = C._derive_privileged_roles(
            _ACCOUNT, account_role_records=[], database_role_records=[_database_role("DB_OWNER_ROLE")],
            children_index={}, role_signals=signals, user_role_grants=[], closure_memo={},
            completeness=PRIVILEGE_COMPLETENESS_COMPLETE,
        )
        assert len(roles) == 1
        assert roles[0]["owns_database_count"] == 1
        assert roles[0]["role_type"] == _DR

    def test_managed_access_schema_ownership_flagged(self):
        """Case AK: schema ownership inside a managed-access schema is
        tracked separately from an ordinary schema."""
        signals = C._build_role_signals(
            [_object_grant("SCHEMA_OWNER", object_type="schema", ownership=True, object_fqn="MYDB.SENSITIVE")],
            security_integration_names=set(), storage_integration_names=set(),
            external_access_integration_names=set(), managed_access_schema_fqns={"MYDB.SENSITIVE"},
        )
        roles = C._derive_privileged_roles(
            _ACCOUNT, account_role_records=[_account_role("SCHEMA_OWNER")], database_role_records=[],
            children_index={}, role_signals=signals, user_role_grants=[], closure_memo={},
            completeness=PRIVILEGE_COMPLETENESS_COMPLETE,
        )
        assert roles[0]["owns_managed_access_schema_count"] == 1
        assert roles[0]["owns_schema_count"] == 1

    def test_security_integration_ownership_cross_referenced(self):
        """Case AM: OWNERSHIP on an 'integration'-typed object grant is
        attributed to owns_security_integration_count only when its FQN
        matches a known security-integration name."""
        signals = C._build_role_signals(
            [_object_grant("INTEGRATION_ADMIN", object_type="integration", ownership=True, object_fqn="MY_SCIM")],
            security_integration_names={"MY_SCIM"}, storage_integration_names=set(),
            external_access_integration_names=set(), managed_access_schema_fqns=set(),
        )
        roles = C._derive_privileged_roles(
            _ACCOUNT, account_role_records=[_account_role("INTEGRATION_ADMIN")], database_role_records=[],
            children_index={}, role_signals=signals, user_role_grants=[], closure_memo={},
            completeness=PRIVILEGE_COMPLETENESS_COMPLETE,
        )
        assert roles[0]["owns_security_integration_count"] == 1
        assert roles[0]["owns_storage_integration_count"] == 0

    def test_network_policy_ownership_tracked(self):
        """Case AO."""
        signals = C._build_role_signals(
            [_object_grant("NETADMIN", object_type="network_policy", ownership=True)],
            security_integration_names=set(), storage_integration_names=set(),
            external_access_integration_names=set(), managed_access_schema_fqns=set(),
        )
        roles = C._derive_privileged_roles(
            _ACCOUNT, account_role_records=[_account_role("NETADMIN")], database_role_records=[],
            children_index={}, role_signals=signals, user_role_grants=[], closure_memo={},
            completeness=PRIVILEGE_COMPLETENESS_COMPLETE,
        )
        assert roles[0]["owns_network_policy_count"] == 1

    def test_authentication_policy_ownership_tracked(self):
        """Case AN."""
        signals = C._build_role_signals(
            [_object_grant("AUTHADMIN", object_type="authentication_policy", ownership=True)],
            security_integration_names=set(), storage_integration_names=set(),
            external_access_integration_names=set(), managed_access_schema_fqns=set(),
        )
        roles = C._derive_privileged_roles(
            _ACCOUNT, account_role_records=[_account_role("AUTHADMIN")], database_role_records=[],
            children_index={}, role_signals=signals, user_role_grants=[], closure_memo={},
            completeness=PRIVILEGE_COMPLETENESS_COMPLETE,
        )
        assert roles[0]["owns_authentication_policy_count"] == 1

    def test_future_ownership_tracked_high_risk(self):
        """Case AZ."""
        signals = C._build_role_signals(
            [_object_grant("FUTURE_OWNER", object_type="database", ownership=True, future_grant=True)],
            security_integration_names=set(), storage_integration_names=set(),
            external_access_integration_names=set(), managed_access_schema_fqns=set(),
        )
        roles = C._derive_privileged_roles(
            _ACCOUNT, account_role_records=[_account_role("FUTURE_OWNER")], database_role_records=[],
            children_index={}, role_signals=signals, user_role_grants=[], closure_memo={},
            completeness=PRIVILEGE_COMPLETENESS_COMPLETE,
        )
        assert roles[0]["future_ownership_count"] == 1

    def test_direct_user_assignment_count(self):
        roles = C._derive_privileged_roles(
            _ACCOUNT, account_role_records=[_account_role("CUSTOM_ADMIN")], database_role_records=[],
            children_index={},
            role_signals=C._build_role_signals(
                [_object_grant("CUSTOM_ADMIN", privilege="MANAGE GRANTS")],
                security_integration_names=set(), storage_integration_names=set(),
                external_access_integration_names=set(), managed_access_schema_fqns=set(),
            ),
            user_role_grants=[_user_role_grant("A", "CUSTOM_ADMIN"), _user_role_grant("B", "CUSTOM_ADMIN")],
            closure_memo={}, completeness=PRIVILEGE_COMPLETENESS_COMPLETE,
        )
        assert roles[0]["direct_user_assignment_count"] == 2


# ── PUBLIC exposure ───────────────────────────────────────────────────────────


class TestPublicExposure:
    def test_no_future_public_grants_is_zero_not_none(self):
        """With object grants collected but none targeting PUBLIC, the
        future count is a real, known zero (unlike current_public_exposure
        below, which is a genuine collection gap)."""
        result = C._derive_public_exposure(_ACCOUNT, object_grant_records=[], future_grants_status="complete")
        assert result["future_public_exposure_count"] == 0

    def test_current_exposure_is_none_not_zero(self):
        """Section 55/AR: current PUBLIC object grants were never
        collected (message 2/3 excluded PUBLIC from per-role SHOW GRANTS
        TO ROLE enumeration) — this is a documented gap, not a real zero."""
        result = C._derive_public_exposure(_ACCOUNT, object_grant_records=[], future_grants_status="complete")
        assert result["current_public_exposure_count"] is None
        assert result["current_public_exposure_data_available"] is False

    def test_future_select_to_public_counted(self):
        """Case AU/AS."""
        grants = [_object_grant("PUBLIC", future_grant=True, object_type="schema",
                                 privilege="SELECT", privilege_category="data_read")]
        result = C._derive_public_exposure(_ACCOUNT, object_grant_records=grants, future_grants_status="complete")
        assert result["future_public_exposure_count"] == 1
        assert result["future_public_read_count"] == 1

    def test_future_write_to_public_counted(self):
        """Case AY."""
        grants = [_object_grant("PUBLIC", future_grant=True, object_type="schema",
                                 privilege="INSERT", privilege_category="data_write")]
        result = C._derive_public_exposure(_ACCOUNT, object_grant_records=grants, future_grants_status="complete")
        assert result["future_public_write_count"] == 1

    def test_future_ownership_to_public_counted(self):
        """Case AZ (PUBLIC variant): future OWNERSHIP to PUBLIC — an
        extremely broad grant, tracked distinctly from ordinary future
        grants."""
        grants = [_object_grant("PUBLIC", future_grant=True, object_type="database", ownership=True)]
        result = C._derive_public_exposure(_ACCOUNT, object_grant_records=grants, future_grants_status="complete")
        assert result["future_public_ownership_count"] == 1

    def test_future_grant_removal_reflected(self):
        """Case BA: removing a future grant to PUBLIC is reflected by the
        count simply dropping to 0 when no such grant exists any more."""
        result = C._derive_public_exposure(_ACCOUNT, object_grant_records=[], future_grants_status="complete")
        assert result["future_public_exposure_count"] == 0

    def test_only_future_grants_counted_not_current(self):
        """A current (non-future) grant to PUBLIC must NOT be counted
        here — this connector never collects current PUBLIC grants, so
        any current_grant=False row reaching this function would be a
        bug upstream; defensively, this function only counts
        future_grant=True rows."""
        grants = [_object_grant("PUBLIC", future_grant=False, object_type="schema", privilege="SELECT")]
        result = C._derive_public_exposure(_ACCOUNT, object_grant_records=grants, future_grants_status="complete")
        assert result["future_public_exposure_count"] == 0

    def test_exposure_category_is_account_wide_never_internet(self):
        """Case AW (MANDATORY): PUBLIC != internet public. The exposure
        category must be the Snowflake-internal wording, never anything
        resembling internet/public-internet exposure."""
        result = C._derive_public_exposure(_ACCOUNT, object_grant_records=[], future_grants_status="complete")
        assert result["exposure_category"] == PUBLIC_EXPOSURE_CATEGORY_ACCOUNT_WIDE
        assert "internet" not in result["exposure_category"].lower()

    def test_record_shape_never_mentions_internet_exposure(self):
        """Belt-and-suspenders on the wording rule: scan the entire
        serialized record for the word 'internet' — it must never
        appear anywhere in a PUBLIC-exposure record."""
        result = C._derive_public_exposure(_ACCOUNT, object_grant_records=[], future_grants_status="complete")
        assert "internet" not in str(result).lower()

    def test_completeness_partial_when_future_grants_incomplete(self):
        result = C._derive_public_exposure(_ACCOUNT, object_grant_records=[], future_grants_status="partial")
        assert result["privilege_completeness"] == PRIVILEGE_COMPLETENESS_UNKNOWN

    def test_completeness_partial_when_future_grants_complete(self):
        """Even when the future-grants family itself is fully complete,
        the record's own completeness is capped at 'partial' — the
        CURRENT-grant side of PUBLIC exposure is a structural, permanent
        gap this message documents rather than hides."""
        result = C._derive_public_exposure(_ACCOUNT, object_grant_records=[], future_grants_status="complete")
        assert result["privilege_completeness"] == PRIVILEGE_COMPLETENESS_PARTIAL


# ── Scale ─────────────────────────────────────────────────────────────────────
#
# Synthetic scale targets split across dedicated tests (never one giant
# fixture): 25,000 users, 5,000 roles, 10,000 hierarchy edges, 100,000
# object grants, 20,000 future grants. These verify derivation completes
# without per-principal explosion and without pathological slowdown —
# not a formal perf benchmark, just a smoke test that the memoized
# closure/rollup approach scales roughly linearly, not combinatorially.


class TestScale:
    def test_25k_users_25k_role_grants(self):
        user_records = [_user(f"user_{i}") for i in range(25_000)]
        # Every 100th user gets ACCOUNTADMIN directly; the rest get an
        # ordinary role and must be excluded from the privileged-user
        # output entirely.
        grants = [
            _user_role_grant(f"user_{i}", "ACCOUNTADMIN" if i % 100 == 0 else "ORDINARY_ROLE")
            for i in range(25_000)
        ]
        users = C._derive_privileged_users(
            _ACCOUNT, user_records=user_records, user_role_grants=grants,
            children_index={}, role_signals={}, closure_memo={},
            completeness=PRIVILEGE_COMPLETENESS_COMPLETE,
        )
        assert len(users) == 250
        assert all(u["highest_known_privilege_tier"] == PRIVILEGE_TIER_CRITICAL for u in users)

    def test_5k_roles_10k_hierarchy_edges(self):
        account_roles = [_account_role(f"ROLE_{i}") for i in range(5_000)]
        # 10,000 edges: each role i (i>0) has two parents among earlier
        # roles, forming a dense-but-acyclic DAG.
        hierarchy = []
        for i in range(1, 5_000):
            hierarchy.append(_hierarchy_edge(f"ROLE_{i}", _AR, f"ROLE_{(i - 1) // 2}", _AR))
            hierarchy.append(_hierarchy_edge(f"ROLE_{i}", _AR, f"ROLE_{max(0, i - 2)}", _AR))
        assert len(hierarchy) == 9998
        children_index = C._build_role_children_index(hierarchy)
        memo: dict = {}
        closure = C._role_closure(C._role_key(_AR, "ROLE_0"), children_index, memo)
        assert len(closure) >= 1
        # No crash, no unbounded growth — closure is bounded by total node count.
        assert len(closure) <= 5_000

    def test_100k_object_grants(self):
        grants = [
            _object_grant(f"ROLE_{i % 5000}", object_type="database" if i % 10 == 0 else "table",
                           privilege="OWNERSHIP" if i % 10 == 0 else "SELECT",
                           ownership=(i % 10 == 0))
            for i in range(100_000)
        ]
        signals = C._build_role_signals(
            grants, security_integration_names=set(), storage_integration_names=set(),
            external_access_integration_names=set(), managed_access_schema_fqns=set(),
        )
        assert len(signals) == 5000
        assert signals[C._role_key(_AR, "ROLE_0")]["owns_database_count"] >= 1

    def test_20k_future_grants(self):
        grants = [
            _object_grant("PUBLIC", future_grant=True, object_type="schema",
                           privilege="SELECT", privilege_category="data_read")
            for _ in range(20_000)
        ]
        result = C._derive_public_exposure(_ACCOUNT, object_grant_records=grants, future_grants_status="complete")
        assert result["future_public_exposure_count"] == 20_000
        assert result["future_public_read_count"] == 20_000
