"""Microsoft Entra ID identity normalization tests (Entra message 2 of 8).

Covers ``EntraConnector._normalize_user`` / ``_normalize_group`` /
``_normalize_membership`` in isolation: accountEnabled tri-state discipline,
userType taxonomy, lifecycle-posture combination, externalUserState,
group-type taxonomy (security/M365/dynamic/role-assignable), groupTypes
normalization, membership-count bucketing, and the sensitive-data
exclusion boundary.
"""

from __future__ import annotations

import pytest

from app.connectors.entra import EntraConnector
from app.connectors.entra_schema import (
    ACCOUNT_ENABLED_DISABLED,
    ACCOUNT_ENABLED_ENABLED,
    ACCOUNT_ENABLED_UNKNOWN,
    EXTERNAL_USER_STATE_ACCEPTED,
    EXTERNAL_USER_STATE_PENDING,
    EXTERNAL_USER_STATE_UNKNOWN,
    GROUP_TYPE_DISTRIBUTION_OR_MAIL,
    GROUP_TYPE_DYNAMIC_MICROSOFT_365,
    GROUP_TYPE_DYNAMIC_SECURITY,
    GROUP_TYPE_MICROSOFT_365,
    GROUP_TYPE_OTHER,
    GROUP_TYPE_SECURITY,
    GROUP_TYPE_UNKNOWN,
    LIFECYCLE_DISABLED_GUEST,
    LIFECYCLE_DISABLED_MEMBER,
    LIFECYCLE_ENABLED_GUEST,
    LIFECYCLE_ENABLED_MEMBER,
    LIFECYCLE_UNKNOWN,
    MEMBERSHIP_COUNT_LARGE,
    MEMBERSHIP_COUNT_MEDIUM,
    MEMBERSHIP_COUNT_SMALL,
    MEMBERSHIP_COUNT_UNKNOWN,
    MEMBERSHIP_COUNT_VERY_LARGE,
    MEMBERSHIP_COUNT_ZERO,
    USER_TYPE_GUEST,
    USER_TYPE_MEMBER,
    USER_TYPE_UNKNOWN,
    categorize_account_enabled,
    categorize_external_user_state,
    categorize_group_type,
    categorize_membership_count,
    categorize_user_type,
    lifecycle_posture_for_user,
    normalize_group_types,
)

_TENANT = "id:t1"


def _user(user_id: str = "u1", **overrides) -> dict:
    base = {
        "id": user_id,
        "userPrincipalName": f"{user_id}@example.com",
        "displayName": "Test User",
        "accountEnabled": True,
        "userType": "Member",
        "createdDateTime": "2020-01-01T00:00:00Z",
    }
    base.update(overrides)
    return base


def _group(group_id: str = "g1", **overrides) -> dict:
    base = {
        "id": group_id,
        "displayName": "Engineering",
        "securityEnabled": True,
        "mailEnabled": False,
        "groupTypes": [],
        "isAssignableToRole": False,
    }
    base.update(overrides)
    return base


# ════════════════════════════════════════════════════════════════════════════
# accountEnabled tri-state
# ════════════════════════════════════════════════════════════════════════════


class TestAccountEnabledTriState:
    @pytest.mark.parametrize("raw,expected", [
        (True, ACCOUNT_ENABLED_ENABLED),
        (False, ACCOUNT_ENABLED_DISABLED),
        (None, ACCOUNT_ENABLED_UNKNOWN),
        ("true", ACCOUNT_ENABLED_UNKNOWN),
        (1, ACCOUNT_ENABLED_UNKNOWN),
        ("", ACCOUNT_ENABLED_UNKNOWN),
    ])
    def test_categorize_account_enabled(self, raw, expected):
        assert categorize_account_enabled(raw) == expected

    def test_missing_account_enabled_is_unknown_not_disabled(self):
        rec = EntraConnector._normalize_user(_TENANT, _user(accountEnabled=None))
        assert rec["account_enabled_category"] == ACCOUNT_ENABLED_UNKNOWN

    def test_bool_never_used_for_none(self):
        # bool(None) is False in Python — this must never leak into the
        # normalized category.
        rec = EntraConnector._normalize_user(_TENANT, _user(accountEnabled=None))
        assert rec["account_enabled_category"] != ACCOUNT_ENABLED_DISABLED


# ════════════════════════════════════════════════════════════════════════════
# userType taxonomy
# ════════════════════════════════════════════════════════════════════════════


class TestUserType:
    @pytest.mark.parametrize("raw,expected", [
        ("Member", USER_TYPE_MEMBER),
        ("Guest", USER_TYPE_GUEST),
        (None, USER_TYPE_UNKNOWN),
        ("", USER_TYPE_UNKNOWN),
        ("member", USER_TYPE_UNKNOWN),  # case-sensitive per Graph's own casing
        ("Contractor", USER_TYPE_UNKNOWN),
    ])
    def test_categorize_user_type(self, raw, expected):
        assert categorize_user_type(raw) == expected

    def test_unknown_user_type_never_defaults_to_member(self):
        rec = EntraConnector._normalize_user(_TENANT, _user(userType="SomethingNew"))
        assert rec["user_type_category"] == USER_TYPE_UNKNOWN
        assert rec["member"] is False
        assert rec["guest"] is False

    def test_guest_and_member_flags_mutually_exclusive(self):
        member = EntraConnector._normalize_user(_TENANT, _user(userType="Member"))
        guest = EntraConnector._normalize_user(_TENANT, _user(userType="Guest"))
        assert member["member"] is True and member["guest"] is False
        assert guest["guest"] is True and guest["member"] is False


# ════════════════════════════════════════════════════════════════════════════
# Lifecycle posture combination
# ════════════════════════════════════════════════════════════════════════════


class TestLifecyclePosture:
    @pytest.mark.parametrize("account_enabled,user_type,expected", [
        (True, "Member", LIFECYCLE_ENABLED_MEMBER),
        (False, "Member", LIFECYCLE_DISABLED_MEMBER),
        (True, "Guest", LIFECYCLE_ENABLED_GUEST),
        (False, "Guest", LIFECYCLE_DISABLED_GUEST),
        (None, "Member", LIFECYCLE_UNKNOWN),
        (True, None, LIFECYCLE_UNKNOWN),
        (None, None, LIFECYCLE_UNKNOWN),
    ])
    def test_lifecycle_posture_for_user(self, account_enabled, user_type, expected):
        ae_cat = categorize_account_enabled(account_enabled)
        ut_cat = categorize_user_type(user_type)
        assert lifecycle_posture_for_user(ae_cat, ut_cat) == expected

    def test_guest_is_not_treated_as_inherently_disabled_or_risky(self):
        rec = EntraConnector._normalize_user(_TENANT, _user(userType="Guest", accountEnabled=True))
        assert rec["lifecycle_posture"] == LIFECYCLE_ENABLED_GUEST
        assert rec["guest"] is True

    def test_full_normalization_enabled_member(self):
        rec = EntraConnector._normalize_user(_TENANT, _user())
        assert rec["lifecycle_posture"] == LIFECYCLE_ENABLED_MEMBER

    def test_full_normalization_disabled_guest(self):
        rec = EntraConnector._normalize_user(_TENANT, _user(userType="Guest", accountEnabled=False))
        assert rec["lifecycle_posture"] == LIFECYCLE_DISABLED_GUEST


# ════════════════════════════════════════════════════════════════════════════
# External user state
# ════════════════════════════════════════════════════════════════════════════


class TestExternalUserState:
    @pytest.mark.parametrize("raw,expected", [
        ("PendingAcceptance", EXTERNAL_USER_STATE_PENDING),
        ("Accepted", EXTERNAL_USER_STATE_ACCEPTED),
        (None, EXTERNAL_USER_STATE_UNKNOWN),
        ("SomeOtherState", EXTERNAL_USER_STATE_UNKNOWN),
    ])
    def test_categorize_external_user_state(self, raw, expected):
        assert categorize_external_user_state(raw) == expected

    def test_missing_external_state_on_member_is_unknown(self):
        rec = EntraConnector._normalize_user(_TENANT, _user(userType="Member"))
        assert rec["external_user_state_category"] == EXTERNAL_USER_STATE_UNKNOWN


# ════════════════════════════════════════════════════════════════════════════
# UPN rename / stable identity
# ════════════════════════════════════════════════════════════════════════════


class TestStableUserIdentity:
    def test_record_id_derives_from_tenant_plus_object_id(self):
        rec = EntraConnector._normalize_user(_TENANT, _user("u1"))
        assert rec["record_id"] == f"{_TENANT}/user/u1"

    def test_display_name_change_does_not_affect_record_id(self):
        rec1 = EntraConnector._normalize_user(_TENANT, _user("u1", displayName="Old Name"))
        rec2 = EntraConnector._normalize_user(_TENANT, _user("u1", displayName="New Name"))
        assert rec1["record_id"] == rec2["record_id"]

    def test_missing_user_id_returns_none(self):
        assert EntraConnector._normalize_user(_TENANT, {"userPrincipalName": "x@example.com"}) is None


# ════════════════════════════════════════════════════════════════════════════
# Group type taxonomy
# ════════════════════════════════════════════════════════════════════════════


class TestGroupTypeTaxonomy:
    def test_security_group(self):
        assert categorize_group_type(True, False, []) == GROUP_TYPE_SECURITY

    def test_microsoft_365_group(self):
        assert categorize_group_type(False, True, ["Unified"]) == GROUP_TYPE_MICROSOFT_365

    def test_dynamic_security_group(self):
        assert categorize_group_type(True, False, ["DynamicMembership"]) == GROUP_TYPE_DYNAMIC_SECURITY

    def test_dynamic_microsoft_365_group(self):
        assert categorize_group_type(False, True, ["Unified", "DynamicMembership"]) == GROUP_TYPE_DYNAMIC_MICROSOFT_365

    def test_mail_enabled_non_security_distribution_group(self):
        assert categorize_group_type(False, True, []) == GROUP_TYPE_DISTRIBUTION_OR_MAIL

    def test_unknown_when_security_enabled_missing(self):
        assert categorize_group_type(None, True, []) == GROUP_TYPE_UNKNOWN

    def test_unknown_when_mail_enabled_missing(self):
        assert categorize_group_type(True, None, []) == GROUP_TYPE_UNKNOWN

    def test_unknown_never_defaults_to_ordinary_security(self):
        result = categorize_group_type(None, None, [])
        assert result == GROUP_TYPE_UNKNOWN
        assert result != GROUP_TYPE_SECURITY

    def test_other_category_for_uncommon_combination(self):
        # security=False, mail=False, no groupTypes evidence — a real but
        # uncommon Entra combination (e.g. a group with neither flag set).
        assert categorize_group_type(False, False, []) == GROUP_TYPE_OTHER

    def test_full_normalization_security_group(self):
        rec = EntraConnector._normalize_group(_TENANT, _group(), membership_count=0)
        assert rec["group_type_category"] == GROUP_TYPE_SECURITY
        assert rec["security_group"] is True

    def test_full_normalization_dynamic_m365_group(self):
        rec = EntraConnector._normalize_group(
            _TENANT, _group(securityEnabled=False, mailEnabled=True, groupTypes=["Unified", "DynamicMembership"]),
            membership_count=0,
        )
        assert rec["group_type_category"] == GROUP_TYPE_DYNAMIC_MICROSOFT_365
        assert rec["dynamic_membership"] is True
        assert rec["microsoft_365_group"] is True


class TestSecurityMailEnabledTriState:
    @pytest.mark.parametrize("raw,expected", [(True, True), (False, False), (None, None)])
    def test_security_enabled_preserved_tristate(self, raw, expected):
        rec = EntraConnector._normalize_group(_TENANT, _group(securityEnabled=raw), membership_count=0)
        assert rec["security_enabled"] is expected

    @pytest.mark.parametrize("raw,expected", [(True, True), (False, False), (None, None)])
    def test_mail_enabled_preserved_tristate(self, raw, expected):
        rec = EntraConnector._normalize_group(_TENANT, _group(mailEnabled=raw), membership_count=0)
        assert rec["mail_enabled"] is expected

    def test_unknown_security_enabled_never_coerced_to_false(self):
        rec = EntraConnector._normalize_group(_TENANT, _group(securityEnabled=None), membership_count=0)
        assert rec["security_enabled"] is None
        assert rec["security_enabled"] is not False


class TestRoleAssignable:
    @pytest.mark.parametrize("raw,expected", [(True, True), (False, False), (None, None)])
    def test_role_assignable_tristate_preserved(self, raw, expected):
        rec = EntraConnector._normalize_group(_TENANT, _group(isAssignableToRole=raw), membership_count=0)
        assert rec["role_assignable"] is expected

    def test_missing_role_assignable_is_none_not_false(self):
        group = _group()
        del group["isAssignableToRole"]
        rec = EntraConnector._normalize_group(_TENANT, group, membership_count=0)
        assert rec["role_assignable"] is None


class TestGroupTypesNormalization:
    def test_deduplicated(self):
        assert normalize_group_types(["Unified", "Unified"]) == ["Unified"]

    def test_sorted_deterministically(self):
        assert normalize_group_types(["Unified", "DynamicMembership"]) == ["DynamicMembership", "Unified"]

    def test_order_independent_of_api_response(self):
        a = normalize_group_types(["DynamicMembership", "Unified"])
        b = normalize_group_types(["Unified", "DynamicMembership"])
        assert a == b

    def test_unrecognized_value_preserved(self):
        assert "SomeFutureType" in normalize_group_types(["SomeFutureType"])

    def test_non_list_input_returns_empty(self):
        assert normalize_group_types(None) == []
        assert normalize_group_types("Unified") == []

    def test_missing_group_id_returns_none(self):
        assert EntraConnector._normalize_group(_TENANT, {"displayName": "x"}, membership_count=0) is None

    def test_group_rename_does_not_affect_record_id(self):
        rec1 = EntraConnector._normalize_group(_TENANT, _group("g1", displayName="Old"), membership_count=0)
        rec2 = EntraConnector._normalize_group(_TENANT, _group("g1", displayName="New"), membership_count=0)
        assert rec1["record_id"] == rec2["record_id"]


# ════════════════════════════════════════════════════════════════════════════
# Membership count bucketing
# ════════════════════════════════════════════════════════════════════════════


class TestMembershipCountBucketing:
    @pytest.mark.parametrize("count,expected", [
        (0, MEMBERSHIP_COUNT_ZERO),
        (1, MEMBERSHIP_COUNT_SMALL),
        (5, MEMBERSHIP_COUNT_SMALL),
        (6, MEMBERSHIP_COUNT_MEDIUM),
        (20, MEMBERSHIP_COUNT_MEDIUM),
        (21, MEMBERSHIP_COUNT_LARGE),
        (100, MEMBERSHIP_COUNT_LARGE),
        (101, MEMBERSHIP_COUNT_VERY_LARGE),
        (None, MEMBERSHIP_COUNT_UNKNOWN),
        (-1, MEMBERSHIP_COUNT_UNKNOWN),
        (True, MEMBERSHIP_COUNT_UNKNOWN),  # bool must not pass as int
    ])
    def test_categorize_membership_count(self, count, expected):
        assert categorize_membership_count(count) == expected

    def test_denied_membership_is_unknown_not_zero(self):
        rec = EntraConnector._normalize_group(_TENANT, _group(), membership_count=None)
        assert rec["membership_count"] is None
        assert rec["membership_count_category"] == MEMBERSHIP_COUNT_UNKNOWN

    def test_zero_is_distinct_from_unknown(self):
        rec = EntraConnector._normalize_group(_TENANT, _group(), membership_count=0)
        assert rec["membership_count"] == 0
        assert rec["membership_count_category"] == MEMBERSHIP_COUNT_ZERO


# ════════════════════════════════════════════════════════════════════════════
# Membership normalization
# ════════════════════════════════════════════════════════════════════════════


class TestMembershipNormalization:
    def test_direct_membership_type(self):
        user_rec = EntraConnector._normalize_user(_TENANT, _user("u1"))
        group_rec = EntraConnector._normalize_group(_TENANT, _group("g1"), membership_count=1)
        rec = EntraConnector._normalize_membership(_TENANT, user_rec, group_rec, "u1")
        assert rec["membership_type"] == "direct"

    def test_stable_membership_id(self):
        user_rec = EntraConnector._normalize_user(_TENANT, _user("u1"))
        group_rec = EntraConnector._normalize_group(_TENANT, _group("g1"), membership_count=1)
        rec = EntraConnector._normalize_membership(_TENANT, user_rec, group_rec, "u1")
        assert rec["record_id"] == f"{_TENANT}/membership/g1/u1"

    def test_guest_membership_context_preserved(self):
        user_rec = EntraConnector._normalize_user(_TENANT, _user("u1", userType="Guest"))
        group_rec = EntraConnector._normalize_group(_TENANT, _group("g1"), membership_count=1)
        rec = EntraConnector._normalize_membership(_TENANT, user_rec, group_rec, "u1")
        assert rec["user_type_category"] == USER_TYPE_GUEST

    def test_role_assignable_group_context_preserved(self):
        user_rec = EntraConnector._normalize_user(_TENANT, _user("u1"))
        group_rec = EntraConnector._normalize_group(_TENANT, _group("g1", isAssignableToRole=True), membership_count=1)
        rec = EntraConnector._normalize_membership(_TENANT, user_rec, group_rec, "u1")
        assert rec["role_assignable_group"] is True

    def test_missing_user_record_defaults_to_unknown_context(self):
        group_rec = EntraConnector._normalize_group(_TENANT, _group("g1"), membership_count=1)
        rec = EntraConnector._normalize_membership(_TENANT, None, group_rec, "u1")
        assert rec["user_type_category"] == "unknown"
        assert rec["account_enabled_category"] == "unknown"

    def test_membership_never_duplicates_full_user_or_group_record(self):
        user_rec = EntraConnector._normalize_user(_TENANT, _user("u1"))
        group_rec = EntraConnector._normalize_group(_TENANT, _group("g1"), membership_count=1)
        rec = EntraConnector._normalize_membership(_TENANT, user_rec, group_rec, "u1")
        assert "display_name" not in rec
        assert "membership_count" not in rec


# ════════════════════════════════════════════════════════════════════════════
# Sensitive-data exclusion
# ════════════════════════════════════════════════════════════════════════════


class TestSensitiveDataExclusion:
    def test_user_excludes_phone_and_address_fields(self):
        raw = _user(mobilePhone="+1-555-0100", businessPhones=["+1-555-0101"], streetAddress="1 Main St")
        rec = EntraConnector._normalize_user(_TENANT, raw)
        blob = str(rec)
        assert "555-0100" not in blob
        assert "555-0101" not in blob
        assert "1 Main St" not in blob

    def test_user_excludes_password_profile(self):
        raw = _user(passwordProfile={"password": "SuperSecret123!"})
        rec = EntraConnector._normalize_user(_TENANT, raw)
        assert "SuperSecret123!" not in str(rec)
        assert "passwordProfile" not in rec

    def test_user_excludes_proxy_addresses_and_manager(self):
        raw = _user(proxyAddresses=["SMTP:alt@example.com"], manager={"id": "mgr1"})
        rec = EntraConnector._normalize_user(_TENANT, raw)
        assert "proxyAddresses" not in rec
        assert "manager" not in rec
        assert "alt@example.com" not in str(rec)

    def test_group_excludes_membership_rule(self):
        raw = _group(membershipRule='(user.department -eq "Finance")')
        rec = EntraConnector._normalize_group(_TENANT, raw, membership_count=0)
        assert "membershipRule" not in rec
        assert "Finance" not in str(rec)

    def test_group_excludes_owners_and_mail_aliases(self):
        raw = _group(owners=["u1"], proxyAddresses=["SMTP:group@example.com"], mail="group@example.com")
        rec = EntraConnector._normalize_group(_TENANT, raw, membership_count=0)
        assert "owners" not in rec
        assert "proxyAddresses" not in rec
        assert "mail" not in rec

    def test_no_raw_profile_or_dict_dumped(self):
        raw = _user(customAttribute="should-never-appear")
        rec = EntraConnector._normalize_user(_TENANT, raw)
        assert "should-never-appear" not in str(rec)
