"""Okta identity normalization tests (Okta message 2 of 8).

Covers ``OktaConnector._normalize_user`` / ``_normalize_group`` /
``_normalize_membership`` in isolation: every lifecycle status, unknown/
malformed status discipline, group type taxonomy, built-in/Everyone-group
detection, membership count bucketing, last-login categorization, and the
sensitive-data exclusion boundary.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.connectors.okta import OktaConnector
from app.connectors.okta_schema import (
    GROUP_TYPE_APP_GROUP,
    GROUP_TYPE_BUILT_IN,
    GROUP_TYPE_OKTA_GROUP,
    GROUP_TYPE_UNKNOWN,
    LAST_LOGIN_NEVER,
    LAST_LOGIN_RECENT,
    LAST_LOGIN_STALE,
    LAST_LOGIN_UNKNOWN,
    LIFECYCLE_ACTIVE,
    LIFECYCLE_DEPROVISIONED,
    LIFECYCLE_LOCKED,
    LIFECYCLE_PASSWORD_EXPIRED,
    LIFECYCLE_PRE_ACTIVE,
    LIFECYCLE_RECOVERY,
    LIFECYCLE_SUSPENDED,
    LIFECYCLE_UNKNOWN,
    MEMBERSHIP_COUNT_LARGE,
    MEMBERSHIP_COUNT_MEDIUM,
    MEMBERSHIP_COUNT_SMALL,
    MEMBERSHIP_COUNT_UNKNOWN,
    MEMBERSHIP_COUNT_VERY_LARGE,
    MEMBERSHIP_COUNT_ZERO,
    USER_STATUS_ACTIVE,
    USER_STATUS_DEPROVISIONED,
    USER_STATUS_LOCKED_OUT,
    USER_STATUS_PASSWORD_EXPIRED,
    USER_STATUS_PROVISIONED,
    USER_STATUS_RECOVERY,
    USER_STATUS_STAGED,
    USER_STATUS_SUSPENDED,
    USER_STATUS_UNKNOWN,
    categorize_group_type,
    categorize_last_login,
    categorize_membership_count,
    categorize_user_status,
    is_everyone_group,
    lifecycle_posture_for_status,
)

_TENANT = "id:t1"


def _user(user_id: str = "u1", **overrides) -> dict:
    base = {
        "id": user_id,
        "status": "ACTIVE",
        "profile": {"login": f"{user_id}@example.com", "firstName": "First", "lastName": "Last"},
        "credentials": {"provider": {"type": "OKTA"}},
        "type": {"id": "typ1"},
    }
    base.update(overrides)
    return base


def _group(group_id: str = "g1", **overrides) -> dict:
    base = {
        "id": group_id,
        "type": "OKTA_GROUP",
        "profile": {"name": "Engineering", "description": "Eng team"},
    }
    base.update(overrides)
    return base


# ════════════════════════════════════════════════════════════════════════════
# User lifecycle status — every known status
# ════════════════════════════════════════════════════════════════════════════


class TestEveryLifecycleStatus:
    @pytest.mark.parametrize("raw_status,expected_posture,expected_flags", [
        ("STAGED", LIFECYCLE_PRE_ACTIVE, {"staged": True}),
        ("PROVISIONED", LIFECYCLE_PRE_ACTIVE, {"provisioned": True}),
        ("ACTIVE", LIFECYCLE_ACTIVE, {"active": True}),
        ("RECOVERY", LIFECYCLE_RECOVERY, {"recovery": True}),
        ("LOCKED_OUT", LIFECYCLE_LOCKED, {"locked_out": True}),
        ("PASSWORD_EXPIRED", LIFECYCLE_PASSWORD_EXPIRED, {"password_expired": True}),
        ("SUSPENDED", LIFECYCLE_SUSPENDED, {"suspended": True}),
        ("DEPROVISIONED", LIFECYCLE_DEPROVISIONED, {"deprovisioned": True}),
    ])
    def test_status_maps_to_expected_posture_and_flags(self, raw_status, expected_posture, expected_flags):
        rec = OktaConnector._normalize_user(_TENANT, _user(status=raw_status))
        assert rec["status"] == raw_status
        assert rec["lifecycle_posture"] == expected_posture
        for flag, value in expected_flags.items():
            assert rec[flag] is value
        # Every OTHER boolean flag must be False.
        all_flags = {
            "active", "staged", "provisioned", "recovery", "locked_out",
            "password_expired", "suspended", "deprovisioned",
        }
        for flag in all_flags - set(expected_flags):
            assert rec[flag] is False

    def test_suspended_and_deprovisioned_are_never_conflated(self):
        suspended = OktaConnector._normalize_user(_TENANT, _user(status="SUSPENDED"))
        deprovisioned = OktaConnector._normalize_user(_TENANT, _user(status="DEPROVISIONED"))
        assert suspended["lifecycle_posture"] != deprovisioned["lifecycle_posture"]
        assert suspended["suspended"] is True and suspended["deprovisioned"] is False
        assert deprovisioned["deprovisioned"] is True and deprovisioned["suspended"] is False


class TestUnknownAndMalformedStatus:
    def test_unknown_status_string(self):
        assert categorize_user_status("SOME_FUTURE_STATUS") == USER_STATUS_UNKNOWN

    def test_none_status(self):
        assert categorize_user_status(None) == USER_STATUS_UNKNOWN

    def test_non_string_status(self):
        assert categorize_user_status(12345) == USER_STATUS_UNKNOWN
        assert categorize_user_status({"weird": "shape"}) == USER_STATUS_UNKNOWN

    def test_empty_string_status(self):
        assert categorize_user_status("") == USER_STATUS_UNKNOWN

    def test_lowercase_status_still_recognized(self):
        # Okta's real API always returns uppercase, but normalization
        # should not silently misclassify a differently-cased match.
        assert categorize_user_status("active") == USER_STATUS_ACTIVE

    def test_unknown_status_produces_unknown_posture_not_active(self):
        rec = OktaConnector._normalize_user(_TENANT, _user(status="SOME_FUTURE_STATUS"))
        assert rec["status"] == USER_STATUS_UNKNOWN
        assert rec["lifecycle_posture"] == LIFECYCLE_UNKNOWN
        assert rec["active"] is False

    def test_unknown_status_all_flags_false(self):
        rec = OktaConnector._normalize_user(_TENANT, _user(status=None))
        for flag in (
            "active", "staged", "provisioned", "recovery", "locked_out",
            "password_expired", "suspended", "deprovisioned",
        ):
            assert rec[flag] is False

    def test_malformed_status_is_dict(self):
        rec = OktaConnector._normalize_user(_TENANT, _user(status={"nested": "value"}))
        assert rec["status"] == USER_STATUS_UNKNOWN
        assert rec["lifecycle_posture"] == LIFECYCLE_UNKNOWN

    def test_lifecycle_posture_for_status_unknown_input(self):
        assert lifecycle_posture_for_status("NOT_A_REAL_STATUS") == LIFECYCLE_UNKNOWN
        assert lifecycle_posture_for_status(USER_STATUS_UNKNOWN) == LIFECYCLE_UNKNOWN


# ════════════════════════════════════════════════════════════════════════════
# User identity / profile handling
# ════════════════════════════════════════════════════════════════════════════


class TestUserIdentityAndProfile:
    def test_missing_user_id_returns_none(self):
        assert OktaConnector._normalize_user(_TENANT, {"status": "ACTIVE"}) is None

    def test_login_extracted(self):
        rec = OktaConnector._normalize_user(_TENANT, _user())
        assert rec["login"] == "u1@example.com"

    def test_display_name_assembled_from_first_last(self):
        rec = OktaConnector._normalize_user(_TENANT, _user())
        assert rec["display_name"] == "First Last"

    def test_display_name_none_when_no_name_parts(self):
        raw = _user()
        raw["profile"] = {"login": "u1@example.com"}
        rec = OktaConnector._normalize_user(_TENANT, raw)
        assert rec["display_name"] is None

    def test_credential_provider_category_extracted(self):
        rec = OktaConnector._normalize_user(_TENANT, _user())
        assert rec["credential_provider_category"] == "OKTA"

    def test_user_type_id_extracted(self):
        rec = OktaConnector._normalize_user(_TENANT, _user())
        assert rec["user_type_id"] == "typ1"

    def test_arbitrary_profile_fields_never_copied(self):
        raw = _user()
        raw["profile"]["mobilePhone"] = "+15555550100"
        raw["profile"]["department"] = "Engineering"
        raw["profile"]["title"] = "Staff Engineer"
        rec = OktaConnector._normalize_user(_TENANT, raw)
        assert "mobilePhone" not in rec
        assert "department" not in rec
        assert "title" not in rec
        assert "+15555550100" not in str(rec)


# ════════════════════════════════════════════════════════════════════════════
# Last-login categorization
# ════════════════════════════════════════════════════════════════════════════


class TestLastLoginCategorization:
    def test_none_is_never(self):
        assert categorize_last_login(None) == LAST_LOGIN_NEVER

    def test_recent(self):
        now = datetime(2024, 6, 15, tzinfo=timezone.utc)
        recent = (now - timedelta(days=5)).isoformat().replace("+00:00", "Z")
        assert categorize_last_login(recent, now=now) == LAST_LOGIN_RECENT

    def test_stale(self):
        now = datetime(2024, 6, 15, tzinfo=timezone.utc)
        stale = (now - timedelta(days=90)).isoformat().replace("+00:00", "Z")
        assert categorize_last_login(stale, now=now) == LAST_LOGIN_STALE

    def test_unparseable_is_unknown(self):
        assert categorize_last_login("not-a-timestamp") == LAST_LOGIN_UNKNOWN

    def test_non_string_is_unknown(self):
        assert categorize_last_login(12345) == LAST_LOGIN_UNKNOWN

    def test_boundary_exactly_30_days_is_recent(self):
        now = datetime(2024, 6, 15, tzinfo=timezone.utc)
        boundary = (now - timedelta(days=30)).isoformat().replace("+00:00", "Z")
        assert categorize_last_login(boundary, now=now) == LAST_LOGIN_RECENT


# ════════════════════════════════════════════════════════════════════════════
# Groups — type taxonomy, built-in/Everyone detection
# ════════════════════════════════════════════════════════════════════════════


class TestGroupTypeTaxonomy:
    def test_ordinary_okta_group(self):
        assert categorize_group_type("OKTA_GROUP") == GROUP_TYPE_OKTA_GROUP

    def test_app_group(self):
        assert categorize_group_type("APP_GROUP") == GROUP_TYPE_APP_GROUP

    def test_built_in_group(self):
        assert categorize_group_type("BUILT_IN") == GROUP_TYPE_BUILT_IN

    def test_unknown_group_type(self):
        assert categorize_group_type("SOME_FUTURE_TYPE") == GROUP_TYPE_UNKNOWN

    def test_none_group_type(self):
        assert categorize_group_type(None) == GROUP_TYPE_UNKNOWN

    def test_unknown_type_never_becomes_ordinary_group(self):
        rec = OktaConnector._normalize_group(_TENANT, _group(type="TOTALLY_NEW"), membership_count=0)
        assert rec["group_type"] == GROUP_TYPE_UNKNOWN
        assert rec["built_in"] is False


class TestEveryoneGroupDetection:
    def test_built_in_everyone_is_detected(self):
        assert is_everyone_group(GROUP_TYPE_BUILT_IN, "Everyone") is True

    def test_ordinary_group_named_everyone_is_not_misclassified(self):
        """A group named 'Everyone' that is NOT actually BUILT_IN must
        never be treated as the system Everyone group — API type metadata
        is authoritative, not the name alone."""
        assert is_everyone_group(GROUP_TYPE_OKTA_GROUP, "Everyone") is False

    def test_built_in_group_with_different_name_is_not_everyone(self):
        assert is_everyone_group(GROUP_TYPE_BUILT_IN, "Some Other Built-in Group") is False

    def test_full_normalization_everyone_group(self):
        rec = OktaConnector._normalize_group(
            _TENANT, _group(type="BUILT_IN", profile={"name": "Everyone"}), membership_count=100,
        )
        assert rec["everyone_group"] is True
        assert rec["built_in"] is True

    def test_full_normalization_ordinary_group_named_everyone(self):
        rec = OktaConnector._normalize_group(
            _TENANT, _group(type="OKTA_GROUP", profile={"name": "Everyone"}), membership_count=3,
        )
        assert rec["everyone_group"] is False


class TestGroupProfileHandling:
    def test_missing_group_id_returns_none(self):
        assert OktaConnector._normalize_group(_TENANT, {"type": "OKTA_GROUP"}, membership_count=0) is None

    def test_group_name_extracted(self):
        rec = OktaConnector._normalize_group(_TENANT, _group(), membership_count=0)
        assert rec["group_name"] == "Engineering"

    def test_description_extracted_and_truncated(self):
        raw = _group()
        raw["profile"]["description"] = "x" * 500
        rec = OktaConnector._normalize_group(_TENANT, raw, membership_count=0)
        assert len(rec["description"]) == 200

    def test_arbitrary_group_profile_fields_never_copied(self):
        raw = _group()
        raw["profile"]["customAttribute"] = "sensitive-org-data"
        rec = OktaConnector._normalize_group(_TENANT, raw, membership_count=0)
        assert "customAttribute" not in rec
        assert "sensitive-org-data" not in str(rec)


# ════════════════════════════════════════════════════════════════════════════
# Membership count bucketing
# ════════════════════════════════════════════════════════════════════════════


class TestMembershipCountBuckets:
    def test_zero(self):
        assert categorize_membership_count(0) == MEMBERSHIP_COUNT_ZERO

    def test_small(self):
        assert categorize_membership_count(3) == MEMBERSHIP_COUNT_SMALL
        assert categorize_membership_count(5) == MEMBERSHIP_COUNT_SMALL

    def test_medium(self):
        assert categorize_membership_count(6) == MEMBERSHIP_COUNT_MEDIUM
        assert categorize_membership_count(20) == MEMBERSHIP_COUNT_MEDIUM

    def test_large(self):
        assert categorize_membership_count(21) == MEMBERSHIP_COUNT_LARGE
        assert categorize_membership_count(100) == MEMBERSHIP_COUNT_LARGE

    def test_very_large(self):
        assert categorize_membership_count(101) == MEMBERSHIP_COUNT_VERY_LARGE
        assert categorize_membership_count(50_000) == MEMBERSHIP_COUNT_VERY_LARGE

    def test_none_is_unknown_not_zero(self):
        """A missing/denied membership count must NEVER be reported as 0."""
        assert categorize_membership_count(None) == MEMBERSHIP_COUNT_UNKNOWN

    def test_negative_is_unknown(self):
        assert categorize_membership_count(-1) == MEMBERSHIP_COUNT_UNKNOWN

    def test_bool_is_unknown_not_coerced_to_int(self):
        assert categorize_membership_count(True) == MEMBERSHIP_COUNT_UNKNOWN

    def test_non_int_is_unknown(self):
        assert categorize_membership_count("5") == MEMBERSHIP_COUNT_UNKNOWN


# ════════════════════════════════════════════════════════════════════════════
# Membership normalization
# ════════════════════════════════════════════════════════════════════════════


class TestMembershipNormalization:
    def test_denormalizes_login_and_group_name(self):
        user_rec = OktaConnector._normalize_user(_TENANT, _user())
        group_rec = OktaConnector._normalize_group(_TENANT, _group(), membership_count=1)
        rec = OktaConnector._normalize_membership(_TENANT, user_rec, group_rec, "u1")
        assert rec["user_login"] == "u1@example.com"
        assert rec["group_name"] == "Engineering"
        assert rec["user_status"] == "ACTIVE"

    def test_missing_user_record_degrades_gracefully(self):
        """If a member ID isn't in the collected user index (edge case),
        the membership record must still be created with unknown-safe
        defaults, never crash."""
        group_rec = OktaConnector._normalize_group(_TENANT, _group(), membership_count=1)
        rec = OktaConnector._normalize_membership(_TENANT, None, group_rec, "u-missing")
        assert rec["user_login"] is None
        assert rec["user_status"] == "UNKNOWN"

    def test_does_not_duplicate_full_user_or_group_record(self):
        user_rec = OktaConnector._normalize_user(_TENANT, _user())
        group_rec = OktaConnector._normalize_group(_TENANT, _group(), membership_count=1)
        rec = OktaConnector._normalize_membership(_TENANT, user_rec, group_rec, "u1")
        assert "credential_provider_category" not in rec
        assert "description" not in rec
        assert "membership_count" not in rec


# ════════════════════════════════════════════════════════════════════════════
# Sensitive-data exclusion
# ════════════════════════════════════════════════════════════════════════════


class TestSensitiveDataExclusion:
    def test_password_excluded(self):
        raw = _user()
        raw["credentials"] = {
            "password": {"value": "should-never-appear"},
            "provider": {"type": "OKTA"},
        }
        rec = OktaConnector._normalize_user(_TENANT, raw)
        assert "password" not in rec
        assert "should-never-appear" not in str(rec)

    def test_credentials_object_excluded(self):
        raw = _user()
        raw["credentials"] = {
            "password": {"value": "secret"},
            "recovery_question": {"question": "What is your pet's name?", "answer": "Rex"},
            "provider": {"type": "OKTA"},
        }
        rec = OktaConnector._normalize_user(_TENANT, raw)
        assert "credentials" not in rec
        assert "Rex" not in str(rec)
        assert "pet's name" not in str(rec)

    def test_phone_excluded(self):
        raw = _user()
        raw["profile"]["mobilePhone"] = "+15555550100"
        raw["profile"]["primaryPhone"] = "+15555550199"
        rec = OktaConnector._normalize_user(_TENANT, raw)
        assert "+15555550100" not in str(rec)
        assert "+15555550199" not in str(rec)

    def test_custom_attributes_excluded(self):
        raw = _user()
        raw["profile"]["customField1"] = "sensitive-value-1"
        raw["profile"]["employeeNumber"] = "EMP12345"
        rec = OktaConnector._normalize_user(_TENANT, raw)
        assert "sensitive-value-1" not in str(rec)
        assert "EMP12345" not in str(rec)

    def test_recovery_answer_excluded(self):
        raw = _user()
        raw["credentials"] = {
            "recovery_question": {"question": "q", "answer": "my-secret-answer"},
            "provider": {"type": "OKTA"},
        }
        rec = OktaConnector._normalize_user(_TENANT, raw)
        assert "my-secret-answer" not in str(rec)

    def test_mfa_secrets_excluded(self):
        raw = _user()
        raw["credentials"] = {
            "provider": {"type": "OKTA"},
        }
        raw["factors"] = [{"factorType": "token:software:totp", "secret": "TOTP_SEED_MUST_NOT_APPEAR"}]
        rec = OktaConnector._normalize_user(_TENANT, raw)
        assert "TOTP_SEED_MUST_NOT_APPEAR" not in str(rec)
        assert "factors" not in rec

    def test_session_token_excluded(self):
        raw = _user()
        raw["sessionToken"] = "SESSION_TOKEN_MUST_NOT_APPEAR"
        rec = OktaConnector._normalize_user(_TENANT, raw)
        assert "SESSION_TOKEN_MUST_NOT_APPEAR" not in str(rec)

    def test_address_excluded(self):
        raw = _user()
        raw["profile"]["streetAddress"] = "123 Main St"
        raw["profile"]["city"] = "Springfield"
        rec = OktaConnector._normalize_user(_TENANT, raw)
        assert "123 Main St" not in str(rec)
        assert "Springfield" not in str(rec)

    def test_manager_excluded_unless_needed(self):
        raw = _user()
        raw["profile"]["manager"] = "manager@example.com"
        raw["profile"]["managerId"] = "u-manager-id"
        rec = OktaConnector._normalize_user(_TENANT, raw)
        assert "manager@example.com" not in str(rec)
        assert "u-manager-id" not in str(rec)

    def test_group_rule_payloads_excluded(self):
        raw = _group()
        raw["_embedded"] = {"stats": {"rules": [{"conditions": "sensitive-rule-logic"}]}}
        rec = OktaConnector._normalize_group(_TENANT, raw, membership_count=0)
        assert "sensitive-rule-logic" not in str(rec)
