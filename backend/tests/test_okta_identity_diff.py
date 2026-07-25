"""Okta identity diff/risk-classification tests (Okta message 2 of 8).

Uses the REAL ``compute_diff()`` and ``classify_okta_change()`` — never
hand-built Change objects standing in for the diff pipeline — to verify
lifecycle-transition classification, group/membership add/removed
semantics, provider metadata, and the ignored-timestamp discipline.
"""

from __future__ import annotations

from types import SimpleNamespace as NS

import pytest

from app.services.diff_service import _tracked_fields_for, compute_diff
from app.services.risk_rules.okta import classify_okta_change


def _snap(records: list[dict]) -> NS:
    return NS(state=records)


def _user_record(**overrides) -> dict:
    base = {
        "record_type": "okta_user",
        "record_id": "id:t1/user/u1",
        "provider_resource_id": "users/u1",
        "tenant_id": "id:t1",
        "user_id": "u1",
        "login": "u1@example.com",
        "display_name": "First Last",
        "status": "ACTIVE",
        "lifecycle_posture": "active",
        "active": True,
        "staged": False,
        "provisioned": False,
        "recovery": False,
        "locked_out": False,
        "password_expired": False,
        "suspended": False,
        "deprovisioned": False,
        "user_type_id": "typ1",
        "credential_provider_category": "OKTA",
        "last_login_category": "recent",
        "created": "2020-01-01T00:00:00.000Z",
        "activated": "2020-01-02T00:00:00.000Z",
    }
    base.update(overrides)
    return base


def _group_record(**overrides) -> dict:
    base = {
        "record_type": "okta_group",
        "record_id": "id:t1/group/g1",
        "provider_resource_id": "groups/g1",
        "tenant_id": "id:t1",
        "group_id": "g1",
        "group_name": "Engineering",
        "group_type": "OKTA_GROUP",
        "description": "Eng team",
        "built_in": False,
        "everyone_group": False,
        "membership_count": 5,
        "membership_count_category": "1-5",
    }
    base.update(overrides)
    return base


def _membership_record(**overrides) -> dict:
    base = {
        "record_type": "okta_group_membership",
        "record_id": "id:t1/membership/g1/u1",
        "provider_resource_id": "groups/g1/users/u1",
        "tenant_id": "id:t1",
        "user_id": "u1",
        "group_id": "g1",
        "user_login": "u1@example.com",
        "group_name": "Engineering",
        "group_type": "OKTA_GROUP",
        "user_status": "ACTIVE",
        "built_in_group": False,
    }
    base.update(overrides)
    return base


def _find_field_change(changes: list[dict], field_path: str) -> dict:
    match = [c for c in changes if c["field_path"] == field_path]
    assert match, f"no change found for field_path={field_path!r} in {changes}"
    return match[0]


def _status_transition(prev_status: str, new_status: str) -> list[dict]:
    prev = [_user_record(status=prev_status)]
    new = [_user_record(status=new_status)]
    return compute_diff(_snap(prev), _snap(new))


# ════════════════════════════════════════════════════════════════════════════
# A-J: single-status records (via compute_diff "added" path is covered
#      elsewhere; here we assert normalization survives a diff round-trip
#      unchanged when nothing differs)
# ════════════════════════════════════════════════════════════════════════════


class TestNoSpuriousChangeWhenIdentical:
    @pytest.mark.parametrize("status", [
        "STAGED", "PROVISIONED", "ACTIVE", "RECOVERY", "LOCKED_OUT",
        "PASSWORD_EXPIRED", "SUSPENDED", "DEPROVISIONED",
    ])
    def test_identical_status_produces_no_change(self, status):
        rec = _user_record(status=status)
        changes = compute_diff(_snap([rec]), _snap([dict(rec)]))
        assert changes == []


# ════════════════════════════════════════════════════════════════════════════
# K-T: lifecycle transitions
# ════════════════════════════════════════════════════════════════════════════


class TestLifecycleTransitions:
    def test_active_to_suspended_is_low(self):
        changes = _status_transition("ACTIVE", "SUSPENDED")
        change = _find_field_change(changes, "status")
        level, reason = classify_okta_change(NS(**change))
        assert level == "low"
        assert "suspended" in reason.lower()

    def test_suspended_to_active_is_medium(self):
        changes = _status_transition("SUSPENDED", "ACTIVE")
        change = _find_field_change(changes, "status")
        level, reason = classify_okta_change(NS(**change))
        assert level == "medium"
        assert "restored" in reason.lower()

    def test_active_to_deprovisioned_is_low(self):
        changes = _status_transition("ACTIVE", "DEPROVISIONED")
        change = _find_field_change(changes, "status")
        level, _ = classify_okta_change(NS(**change))
        assert level == "low"

    def test_deprovisioned_to_active_is_medium(self):
        changes = _status_transition("DEPROVISIONED", "ACTIVE")
        change = _find_field_change(changes, "status")
        level, reason = classify_okta_change(NS(**change))
        assert level == "medium"

    def test_active_to_locked_is_low(self):
        changes = _status_transition("ACTIVE", "LOCKED_OUT")
        change = _find_field_change(changes, "status")
        level, _ = classify_okta_change(NS(**change))
        assert level == "low"

    def test_locked_to_active_is_medium(self):
        changes = _status_transition("LOCKED_OUT", "ACTIVE")
        change = _find_field_change(changes, "status")
        level, _ = classify_okta_change(NS(**change))
        assert level == "medium"

    def test_active_to_password_expired_is_low(self):
        changes = _status_transition("ACTIVE", "PASSWORD_EXPIRED")
        change = _find_field_change(changes, "status")
        level, _ = classify_okta_change(NS(**change))
        assert level == "low"

    def test_password_expired_to_active_is_low(self):
        changes = _status_transition("PASSWORD_EXPIRED", "ACTIVE")
        change = _find_field_change(changes, "status")
        level, _ = classify_okta_change(NS(**change))
        assert level == "low"

    def test_active_to_recovery_is_low(self):
        changes = _status_transition("ACTIVE", "RECOVERY")
        change = _find_field_change(changes, "status")
        level, _ = classify_okta_change(NS(**change))
        assert level == "low"

    def test_recovery_to_active_is_low(self):
        changes = _status_transition("RECOVERY", "ACTIVE")
        change = _find_field_change(changes, "status")
        level, _ = classify_okta_change(NS(**change))
        assert level == "low"

    def test_suspended_and_deprovisioned_never_conflated_in_classification(self):
        """Restoring from SUSPENDED and restoring from DEPROVISIONED must
        each mention their own distinct prior state, never interchange."""
        _, suspended_reason = classify_okta_change(
            NS(**_find_field_change(_status_transition("SUSPENDED", "ACTIVE"), "status"))
        )
        _, deprovisioned_reason = classify_okta_change(
            NS(**_find_field_change(_status_transition("DEPROVISIONED", "ACTIVE"), "status"))
        )
        assert "suspended" in suspended_reason.lower()
        assert "deprovisioned" in deprovisioned_reason.lower()
        assert suspended_reason != deprovisioned_reason

    def test_unknown_new_status_is_medium(self):
        changes = _status_transition("ACTIVE", "SOME_BRAND_NEW_STATUS")
        change = _find_field_change(changes, "status")
        level, reason = classify_okta_change(NS(**change))
        assert level == "medium"
        assert "unrecognized" in reason.lower()

    def test_pre_active_to_active_is_low(self):
        changes = _status_transition("STAGED", "ACTIVE")
        change = _find_field_change(changes, "status")
        level, _ = classify_okta_change(NS(**change))
        assert level == "low"

    def test_restrictive_never_labeled_high(self):
        for prev, new in [("ACTIVE", "SUSPENDED"), ("ACTIVE", "DEPROVISIONED"), ("ACTIVE", "LOCKED_OUT")]:
            changes = _status_transition(prev, new)
            change = _find_field_change(changes, "status")
            level, _ = classify_okta_change(NS(**change))
            assert level in ("low", "informational"), f"{prev}->{new} was {level}, expected low"


# ════════════════════════════════════════════════════════════════════════════
# U-W: login change / user added / user removed
# ════════════════════════════════════════════════════════════════════════════


class TestUserIdentityChurn:
    def test_login_change_same_user_id_is_modification_not_replacement(self):
        prev = [_user_record(login="old@example.com")]
        new = [_user_record(login="new@example.com")]
        changes = compute_diff(_snap(prev), _snap(new))
        change_types = {c["change_type"] for c in changes}
        assert change_types == {"modified"}
        login_change = _find_field_change(changes, "login")
        assert login_change["prev_value"] == "old@example.com"
        assert login_change["new_value"] == "new@example.com"

    def test_added_active_user_is_low(self):
        changes = compute_diff(_snap([]), _snap([_user_record()]))
        assert len(changes) == 1
        assert changes[0]["change_type"] == "added"
        level, reason = classify_okta_change(NS(**changes[0]))
        assert level == "low"
        assert "high" not in reason.lower()

    def test_removed_user_is_low_and_not_a_deletion_claim(self):
        changes = compute_diff(_snap([_user_record()]), _snap([]))
        assert len(changes) == 1
        assert changes[0]["change_type"] == "removed"
        level, reason = classify_okta_change(NS(**changes[0]))
        assert level == "low"
        assert "does not by itself confirm" in reason.lower()


# ════════════════════════════════════════════════════════════════════════════
# X-AE: groups
# ════════════════════════════════════════════════════════════════════════════


class TestGroupChanges:
    def test_group_created_is_low(self):
        changes = compute_diff(_snap([]), _snap([_group_record()]))
        level, _ = classify_okta_change(NS(**changes[0]))
        assert level == "low"

    def test_group_removed_is_low(self):
        changes = compute_diff(_snap([_group_record()]), _snap([]))
        level, _ = classify_okta_change(NS(**changes[0]))
        assert level == "low"

    def test_group_renamed(self):
        prev = [_group_record(group_name="Old Name")]
        new = [_group_record(group_name="New Name")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "group_name")
        level, reason = classify_okta_change(NS(**change))
        assert level == "low"
        assert "renamed" in reason.lower()

    def test_group_type_change_to_built_in_deterministic_evidence(self):
        prev = [_group_record(group_type="OKTA_GROUP", built_in=False)]
        new = [_group_record(group_type="BUILT_IN", built_in=True)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "built_in")
        level, _ = classify_okta_change(NS(**change))
        assert level == "medium"

    def test_membership_count_increase(self):
        prev = [_group_record(membership_count=5)]
        new = [_group_record(membership_count=10)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "membership_count")
        level, reason = classify_okta_change(NS(**change))
        assert level == "low"
        assert "increased" in reason.lower()

    def test_membership_count_decrease(self):
        prev = [_group_record(membership_count=10)]
        new = [_group_record(membership_count=5)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "membership_count")
        level, reason = classify_okta_change(NS(**change))
        assert level == "low"
        assert "decreased" in reason.lower()

    def test_missing_count_becoming_known_is_not_a_fabricated_decrease(self):
        prev = [_group_record(membership_count=None)]
        new = [_group_record(membership_count=5)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "membership_count")
        level, reason = classify_okta_change(NS(**change))
        assert "unknown" in reason.lower() or "determined" in reason.lower()


# ════════════════════════════════════════════════════════════════════════════
# AI-AN: memberships
# ════════════════════════════════════════════════════════════════════════════


class TestMembershipChanges:
    def test_user_added_to_group(self):
        changes = compute_diff(_snap([]), _snap([_membership_record()]))
        assert changes[0]["change_type"] == "added"
        level, reason = classify_okta_change(NS(**changes[0]))
        assert level == "low"
        assert "added" in reason.lower()

    def test_user_removed_from_group(self):
        changes = compute_diff(_snap([_membership_record()]), _snap([]))
        assert changes[0]["change_type"] == "removed"
        level, reason = classify_okta_change(NS(**changes[0]))
        assert level == "low"
        assert "removed" in reason.lower()

    def test_built_in_group_membership_noted(self):
        rec = _membership_record(built_in_group=True, group_type="BUILT_IN")
        changes = compute_diff(_snap([]), _snap([rec]))
        level, reason = classify_okta_change(NS(**changes[0]))
        assert level == "low"
        assert "built-in" in reason.lower() or "system" in reason.lower()

    def test_suspended_user_membership_change(self):
        rec = _membership_record(user_status="SUSPENDED")
        changes = compute_diff(_snap([]), _snap([rec]))
        level, _ = classify_okta_change(NS(**changes[0]))
        assert level == "low"  # no privilege claims yet — message 5 owns that context

    def test_active_user_membership_change(self):
        rec = _membership_record(user_status="ACTIVE")
        changes = compute_diff(_snap([]), _snap([rec]))
        level, _ = classify_okta_change(NS(**changes[0]))
        assert level == "low"

    def test_duplicate_membership_dedup_in_record_index(self):
        from app.services.diff_service import build_record_index

        rec = _membership_record()
        index = build_record_index([rec, dict(rec)])
        assert len(index) == 1


# ════════════════════════════════════════════════════════════════════════════
# BF-BH: real provider metadata
# ════════════════════════════════════════════════════════════════════════════


class TestProviderMetadata:
    def test_user_provider_metadata(self):
        changes = compute_diff(
            _snap([_user_record(status="ACTIVE")]),
            _snap([_user_record(status="SUSPENDED")]),
        )
        change = _find_field_change(changes, "status")
        pm = change["provider_metadata"]
        assert pm["record_type"] == "okta_user"
        assert pm["tenant_id"] == "id:t1"
        assert pm["user_id"] == "u1"
        assert pm["login"] == "u1@example.com"

    def test_group_provider_metadata(self):
        changes = compute_diff(
            _snap([_group_record(group_name="Old")]),
            _snap([_group_record(group_name="New")]),
        )
        change = _find_field_change(changes, "group_name")
        pm = change["provider_metadata"]
        assert pm["record_type"] == "okta_group"
        assert pm["tenant_id"] == "id:t1"
        assert pm["group_id"] == "g1"
        assert pm["group_name"] == "New"

    def test_membership_provider_metadata(self):
        changes = compute_diff(_snap([]), _snap([_membership_record()]))
        pm = changes[0]["provider_metadata"]
        assert pm["record_type"] == "okta_group_membership"
        assert pm["tenant_id"] == "id:t1"
        assert pm["user_id"] == "u1"
        assert pm["user_login"] == "u1@example.com"
        assert pm["group_id"] == "g1"
        assert pm["group_name"] == "Engineering"

    def test_provider_metadata_never_includes_arbitrary_profile_fields(self):
        changes = compute_diff(_snap([]), _snap([_user_record()]))
        pm = changes[0]["provider_metadata"]
        assert "mobilePhone" not in pm
        assert "credentials" not in pm
        assert "profile" not in pm


# ════════════════════════════════════════════════════════════════════════════
# BI-BL: ignored timestamps / unknown-not-active / missing-not-zero
# ════════════════════════════════════════════════════════════════════════════


class TestIgnoredTimestampsAndUnknownDiscipline:
    def test_last_login_category_not_tracked(self):
        fields = _tracked_fields_for({"record_type": "okta_user"})
        assert "last_login_category" not in fields

    def test_created_and_activated_not_tracked(self):
        fields = _tracked_fields_for({"record_type": "okta_user"})
        assert "created" not in fields
        assert "activated" not in fields

    def test_last_login_change_alone_produces_no_change(self):
        prev = [_user_record(last_login_category="stale")]
        new = [_user_record(last_login_category="recent")]
        changes = compute_diff(_snap(prev), _snap(new))
        assert changes == []

    def test_created_activated_change_alone_produces_no_change(self):
        prev = [_user_record(created="2020-01-01T00:00:00.000Z", activated="2020-01-02T00:00:00.000Z")]
        new = [_user_record(created="2021-01-01T00:00:00.000Z", activated="2021-01-02T00:00:00.000Z")]
        changes = compute_diff(_snap(prev), _snap(new))
        assert changes == []

    def test_unknown_status_never_converted_to_active_in_diff(self):
        changes = _status_transition("ACTIVE", "TOTALLY_UNRECOGNIZED_STATUS")
        change = _find_field_change(changes, "status")
        assert change["new_value"] != "ACTIVE"

    def test_missing_membership_list_not_treated_as_zero_in_tracked_fields(self):
        # membership_count=None must survive the diff round-trip as None,
        # never silently coerced to 0.
        prev = [_group_record(membership_count=None)]
        new = [_group_record(membership_count=None)]
        changes = compute_diff(_snap(prev), _snap(new))
        assert changes == []  # no spurious "0 -> 0" style diff noise

    def test_okta_group_membership_unmapped_field_returns_empty(self):
        fields = _tracked_fields_for({"record_type": "okta_group_membership_totally_unknown_future_subtype"})
        assert fields == ()
