"""Microsoft Entra ID identity diff/risk-classification tests (Entra
message 2 of 8).

Uses the REAL ``compute_diff()`` and ``classify_entra_change()`` — never
hand-built Change objects standing in for the diff pipeline — to verify
lifecycle-transition classification, group/membership add/removed
semantics, provider metadata, and the ignored-timestamp discipline.
"""

from __future__ import annotations

from types import SimpleNamespace as NS

import pytest

from app.services.diff_service import _tracked_fields_for, compute_diff
from app.services.risk_rules.entra import classify_entra_change

_TENANT = "id:t1"


def _snap(records: list[dict]) -> NS:
    return NS(state=records)


def _user_record(**overrides) -> dict:
    base = {
        "record_type": "entra_user",
        "record_id": f"{_TENANT}/user/u1",
        "provider_resource_id": "users/u1",
        "tenant_id": _TENANT,
        "user_id": "u1",
        "user_principal_name": "u1@example.com",
        "display_name": "Test User",
        "account_enabled_category": "enabled",
        "user_type_category": "Member",
        "guest": False,
        "member": True,
        "lifecycle_posture": "enabled_member",
        "external_user_state_category": "unknown",
        "on_premises_sync_enabled_category": "unknown",
        "created_date_time": "2020-01-01T00:00:00Z",
    }
    base.update(overrides)
    return base


def _group_record(**overrides) -> dict:
    base = {
        "record_type": "entra_group",
        "record_id": f"{_TENANT}/group/g1",
        "provider_resource_id": "groups/g1",
        "tenant_id": _TENANT,
        "group_id": "g1",
        "display_name": "Engineering",
        "security_enabled": True,
        "mail_enabled": False,
        "group_types": [],
        "group_type_category": "security",
        "dynamic_membership": False,
        "microsoft_365_group": False,
        "security_group": True,
        "role_assignable": False,
        "membership_count": 5,
        "membership_count_category": "1-5",
    }
    base.update(overrides)
    return base


def _membership_record(**overrides) -> dict:
    base = {
        "record_type": "entra_group_membership",
        "record_id": f"{_TENANT}/membership/g1/u1",
        "provider_resource_id": "groups/g1/members/u1",
        "tenant_id": _TENANT,
        "user_id": "u1",
        "group_id": "g1",
        "user_principal_name": "u1@example.com",
        "group_name": "Engineering",
        "user_type_category": "Member",
        "account_enabled_category": "enabled",
        "group_type_category": "security",
        "dynamic_group": False,
        "role_assignable_group": False,
        "membership_type": "direct",
    }
    base.update(overrides)
    return base


def _find_field_change(changes: list[dict], field_path: str) -> dict:
    match = [c for c in changes if c["field_path"] == field_path]
    assert match, f"no change found for field_path={field_path!r} in {changes}"
    return match[0]


def _account_enabled_transition(prev_cat: str, new_cat: str) -> list[dict]:
    prev = [_user_record(account_enabled_category=prev_cat)]
    new = [_user_record(account_enabled_category=new_cat)]
    return compute_diff(_snap(prev), _snap(new))


# ════════════════════════════════════════════════════════════════════════════
# No spurious changes when identical
# ════════════════════════════════════════════════════════════════════════════


class TestNoSpuriousChangeWhenIdentical:
    def test_identical_user_produces_no_change(self):
        rec = _user_record()
        changes = compute_diff(_snap([rec]), _snap([dict(rec)]))
        assert changes == []

    def test_identical_group_produces_no_change(self):
        rec = _group_record()
        changes = compute_diff(_snap([rec]), _snap([dict(rec)]))
        assert changes == []

    def test_identical_membership_produces_no_change(self):
        rec = _membership_record()
        changes = compute_diff(_snap([rec]), _snap([dict(rec)]))
        assert changes == []

    def test_same_data_reordered_produces_no_changes(self):
        u1, u2 = _user_record(user_id="u1", record_id=f"{_TENANT}/user/u1"), _user_record(user_id="u2", record_id=f"{_TENANT}/user/u2")
        changes = compute_diff(_snap([u1, u2]), _snap([dict(u2), dict(u1)]))
        assert changes == []


# ════════════════════════════════════════════════════════════════════════════
# User lifecycle transitions
# ════════════════════════════════════════════════════════════════════════════


class TestUserLifecycleTransitions:
    def test_enabled_to_disabled_is_low(self):
        changes = _account_enabled_transition("enabled", "disabled")
        change = _find_field_change(changes, "account_enabled_category")
        level, reason = classify_entra_change(change)
        assert level == "low"
        assert "disabled" in reason.lower()

    def test_disabled_to_enabled_is_medium(self):
        changes = _account_enabled_transition("disabled", "enabled")
        change = _find_field_change(changes, "account_enabled_category")
        level, reason = classify_entra_change(change)
        assert level == "medium"
        assert "restored" in reason.lower()

    def test_unknown_to_enabled_is_medium(self):
        changes = _account_enabled_transition("unknown", "enabled")
        change = _find_field_change(changes, "account_enabled_category")
        level, _ = classify_entra_change(change)
        assert level == "medium"

    def test_enabled_to_unknown_is_medium_needs_review(self):
        changes = _account_enabled_transition("enabled", "unknown")
        change = _find_field_change(changes, "account_enabled_category")
        level, reason = classify_entra_change(change)
        assert level == "medium"
        assert "review" in reason.lower() or "unrecognized" in reason.lower()

    def test_member_to_guest_is_low(self):
        prev = [_user_record(user_type_category="Member", guest=False, member=True)]
        new = [_user_record(user_type_category="Guest", guest=True, member=False)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "user_type_category")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_guest_to_member_is_low(self):
        prev = [_user_record(user_type_category="Guest", guest=True, member=False)]
        new = [_user_record(user_type_category="Member", guest=False, member=True)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "user_type_category")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_upn_rename_is_low(self):
        prev = [_user_record(user_principal_name="old@example.com")]
        new = [_user_record(user_principal_name="new@example.com")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "user_principal_name")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_display_name_change_is_low(self):
        prev = [_user_record(display_name="Old Name")]
        new = [_user_record(display_name="New Name")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "display_name")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_pending_to_accepted_is_medium(self):
        prev = [_user_record(user_type_category="Guest", external_user_state_category="PendingAcceptance")]
        new = [_user_record(user_type_category="Guest", external_user_state_category="Accepted")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "external_user_state_category")
        level, reason = classify_entra_change(change)
        assert level == "medium"
        assert "accepted" in reason.lower() or "active" in reason.lower()

    def test_accepted_to_pending_is_low(self):
        prev = [_user_record(user_type_category="Guest", external_user_state_category="Accepted")]
        new = [_user_record(user_type_category="Guest", external_user_state_category="PendingAcceptance")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "external_user_state_category")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_added_enabled_user_is_low(self):
        changes = compute_diff(_snap([]), _snap([_user_record()]))
        change = next(c for c in changes if c["change_type"] == "added")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_added_guest_is_low(self):
        rec = _user_record(user_type_category="Guest", guest=True, member=False)
        changes = compute_diff(_snap([]), _snap([rec]))
        change = next(c for c in changes if c["change_type"] == "added")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_removed_user_is_low(self):
        changes = compute_diff(_snap([_user_record()]), _snap([]))
        change = next(c for c in changes if c["change_type"] == "removed")
        level, reason = classify_entra_change(change)
        assert level == "low"
        assert "no longer present" in reason.lower()

    def test_on_premises_sync_change_is_medium(self):
        prev = [_user_record(on_premises_sync_enabled_category="disabled")]
        new = [_user_record(on_premises_sync_enabled_category="enabled")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "on_premises_sync_enabled_category")
        level, _ = classify_entra_change(change)
        assert level == "medium"


# ════════════════════════════════════════════════════════════════════════════
# Group changes
# ════════════════════════════════════════════════════════════════════════════


class TestGroupChanges:
    def test_added_group_is_low(self):
        changes = compute_diff(_snap([]), _snap([_group_record()]))
        change = next(c for c in changes if c["change_type"] == "added")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_removed_group_is_low(self):
        changes = compute_diff(_snap([_group_record()]), _snap([]))
        change = next(c for c in changes if c["change_type"] == "removed")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_rename_is_low(self):
        prev = [_group_record(display_name="Old")]
        new = [_group_record(display_name="New")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "display_name")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_mail_enabled_change_is_low(self):
        prev = [_group_record(mail_enabled=False)]
        new = [_group_record(mail_enabled=True)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "mail_enabled")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_security_enabled_false_to_true_is_medium(self):
        prev = [_group_record(security_enabled=False)]
        new = [_group_record(security_enabled=True)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "security_enabled")
        level, _ = classify_entra_change(change)
        assert level == "medium"

    def test_security_enabled_true_to_false_is_low(self):
        prev = [_group_record(security_enabled=True)]
        new = [_group_record(security_enabled=False)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "security_enabled")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_dynamic_membership_enabled_is_medium(self):
        prev = [_group_record(dynamic_membership=False)]
        new = [_group_record(dynamic_membership=True)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "dynamic_membership")
        level, reason = classify_entra_change(change)
        assert level == "medium"
        assert "dynamic" in reason.lower()

    def test_dynamic_membership_disabled_is_low(self):
        prev = [_group_record(dynamic_membership=True)]
        new = [_group_record(dynamic_membership=False)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "dynamic_membership")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_role_assignable_enabled_is_high(self):
        prev = [_group_record(role_assignable=False)]
        new = [_group_record(role_assignable=True)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "role_assignable")
        level, reason = classify_entra_change(change)
        assert level == "high"
        assert "eligible" in reason.lower() or "role" in reason.lower()
        assert "escalation" not in reason.lower()

    def test_role_assignable_disabled_is_low(self):
        prev = [_group_record(role_assignable=True)]
        new = [_group_record(role_assignable=False)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "role_assignable")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_membership_count_increase_is_low(self):
        prev = [_group_record(membership_count=5)]
        new = [_group_record(membership_count=10)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "membership_count")
        level, _ = classify_entra_change(change)
        assert level == "low"


# ════════════════════════════════════════════════════════════════════════════
# Membership changes
# ════════════════════════════════════════════════════════════════════════════


class TestMembershipChanges:
    def test_ordinary_user_added_to_group_is_low(self):
        changes = compute_diff(_snap([]), _snap([_membership_record()]))
        change = next(c for c in changes if c["change_type"] == "added")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_ordinary_user_removed_from_group_is_low(self):
        changes = compute_diff(_snap([_membership_record()]), _snap([]))
        change = next(c for c in changes if c["change_type"] == "removed")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_user_added_to_role_assignable_group_is_medium(self):
        rec = _membership_record(role_assignable_group=True)
        changes = compute_diff(_snap([]), _snap([rec]))
        change = next(c for c in changes if c["change_type"] == "added")
        level, reason = classify_entra_change(change)
        assert level == "medium"
        assert "not confirmed" in reason.lower() or "no directory role" in reason.lower()

    def test_guest_added_to_security_group_is_medium(self):
        rec = _membership_record(user_type_category="Guest", group_type_category="security")
        changes = compute_diff(_snap([]), _snap([rec]))
        change = next(c for c in changes if c["change_type"] == "added")
        level, reason = classify_entra_change(change)
        assert level == "medium"
        assert "attacker" not in reason.lower()

    def test_guest_added_to_ordinary_m365_group_is_low(self):
        rec = _membership_record(user_type_category="Guest", group_type_category="microsoft_365")
        changes = compute_diff(_snap([]), _snap([rec]))
        change = next(c for c in changes if c["change_type"] == "added")
        level, _ = classify_entra_change(change)
        assert level == "low"


# ════════════════════════════════════════════════════════════════════════════
# Provider metadata / ignored timestamps
# ════════════════════════════════════════════════════════════════════════════


class TestProviderMetadataAndTimestamps:
    def test_user_change_has_tenant_and_user_context(self):
        prev = [_user_record(display_name="Old")]
        new = [_user_record(display_name="New")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "display_name")
        pm = change["provider_metadata"]
        assert pm["tenant_id"] == _TENANT
        assert pm["user_id"] == "u1"
        assert pm["user_principal_name"] == "u1@example.com"
        assert "client_secret" not in pm
        assert "access_token" not in pm

    def test_group_change_has_tenant_and_group_context(self):
        prev = [_group_record(display_name="Old")]
        new = [_group_record(display_name="New")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "display_name")
        pm = change["provider_metadata"]
        assert pm["tenant_id"] == _TENANT
        assert pm["group_id"] == "g1"
        assert pm["display_name"] == "New"

    def test_membership_change_has_full_context(self):
        rec = _membership_record()
        changes = compute_diff(_snap([]), _snap([rec]))
        change = next(c for c in changes if c["change_type"] == "added")
        pm = change["provider_metadata"]
        assert pm["tenant_id"] == _TENANT
        assert pm["user_id"] == "u1"
        assert pm["group_id"] == "g1"
        assert pm["group_name"] == "Engineering"

    def test_created_date_time_change_ignored(self):
        prev = [_user_record(created_date_time="2020-01-01T00:00:00Z")]
        new = [_user_record(created_date_time="2024-06-01T00:00:00Z")]
        changes = compute_diff(_snap(prev), _snap(new))
        assert changes == []

    def test_sign_in_activity_field_not_tracked(self):
        """Sign-in activity is not collected at all this message; confirm
        the tracked-fields tuple for entra_user contains no sign-in field
        name, so a future addition of the raw field would not accidentally
        start generating noisy Changes without an explicit decision."""
        tracked = _tracked_fields_for({"record_type": "entra_user"})
        assert "sign_in_activity" not in tracked
        assert "last_sign_in_category" not in tracked

    def test_unknown_entra_record_type_fails_safe(self):
        change = {
            "change_type": "modified",
            "provider_metadata": {"record_type": "entra_future_thing"},
        }
        level, _ = classify_entra_change(change)
        assert level == "low"
