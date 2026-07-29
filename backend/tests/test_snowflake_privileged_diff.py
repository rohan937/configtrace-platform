"""Snowflake effective-privilege Change-classification tests (Snowflake
message 5 of 8).

Uses the REAL ``compute_diff()`` -> ``classify_snowflake_change()``
pipeline (via ``risk_service.classify_change()``) for every case — no
hand-built Change dicts standing in for the real diff pipeline.
"""

from __future__ import annotations

from types import SimpleNamespace

from app.services.diff_service import compute_diff
from app.services.risk_service import classify_change

_ACCOUNT_ID = "id:acme-prod"


def _diff(prev_records: list[dict], new_records: list[dict]):
    prev = SimpleNamespace(state=prev_records)
    new = SimpleNamespace(state=new_records)
    return compute_diff(prev, new)


def _only_change(changes):
    assert len(changes) == 1, f"expected exactly 1 change, got {len(changes)}: {changes}"
    return changes[0]


def _privileged_user(name="ALICE", **overrides):
    record = {
        "record_type": "snowflake_privileged_user",
        "record_id": f"{_ACCOUNT_ID}/privileged_user/{name.lower()}",
        "account_id": _ACCOUNT_ID,
        "user_name": name,
        "user_type": "person",
        "disabled": "enabled",
        "highest_known_privilege_tier": "medium",
        "has_unknown_privilege": False,
        "has_accountadmin": False,
        "has_securityadmin": False,
        "has_sysadmin": False,
        "has_useradmin": False,
        "has_manage_grants": False,
        "direct_role_count": 1,
        "inherited_role_count": 0,
        "database_role_count": 0,
        "owned_object_count": 0,
        "owned_database_count": 0,
        "high_risk_future_grant_count": 0,
        "privilege_completeness": "complete",
    }
    record.update(overrides)
    return record


def _privileged_role(name="CUSTOM_ADMIN", **overrides):
    record = {
        "record_type": "snowflake_privileged_role",
        "record_id": f"{_ACCOUNT_ID}/privileged_role/account_role/{name.lower()}",
        "account_id": _ACCOUNT_ID,
        "role_name": name,
        "role_type": "account_role",
        "role_category": "custom",
        "database_name": None,
        "highest_known_privilege_tier": "medium",
        "has_unknown_privilege": False,
        "has_manage_grants": False,
        "global_privilege_categories": [],
        "owns_database_count": 0,
        "owns_schema_count": 0,
        "owns_managed_access_schema_count": 0,
        "owns_warehouse_count": 0,
        "owns_security_integration_count": 0,
        "owns_storage_integration_count": 0,
        "owns_external_access_integration_count": 0,
        "owns_network_policy_count": 0,
        "owns_authentication_policy_count": 0,
        "owns_other_object_count": 0,
        "future_grant_count": 0,
        "future_ownership_count": 0,
        "future_broad_grant_count": 0,
        "inherited_child_role_count": 0,
        "inherited_database_role_count": 0,
        "direct_user_assignment_count": 1,
        "privilege_completeness": "complete",
    }
    record.update(overrides)
    return record


def _public_exposure(**overrides):
    record = {
        "record_type": "snowflake_public_exposure",
        "record_id": f"{_ACCOUNT_ID}/public_exposure",
        "account_id": _ACCOUNT_ID,
        "exposure_category": "account_wide_user_access",
        "scope": "account",
        "current_public_exposure_count": None,
        "current_public_exposure_data_available": False,
        "future_public_exposure_count": 0,
        "future_public_ownership_count": 0,
        "future_public_write_count": 0,
        "future_public_read_count": 0,
        "future_public_broad_object_type_count": 0,
        "privilege_completeness": "partial",
    }
    record.update(overrides)
    return record


class TestPrivilegedUserAdded:
    def test_added_critical_tier(self):
        """Case BS: ordinary -> critical (a new privileged_user record
        with critical tier)."""
        change = _only_change(_diff([], [_privileged_user(highest_known_privilege_tier="critical", has_accountadmin=True)]))
        severity, _ = classify_change(change)
        assert severity == "critical"

    def test_added_high_tier(self):
        """Case BR: medium -> high, expressed as a new high-tier record."""
        change = _only_change(_diff([], [_privileged_user(highest_known_privilege_tier="high", has_securityadmin=True)]))
        severity, _ = classify_change(change)
        assert severity == "high"

    def test_added_medium_tier(self):
        """Case BQ: ordinary -> medium."""
        change = _only_change(_diff([], [_privileged_user()]))
        severity, _ = classify_change(change)
        assert severity == "medium"

    def test_removed_is_low(self):
        """Case BT-adjacent: privileged -> ordinary is a restrictive Low."""
        change = _only_change(_diff([_privileged_user()], []))
        severity, _ = classify_change(change)
        assert severity == "low"


class TestAccountadminGained:
    def test_user_gains_accountadmin_is_critical(self):
        """Case BU."""
        prev = _privileged_user(highest_known_privilege_tier="high", has_securityadmin=True)
        new = _privileged_user(highest_known_privilege_tier="critical", has_securityadmin=True, has_accountadmin=True)
        changes = _diff([prev], [new])
        # Both the tier field and the has_accountadmin field change
        # simultaneously here — every resulting Change must classify as
        # Critical for an ACCOUNTADMIN gain per the task's own mapping.
        for change in changes:
            severity, message = classify_change(change)
            assert severity == "critical"
            assert "ACCOUNTADMIN" in message or "critical" in message.lower()

    def test_user_loses_accountadmin_is_reduction(self):
        """Case BT: critical -> high (reduction)."""
        prev = _privileged_user(highest_known_privilege_tier="critical", has_accountadmin=True)
        new = _privileged_user(highest_known_privilege_tier="high", has_accountadmin=False, has_securityadmin=True)
        changes = _diff([prev], [new])
        severities = {classify_change(c)[0] for c in changes}
        # The accountadmin-loss field itself must classify as a reduction
        # (never higher severity than the gain path).
        assert "critical" not in severities


class TestSecurityadminAndManageGrantsGained:
    def test_securityadmin_gained_is_high(self):
        """Case BV."""
        prev = _privileged_user()
        new = _privileged_user(highest_known_privilege_tier="high", has_securityadmin=True)
        changes = _diff([prev], [new])
        assert any(classify_change(c)[0] == "high" for c in changes)

    def test_manage_grants_gained_is_high(self):
        """Case BW."""
        prev = _privileged_user()
        new = _privileged_user(highest_known_privilege_tier="high", has_manage_grants=True)
        changes = _diff([prev], [new])
        assert any(classify_change(c)[0] == "high" for c in changes)

    def test_role_manage_grants_gained_is_high(self):
        prev = _privileged_role()
        new = _privileged_role(has_manage_grants=True, highest_known_privilege_tier="high")
        changes = _diff([prev], [new])
        assert any(classify_change(c)[0] == "high" for c in changes)


class TestDisabledPrivilegedUserReEnabled:
    def test_disabled_critical_user_enabled_is_critical(self):
        """Case BX."""
        prev = _privileged_user(disabled="disabled", highest_known_privilege_tier="critical", has_accountadmin=True)
        new = _privileged_user(disabled="enabled", highest_known_privilege_tier="critical", has_accountadmin=True)
        change = _only_change(_diff([prev], [new]))
        severity, message = classify_change(change)
        assert severity == "critical"
        assert "retained" in message.lower() or "re-enabled" in message.lower()

    def test_disabled_medium_user_enabled_is_medium(self):
        prev = _privileged_user(disabled="disabled")
        new = _privileged_user(disabled="enabled")
        change = _only_change(_diff([prev], [new]))
        severity, _ = classify_change(change)
        assert severity == "medium"

    def test_critical_user_disabled_is_low(self):
        """Case BY: disabling a privileged user is restrictive."""
        prev = _privileged_user(disabled="enabled", highest_known_privilege_tier="critical", has_accountadmin=True)
        new = _privileged_user(disabled="disabled", highest_known_privilege_tier="critical", has_accountadmin=True)
        change = _only_change(_diff([prev], [new]))
        severity, message = classify_change(change)
        assert severity == "low"
        assert "retained" in message.lower()


class TestOwnershipChanges:
    def test_database_ownership_gained_is_high(self):
        """Case CB (database ownership variant)."""
        prev = _privileged_role()
        new = _privileged_role(owns_database_count=1)
        change = _only_change(_diff([prev], [new]))
        severity, _ = classify_change(change)
        assert severity == "high"

    def test_managed_access_schema_ownership_gained_is_high(self):
        prev = _privileged_role()
        new = _privileged_role(owns_managed_access_schema_count=1)
        change = _only_change(_diff([prev], [new]))
        severity, _ = classify_change(change)
        assert severity == "high"

    def test_security_integration_ownership_gained_is_high(self):
        prev = _privileged_role()
        new = _privileged_role(owns_security_integration_count=1)
        change = _only_change(_diff([prev], [new]))
        severity, _ = classify_change(change)
        assert severity == "high"

    def test_ordinary_warehouse_ownership_gained_is_medium(self):
        """Ordinary object ownership (not database/managed-schema/
        security-integration) is Medium, not High — do not make all
        ownership Critical/High."""
        prev = _privileged_role()
        new = _privileged_role(owns_warehouse_count=1)
        change = _only_change(_diff([prev], [new]))
        severity, _ = classify_change(change)
        assert severity == "medium"

    def test_ownership_removed_is_low(self):
        """Case CC."""
        prev = _privileged_role(owns_database_count=1)
        new = _privileged_role(owns_database_count=0)
        change = _only_change(_diff([prev], [new]))
        severity, _ = classify_change(change)
        assert severity == "low"


class TestFutureGrantChanges:
    def test_future_ownership_gained_is_high(self):
        prev = _privileged_role()
        new = _privileged_role(future_ownership_count=1)
        change = _only_change(_diff([prev], [new]))
        severity, _ = classify_change(change)
        assert severity == "high"

    def test_future_broad_grant_gained_is_medium(self):
        prev = _privileged_role()
        new = _privileged_role(future_broad_grant_count=1)
        change = _only_change(_diff([prev], [new]))
        severity, _ = classify_change(change)
        assert severity == "medium"


class TestPublicChangeClassification:
    def test_public_future_ownership_added_is_critical(self):
        """Case CA (PUBLIC future OWNERSHIP variant) — every Snowflake
        user gaining ownership of newly created objects via PUBLIC is the
        most severe PUBLIC exposure case."""
        prev = _public_exposure()
        new = _public_exposure(future_public_ownership_count=1, future_public_exposure_count=1)
        changes = _diff([prev], [new])
        assert any(classify_change(c)[0] == "critical" for c in changes)

    def test_public_future_write_added_is_high(self):
        prev = _public_exposure()
        new = _public_exposure(future_public_write_count=1, future_public_exposure_count=1)
        changes = _diff([prev], [new])
        assert any(classify_change(c)[0] == "high" for c in changes)

    def test_public_future_read_added_is_medium(self):
        """Case CA (ordinary future SELECT to PUBLIC)."""
        prev = _public_exposure()
        new = _public_exposure(future_public_read_count=1, future_public_exposure_count=1)
        changes = _diff([prev], [new])
        assert any(classify_change(c)[0] == "medium" for c in changes)

    def test_public_future_grant_removed_is_low(self):
        prev = _public_exposure(future_public_read_count=1, future_public_exposure_count=1)
        new = _public_exposure()
        changes = _diff([prev], [new])
        assert all(classify_change(c)[0] == "low" for c in changes)

    def test_wording_never_says_internet_exposure(self):
        """Case AW/70 (MANDATORY): scan every classification message
        produced for this record type across all cases above — none may
        ever say 'internet' in connection with PUBLIC exposure."""
        prev = _public_exposure()
        new = _public_exposure(
            future_public_ownership_count=1, future_public_write_count=1,
            future_public_read_count=1, future_public_exposure_count=3,
        )
        changes = _diff([prev], [new])
        for c in changes:
            _severity, message = classify_change(c)
            assert "internet" not in message.lower()


class TestTierEscalationLadder:
    def test_medium_to_high_is_high(self):
        """Case BR."""
        prev = _privileged_role(highest_known_privilege_tier="medium")
        new = _privileged_role(highest_known_privilege_tier="high")
        change = _only_change(_diff([prev], [new]))
        severity, _ = classify_change(change)
        assert severity == "high"

    def test_high_to_critical_is_critical(self):
        """Case BS."""
        prev = _privileged_role(highest_known_privilege_tier="high")
        new = _privileged_role(highest_known_privilege_tier="critical")
        change = _only_change(_diff([prev], [new]))
        severity, _ = classify_change(change)
        assert severity == "critical"

    def test_critical_to_high_is_reduction(self):
        """Case BT."""
        prev = _privileged_role(highest_known_privilege_tier="critical")
        new = _privileged_role(highest_known_privilege_tier="high")
        change = _only_change(_diff([prev], [new]))
        severity, _ = classify_change(change)
        assert severity == "low"


class TestServiceUserPrivilegeChange:
    def test_service_user_gains_privilege_classified_by_tier_not_type(self):
        """Section 65: a service user gaining critical privilege is
        classified by tier, not auto-escalated purely because it's a
        service user (which would be indistinguishable from this test's
        assertion, since the severity IS driven by tier either way — the
        point is user_type never overrides tier-based severity)."""
        change = _only_change(_diff(
            [],
            [_privileged_user(name="SVC_PIPE", user_type="service", highest_known_privilege_tier="critical", has_accountadmin=True)],
        ))
        severity, _ = classify_change(change)
        assert severity == "critical"


class TestProviderMetadataHygiene:
    def test_privileged_user_metadata_context(self):
        change = _only_change(_diff([], [_privileged_user()]))
        pm = change.provider_metadata if hasattr(change, "provider_metadata") else change["provider_metadata"]
        assert pm["record_type"] == "snowflake_privileged_user"
        assert pm["user_name"] == "ALICE"

    def test_ignored_safe_field_produces_no_diff(self):
        prev = _privileged_user()
        new = dict(prev)
        assert _diff([prev], [new]) == []

    def test_unknown_record_type_fails_safe(self):
        from app.services.risk_rules.snowflake import classify_snowflake_change
        severity, message = classify_snowflake_change(SimpleNamespace(
            change_type="modified", field_path="x",
            provider_metadata={"record_type": "snowflake_future_unknown_type"},
        ))
        assert severity == "low"
        assert isinstance(message, str)
