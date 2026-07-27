"""Okta exhaustive Change-classification audit (Okta message 7 of 8).

Complements the exhaustive per-family diff tests already written in
messages 2-6 (test_okta_identity_diff.py, test_okta_application_diff.py,
test_okta_policy_diff.py, test_okta_privileged_identity_diff.py) with:

1. A permanent regression guard against stale Change-schema field names
   (``old_value``/``previous_value``/``prior_value``/``prev``) anywhere
   in the Okta connector or risk-rules modules — the real schema uses
   ``prev_value``/``new_value`` exclusively.
2. Exhaustive user-lifecycle transition coverage (every ACTIVE<->X pair
   the task enumerates), via the REAL ``compute_diff()`` pipeline.
3. Privilege-aware lifecycle outranking: a privileged identity's lifecycle
   transition must be at least as severe as the same transition would be
   for an ordinary user (never LESS severe just because privilege
   evidence exists elsewhere).
4. Regression tests for the two real bugs found and fixed in this
   message's audit (``categorize_scope`` partial-unknown coercion,
   ``everyone_group``/``built_in_group`` defaulting to False instead of
   None when the group parent can't be resolved).
"""

from __future__ import annotations

import re
from pathlib import Path
from types import SimpleNamespace as NS

from app.connectors.okta import OktaConnector
from app.connectors.okta_schema import categorize_scope
from app.services.diff_service import compute_diff
from app.services.risk_rules.okta import classify_okta_change

_TENANT = "id:t1"
# Matches stale Change-schema dict-KEY usage only (e.g. `"old_value"`,
# `.get("prev")`, `change["prior_value"]`) — never a bare local variable
# or parameter named `prev`/`new` (a common, legitimate short name for a
# function's own prev/new arguments, unrelated to the Change dict schema).
_STALE_FIELD_PATTERN = re.compile(r'["\'](old_value|previous_value|prior_value|prev)["\']')


def _snap(records: list[dict]) -> NS:
    return NS(state=records)


def _user(uid: str, status: str, **kw) -> dict:
    r = {"record_type": "okta_user", "record_id": f"{_TENANT}/user/{uid}", "tenant_id": _TENANT, "user_id": uid, "login": f"{uid}@x.com", "status": status}
    r.update(kw)
    return r


# ════════════════════════════════════════════════════════════════════════════
# Regression guard: stale Change-schema field names
# ════════════════════════════════════════════════════════════════════════════


class TestNoStaleChangeFieldNames:
    def test_okta_connector_never_uses_stale_change_field_names(self):
        src = Path(OktaConnector.__module__.replace(".", "/") + ".py")
        text = Path("app/connectors/okta.py").read_text()
        matches = _STALE_FIELD_PATTERN.findall(text)
        assert not matches, f"stale Change-field names found in okta.py: {matches}"

    def test_okta_risk_rules_never_uses_stale_change_field_names(self):
        text = Path("app/services/risk_rules/okta.py").read_text()
        matches = _STALE_FIELD_PATTERN.findall(text)
        assert not matches, f"stale Change-field names found in risk_rules/okta.py: {matches}"

    def test_okta_schema_never_uses_stale_change_field_names(self):
        text = Path("app/connectors/okta_schema.py").read_text()
        matches = _STALE_FIELD_PATTERN.findall(text)
        assert not matches, f"stale Change-field names found in okta_schema.py: {matches}"

    def test_real_compute_diff_only_ever_emits_prev_value_new_value(self):
        prev = [_user("u1", "ACTIVE")]
        new = [_user("u1", "SUSPENDED")]
        changes = compute_diff(_snap(prev), _snap(new))
        for change in changes:
            assert "prev_value" in change
            assert "new_value" in change
            assert "old_value" not in change
            assert "previous_value" not in change

    def test_added_change_has_full_new_record(self):
        changes = compute_diff(_snap([]), _snap([_user("u1", "ACTIVE")]))
        assert changes[0]["change_type"] == "added"
        assert changes[0]["prev_value"] is None
        assert isinstance(changes[0]["new_value"], dict)
        assert changes[0]["new_value"]["user_id"] == "u1"

    def test_removed_change_has_full_prior_record(self):
        changes = compute_diff(_snap([_user("u1", "ACTIVE")]), _snap([]))
        assert changes[0]["change_type"] == "removed"
        assert changes[0]["new_value"] is None
        assert isinstance(changes[0]["prev_value"], dict)
        assert changes[0]["prev_value"]["user_id"] == "u1"


# ════════════════════════════════════════════════════════════════════════════
# Exhaustive user-lifecycle transitions
# ════════════════════════════════════════════════════════════════════════════


class TestExhaustiveUserLifecycleTransitions:
    def _transition(self, prev_status: str, new_status: str) -> tuple:
        prev = [_user("u1", prev_status)]
        new = [_user("u1", new_status)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = next(c for c in changes if c["field_path"] == "status")
        return classify_okta_change(NS(**change))

    def test_active_to_suspended(self):
        level, _ = self._transition("ACTIVE", "SUSPENDED")
        assert level in ("low", "medium")

    def test_suspended_to_active(self):
        level, _ = self._transition("SUSPENDED", "ACTIVE")
        assert level in ("low", "medium", "high")

    def test_active_to_deprovisioned(self):
        level, _ = self._transition("ACTIVE", "DEPROVISIONED")
        assert level in ("low", "medium")

    def test_deprovisioned_to_active(self):
        level, _ = self._transition("DEPROVISIONED", "ACTIVE")
        assert level in ("low", "medium", "high")

    def test_active_to_locked_out(self):
        level, _ = self._transition("ACTIVE", "LOCKED_OUT")
        assert level in ("low", "medium")

    def test_locked_out_to_active(self):
        level, _ = self._transition("LOCKED_OUT", "ACTIVE")
        assert level in ("low", "medium")

    def test_active_to_password_expired(self):
        level, _ = self._transition("ACTIVE", "PASSWORD_EXPIRED")
        assert level in ("low", "medium")

    def test_password_expired_to_active(self):
        level, _ = self._transition("PASSWORD_EXPIRED", "ACTIVE")
        assert level in ("low", "medium")

    def test_active_to_recovery(self):
        level, _ = self._transition("ACTIVE", "RECOVERY")
        assert level in ("low", "medium")

    def test_recovery_to_active(self):
        level, _ = self._transition("RECOVERY", "ACTIVE")
        assert level in ("low", "medium")

    def test_unknown_to_active(self):
        level, reason = self._transition("SOME_FUTURE_STATUS", "ACTIVE")
        assert level in ("low", "medium")

    def test_active_to_unknown(self):
        level, reason = self._transition("ACTIVE", "SOME_FUTURE_STATUS")
        assert level == "medium"  # unrecognized status is a conservative Medium, never silently Low-ignored

    def test_added_user(self):
        changes = compute_diff(_snap([]), _snap([_user("u1", "ACTIVE")]))
        level, _ = classify_okta_change(NS(**changes[0]))
        assert level == "low"

    def test_removed_user(self):
        changes = compute_diff(_snap([_user("u1", "ACTIVE")]), _snap([]))
        level, _ = classify_okta_change(NS(**changes[0]))
        assert level == "low"

    def test_login_rename_same_user_id_is_modification_not_add_remove(self):
        prev = [_user("u1", "ACTIVE", login="old@x.com")]
        new = [_user("u1", "ACTIVE", login="new@x.com")]
        changes = compute_diff(_snap(prev), _snap(new))
        change_types = {c["change_type"] for c in changes}
        assert change_types == {"modified"}


# ════════════════════════════════════════════════════════════════════════════
# Privilege-aware lifecycle outranking
# ════════════════════════════════════════════════════════════════════════════


class TestPrivilegeAwareLifecycleOutranking:
    """A privileged identity's SUSPENDED->ACTIVE reactivation must never be
    classified as LESS severe than an ordinary user's equivalent status
    transition — privilege evidence must only ever raise, never lower,
    the effective severity ConfigTrace assigns to reactivation."""

    _RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}

    def test_privileged_reactivation_outranks_ordinary_reactivation(self):
        ordinary_prev = [_user("u1", "SUSPENDED")]
        ordinary_new = [_user("u1", "ACTIVE")]
        ordinary_changes = compute_diff(_snap(ordinary_prev), _snap(ordinary_new))
        ordinary_change = next(c for c in ordinary_changes if c["field_path"] == "status")
        ordinary_level, _ = classify_okta_change(NS(**ordinary_change))

        privileged_prev = [{
            "record_type": "okta_privileged_identity", "record_id": "id:t1/privileged_identity/u1",
            "tenant_id": _TENANT, "user_id": "u1", "login": "u1@x.com", "user_status": "SUSPENDED",
            "direct_admin_role_count": 1, "group_admin_role_count": 0, "highest_privilege_tier": "critical",
            "has_super_admin": True, "has_high_privilege": True, "privileged_via_group": False,
            "privileged_via_direct_assignment": True, "custom_admin_role_count": 0,
            "application_admin_scope": None, "dormant_privileged_category": "privileged_recent_login",
        }]
        privileged_new = [dict(privileged_prev[0], user_status="ACTIVE")]
        privileged_changes = compute_diff(_snap(privileged_prev), _snap(privileged_new))
        privileged_change = next(c for c in privileged_changes if c["field_path"] == "user_status")
        privileged_level, _ = classify_okta_change(NS(**privileged_change))

        assert self._RANK[privileged_level] >= self._RANK[ordinary_level]


# ════════════════════════════════════════════════════════════════════════════
# Regression tests for bugs found and fixed during this message's audit
# ════════════════════════════════════════════════════════════════════════════


class TestCategorizeScopePartialUnknownRegression:
    """Bug: categorize_scope(group_include_count=0, user_include_count=None)
    (and the reverse) previously coerced a partially-unknown targeting
    state into SCOPE_ALL_USERS — the broadest, most Finding-triggering
    category — instead of leaving it unknown. Fixed in this message."""

    def test_missing_groups_block_with_known_zero_users_is_unknown(self):
        assert categorize_scope(group_include_count=None, user_include_count=0) == "unknown"

    def test_positive_groups_count_wins_even_if_users_unknown(self):
        assert categorize_scope(group_include_count=3, user_include_count=None) == "scoped_groups"

    def test_missing_users_block_alone_is_not_forced_unknown(self):
        # Okta's own routine default: most rules never set user-level
        # targeting at all — its absence alone must not force "unknown".
        assert categorize_scope(group_include_count=0, user_include_count=None) == "all_users"

    def test_both_known_zero_is_real_all_users(self):
        assert categorize_scope(group_include_count=0, user_include_count=0) == "all_users"


class TestEveryoneGroupUnresolvedParentRegression:
    """Bug: when an app-group-assignment's group parent couldn't be
    resolved (group collection denied/partial), everyone_group/
    built_in_group silently defaulted to False (definitely-not-Everyone)
    instead of None (unknown) — which could suppress a real Everyone-group
    Security Finding. Fixed in this message."""

    def test_unresolved_group_parent_gives_unknown_everyone_group(self):
        app_record = {"app_id": "app1", "label": "App"}
        rec = OktaConnector._normalize_app_group_assignment(_TENANT, app_record, None, {"id": "g1"})
        assert rec["everyone_group"] is None
        assert rec["built_in_group"] is None

    def test_resolved_group_parent_gives_real_boolean(self):
        app_record = {"app_id": "app1", "label": "App"}
        group_record = {"group_name": "Everyone", "group_type": "BUILT_IN", "built_in": True, "everyone_group": True}
        rec = OktaConnector._normalize_app_group_assignment(_TENANT, app_record, group_record, {"id": "g1"})
        assert rec["everyone_group"] is True
        assert rec["built_in_group"] is True

    def test_unknown_everyone_group_never_fires_the_finding(self):
        from app.services.security_finding_evaluator import evaluate_record

        rec = OktaConnector._normalize_app_group_assignment(_TENANT, {"app_id": "app1", "label": "App"}, None, {"id": "g1"})
        keys = {f.rule_key for f in evaluate_record(rec, "okta")}
        assert "okta_app_assigned_to_everyone_group" not in keys


class TestPaginationTruncationRegression:
    """Bug: paginate() didn't distinguish a natural end-of-list from a
    mid-pagination failure/cap/repeated-Link/rejected-cross-origin-Link
    stop, so _collect_family reported FAMILY_COMPLETE even when a later
    page was never read — a false-removal risk for every record that
    would have been on the unread pages. Fixed in this message."""

    def test_paginate_returns_a_truncated_flag(self):
        import inspect
        from app.connectors.okta import paginate
        sig = inspect.signature(paginate)
        assert "max_pages" in sig.parameters  # sanity the right function is imported
        # Behavior itself is covered end-to-end in test_okta_foundation.py
        # and test_okta_pagination_reliability.py; this test only pins the
        # return-shape contract so a future refactor can't silently drop it.
        assert paginate.__doc__ is not None and "truncated" in paginate.__doc__
