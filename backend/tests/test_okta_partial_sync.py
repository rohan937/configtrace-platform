"""Okta partial-sync / false-removal prevention tests (Okta message 7 of 8).

Uses the REAL ``compute_diff()`` (never a hand-rolled removal-detection
stand-in) to verify:

* a denied/unavailable family never produces fabricated "removed" Changes
  for the records that would have belonged to it;
* an unrelated COMPLETE family still reports real removals normally;
* per-parent completeness (group membership walks, per-app assignment
  walks, per-policy rule walks) scopes suppression to just the failed
  parent, not the whole tenant;
* derived records (privileged identity/group) and the admin-role catalog
  are suppressed using the correct underlying family keys;
* first-sync / recovery-after-partial-sync semantics.
"""

from __future__ import annotations

from types import SimpleNamespace as NS

from app.services.diff_service import compute_diff

_TENANT = "id:t1"


def _snap(records: list[dict]) -> NS:
    return NS(state=records)


def _org(**family_completeness) -> dict:
    return {
        "record_type": "okta_organization", "record_id": _TENANT, "tenant_id": _TENANT,
        "family_completeness": family_completeness,
    }


def _user(uid: str, **kw) -> dict:
    r = {"record_type": "okta_user", "record_id": f"{_TENANT}/user/{uid}", "tenant_id": _TENANT, "user_id": uid, "login": f"{uid}@x.com", "status": "ACTIVE"}
    r.update(kw)
    return r


def _group(gid: str, **kw) -> dict:
    r = {"record_type": "okta_group", "record_id": f"{_TENANT}/group/{gid}", "tenant_id": _TENANT, "group_id": gid, "group_name": gid, "membership_collection_status": "complete"}
    r.update(kw)
    return r


def _membership(gid: str, uid: str) -> dict:
    return {"record_type": "okta_group_membership", "record_id": f"{_TENANT}/membership/{gid}/{uid}", "tenant_id": _TENANT, "group_id": gid, "user_id": uid}


def _app(app_id: str, **kw) -> dict:
    r = {
        "record_type": "okta_application", "record_id": f"{_TENANT}/app/{app_id}", "tenant_id": _TENANT, "app_id": app_id,
        "label": app_id, "user_assignment_collection_status": "complete", "group_assignment_collection_status": "complete",
    }
    r.update(kw)
    return r


def _app_user_assignment(app_id: str, uid: str) -> dict:
    return {"record_type": "okta_application_user_assignment", "record_id": f"{_TENANT}/app_assignment/{app_id}/user/{uid}", "tenant_id": _TENANT, "app_id": app_id, "user_id": uid}


def _app_group_assignment(app_id: str, gid: str) -> dict:
    return {"record_type": "okta_application_group_assignment", "record_id": f"{_TENANT}/app_assignment/{app_id}/group/{gid}", "tenant_id": _TENANT, "app_id": app_id, "group_id": gid}


def _policy(pid: str, **kw) -> dict:
    r = {"record_type": "okta_policy", "record_id": f"{_TENANT}/policy/{pid}", "tenant_id": _TENANT, "policy_id": pid, "policy_name": pid, "rule_collection_status": "complete"}
    r.update(kw)
    return r


def _rule(pid: str, rid: str) -> dict:
    return {"record_type": "okta_policy_rule", "record_id": f"{_TENANT}/policy_rule/{pid}/{rid}", "tenant_id": _TENANT, "policy_id": pid, "rule_id": rid, "rule_name": rid}


def _authenticator(aid: str) -> dict:
    return {"record_type": "okta_authenticator", "record_id": f"{_TENANT}/authenticator/{aid}", "tenant_id": _TENANT, "authenticator_id": aid, "key": "okta_verify"}


def _admin_role(role_id: str, **kw) -> dict:
    r = {"record_type": "okta_admin_role", "record_id": f"{_TENANT}/admin_role/{role_id}", "tenant_id": _TENANT, "role_id": role_id, "role_type": role_id, "custom": False}
    r.update(kw)
    return r


def _user_assignment(uid: str, role_id: str) -> dict:
    return {"record_type": "okta_user_admin_role_assignment", "record_id": f"{_TENANT}/user_admin_role/{uid}/{role_id}/all", "tenant_id": _TENANT, "user_id": uid, "role_id": role_id}


def _group_assignment(gid: str, role_id: str) -> dict:
    return {"record_type": "okta_group_admin_role_assignment", "record_id": f"{_TENANT}/group_admin_role/{gid}/{role_id}/all", "tenant_id": _TENANT, "group_id": gid, "role_id": role_id}


def _privileged_identity(uid: str) -> dict:
    return {"record_type": "okta_privileged_identity", "record_id": f"{_TENANT}/privileged_identity/{uid}", "tenant_id": _TENANT, "user_id": uid}


def _privileged_group(gid: str) -> dict:
    return {"record_type": "okta_privileged_group", "record_id": f"{_TENANT}/privileged_group/{gid}", "tenant_id": _TENANT, "group_id": gid}


def _removed_ids(changes: list[dict]) -> set:
    return {c["record_identifier"] for c in changes if c["change_type"] == "removed"}


# ════════════════════════════════════════════════════════════════════════════
# Tenant-wide family suppression
# ════════════════════════════════════════════════════════════════════════════


class TestTenantWideFamilySuppression:
    def test_users_denied_suppresses_all_user_removals(self):
        prev = [_org(users="complete"), _user("u1"), _user("u2"), _user("u3")]
        new = [_org(users="denied")]
        changes = compute_diff(_snap(prev), _snap(new))
        assert changes == []

    def test_users_unavailable_suppresses_removals(self):
        prev = [_org(users="complete"), _user("u1")]
        new = [_org(users="unavailable")]
        changes = compute_diff(_snap(prev), _snap(new))
        assert changes == []

    def test_users_partial_suppresses_removals(self):
        prev = [_org(users="complete"), _user("u1")]
        new = [_org(users="partial")]
        changes = compute_diff(_snap(prev), _snap(new))
        assert changes == []

    def test_users_throttled_suppresses_removals(self):
        prev = [_org(users="complete"), _user("u1")]
        new = [_org(users="throttled")]
        changes = compute_diff(_snap(prev), _snap(new))
        assert changes == []

    def test_users_complete_allows_real_removal(self):
        prev = [_org(users="complete"), _user("u1"), _user("u2")]
        new = [_org(users="complete"), _user("u1")]
        changes = compute_diff(_snap(prev), _snap(new))
        assert any(c["change_type"] == "removed" for c in changes)

    def test_unrelated_family_denied_does_not_affect_users(self):
        prev = [_org(users="complete", applications="complete"), _user("u1"), _user("u2")]
        new = [_org(users="complete", applications="denied"), _user("u1")]
        changes = compute_diff(_snap(prev), _snap(new))
        assert any(c["change_type"] == "removed" for c in changes)

    def test_applications_denied_suppresses_app_removals(self):
        prev = [_org(applications="complete"), _app("a1")]
        new = [_org(applications="denied")]
        changes = compute_diff(_snap(prev), _snap(new))
        assert changes == []

    def test_policies_denied_suppresses_policy_removals(self):
        prev = [_org(policies="complete"), _policy("p1")]
        new = [_org(policies="denied")]
        changes = compute_diff(_snap(prev), _snap(new))
        assert changes == []

    def test_authenticators_denied_suppresses_removals(self):
        prev = [_org(authenticators="complete"), _authenticator("auth1")]
        new = [_org(authenticators="denied")]
        changes = compute_diff(_snap(prev), _snap(new))
        assert changes == []

    def test_org_record_itself_removed_is_never_suppressed(self):
        prev = [_org(users="complete"), _user("u1")]
        new = []
        changes = compute_diff(_snap(prev), _snap(new))
        removed_types = {c["provider_metadata"].get("record_type") for c in changes if c["change_type"] == "removed"}
        assert "okta_organization" in removed_types

    def test_no_org_record_in_new_snapshot_falls_back_to_normal_removal(self):
        # Malformed/missing org record — cannot consult completeness, so the
        # normal (unsuppressed) removal path proceeds rather than guessing.
        prev = [_org(users="complete"), _user("u1")]
        new = [_user("u1")]  # org record itself absent, user still present
        changes = compute_diff(_snap(prev), _snap(new))
        # u1 is unchanged (still present in both snapshots); only the org
        # record's own removal is reported — that removal is never
        # suppressed since there's no org record left to consult at all.
        assert len(changes) == 1
        assert changes[0]["change_type"] == "removed"
        assert changes[0]["provider_metadata"].get("record_type") == "okta_organization"
        # verify org removal is reported (not suppressed) in a second variant
        prev2 = [_org(users="denied"), _user("u1")]
        new2 = [_user("u1")]
        changes2 = compute_diff(_snap(prev2), _snap(new2))
        assert any(c["change_type"] == "removed" and c["provider_metadata"].get("record_type") == "okta_organization" for c in changes2)


# ════════════════════════════════════════════════════════════════════════════
# Per-parent completeness (group membership / app assignments / policy rules)
# ════════════════════════════════════════════════════════════════════════════


class TestPerParentCompleteness:
    def test_group_a_complete_b_denied_c_complete(self):
        prev = [
            _org(groups="complete", memberships="partial"),
            _group("A", membership_collection_status="complete"),
            _group("B", membership_collection_status="denied"),
            _group("C", membership_collection_status="complete"),
            _membership("A", "u1"), _membership("B", "u2"), _membership("C", "u3"),
        ]
        new = [
            _org(groups="complete", memberships="partial"),
            _group("A", membership_collection_status="complete"),
            _group("B", membership_collection_status="denied"),
            _group("C", membership_collection_status="complete"),
        ]
        changes = compute_diff(_snap(prev), _snap(new))
        removed_groups = {c["provider_metadata"].get("group_id") for c in changes if c["change_type"] == "removed" and c["provider_metadata"].get("record_type") == "okta_group_membership"}
        assert removed_groups == {"A", "C"}

    def test_app_a_user_assignments_denied_group_assignments_complete(self):
        prev = [
            _org(applications="complete", app_user_assignments="partial", app_group_assignments="complete"),
            _app("app1", user_assignment_collection_status="denied", group_assignment_collection_status="complete"),
            _app_user_assignment("app1", "u1"),
            _app_group_assignment("app1", "g1"),
        ]
        new = [
            _org(applications="complete", app_user_assignments="partial", app_group_assignments="complete"),
            _app("app1", user_assignment_collection_status="denied", group_assignment_collection_status="complete"),
        ]
        changes = compute_diff(_snap(prev), _snap(new))
        removed = [(c["provider_metadata"].get("record_type")) for c in changes if c["change_type"] == "removed"]
        assert "okta_application_user_assignment" not in removed
        assert "okta_application_group_assignment" in removed

    def test_policy_rules_per_policy(self):
        prev = [
            _org(policies="complete", policy_rules="partial"),
            _policy("p1", rule_collection_status="complete"),
            _policy("p2", rule_collection_status="denied"),
            _rule("p1", "r1"), _rule("p2", "r2"),
        ]
        new = [
            _org(policies="complete", policy_rules="partial"),
            _policy("p1", rule_collection_status="complete"),
            _policy("p2", rule_collection_status="denied"),
        ]
        changes = compute_diff(_snap(prev), _snap(new))
        removed_policies = {c["provider_metadata"].get("policy_id") for c in changes if c["change_type"] == "removed" and c["provider_metadata"].get("record_type") == "okta_policy_rule"}
        assert removed_policies == {"p1"}

    def test_parent_group_itself_removed_falls_back_to_tenant_wide_check(self):
        # Group B's parent record is ALSO gone from the new snapshot (e.g.
        # group B was itself removed) — the membership suppression falls
        # back to the tenant-wide "groups"/"memberships" family check.
        prev = [
            _org(groups="complete", memberships="complete"),
            _group("B", membership_collection_status="complete"),
            _membership("B", "u2"),
        ]
        new = [_org(groups="complete", memberships="complete")]
        changes = compute_diff(_snap(prev), _snap(new))
        # Both the group and its membership are real removals since both
        # families are reported complete.
        removed_types = {c["provider_metadata"].get("record_type") for c in changes if c["change_type"] == "removed"}
        assert "okta_group" in removed_types
        assert "okta_group_membership" in removed_types

    def test_parent_group_removed_with_incomplete_family_suppresses_membership(self):
        prev = [
            _org(groups="complete", memberships="denied"),
            _group("B", membership_collection_status="denied"),
            _membership("B", "u2"),
        ]
        new = [_org(groups="complete", memberships="denied")]
        changes = compute_diff(_snap(prev), _snap(new))
        removed_types = {c["provider_metadata"].get("record_type") for c in changes if c["change_type"] == "removed"}
        assert "okta_group_membership" not in removed_types


# ════════════════════════════════════════════════════════════════════════════
# Derived records (privileged identity/group) and admin-role catalog
# ════════════════════════════════════════════════════════════════════════════


class TestDerivedRecordSuppression:
    def test_privileged_identity_suppressed_when_user_assignments_denied(self):
        prev = [_org(user_admin_role_assignments="complete", group_admin_role_assignments="complete"), _privileged_identity("u1")]
        new = [_org(user_admin_role_assignments="denied", group_admin_role_assignments="complete")]
        changes = compute_diff(_snap(prev), _snap(new))
        assert changes == []

    def test_privileged_identity_suppressed_when_group_assignments_denied(self):
        prev = [_org(user_admin_role_assignments="complete", group_admin_role_assignments="complete"), _privileged_identity("u1")]
        new = [_org(user_admin_role_assignments="complete", group_admin_role_assignments="denied")]
        changes = compute_diff(_snap(prev), _snap(new))
        assert changes == []

    def test_privileged_identity_real_removal_when_both_complete(self):
        prev = [_org(user_admin_role_assignments="complete", group_admin_role_assignments="complete"), _privileged_identity("u1")]
        new = [_org(user_admin_role_assignments="complete", group_admin_role_assignments="complete")]
        changes = compute_diff(_snap(prev), _snap(new))
        assert any(c["change_type"] == "removed" for c in changes)

    def test_privileged_group_suppressed_when_group_assignments_denied(self):
        prev = [_org(group_admin_role_assignments="complete"), _privileged_group("g1")]
        new = [_org(group_admin_role_assignments="denied")]
        changes = compute_diff(_snap(prev), _snap(new))
        assert changes == []

    def test_custom_admin_role_suppressed_when_custom_roles_denied(self):
        prev = [_org(custom_admin_roles="complete"), _admin_role("cr1", custom=True)]
        new = [_org(custom_admin_roles="denied")]
        changes = compute_diff(_snap(prev), _snap(new))
        assert changes == []

    def test_builtin_admin_role_suppressed_only_when_both_assignment_families_fail(self):
        prev = [_org(user_admin_role_assignments="denied", group_admin_role_assignments="denied"), _admin_role("SUPER_ADMIN", custom=False)]
        new = [_org(user_admin_role_assignments="denied", group_admin_role_assignments="denied")]
        changes = compute_diff(_snap(prev), _snap(new))
        assert changes == []

    def test_builtin_admin_role_real_removal_when_one_family_complete(self):
        # Only the group-assignment family is denied; the user-assignment
        # family succeeded and found no one with this role — a real signal.
        prev = [_org(user_admin_role_assignments="complete", group_admin_role_assignments="denied"), _admin_role("SUPER_ADMIN", custom=False)]
        new = [_org(user_admin_role_assignments="complete", group_admin_role_assignments="denied")]
        changes = compute_diff(_snap(prev), _snap(new))
        assert any(c["change_type"] == "removed" for c in changes)

    def test_user_admin_role_assignment_suppressed(self):
        prev = [_org(user_admin_role_assignments="complete"), _user_assignment("u1", "SUPER_ADMIN")]
        new = [_org(user_admin_role_assignments="denied")]
        changes = compute_diff(_snap(prev), _snap(new))
        assert changes == []

    def test_group_admin_role_assignment_suppressed(self):
        prev = [_org(group_admin_role_assignments="complete"), _group_assignment("g1", "APP_ADMIN")]
        new = [_org(group_admin_role_assignments="denied")]
        changes = compute_diff(_snap(prev), _snap(new))
        assert changes == []


# ════════════════════════════════════════════════════════════════════════════
# First-sync / recovery-after-partial-sync semantics
# ════════════════════════════════════════════════════════════════════════════


class TestFirstSyncSemantics:
    def test_first_sync_produces_no_changes(self):
        # First sync: prev snapshot is empty (no baseline exists yet).
        new = [_org(users="complete"), _user("u1", status="ACTIVE")]
        # Simulate "first sync" as an empty previous snapshot.
        changes = compute_diff(_snap([]), _snap(new))
        # Every record shows as "added" — this is expected and does NOT
        # fabricate historical drift; a Super Admin existing on day one is
        # a Security Finding, never a "Super Admin added" Change implying
        # a recent grant.
        assert all(c["change_type"] == "added" for c in changes)

    def test_recovery_after_partial_sync_shows_as_added_not_mass_removal(self):
        # sync 1: complete. sync 2/3: denied (blind period — records
        # absent from those snapshots, per _collect_family's fail-soft
        # design). sync 4: complete again.
        sync1 = [_org(users="complete"), _user("u1"), _user("u2")]
        sync2 = [_org(users="denied")]  # blind period: no user records collected
        sync3 = [_org(users="denied")]
        sync4 = [_org(users="complete"), _user("u1"), _user("u2"), _user("u3")]

        changes_1_to_2 = compute_diff(_snap(sync1), _snap(sync2))
        assert changes_1_to_2 == []  # suppressed, not "u1 and u2 removed"

        changes_2_to_3 = compute_diff(_snap(sync2), _snap(sync3))
        assert changes_2_to_3 == []  # both blind, nothing to compare

        changes_3_to_4 = compute_diff(_snap(sync3), _snap(sync4))
        # Re-baseline semantics (documented choice): recovery reports the
        # regained visibility as "added", never a fabricated "here is
        # exactly what changed during the blind window" diff.
        assert len(changes_3_to_4) == 3  # u1, u2 (re-appearing) + u3 (new)
        assert all(c["change_type"] == "added" for c in changes_3_to_4)
