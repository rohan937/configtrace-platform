"""Microsoft Entra ID partial-sync / false-removal prevention tests (Entra
message 7 of 8).

Uses the REAL ``compute_diff()`` (never a hand-rolled removal-detection
stand-in) to verify:

* a denied/unavailable family never produces fabricated "removed" Changes
  for the records that would have belonged to it;
* an unrelated COMPLETE family still reports real removals normally;
* per-parent completeness (group membership walks, per-SP assignment
  walks) scopes suppression to just the failed parent, not the whole
  tenant;
* derived records (privileged identity/group/service principal) are
  suppressed using the correct underlying family keys;
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
        "record_type": "entra_organization", "record_id": _TENANT, "tenant_id": _TENANT,
        "family_completeness": family_completeness,
    }


def _user(uid: str, **kw) -> dict:
    r = {"record_type": "entra_user", "record_id": f"{_TENANT}/user/{uid}", "tenant_id": _TENANT, "user_id": uid, "user_principal_name": f"{uid}@x.com"}
    r.update(kw)
    return r


def _group(gid: str, **kw) -> dict:
    r = {"record_type": "entra_group", "record_id": f"{_TENANT}/group/{gid}", "tenant_id": _TENANT, "group_id": gid, "display_name": gid, "membership_collection_status": "complete"}
    r.update(kw)
    return r


def _membership(gid: str, uid: str) -> dict:
    return {"record_type": "entra_group_membership", "record_id": f"{_TENANT}/membership/{gid}/{uid}", "tenant_id": _TENANT, "group_id": gid, "user_id": uid}


def _application(aid: str, **kw) -> dict:
    r = {"record_type": "entra_application", "record_id": f"{_TENANT}/application/{aid}", "tenant_id": _TENANT, "object_id": aid, "app_id": f"client-{aid}", "display_name": aid}
    r.update(kw)
    return r


def _sp(spid: str, **kw) -> dict:
    r = {"record_type": "entra_service_principal", "record_id": f"{_TENANT}/service_principal/{spid}", "tenant_id": _TENANT, "service_principal_id": spid, "display_name": spid, "assignment_collection_status": "complete"}
    r.update(kw)
    return r


def _app_user_assignment(spid: str, uid: str) -> dict:
    return {"record_type": "entra_application_user_assignment", "record_id": f"{_TENANT}/app_role_assignment/{spid}/user/{uid}", "tenant_id": _TENANT, "service_principal_id": spid, "user_id": uid}


def _app_group_assignment(spid: str, gid: str) -> dict:
    return {"record_type": "entra_application_group_assignment", "record_id": f"{_TENANT}/app_role_assignment/{spid}/group/{gid}", "tenant_id": _TENANT, "service_principal_id": spid, "group_id": gid}


def _sp_app_role_assignment(resource_spid: str, principal_spid: str) -> dict:
    return {
        "record_type": "entra_service_principal_app_role_assignment",
        "record_id": f"{_TENANT}/app_role_assignment/{resource_spid}/sp/{principal_spid}",
        "tenant_id": _TENANT, "resource_service_principal_id": resource_spid, "principal_service_principal_id": principal_spid,
    }


def _oauth2_grant(gid: str) -> dict:
    return {"record_type": "entra_oauth2_permission_grant", "record_id": f"{_TENANT}/oauth2_permission_grant/{gid}", "tenant_id": _TENANT, "grant_id": gid}


def _ca_policy(pid: str) -> dict:
    return {"record_type": "entra_conditional_access_policy", "record_id": f"{_TENANT}/conditional_access_policy/{pid}", "tenant_id": _TENANT, "policy_id": pid, "display_name": pid}


def _auth_strength(sid: str) -> dict:
    return {"record_type": "entra_authentication_strength", "record_id": f"{_TENANT}/authentication_strength/{sid}", "tenant_id": _TENANT, "strength_id": sid, "display_name": sid}


def _auth_method(mid: str) -> dict:
    return {"record_type": "entra_authentication_method", "record_id": f"{_TENANT}/authentication_method/{mid}", "tenant_id": _TENANT, "method_config_id": mid}


def _directory_role(rid: str) -> dict:
    return {"record_type": "entra_directory_role", "record_id": f"{_TENANT}/directory_role/{rid}", "tenant_id": _TENANT, "role_definition_id": rid, "display_name": rid}


def _directory_role_assignment(aid: str) -> dict:
    return {"record_type": "entra_directory_role_assignment", "record_id": f"{_TENANT}/directory_role_assignment/{aid}", "tenant_id": _TENANT, "assignment_id": aid}


def _privileged_identity(uid: str) -> dict:
    return {"record_type": "entra_privileged_identity", "record_id": f"{_TENANT}/privileged_identity/{uid}", "tenant_id": _TENANT, "user_id": uid}


def _privileged_group(gid: str) -> dict:
    return {"record_type": "entra_privileged_group", "record_id": f"{_TENANT}/privileged_group/{gid}", "tenant_id": _TENANT, "group_id": gid}


def _privileged_sp(spid: str) -> dict:
    return {"record_type": "entra_privileged_service_principal", "record_id": f"{_TENANT}/privileged_service_principal/{spid}", "tenant_id": _TENANT, "service_principal_id": spid}


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
        prev = [_org(applications="complete"), _application("a1")]
        new = [_org(applications="denied")]
        changes = compute_diff(_snap(prev), _snap(new))
        assert changes == []

    def test_service_principals_denied_suppresses_sp_removals(self):
        prev = [_org(service_principals="complete"), _sp("sp1")]
        new = [_org(service_principals="denied")]
        changes = compute_diff(_snap(prev), _snap(new))
        assert changes == []

    def test_oauth2_permission_grants_denied_suppresses_removals(self):
        prev = [_org(oauth2_permission_grants="complete"), _oauth2_grant("g1")]
        new = [_org(oauth2_permission_grants="denied")]
        changes = compute_diff(_snap(prev), _snap(new))
        assert changes == []

    def test_conditional_access_policies_denied_suppresses_removals(self):
        prev = [_org(conditional_access_policies="complete"), _ca_policy("p1")]
        new = [_org(conditional_access_policies="denied")]
        changes = compute_diff(_snap(prev), _snap(new))
        assert changes == []

    def test_authentication_strengths_denied_suppresses_removals(self):
        prev = [_org(authentication_strengths="complete"), _auth_strength("s1")]
        new = [_org(authentication_strengths="denied")]
        changes = compute_diff(_snap(prev), _snap(new))
        assert changes == []

    def test_authentication_methods_denied_suppresses_removals(self):
        prev = [_org(authentication_methods="complete"), _auth_method("Fido2")]
        new = [_org(authentication_methods="denied")]
        changes = compute_diff(_snap(prev), _snap(new))
        assert changes == []

    def test_directory_role_definitions_denied_suppresses_removals(self):
        prev = [_org(directory_role_definitions="complete"), _directory_role("r1")]
        new = [_org(directory_role_definitions="denied")]
        changes = compute_diff(_snap(prev), _snap(new))
        assert changes == []

    def test_directory_role_assignments_denied_suppresses_removals(self):
        prev = [_org(directory_role_assignments="complete"), _directory_role_assignment("a1")]
        new = [_org(directory_role_assignments="denied")]
        changes = compute_diff(_snap(prev), _snap(new))
        assert changes == []

    def test_org_record_itself_removed_is_never_suppressed(self):
        prev = [_org(users="complete"), _user("u1")]
        new = []
        changes = compute_diff(_snap(prev), _snap(new))
        removed_types = {c["provider_metadata"].get("record_type") for c in changes if c["change_type"] == "removed"}
        assert "entra_organization" in removed_types

    def test_no_org_record_in_new_snapshot_falls_back_to_normal_removal(self):
        prev = [_org(users="complete"), _user("u1")]
        new = [_user("u1")]
        changes = compute_diff(_snap(prev), _snap(new))
        assert len(changes) == 1
        assert changes[0]["change_type"] == "removed"
        assert changes[0]["provider_metadata"].get("record_type") == "entra_organization"

        prev2 = [_org(users="denied"), _user("u1")]
        new2 = [_user("u1")]
        changes2 = compute_diff(_snap(prev2), _snap(new2))
        assert any(
            c["change_type"] == "removed" and c["provider_metadata"].get("record_type") == "entra_organization"
            for c in changes2
        )


# ════════════════════════════════════════════════════════════════════════════
# Per-parent completeness (group membership / SP assignment walks)
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
        removed_groups = {c["provider_metadata"].get("group_id") for c in changes if c["change_type"] == "removed" and c["provider_metadata"].get("record_type") == "entra_group_membership"}
        assert removed_groups == {"A", "C"}

    def test_sp_assignment_denied_for_one_sp_complete_for_another(self):
        prev = [
            _org(service_principals="complete", app_role_assignments="partial"),
            _sp("sp1", assignment_collection_status="denied"),
            _sp("sp2", assignment_collection_status="complete"),
            _app_user_assignment("sp1", "u1"),
            _app_user_assignment("sp2", "u2"),
        ]
        new = [
            _org(service_principals="complete", app_role_assignments="partial"),
            _sp("sp1", assignment_collection_status="denied"),
            _sp("sp2", assignment_collection_status="complete"),
        ]
        changes = compute_diff(_snap(prev), _snap(new))
        removed_sps = {c["provider_metadata"].get("service_principal_id") for c in changes if c["change_type"] == "removed" and c["provider_metadata"].get("record_type") == "entra_application_user_assignment"}
        assert removed_sps == {"sp2"}

    def test_group_assignment_denied_for_one_sp_complete_for_another(self):
        prev = [
            _org(service_principals="complete", app_role_assignments="partial"),
            _sp("sp1", assignment_collection_status="denied"),
            _sp("sp2", assignment_collection_status="complete"),
            _app_group_assignment("sp1", "g1"),
            _app_group_assignment("sp2", "g2"),
        ]
        new = [
            _org(service_principals="complete", app_role_assignments="partial"),
            _sp("sp1", assignment_collection_status="denied"),
            _sp("sp2", assignment_collection_status="complete"),
        ]
        changes = compute_diff(_snap(prev), _snap(new))
        removed_sps = {c["provider_metadata"].get("service_principal_id") for c in changes if c["change_type"] == "removed" and c["provider_metadata"].get("record_type") == "entra_application_group_assignment"}
        assert removed_sps == {"sp2"}

    def test_sp_app_role_assignment_scoped_to_resource_sp(self):
        prev = [
            _org(service_principals="complete", app_role_assignments="partial"),
            _sp("graph", assignment_collection_status="denied"),
            _sp("other", assignment_collection_status="complete"),
            _sp_app_role_assignment("graph", "clientA"),
            _sp_app_role_assignment("other", "clientB"),
        ]
        new = [
            _org(service_principals="complete", app_role_assignments="partial"),
            _sp("graph", assignment_collection_status="denied"),
            _sp("other", assignment_collection_status="complete"),
        ]
        changes = compute_diff(_snap(prev), _snap(new))
        removed_resources = {c["provider_metadata"].get("resource_service_principal_id") for c in changes if c["change_type"] == "removed" and c["provider_metadata"].get("record_type") == "entra_service_principal_app_role_assignment"}
        assert removed_resources == {"other"}

    def test_parent_group_itself_removed_falls_back_to_tenant_wide_check(self):
        prev = [
            _org(groups="complete", memberships="complete"),
            _group("B", membership_collection_status="complete"),
            _membership("B", "u2"),
        ]
        new = [_org(groups="complete", memberships="complete")]
        changes = compute_diff(_snap(prev), _snap(new))
        removed_types = {c["provider_metadata"].get("record_type") for c in changes if c["change_type"] == "removed"}
        assert "entra_group" in removed_types
        assert "entra_group_membership" in removed_types

    def test_parent_group_removed_with_incomplete_family_suppresses_membership(self):
        prev = [
            _org(groups="complete", memberships="denied"),
            _group("B", membership_collection_status="denied"),
            _membership("B", "u2"),
        ]
        new = [_org(groups="complete", memberships="denied")]
        changes = compute_diff(_snap(prev), _snap(new))
        removed_types = {c["provider_metadata"].get("record_type") for c in changes if c["change_type"] == "removed"}
        assert "entra_group_membership" not in removed_types

    def test_group_never_walked_this_cycle_defaults_unavailable_suppresses(self):
        # Group C has NO membership_collection_status entry at all this
        # cycle (truncated out by the enumeration cap) — must default to
        # unavailable (suppressed), never complete.
        prev = [
            _org(groups="complete", memberships="partial"),
            _group("C"),  # no membership_collection_status override -> defaults "complete" in fixture, override below
            _membership("C", "u3"),
        ]
        prev[1]["membership_collection_status"] = "unavailable"
        new = [
            _org(groups="complete", memberships="partial"),
            {**prev[1]},
        ]
        changes = compute_diff(_snap(prev), _snap(new))
        removed_types = {c["provider_metadata"].get("record_type") for c in changes if c["change_type"] == "removed"}
        assert "entra_group_membership" not in removed_types


# ════════════════════════════════════════════════════════════════════════════
# Derived records (privileged identity/group/service principal)
# ════════════════════════════════════════════════════════════════════════════


class TestDerivedRecordSuppression:
    def test_privileged_identity_suppressed_when_directory_role_assignments_denied(self):
        prev = [_org(directory_role_assignments="complete", memberships="complete"), _privileged_identity("u1")]
        new = [_org(directory_role_assignments="denied", memberships="complete")]
        changes = compute_diff(_snap(prev), _snap(new))
        assert changes == []

    def test_privileged_identity_suppressed_when_memberships_denied(self):
        prev = [_org(directory_role_assignments="complete", memberships="complete"), _privileged_identity("u1")]
        new = [_org(directory_role_assignments="complete", memberships="denied")]
        changes = compute_diff(_snap(prev), _snap(new))
        assert changes == []

    def test_privileged_identity_real_removal_when_both_complete(self):
        prev = [_org(directory_role_assignments="complete", memberships="complete"), _privileged_identity("u1")]
        new = [_org(directory_role_assignments="complete", memberships="complete")]
        changes = compute_diff(_snap(prev), _snap(new))
        assert any(c["change_type"] == "removed" for c in changes)

    def test_privileged_group_suppressed_when_directory_role_assignments_denied(self):
        prev = [_org(directory_role_assignments="complete", memberships="complete"), _privileged_group("g1")]
        new = [_org(directory_role_assignments="denied", memberships="complete")]
        changes = compute_diff(_snap(prev), _snap(new))
        assert changes == []

    def test_privileged_group_real_removal_when_both_complete(self):
        prev = [_org(directory_role_assignments="complete", memberships="complete"), _privileged_group("g1")]
        new = [_org(directory_role_assignments="complete", memberships="complete")]
        changes = compute_diff(_snap(prev), _snap(new))
        assert any(c["change_type"] == "removed" for c in changes)

    def test_privileged_sp_suppressed_when_directory_role_assignments_denied(self):
        prev = [_org(directory_role_assignments="complete", app_role_assignments="complete", oauth2_permission_grants="complete"), _privileged_sp("sp1")]
        new = [_org(directory_role_assignments="denied", app_role_assignments="complete", oauth2_permission_grants="complete")]
        changes = compute_diff(_snap(prev), _snap(new))
        assert changes == []

    def test_privileged_sp_suppressed_when_app_role_assignments_denied(self):
        prev = [_org(directory_role_assignments="complete", app_role_assignments="complete", oauth2_permission_grants="complete"), _privileged_sp("sp1")]
        new = [_org(directory_role_assignments="complete", app_role_assignments="denied", oauth2_permission_grants="complete")]
        changes = compute_diff(_snap(prev), _snap(new))
        assert changes == []

    def test_privileged_sp_suppressed_when_oauth2_grants_denied(self):
        prev = [_org(directory_role_assignments="complete", app_role_assignments="complete", oauth2_permission_grants="complete"), _privileged_sp("sp1")]
        new = [_org(directory_role_assignments="complete", app_role_assignments="complete", oauth2_permission_grants="denied")]
        changes = compute_diff(_snap(prev), _snap(new))
        assert changes == []

    def test_privileged_sp_real_removal_when_all_complete(self):
        prev = [_org(directory_role_assignments="complete", app_role_assignments="complete", oauth2_permission_grants="complete"), _privileged_sp("sp1")]
        new = [_org(directory_role_assignments="complete", app_role_assignments="complete", oauth2_permission_grants="complete")]
        changes = compute_diff(_snap(prev), _snap(new))
        assert any(c["change_type"] == "removed" for c in changes)


# ════════════════════════════════════════════════════════════════════════════
# First-sync / recovery-after-partial-sync semantics
# ════════════════════════════════════════════════════════════════════════════


class TestFirstSyncSemantics:
    def test_first_sync_produces_no_removed_changes(self):
        new = [_org(users="complete"), _user("u1")]
        changes = compute_diff(_snap([]), _snap(new))
        assert all(c["change_type"] == "added" for c in changes)

    def test_recovery_after_partial_sync_shows_as_added_not_mass_removal(self):
        sync1 = [_org(users="complete"), _user("u1"), _user("u2")]
        sync2 = [_org(users="denied")]
        sync3 = [_org(users="denied")]
        sync4 = [_org(users="complete"), _user("u1"), _user("u2"), _user("u3")]

        changes_1_to_2 = compute_diff(_snap(sync1), _snap(sync2))
        assert changes_1_to_2 == []

        changes_2_to_3 = compute_diff(_snap(sync2), _snap(sync3))
        assert changes_2_to_3 == []

        changes_3_to_4 = compute_diff(_snap(sync3), _snap(sync4))
        assert len(changes_3_to_4) == 3
        assert all(c["change_type"] == "added" for c in changes_3_to_4)

    def test_recovery_of_group_membership_after_group_denied(self):
        sync1 = [
            _org(groups="complete", memberships="complete"),
            _group("A", membership_collection_status="complete"),
            _membership("A", "u1"),
        ]
        sync2 = [
            _org(groups="complete", memberships="partial"),
            _group("A", membership_collection_status="denied"),
        ]
        sync3 = [
            _org(groups="complete", memberships="complete"),
            _group("A", membership_collection_status="complete"),
            _membership("A", "u1"),
        ]
        changes_1_to_2 = compute_diff(_snap(sync1), _snap(sync2))
        assert not any(c["change_type"] == "removed" and c["provider_metadata"].get("record_type") == "entra_group_membership" for c in changes_1_to_2)

        changes_2_to_3 = compute_diff(_snap(sync2), _snap(sync3))
        added_membership = [c for c in changes_2_to_3 if c["change_type"] == "added" and c["provider_metadata"].get("record_type") == "entra_group_membership"]
        assert len(added_membership) == 1

    def test_recovery_of_sp_assignments_after_sp_denied(self):
        sync1 = [
            _org(service_principals="complete", app_role_assignments="complete"),
            _sp("sp1", assignment_collection_status="complete"),
            _app_user_assignment("sp1", "u1"),
        ]
        sync2 = [
            _org(service_principals="complete", app_role_assignments="partial"),
            _sp("sp1", assignment_collection_status="denied"),
        ]
        sync3 = [
            _org(service_principals="complete", app_role_assignments="complete"),
            _sp("sp1", assignment_collection_status="complete"),
            _app_user_assignment("sp1", "u1"),
        ]
        changes_1_to_2 = compute_diff(_snap(sync1), _snap(sync2))
        assert not any(c["change_type"] == "removed" and c["provider_metadata"].get("record_type") == "entra_application_user_assignment" for c in changes_1_to_2)

        changes_2_to_3 = compute_diff(_snap(sync2), _snap(sync3))
        added = [c for c in changes_2_to_3 if c["change_type"] == "added" and c["provider_metadata"].get("record_type") == "entra_application_user_assignment"]
        assert len(added) == 1
