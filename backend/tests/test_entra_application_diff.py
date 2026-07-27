"""Microsoft Entra ID application security diff/risk-classification tests
(Entra message 3 of 8).

Uses the REAL ``compute_diff()`` and ``classify_entra_change()`` — never
hand-built Change objects standing in for the diff pipeline — to verify
sign-in-audience/service-principal/assignment-required/redirect/credential
Change classification, user/group/service-principal assignment semantics,
tenant-wide consent classification, high-risk delegated scope
classification, provider metadata, and the ignored-timestamp discipline.
"""

from __future__ import annotations

from types import SimpleNamespace as NS

from app.services.diff_service import compute_diff
from app.services.risk_rules.entra import classify_entra_change

_TENANT = "id:t1"


def _snap(records: list[dict]) -> NS:
    return NS(state=records)


def _application_record(**overrides) -> dict:
    base = {
        "record_type": "entra_application",
        "record_id": f"{_TENANT}/application/a1",
        "provider_resource_id": "applications/a1",
        "tenant_id": _TENANT,
        "object_id": "a1",
        "app_id": "client-a1",
        "display_name": "Test App",
        "sign_in_audience_category": "single_tenant",
        "publisher_domain": None,
        "web_redirect_count": 1,
        "spa_redirect_count": 0,
        "public_client_redirect_count": 0,
        "has_http_redirect": False,
        "web_has_http_redirect": False,
        "has_localhost_redirect": False,
        "has_loopback_redirect": False,
        "has_custom_scheme_redirect": False,
        "has_wildcard_redirect": False,
        "requested_resource_api_count": 1,
        "requested_delegated_permission_count": 1,
        "requested_application_permission_count": 0,
        "password_credential_count": 0,
        "key_credential_count": 0,
        "nearest_credential_expiry_category": "no_credentials",
        "app_role_count": 0,
        "app_role_enabled_count": 0,
    }
    base.update(overrides)
    return base


def _sp_record(**overrides) -> dict:
    base = {
        "record_type": "entra_service_principal",
        "record_id": f"{_TENANT}/service_principal/sp1",
        "provider_resource_id": "servicePrincipals/sp1",
        "tenant_id": _TENANT,
        "service_principal_id": "sp1",
        "app_id": "client-sp1",
        "display_name": "Test SP",
        "service_principal_type_category": "Application",
        "account_enabled": True,
        "assignment_required": False,
        "app_owner_organization_category": "tenant_owned",
        "is_microsoft_first_party": False,
        "is_microsoft_graph_resource": False,
        "verified_publisher_category": "unverified",
        "app_role_count": 0,
        "oauth2_permission_scope_count": 0,
        "password_credential_count": 0,
        "key_credential_count": 0,
        "nearest_credential_expiry_category": "no_credentials",
    }
    base.update(overrides)
    return base


def _user_assignment_record(**overrides) -> dict:
    base = {
        "record_type": "entra_application_user_assignment",
        "record_id": f"{_TENANT}/app_role_assignment/assign1",
        "provider_resource_id": "servicePrincipals/sp1/appRoleAssignedTo/u1",
        "tenant_id": _TENANT,
        "service_principal_id": "sp1",
        "app_id": "client-sp1",
        "application_name": "Test SP",
        "principal_id": "u1",
        "user_id": "u1",
        "user_principal_name": "u1@example.com",
        "account_enabled_category": "enabled",
        "user_type_category": "Member",
        "app_role_category": "Reader",
        "app_role_risk_category": "ordinary",
        "assignment_type": "user",
    }
    base.update(overrides)
    return base


def _group_assignment_record(**overrides) -> dict:
    base = {
        "record_type": "entra_application_group_assignment",
        "record_id": f"{_TENANT}/app_role_assignment/assign2",
        "provider_resource_id": "servicePrincipals/sp1/appRoleAssignedTo/g1",
        "tenant_id": _TENANT,
        "service_principal_id": "sp1",
        "app_id": "client-sp1",
        "application_name": "Test SP",
        "group_id": "g1",
        "group_name": "Engineering",
        "group_type_category": "security",
        "dynamic_group": False,
        "role_assignable_group": False,
        "app_role_category": "Reader",
        "app_role_risk_category": "ordinary",
        "assignment_type": "group",
    }
    base.update(overrides)
    return base


def _sp_assignment_record(**overrides) -> dict:
    base = {
        "record_type": "entra_service_principal_app_role_assignment",
        "record_id": f"{_TENANT}/app_role_assignment/assign3",
        "provider_resource_id": "servicePrincipals/sp1/appRoleAssignedTo/sp2",
        "tenant_id": _TENANT,
        "resource_service_principal_id": "sp1",
        "resource_app_id": "client-sp1",
        "resource_name": "Resource SP",
        "resource_is_microsoft_graph": False,
        "principal_service_principal_id": "sp2",
        "principal_app_id": "client-sp2",
        "principal_name": "Automation SP",
        "app_role_category": "Reader",
        "app_role_risk_category": "ordinary",
        "assignment_type": "service_principal",
    }
    base.update(overrides)
    return base


def _grant_record(**overrides) -> dict:
    base = {
        "record_type": "entra_oauth2_permission_grant",
        "record_id": f"{_TENANT}/oauth2_permission_grant/g1",
        "provider_resource_id": "oauth2PermissionGrants/g1",
        "tenant_id": _TENANT,
        "grant_id": "g1",
        "client_service_principal_id": "sp1",
        "client_name": "Client SP",
        "resource_service_principal_id": "sp2",
        "resource_name": "Resource SP",
        "resource_is_microsoft_graph": False,
        "consent_type_category": "Principal",
        "principal_id": "u1",
        "scope_count": 1,
        "scopes": ["User.Read"],
        "high_risk_scope_present": False,
    }
    base.update(overrides)
    return base


def _find_field_change(changes: list[dict], field_path: str) -> dict:
    match = [c for c in changes if c["field_path"] == field_path]
    assert match, f"no change found for field_path={field_path!r} in {changes}"
    return match[0]


# ════════════════════════════════════════════════════════════════════════════
# No spurious changes when identical
# ════════════════════════════════════════════════════════════════════════════


class TestNoSpuriousChangeWhenIdentical:
    def test_identical_application_produces_no_change(self):
        rec = _application_record()
        changes = compute_diff(_snap([rec]), _snap([dict(rec)]))
        assert changes == []

    def test_identical_sp_produces_no_change(self):
        rec = _sp_record()
        changes = compute_diff(_snap([rec]), _snap([dict(rec)]))
        assert changes == []

    def test_same_data_reordered_produces_no_changes(self):
        a1 = _application_record(object_id="a1", record_id=f"{_TENANT}/application/a1")
        a2 = _application_record(object_id="a2", record_id=f"{_TENANT}/application/a2")
        changes = compute_diff(_snap([a1, a2]), _snap([dict(a2), dict(a1)]))
        assert changes == []


# ════════════════════════════════════════════════════════════════════════════
# Application changes
# ════════════════════════════════════════════════════════════════════════════


class TestApplicationChanges:
    def test_single_to_multi_tenant_is_medium(self):
        prev = [_application_record(sign_in_audience_category="single_tenant")]
        new = [_application_record(sign_in_audience_category="multi_tenant")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "sign_in_audience_category")
        level, reason = classify_entra_change(change)
        assert level == "medium"
        assert "eligible" in reason.lower() or "broaden" in reason.lower()

    def test_multi_to_single_tenant_is_low(self):
        prev = [_application_record(sign_in_audience_category="multi_tenant")]
        new = [_application_record(sign_in_audience_category="single_tenant")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "sign_in_audience_category")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_app_added_is_low(self):
        changes = compute_diff(_snap([]), _snap([_application_record()]))
        change = next(c for c in changes if c["change_type"] == "added")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_app_removed_is_low(self):
        changes = compute_diff(_snap([_application_record()]), _snap([]))
        change = next(c for c in changes if c["change_type"] == "removed")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_http_redirect_introduced_is_medium(self):
        prev = [_application_record(has_http_redirect=False, web_has_http_redirect=False)]
        new = [_application_record(has_http_redirect=True, web_has_http_redirect=True)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "web_has_http_redirect")
        level, _ = classify_entra_change(change)
        assert level == "medium"

    def test_http_redirect_removed_is_low(self):
        prev = [_application_record(has_http_redirect=True, web_has_http_redirect=True)]
        new = [_application_record(has_http_redirect=False, web_has_http_redirect=False)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "web_has_http_redirect")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_wildcard_redirect_introduced_is_high(self):
        prev = [_application_record(has_wildcard_redirect=False)]
        new = [_application_record(has_wildcard_redirect=True)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "has_wildcard_redirect")
        level, _ = classify_entra_change(change)
        assert level == "high"

    def test_localhost_redirect_change_not_over_ranked(self):
        prev = [_application_record(has_localhost_redirect=False)]
        new = [_application_record(has_localhost_redirect=True)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "has_localhost_redirect")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_credential_expired_is_medium(self):
        prev = [_application_record(nearest_credential_expiry_category="healthy")]
        new = [_application_record(nearest_credential_expiry_category="expired")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "nearest_credential_expiry_category")
        level, _ = classify_entra_change(change)
        assert level == "medium"

    def test_credential_added_is_medium(self):
        prev = [_application_record(password_credential_count=0)]
        new = [_application_record(password_credential_count=1)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "password_credential_count")
        level, reason = classify_entra_change(change)
        assert level == "medium"
        assert "secret" not in reason.lower() or "exposure" not in reason.lower()

    def test_credential_removed_is_low(self):
        prev = [_application_record(password_credential_count=1)]
        new = [_application_record(password_credential_count=0)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "password_credential_count")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_requested_permission_count_change_is_low(self):
        prev = [_application_record(requested_delegated_permission_count=1)]
        new = [_application_record(requested_delegated_permission_count=2)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "requested_delegated_permission_count")
        level, reason = classify_entra_change(change)
        assert level == "low"
        assert "requested" in reason.lower()


# ════════════════════════════════════════════════════════════════════════════
# Service principal changes
# ════════════════════════════════════════════════════════════════════════════


class TestServicePrincipalChanges:
    def test_disabled_to_enabled_is_medium(self):
        prev = [_sp_record(account_enabled=False)]
        new = [_sp_record(account_enabled=True)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "account_enabled")
        level, reason = classify_entra_change(change)
        assert level == "medium"
        assert "restored" in reason.lower()

    def test_enabled_to_disabled_is_low(self):
        prev = [_sp_record(account_enabled=True)]
        new = [_sp_record(account_enabled=False)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "account_enabled")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_assignment_required_removed_is_medium(self):
        prev = [_sp_record(assignment_required=True)]
        new = [_sp_record(assignment_required=False)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "assignment_required")
        level, reason = classify_entra_change(change)
        assert level == "medium"
        assert "no longer requires" in reason.lower()

    def test_assignment_required_added_is_low(self):
        prev = [_sp_record(assignment_required=False)]
        new = [_sp_record(assignment_required=True)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "assignment_required")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_sp_added_is_low(self):
        changes = compute_diff(_snap([]), _snap([_sp_record()]))
        change = next(c for c in changes if c["change_type"] == "added")
        level, _ = classify_entra_change(change)
        assert level == "low"


# ════════════════════════════════════════════════════════════════════════════
# User / group assignment changes
# ════════════════════════════════════════════════════════════════════════════


class TestAssignmentChanges:
    def test_ordinary_user_assignment_added_is_low(self):
        changes = compute_diff(_snap([]), _snap([_user_assignment_record()]))
        change = next(c for c in changes if c["change_type"] == "added")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_guest_user_assignment_is_medium(self):
        rec = _user_assignment_record(user_type_category="Guest")
        changes = compute_diff(_snap([]), _snap([rec]))
        change = next(c for c in changes if c["change_type"] == "added")
        level, _ = classify_entra_change(change)
        assert level == "medium"

    def test_disabled_user_assignment_is_low(self):
        rec = _user_assignment_record(account_enabled_category="disabled")
        changes = compute_diff(_snap([]), _snap([rec]))
        change = next(c for c in changes if c["change_type"] == "added")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_user_assignment_removed_is_low(self):
        changes = compute_diff(_snap([_user_assignment_record()]), _snap([]))
        change = next(c for c in changes if c["change_type"] == "removed")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_group_assignment_added_is_medium(self):
        changes = compute_diff(_snap([]), _snap([_group_assignment_record()]))
        change = next(c for c in changes if c["change_type"] == "added")
        level, _ = classify_entra_change(change)
        assert level == "medium"

    def test_dynamic_group_assignment_is_medium(self):
        rec = _group_assignment_record(dynamic_group=True)
        changes = compute_diff(_snap([]), _snap([rec]))
        change = next(c for c in changes if c["change_type"] == "added")
        level, reason = classify_entra_change(change)
        assert level == "medium"
        assert "automatically" in reason.lower() or "dynamic" in reason.lower()

    def test_role_assignable_group_assignment_is_medium(self):
        rec = _group_assignment_record(role_assignable_group=True)
        changes = compute_diff(_snap([]), _snap([rec]))
        change = next(c for c in changes if c["change_type"] == "added")
        level, _ = classify_entra_change(change)
        assert level == "medium"

    def test_group_assignment_removed_is_low(self):
        changes = compute_diff(_snap([_group_assignment_record()]), _snap([]))
        change = next(c for c in changes if c["change_type"] == "removed")
        level, _ = classify_entra_change(change)
        assert level == "low"


# ════════════════════════════════════════════════════════════════════════════
# Service-principal application-permission changes
# ════════════════════════════════════════════════════════════════════════════


class TestServicePrincipalPermissionChanges:
    def test_high_risk_permission_added_is_high(self):
        rec = _sp_assignment_record(app_role_category="Directory.ReadWrite.All", app_role_risk_category="high_risk")
        changes = compute_diff(_snap([]), _snap([rec]))
        change = next(c for c in changes if c["change_type"] == "added")
        level, reason = classify_entra_change(change)
        assert level == "high"
        assert "high-risk" in reason.lower()

    def test_unknown_permission_added_is_medium_not_safe(self):
        rec = _sp_assignment_record(app_role_category=None, app_role_risk_category="unknown")
        changes = compute_diff(_snap([]), _snap([rec]))
        change = next(c for c in changes if c["change_type"] == "added")
        level, reason = classify_entra_change(change)
        assert level == "medium"
        assert "review" in reason.lower()

    def test_ordinary_permission_added_is_medium(self):
        changes = compute_diff(_snap([]), _snap([_sp_assignment_record()]))
        change = next(c for c in changes if c["change_type"] == "added")
        level, _ = classify_entra_change(change)
        assert level == "medium"

    def test_permission_removed_is_low(self):
        changes = compute_diff(_snap([_sp_assignment_record()]), _snap([]))
        change = next(c for c in changes if c["change_type"] == "removed")
        level, _ = classify_entra_change(change)
        assert level == "low"


# ════════════════════════════════════════════════════════════════════════════
# OAuth2 delegated consent changes
# ════════════════════════════════════════════════════════════════════════════


class TestOAuth2GrantChanges:
    def test_all_principals_consent_added_is_medium(self):
        rec = _grant_record(consent_type_category="AllPrincipals", principal_id=None)
        changes = compute_diff(_snap([]), _snap([rec]))
        change = next(c for c in changes if c["change_type"] == "added")
        level, reason = classify_entra_change(change)
        assert level == "medium"
        assert "tenant-wide" in reason.lower() or "admin" in reason.lower()

    def test_principal_scoped_consent_added_is_low(self):
        changes = compute_diff(_snap([]), _snap([_grant_record()]))
        change = next(c for c in changes if c["change_type"] == "added")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_high_risk_scope_grant_is_high(self):
        rec = _grant_record(high_risk_scope_present=True, scopes=["Directory.ReadWrite.All"])
        changes = compute_diff(_snap([]), _snap([rec]))
        change = next(c for c in changes if c["change_type"] == "added")
        level, reason = classify_entra_change(change)
        assert level == "high"
        assert "compromise" not in reason.lower()
        assert "phishing" not in reason.lower()

    def test_grant_removed_is_low(self):
        changes = compute_diff(_snap([_grant_record()]), _snap([]))
        change = next(c for c in changes if c["change_type"] == "removed")
        level, _ = classify_entra_change(change)
        assert level == "low"

    def test_high_risk_all_principals_grant_is_high(self):
        rec = _grant_record(consent_type_category="AllPrincipals", principal_id=None, high_risk_scope_present=True)
        changes = compute_diff(_snap([]), _snap([rec]))
        change = next(c for c in changes if c["change_type"] == "added")
        level, _ = classify_entra_change(change)
        assert level == "high"


# ════════════════════════════════════════════════════════════════════════════
# Provider metadata / ignored timestamps
# ════════════════════════════════════════════════════════════════════════════


class TestProviderMetadataAndTimestamps:
    def test_application_change_has_context(self):
        prev = [_application_record(display_name="Old")]
        new = [_application_record(display_name="New")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "display_name")
        pm = change["provider_metadata"]
        assert pm["tenant_id"] == _TENANT
        assert pm["object_id"] == "a1"
        assert pm["app_id"] == "client-a1"
        assert "client_secret" not in pm
        assert "access_token" not in pm

    def test_service_principal_change_has_context(self):
        prev = [_sp_record(display_name="Old")]
        new = [_sp_record(display_name="New")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "display_name")
        pm = change["provider_metadata"]
        assert pm["service_principal_id"] == "sp1"
        assert pm["app_id"] == "client-sp1"

    def test_assignment_change_has_context(self):
        rec = _user_assignment_record()
        changes = compute_diff(_snap([]), _snap([rec]))
        change = next(c for c in changes if c["change_type"] == "added")
        pm = change["provider_metadata"]
        assert pm["service_principal_id"] == "sp1"
        assert pm["app_role_category"] == "Reader"

    def test_sp_permission_change_has_context(self):
        rec = _sp_assignment_record()
        changes = compute_diff(_snap([]), _snap([rec]))
        change = next(c for c in changes if c["change_type"] == "added")
        pm = change["provider_metadata"]
        assert pm["resource_name"] == "Resource SP"
        assert pm["principal_name"] == "Automation SP"
        assert pm["app_role_risk_category"] == "ordinary"

    def test_grant_change_has_context(self):
        rec = _grant_record()
        changes = compute_diff(_snap([]), _snap([rec]))
        change = next(c for c in changes if c["change_type"] == "added")
        pm = change["provider_metadata"]
        assert pm["client_name"] == "Client SP"
        assert pm["resource_name"] == "Resource SP"
        assert pm["consent_type_category"] == "Principal"

    def test_unknown_entra_record_type_fails_safe(self):
        change = {
            "change_type": "modified",
            "provider_metadata": {"record_type": "entra_future_thing"},
        }
        level, _ = classify_entra_change(change)
        assert level == "low"
