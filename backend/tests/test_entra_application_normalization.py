"""Microsoft Entra ID application security normalization tests (Entra
message 3 of 8).

Covers ``EntraConnector._normalize_application`` /
``_normalize_service_principal`` / ``_normalize_app_user_assignment`` /
``_normalize_app_group_assignment`` / ``_normalize_sp_app_role_assignment``
/ ``_normalize_oauth2_permission_grant`` in isolation: sign-in audience
taxonomy, redirect posture, credential expiry, service-principal type
taxonomy, assignment-required tri-state, publisher/ownership posture,
requested-vs-granted permission separation, consent-type taxonomy, scope
parsing, permission risk categorization, unknown-state discipline, and the
sensitive-data exclusion boundary.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.connectors.entra import EntraConnector
from app.connectors.entra_schema import (
    APP_OWNER_ORG_EXTERNAL,
    APP_OWNER_ORG_TENANT_OWNED,
    APP_OWNER_ORG_UNKNOWN,
    CONSENT_TYPE_ALL_PRINCIPALS,
    CONSENT_TYPE_PRINCIPAL,
    CONSENT_TYPE_UNKNOWN,
    CREDENTIAL_EXPIRED,
    CREDENTIAL_EXPIRING_SOON,
    CREDENTIAL_FAR_FUTURE,
    CREDENTIAL_HEALTHY,
    CREDENTIAL_NO_CREDENTIALS,
    CREDENTIAL_UNKNOWN,
    MICROSOFT_GRAPH_APP_ID,
    PERMISSION_RISK_HIGH,
    PERMISSION_RISK_ORDINARY,
    PERMISSION_RISK_UNKNOWN,
    PUBLISHER_UNKNOWN,
    PUBLISHER_UNVERIFIED,
    PUBLISHER_VERIFIED,
    SIGN_IN_AUDIENCE_MULTI_TENANT,
    SIGN_IN_AUDIENCE_MULTI_TENANT_AND_PERSONAL,
    SIGN_IN_AUDIENCE_PERSONAL_ONLY_CATEGORY,
    SIGN_IN_AUDIENCE_SINGLE_TENANT,
    SIGN_IN_AUDIENCE_UNKNOWN,
    SP_TYPE_APPLICATION,
    SP_TYPE_MANAGED_IDENTITY,
    SP_TYPE_UNKNOWN,
    categorize_app_owner_organization,
    categorize_consent_type,
    categorize_nearest_credential_expiry,
    categorize_permission_risk,
    categorize_service_principal_type,
    categorize_sign_in_audience,
    categorize_verified_publisher,
    normalize_scopes,
    summarize_application_redirects,
    summarize_required_resource_access,
)

_TENANT = "id:t1"
_TENANT_GUID = "t1"


def _application(**overrides) -> dict:
    base = {
        "id": "a1",
        "appId": "client-a1",
        "displayName": "Test App",
        "signInAudience": "AzureADMyOrg",
        "web": {"redirectUris": []},
        "spa": {"redirectUris": []},
        "publicClient": {"redirectUris": []},
        "requiredResourceAccess": [],
        "passwordCredentials": [],
        "keyCredentials": [],
        "appRoles": [],
    }
    base.update(overrides)
    return base


def _service_principal(**overrides) -> dict:
    base = {
        "id": "sp1",
        "appId": "client-sp1",
        "displayName": "Test SP",
        "servicePrincipalType": "Application",
        "accountEnabled": True,
        "appRoleAssignmentRequired": False,
        "appOwnerOrganizationId": _TENANT_GUID,
        "verifiedPublisher": {},
        "passwordCredentials": [],
        "keyCredentials": [],
        "appRoles": [],
        "oauth2PermissionScopes": [],
    }
    base.update(overrides)
    return base


# ════════════════════════════════════════════════════════════════════════════
# Sign-in audience
# ════════════════════════════════════════════════════════════════════════════


class TestSignInAudience:
    @pytest.mark.parametrize("raw,expected", [
        ("AzureADMyOrg", SIGN_IN_AUDIENCE_SINGLE_TENANT),
        ("AzureADMultipleOrgs", SIGN_IN_AUDIENCE_MULTI_TENANT),
        ("AzureADandPersonalMicrosoftAccount", SIGN_IN_AUDIENCE_MULTI_TENANT_AND_PERSONAL),
        ("PersonalMicrosoftAccount", SIGN_IN_AUDIENCE_PERSONAL_ONLY_CATEGORY),
        (None, SIGN_IN_AUDIENCE_UNKNOWN),
        ("SomeFutureValue", SIGN_IN_AUDIENCE_UNKNOWN),
    ])
    def test_categorize_sign_in_audience(self, raw, expected):
        assert categorize_sign_in_audience(raw) == expected

    def test_multi_tenant_not_treated_as_malicious(self):
        # The categorizer itself carries no severity judgment — it's a
        # pure structural mapping. This just confirms it doesn't raise or
        # special-case multi-tenant into some "danger" sentinel string.
        assert categorize_sign_in_audience("AzureADMultipleOrgs") == SIGN_IN_AUDIENCE_MULTI_TENANT

    def test_full_normalization(self):
        rec = EntraConnector._normalize_application(_TENANT, _application(signInAudience="AzureADMultipleOrgs"))
        assert rec["sign_in_audience_category"] == SIGN_IN_AUDIENCE_MULTI_TENANT

    def test_unknown_audience_never_guessed(self):
        rec = EntraConnector._normalize_application(_TENANT, _application(signInAudience=None))
        assert rec["sign_in_audience_category"] == SIGN_IN_AUDIENCE_UNKNOWN


# ════════════════════════════════════════════════════════════════════════════
# Redirect posture
# ════════════════════════════════════════════════════════════════════════════


class TestRedirectPosture:
    def test_https_web_redirect(self):
        posture = summarize_application_redirects(["https://a.com/cb"], None, None)
        assert posture["web_redirect_count"] == 1
        assert posture["has_http_redirect"] is False
        assert posture["web_has_http_redirect"] is False

    def test_http_web_redirect(self):
        posture = summarize_application_redirects(["http://a.com/cb"], None, None)
        assert posture["has_http_redirect"] is True
        assert posture["web_has_http_redirect"] is True

    def test_localhost_redirect(self):
        posture = summarize_application_redirects(None, ["http://localhost:3000/cb"], None)
        assert posture["has_localhost_redirect"] is True

    def test_loopback_redirect(self):
        posture = summarize_application_redirects(None, None, ["http://127.0.0.1/cb"])
        assert posture["has_loopback_redirect"] is True

    def test_spa_redirect_counted_separately(self):
        posture = summarize_application_redirects(["https://a.com"], ["https://b.com"], None)
        assert posture["web_redirect_count"] == 1
        assert posture["spa_redirect_count"] == 1

    def test_public_client_redirect_counted(self):
        posture = summarize_application_redirects(None, None, ["myapp://cb"])
        assert posture["public_client_redirect_count"] == 1

    def test_custom_scheme_redirect(self):
        posture = summarize_application_redirects(None, None, ["myapp://cb"])
        assert posture["has_custom_scheme_redirect"] is True

    def test_http_introduced(self):
        before = summarize_application_redirects(["https://a.com"], None, None)
        after = summarize_application_redirects(["https://a.com", "http://a.com"], None, None)
        assert before["has_http_redirect"] is False
        assert after["has_http_redirect"] is True

    def test_http_removed(self):
        before = summarize_application_redirects(["http://a.com"], None, None)
        after = summarize_application_redirects([], None, None)
        assert before["has_http_redirect"] is True
        assert after["has_http_redirect"] is False

    def test_multiple_redirects_counted(self):
        posture = summarize_application_redirects(["https://a.com", "https://b.com", "http://c.com"], None, None)
        assert posture["web_redirect_count"] == 3

    def test_raw_uri_never_stored(self):
        rec = EntraConnector._normalize_application(
            _TENANT, _application(web={"redirectUris": ["https://secret-internal-host.example/cb?token=abc"]}),
        )
        assert "secret-internal-host" not in str(rec)
        assert "token=abc" not in str(rec)

    def test_wildcard_redirect_detected(self):
        posture = summarize_application_redirects(["https://*.example.com/cb"], None, None)
        assert posture["has_wildcard_redirect"] is True

    def test_no_redirects_all_zero(self):
        posture = summarize_application_redirects(None, None, None)
        assert posture["web_redirect_count"] == 0
        assert posture["has_http_redirect"] is False


# ════════════════════════════════════════════════════════════════════════════
# Credential metadata / expiry
# ════════════════════════════════════════════════════════════════════════════


class TestCredentialExpiry:
    def test_no_credentials(self):
        assert categorize_nearest_credential_expiry([]) == CREDENTIAL_NO_CREDENTIALS

    def test_one_healthy_password_credential(self):
        future = (datetime.now(timezone.utc) + timedelta(days=180)).isoformat().replace("+00:00", "Z")
        result = categorize_nearest_credential_expiry([{"endDateTime": future}])
        assert result == CREDENTIAL_HEALTHY

    def test_one_key_credential_far_future(self):
        future = (datetime.now(timezone.utc) + timedelta(days=800)).isoformat().replace("+00:00", "Z")
        assert categorize_nearest_credential_expiry([{"endDateTime": future}]) == CREDENTIAL_FAR_FUTURE

    def test_expired_credential(self):
        past = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat().replace("+00:00", "Z")
        assert categorize_nearest_credential_expiry([{"endDateTime": past}]) == CREDENTIAL_EXPIRED

    def test_expiring_soon_credential(self):
        soon = (datetime.now(timezone.utc) + timedelta(days=10)).isoformat().replace("+00:00", "Z")
        assert categorize_nearest_credential_expiry([{"endDateTime": soon}]) == CREDENTIAL_EXPIRING_SOON

    def test_unparseable_enddatetime_unknown(self):
        assert categorize_nearest_credential_expiry([{"endDateTime": "not-a-date"}]) == CREDENTIAL_UNKNOWN

    def test_nearest_expiry_wins_across_multiple_credentials(self):
        soon = (datetime.now(timezone.utc) + timedelta(days=5)).isoformat().replace("+00:00", "Z")
        far = (datetime.now(timezone.utc) + timedelta(days=800)).isoformat().replace("+00:00", "Z")
        result = categorize_nearest_credential_expiry([{"endDateTime": far}, {"endDateTime": soon}])
        assert result == CREDENTIAL_EXPIRING_SOON

    def test_secret_text_never_read(self):
        rec = EntraConnector._normalize_application(
            _TENANT, _application(passwordCredentials=[{"secretText": "super-secret-value", "endDateTime": "2099-01-01T00:00:00Z"}]),
        )
        assert "super-secret-value" not in str(rec)
        assert "secretText" not in rec

    def test_key_bytes_never_read(self):
        rec = EntraConnector._normalize_application(
            _TENANT, _application(keyCredentials=[{"key": "base64keybytes==", "endDateTime": "2099-01-01T00:00:00Z"}]),
        )
        assert "base64keybytes" not in str(rec)
        assert "key" not in rec

    def test_credential_counts_tracked(self):
        rec = EntraConnector._normalize_application(
            _TENANT, _application(
                passwordCredentials=[{"endDateTime": "2099-01-01T00:00:00Z"}],
                keyCredentials=[{"endDateTime": "2099-01-01T00:00:00Z"}, {"endDateTime": "2099-01-01T00:00:00Z"}],
            ),
        )
        assert rec["password_credential_count"] == 1
        assert rec["key_credential_count"] == 2


# ════════════════════════════════════════════════════════════════════════════
# Service principal taxonomy
# ════════════════════════════════════════════════════════════════════════════


class TestServicePrincipalType:
    @pytest.mark.parametrize("raw,expected", [
        ("Application", SP_TYPE_APPLICATION),
        ("ManagedIdentity", SP_TYPE_MANAGED_IDENTITY),
        (None, SP_TYPE_UNKNOWN),
        ("SomeFutureType", SP_TYPE_UNKNOWN),
    ])
    def test_categorize_service_principal_type(self, raw, expected):
        assert categorize_service_principal_type(raw) == expected

    def test_managed_identity_not_treated_as_ordinary_app(self):
        rec = EntraConnector._normalize_service_principal(
            _TENANT, _service_principal(servicePrincipalType="ManagedIdentity"), _TENANT_GUID,
        )
        assert rec["service_principal_type_category"] == SP_TYPE_MANAGED_IDENTITY

    def test_account_enabled_tristate(self):
        for raw, expected in [(True, True), (False, False), (None, None)]:
            rec = EntraConnector._normalize_service_principal(_TENANT, _service_principal(accountEnabled=raw), _TENANT_GUID)
            assert rec["account_enabled"] is expected

    def test_assignment_required_tristate(self):
        for raw, expected in [(True, True), (False, False), (None, None)]:
            rec = EntraConnector._normalize_service_principal(_TENANT, _service_principal(appRoleAssignmentRequired=raw), _TENANT_GUID)
            assert rec["assignment_required"] is expected

    def test_missing_assignment_required_is_none_not_false(self):
        sp = _service_principal()
        del sp["appRoleAssignmentRequired"]
        rec = EntraConnector._normalize_service_principal(_TENANT, sp, _TENANT_GUID)
        assert rec["assignment_required"] is None

    def test_tenant_owned(self):
        assert categorize_app_owner_organization(_TENANT_GUID, _TENANT_GUID) == APP_OWNER_ORG_TENANT_OWNED

    def test_external_tenant(self):
        assert categorize_app_owner_organization("different-tenant-guid", _TENANT_GUID) == APP_OWNER_ORG_EXTERNAL

    def test_unknown_owner_organization(self):
        assert categorize_app_owner_organization(None, _TENANT_GUID) == APP_OWNER_ORG_UNKNOWN

    def test_verified_publisher(self):
        assert categorize_verified_publisher({"verifiedPublisherId": "123"}) == PUBLISHER_VERIFIED

    def test_unverified_publisher(self):
        assert categorize_verified_publisher({}) == PUBLISHER_UNVERIFIED

    def test_unknown_publisher_when_not_a_dict(self):
        assert categorize_verified_publisher(None) == PUBLISHER_UNKNOWN

    def test_microsoft_graph_resource_recognized(self):
        rec = EntraConnector._normalize_service_principal(_TENANT, _service_principal(appId=MICROSOFT_GRAPH_APP_ID), _TENANT_GUID)
        assert rec["is_microsoft_graph_resource"] is True

    def test_ordinary_app_not_microsoft_graph(self):
        rec = EntraConnector._normalize_service_principal(_TENANT, _service_principal(appId="some-other-app-id"), _TENANT_GUID)
        assert rec["is_microsoft_graph_resource"] is False

    def test_missing_sp_id_returns_none(self):
        assert EntraConnector._normalize_service_principal(_TENANT, {"appId": "x"}, _TENANT_GUID) is None


# ════════════════════════════════════════════════════════════════════════════
# Requested-vs-granted permission separation
# ════════════════════════════════════════════════════════════════════════════


class TestRequestedVsGranted:
    def test_requested_delegated_permission_counted(self):
        result = summarize_required_resource_access([
            {"resourceAppId": "x", "resourceAccess": [{"id": "a", "type": "Scope"}]},
        ])
        assert result["requested_delegated_permission_count"] == 1
        assert result["requested_application_permission_count"] == 0

    def test_requested_application_permission_counted(self):
        result = summarize_required_resource_access([
            {"resourceAppId": "x", "resourceAccess": [{"id": "a", "type": "Role"}]},
        ])
        assert result["requested_application_permission_count"] == 1

    def test_requested_high_risk_permission_does_not_imply_grant(self):
        """Requested permissions are never equated with granted access —
        this is a structural fact confirmed by the SEPARATE record types:
        entra_application (requested) vs entra_oauth2_permission_grant /
        entra_service_principal_app_role_assignment (granted)."""
        rec = EntraConnector._normalize_application(
            _TENANT, _application(requiredResourceAccess=[
                {"resourceAppId": MICROSOFT_GRAPH_APP_ID, "resourceAccess": [{"id": "x", "type": "Role"}]},
            ]),
        )
        assert "granted" not in rec
        assert rec["requested_application_permission_count"] == 1

    def test_raw_required_resource_access_never_stored(self):
        rec = EntraConnector._normalize_application(
            _TENANT, _application(requiredResourceAccess=[
                {"resourceAppId": "secret-resource-guid-1234", "resourceAccess": [{"id": "perm-guid-5678", "type": "Role"}]},
            ]),
        )
        assert "secret-resource-guid-1234" not in str(rec)
        assert "perm-guid-5678" not in str(rec)

    def test_resource_api_count(self):
        result = summarize_required_resource_access([
            {"resourceAppId": "x", "resourceAccess": []},
            {"resourceAppId": "y", "resourceAccess": []},
        ])
        assert result["requested_resource_api_count"] == 2

    def test_non_list_input_returns_zeros(self):
        result = summarize_required_resource_access(None)
        assert result["requested_resource_api_count"] == 0


# ════════════════════════════════════════════════════════════════════════════
# Consent type / scope parsing / permission risk
# ════════════════════════════════════════════════════════════════════════════


class TestConsentAndScopes:
    @pytest.mark.parametrize("raw,expected", [
        ("AllPrincipals", CONSENT_TYPE_ALL_PRINCIPALS),
        ("Principal", CONSENT_TYPE_PRINCIPAL),
        (None, CONSENT_TYPE_UNKNOWN),
        ("SomeFutureType", CONSENT_TYPE_UNKNOWN),
    ])
    def test_categorize_consent_type(self, raw, expected):
        assert categorize_consent_type(raw) == expected

    def test_scope_normalization_dedup_sort(self):
        assert normalize_scopes("User.Read Mail.Read User.Read") == ["Mail.Read", "User.Read"]

    def test_scope_normalization_order_independent(self):
        a = normalize_scopes("Mail.Read User.Read")
        b = normalize_scopes("User.Read Mail.Read")
        assert a == b

    def test_empty_scope_string(self):
        assert normalize_scopes("") == []
        assert normalize_scopes(None) == []

    def test_high_risk_scope_recognized(self):
        assert categorize_permission_risk("Directory.ReadWrite.All") == PERMISSION_RISK_HIGH

    def test_ordinary_scope(self):
        assert categorize_permission_risk("User.Read") == PERMISSION_RISK_ORDINARY

    def test_unresolved_permission_value_never_downgraded_to_ordinary(self):
        """An unresolved permission (no value string at all — e.g. an
        appRoleId that couldn't be looked up) stays unknown. A RESOLVED
        value string simply not on the curated high-risk list is
        legitimately "ordinary" — that's a different, correctly-handled
        case (see test_known_app_role_resolves_to_value_and_risk /
        test_unknown_app_role_id_stays_unknown)."""
        result = categorize_permission_risk(None)
        assert result == PERMISSION_RISK_UNKNOWN
        assert result != PERMISSION_RISK_ORDINARY

    def test_no_principal_for_all_principals_consent(self):
        sp_by_id = {"sp1": {"display_name": "Client"}, "sp2": {"display_name": "Resource"}}
        rec = EntraConnector._normalize_oauth2_permission_grant(
            _TENANT, {"id": "g1", "clientId": "sp1", "resourceId": "sp2", "consentType": "AllPrincipals", "scope": "User.Read", "principalId": "should-be-ignored"},
            sp_by_id,
        )
        assert rec["principal_id"] is None

    def test_principal_scoped_consent_has_principal_id(self):
        sp_by_id = {"sp1": {"display_name": "Client"}, "sp2": {"display_name": "Resource"}}
        rec = EntraConnector._normalize_oauth2_permission_grant(
            _TENANT, {"id": "g1", "clientId": "sp1", "resourceId": "sp2", "consentType": "Principal", "scope": "User.Read", "principalId": "u1"},
            sp_by_id,
        )
        assert rec["principal_id"] == "u1"

    def test_duplicate_scopes_deduped_in_grant(self):
        sp_by_id = {}
        rec = EntraConnector._normalize_oauth2_permission_grant(
            _TENANT, {"id": "g1", "clientId": "sp1", "resourceId": "sp2", "consentType": "AllPrincipals", "scope": "User.Read User.Read Mail.Read"},
            sp_by_id,
        )
        assert rec["scope_count"] == 2

    def test_high_risk_scope_flag_set(self):
        sp_by_id = {}
        rec = EntraConnector._normalize_oauth2_permission_grant(
            _TENANT, {"id": "g1", "clientId": "sp1", "resourceId": "sp2", "consentType": "AllPrincipals", "scope": "Directory.ReadWrite.All"},
            sp_by_id,
        )
        assert rec["high_risk_scope_present"] is True

    def test_missing_grant_id_returns_none(self):
        assert EntraConnector._normalize_oauth2_permission_grant(_TENANT, {"clientId": "sp1"}, {}) is None

    def test_raw_scope_string_not_preserved_as_opaque_blob(self):
        sp_by_id = {}
        rec = EntraConnector._normalize_oauth2_permission_grant(
            _TENANT, {"id": "g1", "clientId": "sp1", "resourceId": "sp2", "consentType": "AllPrincipals", "scope": "User.Read Mail.Read Files.Read"},
            sp_by_id,
        )
        assert rec["scopes"] == ["Files.Read", "Mail.Read", "User.Read"]
        assert isinstance(rec["scopes"], list)


# ════════════════════════════════════════════════════════════════════════════
# Assignment normalization / principal branching
# ════════════════════════════════════════════════════════════════════════════


class TestAssignmentNormalization:
    def test_user_assignment_resolves_local_user_context(self):
        sp_record = EntraConnector._normalize_service_principal(_TENANT, _service_principal(), _TENANT_GUID)
        user_record = {"user_principal_name": "alice@example.com", "account_enabled_category": "enabled", "user_type_category": "Member"}
        rec = EntraConnector._normalize_app_user_assignment(
            _TENANT, sp_record, user_record, {"id": "assign1", "principalId": "u1", "appRoleId": "role1"},
        )
        assert rec["user_principal_name"] == "alice@example.com"
        assert rec["assignment_type"] == "user"

    def test_group_assignment_resolves_local_group_context(self):
        sp_record = EntraConnector._normalize_service_principal(_TENANT, _service_principal(), _TENANT_GUID)
        group_record = {"display_name": "Engineering", "group_type_category": "security", "dynamic_membership": False, "role_assignable": False}
        rec = EntraConnector._normalize_app_group_assignment(
            _TENANT, sp_record, group_record, {"id": "assign1", "principalId": "g1", "appRoleId": "role1"},
        )
        assert rec["group_name"] == "Engineering"
        assert rec["assignment_type"] == "group"

    def test_sp_assignment_resolves_principal_sp_context(self):
        resource_sp = EntraConnector._normalize_service_principal(_TENANT, _service_principal(id="sp1"), _TENANT_GUID)
        principal_sp = EntraConnector._normalize_service_principal(_TENANT, _service_principal(id="sp2", displayName="Automation SP"), _TENANT_GUID)
        rec = EntraConnector._normalize_sp_app_role_assignment(
            _TENANT, resource_sp, principal_sp, {"id": "assign1", "principalId": "sp2", "appRoleId": "role1"},
        )
        assert rec["principal_name"] == "Automation SP"
        assert rec["assignment_type"] == "service_principal"

    def test_default_app_role_id_resolves_to_default(self):
        roles_by_id = {}
        value, risk = EntraConnector._resolve_app_role(roles_by_id, "00000000-0000-0000-0000-000000000000")
        assert value == "(default)"

    def test_unknown_app_role_id_stays_unknown(self):
        value, risk = EntraConnector._resolve_app_role({}, "not-in-index")
        assert value is None
        assert risk == PERMISSION_RISK_UNKNOWN

    def test_known_app_role_resolves_to_value_and_risk(self):
        roles_by_id = {"role1": {"id": "role1", "value": "Directory.ReadWrite.All"}}
        value, risk = EntraConnector._resolve_app_role(roles_by_id, "role1")
        assert value == "Directory.ReadWrite.All"
        assert risk == PERMISSION_RISK_HIGH

    def test_missing_principal_id_returns_none(self):
        sp_record = EntraConnector._normalize_service_principal(_TENANT, _service_principal(), _TENANT_GUID)
        assert EntraConnector._normalize_app_user_assignment(_TENANT, sp_record, None, {"id": "x"}) is None

    def test_assignment_never_duplicates_full_sp_record(self):
        sp_record = EntraConnector._normalize_service_principal(_TENANT, _service_principal(), _TENANT_GUID)
        rec = EntraConnector._normalize_app_user_assignment(
            _TENANT, sp_record, None, {"id": "assign1", "principalId": "u1", "appRoleId": "role1"},
        )
        assert "app_role_count" not in rec
        assert "oauth2_permission_scope_count" not in rec
