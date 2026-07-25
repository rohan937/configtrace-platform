"""Okta application normalization tests (Okta message 3 of 8).

Covers ``OktaConnector._normalize_application`` /
``_normalize_app_user_assignment`` / ``_normalize_app_group_assignment`` in
isolation: application status tri-state, sign-on mode / protocol taxonomy,
OIDC redirect categorization, SAML posture, unknown-value discipline, and
the sensitive-data exclusion boundary.
"""

from __future__ import annotations

import pytest

from app.connectors.okta import OktaConnector
from app.connectors.okta_schema import (
    APP_STATUS_ACTIVE,
    APP_STATUS_INACTIVE,
    APP_STATUS_UNKNOWN,
    APP_TYPE_UNKNOWN,
    APP_TYPE_WEB,
    PROTOCOL_CATEGORY_OIDC_OAUTH,
    PROTOCOL_CATEGORY_OTHER,
    PROTOCOL_CATEGORY_SAML,
    PROTOCOL_CATEGORY_UNKNOWN,
    PROTOCOL_CATEGORY_WS_FEDERATION,
    SIGN_ON_MODE_AUTO_LOGIN,
    SIGN_ON_MODE_BASIC_AUTH,
    SIGN_ON_MODE_BOOKMARK,
    SIGN_ON_MODE_OAUTH_2_0,
    SIGN_ON_MODE_OPENID_CONNECT,
    SIGN_ON_MODE_SAML_2_0,
    SIGN_ON_MODE_SWA,
    SIGN_ON_MODE_UNKNOWN,
    SIGN_ON_MODE_WS_FEDERATION,
    TOKEN_AUTH_METHOD_NONE,
    TOKEN_AUTH_METHOD_UNKNOWN,
    categorize_app_status,
    categorize_app_type,
    categorize_assignment_scope,
    categorize_redirect_uris,
    categorize_sign_on_mode,
    categorize_token_auth_method,
    protocol_category_for_sign_on_mode,
)

_TENANT = "id:t1"


def _app(app_id: str = "app1", **overrides) -> dict:
    base = {
        "id": app_id,
        "label": "My App",
        "status": "ACTIVE",
        "signOnMode": "OPENID_CONNECT",
        "settings": {"oauthClient": {
            "redirect_uris": ["https://app.example.com/cb"],
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "application_type": "web",
            "token_endpoint_auth_method": "client_secret_basic",
        }},
    }
    base.update(overrides)
    return base


def _saml_app(app_id: str = "app1", **overrides) -> dict:
    base = {
        "id": app_id,
        "label": "My SAML App",
        "status": "ACTIVE",
        "signOnMode": "SAML_2_0",
        "settings": {"signOn": {
            "destination": "https://sp.example.com/acs",
            "audience": "https://sp.example.com",
            "responseSigned": True,
            "assertionSigned": True,
            "signatureAlgorithm": "RSA_SHA256",
            "digestAlgorithm": "SHA256",
            "assertionEncrypted": False,
        }},
    }
    base.update(overrides)
    return base


# ════════════════════════════════════════════════════════════════════════════
# Application status
# ════════════════════════════════════════════════════════════════════════════


class TestApplicationStatus:
    def test_active(self):
        assert categorize_app_status("ACTIVE") == APP_STATUS_ACTIVE

    def test_inactive(self):
        assert categorize_app_status("INACTIVE") == APP_STATUS_INACTIVE

    def test_unknown_status_string(self):
        assert categorize_app_status("SOME_FUTURE_STATUS") == APP_STATUS_UNKNOWN

    def test_none_status(self):
        assert categorize_app_status(None) == APP_STATUS_UNKNOWN

    def test_non_string_status(self):
        assert categorize_app_status(12345) == APP_STATUS_UNKNOWN

    def test_unknown_status_not_coerced_to_inactive(self):
        rec = OktaConnector._normalize_application(
            _TENANT, _app(status="SOME_FUTURE_STATUS"), user_assignment_count=0, group_assignment_count=0,
        )
        assert rec["status"] == APP_STATUS_UNKNOWN
        assert rec["status"] != APP_STATUS_INACTIVE
        assert rec["active"] is False

    def test_active_flag_true_only_for_active(self):
        active_rec = OktaConnector._normalize_application(
            _TENANT, _app(status="ACTIVE"), user_assignment_count=0, group_assignment_count=0,
        )
        inactive_rec = OktaConnector._normalize_application(
            _TENANT, _app(status="INACTIVE"), user_assignment_count=0, group_assignment_count=0,
        )
        assert active_rec["active"] is True
        assert inactive_rec["active"] is False


# ════════════════════════════════════════════════════════════════════════════
# Sign-on mode / protocol taxonomy
# ════════════════════════════════════════════════════════════════════════════


class TestSignOnModeTaxonomy:
    @pytest.mark.parametrize("raw_mode,expected", [
        ("SAML_2_0", SIGN_ON_MODE_SAML_2_0),
        ("OPENID_CONNECT", SIGN_ON_MODE_OPENID_CONNECT),
        ("OAUTH_2_0", SIGN_ON_MODE_OAUTH_2_0),
        ("SWA", SIGN_ON_MODE_SWA),
        ("AUTO_LOGIN", SIGN_ON_MODE_AUTO_LOGIN),
        ("BASIC_AUTH", SIGN_ON_MODE_BASIC_AUTH),
        ("WS_FEDERATION", SIGN_ON_MODE_WS_FEDERATION),
        ("BOOKMARK", SIGN_ON_MODE_BOOKMARK),
    ])
    def test_every_known_mode(self, raw_mode, expected):
        assert categorize_sign_on_mode(raw_mode) == expected

    def test_unknown_sign_on_mode(self):
        assert categorize_sign_on_mode("SOME_FUTURE_MODE") == SIGN_ON_MODE_UNKNOWN

    def test_none_sign_on_mode(self):
        assert categorize_sign_on_mode(None) == SIGN_ON_MODE_UNKNOWN

    def test_protocol_category_saml(self):
        assert protocol_category_for_sign_on_mode(SIGN_ON_MODE_SAML_2_0) == PROTOCOL_CATEGORY_SAML

    def test_protocol_category_oidc(self):
        assert protocol_category_for_sign_on_mode(SIGN_ON_MODE_OPENID_CONNECT) == PROTOCOL_CATEGORY_OIDC_OAUTH

    def test_protocol_category_oauth(self):
        assert protocol_category_for_sign_on_mode(SIGN_ON_MODE_OAUTH_2_0) == PROTOCOL_CATEGORY_OIDC_OAUTH

    def test_protocol_category_ws_federation(self):
        assert protocol_category_for_sign_on_mode(SIGN_ON_MODE_WS_FEDERATION) == PROTOCOL_CATEGORY_WS_FEDERATION

    def test_protocol_category_other_for_swa_bookmark(self):
        assert protocol_category_for_sign_on_mode(SIGN_ON_MODE_SWA) == PROTOCOL_CATEGORY_OTHER
        assert protocol_category_for_sign_on_mode(SIGN_ON_MODE_BOOKMARK) == PROTOCOL_CATEGORY_OTHER

    def test_protocol_category_unknown_never_becomes_other(self):
        assert protocol_category_for_sign_on_mode(SIGN_ON_MODE_UNKNOWN) == PROTOCOL_CATEGORY_UNKNOWN


class TestApplicationTaxonomyFullNormalization:
    def test_saml_app(self):
        rec = OktaConnector._normalize_application(
            _TENANT, _saml_app(), user_assignment_count=0, group_assignment_count=0,
        )
        assert rec["sign_on_mode"] == SIGN_ON_MODE_SAML_2_0
        assert rec["protocol_category"] == PROTOCOL_CATEGORY_SAML

    def test_oidc_app(self):
        rec = OktaConnector._normalize_application(
            _TENANT, _app(signOnMode="OPENID_CONNECT"), user_assignment_count=0, group_assignment_count=0,
        )
        assert rec["protocol_category"] == PROTOCOL_CATEGORY_OIDC_OAUTH

    def test_swa_app(self):
        rec = OktaConnector._normalize_application(
            _TENANT, _app(signOnMode="SWA", settings={}), user_assignment_count=0, group_assignment_count=0,
        )
        assert rec["sign_on_mode"] == SIGN_ON_MODE_SWA
        assert rec["protocol_category"] == PROTOCOL_CATEGORY_OTHER

    def test_ws_fed_app(self):
        rec = OktaConnector._normalize_application(
            _TENANT, _app(signOnMode="WS_FEDERATION", settings={}), user_assignment_count=0, group_assignment_count=0,
        )
        assert rec["protocol_category"] == PROTOCOL_CATEGORY_WS_FEDERATION

    def test_bookmark_app(self):
        rec = OktaConnector._normalize_application(
            _TENANT, _app(signOnMode="BOOKMARK", settings={}), user_assignment_count=0, group_assignment_count=0,
        )
        assert rec["sign_on_mode"] == SIGN_ON_MODE_BOOKMARK

    def test_unknown_sign_on_mode_app(self):
        rec = OktaConnector._normalize_application(
            _TENANT, _app(signOnMode="SOMETHING_NEW", settings={}), user_assignment_count=0, group_assignment_count=0,
        )
        assert rec["sign_on_mode"] == SIGN_ON_MODE_UNKNOWN
        assert rec["protocol_category"] == PROTOCOL_CATEGORY_UNKNOWN
        # Unknown mode must never silently fall back to a guessed OIDC/SAML shape.
        assert "redirect_count" not in rec
        assert "saml_destination_configured" not in rec


# ════════════════════════════════════════════════════════════════════════════
# Stable identity / label
# ════════════════════════════════════════════════════════════════════════════


class TestApplicationIdentity:
    def test_missing_app_id_returns_none(self):
        assert OktaConnector._normalize_application(
            _TENANT, {"status": "ACTIVE"}, user_assignment_count=0, group_assignment_count=0,
        ) is None

    def test_label_extracted(self):
        rec = OktaConnector._normalize_application(
            _TENANT, _app(label="Salesforce"), user_assignment_count=0, group_assignment_count=0,
        )
        assert rec["label"] == "Salesforce"


# ════════════════════════════════════════════════════════════════════════════
# OIDC redirect categorization
# ════════════════════════════════════════════════════════════════════════════


class TestRedirectCategorization:
    def test_https_redirect(self):
        r = categorize_redirect_uris(["https://app.example.com/cb"])
        assert r["https_redirect_count"] == 1
        assert r["http_redirect_count"] == 0

    def test_http_redirect(self):
        r = categorize_redirect_uris(["http://app.example.com/cb"])
        assert r["http_redirect_count"] == 1

    def test_localhost_redirect(self):
        r = categorize_redirect_uris(["http://localhost:3000/cb"])
        assert r["localhost_redirect_count"] == 1

    def test_loopback_redirect(self):
        r = categorize_redirect_uris(["http://127.0.0.1/cb"])
        assert r["loopback_redirect_count"] == 1

    def test_custom_scheme(self):
        r = categorize_redirect_uris(["myapp://cb"])
        assert r["custom_scheme_redirect_count"] == 1

    def test_wildcard_redirect(self):
        r = categorize_redirect_uris(["https://*.example.com/cb"])
        assert r["wildcard_redirect_present"] is True

    def test_multiple_redirects(self):
        r = categorize_redirect_uris([
            "https://a.example.com/cb", "https://b.example.com/cb", "http://localhost/cb",
        ])
        assert r["redirect_count"] == 3
        assert r["https_redirect_count"] == 2
        assert r["localhost_redirect_count"] == 1

    def test_empty_redirect_list(self):
        r = categorize_redirect_uris([])
        assert r["redirect_count"] == 0
        assert r["wildcard_redirect_present"] is False

    def test_redirect_collection_unknown_when_not_a_list(self):
        r = categorize_redirect_uris(None)
        assert r["redirect_count"] is None
        assert r["wildcard_redirect_present"] is None

    def test_no_wildcard_when_absent(self):
        r = categorize_redirect_uris(["https://app.example.com/cb"])
        assert r["wildcard_redirect_present"] is False

    def test_raw_uris_never_returned(self):
        r = categorize_redirect_uris(["https://secret-path.example.com/cb?token=abc"])
        assert "secret-path" not in str(r)
        assert "token=abc" not in str(r)


class TestAppTypeAndTokenAuthMethod:
    def test_app_type_web(self):
        assert categorize_app_type("web") == APP_TYPE_WEB

    def test_app_type_unknown(self):
        assert categorize_app_type("something_new") == APP_TYPE_UNKNOWN

    def test_token_auth_method_none(self):
        assert categorize_token_auth_method("none") == TOKEN_AUTH_METHOD_NONE

    def test_token_auth_method_unknown(self):
        assert categorize_token_auth_method("something_new") == TOKEN_AUTH_METHOD_UNKNOWN

    def test_unknown_token_auth_method_full_normalization(self):
        raw = _app()
        raw["settings"]["oauthClient"]["token_endpoint_auth_method"] = "something_new"
        rec = OktaConnector._normalize_application(_TENANT, raw, user_assignment_count=0, group_assignment_count=0)
        assert rec["token_endpoint_auth_method_category"] == TOKEN_AUTH_METHOD_UNKNOWN

    def test_grant_type_list_summarized(self):
        raw = _app()
        raw["settings"]["oauthClient"]["grant_types"] = ["refresh_token", "authorization_code"]
        rec = OktaConnector._normalize_application(_TENANT, raw, user_assignment_count=0, group_assignment_count=0)
        assert rec["grant_types_summary"] == "authorization_code,refresh_token"

    def test_response_types_summarized(self):
        raw = _app()
        raw["settings"]["oauthClient"]["response_types"] = ["token", "code"]
        rec = OktaConnector._normalize_application(_TENANT, raw, user_assignment_count=0, group_assignment_count=0)
        assert rec["response_types_summary"] == "code,token"


# ════════════════════════════════════════════════════════════════════════════
# SAML posture
# ════════════════════════════════════════════════════════════════════════════


class TestSamlPosture:
    def test_response_signing_enabled(self):
        rec = OktaConnector._normalize_application(_TENANT, _saml_app(), user_assignment_count=0, group_assignment_count=0)
        assert rec["saml_response_signed"] is True

    def test_assertion_signing_enabled(self):
        rec = OktaConnector._normalize_application(_TENANT, _saml_app(), user_assignment_count=0, group_assignment_count=0)
        assert rec["saml_assertion_signed"] is True

    def test_signing_posture_unknown_when_absent(self):
        raw = _saml_app(settings={"signOn": {}})
        rec = OktaConnector._normalize_application(_TENANT, raw, user_assignment_count=0, group_assignment_count=0)
        assert rec["saml_response_signed"] is None
        assert rec["saml_assertion_signed"] is None

    def test_encryption_enabled(self):
        raw = _saml_app()
        raw["settings"]["signOn"]["assertionEncrypted"] = True
        rec = OktaConnector._normalize_application(_TENANT, raw, user_assignment_count=0, group_assignment_count=0)
        assert rec["saml_encryption_enabled"] is True

    def test_encryption_unknown_when_absent(self):
        raw = _saml_app(settings={"signOn": {}})
        rec = OktaConnector._normalize_application(_TENANT, raw, user_assignment_count=0, group_assignment_count=0)
        assert rec["saml_encryption_enabled"] is None

    def test_destination_configured(self):
        rec = OktaConnector._normalize_application(_TENANT, _saml_app(), user_assignment_count=0, group_assignment_count=0)
        assert rec["saml_destination_configured"] is True

    def test_audience_configured(self):
        rec = OktaConnector._normalize_application(_TENANT, _saml_app(), user_assignment_count=0, group_assignment_count=0)
        assert rec["saml_audience_configured"] is True

    def test_no_certificate_persisted(self):
        raw = _saml_app()
        raw["settings"]["signOn"]["kid"] = "certificate-key-id-should-not-appear"
        raw["settings"]["signOn"]["certificate"] = "-----BEGIN CERTIFICATE-----FAKECERTBODY-----END CERTIFICATE-----"
        rec = OktaConnector._normalize_application(_TENANT, raw, user_assignment_count=0, group_assignment_count=0)
        assert "certificate" not in str(rec)
        assert "FAKECERTBODY" not in str(rec)

    def test_no_metadata_xml_persisted(self):
        raw = _saml_app()
        raw["settings"]["signOn"]["slo"] = {"issuer": "x"}
        raw["_links"] = {"metadata": {"href": "https://example.okta.com/app/xyz/sso/saml/metadata"}}
        rec = OktaConnector._normalize_application(_TENANT, raw, user_assignment_count=0, group_assignment_count=0)
        assert "metadata" not in rec
        assert "_links" not in rec

    def test_signature_algorithm_category(self):
        rec = OktaConnector._normalize_application(_TENANT, _saml_app(), user_assignment_count=0, group_assignment_count=0)
        assert rec["saml_signature_algorithm_category"] == "RSA_SHA256"

    def test_digest_algorithm_category(self):
        rec = OktaConnector._normalize_application(_TENANT, _saml_app(), user_assignment_count=0, group_assignment_count=0)
        assert rec["saml_digest_algorithm_category"] == "SHA256"


# ════════════════════════════════════════════════════════════════════════════
# Assignment scope taxonomy
# ════════════════════════════════════════════════════════════════════════════


class TestAssignmentScope:
    def test_user_scope(self):
        assert categorize_assignment_scope("USER") == "USER"

    def test_group_scope(self):
        assert categorize_assignment_scope("GROUP") == "GROUP"

    def test_unknown_scope(self):
        assert categorize_assignment_scope("SOMETHING_NEW") == "unknown"

    def test_none_scope(self):
        assert categorize_assignment_scope(None) == "unknown"


# ════════════════════════════════════════════════════════════════════════════
# Assignment normalization
# ════════════════════════════════════════════════════════════════════════════


class TestAssignmentNormalization:
    def test_user_assignment_denormalizes_login_and_app_label(self):
        app_rec = OktaConnector._normalize_application(_TENANT, _app(), user_assignment_count=0, group_assignment_count=0)
        user_rec = {"login": "u1@example.com", "status": "ACTIVE"}
        rec = OktaConnector._normalize_app_user_assignment(
            _TENANT, app_rec, user_rec, {"id": "u1", "status": "ACTIVE", "scope": "USER"},
        )
        assert rec["user_login"] == "u1@example.com"
        assert rec["app_label"] == "My App"
        assert rec["assignment_scope_category"] == "USER"

    def test_missing_user_record_degrades_gracefully(self):
        app_rec = OktaConnector._normalize_application(_TENANT, _app(), user_assignment_count=0, group_assignment_count=0)
        rec = OktaConnector._normalize_app_user_assignment(
            _TENANT, app_rec, None, {"id": "u-missing", "status": "ACTIVE", "scope": "USER"},
        )
        assert rec["user_login"] is None
        assert rec["user_status"] == "UNKNOWN"

    def test_group_assignment_denormalizes_group_name(self):
        app_rec = OktaConnector._normalize_application(_TENANT, _app(), user_assignment_count=0, group_assignment_count=0)
        group_rec = {"group_name": "Engineering", "group_type": "OKTA_GROUP", "built_in": False, "everyone_group": False}
        rec = OktaConnector._normalize_app_group_assignment(_TENANT, app_rec, group_rec, {"id": "g1"})
        assert rec["group_name"] == "Engineering"
        assert rec["app_label"] == "My App"

    def test_missing_group_record_degrades_gracefully(self):
        app_rec = OktaConnector._normalize_application(_TENANT, _app(), user_assignment_count=0, group_assignment_count=0)
        rec = OktaConnector._normalize_app_group_assignment(_TENANT, app_rec, None, {"id": "g-missing"})
        assert rec["group_name"] is None
        assert rec["group_type"] == "unknown"

    def test_does_not_duplicate_full_app_or_user_record(self):
        app_rec = OktaConnector._normalize_application(_TENANT, _app(), user_assignment_count=0, group_assignment_count=0)
        user_rec = {"login": "u1@example.com", "status": "ACTIVE"}
        rec = OktaConnector._normalize_app_user_assignment(
            _TENANT, app_rec, user_rec, {"id": "u1", "status": "ACTIVE", "scope": "USER"},
        )
        assert "redirect_count" not in rec
        assert "grant_types_summary" not in rec
        assert "credential_provider_category" not in rec


# ════════════════════════════════════════════════════════════════════════════
# Sensitive-data exclusion
# ════════════════════════════════════════════════════════════════════════════


class TestSensitiveDataExclusion:
    def test_client_secret_excluded(self):
        raw = _app()
        raw["credentials"] = {"oauthClient": {"client_secret": "SHOULD_NEVER_APPEAR"}}
        rec = OktaConnector._normalize_application(_TENANT, raw, user_assignment_count=0, group_assignment_count=0)
        assert "SHOULD_NEVER_APPEAR" not in str(rec)
        assert "client_secret" not in rec

    def test_credentials_object_excluded(self):
        raw = _app()
        raw["credentials"] = {
            "signing": {"rotationMode": "AUTO"},
            "oauthClient": {"client_secret": "secret-value", "client_id": "abc123"},
        }
        rec = OktaConnector._normalize_application(_TENANT, raw, user_assignment_count=0, group_assignment_count=0)
        assert "credentials" not in rec
        assert "secret-value" not in str(rec)
        # Only the scoped, safe rotationMode sub-field is read.
        assert rec["signing_key_rotation_category"] == "AUTO"

    def test_app_password_excluded(self):
        app_rec = OktaConnector._normalize_application(_TENANT, _app(), user_assignment_count=0, group_assignment_count=0)
        raw_assignment = {
            "id": "u1", "status": "ACTIVE", "scope": "USER",
            "credentials": {"userName": "u1@example.com", "password": {"value": "SHOULD_NEVER_APPEAR"}},
        }
        rec = OktaConnector._normalize_app_user_assignment(_TENANT, app_rec, None, raw_assignment)
        assert "SHOULD_NEVER_APPEAR" not in str(rec)
        assert "credentials" not in rec

    def test_private_key_excluded(self):
        raw = _app()
        raw["credentials"] = {"signing": {"kid": "key123", "privateKey": "-----BEGIN PRIVATE KEY-----FAKE-----END PRIVATE KEY-----"}}
        rec = OktaConnector._normalize_application(_TENANT, raw, user_assignment_count=0, group_assignment_count=0)
        assert "PRIVATE KEY" not in str(rec)
        assert "privateKey" not in rec

    def test_certificate_body_excluded(self):
        raw = _saml_app()
        raw["settings"]["signOn"]["certificate"] = "FAKE_CERT_BODY_MUST_NOT_APPEAR"
        rec = OktaConnector._normalize_application(_TENANT, raw, user_assignment_count=0, group_assignment_count=0)
        assert "FAKE_CERT_BODY_MUST_NOT_APPEAR" not in str(rec)

    def test_raw_saml_metadata_excluded(self):
        raw = _saml_app()
        raw["_embedded"] = {"metadata": "<EntityDescriptor>FAKE_XML_METADATA_MUST_NOT_APPEAR</EntityDescriptor>"}
        rec = OktaConnector._normalize_application(_TENANT, raw, user_assignment_count=0, group_assignment_count=0)
        assert "FAKE_XML_METADATA_MUST_NOT_APPEAR" not in str(rec)
        assert "_embedded" not in rec

    def test_custom_profile_excluded(self):
        raw = _app()
        raw["profile"] = {"customField": "sensitive-app-instance-data"}
        rec = OktaConnector._normalize_application(_TENANT, raw, user_assignment_count=0, group_assignment_count=0)
        assert "sensitive-app-instance-data" not in str(rec)
        assert "profile" not in rec

    def test_query_and_fragment_not_stored_in_redirect_summary(self):
        raw = _app()
        raw["settings"]["oauthClient"]["redirect_uris"] = [
            "https://app.example.com/cb?token=SHOULD_NOT_APPEAR&state=xyz#fragment-should-not-appear",
        ]
        rec = OktaConnector._normalize_application(_TENANT, raw, user_assignment_count=0, group_assignment_count=0)
        assert "SHOULD_NOT_APPEAR" not in str(rec)
        assert "fragment-should-not-appear" not in str(rec)
        assert rec["redirect_count"] == 1

    def test_access_token_refresh_token_excluded(self):
        raw = _app()
        raw["accessToken"] = "SHOULD_NEVER_APPEAR_ACCESS"
        raw["refreshToken"] = "SHOULD_NEVER_APPEAR_REFRESH"
        rec = OktaConnector._normalize_application(_TENANT, raw, user_assignment_count=0, group_assignment_count=0)
        assert "SHOULD_NEVER_APPEAR_ACCESS" not in str(rec)
        assert "SHOULD_NEVER_APPEAR_REFRESH" not in str(rec)

    def test_authorization_code_excluded(self):
        raw = _app()
        raw["authorizationCode"] = "SHOULD_NEVER_APPEAR_CODE"
        rec = OktaConnector._normalize_application(_TENANT, raw, user_assignment_count=0, group_assignment_count=0)
        assert "SHOULD_NEVER_APPEAR_CODE" not in str(rec)
