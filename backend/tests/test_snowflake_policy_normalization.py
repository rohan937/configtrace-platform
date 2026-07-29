"""Snowflake security-policy normalization tests (Snowflake message 4 of 8).

Covers field-by-field normalization: broad-network-access detection,
authentication-method/MFA/client-type taxonomies, SAML/OAuth/SCIM security-
integration posture, storage-provider taxonomy, external-access posture,
unknown-field discipline, and sensitive-data exclusion. Unit-level only —
calls the connector's normalizer/categorizer functions directly, no HTTP
mocking needed.
"""

from __future__ import annotations

import pytest

from app.connectors.snowflake import SnowflakeConnector, _count_list_like
from app.connectors.snowflake_schema import (
    AUTH_METHOD_KEYPAIR,
    AUTH_METHOD_OAUTH,
    AUTH_METHOD_PASSWORD,
    AUTH_METHOD_PROGRAMMATIC_ACCESS_TOKEN,
    AUTH_METHOD_SAML,
    BROAD_ACCESS_FALSE,
    BROAD_ACCESS_TRUE,
    BROAD_ACCESS_UNKNOWN,
    CLIENT_TYPES_ALL,
    CLIENT_TYPES_RESTRICTED,
    CLIENT_TYPES_UNKNOWN,
    DETAIL_COMPLETE,
    DETAIL_UNAVAILABLE,
    INTEGRATION_TYPE_EXTERNAL_OAUTH,
    INTEGRATION_TYPE_OAUTH_SNOWFLAKE,
    INTEGRATION_TYPE_SAML2,
    INTEGRATION_TYPE_SCIM,
    INTEGRATION_TYPE_UNKNOWN,
    MFA_ENROLLMENT_OPTIONAL,
    MFA_ENROLLMENT_REQUIRED,
    MFA_ENROLLMENT_UNKNOWN,
    PRINCIPAL_TYPE_ACCOUNT_ROLE,
    SNOWFLAKE_AUTHENTICATION_POLICY,
    SNOWFLAKE_EXTERNAL_ACCESS_INTEGRATION,
    SNOWFLAKE_NETWORK_POLICY,
    SNOWFLAKE_NETWORK_RULE,
    SNOWFLAKE_SECURITY_INTEGRATION,
    SNOWFLAKE_STORAGE_INTEGRATION,
    STORAGE_PROVIDER_AZURE,
    STORAGE_PROVIDER_GCS,
    STORAGE_PROVIDER_S3,
    STORAGE_PROVIDER_UNKNOWN,
    TRISTATE_FALSE,
    TRISTATE_TRUE,
    TRISTATE_UNKNOWN,
    categorize_auth_methods,
    categorize_broad_access,
    categorize_client_types,
    categorize_integration_type,
    categorize_mfa_enrollment,
    categorize_storage_provider,
)

_ACCOUNT_ID = "id:acme-prod"


# ── Broad-network-access ──────────────────────────────────────────────────────


class TestBroadAccess:
    def test_true(self):
        assert categorize_broad_access(True) == BROAD_ACCESS_TRUE

    def test_false(self):
        assert categorize_broad_access(False) == BROAD_ACCESS_FALSE

    def test_none_is_unknown_never_false(self):
        assert categorize_broad_access(None) == BROAD_ACCESS_UNKNOWN

    def test_anywhere_sentinel_detection_ipv4(self):
        assert SnowflakeConnector._contains_anywhere_sentinel("10.0.0.0/8, 0.0.0.0/0") is True

    def test_anywhere_sentinel_detection_ipv6(self):
        assert SnowflakeConnector._contains_anywhere_sentinel("::/0") is True

    def test_no_broad_cidr(self):
        assert SnowflakeConnector._contains_anywhere_sentinel("10.0.0.0/8, 192.168.1.0/24") is False

    def test_private_ranges_do_not_trigger_broad_access(self):
        assert SnowflakeConnector._contains_anywhere_sentinel("10.0.0.0/8") is False
        assert SnowflakeConnector._contains_anywhere_sentinel("192.168.0.0/16") is False

    def test_missing_value_is_unknown(self):
        assert SnowflakeConnector._contains_anywhere_sentinel(None) is None

    def test_non_string_value_is_unknown(self):
        assert SnowflakeConnector._contains_anywhere_sentinel(42) is None


# ── Authentication methods ────────────────────────────────────────────────────


class TestAuthMethods:
    def test_password_and_saml(self):
        result = categorize_auth_methods("['PASSWORD', 'SAML']")
        assert AUTH_METHOD_PASSWORD in result
        assert AUTH_METHOD_SAML in result

    def test_keypair_and_pat(self):
        result = categorize_auth_methods(['KEYPAIR', 'PROGRAMMATIC_ACCESS_TOKEN'])
        assert AUTH_METHOD_KEYPAIR in result
        assert AUTH_METHOD_PROGRAMMATIC_ACCESS_TOKEN in result

    def test_oauth(self):
        assert categorize_auth_methods(['OAUTH']) == [AUTH_METHOD_OAUTH]

    def test_unrecognized_method_dropped_not_invented(self):
        result = categorize_auth_methods("['PASSWORD', 'SOME_FUTURE_METHOD']")
        assert result == [AUTH_METHOD_PASSWORD]

    def test_missing_is_empty_list(self):
        assert categorize_auth_methods(None) == []

    def test_non_string_non_list_is_empty(self):
        assert categorize_auth_methods(42) == []


# ── MFA enrollment ────────────────────────────────────────────────────────────


class TestMfaEnrollment:
    def test_required(self):
        assert categorize_mfa_enrollment("REQUIRED") == MFA_ENROLLMENT_REQUIRED

    def test_optional(self):
        assert categorize_mfa_enrollment("OPTIONAL") == MFA_ENROLLMENT_OPTIONAL

    def test_required_password_only(self):
        assert categorize_mfa_enrollment("REQUIRED_PASSWORD_ONLY") == "required_password_only"

    def test_missing_is_unknown(self):
        assert categorize_mfa_enrollment(None) == MFA_ENROLLMENT_UNKNOWN

    def test_malformed_is_unknown(self):
        assert categorize_mfa_enrollment("SOMETHING_ELSE") == MFA_ENROLLMENT_UNKNOWN


# ── Client types ──────────────────────────────────────────────────────────────


class TestClientTypes:
    def test_all(self):
        assert categorize_client_types("['ALL']") == CLIENT_TYPES_ALL

    def test_restricted(self):
        assert categorize_client_types("['SNOWFLAKE_UI', 'DRIVERS']") == CLIENT_TYPES_RESTRICTED

    def test_missing_is_unknown(self):
        assert categorize_client_types(None) == CLIENT_TYPES_UNKNOWN

    def test_empty_list_is_unknown(self):
        assert categorize_client_types([]) == CLIENT_TYPES_UNKNOWN


# ── Security-integration type ─────────────────────────────────────────────────


class TestIntegrationType:
    def test_saml2(self):
        assert categorize_integration_type("SAML2") == INTEGRATION_TYPE_SAML2

    def test_snowflake_oauth(self):
        assert categorize_integration_type("OAUTH") == INTEGRATION_TYPE_OAUTH_SNOWFLAKE

    def test_external_oauth_distinguished_from_snowflake_oauth(self):
        assert categorize_integration_type("EXTERNAL_OAUTH") == INTEGRATION_TYPE_EXTERNAL_OAUTH
        assert categorize_integration_type("EXTERNAL_OAUTH") != categorize_integration_type("OAUTH")

    def test_scim(self):
        assert categorize_integration_type("SCIM") == INTEGRATION_TYPE_SCIM

    def test_type_with_subtype_suffix(self):
        """SHOW SECURITY INTEGRATIONS may render type as e.g.
        'OAUTH - SNOWFLAKE_OAUTH' — the leading token must still match."""
        assert categorize_integration_type("OAUTH - SNOWFLAKE_OAUTH") == INTEGRATION_TYPE_OAUTH_SNOWFLAKE

    def test_unrecognized_is_unknown(self):
        assert categorize_integration_type("SOME_FUTURE_TYPE") == INTEGRATION_TYPE_UNKNOWN

    def test_none_is_unknown(self):
        assert categorize_integration_type(None) == INTEGRATION_TYPE_UNKNOWN


# ── Storage provider ──────────────────────────────────────────────────────────


class TestStorageProvider:
    def test_s3(self):
        assert categorize_storage_provider("S3") == STORAGE_PROVIDER_S3

    def test_s3_china_and_gov_map_to_s3(self):
        assert categorize_storage_provider("S3CHINA") == STORAGE_PROVIDER_S3
        assert categorize_storage_provider("S3GOV") == STORAGE_PROVIDER_S3

    def test_azure(self):
        assert categorize_storage_provider("AZURE") == STORAGE_PROVIDER_AZURE

    def test_gcs(self):
        assert categorize_storage_provider("GCS") == STORAGE_PROVIDER_GCS

    def test_missing_is_unknown(self):
        assert categorize_storage_provider(None) == STORAGE_PROVIDER_UNKNOWN


# ── List-like count parsing ────────────────────────────────────────────────────


class TestCountListLike:
    def test_bracketed_string_list(self):
        assert _count_list_like("['a', 'b', 'c']") == 3

    def test_native_list(self):
        assert _count_list_like(["a", "b"]) == 2

    def test_empty_brackets(self):
        assert _count_list_like("[]") == 0

    def test_none_value(self):
        assert _count_list_like("NONE") == 0

    def test_missing_is_none_not_zero(self):
        assert _count_list_like(None) is None

    def test_malformed_is_none(self):
        assert _count_list_like(42) is None


# ── Network policy normalizer ──────────────────────────────────────────────────


class TestNormalizeNetworkPolicy:
    def test_full_row_with_broad_access(self):
        row = {"NAME": "OPEN", "OWNER": "SECURITYADMIN", "ENTRIES_IN_ALLOWED_IP_LIST": "1", "ENTRIES_IN_BLOCKED_IP_LIST": "0", "ENTRIES_IN_ALLOWED_NETWORK_RULES": "0", "ENTRIES_IN_BLOCKED_NETWORK_RULES": "0"}
        record = SnowflakeConnector._normalize_network_policy(_ACCOUNT_ID, row, allows_anywhere_ipv4=True, allows_anywhere_ipv6=False, detail_collection_status=DETAIL_COMPLETE)
        assert record["record_type"] == SNOWFLAKE_NETWORK_POLICY
        assert record["allows_anywhere_ipv4"] == BROAD_ACCESS_TRUE
        assert record["allows_anywhere_ipv6"] == BROAD_ACCESS_FALSE
        assert record["has_allowlist"] is True
        assert record["has_blocklist"] is False

    def test_detail_not_attempted_defaults_unknown(self):
        row = {"NAME": "OPEN", "ENTRIES_IN_ALLOWED_IP_LIST": "1"}
        record = SnowflakeConnector._normalize_network_policy(_ACCOUNT_ID, row)
        assert record["allows_anywhere_ipv4"] == BROAD_ACCESS_UNKNOWN
        assert record["detail_collection_status"] == DETAIL_UNAVAILABLE

    def test_missing_name_returns_none(self):
        assert SnowflakeConnector._normalize_network_policy(_ACCOUNT_ID, {"NAME": None}) is None

    def test_missing_counts_are_none_not_zero(self):
        record = SnowflakeConnector._normalize_network_policy(_ACCOUNT_ID, {"NAME": "P"})
        assert record["allowed_ipv4_count"] is None
        assert record["has_allowlist"] is None


# ── Network rule normalizer ────────────────────────────────────────────────────


class TestNormalizeNetworkRule:
    def test_full_row(self):
        row = {"NAME": "MY_RULE", "DATABASE_NAME": "MYDB", "SCHEMA_NAME": "PUBLIC", "OWNER": "SYSADMIN", "TYPE": "host_port", "MODE": "egress", "ENTRIES_IN_VALUELIST": "3"}
        record = SnowflakeConnector._normalize_network_rule(_ACCOUNT_ID, row)
        assert record["record_type"] == SNOWFLAKE_NETWORK_RULE
        assert record["rule_type"] == "HOST_PORT"
        assert record["rule_mode"] == "EGRESS"
        assert record["value_count"] == 3

    def test_missing_name_returns_none(self):
        assert SnowflakeConnector._normalize_network_rule(_ACCOUNT_ID, {"NAME": None}) is None

    def test_no_raw_values_field_exists(self):
        row = {"NAME": "MY_RULE", "ENTRIES_IN_VALUELIST": "3"}
        record = SnowflakeConnector._normalize_network_rule(_ACCOUNT_ID, row)
        assert "value_list" not in record
        assert "values" not in record


# ── Authentication policy normalizer ──────────────────────────────────────────


class TestNormalizeAuthenticationPolicy:
    def test_full_row_with_properties(self):
        row = {"NAME": "STRICT", "OWNER": "SECURITYADMIN", "SET_ON": "account"}
        props = {"AUTHENTICATION_METHODS": "['SAML','PASSWORD']", "MFA_ENROLLMENT": "REQUIRED", "CLIENT_TYPES": "['ALL']"}
        record = SnowflakeConnector._normalize_authentication_policy(_ACCOUNT_ID, row, properties=props)
        assert record["record_type"] == SNOWFLAKE_AUTHENTICATION_POLICY
        assert record["set_on"] == "ACCOUNT"
        assert record["mfa_enrollment"] == MFA_ENROLLMENT_REQUIRED
        assert AUTH_METHOD_SAML in record["authentication_methods"]
        assert record["detail_collection_status"] == DETAIL_COMPLETE

    def test_properties_none_means_unavailable_detail(self):
        row = {"NAME": "STRICT", "SET_ON": "account"}
        record = SnowflakeConnector._normalize_authentication_policy(_ACCOUNT_ID, row, properties=None)
        assert record["mfa_enrollment"] == "unknown"
        assert record["authentication_methods"] is None
        assert record["detail_collection_status"] == DETAIL_UNAVAILABLE

    def test_missing_name_returns_none(self):
        assert SnowflakeConnector._normalize_authentication_policy(_ACCOUNT_ID, {"NAME": None}) is None

    def test_service_user_context_never_flagged_mfa_disabled(self):
        """Service-user PAT/key-pair authentication is never interpreted
        as 'MFA disabled' in the same sense as human login — this
        normalizer never even inspects user_type, confirming the two
        concerns are structurally separate."""
        row = {"NAME": "STRICT", "SET_ON": "account"}
        props = {"AUTHENTICATION_METHODS": "['PROGRAMMATIC_ACCESS_TOKEN']", "MFA_ENROLLMENT": "OPTIONAL"}
        record = SnowflakeConnector._normalize_authentication_policy(_ACCOUNT_ID, row, properties=props)
        assert "user_type" not in record
        assert "mfa_disabled" not in record


# ── Security integration normalizer ───────────────────────────────────────────


class TestNormalizeSecurityIntegration:
    def test_saml2_posture(self):
        row = {"NAME": "MY_SAML", "TYPE": "SAML2", "ENABLED": "true", "OWNER": "SECURITYADMIN"}
        props = {"SAML2_ISSUER": "https://idp.example.com", "SAML2_SSO_URL": "https://idp.example.com/sso", "SAML2_X509_CERT": "MIIB..."}
        record = SnowflakeConnector._normalize_security_integration(_ACCOUNT_ID, row, properties=props)
        assert record["record_type"] == SNOWFLAKE_SECURITY_INTEGRATION
        assert record["integration_type"] == INTEGRATION_TYPE_SAML2
        assert record["saml2_certificate_configured"] == TRISTATE_TRUE
        assert record["saml2_issuer_configured"] == TRISTATE_TRUE

    def test_saml2_certificate_body_never_stored(self):
        row = {"NAME": "MY_SAML", "TYPE": "SAML2", "ENABLED": "true"}
        props = {"SAML2_X509_CERT": "MIIB-full-certificate-body-would-go-here"}
        record = SnowflakeConnector._normalize_security_integration(_ACCOUNT_ID, row, properties=props)
        assert "MIIB-full-certificate-body-would-go-here" not in str(record)
        assert record["saml2_certificate_configured"] == TRISTATE_TRUE

    def test_oauth_snowflake_posture(self):
        row = {"NAME": "MY_OAUTH", "TYPE": "OAUTH", "ENABLED": "true"}
        props = {"OAUTH_CLIENT_TYPE": "CONFIDENTIAL"}
        record = SnowflakeConnector._normalize_security_integration(_ACCOUNT_ID, row, properties=props)
        assert record["integration_type"] == INTEGRATION_TYPE_OAUTH_SNOWFLAKE
        assert record["oauth_client_category"] == "CONFIDENTIAL"

    def test_external_oauth_posture(self):
        row = {"NAME": "MY_EXT_OAUTH", "TYPE": "EXTERNAL_OAUTH", "ENABLED": "true"}
        props = {"EXTERNAL_OAUTH_ISSUER": "https://issuer.example.com", "EXTERNAL_OAUTH_TYPE": "CUSTOM"}
        record = SnowflakeConnector._normalize_security_integration(_ACCOUNT_ID, row, properties=props)
        assert record["integration_type"] == INTEGRATION_TYPE_EXTERNAL_OAUTH
        assert record["oauth_issuer_configured"] == TRISTATE_TRUE

    def test_scim_run_as_role(self):
        row = {"NAME": "MY_SCIM", "TYPE": "SCIM", "ENABLED": "true"}
        props = {"SCIM_RUN_AS_ROLE": "SCIM_PROVISIONER_ROLE"}
        record = SnowflakeConnector._normalize_security_integration(_ACCOUNT_ID, row, properties=props)
        assert record["integration_type"] == INTEGRATION_TYPE_SCIM
        assert record["scim_run_as_role"] == "SCIM_PROVISIONER_ROLE"

    def test_scim_run_as_role_not_classified_by_name_alone(self):
        """Message 4 preserves the run_as_role identifier; it must never
        itself compute a privilege tier from the role's name."""
        row = {"NAME": "MY_SCIM", "TYPE": "SCIM", "ENABLED": "true"}
        props = {"SCIM_RUN_AS_ROLE": "ACCOUNTADMIN"}
        record = SnowflakeConnector._normalize_security_integration(_ACCOUNT_ID, row, properties=props)
        assert record["scim_run_as_role"] == "ACCOUNTADMIN"
        assert "privilege_tier" not in record
        assert "risk" not in record

    def test_missing_name_returns_none(self):
        assert SnowflakeConnector._normalize_security_integration(_ACCOUNT_ID, {"NAME": None}) is None

    def test_enabled_unknown_when_missing(self):
        row = {"NAME": "MY_SAML", "TYPE": "SAML2"}
        record = SnowflakeConnector._normalize_security_integration(_ACCOUNT_ID, row)
        assert record["enabled"] == TRISTATE_UNKNOWN

    def test_no_raw_property_map_persisted(self):
        row = {"NAME": "MY_SAML", "TYPE": "SAML2", "ENABLED": "true"}
        props = {"SAML2_ISSUER": "https://idp.example.com", "SOME_UNRECOGNIZED_PROPERTY": "leaked-value"}
        record = SnowflakeConnector._normalize_security_integration(_ACCOUNT_ID, row, properties=props)
        assert "leaked-value" not in str(record)
        assert "SOME_UNRECOGNIZED_PROPERTY" not in record


# ── Storage integration normalizer ────────────────────────────────────────────


class TestNormalizeStorageIntegration:
    def test_s3_posture(self):
        row = {"NAME": "MY_S3", "ENABLED": "true"}
        props = {"STORAGE_PROVIDER": "S3", "STORAGE_ALLOWED_LOCATIONS": "['s3://a/', 's3://b/']", "STORAGE_AWS_IAM_USER_ARN": "arn:aws:iam::123:user/x"}
        record = SnowflakeConnector._normalize_storage_integration(_ACCOUNT_ID, row, properties=props)
        assert record["record_type"] == SNOWFLAKE_STORAGE_INTEGRATION
        assert record["storage_provider"] == STORAGE_PROVIDER_S3
        assert record["allowed_location_count"] == 2
        assert record["cloud_identity_configured"] == TRISTATE_TRUE

    def test_cloud_credentials_never_stored(self):
        row = {"NAME": "MY_S3", "ENABLED": "true"}
        props = {"STORAGE_AWS_IAM_USER_ARN": "arn:aws:iam::123456789012:user/snowflake-role"}
        record = SnowflakeConnector._normalize_storage_integration(_ACCOUNT_ID, row, properties=props)
        assert "arn:aws:iam::123456789012:user/snowflake-role" not in str(record)

    def test_missing_name_returns_none(self):
        assert SnowflakeConnector._normalize_storage_integration(_ACCOUNT_ID, {"NAME": None}) is None

    def test_location_count_unknown_when_detail_unavailable(self):
        record = SnowflakeConnector._normalize_storage_integration(_ACCOUNT_ID, {"NAME": "MY_S3"})
        assert record["allowed_location_count"] is None
        assert record["storage_provider"] == "unknown"


# ── External access integration normalizer ────────────────────────────────────


class TestNormalizeExternalAccessIntegration:
    def test_full_posture(self):
        row = {"NAME": "MY_EAI", "ENABLED": "true"}
        props = {
            "ALLOWED_NETWORK_RULES": "['RULE_A']",
            "ALLOWED_AUTHENTICATION_SECRETS": "['SECRET_A', 'SECRET_B']",
            "ALLOWED_API_AUTHENTICATION_INTEGRATIONS": "[]",
        }
        record = SnowflakeConnector._normalize_external_access_integration(_ACCOUNT_ID, row, properties=props)
        assert record["record_type"] == SNOWFLAKE_EXTERNAL_ACCESS_INTEGRATION
        assert record["allowed_network_rule_count"] == 1
        assert record["allowed_secret_count"] == 2
        assert record["allowed_api_authentication_integration_count"] == 0

    def test_secret_names_never_stored(self):
        row = {"NAME": "MY_EAI", "ENABLED": "true"}
        props = {"ALLOWED_AUTHENTICATION_SECRETS": "['MY_SENSITIVE_SECRET_NAME']"}
        record = SnowflakeConnector._normalize_external_access_integration(_ACCOUNT_ID, row, properties=props)
        assert "MY_SENSITIVE_SECRET_NAME" not in str(record)

    def test_missing_name_returns_none(self):
        assert SnowflakeConnector._normalize_external_access_integration(_ACCOUNT_ID, {"NAME": None}) is None

    def test_existence_not_inherently_risky(self):
        """The normalizer itself never assigns a severity/risk field —
        that is the risk classifier's job, keeping normalization and
        classification concerns separate."""
        row = {"NAME": "MY_EAI", "ENABLED": "true"}
        record = SnowflakeConnector._normalize_external_access_integration(_ACCOUNT_ID, row, properties={})
        assert "risk" not in record
        assert "severity" not in record
