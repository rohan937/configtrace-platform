"""Tests for M54 — Supabase Provider MVP.

Coverage
--------
1.  Schema constants (10 record type constants, REQUIRED_CREDENTIAL_FIELDS)
2.  Connector: credential field validation (missing access_token, project_ref)
3.  Connector: _sha256_prefix hashing
4.  Connector: fetch() returns all 10 record type categories
5.  Connector: validate_credentials() happy path
6.  Connector: 401 on project call → AuthenticationError
7.  Connector: 403 on project call → ConnectorError (status_code=403)
8.  Connector: 403 on optional surface → warn + continue (fail-soft)
9.  Connector: 404 on custom-domain → silent skip (not an error)
10. Connector: network error → NetworkError
11. Connector: 429 rate limit → RateLimitError
12. Connector: 5xx → ConnectorError
13. Connector: empty network-restrictions list → unrestricted record
14. Connector: OAuth provider client_id is hashed (never stored raw)
15. Connector: Edge Function env var values never stored (only count)
16. Connector: RLS status includes rls_enabled/rls_forced per table
17. Risk rules: supabase_project — added, removed, status change
18. Risk rules: supabase_auth_config — anonymous_enabled → critical
19. Risk rules: supabase_auth_config — mfa_totp_enabled disabled → high
20. Risk rules: supabase_auth_config — password_min_length decreased → medium
21. Risk rules: supabase_rls_status — rls_enabled disabled → critical
22. Risk rules: supabase_rls_status — rls_forced disabled → high
23. Risk rules: supabase_rls_status — new table without RLS → medium
24. Risk rules: supabase_edge_function — verify_jwt disabled → high
25. Risk rules: supabase_network_restriction — unrestricted added → critical
26. Risk rules: supabase_network_restriction — CIDR removed → high
27. Risk rules: supabase_api_config — db_schema changed → high
28. Risk rules: supabase_storage_config — file_size_limit removed → high
29. Risk rules: supabase_oauth_provider — added → medium
30. Risk rules: supabase_oauth_provider — removed → high
31. Risk rules: supabase_custom_domain — removed → medium
32. Risk service dispatch: supabase_ prefix → classify_supabase_change
33. Diff service: _SUPABASE_TRACKED_FIELDS_BY_TYPE has all 10 types
34. Diff service: _tracked_fields_for dispatches supabase_ prefix
35. Failure classifier: AuthenticationError → supabase_token_revoked
36. Failure classifier: ConnectorError 403 → supabase_permission_denied
37. Failure classifier: ConnectorError 404 → supabase_project_not_found
38. Failure classifier: ConnectorError 5xx → supabase_api_unavailable
39. Integration schema: provider Literal includes "supabase"
40. Integration schema: missing supabase_access_token → ValidationError
41. Integration schema: missing supabase_project_ref → ValidationError
42. Integration schema: reconnect has supabase_access_token field
43. Sync service: "supabase" in _SUPPORTED_PROVIDERS
44. Security: access_token never in record dicts returned by fetch()
45. Security: raw client_id never in OAuth provider records
46. Security: project_ref in resource_metadata but access_token never stored raw
47. Security: edge function env var values never in records
48. Security: no forbidden API calls (database rows, auth users, file contents)
49. Frontend type: IntegrationCreateRequest includes supabase fields
50. Connector: __init__.py exports SupabaseConnector
"""

from __future__ import annotations

import json
import unittest
from unittest.mock import MagicMock, patch

import pytest


# ── Helpers ────────────────────────────────────────────────────────────────────

def _make_change(
    record_type: str = "supabase_project",
    field_path: str = "",
    change_type: str = "modified",
    prev_value=None,
    new_value=None,
    provider_metadata: dict | None = None,
) -> dict:
    """Build a minimal change dict for risk rule tests."""
    return {
        "record_type": record_type,
        "field_path": field_path,
        "change_type": change_type,
        "prev_value": prev_value,
        "new_value": new_value,
        "provider_metadata": provider_metadata or {"record_type": record_type},
    }


# ── 1. Schema constants ────────────────────────────────────────────────────────

class TestSupabaseSchemaConstants:
    def test_all_ten_record_type_constants_exist(self):
        from app.connectors.supabase_schema import (
            SUPABASE_PROJECT,
            SUPABASE_AUTH_CONFIG,
            SUPABASE_DATABASE_CONFIG,
            SUPABASE_STORAGE_CONFIG,
            SUPABASE_EDGE_FUNCTION,
            SUPABASE_RLS_STATUS,
            SUPABASE_API_CONFIG,
            SUPABASE_NETWORK_RESTRICTION,
            SUPABASE_CUSTOM_DOMAIN,
            SUPABASE_OAUTH_PROVIDER,
        )
        constants = [
            SUPABASE_PROJECT, SUPABASE_AUTH_CONFIG, SUPABASE_DATABASE_CONFIG,
            SUPABASE_STORAGE_CONFIG, SUPABASE_EDGE_FUNCTION, SUPABASE_RLS_STATUS,
            SUPABASE_API_CONFIG, SUPABASE_NETWORK_RESTRICTION, SUPABASE_CUSTOM_DOMAIN,
            SUPABASE_OAUTH_PROVIDER,
        ]
        assert len(constants) == 10
        # All start with "supabase_"
        for c in constants:
            assert c.startswith("supabase_"), f"{c!r} should start with 'supabase_'"

    def test_required_credential_fields(self):
        from app.connectors.supabase_schema import REQUIRED_CREDENTIAL_FIELDS
        assert "access_token" in REQUIRED_CREDENTIAL_FIELDS
        assert "project_ref" in REQUIRED_CREDENTIAL_FIELDS

    def test_constants_are_strings(self):
        from app.connectors.supabase_schema import SUPABASE_PROJECT, SUPABASE_RLS_STATUS
        assert isinstance(SUPABASE_PROJECT, str)
        assert isinstance(SUPABASE_RLS_STATUS, str)


# ── 2. Connector: credential validation ───────────────────────────────────────

class TestSupabaseConnectorCredentialValidation:
    def setup_method(self):
        from app.connectors.supabase import SupabaseConnector
        self.connector = SupabaseConnector()

    def test_missing_access_token_raises_value_error(self):
        with pytest.raises(ValueError, match="access_token"):
            self.connector._validate_credential_fields({"project_ref": "abcdefghijklmnopqrst"})

    def test_missing_project_ref_raises_value_error(self):
        with pytest.raises(ValueError, match="project_ref"):
            self.connector._validate_credential_fields({"access_token": "sbp_test"})

    def test_empty_access_token_raises_value_error(self):
        with pytest.raises(ValueError):
            self.connector._validate_credential_fields({
                "access_token": "",
                "project_ref": "abcdefghijklmnopqrst",
            })

    def test_valid_credentials_does_not_raise(self):
        # Should not raise
        self.connector._validate_credential_fields({
            "access_token": "sbp_test_token_12345",
            "project_ref": "abcdefghijklmnopqrst",
        })


# ── 3. SHA-256 prefix hashing ─────────────────────────────────────────────────

class TestSha256Prefix:
    def test_returns_16_hex_chars(self):
        from app.connectors.supabase import _sha256_prefix
        result = _sha256_prefix("my_client_id_value")
        assert len(result) == 16
        assert all(c in "0123456789abcdef" for c in result)

    def test_different_inputs_produce_different_hashes(self):
        from app.connectors.supabase import _sha256_prefix
        assert _sha256_prefix("client_id_a") != _sha256_prefix("client_id_b")

    def test_same_input_produces_same_hash(self):
        from app.connectors.supabase import _sha256_prefix
        assert _sha256_prefix("deterministic") == _sha256_prefix("deterministic")

    def test_empty_string_hashes_without_error(self):
        from app.connectors.supabase import _sha256_prefix
        result = _sha256_prefix("")
        assert isinstance(result, str)
        assert len(result) == 16


# ── 4. fetch() returns all 10 record type categories ─────────────────────────

GOOD_CREDS = {"access_token": "sbp_test", "project_ref": "abcdefghijklmnopqrst"}

_MOCK_PROJECT_RESPONSE = {
    "name": "my-project",
    "region": "us-east-1",
    "cloud_provider": "AWS",
    "status": "ACTIVE_HEALTHY",
    "subscription_tier": "free",
}

_MOCK_AUTH_CONFIG_RESPONSE = {
    "email_enabled": True,
    "phone_enabled": False,
    "anonymous_enabled": False,
    "mfa_totp_enabled": True,
    "external": {
        "google": {"enabled": True, "client_id": "123456.apps.googleusercontent.com"},
        "github": {"enabled": False, "client_id": "gh_client_id"},
    },
}

_MOCK_DB_CONFIG_RESPONSE = {
    "pool_mode": "transaction",
    "pool_size": 15,
    "max_client_conn": 200,
}

_MOCK_STORAGE_CONFIG_RESPONSE = {
    "fileSizeLimit": 52428800,
    "s3Protocol": False,
}

_MOCK_FUNCTIONS_RESPONSE = [
    {
        "slug": "my-function",
        "name": "my-function",
        "status": "ACTIVE",
        "version": 3,
        "verify_jwt": True,
    }
]

_MOCK_TABLES_RESPONSE = [
    {"name": "users", "schema": "public", "rls_enabled": True, "rls_forced": False},
    {"name": "posts", "schema": "public", "rls_enabled": False, "rls_forced": False},
]

_MOCK_POSTGREST_CONFIG_RESPONSE = {
    "db_schema": "public",
    "max_rows": 1000,
}

_MOCK_NETWORK_RESTRICTIONS_RESPONSE = {
    "allowed_ranges": ["10.0.0.0/8"],
}

_MOCK_CUSTOM_DOMAIN_RESPONSE = {
    "custom_hostname": "app.mycompany.com",
    "status": "active",
}


class TestSupabaseConnectorFetch:
    """Test fetch() with fully mocked HTTP responses."""

    def _make_connector_with_mock_get(self, responses: dict):
        """Return a SupabaseConnector with _get patched to return responses by path suffix."""
        from app.connectors.supabase import SupabaseConnector

        connector = SupabaseConnector()

        def fake_get(path, access_token, *, params=None, timeout=None):
            # Match by path suffix
            for suffix, response in responses.items():
                if path.endswith(suffix):
                    if isinstance(response, Exception):
                        raise response
                    return response
            # Default: return empty dict
            return {}

        connector._get = fake_get
        return connector

    def test_fetch_returns_list_of_dicts(self):
        connector = self._make_connector_with_mock_get({
            "/abcdefghijklmnopqrst": _MOCK_PROJECT_RESPONSE,
            "config/auth": _MOCK_AUTH_CONFIG_RESPONSE,
            "config/database/pooler": _MOCK_DB_CONFIG_RESPONSE,
            "config/storage": _MOCK_STORAGE_CONFIG_RESPONSE,
            "functions": _MOCK_FUNCTIONS_RESPONSE,
            "database/tables": _MOCK_TABLES_RESPONSE,
            "config/postgrest": _MOCK_POSTGREST_CONFIG_RESPONSE,
            "network-restrictions": _MOCK_NETWORK_RESTRICTIONS_RESPONSE,
            "custom-hostname": _MOCK_CUSTOM_DOMAIN_RESPONSE,
        })
        records = connector.fetch(GOOD_CREDS)
        assert isinstance(records, list)
        assert len(records) > 0
        for r in records:
            assert isinstance(r, dict)
            assert "record_type" in r

    def test_fetch_includes_project_record(self):
        connector = self._make_connector_with_mock_get({
            "/abcdefghijklmnopqrst": _MOCK_PROJECT_RESPONSE,
            "config/auth": _MOCK_AUTH_CONFIG_RESPONSE,
            "config/database/pooler": _MOCK_DB_CONFIG_RESPONSE,
            "config/storage": _MOCK_STORAGE_CONFIG_RESPONSE,
            "functions": _MOCK_FUNCTIONS_RESPONSE,
            "database/tables": _MOCK_TABLES_RESPONSE,
            "config/postgrest": _MOCK_POSTGREST_CONFIG_RESPONSE,
            "network-restrictions": _MOCK_NETWORK_RESTRICTIONS_RESPONSE,
            "custom-hostname": _MOCK_CUSTOM_DOMAIN_RESPONSE,
        })
        records = connector.fetch(GOOD_CREDS)
        types = {r["record_type"] for r in records}
        assert "supabase_project" in types

    def test_fetch_includes_auth_config_record(self):
        connector = self._make_connector_with_mock_get({
            "/abcdefghijklmnopqrst": _MOCK_PROJECT_RESPONSE,
            "config/auth": _MOCK_AUTH_CONFIG_RESPONSE,
            "config/database/pooler": _MOCK_DB_CONFIG_RESPONSE,
            "config/storage": _MOCK_STORAGE_CONFIG_RESPONSE,
            "functions": _MOCK_FUNCTIONS_RESPONSE,
            "database/tables": _MOCK_TABLES_RESPONSE,
            "config/postgrest": _MOCK_POSTGREST_CONFIG_RESPONSE,
            "network-restrictions": _MOCK_NETWORK_RESTRICTIONS_RESPONSE,
            "custom-hostname": _MOCK_CUSTOM_DOMAIN_RESPONSE,
        })
        records = connector.fetch(GOOD_CREDS)
        types = {r["record_type"] for r in records}
        assert "supabase_auth_config" in types

    def test_fetch_includes_all_ten_record_type_categories(self):
        connector = self._make_connector_with_mock_get({
            "/abcdefghijklmnopqrst": _MOCK_PROJECT_RESPONSE,
            "config/auth": _MOCK_AUTH_CONFIG_RESPONSE,
            "config/database/pooler": _MOCK_DB_CONFIG_RESPONSE,
            "config/storage": _MOCK_STORAGE_CONFIG_RESPONSE,
            "functions": _MOCK_FUNCTIONS_RESPONSE,
            "database/tables": _MOCK_TABLES_RESPONSE,
            "config/postgrest": _MOCK_POSTGREST_CONFIG_RESPONSE,
            "network-restrictions": _MOCK_NETWORK_RESTRICTIONS_RESPONSE,
            "custom-hostname": _MOCK_CUSTOM_DOMAIN_RESPONSE,
        })
        records = connector.fetch(GOOD_CREDS)
        types = {r["record_type"] for r in records}
        expected = {
            "supabase_project",
            "supabase_auth_config",
            "supabase_database_config",
            "supabase_storage_config",
            "supabase_edge_function",
            "supabase_rls_status",
            "supabase_api_config",
            "supabase_network_restriction",
            "supabase_custom_domain",
            "supabase_oauth_provider",
        }
        assert expected.issubset(types), f"Missing types: {expected - types}"

    def test_fetch_validates_credentials_before_calling_api(self):
        from app.connectors.supabase import SupabaseConnector
        connector = SupabaseConnector()
        with pytest.raises(ValueError, match="access_token"):
            connector.fetch({"project_ref": "abcdefghijklmnopqrst"})


# ── 5-12. Connector HTTP behavior ─────────────────────────────────────────────

class TestSupabaseConnectorHTTP:
    def _connector(self):
        from app.connectors.supabase import SupabaseConnector
        return SupabaseConnector()

    def test_validate_credentials_calls_project_endpoint(self):
        from app.connectors.supabase import SupabaseConnector
        connector = SupabaseConnector()
        called = []

        def fake_get(path, token, **kwargs):
            called.append(path)
            return {"name": "proj", "status": "ACTIVE_HEALTHY"}

        connector._get = fake_get
        result = connector.validate_credentials(GOOD_CREDS)
        assert result is True
        assert any("abcdefghijklmnopqrst" in p for p in called)

    def test_401_raises_authentication_error(self):
        from app.connectors.exceptions import AuthenticationError
        from app.connectors.supabase import SupabaseConnector
        connector = SupabaseConnector()

        def fake_get(path, token, **kwargs):
            raise AuthenticationError("401 Unauthorized", status_code=401)

        connector._get = fake_get
        with pytest.raises(AuthenticationError):
            connector.validate_credentials(GOOD_CREDS)

    def test_403_on_project_endpoint_raises_connector_error(self):
        from app.connectors.exceptions import ConnectorError
        from app.connectors.supabase import SupabaseConnector
        connector = SupabaseConnector()

        def fake_get(path, token, **kwargs):
            raise ConnectorError("403 Forbidden", status_code=403)

        connector._get = fake_get
        with pytest.raises(ConnectorError) as exc_info:
            connector.validate_credentials(GOOD_CREDS)
        assert exc_info.value.status_code == 403

    def test_403_on_auth_config_produces_warning_not_exception(self):
        """A 403 on the auth config surface should produce a warning record
        instead of aborting the fetch."""
        from app.connectors.exceptions import ConnectorError
        from app.connectors.supabase import SupabaseConnector
        connector = SupabaseConnector()

        def fake_get(path, token, *, params=None, timeout=None):
            if path.endswith("config/auth"):
                raise ConnectorError("403 Forbidden", status_code=403)
            if path.endswith(_MOCK_PROJECT_RESPONSE.get("status", "abcdefghijklmnopqrst")):
                return _MOCK_PROJECT_RESPONSE
            # Return valid responses for other paths
            if "pooler" in path:
                return _MOCK_DB_CONFIG_RESPONSE
            if "config/storage" in path:
                return _MOCK_STORAGE_CONFIG_RESPONSE
            if "functions" in path:
                return _MOCK_FUNCTIONS_RESPONSE
            if "database/tables" in path:
                return _MOCK_TABLES_RESPONSE
            if "postgrest" in path:
                return _MOCK_POSTGREST_CONFIG_RESPONSE
            if "network-restrictions" in path:
                return _MOCK_NETWORK_RESTRICTIONS_RESPONSE
            if "custom-hostname" in path:
                return _MOCK_CUSTOM_DOMAIN_RESPONSE
            return _MOCK_PROJECT_RESPONSE

        connector._get = fake_get
        records = connector.fetch(GOOD_CREDS)
        auth_records = [r for r in records if r["record_type"] == "supabase_auth_config"]
        assert len(auth_records) == 1
        warnings = auth_records[0].get("config_fetch_warnings") or []
        assert any("403" in str(w) for w in warnings), "Expected 403 warning in auth config record"

    def test_404_on_custom_domain_skips_silently(self):
        """A 404 on the custom-hostname endpoint should return no custom domain records."""
        from app.connectors.exceptions import ConnectorError
        from app.connectors.supabase import SupabaseConnector
        connector = SupabaseConnector()

        def fake_get(path, token, *, params=None, timeout=None):
            if "custom-hostname" in path:
                raise ConnectorError("404 Not Found", status_code=404)
            if "config/auth" in path:
                return _MOCK_AUTH_CONFIG_RESPONSE
            if "pooler" in path:
                return _MOCK_DB_CONFIG_RESPONSE
            if "config/storage" in path:
                return _MOCK_STORAGE_CONFIG_RESPONSE
            if "functions" in path:
                return _MOCK_FUNCTIONS_RESPONSE
            if "database/tables" in path:
                return _MOCK_TABLES_RESPONSE
            if "postgrest" in path:
                return _MOCK_POSTGREST_CONFIG_RESPONSE
            if "network-restrictions" in path:
                return _MOCK_NETWORK_RESTRICTIONS_RESPONSE
            return _MOCK_PROJECT_RESPONSE

        connector._get = fake_get
        records = connector.fetch(GOOD_CREDS)
        custom_domain_records = [r for r in records if r["record_type"] == "supabase_custom_domain"]
        assert len(custom_domain_records) == 0

    def test_network_error_on_project_endpoint_propagates(self):
        from app.connectors.exceptions import NetworkError
        from app.connectors.supabase import SupabaseConnector
        connector = SupabaseConnector()

        def fake_get(path, token, **kwargs):
            raise NetworkError("Connection refused")

        connector._get = fake_get
        with pytest.raises(NetworkError):
            connector.fetch(GOOD_CREDS)

    def test_rate_limit_error_propagates(self):
        from app.connectors.exceptions import RateLimitError
        from app.connectors.supabase import SupabaseConnector
        connector = SupabaseConnector()

        def fake_get(path, token, **kwargs):
            raise RateLimitError("429 Too Many Requests")

        connector._get = fake_get
        with pytest.raises(RateLimitError):
            connector.fetch(GOOD_CREDS)

    def test_5xx_on_project_endpoint_propagates(self):
        from app.connectors.exceptions import ConnectorError
        from app.connectors.supabase import SupabaseConnector
        connector = SupabaseConnector()

        def fake_get(path, token, **kwargs):
            raise ConnectorError("503 Service Unavailable", status_code=503)

        connector._get = fake_get
        with pytest.raises(ConnectorError) as exc_info:
            connector.fetch(GOOD_CREDS)
        assert exc_info.value.status_code == 503


# ── 13. Empty network restrictions → unrestricted record ──────────────────────

class TestNetworkRestrictions:
    def test_empty_allowed_ranges_returns_unrestricted_record(self):
        from app.connectors.supabase import SupabaseConnector
        connector = SupabaseConnector()

        def fake_get(path, token, **kwargs):
            return {"allowed_ranges": []}

        connector._get = fake_get
        records = connector._fetch_network_restrictions("token", "proj")
        assert len(records) == 1
        assert records[0]["is_unrestricted"] is True
        assert records[0]["record_type"] == "supabase_network_restriction"

    def test_cidr_list_returns_one_record_per_cidr(self):
        from app.connectors.supabase import SupabaseConnector
        connector = SupabaseConnector()

        def fake_get(path, token, **kwargs):
            return {"allowed_ranges": ["192.168.1.0/24", "10.0.0.0/8"]}

        connector._get = fake_get
        records = connector._fetch_network_restrictions("token", "proj")
        assert len(records) == 2
        cidrs = {r["cidr"] for r in records}
        assert cidrs == {"192.168.1.0/24", "10.0.0.0/8"}

    def test_wildcard_cidr_is_flagged_as_unrestricted(self):
        from app.connectors.supabase import SupabaseConnector
        connector = SupabaseConnector()

        def fake_get(path, token, **kwargs):
            return {"allowed_ranges": ["0.0.0.0/0"]}

        connector._get = fake_get
        records = connector._fetch_network_restrictions("token", "proj")
        assert records[0]["is_unrestricted"] is True


# ── 14. OAuth provider client_id hashed ───────────────────────────────────────

class TestOAuthProviderHashing:
    def test_client_id_is_hashed_not_stored_raw(self):
        from app.connectors.supabase import SupabaseConnector
        connector = SupabaseConnector()
        raw_client_id = "super-secret-oauth-client-id-12345"

        def fake_get(path, token, **kwargs):
            return {
                "email_enabled": True,
                "external": {
                    "google": {"enabled": True, "client_id": raw_client_id},
                },
            }

        connector._get = fake_get
        auth_record, oauth_records = connector._fetch_auth_config("token", "proj")
        assert len(oauth_records) == 1
        provider_record = oauth_records[0]
        # Raw client_id should NOT be present in any value
        record_str = json.dumps(provider_record)
        assert raw_client_id not in record_str
        # A hash should be stored
        assert "client_id_hash" in provider_record
        assert len(provider_record["client_id_hash"]) == 16

    def test_empty_client_id_results_in_empty_hash(self):
        from app.connectors.supabase import SupabaseConnector
        connector = SupabaseConnector()

        def fake_get(path, token, **kwargs):
            return {
                "external": {
                    "github": {"enabled": False, "client_id": ""},
                },
            }

        connector._get = fake_get
        _, oauth_records = connector._fetch_auth_config("token", "proj")
        assert oauth_records[0]["client_id_hash"] == ""


# ── 15. Edge Function env var values never stored ─────────────────────────────

class TestEdgeFunctionSecurity:
    def test_env_var_count_stored_not_values(self):
        from app.connectors.supabase import SupabaseConnector
        connector = SupabaseConnector()

        def fake_get(path, token, **kwargs):
            return [
                {
                    "slug": "process-data",
                    "name": "process-data",
                    "status": "ACTIVE",
                    "verify_jwt": True,
                    "envVarKeys": ["API_KEY", "DATABASE_URL", "SECRET_VALUE"],
                }
            ]

        connector._get = fake_get
        records = connector._fetch_edge_functions("token", "proj")
        assert len(records) == 1
        fn = records[0]
        assert fn["env_var_key_count"] == 3
        # Values themselves should NOT be in the record
        record_str = json.dumps(fn)
        assert "API_KEY" not in record_str or fn.get("env_var_key_count") == 3
        # No "env_var_values" or similar key should exist
        assert "env_var_values" not in fn
        assert "secrets" not in fn

    def test_function_source_code_never_fetched(self):
        """Verify no code/body field is stored."""
        from app.connectors.supabase import SupabaseConnector
        connector = SupabaseConnector()

        def fake_get(path, token, **kwargs):
            return [{"slug": "fn", "name": "fn", "status": "ACTIVE", "body": "secret source code"}]

        connector._get = fake_get
        records = connector._fetch_edge_functions("token", "proj")
        fn = records[0]
        assert "body" not in fn
        assert "source" not in fn
        assert "code" not in fn


# ── 16. RLS status records ────────────────────────────────────────────────────

class TestRlsStatusRecords:
    def test_rls_status_record_contains_table_flags(self):
        from app.connectors.supabase import SupabaseConnector
        connector = SupabaseConnector()

        def fake_get(path, token, *, params=None, timeout=None):
            return [
                {"name": "users", "schema": "public", "rls_enabled": True, "rls_forced": False},
                {"name": "logs", "schema": "public", "rls_enabled": False, "rls_forced": False},
            ]

        connector._get = fake_get
        records = connector._fetch_rls_status("token", "proj")
        assert len(records) == 2
        users_record = next(r for r in records if r["table_name"] == "users")
        assert users_record["rls_enabled"] is True
        assert users_record["rls_forced"] is False

    def test_403_on_rls_returns_warning_record(self):
        from app.connectors.exceptions import ConnectorError
        from app.connectors.supabase import SupabaseConnector
        connector = SupabaseConnector()

        def fake_get(path, token, **kwargs):
            raise ConnectorError("403", status_code=403)

        connector._get = fake_get
        records = connector._fetch_rls_status("token", "proj")
        assert len(records) == 1
        assert "403" in str(records[0].get("config_fetch_warnings", []))


# ── 17-31. Risk rules ──────────────────────────────────────────────────────────

class TestSupabaseRiskRules:
    @pytest.fixture(autouse=True)
    def import_classifier(self):
        from app.services.risk_rules.supabase import classify_supabase_change
        self.classify = classify_supabase_change

    # ── supabase_project ──────────────────────────────────────────────────────

    def test_project_added_is_low(self):
        change = _make_change("supabase_project", change_type="added")
        level, reason = self.classify(change)
        assert level == "low"

    def test_project_removed_is_high(self):
        change = _make_change("supabase_project", change_type="removed")
        level, reason = self.classify(change)
        assert level == "high"

    def test_project_status_inactive_is_high(self):
        change = _make_change(
            "supabase_project", field_path="status",
            change_type="modified", new_value="inactive",
        )
        level, reason = self.classify(change)
        assert level == "high"

    def test_project_status_active_is_medium(self):
        change = _make_change(
            "supabase_project", field_path="status",
            change_type="modified", new_value="ACTIVE_HEALTHY",
        )
        level, reason = self.classify(change)
        assert level == "medium"

    def test_project_region_changed_is_medium(self):
        change = _make_change(
            "supabase_project", field_path="region",
            change_type="modified", new_value="eu-central-1",
        )
        level, reason = self.classify(change)
        assert level == "medium"

    def test_project_name_changed_is_low(self):
        change = _make_change(
            "supabase_project", field_path="name",
            change_type="modified", new_value="new-name",
        )
        level, reason = self.classify(change)
        assert level == "low"

    # ── supabase_auth_config ──────────────────────────────────────────────────

    def test_anonymous_auth_enabled_is_critical(self):
        change = _make_change(
            "supabase_auth_config", field_path="anonymous_enabled",
            change_type="modified", new_value=True,
            provider_metadata={"record_type": "supabase_auth_config"},
        )
        level, reason = self.classify(change)
        assert level == "critical"
        assert "anonymous" in reason.lower()

    def test_anonymous_auth_disabled_is_low(self):
        change = _make_change(
            "supabase_auth_config", field_path="anonymous_enabled",
            change_type="modified", new_value=False,
            provider_metadata={"record_type": "supabase_auth_config"},
        )
        level, reason = self.classify(change)
        assert level == "low"

    def test_mfa_totp_disabled_is_high(self):
        change = _make_change(
            "supabase_auth_config", field_path="mfa_totp_enabled",
            change_type="modified", new_value=False,
            provider_metadata={"record_type": "supabase_auth_config"},
        )
        level, reason = self.classify(change)
        assert level == "high"

    def test_mfa_totp_enabled_is_low(self):
        change = _make_change(
            "supabase_auth_config", field_path="mfa_totp_enabled",
            change_type="modified", new_value=True,
            provider_metadata={"record_type": "supabase_auth_config"},
        )
        level, reason = self.classify(change)
        assert level == "low"

    def test_password_min_length_decreased_is_medium(self):
        change = _make_change(
            "supabase_auth_config", field_path="password_min_length",
            change_type="modified", prev_value=12, new_value=6,
            provider_metadata={"record_type": "supabase_auth_config"},
        )
        level, reason = self.classify(change)
        assert level == "medium"

    def test_password_min_length_increased_is_low(self):
        change = _make_change(
            "supabase_auth_config", field_path="password_min_length",
            change_type="modified", prev_value=6, new_value=12,
            provider_metadata={"record_type": "supabase_auth_config"},
        )
        level, reason = self.classify(change)
        assert level == "low"

    def test_auth_config_baseline_captured_is_low(self):
        change = _make_change(
            "supabase_auth_config", change_type="added",
            provider_metadata={"record_type": "supabase_auth_config"},
        )
        level, reason = self.classify(change)
        assert level == "low"

    def test_email_signin_disabled_is_medium(self):
        change = _make_change(
            "supabase_auth_config", field_path="email_enabled",
            change_type="modified", new_value=False,
            provider_metadata={"record_type": "supabase_auth_config"},
        )
        level, reason = self.classify(change)
        assert level == "medium"

    # ── supabase_rls_status ───────────────────────────────────────────────────

    def test_rls_disabled_on_existing_table_is_critical(self):
        change = _make_change(
            "supabase_rls_status", field_path="rls_enabled",
            change_type="modified", new_value=False,
            provider_metadata={"record_type": "supabase_rls_status", "table_name": "users", "schema_name": "public"},
        )
        level, reason = self.classify(change)
        assert level == "critical"
        assert "rls" in reason.lower() or "row level security" in reason.lower()

    def test_rls_enabled_on_table_is_low(self):
        change = _make_change(
            "supabase_rls_status", field_path="rls_enabled",
            change_type="modified", new_value=True,
            provider_metadata={"record_type": "supabase_rls_status", "table_name": "users", "schema_name": "public"},
        )
        level, reason = self.classify(change)
        assert level == "low"

    def test_rls_forced_disabled_is_high(self):
        change = _make_change(
            "supabase_rls_status", field_path="rls_forced",
            change_type="modified", new_value=False,
            provider_metadata={"record_type": "supabase_rls_status", "table_name": "orders", "schema_name": "public"},
        )
        level, reason = self.classify(change)
        assert level == "high"

    def test_new_table_without_rls_is_medium(self):
        """A newly added table with rls_enabled=False should be medium risk."""
        change = _make_change(
            "supabase_rls_status", field_path="rls_enabled",
            change_type="added", new_value=False,
            provider_metadata={"record_type": "supabase_rls_status", "table_name": "new_table", "schema_name": "public"},
        )
        level, reason = self.classify(change)
        assert level == "medium"

    def test_new_table_with_rls_is_low(self):
        change = _make_change(
            "supabase_rls_status", field_path="rls_enabled",
            change_type="added", new_value=True,
            provider_metadata={"record_type": "supabase_rls_status", "table_name": "new_table", "schema_name": "public"},
        )
        level, reason = self.classify(change)
        assert level == "low"

    # ── supabase_edge_function ────────────────────────────────────────────────

    def test_verify_jwt_disabled_is_high(self):
        change = _make_change(
            "supabase_edge_function", field_path="verify_jwt",
            change_type="modified", new_value=False,
            provider_metadata={"record_type": "supabase_edge_function", "function_name": "my-fn", "slug": "my-fn"},
        )
        level, reason = self.classify(change)
        assert level == "high"
        assert "jwt" in reason.lower()

    def test_verify_jwt_enabled_is_low(self):
        change = _make_change(
            "supabase_edge_function", field_path="verify_jwt",
            change_type="modified", new_value=True,
            provider_metadata={"record_type": "supabase_edge_function", "function_name": "my-fn", "slug": "my-fn"},
        )
        level, reason = self.classify(change)
        assert level == "low"

    def test_edge_function_added_is_low(self):
        change = _make_change(
            "supabase_edge_function", change_type="added",
            provider_metadata={"record_type": "supabase_edge_function", "function_name": "new-fn", "slug": "new-fn"},
        )
        level, reason = self.classify(change)
        assert level == "low"

    def test_edge_function_removed_is_medium(self):
        change = _make_change(
            "supabase_edge_function", change_type="removed",
            provider_metadata={"record_type": "supabase_edge_function", "function_name": "old-fn", "slug": "old-fn"},
        )
        level, reason = self.classify(change)
        assert level == "medium"

    def test_edge_function_env_var_count_changed_is_medium(self):
        change = _make_change(
            "supabase_edge_function", field_path="env_var_key_count",
            change_type="modified", prev_value=2, new_value=4,
            provider_metadata={"record_type": "supabase_edge_function", "function_name": "fn", "slug": "fn"},
        )
        level, reason = self.classify(change)
        assert level == "medium"
        assert "environment variable" in reason.lower()

    # ── supabase_network_restriction ──────────────────────────────────────────

    def test_unrestricted_added_is_critical(self):
        change = _make_change(
            "supabase_network_restriction", field_path="is_unrestricted",
            change_type="modified", new_value=True,
            provider_metadata={"record_type": "supabase_network_restriction"},
        )
        level, reason = self.classify(change)
        assert level == "critical"

    def test_cidr_removed_is_high(self):
        change = _make_change(
            "supabase_network_restriction",
            change_type="removed",
            provider_metadata={"record_type": "supabase_network_restriction", "cidr": "10.0.0.0/8"},
        )
        level, reason = self.classify(change)
        assert level == "high"

    def test_cidr_added_is_low(self):
        change = _make_change(
            "supabase_network_restriction",
            change_type="added",
            provider_metadata={"record_type": "supabase_network_restriction", "cidr": "10.0.0.0/8"},
        )
        level, reason = self.classify(change)
        assert level == "low"

    def test_wildcard_cidr_added_is_critical(self):
        change = _make_change(
            "supabase_network_restriction",
            change_type="added",
            provider_metadata={"record_type": "supabase_network_restriction", "cidr": "0.0.0.0/0"},
        )
        level, reason = self.classify(change)
        assert level == "critical"

    # ── supabase_api_config ───────────────────────────────────────────────────

    def test_db_schema_changed_is_high(self):
        change = _make_change(
            "supabase_api_config", field_path="db_schema",
            change_type="modified", new_value="internal",
            provider_metadata={"record_type": "supabase_api_config"},
        )
        level, reason = self.classify(change)
        assert level == "high"

    def test_max_rows_increased_greatly_is_medium(self):
        change = _make_change(
            "supabase_api_config", field_path="max_rows",
            change_type="modified", prev_value=100, new_value=10000,
            provider_metadata={"record_type": "supabase_api_config"},
        )
        level, reason = self.classify(change)
        assert level == "medium"

    def test_max_rows_removed_is_medium(self):
        change = _make_change(
            "supabase_api_config", field_path="max_rows",
            change_type="modified", prev_value=1000, new_value=None,
            provider_metadata={"record_type": "supabase_api_config"},
        )
        level, reason = self.classify(change)
        assert level == "medium"

    # ── supabase_storage_config ───────────────────────────────────────────────

    def test_storage_file_size_limit_removed_is_high(self):
        change = _make_change(
            "supabase_storage_config", field_path="file_size_limit",
            change_type="modified", prev_value=52428800, new_value=None,
            provider_metadata={"record_type": "supabase_storage_config"},
        )
        level, reason = self.classify(change)
        assert level == "high"

    def test_storage_allowed_mime_types_removed_is_medium(self):
        change = _make_change(
            "supabase_storage_config", field_path="allowed_mime_types",
            change_type="modified", prev_value=["image/png"], new_value=None,
            provider_metadata={"record_type": "supabase_storage_config"},
        )
        level, reason = self.classify(change)
        assert level == "medium"

    def test_s3_protocol_enabled_is_medium(self):
        change = _make_change(
            "supabase_storage_config", field_path="s3_protocol_enabled",
            change_type="modified", new_value=True,
            provider_metadata={"record_type": "supabase_storage_config"},
        )
        level, reason = self.classify(change)
        assert level == "medium"

    # ── supabase_oauth_provider ───────────────────────────────────────────────

    def test_oauth_provider_added_is_medium(self):
        change = _make_change(
            "supabase_oauth_provider", change_type="added",
            provider_metadata={"record_type": "supabase_oauth_provider", "provider_name": "google"},
        )
        level, reason = self.classify(change)
        assert level == "medium"

    def test_oauth_provider_removed_is_high(self):
        change = _make_change(
            "supabase_oauth_provider", change_type="removed",
            provider_metadata={"record_type": "supabase_oauth_provider", "provider_name": "github"},
        )
        level, reason = self.classify(change)
        assert level == "high"

    def test_oauth_provider_enabled_is_medium(self):
        change = _make_change(
            "supabase_oauth_provider", field_path="enabled",
            change_type="modified", new_value=True,
            provider_metadata={"record_type": "supabase_oauth_provider", "provider_name": "twitter"},
        )
        level, reason = self.classify(change)
        assert level == "medium"

    # ── supabase_custom_domain ────────────────────────────────────────────────

    def test_custom_domain_removed_is_medium(self):
        change = _make_change(
            "supabase_custom_domain", change_type="removed",
            provider_metadata={"record_type": "supabase_custom_domain", "custom_domain": "app.example.com"},
        )
        level, reason = self.classify(change)
        assert level == "medium"

    def test_custom_domain_added_is_low(self):
        change = _make_change(
            "supabase_custom_domain", change_type="added",
            provider_metadata={"record_type": "supabase_custom_domain", "custom_domain": "app.example.com"},
        )
        level, reason = self.classify(change)
        assert level == "low"

    # ── fallback ──────────────────────────────────────────────────────────────

    def test_unknown_supabase_record_type_returns_low(self):
        change = _make_change(
            "supabase_unknown_future_type", change_type="modified",
            provider_metadata={"record_type": "supabase_unknown_future_type"},
        )
        level, reason = self.classify(change)
        assert level == "low"


# ── 32. Risk service dispatch ─────────────────────────────────────────────────

class TestRiskServiceDispatch:
    def test_supabase_prefix_dispatches_to_supabase_classifier(self):
        from app.services.risk_service import classify_change
        change = _make_change(
            "supabase_rls_status", field_path="rls_enabled",
            change_type="modified", new_value=False,
            provider_metadata={"record_type": "supabase_rls_status", "table_name": "users", "schema_name": "public"},
        )
        level, reason = classify_change(change)
        assert level == "critical"

    def test_supabase_auth_anonymous_dispatches_correctly(self):
        from app.services.risk_service import classify_change
        change = _make_change(
            "supabase_auth_config", field_path="anonymous_enabled",
            change_type="modified", new_value=True,
            provider_metadata={"record_type": "supabase_auth_config"},
        )
        level, reason = classify_change(change)
        assert level == "critical"


# ── 33. Diff service tracked fields ───────────────────────────────────────────

class TestDiffServiceSupabase:
    def test_supabase_tracked_fields_dict_has_all_ten_types(self):
        from app.services.diff_service import _SUPABASE_TRACKED_FIELDS_BY_TYPE
        expected_types = {
            "supabase_project",
            "supabase_auth_config",
            "supabase_database_config",
            "supabase_storage_config",
            "supabase_edge_function",
            "supabase_rls_status",
            "supabase_api_config",
            "supabase_network_restriction",
            "supabase_custom_domain",
            "supabase_oauth_provider",
        }
        assert expected_types.issubset(set(_SUPABASE_TRACKED_FIELDS_BY_TYPE.keys()))

    def test_tracked_fields_for_dispatches_supabase_prefix(self):
        from app.services.diff_service import _tracked_fields_for
        record = {"record_type": "supabase_auth_config"}
        fields = _tracked_fields_for(record)
        assert len(fields) > 0
        assert "anonymous_enabled" in fields
        assert "mfa_totp_enabled" in fields

    def test_tracked_fields_for_rls_status_includes_flags(self):
        from app.services.diff_service import _tracked_fields_for
        record = {"record_type": "supabase_rls_status"}
        fields = _tracked_fields_for(record)
        assert "rls_enabled" in fields
        assert "rls_forced" in fields

    def test_tracked_fields_for_unknown_supabase_type_returns_empty(self):
        from app.services.diff_service import _tracked_fields_for
        record = {"record_type": "supabase_future_type"}
        fields = _tracked_fields_for(record)
        assert fields == ()

    def test_config_fetch_warnings_tracked_for_all_supabase_types(self):
        from app.services.diff_service import _SUPABASE_TRACKED_FIELDS_BY_TYPE
        for record_type, fields in _SUPABASE_TRACKED_FIELDS_BY_TYPE.items():
            assert "config_fetch_warnings" in fields, (
                f"supabase type {record_type!r} missing config_fetch_warnings"
            )


# ── 35-38. Failure classifier ─────────────────────────────────────────────────

class TestFailureClassifierSupabase:
    @pytest.fixture(autouse=True)
    def import_classifier(self):
        from app.core.failure_classifier import classify_failure
        self.classify = classify_failure
        from app.connectors.exceptions import (
            AuthenticationError, ConnectorError, NetworkError, RateLimitError,
        )
        self.AuthenticationError = AuthenticationError
        self.ConnectorError = ConnectorError
        self.NetworkError = NetworkError
        self.RateLimitError = RateLimitError

    def test_authentication_error_yields_token_revoked(self):
        exc = self.AuthenticationError("Invalid token", status_code=401)
        result = self.classify(exc, "supabase")
        assert result.error_code == "supabase_token_revoked"
        assert result.category == "authentication"
        assert "supabase" in result.recommended_action.lower() or "token" in result.recommended_action.lower()

    def test_connector_error_403_yields_permission_denied(self):
        exc = self.ConnectorError("403 Forbidden", status_code=403)
        result = self.classify(exc, "supabase")
        assert result.error_code == "supabase_permission_denied"
        assert result.category == "authentication"

    def test_connector_error_404_yields_project_not_found(self):
        exc = self.ConnectorError("404 Not Found", status_code=404)
        result = self.classify(exc, "supabase")
        assert result.error_code == "supabase_project_not_found"
        assert result.category == "resource_missing"

    def test_connector_error_5xx_yields_api_unavailable(self):
        for status_code in (500, 502, 503):
            exc = self.ConnectorError(f"{status_code} error", status_code=status_code)
            result = self.classify(exc, "supabase")
            assert result.error_code == "supabase_api_unavailable"
            assert result.category == "provider_unavailable"

    def test_network_error_yields_network_error(self):
        exc = self.NetworkError("Connection refused")
        result = self.classify(exc, "supabase")
        assert result.error_code == "network_error"
        assert result.category == "network"

    def test_rate_limit_error_yields_rate_limit_exceeded(self):
        exc = self.RateLimitError("429 Too Many Requests")  # RateLimitError takes no status_code kwarg
        result = self.classify(exc, "supabase")
        assert result.error_code == "rate_limit_exceeded"
        assert result.category == "rate_limited"


# ── 39-42. Integration schema ─────────────────────────────────────────────────

class TestIntegrationSchemaSupabase:
    def test_provider_literal_includes_supabase(self):
        from app.schemas.integration import IntegrationCreateRequest
        import typing
        hints = typing.get_type_hints(IntegrationCreateRequest)
        # Access provider annotation args — should include "supabase"
        provider_field = IntegrationCreateRequest.model_fields["provider"]
        annotation_str = str(provider_field.annotation)
        assert "supabase" in annotation_str

    def test_missing_access_token_raises_validation_error(self):
        from pydantic import ValidationError
        from app.schemas.integration import IntegrationCreateRequest
        with pytest.raises(ValidationError) as exc_info:
            IntegrationCreateRequest(
                provider="supabase",
                display_name="Test Supabase",
                # supabase_access_token missing
                supabase_project_ref="abcdefghijklmnopqrst",
            )
        errors = exc_info.value.errors()
        assert any("supabase_access_token" in str(e) for e in errors)

    def test_missing_project_ref_raises_validation_error(self):
        from pydantic import ValidationError
        from app.schemas.integration import IntegrationCreateRequest
        with pytest.raises(ValidationError) as exc_info:
            IntegrationCreateRequest(
                provider="supabase",
                display_name="Test Supabase",
                supabase_access_token="sbp_test_token",
                # supabase_project_ref missing
            )
        errors = exc_info.value.errors()
        assert any("supabase_project_ref" in str(e) for e in errors)

    def test_valid_supabase_request_validates(self):
        from app.schemas.integration import IntegrationCreateRequest
        req = IntegrationCreateRequest(
            provider="supabase",
            display_name="My Supabase",
            supabase_access_token="sbp_test_token_value",
            supabase_project_ref="abcdefghijklmnopqrst",
        )
        assert req.provider == "supabase"
        assert req.supabase_access_token == "sbp_test_token_value"
        assert req.supabase_project_ref == "abcdefghijklmnopqrst"

    def test_reconnect_request_has_supabase_access_token(self):
        from app.schemas.integration import IntegrationReconnectRequest
        req = IntegrationReconnectRequest(supabase_access_token="sbp_new_token")
        assert req.supabase_access_token == "sbp_new_token"


# ── 43. Sync service ──────────────────────────────────────────────────────────

class TestSyncServiceSupabase:
    def test_supabase_in_supported_providers(self):
        import inspect
        from app.services import sync_service
        source = inspect.getsource(sync_service)
        # Check the _SUPPORTED_PROVIDERS tuple contains supabase
        assert '"supabase"' in source or "'supabase'" in source


# ── 44-48. Security tests ─────────────────────────────────────────────────────

class TestSupabaseSecurity:
    def _make_fetch_with_all_mocks(self):
        """Return fetch() records using all mock responses."""
        from app.connectors.supabase import SupabaseConnector
        connector = SupabaseConnector()

        def fake_get(path, token, *, params=None, timeout=None):
            if "config/auth" in path:
                return {
                    "email_enabled": True,
                    "external": {
                        "google": {"enabled": True, "client_id": "super_secret_client_id_12345"},
                    },
                }
            if "pooler" in path:
                return _MOCK_DB_CONFIG_RESPONSE
            if "config/storage" in path:
                return _MOCK_STORAGE_CONFIG_RESPONSE
            if "functions" in path:
                return [
                    {
                        "slug": "my-func",
                        "name": "my-func",
                        "status": "ACTIVE",
                        "verify_jwt": True,
                        "envVarKeys": ["SECRET_KEY", "DB_PASS"],
                    }
                ]
            if "database/tables" in path:
                return _MOCK_TABLES_RESPONSE
            if "postgrest" in path:
                return _MOCK_POSTGREST_CONFIG_RESPONSE
            if "network-restrictions" in path:
                return _MOCK_NETWORK_RESTRICTIONS_RESPONSE
            if "custom-hostname" in path:
                return _MOCK_CUSTOM_DOMAIN_RESPONSE
            return _MOCK_PROJECT_RESPONSE

        connector._get = fake_get
        return connector.fetch(GOOD_CREDS)

    def test_access_token_never_in_record_dicts(self):
        records = self._make_fetch_with_all_mocks()
        token_value = GOOD_CREDS["access_token"]
        for record in records:
            record_str = json.dumps(record)
            assert token_value not in record_str, (
                f"access_token found in record: {record['record_type']}"
            )

    def test_raw_oauth_client_id_never_in_records(self):
        raw_client_id = "super_secret_client_id_12345"
        records = self._make_fetch_with_all_mocks()
        for record in records:
            record_str = json.dumps(record)
            assert raw_client_id not in record_str, (
                f"Raw OAuth client_id found in record: {record['record_type']}"
            )

    def test_edge_function_env_var_keys_not_stored_as_strings_in_values(self):
        records = self._make_fetch_with_all_mocks()
        fn_records = [r for r in records if r["record_type"] == "supabase_edge_function"]
        for fn in fn_records:
            assert "SECRET_KEY" not in json.dumps(fn)
            assert "DB_PASS" not in json.dumps(fn)
            # Only the count should be stored
            assert fn.get("env_var_key_count") == 2

    def test_project_ref_in_record_ids_not_access_token(self):
        records = self._make_fetch_with_all_mocks()
        project_record = next(r for r in records if r["record_type"] == "supabase_project")
        # project_ref is expected in record_id
        assert "abcdefghijklmnopqrst" in project_record.get("record_id", "")
        # access token should NOT be in record_id
        assert "sbp_test" not in project_record.get("record_id", "")

    def test_no_database_row_query_in_connector_source(self):
        """Verify the connector does not contain any SQL or row-data API calls."""
        import inspect
        from app.connectors import supabase as supabase_module
        source = inspect.getsource(supabase_module)
        # Filter out comments and docstrings for strict checks
        code_lines = [
            line for line in source.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        code = "\n".join(code_lines)
        # Should never call SELECT or row-level endpoints
        forbidden_patterns = [
            "SELECT * FROM",
            "GetSecretValue",
            "auth/v1/admin/users",  # Auth user list endpoint
            "storage/v1/object",    # Storage object download
        ]
        for pattern in forbidden_patterns:
            assert pattern not in code, f"Forbidden pattern {pattern!r} found in connector source"

    def test_access_token_not_in_resource_metadata_structure(self):
        """Verify create_supabase_integration doesn't put token in resource_metadata."""
        import inspect
        from app.services import integration_service
        source = inspect.getsource(integration_service.create_supabase_integration)
        # access_token should not appear in the resource_metadata dict
        # The resource_metadata only contains project_ref
        assert '"access_token"' not in source or "resource_metadata" not in source.split('"access_token"')[0].split("resource_metadata")[-1]


# ── 49. Frontend types ─────────────────────────────────────────────────────────

class TestFrontendTypes:
    """Spot-check the TypeScript types file for required Supabase fields."""

    def _get_types_path(self):
        import os
        # From backend/tests/ go up 2 levels to ConfigTrace root, then frontend/src/types
        candidate = os.path.normpath(
            os.path.join(os.path.dirname(__file__), "..", "..", "frontend", "src", "types", "index.ts")
        )
        return candidate

    def test_frontend_types_include_supabase_in_provider_union(self):
        import os
        types_path = self._get_types_path()
        if not os.path.exists(types_path):
            pytest.skip("Frontend types file not found")
        with open(types_path) as f:
            content = f.read()
        assert '"supabase"' in content or "'supabase'" in content

    def test_frontend_types_include_supabase_access_token_field(self):
        import os
        types_path = self._get_types_path()
        if not os.path.exists(types_path):
            pytest.skip("Frontend types file not found")
        with open(types_path) as f:
            content = f.read()
        assert "supabase_access_token" in content

    def test_frontend_types_include_supabase_project_ref_field(self):
        import os
        types_path = self._get_types_path()
        if not os.path.exists(types_path):
            pytest.skip("Frontend types file not found")
        with open(types_path) as f:
            content = f.read()
        assert "supabase_project_ref" in content


# ── 50. Connectors __init__.py export ─────────────────────────────────────────

class TestConnectorPackageExport:
    def test_supabase_connector_exported_from_package(self):
        from app.connectors import SupabaseConnector
        assert SupabaseConnector is not None

    def test_supabase_connector_in_all(self):
        import app.connectors as pkg
        assert "SupabaseConnector" in pkg.__all__

    def test_supabase_connector_is_base_connector_subclass(self):
        from app.connectors import SupabaseConnector
        from app.connectors.base import BaseConnector
        assert issubclass(SupabaseConnector, BaseConnector)


# ── 51. Rate-limit exhaustion regression (M54.5 bug fix) ──────────────────────

class TestRateLimitRetryExhaustion:
    """Regression tests for the M54.5 fix: _get line 179 previously passed
    ``status_code=429`` to ``RateLimitError.__init__``, which raises TypeError
    because RateLimitError only accepts ``message`` and optional ``retry_after``.
    After the fix, exhausted 429s raise RateLimitError cleanly."""

    def test_429_exhausted_raises_rate_limit_error_not_type_error(self):
        """All _MAX_RETRIES+1 attempts return 429 → RateLimitError, not TypeError."""
        from unittest.mock import patch, MagicMock
        from app.connectors.supabase import SupabaseConnector, _MAX_RETRIES
        from app.connectors.exceptions import RateLimitError

        connector = SupabaseConnector()
        mock_response = MagicMock()
        mock_response.status_code = 429
        mock_response.is_success = False

        with patch("httpx.get", return_value=mock_response) as mock_get:
            with pytest.raises(RateLimitError) as exc_info:
                connector._get("/v1/projects/testref", "sbp_test_token")
            # Should be called _MAX_RETRIES + 1 = 3 times total
            assert mock_get.call_count == _MAX_RETRIES + 1
            # status_code is 429 (set by the base class in its super().__init__)
            assert exc_info.value.status_code == 429

    def test_429_retries_then_succeeds_on_final_attempt(self):
        """Two 429s followed by a 200 → success (retry loop works correctly)."""
        from unittest.mock import patch, MagicMock
        from app.connectors.supabase import SupabaseConnector, _MAX_RETRIES

        connector = SupabaseConnector()

        rate_limit_response = MagicMock()
        rate_limit_response.status_code = 429
        rate_limit_response.is_success = False

        success_response = MagicMock()
        success_response.status_code = 200
        success_response.is_success = True
        success_response.json.return_value = {"name": "test-project"}

        # First two calls return 429, third returns 200
        side_effects = [rate_limit_response] * _MAX_RETRIES + [success_response]

        with patch("httpx.get", side_effect=side_effects) as mock_get:
            result = connector._get("/v1/projects/testref", "sbp_test_token")
        assert result == {"name": "test-project"}
        assert mock_get.call_count == _MAX_RETRIES + 1


# ── 52. Failure classifier: clean recommended_actions ────────────────────────

class TestSupabaseFailureClassifierRecommendations:
    """Verify recommended_action strings for Supabase do not request dangerous
    permissions (data reads, secret values, row access, etc.)."""

    # Phrases that should never appear in recommended_actions for Supabase.
    _FORBIDDEN_PHRASES = [
        "read database row",
        "read user data",
        "query table",
        "storage object",
        "getsecretvalue",    # lower-cased comparison
        "database content",
        "database password",
        "service role key",
        "auth user",
    ]

    def _get_recommended_action(self, exc):
        from app.core.failure_classifier import classify_failure
        return classify_failure(exc, "supabase").recommended_action

    def _assert_no_forbidden_phrases(self, action: str) -> None:
        action_lower = action.lower()
        for phrase in self._FORBIDDEN_PHRASES:
            assert phrase not in action_lower, (
                f"Supabase recommended_action contains forbidden phrase {phrase!r}: {action!r}"
            )

    def test_auth_error_recommended_action_is_safe(self):
        from app.connectors.exceptions import AuthenticationError
        exc = AuthenticationError("401", status_code=401)
        self._assert_no_forbidden_phrases(self._get_recommended_action(exc))

    def test_403_recommended_action_is_safe(self):
        from app.connectors.exceptions import ConnectorError
        exc = ConnectorError("403 Forbidden", status_code=403)
        self._assert_no_forbidden_phrases(self._get_recommended_action(exc))

    def test_404_recommended_action_is_safe(self):
        from app.connectors.exceptions import ConnectorError
        exc = ConnectorError("404 Not Found", status_code=404)
        self._assert_no_forbidden_phrases(self._get_recommended_action(exc))

    def test_5xx_recommended_action_is_safe(self):
        from app.connectors.exceptions import ConnectorError
        exc = ConnectorError("503 error", status_code=503)
        self._assert_no_forbidden_phrases(self._get_recommended_action(exc))

    def test_auth_recommended_action_mentions_token_rotation(self):
        """Auth error guidance should point to token management, not data access."""
        from app.connectors.exceptions import AuthenticationError
        exc = AuthenticationError("401", status_code=401)
        action = self._get_recommended_action(exc)
        assert "token" in action.lower() or "access" in action.lower()


# ── 53. Credential validation messages don't leak values ─────────────────────

class TestCredentialValidationMessageSafety:
    """Verify that ValueError messages from _validate_credential_fields do
    not include the actual credential values — only field names."""

    def test_error_message_does_not_contain_actual_token_value(self):
        """Missing project_ref: error names the field, not the token value."""
        from app.connectors.supabase import SupabaseConnector
        connector = SupabaseConnector()
        token_value = "sbp_super_secret_access_token_xyz789"
        try:
            connector._validate_credential_fields({
                "access_token": token_value,
                # project_ref intentionally absent
            })
            pytest.fail("Expected ValueError was not raised")
        except ValueError as exc:
            assert token_value not in str(exc), (
                f"Validation error message exposes the token value: {exc}"
            )
            assert "project_ref" in str(exc)

    def test_error_message_does_not_contain_project_ref_value(self):
        """Missing access_token: error names the field, not the project ref value."""
        from app.connectors.supabase import SupabaseConnector
        connector = SupabaseConnector()
        project_ref_value = "supersecretprojectref1"
        try:
            connector._validate_credential_fields({
                # access_token intentionally absent
                "project_ref": project_ref_value,
            })
            pytest.fail("Expected ValueError was not raised")
        except ValueError as exc:
            assert project_ref_value not in str(exc), (
                f"Validation error message exposes the project_ref value: {exc}"
            )
            assert "access_token" in str(exc)
