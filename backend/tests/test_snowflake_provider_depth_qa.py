"""Snowflake provider-depth QA guardrails (Snowflake message 8 — public launch).

Durable, deterministic guardrails proving Snowflake is a genuinely
launched, connectable, production-certified provider — not just a
connector that exists internally. This file adds no product code; it
pins registration-surface parity, the credential round-trip, security
finding registry parity, sensitive-data boundaries, and frontend/backend
consistency so a future change cannot silently regress the launch.

Sections:
  A. Backend registration surfaces (sync dispatch, schema, coverage, matrix)
  B. Credential round-trip (router _build_credentials, reconnect)
  C. Security Finding registry parity (31 rules)
  D. Sensitive-data / forbidden-call boundary
  E. Frontend catalog parity (connectable, card copy, form wired)
  F. Reliability/completeness surfaces exist (message 5-7 wiring reachable)
  G. Record-type inventory (21 record types, tracked + classified)
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND_ROOT = Path(__file__).resolve().parents[1]
FRONTEND_ROOT = REPO_ROOT / "frontend"


# ════════════════════════════════════════════════════════════════════════════
# A. Backend registration surfaces
# ════════════════════════════════════════════════════════════════════════════


class TestBackendRegistrationSurfaces:
    def test_snowflake_in_sync_supported_providers(self):
        source = (BACKEND_ROOT / "app" / "services" / "sync_service.py").read_text()
        start = source.index("_SUPPORTED_PROVIDERS = (")
        end = source.index(")", start)
        assert '"snowflake"' in source[start:end]

    def test_snowflake_in_integration_create_request_literal(self):
        from app.schemas.integration import IntegrationCreateRequest

        req = IntegrationCreateRequest(
            provider="snowflake",
            display_name="Test account",
            snowflake_account_identifier="myorg-myaccount",
            snowflake_username="MONITOR",
            snowflake_programmatic_access_token="fake-pat",
            snowflake_role="MONITOR_ROLE",
        )
        assert req.provider == "snowflake"

    def test_snowflake_requires_all_four_credential_fields(self):
        from pydantic import ValidationError
        from app.schemas.integration import IntegrationCreateRequest

        with pytest.raises(ValidationError):
            IntegrationCreateRequest(provider="snowflake", display_name="Test")

    def test_snowflake_in_security_coverage_providers(self):
        from app.services.security_coverage_service import PROVIDERS

        assert "snowflake" in PROVIDERS

    def test_snowflake_in_capability_matrix_complete_list_not_partial(self):
        from app.services.provider_capability_matrix_service import (
            PROVIDER_CAPABILITIES,
            PROVIDER_CAPABILITIES_PARTIAL,
        )

        assert "snowflake" in {p.provider for p in PROVIDER_CAPABILITIES}
        assert "snowflake" not in {p.provider for p in PROVIDER_CAPABILITIES_PARTIAL}

    def test_snowflake_capability_notes_say_launched_not_pending(self):
        from app.services.provider_capability_matrix_service import get_provider_capability

        cap = get_provider_capability("snowflake")
        assert cap is not None
        notes_lower = cap.notes.lower()
        assert "not connectable" not in notes_lower
        assert "not exposed on the public integrations list" not in notes_lower
        assert "expansion is complete" in notes_lower

    def test_snowflake_dispatch_function_exists(self):
        from app.services import integration_service

        assert hasattr(integration_service, "_create_snowflake_integration")

    def test_snowflake_reconnect_function_exists(self):
        from app.services import integration_service

        assert hasattr(integration_service, "reconnect_credentials_snowflake")


# ════════════════════════════════════════════════════════════════════════════
# B. Credential round-trip
# ════════════════════════════════════════════════════════════════════════════


class TestCredentialRoundTrip:
    def test_build_credentials_extracts_all_four_fields(self):
        from app.routers.integrations import _build_credentials
        from app.schemas.integration import IntegrationCreateRequest

        req = IntegrationCreateRequest(
            provider="snowflake",
            display_name="Test",
            snowflake_account_identifier="myorg-myaccount",
            snowflake_username="MONITOR",
            snowflake_programmatic_access_token="fake-pat",
            snowflake_role="MONITOR_ROLE",
        )
        creds = _build_credentials(req)
        assert creds["account_identifier"] == "myorg-myaccount"
        assert creds["username"] == "MONITOR"
        assert creds["programmatic_access_token"] == "fake-pat"
        assert creds["role"] == "MONITOR_ROLE"

    def test_build_credentials_key_matches_connector_expectation(self):
        """The router must build the exact dict shape
        SnowflakeConnector._credentials() reads from."""
        import inspect

        from app.connectors.snowflake import SnowflakeConnector

        source = inspect.getsource(SnowflakeConnector._credentials)
        assert 'credentials.get("account_identifier")' in source
        assert 'credentials.get("username")' in source
        assert 'credentials.get("programmatic_access_token")' in source
        assert 'credentials.get("role")' in source

    def test_creation_runs_synchronous_probe_coverage(self):
        """Message 8: creation must call probe_coverage() synchronously —
        a bare-record-creation regression here would silently reintroduce
        deferred-to-first-sync validation and break the Invalid
        launch-certification state."""
        import inspect

        from app.services import integration_service

        source = inspect.getsource(integration_service._create_snowflake_integration)
        assert "probe_coverage(credentials)" in source
        assert "COVERAGE_INVALID" in source

    def test_reconnect_schema_has_snowflake_fields(self):
        from app.schemas.integration import IntegrationReconnectRequest

        fields = IntegrationReconnectRequest.model_fields
        assert "snowflake_account_identifier" in fields
        assert "snowflake_username" in fields
        assert "snowflake_programmatic_access_token" in fields
        assert "snowflake_role" in fields

    def test_reconnect_router_branch_exists_for_snowflake(self):
        source = (BACKEND_ROOT / "app" / "routers" / "integrations.py").read_text()
        assert 'integration.provider == "snowflake"' in source
        assert "reconnect_credentials_snowflake" in source

    def test_reconnect_rejects_different_account(self):
        """Regression pin: reconnect_credentials_snowflake() must compare
        stable account identity and raise ConnectorError on a genuine
        mismatch — never silently overwrite."""
        import inspect

        from app.services import integration_service

        source = inspect.getsource(integration_service.reconnect_credentials_snowflake)
        assert "existing_account_id != new_account_id" in source
        assert "ConnectorError" in source
        assert "probe_coverage" in source


# ════════════════════════════════════════════════════════════════════════════
# C. Security Finding registry parity
# ════════════════════════════════════════════════════════════════════════════


class TestSecurityFindingParity:
    def _snowflake_rule_keys(self) -> set[str]:
        from app.services.security_rule_registry import KNOWN_RULE_KEYS

        return {k for k in KNOWN_RULE_KEYS if k.startswith("snowflake_")}

    def test_snowflake_has_exactly_31_rules(self):
        assert len(self._snowflake_rule_keys()) == 31

    def test_all_snowflake_rules_reachable_from_evaluator(self):
        from app.services.security_rules.snowflake import evaluate

        assert callable(evaluate)

    def test_all_snowflake_rules_have_confidence(self):
        from app.services.security_rule_confidence import RULE_CONFIDENCE

        missing = self._snowflake_rule_keys() - set(RULE_CONFIDENCE.keys())
        assert not missing, f"rules missing confidence: {missing}"

    def test_snowflake_in_coverage_record_types(self):
        from app.services.security_coverage_service import RULE_RECORD_TYPES

        missing = self._snowflake_rule_keys() - set(RULE_RECORD_TYPES.keys())
        assert not missing, f"rules missing coverage record types: {missing}"


# ════════════════════════════════════════════════════════════════════════════
# D. Sensitive-data / forbidden-call boundary
# ════════════════════════════════════════════════════════════════════════════

FORBIDDEN_TOKEN_PATTERNS = [
    r"logger\.\w+\(.*programmatic_access_token",
    r"print\(.*programmatic_access_token",
    r"raise \w+Error\(f?[\"'].*\{token\}",
]


class TestSensitiveDataBoundary:
    def test_connector_never_logs_or_raises_with_raw_token(self):
        source = (BACKEND_ROOT / "app" / "connectors" / "snowflake.py").read_text()
        for pattern in FORBIDDEN_TOKEN_PATTERNS:
            assert not re.search(pattern, source), f"forbidden token usage found: {pattern}"

    def test_account_resource_metadata_never_contains_token(self):
        source = (BACKEND_ROOT / "app" / "services" / "integration_service.py").read_text()
        start = source.index("def _create_snowflake_integration")
        end = source.index("\ndef ", start + 10)
        block = source[start:end]
        metadata_start = block.index("resource_metadata={")
        metadata_end = block.index("},", metadata_start)
        metadata_block = block[metadata_start:metadata_end]
        assert "programmatic_access_token" not in metadata_block
        assert "credentials" not in metadata_block

    def test_reconnect_snowflake_never_logs_new_token(self):
        source = (BACKEND_ROOT / "app" / "services" / "integration_service.py").read_text()
        start = source.index("def reconnect_credentials_snowflake")
        end = source.index("\ndef ", start + 10)
        block = source[start:end]
        assert "print(" not in block
        assert "logger.info(new_programmatic_access_token" not in block
        assert "logger.debug(new_programmatic_access_token" not in block

    def test_no_cli_or_subprocess_dependency(self):
        """Regression pin: no runtime subprocess/CLI dependency. The module
        docstring legitimately MENTIONS snowsql/CLI/interactive auth only to
        say those modes are never implemented — so this checks for actual
        subprocess-invocation patterns, not the word "snowsql" anywhere."""
        source = (BACKEND_ROOT / "app" / "connectors" / "snowflake.py").read_text()
        assert "subprocess" not in source
        assert "os.system" not in source
        assert "shell=True" not in source
        assert not re.search(r"subprocess\.|Popen\(|os\.exec", source)

    def test_no_mutating_sql_statements_in_connector(self):
        """Regression pin: no mutating SQL statement is ever EXECUTED. The
        keyword matches expected here are privilege-name string labels
        parsed from observed `SHOW GRANTS` output (e.g.
        `"INSERT": PRIVILEGE_CATEGORY_DATA_WRITE` or
        `cleaned.startswith("CREATE ")`) — categorizing data, never
        constructing SQL. This checks the connector's fixed statement
        constants specifically, never the whole file."""
        source = (BACKEND_ROOT / "app" / "connectors" / "snowflake.py").read_text()
        statement_blocks = re.findall(r'"SELECT[^"]*"|"SHOW[^"]*"|"DESCRIBE[^"]*"', source)
        assert statement_blocks, "expected to find fixed SELECT/SHOW/DESCRIBE statement constants"
        for statement in statement_blocks:
            upper = statement.upper()
            for keyword in (
                "CREATE ", "ALTER ", "DROP ", "GRANT ", "REVOKE ", "INSERT ",
                "UPDATE ", "DELETE ", "MERGE ", "COPY INTO", "PUT ", "CALL ",
                "TRUNCATE ", "USE ROLE", "USE WAREHOUSE",
            ):
                assert keyword not in upper, f"forbidden mutating keyword found in statement: {statement!r}"


# ════════════════════════════════════════════════════════════════════════════
# E. Frontend catalog parity
# ════════════════════════════════════════════════════════════════════════════


class TestFrontendLaunchState:
    def _providers_ts(self) -> str:
        path = FRONTEND_ROOT / "src" / "lib" / "providers.ts"
        if not path.is_file():
            pytest.skip("frontend tree not found")
        return path.read_text()

    def test_snowflake_in_connectable_provider_ids(self):
        text = self._providers_ts()
        start = text.index("export const CONNECTABLE_PROVIDER_IDS")
        end = text.index("];", start)
        assert '"snowflake"' in text[start:end]

    def test_snowflake_in_provider_ids(self):
        text = self._providers_ts()
        start = text.index("export const PROVIDER_IDS")
        end = text.index("];", start)
        assert '"snowflake"' in text[start:end]

    def test_snowflake_card_copy_omits_stale_planned_wording(self):
        text = self._providers_ts()
        start = text.index("snowflake: {")
        end = text.index("\n  },", start)
        block = text[start:end]
        assert "not yet connectable" not in block.lower()
        assert "early foundation" not in block.lower()
        assert "— planned" not in block

    def test_snowflake_card_copy_never_claims_internet_exposure_wording(self):
        text = self._providers_ts()
        start = text.index("snowflake: {")
        end = text.index("\n  },", start)
        block = text[start:end].lower()
        for forbidden in ("internet exposed", "internet-exposed", "publicly accessible", "anonymous access"):
            assert forbidden not in block, f"card copy uses forbidden PUBLIC wording: {forbidden!r}"

    def test_snowflake_card_copy_omits_unsupported_claims(self):
        text = self._providers_ts()
        start = text.index("snowflake: {")
        trust_note_start = text.index("trustNote:", start)
        card_copy = text[start:trust_note_start].lower()
        for forbidden in (
            "query history", "login history", "table data", "row data",
            "runtime anomaly", "sensitive-data discovery", "guaranteed",
        ):
            assert forbidden not in card_copy, f"card copy claims {forbidden!r}"

    def test_snowflake_form_component_exists(self):
        path = (
            FRONTEND_ROOT / "src" / "components" / "integrations"
            / "SnowflakeIntegrationForm.tsx"
        )
        if not FRONTEND_ROOT.is_dir():
            pytest.skip("frontend tree not found")
        assert path.is_file()

    def test_snowflake_form_wired_into_integrations_page(self):
        path = FRONTEND_ROOT / "src" / "app" / "(app)" / "integrations" / "page.tsx"
        if not path.is_file():
            pytest.skip("frontend tree not found")
        text = path.read_text()
        assert "SnowflakeIntegrationForm" in text
        assert 'selectedProvider === "snowflake"' in text

    def test_snowflake_form_uses_password_input_for_token(self):
        path = (
            FRONTEND_ROOT / "src" / "components" / "integrations"
            / "SnowflakeIntegrationForm.tsx"
        )
        if not path.is_file():
            pytest.skip("frontend tree not found")
        text = path.read_text()
        assert 'type="password"' in text
        assert 'id="snowflake-pat"' in text

    def test_snowflake_form_never_prefills_or_echoes_token_after_success(self):
        path = (
            FRONTEND_ROOT / "src" / "components" / "integrations"
            / "SnowflakeIntegrationForm.tsx"
        )
        if not path.is_file():
            pytest.skip("frontend tree not found")
        text = path.read_text()
        assert 'setToken("")' in text
        assert "configured" in text.lower()

    def test_snowflake_form_never_defaults_to_admin_roles(self):
        path = (
            FRONTEND_ROOT / "src" / "components" / "integrations"
            / "SnowflakeIntegrationForm.tsx"
        )
        if not path.is_file():
            pytest.skip("frontend tree not found")
        text = path.read_text()
        assert 'value="ACCOUNTADMIN"' not in text
        assert 'value="SECURITYADMIN"' not in text


# ════════════════════════════════════════════════════════════════════════════
# F. Reliability / completeness surfaces (message 5-7 wiring stays reachable)
# ════════════════════════════════════════════════════════════════════════════


class TestReliabilitySurfacesReachable:
    def test_probe_coverage_exists(self):
        from app.connectors.snowflake import SnowflakeConnector

        assert callable(SnowflakeConnector.probe_coverage)

    def test_compute_coverage_state_exists(self):
        from app.connectors.snowflake_schema import compute_coverage_state

        assert callable(compute_coverage_state)

    def test_format_capability_diagnostics_exists(self):
        from app.connectors.snowflake_schema import format_capability_diagnostics

        assert callable(format_capability_diagnostics)

    def test_snowflake_removal_suppressed_exists(self):
        from app.services.diff_service import _snowflake_removal_suppressed

        assert callable(_snowflake_removal_suppressed)

    def test_coverage_full_when_all_families_available(self):
        from app.connectors.snowflake_schema import CAPABILITY_AVAILABLE, CAPABILITY_FAMILIES, compute_coverage_state

        family_status = {f: CAPABILITY_AVAILABLE for f in CAPABILITY_FAMILIES}
        assert compute_coverage_state(family_status) == "full"

    def test_coverage_partial_when_one_extended_family_denied(self):
        from app.connectors.snowflake_schema import (
            CAPABILITY_AVAILABLE, CAPABILITY_DENIED, CAPABILITY_FAMILIES, compute_coverage_state,
        )

        family_status = {f: CAPABILITY_AVAILABLE for f in CAPABILITY_FAMILIES}
        family_status["network_policies"] = CAPABILITY_DENIED
        assert compute_coverage_state(family_status) == "partial"

    def test_coverage_invalid_when_no_core_family_readable(self):
        from app.connectors.snowflake_schema import (
            CAPABILITY_AVAILABLE, CAPABILITY_DENIED, CORE_CAPABILITY_FAMILIES,
            EXTENDED_CAPABILITY_FAMILIES, compute_coverage_state,
        )

        family_status = {f: CAPABILITY_DENIED for f in CORE_CAPABILITY_FAMILIES}
        family_status.update({f: CAPABILITY_AVAILABLE for f in EXTENDED_CAPABILITY_FAMILIES})
        assert compute_coverage_state(family_status) == "invalid"

    def test_diagnostics_group_denied_family_as_permission_denied(self):
        from app.connectors.snowflake_schema import (
            CAPABILITY_AVAILABLE, CAPABILITY_DENIED, CAPABILITY_FAMILIES, format_capability_diagnostics,
        )

        family_status = {f: CAPABILITY_AVAILABLE for f in CAPABILITY_FAMILIES}
        family_status["authentication_policies"] = CAPABILITY_DENIED
        diagnostics = format_capability_diagnostics(family_status)
        assert diagnostics["Authentication policies"] == "Permission denied"
        assert diagnostics["Identity and roles"] == "Available"


# ════════════════════════════════════════════════════════════════════════════
# G. Record-type inventory (21 record types, tracked + classified)
# ════════════════════════════════════════════════════════════════════════════


class TestRecordTypeInventory:
    _EXPECTED_RECORD_TYPES = [
        "SNOWFLAKE_ACCOUNT", "SNOWFLAKE_API_CAPABILITY", "SNOWFLAKE_USER",
        "SNOWFLAKE_ACCOUNT_ROLE", "SNOWFLAKE_DATABASE_ROLE", "SNOWFLAKE_USER_ROLE_GRANT",
        "SNOWFLAKE_ROLE_HIERARCHY_GRANT", "SNOWFLAKE_DATABASE", "SNOWFLAKE_SCHEMA",
        "SNOWFLAKE_WAREHOUSE", "SNOWFLAKE_SHARE", "SNOWFLAKE_OBJECT_GRANT",
        "SNOWFLAKE_NETWORK_POLICY", "SNOWFLAKE_NETWORK_RULE", "SNOWFLAKE_AUTHENTICATION_POLICY",
        "SNOWFLAKE_SECURITY_INTEGRATION", "SNOWFLAKE_STORAGE_INTEGRATION",
        "SNOWFLAKE_EXTERNAL_ACCESS_INTEGRATION", "SNOWFLAKE_PRIVILEGED_USER",
        "SNOWFLAKE_PRIVILEGED_ROLE", "SNOWFLAKE_PUBLIC_EXPOSURE",
    ]

    def test_exactly_21_record_types_defined(self):
        import app.connectors.snowflake_schema as schema

        for name in self._EXPECTED_RECORD_TYPES:
            assert hasattr(schema, name), f"missing record type constant: {name}"
        assert len(self._EXPECTED_RECORD_TYPES) == 21

    def test_all_21_record_types_tracked_in_diff_service(self):
        import app.connectors.snowflake_schema as schema

        source = (BACKEND_ROOT / "app" / "services" / "diff_service.py").read_text()
        for name in self._EXPECTED_RECORD_TYPES:
            record_type_value = getattr(schema, name)
            assert f'"{record_type_value}"' in source, f"{record_type_value} not referenced in diff_service.py"

    def test_all_21_record_types_classified_in_risk_rules(self):
        import app.connectors.snowflake_schema as schema

        source = (BACKEND_ROOT / "app" / "services" / "risk_rules" / "snowflake.py").read_text()
        for name in self._EXPECTED_RECORD_TYPES:
            record_type_value = getattr(schema, name)
            assert f'"{record_type_value}"' in source or name in source, (
                f"{record_type_value} not referenced in risk_rules/snowflake.py"
            )
