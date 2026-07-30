"""Snowflake provider registration/contract tests (Snowflake message 1 of 8).

Covers everything OUTSIDE the connector's internal collection logic (that's
``test_snowflake_foundation.py``): provider dispatch wiring (sync_task,
integration_service, sync_service), the credential schema, diff/risk
dispatch (never falling through to an unrelated provider), the capability
matrix entry (staged in PROVIDER_CAPABILITIES_PARTIAL, not the canonical
complete list), and the frontend catalog state (present but explicitly not
yet user-connectable).
"""

from __future__ import annotations

import inspect

import pytest

_ACCOUNT_ID = "myorg-myaccount"
_USERNAME = "CONFIGTRACE_MONITOR"
_TOKEN = "fake-snowflake-pat-value"
_ROLE = "CONFIGTRACE_MONITORING_ROLE"


# ── Provider dispatch wiring ──────────────────────────────────────────────────


class TestProviderDispatchWiring:
    def test_sync_task_dispatches_snowflake(self):
        import app.workers.sync_task as sync_task_module

        source = inspect.getsource(sync_task_module)
        assert 'integration.provider == "snowflake"' in source
        assert "SnowflakeConnector" in source

    def test_integration_service_dispatches_snowflake(self):
        import app.services.integration_service as isvc

        source = inspect.getsource(isvc)
        assert 'provider == "snowflake"' in source
        assert "_create_snowflake_integration" in source

    def test_sync_service_supported_providers_contains_snowflake(self):
        source = (
            __import__("pathlib").Path(__file__).resolve().parents[1]
            / "app" / "services" / "sync_service.py"
        ).read_text()
        start = source.index("_SUPPORTED_PROVIDERS = (")
        end = source.index(")", start)
        assert '"snowflake"' in source[start:end]

    def test_create_integration_creates_row_without_leaking_secret(
        self, test_user, db_session,
    ):
        from unittest.mock import patch

        from app.connectors.snowflake import SnowflakeConnector
        from app.connectors.snowflake_schema import COVERAGE_FULL
        from app.models.resource import Resource
        from app.schemas.integration import IntegrationResponse
        from app.services import integration_service

        credentials = {
            "account_identifier": _ACCOUNT_ID,
            "username": _USERNAME,
            "programmatic_access_token": _TOKEN,
            "role": _ROLE,
        }
        coverage_result = {
            "coverage": COVERAGE_FULL,
            "account_id": "id:myorg-myaccount",
            "session_role": _ROLE,
            "family_status": {},
            "diagnostics": {},
        }
        with patch.object(SnowflakeConnector, "probe_coverage", return_value=coverage_result):
            integration = integration_service.create_integration(
                user_id=test_user.id,
                provider="snowflake",
                display_name="snowflake-test",
                credentials=credentials,
                db=db_session,
            )
        try:
            assert integration.provider == "snowflake"
            assert integration.encrypted_credentials is not None
            assert integration.credential_iv is not None

            resource = (
                db_session.query(Resource)
                .filter(Resource.integration_id == integration.id)
                .first()
            )
            assert resource is not None
            assert resource.provider_resource_type == "snowflake_account"
            metadata_blob = str(resource.resource_metadata)
            assert _TOKEN not in metadata_blob

            response = IntegrationResponse.model_validate(integration)
            response_blob = response.model_dump_json()
            assert _TOKEN not in response_blob
        finally:
            db_session.delete(integration)
            db_session.commit()

    def test_create_integration_rejects_malformed_account_identifier(self, test_user, db_session):
        from app.services import integration_service

        credentials = {
            "account_identifier": "https://evil.example",
            "username": _USERNAME,
            "programmatic_access_token": _TOKEN,
            "role": _ROLE,
        }
        with pytest.raises(ValueError):
            integration_service.create_integration(
                user_id=test_user.id,
                provider="snowflake",
                display_name="snowflake-bad-account",
                credentials=credentials,
                db=db_session,
            )

    def test_create_integration_contacts_snowflake_synchronously(self, test_user, db_session):
        """Message 8 (public launch): creating the integration now runs
        synchronous credential validation via ``probe_coverage()`` — this
        supersedes message 1's deferred-to-first-sync behavior, matching
        the Okta/Entra launch precedent."""
        from unittest.mock import patch

        from app.connectors.snowflake import SnowflakeConnector
        from app.connectors.snowflake_schema import COVERAGE_FULL
        from app.services import integration_service

        credentials = {
            "account_identifier": _ACCOUNT_ID,
            "username": _USERNAME,
            "programmatic_access_token": _TOKEN,
            "role": _ROLE,
        }
        coverage_result = {
            "coverage": COVERAGE_FULL,
            "account_id": "id:myorg-myaccount",
            "session_role": _ROLE,
            "family_status": {},
            "diagnostics": {},
        }
        with patch.object(SnowflakeConnector, "probe_coverage", return_value=coverage_result) as mock_probe:
            integration = integration_service.create_integration(
                user_id=test_user.id,
                provider="snowflake",
                display_name="snowflake-contact",
                credentials=credentials,
                db=db_session,
            )
            mock_probe.assert_called_once()
        db_session.delete(integration)
        db_session.commit()


# ── Credential schema ──────────────────────────────────────────────────────────


class TestCredentialSchema:
    def test_snowflake_in_provider_literal(self):
        from app.schemas.integration import IntegrationCreateRequest

        req = IntegrationCreateRequest(
            provider="snowflake",
            display_name="Test account",
            snowflake_account_identifier=_ACCOUNT_ID,
            snowflake_username=_USERNAME,
            snowflake_programmatic_access_token=_TOKEN,
            snowflake_role=_ROLE,
        )
        assert req.provider == "snowflake"

    def test_missing_account_identifier_rejected(self):
        from pydantic import ValidationError
        from app.schemas.integration import IntegrationCreateRequest

        with pytest.raises(ValidationError):
            IntegrationCreateRequest(
                provider="snowflake",
                display_name="Test",
                snowflake_username=_USERNAME,
                snowflake_programmatic_access_token=_TOKEN,
                snowflake_role=_ROLE,
            )

    def test_missing_username_rejected(self):
        from pydantic import ValidationError
        from app.schemas.integration import IntegrationCreateRequest

        with pytest.raises(ValidationError):
            IntegrationCreateRequest(
                provider="snowflake",
                display_name="Test",
                snowflake_account_identifier=_ACCOUNT_ID,
                snowflake_programmatic_access_token=_TOKEN,
                snowflake_role=_ROLE,
            )

    def test_missing_token_rejected(self):
        from pydantic import ValidationError
        from app.schemas.integration import IntegrationCreateRequest

        with pytest.raises(ValidationError):
            IntegrationCreateRequest(
                provider="snowflake",
                display_name="Test",
                snowflake_account_identifier=_ACCOUNT_ID,
                snowflake_username=_USERNAME,
                snowflake_role=_ROLE,
            )

    def test_missing_role_rejected(self):
        from pydantic import ValidationError
        from app.schemas.integration import IntegrationCreateRequest

        with pytest.raises(ValidationError):
            IntegrationCreateRequest(
                provider="snowflake",
                display_name="Test",
                snowflake_account_identifier=_ACCOUNT_ID,
                snowflake_username=_USERNAME,
                snowflake_programmatic_access_token=_TOKEN,
            )

    def test_build_credentials_extracts_snowflake_fields(self):
        from app.routers.integrations import _build_credentials
        from app.schemas.integration import IntegrationCreateRequest

        req = IntegrationCreateRequest(
            provider="snowflake",
            display_name="Test",
            snowflake_account_identifier=_ACCOUNT_ID,
            snowflake_username=_USERNAME,
            snowflake_programmatic_access_token=_TOKEN,
            snowflake_role=_ROLE,
        )
        creds = _build_credentials(req)
        assert creds["account_identifier"] == _ACCOUNT_ID
        assert creds["username"] == _USERNAME
        assert creds["programmatic_access_token"] == _TOKEN
        assert creds["role"] == _ROLE


# ── Diff / risk dispatch ────────────────────────────────────────────────────────


class TestDiffRiskDispatch:
    def test_account_change_routes_to_snowflake_classifier(self):
        from app.services.risk_service import classify_change

        change = {
            "change_type": "modified",
            "provider_metadata": {"record_type": "snowflake_account"},
            "field_path": "monitoring_role",
        }
        level, reason = classify_change(change)
        assert "Snowflake" in reason

    def test_capability_change_routes_to_snowflake_classifier(self):
        from app.services.risk_service import classify_change

        change = {
            "change_type": "modified",
            "provider_metadata": {"record_type": "snowflake_api_capability"},
            "field_path": "status",
            "prev_value": "available",
            "new_value": "denied",
        }
        level, reason = classify_change(change)
        assert level == "medium"
        assert "Snowflake" in reason

    def test_unknown_snowflake_record_type_fails_safe(self):
        from app.services.risk_rules.snowflake import classify_snowflake_change

        change = {
            "change_type": "modified",
            "provider_metadata": {"record_type": "snowflake_future_thing"},
        }
        level, reason = classify_snowflake_change(change)
        assert level == "low"

    def test_real_compute_diff_produces_snowflake_provider_metadata(self):
        from types import SimpleNamespace

        from app.services.diff_service import compute_diff

        prev_snapshot = SimpleNamespace(state=[{
            "record_type": "snowflake_account",
            "record_id": "id:acme-prod",
            "account_id": "id:acme-prod",
            "organization_name": "ACME",
            "account_name": "PROD",
        }])
        new_snapshot = SimpleNamespace(state=[{
            "record_type": "snowflake_account",
            "record_id": "id:acme-prod",
            "account_id": "id:acme-prod",
            "organization_name": "ACME",
            "account_name": "PROD",
            "monitoring_role": "NEW_ROLE",
        }])
        changes = compute_diff(prev_snapshot, new_snapshot)
        assert len(changes) == 1
        change = changes[0]
        pm = change["provider_metadata"]
        assert pm["record_type"] == "snowflake_account"
        assert "programmatic_access_token" not in pm
        assert "username" not in pm


# ── Capability matrix ─────────────────────────────────────────────────────────


class TestCapabilityMatrix:
    def test_snowflake_registered_in_complete_list_not_partial_list(self):
        """Message 8 (public launch): Snowflake has graduated from the
        PROVIDER_CAPABILITIES_PARTIAL staging list into the canonical
        PROVIDER_CAPABILITIES list — same transition Okta/Entra made at
        their own message 8."""
        from app.services.provider_capability_matrix_service import (
            PROVIDER_CAPABILITIES,
            PROVIDER_CAPABILITIES_PARTIAL,
        )

        assert "snowflake" in {p.provider for p in PROVIDER_CAPABILITIES}
        assert "snowflake" not in {p.provider for p in PROVIDER_CAPABILITIES_PARTIAL}

    def test_snowflake_drift_true_security_rules_true(self):
        from app.services.provider_capability_matrix_service import get_provider_capability

        cap = get_provider_capability("snowflake")
        assert cap is not None
        assert cap.drift.drift_snapshots is True
        assert cap.drift.drift_diff is True
        assert cap.drift.drift_risk_classification is True
        # Message 8: drift_review_workflow flips True (generic review UI,
        # no Snowflake-specific code) — same as Okta's own message-8 flip.
        assert cap.drift.drift_review_workflow is True
        # Security Findings landed in Snowflake message 6; activity/case/
        # evidence-graph capabilities remain out of scope for this provider.
        assert cap.security.security_rules is True
        assert cap.security.activity_ingestion is False
        assert cap.security.case_report is False
        assert cap.security.activity_ingestion is False
        assert cap.security.demo_seed_clear is False

    def test_snowflake_category_is_valid(self):
        from app.services.provider_capability_matrix_service import (
            CATEGORIES,
            get_provider_capability,
        )

        cap = get_provider_capability("snowflake")
        assert cap.category in CATEGORIES
        assert cap.category == "database_backend"

    def test_snowflake_maturity_is_valid(self):
        from app.services.provider_capability_matrix_service import (
            MATURITY_LEVELS,
            get_provider_capability,
        )

        cap = get_provider_capability("snowflake")
        assert cap.maturity in MATURITY_LEVELS

    def test_get_matrix_includes_snowflake_now_launched(self):
        """Message 8: get_matrix() surfaces PROVIDER_CAPABILITIES (the
        canonical complete list) — Snowflake has graduated out of the
        PARTIAL staging list and now appears in the public matrix
        endpoint's provider list, same as Okta/Entra at their own
        message 8."""
        from app.services.provider_capability_matrix_service import get_matrix

        matrix = get_matrix()
        provider_ids = {p["provider"] for p in matrix["providers"]}
        assert "snowflake" in provider_ids

    def test_snowflake_in_security_coverage_providers(self):
        from app.services.security_coverage_service import PROVIDERS

        assert "snowflake" in PROVIDERS


# ── Frontend catalog state ────────────────────────────────────────────────────


class TestFrontendCatalogState:
    """Source-scan checks (no TS execution) confirming Snowflake is now
    publicly connectable and Live (message 8 of 8 — public launch)."""

    def _providers_ts_text(self) -> str:
        from pathlib import Path

        path = (
            Path(__file__).resolve().parents[2]
            / "frontend" / "src" / "lib" / "providers.ts"
        )
        if not path.is_file():
            pytest.skip("frontend tree not found")
        return path.read_text()

    def test_snowflake_present_in_provider_id_type(self):
        text = self._providers_ts_text()
        assert '"snowflake"' in text

    def test_snowflake_has_a_providers_map_entry(self):
        text = self._providers_ts_text()
        assert "snowflake: {" in text

    def test_snowflake_in_connectable_provider_ids(self):
        text = self._providers_ts_text()
        start = text.index("export const CONNECTABLE_PROVIDER_IDS")
        end = text.index("];", start)
        block = text[start:end]
        assert '"snowflake"' in block

    def test_snowflake_in_provider_ids_display_order(self):
        text = self._providers_ts_text()
        start = text.index("export const PROVIDER_IDS")
        end = text.index("];", start)
        block = text[start:end]
        assert '"snowflake"' in block

    def test_snowflake_card_copy_no_longer_says_not_yet_connectable(self):
        text = self._providers_ts_text()
        start = text.index("snowflake: {")
        end = text.index("\n  },", start)
        block = text[start:end].lower()
        assert "not yet" not in block
        assert "not yet connectable" not in block
        assert "early foundation" not in block

    def test_snowflake_card_copy_does_not_claim_credential_storage(self):
        text = self._providers_ts_text()
        start = text.index("snowflake: {")
        end = text.index("\n  },", start)
        block = text[start:end].lower()
        for forbidden in ("stores the token value", "stores your password"):
            assert forbidden not in block


# ── Type import sanity (schema/connector modules load cleanly) ─────────────────


class TestModuleImportSanity:
    def test_snowflake_schema_module_imports(self):
        import app.connectors.snowflake_schema  # noqa: F401

    def test_snowflake_connector_module_imports(self):
        import app.connectors.snowflake  # noqa: F401

    def test_snowflake_risk_rules_module_imports(self):
        import app.services.risk_rules.snowflake  # noqa: F401

    def test_all_thirteen_capability_families_are_unique(self):
        from app.connectors.snowflake_schema import CAPABILITY_FAMILIES

        assert len(CAPABILITY_FAMILIES) == 13
        assert len(set(CAPABILITY_FAMILIES)) == 13

    def test_record_types_are_snowflake_prefixed(self):
        from app.connectors.snowflake_schema import ALL_SNOWFLAKE_RECORD_TYPES

        for rt in ALL_SNOWFLAKE_RECORD_TYPES:
            assert rt.startswith("snowflake_")
