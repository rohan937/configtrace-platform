"""Microsoft Entra ID provider registration/contract tests (Entra message 1
of 8).

Covers everything OUTSIDE the connector's internal collection logic (that's
``test_entra_foundation.py``): provider dispatch wiring (sync_task,
integration_service, sync_service), the credential schema, diff/risk
dispatch (never falling through to an unrelated provider), the capability
matrix entry, and the frontend catalog state (present but not yet
connectable).
"""

from __future__ import annotations

import inspect

import pytest

_TENANT_ID = "11111111-1111-1111-1111-111111111111"
_CLIENT_ID = "22222222-2222-2222-2222-222222222222"
_SECRET = "fake-entra-client-secret-value"


# ── Provider dispatch wiring ──────────────────────────────────────────────────

class TestProviderDispatchWiring:
    def test_sync_task_dispatches_entra(self):
        import app.workers.sync_task as sync_task_module

        source = inspect.getsource(sync_task_module)
        assert 'integration.provider == "entra"' in source
        assert "EntraConnector" in source

    def test_integration_service_dispatches_entra(self):
        import app.services.integration_service as isvc

        source = inspect.getsource(isvc)
        assert 'provider == "entra"' in source
        assert "_create_entra_integration" in source

    def test_sync_service_supported_providers_contains_entra(self):
        source = (
            __import__("pathlib").Path(__file__).resolve().parents[1]
            / "app" / "services" / "sync_service.py"
        ).read_text()
        start = source.index("_SUPPORTED_PROVIDERS = (")
        end = source.index(")", start)
        assert '"entra"' in source[start:end]

    def test_create_integration_creates_row_without_leaking_secret(
        self, test_user, db_session,
    ):
        from unittest.mock import patch

        from app.models.resource import Resource
        from app.schemas.integration import IntegrationResponse
        from app.services import integration_service

        credentials = {"tenant_id": _TENANT_ID, "client_id": _CLIENT_ID, "client_secret": _SECRET}
        integration = integration_service.create_integration(
            user_id=test_user.id,
            provider="entra",
            display_name="entra-test",
            credentials=credentials,
            db=db_session,
        )
        try:
            assert integration.provider == "entra"
            assert integration.encrypted_credentials is not None
            assert integration.credential_iv is not None

            resource = (
                db_session.query(Resource)
                .filter(Resource.integration_id == integration.id)
                .first()
            )
            assert resource is not None
            assert resource.provider_resource_type == "entra_organization"
            metadata_blob = str(resource.resource_metadata)
            assert _SECRET not in metadata_blob

            response = IntegrationResponse.model_validate(integration)
            response_blob = response.model_dump_json()
            assert _SECRET not in response_blob
        finally:
            db_session.delete(integration)
            db_session.commit()

    def test_create_integration_rejects_malformed_tenant_id(self, test_user, db_session):
        from app.services import integration_service

        credentials = {"tenant_id": "not-a-guid", "client_id": _CLIENT_ID, "client_secret": _SECRET}
        with pytest.raises(ValueError):
            integration_service.create_integration(
                user_id=test_user.id,
                provider="entra",
                display_name="entra-bad-tenant",
                credentials=credentials,
                db=db_session,
            )

    def test_create_integration_rejects_multi_tenant_audience(self, test_user, db_session):
        from app.services import integration_service

        credentials = {"tenant_id": "common", "client_id": _CLIENT_ID, "client_secret": _SECRET}
        with pytest.raises(ValueError):
            integration_service.create_integration(
                user_id=test_user.id,
                provider="entra",
                display_name="entra-common-tenant",
                credentials=credentials,
                db=db_session,
            )


# ── Credential schema ──────────────────────────────────────────────────────────

class TestCredentialSchema:
    def test_entra_in_provider_literal(self):
        from app.schemas.integration import IntegrationCreateRequest

        req = IntegrationCreateRequest(
            provider="entra",
            display_name="Test tenant",
            entra_tenant_id=_TENANT_ID,
            entra_client_id=_CLIENT_ID,
            entra_client_secret=_SECRET,
        )
        assert req.provider == "entra"

    def test_missing_tenant_id_rejected(self):
        from pydantic import ValidationError
        from app.schemas.integration import IntegrationCreateRequest

        with pytest.raises(ValidationError):
            IntegrationCreateRequest(
                provider="entra",
                display_name="Test",
                entra_client_id=_CLIENT_ID,
                entra_client_secret=_SECRET,
            )

    def test_missing_client_id_rejected(self):
        from pydantic import ValidationError
        from app.schemas.integration import IntegrationCreateRequest

        with pytest.raises(ValidationError):
            IntegrationCreateRequest(
                provider="entra",
                display_name="Test",
                entra_tenant_id=_TENANT_ID,
                entra_client_secret=_SECRET,
            )

    def test_missing_client_secret_rejected(self):
        from pydantic import ValidationError
        from app.schemas.integration import IntegrationCreateRequest

        with pytest.raises(ValidationError):
            IntegrationCreateRequest(
                provider="entra",
                display_name="Test",
                entra_tenant_id=_TENANT_ID,
                entra_client_id=_CLIENT_ID,
            )

    def test_build_credentials_extracts_entra_fields(self):
        from app.routers.integrations import _build_credentials
        from app.schemas.integration import IntegrationCreateRequest

        req = IntegrationCreateRequest(
            provider="entra",
            display_name="Test",
            entra_tenant_id=_TENANT_ID,
            entra_client_id=_CLIENT_ID,
            entra_client_secret=_SECRET,
        )
        creds = _build_credentials(req)
        assert creds["tenant_id"] == _TENANT_ID
        assert creds["client_id"] == _CLIENT_ID
        assert creds["client_secret"] == _SECRET


# ── Diff / risk dispatch ────────────────────────────────────────────────────────

class TestDiffRiskDispatch:
    def test_organization_change_routes_to_entra_classifier(self):
        from app.services.risk_service import classify_change

        change = {
            "change_type": "modified",
            "provider_metadata": {"record_type": "entra_organization"},
            "field_path": "display_name",
        }
        level, reason = classify_change(change)
        assert "Entra" in reason

    def test_capability_change_routes_to_entra_classifier(self):
        from app.services.risk_service import classify_change

        change = {
            "change_type": "modified",
            "provider_metadata": {"record_type": "entra_api_capability"},
            "field_path": "status",
            "prev_value": "available",
            "new_value": "denied",
        }
        level, reason = classify_change(change)
        assert level == "medium"
        assert "Entra" in reason

    def test_unknown_entra_record_type_fails_safe(self):
        from app.services.risk_rules.entra import classify_entra_change

        change = {
            "change_type": "modified",
            "provider_metadata": {"record_type": "entra_future_thing"},
        }
        level, reason = classify_entra_change(change)
        assert level == "low"

    def test_real_compute_diff_produces_entra_provider_metadata(self):
        from types import SimpleNamespace

        from app.services.diff_service import compute_diff

        prev_snapshot = SimpleNamespace(state=[{
            "record_type": "entra_organization",
            "record_id": "id:" + _TENANT_ID,
            "tenant_id": "id:" + _TENANT_ID,
            "display_name": "Old Name",
        }])
        new_snapshot = SimpleNamespace(state=[{
            "record_type": "entra_organization",
            "record_id": "id:" + _TENANT_ID,
            "tenant_id": "id:" + _TENANT_ID,
            "display_name": "New Name",
        }])
        changes = compute_diff(prev_snapshot, new_snapshot)
        assert len(changes) == 1
        change = changes[0]
        pm = change["provider_metadata"]
        assert pm["record_type"] == "entra_organization"
        assert "client_id" not in pm
        assert "client_secret" not in pm
        assert "access_token" not in pm


# ── Capability matrix ─────────────────────────────────────────────────────────

class TestCapabilityMatrix:
    def test_entra_registered_in_partial_list_not_complete_list(self):
        from app.services.provider_capability_matrix_service import (
            PROVIDER_CAPABILITIES,
            PROVIDER_CAPABILITIES_PARTIAL,
        )

        assert "entra" in {p.provider for p in PROVIDER_CAPABILITIES_PARTIAL}
        assert "entra" not in {p.provider for p in PROVIDER_CAPABILITIES}

    def test_entra_drift_snapshots_true_security_rules_true(self):
        from app.services.provider_capability_matrix_service import get_provider_capability

        cap = get_provider_capability("entra")
        assert cap is not None
        assert cap.drift.drift_snapshots is True
        assert cap.drift.drift_diff is True
        assert cap.drift.drift_risk_classification is True
        assert cap.drift.drift_review_workflow is False
        # Security Findings landed in Entra message 6 — security_rules is now
        # True, but the provider remains internal/non-connectable (no
        # activity ingestion/demo seeding) until Entra message 8.
        assert cap.security.security_rules is True
        assert cap.security.activity_ingestion is False
        assert cap.security.demo_seed_clear is False

    def test_entra_category_is_valid(self):
        from app.services.provider_capability_matrix_service import (
            CATEGORIES,
            get_provider_capability,
        )

        cap = get_provider_capability("entra")
        assert cap.category in CATEGORIES

    def test_entra_maturity_is_valid(self):
        from app.services.provider_capability_matrix_service import (
            MATURITY_LEVELS,
            get_provider_capability,
        )

        cap = get_provider_capability("entra")
        assert cap.maturity in MATURITY_LEVELS

    def test_get_matrix_does_not_include_entra_yet(self):
        """entra is in PROVIDER_CAPABILITIES_PARTIAL (a staging list), not
        PROVIDER_CAPABILITIES — get_matrix() only reports the latter, so
        Entra must not appear in the public matrix endpoint's provider list
        until a later message promotes it."""
        from app.services.provider_capability_matrix_service import get_matrix

        matrix = get_matrix()
        provider_ids = {p["provider"] for p in matrix["providers"]}
        assert "entra" not in provider_ids

    def test_entra_not_in_security_coverage_providers_yet(self):
        from app.services.security_coverage_service import PROVIDERS

        assert "entra" not in PROVIDERS


# ── Frontend catalog state ────────────────────────────────────────────────────

class TestFrontendCatalogState:
    """Source-scan checks (no TS execution) confirming Entra is present for
    metadata lookups but NOT yet user-connectable."""

    def _providers_ts_text(self) -> str:
        from pathlib import Path

        path = (
            Path(__file__).resolve().parents[2]
            / "frontend" / "src" / "lib" / "providers.ts"
        )
        if not path.is_file():
            pytest.skip("frontend tree not found")
        return path.read_text()

    def test_entra_present_in_provider_id_type(self):
        text = self._providers_ts_text()
        assert '"entra"' in text

    def test_entra_has_a_providers_map_entry(self):
        text = self._providers_ts_text()
        assert "entra: {" in text

    def test_entra_not_in_connectable_provider_ids(self):
        text = self._providers_ts_text()
        start = text.index("export const CONNECTABLE_PROVIDER_IDS")
        end = text.index("];", start)
        block = text[start:end]
        assert '"entra"' not in block

    def test_entra_not_in_provider_ids_display_order(self):
        text = self._providers_ts_text()
        start = text.index("export const PROVIDER_IDS")
        end = text.index("];", start)
        block = text[start:end]
        assert '"entra"' not in block

    def test_entra_trust_note_does_not_claim_live_coverage(self):
        text = self._providers_ts_text()
        start = text.index("entra: {")
        end = text.index("\n  },", start)
        block = text[start:end]
        assert "foundation" in block.lower() or "planned" in block.lower()

    def test_entra_display_name_is_microsoft_entra_id_not_azure_ad(self):
        text = self._providers_ts_text()
        start = text.index("entra: {")
        end = text.index("\n  },", start)
        block = text[start:end]
        label_line = next(line for line in block.splitlines() if line.strip().startswith("label:"))
        assert "Microsoft Entra ID" in label_line
        assert "Azure AD" not in label_line

    def test_entra_card_copy_does_not_claim_unsupported_features(self):
        """The card-facing description/monitoredSurfaces copy must not
        claim credential/secret handling. The trustNote is exempt — it
        legitimately *disclaims* these as a reassurance, the same pattern
        every other provider's trustNote uses."""
        text = self._providers_ts_text()
        start = text.index("entra: {")
        trust_note_start = text.index("trustNote:", start)
        card_copy = text[start:trust_note_start].lower()
        for forbidden in ("client_secret", "otp seed", "session token", "private key"):
            assert forbidden not in card_copy

    def test_entra_does_not_claim_national_cloud_support(self):
        text = self._providers_ts_text()
        start = text.index("entra: {")
        end = text.index("\n  },", start)
        block = text[start:end]
        assert "GCC High" in block or "national cloud" in block.lower()
        # Never silently claim national-cloud support.
        assert "GCC High, DoD, and China" in block or "not supported" in block.lower()


# ── Distinct from the existing Azure infrastructure provider ────────────────

class TestDistinctFromAzureProvider:
    def test_entra_connector_does_not_import_azure_connector(self):
        import app.connectors.entra as entra_module

        source = inspect.getsource(entra_module)
        assert "AzureConnector" not in source
        assert "app.connectors.azure" not in source

    def test_entra_record_types_do_not_collide_with_azure_record_types(self):
        from app.connectors.entra_schema import ENTRA_RECORD_TYPES

        for rt in ENTRA_RECORD_TYPES:
            assert not rt.startswith("azure_")
            assert rt.startswith("entra_")

    def test_azure_connector_untouched_still_registered(self):
        """This message must not remove or weaken the existing Azure
        infrastructure provider's registration."""
        from app.services.provider_capability_matrix_service import get_provider_capability

        cap = get_provider_capability("azure")
        assert cap is not None
        assert cap.label == "Azure"


# ── National cloud / OAuth scope documentation ──────────────────────────────

class TestCloudScopeDocumented:
    def test_connector_docstring_documents_commercial_cloud_only(self):
        import app.connectors.entra as entra_module

        assert entra_module.__doc__ is not None
        doc_lower = entra_module.__doc__.lower()
        assert "commercial" in doc_lower or "global cloud" in doc_lower
        assert "gcc high" in doc_lower or "not supported" in doc_lower

    def test_connector_docstring_documents_certificate_auth_as_future(self):
        import app.connectors.entra as entra_module

        doc_lower = entra_module.__doc__.lower()
        assert "certificate" in doc_lower
        assert "future enhancement" in doc_lower or "not implemented" in doc_lower

    def test_graph_scope_is_default_not_delegated(self):
        import app.connectors.entra as entra_module

        assert entra_module._GRAPH_SCOPE == "https://graph.microsoft.com/.default"
