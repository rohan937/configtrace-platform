"""Sentry provider registration/contract tests (Sentry message 1 of 8).

Covers everything OUTSIDE the connector's internal collection logic
(that's ``test_sentry_foundation.py``): provider dispatch wiring
(sync_task, integration_service, sync_service), the credential schema,
diff/risk dispatch (never falling through to an unrelated provider), the
capability matrix entry (staged in PROVIDER_CAPABILITIES_PARTIAL, not the
canonical complete list), the frontend catalog state (present but
explicitly not yet user-connectable), and the telemetry-vs-provider
separation boundary (ConfigTrace's own Sentry SDK/env vars, if ever
added, must never leak into this connector).
"""

from __future__ import annotations

import inspect

import pytest

_SLUG = "my-organization"
_TOKEN = "fake-sentry-auth-token-value"


# ── Provider dispatch wiring ──────────────────────────────────────────────────


class TestProviderDispatchWiring:
    def test_sync_task_dispatches_sentry(self):
        import app.workers.sync_task as sync_task_module

        source = inspect.getsource(sync_task_module)
        assert 'integration.provider == "sentry"' in source
        assert "SentryConnector" in source

    def test_integration_service_dispatches_sentry(self):
        import app.services.integration_service as isvc

        source = inspect.getsource(isvc)
        assert 'provider == "sentry"' in source
        assert "_create_sentry_integration" in source

    def test_sync_service_supported_providers_contains_sentry(self):
        source = (
            __import__("pathlib").Path(__file__).resolve().parents[1]
            / "app" / "services" / "sync_service.py"
        ).read_text()
        start = source.index("_SUPPORTED_PROVIDERS = (")
        end = source.index(")", start)
        assert '"sentry"' in source[start:end]

    def test_create_integration_creates_row_without_leaking_secret(
        self, test_user, db_session,
    ):
        from app.models.resource import Resource
        from app.schemas.integration import IntegrationResponse
        from app.services import integration_service

        credentials = {
            "organization_slug": _SLUG,
            "auth_token": _TOKEN,
        }
        integration = integration_service.create_integration(
            user_id=test_user.id,
            provider="sentry",
            display_name="sentry-test",
            credentials=credentials,
            db=db_session,
        )
        try:
            assert integration.provider == "sentry"
            assert integration.encrypted_credentials is not None
            assert integration.credential_iv is not None

            resource = (
                db_session.query(Resource)
                .filter(Resource.integration_id == integration.id)
                .first()
            )
            assert resource is not None
            assert resource.provider_resource_type == "sentry_organization"
            metadata_blob = str(resource.resource_metadata)
            assert _TOKEN not in metadata_blob

            response = IntegrationResponse.model_validate(integration)
            response_blob = response.model_dump_json()
            assert _TOKEN not in response_blob
        finally:
            db_session.delete(integration)
            db_session.commit()

    def test_create_integration_rejects_malformed_organization_slug(self, test_user, db_session):
        from app.services import integration_service

        credentials = {
            "organization_slug": "https://evil.example",
            "auth_token": _TOKEN,
        }
        with pytest.raises(ValueError):
            integration_service.create_integration(
                user_id=test_user.id,
                provider="sentry",
                display_name="sentry-bad-slug",
                credentials=credentials,
                db=db_session,
            )

    def test_create_integration_does_not_contact_sentry(self, test_user, db_session):
        """Message 1 defers credential validation to first sync — creating
        the integration must never make an outbound HTTP call."""
        from unittest.mock import patch

        from app.connectors.sentry import SentryConnector
        from app.services import integration_service

        credentials = {
            "organization_slug": _SLUG,
            "auth_token": _TOKEN,
        }
        with patch.object(SentryConnector, "validate_credentials") as mock_validate:
            integration = integration_service.create_integration(
                user_id=test_user.id,
                provider="sentry",
                display_name="sentry-no-contact",
                credentials=credentials,
                db=db_session,
            )
            mock_validate.assert_not_called()
        db_session.delete(integration)
        db_session.commit()


# ── Credential schema ──────────────────────────────────────────────────────────


class TestCredentialSchema:
    def test_sentry_in_provider_literal(self):
        from app.schemas.integration import IntegrationCreateRequest

        req = IntegrationCreateRequest(
            provider="sentry",
            display_name="Test org",
            sentry_organization_slug=_SLUG,
            sentry_auth_token=_TOKEN,
        )
        assert req.provider == "sentry"

    def test_missing_organization_slug_rejected(self):
        from pydantic import ValidationError
        from app.schemas.integration import IntegrationCreateRequest

        with pytest.raises(ValidationError):
            IntegrationCreateRequest(
                provider="sentry",
                display_name="Test",
                sentry_auth_token=_TOKEN,
            )

    def test_missing_auth_token_rejected(self):
        from pydantic import ValidationError
        from app.schemas.integration import IntegrationCreateRequest

        with pytest.raises(ValidationError):
            IntegrationCreateRequest(
                provider="sentry",
                display_name="Test",
                sentry_organization_slug=_SLUG,
            )

    def test_build_credentials_extracts_sentry_fields(self):
        from app.routers.integrations import _build_credentials
        from app.schemas.integration import IntegrationCreateRequest

        req = IntegrationCreateRequest(
            provider="sentry",
            display_name="Test",
            sentry_organization_slug=_SLUG,
            sentry_auth_token=_TOKEN,
        )
        creds = _build_credentials(req)
        assert creds["organization_slug"] == _SLUG
        assert creds["auth_token"] == _TOKEN


# ── Diff / risk dispatch ────────────────────────────────────────────────────────


class TestDiffRiskDispatch:
    def test_organization_change_routes_to_sentry_classifier(self):
        from app.services.risk_service import classify_change

        change = {
            "change_type": "modified",
            "provider_metadata": {"record_type": "sentry_organization"},
            "field_path": "name",
        }
        level, reason = classify_change(change)
        assert "Sentry" in reason

    def test_capability_change_routes_to_sentry_classifier(self):
        from app.services.risk_service import classify_change

        change = {
            "change_type": "modified",
            "provider_metadata": {"record_type": "sentry_api_capability"},
            "field_path": "status",
            "prev_value": "available",
            "new_value": "denied",
        }
        level, reason = classify_change(change)
        assert level == "medium"
        assert "Sentry" in reason

    def test_unknown_sentry_record_type_fails_safe(self):
        from app.services.risk_rules.sentry import classify_sentry_change

        change = {
            "change_type": "modified",
            "provider_metadata": {"record_type": "sentry_future_thing"},
        }
        level, reason = classify_sentry_change(change)
        assert level == "low"

    def test_real_compute_diff_produces_sentry_provider_metadata(self):
        from types import SimpleNamespace

        from app.services.diff_service import compute_diff

        prev_snapshot = SimpleNamespace(state=[{
            "record_type": "sentry_organization",
            "record_id": "id:123456",
            "organization_id": "id:123456",
            "slug": _SLUG,
            "name": "My Organization",
        }])
        new_snapshot = SimpleNamespace(state=[{
            "record_type": "sentry_organization",
            "record_id": "id:123456",
            "organization_id": "id:123456",
            "slug": _SLUG,
            "name": "My Renamed Organization",
        }])
        changes = compute_diff(prev_snapshot, new_snapshot)
        assert len(changes) == 1
        change = changes[0]
        pm = change["provider_metadata"]
        assert pm["record_type"] == "sentry_organization"
        assert "auth_token" not in pm

    def test_slug_change_is_tracked(self):
        from types import SimpleNamespace

        from app.services.diff_service import compute_diff

        prev_snapshot = SimpleNamespace(state=[{
            "record_type": "sentry_organization",
            "record_id": "id:123456",
            "organization_id": "id:123456",
            "slug": "old-slug",
            "name": "My Organization",
        }])
        new_snapshot = SimpleNamespace(state=[{
            "record_type": "sentry_organization",
            "record_id": "id:123456",
            "organization_id": "id:123456",
            "slug": "new-slug",
            "name": "My Organization",
        }])
        changes = compute_diff(prev_snapshot, new_snapshot)
        assert len(changes) == 1
        assert changes[0]["field_path"] == "slug"

    def test_family_completeness_not_tracked(self):
        """family_completeness is informational context only — a
        permission change alone must never produce a noisy Change."""
        from types import SimpleNamespace

        from app.services.diff_service import compute_diff

        prev_snapshot = SimpleNamespace(state=[{
            "record_type": "sentry_organization",
            "record_id": "id:123456",
            "organization_id": "id:123456",
            "slug": _SLUG,
            "name": "My Organization",
            "family_completeness": {"projects": "complete"},
        }])
        new_snapshot = SimpleNamespace(state=[{
            "record_type": "sentry_organization",
            "record_id": "id:123456",
            "organization_id": "id:123456",
            "slug": _SLUG,
            "name": "My Organization",
            "family_completeness": {"projects": "unavailable"},
        }])
        changes = compute_diff(prev_snapshot, new_snapshot)
        assert len(changes) == 0


# ── Capability matrix ─────────────────────────────────────────────────────────


class TestCapabilityMatrix:
    def test_sentry_registered_in_partial_list_not_complete_list(self):
        """Message 1: Sentry is foundation-only — it must appear in the
        PROVIDER_CAPABILITIES_PARTIAL staging list, not the canonical
        PROVIDER_CAPABILITIES list."""
        from app.services.provider_capability_matrix_service import (
            PROVIDER_CAPABILITIES,
            PROVIDER_CAPABILITIES_PARTIAL,
        )

        assert "sentry" in {p.provider for p in PROVIDER_CAPABILITIES_PARTIAL}
        assert "sentry" not in {p.provider for p in PROVIDER_CAPABILITIES}

    def test_sentry_drift_true_security_rules_true(self):
        from app.services.provider_capability_matrix_service import get_provider_capability

        cap = get_provider_capability("sentry")
        assert cap is not None
        assert cap.drift.drift_snapshots is True
        assert cap.drift.drift_diff is True
        assert cap.drift.drift_risk_classification is True
        assert cap.drift.drift_review_workflow is False
        # Security Findings implemented in Sentry message 6.
        assert cap.security.security_rules is True
        assert cap.security.activity_ingestion is False
        assert cap.security.demo_seed_clear is False

    def test_sentry_category_is_valid(self):
        from app.services.provider_capability_matrix_service import (
            CATEGORIES,
            get_provider_capability,
        )

        cap = get_provider_capability("sentry")
        assert cap.category in CATEGORIES
        assert cap.category == "observability"

    def test_sentry_maturity_is_valid(self):
        from app.services.provider_capability_matrix_service import (
            MATURITY_LEVELS,
            get_provider_capability,
        )

        cap = get_provider_capability("sentry")
        assert cap.maturity in MATURITY_LEVELS
        assert cap.maturity == "planned"

    def test_get_matrix_excludes_sentry_until_complete(self):
        """get_matrix() only ever surfaces PROVIDER_CAPABILITIES (the
        canonical complete list) — Sentry is staged in PARTIAL and must
        not appear in the public matrix endpoint's provider list yet."""
        from app.services.provider_capability_matrix_service import get_matrix

        matrix = get_matrix()
        provider_ids = {p["provider"] for p in matrix["providers"]}
        assert "sentry" not in provider_ids

    def test_sentry_in_security_coverage_providers(self):
        from app.services.security_coverage_service import PROVIDERS

        assert "sentry" in PROVIDERS


# ── Frontend catalog state ────────────────────────────────────────────────────


class TestFrontendCatalogState:
    """Source-scan checks (no TS execution) confirming Sentry is present
    internally but NOT yet user-connectable (message 1 of 8)."""

    def _providers_ts_text(self) -> str:
        from pathlib import Path

        path = (
            Path(__file__).resolve().parents[2]
            / "frontend" / "src" / "lib" / "providers.ts"
        )
        if not path.is_file():
            pytest.skip("frontend tree not found")
        return path.read_text()

    def test_sentry_present_in_provider_id_type(self):
        text = self._providers_ts_text()
        assert '"sentry"' in text

    def test_sentry_has_a_providers_map_entry(self):
        text = self._providers_ts_text()
        assert "sentry: {" in text

    def test_sentry_not_in_connectable_provider_ids(self):
        text = self._providers_ts_text()
        start = text.index("export const CONNECTABLE_PROVIDER_IDS")
        end = text.index("];", start)
        block = text[start:end]
        assert '"sentry"' not in block

    def test_sentry_not_in_provider_ids_display_order(self):
        text = self._providers_ts_text()
        start = text.index("export const PROVIDER_IDS")
        end = text.index("];", start)
        block = text[start:end]
        assert '"sentry"' not in block

    def test_sentry_card_copy_is_truthful_about_not_yet_connectable(self):
        text = self._providers_ts_text()
        start = text.index("sentry: {")
        end = text.index("\n  },", start)
        block = text[start:end].lower()
        assert "not yet" in block or "not yet connectable" in block or "planned" in block

    def test_sentry_card_copy_does_not_claim_credential_storage(self):
        text = self._providers_ts_text()
        start = text.index("sentry: {")
        end = text.index("\n  },", start)
        block = text[start:end].lower()
        for forbidden in ("stores the token value", "stores your password"):
            assert forbidden not in block

    def test_sentry_card_copy_never_claims_event_data_monitoring(self):
        """The description/monitoredSurfaces copy (what ConfigTrace
        actively monitors) must never claim event data. The trustNote is
        exempt — it legitimately *disclaims* these as a reassurance, same
        pattern as every other provider's trustNote (see
        test_snowflake_provider_depth_qa.py's analogous check)."""
        text = self._providers_ts_text()
        start = text.index("sentry: {")
        trust_note_start = text.index("trustNote:", start)
        card_copy = text[start:trust_note_start].lower()
        for forbidden in ("stack trace", "error event", "breadcrumb", "issue message"):
            assert forbidden not in card_copy


# ── Telemetry vs monitored-provider separation ──────────────────────────────────


class TestTelemetrySeparation:
    """Permanent boundary: ConfigTrace's OWN Sentry SDK/telemetry
    configuration (if ever added) must never be confused with a
    customer's Sentry integration credentials. See the connector module
    docstring's dedicated section on this."""

    def test_connector_never_imports_sentry_sdk(self):
        source = (
            __import__("pathlib").Path(__file__).resolve().parents[1]
            / "app" / "connectors" / "sentry.py"
        ).read_text()
        assert "import sentry_sdk" not in source
        assert "from sentry_sdk" not in source
        assert "sentry_sdk.init(" not in source

    def test_connector_never_reads_sentry_dsn_env_var(self):
        """SENTRY_DSN legitimately appears in this module's own docstring
        prose explaining that it is NEVER read — this test checks for an
        actual environment-variable ACCESS pattern, not the bare string."""
        source = (
            __import__("pathlib").Path(__file__).resolve().parents[1]
            / "app" / "connectors" / "sentry.py"
        ).read_text()
        assert "os.environ" not in source
        assert "os.getenv" not in source
        assert 'environ["SENTRY_DSN"]' not in source
        assert 'environ.get("SENTRY_DSN"' not in source

    def test_connector_never_reads_sentry_auth_token_env_var(self):
        source = (
            __import__("pathlib").Path(__file__).resolve().parents[1]
            / "app" / "connectors" / "sentry.py"
        ).read_text()
        assert 'environ["SENTRY_AUTH_TOKEN"]' not in source
        assert 'environ.get("SENTRY_AUTH_TOKEN"' not in source

    def test_customer_token_comes_only_from_credentials_dict(self):
        """validate_credentials/fetch both derive the token exclusively
        from the `credentials` dict argument — never a module-level
        constant, global, or environment variable."""
        from app.connectors.sentry import SentryConnector

        validate_source = inspect.getsource(SentryConnector.validate_credentials)
        fetch_source = inspect.getsource(SentryConnector.fetch)
        for source in (validate_source, fetch_source):
            assert "credentials.get(" in source or "self._credentials(credentials)" in source
            assert "os.environ" not in source
            assert "os.getenv" not in source

    def test_no_global_sentry_env_vars_added_to_settings(self):
        source = (
            __import__("pathlib").Path(__file__).resolve().parents[1]
            / "app" / "config.py"
        ).read_text()
        assert "SENTRY_AUTH_TOKEN" not in source
        assert "SENTRY_ORG" not in source


# ── Type import sanity (schema/connector modules load cleanly) ─────────────────


class TestModuleImportSanity:
    def test_sentry_schema_module_imports(self):
        import app.connectors.sentry_schema  # noqa: F401

    def test_sentry_connector_module_imports(self):
        import app.connectors.sentry  # noqa: F401

    def test_sentry_risk_rules_module_imports(self):
        import app.services.risk_rules.sentry  # noqa: F401

    def test_all_ten_capability_families_are_unique(self):
        from app.connectors.sentry_schema import CAPABILITY_FAMILIES

        assert len(CAPABILITY_FAMILIES) == 10
        assert len(set(CAPABILITY_FAMILIES)) == 10

    def test_record_types_are_sentry_prefixed(self):
        from app.connectors.sentry_schema import ALL_SENTRY_RECORD_TYPES

        for rt in ALL_SENTRY_RECORD_TYPES:
            assert rt.startswith("sentry_")

    def test_no_mutating_http_methods_in_connector(self):
        source = (
            __import__("pathlib").Path(__file__).resolve().parents[1]
            / "app" / "connectors" / "sentry.py"
        ).read_text()
        for method in (".post(", ".put(", ".patch(", ".delete("):
            assert method not in source
