"""Okta provider registration/contract tests (Okta message 1 of 8).

Covers everything OUTSIDE the connector's internal collection logic (that's
``test_okta_foundation.py``): provider dispatch wiring (sync_task,
integration_service, sync_service), the credential schema, diff/risk
dispatch (never falling through to an unrelated provider), the capability
matrix entry, and the frontend catalog state (present but not yet
connectable).
"""

from __future__ import annotations

import inspect

import pytest

_ORG_URL = "https://example.okta.com"
_TOKEN = "fake-okta-api-token-value"


# ── Provider dispatch wiring ──────────────────────────────────────────────────

class TestProviderDispatchWiring:
    def test_sync_task_dispatches_okta(self):
        import app.workers.sync_task as sync_task_module

        source = inspect.getsource(sync_task_module)
        assert 'integration.provider == "okta"' in source
        assert "OktaConnector" in source

    def test_integration_service_dispatches_okta(self):
        import app.services.integration_service as isvc

        source = inspect.getsource(isvc)
        assert 'provider == "okta"' in source
        assert "_create_okta_integration" in source

    def test_sync_service_supported_providers_contains_okta(self):
        source = (
            __import__("pathlib").Path(__file__).resolve().parents[1]
            / "app" / "services" / "sync_service.py"
        ).read_text()
        start = source.index("_SUPPORTED_PROVIDERS = (")
        end = source.index(")", start)
        assert '"okta"' in source[start:end]

    def test_create_integration_creates_row_without_leaking_token(
        self, test_user, db_session,
    ):
        from app.models.resource import Resource
        from app.schemas.integration import IntegrationResponse
        from app.services import integration_service

        credentials = {"org_url": _ORG_URL, "api_token": _TOKEN}
        integration = integration_service.create_integration(
            user_id=test_user.id,
            provider="okta",
            display_name="okta-test",
            credentials=credentials,
            db=db_session,
        )
        try:
            assert integration.provider == "okta"
            assert integration.encrypted_credentials is not None
            assert integration.credential_iv is not None

            resource = (
                db_session.query(Resource)
                .filter(Resource.integration_id == integration.id)
                .first()
            )
            assert resource is not None
            assert resource.provider_resource_type == "okta_organization"
            metadata_blob = str(resource.resource_metadata)
            assert _TOKEN not in metadata_blob

            response = IntegrationResponse.model_validate(integration)
            response_blob = response.model_dump_json()
            assert _TOKEN not in response_blob
        finally:
            db_session.delete(integration)
            db_session.commit()

    def test_unsupported_provider_error_mentions_okta(self):
        from app.services import integration_service

        with pytest.raises(ValueError) as exc_info:
            integration_service.create_integration(
                user_id=None,  # never reached — validated before use
                provider="not-a-real-provider",
                display_name="x",
                credentials={},
                db=None,
            )
        assert "okta" in str(exc_info.value)


# ── Credential schema ─────────────────────────────────────────────────────────

class TestCredentialSchema:
    def test_okta_in_provider_literal(self):
        from app.schemas.integration import IntegrationCreateRequest

        req = IntegrationCreateRequest(
            provider="okta",
            display_name="test",
            okta_org_url=_ORG_URL,
            okta_api_token=_TOKEN,
        )
        assert req.provider == "okta"

    def test_validator_rejects_okta_without_org_url(self):
        from app.schemas.integration import IntegrationCreateRequest

        with pytest.raises(Exception):
            IntegrationCreateRequest(
                provider="okta", display_name="test", okta_api_token=_TOKEN,
            )

    def test_validator_rejects_okta_without_api_token(self):
        from app.schemas.integration import IntegrationCreateRequest

        with pytest.raises(Exception):
            IntegrationCreateRequest(
                provider="okta", display_name="test", okta_org_url=_ORG_URL,
            )

    def test_response_schema_never_exposes_api_token(self):
        from app.schemas.integration import IntegrationResponse

        field_names = set(IntegrationResponse.model_fields.keys())
        assert "okta_api_token" not in field_names
        assert "api_token" not in field_names
        assert "encrypted_credentials" not in field_names
        assert "credential_iv" not in field_names

    def test_router_builds_okta_credentials(self):
        from app.routers.integrations import _build_credentials
        from app.schemas.integration import IntegrationCreateRequest

        req = IntegrationCreateRequest(
            provider="okta",
            display_name="test",
            okta_org_url=_ORG_URL,
            okta_api_token=_TOKEN,
        )
        creds = _build_credentials(req)
        assert creds["org_url"] == _ORG_URL
        assert creds["api_token"] == _TOKEN


# ── Diff / risk dispatch (never falls through to an unrelated provider) ─────

class TestDiffAndRiskDispatch:
    def test_tracked_fields_dispatch_never_falls_to_generic_tuple(self):
        from app.services.diff_service import _tracked_fields_for

        fields = _tracked_fields_for({"record_type": "okta_organization"})
        assert "org_hostname" in fields
        # An unmapped okta_* subtype must return () — never fall through to
        # the generic (non-prefixed) _TRACKED_FIELDS tuple used for bare
        # Cloudflare DNS records.
        unmapped = _tracked_fields_for({"record_type": "okta_totally_unknown_type"})
        assert unmapped == ()

    def test_capability_tracked_fields(self):
        from app.services.diff_service import _tracked_fields_for

        fields = _tracked_fields_for({"record_type": "okta_api_capability"})
        assert fields == ("status",)

    def test_classify_change_routes_okta_to_its_own_classifier_not_cloudflare(self):
        from app.services.risk_service import classify_change

        change = type("FakeChange", (), {
            "change_type": "modified",
            "field_path": "status_category",
            "new_value": "suspended",
            "prev_value": "active",
            "provider_metadata": {"record_type": "okta_organization"},
        })()
        level, reason = classify_change(change)
        assert "okta" in reason.lower() or "organization" in reason.lower()

    def test_classify_change_unknown_okta_subtype_fails_safe(self):
        from app.services.risk_service import classify_change

        change = type("FakeChange", (), {
            "change_type": "modified",
            "field_path": "x",
            "new_value": "y",
            "prev_value": "z",
            "provider_metadata": {"record_type": "okta_future_unbuilt_type"},
        })()
        level, reason = classify_change(change)
        assert level == "low"


# ── Capability matrix ──────────────────────────────────────────────────────────

class TestCapabilityMatrix:
    def test_okta_registered_in_partial_list_not_complete_list(self):
        from app.services.provider_capability_matrix_service import (
            PROVIDER_CAPABILITIES,
            PROVIDER_CAPABILITIES_PARTIAL,
        )

        assert "okta" in {p.provider for p in PROVIDER_CAPABILITIES_PARTIAL}
        assert "okta" not in {p.provider for p in PROVIDER_CAPABILITIES}

    def test_okta_drift_snapshots_true_but_security_stack_entirely_false(self):
        from app.services.provider_capability_matrix_service import get_provider_capability

        cap = get_provider_capability("okta")
        assert cap is not None
        assert cap.drift.drift_snapshots is True
        assert cap.drift.drift_diff is True
        assert cap.drift.drift_risk_classification is True
        assert cap.drift.drift_review_workflow is False
        assert cap.security.security_rules is False
        assert cap.security.activity_ingestion is False
        assert cap.security.demo_seed_clear is False

    def test_okta_category_is_valid(self):
        from app.services.provider_capability_matrix_service import (
            CATEGORIES,
            get_provider_capability,
        )

        cap = get_provider_capability("okta")
        assert cap.category in CATEGORIES

    def test_okta_maturity_is_valid(self):
        from app.services.provider_capability_matrix_service import (
            MATURITY_LEVELS,
            get_provider_capability,
        )

        cap = get_provider_capability("okta")
        assert cap.maturity in MATURITY_LEVELS

    def test_get_matrix_does_not_include_okta_yet(self):
        """okta is in PROVIDER_CAPABILITIES_PARTIAL (a staging list), not
        PROVIDER_CAPABILITIES — get_matrix() only reports the latter, so
        Okta must not appear in the public matrix endpoint's provider list
        until a later message promotes it."""
        from app.services.provider_capability_matrix_service import get_matrix

        matrix = get_matrix()
        provider_ids = {p["provider"] for p in matrix["providers"]}
        assert "okta" not in provider_ids


# ── Frontend catalog state ────────────────────────────────────────────────────

class TestFrontendCatalogState:
    """Source-scan checks (no TS execution) confirming Okta is present for
    metadata lookups but NOT yet user-connectable."""

    def _providers_ts_text(self) -> str:
        from pathlib import Path

        path = (
            Path(__file__).resolve().parents[2]
            / "frontend" / "src" / "lib" / "providers.ts"
        )
        return path.read_text()

    def test_okta_present_in_provider_id_type(self):
        text = self._providers_ts_text()
        assert '"okta"' in text

    def test_okta_has_a_providers_map_entry(self):
        text = self._providers_ts_text()
        assert "okta: {" in text

    def test_okta_not_in_connectable_provider_ids(self):
        text = self._providers_ts_text()
        start = text.index("export const CONNECTABLE_PROVIDER_IDS")
        end = text.index("];", start)
        block = text[start:end]
        assert '"okta"' not in block

    def test_okta_not_in_provider_ids_display_order(self):
        text = self._providers_ts_text()
        start = text.index("export const PROVIDER_IDS")
        end = text.index("];", start)
        block = text[start:end]
        assert '"okta"' not in block

    def test_okta_trust_note_does_not_claim_live_coverage(self):
        text = self._providers_ts_text()
        start = text.index("okta: {")
        end = text.index("\n  },", start)
        block = text[start:end]
        assert "foundation" in block.lower() or "planned" in block.lower()

    def test_okta_card_copy_does_not_claim_unsupported_features(self):
        """The card-facing description/monitoredSurfaces copy must not
        claim credential/secret handling. The trustNote is exempt — it
        legitimately *disclaims* these as a reassurance, the same pattern
        every other provider's trustNote uses."""
        text = self._providers_ts_text()
        start = text.index("okta: {")
        trust_note_start = text.index("trustNote:", start)
        card_copy = text[start:trust_note_start].lower()
        for forbidden in ("password", "otp seed", "session token", "private key"):
            assert forbidden not in card_copy


# ── OAuth deferral documentation ────────────────────────────────────────────

class TestOAuthDeferralDocumented:
    def test_connector_docstring_documents_oauth_as_future_enhancement(self):
        import app.connectors.okta as okta_module

        assert "OAuth" in okta_module.__doc__
        assert "future enhancement" in okta_module.__doc__.lower() or "not implemented" in okta_module.__doc__.lower()
