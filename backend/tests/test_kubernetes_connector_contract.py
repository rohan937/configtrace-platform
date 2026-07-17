"""Kubernetes provider registration/contract tests (Kubernetes message 1 of 9).

Covers everything OUTSIDE the connector's internal collection logic (that's
``test_kubernetes_foundation.py``): validate_credentials() routing, provider
dispatch wiring (sync_task, integration_service, sync_service), the
credential schema, diff/risk dispatch (never falling through to an
unrelated provider), the capability matrix entry, and the frontend catalog
state (present but not yet connectable).
"""

from __future__ import annotations

import inspect
from unittest.mock import MagicMock, patch

import pytest
from kubernetes.client.rest import ApiException

from app.connectors.exceptions import AuthenticationError, ConnectorError, NetworkError
from app.connectors.kubernetes import KubernetesConnector


def _fake_kubeconfig() -> str:
    return """
apiVersion: v1
kind: Config
current-context: ctx
clusters:
  - name: c
    cluster:
      server: https://10.0.0.5:6443
contexts:
  - name: ctx
    context:
      cluster: c
      user: u
users:
  - name: u
    user:
      token: "fake-token"
"""


# ── validate_credentials() routing ───────────────────────────────────────────

class TestValidateCredentials:
    def _connector_with_stubbed_client(self, version_side_effect):
        connector = KubernetesConnector()
        fake_api_client = MagicMock()
        fake_api_client.configuration.verify_ssl = True
        fake_api_client.configuration.host = "https://10.0.0.5:6443"

        patcher = patch.object(
            connector, "_build_api_client",
            return_value=(fake_api_client, {}, "ctx"),
        )
        version_patcher = patch("kubernetes.client.VersionApi")
        return connector, patcher, version_patcher, fake_api_client, version_side_effect

    def test_success_returns_true(self):
        connector, patcher, version_patcher, _api_client, _ = self._connector_with_stubbed_client(None)
        with patcher, version_patcher as mock_version_api:
            mock_version_api.return_value.get_code.return_value = MagicMock(git_version="v1.29.0")
            assert connector.validate_credentials({"kubeconfig": _fake_kubeconfig()}) is True

    def test_401_raises_authentication_error(self):
        connector, patcher, version_patcher, _api_client, _ = self._connector_with_stubbed_client(None)
        with patcher, version_patcher as mock_version_api:
            mock_version_api.return_value.get_code.side_effect = ApiException(status=401)
            with pytest.raises(AuthenticationError):
                connector.validate_credentials({"kubeconfig": _fake_kubeconfig()})

    def test_connection_error_raises_network_error(self):
        connector, patcher, version_patcher, _api_client, _ = self._connector_with_stubbed_client(None)
        with patcher, version_patcher as mock_version_api:
            mock_version_api.return_value.get_code.side_effect = ConnectionError("no route")
            with pytest.raises(NetworkError):
                connector.validate_credentials({"kubeconfig": _fake_kubeconfig()})

    def test_does_not_require_cluster_admin(self):
        # Structural guarantee: validate_credentials only calls VersionApi,
        # never a privileged cluster-admin-only endpoint.
        source = inspect.getsource(KubernetesConnector.validate_credentials)
        assert "VersionApi" in source
        assert "create_" not in source
        assert "delete_" not in source
        assert "patch_" not in source

    def test_malformed_kubeconfig_fails_before_any_api_call(self):
        connector = KubernetesConnector()
        with pytest.raises(ConnectorError):
            connector.validate_credentials({"kubeconfig": "not valid: [yaml"})


# ── Provider dispatch wiring ──────────────────────────────────────────────────

class TestProviderDispatchWiring:
    def test_sync_task_dispatches_kubernetes(self):
        import app.workers.sync_task as sync_task_module

        source = inspect.getsource(sync_task_module)
        assert 'integration.provider == "kubernetes"' in source
        assert "KubernetesConnector" in source

    def test_integration_service_dispatches_kubernetes(self):
        import app.services.integration_service as isvc

        source = inspect.getsource(isvc)
        assert 'provider == "kubernetes"' in source
        assert "_create_kubernetes_integration" in source

    def test_sync_service_supported_providers_contains_kubernetes(self):
        import app.services.sync_service as sync_service_module

        source = inspect.getsource(sync_service_module)
        assert '"kubernetes"' in source

    def test_create_integration_creates_row_without_leaking_kubeconfig(
        self, test_user, db_session,
    ):
        from app.models.resource import Resource
        from app.schemas.integration import IntegrationResponse
        from app.services import integration_service

        kubeconfig = _fake_kubeconfig()
        credentials = {
            "kubeconfig": kubeconfig,
            "context": "ctx",
            "cluster_name": "staging-cluster",
        }
        integration = integration_service.create_integration(
            user_id=test_user.id,
            provider="kubernetes",
            display_name="k8s-test",
            credentials=credentials,
            db=db_session,
        )
        try:
            assert integration.provider == "kubernetes"
            assert integration.encrypted_credentials is not None
            assert integration.credential_iv is not None

            resource = (
                db_session.query(Resource)
                .filter(Resource.integration_id == integration.id)
                .first()
            )
            assert resource is not None
            assert resource.provider_resource_type == "kubernetes_cluster"
            metadata_blob = str(resource.resource_metadata)
            assert "fake-token" not in metadata_blob
            assert kubeconfig not in metadata_blob
            assert "apiVersion" not in metadata_blob

            response = IntegrationResponse.model_validate(integration)
            response_blob = response.model_dump_json()
            assert "fake-token" not in response_blob
            assert kubeconfig not in response_blob
        finally:
            db_session.delete(integration)
            db_session.commit()

    def test_unsupported_provider_error_mentions_kubernetes(self):
        from app.services import integration_service

        with pytest.raises(ValueError) as exc_info:
            integration_service.create_integration(
                user_id=None,  # never reached — validated before use
                provider="not-a-real-provider",
                display_name="x",
                credentials={},
                db=None,
            )
        assert "kubernetes" in str(exc_info.value)


# ── Credential schema ─────────────────────────────────────────────────────────

class TestCredentialSchema:
    def test_kubernetes_in_provider_literal(self):
        from app.schemas.integration import IntegrationCreateRequest

        req = IntegrationCreateRequest(
            provider="kubernetes",
            display_name="test",
            kubeconfig=_fake_kubeconfig(),
        )
        assert req.provider == "kubernetes"

    def test_validator_rejects_kubernetes_without_kubeconfig(self):
        from app.schemas.integration import IntegrationCreateRequest

        with pytest.raises(Exception):
            IntegrationCreateRequest(provider="kubernetes", display_name="test")

    def test_namespace_allowlist_accepts_list_of_strings(self):
        from app.schemas.integration import IntegrationCreateRequest

        req = IntegrationCreateRequest(
            provider="kubernetes",
            display_name="test",
            kubeconfig=_fake_kubeconfig(),
            namespace_allowlist=["team-a", "team-b"],
        )
        assert req.namespace_allowlist == ["team-a", "team-b"]

    def test_response_schema_never_exposes_kubeconfig(self):
        from app.schemas.integration import IntegrationResponse

        field_names = set(IntegrationResponse.model_fields.keys())
        assert "kubeconfig" not in field_names
        assert "encrypted_credentials" not in field_names
        assert "credential_iv" not in field_names


# ── Diff / risk dispatch (never falls through to an unrelated provider) ─────

class TestDiffAndRiskDispatch:
    def test_tracked_fields_dispatch_never_falls_to_generic_tuple(self):
        from app.services.diff_service import _tracked_fields_for

        fields = _tracked_fields_for({"record_type": "kubernetes_cluster"})
        assert "kubernetes_version" in fields
        # An unmapped kubernetes_* subtype must return () — never fall
        # through to the generic (non-prefixed) _TRACKED_FIELDS tuple used
        # for bare Cloudflare DNS records.
        unmapped = _tracked_fields_for({"record_type": "kubernetes_totally_unknown_type"})
        assert unmapped == ()

    def test_namespace_tracked_fields_include_psa_labels(self):
        from app.services.diff_service import _tracked_fields_for

        fields = _tracked_fields_for({"record_type": "kubernetes_namespace"})
        assert "psa_enforce" in fields
        assert "phase" in fields

    def test_api_capability_has_no_tracked_fields(self):
        from app.services.diff_service import _tracked_fields_for

        fields = _tracked_fields_for({"record_type": "kubernetes_api_capability"})
        assert fields == ()

    def test_classify_change_routes_kubernetes_to_its_own_classifier_not_cloudflare(self):
        from app.services.risk_service import classify_change

        change = MagicMock()
        change.provider_metadata = {"record_type": "kubernetes_namespace"}
        change.field_path = "psa_enforce"
        change.change_type = "modified"
        change.new_value = None
        change.prev_value = "restricted"
        level, reason = classify_change(change)
        assert "kubernetes" in reason.lower() or "pod security" in reason.lower()

    def test_classify_kubernetes_change_never_raises_on_unknown_record_type(self):
        from app.services.risk_rules.kubernetes import classify_kubernetes_change

        change = {
            "provider_metadata": {"record_type": "kubernetes_not_built_yet"},
            "change_type": "modified",
            "field_path": "x",
        }
        level, reason = classify_kubernetes_change(change)
        assert level == "low"
        assert "kubernetes" in reason.lower()


# ── Capability matrix ─────────────────────────────────────────────────────────

class TestCapabilityMatrix:
    def test_get_provider_capability_kubernetes_not_none(self):
        from app.services.provider_capability_matrix_service import get_provider_capability

        cap = get_provider_capability("kubernetes")
        assert cap is not None

    def test_kubernetes_maturity_is_planned(self):
        from app.services.provider_capability_matrix_service import get_provider_capability

        cap = get_provider_capability("kubernetes")
        assert cap.maturity == "planned"

    def test_kubernetes_drift_snapshots_true_but_nothing_else(self):
        from app.services.provider_capability_matrix_service import get_provider_capability

        cap = get_provider_capability("kubernetes")
        assert cap.drift.drift_snapshots is True
        assert cap.drift.drift_diff is False
        assert cap.drift.drift_risk_classification is False
        assert cap.drift.drift_review_workflow is False

    def test_kubernetes_security_stack_entirely_false(self):
        from app.services.provider_capability_matrix_service import get_provider_capability

        cap = get_provider_capability("kubernetes")
        assert cap.security.security_rules is False
        assert cap.security.activity_ingestion is False
        assert cap.security.demo_seed_clear is False

    def test_kubernetes_category_is_valid(self):
        from app.services.provider_capability_matrix_service import (
            CATEGORIES,
            get_provider_capability,
        )

        cap = get_provider_capability("kubernetes")
        assert cap.category in CATEGORIES

    def test_kubernetes_no_longer_head_of_expansion_queue(self):
        from app.services.provider_expansion_framework import get_framework

        fw = get_framework()
        queue_providers = [p["provider"] for p in fw["recommended_next_providers"]]
        assert "kubernetes" not in queue_providers


# ── Frontend catalog state ────────────────────────────────────────────────────

class TestFrontendCatalogState:
    """Source-scan checks (no TS execution) confirming Kubernetes is present
    for metadata lookups but NOT yet user-connectable, matching the
    foundation-stage decision documented in kubernetes_foundation_contract.md."""

    def _providers_ts_text(self) -> str:
        from pathlib import Path

        path = (
            Path(__file__).resolve().parents[2]
            / "frontend" / "src" / "lib" / "providers.ts"
        )
        return path.read_text()

    def test_kubernetes_present_in_provider_id_type(self):
        text = self._providers_ts_text()
        assert '"kubernetes"' in text

    def test_kubernetes_has_a_providers_map_entry(self):
        text = self._providers_ts_text()
        assert "kubernetes: {" in text

    def test_kubernetes_not_in_connectable_provider_ids(self):
        text = self._providers_ts_text()
        start = text.index("export const CONNECTABLE_PROVIDER_IDS")
        end = text.index("];", start)
        block = text[start:end]
        assert '"kubernetes"' not in block

    def test_kubernetes_not_in_provider_ids_display_order(self):
        text = self._providers_ts_text()
        start = text.index("export const PROVIDER_IDS")
        end = text.index("];", start)
        block = text[start:end]
        assert '"kubernetes"' not in block

    def test_kubernetes_trust_note_does_not_claim_live_coverage(self):
        text = self._providers_ts_text()
        start = text.index("kubernetes: {")
        end = text.index("\n  },", start)
        block = text[start:end]
        assert "foundation" in block.lower() or "planned" in block.lower()
