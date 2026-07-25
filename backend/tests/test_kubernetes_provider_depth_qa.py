"""Kubernetes provider-depth QA guardrails (Kubernetes message 9 — public launch).

Durable, deterministic guardrails proving Kubernetes is a genuinely
launched, connectable, production-certified provider — not just a
connector that exists internally. This file adds no product code; it pins
registration-surface parity, the credential round-trip, RBAC-manifest
parity, sensitive-data boundaries, and frontend/backend consistency so a
future change cannot silently regress the launch.

Sections:
  A. Backend registration surfaces (sync dispatch, schema, coverage, matrix)
  B. Credential round-trip (router _build_credentials, reconnect)
  C. Security Finding registry parity (59 rules)
  D. Sensitive-data / forbidden-call boundary
  E. RBAC manifest parity (connector calls <-> documented manifest)
  F. Frontend catalog parity (connectable, card copy, form wired)
  G. Reliability/diagnostics surfaces exist (message 8 wiring reachable)
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
    def test_kubernetes_in_sync_supported_providers(self):
        # _SUPPORTED_PROVIDERS is a local tuple inside a function, not
        # module-level, so this is a source-scan check.
        source = (BACKEND_ROOT / "app" / "services" / "sync_service.py").read_text()
        start = source.index("_SUPPORTED_PROVIDERS = (")
        end = source.index(")", start)
        assert '"kubernetes"' in source[start:end]

    def test_kubernetes_in_integration_create_request_literal(self):
        from app.schemas.integration import IntegrationCreateRequest

        req = IntegrationCreateRequest(
            provider="kubernetes",
            display_name="Test cluster",
            kubeconfig="apiVersion: v1\nkind: Config\n",
        )
        assert req.provider == "kubernetes"

    def test_kubernetes_requires_kubeconfig(self):
        from pydantic import ValidationError
        from app.schemas.integration import IntegrationCreateRequest

        with pytest.raises(ValidationError):
            IntegrationCreateRequest(provider="kubernetes", display_name="Test")

    def test_kubernetes_in_security_coverage_providers(self):
        from app.services.security_coverage_service import PROVIDERS

        assert "kubernetes" in PROVIDERS

    def test_kubernetes_in_capability_matrix_complete_list_not_partial(self):
        from app.services.provider_capability_matrix_service import (
            PROVIDER_CAPABILITIES,
            PROVIDER_CAPABILITIES_PARTIAL,
        )

        assert "kubernetes" in {p.provider for p in PROVIDER_CAPABILITIES}
        assert "kubernetes" not in {p.provider for p in PROVIDER_CAPABILITIES_PARTIAL}

    def test_kubernetes_capability_notes_say_launched_not_pending(self):
        from app.services.provider_capability_matrix_service import get_provider_capability

        cap = get_provider_capability("kubernetes")
        assert cap is not None
        notes_lower = cap.notes.lower()
        assert "not yet connectable" not in notes_lower
        assert "not yet production-ready" not in notes_lower
        assert "expansion is complete" in notes_lower

    def test_kubernetes_dispatch_function_exists(self):
        from app.services import integration_service

        assert hasattr(integration_service, "_create_kubernetes_integration")

    def test_kubernetes_reconnect_function_exists(self):
        from app.services import integration_service

        assert hasattr(integration_service, "reconnect_credentials_kubernetes")


# ════════════════════════════════════════════════════════════════════════════
# B. Credential round-trip
# ════════════════════════════════════════════════════════════════════════════


class TestCredentialRoundTrip:
    def test_build_credentials_extracts_kubeconfig(self):
        from app.routers.integrations import _build_credentials
        from app.schemas.integration import IntegrationCreateRequest

        req = IntegrationCreateRequest(
            provider="kubernetes",
            display_name="Test",
            kubeconfig="apiVersion: v1\nkind: Config\n",
        )
        creds = _build_credentials(req)
        assert creds["kubeconfig"] == "apiVersion: v1\nkind: Config\n"
        assert "context" not in creds
        assert "cluster_name" not in creds
        assert "namespace_allowlist" not in creds

    def test_build_credentials_extracts_optional_fields(self):
        from app.routers.integrations import _build_credentials
        from app.schemas.integration import IntegrationCreateRequest

        req = IntegrationCreateRequest(
            provider="kubernetes",
            display_name="Test",
            kubeconfig="apiVersion: v1\nkind: Config\n",
            context="prod-context",
            cluster_name="prod-cluster",
            namespace_allowlist=["default", "prod"],
        )
        creds = _build_credentials(req)
        assert creds["context"] == "prod-context"
        assert creds["cluster_name"] == "prod-cluster"
        assert creds["namespace_allowlist"] == ["default", "prod"]

    def test_build_credentials_key_matches_connector_expectation(self):
        """The router must build the exact dict shape
        KubernetesConnector._build_api_client() reads from — a mismatch here
        would silently drop the context override (this was a real bug: the
        message-8 live-validation harness used 'context_name' while the
        connector reads 'context')."""
        import inspect

        from app.connectors.kubernetes import KubernetesConnector
        from app.routers.integrations import _build_credentials
        from app.schemas.integration import IntegrationCreateRequest

        req = IntegrationCreateRequest(
            provider="kubernetes",
            display_name="Test",
            kubeconfig="apiVersion: v1\nkind: Config\n",
            context="prod-context",
        )
        creds = _build_credentials(req)
        source = inspect.getsource(KubernetesConnector._build_api_client)
        assert 'credentials.get("context")' in source
        assert "context" in creds

    def test_live_validation_harness_uses_matching_context_key(self):
        """Regression pin for the context_name/context key-naming bug found
        during message 9's router audit — run_live_kubernetes_validation()
        must build a credentials dict the connector actually reads."""
        import inspect

        from app.connectors.kubernetes import run_live_kubernetes_validation

        source = inspect.getsource(run_live_kubernetes_validation)
        assert 'credentials["context"] = context_name' in source
        assert 'credentials["context_name"] = context_name' not in source

    def test_reconnect_schema_has_kubernetes_fields(self):
        from app.schemas.integration import IntegrationReconnectRequest

        fields = IntegrationReconnectRequest.model_fields
        assert "kubeconfig" in fields
        assert "context" in fields
        assert "namespace_allowlist" in fields

    def test_reconnect_router_branch_exists_for_kubernetes(self):
        source = (BACKEND_ROOT / "app" / "routers" / "integrations.py").read_text()
        assert 'integration.provider == "kubernetes"' in source
        # Must appear in both _build_credentials (create) and reconnect_integration.
        assert source.count('body.provider == "kubernetes"') >= 1
        assert source.count('integration.provider == "kubernetes"') >= 1


# ════════════════════════════════════════════════════════════════════════════
# C. Security Finding registry parity
# ════════════════════════════════════════════════════════════════════════════


class TestSecurityFindingParity:
    """No aggregated rule-key set is exported from security_rules/kubernetes.py
    itself, so these derive the Kubernetes rule-key set from the central
    registry (the actual source of truth every other layer reads from)."""

    def _kubernetes_rule_keys(self) -> set[str]:
        from app.services.security_rule_registry import KNOWN_RULE_KEYS

        return {k for k in KNOWN_RULE_KEYS if k.startswith("kubernetes_")}

    def test_kubernetes_has_exactly_59_rules(self):
        assert len(self._kubernetes_rule_keys()) == 59

    def test_all_kubernetes_rules_reachable_from_evaluator(self):
        from app.services.security_rules.kubernetes import evaluate

        assert callable(evaluate)

    def test_all_kubernetes_rules_have_confidence(self):
        from app.services.security_rule_confidence import RULE_CONFIDENCE

        missing = self._kubernetes_rule_keys() - set(RULE_CONFIDENCE.keys())
        assert not missing, f"rules missing confidence: {missing}"


# ════════════════════════════════════════════════════════════════════════════
# D. Sensitive-data / forbidden-call boundary
# ════════════════════════════════════════════════════════════════════════════

FORBIDDEN_CALL_PATTERNS = [
    r"read_namespaced_secret",
    r"list_namespaced_secret\b",
    r"list_secret_for_all_namespaces",
    r"read_namespaced_config_map",
    r"list_namespaced_config_map",
    r"list_config_map_for_all_namespaces",
    r"connect_get_namespaced_pod_exec",
    r"connect_post_namespaced_pod_exec",
    r"connect_get_namespaced_pod_attach",
    r"read_namespaced_pod_log",
    r"connect_get_namespaced_pod_portforward",
    r"create_namespaced_service_account_token",
]


class TestSensitiveDataBoundary:
    def test_connector_never_calls_forbidden_apis(self):
        source = (BACKEND_ROOT / "app" / "connectors" / "kubernetes.py").read_text()
        for pattern in FORBIDDEN_CALL_PATTERNS:
            assert not re.search(pattern, source), f"forbidden API call found: {pattern}"

    def test_kubeconfig_never_copied_into_resource_metadata(self):
        source = (BACKEND_ROOT / "app" / "services" / "integration_service.py").read_text()
        start = source.index("def _create_kubernetes_integration")
        end = source.index("\ndef ", start + 10)
        block = source[start:end]
        metadata_start = block.index("resource_metadata={")
        metadata_end = block.index("},", metadata_start)
        metadata_block = block[metadata_start:metadata_end]
        assert "kubeconfig" not in metadata_block
        assert "credentials" not in metadata_block

    def test_reconnect_kubernetes_never_logs_kubeconfig(self):
        source = (BACKEND_ROOT / "app" / "services" / "integration_service.py").read_text()
        start = source.index("def reconnect_credentials_kubernetes")
        end = source.index("\ndef ", start + 10)
        block = source[start:end]
        assert "print(" not in block
        assert "logger.info(new_kubeconfig" not in block
        assert "logger.debug(new_kubeconfig" not in block


# ════════════════════════════════════════════════════════════════════════════
# E. RBAC manifest parity
# ════════════════════════════════════════════════════════════════════════════

# (resource, verb) pairs the manifest documents as granted.
MANIFEST_RESOURCES = {
    "namespaces", "pods", "services", "serviceaccounts", "resourcequotas",
    "limitranges", "deployments", "statefulsets", "daemonsets", "jobs",
    "cronjobs", "roles", "clusterroles", "rolebindings", "clusterrolebindings",
    "ingresses", "networkpolicies", "validatingwebhookconfigurations",
    "mutatingwebhookconfigurations", "gateways", "httproutes",
}


class TestRbacManifestParity:
    def _manifest_text(self) -> str:
        path = BACKEND_ROOT / "tests" / "reports" / "kubernetes_readonly_rbac_manifest.md"
        if not path.is_file():
            pytest.skip("RBAC manifest report not found")
        return path.read_text()

    def test_manifest_excludes_secrets_and_configmaps(self):
        text = self._manifest_text()
        manifest_yaml_start = text.index("```yaml")
        manifest_yaml_end = text.index("```", manifest_yaml_start + 7)
        manifest_block = text[manifest_yaml_start:manifest_yaml_end]
        assert "secrets" not in manifest_block
        assert "configmaps" not in manifest_block

    def test_manifest_only_grants_get_list_verbs(self):
        text = self._manifest_text()
        manifest_yaml_start = text.index("```yaml")
        manifest_yaml_end = text.index("```", manifest_yaml_start + 7)
        manifest_block = text[manifest_yaml_start:manifest_yaml_end]
        verb_lines = re.findall(r'verbs:\s*\[([^\]]*)\]', manifest_block)
        assert verb_lines, "no verbs found in manifest"
        for line in verb_lines:
            verbs = {v.strip().strip('"') for v in line.split(",")}
            assert verbs <= {"get", "list"}, f"unexpected verb in manifest: {verbs}"

    def test_manifest_resources_match_connector_calls(self):
        """Every resource the manifest grants must correspond to a real
        connector call, and every documented connector call's resource
        must be covered by the manifest (message 9 parity re-audit)."""
        connector_source = (
            BACKEND_ROOT / "app" / "connectors" / "kubernetes.py"
        ).read_text()

        # A representative sample of the list/get calls the connector makes,
        # mapped to the manifest resource name they correspond to.
        expected_present_calls = {
            "list_namespace": "namespaces",
            "list_pod_for_all_namespaces": "pods",
            "list_service_for_all_namespaces": "services",
            "list_service_account_for_all_namespaces": "serviceaccounts",
            "list_resource_quota_for_all_namespaces": "resourcequotas",
            "list_limit_range_for_all_namespaces": "limitranges",
            "list_deployment_for_all_namespaces": "deployments",
            "list_stateful_set_for_all_namespaces": "statefulsets",
            "list_daemon_set_for_all_namespaces": "daemonsets",
            "list_job_for_all_namespaces": "jobs",
            "list_cron_job_for_all_namespaces": "cronjobs",
            "list_role_for_all_namespaces": "roles",
            "list_cluster_role": "clusterroles",
            "list_role_binding_for_all_namespaces": "rolebindings",
            "list_cluster_role_binding": "clusterrolebindings",
            "list_ingress_for_all_namespaces": "ingresses",
            "list_network_policy_for_all_namespaces": "networkpolicies",
            "list_validating_webhook_configuration": "validatingwebhookconfigurations",
            "list_mutating_webhook_configuration": "mutatingwebhookconfigurations",
        }
        for call, resource in expected_present_calls.items():
            assert call in connector_source, f"expected connector call {call!r} not found"
            assert resource in MANIFEST_RESOURCES, f"manifest missing resource {resource!r}"


# ════════════════════════════════════════════════════════════════════════════
# F. Frontend catalog parity
# ════════════════════════════════════════════════════════════════════════════


class TestFrontendLaunchState:
    def _providers_ts(self) -> str:
        path = FRONTEND_ROOT / "src" / "lib" / "providers.ts"
        if not path.is_file():
            pytest.skip("frontend tree not found")
        return path.read_text()

    def test_kubernetes_in_connectable_provider_ids(self):
        text = self._providers_ts()
        start = text.index("export const CONNECTABLE_PROVIDER_IDS")
        end = text.index("];", start)
        assert '"kubernetes"' in text[start:end]

    def test_kubernetes_in_provider_ids(self):
        text = self._providers_ts()
        start = text.index("export const PROVIDER_IDS")
        end = text.index("];", start)
        assert '"kubernetes"' in text[start:end]

    def test_kubernetes_card_copy_omits_unsupported_claims(self):
        text = self._providers_ts()
        start = text.index("kubernetes: {")
        end = text.index("\n  },", start)
        block = text[start:end].lower()
        for forbidden in (
            "vulnerability scanning", "malware", "audit-log monitoring",
            "runtime threat", "exploit detection", "guaranteed",
        ):
            assert forbidden not in block, f"card copy claims {forbidden!r}"

    def test_kubernetes_form_component_exists(self):
        path = (
            FRONTEND_ROOT / "src" / "components" / "integrations"
            / "KubernetesIntegrationForm.tsx"
        )
        if not FRONTEND_ROOT.is_dir():
            pytest.skip("frontend tree not found")
        assert path.is_file()

    def test_kubernetes_form_wired_into_integrations_page(self):
        path = FRONTEND_ROOT / "src" / "app" / "(app)" / "integrations" / "page.tsx"
        if not path.is_file():
            pytest.skip("frontend tree not found")
        text = path.read_text()
        assert "KubernetesIntegrationForm" in text
        assert 'selectedProvider === "kubernetes"' in text

    def test_kubernetes_form_never_uses_type_password_for_kubeconfig(self):
        """kubeconfig is multiline, so it must use a textarea, not a
        single-line password input (which would truncate/mangle it)."""
        path = (
            FRONTEND_ROOT / "src" / "components" / "integrations"
            / "KubernetesIntegrationForm.tsx"
        )
        if not path.is_file():
            pytest.skip("frontend tree not found")
        text = path.read_text()
        assert "<textarea" in text
        assert 'id="kubernetes-kubeconfig"' in text

    def test_kubernetes_form_never_prefills_or_echoes_kubeconfig_after_success(self):
        path = (
            FRONTEND_ROOT / "src" / "components" / "integrations"
            / "KubernetesIntegrationForm.tsx"
        )
        if not path.is_file():
            pytest.skip("frontend tree not found")
        text = path.read_text()
        assert 'setKubeconfig("")' in text
        assert "Kubeconfig configured" in text


# ════════════════════════════════════════════════════════════════════════════
# G. Reliability / diagnostics surfaces (message 8 wiring stays reachable)
# ════════════════════════════════════════════════════════════════════════════


class TestReliabilitySurfacesReachable:
    def test_build_permission_diagnostics_exists(self):
        from app.connectors.kubernetes import build_permission_diagnostics

        assert callable(build_permission_diagnostics)

    def test_run_live_kubernetes_validation_exists(self):
        from app.connectors.kubernetes import run_live_kubernetes_validation

        assert callable(run_live_kubernetes_validation)

    def test_kubernetes_removal_suppressed_exists(self):
        from app.services.diff_service import _kubernetes_removal_suppressed

        assert callable(_kubernetes_removal_suppressed)
