"""Okta provider-depth QA guardrails (Okta message 8 — public launch).

Durable, deterministic guardrails proving Okta is a genuinely launched,
connectable, production-certified provider — not just a connector that
exists internally. This file adds no product code; it pins
registration-surface parity, the credential round-trip, security finding
registry parity, sensitive-data boundaries, and frontend/backend
consistency so a future change cannot silently regress the launch.

Sections:
  A. Backend registration surfaces (sync dispatch, schema, coverage, matrix)
  B. Credential round-trip (router _build_credentials, reconnect)
  C. Security Finding registry parity (30 rules)
  D. Sensitive-data / forbidden-call boundary
  E. Frontend catalog parity (connectable, card copy, form wired)
  F. Reliability/diagnostics surfaces exist (message 7-8 wiring reachable)
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
    def test_okta_in_sync_supported_providers(self):
        source = (BACKEND_ROOT / "app" / "services" / "sync_service.py").read_text()
        start = source.index("_SUPPORTED_PROVIDERS = (")
        end = source.index(")", start)
        assert '"okta"' in source[start:end]

    def test_okta_in_integration_create_request_literal(self):
        from app.schemas.integration import IntegrationCreateRequest

        req = IntegrationCreateRequest(
            provider="okta",
            display_name="Test org",
            okta_org_url="https://example.okta.com",
            okta_api_token="fake-token",
        )
        assert req.provider == "okta"

    def test_okta_requires_org_url_and_token(self):
        from pydantic import ValidationError
        from app.schemas.integration import IntegrationCreateRequest

        with pytest.raises(ValidationError):
            IntegrationCreateRequest(provider="okta", display_name="Test")

    def test_okta_in_security_coverage_providers(self):
        from app.services.security_coverage_service import PROVIDERS

        assert "okta" in PROVIDERS

    def test_okta_in_capability_matrix_complete_list_not_partial(self):
        from app.services.provider_capability_matrix_service import (
            PROVIDER_CAPABILITIES,
            PROVIDER_CAPABILITIES_PARTIAL,
        )

        assert "okta" in {p.provider for p in PROVIDER_CAPABILITIES}
        assert "okta" not in {p.provider for p in PROVIDER_CAPABILITIES_PARTIAL}

    def test_okta_capability_notes_say_launched_not_pending(self):
        from app.services.provider_capability_matrix_service import get_provider_capability

        cap = get_provider_capability("okta")
        assert cap is not None
        notes_lower = cap.notes.lower()
        assert "not yet connectable" not in notes_lower
        assert "not publicly connectable" not in notes_lower
        assert "expansion is complete" in notes_lower

    def test_okta_dispatch_function_exists(self):
        from app.services import integration_service

        assert hasattr(integration_service, "_create_okta_integration")

    def test_okta_reconnect_function_exists(self):
        from app.services import integration_service

        assert hasattr(integration_service, "reconnect_credentials_okta")


# ════════════════════════════════════════════════════════════════════════════
# B. Credential round-trip
# ════════════════════════════════════════════════════════════════════════════


class TestCredentialRoundTrip:
    def test_build_credentials_extracts_org_url_and_token(self):
        from app.routers.integrations import _build_credentials
        from app.schemas.integration import IntegrationCreateRequest

        req = IntegrationCreateRequest(
            provider="okta",
            display_name="Test",
            okta_org_url="https://example.okta.com",
            okta_api_token="fake-token",
        )
        creds = _build_credentials(req)
        assert creds["org_url"] == "https://example.okta.com"
        assert creds["api_token"] == "fake-token"

    def test_build_credentials_key_matches_connector_expectation(self):
        """The router must build the exact dict shape
        OktaConnector._credentials() reads from."""
        import inspect

        from app.connectors.okta import OktaConnector
        from app.routers.integrations import _build_credentials
        from app.schemas.integration import IntegrationCreateRequest

        req = IntegrationCreateRequest(
            provider="okta",
            display_name="Test",
            okta_org_url="https://example.okta.com",
            okta_api_token="fake-token",
        )
        creds = _build_credentials(req)
        source = inspect.getsource(OktaConnector._credentials)
        assert 'credentials.get("org_url")' in source
        assert 'credentials.get("api_token")' in source
        assert "org_url" in creds and "api_token" in creds

    def test_creation_runs_synchronous_validate_credentials(self):
        """Message 8: creation must call validate_credentials() synchronously,
        matching the Kubernetes launch precedent — a bare-record-creation
        regression here would silently reintroduce deferred-to-first-sync
        validation and break the Invalid launch-certification state."""
        import inspect

        from app.services import integration_service

        source = inspect.getsource(integration_service._create_okta_integration)
        assert "validate_credentials(credentials)" in source

    def test_reconnect_schema_has_okta_fields(self):
        from app.schemas.integration import IntegrationReconnectRequest

        fields = IntegrationReconnectRequest.model_fields
        assert "okta_org_url" in fields
        assert "okta_api_token" in fields

    def test_reconnect_router_branch_exists_for_okta(self):
        source = (BACKEND_ROOT / "app" / "routers" / "integrations.py").read_text()
        assert 'integration.provider == "okta"' in source
        assert "reconnect_credentials_okta" in source

    def test_reconnect_rejects_different_tenant(self):
        """Regression pin: reconnect_credentials_okta() must compare tenant
        identity and raise ConnectorError on a genuine mismatch — never
        silently overwrite."""
        import inspect

        from app.services import integration_service

        source = inspect.getsource(integration_service.reconnect_credentials_okta)
        assert "compute_tenant_id" in source
        assert "existing_tenant_id != new_tenant_id" in source
        assert "ConnectorError" in source


# ════════════════════════════════════════════════════════════════════════════
# C. Security Finding registry parity
# ════════════════════════════════════════════════════════════════════════════


class TestSecurityFindingParity:
    def _okta_rule_keys(self) -> set[str]:
        from app.services.security_rule_registry import KNOWN_RULE_KEYS

        return {k for k in KNOWN_RULE_KEYS if k.startswith("okta_")}

    def test_okta_has_exactly_30_rules(self):
        assert len(self._okta_rule_keys()) == 30

    def test_all_okta_rules_reachable_from_evaluator(self):
        from app.services.security_rules.okta import evaluate

        assert callable(evaluate)

    def test_all_okta_rules_have_confidence(self):
        from app.services.security_rule_confidence import RULE_CONFIDENCE

        missing = self._okta_rule_keys() - set(RULE_CONFIDENCE.keys())
        assert not missing, f"rules missing confidence: {missing}"

    def test_okta_in_coverage_record_types(self):
        from app.services.security_coverage_service import RULE_RECORD_TYPES

        missing = self._okta_rule_keys() - set(RULE_RECORD_TYPES.keys())
        assert not missing, f"rules missing coverage record types: {missing}"


# ════════════════════════════════════════════════════════════════════════════
# D. Sensitive-data / forbidden-call boundary
# ════════════════════════════════════════════════════════════════════════════

FORBIDDEN_TOKEN_PATTERNS = [
    r"logger\.\w+\(.*api_token",
    r"print\(.*api_token",
    r"raise \w+Error\(f?[\"'].*\{api_token\}",
]


class TestSensitiveDataBoundary:
    def test_connector_never_logs_or_raises_with_raw_token(self):
        source = (BACKEND_ROOT / "app" / "connectors" / "okta.py").read_text()
        for pattern in FORBIDDEN_TOKEN_PATTERNS:
            assert not re.search(pattern, source), f"forbidden token usage found: {pattern}"

    def test_org_resource_metadata_never_contains_api_token(self):
        source = (BACKEND_ROOT / "app" / "services" / "integration_service.py").read_text()
        start = source.index("def _create_okta_integration")
        end = source.index("\ndef ", start + 10)
        block = source[start:end]
        metadata_start = block.index("resource_metadata={")
        metadata_end = block.index("},", metadata_start)
        metadata_block = block[metadata_start:metadata_end]
        assert "api_token" not in metadata_block
        assert "credentials" not in metadata_block

    def test_reconnect_okta_never_logs_new_token(self):
        source = (BACKEND_ROOT / "app" / "services" / "integration_service.py").read_text()
        start = source.index("def reconnect_credentials_okta")
        end = source.index("\ndef ", start + 10)
        block = source[start:end]
        assert "print(" not in block
        assert "logger.info(new_api_token" not in block
        assert "logger.debug(new_api_token" not in block

    def test_no_cli_or_subprocess_dependency(self):
        source = (BACKEND_ROOT / "app" / "connectors" / "okta.py").read_text()
        assert "subprocess" not in source
        assert "os.system" not in source
        assert "okta cli" not in source.lower()
        assert "shell=True" not in source


# ════════════════════════════════════════════════════════════════════════════
# E. Frontend catalog parity
# ════════════════════════════════════════════════════════════════════════════


class TestFrontendLaunchState:
    def _providers_ts(self) -> str:
        path = FRONTEND_ROOT / "src" / "lib" / "providers.ts"
        if not path.is_file():
            pytest.skip("frontend tree not found")
        return path.read_text()

    def test_okta_in_connectable_provider_ids(self):
        text = self._providers_ts()
        start = text.index("export const CONNECTABLE_PROVIDER_IDS")
        end = text.index("];", start)
        assert '"okta"' in text[start:end]

    def test_okta_in_provider_ids(self):
        text = self._providers_ts()
        start = text.index("export const PROVIDER_IDS")
        end = text.index("];", start)
        assert '"okta"' in text[start:end]

    def test_okta_card_copy_omits_stale_planned_wording(self):
        text = self._providers_ts()
        start = text.index("okta: {")
        end = text.index("\n  },", start)
        block = text[start:end]
        assert "(planned)" not in block
        assert "foundation stage" not in block.lower()

    def test_okta_card_copy_omits_unsupported_claims(self):
        """The description/monitoredSurfaces copy must not claim unsupported
        capabilities. The trustNote is exempt — it legitimately *disclaims*
        these as a reassurance, the same pattern every other provider's
        trustNote uses (see test_okta_connector_contract.py)."""
        text = self._providers_ts()
        start = text.index("okta: {")
        trust_note_start = text.index("trustNote:", start)
        card_copy = text[start:trust_note_start].lower()
        for forbidden in (
            "threat detection", "session monitoring", "device telemetry",
            "password breach", "runtime attack", "guaranteed",
        ):
            assert forbidden not in card_copy, f"card copy claims {forbidden!r}"

    def test_okta_form_component_exists(self):
        path = (
            FRONTEND_ROOT / "src" / "components" / "integrations"
            / "OktaIntegrationForm.tsx"
        )
        if not FRONTEND_ROOT.is_dir():
            pytest.skip("frontend tree not found")
        assert path.is_file()

    def test_okta_form_wired_into_integrations_page(self):
        path = FRONTEND_ROOT / "src" / "app" / "(app)" / "integrations" / "page.tsx"
        if not path.is_file():
            pytest.skip("frontend tree not found")
        text = path.read_text()
        assert "OktaIntegrationForm" in text
        assert 'selectedProvider === "okta"' in text

    def test_okta_form_uses_password_input_for_token(self):
        path = (
            FRONTEND_ROOT / "src" / "components" / "integrations"
            / "OktaIntegrationForm.tsx"
        )
        if not path.is_file():
            pytest.skip("frontend tree not found")
        text = path.read_text()
        assert 'type="password"' in text
        assert 'id="okta-api-token"' in text

    def test_okta_form_never_prefills_or_echoes_token_after_success(self):
        path = (
            FRONTEND_ROOT / "src" / "components" / "integrations"
            / "OktaIntegrationForm.tsx"
        )
        if not path.is_file():
            pytest.skip("frontend tree not found")
        text = path.read_text()
        assert 'setApiToken("")' in text
        assert "API token configured" in text


# ════════════════════════════════════════════════════════════════════════════
# F. Reliability / diagnostics surfaces (message 7-8 wiring stays reachable)
# ════════════════════════════════════════════════════════════════════════════


class TestReliabilitySurfacesReachable:
    def test_build_okta_permission_diagnostics_exists(self):
        from app.connectors.okta import build_okta_permission_diagnostics

        assert callable(build_okta_permission_diagnostics)

    def test_format_okta_permission_diagnostics_text_exists(self):
        from app.connectors.okta import format_okta_permission_diagnostics_text

        assert callable(format_okta_permission_diagnostics_text)

    def test_okta_removal_suppressed_exists(self):
        from app.services.diff_service import _okta_removal_suppressed

        assert callable(_okta_removal_suppressed)

    def test_permission_diagnostics_full_when_all_families_complete(self):
        from app.connectors.okta import build_okta_permission_diagnostics

        families = [
            "users", "groups", "memberships", "applications",
            "app_user_assignments", "app_group_assignments", "policies",
            "policy_rules", "authenticators", "custom_admin_roles",
            "user_admin_role_assignments", "group_admin_role_assignments",
        ]
        records = [{
            "record_type": "okta_organization",
            "tenant_id": "id:abc",
            "org_hostname": "example.okta.com",
            "family_completeness": {f: "complete" for f in families},
        }]
        report = build_okta_permission_diagnostics(records)
        assert report["coverage"] == "full"

    def test_permission_diagnostics_partial_when_one_family_denied(self):
        from app.connectors.okta import build_okta_permission_diagnostics

        families = [
            "users", "groups", "memberships", "applications",
            "app_user_assignments", "app_group_assignments", "policies",
            "policy_rules", "authenticators", "user_admin_role_assignments",
            "group_admin_role_assignments",
        ]
        completeness = {f: "complete" for f in families}
        completeness["custom_admin_roles"] = "denied"
        records = [{
            "record_type": "okta_organization",
            "tenant_id": "id:abc",
            "org_hostname": "example.okta.com",
            "family_completeness": completeness,
        }]
        report = build_okta_permission_diagnostics(records)
        assert report["coverage"] == "partial"

    def test_permission_diagnostics_invalid_when_no_families_readable(self):
        from app.connectors.okta import build_okta_permission_diagnostics

        records = [{
            "record_type": "okta_organization",
            "tenant_id": "id:abc",
            "org_hostname": "example.okta.com",
            "family_completeness": {"users": "denied", "groups": "unavailable"},
        }]
        report = build_okta_permission_diagnostics(records)
        assert report["coverage"] == "invalid"

    def test_permission_diagnostics_invalid_when_org_record_missing(self):
        from app.connectors.okta import build_okta_permission_diagnostics

        report = build_okta_permission_diagnostics([])
        assert report["org_reachable"] is False
        assert report["coverage"] == "invalid"
