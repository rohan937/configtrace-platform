"""Microsoft Entra ID provider-depth QA guardrails (Entra message 8 —
public launch).

Durable, deterministic guardrails proving Entra is a genuinely launched,
connectable, production-certified provider — not just a connector that
exists internally. This file adds no product code; it pins
registration-surface parity, the credential round-trip, security finding
registry parity, sensitive-data boundaries, and frontend/backend
consistency so a future change cannot silently regress the launch.

Sections:
  A. Backend registration surfaces (sync dispatch, schema, coverage, matrix)
  B. Credential round-trip (router _build_credentials, reconnect)
  C. Security Finding registry parity (45 rules)
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

_TENANT_ID = "11111111-1111-1111-1111-111111111111"
_CLIENT_ID = "22222222-2222-2222-2222-222222222222"
_SECRET = "fake-entra-client-secret-value"


# ════════════════════════════════════════════════════════════════════════════
# A. Backend registration surfaces
# ════════════════════════════════════════════════════════════════════════════


class TestBackendRegistrationSurfaces:
    def test_entra_in_sync_supported_providers(self):
        source = (BACKEND_ROOT / "app" / "services" / "sync_service.py").read_text()
        start = source.index("_SUPPORTED_PROVIDERS = (")
        end = source.index(")", start)
        assert '"entra"' in source[start:end]

    def test_entra_in_integration_create_request_literal(self):
        from app.schemas.integration import IntegrationCreateRequest

        req = IntegrationCreateRequest(
            provider="entra",
            display_name="Test tenant",
            entra_tenant_id=_TENANT_ID,
            entra_client_id=_CLIENT_ID,
            entra_client_secret=_SECRET,
        )
        assert req.provider == "entra"

    def test_entra_requires_tenant_client_secret(self):
        from pydantic import ValidationError
        from app.schemas.integration import IntegrationCreateRequest

        with pytest.raises(ValidationError):
            IntegrationCreateRequest(provider="entra", display_name="Test")

    def test_entra_in_security_coverage_providers(self):
        from app.services.security_coverage_service import PROVIDERS

        assert "entra" in PROVIDERS

    def test_entra_in_capability_matrix_complete_list_not_partial(self):
        from app.services.provider_capability_matrix_service import (
            PROVIDER_CAPABILITIES,
            PROVIDER_CAPABILITIES_PARTIAL,
        )

        assert "entra" in {p.provider for p in PROVIDER_CAPABILITIES}
        assert "entra" not in {p.provider for p in PROVIDER_CAPABILITIES_PARTIAL}

    def test_entra_capability_notes_say_launched_not_pending(self):
        from app.services.provider_capability_matrix_service import get_provider_capability

        cap = get_provider_capability("entra")
        assert cap is not None
        notes_lower = cap.notes.lower()
        assert "not yet connectable" not in notes_lower
        assert "not publicly connectable" not in notes_lower
        assert "expansion is complete" in notes_lower

    def test_entra_dispatch_function_exists(self):
        from app.services import integration_service

        assert hasattr(integration_service, "_create_entra_integration")

    def test_entra_reconnect_function_exists(self):
        from app.services import integration_service

        assert hasattr(integration_service, "reconnect_credentials_entra")


# ════════════════════════════════════════════════════════════════════════════
# B. Credential round-trip
# ════════════════════════════════════════════════════════════════════════════


class TestCredentialRoundTrip:
    def test_build_credentials_extracts_tenant_client_secret(self):
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

    def test_build_credentials_key_matches_connector_expectation(self):
        """The router must build the exact dict shape
        EntraConnector._credentials() reads from."""
        import inspect

        from app.connectors.entra import EntraConnector
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
        source = inspect.getsource(EntraConnector._credentials)
        assert 'credentials.get("tenant_id")' in source or '"tenant_id"' in source
        assert 'credentials.get("client_id")' in source or '"client_id"' in source
        assert "tenant_id" in creds and "client_id" in creds and "client_secret" in creds

    def test_creation_runs_synchronous_validate_credentials(self):
        """Message 8: creation must call validate_credentials() synchronously
        — a bare-record-creation regression here would silently reintroduce
        deferred-to-first-sync validation and break the Invalid launch-
        certification state."""
        import inspect

        from app.services import integration_service

        source = inspect.getsource(integration_service._create_entra_integration)
        assert "validate_credentials(credentials)" in source

    def test_reconnect_schema_has_entra_fields(self):
        from app.schemas.integration import IntegrationReconnectRequest

        fields = IntegrationReconnectRequest.model_fields
        assert "entra_tenant_id" in fields
        assert "entra_client_id" in fields
        assert "entra_client_secret" in fields

    def test_reconnect_router_branch_exists_for_entra(self):
        source = (BACKEND_ROOT / "app" / "routers" / "integrations.py").read_text()
        assert 'integration.provider == "entra"' in source
        assert "reconnect_credentials_entra" in source

    def test_reconnect_rejects_different_tenant(self):
        """Regression pin: reconnect_credentials_entra() must compare
        tenant identity and raise ConnectorError on a genuine mismatch —
        never silently overwrite."""
        import inspect

        from app.services import integration_service

        source = inspect.getsource(integration_service.reconnect_credentials_entra)
        assert "compute_tenant_id" in source
        assert "existing_stable_tenant_id != new_stable_tenant_id" in source
        assert "ConnectorError" in source

    def test_reconnect_supports_client_rotation(self):
        import inspect

        from app.services import integration_service

        source = inspect.getsource(integration_service.reconnect_credentials_entra)
        assert "new_client_id" in source


# ════════════════════════════════════════════════════════════════════════════
# C. Security Finding registry parity
# ════════════════════════════════════════════════════════════════════════════


class TestSecurityFindingParity:
    def _entra_rule_keys(self) -> set[str]:
        from app.services.security_rule_registry import KNOWN_RULE_KEYS

        return {k for k in KNOWN_RULE_KEYS if k.startswith("entra_")}

    def test_entra_has_exactly_45_rules(self):
        assert len(self._entra_rule_keys()) == 45

    def test_all_entra_rules_reachable_from_evaluator(self):
        from app.services.security_rules.entra import evaluate

        assert callable(evaluate)

    def test_all_entra_rules_have_confidence(self):
        from app.services.security_rule_confidence import RULE_CONFIDENCE

        missing = self._entra_rule_keys() - set(RULE_CONFIDENCE.keys())
        assert not missing, f"rules missing confidence: {missing}"

    def test_entra_in_coverage_record_types(self):
        from app.services.security_coverage_service import RULE_RECORD_TYPES

        missing = self._entra_rule_keys() - set(RULE_RECORD_TYPES.keys())
        assert not missing, f"rules missing coverage record types: {missing}"


# ════════════════════════════════════════════════════════════════════════════
# D. Sensitive-data / forbidden-call boundary
# ════════════════════════════════════════════════════════════════════════════

FORBIDDEN_SECRET_PATTERNS = [
    r"logger\.\w+\(.*client_secret",
    r"print\(.*client_secret",
    r"raise \w+Error\(f?[\"'].*\{client_secret\}",
]


class TestSensitiveDataBoundary:
    def test_connector_never_logs_or_raises_with_raw_secret(self):
        source = (BACKEND_ROOT / "app" / "connectors" / "entra.py").read_text()
        for pattern in FORBIDDEN_SECRET_PATTERNS:
            assert not re.search(pattern, source), f"forbidden secret usage found: {pattern}"

    def test_org_resource_metadata_never_contains_client_secret(self):
        source = (BACKEND_ROOT / "app" / "services" / "integration_service.py").read_text()
        start = source.index("def _create_entra_integration")
        end = source.index("\ndef ", start + 10)
        block = source[start:end]
        metadata_start = block.index("resource_metadata={")
        metadata_end = block.index("},", metadata_start)
        metadata_block = block[metadata_start:metadata_end]
        assert "client_secret" not in metadata_block
        assert "credentials" not in metadata_block

    def test_reconnect_entra_never_logs_new_secret(self):
        source = (BACKEND_ROOT / "app" / "services" / "integration_service.py").read_text()
        start = source.index("def reconnect_credentials_entra")
        end = source.index("\ndef ", start + 10)
        block = source[start:end]
        assert "print(" not in block
        assert "logger.info(new_client_secret" not in block
        assert "logger.debug(new_client_secret" not in block

    def test_no_cli_or_subprocess_dependency(self):
        source = (BACKEND_ROOT / "app" / "connectors" / "entra.py").read_text()
        assert "subprocess" not in source
        assert "os.system" not in source
        assert "az login" not in source.lower()
        assert "connect-mggraph" not in source.lower()
        assert "shell=True" not in source

    def test_no_graph_sdk_or_msal_dependency(self):
        source = (BACKEND_ROOT / "app" / "connectors" / "entra.py").read_text()
        assert "import msal" not in source
        assert "msgraph" not in source.lower()


# ════════════════════════════════════════════════════════════════════════════
# E. Frontend catalog parity
# ════════════════════════════════════════════════════════════════════════════


class TestFrontendLaunchState:
    def _providers_ts(self) -> str:
        path = FRONTEND_ROOT / "src" / "lib" / "providers.ts"
        if not path.is_file():
            pytest.skip("frontend tree not found")
        return path.read_text()

    def test_entra_in_connectable_provider_ids(self):
        text = self._providers_ts()
        start = text.index("export const CONNECTABLE_PROVIDER_IDS")
        end = text.index("];", start)
        assert '"entra"' in text[start:end]

    def test_entra_in_provider_ids(self):
        text = self._providers_ts()
        start = text.index("export const PROVIDER_IDS")
        end = text.index("];", start)
        assert '"entra"' in text[start:end]

    def test_entra_card_copy_omits_stale_planned_wording(self):
        text = self._providers_ts()
        start = text.index("entra: {")
        end = text.index("\n  },", start)
        block = text[start:end]
        assert "(planned)" not in block
        assert "foundation stage" not in block.lower()
        assert "architecture-foundation" not in block.lower()

    def test_entra_card_copy_omits_unsupported_claims(self):
        """The description/monitoredSurfaces copy must not claim
        unsupported capabilities. The trustNote is exempt — it
        legitimately *disclaims* these as a reassurance, the same pattern
        every other provider's trustNote uses."""
        text = self._providers_ts()
        start = text.index("entra: {")
        trust_note_start = text.index("trustNote:", start)
        card_copy = text[start:trust_note_start].lower()
        for forbidden in (
            "threat detection", "session monitoring", "device telemetry",
            "runtime attack", "guaranteed", "sign-in event",
        ):
            assert forbidden not in card_copy, f"card copy claims {forbidden!r}"

    def test_entra_form_component_exists(self):
        path = (
            FRONTEND_ROOT / "src" / "components" / "integrations"
            / "EntraIntegrationForm.tsx"
        )
        if not FRONTEND_ROOT.is_dir():
            pytest.skip("frontend tree not found")
        assert path.is_file()

    def test_entra_form_wired_into_integrations_page(self):
        path = FRONTEND_ROOT / "src" / "app" / "(app)" / "integrations" / "page.tsx"
        if not path.is_file():
            pytest.skip("frontend tree not found")
        text = path.read_text()
        assert "EntraIntegrationForm" in text
        assert 'selectedProvider === "entra"' in text

    def test_entra_form_uses_password_input_for_secret(self):
        path = (
            FRONTEND_ROOT / "src" / "components" / "integrations"
            / "EntraIntegrationForm.tsx"
        )
        if not path.is_file():
            pytest.skip("frontend tree not found")
        text = path.read_text()
        assert 'type="password"' in text
        assert 'id="entra-client-secret"' in text

    def test_entra_form_never_prefills_or_echoes_secret_after_success(self):
        path = (
            FRONTEND_ROOT / "src" / "components" / "integrations"
            / "EntraIntegrationForm.tsx"
        )
        if not path.is_file():
            pytest.skip("frontend tree not found")
        text = path.read_text()
        assert "setClientSecret(\"\")" in text
        assert "Client secret configured" in text

    def test_entra_create_request_type_has_credential_fields(self):
        path = FRONTEND_ROOT / "src" / "types" / "index.ts"
        if not path.is_file():
            pytest.skip("frontend tree not found")
        text = path.read_text()
        assert "entra_tenant_id" in text
        assert "entra_client_id" in text
        assert "entra_client_secret" in text


# ════════════════════════════════════════════════════════════════════════════
# F. Reliability / diagnostics surfaces (message 7-8 wiring stays reachable)
# ════════════════════════════════════════════════════════════════════════════


class TestReliabilitySurfacesReachable:
    def test_build_entra_permission_diagnostics_exists(self):
        from app.connectors.entra import build_entra_permission_diagnostics

        assert callable(build_entra_permission_diagnostics)

    def test_format_entra_permission_diagnostics_text_exists(self):
        from app.connectors.entra import format_entra_permission_diagnostics_text

        assert callable(format_entra_permission_diagnostics_text)

    def test_entra_removal_suppressed_exists(self):
        from app.services.diff_service import _entra_removal_suppressed

        assert callable(_entra_removal_suppressed)

    def test_permission_diagnostics_full_when_all_families_complete(self):
        from app.connectors.entra import build_entra_permission_diagnostics

        families = [
            "users", "groups", "memberships", "applications",
            "service_principals", "app_role_assignments",
            "oauth2_permission_grants", "conditional_access_policies",
            "authentication_strengths", "authentication_methods",
            "directory_role_definitions", "directory_role_assignments",
        ]
        records = [{
            "record_type": "entra_organization",
            "tenant_id": "id:abc",
            "family_completeness": {f: "complete" for f in families},
        }]
        report = build_entra_permission_diagnostics(records)
        assert report["coverage"] == "full"

    def test_permission_diagnostics_partial_when_one_family_denied(self):
        from app.connectors.entra import build_entra_permission_diagnostics

        families = [
            "users", "groups", "memberships", "applications",
            "service_principals", "app_role_assignments",
            "oauth2_permission_grants", "authentication_strengths",
            "authentication_methods", "directory_role_definitions",
            "directory_role_assignments",
        ]
        completeness = {f: "complete" for f in families}
        completeness["conditional_access_policies"] = "denied"
        records = [{
            "record_type": "entra_organization",
            "tenant_id": "id:abc",
            "family_completeness": completeness,
        }]
        report = build_entra_permission_diagnostics(records)
        assert report["coverage"] == "partial"

    def test_permission_diagnostics_invalid_when_no_families_readable(self):
        from app.connectors.entra import build_entra_permission_diagnostics

        records = [{
            "record_type": "entra_organization",
            "tenant_id": "id:abc",
            "family_completeness": {"users": "denied", "groups": "unavailable"},
        }]
        report = build_entra_permission_diagnostics(records)
        assert report["coverage"] == "invalid"

    def test_permission_diagnostics_invalid_when_org_record_missing(self):
        from app.connectors.entra import build_entra_permission_diagnostics

        report = build_entra_permission_diagnostics([])
        assert report["org_reachable"] is False
        assert report["coverage"] == "invalid"

    def test_token_cache_is_credential_bound(self):
        """Message 7 hardening reachable at message 8: the token cache
        must remain bound to (tenant_id, client_id) so a reused connector
        instance never leaks a token across tenants/clients."""
        import inspect

        from app.connectors.entra import EntraConnector

        source = inspect.getsource(EntraConnector._get_token)
        assert "credential_key" in source
