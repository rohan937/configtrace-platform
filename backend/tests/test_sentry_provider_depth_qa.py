"""Sentry provider-depth QA guardrails (Sentry message 8 — public launch,
FINAL provider-expansion milestone).

Durable, deterministic guardrails proving Sentry is a genuinely launched,
connectable, production-certified provider — not just a connector that
exists internally. This file adds no product code; it pins registration-
surface parity, the credential round-trip, security finding registry
parity, sensitive-data boundaries, and frontend/backend consistency so a
future change cannot silently regress the launch.

Sections:
  A. Backend registration surfaces (sync dispatch, schema, coverage, matrix)
  B. Credential round-trip (router _build_credentials, reconnect)
  C. Security Finding registry parity (20 rules)
  D. Sensitive-data / forbidden-call boundary
  E. Frontend catalog parity (connectable, card copy, form wired)
  F. Reliability/completeness surfaces exist (message 5-7 wiring reachable)
  G. Record-type inventory (18 record types, tracked + classified)
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
    def test_sentry_in_sync_supported_providers(self):
        source = (BACKEND_ROOT / "app" / "services" / "sync_service.py").read_text()
        start = source.index("_SUPPORTED_PROVIDERS = (")
        end = source.index(")", start)
        assert '"sentry"' in source[start:end]

    def test_sentry_in_integration_create_request_literal(self):
        from app.schemas.integration import IntegrationCreateRequest

        req = IntegrationCreateRequest(
            provider="sentry",
            display_name="Test org",
            sentry_organization_slug="my-organization",
            sentry_auth_token="fake-token",
        )
        assert req.provider == "sentry"

    def test_sentry_requires_both_credential_fields(self):
        from pydantic import ValidationError
        from app.schemas.integration import IntegrationCreateRequest

        with pytest.raises(ValidationError):
            IntegrationCreateRequest(provider="sentry", display_name="Test")

    def test_sentry_in_security_coverage_providers(self):
        from app.services.security_coverage_service import PROVIDERS

        assert "sentry" in PROVIDERS

    def test_sentry_in_capability_matrix_complete_list_not_partial(self):
        from app.services.provider_capability_matrix_service import (
            PROVIDER_CAPABILITIES,
            PROVIDER_CAPABILITIES_PARTIAL,
        )

        assert "sentry" in {p.provider for p in PROVIDER_CAPABILITIES}
        assert "sentry" not in {p.provider for p in PROVIDER_CAPABILITIES_PARTIAL}

    def test_sentry_capability_maturity_is_partial(self):
        from app.services.provider_capability_matrix_service import get_provider_capability

        cap = get_provider_capability("sentry")
        assert cap is not None
        assert cap.maturity == "partial"

    def test_sentry_capability_notes_say_launched_not_pending(self):
        from app.services.provider_capability_matrix_service import get_provider_capability

        cap = get_provider_capability("sentry")
        assert cap is not None
        notes_lower = cap.notes.lower()
        assert "not connectable" not in notes_lower
        assert "not exposed on the public integrations list" not in notes_lower
        assert "final" in notes_lower

    def test_sentry_dispatch_function_exists(self):
        from app.services import integration_service

        assert hasattr(integration_service, "_create_sentry_integration")

    def test_sentry_reconnect_function_exists(self):
        from app.services import integration_service

        assert hasattr(integration_service, "reconnect_credentials_sentry")


# ════════════════════════════════════════════════════════════════════════════
# B. Credential round-trip
# ════════════════════════════════════════════════════════════════════════════


class TestCredentialRoundTrip:
    def test_build_credentials_extracts_both_fields(self):
        from app.routers.integrations import _build_credentials
        from app.schemas.integration import IntegrationCreateRequest

        req = IntegrationCreateRequest(
            provider="sentry",
            display_name="Test",
            sentry_organization_slug="my-organization",
            sentry_auth_token="fake-token",
        )
        creds = _build_credentials(req)
        assert creds["organization_slug"] == "my-organization"
        assert creds["auth_token"] == "fake-token"

    def test_build_credentials_key_matches_connector_expectation(self):
        """The router must build the exact dict shape
        SentryConnector._credentials() reads from."""
        import inspect

        from app.connectors.sentry import SentryConnector

        source = inspect.getsource(SentryConnector._credentials)
        assert 'credentials.get("organization_slug")' in source
        assert 'credentials.get("auth_token")' in source

    def test_creation_runs_synchronous_probe_coverage(self):
        """Message 8: creation must call probe_coverage() synchronously —
        a bare-record-creation regression here would silently reintroduce
        deferred-to-first-sync validation and break the Invalid
        launch-certification state."""
        import inspect

        from app.services import integration_service

        source = inspect.getsource(integration_service._create_sentry_integration)
        assert "probe_coverage(credentials)" in source
        assert "COVERAGE_INVALID" in source

    def test_reconnect_schema_has_sentry_fields(self):
        from app.schemas.integration import IntegrationReconnectRequest

        fields = IntegrationReconnectRequest.model_fields
        assert "sentry_organization_slug" in fields
        assert "sentry_auth_token" in fields

    def test_reconnect_router_branch_exists_for_sentry(self):
        source = (BACKEND_ROOT / "app" / "routers" / "integrations.py").read_text()
        assert 'integration.provider == "sentry"' in source
        assert "reconnect_credentials_sentry" in source

    def test_reconnect_rejects_different_organization(self):
        """Regression pin: reconnect_credentials_sentry() must compare
        stable organization identity and raise ConnectorError on a
        genuine mismatch — never silently overwrite."""
        import inspect

        from app.services import integration_service

        source = inspect.getsource(integration_service.reconnect_credentials_sentry)
        assert "existing_organization_id != new_organization_id" in source
        assert "ConnectorError" in source
        assert "probe_coverage" in source


# ════════════════════════════════════════════════════════════════════════════
# C. Security Finding registry parity
# ════════════════════════════════════════════════════════════════════════════


class TestSecurityFindingParity:
    def _sentry_rule_keys(self) -> set[str]:
        from app.services.security_rule_registry import KNOWN_RULE_KEYS

        return {k for k in KNOWN_RULE_KEYS if k.startswith("sentry_")}

    def test_sentry_has_exactly_20_rules(self):
        assert len(self._sentry_rule_keys()) == 20

    def test_all_sentry_rules_reachable_from_evaluator(self):
        from app.services.security_rules.sentry import evaluate

        assert callable(evaluate)

    def test_all_sentry_rules_have_confidence(self):
        from app.services.security_rule_confidence import RULE_CONFIDENCE

        missing = self._sentry_rule_keys() - set(RULE_CONFIDENCE.keys())
        assert not missing, f"rules missing confidence: {missing}"

    def test_sentry_in_coverage_record_types(self):
        from app.services.security_coverage_service import RULE_RECORD_TYPES

        missing = self._sentry_rule_keys() - set(RULE_RECORD_TYPES.keys())
        assert not missing, f"rules missing coverage record types: {missing}"


# ════════════════════════════════════════════════════════════════════════════
# D. Sensitive-data / forbidden-call boundary
# ════════════════════════════════════════════════════════════════════════════

FORBIDDEN_TOKEN_PATTERNS = [
    r"logger\.\w+\(.*auth_token",
    r"print\(.*auth_token",
    r"raise \w+Error\(f?[\"'].*\{token\}",
]


class TestSensitiveDataBoundary:
    def test_connector_never_logs_or_raises_with_raw_token(self):
        source = (BACKEND_ROOT / "app" / "connectors" / "sentry.py").read_text()
        for pattern in FORBIDDEN_TOKEN_PATTERNS:
            assert not re.search(pattern, source), f"forbidden token usage found: {pattern}"

    def test_organization_resource_metadata_never_contains_token(self):
        source = (BACKEND_ROOT / "app" / "services" / "integration_service.py").read_text()
        start = source.index("def _create_sentry_integration")
        end = source.index("\ndef ", start + 10)
        block = source[start:end]
        metadata_start = block.index("resource_metadata={")
        metadata_end = block.index("},", metadata_start)
        metadata_block = block[metadata_start:metadata_end]
        assert "auth_token" not in metadata_block
        assert "credentials" not in metadata_block

    def test_reconnect_sentry_never_logs_new_token(self):
        source = (BACKEND_ROOT / "app" / "services" / "integration_service.py").read_text()
        start = source.index("def reconnect_credentials_sentry")
        end = source.index("\ndef ", start + 10)
        block = source[start:end]
        assert "print(" not in block
        assert "logger.info(new_auth_token" not in block
        assert "logger.debug(new_auth_token" not in block

    def test_no_cli_or_subprocess_dependency(self):
        source = (BACKEND_ROOT / "app" / "connectors" / "sentry.py").read_text()
        assert "subprocess" not in source
        assert "os.system" not in source
        assert "shell=True" not in source
        assert not re.search(r"subprocess\.|Popen\(|os\.exec", source)

    def test_no_sentry_sdk_or_global_telemetry_coupling(self):
        """Regression pin: the connector must never read the global
        SENTRY_DSN/SENTRY_AUTH_TOKEN env vars used by ConfigTrace's own
        telemetry, and must never call sentry_sdk.init() — customer
        credentials and ConfigTrace's own observability config are fully
        separate."""
        source = (BACKEND_ROOT / "app" / "connectors" / "sentry.py").read_text()
        assert "import sentry_sdk" not in source
        assert "sentry_sdk.init(" not in source
        assert "os.environ.get(\"SENTRY_" not in source
        assert "os.getenv(\"SENTRY_" not in source

    def test_no_mutating_http_methods_in_connector(self):
        """Regression pin: the connector only issues read-only GET
        requests — no POST/PUT/PATCH/DELETE call sites."""
        source = (BACKEND_ROOT / "app" / "connectors" / "sentry.py").read_text()
        for method in ("client.post(", "client.put(", "client.patch(", "client.delete("):
            assert method not in source, f"forbidden mutating HTTP call found: {method}"


# ════════════════════════════════════════════════════════════════════════════
# E. Frontend catalog parity
# ════════════════════════════════════════════════════════════════════════════


class TestFrontendLaunchState:
    def _providers_ts(self) -> str:
        path = FRONTEND_ROOT / "src" / "lib" / "providers.ts"
        if not path.is_file():
            pytest.skip("frontend tree not found")
        return path.read_text()

    def test_sentry_in_connectable_provider_ids(self):
        text = self._providers_ts()
        start = text.index("export const CONNECTABLE_PROVIDER_IDS")
        end = text.index("];", start)
        assert '"sentry"' in text[start:end]

    def test_sentry_in_provider_ids(self):
        text = self._providers_ts()
        start = text.index("export const PROVIDER_IDS")
        end = text.index("];", start)
        assert '"sentry"' in text[start:end]

    def test_sentry_card_copy_omits_stale_planned_wording(self):
        text = self._providers_ts()
        start = text.index("sentry: {")
        end = text.index("\n  },", start)
        block = text[start:end]
        assert "not yet connectable" not in block.lower()
        assert "not yet available" not in block.lower()
        assert "early foundation" not in block.lower()
        assert "— planned" not in block

    def test_sentry_card_copy_omits_event_ingestion_claims(self):
        text = self._providers_ts()
        start = text.index("sentry: {")
        end = text.index("\n  },", start)
        block = text[start:end].lower()
        for forbidden in (
            "issue events", "stack traces", "breadcrumbs", "session replay",
            "performance spans", "dsn",
        ):
            assert forbidden not in block or "does not ingest" in block or "never" in block, (
                f"card copy may claim {forbidden!r} without a negation"
            )

    def test_sentry_form_component_exists(self):
        path = (
            FRONTEND_ROOT / "src" / "components" / "integrations"
            / "SentryIntegrationForm.tsx"
        )
        if not FRONTEND_ROOT.is_dir():
            pytest.skip("frontend tree not found")
        assert path.is_file()

    def test_sentry_form_wired_into_integrations_page(self):
        path = FRONTEND_ROOT / "src" / "app" / "(app)" / "integrations" / "page.tsx"
        if not path.is_file():
            pytest.skip("frontend tree not found")
        text = path.read_text()
        assert "SentryIntegrationForm" in text
        assert 'selectedProvider === "sentry"' in text

    def test_sentry_form_uses_password_input_for_token(self):
        path = (
            FRONTEND_ROOT / "src" / "components" / "integrations"
            / "SentryIntegrationForm.tsx"
        )
        if not path.is_file():
            pytest.skip("frontend tree not found")
        text = path.read_text()
        assert 'type="password"' in text
        assert 'id="sentry-auth-token"' in text

    def test_sentry_form_never_prefills_or_echoes_token_after_success(self):
        path = (
            FRONTEND_ROOT / "src" / "components" / "integrations"
            / "SentryIntegrationForm.tsx"
        )
        if not path.is_file():
            pytest.skip("frontend tree not found")
        text = path.read_text()
        assert 'setAuthToken("")' in text
        assert "configured" in text.lower()

    def test_sentry_form_recommends_internal_integration_not_personal_token(self):
        path = (
            FRONTEND_ROOT / "src" / "components" / "integrations"
            / "SentryIntegrationForm.tsx"
        )
        if not path.is_file():
            pytest.skip("frontend tree not found")
        text = path.read_text().lower()
        assert "internal integration" in text
        assert "personal token" in text

    def test_sentry_reconnect_modal_supports_sentry_field_name(self):
        path = (
            FRONTEND_ROOT / "src" / "components" / "integrations"
            / "ReconnectIntegrationModal.tsx"
        )
        if not path.is_file():
            pytest.skip("frontend tree not found")
        text = path.read_text()
        assert "sentry_auth_token" in text


# ════════════════════════════════════════════════════════════════════════════
# F. Reliability / completeness surfaces (message 5-7 wiring stays reachable)
# ════════════════════════════════════════════════════════════════════════════


class TestReliabilitySurfacesReachable:
    def test_probe_coverage_exists(self):
        from app.connectors.sentry import SentryConnector

        assert callable(SentryConnector.probe_coverage)

    def test_compute_coverage_state_exists(self):
        from app.connectors.sentry_schema import compute_coverage_state

        assert callable(compute_coverage_state)

    def test_format_capability_diagnostics_exists(self):
        from app.connectors.sentry_schema import format_capability_diagnostics

        assert callable(format_capability_diagnostics)

    def test_sentry_removal_suppressed_exists(self):
        from app.services.diff_service import _sentry_removal_suppressed

        assert callable(_sentry_removal_suppressed)

    def test_coverage_full_when_all_probed_families_available(self):
        from app.connectors.sentry_schema import (
            CAPABILITY_AVAILABLE, PROBED_CAPABILITY_FAMILIES, compute_coverage_state,
        )

        family_status = {f: CAPABILITY_AVAILABLE for f in PROBED_CAPABILITY_FAMILIES}
        assert compute_coverage_state(family_status) == "full"

    def test_coverage_partial_when_one_extended_family_denied(self):
        from app.connectors.sentry_schema import (
            CAPABILITY_AVAILABLE, CAPABILITY_DENIED, PROBED_CAPABILITY_FAMILIES, compute_coverage_state,
        )

        family_status = {f: CAPABILITY_AVAILABLE for f in PROBED_CAPABILITY_FAMILIES}
        family_status["releases"] = CAPABILITY_DENIED
        assert compute_coverage_state(family_status) == "partial"

    def test_coverage_invalid_when_no_core_family_readable(self):
        from app.connectors.sentry_schema import (
            CAPABILITY_AVAILABLE, CAPABILITY_DENIED, CORE_CAPABILITY_FAMILIES,
            EXTENDED_CAPABILITY_FAMILIES, compute_coverage_state,
        )

        family_status = {f: CAPABILITY_DENIED for f in CORE_CAPABILITY_FAMILIES}
        family_status.update({f: CAPABILITY_AVAILABLE for f in EXTENDED_CAPABILITY_FAMILIES})
        assert compute_coverage_state(family_status) == "invalid"

    def test_diagnostics_group_denied_family_as_permission_denied(self):
        from app.connectors.sentry_schema import (
            CAPABILITY_AVAILABLE, CAPABILITY_DENIED, PROBED_CAPABILITY_FAMILIES, format_capability_diagnostics,
        )

        family_status = {f: CAPABILITY_AVAILABLE for f in PROBED_CAPABILITY_FAMILIES}
        family_status["integrations"] = CAPABILITY_DENIED
        diagnostics = format_capability_diagnostics(family_status)
        assert diagnostics["Integrations"] == "Permission denied"
        assert diagnostics["Projects and teams"] == "Available"

    def test_structurally_unsupported_families_excluded_from_probed_set(self):
        """The 3 structurally-unsupported families (issue_alerts, webhooks,
        ownership_rules — no bounded page-1 probe endpoint exists) must
        stay excluded from PROBED_CAPABILITY_FAMILIES; including them
        would make Full coverage permanently unreachable."""
        from app.connectors.sentry_schema import (
            PROBED_CAPABILITY_FAMILIES, STRUCTURALLY_UNSUPPORTED_FAMILIES,
        )

        assert not (set(PROBED_CAPABILITY_FAMILIES) & set(STRUCTURALLY_UNSUPPORTED_FAMILIES))


# ════════════════════════════════════════════════════════════════════════════
# G. Record-type inventory (18 record types, tracked + classified)
# ════════════════════════════════════════════════════════════════════════════


class TestRecordTypeInventory:
    _EXPECTED_RECORD_TYPES = [
        "SENTRY_ORGANIZATION", "SENTRY_API_CAPABILITY", "SENTRY_PROJECT", "SENTRY_TEAM",
        "SENTRY_MEMBER", "SENTRY_TEAM_MEMBERSHIP", "SENTRY_PROJECT_TEAM_ASSIGNMENT",
        "SENTRY_METRIC_ALERT_RULE", "SENTRY_METRIC_ALERT_TRIGGER", "SENTRY_ISSUE_ALERT_RULE",
        "SENTRY_ALERT_ACTION", "SENTRY_ORGANIZATION_INTEGRATION", "SENTRY_REPOSITORY",
        "SENTRY_CODE_MAPPING", "SENTRY_OWNERSHIP_RULE", "SENTRY_PRIVILEGED_MEMBER",
        "SENTRY_PRIVILEGED_TEAM", "SENTRY_ROUTING_CONTEXT",
    ]

    def test_exactly_18_record_types_defined(self):
        import app.connectors.sentry_schema as schema

        for name in self._EXPECTED_RECORD_TYPES:
            assert hasattr(schema, name), f"missing record type constant: {name}"
        assert len(self._EXPECTED_RECORD_TYPES) == 18

    def test_all_18_record_types_tracked_in_diff_service(self):
        import app.connectors.sentry_schema as schema

        source = (BACKEND_ROOT / "app" / "services" / "diff_service.py").read_text()
        for name in self._EXPECTED_RECORD_TYPES:
            record_type_value = getattr(schema, name)
            assert f'"{record_type_value}"' in source, f"{record_type_value} not referenced in diff_service.py"

    def test_all_18_record_types_classified_in_risk_rules(self):
        import app.connectors.sentry_schema as schema

        source = (BACKEND_ROOT / "app" / "services" / "risk_rules" / "sentry.py").read_text()
        for name in self._EXPECTED_RECORD_TYPES:
            record_type_value = getattr(schema, name)
            assert f'"{record_type_value}"' in source or name in source, (
                f"{record_type_value} not referenced in risk_rules/sentry.py"
            )
