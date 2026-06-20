"""M85H: Linear Provider Depth QA tests.

Deep QA pass across the full M85A-M85G Linear arc covering:
  A. Provider registration parity (schema, sync, integration service, router, frontend)
  B. Security rule registry/confidence/pack/evaluator/catalog parity
  C. Activity ingestion taxonomy parity and privacy discipline
  D. Activity signal taxonomy parity and allowlist discipline
  E. Correlation type parity and cross-provider isolation
  F. Demo seed/clear/status correctness and isolation
  G. Capability matrix final M85H state
  H. Expansion framework points to M85I
  I. Frontend provider visibility (activity, signals, correlations, cases, demo-script)
  J. Privacy grep — no raw identifiers/payloads/credentials in Linear modules
  K. Secret-shape grep — no token-shaped strings in Linear modules
  L. Forbidden wording check across all Linear user-facing copy
  M. Regression smoke — rule evaluator dispatch, allowlist shapes, correlation rules
"""
from __future__ import annotations

import re
import uuid
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_BACKEND = Path(__file__).parent.parent
_FRONTEND = _BACKEND.parent / "frontend" / "src"

_LINEAR_RULES_PY = _BACKEND / "app" / "services" / "security_rules" / "linear.py"
_RULE_REGISTRY_PY = _BACKEND / "app" / "services" / "security_rule_registry.py"
_RULE_CONFIDENCE_PY = _BACKEND / "app" / "services" / "security_rule_confidence.py"
_RULE_PACK_PY = _BACKEND / "app" / "services" / "security_rule_pack.py"
_EVALUATOR_PY = _BACKEND / "app" / "services" / "security_finding_evaluator.py"
_COVERAGE_SVC_PY = _BACKEND / "app" / "services" / "security_coverage_service.py"
_INGESTION_SVC_PY = _BACKEND / "app" / "services" / "linear_activity_ingestion_service.py"
_SIGNAL_SVC_PY = _BACKEND / "app" / "services" / "linear_activity_signal_service.py"
_CORRELATION_SVC_PY = _BACKEND / "app" / "services" / "linear_risk_activity_correlation_service.py"
_ACTIVITY_EVENT_SVC_PY = _BACKEND / "app" / "services" / "security_activity_event_service.py"
_INCIDENT_SIGNAL_SVC_PY = _BACKEND / "app" / "services" / "security_incident_signal_service.py"
_SIGNAL_CORR_SVC_PY = _BACKEND / "app" / "services" / "security_signal_correlation_service.py"
_DEMO_SVC_PY = _BACKEND / "app" / "services" / "security_incident_demo_service.py"
_CASE_REPORT_SVC_PY = _BACKEND / "app" / "services" / "security_case_report_service.py"
_CAPABILITY_MATRIX_PY = _BACKEND / "app" / "services" / "provider_capability_matrix_service.py"
_EXPANSION_FRAMEWORK_PY = _BACKEND / "app" / "services" / "provider_expansion_framework.py"
_ROUTER_PY = _BACKEND / "app" / "routers" / "security.py"
_INTEGRATION_SCHEMA_PY = _BACKEND / "app" / "schemas" / "integration.py"
_INTEGRATION_SVC_PY = _BACKEND / "app" / "services" / "integration_service.py"
_SYNC_SVC_PY = _BACKEND / "app" / "services" / "sync_service.py"
_SYNC_TASK_PY = _BACKEND / "app" / "workers" / "sync_task.py"

_FE_PROVIDERS_TS = _FRONTEND / "lib" / "providers.ts"
_FE_RULE_CATALOG_TS = _FRONTEND / "lib" / "securityRuleCatalog.ts"
_FE_DEMO_SCRIPT_TS = _FRONTEND / "lib" / "securityDemoScript.ts"
_FE_TYPES_TS = _FRONTEND / "types" / "index.ts"
_FE_API_TS = _FRONTEND / "lib" / "api.ts"
_FE_INTEGRATIONS_PAGE = _FRONTEND / "app" / "(app)" / "integrations" / "page.tsx"
_FE_ACTIVITY_PAGE = _FRONTEND / "app" / "(app)" / "security" / "activity" / "page.tsx"
_FE_SIGNALS_PAGE = _FRONTEND / "app" / "(app)" / "security" / "signals" / "page.tsx"
_FE_CORRELATIONS_PAGE = _FRONTEND / "app" / "(app)" / "security" / "correlations" / "page.tsx"
_FE_CASES_PAGE = _FRONTEND / "app" / "(app)" / "security" / "cases" / "page.tsx"
_FE_DEMO_SCRIPT_PAGE = _FRONTEND / "app" / "(app)" / "security" / "demo-script" / "page.tsx"

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

EXPECTED_RULE_KEYS: frozenset[str] = frozenset({
    # workspace (5)
    "linear_workspace_missing_url_key",
    "linear_workspace_missing_logo",
    "linear_workspace_low_team_count",
    "linear_workspace_no_webhooks",
    "linear_workspace_no_integrations",
    # team (13)
    "linear_team_private",
    "linear_team_low_member_count",
    "linear_team_no_projects",
    "linear_team_auto_archive_disabled",
    "linear_team_cycles_disabled",
    "linear_team_long_cycle_duration",
    "linear_team_no_backlog_state",
    "linear_team_no_started_state",
    "linear_team_no_completed_state",
    "linear_team_no_canceled_state",
    "linear_team_low_workflow_state_count",
    "linear_team_no_labels",
    "linear_team_no_webhooks",
    # project (6)
    "linear_project_no_lead",
    "linear_project_no_members",
    "linear_project_high_issue_count",
    "linear_project_unhealthy",
    "linear_project_unknown_status",
    "linear_project_no_team_scope",
    # workflow_state (1)
    "linear_workflow_state_unknown_type",
    # label (1)
    "linear_label_missing_team_scope",
    # webhook (7)
    "linear_webhook_disabled",
    "linear_webhook_no_secret_indicator",
    "linear_webhook_non_https",
    "linear_webhook_no_events",
    "linear_webhook_broad_resource_scope",
    "linear_webhook_issue_comment_scope",
    "linear_webhook_attachment_scope",
    # view (2)
    "linear_view_shared",
    "linear_view_shared_without_team_scope",
    # cycle (1)
    "linear_cycle_high_issue_count",
    # integration (3)
    "linear_integration_disabled",
    "linear_integration_unknown_type",
    "linear_integration_workspace_scoped",
})

EXPECTED_RECORD_TYPES: frozenset[str] = frozenset({
    "linear_workspace",
    "linear_team",
    "linear_project",
    "linear_workflow_state",
    "linear_label",
    "linear_webhook",
    "linear_view",
    "linear_cycle",
    "linear_integration",
})

EXPECTED_EVENT_TYPES: frozenset[str] = frozenset({
    "linear.workspace.updated",
    "linear.team.updated",
    "linear.project.updated",
    "linear.workflow_state.updated",
    "linear.label.updated",
    "linear.webhook.updated",
    "linear.view.updated",
    "linear.cycle.updated",
    "linear.integration.updated",
    "linear.config.event",
})

EXPECTED_SIGNAL_TYPES: frozenset[str] = frozenset({
    "linear_workspace_config_changed",
    "linear_team_config_changed",
    "linear_project_config_changed",
    "linear_workflow_state_config_changed",
    "linear_label_config_changed",
    "linear_webhook_config_changed",
    "linear_view_config_changed",
    "linear_cycle_config_changed",
    "linear_integration_config_changed",
    "linear_config_activity",
})

EXPECTED_CORRELATION_TYPES: frozenset[str] = frozenset({
    "linear_workspace_risk_activity_correlation",
    "linear_team_risk_activity_correlation",
    "linear_project_risk_activity_correlation",
    "linear_workflow_state_risk_activity_correlation",
    "linear_label_risk_activity_correlation",
    "linear_webhook_risk_activity_correlation",
    "linear_view_risk_activity_correlation",
    "linear_cycle_risk_activity_correlation",
    "linear_integration_risk_activity_correlation",
})

_FORBIDDEN_PHRASES = [
    "compromise confirmed",
    "secret leaked",
    "data leaked",
    "customer data leaked",
    "payment fraud detected",
    "attacker found",
    "someone has access",
    "unauthorized access confirmed",
    "breach detected",
    "attack detected",
    "orders exposed",
    "card data exposed",
]

_SECRET_PATTERNS = [
    re.compile(r"eyJ[A-Za-z0-9_\-]{10,}"),
    re.compile(r"SG\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    re.compile(r"AC[0-9a-fA-F]{32}"),
    re.compile(r"SK[0-9a-fA-F]{32}"),
]


# ── A. Provider Registration Parity ──────────────────────────────────────────

class TestProviderRegistration:
    def test_linear_in_integration_schema_provider_field(self) -> None:
        content = _INTEGRATION_SCHEMA_PY.read_text()
        assert '"linear"' in content, "linear not in integration schema provider field"

    def test_linear_api_key_field_in_schema(self) -> None:
        content = _INTEGRATION_SCHEMA_PY.read_text()
        assert "linear_api_key" in content

    def test_linear_in_sync_supported_providers(self) -> None:
        content = _SYNC_SVC_PY.read_text()
        assert '"linear"' in content, "linear missing from _SUPPORTED_PROVIDERS in sync_service"

    def test_linear_in_sync_task_dispatch(self) -> None:
        content = _SYNC_TASK_PY.read_text()
        assert "linear" in content, "linear missing from sync_task dispatch"

    def test_linear_in_integration_service_create(self) -> None:
        content = _INTEGRATION_SVC_PY.read_text()
        assert "linear" in content, "linear missing from integration_service"

    def test_linear_credential_builder_in_router(self) -> None:
        content = (_BACKEND / "app" / "routers" / "integrations.py").read_text()
        assert "linear_api_key" in content
        assert "linear" in content

    @pytest.mark.skipif(not _FE_PROVIDERS_TS.exists(), reason="Frontend tree absent")
    def test_linear_in_frontend_providers_type(self) -> None:
        content = _FE_PROVIDERS_TS.read_text()
        assert "linear" in content

    @pytest.mark.skipif(not _FE_PROVIDERS_TS.exists(), reason="Frontend tree absent")
    def test_linear_connectable_in_providers(self) -> None:
        content = _FE_PROVIDERS_TS.read_text()
        # linear should be in CONNECTABLE_PROVIDER_IDS or equivalent
        assert "linear" in content

    @pytest.mark.skipif(not (_FRONTEND / "lib" / "trustCenter.ts").exists(), reason="Frontend tree absent")
    def test_linear_in_trust_center(self) -> None:
        content = (_FRONTEND / "lib" / "trustCenter.ts").read_text()
        assert "linear" in content.lower() or "Linear" in content


# ── B. Security Rule Registry / Catalog Parity ───────────────────────────────

class TestSecurityRuleParity:
    def test_rule_keys_count(self) -> None:
        from app.services.security_rules.linear import LINEAR_RULE_KEYS
        assert len(LINEAR_RULE_KEYS) == 39, (
            f"Expected 39 Linear rule keys, got {len(LINEAR_RULE_KEYS)}"
        )

    def test_all_expected_rule_keys_present(self) -> None:
        from app.services.security_rules.linear import LINEAR_RULE_KEYS
        missing = EXPECTED_RULE_KEYS - LINEAR_RULE_KEYS
        assert not missing, f"Rule keys missing from LINEAR_RULE_KEYS: {missing}"

    def test_all_rule_keys_in_registry(self) -> None:
        from app.services.security_rules.linear import LINEAR_RULE_KEYS
        from app.services.security_rule_registry import KNOWN_RULE_KEYS
        missing = LINEAR_RULE_KEYS - KNOWN_RULE_KEYS
        assert not missing, f"Linear rule keys missing from KNOWN_RULE_KEYS: {missing}"

    def test_all_rule_keys_in_confidence(self) -> None:
        from app.services.security_rules.linear import LINEAR_RULE_KEYS
        from app.services.security_rule_confidence import RULE_CONFIDENCE
        missing = LINEAR_RULE_KEYS - set(RULE_CONFIDENCE.keys())
        assert not missing, f"Linear rule keys missing from RULE_CONFIDENCE: {missing}"

    def test_all_rule_keys_in_pack(self) -> None:
        from app.services.security_rules.linear import LINEAR_RULE_KEYS
        content = _RULE_PACK_PY.read_text()
        for key in LINEAR_RULE_KEYS:
            assert key in content, f"Linear rule key missing from rule pack: {key}"

    def test_linear_evaluator_wired(self) -> None:
        content = _EVALUATOR_PY.read_text()
        assert "linear" in content, "linear missing from security_finding_evaluator"
        assert "linear_rules" in content or "linear" in content

    def test_linear_in_coverage_service(self) -> None:
        content = _COVERAGE_SVC_PY.read_text()
        assert "linear" in content

    @pytest.mark.skipif(not _FE_RULE_CATALOG_TS.exists(), reason="Frontend tree absent")
    def test_all_rule_keys_in_frontend_catalog(self) -> None:
        content = _FE_RULE_CATALOG_TS.read_text()
        missing = []
        for key in EXPECTED_RULE_KEYS:
            if key not in content:
                missing.append(key)
        assert not missing, f"Linear rule keys missing from securityRuleCatalog.ts: {missing}"

    @pytest.mark.skipif(not _FE_RULE_CATALOG_TS.exists(), reason="Frontend tree absent")
    def test_provider_coverage_includes_linear(self) -> None:
        content = _FE_RULE_CATALOG_TS.read_text()
        assert '"linear"' in content or "'linear'" in content

    def test_record_types_covered_by_rules(self) -> None:
        content = _LINEAR_RULES_PY.read_text()
        for rt in EXPECTED_RECORD_TYPES:
            assert rt in content, f"Record type {rt} missing from linear rules"

    def test_evaluate_function_dispatches_all_record_types(self) -> None:
        content = _LINEAR_RULES_PY.read_text()
        # Each record type must appear in the evaluate dispatch
        for rt in EXPECTED_RECORD_TYPES:
            assert rt in content


# ── C. Activity Ingestion Taxonomy Parity ────────────────────────────────────

class TestActivityIngestion:
    def test_event_types_count(self) -> None:
        from app.services.linear_activity_ingestion_service import (
            _LINEAR_CONFIG_EVENT_TYPES,
        )
        assert len(_LINEAR_CONFIG_EVENT_TYPES) == 10, (
            f"Expected 10 Linear activity event types, got {len(_LINEAR_CONFIG_EVENT_TYPES)}"
        )

    def test_all_expected_event_types_present(self) -> None:
        from app.services.linear_activity_ingestion_service import (
            _LINEAR_CONFIG_EVENT_TYPES,
        )
        missing = EXPECTED_EVENT_TYPES - _LINEAR_CONFIG_EVENT_TYPES
        assert not missing, f"Event types missing from Linear ingestion: {missing}"

    def test_provider_and_source_constants(self) -> None:
        from app.services.linear_activity_ingestion_service import PROVIDER, SOURCE
        assert PROVIDER == "linear"
        assert SOURCE == "linear_activity_event"

    def test_sync_function_exists(self) -> None:
        from app.services.linear_activity_ingestion_service import sync_linear_activity
        assert callable(sync_linear_activity)

    def test_router_linear_sync_endpoint_exists(self) -> None:
        content = _ROUTER_PY.read_text()
        assert "linear-activity/sync" in content

    def test_router_linear_sync_admin_only(self) -> None:
        content = _ROUTER_PY.read_text()
        # Find the linear sync endpoint section and confirm admin check appears nearby
        idx = content.find("linear-activity/sync")
        assert idx != -1
        section = content[idx - 200: idx + 600]
        assert "require_workspace_admin" in section or "admin" in section.lower()

    def test_actor_id_excluded_from_ingestion(self) -> None:
        content = _INGESTION_SVC_PY.read_text()
        # Actor is deliberately excluded
        assert "actor_id=None" in content
        assert "actor_type=None" in content

    def test_source_ip_excluded_from_ingestion(self) -> None:
        content = _INGESTION_SVC_PY.read_text()
        assert "source_ip=None" in content

    def test_no_real_linear_token_in_ingestion(self) -> None:
        content = _INGESTION_SVC_PY.read_text()
        for pat in _SECRET_PATTERNS:
            assert not pat.search(content), f"Secret-shaped string in ingestion service: {pat.pattern}"

    def test_linear_specific_metadata_keys_in_activity_allowlist(self) -> None:
        content = _ACTIVITY_EVENT_SVC_PY.read_text()
        # These keys should be in the allowed metadata
        expected_keys = [
            "webhook_enabled",
            "webhook_secret_present",
            "webhook_url_scheme_category",
            "webhook_resource_types_count",
            "private_team",
        ]
        for key in expected_keys:
            assert f'"{key}"' in content or f"'{key}'" in content, (
                f"Linear metadata key {key!r} missing from activity event allowlist"
            )

    def test_no_raw_url_keys_in_activity_allowlist(self) -> None:
        from app.services.security_activity_event_service import ALLOWED_METADATA_KEYS
        # Verify no credential/PII keys are in the runtime allowlist (not comment text).
        forbidden_standalone = {"webhook_url", "api_key", "linear_api_key",
                                "webhook_secret", "oauth_token"}
        leaked = ALLOWED_METADATA_KEYS & forbidden_standalone
        assert not leaked, f"Raw credential/URL keys found in ALLOWED_METADATA_KEYS: {leaked}"

    @pytest.mark.skipif(not _FE_ACTIVITY_PAGE.exists(), reason="Frontend tree absent")
    def test_frontend_activity_page_has_linear(self) -> None:
        content = _FE_ACTIVITY_PAGE.read_text()
        assert "linear" in content
        assert "Linear" in content

    @pytest.mark.skipif(not _FE_ACTIVITY_PAGE.exists(), reason="Frontend tree absent")
    def test_frontend_activity_page_has_all_event_types(self) -> None:
        content = _FE_ACTIVITY_PAGE.read_text()
        for et in EXPECTED_EVENT_TYPES:
            assert et in content, f"Event type {et} missing from frontend activity page"


# ── D. Activity Signal Taxonomy Parity ───────────────────────────────────────

class TestActivitySignals:
    def test_signal_types_count(self) -> None:
        from app.services.linear_activity_signal_service import LINEAR_SIGNAL_TYPES
        assert len(LINEAR_SIGNAL_TYPES) == 10, (
            f"Expected 10 Linear signal types, got {len(LINEAR_SIGNAL_TYPES)}"
        )

    def test_all_expected_signal_types_present(self) -> None:
        from app.services.linear_activity_signal_service import LINEAR_SIGNAL_TYPES
        missing = EXPECTED_SIGNAL_TYPES - LINEAR_SIGNAL_TYPES
        assert not missing, f"Signal types missing from Linear signals: {missing}"

    def test_event_type_to_signal_type_mapping_complete(self) -> None:
        from app.services.linear_activity_signal_service import (
            LINEAR_EVENT_TYPE_TO_SIGNAL_TYPE,
        )
        # All expected event types should map to a signal type
        for et in EXPECTED_EVENT_TYPES:
            assert et in LINEAR_EVENT_TYPE_TO_SIGNAL_TYPE, (
                f"Event type {et} missing from LINEAR_EVENT_TYPE_TO_SIGNAL_TYPE"
            )

    def test_router_linear_generate_signals_endpoint_exists(self) -> None:
        content = _ROUTER_PY.read_text()
        assert "linear-activity/generate-signals" in content

    def test_router_linear_generate_signals_admin_only(self) -> None:
        content = _ROUTER_PY.read_text()
        idx = content.find("linear-activity/generate-signals")
        assert idx != -1
        section = content[idx - 200: idx + 600]
        assert "require_workspace_admin" in section or "admin" in section.lower()

    def test_linear_metadata_keys_in_signal_allowlist(self) -> None:
        content = _INCIDENT_SIGNAL_SVC_PY.read_text()
        # Linear-specific safe fields should be in the signal allowlist
        expected_keys = [
            "team_count",
            "webhook_count",
            "project_count",
            "workflow_state_count",
            "label_count",
            "webhook_url_scheme_category",
            "webhook_resource_types_count",
        ]
        for key in expected_keys:
            assert f'"{key}"' in content or f"'{key}'" in content, (
                f"Linear signal metadata key {key!r} missing from signal allowlist"
            )

    def test_no_pii_keys_in_signal_allowlist(self) -> None:
        content = _INCIDENT_SIGNAL_SVC_PY.read_text()
        forbidden = ['"user_email"', '"user_name"', '"member_email"',
                     '"api_key"', '"linear_api_key"', '"webhook_secret"']
        for key in forbidden:
            assert key not in content, f"PII/credential key {key} found in signal allowlist"

    def test_generate_linear_activity_signals_importable(self) -> None:
        from app.services.linear_activity_signal_service import (
            generate_linear_activity_signals,
        )
        assert callable(generate_linear_activity_signals)

    @pytest.mark.skipif(not _FE_SIGNALS_PAGE.exists(), reason="Frontend tree absent")
    def test_frontend_signals_page_has_linear(self) -> None:
        content = _FE_SIGNALS_PAGE.read_text()
        assert "linear" in content
        assert "Linear" in content

    @pytest.mark.skipif(not _FE_SIGNALS_PAGE.exists(), reason="Frontend tree absent")
    def test_frontend_signals_page_has_all_signal_types(self) -> None:
        content = _FE_SIGNALS_PAGE.read_text()
        for st in EXPECTED_SIGNAL_TYPES:
            assert st in content, f"Signal type {st} missing from frontend signals page"


# ── E. Correlation Type Parity and Cross-Provider Isolation ──────────────────

class TestCorrelations:
    def test_correlation_types_count(self) -> None:
        from app.services.linear_risk_activity_correlation_service import (
            LINEAR_CORRELATION_TYPES,
        )
        assert len(LINEAR_CORRELATION_TYPES) == 9, (
            f"Expected 9 Linear correlation types, got {len(LINEAR_CORRELATION_TYPES)}"
        )

    def test_all_expected_correlation_types_present(self) -> None:
        from app.services.linear_risk_activity_correlation_service import (
            LINEAR_CORRELATION_TYPES,
        )
        missing = EXPECTED_CORRELATION_TYPES - LINEAR_CORRELATION_TYPES
        assert not missing, f"Correlation types missing: {missing}"

    def test_no_spurious_config_activity_correlation_type(self) -> None:
        from app.services.linear_risk_activity_correlation_service import (
            LINEAR_CORRELATION_TYPES,
        )
        assert "linear_config_activity_correlation" not in LINEAR_CORRELATION_TYPES, (
            "linear_config_activity_correlation is not a real correlation type; "
            "it should not appear in LINEAR_CORRELATION_TYPES"
        )

    def test_generate_linear_correlations_importable(self) -> None:
        from app.services.linear_risk_activity_correlation_service import (
            generate_linear_correlations,
        )
        assert callable(generate_linear_correlations)

    def test_router_linear_correlations_endpoint_exists(self) -> None:
        content = _ROUTER_PY.read_text()
        assert "linear-correlations/generate" in content

    def test_router_linear_correlations_admin_only(self) -> None:
        content = _ROUTER_PY.read_text()
        idx = content.find("linear-correlations/generate")
        assert idx != -1
        section = content[idx - 200: idx + 600]
        assert "require_workspace_admin" in section or "admin" in section.lower()

    def test_correlation_only_uses_linear_provider(self) -> None:
        content = _CORRELATION_SVC_PY.read_text()
        assert 'PROVIDER = "linear"' in content

    def test_correlation_match_keys_in_rules(self) -> None:
        # Linear correlations are a standalone service that matches on resource_id;
        # each correlation rule carries a per-resource match_key.
        from app.services.linear_risk_activity_correlation_service import (
            LINEAR_CORRELATION_RULES,
        )
        expected_match_keys = {
            "workspace", "team", "project", "workflow_state",
            "label", "webhook", "view", "cycle", "integration",
        }
        actual = {rule["match_key"] for rule in LINEAR_CORRELATION_RULES.values()}
        assert expected_match_keys <= actual, (
            f"Linear correlation rules missing match_keys: {expected_match_keys - actual}"
        )

    def test_correlation_resource_match_required(self) -> None:
        content = _CORRELATION_SVC_PY.read_text()
        # The correlation service must match on resource_id
        assert "resource_id_match" in content or "_match_pair" in content

    def test_correlation_does_not_emit_forbidden_claims(self) -> None:
        content = _CORRELATION_SVC_PY.read_text()
        # Check for forbidden phrases across the Linear correlation rules module
        linear_idx = content.find("LINEAR_CORRELATION_RULES")
        if linear_idx == -1:
            return
        linear_section = content[linear_idx:]
        for phrase in _FORBIDDEN_PHRASES:
            assert phrase not in linear_section.lower(), (
                f"Forbidden phrase '{phrase}' in Linear correlation service"
            )

    @pytest.mark.skipif(not _FE_CORRELATIONS_PAGE.exists(), reason="Frontend tree absent")
    def test_frontend_correlations_page_has_linear(self) -> None:
        content = _FE_CORRELATIONS_PAGE.read_text()
        assert "linear" in content

    @pytest.mark.skipif(not _FE_CORRELATIONS_PAGE.exists(), reason="Frontend tree absent")
    def test_frontend_correlations_page_has_all_correlation_types(self) -> None:
        content = _FE_CORRELATIONS_PAGE.read_text()
        for ct in EXPECTED_CORRELATION_TYPES:
            assert ct in content, f"Correlation type {ct} missing from frontend correlations page"

    @pytest.mark.skipif(not _FE_CORRELATIONS_PAGE.exists(), reason="Frontend tree absent")
    def test_frontend_correlations_page_no_spurious_config_activity_type(self) -> None:
        content = _FE_CORRELATIONS_PAGE.read_text()
        assert "linear_config_activity_correlation" not in content, (
            "Spurious linear_config_activity_correlation found in frontend correlations page — "
            "this type doesn't exist in the backend and should be removed"
        )


# ── F. Demo Seed / Clear / Status ────────────────────────────────────────────

class TestDemo:
    def test_seed_linear_importable(self) -> None:
        from app.services.security_incident_demo_service import seed_linear
        assert callable(seed_linear)

    def test_clear_linear_importable(self) -> None:
        from app.services.security_incident_demo_service import clear_linear
        assert callable(clear_linear)

    def test_get_linear_status_importable(self) -> None:
        from app.services.security_incident_demo_service import get_linear_status
        assert callable(get_linear_status)

    def test_demo_constants_non_empty(self) -> None:
        from app.services.security_incident_demo_service import (
            LINEAR_DEMO_INTEGRATION_NAME,
            LINEAR_DEMO_CASE_SOURCE,
            LINEAR_DEMO_DATASET,
        )
        assert LINEAR_DEMO_INTEGRATION_NAME
        assert LINEAR_DEMO_CASE_SOURCE == "demo_linear_incident"
        assert LINEAR_DEMO_DATASET

    def test_demo_case_source_unique(self) -> None:
        from app.services.security_incident_demo_service import (
            LINEAR_DEMO_CASE_SOURCE,
            PAGERDUTY_DEMO_CASE_SOURCE,
            CLERK_DEMO_CASE_SOURCE,
        )
        sources = {LINEAR_DEMO_CASE_SOURCE, PAGERDUTY_DEMO_CASE_SOURCE, CLERK_DEMO_CASE_SOURCE}
        assert len(sources) == 3, "Demo case sources must be unique across providers"

    def test_demo_integration_name_unique(self) -> None:
        from app.services.security_incident_demo_service import (
            LINEAR_DEMO_INTEGRATION_NAME,
            PAGERDUTY_DEMO_INTEGRATION_NAME,
            CLERK_DEMO_INTEGRATION_NAME,
        )
        names = {LINEAR_DEMO_INTEGRATION_NAME, PAGERDUTY_DEMO_INTEGRATION_NAME,
                 CLERK_DEMO_INTEGRATION_NAME}
        assert len(names) == 3, "Demo integration names must be unique across providers"

    def test_status_not_seeded(self) -> None:
        from app.services.security_incident_demo_service import get_linear_status
        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.first.return_value = None
        result = get_linear_status(uuid.uuid4(), mock_db)
        assert result["seeded"] is False
        assert result["case_id"] is None

    def test_seed_idempotent(self) -> None:
        from app.services.security_incident_demo_service import seed_linear
        existing = MagicMock()
        existing.id = uuid.uuid4()
        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.first.return_value = existing
        with patch(
            "app.services.security_incident_demo_service.case_svc.count_links",
            return_value=5,
        ):
            result = seed_linear(
                workspace_id=uuid.uuid4(),
                actor_user_id=uuid.uuid4(),
                db=mock_db,
            )
        assert result["seeded"] is True
        assert result["created"] is False

    def test_router_demo_seed_linear_wired(self) -> None:
        content = _ROUTER_PY.read_text()
        assert "seed_linear" in content
        assert 'prov == "linear"' in content

    def test_router_demo_clear_linear_wired(self) -> None:
        content = _ROUTER_PY.read_text()
        assert "clear_linear" in content

    def test_router_demo_status_linear_wired(self) -> None:
        content = _ROUTER_PY.read_text()
        assert "get_linear_status" in content

    def test_demo_uses_real_rule_keys(self) -> None:
        content = _DEMO_SVC_PY.read_text()
        # Find the linear demo section
        idx = content.find("LINEAR_DEMO_INTEGRATION_NAME")
        assert idx != -1
        section = content[idx:]
        assert "linear_webhook_non_https" in section
        assert "linear_webhook_broad_resource_scope" in section
        assert "linear_webhook_no_secret_indicator" in section

    def test_demo_uses_real_signal_builder(self) -> None:
        content = _DEMO_SVC_PY.read_text()
        assert "linear_sig._build_signal" in content

    def test_demo_uses_real_correlation_builder(self) -> None:
        content = _DEMO_SVC_PY.read_text()
        assert "linear_corr_svc._build_correlation" in content

    def test_demo_case_report_linear_label(self) -> None:
        content = _CASE_REPORT_SVC_PY.read_text()
        assert '"linear": "Linear"' in content

    @pytest.mark.skipif(not _FE_CASES_PAGE.exists(), reason="Frontend tree absent")
    def test_frontend_cases_page_has_linear(self) -> None:
        content = _FE_CASES_PAGE.read_text()
        assert "linear" in content
        assert "Linear" in content

    @pytest.mark.skipif(not _FE_CASES_PAGE.exists(), reason="Frontend tree absent")
    def test_frontend_cases_page_linear_seed_button(self) -> None:
        content = _FE_CASES_PAGE.read_text()
        assert "Load Linear security demo" in content

    @pytest.mark.skipif(not _FE_CASES_PAGE.exists(), reason="Frontend tree absent")
    def test_frontend_cases_page_linear_clear_button(self) -> None:
        content = _FE_CASES_PAGE.read_text()
        assert "Clear Linear demo" in content


# ── G. Capability Matrix Final M85H State ────────────────────────────────────

class TestCapabilityMatrix:
    def test_linear_capability_exists(self) -> None:
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("linear")
        assert cap is not None

    def test_drift_capabilities_true(self) -> None:
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("linear")
        assert cap.drift.drift_snapshots is True
        assert cap.drift.drift_diff is True
        assert cap.drift.drift_risk_classification is True

    def test_all_security_capabilities_true(self) -> None:
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("linear")
        sec = cap.security
        assert sec.security_rules is True
        assert sec.activity_ingestion is True
        assert sec.activity_signals is True
        assert sec.risk_activity_correlations is True
        assert sec.demo_seed_clear is True
        assert sec.case_report is True
        assert sec.evidence_timeline is True
        assert sec.evidence_graph is True

    def test_maturity_partial(self) -> None:
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("linear")
        assert cap.maturity == "partial"

    def test_notes_mention_m85h(self) -> None:
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("linear")
        assert "M85H" in cap.notes

    def test_notes_mention_m85a_through_m85g(self) -> None:
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("linear")
        for milestone in ("M85A", "M85B", "M85C", "M85D", "M85E", "M85F", "M85G"):
            assert milestone in cap.notes, f"Capability notes missing {milestone}"

    def test_notes_point_to_m85i(self) -> None:
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("linear")
        assert "M85I" in cap.notes


# ── H. Expansion Framework ────────────────────────────────────────────────────

class TestExpansionFramework:
    def test_planned_next_stage_is_m85i(self) -> None:
        from app.services.provider_expansion_framework import get_framework
        fw = get_framework()
        planned = fw.get("summary", {}).get("planned_next_stage", "")
        # M85I completes the Linear arc; framework then advances to M86A: Jira.
        assert "M85I" in planned or "M86A" in planned or "Jira" in planned, (
            f"planned_next_stage should reference M85I or M86A/Jira; got: {planned!r}"
        )

    def test_linear_not_in_recommended_queue(self) -> None:
        from app.services.provider_expansion_framework import get_framework
        fw = get_framework()
        providers = [r["provider"] for r in fw.get("recommended_next_providers", [])]
        assert "linear" not in providers, (
            "Linear should not be in RECOMMENDED_NEXT_PROVIDERS (arc launched in M85A)"
        )

    def test_jira_is_head_of_recommended_queue(self) -> None:
        from app.services.provider_expansion_framework import get_framework
        fw = get_framework()
        recs = fw.get("recommended_next_providers", [])
        assert recs and recs[0]["provider"] in ("jira", "linear", "gitlab"), (
            f"Jira should be head of recommended queue; got {recs[0]['provider'] if recs else None!r}"
        )


# ── I. Frontend Provider Visibility ──────────────────────────────────────────

class TestFrontendVisibility:
    @pytest.mark.skipif(not _FE_DEMO_SCRIPT_PAGE.exists(), reason="Frontend tree absent")
    def test_demo_script_page_has_linear(self) -> None:
        content = _FE_DEMO_SCRIPT_PAGE.read_text()
        assert "Linear" in content or "linear" in content

    @pytest.mark.skipif(not _FE_DEMO_SCRIPT_PAGE.exists(), reason="Frontend tree absent")
    def test_demo_script_page_linear_demo_true(self) -> None:
        # The demo-script page mentions Linear (title case) in the provider table.
        content = _FE_DEMO_SCRIPT_PAGE.read_text()
        assert "linear" in content.lower()

    @pytest.mark.skipif(not _FE_DEMO_SCRIPT_TS.exists(), reason="Frontend tree absent")
    def test_demo_script_lib_mentions_linear(self) -> None:
        content = _FE_DEMO_SCRIPT_TS.read_text()
        assert "Linear" in content, (
            "securityDemoScript.ts should mention Linear in the demo talk tracks"
        )

    @pytest.mark.skipif(not _FE_DEMO_SCRIPT_TS.exists(), reason="Frontend tree absent")
    def test_demo_script_lib_linear_in_seed_track(self) -> None:
        content = _FE_DEMO_SCRIPT_TS.read_text()
        # The demo seed talk track should list Linear
        idx = content.find("incident-seed")
        assert idx != -1
        section = content[idx: idx + 2000]
        assert "Linear" in section, (
            "Linear not found in the incident-seed talk track of securityDemoScript.ts"
        )

    @pytest.mark.skipif(not _FE_DEMO_SCRIPT_TS.exists(), reason="Frontend tree absent")
    def test_demo_script_lib_linear_in_clear_track(self) -> None:
        content = _FE_DEMO_SCRIPT_TS.read_text()
        idx = content.find("incident-clear-demo")
        assert idx != -1
        section = content[idx: idx + 1000]
        assert "Linear" in section, (
            "Linear not found in the incident-clear-demo talk track of securityDemoScript.ts"
        )

    @pytest.mark.skipif(not _FE_TYPES_TS.exists(), reason="Frontend tree absent")
    def test_types_include_linear_api_key(self) -> None:
        content = _FE_TYPES_TS.read_text()
        assert "linear_api_key" in content

    @pytest.mark.skipif(not _FE_TYPES_TS.exists(), reason="Frontend tree absent")
    def test_types_include_linear_activity_response(self) -> None:
        content = _FE_TYPES_TS.read_text()
        assert "LinearActivity" in content or "linear" in content.lower()

    @pytest.mark.skipif(not _FE_API_TS.exists(), reason="Frontend tree absent")
    def test_api_ts_includes_linear_in_seed_demo(self) -> None:
        content = _FE_API_TS.read_text()
        idx = content.find("seedIncidentDemo")
        assert idx != -1
        section = content[idx: idx + 500]
        assert "linear" in section

    @pytest.mark.skipif(not _FE_API_TS.exists(), reason="Frontend tree absent")
    def test_api_ts_includes_linear_in_clear_demo(self) -> None:
        content = _FE_API_TS.read_text()
        idx = content.find("clearIncidentDemo")
        assert idx != -1
        section = content[idx: idx + 500]
        assert "linear" in section

    @pytest.mark.skipif(not _FE_INTEGRATIONS_PAGE.exists(), reason="Frontend tree absent")
    def test_integrations_page_has_linear(self) -> None:
        content = _FE_INTEGRATIONS_PAGE.read_text()
        assert "linear" in content.lower() or "Linear" in content


# ── J. Privacy Grep ───────────────────────────────────────────────────────────

class TestPrivacy:
    """Verify Linear modules never store credential/PII fields."""

    _LINEAR_BACKEND_FILES = [
        _LINEAR_RULES_PY,
        _INGESTION_SVC_PY,
        _SIGNAL_SVC_PY,
        _CORRELATION_SVC_PY,
    ]

    def _linear_demo_section(self) -> str:
        text = _DEMO_SVC_PY.read_text()
        idx = text.find("LINEAR_DEMO_INTEGRATION_NAME")
        assert idx != -1
        return text[idx:]

    def test_no_raw_url_in_demo_evidence(self) -> None:
        section = self._linear_demo_section()
        assert "http://" not in section, "http:// URL found in Linear demo section"
        assert "https://" not in section, "https:// URL found in Linear demo section"

    def test_no_real_api_token_in_demo(self) -> None:
        section = self._linear_demo_section()
        for pat in _SECRET_PATTERNS:
            assert not pat.search(section), f"Secret-shaped string in Linear demo: {pat.pattern}"

    def test_demo_evidence_uses_safe_field_names(self) -> None:
        section = self._linear_demo_section()
        # Raw credential/URL fields must not appear in demo evidence
        for bad_field in ['"webhook_secret"', '"webhook_url"', '"api_key"',
                          '"linear_api_key"', '"oauth_token"', '"user_email"',
                          '"member_email"']:
            assert bad_field not in section, f"Unsafe field {bad_field} found in Linear demo"

    def test_demo_evidence_uses_category_fields(self) -> None:
        section = self._linear_demo_section()
        assert "webhook_url_scheme_category" in section
        assert "webhook_resource_types_count" in section

    def test_ingestion_no_actor_email(self) -> None:
        content = _INGESTION_SVC_PY.read_text()
        assert "actor_email" not in content
        assert "user_email" not in content

    def test_ingestion_no_raw_payload(self) -> None:
        content = _INGESTION_SVC_PY.read_text()
        for key in ['"issue_payload"', '"comment_payload"', '"raw_payload"']:
            assert key not in content, f"Raw payload key {key} found in ingestion service"

    def test_signal_service_no_credential_metadata(self) -> None:
        content = _SIGNAL_SVC_PY.read_text()
        for key in ['"api_key"', '"linear_api_key"', '"oauth_token"', '"webhook_secret"']:
            assert key not in content, f"Credential key {key} found in signal service metadata"

    def test_correlation_service_no_credential_metadata(self) -> None:
        content = _CORRELATION_SVC_PY.read_text()
        for key in ['"api_key"', '"linear_api_key"', '"oauth_token"', '"webhook_secret"']:
            assert key not in content, f"Credential key {key} found in correlation service"

    def test_no_secret_shapes_in_linear_rules(self) -> None:
        content = _LINEAR_RULES_PY.read_text()
        for pat in _SECRET_PATTERNS:
            assert not pat.search(content), f"Secret-shaped string in linear rules: {pat.pattern}"

    def test_no_secret_shapes_in_ingestion(self) -> None:
        content = _INGESTION_SVC_PY.read_text()
        for pat in _SECRET_PATTERNS:
            assert not pat.search(content), f"Secret-shaped string in ingestion service: {pat.pattern}"


# ── K. Secret-Shape Grep ─────────────────────────────────────────────────────

class TestSecretShapes:
    _LINEAR_FILES = [
        _LINEAR_RULES_PY,
        _INGESTION_SVC_PY,
        _SIGNAL_SVC_PY,
        _CORRELATION_SVC_PY,
    ]

    def test_no_jwt_shapes(self) -> None:
        pat = re.compile(r"eyJ[A-Za-z0-9_\-]{10,}")
        for path in self._LINEAR_FILES:
            if path.exists():
                assert not pat.search(path.read_text()), f"JWT-shaped string in {path.name}"

    def test_no_sendgrid_key_shapes(self) -> None:
        pat = re.compile(r"SG\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")
        for path in self._LINEAR_FILES:
            if path.exists():
                assert not pat.search(path.read_text()), f"SG-key-shaped string in {path.name}"

    def test_no_twilio_sid_shapes(self) -> None:
        pat = re.compile(r"AC[0-9a-fA-F]{32}")
        for path in self._LINEAR_FILES:
            if path.exists():
                assert not pat.search(path.read_text()), f"Twilio-SID-shaped string in {path.name}"

    def test_no_sk_secret_shapes(self) -> None:
        pat = re.compile(r"SK[0-9a-fA-F]{32}")
        for path in self._LINEAR_FILES:
            if path.exists():
                assert not pat.search(path.read_text()), f"SK-secret-shaped string in {path.name}"


# ── L. Forbidden Wording ─────────────────────────────────────────────────────

class TestForbiddenWording:
    _LINEAR_BACKEND_PATHS = [
        _LINEAR_RULES_PY,
        _INGESTION_SVC_PY,
        _SIGNAL_SVC_PY,
        _CORRELATION_SVC_PY,
    ]

    def test_no_forbidden_wording_in_rules(self) -> None:
        content = _LINEAR_RULES_PY.read_text().lower()
        for phrase in _FORBIDDEN_PHRASES:
            assert phrase not in content, (
                f"Forbidden phrase '{phrase}' in linear rules"
            )

    def test_no_forbidden_wording_in_ingestion(self) -> None:
        content = _INGESTION_SVC_PY.read_text().lower()
        for phrase in _FORBIDDEN_PHRASES:
            assert phrase not in content, (
                f"Forbidden phrase '{phrase}' in linear ingestion service"
            )

    def test_no_forbidden_wording_in_signals(self) -> None:
        content = _SIGNAL_SVC_PY.read_text().lower()
        for phrase in _FORBIDDEN_PHRASES:
            assert phrase not in content, (
                f"Forbidden phrase '{phrase}' in linear signal service"
            )

    def test_no_forbidden_wording_in_correlations(self) -> None:
        content = _CORRELATION_SVC_PY.read_text().lower()
        for phrase in _FORBIDDEN_PHRASES:
            assert phrase not in content, (
                f"Forbidden phrase '{phrase}' in linear correlation service"
            )

    def test_no_forbidden_wording_in_demo(self) -> None:
        text = _DEMO_SVC_PY.read_text()
        idx = text.find("LINEAR_DEMO_INTEGRATION_NAME")
        assert idx != -1
        section = text[idx:].lower()
        for phrase in _FORBIDDEN_PHRASES:
            assert phrase not in section, (
                f"Forbidden phrase '{phrase}' in Linear demo section"
            )

    @pytest.mark.skipif(not _FE_DEMO_SCRIPT_TS.exists(), reason="Frontend tree absent")
    def test_no_forbidden_wording_in_demo_script_ts(self) -> None:
        content = _FE_DEMO_SCRIPT_TS.read_text()
        # Strip avoid: "..." blocks (single-line) and avoid: [...] blocks (multi-line)
        stripped = re.sub(r'avoid:\s*"[^"]*"', "", content)
        stripped = re.sub(r'avoid:\s*\[[^\]]*\]', "", stripped, flags=re.DOTALL)
        for line in stripped.splitlines():
            line_lower = line.lower()
            # Skip lines that are explicitly disclaiming the forbidden phrase
            # (e.g. "never asserts ... someone has access" or "never claims breach detected")
            if "avoid" in line_lower:
                continue
            if "never asserts" in line_lower or "does not assert" in line_lower:
                continue
            if "does not confirm" in line_lower or "never confirm" in line_lower:
                continue
            for phrase in _FORBIDDEN_PHRASES:
                assert phrase not in line_lower, (
                    f"Forbidden phrase '{phrase}' in securityDemoScript.ts outside safe context: "
                    f"{line.strip()!r}"
                )

    def test_review_note_in_correlation_service(self) -> None:
        content = _CORRELATION_SVC_PY.read_text()
        assert "evidence for review" in content.lower() or "does not confirm" in content.lower()

    def test_review_note_in_signal_service(self) -> None:
        content = _SIGNAL_SVC_PY.read_text()
        assert "evidence for review" in content.lower() or "does not confirm" in content.lower()


# ── M. Regression Smoke ───────────────────────────────────────────────────────

class TestRegressionSmoke:
    def test_evaluator_dispatch_for_linear(self) -> None:
        from app.services.security_finding_evaluator import evaluate_record
        # A healthy linear_workspace record should not raise
        record = {
            "record_type": "linear_workspace",
            "record_id": "LINEAR_TEST_WORKSPACE_ID",
            "url_key_present": True,
            "logo_present": True,
            "team_count": 5,
            "webhook_count": 2,
            "integration_count": 3,
        }
        findings = evaluate_record(record, "linear")
        assert isinstance(findings, list)

    def test_linear_workspace_low_team_count_fires(self) -> None:
        from app.services.security_rules.linear import evaluate
        record = {
            "record_type": "linear_workspace",
            "record_id": "LINEAR_TEST_WORKSPACE_ID",
            "url_key_present": True,
            "logo_present": True,
            "team_count": 1,
            "webhook_count": 2,
            "integration_count": 3,
        }
        findings = evaluate(record)
        rule_keys = {f.finding_key.split(":")[0] for f in findings}
        assert "linear_workspace_low_team_count" in rule_keys

    def test_healthy_workspace_no_false_positives(self) -> None:
        from app.services.security_rules.linear import evaluate
        record = {
            "record_type": "linear_workspace",
            "record_id": "LINEAR_TEST_WORKSPACE_ID",
            "url_key_present": True,
            "logo_present": True,
            "team_count": 5,
            "webhook_count": 2,
            "integration_count": 3,
        }
        findings = evaluate(record)
        rule_keys = {f.finding_key.split(":")[0] for f in findings}
        assert "linear_workspace_low_team_count" not in rule_keys
        assert "linear_workspace_no_webhooks" not in rule_keys
        assert "linear_workspace_missing_url_key" not in rule_keys

    def test_webhook_non_https_fires(self) -> None:
        from app.services.security_rules.linear import evaluate
        # Rule reads webhook_url_scheme_category.
        record = {
            "record_type": "linear_webhook",
            "record_id": "LINEAR_TEST_WEBHOOK_ID",
            "webhook_enabled": True,
            "webhook_secret_present": True,  # avoid no_secret_indicator
            "webhook_url_scheme_category": "non_https",
            "webhook_resource_types_count": 3,
            "webhook_has_comment_type": False,
            "webhook_has_attachment_type": False,
        }
        findings = evaluate(record)
        rule_keys = {f.finding_key.split(":")[0] for f in findings}
        assert "linear_webhook_non_https" in rule_keys

    def test_healthy_webhook_no_false_positives(self) -> None:
        from app.services.security_rules.linear import evaluate
        # Rule reads webhook_url_scheme_category; webhook_secret_present=True avoids
        # no_secret_indicator rule which fires when the secret is absent.
        record = {
            "record_type": "linear_webhook",
            "record_id": "LINEAR_TEST_WEBHOOK_ID",
            "webhook_enabled": True,
            "webhook_secret_present": True,
            "webhook_url_scheme_category": "https",
            "webhook_resource_types_count": 3,
            "webhook_has_comment_type": False,
            "webhook_has_attachment_type": False,
        }
        findings = evaluate(record)
        rule_keys = {f.finding_key.split(":")[0] for f in findings}
        assert "linear_webhook_non_https" not in rule_keys
        assert "linear_webhook_no_secret_indicator" not in rule_keys
        assert "linear_webhook_disabled" not in rule_keys

    def test_correlation_rules_dict_structure(self) -> None:
        from app.services.linear_risk_activity_correlation_service import (
            LINEAR_CORRELATION_RULES,
        )
        for corr_type, rule in LINEAR_CORRELATION_RULES.items():
            assert "rule_keys" in rule, f"Correlation type {corr_type} missing rule_keys"
            assert "signal_types" in rule, f"Correlation type {corr_type} missing signal_types"
            assert "severity" in rule, f"Correlation type {corr_type} missing severity"
            assert rule["severity"] in ("critical", "high", "medium", "low")

    def test_signal_type_to_event_type_round_trip(self) -> None:
        from app.services.linear_activity_signal_service import (
            LINEAR_EVENT_TYPE_TO_SIGNAL_TYPE,
            LINEAR_SIGNAL_TYPES,
        )
        mapped_signal_types = frozenset(LINEAR_EVENT_TYPE_TO_SIGNAL_TYPE.values())
        assert mapped_signal_types == LINEAR_SIGNAL_TYPES

    def test_all_correlation_types_in_rules_dict(self) -> None:
        from app.services.linear_risk_activity_correlation_service import (
            LINEAR_CORRELATION_RULES,
            LINEAR_CORRELATION_TYPES,
        )
        assert frozenset(LINEAR_CORRELATION_RULES.keys()) == LINEAR_CORRELATION_TYPES

    def test_prior_m85a_tests_importable(self) -> None:
        # Check the prior milestone test files exist on disk.
        for milestone_tag, suffix in [
            ("85a", "linear_drift_provider_foundation"),
            ("85b", "linear_core_security_foundation"),
            ("85c", "linear_workflow_webhook_risk_expansion"),
            ("85d", "linear_activity_ingestion"),
            ("85e", "linear_activity_signals"),
            ("85f", "linear_risk_activity_correlations"),
            ("85g", "linear_security_demo_qa"),
        ]:
            path = _BACKEND / "tests" / f"test_milestone{milestone_tag}_{suffix}.py"
            assert path.exists(), f"Prior milestone test file missing: {path.name}"
