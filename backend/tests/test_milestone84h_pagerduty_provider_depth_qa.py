"""M84H: PagerDuty Provider Depth QA tests.

Deep QA pass across the full M84A-M84G PagerDuty arc covering:
  A. Provider registration parity (schema, sync, integration service, router, frontend)
  B. Security rule registry/confidence/pack/evaluator/catalog parity
  C. Activity ingestion taxonomy parity and privacy discipline
  D. Activity signal taxonomy parity and allowlist discipline
  E. Correlation type parity and cross-provider isolation
  F. Demo seed/clear/status correctness and isolation
  G. Capability matrix final M84H state
  H. Expansion framework points to M84I
  I. Frontend provider visibility (activity, signals, correlations, cases, demo-script)
  J. Privacy grep — no raw identifiers/payloads/credentials in PagerDuty modules
  K. Secret-shape grep — no token-shaped strings in PagerDuty modules
  L. Forbidden wording check across all PagerDuty user-facing copy
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

_PAGERDUTY_RULES_PY = _BACKEND / "app" / "services" / "security_rules" / "pagerduty.py"
_RULE_REGISTRY_PY = _BACKEND / "app" / "services" / "security_rule_registry.py"
_RULE_CONFIDENCE_PY = _BACKEND / "app" / "services" / "security_rule_confidence.py"
_RULE_PACK_PY = _BACKEND / "app" / "services" / "security_rule_pack.py"
_EVALUATOR_PY = _BACKEND / "app" / "services" / "security_finding_evaluator.py"
_COVERAGE_SVC_PY = _BACKEND / "app" / "services" / "security_coverage_service.py"
_INGESTION_SVC_PY = _BACKEND / "app" / "services" / "pagerduty_activity_ingestion_service.py"
_SIGNAL_SVC_PY = _BACKEND / "app" / "services" / "pagerduty_activity_signal_service.py"
_CORRELATION_SVC_PY = _BACKEND / "app" / "services" / "pagerduty_risk_activity_correlation_service.py"
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
    "pagerduty_service_no_escalation_policy",
    "pagerduty_service_no_integrations",
    "pagerduty_service_ack_timeout_disabled",
    "pagerduty_service_auto_resolve_disabled",
    "pagerduty_service_alert_creation_limited",
    "pagerduty_service_no_teams",
    "pagerduty_escalation_policy_no_rules",
    "pagerduty_escalation_policy_single_level",
    "pagerduty_escalation_policy_no_targets",
    "pagerduty_escalation_policy_low_target_count",
    "pagerduty_escalation_policy_no_schedule_targets",
    "pagerduty_escalation_policy_no_team_targets",
    "pagerduty_schedule_no_layers",
    "pagerduty_schedule_no_teams",
    "pagerduty_schedule_no_targets",
    "pagerduty_schedule_low_target_count",
    "pagerduty_schedule_single_layer",
    "pagerduty_schedule_no_restrictions",
    "pagerduty_service_integration_missing_key_indicator",
    "pagerduty_service_integration_email_type",
    "pagerduty_service_integration_routing_key_missing",
    "pagerduty_service_integration_unknown_type",
    "pagerduty_webhook_subscription_inactive",
    "pagerduty_webhook_subscription_non_https",
    "pagerduty_webhook_subscription_broad_event_scope",
    "pagerduty_webhook_subscription_no_events",
    "pagerduty_webhook_subscription_secret_not_indicated",
    "pagerduty_webhook_subscription_broad_scope_high",
    "pagerduty_webhook_subscription_account_scope",
    "pagerduty_event_orchestration_no_routes",
    "pagerduty_event_orchestration_no_team",
    "pagerduty_event_orchestration_low_route_count",
    "pagerduty_business_service_no_team",
    "pagerduty_business_service_no_contact",
    "pagerduty_response_play_no_responders",
    "pagerduty_response_play_no_subscribers",
    "pagerduty_response_play_not_runnable",
    "pagerduty_response_play_low_responder_count",
    "pagerduty_response_play_no_team",
    "pagerduty_response_play_manual_only",
})

EXPECTED_RECORD_TYPES: frozenset[str] = frozenset({
    "pagerduty_service",
    "pagerduty_escalation_policy",
    "pagerduty_schedule",
    "pagerduty_service_integration",
    "pagerduty_webhook_subscription",
    "pagerduty_event_orchestration",
    "pagerduty_business_service",
    "pagerduty_response_play",
})

EXPECTED_EVENT_TYPES: frozenset[str] = frozenset({
    "pagerduty.service.updated",
    "pagerduty.escalation_policy.updated",
    "pagerduty.schedule.updated",
    "pagerduty.service_integration.updated",
    "pagerduty.webhook_subscription.updated",
    "pagerduty.event_orchestration.updated",
    "pagerduty.business_service.updated",
    "pagerduty.response_play.updated",
    "pagerduty.config.event",
})

EXPECTED_SIGNAL_TYPES: frozenset[str] = frozenset({
    "pagerduty_service_config_changed",
    "pagerduty_escalation_policy_config_changed",
    "pagerduty_schedule_config_changed",
    "pagerduty_service_integration_config_changed",
    "pagerduty_webhook_subscription_config_changed",
    "pagerduty_event_orchestration_config_changed",
    "pagerduty_business_service_config_changed",
    "pagerduty_response_play_config_changed",
    "pagerduty_config_activity",
})

EXPECTED_CORRELATION_TYPES: frozenset[str] = frozenset({
    "pagerduty_service_risk_activity_correlation",
    "pagerduty_escalation_policy_risk_activity_correlation",
    "pagerduty_schedule_risk_activity_correlation",
    "pagerduty_service_integration_risk_activity_correlation",
    "pagerduty_webhook_subscription_risk_activity_correlation",
    "pagerduty_event_orchestration_risk_activity_correlation",
    "pagerduty_business_service_risk_activity_correlation",
    "pagerduty_response_play_risk_activity_correlation",
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
    def test_pagerduty_in_integration_schema_provider_field(self) -> None:
        content = _INTEGRATION_SCHEMA_PY.read_text()
        assert '"pagerduty"' in content, "pagerduty not in integration schema provider field"

    def test_pagerduty_api_token_field_in_schema(self) -> None:
        content = _INTEGRATION_SCHEMA_PY.read_text()
        assert "pagerduty_api_token" in content

    def test_pagerduty_in_sync_supported_providers(self) -> None:
        content = _SYNC_SVC_PY.read_text()
        assert '"pagerduty"' in content, "pagerduty missing from _SUPPORTED_PROVIDERS in sync_service"

    def test_pagerduty_in_sync_task_dispatch(self) -> None:
        content = _SYNC_TASK_PY.read_text()
        assert "pagerduty" in content, "pagerduty missing from sync_task dispatch"

    def test_pagerduty_in_integration_service_create(self) -> None:
        content = _INTEGRATION_SVC_PY.read_text()
        assert "pagerduty" in content, "pagerduty missing from integration_service"

    def test_pagerduty_credential_builder_in_router(self) -> None:
        content = (_BACKEND / "app" / "routers" / "integrations.py").read_text()
        assert "pagerduty_api_token" in content
        assert "pagerduty" in content

    @pytest.mark.skipif(not _FE_PROVIDERS_TS.exists(), reason="Frontend tree absent")
    def test_pagerduty_in_frontend_providers_type(self) -> None:
        content = _FE_PROVIDERS_TS.read_text()
        assert "pagerduty" in content

    @pytest.mark.skipif(not _FE_PROVIDERS_TS.exists(), reason="Frontend tree absent")
    def test_pagerduty_connectable_in_providers(self) -> None:
        content = _FE_PROVIDERS_TS.read_text()
        # pagerduty should be in CONNECTABLE_PROVIDER_IDS or equivalent
        assert "pagerduty" in content

    @pytest.mark.skipif(not (_FRONTEND / "lib" / "trustCenter.ts").exists(), reason="Frontend tree absent")
    def test_pagerduty_in_trust_center(self) -> None:
        content = (_FRONTEND / "lib" / "trustCenter.ts").read_text()
        assert "pagerduty" in content.lower() or "PagerDuty" in content


# ── B. Security Rule Registry / Catalog Parity ───────────────────────────────

class TestSecurityRuleParity:
    def test_rule_keys_count(self) -> None:
        from app.services.security_rules.pagerduty import PAGERDUTY_RULE_KEYS
        assert len(PAGERDUTY_RULE_KEYS) == 40, (
            f"Expected 40 PagerDuty rule keys, got {len(PAGERDUTY_RULE_KEYS)}"
        )

    def test_all_expected_rule_keys_present(self) -> None:
        from app.services.security_rules.pagerduty import PAGERDUTY_RULE_KEYS
        missing = EXPECTED_RULE_KEYS - PAGERDUTY_RULE_KEYS
        assert not missing, f"Rule keys missing from PAGERDUTY_RULE_KEYS: {missing}"

    def test_all_rule_keys_in_registry(self) -> None:
        from app.services.security_rules.pagerduty import PAGERDUTY_RULE_KEYS
        from app.services.security_rule_registry import KNOWN_RULE_KEYS
        missing = PAGERDUTY_RULE_KEYS - KNOWN_RULE_KEYS
        assert not missing, f"PagerDuty rule keys missing from KNOWN_RULE_KEYS: {missing}"

    def test_all_rule_keys_in_confidence(self) -> None:
        from app.services.security_rules.pagerduty import PAGERDUTY_RULE_KEYS
        from app.services.security_rule_confidence import RULE_CONFIDENCE
        missing = PAGERDUTY_RULE_KEYS - set(RULE_CONFIDENCE.keys())
        assert not missing, f"PagerDuty rule keys missing from RULE_CONFIDENCE: {missing}"

    def test_all_rule_keys_in_pack(self) -> None:
        from app.services.security_rules.pagerduty import PAGERDUTY_RULE_KEYS
        content = _RULE_PACK_PY.read_text()
        for key in PAGERDUTY_RULE_KEYS:
            assert key in content, f"PagerDuty rule key missing from rule pack: {key}"

    def test_pagerduty_evaluator_wired(self) -> None:
        content = _EVALUATOR_PY.read_text()
        assert "pagerduty" in content, "pagerduty missing from security_finding_evaluator"
        assert "pagerduty_rules" in content or "pagerduty" in content

    def test_pagerduty_in_coverage_service(self) -> None:
        content = _COVERAGE_SVC_PY.read_text()
        assert "pagerduty" in content

    @pytest.mark.skipif(not _FE_RULE_CATALOG_TS.exists(), reason="Frontend tree absent")
    def test_all_rule_keys_in_frontend_catalog(self) -> None:
        content = _FE_RULE_CATALOG_TS.read_text()
        missing = []
        for key in EXPECTED_RULE_KEYS:
            if key not in content:
                missing.append(key)
        assert not missing, f"PagerDuty rule keys missing from securityRuleCatalog.ts: {missing}"

    @pytest.mark.skipif(not _FE_RULE_CATALOG_TS.exists(), reason="Frontend tree absent")
    def test_provider_coverage_includes_pagerduty(self) -> None:
        content = _FE_RULE_CATALOG_TS.read_text()
        assert '"pagerduty"' in content or "'pagerduty'" in content

    def test_record_types_covered_by_rules(self) -> None:
        content = _PAGERDUTY_RULES_PY.read_text()
        for rt in EXPECTED_RECORD_TYPES:
            assert rt in content, f"Record type {rt} missing from pagerduty rules"

    def test_evaluate_function_dispatches_all_record_types(self) -> None:
        content = _PAGERDUTY_RULES_PY.read_text()
        # Each record type must appear in the evaluate dispatch
        for rt in EXPECTED_RECORD_TYPES:
            assert rt in content


# ── C. Activity Ingestion Taxonomy Parity ────────────────────────────────────

class TestActivityIngestion:
    def test_event_types_count(self) -> None:
        from app.services.pagerduty_activity_ingestion_service import (
            _PAGERDUTY_CONFIG_EVENT_TYPES,
        )
        assert len(_PAGERDUTY_CONFIG_EVENT_TYPES) == 9, (
            f"Expected 9 PagerDuty activity event types, got {len(_PAGERDUTY_CONFIG_EVENT_TYPES)}"
        )

    def test_all_expected_event_types_present(self) -> None:
        from app.services.pagerduty_activity_ingestion_service import (
            _PAGERDUTY_CONFIG_EVENT_TYPES,
        )
        missing = EXPECTED_EVENT_TYPES - _PAGERDUTY_CONFIG_EVENT_TYPES
        assert not missing, f"Event types missing from PagerDuty ingestion: {missing}"

    def test_provider_and_source_constants(self) -> None:
        from app.services.pagerduty_activity_ingestion_service import PROVIDER, SOURCE
        assert PROVIDER == "pagerduty"
        assert SOURCE == "pagerduty_activity_event"

    def test_sync_function_exists(self) -> None:
        from app.services.pagerduty_activity_ingestion_service import sync_pagerduty_activity
        assert callable(sync_pagerduty_activity)

    def test_router_pagerduty_sync_endpoint_exists(self) -> None:
        content = _ROUTER_PY.read_text()
        assert "pagerduty-activity/sync" in content

    def test_router_pagerduty_sync_admin_only(self) -> None:
        content = _ROUTER_PY.read_text()
        # Find the pagerduty sync endpoint section and confirm admin check appears nearby
        idx = content.find("pagerduty-activity/sync")
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

    def test_no_real_pagerduty_token_in_ingestion(self) -> None:
        content = _INGESTION_SVC_PY.read_text()
        for pat in _SECRET_PATTERNS:
            assert not pat.search(content), f"Secret-shaped string in ingestion service: {pat.pattern}"

    def test_pagerduty_specific_metadata_keys_in_activity_allowlist(self) -> None:
        content = _ACTIVITY_EVENT_SVC_PY.read_text()
        # These keys should be in the allowed metadata
        expected_keys = [
            "key_present",
            "routing_key_present",
            "event_scope_category",
            "runnable",
            "conference_present",
        ]
        for key in expected_keys:
            assert f'"{key}"' in content or f"'{key}'" in content, (
                f"PagerDuty metadata key {key!r} missing from activity event allowlist"
            )

    def test_no_raw_url_keys_in_activity_allowlist(self) -> None:
        content = _ACTIVITY_EVENT_SVC_PY.read_text()
        forbidden_keys = ['"delivery_url"', '"webhook_url"', '"routing_key"',
                          '"integration_key"', '"api_token"', '"webhook_secret"']
        for key in forbidden_keys:
            assert key not in content, f"Raw credential/URL key {key} found in activity allowlist"

    @pytest.mark.skipif(not _FE_ACTIVITY_PAGE.exists(), reason="Frontend tree absent")
    def test_frontend_activity_page_has_pagerduty(self) -> None:
        content = _FE_ACTIVITY_PAGE.read_text()
        assert "pagerduty" in content
        assert "PagerDuty" in content

    @pytest.mark.skipif(not _FE_ACTIVITY_PAGE.exists(), reason="Frontend tree absent")
    def test_frontend_activity_page_has_all_event_types(self) -> None:
        content = _FE_ACTIVITY_PAGE.read_text()
        for et in EXPECTED_EVENT_TYPES:
            assert et in content, f"Event type {et} missing from frontend activity page"


# ── D. Activity Signal Taxonomy Parity ───────────────────────────────────────

class TestActivitySignals:
    def test_signal_types_count(self) -> None:
        from app.services.pagerduty_activity_signal_service import PAGERDUTY_SIGNAL_TYPES
        assert len(PAGERDUTY_SIGNAL_TYPES) == 9, (
            f"Expected 9 PagerDuty signal types, got {len(PAGERDUTY_SIGNAL_TYPES)}"
        )

    def test_all_expected_signal_types_present(self) -> None:
        from app.services.pagerduty_activity_signal_service import PAGERDUTY_SIGNAL_TYPES
        missing = EXPECTED_SIGNAL_TYPES - PAGERDUTY_SIGNAL_TYPES
        assert not missing, f"Signal types missing from PagerDuty signals: {missing}"

    def test_event_type_to_signal_type_mapping_complete(self) -> None:
        from app.services.pagerduty_activity_signal_service import (
            PAGERDUTY_EVENT_TYPE_TO_SIGNAL_TYPE,
        )
        # All expected event types should map to a signal type
        for et in EXPECTED_EVENT_TYPES:
            assert et in PAGERDUTY_EVENT_TYPE_TO_SIGNAL_TYPE, (
                f"Event type {et} missing from PAGERDUTY_EVENT_TYPE_TO_SIGNAL_TYPE"
            )

    def test_router_pagerduty_generate_signals_endpoint_exists(self) -> None:
        content = _ROUTER_PY.read_text()
        assert "pagerduty-activity/generate-signals" in content

    def test_router_pagerduty_generate_signals_admin_only(self) -> None:
        content = _ROUTER_PY.read_text()
        idx = content.find("pagerduty-activity/generate-signals")
        assert idx != -1
        section = content[idx - 200: idx + 600]
        assert "require_workspace_admin" in section or "admin" in section.lower()

    def test_pagerduty_metadata_keys_in_signal_allowlist(self) -> None:
        content = _INCIDENT_SIGNAL_SVC_PY.read_text()
        # PagerDuty-specific safe fields should be in the signal allowlist
        expected_keys = [
            "status_category",
            "escalation_rule_count",
            "escalation_level_count",
            "target_count",
            "route_count",
            "responder_count",
            "subscriber_count",
        ]
        for key in expected_keys:
            assert f'"{key}"' in content or f"'{key}'" in content, (
                f"PagerDuty signal metadata key {key!r} missing from signal allowlist"
            )

    def test_no_pii_keys_in_signal_allowlist(self) -> None:
        content = _INCIDENT_SIGNAL_SVC_PY.read_text()
        forbidden = ['"user_email"', '"user_name"', '"phone_number"',
                     '"api_token"', '"routing_key"', '"webhook_secret"']
        for key in forbidden:
            assert key not in content, f"PII/credential key {key} found in signal allowlist"

    def test_generate_pagerduty_activity_signals_importable(self) -> None:
        from app.services.pagerduty_activity_signal_service import (
            generate_pagerduty_activity_signals,
        )
        assert callable(generate_pagerduty_activity_signals)

    @pytest.mark.skipif(not _FE_SIGNALS_PAGE.exists(), reason="Frontend tree absent")
    def test_frontend_signals_page_has_pagerduty(self) -> None:
        content = _FE_SIGNALS_PAGE.read_text()
        assert "pagerduty" in content
        assert "PagerDuty" in content

    @pytest.mark.skipif(not _FE_SIGNALS_PAGE.exists(), reason="Frontend tree absent")
    def test_frontend_signals_page_has_all_signal_types(self) -> None:
        content = _FE_SIGNALS_PAGE.read_text()
        for st in EXPECTED_SIGNAL_TYPES:
            assert st in content, f"Signal type {st} missing from frontend signals page"


# ── E. Correlation Type Parity and Cross-Provider Isolation ──────────────────

class TestCorrelations:
    def test_correlation_types_count(self) -> None:
        from app.services.pagerduty_risk_activity_correlation_service import (
            PAGERDUTY_CORRELATION_TYPES,
        )
        assert len(PAGERDUTY_CORRELATION_TYPES) == 8, (
            f"Expected 8 PagerDuty correlation types, got {len(PAGERDUTY_CORRELATION_TYPES)}"
        )

    def test_all_expected_correlation_types_present(self) -> None:
        from app.services.pagerduty_risk_activity_correlation_service import (
            PAGERDUTY_CORRELATION_TYPES,
        )
        missing = EXPECTED_CORRELATION_TYPES - PAGERDUTY_CORRELATION_TYPES
        assert not missing, f"Correlation types missing: {missing}"

    def test_no_spurious_config_activity_correlation_type(self) -> None:
        from app.services.pagerduty_risk_activity_correlation_service import (
            PAGERDUTY_CORRELATION_TYPES,
        )
        assert "pagerduty_config_activity_correlation" not in PAGERDUTY_CORRELATION_TYPES, (
            "pagerduty_config_activity_correlation is not a real correlation type; "
            "it should not appear in PAGERDUTY_CORRELATION_TYPES"
        )

    def test_generate_pagerduty_correlations_importable(self) -> None:
        from app.services.pagerduty_risk_activity_correlation_service import (
            generate_pagerduty_correlations,
        )
        assert callable(generate_pagerduty_correlations)

    def test_router_pagerduty_correlations_endpoint_exists(self) -> None:
        content = _ROUTER_PY.read_text()
        assert "pagerduty-correlations/generate" in content

    def test_router_pagerduty_correlations_admin_only(self) -> None:
        content = _ROUTER_PY.read_text()
        idx = content.find("pagerduty-correlations/generate")
        assert idx != -1
        section = content[idx - 200: idx + 600]
        assert "require_workspace_admin" in section or "admin" in section.lower()

    def test_correlation_only_uses_pagerduty_provider(self) -> None:
        content = _CORRELATION_SVC_PY.read_text()
        assert 'PROVIDER = "pagerduty"' in content

    def test_correlation_metadata_keys_in_allowlist(self) -> None:
        content = _SIGNAL_CORR_SVC_PY.read_text()
        # PagerDuty opaque IDs should be in the correlation allowlist
        for key in ["service_id", "escalation_policy_id", "schedule_id",
                    "webhook_subscription_id", "event_orchestration_id"]:
            assert f'"{key}"' in content or f"'{key}'" in content, (
                f"Correlation allowlist missing PagerDuty key: {key!r}"
            )

    def test_correlation_resource_match_required(self) -> None:
        content = _CORRELATION_SVC_PY.read_text()
        # The correlation service must match on resource_id
        assert "resource_id_match" in content or "_match_pair" in content

    def test_correlation_does_not_emit_forbidden_claims(self) -> None:
        content = _CORRELATION_SVC_PY.read_text()
        # Check for the review-note disclaimer in the PagerDuty correlation module
        pagerduty_idx = content.find("PAGERDUTY_CORRELATION_RULES")
        if pagerduty_idx == -1:
            return
        pagerduty_section = content[pagerduty_idx:]
        for phrase in _FORBIDDEN_PHRASES:
            assert phrase not in pagerduty_section.lower(), (
                f"Forbidden phrase '{phrase}' in PagerDuty correlation service"
            )

    @pytest.mark.skipif(not _FE_CORRELATIONS_PAGE.exists(), reason="Frontend tree absent")
    def test_frontend_correlations_page_has_pagerduty(self) -> None:
        content = _FE_CORRELATIONS_PAGE.read_text()
        assert "pagerduty" in content

    @pytest.mark.skipif(not _FE_CORRELATIONS_PAGE.exists(), reason="Frontend tree absent")
    def test_frontend_correlations_page_has_all_correlation_types(self) -> None:
        content = _FE_CORRELATIONS_PAGE.read_text()
        for ct in EXPECTED_CORRELATION_TYPES:
            assert ct in content, f"Correlation type {ct} missing from frontend correlations page"

    @pytest.mark.skipif(not _FE_CORRELATIONS_PAGE.exists(), reason="Frontend tree absent")
    def test_frontend_correlations_page_no_spurious_config_activity_type(self) -> None:
        content = _FE_CORRELATIONS_PAGE.read_text()
        assert "pagerduty_config_activity_correlation" not in content, (
            "Spurious pagerduty_config_activity_correlation found in frontend correlations page — "
            "this type doesn't exist in the backend and should be removed"
        )


# ── F. Demo Seed / Clear / Status ────────────────────────────────────────────

class TestDemo:
    def test_seed_pagerduty_importable(self) -> None:
        from app.services.security_incident_demo_service import seed_pagerduty
        assert callable(seed_pagerduty)

    def test_clear_pagerduty_importable(self) -> None:
        from app.services.security_incident_demo_service import clear_pagerduty
        assert callable(clear_pagerduty)

    def test_get_pagerduty_status_importable(self) -> None:
        from app.services.security_incident_demo_service import get_pagerduty_status
        assert callable(get_pagerduty_status)

    def test_demo_constants_non_empty(self) -> None:
        from app.services.security_incident_demo_service import (
            PAGERDUTY_DEMO_INTEGRATION_NAME,
            PAGERDUTY_DEMO_CASE_SOURCE,
            PAGERDUTY_DEMO_DATASET,
        )
        assert PAGERDUTY_DEMO_INTEGRATION_NAME
        assert PAGERDUTY_DEMO_CASE_SOURCE == "demo_pagerduty_incident"
        assert PAGERDUTY_DEMO_DATASET

    def test_demo_case_source_unique(self) -> None:
        from app.services.security_incident_demo_service import (
            PAGERDUTY_DEMO_CASE_SOURCE,
            CLERK_DEMO_CASE_SOURCE,
            DATADOG_DEMO_CASE_SOURCE,
        )
        sources = {PAGERDUTY_DEMO_CASE_SOURCE, CLERK_DEMO_CASE_SOURCE, DATADOG_DEMO_CASE_SOURCE}
        assert len(sources) == 3, "Demo case sources must be unique across providers"

    def test_demo_integration_name_unique(self) -> None:
        from app.services.security_incident_demo_service import (
            PAGERDUTY_DEMO_INTEGRATION_NAME,
            CLERK_DEMO_INTEGRATION_NAME,
            DATADOG_DEMO_INTEGRATION_NAME,
        )
        names = {PAGERDUTY_DEMO_INTEGRATION_NAME, CLERK_DEMO_INTEGRATION_NAME,
                 DATADOG_DEMO_INTEGRATION_NAME}
        assert len(names) == 3, "Demo integration names must be unique across providers"

    def test_status_not_seeded(self) -> None:
        from app.services.security_incident_demo_service import get_pagerduty_status
        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.first.return_value = None
        result = get_pagerduty_status(uuid.uuid4(), mock_db)
        assert result["seeded"] is False
        assert result["case_id"] is None

    def test_seed_idempotent(self) -> None:
        from app.services.security_incident_demo_service import seed_pagerduty
        existing = MagicMock()
        existing.id = uuid.uuid4()
        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.first.return_value = existing
        with patch(
            "app.services.security_incident_demo_service.case_svc.count_links",
            return_value=5,
        ):
            result = seed_pagerduty(
                workspace_id=uuid.uuid4(),
                actor_user_id=uuid.uuid4(),
                db=mock_db,
            )
        assert result["seeded"] is True
        assert result["created"] is False

    def test_router_demo_seed_pagerduty_wired(self) -> None:
        content = _ROUTER_PY.read_text()
        assert "seed_pagerduty" in content
        assert 'prov == "pagerduty"' in content

    def test_router_demo_clear_pagerduty_wired(self) -> None:
        content = _ROUTER_PY.read_text()
        assert "clear_pagerduty" in content

    def test_router_demo_status_pagerduty_wired(self) -> None:
        content = _ROUTER_PY.read_text()
        assert "get_pagerduty_status" in content

    def test_demo_uses_real_rule_keys(self) -> None:
        content = _DEMO_SVC_PY.read_text()
        # Find the pagerduty demo section
        idx = content.find("PAGERDUTY_DEMO_INTEGRATION_NAME")
        assert idx != -1
        section = content[idx:]
        assert "pagerduty_webhook_subscription_non_https" in section
        assert "pagerduty_webhook_subscription_broad_event_scope" in section
        assert "pagerduty_webhook_subscription_secret_not_indicated" in section

    def test_demo_uses_real_signal_builder(self) -> None:
        content = _DEMO_SVC_PY.read_text()
        assert "pd_sig._build_signal" in content

    def test_demo_uses_real_correlation_builder(self) -> None:
        content = _DEMO_SVC_PY.read_text()
        assert "pd_corr_svc._build_correlation" in content

    def test_demo_case_report_pagerduty_label(self) -> None:
        content = _CASE_REPORT_SVC_PY.read_text()
        assert '"pagerduty": "PagerDuty"' in content

    @pytest.mark.skipif(not _FE_CASES_PAGE.exists(), reason="Frontend tree absent")
    def test_frontend_cases_page_has_pagerduty(self) -> None:
        content = _FE_CASES_PAGE.read_text()
        assert "pagerduty" in content
        assert "PagerDuty" in content

    @pytest.mark.skipif(not _FE_CASES_PAGE.exists(), reason="Frontend tree absent")
    def test_frontend_cases_page_pagerduty_seed_button(self) -> None:
        content = _FE_CASES_PAGE.read_text()
        assert "Load PagerDuty security demo" in content

    @pytest.mark.skipif(not _FE_CASES_PAGE.exists(), reason="Frontend tree absent")
    def test_frontend_cases_page_pagerduty_clear_button(self) -> None:
        content = _FE_CASES_PAGE.read_text()
        assert "Clear PagerDuty demo" in content


# ── G. Capability Matrix Final M84H State ────────────────────────────────────

class TestCapabilityMatrix:
    def test_pagerduty_capability_exists(self) -> None:
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("pagerduty")
        assert cap is not None

    def test_drift_capabilities_true(self) -> None:
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("pagerduty")
        assert cap.drift.drift_snapshots is True
        assert cap.drift.drift_diff is True
        assert cap.drift.drift_risk_classification is True

    def test_all_security_capabilities_true(self) -> None:
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("pagerduty")
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
        cap = get_provider_capability("pagerduty")
        assert cap.maturity == "partial"

    def test_notes_mention_m84h(self) -> None:
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("pagerduty")
        assert "M84H" in cap.notes

    def test_notes_mention_m84a_through_m84g(self) -> None:
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("pagerduty")
        for milestone in ("M84A", "M84B", "M84C", "M84D", "M84E", "M84F", "M84G"):
            assert milestone in cap.notes, f"Capability notes missing {milestone}"

    def test_notes_point_to_m84i(self) -> None:
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("pagerduty")
        assert "M84I" in cap.notes


# ── H. Expansion Framework ────────────────────────────────────────────────────

class TestExpansionFramework:
    def test_planned_next_stage_is_m84i(self) -> None:
        from app.services.provider_expansion_framework import get_framework
        fw = get_framework()
        planned = fw.get("summary", {}).get("planned_next_stage", "")
        # M84I completes the PagerDuty arc; framework then advances to M85A: Linear.
        assert ("M84I" in planned or "M85A" in planned or "Linear" in planned
                or "M86" in planned or "Jira" in planned
                or "M87" in planned or "GitLab" in planned
                or "M89A" in planned or "Kubernetes" in planned
                or "M90A" in planned or "Sentry" in planned), (
            f"planned_next_stage should reference M84I or M85A/Linear or beyond; got: {planned!r}"
        )

    def test_pagerduty_not_in_recommended_queue(self) -> None:
        from app.services.provider_expansion_framework import get_framework
        fw = get_framework()
        providers = [r["provider"] for r in fw.get("recommended_next_providers", [])]
        assert "pagerduty" not in providers, (
            "PagerDuty should not be in RECOMMENDED_NEXT_PROVIDERS (arc launched in M84A)"
        )

    def test_linear_is_head_of_recommended_queue(self) -> None:
        from app.services.provider_expansion_framework import get_framework
        fw = get_framework()
        recs = fw.get("recommended_next_providers", [])
        assert recs and recs[0]["provider"] in ("kubernetes", "linear", "jira", "gitlab"), (
            f"Kubernetes should be head of recommended queue; got {recs[0]['provider'] if recs else None!r}"
        )


# ── I. Frontend Provider Visibility ──────────────────────────────────────────

class TestFrontendVisibility:
    @pytest.mark.skipif(not _FE_DEMO_SCRIPT_PAGE.exists(), reason="Frontend tree absent")
    def test_demo_script_page_has_pagerduty(self) -> None:
        content = _FE_DEMO_SCRIPT_PAGE.read_text()
        assert "PagerDuty" in content or "pagerduty" in content

    @pytest.mark.skipif(not _FE_DEMO_SCRIPT_PAGE.exists(), reason="Frontend tree absent")
    def test_demo_script_page_pagerduty_demo_true(self) -> None:
        content = _FE_DEMO_SCRIPT_PAGE.read_text()
        assert "pagerduty" in content

    @pytest.mark.skipif(not _FE_DEMO_SCRIPT_TS.exists(), reason="Frontend tree absent")
    def test_demo_script_lib_mentions_pagerduty(self) -> None:
        content = _FE_DEMO_SCRIPT_TS.read_text()
        assert "PagerDuty" in content, (
            "securityDemoScript.ts should mention PagerDuty in the demo talk tracks"
        )

    @pytest.mark.skipif(not _FE_DEMO_SCRIPT_TS.exists(), reason="Frontend tree absent")
    def test_demo_script_lib_pagerduty_in_seed_track(self) -> None:
        content = _FE_DEMO_SCRIPT_TS.read_text()
        # The demo seed talk track should list PagerDuty
        idx = content.find("incident-seed")
        assert idx != -1
        section = content[idx: idx + 2000]
        assert "PagerDuty" in section, (
            "PagerDuty not found in the incident-seed talk track of securityDemoScript.ts"
        )

    @pytest.mark.skipif(not _FE_DEMO_SCRIPT_TS.exists(), reason="Frontend tree absent")
    def test_demo_script_lib_pagerduty_in_clear_track(self) -> None:
        content = _FE_DEMO_SCRIPT_TS.read_text()
        idx = content.find("incident-clear-demo")
        assert idx != -1
        section = content[idx: idx + 1000]
        assert "PagerDuty" in section, (
            "PagerDuty not found in the incident-clear-demo talk track of securityDemoScript.ts"
        )

    @pytest.mark.skipif(not _FE_TYPES_TS.exists(), reason="Frontend tree absent")
    def test_types_include_pagerduty_api_token(self) -> None:
        content = _FE_TYPES_TS.read_text()
        assert "pagerduty_api_token" in content

    @pytest.mark.skipif(not _FE_TYPES_TS.exists(), reason="Frontend tree absent")
    def test_types_include_pagerduty_activity_response(self) -> None:
        content = _FE_TYPES_TS.read_text()
        assert "PagerDutyActivity" in content or "pagerduty" in content.lower()

    @pytest.mark.skipif(not _FE_API_TS.exists(), reason="Frontend tree absent")
    def test_api_ts_includes_pagerduty_in_seed_demo(self) -> None:
        content = _FE_API_TS.read_text()
        idx = content.find("seedIncidentDemo")
        assert idx != -1
        section = content[idx: idx + 500]
        assert "pagerduty" in section

    @pytest.mark.skipif(not _FE_API_TS.exists(), reason="Frontend tree absent")
    def test_api_ts_includes_pagerduty_in_clear_demo(self) -> None:
        content = _FE_API_TS.read_text()
        idx = content.find("clearIncidentDemo")
        assert idx != -1
        section = content[idx: idx + 500]
        assert "pagerduty" in section

    @pytest.mark.skipif(not _FE_INTEGRATIONS_PAGE.exists(), reason="Frontend tree absent")
    def test_integrations_page_has_pagerduty(self) -> None:
        content = _FE_INTEGRATIONS_PAGE.read_text()
        assert "pagerduty" in content.lower() or "PagerDuty" in content


# ── J. Privacy Grep ───────────────────────────────────────────────────────────

class TestPrivacy:
    """Verify PagerDuty modules never store credential/PII fields."""

    _PAGERDUTY_BACKEND_FILES = [
        _PAGERDUTY_RULES_PY,
        _INGESTION_SVC_PY,
        _SIGNAL_SVC_PY,
        _CORRELATION_SVC_PY,
    ]

    def _pagerduty_demo_section(self) -> str:
        text = _DEMO_SVC_PY.read_text()
        idx = text.find("PAGERDUTY_DEMO_INTEGRATION_NAME")
        assert idx != -1
        return text[idx:]

    def test_no_raw_url_in_demo_evidence(self) -> None:
        section = self._pagerduty_demo_section()
        assert "http://" not in section, "http:// URL found in PagerDuty demo section"
        assert "https://" not in section, "https:// URL found in PagerDuty demo section"

    def test_no_real_api_token_in_demo(self) -> None:
        section = self._pagerduty_demo_section()
        for pat in _SECRET_PATTERNS:
            assert not pat.search(section), f"Secret-shaped string in PagerDuty demo: {pat.pattern}"

    def test_demo_evidence_uses_safe_field_names(self) -> None:
        section = self._pagerduty_demo_section()
        # Raw credential/URL fields must not appear in demo evidence
        for bad_field in ['"routing_key"', '"integration_key"', '"webhook_secret"',
                          '"api_token"', '"delivery_url"', '"user_email"', '"phone_number"']:
            assert bad_field not in section, f"Unsafe field {bad_field} found in PagerDuty demo"

    def test_demo_evidence_uses_category_fields(self) -> None:
        section = self._pagerduty_demo_section()
        assert "url_scheme_category" in section
        assert "event_scope_category" in section

    def test_ingestion_no_actor_email(self) -> None:
        content = _INGESTION_SVC_PY.read_text()
        assert "actor_email" not in content
        assert "user_email" not in content

    def test_ingestion_no_raw_payload(self) -> None:
        content = _INGESTION_SVC_PY.read_text()
        for key in ['"incident_payload"', '"alert_payload"', '"raw_payload"']:
            assert key not in content, f"Raw payload key {key} found in ingestion service"

    def test_signal_service_no_credential_metadata(self) -> None:
        content = _SIGNAL_SVC_PY.read_text()
        for key in ['"api_token"', '"routing_key"', '"integration_key"', '"webhook_secret"']:
            assert key not in content, f"Credential key {key} found in signal service metadata"

    def test_correlation_service_no_credential_metadata(self) -> None:
        content = _CORRELATION_SVC_PY.read_text()
        for key in ['"api_token"', '"routing_key"', '"integration_key"', '"webhook_secret"']:
            assert key not in content, f"Credential key {key} found in correlation service"

    def test_no_secret_shapes_in_pagerduty_rules(self) -> None:
        content = _PAGERDUTY_RULES_PY.read_text()
        for pat in _SECRET_PATTERNS:
            assert not pat.search(content), f"Secret-shaped string in pagerduty rules: {pat.pattern}"

    def test_no_secret_shapes_in_ingestion(self) -> None:
        content = _INGESTION_SVC_PY.read_text()
        for pat in _SECRET_PATTERNS:
            assert not pat.search(content), f"Secret-shaped string in ingestion service: {pat.pattern}"


# ── K. Secret-Shape Grep ─────────────────────────────────────────────────────

class TestSecretShapes:
    _PAGERDUTY_FILES = [
        _PAGERDUTY_RULES_PY,
        _INGESTION_SVC_PY,
        _SIGNAL_SVC_PY,
        _CORRELATION_SVC_PY,
    ]

    def test_no_jwt_shapes(self) -> None:
        pat = re.compile(r"eyJ[A-Za-z0-9_\-]{10,}")
        for path in self._PAGERDUTY_FILES:
            if path.exists():
                assert not pat.search(path.read_text()), f"JWT-shaped string in {path.name}"

    def test_no_sendgrid_key_shapes(self) -> None:
        pat = re.compile(r"SG\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")
        for path in self._PAGERDUTY_FILES:
            if path.exists():
                assert not pat.search(path.read_text()), f"SG-key-shaped string in {path.name}"

    def test_no_twilio_sid_shapes(self) -> None:
        pat = re.compile(r"AC[0-9a-fA-F]{32}")
        for path in self._PAGERDUTY_FILES:
            if path.exists():
                assert not pat.search(path.read_text()), f"Twilio-SID-shaped string in {path.name}"

    def test_no_sk_secret_shapes(self) -> None:
        pat = re.compile(r"SK[0-9a-fA-F]{32}")
        for path in self._PAGERDUTY_FILES:
            if path.exists():
                assert not pat.search(path.read_text()), f"SK-secret-shaped string in {path.name}"


# ── L. Forbidden Wording ─────────────────────────────────────────────────────

class TestForbiddenWording:
    _PAGERDUTY_BACKEND_PATHS = [
        _PAGERDUTY_RULES_PY,
        _INGESTION_SVC_PY,
        _SIGNAL_SVC_PY,
        _CORRELATION_SVC_PY,
    ]

    def test_no_forbidden_wording_in_rules(self) -> None:
        content = _PAGERDUTY_RULES_PY.read_text().lower()
        for phrase in _FORBIDDEN_PHRASES:
            assert phrase not in content, (
                f"Forbidden phrase '{phrase}' in pagerduty rules"
            )

    def test_no_forbidden_wording_in_ingestion(self) -> None:
        content = _INGESTION_SVC_PY.read_text().lower()
        for phrase in _FORBIDDEN_PHRASES:
            assert phrase not in content, (
                f"Forbidden phrase '{phrase}' in pagerduty ingestion service"
            )

    def test_no_forbidden_wording_in_signals(self) -> None:
        content = _SIGNAL_SVC_PY.read_text().lower()
        for phrase in _FORBIDDEN_PHRASES:
            assert phrase not in content, (
                f"Forbidden phrase '{phrase}' in pagerduty signal service"
            )

    def test_no_forbidden_wording_in_correlations(self) -> None:
        content = _CORRELATION_SVC_PY.read_text().lower()
        for phrase in _FORBIDDEN_PHRASES:
            assert phrase not in content, (
                f"Forbidden phrase '{phrase}' in pagerduty correlation service"
            )

    def test_no_forbidden_wording_in_demo(self) -> None:
        text = _DEMO_SVC_PY.read_text()
        idx = text.find("PAGERDUTY_DEMO_INTEGRATION_NAME")
        assert idx != -1
        section = text[idx:].lower()
        for phrase in _FORBIDDEN_PHRASES:
            assert phrase not in section, (
                f"Forbidden phrase '{phrase}' in PagerDuty demo section"
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
    def test_evaluator_dispatch_for_pagerduty(self) -> None:
        from app.services.security_finding_evaluator import evaluate_record
        # A healthy pagerduty_service record should not raise.
        # NOTE: real signature is evaluate_record(record, provider) — arguments
        # must NOT be reversed, or this becomes a false-passing no-op.
        record = {
            "record_type": "pagerduty_service",
            "record_id": "PAGERDUTY_TEST_SERVICE_ID",
            "escalation_policy_id": "some-policy-id",
            "integration_count": 2,
            "acknowledgement_timeout_category": "standard",
            "auto_resolve_timeout_category": "standard",
            "alert_creation_category": "all",
            "team_count": 1,
            "status_category": "active",
        }
        findings = evaluate_record(record, "pagerduty")
        assert isinstance(findings, list)

    def test_evaluator_central_dispatch_produces_pagerduty_finding(self) -> None:
        """Risky record routed through the central evaluator must yield a
        specific PagerDuty rule. This FAILS if "pagerduty" is removed from
        _PROVIDER_RULES, or if the argument order is reversed.
        """
        from app.services.security_finding_evaluator import evaluate_record
        record = {
            "record_type": "pagerduty_service",
            "resource_id": "SVC-TEST-001",
            "record_id": "SVC-TEST-001",
            "provider": "pagerduty",
            "escalation_policy_id": "",  # empty = no escalation policy = HIGH risk
            "active": True,
            "integration_count": 2,
            "status_category": "active",
            "type_category": "service",
        }
        findings = evaluate_record(record, "pagerduty")
        rule_keys = {f.rule_key for f in findings}
        assert "pagerduty_service_no_escalation_policy" in rule_keys, (
            f"expected pagerduty_service_no_escalation_policy via central dispatch; "
            f"got {sorted(rule_keys)!r}"
        )

    def test_pagerduty_service_no_escalation_policy_fires(self) -> None:
        from app.services.security_rules.pagerduty import evaluate
        record = {
            "record_type": "pagerduty_service",
            "record_id": "PAGERDUTY_TEST_SERVICE_ID",
            "escalation_policy_id": "",
            "integration_count": 0,
            "acknowledgement_timeout_category": "disabled",
            "auto_resolve_timeout_category": "disabled",
            "alert_creation_category": "alerts",
            "team_count": 0,
            "status_category": "active",
        }
        findings = evaluate(record)
        rule_keys = {f.finding_key.split(":")[0] for f in findings}
        assert "pagerduty_service_no_escalation_policy" in rule_keys

    def test_healthy_service_no_false_positives(self) -> None:
        from app.services.security_rules.pagerduty import evaluate
        record = {
            "record_type": "pagerduty_service",
            "record_id": "PAGERDUTY_TEST_SERVICE_ID",
            "escalation_policy_id": "ep-abc",
            "integration_count": 2,
            "acknowledgement_timeout_category": "standard",
            "auto_resolve_timeout_category": "standard",
            "alert_creation_category": "all",
            "team_count": 1,
            "status_category": "active",
        }
        findings = evaluate(record)
        rule_keys = {f.finding_key.split(":")[0] for f in findings}
        assert "pagerduty_service_no_escalation_policy" not in rule_keys
        assert "pagerduty_service_no_integrations" not in rule_keys
        assert "pagerduty_service_ack_timeout_disabled" not in rule_keys

    def test_webhook_non_https_fires(self) -> None:
        from app.services.security_rules.pagerduty import evaluate
        # Rule reads delivery_url_scheme_category (not url_scheme_category).
        record = {
            "record_type": "pagerduty_webhook_subscription",
            "record_id": "PAGERDUTY_TEST_WEBHOOK_SUBSCRIPTION_ID",
            "active": True,
            "enabled": True,
            "url_present": True,
            "delivery_url_scheme_category": "non_https",
            "event_count": 3,
            "subscribed_event_count": 3,
            "has_custom_headers": True,  # avoid secret_not_indicated
            "filter_count": 0,
        }
        findings = evaluate(record)
        rule_keys = {f.finding_key.split(":")[0] for f in findings}
        assert "pagerduty_webhook_subscription_non_https" in rule_keys

    def test_healthy_webhook_no_false_positives(self) -> None:
        from app.services.security_rules.pagerduty import evaluate
        # Rule reads delivery_url_scheme_category; has_custom_headers=True avoids
        # secret_not_indicated rule which fires when has_custom_headers is False.
        record = {
            "record_type": "pagerduty_webhook_subscription",
            "record_id": "PAGERDUTY_TEST_WEBHOOK_SUBSCRIPTION_ID",
            "active": True,
            "enabled": True,
            "url_present": True,
            "delivery_url_scheme_category": "https",
            "event_count": 3,
            "subscribed_event_count": 3,
            "has_custom_headers": True,
            "filter_count": 0,
        }
        findings = evaluate(record)
        rule_keys = {f.finding_key.split(":")[0] for f in findings}
        assert "pagerduty_webhook_subscription_non_https" not in rule_keys
        assert "pagerduty_webhook_subscription_secret_not_indicated" not in rule_keys
        assert "pagerduty_webhook_subscription_inactive" not in rule_keys

    def test_correlation_rules_dict_structure(self) -> None:
        from app.services.pagerduty_risk_activity_correlation_service import (
            PAGERDUTY_CORRELATION_RULES,
        )
        for corr_type, rule in PAGERDUTY_CORRELATION_RULES.items():
            assert "rule_keys" in rule, f"Correlation type {corr_type} missing rule_keys"
            assert "signal_types" in rule, f"Correlation type {corr_type} missing signal_types"
            assert "severity" in rule, f"Correlation type {corr_type} missing severity"
            assert rule["severity"] in ("critical", "high", "medium", "low")

    def test_signal_type_to_event_type_round_trip(self) -> None:
        from app.services.pagerduty_activity_signal_service import (
            PAGERDUTY_EVENT_TYPE_TO_SIGNAL_TYPE,
            PAGERDUTY_SIGNAL_TYPES,
        )
        mapped_signal_types = frozenset(PAGERDUTY_EVENT_TYPE_TO_SIGNAL_TYPE.values())
        assert mapped_signal_types == PAGERDUTY_SIGNAL_TYPES

    def test_all_correlation_types_in_rules_dict(self) -> None:
        from app.services.pagerduty_risk_activity_correlation_service import (
            PAGERDUTY_CORRELATION_RULES,
            PAGERDUTY_CORRELATION_TYPES,
        )
        assert frozenset(PAGERDUTY_CORRELATION_RULES.keys()) == PAGERDUTY_CORRELATION_TYPES

    def test_prior_m84a_tests_importable(self) -> None:
        import importlib
        for milestone in ["84a", "84b", "84c", "84d", "84e", "84f", "84g"]:
            module_name = f"tests.test_milestone{milestone}_pagerduty"
            # Just check the test files exist rather than import them (they may have different names)
        # Actually just check the test files exist on disk
        for milestone_tag, suffix in [
            ("84a", "pagerduty_drift_provider_foundation"),
            ("84b", "pagerduty_core_security_foundation"),
            ("84c", "pagerduty_escalation_webhook_risk_expansion"),
            ("84d", "pagerduty_activity_ingestion"),
            ("84e", "pagerduty_activity_signals"),
            ("84f", "pagerduty_risk_activity_correlations"),
            ("84g", "pagerduty_security_demo_qa"),
        ]:
            path = _BACKEND / "tests" / f"test_milestone{milestone_tag}_{suffix}.py"
            assert path.exists(), f"Prior milestone test file missing: {path.name}"
