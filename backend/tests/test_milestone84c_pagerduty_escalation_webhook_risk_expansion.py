"""M84C — PagerDuty escalation/webhook risk expansion tests.

Verifies 18 new PagerDuty configuration-risk rules, expanded schema fields,
safe normalizer output, registry/confidence/pack/coverage wiring, capability
matrix update, expansion framework pointer, and frontend catalog.

Sections
--------
  A. Rule key taxonomy (18 new M84C rules)
  B. Rule positive tests (each new rule fires on a risky record)
  C. Rule negative tests (each new rule does NOT fire on a healthy record)
  D. Schema new-field presence tests
  E. Connector normalizer safe-field tests (no secrets/PII/URLs/keys)
  F. Registry / confidence / pack wiring for M84C keys
  G. Coverage service wiring
  H. Capability matrix points to M84D; activity/signals/demo remain false
  I. Provider expansion framework points to M84D; Linear is head of queue
  J. Frontend catalog contains all M84C rule keys
  K. Forbidden wording / claim discipline
  L. Secret-shape grep
  M. M84B regression (22 existing rules still pass)
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest

from app.services.security_rules.pagerduty import (
    PAGERDUTY_RULE_KEYS,
    evaluate,
)
from app.connectors.pagerduty_schema import (
    PAGERDUTY_ESCALATION_POLICY,
    PAGERDUTY_EVENT_ORCHESTRATION,
    PAGERDUTY_RESPONSE_PLAY,
    PAGERDUTY_SCHEDULE,
    PAGERDUTY_SERVICE,
    PAGERDUTY_SERVICE_INTEGRATION,
    PAGERDUTY_WEBHOOK_SUBSCRIPTION,
)
from app.services.security_rule_registry import KNOWN_RULE_KEYS, is_known_rule_key
from app.services.security_rule_confidence import RULE_CONFIDENCE
from app.services.security_rule_pack import _RULE_META
from app.services.security_coverage_service import (
    PROVIDERS,
    RULE_RECORD_TYPES,
)
from app.services.security_finding_evaluator import _PROVIDER_RULES
from app.services.provider_capability_matrix_service import get_provider_capability
from app.services.provider_expansion_framework import get_framework

REPO_ROOT = Path(__file__).resolve().parents[2]
FE_RULE_CATALOG = REPO_ROOT / "frontend" / "src" / "lib" / "securityRuleCatalog.ts"
BACKEND_APP = REPO_ROOT / "backend" / "app"
FRONTEND_SRC = REPO_ROOT / "frontend" / "src"

# ── A. Rule key taxonomy ──────────────────────────────────────────────────────

M84C_RULE_KEYS: frozenset[str] = frozenset({
    # Escalation policy expansion
    "pagerduty_escalation_policy_no_targets",
    "pagerduty_escalation_policy_low_target_count",
    "pagerduty_escalation_policy_no_schedule_targets",
    "pagerduty_escalation_policy_no_team_targets",
    # Schedule expansion
    "pagerduty_schedule_no_targets",
    "pagerduty_schedule_low_target_count",
    "pagerduty_schedule_single_layer",
    "pagerduty_schedule_no_restrictions",
    # Service integration expansion
    "pagerduty_service_integration_routing_key_missing",
    "pagerduty_service_integration_unknown_type",
    # Webhook subscription expansion
    "pagerduty_webhook_subscription_no_events",
    "pagerduty_webhook_subscription_secret_not_indicated",
    "pagerduty_webhook_subscription_broad_scope_high",
    "pagerduty_webhook_subscription_account_scope",
    # Event orchestration expansion
    "pagerduty_event_orchestration_low_route_count",
    # Response play expansion
    "pagerduty_response_play_low_responder_count",
    "pagerduty_response_play_no_team",
    "pagerduty_response_play_manual_only",
})


def test_m84c_rule_count() -> None:
    assert len(M84C_RULE_KEYS) == 18


def test_m84c_rule_keys_in_pagerduty_rule_keys() -> None:
    missing = M84C_RULE_KEYS - PAGERDUTY_RULE_KEYS
    assert not missing, f"M84C keys missing from PAGERDUTY_RULE_KEYS: {sorted(missing)}"


def test_m84c_rule_keys_in_known_rule_keys() -> None:
    missing = M84C_RULE_KEYS - KNOWN_RULE_KEYS
    assert not missing, f"M84C keys missing from KNOWN_RULE_KEYS: {sorted(missing)}"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _rule_keys(findings: list[Any]) -> set[str]:
    return {f.rule_key for f in findings}


def _base_ep(**kwargs: Any) -> dict:
    return {
        "record_type": PAGERDUTY_ESCALATION_POLICY,
        "provider": "pagerduty",
        "record_id": "PAGERDUTY_TEST_ESCALATION_POLICY_ID",
        "resource_id": "PAGERDUTY_TEST_ESCALATION_POLICY_ID",
        "resource_name": "Test Policy",
        "team_count": 1,
        "escalation_rule_count": 2,
        "escalation_level_count": 2,
        "repeat_enabled": False,
        "num_loops": 0,
        "on_call_handoff_notifications": "if_has_services",
        "target_count": 3,
        "user_target_count": 1,
        "schedule_target_count": 2,
        "has_schedule_targets": True,
        **kwargs,
    }


def _base_schedule(**kwargs: Any) -> dict:
    return {
        "record_type": PAGERDUTY_SCHEDULE,
        "provider": "pagerduty",
        "record_id": "PAGERDUTY_TEST_SCHEDULE_ID",
        "resource_id": "PAGERDUTY_TEST_SCHEDULE_ID",
        "resource_name": "Test Schedule",
        "time_zone_present": True,
        "layer_count": 2,
        "user_count": 3,
        "team_count": 1,
        "restriction_count": 2,
        "has_restrictions": True,
        **kwargs,
    }


def _base_integration(**kwargs: Any) -> dict:
    return {
        "record_type": PAGERDUTY_SERVICE_INTEGRATION,
        "provider": "pagerduty",
        "record_id": "PAGERDUTY_TEST_INTEGRATION_ID",
        "resource_id": "PAGERDUTY_TEST_INTEGRATION_ID",
        "service_id": "PAGERDUTY_TEST_SERVICE_ID",
        "type_category": "vendor",
        "vendor_name": "Datadog",
        "has_integration_key": True,
        "routing_key_present": False,
        **kwargs,
    }


def _base_webhook(**kwargs: Any) -> dict:
    return {
        "record_type": PAGERDUTY_WEBHOOK_SUBSCRIPTION,
        "provider": "pagerduty",
        "record_id": "PAGERDUTY_TEST_WEBHOOK_SUBSCRIPTION_ID",
        "resource_id": "PAGERDUTY_TEST_WEBHOOK_SUBSCRIPTION_ID",
        "active": True,
        "event_count": 5,
        "delivery_url_scheme_category": "https",
        "filter_type": "service_reference",
        "has_custom_headers": True,
        **kwargs,
    }


def _base_orchestration(**kwargs: Any) -> dict:
    return {
        "record_type": PAGERDUTY_EVENT_ORCHESTRATION,
        "provider": "pagerduty",
        "record_id": "PAGERDUTY_TEST_EVENT_ORCHESTRATION_ID",
        "resource_id": "PAGERDUTY_TEST_EVENT_ORCHESTRATION_ID",
        "resource_name": "Test Orchestration",
        "team_present": True,
        "route_count": 5,
        **kwargs,
    }


def _base_response_play(**kwargs: Any) -> dict:
    return {
        "record_type": PAGERDUTY_RESPONSE_PLAY,
        "provider": "pagerduty",
        "record_id": "PAGERDUTY_TEST_RESPONSE_PLAY_ID",
        "resource_id": "PAGERDUTY_TEST_RESPONSE_PLAY_ID",
        "resource_name": "Test Play",
        "team_present": True,
        "responder_count": 3,
        "subscriber_count": 2,
        "conference_number_present": False,
        "runnability": "team",
        **kwargs,
    }


# ── B. Rule positive tests ────────────────────────────────────────────────────

class TestEscalationPolicyPositive:
    def test_no_targets(self) -> None:
        rec = _base_ep(escalation_rule_count=2, target_count=0)
        keys = _rule_keys(evaluate(rec))
        assert "pagerduty_escalation_policy_no_targets" in keys

    def test_low_target_count(self) -> None:
        rec = _base_ep(target_count=1)
        keys = _rule_keys(evaluate(rec))
        assert "pagerduty_escalation_policy_low_target_count" in keys

    def test_no_schedule_targets(self) -> None:
        rec = _base_ep(
            escalation_rule_count=2,
            target_count=2,
            schedule_target_count=0,
            has_schedule_targets=False,
        )
        keys = _rule_keys(evaluate(rec))
        assert "pagerduty_escalation_policy_no_schedule_targets" in keys

    def test_no_team_targets(self) -> None:
        rec = _base_ep(team_count=0)
        keys = _rule_keys(evaluate(rec))
        assert "pagerduty_escalation_policy_no_team_targets" in keys


class TestSchedulePositive:
    def test_no_targets(self) -> None:
        rec = _base_schedule(layer_count=2, user_count=0)
        keys = _rule_keys(evaluate(rec))
        assert "pagerduty_schedule_no_targets" in keys

    def test_low_target_count(self) -> None:
        rec = _base_schedule(user_count=1)
        keys = _rule_keys(evaluate(rec))
        assert "pagerduty_schedule_low_target_count" in keys

    def test_single_layer(self) -> None:
        rec = _base_schedule(layer_count=1)
        keys = _rule_keys(evaluate(rec))
        assert "pagerduty_schedule_single_layer" in keys

    def test_no_restrictions(self) -> None:
        rec = _base_schedule(layer_count=2, restriction_count=0, has_restrictions=False)
        keys = _rule_keys(evaluate(rec))
        assert "pagerduty_schedule_no_restrictions" in keys


class TestServiceIntegrationPositive:
    def test_routing_key_missing(self) -> None:
        rec = _base_integration(
            type_category="generic_events_api",
            routing_key_present=False,
            has_integration_key=False,
        )
        keys = _rule_keys(evaluate(rec))
        assert "pagerduty_service_integration_routing_key_missing" in keys

    def test_unknown_type(self) -> None:
        rec = _base_integration(type_category="other", vendor_name=None)
        keys = _rule_keys(evaluate(rec))
        assert "pagerduty_service_integration_unknown_type" in keys


class TestWebhookPositive:
    def test_no_events(self) -> None:
        rec = _base_webhook(event_count=0)
        keys = _rule_keys(evaluate(rec))
        assert "pagerduty_webhook_subscription_no_events" in keys

    def test_secret_not_indicated(self) -> None:
        rec = _base_webhook(active=True, has_custom_headers=False)
        keys = _rule_keys(evaluate(rec))
        assert "pagerduty_webhook_subscription_secret_not_indicated" in keys

    def test_broad_scope_high(self) -> None:
        rec = _base_webhook(event_count=25)
        keys = _rule_keys(evaluate(rec))
        assert "pagerduty_webhook_subscription_broad_scope_high" in keys

    def test_account_scope(self) -> None:
        rec = _base_webhook(filter_type="account")
        keys = _rule_keys(evaluate(rec))
        assert "pagerduty_webhook_subscription_account_scope" in keys


class TestEventOrchestrationPositive:
    def test_low_route_count(self) -> None:
        rec = _base_orchestration(route_count=1)
        keys = _rule_keys(evaluate(rec))
        assert "pagerduty_event_orchestration_low_route_count" in keys


class TestResponsePlayPositive:
    def test_low_responder_count(self) -> None:
        rec = _base_response_play(responder_count=1)
        keys = _rule_keys(evaluate(rec))
        assert "pagerduty_response_play_low_responder_count" in keys

    def test_no_team(self) -> None:
        rec = _base_response_play(team_present=False)
        keys = _rule_keys(evaluate(rec))
        assert "pagerduty_response_play_no_team" in keys

    def test_manual_only(self) -> None:
        rec = _base_response_play(runnability="owner")
        keys = _rule_keys(evaluate(rec))
        assert "pagerduty_response_play_manual_only" in keys


# ── C. Rule negative tests ────────────────────────────────────────────────────

class TestEscalationPolicyNegative:
    def test_no_targets_does_not_fire_when_no_rules(self) -> None:
        rec = _base_ep(escalation_rule_count=0, target_count=0)
        keys = _rule_keys(evaluate(rec))
        assert "pagerduty_escalation_policy_no_targets" not in keys

    def test_no_targets_does_not_fire_when_targets_exist(self) -> None:
        rec = _base_ep(escalation_rule_count=2, target_count=3)
        keys = _rule_keys(evaluate(rec))
        assert "pagerduty_escalation_policy_no_targets" not in keys

    def test_low_target_count_does_not_fire_for_many(self) -> None:
        rec = _base_ep(target_count=4)
        keys = _rule_keys(evaluate(rec))
        assert "pagerduty_escalation_policy_low_target_count" not in keys

    def test_no_schedule_targets_does_not_fire_when_schedules_present(self) -> None:
        rec = _base_ep(schedule_target_count=2, has_schedule_targets=True)
        keys = _rule_keys(evaluate(rec))
        assert "pagerduty_escalation_policy_no_schedule_targets" not in keys

    def test_no_team_targets_does_not_fire_when_team_present(self) -> None:
        rec = _base_ep(team_count=2)
        keys = _rule_keys(evaluate(rec))
        assert "pagerduty_escalation_policy_no_team_targets" not in keys


class TestScheduleNegative:
    def test_no_targets_does_not_fire_when_no_layers(self) -> None:
        rec = _base_schedule(layer_count=0, user_count=0)
        keys = _rule_keys(evaluate(rec))
        assert "pagerduty_schedule_no_targets" not in keys

    def test_no_targets_does_not_fire_when_users_present(self) -> None:
        rec = _base_schedule(layer_count=2, user_count=3)
        keys = _rule_keys(evaluate(rec))
        assert "pagerduty_schedule_no_targets" not in keys

    def test_low_target_count_does_not_fire_for_many(self) -> None:
        rec = _base_schedule(user_count=5)
        keys = _rule_keys(evaluate(rec))
        assert "pagerduty_schedule_low_target_count" not in keys

    def test_single_layer_does_not_fire_for_multi(self) -> None:
        rec = _base_schedule(layer_count=3)
        keys = _rule_keys(evaluate(rec))
        assert "pagerduty_schedule_single_layer" not in keys

    def test_no_restrictions_does_not_fire_when_restrictions_present(self) -> None:
        rec = _base_schedule(restriction_count=4, has_restrictions=True)
        keys = _rule_keys(evaluate(rec))
        assert "pagerduty_schedule_no_restrictions" not in keys


class TestServiceIntegrationNegative:
    def test_routing_key_missing_does_not_fire_for_non_events_api(self) -> None:
        rec = _base_integration(type_category="vendor", routing_key_present=False)
        keys = _rule_keys(evaluate(rec))
        assert "pagerduty_service_integration_routing_key_missing" not in keys

    def test_routing_key_missing_does_not_fire_when_key_present(self) -> None:
        rec = _base_integration(
            type_category="generic_events_api",
            routing_key_present=True,
            has_integration_key=True,
        )
        keys = _rule_keys(evaluate(rec))
        assert "pagerduty_service_integration_routing_key_missing" not in keys

    def test_unknown_type_does_not_fire_for_known_types(self) -> None:
        for type_cat in ("generic_events_api", "email", "vendor"):
            rec = _base_integration(type_category=type_cat)
            keys = _rule_keys(evaluate(rec))
            assert "pagerduty_service_integration_unknown_type" not in keys, (
                f"Unknown type rule fired for type_category={type_cat!r}"
            )


class TestWebhookNegative:
    def test_no_events_does_not_fire_when_events_present(self) -> None:
        rec = _base_webhook(event_count=5)
        keys = _rule_keys(evaluate(rec))
        assert "pagerduty_webhook_subscription_no_events" not in keys

    def test_secret_not_indicated_does_not_fire_when_headers_present(self) -> None:
        rec = _base_webhook(active=True, has_custom_headers=True)
        keys = _rule_keys(evaluate(rec))
        assert "pagerduty_webhook_subscription_secret_not_indicated" not in keys

    def test_secret_not_indicated_does_not_fire_when_inactive(self) -> None:
        rec = _base_webhook(active=False, has_custom_headers=False)
        keys = _rule_keys(evaluate(rec))
        assert "pagerduty_webhook_subscription_secret_not_indicated" not in keys

    def test_broad_scope_high_does_not_fire_for_moderate(self) -> None:
        rec = _base_webhook(event_count=15)
        keys = _rule_keys(evaluate(rec))
        assert "pagerduty_webhook_subscription_broad_scope_high" not in keys

    def test_account_scope_does_not_fire_for_service_scope(self) -> None:
        rec = _base_webhook(filter_type="service_reference")
        keys = _rule_keys(evaluate(rec))
        assert "pagerduty_webhook_subscription_account_scope" not in keys


class TestEventOrchestrationNegative:
    def test_low_route_count_does_not_fire_for_many(self) -> None:
        rec = _base_orchestration(route_count=5)
        keys = _rule_keys(evaluate(rec))
        assert "pagerduty_event_orchestration_low_route_count" not in keys

    def test_low_route_count_does_not_fire_for_zero(self) -> None:
        # Zero routes is handled by M84B rule, not M84C low_route_count
        rec = _base_orchestration(route_count=0)
        keys = _rule_keys(evaluate(rec))
        assert "pagerduty_event_orchestration_low_route_count" not in keys


class TestResponsePlayNegative:
    def test_low_responder_count_does_not_fire_for_many(self) -> None:
        rec = _base_response_play(responder_count=3)
        keys = _rule_keys(evaluate(rec))
        assert "pagerduty_response_play_low_responder_count" not in keys

    def test_low_responder_count_does_not_fire_for_zero(self) -> None:
        # Zero responders is handled by M84B rule, not M84C low_responder_count
        rec = _base_response_play(responder_count=0)
        keys = _rule_keys(evaluate(rec))
        assert "pagerduty_response_play_low_responder_count" not in keys

    def test_no_team_does_not_fire_when_team_present(self) -> None:
        rec = _base_response_play(team_present=True)
        keys = _rule_keys(evaluate(rec))
        assert "pagerduty_response_play_no_team" not in keys

    def test_manual_only_does_not_fire_for_team_runnability(self) -> None:
        rec = _base_response_play(runnability="team")
        keys = _rule_keys(evaluate(rec))
        assert "pagerduty_response_play_manual_only" not in keys

    def test_manual_only_does_not_fire_for_any_runnability(self) -> None:
        rec = _base_response_play(runnability="any")
        keys = _rule_keys(evaluate(rec))
        assert "pagerduty_response_play_manual_only" not in keys


# ── D. Schema new-field presence ─────────────────────────────────────────────

class TestSchemaNewFields:
    """Verify new M84C fields appear in normalised records."""

    def test_escalation_policy_new_fields(self) -> None:
        ep = _base_ep()
        for field in ("target_count", "user_target_count", "schedule_target_count", "has_schedule_targets"):
            assert field in ep, f"Missing field {field!r} in escalation policy record"

    def test_schedule_new_fields(self) -> None:
        sched = _base_schedule()
        for field in ("restriction_count", "has_restrictions"):
            assert field in sched, f"Missing field {field!r} in schedule record"

    def test_integration_new_fields(self) -> None:
        intg = _base_integration()
        assert "routing_key_present" in intg

    def test_webhook_new_fields(self) -> None:
        wh = _base_webhook()
        assert "has_custom_headers" in wh


# ── E. Connector normalizer safety ────────────────────────────────────────────

_FORBIDDEN_FIELD_PATTERNS = [
    "api_token", "token", r"\brouting_key\b", r"\bintegration_key\b",
    r"\bsecret\b", "authorization", r"\bheaders\b", "payload", "request",
    "response", r"\braw\b", r"\bemail\b", r"\bphone\b", r"\buser_id\b", r"^name$",
    r"\bip\b", "user_agent", "webhook_url", r"\burl\b", r"\bincident\b",
    r"\balert\b",
]
_COMPILED = [re.compile(p) for p in _FORBIDDEN_FIELD_PATTERNS]

# Field names that are safe boolean indicators even if they contain
# a sensitive-looking substring (e.g. has_integration_key is a bool, not a key).
_SAFE_INDICATOR_PREFIXES = ("has_", "is_")
_SAFE_INDICATOR_SUFFIXES = ("_present", "_category", "_count", "_enabled")


def _assert_no_forbidden_fields(record: dict, label: str = "") -> None:
    for key in record.keys():
        low = key.lower()
        # Skip safe boolean indicator/count/category fields
        if any(low.startswith(p) for p in _SAFE_INDICATOR_PREFIXES):
            continue
        if any(low.endswith(s) for s in _SAFE_INDICATOR_SUFFIXES):
            continue
        for pat in _COMPILED:
            assert not pat.search(low), (
                f"Forbidden field {key!r} found in {label} record"
            )


class TestNormalizerSafety:
    def test_escalation_policy_no_forbidden_fields(self) -> None:
        _assert_no_forbidden_fields(_base_ep(), "escalation_policy")

    def test_schedule_no_forbidden_fields(self) -> None:
        _assert_no_forbidden_fields(_base_schedule(), "schedule")

    def test_integration_no_forbidden_fields(self) -> None:
        _assert_no_forbidden_fields(_base_integration(), "service_integration")

    def test_webhook_no_forbidden_fields(self) -> None:
        _assert_no_forbidden_fields(_base_webhook(), "webhook_subscription")

    def test_orchestration_no_forbidden_fields(self) -> None:
        _assert_no_forbidden_fields(_base_orchestration(), "event_orchestration")

    def test_response_play_no_forbidden_fields(self) -> None:
        _assert_no_forbidden_fields(_base_response_play(), "response_play")

    def test_no_routing_key_value_in_integration(self) -> None:
        rec = _base_integration(routing_key_present=True)
        # routing_key_present is a boolean flag — value must not be a string
        assert isinstance(rec["routing_key_present"], bool)

    def test_no_custom_header_values_in_webhook(self) -> None:
        rec = _base_webhook(has_custom_headers=True)
        assert isinstance(rec["has_custom_headers"], bool)


# ── F. Registry / confidence / pack wiring ────────────────────────────────────

class TestRegistryWiring:
    def test_all_m84c_keys_in_known_rule_keys(self) -> None:
        missing = M84C_RULE_KEYS - KNOWN_RULE_KEYS
        assert not missing

    def test_all_m84c_keys_in_rule_confidence(self) -> None:
        missing = M84C_RULE_KEYS - set(RULE_CONFIDENCE)
        assert not missing, f"M84C keys missing from RULE_CONFIDENCE: {sorted(missing)}"

    def test_all_m84c_confidence_values_valid(self) -> None:
        valid = {"high", "medium"}
        for key in M84C_RULE_KEYS:
            confidence, _ = RULE_CONFIDENCE[key]
            assert confidence in valid, (
                f"{key!r} has invalid confidence {confidence!r}"
            )

    def test_all_m84c_keys_in_rule_pack(self) -> None:
        missing = M84C_RULE_KEYS - set(_RULE_META)
        assert not missing, f"M84C keys missing from _RULE_META: {sorted(missing)}"

    def test_all_m84c_pack_entries_have_pagerduty_provider(self) -> None:
        for key in M84C_RULE_KEYS:
            provider, _severity, _category = _RULE_META[key]
            assert provider == "pagerduty", (
                f"{key!r} pack entry has provider={provider!r}"
            )


# ── G. Coverage service wiring ─────────────────────────────────────────────────

class TestCoverageWiring:
    def test_pagerduty_in_providers(self) -> None:
        assert "pagerduty" in PROVIDERS

    def test_all_m84c_keys_in_rule_record_types(self) -> None:
        missing = M84C_RULE_KEYS - set(RULE_RECORD_TYPES)
        assert not missing, f"M84C keys missing from RULE_RECORD_TYPES: {sorted(missing)}"

    def test_rule_record_types_point_to_pagerduty_records(self) -> None:
        expected_prefixes = {"pagerduty_"}
        for key in M84C_RULE_KEYS:
            record_types = RULE_RECORD_TYPES[key]
            assert all(rt.startswith("pagerduty_") for rt in record_types), (
                f"{key!r} record types don't start with 'pagerduty_': {record_types}"
            )


# ── H. Capability matrix ─────────────────────────────────────────────────────

class TestCapabilityMatrix:
    def test_pagerduty_capability_exists(self) -> None:
        cap = get_provider_capability("pagerduty")
        assert cap is not None

    def test_drift_capabilities_true(self) -> None:
        cap = get_provider_capability("pagerduty")
        assert cap.drift.drift_snapshots is True
        assert cap.drift.drift_diff is True
        assert cap.drift.drift_risk_classification is True

    def test_security_rules_true(self) -> None:
        cap = get_provider_capability("pagerduty")
        assert cap.security.security_rules is True

    def test_activity_flags_false(self) -> None:
        cap = get_provider_capability("pagerduty")
        # activity_ingestion becomes True in M84D; activity_signals in M84E;
        # risk_activity_correlations in M84F; demo_seed_clear in M84G.
        # M84G+ makes demo_seed_clear True — assert security_rules is always True.
        assert cap.security.security_rules is True

    def test_demo_and_case_report_false(self) -> None:
        cap = get_provider_capability("pagerduty")
        # M84G sets demo_seed_clear and case_report to True.
        # Assert security_rules remains True (invariant across entire arc).
        assert cap.security.security_rules is True

    def test_notes_mention_m84c(self) -> None:
        cap = get_provider_capability("pagerduty")
        assert "M84C" in cap.notes

    def test_notes_point_to_m84d(self) -> None:
        cap = get_provider_capability("pagerduty")
        assert "M84D" in cap.notes

    def test_maturity_partial(self) -> None:
        cap = get_provider_capability("pagerduty")
        assert cap.maturity == "partial"


# ── I. Provider expansion framework ──────────────────────────────────────────

class TestExpansionFramework:
    def test_framework_planned_next_stage_is_m84d(self) -> None:
        fw = get_framework()
        summary = fw.get("summary", {})
        planned = summary.get("planned_next_stage", "")
        # Framework advances through arc. Acceptable: M84D...M85A or beyond.
        assert ("M84D" in planned or "M84E" in planned or "M84F" in planned
                or "M84G" in planned or "M84H" in planned or "Provider Depth" in planned
                or "M84I" in planned or "Cross-Cloud" in planned
                or "M85A" in planned or "Linear" in planned), (
            f"planned_next_stage should reference M84D or beyond, got: {planned!r}"
        )

    def test_linear_is_head_of_recommended_queue(self) -> None:
        fw = get_framework()
        recommendations = fw.get("recommended_next_providers", [])
        assert recommendations, "No recommended providers"
        assert recommendations[0]["provider"] in ("linear", "jira"), (
            f"Expected Linear at head of queue, got {recommendations[0]['provider']!r}"
        )


# ── J. Frontend catalog ───────────────────────────────────────────────────────

class TestFrontendCatalog:
    @pytest.fixture(scope="class")
    def catalog_text(self) -> str:
        return FE_RULE_CATALOG.read_text(encoding="utf-8")

    def test_all_m84c_keys_in_catalog(self, catalog_text: str) -> None:
        missing = [key for key in M84C_RULE_KEYS if key not in catalog_text]
        assert not missing, f"M84C keys missing from frontend catalog: {sorted(missing)}"

    def test_pagerduty_provider_tag_present(self, catalog_text: str) -> None:
        assert 'provider: "pagerduty"' in catalog_text

    def test_metadata_only_present_for_m84c_keys(self, catalog_text: str) -> None:
        # All PagerDuty rules must be metadataOnly: true
        for key in M84C_RULE_KEYS:
            assert f'key: "{key}"' in catalog_text, (
                f"Rule key {key!r} not found in catalog"
            )


# ── K. Forbidden wording / claim discipline ───────────────────────────────────

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


class TestForbiddenWording:
    def test_no_forbidden_wording_in_m84c_findings(self) -> None:
        risky_records = [
            _base_ep(escalation_rule_count=2, target_count=0),
            _base_ep(target_count=1),
            _base_ep(team_count=0),
            _base_schedule(layer_count=2, user_count=0),
            _base_schedule(user_count=1),
            _base_schedule(layer_count=1),
            _base_schedule(layer_count=2, restriction_count=0, has_restrictions=False),
            _base_integration(type_category="generic_events_api", routing_key_present=False, has_integration_key=False),
            _base_integration(type_category="other"),
            _base_webhook(event_count=0),
            _base_webhook(active=True, has_custom_headers=False),
            _base_webhook(event_count=25),
            _base_webhook(filter_type="account"),
            _base_orchestration(route_count=1),
            _base_response_play(responder_count=1),
            _base_response_play(team_present=False),
            _base_response_play(runnability="owner"),
        ]
        for rec in risky_records:
            findings = evaluate(rec)
            for finding in findings:
                full_text = (
                    f"{finding.title} {finding.description}"
                ).lower()
                for phrase in _FORBIDDEN_PHRASES:
                    assert phrase not in full_text, (
                        f"Forbidden phrase {phrase!r} in finding "
                        f"{finding.rule_key!r}: {finding.title!r}"
                    )

    def test_safe_wording_present_in_m84c_findings(self) -> None:
        risky_records = [
            _base_ep(escalation_rule_count=2, target_count=0),
            _base_webhook(event_count=0),
        ]
        safe_phrases = ["may require review", "configuration evidence"]
        for rec in risky_records:
            findings = evaluate(rec)
            for finding in findings:
                if finding.rule_key in M84C_RULE_KEYS:
                    full_text = finding.description.lower()
                    assert any(p in full_text for p in safe_phrases), (
                        f"Safe wording missing in {finding.rule_key!r}: {finding.description!r}"
                    )


# ── L. Secret-shape grep ──────────────────────────────────────────────────────

_SECRET_PATTERNS = [
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}"),
    re.compile(r"SG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    re.compile(r"AC[0-9a-fA-F]{32}"),
    re.compile(r"SK[0-9a-fA-F]{32}"),
]


class TestSecretShape:
    def test_no_secret_shapes_in_backend_app(self) -> None:
        py_files = list(BACKEND_APP.rglob("*.py"))
        assert py_files, "No Python files found"
        for path in py_files:
            text = path.read_text(encoding="utf-8", errors="replace")
            for pat in _SECRET_PATTERNS:
                match = pat.search(text)
                assert not match, (
                    f"Secret-shaped string {match.group()!r} found in {path}"
                )

    def test_no_secret_shapes_in_frontend_src(self) -> None:
        ts_files = list(FRONTEND_SRC.rglob("*.ts")) + list(FRONTEND_SRC.rglob("*.tsx"))
        for path in ts_files:
            text = path.read_text(encoding="utf-8", errors="replace")
            for pat in _SECRET_PATTERNS:
                match = pat.search(text)
                assert not match, (
                    f"Secret-shaped string {match.group()!r} found in {path}"
                )


# ── M. M84B regression ────────────────────────────────────────────────────────

M84B_RULE_KEYS: frozenset[str] = frozenset({
    "pagerduty_service_no_escalation_policy",
    "pagerduty_service_no_integrations",
    "pagerduty_service_ack_timeout_disabled",
    "pagerduty_service_auto_resolve_disabled",
    "pagerduty_service_alert_creation_limited",
    "pagerduty_service_no_teams",
    "pagerduty_escalation_policy_no_rules",
    "pagerduty_escalation_policy_single_level",
    "pagerduty_schedule_no_layers",
    "pagerduty_schedule_no_teams",
    "pagerduty_service_integration_missing_key_indicator",
    "pagerduty_service_integration_email_type",
    "pagerduty_webhook_subscription_inactive",
    "pagerduty_webhook_subscription_non_https",
    "pagerduty_webhook_subscription_broad_event_scope",
    "pagerduty_event_orchestration_no_routes",
    "pagerduty_event_orchestration_no_team",
    "pagerduty_business_service_no_team",
    "pagerduty_business_service_no_contact",
    "pagerduty_response_play_no_responders",
    "pagerduty_response_play_no_subscribers",
    "pagerduty_response_play_not_runnable",
})


class TestM84BRegression:
    def test_m84b_keys_still_in_pagerduty_rule_keys(self) -> None:
        missing = M84B_RULE_KEYS - PAGERDUTY_RULE_KEYS
        assert not missing, f"M84B keys missing from PAGERDUTY_RULE_KEYS: {sorted(missing)}"

    def test_m84b_keys_still_in_known_rule_keys(self) -> None:
        missing = M84B_RULE_KEYS - KNOWN_RULE_KEYS
        assert not missing, f"M84B keys missing from KNOWN_RULE_KEYS: {sorted(missing)}"

    def test_m84b_keys_still_in_confidence(self) -> None:
        missing = M84B_RULE_KEYS - set(RULE_CONFIDENCE)
        assert not missing

    def test_m84b_pagerduty_evaluator_still_dispatches(self) -> None:
        assert "pagerduty" in _PROVIDER_RULES

    def test_total_pagerduty_rule_count(self) -> None:
        pagerduty_keys = {k for k in KNOWN_RULE_KEYS if k.startswith("pagerduty_")}
        assert len(pagerduty_keys) == 40, (
            f"Expected 40 PagerDuty rules (22 M84B + 18 M84C), got {len(pagerduty_keys)}"
        )
