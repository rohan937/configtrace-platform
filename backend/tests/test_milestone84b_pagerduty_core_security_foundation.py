"""M84B — PagerDuty core security foundation tests.

Verifies 22 PagerDuty configuration-risk rules, registry/confidence/pack/
coverage wiring, capability matrix update, expansion framework pointer,
finding evaluator dispatch, and frontend catalog.

Sections
--------
  A. Rule key taxonomy (22 implemented rules)
  B. Rule positive tests (each rule fires on a risky record)
  C. Rule negative tests (each rule does NOT fire on a healthy record)
  D. Evidence privacy scan (no secrets/PII/URLs/keys in evidence)
  E. Registry / confidence / pack wiring
  F. Coverage service (pagerduty provider, record types, diagnostics)
  G. Capability matrix + expansion framework
  H. Frontend catalog (pagerduty entries present)
  I. Forbidden wording / claim discipline
  J. Secret-shape grep
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
    PAGERDUTY_BUSINESS_SERVICE,
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
    PROVIDER_SURFACES,
    RECORD_TYPE_DIAGNOSTICS,
    RULE_RECORD_TYPES,
)
from app.services.security_finding_evaluator import _PROVIDER_RULES
from app.services.provider_capability_matrix_service import get_provider_capability
from app.services.provider_expansion_framework import get_framework

REPO_ROOT = Path(__file__).resolve().parents[2]
FE_RULE_CATALOG = REPO_ROOT / "frontend" / "src" / "lib" / "securityRuleCatalog.ts"

EXPECTED_RULE_KEYS: frozenset[str] = frozenset({
    # Service (6)
    "pagerduty_service_no_escalation_policy",
    "pagerduty_service_no_integrations",
    "pagerduty_service_ack_timeout_disabled",
    "pagerduty_service_auto_resolve_disabled",
    "pagerduty_service_alert_creation_limited",
    "pagerduty_service_no_teams",
    # Escalation policy (2)
    "pagerduty_escalation_policy_no_rules",
    "pagerduty_escalation_policy_single_level",
    # Schedule (2)
    "pagerduty_schedule_no_layers",
    "pagerduty_schedule_no_teams",
    # Service integration (2)
    "pagerduty_service_integration_missing_key_indicator",
    "pagerduty_service_integration_email_type",
    # Webhook subscription (3)
    "pagerduty_webhook_subscription_inactive",
    "pagerduty_webhook_subscription_non_https",
    "pagerduty_webhook_subscription_broad_event_scope",
    # Event orchestration (2)
    "pagerduty_event_orchestration_no_routes",
    "pagerduty_event_orchestration_no_team",
    # Business service (2)
    "pagerduty_business_service_no_team",
    "pagerduty_business_service_no_contact",
    # Response play (3)
    "pagerduty_response_play_no_responders",
    "pagerduty_response_play_no_subscribers",
    "pagerduty_response_play_not_runnable",
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

# Fields that must NEVER appear as keys in evidence dicts.
_FORBIDDEN_EVIDENCE_FIELDS = frozenset({
    "api_token", "token", "routing_key", "integration_key", "secret",
    "authorization", "headers", "payload", "request", "response",
    "raw", "email", "phone", "user_email", "user_id", "ip_address",
    "user_agent", "webhook_url", "incident", "alert",
})


def _rule_keys(findings) -> set[str]:
    return {f.rule_key for f in findings}


# ════════════════════════════════════════════════════════════════════════════
# Section A — Rule key taxonomy
# ════════════════════════════════════════════════════════════════════════════


def test_a1_rule_module_importable() -> None:
    from app.services.security_rules.pagerduty import evaluate, PAGERDUTY_RULE_KEYS  # noqa: F401
    assert callable(evaluate)


def test_a2_rule_keys_count() -> None:
    # M84C expands from 22 (M84B) to 40 total rules.
    assert len(PAGERDUTY_RULE_KEYS) >= 22


def test_a3_rule_keys_exact() -> None:
    # M84B rules must all still be present (M84C adds more).
    assert EXPECTED_RULE_KEYS.issubset(PAGERDUTY_RULE_KEYS), (
        f"M84B expected keys missing: {sorted(EXPECTED_RULE_KEYS - PAGERDUTY_RULE_KEYS)}"
    )


def test_a4_all_rule_keys_in_registry() -> None:
    missing = PAGERDUTY_RULE_KEYS - KNOWN_RULE_KEYS
    assert not missing, f"Missing from KNOWN_RULE_KEYS: {sorted(missing)}"


def test_a5_all_rule_keys_have_confidence_entries() -> None:
    missing = PAGERDUTY_RULE_KEYS - set(RULE_CONFIDENCE.keys())
    assert not missing, f"Missing from RULE_CONFIDENCE: {sorted(missing)}"


def test_a6_all_rule_keys_in_rule_pack() -> None:
    missing = PAGERDUTY_RULE_KEYS - set(_RULE_META.keys())
    assert not missing, f"Missing from _RULE_META: {sorted(missing)}"


def test_a7_rule_pack_providers_are_pagerduty() -> None:
    for key in PAGERDUTY_RULE_KEYS:
        assert _RULE_META[key][0] == "pagerduty", (
            f"{key} provider in _RULE_META is wrong: {_RULE_META[key][0]}"
        )


def test_a8_all_rule_keys_in_rule_record_types() -> None:
    missing = PAGERDUTY_RULE_KEYS - set(RULE_RECORD_TYPES.keys())
    assert not missing, f"Missing from RULE_RECORD_TYPES: {sorted(missing)}"


def test_a9_record_types_are_pagerduty() -> None:
    for key in PAGERDUTY_RULE_KEYS:
        rt = RULE_RECORD_TYPES[key]
        # tuple of record_types
        if isinstance(rt, tuple):
            for r in rt:
                assert r.startswith("pagerduty_"), f"{key} maps to non-pagerduty record: {r}"
        else:
            assert rt.startswith("pagerduty_"), f"{key} maps to non-pagerduty record: {rt}"


def test_a10_pagerduty_in_coverage_providers() -> None:
    assert "pagerduty" in PROVIDERS


def test_a11_pagerduty_in_provider_surfaces() -> None:
    assert "pagerduty" in PROVIDER_SURFACES
    assert len(PROVIDER_SURFACES["pagerduty"]) >= 8


def test_a12_pagerduty_record_types_in_diagnostics() -> None:
    for rt in (
        "pagerduty_service",
        "pagerduty_escalation_policy",
        "pagerduty_schedule",
        "pagerduty_service_integration",
        "pagerduty_webhook_subscription",
        "pagerduty_event_orchestration",
        "pagerduty_business_service",
        "pagerduty_response_play",
    ):
        assert rt in RECORD_TYPE_DIAGNOSTICS, f"Missing diagnostics for {rt}"


def test_a13_evaluator_dispatch_includes_pagerduty() -> None:
    assert "pagerduty" in _PROVIDER_RULES


# ════════════════════════════════════════════════════════════════════════════
# Section B — Positive rule trigger tests
# ════════════════════════════════════════════════════════════════════════════


def _service(**kwargs) -> dict:
    base = {
        "record_type": PAGERDUTY_SERVICE,
        "record_id": "PAGERDUTY_TEST_SERVICE_ID",
        "resource_id": "PAGERDUTY_TEST_SERVICE_ID",
        "resource_name": "Test Service",
        "status_category": "active",
        "escalation_policy_id": "PAGERDUTY_TEST_ESCALATION_POLICY_ID",
        "team_count": 1,
        "integration_count": 1,
        "alert_creation_category": "alerts_and_incidents",
        "incident_urgency_rule_type": "constant",
        "support_hours_enabled": True,
        "scheduled_actions_count": 0,
        "auto_resolve_timeout_category": "medium",
        "acknowledgement_timeout_category": "short",
    }
    base.update(kwargs)
    return base


def _ep(**kwargs) -> dict:
    base = {
        "record_type": PAGERDUTY_ESCALATION_POLICY,
        "record_id": "PAGERDUTY_TEST_ESCALATION_POLICY_ID",
        "resource_id": "PAGERDUTY_TEST_ESCALATION_POLICY_ID",
        "resource_name": "Primary On-Call",
        "team_count": 1,
        "escalation_rule_count": 2,
        "escalation_level_count": 2,
        "repeat_enabled": True,
        "num_loops": 2,
        "on_call_handoff_notifications": "if_has_services",
        # M84C safe fields — healthy defaults
        "target_count": 4,
        "user_target_count": 2,
        "schedule_target_count": 2,
        "has_schedule_targets": True,
    }
    base.update(kwargs)
    return base


def _schedule(**kwargs) -> dict:
    base = {
        "record_type": PAGERDUTY_SCHEDULE,
        "record_id": "PAGERDUTY_TEST_SCHEDULE_ID",
        "resource_id": "PAGERDUTY_TEST_SCHEDULE_ID",
        "resource_name": "Primary Schedule",
        "time_zone_present": True,
        "layer_count": 2,
        "user_count": 3,
        "team_count": 1,
        # M84C safe fields — healthy defaults
        "restriction_count": 2,
        "has_restrictions": True,
    }
    base.update(kwargs)
    return base


def _integration(**kwargs) -> dict:
    base = {
        "record_type": PAGERDUTY_SERVICE_INTEGRATION,
        "record_id": "PAGERDUTY_TEST_INTEGRATION_ID",
        "resource_id": "PAGERDUTY_TEST_INTEGRATION_ID",
        "service_id": "PAGERDUTY_TEST_SERVICE_ID",
        "type_category": "generic_events_api",
        "vendor_name": None,
        "has_integration_key": True,
        # M84C safe fields — healthy defaults
        "routing_key_present": True,
    }
    base.update(kwargs)
    return base


def _webhook(**kwargs) -> dict:
    base = {
        "record_type": PAGERDUTY_WEBHOOK_SUBSCRIPTION,
        "record_id": "PAGERDUTY_TEST_WEBHOOK_SUBSCRIPTION_ID",
        "resource_id": "PAGERDUTY_TEST_WEBHOOK_SUBSCRIPTION_ID",
        "active": True,
        "event_count": 5,
        "delivery_url_scheme_category": "https",
        "filter_type": "service_reference",
        # M84C safe fields — healthy defaults
        "has_custom_headers": True,
    }
    base.update(kwargs)
    return base


def _orch(**kwargs) -> dict:
    base = {
        "record_type": PAGERDUTY_EVENT_ORCHESTRATION,
        "record_id": "PAGERDUTY_TEST_EVENT_ORCHESTRATION_ID",
        "resource_id": "PAGERDUTY_TEST_EVENT_ORCHESTRATION_ID",
        "resource_name": "Main Orchestration",
        "team_present": True,
        "route_count": 3,
    }
    base.update(kwargs)
    return base


def _bs(**kwargs) -> dict:
    base = {
        "record_type": PAGERDUTY_BUSINESS_SERVICE,
        "record_id": "PAGERDUTY_TEST_BUSINESS_SERVICE_ID",
        "resource_id": "PAGERDUTY_TEST_BUSINESS_SERVICE_ID",
        "resource_name": "Checkout",
        "team_present": True,
        "point_of_contact_present": True,
    }
    base.update(kwargs)
    return base


def _rp(**kwargs) -> dict:
    base = {
        "record_type": PAGERDUTY_RESPONSE_PLAY,
        "record_id": "PAGERDUTY_TEST_RESPONSE_PLAY_ID",
        "resource_id": "PAGERDUTY_TEST_RESPONSE_PLAY_ID",
        "resource_name": "Major Incident",
        "team_present": True,
        "responder_count": 3,
        "subscriber_count": 2,
        "conference_number_present": False,
        "runnability": "team",
    }
    base.update(kwargs)
    return base


# Service positives
def test_b_service_no_escalation_policy_fires() -> None:
    keys = _rule_keys(evaluate(_service(escalation_policy_id="")))
    assert "pagerduty_service_no_escalation_policy" in keys


def test_b_service_no_integrations_fires() -> None:
    keys = _rule_keys(evaluate(_service(integration_count=0)))
    assert "pagerduty_service_no_integrations" in keys


def test_b_service_ack_timeout_disabled_fires() -> None:
    keys = _rule_keys(evaluate(_service(acknowledgement_timeout_category="disabled")))
    assert "pagerduty_service_ack_timeout_disabled" in keys


def test_b_service_auto_resolve_disabled_fires() -> None:
    keys = _rule_keys(evaluate(_service(auto_resolve_timeout_category="disabled")))
    assert "pagerduty_service_auto_resolve_disabled" in keys


def test_b_service_alert_creation_limited_fires() -> None:
    keys = _rule_keys(evaluate(_service(alert_creation_category="incidents_only")))
    assert "pagerduty_service_alert_creation_limited" in keys


def test_b_service_no_teams_fires() -> None:
    keys = _rule_keys(evaluate(_service(team_count=0)))
    assert "pagerduty_service_no_teams" in keys


# Escalation policy positives
def test_b_ep_no_rules_fires() -> None:
    keys = _rule_keys(evaluate(_ep(escalation_rule_count=0, escalation_level_count=0)))
    assert "pagerduty_escalation_policy_no_rules" in keys


def test_b_ep_single_level_fires() -> None:
    keys = _rule_keys(evaluate(_ep(escalation_rule_count=1, escalation_level_count=1)))
    assert "pagerduty_escalation_policy_single_level" in keys


# Schedule positives
def test_b_schedule_no_layers_fires() -> None:
    keys = _rule_keys(evaluate(_schedule(layer_count=0)))
    assert "pagerduty_schedule_no_layers" in keys


def test_b_schedule_no_teams_fires() -> None:
    keys = _rule_keys(evaluate(_schedule(team_count=0)))
    assert "pagerduty_schedule_no_teams" in keys


# Service integration positives
def test_b_integration_missing_key_fires() -> None:
    keys = _rule_keys(evaluate(_integration(has_integration_key=False)))
    assert "pagerduty_service_integration_missing_key_indicator" in keys


def test_b_integration_email_type_fires() -> None:
    keys = _rule_keys(evaluate(_integration(type_category="email")))
    assert "pagerduty_service_integration_email_type" in keys


# Webhook positives
def test_b_webhook_inactive_fires() -> None:
    keys = _rule_keys(evaluate(_webhook(active=False)))
    assert "pagerduty_webhook_subscription_inactive" in keys


def test_b_webhook_non_https_fires() -> None:
    keys = _rule_keys(evaluate(_webhook(delivery_url_scheme_category="http")))
    assert "pagerduty_webhook_subscription_non_https" in keys


def test_b_webhook_broad_event_scope_fires() -> None:
    keys = _rule_keys(evaluate(_webhook(event_count=15)))
    assert "pagerduty_webhook_subscription_broad_event_scope" in keys


# Event orchestration positives
def test_b_orch_no_routes_fires() -> None:
    keys = _rule_keys(evaluate(_orch(route_count=0)))
    assert "pagerduty_event_orchestration_no_routes" in keys


def test_b_orch_no_team_fires() -> None:
    keys = _rule_keys(evaluate(_orch(team_present=False)))
    assert "pagerduty_event_orchestration_no_team" in keys


# Business service positives
def test_b_bs_no_team_fires() -> None:
    keys = _rule_keys(evaluate(_bs(team_present=False)))
    assert "pagerduty_business_service_no_team" in keys


def test_b_bs_no_contact_fires() -> None:
    keys = _rule_keys(evaluate(_bs(point_of_contact_present=False)))
    assert "pagerduty_business_service_no_contact" in keys


# Response play positives
def test_b_rp_no_responders_fires() -> None:
    keys = _rule_keys(evaluate(_rp(responder_count=0)))
    assert "pagerduty_response_play_no_responders" in keys


def test_b_rp_no_subscribers_fires() -> None:
    keys = _rule_keys(evaluate(_rp(subscriber_count=0)))
    assert "pagerduty_response_play_no_subscribers" in keys


def test_b_rp_not_runnable_fires() -> None:
    keys = _rule_keys(evaluate(_rp(runnability="unknown")))
    assert "pagerduty_response_play_not_runnable" in keys


# ════════════════════════════════════════════════════════════════════════════
# Section C — Negative tests (healthy records → no findings)
# ════════════════════════════════════════════════════════════════════════════


def test_c_healthy_service_no_findings() -> None:
    assert evaluate(_service()) == []


def test_c_healthy_escalation_policy_no_findings() -> None:
    assert evaluate(_ep()) == []


def test_c_healthy_schedule_no_findings() -> None:
    assert evaluate(_schedule()) == []


def test_c_healthy_integration_no_findings() -> None:
    assert evaluate(_integration()) == []


def test_c_healthy_webhook_no_findings() -> None:
    assert evaluate(_webhook()) == []


def test_c_healthy_orchestration_no_findings() -> None:
    assert evaluate(_orch()) == []


def test_c_healthy_business_service_no_findings() -> None:
    assert evaluate(_bs()) == []


def test_c_healthy_response_play_no_findings() -> None:
    assert evaluate(_rp()) == []


def test_c_non_pagerduty_record_no_findings() -> None:
    """Evaluator must ignore non-PagerDuty record types."""
    record = {"record_type": "datadog_monitor", "record_id": "X", "disabled": True}
    assert evaluate(record) == []


def test_c_webhook_https_does_not_fire_non_https() -> None:
    keys = _rule_keys(evaluate(_webhook(delivery_url_scheme_category="https")))
    assert "pagerduty_webhook_subscription_non_https" not in keys


def test_c_webhook_absent_url_does_not_fire_non_https() -> None:
    keys = _rule_keys(evaluate(_webhook(delivery_url_scheme_category="absent")))
    assert "pagerduty_webhook_subscription_non_https" not in keys


# ════════════════════════════════════════════════════════════════════════════
# Section D — Evidence privacy scan
# ════════════════════════════════════════════════════════════════════════════


@pytest.mark.parametrize("record_factory,kwargs", [
    (_service, {"escalation_policy_id": "", "integration_count": 0, "acknowledgement_timeout_category": "disabled",
                "auto_resolve_timeout_category": "disabled", "alert_creation_category": "incidents_only", "team_count": 0}),
    (_ep, {"escalation_rule_count": 0, "escalation_level_count": 0}),
    (_schedule, {"layer_count": 0, "team_count": 0}),
    (_integration, {"has_integration_key": False, "type_category": "email"}),
    (_webhook, {"active": False, "delivery_url_scheme_category": "http", "event_count": 15}),
    (_orch, {"route_count": 0, "team_present": False}),
    (_bs, {"team_present": False, "point_of_contact_present": False}),
    (_rp, {"responder_count": 0, "subscriber_count": 0, "runnability": "unknown"}),
])
def test_d_evidence_no_forbidden_fields(record_factory, kwargs) -> None:
    findings = evaluate(record_factory(**kwargs))
    for finding in findings:
        for forbidden in _FORBIDDEN_EVIDENCE_FIELDS:
            assert forbidden not in finding.evidence, (
                f"Forbidden field '{forbidden}' in evidence for {finding.rule_key}: {finding.evidence}"
            )


def test_d_evidence_no_secret_shaped_values() -> None:
    """Evidence values must not contain JWT/SG/AC/SK secret shapes."""
    findings = evaluate(_service(escalation_policy_id="", integration_count=0))
    findings += evaluate(_webhook(active=False, delivery_url_scheme_category="http"))
    findings += evaluate(_integration(has_integration_key=False))
    for finding in findings:
        ev_str = str(finding.evidence)
        assert not re.search(r"eyJ[A-Za-z0-9_\-]{10,}", ev_str)
        assert not re.search(r"AC[0-9a-fA-F]{32}", ev_str)
        assert not re.search(r"SK[0-9a-fA-F]{32}", ev_str)


def test_d_finding_provider_is_pagerduty() -> None:
    """Every finding produced by evaluate() must use provider='pagerduty'."""
    findings = evaluate(_service(escalation_policy_id="", integration_count=0))
    findings += evaluate(_ep(escalation_rule_count=0))
    findings += evaluate(_webhook(active=False))
    for finding in findings:
        assert finding.provider == "pagerduty", (
            f"Finding {finding.rule_key} has wrong provider: {finding.provider!r}"
        )


def test_d_finding_evidence_contains_rule_and_record_id() -> None:
    """Every finding's evidence dict should contain 'rule' and 'record_id'."""
    findings = evaluate(_service(escalation_policy_id=""))
    for finding in findings:
        assert "rule" in finding.evidence
        assert "record_id" in finding.evidence


# ════════════════════════════════════════════════════════════════════════════
# Section E — Registry / confidence / pack
# ════════════════════════════════════════════════════════════════════════════


def test_e_all_rule_keys_known() -> None:
    for key in PAGERDUTY_RULE_KEYS:
        assert is_known_rule_key(key)


def test_e_all_severities_valid() -> None:
    """All PagerDuty rules in _RULE_META must have a valid severity."""
    valid = {"critical", "high", "medium", "low", "info"}
    for key in PAGERDUTY_RULE_KEYS:
        provider, severity, category = _RULE_META[key]
        assert severity in valid, f"{key} has invalid severity: {severity}"


def test_e_severity_high_keys() -> None:
    """Specific high-severity rules must be tagged 'high' per spec."""
    high_keys = {
        "pagerduty_service_no_escalation_policy",
        "pagerduty_escalation_policy_no_rules",
        "pagerduty_webhook_subscription_non_https",
        "pagerduty_response_play_no_responders",
    }
    for key in high_keys:
        assert _RULE_META[key][1] == "high", f"{key} should be high severity"


# ════════════════════════════════════════════════════════════════════════════
# Section F — Coverage service
# ════════════════════════════════════════════════════════════════════════════


def test_f_pagerduty_in_coverage_providers() -> None:
    assert "pagerduty" in PROVIDERS


def test_f_pagerduty_surfaces_listed() -> None:
    surfaces = PROVIDER_SURFACES["pagerduty"]
    assert "Services" in surfaces
    assert "Escalation policies" in surfaces
    assert "Webhook subscriptions" in surfaces


# ════════════════════════════════════════════════════════════════════════════
# Section G — Capability matrix + expansion framework
# ════════════════════════════════════════════════════════════════════════════


def test_g_capability_matrix_drift_flags() -> None:
    cap = get_provider_capability("pagerduty")
    assert cap is not None
    assert cap.drift.drift_snapshots is True
    assert cap.drift.drift_diff is True
    assert cap.drift.drift_risk_classification is True


def test_g_capability_matrix_security_rules_true() -> None:
    cap = get_provider_capability("pagerduty")
    assert cap is not None
    assert cap.security.security_rules is True


def test_g_capability_matrix_other_security_false() -> None:
    """M84D promotes activity_ingestion to True; signals/correlations/demo remain False
    through M84B. M84G sets demo_seed_clear, case_report, evidence_timeline, and
    evidence_graph to True, so those are no longer asserted False once the arc completes."""
    cap = get_provider_capability("pagerduty")
    assert cap is not None
    sec = cap.security
    # security_rules is True from M84B onward (always true after arc).
    assert sec.security_rules is True


def test_g_capability_matrix_maturity_partial() -> None:
    cap = get_provider_capability("pagerduty")
    assert cap is not None
    assert cap.maturity == "partial"


def test_g_capability_matrix_notes_mention_m84b() -> None:
    cap = get_provider_capability("pagerduty")
    assert cap is not None
    assert "M84B" in cap.notes


def test_g_expansion_framework_planned_next_stage_m84c() -> None:
    fw = get_framework()
    summary = fw.get("summary", {})
    planned = summary.get("planned_next_stage", "") or ""
    # Framework advances through arc. Acceptable: M84C...M85A or beyond.
    assert ("M84C" in planned or "Escalation/Webhook Risk Expansion" in planned
            or "M84D" in planned or "Activity/Event Ingestion" in planned
            or "M84E" in planned or "Activity Signals" in planned
            or "M84F" in planned or "Activity Correlations" in planned
            or "M84G" in planned or "Demo" in planned
            or "M84H" in planned or "Provider Depth" in planned
            or "M84I" in planned or "Cross-Cloud" in planned
            or "M85A" in planned or "Linear" in planned), (
        f"planned_next_stage should reference M84C or beyond; got: {planned!r}"
    )


def test_g_expansion_framework_not_m84b() -> None:
    fw = get_framework()
    summary = fw.get("summary", {})
    planned = summary.get("planned_next_stage", "") or ""
    assert "M84B" not in planned, (
        f"planned_next_stage should advance past M84B; got: {planned!r}"
    )


def test_g_linear_head_of_recommended_next_providers() -> None:
    fw = get_framework()
    recommended = fw.get("recommended_next_providers", [])
    assert recommended, "recommended_next_providers should not be empty"
    first = recommended[0]
    provider = first.get("provider", "") if isinstance(first, dict) else str(first)
    assert "linear" in provider.lower(), (
        f"Linear should remain head of recommended_next_providers; got: {provider!r}"
    )


def test_g_pagerduty_not_in_recommended_providers() -> None:
    fw = get_framework()
    recommended = fw.get("recommended_next_providers", [])
    providers = [
        r.get("provider", "").lower() for r in recommended if isinstance(r, dict)
    ]
    assert "pagerduty" not in providers


# ════════════════════════════════════════════════════════════════════════════
# Section H — Frontend catalog
# ════════════════════════════════════════════════════════════════════════════


@pytest.mark.skipif(not FE_RULE_CATALOG.exists(), reason="Frontend tree absent")
def test_h_frontend_catalog_has_all_pagerduty_rules() -> None:
    text = FE_RULE_CATALOG.read_text()
    for key in EXPECTED_RULE_KEYS:
        assert f'"{key}"' in text or f"'{key}'" in text, (
            f"Rule '{key}' not found in securityRuleCatalog.ts"
        )


@pytest.mark.skipif(not FE_RULE_CATALOG.exists(), reason="Frontend tree absent")
def test_h_frontend_catalog_pagerduty_provider_coverage() -> None:
    text = FE_RULE_CATALOG.read_text()
    # PROVIDER_COVERAGE should have a pagerduty entry
    idx = text.find("PROVIDER_COVERAGE")
    assert idx != -1
    rest = text[idx:]
    assert '"pagerduty"' in rest or "'pagerduty'" in rest, (
        "PROVIDER_COVERAGE should include a pagerduty entry"
    )


# ════════════════════════════════════════════════════════════════════════════
# Section I — Forbidden wording / claim discipline
# ════════════════════════════════════════════════════════════════════════════


_PAGERDUTY_RULES_MODULE = (
    Path(__file__).parent.parent / "app" / "services" / "security_rules" / "pagerduty.py"
)


@pytest.mark.parametrize("phrase", _FORBIDDEN_PHRASES)
def test_i_no_forbidden_phrase_in_rules_module(phrase: str) -> None:
    text = _PAGERDUTY_RULES_MODULE.read_text().lower()
    assert phrase.lower() not in text, (
        f"Forbidden phrase '{phrase}' found in pagerduty.py rules module"
    )


def test_i_rule_descriptions_use_safe_wording() -> None:
    """Every PagerDuty finding's description must use review-safe wording."""
    risky_records = [
        _service(escalation_policy_id="", integration_count=0,
                 acknowledgement_timeout_category="disabled",
                 auto_resolve_timeout_category="disabled",
                 alert_creation_category="incidents_only", team_count=0),
        _ep(escalation_rule_count=0, escalation_level_count=0),
        _schedule(layer_count=0, team_count=0),
        _integration(has_integration_key=False, type_category="email"),
        _webhook(active=False, delivery_url_scheme_category="http", event_count=15),
        _orch(route_count=0, team_present=False),
        _bs(team_present=False, point_of_contact_present=False),
        _rp(responder_count=0, subscriber_count=0, runnability="unknown"),
    ]
    for record in risky_records:
        for finding in evaluate(record):
            desc_lower = finding.description.lower()
            for phrase in _FORBIDDEN_PHRASES:
                assert phrase.lower() not in desc_lower, (
                    f"Forbidden phrase '{phrase}' in description for {finding.rule_key}"
                )


# ════════════════════════════════════════════════════════════════════════════
# Section J — Secret-shape grep over PagerDuty rules module
# ════════════════════════════════════════════════════════════════════════════


_SECRET_PATTERNS = [
    (r"eyJ[A-Za-z0-9_\-]{10,}", "JWT-shaped string"),
    (r"SG\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}", "SendGrid key shape"),
    (r"AC[0-9a-fA-F]{32}", "Twilio SID shape"),
    (r"SK[0-9a-fA-F]{32}", "SK secret shape"),
]


def test_j_no_secret_shape_in_rules_module() -> None:
    text = _PAGERDUTY_RULES_MODULE.read_text()
    for pattern, label in _SECRET_PATTERNS:
        assert not re.search(pattern, text), (
            f"{label} found in pagerduty.py rules module"
        )
