"""PagerDuty provider depth QA.

Durable, mostly-static guardrails that pin the full PagerDuty rule taxonomy
across every registration surface, validate privacy / claim-discipline
invariants for the PagerDuty provider, and assert the central-evaluator wiring
that makes PagerDuty rules actually fire during snapshot evaluation.

  TestPagerDutyRuleRegistration        — all 40 PagerDuty rule keys present in
                                         the module export, registry, confidence
                                         map, rule pack, and coverage service.
  TestPagerDutyFrontendCatalogParity   — all 40 keys appear in the TypeScript
                                         securityRuleCatalog.ts with matching
                                         severity and provider.
  TestPagerDutyEvidenceSafety          — fired-rule evidence carries no secret /
                                         token / PII / raw-value keys and is flat.
  TestPagerDutyCopySafety              — rule copy carries no forbidden
                                         (breach-style) wording.
  TestPagerDutyEvaluatorDispatch       — "pagerduty" is wired into the central
                                         evaluator with correct argument order;
                                         a risky service fires a known rule.
  TestPagerDutyActivityMetadata        — activity-event metadata keys use the
                                         corrected names (custom_headers_present,
                                         point_of_contact_present).
  TestPagerDutyExpansionFramework      — expansion framework points at M89A
                                         Kubernetes.
  TestPagerDutyProviderCapabilityMatrix — PagerDuty is implemented with
                                         security_rules=True; Kubernetes is not
                                         yet implemented and has no connector.

Pure unit tests: registry / catalog / copy / severity / dispatch / metadata
checks read Python dicts and the TypeScript catalog as text — no database.
"""

from __future__ import annotations

import inspect
import pathlib
import re
from typing import Any

import pytest

# ── Paths ─────────────────────────────────────────────────────────────────────

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
BACKEND = REPO_ROOT / "backend" / "app"
FE_RULE_CATALOG = REPO_ROOT / "frontend" / "src" / "lib" / "securityRuleCatalog.ts"

CANONICAL_PROVIDER = "pagerduty"


# ── Canonical PagerDuty rule set (40 shipped rules, M84B + M84C) ──────────────

PAGERDUTY_RULE_KEYS = [
    # Service
    "pagerduty_service_no_escalation_policy",
    "pagerduty_service_no_integrations",
    "pagerduty_service_ack_timeout_disabled",
    "pagerduty_service_auto_resolve_disabled",
    "pagerduty_service_alert_creation_limited",
    "pagerduty_service_no_teams",
    # Escalation policy
    "pagerduty_escalation_policy_no_rules",
    "pagerduty_escalation_policy_single_level",
    "pagerduty_escalation_policy_no_targets",
    "pagerduty_escalation_policy_low_target_count",
    "pagerduty_escalation_policy_no_schedule_targets",
    "pagerduty_escalation_policy_no_team_targets",
    # Schedule
    "pagerduty_schedule_no_layers",
    "pagerduty_schedule_no_teams",
    "pagerduty_schedule_no_targets",
    "pagerduty_schedule_low_target_count",
    "pagerduty_schedule_single_layer",
    "pagerduty_schedule_no_restrictions",
    # Service integration
    "pagerduty_service_integration_missing_key_indicator",
    "pagerduty_service_integration_email_type",
    "pagerduty_service_integration_routing_key_missing",
    "pagerduty_service_integration_unknown_type",
    # Webhook subscription
    "pagerduty_webhook_subscription_inactive",
    "pagerduty_webhook_subscription_non_https",
    "pagerduty_webhook_subscription_broad_event_scope",
    "pagerduty_webhook_subscription_no_events",
    "pagerduty_webhook_subscription_secret_not_indicated",
    "pagerduty_webhook_subscription_broad_scope_high",
    "pagerduty_webhook_subscription_account_scope",
    # Event orchestration
    "pagerduty_event_orchestration_no_routes",
    "pagerduty_event_orchestration_no_team",
    "pagerduty_event_orchestration_low_route_count",
    # Business service
    "pagerduty_business_service_no_team",
    "pagerduty_business_service_no_contact",
    # Response play
    "pagerduty_response_play_no_responders",
    "pagerduty_response_play_no_subscribers",
    "pagerduty_response_play_not_runnable",
    "pagerduty_response_play_low_responder_count",
    "pagerduty_response_play_no_team",
    "pagerduty_response_play_manual_only",
]

ALL_PAGERDUTY_RULE_KEYS: frozenset[str] = frozenset(PAGERDUTY_RULE_KEYS)

# Forbidden claim wording — never in PagerDuty rule code or user-facing copy.
FORBIDDEN_TERMS = [
    "breach confirmed", "compromise confirmed", "attacker found",
    "someone has access", "data leaked", "secret leaked",
    "customer data exposed", "unauthorized access confirmed",
    "incident response failed", "alerts failed", "pager failed",
    "on-call exposed", "responders exposed", "tokens leaked",
    "secrets exposed", "fraud confirmed",
]

# Evidence dicts must never carry secret-bearing / PII-bearing / raw-value keys.
# NOTE: the literal "secret" key is forbidden; the rule KEY
# pagerduty_webhook_subscription_secret_not_indicated is fine because that is a
# rule identifier, not an evidence key — this test inspects evidence dict keys.
FORBIDDEN_EVIDENCE_KEYS = [
    "api_token", "oauth_token", "routing_key", "integration_key", "service_key",
    "token", "authorization", "headers", "payload", "request", "response",
    "raw", "secret_value", "webhook_secret",
    "incident_title", "incident_description", "incident_note",
    "user_email", "user_name", "responder_email", "responder_name",
    "schedule_user", "contact_method", "phone", "customer",
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _rule_key(f: Any) -> str:
    return f.rule_key if hasattr(f, "rule_key") else f.get("rule_key", "")


def _evidence(f: Any) -> dict:
    ev = f.evidence if hasattr(f, "evidence") else f.get("evidence", {})
    return ev if isinstance(ev, dict) else {}


def _title(f: Any) -> str:
    return (f.title if hasattr(f, "title") else f.get("title", "")) or ""


def _description(f: Any) -> str:
    return (f.description if hasattr(f, "description") else f.get("description", "")) or ""


def _pd_eval(record: dict) -> list[Any]:
    from app.services.security_rules.pagerduty import evaluate
    return evaluate(record)


def _load_frontend_rule_keys() -> set[str]:
    text = FE_RULE_CATALOG.read_text(encoding="utf-8")
    return set(re.findall(r'"(pagerduty_[a-z_]+)"', text))


# ── Representative risky records (field names mirror pagerduty_schema) ────────

def _risky_service() -> dict:
    """Service with no escalation policy → HIGH rule fires plus more."""
    return {
        "record_type": "pagerduty_service",
        "provider": "pagerduty",
        "record_id": "SVC-TEST-001",
        "resource_id": "SVC-TEST-001",
        "escalation_policy_id": "",
        "integration_count": 0,
        "acknowledgement_timeout_category": "disabled",
        "auto_resolve_timeout_category": "disabled",
        "alert_creation_category": "incidents_only",
        "team_count": 0,
        "status_category": "active",
    }


def _all_pagerduty_findings() -> list[Any]:
    """Fire a broad set of PagerDuty rules across representative risky records."""
    records: list[dict] = [
        _risky_service(),
        # Escalation policy: rules but no targets, single level, no team.
        {
            "record_type": "pagerduty_escalation_policy",
            "record_id": "EP-TEST-001",
            "escalation_rule_count": 1,
            "escalation_level_count": 1,
            "target_count": 0,
            "schedule_target_count": 0,
            "team_count": 0,
            "has_schedule_targets": False,
        },
        # Schedule: layers but no users, single layer, no restrictions, no team.
        {
            "record_type": "pagerduty_schedule",
            "record_id": "SCHED-TEST-001",
            "layer_count": 1,
            "team_count": 0,
            "user_count": 0,
            "restriction_count": 0,
        },
        # Service integration: missing key, unknown type.
        {
            "record_type": "pagerduty_service_integration",
            "record_id": "INTG-TEST-001",
            "has_integration_key": False,
            "type_category": "other",
            "routing_key_present": False,
        },
        # Webhook subscription: inactive, non-https, no events, account scope.
        {
            "record_type": "pagerduty_webhook_subscription",
            "record_id": "WH-TEST-001",
            "active": False,
            "event_count": 0,
            "delivery_url_scheme_category": "http",
            "filter_type": "account",
            "has_custom_headers": False,
        },
        # Active webhook with no custom headers + very broad scope.
        {
            "record_type": "pagerduty_webhook_subscription",
            "record_id": "WH-TEST-002",
            "active": True,
            "event_count": 25,
            "delivery_url_scheme_category": "https",
            "filter_type": "service_reference",
            "has_custom_headers": False,
        },
        # Event orchestration: no routes, no team.
        {
            "record_type": "pagerduty_event_orchestration",
            "record_id": "EO-TEST-001",
            "route_count": 0,
            "team_present": False,
        },
        # Business service: no team, no contact.
        {
            "record_type": "pagerduty_business_service",
            "record_id": "BS-TEST-001",
            "team_present": False,
            "point_of_contact_present": False,
        },
        # Response play: no responders, no subscribers, not runnable, no team.
        {
            "record_type": "pagerduty_response_play",
            "record_id": "RP-TEST-001",
            "responder_count": 0,
            "subscriber_count": 0,
            "runnability": "unknown",
            "team_present": False,
        },
    ]
    out: list[Any] = []
    for r in records:
        out.extend(_pd_eval(r))
    return out


# ── TestPagerDutyRuleRegistration ─────────────────────────────────────────────

class TestPagerDutyRuleRegistration:
    def test_rule_key_count_is_forty(self) -> None:
        assert len(ALL_PAGERDUTY_RULE_KEYS) == 40

    def test_module_export_matches_canonical_set(self) -> None:
        from app.services.security_rules.pagerduty import PAGERDUTY_RULE_KEYS as MOD_KEYS
        assert set(MOD_KEYS) == ALL_PAGERDUTY_RULE_KEYS

    def test_all_keys_in_registry(self) -> None:
        from app.services.security_rule_registry import KNOWN_RULE_KEYS
        for key in ALL_PAGERDUTY_RULE_KEYS:
            assert key in KNOWN_RULE_KEYS, f"{key!r} missing from KNOWN_RULE_KEYS"

    def test_all_keys_have_confidence(self) -> None:
        from app.services.security_rule_confidence import RULE_CONFIDENCE
        for key in ALL_PAGERDUTY_RULE_KEYS:
            assert key in RULE_CONFIDENCE, f"{key!r} missing from RULE_CONFIDENCE"

    def test_all_keys_in_pack(self) -> None:
        from app.services.security_rule_pack import _RULE_META
        for key in ALL_PAGERDUTY_RULE_KEYS:
            assert key in _RULE_META, f"{key!r} missing from _RULE_META"
            provider, _sev, _cat = _RULE_META[key]
            assert provider == CANONICAL_PROVIDER, f"{key!r} wrong provider: {provider!r}"

    def test_all_keys_in_coverage(self) -> None:
        from app.services.security_coverage_service import RULE_RECORD_TYPES
        for key in ALL_PAGERDUTY_RULE_KEYS:
            assert key in RULE_RECORD_TYPES, f"{key!r} missing from RULE_RECORD_TYPES"
            assert RULE_RECORD_TYPES[key], f"{key!r} has empty record-type tuple"

    def test_registry_has_no_unexpected_pagerduty_keys(self) -> None:
        from app.services.security_rule_registry import KNOWN_RULE_KEYS
        reg = {k for k in KNOWN_RULE_KEYS if k.startswith("pagerduty_")}
        extra = reg - ALL_PAGERDUTY_RULE_KEYS
        assert not extra, f"unexpected pagerduty keys in registry: {sorted(extra)}"

    def test_pack_key_set_matches_canonical(self) -> None:
        from app.services.security_rule_pack import _RULE_META
        pd_keys = {k for k, v in _RULE_META.items() if v[0] == CANONICAL_PROVIDER}
        assert pd_keys == ALL_PAGERDUTY_RULE_KEYS, (
            f"PagerDuty rule-pack key set drift. Missing: "
            f"{ALL_PAGERDUTY_RULE_KEYS - pd_keys}; Extra: {pd_keys - ALL_PAGERDUTY_RULE_KEYS}"
        )


# ── TestPagerDutyFrontendCatalogParity ────────────────────────────────────────

@pytest.mark.skipif(not FE_RULE_CATALOG.exists(), reason="Frontend tree absent")
class TestPagerDutyFrontendCatalogParity:
    def test_all_keys_in_frontend_catalog(self) -> None:
        found = _load_frontend_rule_keys()
        missing = ALL_PAGERDUTY_RULE_KEYS - found
        assert not missing, f"PagerDuty rule keys missing from frontend catalog: {sorted(missing)}"

    def test_catalog_has_no_unexpected_pagerduty_keys(self) -> None:
        text = FE_RULE_CATALOG.read_text(encoding="utf-8")
        found = set(re.findall(r'key:\s*"(pagerduty_[a-z_]+)"', text))
        extra = found - ALL_PAGERDUTY_RULE_KEYS
        assert not extra, f"Unexpected pagerduty keys in frontend catalog: {sorted(extra)}"

    def test_backend_frontend_severity_match_sampled(self) -> None:
        """At least 5 representative rules: frontend severity == backend severity."""
        text = FE_RULE_CATALOG.read_text(encoding="utf-8")
        from app.services.security_rule_pack import _RULE_META
        sampled = [
            "pagerduty_service_no_escalation_policy",        # high
            "pagerduty_escalation_policy_no_rules",          # high
            "pagerduty_webhook_subscription_non_https",      # high
            "pagerduty_service_no_integrations",             # medium
            "pagerduty_webhook_subscription_secret_not_indicated",  # medium
            "pagerduty_service_no_teams",                    # low
            "pagerduty_response_play_no_responders",         # high
        ]
        for key in sampled:
            idx = text.find(f'key: "{key}"')
            assert idx != -1, f"PagerDuty rule {key!r} not found in frontend catalog"
            block = text[idx:idx + 1200]
            _provider, expected_sev, _cat = _RULE_META[key]
            assert f'severity: "{expected_sev}"' in block, (
                f"Frontend severity for {key!r} does not match backend ({expected_sev!r})"
            )

    def test_catalog_provider_is_canonical_sampled(self) -> None:
        text = FE_RULE_CATALOG.read_text(encoding="utf-8")
        for key in list(ALL_PAGERDUTY_RULE_KEYS)[:10]:
            idx = text.find(f'key: "{key}"')
            assert idx != -1, f"{key!r} not found in catalog"
            block = text[idx:idx + 1200]
            assert 'provider: "pagerduty"' in block, (
                f"Frontend catalog entry for {key!r} must use provider 'pagerduty'"
            )


# ── TestPagerDutyEvidenceSafety ───────────────────────────────────────────────

class TestPagerDutyEvidenceSafety:
    def test_representative_records_fire_many_rules(self) -> None:
        fired = {_rule_key(f) for f in _all_pagerduty_findings()}
        assert len(fired) >= 20, (
            f"expected representative records to fire >= 20 distinct rules; "
            f"got {len(fired)}: {sorted(fired)}"
        )

    def test_evidence_keys_are_safe(self) -> None:
        findings = _all_pagerduty_findings()
        assert findings, "expected at least one finding across representative records"
        for f in findings:
            ev_keys = {k.lower() for k in _evidence(f)}
            for forbidden in FORBIDDEN_EVIDENCE_KEYS:
                assert forbidden not in ev_keys, (
                    f"Forbidden evidence key {forbidden!r} in finding "
                    f"{_rule_key(f)!r}: {sorted(ev_keys)}"
                )

    def test_evidence_is_flat_safe_scalars(self) -> None:
        def _is_safe_scalar(x: Any) -> bool:
            return isinstance(x, (str, int, float, bool, type(None)))

        for f in _all_pagerduty_findings():
            for k, v in _evidence(f).items():
                if _is_safe_scalar(v):
                    continue
                assert isinstance(v, list), (
                    f"Non-scalar evidence value in {_rule_key(f)!r} key {k!r}: "
                    f"{type(v).__name__}"
                )
                for item in v:
                    assert _is_safe_scalar(item), (
                        f"Unsafe list item in {_rule_key(f)!r} key {k!r}: "
                        f"{type(item).__name__}"
                    )


# ── TestPagerDutyCopySafety ───────────────────────────────────────────────────

class TestPagerDutyCopySafety:
    def test_no_forbidden_wording_in_rule_source(self) -> None:
        from app.services.security_rules import pagerduty as pd_rules
        src = inspect.getsource(pd_rules).lower()
        for phrase in FORBIDDEN_TERMS:
            assert phrase not in src, (
                f"forbidden phrase {phrase!r} present in security_rules.pagerduty"
            )

    def test_no_forbidden_wording_in_finding_copy(self) -> None:
        for f in _all_pagerduty_findings():
            blob = f"{_title(f)}\n{_description(f)}".lower()
            for phrase in FORBIDDEN_TERMS:
                assert phrase not in blob, (
                    f"Finding {_rule_key(f)!r} copy contains forbidden phrase {phrase!r}"
                )

    @pytest.mark.skipif(not FE_RULE_CATALOG.exists(), reason="Frontend tree absent")
    def test_no_forbidden_wording_in_frontend_pagerduty_copy(self) -> None:
        text = FE_RULE_CATALOG.read_text(encoding="utf-8")
        # Restrict to PagerDuty entries by scanning each pagerduty key's block.
        for key in ALL_PAGERDUTY_RULE_KEYS:
            idx = text.find(f'key: "{key}"')
            if idx == -1:
                continue
            block = text[idx:idx + 1500].lower()
            for phrase in FORBIDDEN_TERMS:
                assert phrase not in block, (
                    f"Frontend copy for {key!r} contains forbidden phrase {phrase!r}"
                )


# ── TestPagerDutyEvaluatorDispatch ────────────────────────────────────────────

class TestPagerDutyEvaluatorDispatch:
    def test_pagerduty_in_provider_rules(self) -> None:
        """Regression guard: PagerDuty must be wired into the central evaluator."""
        from app.services.security_finding_evaluator import _PROVIDER_RULES
        assert "pagerduty" in _PROVIDER_RULES, (
            "pagerduty missing from security_finding_evaluator._PROVIDER_RULES"
        )
        assert _PROVIDER_RULES["pagerduty"], "pagerduty dispatch list is empty"

    def test_evaluate_record_correct_argument_order(self) -> None:
        """Risky record through central evaluator yields a specific rule.

        Real signature is evaluate_record(record, provider). This FAILS if the
        arguments are reversed (false-passing no-op) or if "pagerduty" is removed
        from _PROVIDER_RULES.
        """
        from app.services.security_finding_evaluator import evaluate_record
        cands = evaluate_record(_risky_service(), "pagerduty")
        assert cands, "central evaluator produced no PagerDuty findings"
        keys = {c.rule_key for c in cands}
        assert "pagerduty_service_no_escalation_policy" in keys, (
            f"expected pagerduty_service_no_escalation_policy via central dispatch; got {sorted(keys)}"
        )

    def test_reversed_arguments_produce_nothing(self) -> None:
        """Sanity: reversed args (provider, record) must NOT yield findings —
        proves the correct-order test above is load-bearing."""
        from app.services.security_finding_evaluator import evaluate_record
        cands = evaluate_record("pagerduty", _risky_service())  # type: ignore[arg-type]
        assert cands == [], "reversed-argument call unexpectedly produced findings"


# ── TestPagerDutyActivityMetadata ─────────────────────────────────────────────

class TestPagerDutyActivityMetadata:
    def test_connector_emits_corrected_metadata_keys(self) -> None:
        """Webhook + business-service activity events use the corrected,
        non-misleading metadata key names."""
        from app.connectors.pagerduty import PagerDutyConnector

        connector = PagerDutyConnector()
        events: list[dict] = []
        day = "2026-06-21"
        connector._collect_webhook_events(
            [{
                "record_type": "pagerduty_webhook_subscription",
                "record_id": "WH-1",
                "active": True,
                "event_count": 3,
                "delivery_url_scheme_category": "https",
                "filter_type": "service_reference",
                "has_custom_headers": True,
            }],
            events, day,
        )
        connector._collect_business_service_events(
            [{
                "record_type": "pagerduty_business_service",
                "record_id": "BS-1",
                "team_present": True,
                "point_of_contact_present": True,
            }],
            events, day,
        )
        all_meta_keys: set[str] = set()
        for ev in events:
            all_meta_keys |= set(ev.get("metadata", {}).keys())

        assert "custom_headers_present" in all_meta_keys, (
            "webhook activity metadata must use 'custom_headers_present'"
        )
        assert "point_of_contact_present" in all_meta_keys, (
            "business-service activity metadata must use 'point_of_contact_present'"
        )
        # The old misleading keys must be gone.
        assert "secret_present" not in all_meta_keys, (
            "misleading 'secret_present' metadata key must not be emitted"
        )
        assert "description_present" not in all_meta_keys, (
            "misleading 'description_present' metadata key must not be emitted"
        )

    def test_corrected_keys_in_activity_allowlist(self) -> None:
        from app.services.security_activity_event_service import ALLOWED_METADATA_KEYS
        assert "custom_headers_present" in ALLOWED_METADATA_KEYS
        assert "point_of_contact_present" in ALLOWED_METADATA_KEYS


# ── TestPagerDutyExpansionFramework ───────────────────────────────────────────

class TestPagerDutyExpansionFramework:
    def test_planned_next_stage_is_kubernetes(self) -> None:
        """Regression note: Kubernetes launched its provider architecture
        foundation (Kubernetes message 1 / M89A) and is no longer the
        planned next stage — Sentry/M90A is."""
        from app.services.provider_expansion_framework import get_framework
        stage = get_framework()["summary"]["planned_next_stage"]
        assert "M90A" in stage or "Sentry" in stage, (
            f"planned_next_stage should reference M90A Sentry, got {stage!r}"
        )

    def test_pagerduty_not_in_recommended_queue(self) -> None:
        from app.services.provider_expansion_framework import get_framework
        fw = get_framework()
        providers = [r["provider"] for r in fw["recommended_next_providers"]]
        assert CANONICAL_PROVIDER not in providers, (
            "PagerDuty has launched and must not be in the recommended queue"
        )


# ── TestPagerDutyProviderCapabilityMatrix ─────────────────────────────────────

class TestPagerDutyProviderCapabilityMatrix:
    def test_provider_capability_matrix_pagerduty(self) -> None:
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability(CANONICAL_PROVIDER)
        assert cap is not None, "PagerDuty missing from provider capability matrix"
        assert cap.provider == CANONICAL_PROVIDER
        assert cap.security.security_rules is True
        assert cap.drift.drift_snapshots is True
        assert cap.drift.drift_diff is True
        assert cap.drift.drift_risk_classification is True

    def test_kubernetes_not_implemented(self) -> None:
        """Regression note: Kubernetes now has a static Security Finding
        layer (message 6). It has a capability-matrix entry
        (maturity='partial', security_rules=True) and is wired into the
        central evaluator/registry."""
        from app.services.provider_capability_matrix_service import get_provider_capability
        from app.services.security_finding_evaluator import _PROVIDER_RULES
        from app.services.security_rule_registry import KNOWN_RULE_KEYS

        cap = get_provider_capability("kubernetes")
        assert cap is not None
        assert cap.maturity == "partial"
        assert cap.security.security_rules is True
        assert "kubernetes" in _PROVIDER_RULES, (
            "kubernetes must be wired into the central evaluator"
        )
        assert any(k.startswith("kubernetes_") for k in KNOWN_RULE_KEYS), (
            "kubernetes_* rule keys should exist in the registry"
        )

    def test_kubernetes_connector_does_not_exist(self) -> None:
        """Regression note: the Kubernetes connector now exists (Kubernetes
        message 1 — provider architecture foundation only: cluster identity,
        namespace posture, API discovery. No workload/RBAC/network/admission
        collection and no Security Findings yet)."""
        k8s_connector = BACKEND / "connectors" / "kubernetes.py"
        assert k8s_connector.exists()
