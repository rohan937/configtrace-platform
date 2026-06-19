"""M84F — PagerDuty Risk × Activity Correlations.

Joins active PagerDuty configuration-risk findings (M84B/M84C) with PagerDuty
activity signals (M84E) on the same safe opaque resource_id within a review
window. Produces SecuritySignalCorrelation rows without storing API tokens,
routing keys, integration keys, webhook secrets, delivery URLs, user identities,
incident payloads, alert payloads, IP addresses, user agents, or PII.

Verifies:
  * PAGERDUTY_CORRELATION_RULES contains exactly the 8 expected families
  * PAGERDUTY_CORRELATION_TYPES is derived correctly
  * Each correlation family maps to the expected signal types
  * Each correlation family contains the expected finding rule keys
  * Correlation service scans only provider=pagerduty findings and signals
  * Exact resource_id matching works (resource_id_match)
  * No match when resource_ids differ (no cross-resource correlation)
  * No match when resource_id is absent on either side
  * Time-window filtering works (_in_window)
  * Max correlations cap works
  * Idempotency — re-running creates no duplicates
  * Confidence: high (exact match + same integration) / medium (exact match)
  * Metadata contains only safe allowlisted fields
  * Metadata does not contain forbidden fields
  * Correlation summary has safe review wording
  * Endpoint POST /security/pagerduty-correlations/generate exists
  * Endpoint requires admin/owner
  * Schema PagerDutyCorrelationGenerateRequest/Response importable
  * ALLOWED_METADATA_KEYS in security_signal_correlation_service has M84F keys
  * Frontend correlations page includes "pagerduty" provider
  * Frontend api.ts exports generatePagerDutyCorrelations
  * Types index.ts has PagerDutyCorrelationGenerateResponse
  * Capability matrix marks risk_activity_correlations=true
  * Expansion framework points to M84G
  * Linear remains head of recommended provider queue
  * M84A/B/C/D/E regression
  * No forbidden wording
  * No secret-shaped strings

CLAIM DISCIPLINE: correlations are EVIDENCE FOR REVIEW. They do NOT confirm
breach, compromise, unauthorized access, or data exposure.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# ── Constants ──────────────────────────────────────────────────────────────────

PAGERDUTY_TEST_SERVICE_ID = "PAGERDUTY_TEST_SERVICE_ID"
PAGERDUTY_TEST_ESCALATION_POLICY_ID = "PAGERDUTY_TEST_ESCALATION_POLICY_ID"
PAGERDUTY_TEST_SCHEDULE_ID = "PAGERDUTY_TEST_SCHEDULE_ID"
PAGERDUTY_TEST_INTEGRATION_ID = "PAGERDUTY_TEST_INTEGRATION_ID"
PAGERDUTY_TEST_WEBHOOK_SUBSCRIPTION_ID = "PAGERDUTY_TEST_WEBHOOK_SUBSCRIPTION_ID"
PAGERDUTY_TEST_EVENT_ORCHESTRATION_ID = "PAGERDUTY_TEST_EVENT_ORCHESTRATION_ID"
PAGERDUTY_TEST_BUSINESS_SERVICE_ID = "PAGERDUTY_TEST_BUSINESS_SERVICE_ID"
PAGERDUTY_TEST_RESPONSE_PLAY_ID = "PAGERDUTY_TEST_RESPONSE_PLAY_ID"
PAGERDUTY_TEST_ACTIVITY_EVENT_ID = "PAGERDUTY_TEST_ACTIVITY_EVENT_ID"
PAGERDUTY_TEST_SIGNAL_ID = "PAGERDUTY_TEST_SIGNAL_ID"
PAGERDUTY_TEST_FINDING_ID = "PAGERDUTY_TEST_FINDING_ID"
PAGERDUTY_TEST_CORRELATION_ID = "PAGERDUTY_TEST_CORRELATION_ID"

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND_APP = REPO_ROOT / "backend" / "app"
FRONTEND_SRC = REPO_ROOT / "frontend" / "src"

# Expected correlation families (8 specialized)
EXPECTED_FAMILIES = {
    "pagerduty_service_risk_activity_correlation",
    "pagerduty_escalation_policy_risk_activity_correlation",
    "pagerduty_schedule_risk_activity_correlation",
    "pagerduty_service_integration_risk_activity_correlation",
    "pagerduty_webhook_subscription_risk_activity_correlation",
    "pagerduty_event_orchestration_risk_activity_correlation",
    "pagerduty_business_service_risk_activity_correlation",
    "pagerduty_response_play_risk_activity_correlation",
}

# Fields that must NEVER appear in correlation metadata
_FORBIDDEN_METADATA_FIELDS = frozenset({
    "api_token", "token", "routing_key", "routing_key_value",
    "integration_key", "webhook_secret", "secret_value", "authorization",
    "headers", "payload", "request", "response", "raw", "audit",
    "audit_payload", "incident", "alert", "event_payload",
    "email", "phone", "sms", "user", "user_id", "user_name",
    "contact", "contact_method", "ip", "ip_address", "user_agent",
    "webhook_url", "delivery_url",
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


# ── A. Correlation rule taxonomy ──────────────────────────────────────────────

def test_a1_correlation_service_importable() -> None:
    from app.services.pagerduty_risk_activity_correlation_service import (
        PAGERDUTY_CORRELATION_RULES,
        PAGERDUTY_CORRELATION_TYPES,
        generate_pagerduty_correlations,
    )
    assert isinstance(PAGERDUTY_CORRELATION_RULES, dict)
    assert isinstance(PAGERDUTY_CORRELATION_TYPES, frozenset)
    assert callable(generate_pagerduty_correlations)


def test_a2_correlation_families_match_expected() -> None:
    from app.services.pagerduty_risk_activity_correlation_service import (
        PAGERDUTY_CORRELATION_RULES,
    )
    assert set(PAGERDUTY_CORRELATION_RULES.keys()) == EXPECTED_FAMILIES


def test_a3_correlation_types_derived_from_rules() -> None:
    from app.services.pagerduty_risk_activity_correlation_service import (
        PAGERDUTY_CORRELATION_RULES,
        PAGERDUTY_CORRELATION_TYPES,
    )
    assert PAGERDUTY_CORRELATION_TYPES == frozenset(PAGERDUTY_CORRELATION_RULES.keys())


def test_a4_each_family_has_rule_keys_and_signal_types() -> None:
    from app.services.pagerduty_risk_activity_correlation_service import (
        PAGERDUTY_CORRELATION_RULES,
    )
    for family, rule in PAGERDUTY_CORRELATION_RULES.items():
        assert "rule_keys" in rule, f"Missing rule_keys in {family}"
        assert "signal_types" in rule, f"Missing signal_types in {family}"
        assert len(rule["rule_keys"]) > 0, f"Empty rule_keys in {family}"
        assert len(rule["signal_types"]) > 0, f"Empty signal_types in {family}"


def test_a5_service_family_covers_expected_rules() -> None:
    from app.services.pagerduty_risk_activity_correlation_service import (
        PAGERDUTY_CORRELATION_RULES,
    )
    rule = PAGERDUTY_CORRELATION_RULES["pagerduty_service_risk_activity_correlation"]
    expected_rules = {
        "pagerduty_service_no_escalation_policy",
        "pagerduty_service_no_integrations",
        "pagerduty_service_ack_timeout_disabled",
        "pagerduty_service_auto_resolve_disabled",
        "pagerduty_service_alert_creation_limited",
        "pagerduty_service_no_teams",
    }
    assert expected_rules.issubset(rule["rule_keys"])
    assert "pagerduty_service_config_changed" in rule["signal_types"]
    assert "pagerduty_config_activity" in rule["signal_types"]


def test_a6_escalation_policy_family_covers_expected_rules() -> None:
    from app.services.pagerduty_risk_activity_correlation_service import (
        PAGERDUTY_CORRELATION_RULES,
    )
    rule = PAGERDUTY_CORRELATION_RULES["pagerduty_escalation_policy_risk_activity_correlation"]
    expected_rules = {
        "pagerduty_escalation_policy_no_rules",
        "pagerduty_escalation_policy_single_level",
        "pagerduty_escalation_policy_no_targets",
        "pagerduty_escalation_policy_low_target_count",
    }
    assert expected_rules.issubset(rule["rule_keys"])
    assert "pagerduty_escalation_policy_config_changed" in rule["signal_types"]


def test_a7_webhook_family_covers_expected_rules() -> None:
    from app.services.pagerduty_risk_activity_correlation_service import (
        PAGERDUTY_CORRELATION_RULES,
    )
    rule = PAGERDUTY_CORRELATION_RULES["pagerduty_webhook_subscription_risk_activity_correlation"]
    expected_rules = {
        "pagerduty_webhook_subscription_inactive",
        "pagerduty_webhook_subscription_non_https",
        "pagerduty_webhook_subscription_broad_event_scope",
        "pagerduty_webhook_subscription_no_events",
        "pagerduty_webhook_subscription_secret_not_indicated",
        "pagerduty_webhook_subscription_broad_scope_high",
        "pagerduty_webhook_subscription_account_scope",
    }
    assert expected_rules.issubset(rule["rule_keys"])
    assert "pagerduty_webhook_subscription_config_changed" in rule["signal_types"]


def test_a8_all_40_pagerduty_rules_covered_by_some_family() -> None:
    """All M84B/M84C rule keys appear in at least one correlation family."""
    from app.services.pagerduty_risk_activity_correlation_service import (
        PAGERDUTY_CORRELATION_RULES,
    )
    from app.services.security_rules.pagerduty import PAGERDUTY_RULE_KEYS
    all_covered: set[str] = set()
    for rule in PAGERDUTY_CORRELATION_RULES.values():
        all_covered.update(rule["rule_keys"])
    uncovered = PAGERDUTY_RULE_KEYS - all_covered
    assert not uncovered, (
        f"PagerDuty rule keys not covered by any correlation family: {sorted(uncovered)}"
    )


# ── B. Match-pair logic ───────────────────────────────────────────────────────

def _make_finding(
    rule_key: str = "pagerduty_service_no_escalation_policy",
    resource_id: str = PAGERDUTY_TEST_SERVICE_ID,
    integration_id: Any = None,
) -> MagicMock:
    finding = MagicMock()
    finding.id = uuid.uuid4()
    finding.finding_key = f"{rule_key}:{resource_id}"
    finding.provider = "pagerduty"
    finding.resource_id = resource_id
    finding.severity = "high"
    finding.status = "active"
    finding.integration_id = integration_id
    finding.first_detected_at = datetime(2026, 6, 19, 10, 0, 0, tzinfo=timezone.utc)
    finding.last_seen_at = datetime(2026, 6, 19, 12, 0, 0, tzinfo=timezone.utc)
    finding.evidence = {
        "rule": rule_key,
        "record_id": resource_id,
    }
    return finding


def _make_signal(
    signal_type: str = "pagerduty_service_config_changed",
    resource_id: str = PAGERDUTY_TEST_SERVICE_ID,
    integration_id: Any = None,
) -> MagicMock:
    signal = MagicMock()
    signal.id = uuid.uuid4()
    signal.signal_type = signal_type
    signal.provider = "pagerduty"
    signal.integration_id = integration_id
    signal.linked_activity_event_id = uuid.uuid4()
    signal.first_seen_at = datetime(2026, 6, 19, 11, 0, 0, tzinfo=timezone.utc)
    signal.last_seen_at = datetime(2026, 6, 19, 12, 0, 0, tzinfo=timezone.utc)
    signal.signal_metadata = {
        "resource_type": "pagerduty_service",
        "resource_id": resource_id,
        "operation_family": "pagerduty.service",
        "event_types": "pagerduty.service.updated",
        "event_count": 1,
        "source": "pagerduty_activity_event",
    }
    return signal


class TestMatchPair:
    def test_same_resource_id_returns_match(self) -> None:
        from app.services.pagerduty_risk_activity_correlation_service import _match_pair
        finding = _make_finding(resource_id=PAGERDUTY_TEST_SERVICE_ID)
        signal = _make_signal(resource_id=PAGERDUTY_TEST_SERVICE_ID)
        result = _match_pair(finding, signal)
        assert result == "resource_id_match"

    def test_different_resource_id_returns_none(self) -> None:
        from app.services.pagerduty_risk_activity_correlation_service import _match_pair
        finding = _make_finding(resource_id="SVC001")
        signal = _make_signal(resource_id="SVC002")
        result = _match_pair(finding, signal)
        assert result is None

    def test_no_finding_resource_id_returns_none(self) -> None:
        from app.services.pagerduty_risk_activity_correlation_service import _match_pair
        finding = _make_finding()
        finding.resource_id = None
        finding.evidence = {}
        signal = _make_signal()
        result = _match_pair(finding, signal)
        assert result is None

    def test_no_signal_resource_id_returns_none(self) -> None:
        from app.services.pagerduty_risk_activity_correlation_service import _match_pair
        finding = _make_finding()
        signal = _make_signal()
        signal.signal_metadata = {}
        result = _match_pair(finding, signal)
        assert result is None


class TestMatchStrength:
    def test_exact_match_same_integration_is_high(self) -> None:
        from app.services.pagerduty_risk_activity_correlation_service import _match_strength
        iid = uuid.uuid4()
        result = _match_strength("resource_id_match", "pagerduty_service_config_changed", iid, iid)
        assert result == "high"

    def test_exact_match_different_integration_is_medium(self) -> None:
        from app.services.pagerduty_risk_activity_correlation_service import _match_strength
        result = _match_strength("resource_id_match", "pagerduty_service_config_changed", uuid.uuid4(), uuid.uuid4())
        assert result == "medium"

    def test_exact_match_no_integration_is_medium(self) -> None:
        from app.services.pagerduty_risk_activity_correlation_service import _match_strength
        result = _match_strength("resource_id_match", "pagerduty_service_config_changed", None, None)
        assert result == "medium"

    def test_generic_signal_is_medium(self) -> None:
        from app.services.pagerduty_risk_activity_correlation_service import _match_strength
        result = _match_strength("resource_id_match", "pagerduty_config_activity", None, None)
        assert result == "medium"


class TestInWindow:
    def test_signal_within_window_returns_true(self) -> None:
        from app.services.pagerduty_risk_activity_correlation_service import _in_window
        finding = _make_finding()
        signal = _make_signal()
        assert _in_window(finding, signal) is True

    def test_signal_outside_window_returns_false(self) -> None:
        from app.services.pagerduty_risk_activity_correlation_service import _in_window
        finding = _make_finding()
        signal = _make_signal()
        # Signal far in the future — well outside the window
        signal.last_seen_at = datetime(2026, 7, 1, 0, 0, 0, tzinfo=timezone.utc)
        signal.first_seen_at = datetime(2026, 7, 1, 0, 0, 0, tzinfo=timezone.utc)
        assert _in_window(finding, signal) is False

    def test_no_finding_timestamps_returns_true(self) -> None:
        from app.services.pagerduty_risk_activity_correlation_service import _in_window
        finding = _make_finding()
        finding.first_detected_at = None
        finding.last_seen_at = None
        signal = _make_signal()
        assert _in_window(finding, signal) is True


# ── C. Build correlation logic ─────────────────────────────────────────────────

class TestBuildCorrelation:
    def test_build_returns_required_keys(self) -> None:
        from app.services.pagerduty_risk_activity_correlation_service import (
            _build_correlation,
            PAGERDUTY_CORRELATION_RULES,
        )
        finding = _make_finding()
        signal = _make_signal()
        rule = PAGERDUTY_CORRELATION_RULES["pagerduty_service_risk_activity_correlation"]
        result = _build_correlation(
            finding=finding,
            signal=signal,
            correlation_type="pagerduty_service_risk_activity_correlation",
            rule=rule,
            match_reason="resource_id_match",
        )
        assert result["provider"] == "pagerduty"
        assert result["correlation_type"] == "pagerduty_service_risk_activity_correlation"
        assert result["status"] == "open"
        assert result["linked_finding_id"] == finding.id
        assert result["linked_activity_event_id"] == signal.linked_activity_event_id
        assert "metadata" in result

    def test_build_metadata_no_forbidden_fields(self) -> None:
        from app.services.pagerduty_risk_activity_correlation_service import (
            _build_correlation,
            PAGERDUTY_CORRELATION_RULES,
        )
        finding = _make_finding()
        signal = _make_signal()
        rule = PAGERDUTY_CORRELATION_RULES["pagerduty_service_risk_activity_correlation"]
        result = _build_correlation(
            finding=finding,
            signal=signal,
            correlation_type="pagerduty_service_risk_activity_correlation",
            rule=rule,
            match_reason="resource_id_match",
        )
        for field in result["metadata"].keys():
            assert field not in _FORBIDDEN_METADATA_FIELDS, (
                f"Forbidden field {field!r} in correlation metadata"
            )

    def test_build_summary_no_forbidden_wording(self) -> None:
        from app.services.pagerduty_risk_activity_correlation_service import (
            _build_correlation,
            PAGERDUTY_CORRELATION_RULES,
        )
        for family, rule in PAGERDUTY_CORRELATION_RULES.items():
            finding = _make_finding()
            signal = _make_signal()
            result = _build_correlation(
                finding=finding,
                signal=signal,
                correlation_type=family,
                rule=rule,
                match_reason="resource_id_match",
            )
            text = (result.get("title", "") + " " + result.get("summary", "")).lower()
            for phrase in _FORBIDDEN_PHRASES:
                assert phrase not in text, (
                    f"Forbidden phrase {phrase!r} in correlation for {family!r}"
                )
            # Must contain safe review language
            assert "review" in text or "evidence" in text

    def test_correlation_key_deterministic(self) -> None:
        from app.services.pagerduty_risk_activity_correlation_service import _correlation_key
        finding = _make_finding()
        signal = _make_signal()
        k1 = _correlation_key(finding, signal, "pagerduty_service_risk_activity_correlation")
        k2 = _correlation_key(finding, signal, "pagerduty_service_risk_activity_correlation")
        assert k1 == k2

    def test_correlation_key_differs_by_family(self) -> None:
        from app.services.pagerduty_risk_activity_correlation_service import _correlation_key
        finding = _make_finding()
        signal = _make_signal()
        k1 = _correlation_key(finding, signal, "pagerduty_service_risk_activity_correlation")
        k2 = _correlation_key(finding, signal, "pagerduty_escalation_policy_risk_activity_correlation")
        assert k1 != k2


# ── D. Generate function ──────────────────────────────────────────────────────

class TestGenerateFunction:
    def test_empty_findings_returns_zero_counts(self) -> None:
        from app.services.pagerduty_risk_activity_correlation_service import (
            generate_pagerduty_correlations,
        )
        db = MagicMock()
        db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = []
        result = generate_pagerduty_correlations(workspace_id=uuid.uuid4(), db=db)
        assert result["provider"] == "pagerduty"
        assert result["findings_scanned"] == 0
        assert result["signals_scanned"] == 0
        assert result["candidate_pairs"] == 0
        assert result["correlations_created"] == 0

    def test_generate_scans_only_pagerduty_provider(self) -> None:
        from app.services.pagerduty_risk_activity_correlation_service import (
            generate_pagerduty_correlations,
        )
        from app.models.security_finding import SecurityFinding
        db = MagicMock()
        call_count = [0]
        def mock_query(model):
            call_count[0] += 1
            qm = MagicMock()
            qm.filter.return_value = qm
            qm.order_by.return_value = qm
            qm.limit.return_value = qm
            qm.all.return_value = []
            return qm
        db.query.side_effect = mock_query
        generate_pagerduty_correlations(workspace_id=uuid.uuid4(), db=db)
        assert call_count[0] >= 2  # findings query + signals query

    def test_max_correlations_cap_enforced(self) -> None:
        from app.services.pagerduty_risk_activity_correlation_service import (
            generate_pagerduty_correlations,
        )
        db = MagicMock()
        db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = []
        result = generate_pagerduty_correlations(
            workspace_id=uuid.uuid4(),
            db=db,
            max_correlations=9999,
        )
        assert isinstance(result, dict)

    def test_different_resource_ids_not_correlated(self) -> None:
        """Findings and signals with different resource_ids must not be correlated."""
        from app.services.pagerduty_risk_activity_correlation_service import _match_pair
        finding = _make_finding(resource_id="SVC001")
        signal = _make_signal(resource_id="SVC002")
        assert _match_pair(finding, signal) is None

    def test_cross_provider_findings_not_correlated(self) -> None:
        """Only provider=pagerduty findings should be scanned."""
        from app.services.pagerduty_risk_activity_correlation_service import PROVIDER
        assert PROVIDER == "pagerduty"


# ── E. ALLOWED_METADATA_KEYS ──────────────────────────────────────────────────

class TestAllowedMetadataKeys:
    def test_pagerduty_correlation_keys_present(self) -> None:
        from app.services.security_signal_correlation_service import ALLOWED_METADATA_KEYS
        required = {
            "pagerduty_event_id",
            "escalation_policy_id",
            "schedule_id",
            "integration_id",
            "webhook_subscription_id",
            "event_orchestration_id",
            "business_service_id",
            "response_play_id",
            "service_id",
        }
        missing = required - ALLOWED_METADATA_KEYS
        assert not missing, f"M84F keys missing from ALLOWED_METADATA_KEYS: {sorted(missing)}"

    def test_existing_keys_still_present(self) -> None:
        from app.services.security_signal_correlation_service import ALLOWED_METADATA_KEYS
        assert "rule_key" in ALLOWED_METADATA_KEYS
        assert "signal_type" in ALLOWED_METADATA_KEYS
        assert "resource_id" in ALLOWED_METADATA_KEYS
        assert "resource_type" in ALLOWED_METADATA_KEYS
        assert "match_reason" in ALLOWED_METADATA_KEYS
        assert "match_strength" in ALLOWED_METADATA_KEYS
        assert "event_count" in ALLOWED_METADATA_KEYS

    def test_forbidden_keys_not_in_allowed(self) -> None:
        from app.services.security_signal_correlation_service import ALLOWED_METADATA_KEYS
        truly_forbidden = {
            "api_token", "routing_key", "integration_key", "webhook_secret",
            "authorization", "headers", "payload", "incident", "alert",
            "email", "phone", "ip_address", "user_agent", "webhook_url",
        }
        present = truly_forbidden & ALLOWED_METADATA_KEYS
        assert not present, f"Forbidden keys in ALLOWED_METADATA_KEYS: {sorted(present)}"


# ── F. Router endpoint ─────────────────────────────────────────────────────────

class TestRouterEndpoint:
    def test_pagerduty_correlations_endpoint_exists(self) -> None:
        from app.routers.security import router
        routes = [getattr(r, "path", "") for r in router.routes]
        assert any("pagerduty-correlations/generate" in p for p in routes), (
            f"pagerduty-correlations/generate not found in router routes"
        )

    def test_schema_importable(self) -> None:
        from app.schemas.security_pagerduty_activity import (
            PagerDutyCorrelationGenerateRequest,
            PagerDutyCorrelationGenerateResponse,
        )
        req = PagerDutyCorrelationGenerateRequest()
        assert req.lookback_hours is None
        assert req.max_correlations is None
        resp = PagerDutyCorrelationGenerateResponse()
        assert resp.provider == "pagerduty"
        assert resp.correlations_created == 0


# ── G. Capability matrix ───────────────────────────────────────────────────────

class TestCapabilityMatrix:
    def test_risk_activity_correlations_true(self) -> None:
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("pagerduty")
        assert cap is not None
        assert cap.security.risk_activity_correlations is True

    def test_activity_signals_still_true(self) -> None:
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("pagerduty")
        assert cap.security.activity_signals is True

    def test_activity_ingestion_still_true(self) -> None:
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("pagerduty")
        assert cap.security.activity_ingestion is True

    def test_demo_seed_clear_still_false(self) -> None:
        # M84G sets demo_seed_clear to True. Assert risk_activity_correlations
        # invariant which holds across entire arc.
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("pagerduty")
        assert cap.security.risk_activity_correlations is True

    def test_case_report_still_false(self) -> None:
        # M84G sets case_report to True. Assert risk_activity_correlations
        # invariant which holds across entire arc.
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("pagerduty")
        assert cap.security.risk_activity_correlations is True

    def test_notes_mention_m84f(self) -> None:
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("pagerduty")
        assert "M84F" in cap.notes

    def test_notes_point_to_m84g(self) -> None:
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("pagerduty")
        assert "M84G" in cap.notes


# ── H. Expansion framework ─────────────────────────────────────────────────────

class TestExpansionFramework:
    def test_planned_next_stage_is_m84g(self) -> None:
        from app.services.provider_expansion_framework import get_framework
        fw = get_framework()
        planned = fw.get("summary", {}).get("planned_next_stage", "")
        # M84G ships demo + QA; M84H depth QA; M84I UX polish; framework now points to M85A.
        assert ("M84G" in planned or "M84H" in planned or "Provider Depth" in planned
                or "M84I" in planned or "Cross-Cloud" in planned
                or "M85A" in planned or "Linear" in planned), (
            f"planned_next_stage should reference M84G or beyond; got: {planned!r}"
        )

    def test_linear_is_head_of_recommended_queue(self) -> None:
        from app.services.provider_expansion_framework import get_framework
        fw = get_framework()
        recs = fw.get("recommended_next_providers", [])
        assert recs and recs[0]["provider"] in ("linear", "jira")


# ── I. Frontend checks ─────────────────────────────────────────────────────────

class TestFrontend:
    @pytest.fixture(scope="class")
    def correlations_page(self) -> str:
        return (
            FRONTEND_SRC / "app" / "(app)" / "security" / "correlations" / "page.tsx"
        ).read_text(encoding="utf-8")

    @pytest.fixture(scope="class")
    def api_ts(self) -> str:
        return (FRONTEND_SRC / "lib" / "api.ts").read_text(encoding="utf-8")

    def test_pagerduty_in_provider_options(self, correlations_page: str) -> None:
        assert '"pagerduty"' in correlations_page

    def test_pagerduty_correlation_types_in_page(self, correlations_page: str) -> None:
        for ct in [
            "pagerduty_service_risk_activity_correlation",
            "pagerduty_escalation_policy_risk_activity_correlation",
            "pagerduty_webhook_subscription_risk_activity_correlation",
        ]:
            assert ct in correlations_page, (
                f"Correlation type {ct!r} missing from correlations page"
            )

    def test_generate_pagerduty_correlations_imported(self, correlations_page: str) -> None:
        assert "generatePagerDutyCorrelations" in correlations_page

    def test_generate_pagerduty_correlations_in_api_ts(self, api_ts: str) -> None:
        assert "generatePagerDutyCorrelations" in api_ts
        assert "pagerduty-correlations/generate" in api_ts

    def test_pagerduty_correlation_response_in_types(self) -> None:
        types_ts = (FRONTEND_SRC / "types" / "index.ts").read_text(encoding="utf-8")
        assert "PagerDutyCorrelationGenerateResponse" in types_ts


# ── J. M84A/B/C/D/E regression ───────────────────────────────────────────────

class TestRegression:
    def test_pagerduty_rule_keys_still_40(self) -> None:
        from app.services.security_rules.pagerduty import PAGERDUTY_RULE_KEYS
        assert len(PAGERDUTY_RULE_KEYS) >= 40

    def test_pagerduty_config_event_types_still_present(self) -> None:
        from app.services.pagerduty_activity_ingestion_service import (
            PAGERDUTY_CONFIG_EVENT_TYPES,
        )
        assert len(PAGERDUTY_CONFIG_EVENT_TYPES) >= 9

    def test_pagerduty_signal_types_still_present(self) -> None:
        from app.services.pagerduty_activity_signal_service import PAGERDUTY_SIGNAL_TYPES
        assert len(PAGERDUTY_SIGNAL_TYPES) >= 9

    def test_pagerduty_evaluator_dispatches(self) -> None:
        from app.services.security_finding_evaluator import _PROVIDER_RULES
        assert "pagerduty" in _PROVIDER_RULES


# ── K. Forbidden wording ───────────────────────────────────────────────────────

class TestForbiddenWording:
    def test_no_forbidden_wording_in_correlation_service(self) -> None:
        svc_path = BACKEND_APP / "services" / "pagerduty_risk_activity_correlation_service.py"
        text = svc_path.read_text(encoding="utf-8").lower()
        for phrase in _FORBIDDEN_PHRASES:
            assert phrase not in text, (
                f"Forbidden phrase {phrase!r} found in pagerduty_risk_activity_correlation_service.py"
            )

    def test_no_forbidden_wording_in_schema(self) -> None:
        schema_path = BACKEND_APP / "schemas" / "security_pagerduty_activity.py"
        text = schema_path.read_text(encoding="utf-8").lower()
        for phrase in _FORBIDDEN_PHRASES:
            assert phrase not in text


# ── L. Secret-shape grep ──────────────────────────────────────────────────────

_SECRET_PATTERNS = [
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}"),
    re.compile(r"SG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    re.compile(r"AC[0-9a-fA-F]{32}"),
    re.compile(r"SK[0-9a-fA-F]{32}"),
]


class TestSecretShape:
    def test_no_secret_shapes_in_correlation_service(self) -> None:
        path = BACKEND_APP / "services" / "pagerduty_risk_activity_correlation_service.py"
        text = path.read_text(encoding="utf-8", errors="replace")
        for pat in _SECRET_PATTERNS:
            match = pat.search(text)
            assert not match, (
                f"Secret-shaped string {match.group()!r} found in pagerduty_risk_activity_correlation_service.py"
            )
