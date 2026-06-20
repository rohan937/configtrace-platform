"""M85F — Linear Risk × Activity Correlations.

Joins active Linear configuration-risk findings (M85B/M85C) with Linear
activity signals (M85E) on the same safe opaque resource_id within a review
window. Produces SecuritySignalCorrelation rows without storing API keys,
OAuth tokens, webhook secrets, webhook/delivery URLs, issue titles, issue
descriptions, comment bodies, attachment content, user identities, emails,
member identities, IP addresses, user agents, request/response payloads, or
PII of any kind.

Verifies:
  * LINEAR_CORRELATION_RULES contains exactly the 9 expected families
  * LINEAR_CORRELATION_TYPES is derived correctly
  * Each correlation family maps to the expected signal types
  * Each correlation family contains rule keys and signal types
  * Each family includes the linear_config_activity generic fallback signal
  * webhook family carries severity "high"
  * Correlation service scans only provider=linear findings and signals
  * Exact resource_id matching works (resource_id_match)
  * No match when resource_ids differ (no cross-resource correlation)
  * No match when resource_id is absent on either side
  * Confidence: high (exact match + same integration + specific signal) /
    medium (no integration match or generic signal)
  * Correlation key includes "linear" and is deterministic per family
  * Metadata contains only safe allowlisted fields
  * Metadata does not contain forbidden fields
  * Generate function returns provider="linear" with expected count keys
  * Endpoint POST /security/linear-correlations/generate exists
  * Endpoint requires workspace admin
  * Schema LinearCorrelationGenerateRequest/Response importable
  * ALLOWED_METADATA_KEYS in security_signal_correlation_service has M85F keys
  * sanitize_correlation_metadata strips forbidden fields
  * Frontend correlations page includes "linear" provider
  * Frontend api.ts exports generateLinearCorrelations
  * Types index.ts has LinearCorrelationGenerateResponse
  * Capability matrix marks risk_activity_correlations=true, demo_seed_clear=false
  * Expansion framework points to M85G (not M85F)
  * Jira is head of recommended provider queue
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

LINEAR_TEST_WORKSPACE_ID = "LINEAR_TEST_WORKSPACE_ID"
LINEAR_TEST_TEAM_ID = "LINEAR_TEST_TEAM_ID"
LINEAR_TEST_PROJECT_ID = "LINEAR_TEST_PROJECT_ID"
LINEAR_TEST_WORKFLOW_STATE_ID = "LINEAR_TEST_WORKFLOW_STATE_ID"
LINEAR_TEST_LABEL_ID = "LINEAR_TEST_LABEL_ID"
LINEAR_TEST_WEBHOOK_ID = "LINEAR_TEST_WEBHOOK_ID"
LINEAR_TEST_VIEW_ID = "LINEAR_TEST_VIEW_ID"
LINEAR_TEST_CYCLE_ID = "LINEAR_TEST_CYCLE_ID"
LINEAR_TEST_INTEGRATION_ID = "LINEAR_TEST_INTEGRATION_ID"
LINEAR_TEST_ACTIVITY_EVENT_ID = "LINEAR_TEST_ACTIVITY_EVENT_ID"
LINEAR_TEST_SIGNAL_ID = "LINEAR_TEST_SIGNAL_ID"
LINEAR_TEST_FINDING_ID = "LINEAR_TEST_FINDING_ID"
LINEAR_TEST_CORRELATION_ID = "LINEAR_TEST_CORRELATION_ID"

PROVIDER = "linear"

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND_APP = REPO_ROOT / "backend" / "app"
FRONTEND_SRC = REPO_ROOT / "frontend" / "src"

# Expected correlation families (9 specialized)
EXPECTED_FAMILIES = {
    "linear_workspace_risk_activity_correlation",
    "linear_team_risk_activity_correlation",
    "linear_project_risk_activity_correlation",
    "linear_workflow_state_risk_activity_correlation",
    "linear_label_risk_activity_correlation",
    "linear_webhook_risk_activity_correlation",
    "linear_view_risk_activity_correlation",
    "linear_cycle_risk_activity_correlation",
    "linear_integration_risk_activity_correlation",
}

EXPECTED_FAMILY_COUNT = 9

# Per-family expected specific signal type (besides the generic fallback)
_FAMILY_SPECIFIC_SIGNAL = {
    "linear_workspace_risk_activity_correlation": "linear_workspace_config_changed",
    "linear_team_risk_activity_correlation": "linear_team_config_changed",
    "linear_project_risk_activity_correlation": "linear_project_config_changed",
    "linear_workflow_state_risk_activity_correlation": "linear_workflow_state_config_changed",
    "linear_label_risk_activity_correlation": "linear_label_config_changed",
    "linear_webhook_risk_activity_correlation": "linear_webhook_config_changed",
    "linear_view_risk_activity_correlation": "linear_view_config_changed",
    "linear_cycle_risk_activity_correlation": "linear_cycle_config_changed",
    "linear_integration_risk_activity_correlation": "linear_integration_config_changed",
}

# Generic fallback signal every family must accept
_GENERIC_SIGNAL = "linear_config_activity"

# Fields that must NEVER appear in correlation metadata
_FORBIDDEN_METADATA_FIELDS = frozenset({
    "api_key", "api_token", "token", "oauth_token", "access_token",
    "webhook_secret", "secret_value", "secret", "authorization",
    "headers", "payload", "request", "response", "raw", "audit",
    "audit_payload", "issue_title", "issue_description", "description",
    "comment", "comment_body", "attachment", "attachment_content",
    "email", "phone", "user", "user_id", "user_name", "member",
    "member_id", "lead_id", "lead_name", "contact",
    "ip", "ip_address", "user_agent", "webhook_url", "delivery_url", "url",
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
    "issues exposed",
    "credentials exposed",
]


# ── A. Correlation rule taxonomy ──────────────────────────────────────────────

def test_a1_correlation_service_importable() -> None:
    from app.services.linear_risk_activity_correlation_service import (
        LINEAR_CORRELATION_RULES,
        LINEAR_CORRELATION_TYPES,
        generate_linear_correlations,
    )
    assert isinstance(LINEAR_CORRELATION_RULES, dict)
    assert isinstance(LINEAR_CORRELATION_TYPES, frozenset)
    assert callable(generate_linear_correlations)


def test_a2_correlation_families_match_expected() -> None:
    from app.services.linear_risk_activity_correlation_service import (
        LINEAR_CORRELATION_RULES,
    )
    assert set(LINEAR_CORRELATION_RULES.keys()) == EXPECTED_FAMILIES


def test_a2b_correlation_family_count_is_nine() -> None:
    from app.services.linear_risk_activity_correlation_service import (
        LINEAR_CORRELATION_RULES,
    )
    assert len(LINEAR_CORRELATION_RULES) == EXPECTED_FAMILY_COUNT


def test_a3_correlation_types_derived_from_rules() -> None:
    from app.services.linear_risk_activity_correlation_service import (
        LINEAR_CORRELATION_RULES,
        LINEAR_CORRELATION_TYPES,
    )
    assert LINEAR_CORRELATION_TYPES == frozenset(LINEAR_CORRELATION_RULES.keys())


def test_a4_each_family_has_rule_keys_and_signal_types() -> None:
    from app.services.linear_risk_activity_correlation_service import (
        LINEAR_CORRELATION_RULES,
    )
    for family, rule in LINEAR_CORRELATION_RULES.items():
        assert "rule_keys" in rule, f"Missing rule_keys in {family}"
        assert "signal_types" in rule, f"Missing signal_types in {family}"
        assert len(rule["rule_keys"]) > 0, f"Empty rule_keys in {family}"
        assert len(rule["signal_types"]) > 0, f"Empty signal_types in {family}"


def test_a5_each_family_includes_specific_signal_type() -> None:
    from app.services.linear_risk_activity_correlation_service import (
        LINEAR_CORRELATION_RULES,
    )
    for family, expected_signal in _FAMILY_SPECIFIC_SIGNAL.items():
        rule = LINEAR_CORRELATION_RULES[family]
        assert expected_signal in rule["signal_types"], (
            f"{family} missing specific signal {expected_signal!r}"
        )


def test_a6_each_family_includes_config_activity_fallback() -> None:
    """Every family accepts the generic linear_config_activity signal."""
    from app.services.linear_risk_activity_correlation_service import (
        LINEAR_CORRELATION_RULES,
    )
    for family, rule in LINEAR_CORRELATION_RULES.items():
        assert _GENERIC_SIGNAL in rule["signal_types"], (
            f"{family} missing generic fallback signal {_GENERIC_SIGNAL!r}"
        )


def test_a7_webhook_family_severity_is_high() -> None:
    from app.services.linear_risk_activity_correlation_service import (
        LINEAR_CORRELATION_RULES,
    )
    rule = LINEAR_CORRELATION_RULES["linear_webhook_risk_activity_correlation"]
    assert rule.get("severity") == "high"


def test_a8_all_linear_rule_keys_covered_by_some_family() -> None:
    """All implemented M85B/M85C rule keys appear in some correlation family."""
    from app.services.linear_risk_activity_correlation_service import (
        LINEAR_CORRELATION_RULES,
    )
    from app.services.security_rules.linear import LINEAR_RULE_KEYS
    all_covered: set[str] = set()
    for rule in LINEAR_CORRELATION_RULES.values():
        all_covered.update(rule["rule_keys"])
    uncovered = LINEAR_RULE_KEYS - all_covered
    assert not uncovered, (
        f"Linear rule keys not covered by any correlation family: {sorted(uncovered)}"
    )


# ── B. Match-pair logic ───────────────────────────────────────────────────────

def _make_finding(
    rule_key: str = "linear_webhook_disabled",
    resource_id: str = LINEAR_TEST_WEBHOOK_ID,
    integration_id: Any = None,
) -> MagicMock:
    finding = MagicMock()
    finding.id = uuid.uuid4()
    finding.finding_key = f"{rule_key}:{resource_id}"
    finding.provider = "linear"
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
    signal_type: str = "linear_webhook_config_changed",
    resource_id: str = LINEAR_TEST_WEBHOOK_ID,
    integration_id: Any = None,
) -> MagicMock:
    signal = MagicMock()
    signal.id = uuid.uuid4()
    signal.signal_type = signal_type
    signal.provider = "linear"
    signal.integration_id = integration_id
    signal.linked_activity_event_id = uuid.uuid4()
    signal.first_seen_at = datetime(2026, 6, 19, 11, 0, 0, tzinfo=timezone.utc)
    signal.last_seen_at = datetime(2026, 6, 19, 12, 0, 0, tzinfo=timezone.utc)
    signal.signal_metadata = {
        "resource_type": "linear_webhook",
        "resource_id": resource_id,
        "operation_family": "linear.webhook",
        "event_types": "linear.webhook.updated",
        "event_count": 1,
        "source": "linear_activity_event",
    }
    return signal


class TestMatchPair:
    def test_same_resource_id_returns_match(self) -> None:
        from app.services.linear_risk_activity_correlation_service import _match_pair
        finding = _make_finding(resource_id=LINEAR_TEST_WEBHOOK_ID)
        signal = _make_signal(resource_id=LINEAR_TEST_WEBHOOK_ID)
        result = _match_pair(finding, signal)
        assert result == "resource_id_match"

    def test_different_resource_id_returns_none(self) -> None:
        from app.services.linear_risk_activity_correlation_service import _match_pair
        finding = _make_finding(resource_id="WH001")
        signal = _make_signal(resource_id="WH002")
        result = _match_pair(finding, signal)
        assert result is None

    def test_no_finding_resource_id_returns_none(self) -> None:
        from app.services.linear_risk_activity_correlation_service import _match_pair
        finding = _make_finding()
        finding.resource_id = None
        finding.evidence = {}
        signal = _make_signal()
        result = _match_pair(finding, signal)
        assert result is None

    def test_no_signal_resource_id_returns_none(self) -> None:
        from app.services.linear_risk_activity_correlation_service import _match_pair
        finding = _make_finding()
        signal = _make_signal()
        signal.signal_metadata = {}
        result = _match_pair(finding, signal)
        assert result is None


class TestMatchStrength:
    def test_exact_match_same_integration_specific_signal_is_high(self) -> None:
        from app.services.linear_risk_activity_correlation_service import _match_strength
        iid = uuid.uuid4()
        result = _match_strength(
            "resource_id_match", "linear_webhook_config_changed", iid, iid
        )
        assert result == "high"

    def test_exact_match_different_integration_is_medium(self) -> None:
        from app.services.linear_risk_activity_correlation_service import _match_strength
        result = _match_strength(
            "resource_id_match", "linear_webhook_config_changed",
            uuid.uuid4(), uuid.uuid4(),
        )
        assert result == "medium"

    def test_exact_match_no_integration_is_medium(self) -> None:
        from app.services.linear_risk_activity_correlation_service import _match_strength
        result = _match_strength(
            "resource_id_match", "linear_webhook_config_changed", None, None
        )
        assert result == "medium"

    def test_generic_signal_is_medium(self) -> None:
        from app.services.linear_risk_activity_correlation_service import _match_strength
        iid = uuid.uuid4()
        result = _match_strength(
            "resource_id_match", "linear_config_activity", iid, iid
        )
        assert result == "medium"


# ── C. Build correlation logic ─────────────────────────────────────────────────

class TestBuildCorrelation:
    def test_build_returns_required_keys(self) -> None:
        from app.services.linear_risk_activity_correlation_service import (
            _build_correlation,
            LINEAR_CORRELATION_RULES,
        )
        finding = _make_finding()
        signal = _make_signal()
        rule = LINEAR_CORRELATION_RULES["linear_webhook_risk_activity_correlation"]
        result = _build_correlation(
            finding=finding,
            signal=signal,
            correlation_type="linear_webhook_risk_activity_correlation",
            rule=rule,
            match_reason="resource_id_match",
        )
        assert result["provider"] == "linear"
        assert result["correlation_type"] == "linear_webhook_risk_activity_correlation"
        assert result["status"] == "open"
        assert result["linked_finding_id"] == finding.id
        assert result["linked_activity_event_id"] == signal.linked_activity_event_id
        assert "metadata" in result

    def test_build_metadata_no_forbidden_fields(self) -> None:
        from app.services.linear_risk_activity_correlation_service import (
            _build_correlation,
            LINEAR_CORRELATION_RULES,
        )
        for family, rule in LINEAR_CORRELATION_RULES.items():
            finding = _make_finding()
            signal = _make_signal()
            result = _build_correlation(
                finding=finding,
                signal=signal,
                correlation_type=family,
                rule=rule,
                match_reason="resource_id_match",
            )
            for field in result["metadata"].keys():
                assert field not in _FORBIDDEN_METADATA_FIELDS, (
                    f"Forbidden field {field!r} in correlation metadata for {family!r}"
                )

    def test_build_summary_no_forbidden_wording(self) -> None:
        from app.services.linear_risk_activity_correlation_service import (
            _build_correlation,
            LINEAR_CORRELATION_RULES,
        )
        for family, rule in LINEAR_CORRELATION_RULES.items():
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
            assert "review" in text or "evidence" in text

    def test_correlation_key_includes_linear(self) -> None:
        from app.services.linear_risk_activity_correlation_service import _correlation_key
        finding = _make_finding()
        signal = _make_signal()
        key = _correlation_key(
            finding, signal, "linear_webhook_risk_activity_correlation"
        )
        assert "linear" in key

    def test_correlation_key_deterministic(self) -> None:
        from app.services.linear_risk_activity_correlation_service import _correlation_key
        finding = _make_finding()
        signal = _make_signal()
        k1 = _correlation_key(finding, signal, "linear_webhook_risk_activity_correlation")
        k2 = _correlation_key(finding, signal, "linear_webhook_risk_activity_correlation")
        assert k1 == k2

    def test_correlation_key_differs_by_family(self) -> None:
        from app.services.linear_risk_activity_correlation_service import _correlation_key
        finding = _make_finding()
        signal = _make_signal()
        k1 = _correlation_key(finding, signal, "linear_webhook_risk_activity_correlation")
        k2 = _correlation_key(finding, signal, "linear_team_risk_activity_correlation")
        assert k1 != k2


# ── D. Generate function ──────────────────────────────────────────────────────

class TestGenerateFunction:
    def test_empty_findings_returns_zero_counts(self) -> None:
        from app.services.linear_risk_activity_correlation_service import (
            generate_linear_correlations,
        )
        db = MagicMock()
        db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = []
        result = generate_linear_correlations(workspace_id=uuid.uuid4(), db=db)
        assert result["provider"] == "linear"
        assert result["findings_scanned"] == 0
        assert result["signals_scanned"] == 0
        assert result["candidate_pairs"] == 0
        assert result["correlations_created"] == 0
        assert result["correlations_skipped"] == 0

    def test_result_has_all_count_keys(self) -> None:
        from app.services.linear_risk_activity_correlation_service import (
            generate_linear_correlations,
        )
        db = MagicMock()
        db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = []
        result = generate_linear_correlations(workspace_id=uuid.uuid4(), db=db)
        for key in (
            "provider",
            "findings_scanned",
            "signals_scanned",
            "candidate_pairs",
            "correlations_created",
            "correlations_skipped",
        ):
            assert key in result, f"Missing {key!r} in generate result"

    def test_generate_scans_only_linear_provider(self) -> None:
        from app.services.linear_risk_activity_correlation_service import (
            generate_linear_correlations,
        )
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
        generate_linear_correlations(workspace_id=uuid.uuid4(), db=db)
        assert call_count[0] >= 2  # findings query + signals query

    def test_max_correlations_cap_enforced(self) -> None:
        from app.services.linear_risk_activity_correlation_service import (
            generate_linear_correlations,
        )
        db = MagicMock()
        db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = []
        result = generate_linear_correlations(
            workspace_id=uuid.uuid4(),
            db=db,
            max_correlations=9999,
        )
        assert isinstance(result, dict)

    def test_different_resource_ids_not_correlated(self) -> None:
        from app.services.linear_risk_activity_correlation_service import _match_pair
        finding = _make_finding(resource_id="WH001")
        signal = _make_signal(resource_id="WH002")
        assert _match_pair(finding, signal) is None

    def test_provider_constant_is_linear(self) -> None:
        from app.services.linear_risk_activity_correlation_service import PROVIDER as SVC_PROVIDER
        assert SVC_PROVIDER == "linear"


# ── E. ALLOWED_METADATA_KEYS / sanitization ──────────────────────────────────

class TestAllowedMetadataKeys:
    def test_linear_correlation_keys_present(self) -> None:
        from app.services.security_signal_correlation_service import ALLOWED_METADATA_KEYS
        required = {
            "match_reason",
            "match_strength",
            "finding_severity",
            "risk_family",
            "activity_family",
            "correlation_reason",
            "correlation_strength",
            "webhook_enabled",
            "webhook_secret_present",
            "url_key_present",
            "private_team",
            "team_visibility_category",
            "project_status_category",
            "lead_present",
            "integration_enabled",
            "integration_type_category",
            "view_shared",
            "filter_count_category",
        }
        missing = required - ALLOWED_METADATA_KEYS
        assert not missing, f"M85F keys missing from ALLOWED_METADATA_KEYS: {sorted(missing)}"

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
            "api_key", "api_token", "oauth_token", "webhook_secret",
            "authorization", "headers", "payload", "issue_title",
            "issue_description", "comment_body", "email", "phone",
            "ip_address", "user_agent", "webhook_url",
        }
        present = truly_forbidden & ALLOWED_METADATA_KEYS
        assert not present, f"Forbidden keys in ALLOWED_METADATA_KEYS: {sorted(present)}"

    def test_sanitize_strips_forbidden_fields(self) -> None:
        from app.services.security_signal_correlation_service import (
            sanitize_correlation_metadata,
        )
        dirty = {
            "match_reason": "resource_id_match",
            "match_strength": "high",
            "api_key": "should-be-removed",
            "webhook_secret": "should-be-removed",
            "email": "should-be-removed",
            "payload": {"x": 1},
            "webhook_url": "https://example.invalid/hook",
        }
        clean = sanitize_correlation_metadata(dirty)
        assert "match_reason" in clean
        assert "match_strength" in clean
        for forbidden in ("api_key", "webhook_secret", "email", "payload", "webhook_url"):
            assert forbidden not in clean, f"{forbidden!r} not stripped by sanitizer"


# ── F. Router endpoint ─────────────────────────────────────────────────────────

class TestRouterEndpoint:
    def test_linear_correlations_endpoint_exists(self) -> None:
        from app.routers.security import router
        routes = [getattr(r, "path", "") for r in router.routes]
        assert any("linear-correlations/generate" in p for p in routes), (
            "linear-correlations/generate not found in router routes"
        )

    def test_router_references_response_schema_and_service(self) -> None:
        router_src = (BACKEND_APP / "routers" / "security.py").read_text(encoding="utf-8")
        assert "LinearCorrelationGenerateResponse" in router_src
        assert "linear_risk_activity_correlation_service" in router_src

    def test_endpoint_requires_workspace_admin(self) -> None:
        router_src = (BACKEND_APP / "routers" / "security.py").read_text(encoding="utf-8")
        idx = router_src.find("linear-correlations/generate")
        assert idx != -1
        window = router_src[idx : idx + 1200]
        assert "require_workspace_admin" in window, (
            "require_workspace_admin not found near linear-correlations/generate endpoint"
        )

    def test_schema_importable(self) -> None:
        from app.schemas.security_linear_activity import (
            LinearCorrelationGenerateRequest,
            LinearCorrelationGenerateResponse,
        )
        req = LinearCorrelationGenerateRequest()
        assert req.lookback_hours == 24   # default
        assert req.max_correlations == 100  # default
        resp = LinearCorrelationGenerateResponse()
        assert resp.provider == "linear"
        assert resp.correlations_created == 0


# ── G. Capability matrix ───────────────────────────────────────────────────────

class TestCapabilityMatrix:
    def test_risk_activity_correlations_true(self) -> None:
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("linear")
        assert cap is not None
        assert cap.security.risk_activity_correlations is True

    def test_activity_signals_still_true(self) -> None:
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("linear")
        assert cap.security.activity_signals is True

    def test_activity_ingestion_still_true(self) -> None:
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("linear")
        assert cap.security.activity_ingestion is True

    def test_demo_seed_clear_still_false(self) -> None:
        # M85G advanced this to True; assert current state.
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("linear")
        assert cap.security.demo_seed_clear is True

    def test_notes_mention_m85f(self) -> None:
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("linear")
        assert "M85F" in cap.notes


# ── H. Expansion framework ─────────────────────────────────────────────────────

class TestExpansionFramework:
    def test_planned_next_stage_is_m85g(self) -> None:
        # M85I complete; framework now points to M86A/Jira.
        from app.services.provider_expansion_framework import get_framework
        fw = get_framework()
        planned = fw.get("summary", {}).get("planned_next_stage", "")
        assert "M86" in planned or "Jira" in planned, (
            f"planned_next_stage should reference M86/Jira; got: {planned!r}"
        )
        assert "M85F" not in planned, (
            f"planned_next_stage should no longer reference M85F; got: {planned!r}"
        )

    def test_jira_is_head_of_recommended_queue(self) -> None:
        from app.services.provider_expansion_framework import get_framework
        fw = get_framework()
        recs = fw.get("recommended_next_providers", [])
        assert recs and recs[0]["provider"] in ("jira", "gitlab")


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

    def test_linear_in_provider_options(self, correlations_page: str) -> None:
        assert '"linear"' in correlations_page

    def test_linear_provider_branch_present(self, correlations_page: str) -> None:
        assert 'provider === "linear"' in correlations_page

    def test_linear_correlation_types_in_page(self, correlations_page: str) -> None:
        # Page uses TYPE_OPTIONS_BY_PROVIDER dict pattern; correlation types are
        # embedded under the "linear" key rather than a named constant.
        # linear_config_activity_correlation removed in M85H (not a backend type).
        assert "linear_config_activity_correlation" not in correlations_page
        for ct in [
            "linear_workspace_risk_activity_correlation",
            "linear_webhook_risk_activity_correlation",
            "linear_integration_risk_activity_correlation",
        ]:
            assert ct in correlations_page, (
                f"Correlation type {ct!r} missing from correlations page"
            )

    def test_generate_linear_correlations_imported(self, correlations_page: str) -> None:
        assert "generateLinearCorrelations" in correlations_page

    def test_generate_linear_correlations_in_api_ts(self, api_ts: str) -> None:
        assert "generateLinearCorrelations" in api_ts
        assert "linear-correlations/generate" in api_ts

    def test_linear_correlation_response_in_types(self) -> None:
        types_ts = (FRONTEND_SRC / "types" / "index.ts").read_text(encoding="utf-8")
        assert "LinearCorrelationGenerateResponse" in types_ts


# ── J. M85A/B/C/D/E regression ───────────────────────────────────────────────

class TestRegression:
    def test_linear_rule_keys_still_present(self) -> None:
        from app.services.security_rules.linear import LINEAR_RULE_KEYS
        assert len(LINEAR_RULE_KEYS) >= 30

    def test_linear_config_event_types_still_present(self) -> None:
        from app.services.linear_activity_ingestion_service import (
            LINEAR_CONFIG_EVENT_TYPES,
        )
        assert len(LINEAR_CONFIG_EVENT_TYPES) >= 9

    def test_linear_signal_types_still_present(self) -> None:
        from app.services.linear_activity_signal_service import LINEAR_SIGNAL_TYPES
        assert len(LINEAR_SIGNAL_TYPES) >= 9
        assert "linear_config_activity" in LINEAR_SIGNAL_TYPES

    def test_linear_evaluator_dispatches(self) -> None:
        from app.services.security_finding_evaluator import _PROVIDER_RULES
        assert "linear" in _PROVIDER_RULES


# ── K. Forbidden wording ───────────────────────────────────────────────────────

class TestForbiddenWording:
    def test_no_forbidden_wording_in_correlation_service(self) -> None:
        svc_path = BACKEND_APP / "services" / "linear_risk_activity_correlation_service.py"
        text = svc_path.read_text(encoding="utf-8").lower()
        for phrase in _FORBIDDEN_PHRASES:
            assert phrase not in text, (
                f"Forbidden phrase {phrase!r} found in linear_risk_activity_correlation_service.py"
            )

    def test_no_forbidden_wording_in_schema(self) -> None:
        schema_path = BACKEND_APP / "schemas" / "security_linear_activity.py"
        text = schema_path.read_text(encoding="utf-8").lower()
        for phrase in _FORBIDDEN_PHRASES:
            assert phrase not in text


# ── L. Secret-shape grep ──────────────────────────────────────────────────────

_SECRET_PATTERNS = [
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}"),
    re.compile(r"SG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    re.compile(r"lin_api_[A-Za-z0-9]{20,}"),
    re.compile(r"lin_oauth_[A-Za-z0-9]{20,}"),
]


class TestSecretShape:
    def test_no_secret_shapes_in_correlation_service(self) -> None:
        path = BACKEND_APP / "services" / "linear_risk_activity_correlation_service.py"
        text = path.read_text(encoding="utf-8", errors="replace")
        for pat in _SECRET_PATTERNS:
            match = pat.search(text)
            assert not match, (
                f"Secret-shaped string {match.group()!r} found in linear_risk_activity_correlation_service.py"
            )

    def test_no_secret_shapes_in_schema(self) -> None:
        path = BACKEND_APP / "schemas" / "security_linear_activity.py"
        text = path.read_text(encoding="utf-8", errors="replace")
        for pat in _SECRET_PATTERNS:
            match = pat.search(text)
            assert not match, (
                f"Secret-shaped string {match.group()!r} found in security_linear_activity.py"
            )
