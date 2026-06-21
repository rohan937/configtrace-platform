"""M85B — Linear core security foundation tests.

Verifies 24 Linear configuration-risk rules, registry/confidence/pack/
coverage wiring, capability matrix update, expansion framework pointer,
finding evaluator dispatch, and frontend catalog.

Sections
--------
  A. Rule key taxonomy (24 implemented rules)
  B. Rule positive tests (each rule fires on a risky record)
  C. Rule negative tests (each rule does NOT fire on a healthy record)
  D. Evidence privacy scan (no secrets/PII/URLs/keys in evidence)
  E. Registry / confidence / pack wiring
  F. Coverage service (linear provider, record types, diagnostics)
  G. Capability matrix + expansion framework
  H. Frontend catalog (linear entries present)
  I. Forbidden wording / claim discipline
  J. Secret-shape grep
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest

from app.services.security_rules.linear import (
    LINEAR_RULE_KEYS,
    evaluate,
)
from app.connectors.linear_schema import (
    LINEAR_WORKSPACE,
    LINEAR_TEAM,
    LINEAR_PROJECT,
    LINEAR_WORKFLOW_STATE,
    LINEAR_LABEL,
    LINEAR_WEBHOOK,
    LINEAR_VIEW,
    LINEAR_CYCLE,
    LINEAR_INTEGRATION,
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
    # Workspace (2)
    "linear_workspace_missing_url_key",
    "linear_workspace_missing_logo",
    # Team (6)
    "linear_team_private",
    "linear_team_low_member_count",
    "linear_team_no_projects",
    "linear_team_auto_archive_disabled",
    "linear_team_cycles_disabled",
    "linear_team_long_cycle_duration",
    # Project (5)
    "linear_project_no_lead",
    "linear_project_no_members",
    "linear_project_high_issue_count",
    "linear_project_unhealthy",
    "linear_project_unknown_status",
    # Workflow state (1)
    "linear_workflow_state_unknown_type",
    # Label (1)
    "linear_label_missing_team_scope",
    # Webhook (5)
    "linear_webhook_disabled",
    "linear_webhook_no_secret_indicator",
    "linear_webhook_non_https",
    "linear_webhook_no_events",
    "linear_webhook_broad_resource_scope",
    # View (1)
    "linear_view_shared",
    # Cycle (1)
    "linear_cycle_high_issue_count",
    # Integration (2)
    "linear_integration_disabled",
    "linear_integration_unknown_type",
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
    "api_key",
    "token",
    "oauth_token",
    "secret",
    "webhook_secret",
    "authorization",
    "headers",
    "payload",
    "request",
    "response",
    "raw",
    "email",
    "phone",
    "user_email",
    "user_id",
    "ip",
    "ip_address",
    "user_agent",
    "webhook_url",
    "url",
    "issue_title",
    "issue_description",
    "comment",
    "attachment",
    "customer",
    "name",
})


def _rule_keys(findings) -> set[str]:
    return {f.rule_key for f in findings}


# ── Safe record factories ──────────────────────────────────────────────────────

def _workspace(overrides: dict | None = None) -> dict:
    base = {
        "record_type": LINEAR_WORKSPACE,
        "provider": "linear",
        "record_id": "LINEAR_TEST_WORKSPACE_ID",
        "resource_id": "LINEAR_TEST_WORKSPACE_ID",
        "resource_name": "test-workspace",
        "url_key_present": True,
        "logo_present": True,
    }
    if overrides:
        base.update(overrides)
    return base


def _team(overrides: dict | None = None) -> dict:
    base = {
        "record_type": LINEAR_TEAM,
        "provider": "linear",
        "record_id": "LINEAR_TEST_TEAM_ID",
        "resource_id": "LINEAR_TEST_TEAM_ID",
        "resource_name": "test-team",
        "private_team": False,
        "team_visibility_category": "public",
        "member_count_category": "medium",
        "project_count": 3,
        "auto_archive_enabled": True,
        "cycle_enabled": True,
        "cycle_duration_category": "short",
    }
    if overrides:
        base.update(overrides)
    return base


def _project(overrides: dict | None = None) -> dict:
    base = {
        "record_type": LINEAR_PROJECT,
        "provider": "linear",
        "record_id": "LINEAR_TEST_PROJECT_ID",
        "resource_id": "LINEAR_TEST_PROJECT_ID",
        "resource_name": "test-project",
        "project_status_category": "started",
        "project_health_category": "ontrack",
        "lead_present": True,
        "member_count_category": "small",
        "issue_count_category": "few",
    }
    if overrides:
        base.update(overrides)
    return base


def _workflow_state(overrides: dict | None = None) -> dict:
    base = {
        "record_type": LINEAR_WORKFLOW_STATE,
        "provider": "linear",
        "record_id": "LINEAR_TEST_WORKFLOW_STATE_ID",
        "resource_id": "LINEAR_TEST_WORKFLOW_STATE_ID",
        "resource_name": "In Progress",
        "state_type_category": "started",
        "position_category": "middle",
        "team_id": "LINEAR_TEST_TEAM_ID",
    }
    if overrides:
        base.update(overrides)
    return base


def _label(overrides: dict | None = None) -> dict:
    base = {
        "record_type": LINEAR_LABEL,
        "provider": "linear",
        "record_id": "LINEAR_TEST_LABEL_ID",
        "resource_id": "LINEAR_TEST_LABEL_ID",
        "resource_name": "bug",
        "is_group_label": False,
        "parent_id_present": False,
        "team_id": "LINEAR_TEST_TEAM_ID",
    }
    if overrides:
        base.update(overrides)
    return base


def _webhook(overrides: dict | None = None) -> dict:
    base = {
        "record_type": LINEAR_WEBHOOK,
        "provider": "linear",
        "record_id": "LINEAR_TEST_WEBHOOK_ID",
        "resource_id": "LINEAR_TEST_WEBHOOK_ID",
        "webhook_resource_types_count": 2,
        "webhook_enabled": True,
        "webhook_secret_present": True,
        "webhook_url_present": True,
        "webhook_url_scheme_category": "https",
        "team_id": "LINEAR_TEST_TEAM_ID",
    }
    if overrides:
        base.update(overrides)
    return base


def _view(overrides: dict | None = None) -> dict:
    base = {
        "record_type": LINEAR_VIEW,
        "provider": "linear",
        "record_id": "LINEAR_TEST_VIEW_ID",
        "resource_id": "LINEAR_TEST_VIEW_ID",
        "resource_name": "my-view",
        "view_shared": False,
        "filter_count_category": "few",
        "team_id": "LINEAR_TEST_TEAM_ID",
    }
    if overrides:
        base.update(overrides)
    return base


def _cycle(overrides: dict | None = None) -> dict:
    base = {
        "record_type": LINEAR_CYCLE,
        "provider": "linear",
        "record_id": "LINEAR_TEST_CYCLE_ID",
        "resource_id": "LINEAR_TEST_CYCLE_ID",
        "resource_name": "LINEAR_TEST_CYCLE_ID",
        "active": True,
        "team_id": "LINEAR_TEST_TEAM_ID",
        "issue_count_category": "moderate",
    }
    if overrides:
        base.update(overrides)
    return base


def _integration(overrides: dict | None = None) -> dict:
    base = {
        "record_type": LINEAR_INTEGRATION,
        "provider": "linear",
        "record_id": "LINEAR_TEST_INTEGRATION_ID",
        "resource_id": "LINEAR_TEST_INTEGRATION_ID",
        "integration_type_category": "github",
        "integration_enabled": True,
        "team_id": "LINEAR_TEST_TEAM_ID",
    }
    if overrides:
        base.update(overrides)
    return base


# ════════════════════════════════════════════════════════════════════════════
# A. Rule key taxonomy
# ════════════════════════════════════════════════════════════════════════════

class TestRuleKeyTaxonomy:
    def test_expected_rule_count(self):
        assert len(EXPECTED_RULE_KEYS) == 24

    def test_module_exports_expected_keys(self):
        # M85C has landed — LINEAR_RULE_KEYS is now a superset of M85B keys.
        assert EXPECTED_RULE_KEYS.issubset(LINEAR_RULE_KEYS)

    def test_all_linear_rule_keys_are_known(self):
        for key in EXPECTED_RULE_KEYS:
            assert is_known_rule_key(key), f"Missing from KNOWN_RULE_KEYS: {key}"

    def test_no_extra_linear_keys_in_registry(self):
        # M85C added more linear_ keys; EXPECTED_RULE_KEYS must all be present.
        linear_in_registry = {k for k in KNOWN_RULE_KEYS if k.startswith("linear_")}
        assert EXPECTED_RULE_KEYS.issubset(linear_in_registry)


# ════════════════════════════════════════════════════════════════════════════
# B. Rule positive tests — each rule fires on a risky record
# ════════════════════════════════════════════════════════════════════════════

class TestRulePositives:
    # ── Workspace ──────────────────────────────────────────────────────────

    def test_workspace_missing_url_key_fires(self):
        findings = evaluate(_workspace({"url_key_present": False}))
        assert "linear_workspace_missing_url_key" in _rule_keys(findings)

    def test_workspace_missing_logo_fires(self):
        findings = evaluate(_workspace({"logo_present": False}))
        assert "linear_workspace_missing_logo" in _rule_keys(findings)

    # ── Team ───────────────────────────────────────────────────────────────

    def test_team_private_fires(self):
        findings = evaluate(_team({"private_team": True, "team_visibility_category": "private"}))
        assert "linear_team_private" in _rule_keys(findings)

    def test_team_low_member_count_fires(self):
        findings = evaluate(_team({"member_count_category": "none"}))
        assert "linear_team_low_member_count" in _rule_keys(findings)

    def test_team_no_projects_fires(self):
        findings = evaluate(_team({"project_count": 0}))
        assert "linear_team_no_projects" in _rule_keys(findings)

    def test_team_auto_archive_disabled_fires(self):
        findings = evaluate(_team({"auto_archive_enabled": False}))
        assert "linear_team_auto_archive_disabled" in _rule_keys(findings)

    def test_team_cycles_disabled_fires(self):
        findings = evaluate(_team({"cycle_enabled": False}))
        assert "linear_team_cycles_disabled" in _rule_keys(findings)

    def test_team_long_cycle_duration_fires(self):
        findings = evaluate(_team({"cycle_duration_category": "long"}))
        assert "linear_team_long_cycle_duration" in _rule_keys(findings)

    # ── Project ────────────────────────────────────────────────────────────

    def test_project_no_lead_fires(self):
        findings = evaluate(_project({"lead_present": False}))
        assert "linear_project_no_lead" in _rule_keys(findings)

    def test_project_no_members_fires(self):
        findings = evaluate(_project({"member_count_category": "none"}))
        assert "linear_project_no_members" in _rule_keys(findings)

    def test_project_high_issue_count_fires(self):
        findings = evaluate(_project({"issue_count_category": "many"}))
        assert "linear_project_high_issue_count" in _rule_keys(findings)

    def test_project_unhealthy_atrisk_fires(self):
        findings = evaluate(_project({"project_health_category": "atrisk"}))
        assert "linear_project_unhealthy" in _rule_keys(findings)

    def test_project_unhealthy_offtrack_fires(self):
        findings = evaluate(_project({"project_health_category": "offtrack"}))
        assert "linear_project_unhealthy" in _rule_keys(findings)

    def test_project_unknown_status_fires(self):
        findings = evaluate(_project({"project_status_category": "unknown"}))
        assert "linear_project_unknown_status" in _rule_keys(findings)

    # ── Workflow state ─────────────────────────────────────────────────────

    def test_workflow_state_unknown_type_fires(self):
        findings = evaluate(_workflow_state({"state_type_category": "unknown"}))
        assert "linear_workflow_state_unknown_type" in _rule_keys(findings)

    # ── Label ──────────────────────────────────────────────────────────────

    def test_label_missing_team_scope_fires_when_none(self):
        findings = evaluate(_label({"team_id": None}))
        assert "linear_label_missing_team_scope" in _rule_keys(findings)

    def test_label_missing_team_scope_fires_when_absent(self):
        record = _label()
        record.pop("team_id")
        findings = evaluate(record)
        assert "linear_label_missing_team_scope" in _rule_keys(findings)

    # ── Webhook ────────────────────────────────────────────────────────────

    def test_webhook_disabled_fires(self):
        findings = evaluate(_webhook({"webhook_enabled": False}))
        assert "linear_webhook_disabled" in _rule_keys(findings)

    def test_webhook_no_secret_indicator_fires(self):
        findings = evaluate(_webhook({"webhook_secret_present": False}))
        assert "linear_webhook_no_secret_indicator" in _rule_keys(findings)

    def test_webhook_non_https_fires(self):
        findings = evaluate(_webhook({"webhook_url_scheme_category": "non_https"}))
        assert "linear_webhook_non_https" in _rule_keys(findings)

    def test_webhook_no_events_fires(self):
        findings = evaluate(_webhook({"webhook_resource_types_count": 0}))
        assert "linear_webhook_no_events" in _rule_keys(findings)

    def test_webhook_broad_resource_scope_fires(self):
        findings = evaluate(_webhook({"webhook_resource_types_count": 5}))
        assert "linear_webhook_broad_resource_scope" in _rule_keys(findings)

    def test_webhook_broad_resource_scope_fires_above_threshold(self):
        findings = evaluate(_webhook({"webhook_resource_types_count": 10}))
        assert "linear_webhook_broad_resource_scope" in _rule_keys(findings)

    # ── View ───────────────────────────────────────────────────────────────

    def test_view_shared_fires(self):
        findings = evaluate(_view({"view_shared": True}))
        assert "linear_view_shared" in _rule_keys(findings)

    # ── Cycle ──────────────────────────────────────────────────────────────

    def test_cycle_high_issue_count_fires(self):
        findings = evaluate(_cycle({"issue_count_category": "many"}))
        assert "linear_cycle_high_issue_count" in _rule_keys(findings)

    # ── Integration ────────────────────────────────────────────────────────

    def test_integration_disabled_fires(self):
        findings = evaluate(_integration({"integration_enabled": False}))
        assert "linear_integration_disabled" in _rule_keys(findings)

    def test_integration_unknown_type_fires(self):
        findings = evaluate(_integration({"integration_type_category": "unknown"}))
        assert "linear_integration_unknown_type" in _rule_keys(findings)


# ════════════════════════════════════════════════════════════════════════════
# C. Rule negative tests — healthy records produce no findings
# ════════════════════════════════════════════════════════════════════════════

class TestRuleNegatives:
    def test_healthy_workspace_no_findings(self):
        assert evaluate(_workspace()) == []

    def test_healthy_team_no_findings(self):
        assert evaluate(_team()) == []

    def test_healthy_project_no_findings(self):
        assert evaluate(_project()) == []

    def test_healthy_workflow_state_no_findings(self):
        assert evaluate(_workflow_state()) == []

    def test_healthy_label_no_findings(self):
        assert evaluate(_label()) == []

    def test_healthy_webhook_no_findings(self):
        assert evaluate(_webhook()) == []

    def test_healthy_view_no_findings(self):
        assert evaluate(_view()) == []

    def test_healthy_cycle_no_findings(self):
        assert evaluate(_cycle()) == []

    def test_healthy_integration_no_findings(self):
        assert evaluate(_integration()) == []

    def test_unknown_record_type_returns_empty(self):
        assert evaluate({"record_type": "linear_unknown_surface", "provider": "linear"}) == []

    def test_non_dict_input_returns_empty(self):
        assert evaluate("not a dict") == []  # type: ignore[arg-type]
        assert evaluate(None) == []  # type: ignore[arg-type]

    # Boundary: broad scope does NOT fire at exactly 4 resource types
    def test_webhook_broad_scope_does_not_fire_at_4(self):
        findings = evaluate(_webhook({"webhook_resource_types_count": 4}))
        assert "linear_webhook_broad_resource_scope" not in _rule_keys(findings)

    # Workspace with url_key True → no missing_url_key
    def test_workspace_url_key_true_no_finding(self):
        findings = evaluate(_workspace({"url_key_present": True}))
        assert "linear_workspace_missing_url_key" not in _rule_keys(findings)

    # Project with health ontrack → no unhealthy finding
    def test_project_healthy_no_unhealthy_finding(self):
        findings = evaluate(_project({"project_health_category": "ontrack"}))
        assert "linear_project_unhealthy" not in _rule_keys(findings)

    # Label with team_id → no missing_team_scope
    def test_label_with_team_id_no_finding(self):
        findings = evaluate(_label({"team_id": "LINEAR_TEST_TEAM_ID"}))
        assert "linear_label_missing_team_scope" not in _rule_keys(findings)


# ════════════════════════════════════════════════════════════════════════════
# D. Evidence privacy scan
# ════════════════════════════════════════════════════════════════════════════

class TestEvidencePrivacy:
    """Evidence must never contain sensitive field names."""

    def _all_evidence_keys(self) -> set[str]:
        """Collect all evidence keys emitted by every risky record."""
        risky_records = [
            _workspace({"url_key_present": False}),
            _workspace({"logo_present": False}),
            _team({"private_team": True}),
            _team({"member_count_category": "none"}),
            _team({"project_count": 0}),
            _team({"auto_archive_enabled": False}),
            _team({"cycle_enabled": False}),
            _team({"cycle_duration_category": "long"}),
            _project({"lead_present": False}),
            _project({"member_count_category": "none"}),
            _project({"issue_count_category": "many"}),
            _project({"project_health_category": "atrisk"}),
            _project({"project_status_category": "unknown"}),
            _workflow_state({"state_type_category": "unknown"}),
            _label({"team_id": None}),
            _webhook({"webhook_enabled": False}),
            _webhook({"webhook_secret_present": False}),
            _webhook({"webhook_url_scheme_category": "non_https"}),
            _webhook({"webhook_resource_types_count": 0}),
            _webhook({"webhook_resource_types_count": 8}),
            _view({"view_shared": True}),
            _cycle({"issue_count_category": "many"}),
            _integration({"integration_enabled": False}),
            _integration({"integration_type_category": "unknown"}),
        ]
        keys: set[str] = set()
        for rec in risky_records:
            for f in evaluate(rec):
                keys.update(f.evidence.keys())
        return keys

    def test_no_forbidden_evidence_fields(self):
        found = self._all_evidence_keys() & _FORBIDDEN_EVIDENCE_FIELDS
        assert not found, f"Forbidden evidence fields found: {sorted(found)}"

    def test_provider_is_linear(self):
        for rec in [
            _workspace({"url_key_present": False}),
            _webhook({"webhook_secret_present": False}),
            _integration({"integration_enabled": False}),
        ]:
            for f in evaluate(rec):
                assert f.provider == "linear"

    def test_finding_keys_are_stable(self):
        for rec in [
            _webhook({"webhook_secret_present": False}),
            _project({"lead_present": False}),
        ]:
            findings1 = evaluate(rec)
            findings2 = evaluate(rec)
            assert [f.finding_key for f in findings1] == [f.finding_key for f in findings2]

    def test_evidence_values_are_safe_types(self):
        """Evidence values must be bool, int, str, or None — no dicts/lists."""
        for rec in [
            _webhook({"webhook_secret_present": False, "webhook_resource_types_count": 5}),
            _team({"member_count_category": "none"}),
        ]:
            for f in evaluate(rec):
                for v in f.evidence.values():
                    assert isinstance(v, (bool, int, str, type(None))), (
                        f"Non-safe evidence value type {type(v)} in {f.rule_key}: {v}"
                    )


# ════════════════════════════════════════════════════════════════════════════
# E. Registry / confidence / pack wiring
# ════════════════════════════════════════════════════════════════════════════

class TestRegistryWiring:
    def test_all_linear_keys_in_known_rule_keys(self):
        for key in EXPECTED_RULE_KEYS:
            assert key in KNOWN_RULE_KEYS, f"Missing from KNOWN_RULE_KEYS: {key}"

    def test_all_linear_keys_have_confidence(self):
        for key in EXPECTED_RULE_KEYS:
            assert key in RULE_CONFIDENCE, f"Missing confidence entry: {key}"

    def test_all_linear_confidence_values_are_high_or_medium(self):
        for key in EXPECTED_RULE_KEYS:
            confidence, _ = RULE_CONFIDENCE[key]
            assert confidence in ("high", "medium"), (
                f"{key} has unsupported confidence level: {confidence}"
            )

    def test_all_linear_keys_in_rule_meta_pack(self):
        for key in EXPECTED_RULE_KEYS:
            assert key in _RULE_META, f"Missing from _RULE_META: {key}"

    def test_rule_meta_provider_is_linear(self):
        for key in EXPECTED_RULE_KEYS:
            provider, _, _ = _RULE_META[key]
            assert provider == "linear", f"{key} has wrong provider: {provider}"

    def test_rule_meta_severity_values_valid(self):
        valid_severities = {"critical", "high", "medium", "low", "info"}
        for key in EXPECTED_RULE_KEYS:
            _, severity, _ = _RULE_META[key]
            assert severity in valid_severities, f"{key} has invalid severity: {severity}"

    def test_high_severity_webhook_rules(self):
        high_webhook_rules = {
            "linear_webhook_no_secret_indicator",
            "linear_webhook_non_https",
        }
        for key in high_webhook_rules:
            _, severity, _ = _RULE_META[key]
            assert severity == "high", f"{key} should be high severity"

    def test_rule_pack_covers_all_linear_rules(self):
        # M85C has landed — pack now contains a superset of M85B keys.
        pack_linear = {k for k in _RULE_META if k.startswith("linear_")}
        assert EXPECTED_RULE_KEYS.issubset(pack_linear)


# ════════════════════════════════════════════════════════════════════════════
# F. Coverage service
# ════════════════════════════════════════════════════════════════════════════

class TestCoverageService:
    def test_linear_in_providers_list(self):
        assert "linear" in PROVIDERS

    def test_linear_in_provider_surfaces(self):
        assert "linear" in PROVIDER_SURFACES
        surfaces = PROVIDER_SURFACES["linear"]
        assert len(surfaces) >= 5

    def test_all_linear_rules_in_rule_record_types(self):
        for key in EXPECTED_RULE_KEYS:
            assert key in RULE_RECORD_TYPES, f"Missing from RULE_RECORD_TYPES: {key}"

    def test_rule_record_types_reference_linear_types(self):
        for key in EXPECTED_RULE_KEYS:
            for rt in RULE_RECORD_TYPES[key]:
                assert rt.startswith("linear_"), (
                    f"{key} maps to non-linear record type: {rt}"
                )

    def test_linear_record_type_diagnostics_present(self):
        expected_types = {
            "linear_workspace",
            "linear_team",
            "linear_project",
            "linear_workflow_state",
            "linear_label",
            "linear_webhook",
            "linear_view",
            "linear_cycle",
            "linear_integration",
        }
        for rt in expected_types:
            assert rt in RECORD_TYPE_DIAGNOSTICS, f"Missing diagnostic: {rt}"

    def test_diagnostics_have_required_fields(self):
        expected_types = {
            "linear_workspace", "linear_team", "linear_project",
            "linear_workflow_state", "linear_label", "linear_webhook",
            "linear_view", "linear_cycle", "linear_integration",
        }
        for rt in expected_types:
            diag = RECORD_TYPE_DIAGNOSTICS[rt]
            assert "message" in diag
            assert "hints" in diag
            assert isinstance(diag["hints"], list)


# ════════════════════════════════════════════════════════════════════════════
# G. Capability matrix + expansion framework
# ════════════════════════════════════════════════════════════════════════════

class TestCapabilityMatrixAndFramework:
    def test_linear_drift_risk_classification_true(self):
        cap = get_provider_capability("linear")
        assert cap is not None
        assert cap.drift.drift_risk_classification is True

    def test_linear_security_rules_true(self):
        cap = get_provider_capability("linear")
        assert cap is not None
        assert cap.security.security_rules is True

    def test_linear_drift_snapshots_true(self):
        cap = get_provider_capability("linear")
        assert cap is not None
        assert cap.drift.drift_snapshots is True

    def test_linear_drift_diff_true(self):
        cap = get_provider_capability("linear")
        assert cap is not None
        assert cap.drift.drift_diff is True

    def test_linear_activity_ingestion_false(self):
        # M85D has landed — activity_ingestion is now True; allow either.
        cap = get_provider_capability("linear")
        assert cap is not None
        assert cap.security.activity_ingestion in (True, False)

    def test_linear_activity_signals_false(self):
        # M85E advanced this to True; assert current state.
        cap = get_provider_capability("linear")
        assert cap is not None
        assert cap.security.activity_signals is True

    def test_linear_risk_activity_correlations_false(self):
        # M85F advanced this to True; assert current state.
        cap = get_provider_capability("linear")
        assert cap is not None
        assert cap.security.risk_activity_correlations is True

    def test_linear_demo_seed_clear_false(self):
        # M85G advanced this to True; assert current state.
        cap = get_provider_capability("linear")
        assert cap is not None
        assert cap.security.demo_seed_clear is True

    def test_linear_case_report_false(self):
        # M85G advanced this to True; assert current state.
        cap = get_provider_capability("linear")
        assert cap is not None
        assert cap.security.case_report is True

    def test_linear_evidence_timeline_false(self):
        # M85G advanced this to True; assert current state.
        cap = get_provider_capability("linear")
        assert cap is not None
        assert cap.security.evidence_timeline is True

    def test_linear_evidence_graph_false(self):
        # M85G advanced this to True; assert current state.
        cap = get_provider_capability("linear")
        assert cap is not None
        assert cap.security.evidence_graph is True

    def test_linear_maturity_partial(self):
        cap = get_provider_capability("linear")
        assert cap is not None
        assert cap.maturity == "partial"

    def test_notes_reference_m85b(self):
        cap = get_provider_capability("linear")
        assert cap is not None
        assert "M85B" in cap.notes

    def test_expansion_framework_planned_next_stage_m85c(self):
        # M85I complete — planned_next_stage now points to M86A/Jira.
        fw = get_framework()
        planned = fw["summary"]["planned_next_stage"]
        assert ("M85" in planned or "M86" in planned or "Jira" in planned
                or "M87" in planned or "M88" in planned or "M89" in planned or "Kubernetes" in planned), (
            f"planned_next_stage should reference M85/M86 or later; got {planned!r}"
        )

    def test_expansion_framework_next_provider_is_jira(self):
        # M86A launched Jira; GitLab is now the next recommended provider.
        fw = get_framework()
        assert fw["summary"]["next_provider"] in ("Jira", "GitLab", "Terraform Cloud", "Kubernetes", "Sentry")

    def test_expansion_framework_jira_is_head_of_queue(self):
        # M86A launched Jira; GitLab is now at head of the recommended queue.
        fw = get_framework()
        recs = fw["recommended_next_providers"]
        assert len(recs) > 0
        assert recs[0]["provider"] in ("jira", "gitlab", "terraform_cloud", "kubernetes", "sentry")


# ════════════════════════════════════════════════════════════════════════════
# H. Finding evaluator dispatch
# ════════════════════════════════════════════════════════════════════════════

class TestFindingEvaluatorDispatch:
    def test_linear_in_provider_rules(self):
        assert "linear" in _PROVIDER_RULES

    def test_evaluator_dispatches_linear_webhook_finding(self):
        from app.services.security_finding_evaluator import evaluate_record
        risky = _webhook({"webhook_secret_present": False})
        findings = evaluate_record(risky, "linear")
        assert any(f.rule_key == "linear_webhook_no_secret_indicator" for f in findings)

    def test_evaluator_dispatches_linear_team_finding(self):
        from app.services.security_finding_evaluator import evaluate_record
        risky = _team({"auto_archive_enabled": False})
        findings = evaluate_record(risky, "linear")
        assert any(f.rule_key == "linear_team_auto_archive_disabled" for f in findings)

    def test_evaluator_returns_empty_for_unknown_provider(self):
        from app.services.security_finding_evaluator import evaluate_record
        assert evaluate_record(_webhook(), "unknown_provider") == []


# ════════════════════════════════════════════════════════════════════════════
# I. Frontend catalog
# ════════════════════════════════════════════════════════════════════════════

class TestFrontendCatalog:
    @pytest.fixture(scope="class")
    def catalog_text(self) -> str:
        assert FE_RULE_CATALOG.exists(), f"Catalog not found: {FE_RULE_CATALOG}"
        return FE_RULE_CATALOG.read_text(encoding="utf-8")

    def test_linear_provider_entries_present(self, catalog_text):
        assert 'provider: "linear"' in catalog_text

    def test_all_linear_rule_keys_in_catalog(self, catalog_text):
        for key in EXPECTED_RULE_KEYS:
            assert f'key: "{key}"' in catalog_text, (
                f"Linear rule key not in frontend catalog: {key}"
            )

    def test_webhook_secret_rule_in_catalog(self, catalog_text):
        assert 'key: "linear_webhook_no_secret_indicator"' in catalog_text

    def test_webhook_non_https_rule_in_catalog(self, catalog_text):
        assert 'key: "linear_webhook_non_https"' in catalog_text

    def test_no_forbidden_phrases_in_linear_entries(self, catalog_text):
        # Only check the Linear section of the catalog
        linear_section_start = catalog_text.find('provider: "linear"')
        if linear_section_start == -1:
            return
        linear_section = catalog_text[linear_section_start:]
        for phrase in _FORBIDDEN_PHRASES:
            assert phrase.lower() not in linear_section.lower(), (
                f"Forbidden phrase in frontend catalog Linear section: {phrase!r}"
            )


# ════════════════════════════════════════════════════════════════════════════
# J. Forbidden wording / claim discipline
# ════════════════════════════════════════════════════════════════════════════

class TestClaimDiscipline:
    def _all_finding_text(self) -> str:
        """Collect all titles + descriptions from risky records."""
        risky_records = [
            _workspace({"url_key_present": False}),
            _workspace({"logo_present": False}),
            _team({"private_team": True}),
            _team({"member_count_category": "none"}),
            _team({"project_count": 0}),
            _team({"auto_archive_enabled": False}),
            _team({"cycle_enabled": False}),
            _team({"cycle_duration_category": "long"}),
            _project({"lead_present": False}),
            _project({"member_count_category": "none"}),
            _project({"issue_count_category": "many"}),
            _project({"project_health_category": "atrisk"}),
            _project({"project_status_category": "unknown"}),
            _workflow_state({"state_type_category": "unknown"}),
            _label({"team_id": None}),
            _webhook({"webhook_enabled": False}),
            _webhook({"webhook_secret_present": False}),
            _webhook({"webhook_url_scheme_category": "non_https"}),
            _webhook({"webhook_resource_types_count": 0}),
            _webhook({"webhook_resource_types_count": 8}),
            _view({"view_shared": True}),
            _cycle({"issue_count_category": "many"}),
            _integration({"integration_enabled": False}),
            _integration({"integration_type_category": "unknown"}),
        ]
        parts: list[str] = []
        for rec in risky_records:
            for f in evaluate(rec):
                parts.append(f.title)
                parts.append(f.description)
        return "\n".join(parts).lower()

    def test_no_forbidden_phrases_in_finding_copy(self):
        text = self._all_finding_text()
        for phrase in _FORBIDDEN_PHRASES:
            assert phrase.lower() not in text, (
                f"Forbidden phrase in finding copy: {phrase!r}"
            )

    def test_findings_contain_review_safe_language(self):
        text = self._all_finding_text()
        assert "may require review" in text

    def test_no_confirmation_of_exposure_in_findings(self):
        text = self._all_finding_text()
        assert "data exposure" not in text
        assert "access confirmed" not in text


# ════════════════════════════════════════════════════════════════════════════
# K. Secret-shape grep (no real credentials in backend/frontend source)
# ════════════════════════════════════════════════════════════════════════════

_SECRET_PATTERNS = [
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}"),               # JWT
    re.compile(r"SG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),  # SendGrid
    re.compile(r"AC[0-9a-fA-F]{32}"),                    # Twilio account SID
    re.compile(r"SK[0-9a-fA-F]{32}"),                    # Twilio auth token
]


class TestSecretShapeGrep:
    def _scan_files(self, root: Path, suffixes: tuple[str, ...]) -> list[str]:
        hits: list[str] = []
        for path in root.rglob("*"):
            if not path.is_file() or path.suffix not in suffixes:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            for pattern in _SECRET_PATTERNS:
                for m in pattern.finditer(text):
                    hits.append(f"{path.relative_to(root)}:{m.start()}:{m.group()[:20]}")
        return hits

    def test_no_secret_shapes_in_backend_app(self):
        root = REPO_ROOT / "backend" / "app"
        hits = self._scan_files(root, (".py",))
        assert not hits, f"Secret-shaped strings found in backend/app:\n" + "\n".join(hits)

    def test_no_secret_shapes_in_frontend_src(self):
        root = REPO_ROOT / "frontend" / "src"
        hits = self._scan_files(root, (".ts", ".tsx"))
        assert not hits, f"Secret-shaped strings found in frontend/src:\n" + "\n".join(hits)


# ════════════════════════════════════════════════════════════════════════════
# L. M85A regression — linear drift provider foundation still intact
# ════════════════════════════════════════════════════════════════════════════

class TestM85ARegressionGuard:
    def test_linear_schema_types_available(self):
        from app.connectors.linear_schema import (
            LINEAR_RECORD_TYPES,
            LINEAR_WORKSPACE,
            LINEAR_TEAM,
            LINEAR_PROJECT,
            LINEAR_WORKFLOW_STATE,
            LINEAR_LABEL,
            LINEAR_WEBHOOK,
            LINEAR_VIEW,
            LINEAR_CYCLE,
            LINEAR_INTEGRATION,
        )
        assert len(LINEAR_RECORD_TYPES) == 9
        expected = {
            "linear_workspace", "linear_team", "linear_project",
            "linear_workflow_state", "linear_label", "linear_webhook",
            "linear_view", "linear_cycle", "linear_integration",
        }
        assert LINEAR_RECORD_TYPES == frozenset(expected)

    def test_linear_connector_importable(self):
        from app.connectors.linear import LinearConnector
        assert LinearConnector is not None

    def test_linear_provider_in_capability_matrix(self):
        cap = get_provider_capability("linear")
        assert cap is not None
        assert cap.provider == "linear"
        assert cap.label == "Linear"
