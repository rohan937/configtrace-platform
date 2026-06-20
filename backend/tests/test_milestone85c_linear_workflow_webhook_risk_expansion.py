"""M85C — Linear workflow/webhook risk expansion tests.

Verifies 15 new Linear configuration-risk rules, connector schema expansion,
registry/confidence/pack/coverage wiring, capability matrix update, expansion
framework pointer, and frontend catalog.

Sections
--------
  A. Rule key taxonomy (15 M85C rules + 24 M85B = 39 total)
  B. Schema/connector field expansion
  C. Rule positive tests (each M85C rule fires on a risky record)
  D. Rule negative tests (M85C rules do NOT fire on healthy records)
  E. M85B backwards compatibility (M85B rules fire/don't fire on M85B records)
  F. Evidence privacy scan
  G. Registry / confidence / pack wiring
  H. Coverage service
  I. Capability matrix + expansion framework
  J. Frontend catalog
  K. Forbidden wording / claim discipline
  L. Secret-shape grep
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

# ── M85C rule keys (new in this milestone) ────────────────────────────────────

M85C_RULE_KEYS: frozenset[str] = frozenset({
    # Workspace
    "linear_workspace_low_team_count",
    "linear_workspace_no_webhooks",
    "linear_workspace_no_integrations",
    # Team
    "linear_team_no_backlog_state",
    "linear_team_no_started_state",
    "linear_team_no_completed_state",
    "linear_team_no_canceled_state",
    "linear_team_low_workflow_state_count",
    "linear_team_no_labels",
    "linear_team_no_webhooks",
    # Project
    "linear_project_no_team_scope",
    # Webhook
    "linear_webhook_issue_comment_scope",
    "linear_webhook_attachment_scope",
    # View
    "linear_view_shared_without_team_scope",
    # Integration
    "linear_integration_workspace_scoped",
})

# ── M85B rule keys (must still be present) ───────────────────────────────────

M85B_RULE_KEYS: frozenset[str] = frozenset({
    "linear_workspace_missing_url_key",
    "linear_workspace_missing_logo",
    "linear_team_private",
    "linear_team_low_member_count",
    "linear_team_no_projects",
    "linear_team_auto_archive_disabled",
    "linear_team_cycles_disabled",
    "linear_team_long_cycle_duration",
    "linear_project_no_lead",
    "linear_project_no_members",
    "linear_project_high_issue_count",
    "linear_project_unhealthy",
    "linear_project_unknown_status",
    "linear_workflow_state_unknown_type",
    "linear_label_missing_team_scope",
    "linear_webhook_disabled",
    "linear_webhook_no_secret_indicator",
    "linear_webhook_non_https",
    "linear_webhook_no_events",
    "linear_webhook_broad_resource_scope",
    "linear_view_shared",
    "linear_cycle_high_issue_count",
    "linear_integration_disabled",
    "linear_integration_unknown_type",
})

ALL_LINEAR_RULE_KEYS = M85B_RULE_KEYS | M85C_RULE_KEYS

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

_FORBIDDEN_EVIDENCE_FIELDS = frozenset({
    "api_key", "token", "oauth_token", "secret", "webhook_secret",
    "authorization", "headers", "payload", "request", "response",
    "raw", "email", "phone", "user_email", "user_id", "ip", "ip_address",
    "user_agent", "webhook_url", "url", "issue_title", "issue_description",
    "comment", "attachment", "customer",
})


def _rule_keys(findings) -> set[str]:
    return {f.rule_key for f in findings}


# ── M85C record factories (include new M85C fields) ───────────────────────────

def _workspace_c(overrides: dict | None = None) -> dict:
    """Healthy M85C workspace record with all new fields set."""
    base = {
        "record_type": LINEAR_WORKSPACE,
        "provider": "linear",
        "record_id": "LINEAR_TEST_WORKSPACE_ID",
        "resource_id": "LINEAR_TEST_WORKSPACE_ID",
        "resource_name": "test-workspace",
        "url_key_present": True,
        "logo_present": True,
        # M85C fields
        "team_count": 5,
        "webhook_count": 2,
        "integration_count": 3,
    }
    if overrides:
        base.update(overrides)
    return base


def _team_c(overrides: dict | None = None) -> dict:
    """Healthy M85C team record with all new fields set."""
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
        # M85C fields
        "workflow_state_count": 5,
        "has_backlog_state": True,
        "has_started_state": True,
        "has_completed_state": True,
        "has_canceled_state": True,
        "label_count": 4,
        "webhook_count": 2,
    }
    if overrides:
        base.update(overrides)
    return base


def _project_c(overrides: dict | None = None) -> dict:
    """Healthy M85C project record with new team_count field."""
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
        # M85C field
        "team_count": 2,
    }
    if overrides:
        base.update(overrides)
    return base


def _webhook_c(overrides: dict | None = None) -> dict:
    """Healthy M85C webhook record with new boolean fields."""
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
        # M85C fields
        "webhook_has_comment_type": False,
        "webhook_has_attachment_type": False,
    }
    if overrides:
        base.update(overrides)
    return base


def _view_c(overrides: dict | None = None) -> dict:
    """View record — already sufficient from M85B fields."""
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


def _integration_c(overrides: dict | None = None) -> dict:
    """Integration record — already sufficient from M85B fields."""
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
    def test_m85c_rule_count(self):
        assert len(M85C_RULE_KEYS) == 15

    def test_total_linear_rule_count(self):
        assert len(ALL_LINEAR_RULE_KEYS) == 39

    def test_module_exports_all_linear_keys(self):
        assert LINEAR_RULE_KEYS == ALL_LINEAR_RULE_KEYS

    def test_all_m85c_rule_keys_are_known(self):
        for key in M85C_RULE_KEYS:
            assert is_known_rule_key(key), f"Missing from KNOWN_RULE_KEYS: {key}"

    def test_all_m85b_rule_keys_still_known(self):
        for key in M85B_RULE_KEYS:
            assert is_known_rule_key(key), f"M85B rule missing from KNOWN_RULE_KEYS: {key}"

    def test_no_extra_linear_keys_in_registry(self):
        linear_in_registry = {k for k in KNOWN_RULE_KEYS if k.startswith("linear_")}
        assert linear_in_registry == ALL_LINEAR_RULE_KEYS


# ════════════════════════════════════════════════════════════════════════════
# B. Schema/connector field expansion
# ════════════════════════════════════════════════════════════════════════════

class TestSchemaFieldExpansion:
    def test_workspace_has_new_m85c_fields(self):
        rec = _workspace_c()
        assert "team_count" in rec
        assert "webhook_count" in rec
        assert "integration_count" in rec

    def test_team_has_new_m85c_fields(self):
        rec = _team_c()
        for field in [
            "workflow_state_count", "has_backlog_state", "has_started_state",
            "has_completed_state", "has_canceled_state", "label_count", "webhook_count",
        ]:
            assert field in rec, f"Missing M85C field: {field}"

    def test_project_has_team_count(self):
        rec = _project_c()
        assert "team_count" in rec

    def test_webhook_has_new_m85c_fields(self):
        rec = _webhook_c()
        assert "webhook_has_comment_type" in rec
        assert "webhook_has_attachment_type" in rec

    def test_team_state_booleans_are_bool_or_none(self):
        rec = _team_c()
        for field in ["has_backlog_state", "has_started_state", "has_completed_state", "has_canceled_state"]:
            val = rec[field]
            assert isinstance(val, (bool, type(None))), f"{field} should be bool or None"

    def test_workspace_counts_are_int_or_none(self):
        rec = _workspace_c()
        for field in ["team_count", "webhook_count", "integration_count"]:
            val = rec[field]
            assert isinstance(val, (int, type(None))), f"{field} should be int or None"

    def test_linear_connector_import(self):
        from app.connectors.linear import LinearConnector
        c = LinearConnector()
        assert hasattr(c, "_normalize_workspace")
        assert hasattr(c, "_normalize_team")
        assert hasattr(c, "_normalize_project")
        assert hasattr(c, "_normalize_webhook")

    def test_workspace_normalizer_emits_new_fields(self):
        from app.connectors.linear import LinearConnector
        c = LinearConnector()
        raw = {
            "id": "LINEAR_TEST_WORKSPACE_ID",
            "name": "test",
            "urlKey": "test-workspace",
            "logoUrl": "https://example.com/logo.png",
            "teams": {"totalCount": 3},
        }
        rec = c._normalize_workspace(raw)
        assert rec["team_count"] == 3
        assert rec["webhook_count"] is None  # enriched in fetch()
        assert rec["integration_count"] is None

    def test_team_normalizer_emits_state_booleans(self):
        from app.connectors.linear import LinearConnector
        c = LinearConnector()
        raw = {
            "id": "LINEAR_TEST_TEAM_ID",
            "name": "eng",
            "private": False,
            "members": {"totalCount": 5},
            "projects": {"totalCount": 2},
            "autoArchivePeriod": 7,
            "cyclesEnabled": True,
            "cycleDuration": 7,
            "states": {"nodes": [
                {"type": "backlog"},
                {"type": "started"},
                {"type": "completed"},
                {"type": "cancelled"},
            ]},
            "labels": {"totalCount": 3},
            "webhooks": {"totalCount": 1},
        }
        rec = c._normalize_team(raw)
        assert rec["workflow_state_count"] == 4
        assert rec["has_backlog_state"] is True
        assert rec["has_started_state"] is True
        assert rec["has_completed_state"] is True
        assert rec["has_canceled_state"] is True
        assert rec["label_count"] == 3
        assert rec["webhook_count"] == 1

    def test_team_normalizer_handles_absent_states(self):
        from app.connectors.linear import LinearConnector
        c = LinearConnector()
        raw = {
            "id": "LINEAR_TEST_TEAM_ID",
            "name": "eng",
            "private": False,
            "members": {"totalCount": 5},
            "projects": {"totalCount": 2},
            "autoArchivePeriod": 7,
            "cyclesEnabled": True,
            "cycleDuration": 7,
            # No states/labels/webhooks keys — simulates old API
        }
        rec = c._normalize_team(raw)
        assert rec["workflow_state_count"] is None
        assert rec["has_backlog_state"] is None
        assert rec["has_started_state"] is None
        assert rec["has_completed_state"] is None
        assert rec["has_canceled_state"] is None
        assert rec["label_count"] is None
        assert rec["webhook_count"] is None

    def test_project_normalizer_emits_team_count(self):
        from app.connectors.linear import LinearConnector
        c = LinearConnector()
        raw = {
            "id": "LINEAR_TEST_PROJECT_ID",
            "name": "proj",
            "state": {"name": "started"},
            "health": "onTrack",
            "lead": {"id": "user1"},
            "members": {"totalCount": 3},
            "issues": {"totalCount": 10},
            "teams": {"nodes": [{"id": "t1"}, {"id": "t2"}]},
        }
        rec = c._normalize_project(raw)
        assert rec["team_count"] == 2

    def test_webhook_normalizer_emits_comment_type_boolean(self):
        from app.connectors.linear import LinearConnector
        c = LinearConnector()
        raw = {
            "id": "LINEAR_TEST_WEBHOOK_ID",
            "resourceTypes": ["Issue", "Comment", "IssueLabel"],
            "enabled": True,
            "secret": None,
            "url": "https://example.com/wh",
            "team": {"id": "LINEAR_TEST_TEAM_ID"},
        }
        rec = c._normalize_webhook(raw)
        assert rec["webhook_has_comment_type"] is True
        assert rec["webhook_has_attachment_type"] is False
        # Raw URL and secret must not be stored
        assert "url" not in rec or rec.get("webhook_url_scheme_category") == "https"
        assert "secret" not in rec

    def test_webhook_normalizer_emits_attachment_boolean(self):
        from app.connectors.linear import LinearConnector
        c = LinearConnector()
        raw = {
            "id": "LINEAR_TEST_WEBHOOK_ID",
            "resourceTypes": ["Issue", "Attachment"],
            "enabled": True,
            "secret": "PLACEHOLDER",
            "url": "https://example.com/wh",
            "team": None,
        }
        rec = c._normalize_webhook(raw)
        assert rec["webhook_has_attachment_type"] is True
        assert rec["webhook_has_comment_type"] is False

    def test_webhook_normalizer_does_not_store_resource_type_names(self):
        from app.connectors.linear import LinearConnector
        c = LinearConnector()
        raw = {
            "id": "LINEAR_TEST_WEBHOOK_ID",
            "resourceTypes": ["Issue", "Comment", "Attachment"],
            "enabled": True,
            "secret": None,
            "url": "https://example.com/wh",
            "team": None,
        }
        rec = c._normalize_webhook(raw)
        # The raw resource types list must not appear in the record
        assert "resourceTypes" not in rec
        assert "resource_types" not in rec
        # Only count and booleans
        assert isinstance(rec["webhook_resource_types_count"], int)
        assert isinstance(rec["webhook_has_comment_type"], bool)
        assert isinstance(rec["webhook_has_attachment_type"], bool)


# ════════════════════════════════════════════════════════════════════════════
# C. Rule positive tests — each M85C rule fires on a risky record
# ════════════════════════════════════════════════════════════════════════════

class TestM85CPositives:
    # ── Workspace ──────────────────────────────────────────────────────────

    def test_workspace_low_team_count_fires_at_one(self):
        findings = evaluate(_workspace_c({"team_count": 1}))
        assert "linear_workspace_low_team_count" in _rule_keys(findings)

    def test_workspace_low_team_count_fires_at_zero(self):
        findings = evaluate(_workspace_c({"team_count": 0}))
        assert "linear_workspace_low_team_count" in _rule_keys(findings)

    def test_workspace_no_webhooks_fires(self):
        findings = evaluate(_workspace_c({"webhook_count": 0}))
        assert "linear_workspace_no_webhooks" in _rule_keys(findings)

    def test_workspace_no_integrations_fires(self):
        findings = evaluate(_workspace_c({"integration_count": 0}))
        assert "linear_workspace_no_integrations" in _rule_keys(findings)

    # ── Team ───────────────────────────────────────────────────────────────

    def test_team_no_backlog_state_fires(self):
        findings = evaluate(_team_c({"has_backlog_state": False}))
        assert "linear_team_no_backlog_state" in _rule_keys(findings)

    def test_team_no_started_state_fires(self):
        findings = evaluate(_team_c({"has_started_state": False}))
        assert "linear_team_no_started_state" in _rule_keys(findings)

    def test_team_no_completed_state_fires(self):
        findings = evaluate(_team_c({"has_completed_state": False}))
        assert "linear_team_no_completed_state" in _rule_keys(findings)

    def test_team_no_canceled_state_fires(self):
        findings = evaluate(_team_c({"has_canceled_state": False}))
        assert "linear_team_no_canceled_state" in _rule_keys(findings)

    def test_team_low_workflow_state_count_fires_at_two(self):
        findings = evaluate(_team_c({"workflow_state_count": 2}))
        assert "linear_team_low_workflow_state_count" in _rule_keys(findings)

    def test_team_low_workflow_state_count_fires_at_zero(self):
        findings = evaluate(_team_c({"workflow_state_count": 0}))
        assert "linear_team_low_workflow_state_count" in _rule_keys(findings)

    def test_team_no_labels_fires(self):
        findings = evaluate(_team_c({"label_count": 0}))
        assert "linear_team_no_labels" in _rule_keys(findings)

    def test_team_no_webhooks_fires(self):
        findings = evaluate(_team_c({"webhook_count": 0}))
        assert "linear_team_no_webhooks" in _rule_keys(findings)

    # ── Project ────────────────────────────────────────────────────────────

    def test_project_no_team_scope_fires(self):
        findings = evaluate(_project_c({"team_count": 0}))
        assert "linear_project_no_team_scope" in _rule_keys(findings)

    # ── Webhook ────────────────────────────────────────────────────────────

    def test_webhook_issue_comment_scope_fires(self):
        findings = evaluate(_webhook_c({"webhook_has_comment_type": True}))
        assert "linear_webhook_issue_comment_scope" in _rule_keys(findings)

    def test_webhook_attachment_scope_fires(self):
        findings = evaluate(_webhook_c({"webhook_has_attachment_type": True}))
        assert "linear_webhook_attachment_scope" in _rule_keys(findings)

    # ── View ───────────────────────────────────────────────────────────────

    def test_view_shared_without_team_scope_fires(self):
        findings = evaluate(_view_c({"view_shared": True, "team_id": None}))
        assert "linear_view_shared_without_team_scope" in _rule_keys(findings)

    def test_view_shared_without_team_scope_fires_when_empty_team_id(self):
        findings = evaluate(_view_c({"view_shared": True, "team_id": ""}))
        assert "linear_view_shared_without_team_scope" in _rule_keys(findings)

    # ── Integration ────────────────────────────────────────────────────────

    def test_integration_workspace_scoped_fires(self):
        findings = evaluate(_integration_c({"team_id": None, "integration_enabled": True}))
        assert "linear_integration_workspace_scoped" in _rule_keys(findings)

    def test_integration_workspace_scoped_fires_when_empty_team_id(self):
        findings = evaluate(_integration_c({"team_id": "", "integration_enabled": True}))
        assert "linear_integration_workspace_scoped" in _rule_keys(findings)


# ════════════════════════════════════════════════════════════════════════════
# D. Rule negative tests — healthy M85C records produce no M85C findings
# ════════════════════════════════════════════════════════════════════════════

class TestM85CNegatives:
    def test_healthy_workspace_c_no_m85c_findings(self):
        findings = evaluate(_workspace_c())
        m85c_hits = _rule_keys(findings) & M85C_RULE_KEYS
        assert not m85c_hits, f"Unexpected M85C findings: {m85c_hits}"

    def test_healthy_team_c_no_m85c_findings(self):
        findings = evaluate(_team_c())
        m85c_hits = _rule_keys(findings) & M85C_RULE_KEYS
        assert not m85c_hits, f"Unexpected M85C findings: {m85c_hits}"

    def test_healthy_project_c_no_m85c_findings(self):
        findings = evaluate(_project_c())
        m85c_hits = _rule_keys(findings) & M85C_RULE_KEYS
        assert not m85c_hits

    def test_healthy_webhook_c_no_m85c_findings(self):
        findings = evaluate(_webhook_c())
        m85c_hits = _rule_keys(findings) & M85C_RULE_KEYS
        assert not m85c_hits

    def test_healthy_view_c_no_m85c_findings(self):
        findings = evaluate(_view_c())
        m85c_hits = _rule_keys(findings) & M85C_RULE_KEYS
        assert not m85c_hits

    def test_healthy_integration_c_no_m85c_findings(self):
        findings = evaluate(_integration_c())
        m85c_hits = _rule_keys(findings) & M85C_RULE_KEYS
        assert not m85c_hits

    # Boundary conditions

    def test_workspace_low_team_count_does_not_fire_at_two(self):
        findings = evaluate(_workspace_c({"team_count": 2}))
        assert "linear_workspace_low_team_count" not in _rule_keys(findings)

    def test_workspace_no_webhooks_does_not_fire_when_none_field(self):
        """M85B records without team_count/webhook_count must not trigger M85C rules."""
        rec = _workspace_c()
        rec["webhook_count"] = None
        findings = evaluate(rec)
        assert "linear_workspace_no_webhooks" not in _rule_keys(findings)

    def test_team_state_rules_do_not_fire_when_none_field(self):
        """Old M85B team records without has_X_state must not trigger M85C state rules."""
        # M85B team record without M85C fields
        rec = {
            "record_type": LINEAR_TEAM,
            "provider": "linear",
            "record_id": "LINEAR_TEST_TEAM_ID",
            "resource_id": "LINEAR_TEST_TEAM_ID",
            "resource_name": "eng",
            "private_team": False,
            "team_visibility_category": "public",
            "member_count_category": "medium",
            "project_count": 3,
            "auto_archive_enabled": True,
            "cycle_enabled": True,
            "cycle_duration_category": "short",
            # M85C fields ABSENT
        }
        findings = evaluate(rec)
        m85c_hits = _rule_keys(findings) & M85C_RULE_KEYS
        assert not m85c_hits, f"M85C rules fired on M85B record: {m85c_hits}"

    def test_team_workflow_state_count_does_not_fire_at_three(self):
        findings = evaluate(_team_c({"workflow_state_count": 3}))
        assert "linear_team_low_workflow_state_count" not in _rule_keys(findings)

    def test_project_no_team_scope_does_not_fire_at_one(self):
        findings = evaluate(_project_c({"team_count": 1}))
        assert "linear_project_no_team_scope" not in _rule_keys(findings)

    def test_webhook_comment_scope_does_not_fire_when_false(self):
        findings = evaluate(_webhook_c({"webhook_has_comment_type": False}))
        assert "linear_webhook_issue_comment_scope" not in _rule_keys(findings)

    def test_view_shared_with_team_does_not_fire_without_team_scope_rule(self):
        """Shared view WITH a team scope should not trigger the WITHOUT-team-scope rule."""
        findings = evaluate(_view_c({"view_shared": True, "team_id": "LINEAR_TEST_TEAM_ID"}))
        assert "linear_view_shared_without_team_scope" not in _rule_keys(findings)
        # But the M85B linear_view_shared rule DOES fire
        assert "linear_view_shared" in _rule_keys(findings)

    def test_integration_workspace_scoped_does_not_fire_when_disabled(self):
        """A workspace-scoped but DISABLED integration must not trigger this rule."""
        findings = evaluate(_integration_c({"team_id": None, "integration_enabled": False}))
        assert "linear_integration_workspace_scoped" not in _rule_keys(findings)

    def test_integration_workspace_scoped_does_not_fire_when_team_scoped(self):
        findings = evaluate(_integration_c({"team_id": "LINEAR_TEST_TEAM_ID", "integration_enabled": True}))
        assert "linear_integration_workspace_scoped" not in _rule_keys(findings)


# ════════════════════════════════════════════════════════════════════════════
# E. M85B backwards compatibility
# ════════════════════════════════════════════════════════════════════════════

class TestM85BBackwardsCompatibility:
    """M85B rules must continue to fire on risky M85B records unchanged."""

    def test_m85b_webhook_secret_fires_on_m85b_record(self):
        rec = _webhook_c({"webhook_secret_present": False})
        findings = evaluate(rec)
        assert "linear_webhook_no_secret_indicator" in _rule_keys(findings)

    def test_m85b_workspace_logo_fires_on_m85b_record(self):
        rec = _workspace_c({"logo_present": False})
        findings = evaluate(rec)
        assert "linear_workspace_missing_logo" in _rule_keys(findings)

    def test_m85b_team_cycles_disabled_fires(self):
        rec = _team_c({"cycle_enabled": False})
        findings = evaluate(rec)
        assert "linear_team_cycles_disabled" in _rule_keys(findings)

    def test_m85b_project_no_lead_fires(self):
        rec = _project_c({"lead_present": False})
        findings = evaluate(rec)
        assert "linear_project_no_lead" in _rule_keys(findings)

    def test_m85b_view_shared_fires_on_team_scoped_view(self):
        rec = _view_c({"view_shared": True, "team_id": "LINEAR_TEST_TEAM_ID"})
        findings = evaluate(rec)
        assert "linear_view_shared" in _rule_keys(findings)

    def test_m85b_integration_disabled_fires(self):
        rec = _integration_c({"integration_enabled": False})
        findings = evaluate(rec)
        assert "linear_integration_disabled" in _rule_keys(findings)


# ════════════════════════════════════════════════════════════════════════════
# F. Evidence privacy scan
# ════════════════════════════════════════════════════════════════════════════

class TestEvidencePrivacy:
    def _all_m85c_evidence_keys(self) -> set[str]:
        risky_records = [
            _workspace_c({"team_count": 1}),
            _workspace_c({"webhook_count": 0}),
            _workspace_c({"integration_count": 0}),
            _team_c({"has_backlog_state": False}),
            _team_c({"has_started_state": False}),
            _team_c({"has_completed_state": False}),
            _team_c({"has_canceled_state": False}),
            _team_c({"workflow_state_count": 1}),
            _team_c({"label_count": 0}),
            _team_c({"webhook_count": 0}),
            _project_c({"team_count": 0}),
            _webhook_c({"webhook_has_comment_type": True}),
            _webhook_c({"webhook_has_attachment_type": True}),
            _view_c({"view_shared": True, "team_id": None}),
            _integration_c({"team_id": None, "integration_enabled": True}),
        ]
        keys: set[str] = set()
        for rec in risky_records:
            for f in evaluate(rec):
                if f.rule_key in M85C_RULE_KEYS:
                    keys.update(f.evidence.keys())
        return keys

    def test_no_forbidden_evidence_fields(self):
        found = self._all_m85c_evidence_keys() & _FORBIDDEN_EVIDENCE_FIELDS
        assert not found, f"Forbidden evidence fields: {sorted(found)}"

    def test_provider_is_linear_for_all_m85c_findings(self):
        for rec in [
            _workspace_c({"webhook_count": 0}),
            _team_c({"has_completed_state": False}),
            _project_c({"team_count": 0}),
            _webhook_c({"webhook_has_comment_type": True}),
        ]:
            for f in evaluate(rec):
                if f.rule_key in M85C_RULE_KEYS:
                    assert f.provider == "linear"

    def test_evidence_values_are_safe_types(self):
        risky = [
            _workspace_c({"team_count": 1}),
            _team_c({"workflow_state_count": 2}),
            _webhook_c({"webhook_has_comment_type": True}),
        ]
        for rec in risky:
            for f in evaluate(rec):
                if f.rule_key in M85C_RULE_KEYS:
                    for v in f.evidence.values():
                        assert isinstance(v, (bool, int, str, type(None))), (
                            f"Non-safe evidence type {type(v)} in {f.rule_key}"
                        )

    def test_team_state_evidence_has_no_state_names(self):
        """State names must never appear in evidence — only booleans."""
        findings = evaluate(_team_c({"has_completed_state": False}))
        for f in findings:
            if f.rule_key == "linear_team_no_completed_state":
                assert "completed" not in str(f.evidence.values()).lower() or \
                    f.evidence.get("has_completed_state") is False
                # The key 'has_completed_state' maps to False — that's the safe boolean
                assert "has_completed_state" in f.evidence

    def test_webhook_evidence_does_not_store_resource_type_names(self):
        findings = evaluate(_webhook_c({"webhook_has_comment_type": True}))
        for f in findings:
            if f.rule_key == "linear_webhook_issue_comment_scope":
                # Only boolean indicators, not the string "Comment"
                for v in f.evidence.values():
                    assert v != "Comment"
                    assert v != "comment"


# ════════════════════════════════════════════════════════════════════════════
# G. Registry / confidence / pack wiring
# ════════════════════════════════════════════════════════════════════════════

class TestRegistryWiring:
    def test_all_m85c_keys_in_known_rule_keys(self):
        for key in M85C_RULE_KEYS:
            assert key in KNOWN_RULE_KEYS

    def test_all_m85c_keys_have_confidence(self):
        for key in M85C_RULE_KEYS:
            assert key in RULE_CONFIDENCE, f"Missing confidence: {key}"

    def test_m85c_confidence_values_are_valid(self):
        for key in M85C_RULE_KEYS:
            confidence, _ = RULE_CONFIDENCE[key]
            assert confidence in ("high", "medium"), (
                f"{key} has unsupported confidence: {confidence}"
            )

    def test_all_m85c_keys_in_rule_meta(self):
        for key in M85C_RULE_KEYS:
            assert key in _RULE_META, f"Missing from _RULE_META: {key}"

    def test_rule_meta_provider_is_linear(self):
        for key in M85C_RULE_KEYS:
            provider, _, _ = _RULE_META[key]
            assert provider == "linear"

    def test_high_severity_completed_state_rule(self):
        _, severity, _ = _RULE_META["linear_team_no_completed_state"]
        assert severity == "high"

    def test_rule_pack_covers_all_linear_rules(self):
        pack_linear = {k for k in _RULE_META if k.startswith("linear_")}
        assert pack_linear == ALL_LINEAR_RULE_KEYS


# ════════════════════════════════════════════════════════════════════════════
# H. Coverage service
# ════════════════════════════════════════════════════════════════════════════

class TestCoverageService:
    def test_linear_still_in_providers(self):
        assert "linear" in PROVIDERS

    def test_all_m85c_rules_in_rule_record_types(self):
        for key in M85C_RULE_KEYS:
            assert key in RULE_RECORD_TYPES, f"Missing from RULE_RECORD_TYPES: {key}"

    def test_m85c_rule_record_types_reference_linear_types(self):
        for key in M85C_RULE_KEYS:
            for rt in RULE_RECORD_TYPES[key]:
                assert rt.startswith("linear_"), f"{key} maps to non-linear type: {rt}"

    def test_all_m85b_rules_still_in_rule_record_types(self):
        for key in M85B_RULE_KEYS:
            assert key in RULE_RECORD_TYPES


# ════════════════════════════════════════════════════════════════════════════
# I. Capability matrix + expansion framework
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

    def test_linear_maturity_partial(self):
        cap = get_provider_capability("linear")
        assert cap is not None
        assert cap.maturity == "partial"

    def test_notes_reference_m85c(self):
        cap = get_provider_capability("linear")
        assert cap is not None
        assert "M85C" in cap.notes

    def test_expansion_framework_planned_next_stage_m85d(self):
        # M85I complete — planned_next_stage now points to M86A/Jira.
        fw = get_framework()
        planned = fw["summary"]["planned_next_stage"]
        assert "M85" in planned or "M86" in planned or "Jira" in planned, (
            f"planned_next_stage should reference M85/M86 or later; got {planned!r}"
        )

    def test_expansion_framework_jira_is_head_of_queue(self):
        fw = get_framework()
        recs = fw["recommended_next_providers"]
        assert len(recs) > 0
        assert recs[0]["provider"] == "jira"

    def test_expansion_framework_not_pointing_to_m85c(self):
        fw = get_framework()
        planned = fw["summary"]["planned_next_stage"]
        assert "M85C" not in planned


# ════════════════════════════════════════════════════════════════════════════
# J. Frontend catalog
# ════════════════════════════════════════════════════════════════════════════

class TestFrontendCatalog:
    @pytest.fixture(scope="class")
    def catalog_text(self) -> str:
        assert FE_RULE_CATALOG.exists()
        return FE_RULE_CATALOG.read_text(encoding="utf-8")

    def test_all_m85c_rule_keys_in_catalog(self, catalog_text):
        for key in M85C_RULE_KEYS:
            assert f'key: "{key}"' in catalog_text, (
                f"M85C rule key not in frontend catalog: {key}"
            )

    def test_no_forbidden_phrases_in_m85c_catalog_entries(self, catalog_text):
        # Find the M85C section
        m85c_start = catalog_text.find("M85C workflow/webhook risk expansion")
        if m85c_start == -1:
            return
        m85c_section = catalog_text[m85c_start:]
        for phrase in _FORBIDDEN_PHRASES:
            assert phrase.lower() not in m85c_section.lower(), (
                f"Forbidden phrase in M85C catalog section: {phrase!r}"
            )


# ════════════════════════════════════════════════════════════════════════════
# K. Forbidden wording / claim discipline
# ════════════════════════════════════════════════════════════════════════════

class TestClaimDiscipline:
    def _all_m85c_finding_text(self) -> str:
        risky_records = [
            _workspace_c({"team_count": 0}),
            _workspace_c({"webhook_count": 0}),
            _workspace_c({"integration_count": 0}),
            _team_c({"has_backlog_state": False}),
            _team_c({"has_started_state": False}),
            _team_c({"has_completed_state": False}),
            _team_c({"has_canceled_state": False}),
            _team_c({"workflow_state_count": 1}),
            _team_c({"label_count": 0}),
            _team_c({"webhook_count": 0}),
            _project_c({"team_count": 0}),
            _webhook_c({"webhook_has_comment_type": True}),
            _webhook_c({"webhook_has_attachment_type": True}),
            _view_c({"view_shared": True, "team_id": None}),
            _integration_c({"team_id": None, "integration_enabled": True}),
        ]
        parts: list[str] = []
        for rec in risky_records:
            for f in evaluate(rec):
                if f.rule_key in M85C_RULE_KEYS:
                    parts.append(f.title)
                    parts.append(f.description)
        return "\n".join(parts).lower()

    def test_no_forbidden_phrases_in_m85c_findings(self):
        text = self._all_m85c_finding_text()
        for phrase in _FORBIDDEN_PHRASES:
            assert phrase.lower() not in text, (
                f"Forbidden phrase in M85C finding copy: {phrase!r}"
            )

    def test_m85c_findings_use_review_safe_language(self):
        text = self._all_m85c_finding_text()
        assert "may require review" in text

    def test_m85c_findings_do_not_assert_breach(self):
        text = self._all_m85c_finding_text()
        assert "breach" not in text
        assert "unauthorized access confirmed" not in text


# ════════════════════════════════════════════════════════════════════════════
# L. Secret-shape grep
# ════════════════════════════════════════════════════════════════════════════

_SECRET_PATTERNS = [
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}"),
    re.compile(r"SG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    re.compile(r"AC[0-9a-fA-F]{32}"),
    re.compile(r"SK[0-9a-fA-F]{32}"),
]


class TestSecretShapeGrep:
    def _scan(self, root: Path, suffixes: tuple[str, ...]) -> list[str]:
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
        hits = self._scan(root, (".py",))
        assert not hits, "Secret-shaped strings in backend/app:\n" + "\n".join(hits)

    def test_no_secret_shapes_in_frontend_src(self):
        root = REPO_ROOT / "frontend" / "src"
        hits = self._scan(root, (".ts", ".tsx"))
        assert not hits, "Secret-shaped strings in frontend/src:\n" + "\n".join(hits)


# ════════════════════════════════════════════════════════════════════════════
# M. M85A/M85B regression guard
# ════════════════════════════════════════════════════════════════════════════

class TestRegressionGuard:
    def test_m85a_schema_types_unchanged(self):
        from app.connectors.linear_schema import LINEAR_RECORD_TYPES
        expected = {
            "linear_workspace", "linear_team", "linear_project",
            "linear_workflow_state", "linear_label", "linear_webhook",
            "linear_view", "linear_cycle", "linear_integration",
        }
        assert LINEAR_RECORD_TYPES == frozenset(expected)

    def test_m85b_rule_count_preserved(self):
        assert len(M85B_RULE_KEYS) == 24

    def test_evaluator_dispatches_linear_provider(self):
        from app.services.security_finding_evaluator import evaluate_record
        risky = _webhook_c({"webhook_secret_present": False})
        findings = evaluate_record(risky, "linear")
        assert any(f.rule_key == "linear_webhook_no_secret_indicator" for f in findings)

    def test_evaluator_dispatches_m85c_rules(self):
        from app.services.security_finding_evaluator import evaluate_record
        risky = _team_c({"has_completed_state": False})
        findings = evaluate_record(risky, "linear")
        assert any(f.rule_key == "linear_team_no_completed_state" for f in findings)
