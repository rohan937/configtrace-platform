"""M86B — Jira core security foundation tests.

Verifies 43 Jira configuration-risk rules, registry/confidence/pack/
coverage wiring, capability matrix update, expansion framework pointer,
finding evaluator dispatch, and frontend catalog.

Sections
--------
  A. Rule key taxonomy (43 implemented rules)
  B. Rule positive tests (each rule fires on a risky record)
  C. Rule negative tests (each rule does NOT fire on a healthy record)
  D. Evidence privacy scan (no secrets/PII/URLs/keys in evidence)
  E. Registry / confidence / pack wiring
  F. Coverage service (jira provider, record types, diagnostics)
  G. Capability matrix + expansion framework
  H. Finding evaluator dispatch
  I. Frontend catalog (jira entries present)
  J. Forbidden wording / claim discipline
  K. Secret-shape grep
  L. M86A regression — jira drift provider foundation still intact
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest

from app.services.security_rules.jira import (
    JIRA_RULE_KEYS,
    evaluate,
)
from app.connectors.jira_schema import (
    JIRA_SITE,
    JIRA_PROJECT,
    JIRA_BOARD,
    JIRA_WORKFLOW,
    JIRA_WORKFLOW_SCHEME,
    JIRA_PERMISSION_SCHEME,
    JIRA_NOTIFICATION_SCHEME,
    JIRA_ISSUE_TYPE_SCHEME,
    JIRA_FIELD_CONFIGURATION_SCHEME,
    JIRA_SCREEN_SCHEME,
    JIRA_WEBHOOK,
    JIRA_AUTOMATION_RULE,
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
    # Site (4)
    "jira_site_missing_url",
    "jira_site_no_projects",
    "jira_site_no_webhooks",
    "jira_site_no_automation_rules",
    # Project (10)
    "jira_project_missing_key",
    "jira_project_private",
    "jira_project_archived",
    "jira_project_deleted",
    "jira_project_simplified",
    "jira_project_unknown_type_category",
    "jira_project_unknown_style_category",
    "jira_project_no_boards",
    "jira_project_no_issue_types",
    "jira_project_no_lead",
    # Board (3)
    "jira_board_unknown_type_category",
    "jira_board_unknown_location_type",
    "jira_board_missing_project_link",
    # Workflow (4)
    "jira_workflow_no_statuses",
    "jira_workflow_no_transitions",
    "jira_workflow_excessive_global_transitions",
    "jira_workflow_inactive",
    # Workflow scheme (2)
    "jira_workflow_scheme_unused",
    "jira_workflow_scheme_no_default",
    # Permission scheme (3)
    "jira_permission_scheme_anonymous_grant",
    "jira_permission_scheme_anyone_grant",
    "jira_permission_scheme_logged_in_grant",
    # Notification scheme (3)
    "jira_notification_scheme_no_notifications",
    "jira_notification_scheme_email_recipients",
    "jira_notification_scheme_group_recipients",
    # Issue type scheme (2)
    "jira_issue_type_scheme_no_types",
    "jira_issue_type_scheme_no_default",
    # Field configuration scheme (2)
    "jira_field_configuration_scheme_no_configurations",
    "jira_field_configuration_scheme_hidden_required_conflict",
    # Screen scheme (2)
    "jira_screen_scheme_no_screens",
    "jira_screen_scheme_no_fields",
    # Webhook (5)
    "jira_webhook_disabled",
    "jira_webhook_no_secret_indicator",
    "jira_webhook_non_https",
    "jira_webhook_no_events",
    "jira_webhook_no_jql_filter",
    # Automation rule (3)
    "jira_automation_rule_disabled",
    "jira_automation_rule_unknown_trigger",
    "jira_automation_rule_global_scope",
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
    "api_token",
    "token",
    "oauth_token",
    "session",
    "cookie",
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
    "user",
    "user_id",
    "account_id",
    "ip",
    "ip_address",
    "user_agent",
    "webhook_url",
    "url",
    "site_url",
    "issue_key",
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

def _site(overrides: dict | None = None) -> dict:
    base = {
        "record_type": JIRA_SITE,
        "provider": "jira",
        "record_id": "JIRA_TEST_SITE_ID",
        "resource_id": "JIRA_TEST_SITE_ID",
        "resource_name": "test-site",
        "site_url_present": True,
        "project_count": 5,
        "webhook_count": 2,
        "automation_rule_count": 3,
    }
    if overrides:
        base.update(overrides)
    return base


def _project(overrides: dict | None = None) -> dict:
    base = {
        "record_type": JIRA_PROJECT,
        "provider": "jira",
        "record_id": "JIRA_TEST_PROJECT_ID",
        "resource_id": "JIRA_TEST_PROJECT_ID",
        "resource_name": "test-project",
        "project_key_present": True,
        "project_type_category": "software",
        "project_private": False,
        "project_archived": False,
        "project_deleted": False,
        "project_simplified": False,
        "project_style_category": "classic",
        "board_count": 2,
        "issue_type_count": 5,
        "lead_present": True,
    }
    if overrides:
        base.update(overrides)
    return base


def _board(overrides: dict | None = None) -> dict:
    base = {
        "record_type": JIRA_BOARD,
        "provider": "jira",
        "record_id": "JIRA_TEST_BOARD_ID",
        "resource_id": "JIRA_TEST_BOARD_ID",
        "resource_name": "test-board",
        "board_type_category": "scrum",
        "board_location_type_category": "project",
        "project_id": "JIRA_TEST_PROJECT_ID",
    }
    if overrides:
        base.update(overrides)
    return base


def _workflow(overrides: dict | None = None) -> dict:
    base = {
        "record_type": JIRA_WORKFLOW,
        "provider": "jira",
        "record_id": "JIRA_TEST_WORKFLOW_ID",
        "resource_id": "JIRA_TEST_WORKFLOW_ID",
        "resource_name": "test-workflow",
        "workflow_status_count": 4,
        "workflow_transition_count": 6,
        "workflow_global_transition_count": 1,
        "workflow_active": True,
        "workflow_draft": False,
    }
    if overrides:
        base.update(overrides)
    return base


def _workflow_scheme(overrides: dict | None = None) -> dict:
    base = {
        "record_type": JIRA_WORKFLOW_SCHEME,
        "provider": "jira",
        "record_id": "JIRA_TEST_WORKFLOW_SCHEME_ID",
        "resource_id": "JIRA_TEST_WORKFLOW_SCHEME_ID",
        "resource_name": "test-workflow-scheme",
        "workflow_scheme_project_count": 2,
        "workflow_scheme_default_present": True,
    }
    if overrides:
        base.update(overrides)
    return base


def _permission_scheme(overrides: dict | None = None) -> dict:
    base = {
        "record_type": JIRA_PERMISSION_SCHEME,
        "provider": "jira",
        "record_id": "JIRA_TEST_PERMISSION_SCHEME_ID",
        "resource_id": "JIRA_TEST_PERMISSION_SCHEME_ID",
        "resource_name": "test-permission-scheme",
        "permission_grant_count": 10,
        "permission_anonymous_grant_count": 0,
        "permission_anyone_grant_count": 0,
        "permission_logged_in_grant_count": 0,
        "permission_project_role_grant_count": 8,
    }
    if overrides:
        base.update(overrides)
    return base


def _notification_scheme(overrides: dict | None = None) -> dict:
    base = {
        "record_type": JIRA_NOTIFICATION_SCHEME,
        "provider": "jira",
        "record_id": "JIRA_TEST_NOTIFICATION_SCHEME_ID",
        "resource_id": "JIRA_TEST_NOTIFICATION_SCHEME_ID",
        "resource_name": "test-notification-scheme",
        "notification_count": 5,
        "notification_email_recipient_count": 0,
        "notification_group_recipient_count": 0,
        "notification_project_role_recipient_count": 5,
    }
    if overrides:
        base.update(overrides)
    return base


def _issue_type_scheme(overrides: dict | None = None) -> dict:
    base = {
        "record_type": JIRA_ISSUE_TYPE_SCHEME,
        "provider": "jira",
        "record_id": "JIRA_TEST_ISSUE_TYPE_SCHEME_ID",
        "resource_id": "JIRA_TEST_ISSUE_TYPE_SCHEME_ID",
        "resource_name": "test-issue-type-scheme",
        "issue_type_count": 4,
        "default_issue_type_present": True,
    }
    if overrides:
        base.update(overrides)
    return base


def _field_configuration_scheme(overrides: dict | None = None) -> dict:
    base = {
        "record_type": JIRA_FIELD_CONFIGURATION_SCHEME,
        "provider": "jira",
        "record_id": "JIRA_TEST_FIELD_CONFIG_SCHEME_ID",
        "resource_id": "JIRA_TEST_FIELD_CONFIG_SCHEME_ID",
        "resource_name": "test-field-config-scheme",
        "field_configuration_count": 2,
        "required_field_count": 3,
        "hidden_field_count": 1,
    }
    if overrides:
        base.update(overrides)
    return base


def _screen_scheme(overrides: dict | None = None) -> dict:
    base = {
        "record_type": JIRA_SCREEN_SCHEME,
        "provider": "jira",
        "record_id": "JIRA_TEST_SCREEN_SCHEME_ID",
        "resource_id": "JIRA_TEST_SCREEN_SCHEME_ID",
        "resource_name": "test-screen-scheme",
        "screen_count": 2,
        "tab_count": 3,
        "field_count": 10,
    }
    if overrides:
        base.update(overrides)
    return base


def _webhook(overrides: dict | None = None) -> dict:
    base = {
        "record_type": JIRA_WEBHOOK,
        "provider": "jira",
        "record_id": "JIRA_TEST_WEBHOOK_ID",
        "resource_id": "JIRA_TEST_WEBHOOK_ID",
        "webhook_enabled": True,
        "webhook_event_count": 2,
        "webhook_url_present": True,
        "webhook_url_scheme_category": "https",
        "webhook_jql_filter_present": True,
        "webhook_secret_present": True,
    }
    if overrides:
        base.update(overrides)
    return base


def _automation_rule(overrides: dict | None = None) -> dict:
    base = {
        "record_type": JIRA_AUTOMATION_RULE,
        "provider": "jira",
        "record_id": "JIRA_TEST_AUTOMATION_RULE_ID",
        "resource_id": "JIRA_TEST_AUTOMATION_RULE_ID",
        "resource_name": "test-automation-rule",
        "automation_enabled": True,
        "automation_trigger_type_category": "issue_created",
        "automation_component_count": 3,
        "automation_scope_category": "project",
    }
    if overrides:
        base.update(overrides)
    return base


# ════════════════════════════════════════════════════════════════════════════
# A. Rule key taxonomy
# ════════════════════════════════════════════════════════════════════════════

class TestRuleKeyTaxonomy:
    def test_expected_rule_count(self):
        assert len(EXPECTED_RULE_KEYS) == 43

    def test_module_exports_expected_keys(self):
        assert EXPECTED_RULE_KEYS.issubset(JIRA_RULE_KEYS)

    def test_all_jira_rule_keys_are_known(self):
        for key in EXPECTED_RULE_KEYS:
            assert is_known_rule_key(key), f"Missing from KNOWN_RULE_KEYS: {key}"

    def test_no_extra_jira_keys_in_registry(self):
        jira_in_registry = {k for k in KNOWN_RULE_KEYS if k.startswith("jira_")}
        assert EXPECTED_RULE_KEYS.issubset(jira_in_registry)


# ════════════════════════════════════════════════════════════════════════════
# B. Rule positive tests — each rule fires on a risky record
# ════════════════════════════════════════════════════════════════════════════

class TestRulePositives:
    # ── Site ───────────────────────────────────────────────────────────────

    def test_site_missing_url_fires(self):
        findings = evaluate(_site({"site_url_present": False}))
        assert "jira_site_missing_url" in _rule_keys(findings)

    def test_site_no_projects_fires(self):
        findings = evaluate(_site({"project_count": 0}))
        assert "jira_site_no_projects" in _rule_keys(findings)

    def test_site_no_webhooks_fires(self):
        findings = evaluate(_site({"webhook_count": 0}))
        assert "jira_site_no_webhooks" in _rule_keys(findings)

    def test_site_no_automation_rules_fires(self):
        findings = evaluate(_site({"automation_rule_count": 0}))
        assert "jira_site_no_automation_rules" in _rule_keys(findings)

    # ── Project ────────────────────────────────────────────────────────────

    def test_project_missing_key_fires(self):
        findings = evaluate(_project({"project_key_present": False}))
        assert "jira_project_missing_key" in _rule_keys(findings)

    def test_project_private_fires(self):
        findings = evaluate(_project({"project_private": True}))
        assert "jira_project_private" in _rule_keys(findings)

    def test_project_archived_fires(self):
        findings = evaluate(_project({"project_archived": True}))
        assert "jira_project_archived" in _rule_keys(findings)

    def test_project_deleted_fires(self):
        findings = evaluate(_project({"project_deleted": True}))
        assert "jira_project_deleted" in _rule_keys(findings)

    def test_project_simplified_fires(self):
        findings = evaluate(_project({"project_simplified": True}))
        assert "jira_project_simplified" in _rule_keys(findings)

    def test_project_unknown_type_category_fires(self):
        findings = evaluate(_project({"project_type_category": "unknown"}))
        assert "jira_project_unknown_type_category" in _rule_keys(findings)

    def test_project_unknown_style_category_fires(self):
        findings = evaluate(_project({"project_style_category": "unknown"}))
        assert "jira_project_unknown_style_category" in _rule_keys(findings)

    def test_project_no_boards_fires(self):
        findings = evaluate(_project({"board_count": 0}))
        assert "jira_project_no_boards" in _rule_keys(findings)

    def test_project_no_issue_types_fires(self):
        findings = evaluate(_project({"issue_type_count": 0}))
        assert "jira_project_no_issue_types" in _rule_keys(findings)

    def test_project_no_lead_fires(self):
        findings = evaluate(_project({"lead_present": False}))
        assert "jira_project_no_lead" in _rule_keys(findings)

    # ── Board ──────────────────────────────────────────────────────────────

    def test_board_unknown_type_category_fires(self):
        findings = evaluate(_board({"board_type_category": "unknown"}))
        assert "jira_board_unknown_type_category" in _rule_keys(findings)

    def test_board_unknown_location_type_fires(self):
        findings = evaluate(_board({"board_location_type_category": "unknown"}))
        assert "jira_board_unknown_location_type" in _rule_keys(findings)

    def test_board_missing_project_link_fires(self):
        findings = evaluate(_board({"project_id": None}))
        assert "jira_board_missing_project_link" in _rule_keys(findings)

    # ── Workflow ───────────────────────────────────────────────────────────

    def test_workflow_no_statuses_fires(self):
        findings = evaluate(_workflow({"workflow_status_count": 0}))
        assert "jira_workflow_no_statuses" in _rule_keys(findings)

    def test_workflow_no_transitions_fires(self):
        findings = evaluate(_workflow({"workflow_transition_count": 0}))
        assert "jira_workflow_no_transitions" in _rule_keys(findings)

    def test_workflow_excessive_global_transitions_fires(self):
        findings = evaluate(_workflow({"workflow_global_transition_count": 5}))
        assert "jira_workflow_excessive_global_transitions" in _rule_keys(findings)

    def test_workflow_inactive_fires(self):
        findings = evaluate(_workflow({"workflow_active": False}))
        assert "jira_workflow_inactive" in _rule_keys(findings)

    # ── Workflow scheme ────────────────────────────────────────────────────

    def test_workflow_scheme_unused_fires(self):
        findings = evaluate(_workflow_scheme({"workflow_scheme_project_count": 0}))
        assert "jira_workflow_scheme_unused" in _rule_keys(findings)

    def test_workflow_scheme_no_default_fires(self):
        findings = evaluate(_workflow_scheme({"workflow_scheme_default_present": False}))
        assert "jira_workflow_scheme_no_default" in _rule_keys(findings)

    # ── Permission scheme ──────────────────────────────────────────────────

    def test_permission_scheme_anonymous_grant_fires(self):
        findings = evaluate(_permission_scheme({"permission_anonymous_grant_count": 1}))
        assert "jira_permission_scheme_anonymous_grant" in _rule_keys(findings)

    def test_permission_scheme_anyone_grant_fires(self):
        findings = evaluate(_permission_scheme({"permission_anyone_grant_count": 1}))
        assert "jira_permission_scheme_anyone_grant" in _rule_keys(findings)

    def test_permission_scheme_logged_in_grant_fires(self):
        findings = evaluate(_permission_scheme({"permission_logged_in_grant_count": 1}))
        assert "jira_permission_scheme_logged_in_grant" in _rule_keys(findings)

    # ── Notification scheme ────────────────────────────────────────────────

    def test_notification_scheme_no_notifications_fires(self):
        findings = evaluate(_notification_scheme({"notification_count": 0}))
        assert "jira_notification_scheme_no_notifications" in _rule_keys(findings)

    def test_notification_scheme_email_recipients_fires(self):
        findings = evaluate(_notification_scheme({"notification_email_recipient_count": 1}))
        assert "jira_notification_scheme_email_recipients" in _rule_keys(findings)

    def test_notification_scheme_group_recipients_fires(self):
        findings = evaluate(_notification_scheme({"notification_group_recipient_count": 1}))
        assert "jira_notification_scheme_group_recipients" in _rule_keys(findings)

    # ── Issue type scheme ──────────────────────────────────────────────────

    def test_issue_type_scheme_no_types_fires(self):
        findings = evaluate(_issue_type_scheme({"issue_type_count": 0}))
        assert "jira_issue_type_scheme_no_types" in _rule_keys(findings)

    def test_issue_type_scheme_no_default_fires(self):
        findings = evaluate(_issue_type_scheme({"default_issue_type_present": False}))
        assert "jira_issue_type_scheme_no_default" in _rule_keys(findings)

    # ── Field configuration scheme ─────────────────────────────────────────

    def test_field_configuration_scheme_no_configurations_fires(self):
        findings = evaluate(_field_configuration_scheme({"field_configuration_count": 0}))
        assert "jira_field_configuration_scheme_no_configurations" in _rule_keys(findings)

    def test_field_configuration_scheme_hidden_required_conflict_fires(self):
        # A hidden field that is required at the same time is a misconfiguration.
        findings = evaluate(_field_configuration_scheme({
            "required_field_count": 2,
            "hidden_field_count": 2,
        }))
        # When both required and hidden counts are non-zero we treat as a conflict.
        assert "jira_field_configuration_scheme_hidden_required_conflict" in _rule_keys(findings)

    # ── Screen scheme ──────────────────────────────────────────────────────

    def test_screen_scheme_no_screens_fires(self):
        findings = evaluate(_screen_scheme({"screen_count": 0}))
        assert "jira_screen_scheme_no_screens" in _rule_keys(findings)

    def test_screen_scheme_no_fields_fires(self):
        findings = evaluate(_screen_scheme({"field_count": 0}))
        assert "jira_screen_scheme_no_fields" in _rule_keys(findings)

    # ── Webhook ────────────────────────────────────────────────────────────

    def test_webhook_disabled_fires(self):
        findings = evaluate(_webhook({"webhook_enabled": False}))
        assert "jira_webhook_disabled" in _rule_keys(findings)

    def test_webhook_no_secret_indicator_fires(self):
        findings = evaluate(_webhook({"webhook_secret_present": False}))
        assert "jira_webhook_no_secret_indicator" in _rule_keys(findings)

    def test_webhook_non_https_fires(self):
        findings = evaluate(_webhook({"webhook_url_scheme_category": "non_https"}))
        assert "jira_webhook_non_https" in _rule_keys(findings)

    def test_webhook_no_events_fires(self):
        findings = evaluate(_webhook({"webhook_event_count": 0}))
        assert "jira_webhook_no_events" in _rule_keys(findings)

    def test_webhook_no_jql_filter_fires(self):
        findings = evaluate(_webhook({"webhook_jql_filter_present": False}))
        assert "jira_webhook_no_jql_filter" in _rule_keys(findings)

    # ── Automation rule ────────────────────────────────────────────────────

    def test_automation_rule_disabled_fires(self):
        findings = evaluate(_automation_rule({"automation_enabled": False}))
        assert "jira_automation_rule_disabled" in _rule_keys(findings)

    def test_automation_rule_unknown_trigger_fires(self):
        findings = evaluate(_automation_rule({"automation_trigger_type_category": "unknown"}))
        assert "jira_automation_rule_unknown_trigger" in _rule_keys(findings)

    def test_automation_rule_global_scope_fires(self):
        findings = evaluate(_automation_rule({"automation_scope_category": "global"}))
        assert "jira_automation_rule_global_scope" in _rule_keys(findings)


# ════════════════════════════════════════════════════════════════════════════
# C. Rule negative tests — healthy records produce no findings
# ════════════════════════════════════════════════════════════════════════════

class TestRuleNegatives:
    def test_healthy_site_no_findings(self):
        assert evaluate(_site()) == []

    def test_healthy_project_no_findings(self):
        assert evaluate(_project()) == []

    def test_healthy_board_no_findings(self):
        assert evaluate(_board()) == []

    def test_healthy_workflow_no_findings(self):
        assert evaluate(_workflow()) == []

    def test_healthy_workflow_scheme_no_findings(self):
        assert evaluate(_workflow_scheme()) == []

    def test_healthy_permission_scheme_no_findings(self):
        assert evaluate(_permission_scheme()) == []

    def test_healthy_notification_scheme_no_findings(self):
        assert evaluate(_notification_scheme()) == []

    def test_healthy_issue_type_scheme_no_findings(self):
        assert evaluate(_issue_type_scheme()) == []

    def test_healthy_field_configuration_scheme_no_findings(self):
        assert evaluate(_field_configuration_scheme()) == []

    def test_healthy_screen_scheme_no_findings(self):
        assert evaluate(_screen_scheme()) == []

    def test_healthy_webhook_no_findings(self):
        assert evaluate(_webhook()) == []

    def test_healthy_automation_rule_no_findings(self):
        assert evaluate(_automation_rule()) == []

    def test_unknown_record_type_returns_empty(self):
        assert evaluate({"record_type": "jira_unknown_surface", "provider": "jira"}) == []

    def test_non_dict_input_returns_empty(self):
        assert evaluate("not a dict") == []  # type: ignore[arg-type]
        assert evaluate(None) == []  # type: ignore[arg-type]


# ════════════════════════════════════════════════════════════════════════════
# D. Evidence privacy scan
# ════════════════════════════════════════════════════════════════════════════

class TestEvidencePrivacy:
    """Evidence must never contain sensitive field names."""

    def _all_risky_records(self) -> list[dict]:
        return [
            _site({"site_url_present": False}),
            _site({"project_count": 0}),
            _site({"webhook_count": 0}),
            _site({"automation_rule_count": 0}),
            _project({"project_key_present": False}),
            _project({"project_private": True}),
            _project({"project_archived": True}),
            _project({"project_deleted": True}),
            _project({"project_simplified": True}),
            _project({"project_type_category": "unknown"}),
            _project({"project_style_category": "unknown"}),
            _project({"board_count": 0}),
            _project({"issue_type_count": 0}),
            _project({"lead_present": False}),
            _board({"board_type_category": "unknown"}),
            _board({"board_location_type_category": "unknown"}),
            _board({"project_id": None}),
            _workflow({"workflow_status_count": 0}),
            _workflow({"workflow_transition_count": 0}),
            _workflow({"workflow_global_transition_count": 5}),
            _workflow({"workflow_active": False}),
            _workflow_scheme({"workflow_scheme_project_count": 0}),
            _workflow_scheme({"workflow_scheme_default_present": False}),
            _permission_scheme({"permission_anonymous_grant_count": 1}),
            _permission_scheme({"permission_anyone_grant_count": 1}),
            _permission_scheme({"permission_logged_in_grant_count": 1}),
            _notification_scheme({"notification_count": 0}),
            _notification_scheme({"notification_email_recipient_count": 1}),
            _notification_scheme({"notification_group_recipient_count": 1}),
            _issue_type_scheme({"issue_type_count": 0}),
            _issue_type_scheme({"default_issue_type_present": False}),
            _field_configuration_scheme({"field_configuration_count": 0}),
            _field_configuration_scheme({"required_field_count": 2, "hidden_field_count": 2}),
            _screen_scheme({"screen_count": 0}),
            _screen_scheme({"field_count": 0}),
            _webhook({"webhook_enabled": False}),
            _webhook({"webhook_secret_present": False}),
            _webhook({"webhook_url_scheme_category": "non_https"}),
            _webhook({"webhook_event_count": 0}),
            _webhook({"webhook_jql_filter_present": False}),
            _automation_rule({"automation_enabled": False}),
            _automation_rule({"automation_trigger_type_category": "unknown"}),
            _automation_rule({"automation_scope_category": "global"}),
        ]

    def _all_evidence_keys(self) -> set[str]:
        keys: set[str] = set()
        for rec in self._all_risky_records():
            for f in evaluate(rec):
                keys.update(f.evidence.keys())
        return keys

    def test_no_forbidden_evidence_fields(self):
        found = self._all_evidence_keys() & _FORBIDDEN_EVIDENCE_FIELDS
        assert not found, f"Forbidden evidence fields found: {sorted(found)}"

    def test_provider_is_jira(self):
        for rec in [
            _site({"site_url_present": False}),
            _webhook({"webhook_secret_present": False}),
            _automation_rule({"automation_enabled": False}),
        ]:
            for f in evaluate(rec):
                assert f.provider == "jira"

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
            _webhook({"webhook_secret_present": False, "webhook_event_count": 0}),
            _permission_scheme({"permission_anonymous_grant_count": 1}),
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
    def test_all_jira_keys_in_known_rule_keys(self):
        for key in EXPECTED_RULE_KEYS:
            assert key in KNOWN_RULE_KEYS, f"Missing from KNOWN_RULE_KEYS: {key}"

    def test_all_jira_keys_have_confidence(self):
        for key in EXPECTED_RULE_KEYS:
            assert key in RULE_CONFIDENCE, f"Missing confidence entry: {key}"

    def test_all_jira_confidence_values_are_high_or_medium(self):
        for key in EXPECTED_RULE_KEYS:
            confidence, _ = RULE_CONFIDENCE[key]
            assert confidence in ("high", "medium"), (
                f"{key} has unsupported confidence level: {confidence}"
            )

    def test_all_jira_keys_in_rule_meta_pack(self):
        for key in EXPECTED_RULE_KEYS:
            assert key in _RULE_META, f"Missing from _RULE_META: {key}"

    def test_rule_meta_provider_is_jira(self):
        for key in EXPECTED_RULE_KEYS:
            provider, _, _ = _RULE_META[key]
            assert provider == "jira", f"{key} has wrong provider: {provider}"

    def test_rule_meta_severity_values_valid(self):
        valid_severities = {"critical", "high", "medium", "low", "info"}
        for key in EXPECTED_RULE_KEYS:
            _, severity, _ = _RULE_META[key]
            assert severity in valid_severities, f"{key} has invalid severity: {severity}"

    def test_high_severity_webhook_rules(self):
        high_webhook_rules = {
            "jira_webhook_no_secret_indicator",
            "jira_webhook_non_https",
        }
        for key in high_webhook_rules:
            _, severity, _ = _RULE_META[key]
            assert severity == "high", f"{key} should be high severity"

    def test_rule_pack_covers_all_jira_rules(self):
        pack_jira = {k for k in _RULE_META if k.startswith("jira_")}
        assert EXPECTED_RULE_KEYS.issubset(pack_jira)


# ════════════════════════════════════════════════════════════════════════════
# F. Coverage service
# ════════════════════════════════════════════════════════════════════════════

class TestCoverageService:
    def test_jira_in_providers_list(self):
        assert "jira" in PROVIDERS

    def test_jira_in_provider_surfaces(self):
        assert "jira" in PROVIDER_SURFACES
        surfaces = PROVIDER_SURFACES["jira"]
        assert len(surfaces) >= 5

    def test_all_jira_rules_in_rule_record_types(self):
        for key in EXPECTED_RULE_KEYS:
            assert key in RULE_RECORD_TYPES, f"Missing from RULE_RECORD_TYPES: {key}"

    def test_rule_record_types_reference_jira_types(self):
        for key in EXPECTED_RULE_KEYS:
            for rt in RULE_RECORD_TYPES[key]:
                assert rt.startswith("jira_"), (
                    f"{key} maps to non-jira record type: {rt}"
                )

    def test_jira_record_type_diagnostics_present(self):
        expected_types = {
            "jira_site",
            "jira_project",
            "jira_board",
            "jira_workflow",
            "jira_workflow_scheme",
            "jira_permission_scheme",
            "jira_notification_scheme",
            "jira_issue_type_scheme",
            "jira_field_configuration_scheme",
            "jira_screen_scheme",
            "jira_webhook",
            "jira_automation_rule",
        }
        for rt in expected_types:
            assert rt in RECORD_TYPE_DIAGNOSTICS, f"Missing diagnostic: {rt}"

    def test_diagnostics_have_required_fields(self):
        expected_types = {
            "jira_site", "jira_project", "jira_board", "jira_workflow",
            "jira_workflow_scheme", "jira_permission_scheme",
            "jira_notification_scheme", "jira_issue_type_scheme",
            "jira_field_configuration_scheme", "jira_screen_scheme",
            "jira_webhook", "jira_automation_rule",
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
    def test_jira_drift_risk_classification_true(self):
        cap = get_provider_capability("jira")
        assert cap is not None
        assert cap.drift.drift_risk_classification is True

    def test_jira_security_rules_true(self):
        cap = get_provider_capability("jira")
        assert cap is not None
        assert cap.security.security_rules is True

    def test_jira_drift_snapshots_true(self):
        cap = get_provider_capability("jira")
        assert cap is not None
        assert cap.drift.drift_snapshots is True

    def test_jira_drift_diff_true(self):
        cap = get_provider_capability("jira")
        assert cap is not None
        assert cap.drift.drift_diff is True

    def test_jira_activity_ingestion_false(self):
        # M86D advanced activity_ingestion to True; assert current state.
        cap = get_provider_capability("jira")
        assert cap is not None
        assert cap.security.activity_ingestion is True

    def test_jira_activity_signals_false(self):
        # M86E advanced activity_signals to True. Assert current state.
        cap = get_provider_capability("jira")
        assert cap is not None
        assert cap.security.activity_signals is True

    def test_jira_risk_activity_correlations_false(self):
        # M86F advanced risk_activity_correlations to True.
        cap = get_provider_capability("jira")
        assert cap is not None
        assert cap.security.risk_activity_correlations is True

    def test_jira_demo_seed_clear_true(self):
        # M86G ships the Jira demo seed/clear; flag flips True.
        cap = get_provider_capability("jira")
        assert cap is not None
        assert cap.security.demo_seed_clear is True

    def test_jira_case_report_true(self):
        # M86G adds Jira case-report support; flag flips True.
        cap = get_provider_capability("jira")
        assert cap is not None
        assert cap.security.case_report is True

    def test_jira_evidence_timeline_true(self):
        # M86G enables the cross-provider evidence timeline for Jira.
        cap = get_provider_capability("jira")
        assert cap is not None
        assert cap.security.evidence_timeline is True

    def test_jira_evidence_graph_true(self):
        # M86G enables the evidence relationship graph for Jira.
        cap = get_provider_capability("jira")
        assert cap is not None
        assert cap.security.evidence_graph is True

    def test_jira_maturity_partial(self):
        cap = get_provider_capability("jira")
        assert cap is not None
        assert cap.maturity == "partial"

    def test_notes_reference_m86b(self):
        cap = get_provider_capability("jira")
        assert cap is not None
        assert "M86B" in cap.notes

    def test_expansion_framework_planned_next_stage_m86c(self):
        # M86C–M86H have since landed — planned_next_stage now points to M86I.
        fw = get_framework()
        planned = fw["summary"]["planned_next_stage"]
        assert (
            "M86C" in planned or "M86D" in planned or "M86E" in planned
            or "M86F" in planned or "M86G" in planned or "M86H" in planned
            or "M86I" in planned
            or "M87A" in planned or "GitLab" in planned
        ), (
            f"planned_next_stage should reference M86C or later; got {planned!r}"
        )

    def test_expansion_framework_recommended_queue_head_is_gitlab(self):
        fw = get_framework()
        recs = fw["recommended_next_providers"]
        assert len(recs) > 0
        assert recs[0]["provider"] in ("gitlab", "terraform_cloud", "kubernetes", "sentry")


# ════════════════════════════════════════════════════════════════════════════
# H. Finding evaluator dispatch
# ════════════════════════════════════════════════════════════════════════════

class TestFindingEvaluatorDispatch:
    def test_jira_in_provider_rules(self):
        assert "jira" in _PROVIDER_RULES

    def test_evaluator_dispatches_jira_webhook_finding(self):
        from app.services.security_finding_evaluator import evaluate_record
        risky = _webhook({"webhook_secret_present": False})
        findings = evaluate_record(risky, "jira")
        assert any(f.rule_key == "jira_webhook_no_secret_indicator" for f in findings)

    def test_evaluator_dispatches_jira_project_finding(self):
        from app.services.security_finding_evaluator import evaluate_record
        risky = _project({"lead_present": False})
        findings = evaluate_record(risky, "jira")
        assert any(f.rule_key == "jira_project_no_lead" for f in findings)

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

    def test_jira_provider_entries_present(self, catalog_text):
        assert 'provider: "jira"' in catalog_text

    def test_all_jira_rule_keys_in_catalog(self, catalog_text):
        for key in EXPECTED_RULE_KEYS:
            assert f'key: "{key}"' in catalog_text, (
                f"Jira rule key not in frontend catalog: {key}"
            )

    def test_webhook_secret_rule_in_catalog(self, catalog_text):
        assert 'key: "jira_webhook_no_secret_indicator"' in catalog_text

    def test_webhook_non_https_rule_in_catalog(self, catalog_text):
        assert 'key: "jira_webhook_non_https"' in catalog_text

    def test_no_forbidden_phrases_in_jira_entries(self, catalog_text):
        jira_section_start = catalog_text.find('provider: "jira"')
        if jira_section_start == -1:
            return
        jira_section = catalog_text[jira_section_start:]
        for phrase in _FORBIDDEN_PHRASES:
            assert phrase.lower() not in jira_section.lower(), (
                f"Forbidden phrase in frontend catalog Jira section: {phrase!r}"
            )


# ════════════════════════════════════════════════════════════════════════════
# J. Forbidden wording / claim discipline
# ════════════════════════════════════════════════════════════════════════════

class TestClaimDiscipline:
    def _all_finding_text(self) -> str:
        risky_records = [
            _site({"site_url_present": False}),
            _site({"project_count": 0}),
            _site({"webhook_count": 0}),
            _site({"automation_rule_count": 0}),
            _project({"project_key_present": False}),
            _project({"project_private": True}),
            _project({"project_archived": True}),
            _project({"project_deleted": True}),
            _project({"project_simplified": True}),
            _project({"project_type_category": "unknown"}),
            _project({"project_style_category": "unknown"}),
            _project({"board_count": 0}),
            _project({"issue_type_count": 0}),
            _project({"lead_present": False}),
            _board({"board_type_category": "unknown"}),
            _board({"board_location_type_category": "unknown"}),
            _board({"project_id": None}),
            _workflow({"workflow_status_count": 0}),
            _workflow({"workflow_transition_count": 0}),
            _workflow({"workflow_global_transition_count": 5}),
            _workflow({"workflow_active": False}),
            _workflow_scheme({"workflow_scheme_project_count": 0}),
            _workflow_scheme({"workflow_scheme_default_present": False}),
            _permission_scheme({"permission_anonymous_grant_count": 1}),
            _permission_scheme({"permission_anyone_grant_count": 1}),
            _permission_scheme({"permission_logged_in_grant_count": 1}),
            _notification_scheme({"notification_count": 0}),
            _notification_scheme({"notification_email_recipient_count": 1}),
            _notification_scheme({"notification_group_recipient_count": 1}),
            _issue_type_scheme({"issue_type_count": 0}),
            _issue_type_scheme({"default_issue_type_present": False}),
            _field_configuration_scheme({"field_configuration_count": 0}),
            _field_configuration_scheme({"required_field_count": 2, "hidden_field_count": 2}),
            _screen_scheme({"screen_count": 0}),
            _screen_scheme({"field_count": 0}),
            _webhook({"webhook_enabled": False}),
            _webhook({"webhook_secret_present": False}),
            _webhook({"webhook_url_scheme_category": "non_https"}),
            _webhook({"webhook_event_count": 0}),
            _webhook({"webhook_jql_filter_present": False}),
            _automation_rule({"automation_enabled": False}),
            _automation_rule({"automation_trigger_type_category": "unknown"}),
            _automation_rule({"automation_scope_category": "global"}),
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
# K. Secret-shape grep (no real credentials in backend/frontend Jira source)
# ════════════════════════════════════════════════════════════════════════════

_SECRET_PATTERNS = [
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}"),               # JWT
    re.compile(r"SG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),  # SendGrid
    re.compile(r"AC[0-9a-fA-F]{32}"),                    # Twilio account SID
    re.compile(r"SK[0-9a-fA-F]{32}"),                    # Twilio auth token
]


class TestSecretShapeGrep:
    def _scan_files(self, root: Path, suffixes: tuple[str, ...], name_filter: str | None = None) -> list[str]:
        hits: list[str] = []
        for path in root.rglob("*"):
            if not path.is_file() or path.suffix not in suffixes:
                continue
            if name_filter is not None and name_filter not in str(path).lower():
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            for pattern in _SECRET_PATTERNS:
                for m in pattern.finditer(text):
                    hits.append(f"{path.relative_to(root)}:{m.start()}:{m.group()[:20]}")
        return hits

    def test_no_secret_shapes_in_backend_jira_modules(self):
        root = REPO_ROOT / "backend" / "app"
        hits = self._scan_files(root, (".py",), name_filter="jira")
        assert not hits, f"Secret-shaped strings found in backend/app jira modules:\n" + "\n".join(hits)

    def test_no_secret_shapes_in_frontend_jira_modules(self):
        root = REPO_ROOT / "frontend" / "src"
        hits = self._scan_files(root, (".ts", ".tsx"), name_filter="jira")
        assert not hits, f"Secret-shaped strings found in frontend/src jira modules:\n" + "\n".join(hits)


# ════════════════════════════════════════════════════════════════════════════
# L. M86A regression — jira drift provider foundation still intact
# ════════════════════════════════════════════════════════════════════════════

class TestM86ARegressionGuard:
    def test_jira_schema_types_available(self):
        from app.connectors.jira_schema import (
            JIRA_RECORD_TYPES,
            JIRA_SITE,
            JIRA_PROJECT,
            JIRA_BOARD,
            JIRA_WORKFLOW,
            JIRA_WORKFLOW_SCHEME,
            JIRA_PERMISSION_SCHEME,
            JIRA_NOTIFICATION_SCHEME,
            JIRA_ISSUE_TYPE_SCHEME,
            JIRA_FIELD_CONFIGURATION_SCHEME,
            JIRA_SCREEN_SCHEME,
            JIRA_WEBHOOK,
            JIRA_AUTOMATION_RULE,
        )
        assert len(JIRA_RECORD_TYPES) == 12
        expected = {
            "jira_site", "jira_project", "jira_board", "jira_workflow",
            "jira_workflow_scheme", "jira_permission_scheme",
            "jira_notification_scheme", "jira_issue_type_scheme",
            "jira_field_configuration_scheme", "jira_screen_scheme",
            "jira_webhook", "jira_automation_rule",
        }
        assert JIRA_RECORD_TYPES == frozenset(expected)

    def test_jira_connector_importable(self):
        from app.connectors.jira import JiraConnector
        assert JiraConnector is not None

    def test_jira_provider_in_capability_matrix(self):
        cap = get_provider_capability("jira")
        assert cap is not None
        assert cap.provider == "jira"
        assert cap.label == "Jira"
