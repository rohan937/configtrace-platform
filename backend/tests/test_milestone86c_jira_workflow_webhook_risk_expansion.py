"""M86C — Jira workflow/webhook risk expansion tests.

Verifies 39 new Jira configuration-risk rules (on top of the 43 M86B rules),
registry/confidence/pack/coverage wiring, capability matrix update, expansion
framework pointer, and frontend catalog.

Sections
--------
  A. Registration (registry / confidence / pack / coverage / frontend catalog)
  B. Rule fire tests (risky + healthy)
  C. Privacy / safety (evidence fields, forbidden wording, provider)
  D. Framework (capability matrix + expansion framework pointers)
  E. M86B regression spot-check
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.services.security_rules.jira import (
    JIRA_RULE_KEYS,
    evaluate,
)
from app.connectors.jira_schema import (
    JIRA_WORKFLOW,
    JIRA_WORKFLOW_SCHEME,
    JIRA_PERMISSION_SCHEME,
    JIRA_NOTIFICATION_SCHEME,
    JIRA_WEBHOOK,
    JIRA_AUTOMATION_RULE,
    JIRA_BOARD,
    JIRA_SCREEN_SCHEME,
)
from app.services.security_rule_registry import KNOWN_RULE_KEYS, is_known_rule_key
from app.services.security_rule_confidence import RULE_CONFIDENCE
from app.services.security_rule_pack import _RULE_META
from app.services.security_coverage_service import RULE_RECORD_TYPES
from app.services.provider_capability_matrix_service import get_provider_capability
from app.services.provider_expansion_framework import get_framework

REPO_ROOT = Path(__file__).resolve().parents[2]
FE_RULE_CATALOG = REPO_ROOT / "frontend" / "src" / "lib" / "securityRuleCatalog.ts"

# ── Safe placeholder IDs ──────────────────────────────────────────────────────

JIRA_TEST_WORKFLOW_ID = "JIRA_TEST_WORKFLOW_ID"
JIRA_TEST_WORKFLOW_SCHEME_ID = "JIRA_TEST_WORKFLOW_SCHEME_ID"
JIRA_TEST_PERMISSION_SCHEME_ID = "JIRA_TEST_PERMISSION_SCHEME_ID"
JIRA_TEST_NOTIFICATION_SCHEME_ID = "JIRA_TEST_NOTIFICATION_SCHEME_ID"
JIRA_TEST_WEBHOOK_ID = "JIRA_TEST_WEBHOOK_ID"
JIRA_TEST_AUTOMATION_RULE_ID = "JIRA_TEST_AUTOMATION_RULE_ID"
JIRA_TEST_BOARD_ID = "JIRA_TEST_BOARD_ID"
JIRA_TEST_SCREEN_SCHEME_ID = "JIRA_TEST_SCREEN_SCHEME_ID"
JIRA_TEST_FINDING_ID = "JIRA_TEST_FINDING_ID"


# ── M86C rule keys (new in this milestone) ────────────────────────────────────

M86C_RULE_KEYS: frozenset[str] = frozenset({
    # Workflow (7)
    "jira_workflow_no_done_status",
    "jira_workflow_no_in_progress_status",
    "jira_workflow_high_transition_rule_count",
    "jira_workflow_high_validator_count",
    "jira_workflow_high_condition_count",
    "jira_workflow_high_post_function_count",
    "jira_workflow_orphan_statuses",
    # Workflow scheme (3)
    "jira_workflow_scheme_unmapped_issue_types",
    "jira_workflow_scheme_low_workflow_count",
    "jira_workflow_scheme_high_issue_type_mapping_count",
    # Permission scheme (8)
    "jira_permission_scheme_public_browse_projects",
    "jira_permission_scheme_public_administer_projects",
    "jira_permission_scheme_public_manage_sprints",
    "jira_permission_scheme_public_create_issues",
    "jira_permission_scheme_public_transition_issues",
    "jira_permission_scheme_unknown_holder",
    "jira_permission_scheme_high_privilege_grants",
    "jira_permission_scheme_high_public_grant_count",
    # Notification scheme (2)
    "jira_notification_scheme_unknown_recipients",
    "jira_notification_scheme_high_event_count",
    # Webhook (5)
    "jira_webhook_comment_event_scope",
    "jira_webhook_attachment_event_scope",
    "jira_webhook_sprint_event_scope",
    "jira_webhook_worklog_event_scope",
    "jira_webhook_all_issue_events",
    # Automation rule (8)
    "jira_automation_rule_web_request_action",
    "jira_automation_rule_email_action",
    "jira_automation_rule_external_action",
    "jira_automation_rule_comment_action",
    "jira_automation_rule_high_action_count",
    "jira_automation_rule_high_branch_count",
    "jira_automation_rule_multi_project_scope",
    "jira_automation_rule_unknown_scope",
    # Board (5)
    "jira_board_no_filter_indicator",
    "jira_board_broad_jql_filter",
    "jira_board_high_quick_filter_count",
    "jira_board_unknown_swimlane_strategy",
    "jira_board_no_columns",
    # Screen scheme (1)
    "jira_screen_scheme_unmapped_screens",
})

_FORBIDDEN_PHRASES = [
    "compromise confirmed",
    "breach detected",
    "secret leaked",
    "data leaked",
    "unauthorized access confirmed",
    "attacker found",
    "orders exposed",
]

_FORBIDDEN_EVIDENCE_FIELDS = frozenset({
    "jql", "filter", "url", "email", "token", "api_token", "account_id",
    "user", "issue_key", "issue_title", "comment", "attachment", "customer",
    "webhook_url",
})


def _rule_keys(findings) -> set[str]:
    return {f.rule_key for f in findings}


# ── Safe record factories (healthy by default; all M86C fields populated) ─────

def _workflow(overrides: dict | None = None) -> dict:
    base = {
        "record_type": JIRA_WORKFLOW,
        "provider": "jira",
        "record_id": JIRA_TEST_WORKFLOW_ID,
        "resource_id": JIRA_TEST_WORKFLOW_ID,
        "resource_name": "test-workflow",
        "workflow_status_count": 4,
        "workflow_transition_count": 6,
        "workflow_global_transition_count": 1,
        "workflow_active": True,
        "workflow_draft": False,
        # M86C fields
        "workflow_has_done_status": True,
        "workflow_has_in_progress_status": True,
        "workflow_transition_rule_count": 3,
        "workflow_validator_count": 2,
        "workflow_condition_count": 2,
        "workflow_post_function_count": 3,
        "workflow_orphan_status_count": 0,
        "workflow_status_category_count": 3,
    }
    if overrides:
        base.update(overrides)
    return base


def _workflow_scheme(overrides: dict | None = None) -> dict:
    base = {
        "record_type": JIRA_WORKFLOW_SCHEME,
        "provider": "jira",
        "record_id": JIRA_TEST_WORKFLOW_SCHEME_ID,
        "resource_id": JIRA_TEST_WORKFLOW_SCHEME_ID,
        "resource_name": "test-workflow-scheme",
        "workflow_scheme_project_count": 2,
        "workflow_scheme_default_present": True,
        # M86C fields
        "workflow_scheme_workflow_count": 3,
        "workflow_scheme_issue_type_mapping_count": 4,
        "workflow_scheme_unmapped_issue_type_count": 0,
    }
    if overrides:
        base.update(overrides)
    return base


def _permission_scheme(overrides: dict | None = None) -> dict:
    base = {
        "record_type": JIRA_PERMISSION_SCHEME,
        "provider": "jira",
        "record_id": JIRA_TEST_PERMISSION_SCHEME_ID,
        "resource_id": JIRA_TEST_PERMISSION_SCHEME_ID,
        "resource_name": "test-permission-scheme",
        "permission_grant_count": 10,
        "permission_anonymous_grant_count": 0,
        "permission_anyone_grant_count": 0,
        "permission_logged_in_grant_count": 0,
        "permission_project_role_grant_count": 8,
        # M86C fields
        "permission_public_browse_projects": False,
        "permission_public_administer_projects": False,
        "permission_public_manage_sprints": False,
        "permission_public_create_issues": False,
        "permission_public_transition_issues": False,
        "permission_unknown_holder_count": 0,
        "permission_high_privilege_grant_count": 0,
        "permission_public_grant_count": 0,
    }
    if overrides:
        base.update(overrides)
    return base


def _notification_scheme(overrides: dict | None = None) -> dict:
    base = {
        "record_type": JIRA_NOTIFICATION_SCHEME,
        "provider": "jira",
        "record_id": JIRA_TEST_NOTIFICATION_SCHEME_ID,
        "resource_id": JIRA_TEST_NOTIFICATION_SCHEME_ID,
        "resource_name": "test-notification-scheme",
        "notification_count": 5,
        "notification_email_recipient_count": 0,
        "notification_group_recipient_count": 0,
        "notification_project_role_recipient_count": 5,
        # M86C fields
        "notification_all_watchers_recipient_count": 0,
        "notification_current_assignee_recipient_count": 1,
        "notification_reporter_recipient_count": 1,
        "notification_unknown_recipient_count": 0,
        "notification_event_count": 5,
        "notification_public_recipient_count": 0,
    }
    if overrides:
        base.update(overrides)
    return base


def _webhook(overrides: dict | None = None) -> dict:
    base = {
        "record_type": JIRA_WEBHOOK,
        "provider": "jira",
        "record_id": JIRA_TEST_WEBHOOK_ID,
        "resource_id": JIRA_TEST_WEBHOOK_ID,
        "webhook_enabled": True,
        "webhook_event_count": 2,
        "webhook_url_present": True,
        "webhook_url_scheme_category": "https",
        "webhook_jql_filter_present": True,
        "webhook_secret_present": True,
        # M86C fields
        "webhook_has_issue_events": True,
        "webhook_has_comment_events": False,
        "webhook_has_attachment_events": False,
        "webhook_has_project_events": False,
        "webhook_has_sprint_events": False,
        "webhook_has_worklog_events": False,
        "webhook_all_issue_events": False,
        "webhook_jql_empty_or_broad": False,
        "webhook_event_scope_category": "scoped",
    }
    if overrides:
        base.update(overrides)
    return base


def _automation_rule(overrides: dict | None = None) -> dict:
    base = {
        "record_type": JIRA_AUTOMATION_RULE,
        "provider": "jira",
        "record_id": JIRA_TEST_AUTOMATION_RULE_ID,
        "resource_id": JIRA_TEST_AUTOMATION_RULE_ID,
        "resource_name": "test-automation-rule",
        "automation_enabled": True,
        "automation_trigger_type_category": "issue_created",
        "automation_component_count": 3,
        "automation_scope_category": "project",
        # M86C fields
        "automation_action_count": 2,
        "automation_condition_count": 1,
        "automation_branch_count": 1,
        "automation_has_web_request_action": False,
        "automation_has_email_action": False,
        "automation_has_external_action": False,
        "automation_has_comment_action": False,
        "automation_recently_updated": False,
    }
    if overrides:
        base.update(overrides)
    return base


def _board(overrides: dict | None = None) -> dict:
    base = {
        "record_type": JIRA_BOARD,
        "provider": "jira",
        "record_id": JIRA_TEST_BOARD_ID,
        "resource_id": JIRA_TEST_BOARD_ID,
        "resource_name": "test-board",
        "board_type_category": "scrum",
        "board_location_type_category": "project",
        "project_id": "JIRA_TEST_PROJECT_ID",
        # M86C fields
        "board_filter_present": True,
        "board_jql_filter_broad": False,
        "board_column_count": 3,
        "board_quick_filter_count": 2,
        "board_swimlane_strategy_category": "assignee",
    }
    if overrides:
        base.update(overrides)
    return base


def _screen_scheme(overrides: dict | None = None) -> dict:
    base = {
        "record_type": JIRA_SCREEN_SCHEME,
        "provider": "jira",
        "record_id": JIRA_TEST_SCREEN_SCHEME_ID,
        "resource_id": JIRA_TEST_SCREEN_SCHEME_ID,
        "resource_name": "test-screen-scheme",
        "screen_count": 2,
        "tab_count": 3,
        "field_count": 10,
        # M86C fields
        "screen_tab_count": 3,
        "screen_unmapped_screen_count": 0,
    }
    if overrides:
        base.update(overrides)
    return base


# ════════════════════════════════════════════════════════════════════════════
# A. Registration tests
# ════════════════════════════════════════════════════════════════════════════

def test_m86c_imports():
    assert callable(evaluate)
    assert isinstance(JIRA_RULE_KEYS, frozenset)
    assert len(M86C_RULE_KEYS) == 39
    assert M86C_RULE_KEYS.issubset(JIRA_RULE_KEYS)


def test_new_rule_keys_in_registry():
    for key in M86C_RULE_KEYS:
        assert is_known_rule_key(key), f"Missing from KNOWN_RULE_KEYS: {key}"
        assert key in KNOWN_RULE_KEYS, f"Missing from KNOWN_RULE_KEYS: {key}"


def test_new_rule_keys_in_confidence():
    for key in M86C_RULE_KEYS:
        assert key in RULE_CONFIDENCE, f"Missing confidence: {key}"
        confidence, guard = RULE_CONFIDENCE[key]
        assert confidence in ("high", "medium"), (
            f"{key} has unsupported confidence: {confidence}"
        )
        assert isinstance(guard, str) and guard


def test_new_rule_keys_in_pack():
    for key in M86C_RULE_KEYS:
        assert key in _RULE_META, f"Missing from _RULE_META: {key}"
        provider, severity, category = _RULE_META[key]
        assert provider == "jira", f"{key} has wrong provider: {provider}"
        assert severity in {"critical", "high", "medium", "low", "info"}, (
            f"{key} has invalid severity: {severity}"
        )


def test_new_rule_keys_in_coverage():
    for key in M86C_RULE_KEYS:
        assert key in RULE_RECORD_TYPES, f"Missing from RULE_RECORD_TYPES: {key}"
        for rt in RULE_RECORD_TYPES[key]:
            assert rt.startswith("jira_"), f"{key} maps to non-jira type: {rt}"


def test_new_rule_keys_in_frontend_catalog():
    assert FE_RULE_CATALOG.exists(), f"Catalog not found: {FE_RULE_CATALOG}"
    text = FE_RULE_CATALOG.read_text(encoding="utf-8")
    for key in M86C_RULE_KEYS:
        assert f'key: "{key}"' in text, f"M86C rule key not in frontend catalog: {key}"


# ════════════════════════════════════════════════════════════════════════════
# B. Rule fire tests
# ════════════════════════════════════════════════════════════════════════════

# ── Workflow ──────────────────────────────────────────────────────────────────

def test_jira_workflow_no_done_status_fires_on_risky():
    findings = evaluate(_workflow({"workflow_has_done_status": False}))
    assert "jira_workflow_no_done_status" in _rule_keys(findings)


def test_jira_workflow_no_done_status_no_fire_on_healthy():
    findings = evaluate(_workflow())
    assert "jira_workflow_no_done_status" not in _rule_keys(findings)


def test_jira_workflow_high_validator_count_fires_on_risky():
    findings = evaluate(_workflow({"workflow_validator_count": 6}))
    assert "jira_workflow_high_validator_count" in _rule_keys(findings)


def test_jira_workflow_orphan_statuses_fires_on_risky():
    findings = evaluate(_workflow({"workflow_orphan_status_count": 2}))
    assert "jira_workflow_orphan_statuses" in _rule_keys(findings)


# ── Workflow scheme ───────────────────────────────────────────────────────────

def test_jira_workflow_scheme_unmapped_issue_types_fires_on_risky():
    findings = evaluate(_workflow_scheme({"workflow_scheme_unmapped_issue_type_count": 1}))
    assert "jira_workflow_scheme_unmapped_issue_types" in _rule_keys(findings)


def test_jira_workflow_scheme_unmapped_issue_types_no_fire_on_healthy():
    findings = evaluate(_workflow_scheme())
    assert "jira_workflow_scheme_unmapped_issue_types" not in _rule_keys(findings)


# ── Permission scheme ─────────────────────────────────────────────────────────

def test_jira_permission_scheme_public_administer_fires_on_risky():
    findings = evaluate(_permission_scheme({"permission_public_administer_projects": True}))
    assert "jira_permission_scheme_public_administer_projects" in _rule_keys(findings)


def test_jira_permission_scheme_public_administer_no_fire_on_healthy():
    findings = evaluate(_permission_scheme())
    assert "jira_permission_scheme_public_administer_projects" not in _rule_keys(findings)


def test_jira_permission_scheme_public_create_issues_fires_on_risky():
    findings = evaluate(_permission_scheme({"permission_public_create_issues": True}))
    assert "jira_permission_scheme_public_create_issues" in _rule_keys(findings)


def test_jira_permission_scheme_unknown_holder_fires_on_risky():
    findings = evaluate(_permission_scheme({"permission_unknown_holder_count": 1}))
    assert "jira_permission_scheme_unknown_holder" in _rule_keys(findings)


def test_jira_permission_scheme_high_privilege_grants_fires_on_risky():
    findings = evaluate(_permission_scheme({"permission_high_privilege_grant_count": 6}))
    assert "jira_permission_scheme_high_privilege_grants" in _rule_keys(findings)


# ── Notification scheme ───────────────────────────────────────────────────────

def test_jira_notification_scheme_unknown_recipients_fires_on_risky():
    findings = evaluate(_notification_scheme({"notification_unknown_recipient_count": 1}))
    assert "jira_notification_scheme_unknown_recipients" in _rule_keys(findings)


def test_jira_notification_scheme_high_event_count_fires_on_risky():
    findings = evaluate(_notification_scheme({"notification_event_count": 21}))
    assert "jira_notification_scheme_high_event_count" in _rule_keys(findings)


# ── Webhook ───────────────────────────────────────────────────────────────────

def test_jira_webhook_comment_event_scope_fires_on_risky():
    findings = evaluate(_webhook({"webhook_has_comment_events": True}))
    assert "jira_webhook_comment_event_scope" in _rule_keys(findings)


def test_jira_webhook_all_issue_events_fires_on_risky():
    findings = evaluate(_webhook({"webhook_all_issue_events": True}))
    assert "jira_webhook_all_issue_events" in _rule_keys(findings)


def test_jira_webhook_all_issue_events_no_fire_on_healthy():
    findings = evaluate(_webhook())
    assert "jira_webhook_all_issue_events" not in _rule_keys(findings)


# ── Automation rule ───────────────────────────────────────────────────────────

def test_jira_automation_rule_web_request_action_fires_on_risky():
    findings = evaluate(_automation_rule({"automation_has_web_request_action": True}))
    assert "jira_automation_rule_web_request_action" in _rule_keys(findings)


def test_jira_automation_rule_web_request_action_no_fire_on_healthy():
    findings = evaluate(_automation_rule())
    assert "jira_automation_rule_web_request_action" not in _rule_keys(findings)


def test_jira_automation_rule_external_action_fires_on_risky():
    findings = evaluate(_automation_rule({"automation_has_external_action": True}))
    assert "jira_automation_rule_external_action" in _rule_keys(findings)


def test_jira_automation_rule_high_action_count_fires_on_risky():
    findings = evaluate(_automation_rule({"automation_action_count": 11}))
    assert "jira_automation_rule_high_action_count" in _rule_keys(findings)


def test_jira_automation_rule_multi_project_scope_fires_on_risky():
    findings = evaluate(_automation_rule({"automation_scope_category": "multi-project"}))
    assert "jira_automation_rule_multi_project_scope" in _rule_keys(findings)


# ── Board ─────────────────────────────────────────────────────────────────────

def test_jira_board_broad_jql_filter_fires_on_risky():
    findings = evaluate(_board({"board_jql_filter_broad": True}))
    assert "jira_board_broad_jql_filter" in _rule_keys(findings)


def test_jira_board_no_filter_indicator_fires_on_risky():
    findings = evaluate(_board({"board_filter_present": False}))
    assert "jira_board_no_filter_indicator" in _rule_keys(findings)


def test_jira_board_no_columns_fires_on_risky():
    findings = evaluate(_board({"board_column_count": 0}))
    assert "jira_board_no_columns" in _rule_keys(findings)


# ── Screen scheme ─────────────────────────────────────────────────────────────

def test_jira_screen_scheme_unmapped_screens_fires_on_risky():
    findings = evaluate(_screen_scheme({"screen_unmapped_screen_count": 1}))
    assert "jira_screen_scheme_unmapped_screens" in _rule_keys(findings)


# ════════════════════════════════════════════════════════════════════════════
# C. Privacy / safety tests
# ════════════════════════════════════════════════════════════════════════════

def _all_m86c_risky_records() -> list[dict]:
    return [
        _workflow({"workflow_has_done_status": False}),
        _workflow({"workflow_has_in_progress_status": False}),
        _workflow({"workflow_transition_rule_count": 16}),
        _workflow({"workflow_validator_count": 6}),
        _workflow({"workflow_condition_count": 6}),
        _workflow({"workflow_post_function_count": 11}),
        _workflow({"workflow_orphan_status_count": 2}),
        _workflow_scheme({"workflow_scheme_unmapped_issue_type_count": 1}),
        _workflow_scheme({"workflow_scheme_workflow_count": 0}),
        _workflow_scheme({"workflow_scheme_issue_type_mapping_count": 21}),
        _permission_scheme({"permission_public_browse_projects": True}),
        _permission_scheme({"permission_public_administer_projects": True}),
        _permission_scheme({"permission_public_manage_sprints": True}),
        _permission_scheme({"permission_public_create_issues": True}),
        _permission_scheme({"permission_public_transition_issues": True}),
        _permission_scheme({"permission_unknown_holder_count": 1}),
        _permission_scheme({"permission_high_privilege_grant_count": 6}),
        _permission_scheme({"permission_public_grant_count": 4}),
        _notification_scheme({"notification_unknown_recipient_count": 1}),
        _notification_scheme({"notification_event_count": 21}),
        _webhook({"webhook_has_comment_events": True}),
        _webhook({"webhook_has_attachment_events": True}),
        _webhook({"webhook_has_sprint_events": True}),
        _webhook({"webhook_has_worklog_events": True}),
        _webhook({"webhook_all_issue_events": True}),
        _automation_rule({"automation_has_web_request_action": True}),
        _automation_rule({"automation_has_email_action": True}),
        _automation_rule({"automation_has_external_action": True}),
        _automation_rule({"automation_has_comment_action": True}),
        _automation_rule({"automation_action_count": 11}),
        _automation_rule({"automation_branch_count": 6}),
        _automation_rule({"automation_scope_category": "multi-project"}),
        _automation_rule({"automation_scope_category": "unknown"}),
        _board({"board_filter_present": False}),
        _board({"board_jql_filter_broad": True}),
        _board({"board_quick_filter_count": 11}),
        _board({"board_swimlane_strategy_category": "unknown"}),
        _board({"board_column_count": 0}),
        _screen_scheme({"screen_unmapped_screen_count": 1}),
    ]


def test_m86c_evidence_no_forbidden_fields():
    found: set[str] = set()
    for rec in _all_m86c_risky_records():
        for f in evaluate(rec):
            if f.rule_key in M86C_RULE_KEYS:
                found.update(f.evidence.keys())
    bad = found & _FORBIDDEN_EVIDENCE_FIELDS
    assert not bad, f"Forbidden evidence fields: {sorted(bad)}"


def test_m86c_no_forbidden_wording():
    parts: list[str] = []
    for rec in _all_m86c_risky_records():
        for f in evaluate(rec):
            if f.rule_key in M86C_RULE_KEYS:
                parts.append(f.title)
                parts.append(f.description)
    text = "\n".join(parts).lower()
    for phrase in _FORBIDDEN_PHRASES:
        assert phrase.lower() not in text, f"Forbidden phrase in M86C copy: {phrase!r}"
    # Review-safe language is present
    assert "may require review" in text


def test_m86c_findings_use_provider_jira():
    for rec in _all_m86c_risky_records():
        for f in evaluate(rec):
            if f.rule_key in M86C_RULE_KEYS:
                assert f.provider == "jira"


# ════════════════════════════════════════════════════════════════════════════
# D. Framework tests
# ════════════════════════════════════════════════════════════════════════════

def test_m86c_capability_matrix_points_to_m86d():
    cap = get_provider_capability("jira")
    assert cap is not None
    assert "M86C" in cap.notes
    assert "M86D" in cap.notes


def test_m86c_expansion_framework_points_to_m86d():
    # M86D has since landed — planned_next_stage now points to M86E.
    fw = get_framework()
    planned = fw["summary"]["planned_next_stage"]
    assert "M86D" in planned or "M86E" in planned, (
        f"planned_next_stage should reference M86D or later; got {planned!r}"
    )


def test_gitlab_still_head_of_recommended_queue():
    fw = get_framework()
    recs = fw["recommended_next_providers"]
    assert len(recs) > 0
    assert recs[0]["provider"] == "gitlab"


# ════════════════════════════════════════════════════════════════════════════
# E. M86B regression spot-check
# ════════════════════════════════════════════════════════════════════════════

def test_m86b_permission_anonymous_grants_still_fires():
    findings = evaluate(_permission_scheme({"permission_anonymous_grant_count": 1}))
    assert "jira_permission_scheme_anonymous_grant" in _rule_keys(findings)
    _, severity, _ = _RULE_META["jira_permission_scheme_anonymous_grant"]
    assert severity == "high"


def test_m86b_webhook_non_https_still_fires():
    findings = evaluate(_webhook({"webhook_url_scheme_category": "non_https"}))
    assert "jira_webhook_non_https" in _rule_keys(findings)
    _, severity, _ = _RULE_META["jira_webhook_non_https"]
    assert severity == "high"
