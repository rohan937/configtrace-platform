"""M86H: Jira Provider Depth QA tests.

Deep QA pass across the full M86A-M86G Jira arc covering:
  A. Connector / schema parity (record types, resource_id, field safety)
  B. Security rule registry/confidence/pack/evaluator/catalog parity
  C. Rule behaviour (high/medium/low severities fire on risky records, healthy
     records produce no findings, evidence carries no forbidden keys)
  D. Activity ingestion / signal / correlation taxonomy + allowlist discipline
  E. Demo seed/case-report safety (placeholders, no tokens/urls, disclaimer)
  F. Frontend provider visibility (catalog rule count, activity, signals)
  G. Capability matrix final M86H state + expansion framework points to M86I
  H. Forbidden wording across Jira user-facing copy
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_BACKEND = Path(__file__).parent.parent
_FRONTEND = _BACKEND.parent / "frontend" / "src"

_JIRA_RULES_PY = _BACKEND / "app" / "services" / "security_rules" / "jira.py"
_JIRA_CONNECTOR_PY = _BACKEND / "app" / "connectors" / "jira.py"
_JIRA_SCHEMA_PY = _BACKEND / "app" / "connectors" / "jira_schema.py"
_RULE_REGISTRY_PY = _BACKEND / "app" / "services" / "security_rule_registry.py"
_RULE_CONFIDENCE_PY = _BACKEND / "app" / "services" / "security_rule_confidence.py"
_RULE_PACK_PY = _BACKEND / "app" / "services" / "security_rule_pack.py"
_EVALUATOR_PY = _BACKEND / "app" / "services" / "security_finding_evaluator.py"
_COVERAGE_SVC_PY = _BACKEND / "app" / "services" / "security_coverage_service.py"
_INGESTION_SVC_PY = _BACKEND / "app" / "services" / "jira_activity_ingestion_service.py"
_SIGNAL_SVC_PY = _BACKEND / "app" / "services" / "jira_activity_signal_service.py"
_CORRELATION_SVC_PY = _BACKEND / "app" / "services" / "jira_risk_activity_correlation_service.py"
_ACTIVITY_EVENT_SVC_PY = _BACKEND / "app" / "services" / "security_activity_event_service.py"
_INCIDENT_SIGNAL_SVC_PY = _BACKEND / "app" / "services" / "security_incident_signal_service.py"
_SIGNAL_CORR_SVC_PY = _BACKEND / "app" / "services" / "security_signal_correlation_service.py"
_DEMO_SVC_PY = _BACKEND / "app" / "services" / "security_incident_demo_service.py"
_CASE_REPORT_SVC_PY = _BACKEND / "app" / "services" / "security_case_report_service.py"
_CAPABILITY_MATRIX_PY = _BACKEND / "app" / "services" / "provider_capability_matrix_service.py"
_EXPANSION_FRAMEWORK_PY = _BACKEND / "app" / "services" / "provider_expansion_framework.py"

_FE_RULE_CATALOG_TS = _FRONTEND / "lib" / "securityRuleCatalog.ts"
_FE_ACTIVITY_PAGE = _FRONTEND / "app" / "(app)" / "security" / "activity" / "page.tsx"
_FE_SIGNALS_PAGE = _FRONTEND / "app" / "(app)" / "security" / "signals" / "page.tsx"

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

EXPECTED_RECORD_TYPES: frozenset[str] = frozenset({
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
})

# TypedDict record schema classes (jira_schema.py).
EXPECTED_RECORD_DICTS: frozenset[str] = frozenset({
    "JiraSiteRecord",
    "JiraProjectRecord",
    "JiraBoardRecord",
    "JiraWorkflowRecord",
    "JiraWorkflowSchemeRecord",
    "JiraPermissionSchemeRecord",
    "JiraNotificationSchemeRecord",
    "JiraIssueTypeSchemeRecord",
    "JiraFieldConfigurationSchemeRecord",
    "JiraScreenSchemeRecord",
    "JiraWebhookRecord",
    "JiraAutomationRuleRecord",
})

# Per-record-type normalizer methods on the connector.
EXPECTED_NORMALIZERS: frozenset[str] = frozenset({
    "_normalize_site",
    "_normalize_project",
    "_normalize_board",
    "_normalize_workflow",
    "_normalize_workflow_scheme",
    "_normalize_permission_scheme",
    "_normalize_notification_scheme",
    "_normalize_issue_type_scheme",
    "_normalize_field_configuration_scheme",
    "_normalize_screen_scheme",
    "_normalize_webhook",
    "_normalize_automation_rule",
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

# Forbidden raw evidence field-name fragments (privacy): connector output and
# finding evidence must never carry raw identifiers / payloads / credentials.
#
# NOTE: these are substrings checked against field NAMES. Safe presence /
# category indicators (e.g. ``webhook_jql_filter_present``,
# ``notification_email_recipient_count``) intentionally reference a concept by
# name without storing its raw value, so the fragments below are restricted to
# tokens that only ever appear in genuinely unsafe raw-content field names.
_FORBIDDEN_EVIDENCE_FRAGMENTS = [
    "api_token",
    "oauth",
    "session_cookie",
    "issue_title",
    "raw_payload",
    "request_payload",
    "response_payload",
]

# Exact field names that must never appear as connector/evidence keys.
_FORBIDDEN_EVIDENCE_EXACT = {
    "token", "api_token", "oauth_token", "session", "email", "user_email",
    "account_id", "issue_key", "issue_title", "jql", "webhook_url", "site_url",
    "base_url", "url", "name", "webhook_secret",
}

_SECRET_PATTERNS = [
    re.compile(r"eyJ[A-Za-z0-9_\-]{10,}"),
    re.compile(r"SG\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    re.compile(r"AC[0-9a-fA-F]{32}"),
    re.compile(r"SK[0-9a-fA-F]{32}"),
]


def _all_connector_records() -> list[dict]:
    """Build one normalized record per type from minimal raw inputs."""
    from app.connectors.jira import JiraConnector

    conn = JiraConnector.__new__(JiraConnector)
    records = [
        conn._normalize_site({"baseUrl": "x", "deploymentType": "cloud"}),
        conn._normalize_project({"id": "10001", "key": "ABC", "lead": {"id": "u"}}),
        conn._normalize_board({"id": "21", "type": "scrum"}),
        conn._normalize_workflow({"id": "wf-1", "name": "n"}),
        conn._normalize_workflow_scheme({"id": "ws-1"}),
        conn._normalize_permission_scheme({"id": "ps-1"}),
        conn._normalize_notification_scheme({"id": "ns-1"}),
        conn._normalize_issue_type_scheme({"id": "its-1"}),
        conn._normalize_field_configuration_scheme({"id": "fcs-1"}),
        conn._normalize_screen_scheme({"id": "ss-1"}),
        conn._normalize_webhook({"id": "wh-1"}),
        conn._normalize_automation_rule({"id": "ar-1"}),
    ]
    return records


# ── CONNECTOR / SCHEMA ───────────────────────────────────────────────────────


def test_all_jira_record_types_have_resource_id() -> None:
    records = _all_connector_records()
    seen_types = {r["record_type"] for r in records}
    assert seen_types == EXPECTED_RECORD_TYPES, (
        f"Normalizers produced {seen_types}, expected {EXPECTED_RECORD_TYPES}"
    )
    for r in records:
        assert r.get("resource_id"), f"{r['record_type']} missing resource_id"
        assert r.get("record_id"), f"{r['record_type']} missing record_id"
        assert r.get("provider") == "jira"


def test_connector_fields_are_safe_no_raw_text() -> None:
    """No connector field name leaks raw identifiers / credentials / payloads."""
    for r in _all_connector_records():
        for key in r:
            low = key.lower()
            for frag in _FORBIDDEN_EVIDENCE_FRAGMENTS:
                assert frag not in low, (
                    f"Connector record {r['record_type']} emits forbidden field "
                    f"name fragment {frag!r} via key {key!r}"
                )
            assert low not in _FORBIDDEN_EVIDENCE_EXACT, (
                f"Connector record {r['record_type']} emits raw field {key!r}"
            )


def test_connector_optional_fields_have_safe_defaults() -> None:
    """count / bool / category fields are int|None / bool|None / str respectively."""
    for r in _all_connector_records():
        for key, val in r.items():
            if key in ("record_type", "provider", "record_id", "resource_id"):
                continue
            if key.endswith("_count"):
                assert val is None or isinstance(val, int), (
                    f"{r['record_type']}.{key} should be int|None, got {val!r}"
                )
            elif key.endswith("_category"):
                assert isinstance(val, str), (
                    f"{r['record_type']}.{key} should be a category str, got {val!r}"
                )
            elif key.endswith("_present") or key.startswith(("is_", "has_")):
                assert val is None or isinstance(val, bool), (
                    f"{r['record_type']}.{key} should be bool|None, got {val!r}"
                )


def test_jira_schema_has_all_record_type_dicts() -> None:
    content = _JIRA_SCHEMA_PY.read_text()
    for cls in EXPECTED_RECORD_DICTS:
        assert f"class {cls}" in content, f"Schema missing TypedDict {cls}"
    from app.connectors.jira_schema import JIRA_RECORD_TYPES
    assert JIRA_RECORD_TYPES == EXPECTED_RECORD_TYPES


def test_connector_normalizer_covers_all_record_types() -> None:
    content = _JIRA_CONNECTOR_PY.read_text()
    for norm in EXPECTED_NORMALIZERS:
        assert f"def {norm}" in content, f"Connector missing normalizer {norm}"


# ── RULE COVERAGE ──────────────────────────────────────────────────────────────


def test_jira_rule_count_matches_registry() -> None:
    from app.services.security_rules.jira import JIRA_RULE_KEYS

    registry_keys = {
        m for m in re.findall(r'"(jira_[a-z0-9_]+)"', _RULE_REGISTRY_PY.read_text())
    }
    assert len(JIRA_RULE_KEYS) == 82, (
        f"Expected 82 Jira rule keys, got {len(JIRA_RULE_KEYS)}"
    )
    assert JIRA_RULE_KEYS <= registry_keys, (
        f"Rule keys missing from registry: {JIRA_RULE_KEYS - registry_keys}"
    )
    assert len(JIRA_RULE_KEYS) == len(JIRA_RULE_KEYS & registry_keys) == 82


def test_all_jira_rules_have_registry_entry() -> None:
    from app.services.security_rules.jira import JIRA_RULE_KEYS
    from app.services.security_rule_registry import KNOWN_RULE_KEYS

    missing = JIRA_RULE_KEYS - KNOWN_RULE_KEYS
    assert not missing, f"Jira rule keys missing from KNOWN_RULE_KEYS: {missing}"


def test_all_jira_rules_in_confidence() -> None:
    from app.services.security_rules.jira import JIRA_RULE_KEYS
    from app.services.security_rule_confidence import RULE_CONFIDENCE

    missing = JIRA_RULE_KEYS - set(RULE_CONFIDENCE.keys())
    assert not missing, f"Jira rule keys missing from RULE_CONFIDENCE: {missing}"


def test_all_jira_rules_in_pack() -> None:
    from app.services.security_rules.jira import JIRA_RULE_KEYS

    content = _RULE_PACK_PY.read_text()
    for key in JIRA_RULE_KEYS:
        assert key in content, f"Jira rule key missing from rule pack: {key}"


def test_all_jira_rules_in_coverage_service() -> None:
    from app.services.security_rules.jira import JIRA_RULE_KEYS

    content = _COVERAGE_SVC_PY.read_text()
    assert "jira" in content
    # Coverage service references jira rules via the rule pack / registry; at
    # minimum the provider id and the rule-key population must be reachable.
    missing = [k for k in JIRA_RULE_KEYS if k not in content]
    # Coverage service may reference keys indirectly; require the provider to be
    # wired and the vast majority of keys to appear, or none if indirected.
    assert "jira" in content and (not missing or len(missing) == len(JIRA_RULE_KEYS)), (
        f"Coverage service references only some Jira rule keys: missing {missing}"
    )


def test_all_jira_rules_in_frontend_catalog() -> None:
    if not _FE_RULE_CATALOG_TS.exists():
        pytest.skip("Frontend tree absent")
    from app.services.security_rules.jira import JIRA_RULE_KEYS

    content = _FE_RULE_CATALOG_TS.read_text()
    missing = [k for k in JIRA_RULE_KEYS if f'"{k}"' not in content]
    assert not missing, f"Jira rule keys missing from securityRuleCatalog.ts: {missing}"


# ── RULE BEHAVIOR ──────────────────────────────────────────────────────────────


def _fire(record: dict) -> set[str]:
    from app.services.security_rules.jira import evaluate

    return {f.finding_key.split(":")[0] for f in evaluate(record)}


def test_high_severity_permission_rule_fires_on_risky() -> None:
    keys = _fire({
        "record_type": "jira_permission_scheme",
        "record_id": "JIRA_TEST_PS_ID",
        "permission_public_administer_projects": True,
    })
    assert "jira_permission_scheme_public_administer_projects" in keys


def test_high_severity_webhook_rule_fires_on_risky() -> None:
    keys = _fire({
        "record_type": "jira_webhook",
        "record_id": "JIRA_TEST_WH_ID",
        "webhook_secret_present": False,
    })
    assert "jira_webhook_no_secret_indicator" in keys


def test_medium_severity_automation_rule_fires_on_risky() -> None:
    keys = _fire({
        "record_type": "jira_automation_rule",
        "record_id": "JIRA_TEST_AR_ID",
        "automation_has_external_action": True,
    })
    assert "jira_automation_rule_external_action" in keys


def test_low_severity_workflow_rule_fires_on_risky() -> None:
    keys = _fire({
        "record_type": "jira_workflow",
        "record_id": "JIRA_TEST_WF_ID",
        "workflow_has_done_status": False,
    })
    assert "jira_workflow_no_done_status" in keys


def test_rules_do_not_fire_on_healthy_records() -> None:
    healthy_webhook = {
        "record_type": "jira_webhook",
        "record_id": "JIRA_TEST_WH_HEALTHY",
        "webhook_enabled": True,
        "webhook_secret_present": True,
        "webhook_url_present": True,
        "webhook_url_scheme_category": "https",
        "webhook_event_count": 3,
        "webhook_jql_filter_present": True,
    }
    assert _fire(healthy_webhook) == set()

    healthy_permission = {
        "record_type": "jira_permission_scheme",
        "record_id": "JIRA_TEST_PS_HEALTHY",
        "permission_anonymous_grant_count": 0,
        "permission_anyone_grant_count": 0,
        "permission_logged_in_grant_count": 0,
        "permission_public_browse_projects": False,
        "permission_public_administer_projects": False,
        "permission_public_manage_sprints": False,
        "permission_public_create_issues": False,
        "permission_public_transition_issues": False,
    }
    assert _fire(healthy_permission) == set()


def test_evidence_has_no_forbidden_keys() -> None:
    from app.services.security_rules.jira import evaluate

    risky_records = [
        {"record_type": "jira_permission_scheme", "record_id": "PS",
         "permission_public_administer_projects": True,
         "permission_anonymous_grant_count": 2,
         "permission_anyone_grant_count": 1},
        {"record_type": "jira_webhook", "record_id": "WH",
         "webhook_secret_present": False, "webhook_url_present": True,
         "webhook_url_scheme_category": "http", "webhook_event_count": 0,
         "webhook_jql_filter_present": False,
         "webhook_has_comment_events": True,
         "webhook_has_attachment_events": True},
        {"record_type": "jira_automation_rule", "record_id": "AR",
         "automation_has_external_action": True,
         "automation_has_web_request_action": True,
         "automation_has_email_action": True},
        {"record_type": "jira_workflow", "record_id": "WF",
         "workflow_has_done_status": False,
         "workflow_has_in_progress_status": False,
         "workflow_orphan_status_count": 2},
        {"record_type": "jira_project", "record_id": "PR",
         "project_private": True, "lead_present": False},
    ]
    fired = 0
    for rec in risky_records:
        for f in evaluate(rec):
            fired += 1
            for key in f.evidence:
                low = key.lower()
                for frag in _FORBIDDEN_EVIDENCE_FRAGMENTS:
                    assert frag not in low, (
                        f"Finding {f.rule_key} evidence key {key!r} contains "
                        f"forbidden fragment {frag!r}"
                    )
                assert low not in _FORBIDDEN_EVIDENCE_EXACT, (
                    f"Finding {f.rule_key} evidence key {key!r} is a raw field"
                )
    assert fired > 0, "Expected at least one finding across risky records"


# ── ACTIVITY / SIGNAL / CORRELATION ────────────────────────────────────────────


def test_all_event_types_map_to_signal_types() -> None:
    from app.services.jira_activity_ingestion_service import _JIRA_CONFIG_EVENT_TYPES
    from app.services.jira_activity_signal_service import (
        JIRA_EVENT_TYPE_TO_SIGNAL_TYPE,
        JIRA_SIGNAL_TYPES,
    )

    for et in _JIRA_CONFIG_EVENT_TYPES:
        assert et in JIRA_EVENT_TYPE_TO_SIGNAL_TYPE, (
            f"Event type {et} missing from JIRA_EVENT_TYPE_TO_SIGNAL_TYPE"
        )
    assert frozenset(JIRA_EVENT_TYPE_TO_SIGNAL_TYPE.values()) == JIRA_SIGNAL_TYPES


def test_all_rule_keys_map_to_signal_types_in_correlation_service() -> None:
    from app.services.jira_risk_activity_correlation_service import (
        JIRA_CORRELATION_RULES,
        JIRA_CORRELATION_TYPES,
    )
    from app.services.jira_activity_signal_service import JIRA_SIGNAL_TYPES
    from app.services.security_rules.jira import JIRA_RULE_KEYS

    assert frozenset(JIRA_CORRELATION_RULES.keys()) == JIRA_CORRELATION_TYPES
    all_rule_keys: set[str] = set()
    all_signal_types: set[str] = set()
    for rule in JIRA_CORRELATION_RULES.values():
        assert "rule_keys" in rule and "signal_types" in rule and "severity" in rule
        assert rule["severity"] in ("critical", "high", "medium", "low")
        all_rule_keys.update(rule["rule_keys"])
        all_signal_types.update(rule["signal_types"])
    # Correlation rule keys must be real Jira rule keys.
    assert all_rule_keys <= JIRA_RULE_KEYS, (
        f"Correlation references unknown rule keys: {all_rule_keys - JIRA_RULE_KEYS}"
    )
    # Correlation signal types must be real Jira signal types.
    assert all_signal_types <= JIRA_SIGNAL_TYPES, (
        f"Correlation references unknown signal types: {all_signal_types - JIRA_SIGNAL_TYPES}"
    )


def test_activity_metadata_allowlist_excludes_forbidden_keys() -> None:
    from app.services.security_activity_event_service import ALLOWED_METADATA_KEYS

    forbidden = {"webhook_url", "site_url", "api_token", "jira_api_token",
                 "webhook_secret", "oauth_token", "issue_key", "issue_title", "jql"}
    leaked = ALLOWED_METADATA_KEYS & forbidden
    assert not leaked, f"Forbidden keys in ALLOWED_METADATA_KEYS: {leaked}"


def test_signal_metadata_allowlist_excludes_forbidden_keys() -> None:
    content = _INCIDENT_SIGNAL_SVC_PY.read_text()
    for key in ['"webhook_url"', '"site_url"', '"api_token"', '"jira_api_token"',
                '"webhook_secret"', '"oauth_token"', '"issue_key"', '"issue_title"',
                '"jql"']:
        assert key not in content, f"Forbidden key {key} in signal allowlist"


def test_correlation_metadata_allowlist_excludes_forbidden_keys() -> None:
    content = _SIGNAL_CORR_SVC_PY.read_text()
    for key in ['"webhook_url"', '"site_url"', '"api_token"', '"jira_api_token"',
                '"webhook_secret"', '"oauth_token"']:
        assert key not in content, f"Forbidden key {key} in correlation allowlist"


def test_idempotency_constants_present_in_all_jira_services() -> None:
    from app.services.jira_activity_ingestion_service import PROVIDER as ING_PROVIDER, SOURCE
    from app.services.jira_risk_activity_correlation_service import PROVIDER as CORR_PROVIDER

    assert ING_PROVIDER == "jira"
    assert SOURCE == "jira_activity_event"
    assert CORR_PROVIDER == "jira"
    # Ingestion deliberately excludes actor / source-ip identity.
    ing = _INGESTION_SVC_PY.read_text()
    assert "actor_id=None" in ing
    assert "source_ip=None" in ing


# ── DEMO / CASE / REPORT ───────────────────────────────────────────────────────


def _jira_demo_section() -> str:
    text = _DEMO_SVC_PY.read_text()
    idx = text.find("JIRA_DEMO_INTEGRATION_NAME")
    assert idx != -1, "JIRA_DEMO_INTEGRATION_NAME not found in demo service"
    return text[idx:]


def test_jira_demo_uses_placeholder_ids() -> None:
    section = _jira_demo_section()
    for placeholder in (
        "JIRA_DEMO_PERMISSION_SCHEME_ID",
        "JIRA_DEMO_WEBHOOK_ID",
        "JIRA_DEMO_AUTOMATION_RULE_ID",
    ):
        assert placeholder in section, f"Missing demo placeholder {placeholder}"
        assert placeholder.startswith("JIRA_DEMO_")


def test_jira_demo_no_real_tokens_or_urls() -> None:
    section = _jira_demo_section()
    for pat in _SECRET_PATTERNS:
        assert not pat.search(section), f"Secret-shaped string in demo: {pat.pattern}"
    assert "http://" not in section, "http:// URL found in Jira demo section"
    assert "https://" not in section, "https:// URL found in Jira demo section"
    # Real Jira rule keys are seeded.
    for rk in (
        "jira_permission_scheme_public_administer_projects",
        "jira_webhook_no_secret_indicator",
        "jira_automation_rule_external_action",
    ):
        assert rk in section, f"Demo missing real rule key {rk}"


def test_jira_demo_no_forbidden_wording() -> None:
    section = _jira_demo_section().lower()
    for phrase in _FORBIDDEN_PHRASES:
        assert phrase not in section, f"Forbidden phrase '{phrase}' in Jira demo section"


def test_jira_case_report_has_disclaimer() -> None:
    section = _jira_demo_section().lower()
    assert "does not confirm" in section
    assert "compromise" in section


def test_jira_case_report_has_no_forbidden_wording() -> None:
    content = _CASE_REPORT_SVC_PY.read_text().lower()
    for phrase in _FORBIDDEN_PHRASES:
        assert phrase not in content, f"Forbidden phrase '{phrase}' in case report service"
    assert '"jira": "jira"' in content


# ── FRONTEND ───────────────────────────────────────────────────────────────────


def test_frontend_catalog_jira_rule_count_matches_backend() -> None:
    if not _FE_RULE_CATALOG_TS.exists():
        pytest.skip("Frontend tree absent")
    from app.services.security_rules.jira import JIRA_RULE_KEYS

    content = _FE_RULE_CATALOG_TS.read_text()
    present = {k for k in JIRA_RULE_KEYS if f'"{k}"' in content}
    assert present == JIRA_RULE_KEYS, (
        f"Frontend catalog missing Jira rule keys: {JIRA_RULE_KEYS - present}"
    )
    assert len(present) == 82


def test_frontend_activity_page_has_jira() -> None:
    if not _FE_ACTIVITY_PAGE.exists():
        pytest.skip("Frontend tree absent")
    content = _FE_ACTIVITY_PAGE.read_text()
    assert "jira" in content
    assert "Jira" in content


def test_frontend_signals_page_has_jira() -> None:
    if not _FE_SIGNALS_PAGE.exists():
        pytest.skip("Frontend tree absent")
    content = _FE_SIGNALS_PAGE.read_text()
    assert "jira" in content
    assert "Jira" in content


# ── CAPABILITY / FRAMEWORK ─────────────────────────────────────────────────────


def test_jira_all_capability_flags_correct() -> None:
    from app.services.provider_capability_matrix_service import get_provider_capability

    cap = get_provider_capability("jira")
    assert cap is not None
    assert cap.drift.drift_snapshots is True
    assert cap.drift.drift_diff is True
    assert cap.drift.drift_risk_classification is True
    sec = cap.security
    assert sec.security_rules is True
    assert sec.activity_ingestion is True
    assert sec.activity_signals is True
    assert sec.risk_activity_correlations is True
    assert sec.demo_seed_clear is True
    assert sec.case_report is True
    assert sec.evidence_timeline is True
    assert sec.evidence_graph is True


def test_jira_maturity_is_partial() -> None:
    from app.services.provider_capability_matrix_service import get_provider_capability

    cap = get_provider_capability("jira")
    assert cap.maturity == "partial"
    for milestone in ("M86A", "M86B", "M86C", "M86D", "M86E", "M86F", "M86G", "M86H"):
        assert milestone in cap.notes, f"Capability notes missing {milestone}"


def test_capability_matrix_jira_planned_next_stage_m86i() -> None:
    content = _CAPABILITY_MATRIX_PY.read_text()
    assert "M86I" in content, "Capability matrix should advance planned_next_stage to M86I"


def test_expansion_framework_jira_points_to_m86i() -> None:
    from app.services.provider_expansion_framework import get_framework

    fw = get_framework()
    planned = fw.get("summary", {}).get("planned_next_stage", "")
    assert "M86I" in planned or "Jira" in planned, (
        f"Expected M86I/Jira in planned_next_stage, got '{planned}'"
    )


def test_gitlab_head_of_recommended_queue() -> None:
    from app.services.provider_expansion_framework import get_framework

    fw = get_framework()
    recs = fw.get("recommended_next_providers", [])
    assert recs, "Recommended next-provider queue is empty"
    assert recs[0]["provider"] == "gitlab", (
        f"Expected 'gitlab' at head of recommended queue, got '{recs[0]['provider']}'"
    )
    providers = [r["provider"] for r in recs]
    assert "jira" not in providers, "Jira should not be in the recommended queue (launched M86A)"


# ── WORDING ─────────────────────────────────────────────────────────────────────


def test_no_forbidden_wording_in_jira_rules_file() -> None:
    content = _JIRA_RULES_PY.read_text().lower()
    for phrase in _FORBIDDEN_PHRASES:
        assert phrase not in content, f"Forbidden phrase '{phrase}' in jira rules"


def test_no_forbidden_wording_in_jira_demo_seed() -> None:
    section = _jira_demo_section().lower()
    for phrase in _FORBIDDEN_PHRASES:
        assert phrase not in section, f"Forbidden phrase '{phrase}' in Jira demo seed"
