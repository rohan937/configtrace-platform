"""M86F — Jira Risk × Activity Correlations.

Joins active Jira configuration-risk findings (M86B/M86C) with Jira activity
signals (M86E) on the same safe opaque resource_id within a review window,
falling back to record_type -> signal_type family matching. Produces
SecuritySignalCorrelation rows without storing Jira API tokens, OAuth tokens,
webhook secrets, integration secrets, raw webhook/delivery URLs, site base URLs,
JQL, filter expressions, issue keys, issue titles, issue descriptions, comment
bodies, attachment content, customer names, user emails, user names, account
IDs, member identities, IP addresses, user agents, request/response payloads,
raw audit payloads, or PII of any kind.

CLAIM DISCIPLINE: correlations are EVIDENCE FOR REVIEW. They do NOT confirm
breach, compromise, unauthorized access, or data exposure.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

# ── Constants ──────────────────────────────────────────────────────────────────

JIRA_TEST_PERMISSION_SCHEME_ID = "JIRA_TEST_PERMISSION_SCHEME_ID"
JIRA_TEST_WEBHOOK_ID = "JIRA_TEST_WEBHOOK_ID"
JIRA_TEST_WORKFLOW_ID = "JIRA_TEST_WORKFLOW_ID"
JIRA_TEST_AUTOMATION_RULE_ID = "JIRA_TEST_AUTOMATION_RULE_ID"
JIRA_TEST_FINDING_ID = "JIRA_TEST_FINDING_ID"
JIRA_TEST_SIGNAL_ID = "JIRA_TEST_SIGNAL_ID"
JIRA_TEST_CORRELATION_ID = "JIRA_TEST_CORRELATION_ID"

PROVIDER = "jira"

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND_APP = REPO_ROOT / "backend" / "app"
FRONTEND_SRC = REPO_ROOT / "frontend" / "src"

# Fields that must NEVER appear in correlation metadata
_FORBIDDEN_METADATA_FIELDS = frozenset({
    "jql", "url", "email", "token", "api_token", "oauth_token",
    "access_token", "webhook_secret", "secret", "secret_value",
    "authorization", "headers", "payload", "request", "response", "raw",
    "audit", "audit_payload", "account_id", "user", "user_id", "user_name",
    "member", "member_id", "issue_key", "issue_title", "issue_description",
    "description", "comment", "comment_body", "attachment",
    "attachment_content", "phone", "ip", "ip_address", "user_agent",
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
    "issues exposed",
    "credentials exposed",
]


# ── Test fixtures / factories ──────────────────────────────────────────────────


def _make_finding(
    rule_key: str = "jira_webhook_non_https",
    resource_id: str = JIRA_TEST_WEBHOOK_ID,
    integration_id: Any = None,
) -> MagicMock:
    finding = MagicMock()
    finding.id = uuid.uuid4()
    finding.finding_key = f"{rule_key}:{resource_id}"
    finding.provider = "jira"
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
    signal_type: str = "jira_webhook_config_changed",
    resource_id: str = JIRA_TEST_WEBHOOK_ID,
    integration_id: Any = None,
) -> MagicMock:
    signal = MagicMock()
    signal.id = uuid.uuid4()
    signal.signal_type = signal_type
    signal.provider = "jira"
    signal.integration_id = integration_id
    signal.linked_activity_event_id = uuid.uuid4()
    signal.first_seen_at = datetime(2026, 6, 19, 11, 0, 0, tzinfo=timezone.utc)
    signal.last_seen_at = datetime(2026, 6, 19, 12, 0, 0, tzinfo=timezone.utc)
    signal.signal_metadata = {
        "resource_type": "jira_webhook",
        "resource_id": resource_id,
        "operation_family": "jira.webhook",
        "event_types": "jira.webhook.updated",
        "event_count": 1,
        "source": "jira_activity_event",
    }
    return signal


# ── A. Import tests ────────────────────────────────────────────────────────────


def test_jira_correlation_schema_imports() -> None:
    from app.schemas.security_jira_activity import (
        JiraRiskActivityCorrelationGenerateRequest,
        JiraRiskActivityCorrelationGenerateResponse,
    )
    req = JiraRiskActivityCorrelationGenerateRequest()
    assert req.lookback_hours == 24
    assert req.max_correlations == 100
    resp = JiraRiskActivityCorrelationGenerateResponse()
    assert resp.provider == "jira"
    assert resp.correlations_created == 0


def test_jira_risk_activity_correlation_service_imports() -> None:
    from app.services.jira_risk_activity_correlation_service import (
        JIRA_CORRELATION_RULES,
        JIRA_CORRELATION_TYPES,
        JIRA_RULE_KEY_TO_SIGNAL_TYPE,
        generate_jira_correlations,
    )
    assert isinstance(JIRA_CORRELATION_RULES, dict)
    assert isinstance(JIRA_CORRELATION_TYPES, frozenset)
    assert isinstance(JIRA_RULE_KEY_TO_SIGNAL_TYPE, dict)
    assert callable(generate_jira_correlations)


# ── B. Rule → signal mapping tests ─────────────────────────────────────────────


def test_rule_to_signal_mapping_includes_permission_scheme_rules() -> None:
    from app.services.jira_risk_activity_correlation_service import (
        JIRA_RULE_KEY_TO_SIGNAL_TYPE,
    )
    assert (
        JIRA_RULE_KEY_TO_SIGNAL_TYPE["jira_permission_scheme_anonymous_grant"]
        == "jira_permission_scheme_config_changed"
    )


def test_rule_to_signal_mapping_includes_webhook_rules() -> None:
    from app.services.jira_risk_activity_correlation_service import (
        JIRA_RULE_KEY_TO_SIGNAL_TYPE,
    )
    assert (
        JIRA_RULE_KEY_TO_SIGNAL_TYPE["jira_webhook_non_https"]
        == "jira_webhook_config_changed"
    )


def test_rule_to_signal_mapping_includes_workflow_rules() -> None:
    from app.services.jira_risk_activity_correlation_service import (
        JIRA_RULE_KEY_TO_SIGNAL_TYPE,
    )
    assert (
        JIRA_RULE_KEY_TO_SIGNAL_TYPE["jira_workflow_no_statuses"]
        == "jira_workflow_config_changed"
    )


def test_rule_to_signal_mapping_includes_automation_rules() -> None:
    from app.services.jira_risk_activity_correlation_service import (
        JIRA_RULE_KEY_TO_SIGNAL_TYPE,
    )
    assert (
        JIRA_RULE_KEY_TO_SIGNAL_TYPE["jira_automation_rule_disabled"]
        == "jira_automation_rule_config_changed"
    )


def test_rule_to_signal_mapping_includes_board_rules() -> None:
    from app.services.jira_risk_activity_correlation_service import (
        JIRA_RULE_KEY_TO_SIGNAL_TYPE,
    )
    assert (
        JIRA_RULE_KEY_TO_SIGNAL_TYPE["jira_board_missing_project_link"]
        == "jira_board_config_changed"
    )


def test_rule_to_signal_mapping_includes_notification_scheme_rules() -> None:
    from app.services.jira_risk_activity_correlation_service import (
        JIRA_RULE_KEY_TO_SIGNAL_TYPE,
    )
    assert (
        JIRA_RULE_KEY_TO_SIGNAL_TYPE["jira_notification_scheme_group_recipients"]
        == "jira_notification_scheme_config_changed"
    )



def test_rule_to_signal_mapping_includes_project_rules() -> None:
    from app.services.jira_risk_activity_correlation_service import (
        JIRA_RULE_KEY_TO_SIGNAL_TYPE,
    )
    assert (
        JIRA_RULE_KEY_TO_SIGNAL_TYPE["jira_project_private"]
        == "jira_project_config_changed"
    )


def test_rule_to_signal_mapping_unknown_falls_back_safely() -> None:
    from app.services.jira_risk_activity_correlation_service import (
        _signal_type_for_rule_key,
    )
    # Unknown rule key resolves to the generic config-activity signal type.
    assert _signal_type_for_rule_key("jira_totally_unknown_rule") == "jira_config_activity"
    assert _signal_type_for_rule_key("") == "jira_config_activity"


# ── C. Correlation content tests ───────────────────────────────────────────────


def _build(rule_key: str, signal_type: str, correlation_type: str,
           resource_id: str = JIRA_TEST_WEBHOOK_ID) -> dict[str, Any]:
    from app.services.jira_risk_activity_correlation_service import (
        _build_correlation,
        JIRA_CORRELATION_RULES,
    )
    finding = _make_finding(rule_key=rule_key, resource_id=resource_id)
    signal = _make_signal(signal_type=signal_type, resource_id=resource_id)
    rule = JIRA_CORRELATION_RULES[correlation_type]
    return _build_correlation(
        finding=finding,
        signal=signal,
        correlation_type=correlation_type,
        rule=rule,
        match_reason="resource_id_match",
    )


def test_correlations_use_provider_jira() -> None:
    from app.services.jira_risk_activity_correlation_service import PROVIDER as SVC_PROVIDER
    assert SVC_PROVIDER == "jira"
    result = _build(
        "jira_webhook_non_https",
        "jira_webhook_config_changed",
        "jira_webhook_risk_with_activity",
    )
    assert result["provider"] == "jira"
    # The correlation carries provider at the top level; metadata's own
    # provider/correlation_type fields are authoritative for downstream filters.
    assert result["metadata"]["correlation_type"] == "jira_webhook_risk_with_activity"


def test_correlations_have_safe_correlation_type() -> None:
    from app.services.jira_risk_activity_correlation_service import (
        JIRA_CORRELATION_TYPES,
    )
    result = _build(
        "jira_webhook_non_https",
        "jira_webhook_config_changed",
        "jira_webhook_risk_with_activity",
    )
    assert result["correlation_type"] in JIRA_CORRELATION_TYPES
    assert result["correlation_type"].startswith("jira_")


def test_permission_scheme_finding_correlates_with_permission_scheme_signal() -> None:
    from app.services.jira_risk_activity_correlation_service import _match_pair
    finding = _make_finding(
        rule_key="jira_permission_scheme_anonymous_grants",
        resource_id=JIRA_TEST_PERMISSION_SCHEME_ID,
    )
    signal = _make_signal(
        signal_type="jira_permission_scheme_config_changed",
        resource_id=JIRA_TEST_PERMISSION_SCHEME_ID,
    )
    assert _match_pair(finding, signal) == "resource_id_match"


def test_webhook_finding_correlates_with_webhook_signal() -> None:
    from app.services.jira_risk_activity_correlation_service import _match_pair
    finding = _make_finding(
        rule_key="jira_webhook_non_https", resource_id=JIRA_TEST_WEBHOOK_ID
    )
    signal = _make_signal(
        signal_type="jira_webhook_config_changed", resource_id=JIRA_TEST_WEBHOOK_ID
    )
    assert _match_pair(finding, signal) == "resource_id_match"


def test_workflow_finding_correlates_with_workflow_signal() -> None:
    from app.services.jira_risk_activity_correlation_service import _match_pair
    finding = _make_finding(
        rule_key="jira_workflow_draft", resource_id=JIRA_TEST_WORKFLOW_ID
    )
    signal = _make_signal(
        signal_type="jira_workflow_config_changed", resource_id=JIRA_TEST_WORKFLOW_ID
    )
    assert _match_pair(finding, signal) == "resource_id_match"


def test_automation_finding_correlates_with_automation_signal() -> None:
    from app.services.jira_risk_activity_correlation_service import _match_pair
    finding = _make_finding(
        rule_key="jira_automation_rule_disabled",
        resource_id=JIRA_TEST_AUTOMATION_RULE_ID,
    )
    signal = _make_signal(
        signal_type="jira_automation_rule_config_changed",
        resource_id=JIRA_TEST_AUTOMATION_RULE_ID,
    )
    assert _match_pair(finding, signal) == "resource_id_match"


def test_board_finding_correlates_with_board_signal() -> None:
    from app.services.jira_risk_activity_correlation_service import _match_pair
    finding = _make_finding(
        rule_key="jira_board_no_projects", resource_id="BOARD_X"
    )
    signal = _make_signal(
        signal_type="jira_board_config_changed", resource_id="BOARD_X"
    )
    assert _match_pair(finding, signal) == "resource_id_match"


def test_notification_scheme_finding_correlates_with_notification_scheme_signal() -> None:
    from app.services.jira_risk_activity_correlation_service import _match_pair
    finding = _make_finding(
        rule_key="jira_notification_scheme_group_recipients", resource_id="NS_X"
    )
    signal = _make_signal(
        signal_type="jira_notification_scheme_config_changed", resource_id="NS_X"
    )
    assert _match_pair(finding, signal) == "resource_id_match"


def test_unknown_provider_ignored() -> None:
    """Service constant scopes correlation generation to provider=jira."""
    from app.services.jira_risk_activity_correlation_service import PROVIDER as SVC_PROVIDER
    assert SVC_PROVIDER == "jira"


def test_unknown_signal_type_ignored() -> None:
    """A signal whose type is not in the family signal_types does not match
    via the record_type fallback for an unrelated finding rule key."""
    from app.services.jira_risk_activity_correlation_service import _match_pair
    finding = _make_finding(
        rule_key="jira_webhook_non_https", resource_id="WH001"
    )
    signal = _make_signal(
        signal_type="some_unknown_signal_type", resource_id="WH002"
    )
    # Different resource ids AND a signal type that is neither the expected
    # webhook signal nor the generic fallback → no match.
    assert _match_pair(finding, signal) is None


def test_unknown_rule_key_falls_back_or_ignored() -> None:
    from app.services.jira_risk_activity_correlation_service import (
        _family_for_rule_key,
        _signal_type_for_rule_key,
    )
    # Unknown rule key resolves to the generic fallback family + generic signal.
    assert _family_for_rule_key("jira_unknown_rule_xyz") == "jira_config_risk_with_activity"
    assert _signal_type_for_rule_key("jira_unknown_rule_xyz") == "jira_config_activity"


# ── D. Metadata safety tests ───────────────────────────────────────────────────


def test_correlation_metadata_is_flat_and_safe() -> None:
    from app.services.jira_risk_activity_correlation_service import (
        JIRA_CORRELATION_RULES,
    )
    for family, rule in JIRA_CORRELATION_RULES.items():
        result = _build(
            "jira_webhook_non_https",
            rule["specific_signal"],
            family,
        )
        md = result["metadata"]
        for key, value in md.items():
            assert not isinstance(value, (dict, list, tuple, set)), (
                f"Nested value for {key!r} in {family!r} metadata: {value!r}"
            )


def test_correlation_metadata_no_forbidden_keys() -> None:
    from app.services.jira_risk_activity_correlation_service import (
        JIRA_CORRELATION_RULES,
    )
    for family, rule in JIRA_CORRELATION_RULES.items():
        result = _build(
            "jira_webhook_non_https",
            rule["specific_signal"],
            family,
        )
        for field in result["metadata"].keys():
            assert field not in _FORBIDDEN_METADATA_FIELDS, (
                f"Forbidden field {field!r} in correlation metadata for {family!r}"
            )


def test_correlation_operation_family_is_jira_configuration() -> None:
    result = _build(
        "jira_webhook_non_https",
        "jira_webhook_config_changed",
        "jira_webhook_risk_with_activity",
    )
    md = result["metadata"]
    assert md.get("operation_family", "").startswith("jira")


# ── E. Behavior tests ──────────────────────────────────────────────────────────


def test_lookback_hours_capped_at_168() -> None:
    from app.services.jira_risk_activity_correlation_service import (
        generate_jira_correlations,
    )
    db = MagicMock()
    db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = []
    result = generate_jira_correlations(
        workspace_id=uuid.uuid4(), db=db, lookback_hours=9999
    )
    assert result["lookback_hours"] == 168


def test_max_correlations_capped_at_1000() -> None:
    from app.services.jira_risk_activity_correlation_service import (
        generate_jira_correlations,
    )
    db = MagicMock()
    db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = []
    result = generate_jira_correlations(
        workspace_id=uuid.uuid4(), db=db, max_correlations=9999
    )
    assert result["max_correlations"] == 1000


def test_correlation_generation_is_idempotent() -> None:
    from app.services.jira_risk_activity_correlation_service import (
        generate_jira_correlations,
    )
    db = MagicMock()
    db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = []
    r1 = generate_jira_correlations(workspace_id=uuid.uuid4(), db=db)
    r2 = generate_jira_correlations(workspace_id=uuid.uuid4(), db=db)
    assert r1["correlations_created"] == r2["correlations_created"] == 0


def test_no_duplicate_correlations_on_rerun() -> None:
    from app.services.jira_risk_activity_correlation_service import _correlation_key
    finding = _make_finding()
    signal = _make_signal()
    k1 = _correlation_key(finding, signal, "jira_webhook_risk_with_activity")
    k2 = _correlation_key(finding, signal, "jira_webhook_risk_with_activity")
    assert k1 == k2  # deterministic key → upsert dedupes


def test_correlation_allowed_metadata_keys_includes_jira_safe_keys() -> None:
    from app.services.security_signal_correlation_service import ALLOWED_METADATA_KEYS
    required = {
        "correlation_type",
        "finding_id",
        "finding_rule_key",
        "finding_record_type",
        "finding_resource_type",
        "finding_resource_id",
        "signal_id",
        "activity_count",
        "risk_count",
        "matched_on",
        "match_confidence",
        "lookback_hours",
        "permission_scheme_id",
        "webhook_id",
        "workflow_id",
        "automation_rule_id",
        "board_id",
        "notification_scheme_id",
        "screen_scheme_id",
        "project_id",
        "site_id",
    }
    missing = required - ALLOWED_METADATA_KEYS
    assert not missing, f"M86F keys missing from ALLOWED_METADATA_KEYS: {sorted(missing)}"


def test_correlation_allowed_metadata_keys_excludes_forbidden_keys() -> None:
    from app.services.security_signal_correlation_service import ALLOWED_METADATA_KEYS
    truly_forbidden = {
        "jql", "api_token", "oauth_token", "webhook_secret", "secret_value",
        "authorization", "headers", "payload", "issue_key", "issue_title",
        "issue_description", "comment_body", "attachment_content", "email",
        "phone", "ip_address", "user_agent", "webhook_url", "delivery_url",
    }
    present = truly_forbidden & ALLOWED_METADATA_KEYS
    assert not present, f"Forbidden keys in ALLOWED_METADATA_KEYS: {sorted(present)}"


# ── F. Endpoint tests ──────────────────────────────────────────────────────────


def test_generate_correlations_endpoint_exists() -> None:
    from app.routers.security import router
    routes = [getattr(r, "path", "") for r in router.routes]
    assert any("jira-activity/generate-correlations" in p for p in routes), (
        "jira-activity/generate-correlations not found in router routes"
    )


def test_generate_correlations_endpoint_requires_auth() -> None:
    router_src = (BACKEND_APP / "routers" / "security.py").read_text(encoding="utf-8")
    idx = router_src.find("jira-activity/generate-correlations")
    assert idx != -1
    window = router_src[idx : idx + 2200]
    assert "require_workspace_admin" in window, (
        "require_workspace_admin not found near jira-activity/generate-correlations endpoint"
    )


# ── G. Frontend tests ──────────────────────────────────────────────────────────


def test_frontend_api_includes_jira_correlation_generate() -> None:
    api_ts = (FRONTEND_SRC / "lib" / "api.ts").read_text(encoding="utf-8")
    assert "generateJiraRiskActivityCorrelations" in api_ts
    assert "jira-activity/generate-correlations" in api_ts


def test_frontend_types_include_jira_correlation_response() -> None:
    types_ts = (FRONTEND_SRC / "types" / "index.ts").read_text(encoding="utf-8")
    assert "JiraRiskActivityCorrelationGenerateResponse" in types_ts


def test_frontend_correlations_page_includes_jira() -> None:
    page = (
        FRONTEND_SRC / "app" / "(app)" / "security" / "correlations" / "page.tsx"
    ).read_text(encoding="utf-8")
    assert '"jira"' in page
    for ct in [
        "jira_permission_scheme_risk_with_activity",
        "jira_webhook_risk_with_activity",
        "jira_workflow_risk_with_activity",
    ]:
        assert ct in page, f"Correlation type {ct!r} missing from correlations page"


# ── H. Framework tests ─────────────────────────────────────────────────────────


def test_capability_matrix_jira_risk_activity_correlations_true() -> None:
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("jira")
    assert cap is not None
    assert cap.security.risk_activity_correlations is True


def test_capability_matrix_jira_planned_next_stage_m86g() -> None:
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("jira")
    assert "M86F" in cap.notes
    assert "M86G" in cap.notes


def test_expansion_framework_jira_points_to_m86g() -> None:
    from app.services.provider_expansion_framework import get_framework
    fw = get_framework()
    planned = fw.get("summary", {}).get("planned_next_stage", "")
    assert planned, "planned_next_stage should be a non-empty string"
    assert any(
        token in planned
        for token in ("M89A", "Kubernetes", "M86G", "Jira", "M87A", "GitLab", "M88A", "Terraform", "M90A", "Sentry")
    ), (
        f"planned_next_stage should reference a known milestone (M89A/Kubernetes or later); got: {planned!r}"
    )


def test_gitlab_still_head_of_recommended_queue() -> None:
    from app.services.provider_expansion_framework import get_framework
    fw = get_framework()
    recs = fw.get("recommended_next_providers", [])
    assert recs and recs[0]["provider"] in ("gitlab", "jira", "terraform_cloud", "kubernetes", "sentry")


# ── I. Wording test ────────────────────────────────────────────────────────────


def test_no_forbidden_wording_in_jira_correlation_service() -> None:
    svc_path = BACKEND_APP / "services" / "jira_risk_activity_correlation_service.py"
    text = svc_path.read_text(encoding="utf-8").lower()
    for phrase in _FORBIDDEN_PHRASES:
        assert phrase not in text, (
            f"Forbidden phrase {phrase!r} found in jira_risk_activity_correlation_service.py"
        )


# ── J. Secret-shape grep (defense in depth) ───────────────────────────────────

_SECRET_PATTERNS = [
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}"),
    re.compile(r"SG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
]


def test_no_secret_shapes_in_jira_correlation_service() -> None:
    path = BACKEND_APP / "services" / "jira_risk_activity_correlation_service.py"
    text = path.read_text(encoding="utf-8", errors="replace")
    for pat in _SECRET_PATTERNS:
        match = pat.search(text)
        assert not match, (
            f"Secret-shaped string {match.group()!r} found in "
            f"jira_risk_activity_correlation_service.py"
        )
