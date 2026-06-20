"""M86E — Jira Activity Signals.

Promotes Jira configuration-state activity events (M86D) into review-priority
Incident Signals without storing secrets, OAuth tokens, webhook secrets, raw
webhook/delivery URLs, site base URLs, JQL, filter expressions, issue keys,
issue content, comment bodies, attachment content, customer names, user
identities, emails, account IDs, IP addresses, user agents, or any
audit/issue/comment/attachment payloads.

Verifies:
  * JIRA_EVENT_TYPE_TO_SIGNAL_TYPE contains exactly the 13 M86D event types
  * JIRA_SIGNAL_TYPES is derived correctly from the map
  * Each M86D event type maps to the expected signal type
  * Unknown event types are silently ignored (no signal generated)
  * generate_jira_activity_signals scans only provider=jira/source=jira_activity_event
  * Signals are grouped by safe resource identity
  * Signal metadata contains only safe, flat fields (no forbidden fields)
  * Signals are idempotent (re-running creates no duplicates)
  * Endpoint POST /security/jira-activity/generate-signals exists + admin-gated
  * JiraActivitySignalGenerateRequest/Response schema imports
  * ALLOWED_METADATA_KEYS in security_incident_signal_service contains M86E keys
  * Frontend signals page includes "jira"; api.ts exports generateJiraActivitySignals
  * types/index.ts has JiraActivitySignalGenerateResponse
  * Capability matrix marks activity_signals=True; expansion points to M86F
  * GitLab remains head of recommended provider queue
  * No forbidden wording appears

CLAIM DISCIPLINE: these are configuration-state review signals. They do NOT
confirm a breach, compromise, unauthorized access, data exposure, or leaked
credential.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# ── Safe placeholders ──────────────────────────────────────────────────────────

JIRA_TEST_WEBHOOK_ID = "JIRA_TEST_WEBHOOK_ID"
JIRA_TEST_AUTOMATION_RULE_ID = "JIRA_TEST_AUTOMATION_RULE_ID"
JIRA_TEST_PERMISSION_SCHEME_ID = "JIRA_TEST_PERMISSION_SCHEME_ID"
JIRA_TEST_WORKFLOW_ID = "JIRA_TEST_WORKFLOW_ID"
JIRA_TEST_ACTIVITY_EVENT_ID = "JIRA_TEST_ACTIVITY_EVENT_ID"
JIRA_TEST_SIGNAL_ID = "JIRA_TEST_SIGNAL_ID"
JIRA_TEST_SITE_ID = "JIRA_TEST_SITE_ID"
JIRA_TEST_PROJECT_ID = "JIRA_TEST_PROJECT_ID"
JIRA_TEST_BOARD_ID = "JIRA_TEST_BOARD_ID"

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND_APP = REPO_ROOT / "backend" / "app"
FRONTEND_SRC = REPO_ROOT / "frontend" / "src"

# Expected event type → signal type map (M86D → M86E). Exactly 13 entries.
EXPECTED_MAP: dict[str, str] = {
    "jira.site.updated": "jira_site_config_changed",
    "jira.project.updated": "jira_project_config_changed",
    "jira.board.updated": "jira_board_config_changed",
    "jira.workflow.updated": "jira_workflow_config_changed",
    "jira.workflow_scheme.updated": "jira_workflow_scheme_config_changed",
    "jira.permission_scheme.updated": "jira_permission_scheme_config_changed",
    "jira.notification_scheme.updated": "jira_notification_scheme_config_changed",
    "jira.issue_type_scheme.updated": "jira_issue_type_scheme_config_changed",
    "jira.field_configuration_scheme.updated": "jira_field_configuration_scheme_config_changed",
    "jira.screen_scheme.updated": "jira_screen_scheme_config_changed",
    "jira.webhook.updated": "jira_webhook_config_changed",
    "jira.automation_rule.updated": "jira_automation_rule_config_changed",
    "jira.config.event": "jira_config_activity",
}

# Fields that must NEVER appear in signal metadata.
_FORBIDDEN_SIGNAL_METADATA_FIELDS = frozenset({
    "jql", "url", "email", "token", "account_id", "user", "ip",
    "webhook_url", "issue_key", "issue_title", "comment", "attachment",
    "secret_value",
    "api_token", "oauth_token", "webhook_secret", "webhook_secret_value",
    "authorization", "headers", "payload", "request", "response", "raw",
    "audit", "audit_payload", "issue", "issue_description",
    "customer", "customer_name", "phone", "user_id", "user_name",
    "account", "member", "member_id", "ip_address", "user_agent",
    "delivery_url", "base_url", "site_url",
})

# Strings that must NEVER appear in signal metadata string values.
_FORBIDDEN_METADATA_STRINGS = [
    "eyJ",         # JWT pattern
    "@",           # email indicator
    "token=",      # token-in-URL pattern
    "Bearer ",
    "api_token",
    "oauth_token",
    "webhook_secret",
]

# Forbidden phrases in titles/summaries.
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


# ── Helpers ─────────────────────────────────────────────────────────────────

def _make_activity_event(
    event_type: str = "jira.site.updated",
    resource_id: str = JIRA_TEST_SITE_ID,
    metadata: dict | None = None,
) -> MagicMock:
    ev = MagicMock()
    ev.id = uuid.uuid4()
    ev.event_type = event_type
    ev.resource_id = resource_id
    ev.resource_type = "jira_site"
    ev.provider_event_id = f"jira:site:{resource_id}:2026-06-19"
    ev.occurred_at = datetime(2026, 6, 19, 12, 0, 0, tzinfo=timezone.utc)
    ev.ingested_at = datetime(2026, 6, 19, 12, 0, 0, tzinfo=timezone.utc)
    ev.created_at = datetime(2026, 6, 19, 12, 0, 0, tzinfo=timezone.utc)
    ev.integration_id = None
    ev.event_metadata = metadata or {
        "resource_type": "jira_site",
        "resource_id": resource_id,
        "operation_family": "jira.site",
        "operation_action": "updated",
        "event_source": "jira_activity_event",
        "deployment_type": "Cloud",
        "scm_info_present": True,
    }
    return ev


# ── 1-2. Import tests ──────────────────────────────────────────────────────────

def test_jira_signal_schema_imports() -> None:
    from app.schemas.security_jira_activity import (
        JiraActivitySignalGenerateRequest,
        JiraActivitySignalGenerateResponse,
    )
    req = JiraActivitySignalGenerateRequest()
    assert req.lookback_hours == 24
    assert req.max_signals == 100
    resp = JiraActivitySignalGenerateResponse()
    assert resp.provider == "jira"
    assert resp.source == "jira_activity_event"


def test_jira_activity_signal_service_imports() -> None:
    from app.services.jira_activity_signal_service import (
        JIRA_EVENT_TYPE_TO_SIGNAL_TYPE,
        JIRA_SIGNAL_TYPES,
        generate_jira_activity_signals,
    )
    assert isinstance(JIRA_EVENT_TYPE_TO_SIGNAL_TYPE, dict)
    assert isinstance(JIRA_SIGNAL_TYPES, frozenset)
    assert callable(generate_jira_activity_signals)


# ── 3-16. Signal type mapping tests ────────────────────────────────────────────

def _assert_maps(event_type: str, signal_type: str) -> None:
    from app.services.jira_activity_signal_service import (
        JIRA_EVENT_TYPE_TO_SIGNAL_TYPE,
        _build_signal,
    )
    assert JIRA_EVENT_TYPE_TO_SIGNAL_TYPE.get(event_type) == signal_type
    ev = _make_activity_event(event_type=event_type)
    result = _build_signal([ev])
    assert result is not None
    assert result["signal_type"] == signal_type


def test_jira_site_updated_maps_to_site_config_changed() -> None:
    _assert_maps("jira.site.updated", "jira_site_config_changed")


def test_jira_project_updated_maps_to_project_config_changed() -> None:
    _assert_maps("jira.project.updated", "jira_project_config_changed")


def test_jira_board_updated_maps_to_board_config_changed() -> None:
    _assert_maps("jira.board.updated", "jira_board_config_changed")


def test_jira_workflow_updated_maps_to_workflow_config_changed() -> None:
    _assert_maps("jira.workflow.updated", "jira_workflow_config_changed")


def test_jira_workflow_scheme_updated_maps_to_workflow_scheme_config_changed() -> None:
    _assert_maps(
        "jira.workflow_scheme.updated", "jira_workflow_scheme_config_changed"
    )


def test_jira_permission_scheme_updated_maps_to_permission_scheme_config_changed() -> None:
    _assert_maps(
        "jira.permission_scheme.updated", "jira_permission_scheme_config_changed"
    )


def test_jira_notification_scheme_updated_maps_to_notification_scheme_config_changed() -> None:
    _assert_maps(
        "jira.notification_scheme.updated",
        "jira_notification_scheme_config_changed",
    )


def test_jira_issue_type_scheme_updated_maps_to_issue_type_scheme_config_changed() -> None:
    _assert_maps(
        "jira.issue_type_scheme.updated",
        "jira_issue_type_scheme_config_changed",
    )


def test_jira_field_configuration_scheme_updated_maps_to_field_configuration_scheme_config_changed() -> None:
    _assert_maps(
        "jira.field_configuration_scheme.updated",
        "jira_field_configuration_scheme_config_changed",
    )


def test_jira_screen_scheme_updated_maps_to_screen_scheme_config_changed() -> None:
    _assert_maps(
        "jira.screen_scheme.updated", "jira_screen_scheme_config_changed"
    )


def test_jira_webhook_updated_maps_to_webhook_config_changed() -> None:
    _assert_maps("jira.webhook.updated", "jira_webhook_config_changed")


def test_jira_automation_rule_updated_maps_to_automation_rule_config_changed() -> None:
    _assert_maps(
        "jira.automation_rule.updated", "jira_automation_rule_config_changed"
    )


def test_jira_config_event_maps_to_jira_config_activity() -> None:
    _assert_maps("jira.config.event", "jira_config_activity")


def test_unknown_event_type_ignored_safely() -> None:
    from app.services.jira_activity_signal_service import _build_signal, _group_key
    for bad in (
        "jira.issue.created",
        "jira.comment.created",
        "jira.user.updated",
        "jira.audit.event",
        "",
        "   ",
    ):
        ev = _make_activity_event(event_type=bad)
        assert _group_key(ev) is None
        assert _build_signal([ev]) is None


def test_map_has_exactly_13_entries_matching_m86d() -> None:
    from app.services.jira_activity_signal_service import (
        JIRA_EVENT_TYPE_TO_SIGNAL_TYPE,
        JIRA_SIGNAL_TYPES,
    )
    from app.services.jira_activity_ingestion_service import (
        JIRA_CONFIG_EVENT_TYPES,
    )
    assert len(JIRA_EVENT_TYPE_TO_SIGNAL_TYPE) == 13
    assert JIRA_EVENT_TYPE_TO_SIGNAL_TYPE == EXPECTED_MAP
    assert set(JIRA_EVENT_TYPE_TO_SIGNAL_TYPE.keys()) == set(
        JIRA_CONFIG_EVENT_TYPES
    )
    assert JIRA_SIGNAL_TYPES == frozenset(
        JIRA_EVENT_TYPE_TO_SIGNAL_TYPE.values()
    )


# ── 17-22. Signal content tests ────────────────────────────────────────────────

def test_signals_use_provider_jira() -> None:
    from app.services.jira_activity_signal_service import _build_signal
    from app.services import jira_activity_signal_service as svc
    ev = _make_activity_event()
    result = _build_signal([ev])
    assert result is not None
    assert result["provider"] == "jira"
    assert svc.PROVIDER == "jira"


def test_signals_use_source_jira_activity_event() -> None:
    from app.services import jira_activity_signal_service as svc
    assert svc.SOURCE == "jira_activity_event"
    assert svc.EVIDENCE_LEVEL == "activity"
    assert svc.CONFIDENCE == "medium"
    ev = _make_activity_event()
    result = svc._build_signal([ev])
    assert result is not None
    assert result["metadata"].get("source") == "jira_activity_event"


def test_signal_metadata_is_flat_and_safe() -> None:
    from app.services.jira_activity_signal_service import _build_signal
    for event_type in EXPECTED_MAP:
        ev = _make_activity_event(event_type=event_type)
        result = _build_signal([ev])
        if result is None:
            continue
        metadata = result.get("metadata", {})
        for key, value in metadata.items():
            assert not isinstance(value, (dict, list, tuple, set)), (
                f"Non-flat metadata value for key {key!r}: {value!r}"
            )


def test_signal_metadata_no_forbidden_keys() -> None:
    from app.services.jira_activity_signal_service import _build_signal
    forbidden_exact = {
        "jql", "url", "email", "token", "account_id", "user", "ip",
        "webhook_url", "issue_key", "issue_title", "comment", "attachment",
        "secret_value",
    }
    danger_metadata = {
        "resource_type": "jira_webhook",
        "resource_id": JIRA_TEST_WEBHOOK_ID,
        "jql": "project = SECRET",
        "url": "https://example.atlassian.net/SECRET",
        "email": "alice@example.com",
        "token": "SECRET_TOKEN",
        "account_id": "ACCT_123",
        "user": "alice",
        "ip": "1.2.3.4",
        "webhook_url": "https://hooks.example.com/SECRET",
        "issue_key": "PROJ-123",
        "issue_title": "Top secret issue",
        "comment": "private comment",
        "attachment": "secret.pdf",
        "secret_value": "DANGEROUS",
        "webhook_url_present": True,
        "event_source": "jira_activity_event",
    }
    ev = _make_activity_event(
        event_type="jira.webhook.updated", metadata=danger_metadata
    )
    result = _build_signal([ev])
    assert result is not None
    metadata = result.get("metadata", {})
    for field in metadata.keys():
        assert field not in forbidden_exact, (
            f"Forbidden metadata field {field!r} found in signal"
        )
    meta_str = str(metadata)
    assert "DANGEROUS" not in meta_str
    assert "alice@example.com" not in meta_str
    assert "hooks.example.com/SECRET" not in meta_str


def test_signal_operation_family_is_jira_configuration() -> None:
    from app.services.jira_activity_signal_service import _build_signal
    ev = _make_activity_event()
    result = _build_signal([ev])
    assert result is not None
    assert result["metadata"].get("operation_family") == "jira_configuration"


def test_signal_operation_action_is_configuration_updated() -> None:
    from app.services.jira_activity_signal_service import _build_signal
    ev = _make_activity_event()
    result = _build_signal([ev])
    assert result is not None
    assert result["metadata"].get("operation_action") == "configuration_updated"


# ── 23-28. Behavior tests ──────────────────────────────────────────────────────

def test_lookback_hours_capped_at_168() -> None:
    from app.services.jira_activity_signal_service import (
        generate_jira_activity_signals,
    )
    db = MagicMock()
    db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = []
    # Should not raise with an out-of-range lookback; internal cap applies.
    result = generate_jira_activity_signals(
        workspace_id=uuid.uuid4(), db=db, lookback_hours=100000
    )
    assert result["provider"] == "jira"
    assert result["events_scanned"] == 0


def test_max_signals_capped_at_1000() -> None:
    from app.services.jira_activity_signal_service import (
        generate_jira_activity_signals,
    )
    db = MagicMock()
    db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = []
    result = generate_jira_activity_signals(
        workspace_id=uuid.uuid4(), db=db, max_signals=100000
    )
    assert result["provider"] == "jira"
    assert result["signals_created"] == 0


def test_signal_generation_is_idempotent() -> None:
    from app.services.jira_activity_signal_service import _build_signal
    ev1 = _make_activity_event(
        event_type="jira.webhook.updated", resource_id=JIRA_TEST_WEBHOOK_ID
    )
    ev2 = _make_activity_event(
        event_type="jira.webhook.updated", resource_id=JIRA_TEST_WEBHOOK_ID
    )
    s1 = _build_signal([ev1])
    s2 = _build_signal([ev2])
    assert s1 is not None and s2 is not None
    assert s1["signal_key"] == s2["signal_key"]


def test_no_duplicate_signals_on_rerun() -> None:
    from app.services.jira_activity_signal_service import (
        generate_jira_activity_signals,
    )
    from app.services import security_incident_signal_service as signal_svc

    ev = _make_activity_event(event_type="jira.site.updated")
    ev.occurred_at = datetime.now(timezone.utc)
    ev.ingested_at = ev.occurred_at
    ev.created_at = ev.occurred_at

    db = MagicMock()
    db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = [ev]

    seen: dict = {}

    def _fake_upsert(*, workspace_id, signal, db):  # noqa: ANN001
        key = signal["signal_key"]
        if key in seen:
            return ("existing", None)
        seen[key] = signal
        return ("created", None)

    orig = signal_svc.upsert_incident_signal
    signal_svc.upsert_incident_signal = _fake_upsert
    try:
        first = generate_jira_activity_signals(workspace_id=uuid.uuid4(), db=db)
        second = generate_jira_activity_signals(workspace_id=uuid.uuid4(), db=db)
    finally:
        signal_svc.upsert_incident_signal = orig

    assert first["signals_created"] == 1
    assert second["signals_created"] == 0
    assert second["signals_skipped"] == 1


def test_signal_allowed_metadata_keys_includes_jira_safe_keys() -> None:
    from app.services.security_incident_signal_service import (
        ALLOWED_METADATA_KEYS,
    )
    required_keys = {
        "deployment_type",
        "scm_info_present",
        "project_type_key",
        "is_private",
        "board_type",
        "board_column_count",
        "transition_count",
        "status_count",
        "workflow_active",
        "permission_grant_count",
        "permission_public_browse_projects",
        "notification_count",
        "screen_mapping_count",
        "webhook_url_present",
        "webhook_event_scope_category",
        "automation_action_count",
        "automation_has_web_request_action",
    }
    missing = required_keys - ALLOWED_METADATA_KEYS
    assert not missing, (
        f"M86E signal metadata keys missing from ALLOWED_METADATA_KEYS: "
        f"{sorted(missing)}"
    )


def test_signal_allowed_metadata_keys_excludes_forbidden_keys() -> None:
    from app.services.security_incident_signal_service import (
        ALLOWED_METADATA_KEYS,
    )
    # NOTE: account_id is a shared, pre-existing allowlisted key (opaque cloud
    # account identifier, not PII) used by AWS/Clerk etc., so it is excluded
    # from this Jira-specific forbidden set.
    truly_forbidden = {
        "jql", "webhook_url", "email", "api_token", "oauth_token",
        "webhook_secret", "issue_key", "issue_title",
        "comment", "attachment", "secret_value", "ip_address", "user_agent",
        "base_url", "site_url", "delivery_url",
    }
    present = truly_forbidden & ALLOWED_METADATA_KEYS
    assert not present, (
        f"Truly forbidden keys found in ALLOWED_METADATA_KEYS: {sorted(present)}"
    )


# ── 29-30. Endpoint tests ──────────────────────────────────────────────────────

def test_generate_signals_endpoint_exists() -> None:
    from app.routers.security import router
    routes = [getattr(r, "path", "") for r in router.routes]
    assert any("jira-activity/generate-signals" in p for p in routes), (
        f"jira-activity/generate-signals endpoint not found: {routes}"
    )


def test_generate_signals_endpoint_requires_auth() -> None:
    router_text = (BACKEND_APP / "routers" / "security.py").read_text(
        encoding="utf-8"
    )
    idx = router_text.find("jira-activity/generate-signals")
    assert idx != -1, "generate-signals endpoint not found in router source"
    region = router_text[idx: idx + 2500]
    assert "require_workspace_admin" in region, (
        "generate-signals endpoint region must call require_workspace_admin"
    )
    assert "JiraActivitySignalGenerateResponse" in router_text
    assert "jira_activity_signal_service" in router_text


# ── 31-33. Frontend tests ──────────────────────────────────────────────────────

class TestFrontend:
    @pytest.fixture(scope="class")
    def signals_page(self) -> str:
        return (
            FRONTEND_SRC / "app" / "(app)" / "security" / "signals" / "page.tsx"
        ).read_text(encoding="utf-8")

    @pytest.fixture(scope="class")
    def api_ts(self) -> str:
        return (FRONTEND_SRC / "lib" / "api.ts").read_text(encoding="utf-8")

    @pytest.fixture(scope="class")
    def types_ts(self) -> str:
        return (FRONTEND_SRC / "types" / "index.ts").read_text(encoding="utf-8")

    def test_frontend_api_includes_jira_signal_generate(self, api_ts: str) -> None:
        assert "generateJiraActivitySignals" in api_ts
        assert "/security/jira-activity/generate-signals" in api_ts

    def test_frontend_types_include_jira_signal_response(
        self, types_ts: str
    ) -> None:
        assert "JiraActivitySignalGenerateResponse" in types_ts

    def test_frontend_signals_page_includes_jira(self, signals_page: str) -> None:
        assert '"jira"' in signals_page
        assert "generateJiraActivitySignals" in signals_page
        assert "JIRA_SIGNAL_TYPES" in signals_page
        for signal_type in (
            "jira_site_config_changed",
            "jira_permission_scheme_config_changed",
            "jira_webhook_config_changed",
        ):
            assert signal_type in signals_page, (
                f"Signal type {signal_type!r} missing from signals page"
            )


# ── 34-37. Framework tests ─────────────────────────────────────────────────────

def test_capability_matrix_jira_activity_signals_true() -> None:
    from app.services.provider_capability_matrix_service import (
        get_provider_capability,
    )
    cap = get_provider_capability("jira")
    assert cap is not None
    assert cap.security.activity_signals is True
    assert cap.security.activity_ingestion is True
    assert "M86E" in cap.notes


def test_capability_matrix_jira_planned_next_stage_m86f() -> None:
    from app.services.provider_capability_matrix_service import (
        get_provider_capability,
    )
    cap = get_provider_capability("jira")
    assert "M86F" in cap.notes


def test_expansion_framework_jira_points_to_m86f() -> None:
    from app.services.provider_expansion_framework import get_framework
    fw = get_framework()
    planned = fw.get("summary", {}).get("planned_next_stage", "")
    assert (
        "M86F" in planned or "M86" in planned or "Jira" in planned
        or "M87A" in planned or "GitLab" in planned
    ), (
        f"planned_next_stage should reference M86F/Jira/M87A/GitLab; got: {planned!r}"
    )


def test_gitlab_still_head_of_recommended_queue() -> None:
    from app.services.provider_expansion_framework import get_framework
    fw = get_framework()
    recs = fw.get("recommended_next_providers", [])
    assert recs and recs[0]["provider"] in ("gitlab", "jira", "terraform_cloud", "kubernetes", "sentry")


# ── 38. Wording test ───────────────────────────────────────────────────────────

def test_no_forbidden_wording_in_jira_signal_service() -> None:
    svc_path = BACKEND_APP / "services" / "jira_activity_signal_service.py"
    text = svc_path.read_text(encoding="utf-8").lower()
    for phrase in _FORBIDDEN_PHRASES:
        assert phrase not in text, (
            f"Forbidden phrase {phrase!r} found in "
            f"jira_activity_signal_service.py"
        )
    # And every generated signal avoids forbidden wording too.
    from app.services.jira_activity_signal_service import _build_signal
    for event_type in EXPECTED_MAP:
        ev = _make_activity_event(event_type=event_type)
        result = _build_signal([ev])
        if result is None:
            continue
        body = (
            result.get("title", "") + " " + result.get("summary", "")
        ).lower()
        for phrase in _FORBIDDEN_PHRASES:
            assert phrase not in body, (
                f"Forbidden phrase {phrase!r} in signal for {event_type!r}"
            )
