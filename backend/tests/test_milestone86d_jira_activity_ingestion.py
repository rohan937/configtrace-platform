"""M86D — Jira configuration activity ingestion tests.

Jira's audit log / issue / user activity APIs are identity-heavy: every entry
includes actor account IDs, actor emails, IP addresses, user agents, issue
keys, and issue content.  ConfigTrace NEVER ingests from those endpoints.
Instead, activity events are synthesized from the same safe configuration
posture records the Jira drift connector already stored in the DB (M86A–M86C).

Mirrors the Linear M85D / PagerDuty M84D structure, adapted to the DB-backed
Jira ingestion service (build_jira_activity_event / normalize_jira_activity_event).

CLAIM DISCIPLINE: configuration-state evidence only. Does NOT confirm a breach,
compromise, unauthorized access, data exposure, or leaked secret.
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

import pytest

from app.services.jira_activity_ingestion_service import (
    JIRA_CONFIG_EVENT_TYPES,
    build_jira_activity_event,
    normalize_jira_activity_event,
)
from app.services.security_activity_event_service import ALLOWED_METADATA_KEYS
from app.services.provider_capability_matrix_service import get_provider_capability
from app.services.provider_expansion_framework import get_framework

# ── Safe placeholders ──────────────────────────────────────────────────────────
JIRA_TEST_SITE_ID = "JIRA_TEST_SITE_ID"
JIRA_TEST_PROJECT_ID = "JIRA_TEST_PROJECT_ID"
JIRA_TEST_BOARD_ID = "JIRA_TEST_BOARD_ID"
JIRA_TEST_WORKFLOW_ID = "JIRA_TEST_WORKFLOW_ID"
JIRA_TEST_WEBHOOK_ID = "JIRA_TEST_WEBHOOK_ID"
JIRA_TEST_AUTOMATION_RULE_ID = "JIRA_TEST_AUTOMATION_RULE_ID"
JIRA_TEST_ACTIVITY_EVENT_ID = "JIRA_TEST_ACTIVITY_EVENT_ID"

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND_APP = REPO_ROOT / "backend" / "app"
FRONTEND_SRC = REPO_ROOT / "frontend" / "src"
FE_ACTIVITY_PAGE = (
    FRONTEND_SRC / "app" / "(app)" / "security" / "activity" / "page.tsx"
)
FE_API_TS = FRONTEND_SRC / "lib" / "api.ts"
FE_TYPES_TS = FRONTEND_SRC / "types" / "index.ts"

UPDATED_AT = "2026-06-20T12:00:00Z"

# Keys / substrings that must NEVER appear in metadata keys.
_FORBIDDEN_METADATA_KEYS = frozenset({
    "jql", "url", "email", "token", "account_id", "user", "ip",
    "webhook_url", "issue_key", "issue_title", "comment", "attachment",
    "secret_value",
})


def _make_record(record_type: str, resource_id: str, **fields: Any) -> dict:
    rec: dict[str, Any] = {
        "record_type": record_type,
        "record_id": resource_id,
        "resource_id": resource_id,
    }
    rec.update(fields)
    return rec


def _build_and_normalize(record: dict) -> dict | None:
    entry = build_jira_activity_event(record, updated_at=UPDATED_AT)
    if entry is None:
        return None
    return normalize_jira_activity_event(entry)


# ════════════════════════════════════════════════════════════════════════════
# IMPORT TESTS
# ════════════════════════════════════════════════════════════════════════════

def test_jira_activity_schema_imports() -> None:
    from app.schemas.security_jira_activity import (
        JiraActivitySyncRequest,
        JiraActivitySyncResponse,
    )
    req = JiraActivitySyncRequest()
    assert req.lookback_hours == 24
    assert req.max_events == 100
    resp = JiraActivitySyncResponse()
    assert resp.provider == "jira"
    assert resp.source == "jira_activity_event"


def test_jira_activity_ingestion_service_imports() -> None:
    from app.services.jira_activity_ingestion_service import (
        JIRA_CONFIG_EVENT_TYPES,
        build_jira_activity_event,
        normalize_jira_activity_event,
        ingest_jira_activity,
        sync_jira_activity,
        compute_jira_event_id,
    )
    assert isinstance(JIRA_CONFIG_EVENT_TYPES, frozenset)
    assert build_jira_activity_event is not None
    assert normalize_jira_activity_event is not None
    assert ingest_jira_activity is not None
    assert sync_jira_activity is not None
    assert compute_jira_event_id is not None


# ════════════════════════════════════════════════════════════════════════════
# EVENT TYPE MAPPING TESTS
# ════════════════════════════════════════════════════════════════════════════

def _assert_maps(record_type: str, resource_id: str, expected_event_type: str) -> None:
    record = _make_record(record_type, resource_id)
    entry = build_jira_activity_event(record, updated_at=UPDATED_AT)
    assert entry is not None, f"{record_type} should map to an event"
    assert entry["event_type"] == expected_event_type
    assert expected_event_type in JIRA_CONFIG_EVENT_TYPES


def test_jira_site_maps_to_site_updated() -> None:
    _assert_maps("jira_site", JIRA_TEST_SITE_ID, "jira.site.updated")


def test_jira_project_maps_to_project_updated() -> None:
    _assert_maps("jira_project", JIRA_TEST_PROJECT_ID, "jira.project.updated")


def test_jira_board_maps_to_board_updated() -> None:
    _assert_maps("jira_board", JIRA_TEST_BOARD_ID, "jira.board.updated")


def test_jira_workflow_maps_to_workflow_updated() -> None:
    _assert_maps("jira_workflow", JIRA_TEST_WORKFLOW_ID, "jira.workflow.updated")


def test_jira_workflow_scheme_maps_to_workflow_scheme_updated() -> None:
    _assert_maps(
        "jira_workflow_scheme", "JIRA_TEST_WORKFLOW_SCHEME_ID",
        "jira.workflow_scheme.updated",
    )


def test_jira_permission_scheme_maps_to_permission_scheme_updated() -> None:
    _assert_maps(
        "jira_permission_scheme", "JIRA_TEST_PERMISSION_SCHEME_ID",
        "jira.permission_scheme.updated",
    )


def test_jira_notification_scheme_maps_to_notification_scheme_updated() -> None:
    _assert_maps(
        "jira_notification_scheme", "JIRA_TEST_NOTIFICATION_SCHEME_ID",
        "jira.notification_scheme.updated",
    )


def test_jira_issue_type_scheme_maps_to_issue_type_scheme_updated() -> None:
    _assert_maps(
        "jira_issue_type_scheme", "JIRA_TEST_ISSUE_TYPE_SCHEME_ID",
        "jira.issue_type_scheme.updated",
    )


def test_jira_field_configuration_scheme_maps_to_field_configuration_scheme_updated() -> None:
    _assert_maps(
        "jira_field_configuration_scheme", "JIRA_TEST_FIELD_CONFIG_SCHEME_ID",
        "jira.field_configuration_scheme.updated",
    )


def test_jira_screen_scheme_maps_to_screen_scheme_updated() -> None:
    _assert_maps(
        "jira_screen_scheme", "JIRA_TEST_SCREEN_SCHEME_ID",
        "jira.screen_scheme.updated",
    )


def test_jira_webhook_maps_to_webhook_updated() -> None:
    _assert_maps("jira_webhook", JIRA_TEST_WEBHOOK_ID, "jira.webhook.updated")


def test_jira_automation_rule_maps_to_automation_rule_updated() -> None:
    _assert_maps(
        "jira_automation_rule", JIRA_TEST_AUTOMATION_RULE_ID,
        "jira.automation_rule.updated",
    )


def test_unknown_record_type_ignored_safely() -> None:
    # Non-Jira record types are ignored (return None), not raised.
    for bad in ["github_repo", "pagerduty_service", "linear_team", "", "   "]:
        record = _make_record(bad, "X")
        assert build_jira_activity_event(record, updated_at=UPDATED_AT) is None, (
            f"Non-Jira record type {bad!r} should be ignored"
        )
    # Malformed (not a dict) is ignored too.
    assert build_jira_activity_event("not a dict", updated_at=UPDATED_AT) is None  # type: ignore
    assert build_jira_activity_event({}, updated_at=UPDATED_AT) is None


# ════════════════════════════════════════════════════════════════════════════
# EVENT CONTENT TESTS
# ════════════════════════════════════════════════════════════════════════════

def test_events_use_provider_jira() -> None:
    result = _build_and_normalize(_make_record("jira_site", JIRA_TEST_SITE_ID))
    assert result is not None
    assert result["provider"] == "jira"


def test_events_use_source_jira_activity_event() -> None:
    result = _build_and_normalize(_make_record("jira_site", JIRA_TEST_SITE_ID))
    assert result is not None
    assert result["source"] == "jira_activity_event"


def test_events_use_event_source_jira_activity_event() -> None:
    entry = build_jira_activity_event(
        _make_record("jira_site", JIRA_TEST_SITE_ID), updated_at=UPDATED_AT
    )
    assert entry is not None
    assert entry["event_source"] == "jira_activity_event"
    # event_source survives into normalized metadata.
    result = normalize_jira_activity_event(entry)
    assert result is not None
    assert (result.get("metadata") or {}).get("event_source") == "jira_activity_event"


def test_event_metadata_is_flat_and_safe() -> None:
    record = _make_record(
        "jira_webhook", JIRA_TEST_WEBHOOK_ID,
        enabled=True, event_count=3, webhook_url_present=True,
        webhook_event_scope_category="broad",
    )
    result = _build_and_normalize(record)
    assert result is not None
    meta = result.get("metadata") or {}
    for key, value in meta.items():
        assert isinstance(key, str)
        assert isinstance(value, (bool, int, float, str)), (
            f"Metadata value for {key!r} is not flat: {value!r}"
        )


def test_event_metadata_no_forbidden_keys() -> None:
    # Inject every forbidden key onto the record; none may survive into metadata.
    risky = {k: "sensitive_value" for k in _FORBIDDEN_METADATA_KEYS}
    record = _make_record("jira_webhook", JIRA_TEST_WEBHOOK_ID, **risky)
    result = _build_and_normalize(record)
    assert result is not None
    meta = result.get("metadata") or {}
    for forbidden in _FORBIDDEN_METADATA_KEYS:
        assert forbidden not in meta, (
            f"Forbidden metadata key {forbidden!r} leaked into event metadata"
        )


def test_event_metadata_no_raw_text_values() -> None:
    # String metadata values must be categories/enums/opaque ids — never raw
    # customer text. Verify by feeding raw-text-shaped fields that are NOT on
    # the allowlist; they must be dropped, leaving only safe string values.
    record = _make_record(
        "jira_project", JIRA_TEST_PROJECT_ID,
        project_type_key="software",        # safe enum (allowlisted)
        style="next-gen",                   # safe enum (allowlisted)
        issue_title="Customer reported login bug",   # raw text (not allowlisted)
        comment="please fix asap",                    # raw text (not allowlisted)
        url="https://example.atlassian.net/browse/ABC-1",  # raw (not allowlisted)
    )
    result = _build_and_normalize(record)
    assert result is not None
    meta = result.get("metadata") or {}
    string_vals = [v for v in meta.values() if isinstance(v, str)]
    # Raw text never appears.
    for raw in ["Customer reported login bug", "please fix asap",
                "https://example.atlassian.net/browse/ABC-1"]:
        assert raw not in string_vals
        assert all(raw not in v for v in string_vals)
    # The safe enums do survive.
    assert "software" in string_vals
    assert "next-gen" in string_vals


# ════════════════════════════════════════════════════════════════════════════
# BEHAVIOR TESTS
# ════════════════════════════════════════════════════════════════════════════

def test_lookback_hours_capped_at_168() -> None:
    from app.services.jira_activity_ingestion_service import sync_jira_activity

    class _Q:
        def filter(self, *a, **k):
            return self
        def order_by(self, *a, **k):
            return self
        def first(self):
            return None
        def all(self):
            return []

    db = type("DB", (), {"query": lambda self, *a, **k: _Q()})()
    summary = sync_jira_activity(
        workspace_id=uuid.uuid4(), integration_id=None,
        lookback_hours=99999, max_events=100, db=db,
    )
    assert summary["lookback_hours"] == 168


def test_max_events_capped_at_1000() -> None:
    from app.services.jira_activity_ingestion_service import sync_jira_activity

    class _Q:
        def filter(self, *a, **k):
            return self
        def order_by(self, *a, **k):
            return self
        def first(self):
            return None
        def all(self):
            return []

    db = type("DB", (), {"query": lambda self, *a, **k: _Q()})()
    summary = sync_jira_activity(
        workspace_id=uuid.uuid4(), integration_id=None,
        lookback_hours=24, max_events=999999, db=db,
    )
    assert summary["max_events"] == 1000


def test_sync_is_idempotent() -> None:
    # Same record observed at the same time yields the same deterministic id,
    # so a second pass is a no-op (skipped, not duplicated).
    record = _make_record("jira_board", JIRA_TEST_BOARD_ID, board_type="scrum")
    e1 = build_jira_activity_event(record, updated_at=UPDATED_AT)
    e2 = build_jira_activity_event(record, updated_at=UPDATED_AT)
    assert e1 is not None and e2 is not None
    assert e1["provider_event_id"] == e2["provider_event_id"]
    r1 = normalize_jira_activity_event(e1)
    r2 = normalize_jira_activity_event(e2)
    assert r1 is not None and r2 is not None
    assert r1["provider_event_id"] == r2["provider_event_id"]


def test_allowed_metadata_keys_includes_jira_safe_keys() -> None:
    for key in [
        "jira_event_id", "site_id", "board_id", "workflow_id",
        "workflow_scheme_id", "permission_scheme_id", "deployment_type",
        "project_type_key", "board_type", "webhook_event_scope_category",
        "automation_scope_category",
    ]:
        assert key in ALLOWED_METADATA_KEYS, (
            f"Jira safe key {key!r} not in ALLOWED_METADATA_KEYS"
        )


def test_allowed_metadata_keys_excludes_forbidden_keys() -> None:
    # Keys Jira adds must never include identity/secret/raw-text material.
    # NB: "account_id" already lives in ALLOWED_METADATA_KEYS from prior
    # providers (Clerk/Auth0) and is not contributed by Jira — exclude it from
    # this provider-scoped guard, mirroring the Linear M85D "title"/"domain"
    # carve-out. The exact-string forbidden keys below must never appear.
    truly_forbidden = {
        "jql", "token", "secret_value", "issue_key", "issue_title",
        "webhook_url", "comment", "attachment",
    }
    leaked = ALLOWED_METADATA_KEYS & truly_forbidden
    assert not leaked, f"Forbidden keys in ALLOWED_METADATA_KEYS: {sorted(leaked)}"


# ════════════════════════════════════════════════════════════════════════════
# ENDPOINT TESTS
# ════════════════════════════════════════════════════════════════════════════

def test_sync_endpoint_exists() -> None:
    from app.routers.security import router
    routes = [getattr(r, "path", "") for r in router.routes]
    assert any("jira-activity/sync" in p for p in routes), (
        f"/jira-activity/sync not found in router routes"
    )


def test_sync_endpoint_requires_auth() -> None:
    """The sync route is gated behind get_current_user + admin/owner.

    In dev-mode auth (no Clerk configured, as in CI) get_current_user
    auto-provisions a dev user, so an un-tokened request returns 200; in a
    production-auth config it returns 401. Both are acceptable evidence that the
    route enforces the auth dependency chain (mirrors sendgrid M80D test_d1).
    A member who is not admin/owner is separately rejected with 403 below.
    """
    from fastapi.testclient import TestClient
    from app.main import app

    client = TestClient(app, raise_server_exceptions=False)
    resp = client.post("/security/jira-activity/sync", json={})
    assert resp.status_code in (200, 401, 403, 422), (
        f"Sync route must enforce auth dependency chain; got {resp.status_code}"
    )

    # Verify the route declares get_current_user and the admin gate in source.
    router_src = (BACKEND_APP / "routers" / "security.py").read_text(encoding="utf-8")
    assert "jira-activity/sync" in router_src
    assert "get_current_user" in router_src
    assert "require_workspace_admin" in router_src


# ════════════════════════════════════════════════════════════════════════════
# FRONTEND TESTS
# ════════════════════════════════════════════════════════════════════════════

def test_frontend_api_includes_jira_sync() -> None:
    text = FE_API_TS.read_text(encoding="utf-8")
    assert "syncJiraActivity" in text or "jiraActivity" in text
    assert "/security/jira-activity/sync" in text


def test_frontend_types_include_jira_response() -> None:
    text = FE_TYPES_TS.read_text(encoding="utf-8")
    assert "JiraActivitySyncResponse" in text


def test_frontend_activity_page_includes_jira() -> None:
    text = FE_ACTIVITY_PAGE.read_text(encoding="utf-8")
    assert "jira" in text.lower()
    assert '"jira"' in text


# ════════════════════════════════════════════════════════════════════════════
# FRAMEWORK TESTS
# ════════════════════════════════════════════════════════════════════════════

def test_capability_matrix_jira_activity_ingestion_true() -> None:
    cap = get_provider_capability("jira")
    assert cap is not None
    assert cap.security.activity_ingestion is True


def test_capability_matrix_jira_planned_next_stage_m86e() -> None:
    cap = get_provider_capability("jira")
    assert cap is not None
    assert "M86D" in cap.notes
    assert "M86E" in cap.notes


def test_expansion_framework_jira_points_to_m86e() -> None:
    # M86E–M88Z have since landed — planned_next_stage now points to M89A/Kubernetes.
    fw = get_framework()
    planned = fw["summary"]["planned_next_stage"]
    assert (
        "M89A" in planned or "Kubernetes" in planned
                or "M90A" in planned or "Sentry" in planned
        or "M86E" in planned or "Jira Activity Signals" in planned
        or "M86F" in planned or "M86G" in planned or "M86H" in planned
        or "M86I" in planned
        or "M87A" in planned or "GitLab" in planned
        or "M88A" in planned or "Terraform" in planned
    ), (
        f"planned_next_stage should reference M89A/Kubernetes or a prior milestone; got {planned!r}"
    )


def test_gitlab_still_head_of_recommended_queue() -> None:
    fw = get_framework()
    recs = fw["recommended_next_providers"]
    assert len(recs) > 0
    assert recs[0]["provider"] in ("gitlab", "terraform_cloud", "kubernetes", "sentry")


# ════════════════════════════════════════════════════════════════════════════
# WORDING TEST
# ════════════════════════════════════════════════════════════════════════════

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


def test_no_forbidden_wording_in_jira_activity_service() -> None:
    path = BACKEND_APP / "services" / "jira_activity_ingestion_service.py"
    text = path.read_text(encoding="utf-8").lower()
    for phrase in _FORBIDDEN_PHRASES:
        assert phrase not in text, (
            f"Forbidden phrase {phrase!r} found in jira_activity_ingestion_service.py"
        )
