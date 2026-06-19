"""M85E — Linear Activity Signals.

Promotes Linear configuration-state activity events (M85D) into
review-priority Incident Signals without storing secrets, OAuth tokens,
webhook secrets, raw webhook URLs, issue content, comment bodies,
attachment content, customer names, user identities, emails, phone numbers,
IP addresses, user agents, or any audit/issue/comment/attachment payloads.

Verifies:
  * LINEAR_EVENT_TYPE_TO_SIGNAL_TYPE contains exactly the 10 M85D event types
  * LINEAR_SIGNAL_TYPES is derived correctly from the map
  * Each M85D event type maps to the expected signal type
  * Unknown event types are silently ignored (no signal generated)
  * generate_linear_activity_signals scans only provider=linear/source=linear_activity_event
  * Signals are grouped by safe resource identity
  * Signal metadata contains only safe fields (no forbidden fields)
  * Signals are idempotent (re-running creates no duplicates)
  * linked_activity_event_id is set to the anchor event's id
  * The latest event is picked as the group anchor
  * _build_signal returns provider=linear/evidence_level=activity/confidence=medium
  * Endpoint POST /security/linear-activity/generate-signals exists + admin-gated
  * LinearActivitySignalGenerateRequest/Response schema imports
  * ALLOWED_METADATA_KEYS in security_incident_signal_service contains M85E keys
  * signal_svc.sanitize_signal_metadata strips forbidden fields
  * Frontend signals page includes "linear" as a provider option
  * Frontend api.ts exports generateLinearActivitySignals
  * types/index.ts has LinearActivitySignalGenerateResponse
  * Capability matrix marks activity_signals=True; correlations/demo remain False
  * Expansion framework points to M85F; Jira is head of recommended queue
  * No forbidden wording appears
  * No secret-shaped strings appear

CLAIM DISCIPLINE: these are configuration-state review signals. They do NOT
confirm a breach, compromise, unauthorized access, data exposure, or leaked
credential.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock

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

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND_APP = REPO_ROOT / "backend" / "app"
FRONTEND_SRC = REPO_ROOT / "frontend" / "src"

# Expected event type → signal type map (M85D → M85E). Exactly 10 entries.
EXPECTED_MAP: dict[str, str] = {
    "linear.workspace.updated": "linear_workspace_config_changed",
    "linear.team.updated": "linear_team_config_changed",
    "linear.project.updated": "linear_project_config_changed",
    "linear.workflow_state.updated": "linear_workflow_state_config_changed",
    "linear.label.updated": "linear_label_config_changed",
    "linear.webhook.updated": "linear_webhook_config_changed",
    "linear.view.updated": "linear_view_config_changed",
    "linear.cycle.updated": "linear_cycle_config_changed",
    "linear.integration.updated": "linear_integration_config_changed",
    "linear.config.event": "linear_config_activity",
}

# Fields that must NEVER appear in signal metadata.
_FORBIDDEN_SIGNAL_METADATA_FIELDS = frozenset({
    "api_key", "token", "oauth_token", "webhook_secret_value", "secret_value",
    "authorization", "headers", "payload", "request", "response", "raw",
    "audit", "audit_payload", "issue", "issue_title", "issue_description",
    "comment", "attachment", "customer", "customer_name",
    "email", "phone", "sms", "user", "user_id",
    "member", "member_id", "contact", "contact_method",
    "ip", "ip_address", "user_agent",
    "webhook_url", "hostname",
})

# Strings that must NEVER appear in signal metadata string values.
_FORBIDDEN_METADATA_STRINGS = [
    "eyJ",         # JWT pattern
    "@",           # email indicator
    "token=",      # token-in-URL pattern
    "Bearer ",
    "api_key",
    "oauth_token",
    "webhook_secret_value",
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


# ── A. Event type → signal type taxonomy ──────────────────────────────────────

def test_a1_signal_service_importable() -> None:
    from app.services.linear_activity_signal_service import (
        LINEAR_EVENT_TYPE_TO_SIGNAL_TYPE,
        LINEAR_SIGNAL_TYPES,
        generate_linear_activity_signals,
    )
    assert isinstance(LINEAR_EVENT_TYPE_TO_SIGNAL_TYPE, dict)
    assert isinstance(LINEAR_SIGNAL_TYPES, frozenset)
    assert callable(generate_linear_activity_signals)


def test_a2_event_type_map_has_exactly_10_entries() -> None:
    from app.services.linear_activity_signal_service import (
        LINEAR_EVENT_TYPE_TO_SIGNAL_TYPE,
    )
    assert len(LINEAR_EVENT_TYPE_TO_SIGNAL_TYPE) == 10
    assert len(EXPECTED_MAP) == 10


def test_a3_event_type_map_matches_expected() -> None:
    from app.services.linear_activity_signal_service import (
        LINEAR_EVENT_TYPE_TO_SIGNAL_TYPE,
    )
    assert LINEAR_EVENT_TYPE_TO_SIGNAL_TYPE == EXPECTED_MAP


def test_a4_map_keys_match_m85d_event_types() -> None:
    from app.services.linear_activity_signal_service import (
        LINEAR_EVENT_TYPE_TO_SIGNAL_TYPE,
    )
    from app.services.linear_activity_ingestion_service import (
        LINEAR_CONFIG_EVENT_TYPES,
    )
    assert set(LINEAR_EVENT_TYPE_TO_SIGNAL_TYPE.keys()) == set(
        LINEAR_CONFIG_EVENT_TYPES
    )


def test_a5_signal_types_derived_from_map() -> None:
    from app.services.linear_activity_signal_service import (
        LINEAR_EVENT_TYPE_TO_SIGNAL_TYPE,
        LINEAR_SIGNAL_TYPES,
    )
    expected = frozenset(LINEAR_EVENT_TYPE_TO_SIGNAL_TYPE.values())
    assert LINEAR_SIGNAL_TYPES == expected


def test_a6_each_m85d_event_type_maps_to_expected_signal_type() -> None:
    from app.services.linear_activity_signal_service import (
        LINEAR_EVENT_TYPE_TO_SIGNAL_TYPE,
        _group_key,
    )
    for event_type, expected_signal_type in EXPECTED_MAP.items():
        actual = LINEAR_EVENT_TYPE_TO_SIGNAL_TYPE.get(event_type)
        assert actual == expected_signal_type, (
            f"Event type {event_type!r} maps to {actual!r}, "
            f"expected {expected_signal_type!r}"
        )
        # And the group key reflects the expected signal type.
        ev = _make_activity_event(event_type=event_type)
        gk = _group_key(ev)
        assert gk is not None
        assert expected_signal_type in gk, (
            f"group key {gk!r} for {event_type!r} should contain "
            f"{expected_signal_type!r}"
        )


@pytest.mark.parametrize("bad_type", [
    "linear.issue.created",
    "linear.comment.created",
    "linear.user.updated",
    "linear.audit.event",
    "audit_log.entry",
    "pagerduty.service.updated",
    "github.push",
    "",
    "   ",
])
def test_a7_unknown_event_type_returns_none_from_group_key(bad_type: str) -> None:
    from app.services.linear_activity_signal_service import _group_key
    ev = MagicMock()
    ev.event_type = bad_type
    ev.resource_id = None
    ev.event_metadata = {}
    result = _group_key(ev)
    assert result is None, f"Expected None for event_type={bad_type!r}"


# ── Helpers ─────────────────────────────────────────────────────────────────

def _make_activity_event(
    event_type: str = "linear.workspace.updated",
    resource_id: str = LINEAR_TEST_WORKSPACE_ID,
    metadata: dict | None = None,
) -> MagicMock:
    ev = MagicMock()
    ev.id = uuid.uuid4()
    ev.event_type = event_type
    ev.resource_id = resource_id
    ev.provider_event_id = f"linear:workspace:{resource_id}:2026-06-19"
    ev.occurred_at = datetime(2026, 6, 19, 12, 0, 0, tzinfo=timezone.utc)
    ev.ingested_at = datetime(2026, 6, 19, 12, 0, 0, tzinfo=timezone.utc)
    ev.created_at = datetime(2026, 6, 19, 12, 0, 0, tzinfo=timezone.utc)
    ev.integration_id = None
    ev.event_metadata = metadata or {
        "resource_type": "linear_workspace",
        "resource_id": resource_id,
        "operation_family": "linear.workspace",
        "operation_action": "updated",
        "category": "Workspace configuration",
        "event_source": "linear_activity_event",
        "url_key_present": True,
        "logo_present": True,
        "team_count": 5,
    }
    return ev


# ── B. Signal building tests ──────────────────────────────────────────────────

class TestSignalBuilding:
    def test_build_signal_returns_dict_for_valid_event(self) -> None:
        from app.services.linear_activity_signal_service import _build_signal
        ev = _make_activity_event()
        result = _build_signal([ev])
        assert result is not None
        assert result["provider"] == "linear"
        assert result["signal_type"] == "linear_workspace_config_changed"
        assert result["evidence_level"] == "activity"
        assert result["confidence"] == "medium"
        assert result["linked_activity_event_id"] == ev.id

    def test_build_signal_provider_evidence_confidence(self) -> None:
        from app.services.linear_activity_signal_service import _build_signal
        ev = _make_activity_event()
        result = _build_signal([ev])
        assert result is not None
        assert result["provider"] == "linear"
        assert result["evidence_level"] == "activity"
        assert result["confidence"] == "medium"

    def test_build_signal_returns_none_for_unknown_event_type(self) -> None:
        from app.services.linear_activity_signal_service import _build_signal
        ev = _make_activity_event(event_type="linear.issue.created")
        result = _build_signal([ev])
        assert result is None

    def test_build_signal_title_contains_resource_type(self) -> None:
        from app.services.linear_activity_signal_service import _build_signal
        ev = _make_activity_event()
        result = _build_signal([ev])
        assert result is not None
        assert "linear_workspace" in result["title"]

    def test_build_signal_summary_safe_wording(self) -> None:
        from app.services.linear_activity_signal_service import _build_signal
        ev = _make_activity_event()
        result = _build_signal([ev])
        assert result is not None
        summary_lower = result["summary"].lower()
        for phrase in _FORBIDDEN_PHRASES:
            assert phrase not in summary_lower, (
                f"Forbidden phrase {phrase!r} found in signal summary"
            )
        assert (
            "review" in summary_lower
            or "evidence" in summary_lower
            or "may require" in summary_lower
        )

    def test_build_signal_metadata_no_forbidden_fields(self) -> None:
        from app.services.linear_activity_signal_service import _build_signal
        ev = _make_activity_event()
        result = _build_signal([ev])
        assert result is not None
        metadata = result.get("metadata", {})
        for field in metadata.keys():
            assert field not in _FORBIDDEN_SIGNAL_METADATA_FIELDS, (
                f"Forbidden metadata field {field!r} found in signal"
            )

    def test_build_signal_metadata_no_forbidden_string_values(self) -> None:
        from app.services.linear_activity_signal_service import _build_signal
        ev = _make_activity_event()
        result = _build_signal([ev])
        assert result is not None
        metadata = result.get("metadata", {})
        for value in metadata.values():
            if not isinstance(value, str):
                continue
            for needle in _FORBIDDEN_METADATA_STRINGS:
                assert needle not in value, (
                    f"Forbidden string {needle!r} found in metadata value {value!r}"
                )

    def test_linked_activity_event_id_is_anchor_id(self) -> None:
        from app.services.linear_activity_signal_service import _build_signal
        ev = _make_activity_event()
        result = _build_signal([ev])
        assert result is not None
        assert result["linked_activity_event_id"] == ev.id

    def test_group_key_deterministic(self) -> None:
        from app.services.linear_activity_signal_service import _group_key
        ev1 = _make_activity_event()
        ev2 = _make_activity_event()
        assert _group_key(ev1) == _group_key(ev2)

    def test_same_resource_id_same_group(self) -> None:
        from app.services.linear_activity_signal_service import _group_key
        ev1 = _make_activity_event(resource_id=LINEAR_TEST_TEAM_ID)
        ev2 = _make_activity_event(resource_id=LINEAR_TEST_TEAM_ID)
        assert _group_key(ev1) == _group_key(ev2)

    def test_different_resource_id_different_group(self) -> None:
        from app.services.linear_activity_signal_service import _group_key
        ev1 = _make_activity_event(resource_id="TEAM_001")
        ev2 = _make_activity_event(resource_id="TEAM_002")
        assert _group_key(ev1) != _group_key(ev2)

    def test_group_key_differs_by_signal_type(self) -> None:
        from app.services.linear_activity_signal_service import _group_key
        ev1 = _make_activity_event(event_type="linear.workspace.updated")
        ev2 = _make_activity_event(event_type="linear.team.updated")
        assert _group_key(ev1) != _group_key(ev2)

    def test_signals_idempotent_same_resource_same_key(self) -> None:
        from app.services.linear_activity_signal_service import _build_signal
        ev1 = _make_activity_event(resource_id=LINEAR_TEST_WEBHOOK_ID)
        ev1.event_type = "linear.webhook.updated"
        ev2 = _make_activity_event(resource_id=LINEAR_TEST_WEBHOOK_ID)
        ev2.event_type = "linear.webhook.updated"
        s1 = _build_signal([ev1])
        s2 = _build_signal([ev2])
        assert s1 is not None and s2 is not None
        assert s1["signal_key"] == s2["signal_key"]

    def test_anchor_picks_latest_event(self) -> None:
        from app.services.linear_activity_signal_service import _pick_anchor
        ev1 = _make_activity_event()
        ev1.occurred_at = datetime(2026, 6, 19, 10, 0, 0, tzinfo=timezone.utc)
        ev2 = _make_activity_event()
        ev2.occurred_at = datetime(2026, 6, 19, 12, 0, 0, tzinfo=timezone.utc)
        anchor = _pick_anchor([ev1, ev2])
        assert anchor is ev2


# ── C. Signal metadata privacy ────────────────────────────────────────────────

class TestSignalMetadataPrivacy:
    def test_sanitize_strips_forbidden_fields(self) -> None:
        from app.services.security_incident_signal_service import (
            sanitize_signal_metadata,
        )
        raw = {
            "resource_id": LINEAR_TEST_WEBHOOK_ID,
            "api_key": "SECRET",
            "oauth_token": "SECRET_TOKEN",
            "webhook_secret_value": "WEBHOOK_SECRET",
            "webhook_url": "https://hooks.example.com/abc",
            "email": "user@example.com",
            "ip_address": "1.2.3.4",
            "user_agent": "Mozilla/5.0",
            "issue_title": "Top secret issue",
            "comment": "private comment",
            "event_count": 3,
        }
        result = sanitize_signal_metadata(raw)
        for forbidden in _FORBIDDEN_SIGNAL_METADATA_FIELDS:
            assert forbidden not in result, (
                f"Forbidden field {forbidden!r} survived sanitize_signal_metadata"
            )
        assert "resource_id" in result
        assert "event_count" in result

    def test_signal_build_no_webhook_secret_in_metadata(self) -> None:
        from app.services.linear_activity_signal_service import _build_signal
        ev = _make_activity_event(metadata={
            "resource_type": "linear_webhook",
            "resource_id": LINEAR_TEST_WEBHOOK_ID,
            "webhook_secret_value": "DANGEROUS_SECRET_VALUE",
            "webhook_url": "https://hooks.example.com/DANGEROUS",
            "webhook_secret_present": True,
            "webhook_url_present": True,
            "event_source": "linear_activity_event",
        })
        ev.event_type = "linear.webhook.updated"
        result = _build_signal([ev])
        assert result is not None
        metadata = result.get("metadata", {})
        assert "webhook_secret_value" not in metadata
        assert "webhook_url" not in metadata
        meta_str = str(metadata)
        assert "DANGEROUS_SECRET_VALUE" not in meta_str
        assert "hooks.example.com/DANGEROUS" not in meta_str
        # Safe booleans are allowed.
        assert (
            "webhook_secret_present" in metadata
            or "webhook_url_present" in metadata
        )

    def test_signal_build_no_user_identity_in_metadata(self) -> None:
        from app.services.linear_activity_signal_service import _build_signal
        ev = _make_activity_event(metadata={
            "resource_type": "linear_project",
            "resource_id": LINEAR_TEST_PROJECT_ID,
            "user_id": "USER_123",
            "email": "alice@example.com",
            "member_id": "MEMBER_456",
            "customer_name": "Acme Corp",
            "lead_present": True,
            "project_count": 3,
            "event_source": "linear_activity_event",
        })
        ev.event_type = "linear.project.updated"
        result = _build_signal([ev])
        assert result is not None
        metadata = result.get("metadata", {})
        assert "user_id" not in metadata
        assert "email" not in metadata
        assert "member_id" not in metadata
        assert "customer_name" not in metadata
        # Safe booleans/counts allowed.
        assert "lead_present" in metadata or "project_count" in metadata


# ── D. ALLOWED_METADATA_KEYS wiring ───────────────────────────────────────────

class TestAllowedMetadataKeys:
    def test_linear_signal_keys_in_allowed(self) -> None:
        from app.services.security_incident_signal_service import (
            ALLOWED_METADATA_KEYS,
        )
        required_keys = {
            "url_key_present",
            "logo_present",
            "team_visibility_category",
            "private_team",
            "project_count",
            "auto_archive_enabled",
            "cycle_enabled",
            "cycle_duration_category",
            "workflow_state_count",
            "has_backlog_state",
            "has_started_state",
            "has_completed_state",
            "has_canceled_state",
            "project_status_category",
            "project_health_category",
            "lead_present",
            "issue_count_category",
            "state_type_category",
            "position_category",
            "is_group_label",
            "parent_id_present",
            "webhook_enabled",
            "webhook_secret_present",
            "webhook_url_present",
            "webhook_url_scheme_category",
            "webhook_resource_types_count",
            "webhook_has_comment_type",
            "webhook_has_attachment_type",
            "view_shared",
            "filter_count_category",
            "integration_enabled",
            "integration_count",
            "label_count",
        }
        missing = required_keys - ALLOWED_METADATA_KEYS
        assert not missing, (
            f"M85E signal metadata keys missing from ALLOWED_METADATA_KEYS: "
            f"{sorted(missing)}"
        )

    def test_forbidden_keys_not_in_allowed(self) -> None:
        from app.services.security_incident_signal_service import (
            ALLOWED_METADATA_KEYS,
        )
        truly_forbidden = {
            "api_key", "oauth_token", "webhook_secret_value", "webhook_url",
            "authorization", "headers", "payload", "issue", "comment",
            "attachment", "customer", "email", "phone", "ip_address",
            "user_agent", "user_id", "member_id",
        }
        present = truly_forbidden & ALLOWED_METADATA_KEYS
        assert not present, (
            f"Truly forbidden keys found in ALLOWED_METADATA_KEYS: "
            f"{sorted(present)}"
        )


# ── E. Signal generation service ──────────────────────────────────────────────

class TestSignalGenerationService:
    def test_provider_source_evidence_confidence_constants(self) -> None:
        from app.services import linear_activity_signal_service as svc
        assert svc.PROVIDER == "linear"
        assert svc.SOURCE == "linear_activity_event"
        assert svc.EVIDENCE_LEVEL == "activity"
        assert svc.CONFIDENCE == "medium"

    def test_generate_with_empty_events_returns_zero_counts(self) -> None:
        from app.services.linear_activity_signal_service import (
            generate_linear_activity_signals,
        )
        db = MagicMock()
        db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = []
        result = generate_linear_activity_signals(
            workspace_id=uuid.uuid4(),
            db=db,
        )
        assert result["provider"] == "linear"
        assert result["source"] == "linear_activity_event"
        assert result["events_scanned"] == 0
        assert result["groups_scanned"] == 0
        assert result["signals_created"] == 0
        assert result["signals_skipped"] == 0

    def test_generate_summary_has_required_keys(self) -> None:
        from app.services.linear_activity_signal_service import (
            generate_linear_activity_signals,
        )
        db = MagicMock()
        db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = []
        result = generate_linear_activity_signals(
            workspace_id=uuid.uuid4(),
            db=db,
        )
        for key in (
            "provider",
            "source",
            "events_scanned",
            "groups_scanned",
            "signals_created",
            "signals_skipped",
        ):
            assert key in result, f"Summary missing key: {key!r}"

    def test_generate_only_scans_linear_source(self) -> None:
        from app.services.linear_activity_signal_service import (
            generate_linear_activity_signals,
        )
        from app.models.security_activity_event import SecurityActivityEvent
        db = MagicMock()
        query_mock = MagicMock()
        db.query.return_value = query_mock
        filter_mock = MagicMock()
        query_mock.filter.return_value = filter_mock
        order_mock = MagicMock()
        filter_mock.order_by.return_value = order_mock
        limit_mock = MagicMock()
        order_mock.limit.return_value = limit_mock
        limit_mock.all.return_value = []
        generate_linear_activity_signals(
            workspace_id=uuid.uuid4(),
            db=db,
        )
        assert db.query.called
        assert db.query.call_args[0][0] == SecurityActivityEvent

    def test_generate_unknown_event_type_ignored(self) -> None:
        from app.services.linear_activity_signal_service import (
            generate_linear_activity_signals,
        )
        ev = _make_activity_event(event_type="linear.issue.created")
        ev.occurred_at = datetime.now(timezone.utc)
        db = MagicMock()
        db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = [ev]
        result = generate_linear_activity_signals(
            workspace_id=uuid.uuid4(),
            db=db,
        )
        assert result["groups_scanned"] == 0
        assert result["signals_created"] == 0


# ── F. Router endpoint ─────────────────────────────────────────────────────────

class TestRouterEndpoint:
    @pytest.fixture(scope="class")
    def router_text(self) -> str:
        return (BACKEND_APP / "routers" / "security.py").read_text(
            encoding="utf-8"
        )

    def test_linear_generate_signals_endpoint_exists(self) -> None:
        from app.routers.security import router
        routes = [getattr(r, "path", "") for r in router.routes]
        assert any("linear-activity/generate-signals" in p for p in routes), (
            f"linear-activity/generate-signals endpoint not found: {routes}"
        )

    def test_router_references_generate_signals_path(self, router_text: str) -> None:
        assert "/linear-activity/generate-signals" in router_text

    def test_router_references_response_schema(self, router_text: str) -> None:
        assert "LinearActivitySignalGenerateResponse" in router_text

    def test_router_references_signal_service(self, router_text: str) -> None:
        assert "linear_activity_signal_service" in router_text

    def test_router_generate_signals_requires_workspace_admin(
        self, router_text: str
    ) -> None:
        idx = router_text.find("linear-activity/generate-signals")
        assert idx != -1, "generate-signals endpoint not found in router source"
        # The handler body follows the decorator; scan a window around it.
        region = router_text[idx: idx + 2000]
        assert "require_workspace_admin" in region, (
            "generate-signals endpoint region must call require_workspace_admin"
        )

    def test_schema_importable(self) -> None:
        from app.schemas.security_linear_activity import (
            LinearActivitySignalGenerateRequest,
            LinearActivitySignalGenerateResponse,
        )
        req = LinearActivitySignalGenerateRequest()
        assert req.lookback_hours == 24
        assert req.max_signals == 100
        resp = LinearActivitySignalGenerateResponse()
        assert resp.provider == "linear"
        assert resp.source == "linear_activity_event"


# ── G. Capability matrix ───────────────────────────────────────────────────────

class TestCapabilityMatrix:
    def test_activity_signals_true(self) -> None:
        from app.services.provider_capability_matrix_service import (
            get_provider_capability,
        )
        cap = get_provider_capability("linear")
        assert cap is not None
        assert cap.security.activity_signals is True

    def test_activity_ingestion_still_true(self) -> None:
        from app.services.provider_capability_matrix_service import (
            get_provider_capability,
        )
        cap = get_provider_capability("linear")
        assert cap.security.activity_ingestion is True

    def test_risk_activity_correlations_false(self) -> None:
        # M85F advanced this to True; assert current state.
        from app.services.provider_capability_matrix_service import (
            get_provider_capability,
        )
        cap = get_provider_capability("linear")
        assert cap.security.risk_activity_correlations is True

    def test_demo_seed_clear_false(self) -> None:
        from app.services.provider_capability_matrix_service import (
            get_provider_capability,
        )
        cap = get_provider_capability("linear")
        assert cap.security.demo_seed_clear is False

    def test_notes_mention_m85e(self) -> None:
        from app.services.provider_capability_matrix_service import (
            get_provider_capability,
        )
        cap = get_provider_capability("linear")
        assert "M85E" in cap.notes


# ── H. Expansion framework ─────────────────────────────────────────────────────

class TestExpansionFramework:
    def test_planned_next_stage_is_m85f(self) -> None:
        # M85F is complete; framework now points to M85G.
        from app.services.provider_expansion_framework import get_framework
        fw = get_framework()
        planned = fw.get("summary", {}).get("planned_next_stage", "")
        assert "M85G" in planned, (
            f"planned_next_stage should reference M85G; got: {planned!r}"
        )

    def test_planned_next_stage_not_m85e(self) -> None:
        from app.services.provider_expansion_framework import get_framework
        fw = get_framework()
        planned = fw.get("summary", {}).get("planned_next_stage", "")
        assert "M85E" not in planned

    def test_jira_is_head_of_recommended_queue(self) -> None:
        from app.services.provider_expansion_framework import get_framework
        fw = get_framework()
        recs = fw.get("recommended_next_providers", [])
        assert recs and recs[0]["provider"] == "jira"


# ── I. Frontend checks ─────────────────────────────────────────────────────────

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

    def test_linear_in_provider_type(self, signals_page: str) -> None:
        assert '"linear"' in signals_page

    def test_linear_signal_types_in_page(self, signals_page: str) -> None:
        assert "LINEAR_SIGNAL_TYPES" in signals_page

    def test_generate_linear_signals_imported(self, signals_page: str) -> None:
        assert "generateLinearActivitySignals" in signals_page

    def test_linear_provider_branch_present(self, signals_page: str) -> None:
        assert 'provider === "linear"' in signals_page

    def test_generate_linear_signals_in_api_ts(self, api_ts: str) -> None:
        assert "generateLinearActivitySignals" in api_ts
        assert "/security/linear-activity/generate-signals" in api_ts

    def test_linear_signal_response_in_types(self, types_ts: str) -> None:
        assert "LinearActivitySignalGenerateResponse" in types_ts

    def test_linear_signal_types_list(self, signals_page: str) -> None:
        for signal_type in [
            "linear_workspace_config_changed",
            "linear_team_config_changed",
            "linear_webhook_config_changed",
        ]:
            assert signal_type in signals_page, (
                f"Signal type {signal_type!r} missing from signals page"
            )


# ── J. Forbidden wording ───────────────────────────────────────────────────────

class TestForbiddenWording:
    def test_no_forbidden_wording_in_signal_service(self) -> None:
        svc_path = (
            BACKEND_APP / "services" / "linear_activity_signal_service.py"
        )
        text = svc_path.read_text(encoding="utf-8").lower()
        for phrase in _FORBIDDEN_PHRASES:
            assert phrase not in text, (
                f"Forbidden phrase {phrase!r} found in "
                f"linear_activity_signal_service.py"
            )

    def test_signal_build_summary_no_forbidden_wording(self) -> None:
        from app.services.linear_activity_signal_service import _build_signal
        for event_type in EXPECTED_MAP:
            ev = _make_activity_event(event_type=event_type)
            result = _build_signal([ev])
            if result is None:
                continue
            text = (
                result.get("title", "") + " " + result.get("summary", "")
            ).lower()
            for phrase in _FORBIDDEN_PHRASES:
                assert phrase not in text, (
                    f"Forbidden phrase {phrase!r} in signal for {event_type!r}"
                )


# ── K. Secret-shape grep ──────────────────────────────────────────────────────

_SECRET_PATTERNS = [
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}"),
    re.compile(r"SG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    re.compile(r"AC[0-9a-fA-F]{32}"),
    re.compile(r"SK[0-9a-fA-F]{32}"),
]


class TestSecretShape:
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
                    hits.append(
                        f"{path.relative_to(root)}:{m.start()}:{m.group()[:20]}"
                    )
        return hits

    def test_no_secret_shapes_in_backend_app(self) -> None:
        root = BACKEND_APP
        hits = self._scan(root, (".py",))
        assert not hits, "Secret-shaped strings in backend/app:\n" + "\n".join(hits)

    def test_no_secret_shapes_in_frontend_src(self) -> None:
        root = FRONTEND_SRC
        hits = self._scan(root, (".ts", ".tsx"))
        assert not hits, "Secret-shaped strings in frontend/src:\n" + "\n".join(hits)
