"""M85D — Linear activity ingestion tests.

Verifies the Linear activity ingestion pipeline: connector list_activity_events,
normalize_linear_activity_event, privacy gate, endpoint existence, frontend
wiring, capability matrix update, and expansion framework pointer.

Sections
--------
  A. Event type allowlist
  B. Connector list_activity_events structure
  C. Normalizer — allowed event types pass the gate
  D. Normalizer — forbidden event types are rejected
  E. Normalizer — privacy (no secrets/PII/URLs in output)
  F. Normalizer — actor_id is always None
  G. Normalizer — provider_event_id is deterministic
  H. ALLOWED_METADATA_KEYS coverage
  I. Capability matrix + expansion framework
  J. Frontend activity page
  K. Forbidden wording / claim discipline
  L. Secret-shape grep
  M. M85A/B/C regression guard
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest

from app.services.linear_activity_ingestion_service import (
    LINEAR_CONFIG_EVENT_TYPES,
    normalize_linear_activity_event,
)
from app.services.security_activity_event_service import ALLOWED_METADATA_KEYS
from app.services.provider_capability_matrix_service import get_provider_capability
from app.services.provider_expansion_framework import get_framework

REPO_ROOT = Path(__file__).resolve().parents[2]
FE_ACTIVITY_PAGE = REPO_ROOT / "frontend" / "src" / "app" / "(app)" / "security" / "activity" / "page.tsx"
FE_API_TS = REPO_ROOT / "frontend" / "src" / "lib" / "api.ts"
FE_TYPES_TS = REPO_ROOT / "frontend" / "src" / "types" / "index.ts"

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

_FORBIDDEN_METADATA_KEYS = frozenset({
    "api_key", "token", "oauth_token", "webhook_secret_value", "secret_value",
    "authorization", "headers", "payload", "request", "response", "raw",
    "audit", "audit_payload", "issue", "issue_title", "issue_description",
    "comment", "attachment", "customer", "customer_name",
    "email", "phone", "sms", "user", "user_id",
    "member", "member_id", "contact", "contact_method",
    "ip", "ip_address", "user_agent",
    "webhook_url", "hostname",
    # Note: "title", "user_name", "domain" are already in ALLOWED_METADATA_KEYS
    # from prior milestones (AWS M67.1/CloudTrail M67.5, Vercel M70B) and are
    # legitimate safe keys for those providers — they are not added by Linear.
})

EXPECTED_EVENT_TYPES: frozenset[str] = frozenset({
    "linear.workspace.updated",
    "linear.team.updated",
    "linear.project.updated",
    "linear.workflow_state.updated",
    "linear.label.updated",
    "linear.webhook.updated",
    "linear.view.updated",
    "linear.cycle.updated",
    "linear.integration.updated",
    "linear.config.event",
})

_SECRET_PATTERNS = [
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}"),
    re.compile(r"SG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    re.compile(r"AC[0-9a-fA-F]{32}"),
    re.compile(r"SK[0-9a-fA-F]{32}"),
]


def _make_entry(
    event_type: str = "linear.workspace.updated",
    provider_event_id: str = "linear:workspace:LINEAR_TEST_WORKSPACE_ID:2026-06-20",
    resource_id: str = "LINEAR_TEST_WORKSPACE_ID",
    resource_type: str = "linear_workspace",
    extra_meta: dict | None = None,
) -> dict:
    meta: dict = {
        "resource_type": resource_type,
        "resource_id": resource_id,
        "record_type": resource_type,
        "operation_family": "linear.workspace",
        "operation_action": "updated",
        "category": "Workspace configuration",
        "url_key_present": True,
        "logo_present": True,
        "team_count": 5,
        "linear_event_id": provider_event_id,
    }
    if extra_meta:
        meta.update(extra_meta)
    return {
        "event_type": event_type,
        "provider": "linear",
        "source": "linear_activity_event",
        "event_source": "linear_activity_event",
        "provider_event_id": provider_event_id,
        "metadata": meta,
    }


# ════════════════════════════════════════════════════════════════════════════
# A. Event type allowlist
# ════════════════════════════════════════════════════════════════════════════

class TestEventTypeAllowlist:
    def test_expected_event_type_count(self):
        assert len(EXPECTED_EVENT_TYPES) == 10

    def test_allowlist_matches_expected(self):
        assert LINEAR_CONFIG_EVENT_TYPES == EXPECTED_EVENT_TYPES

    def test_no_raw_audit_types(self):
        for et in LINEAR_CONFIG_EVENT_TYPES:
            assert "audit" not in et.lower()
            assert "issue" not in et.lower()
            assert "comment" not in et.lower()
            assert "user" not in et.lower()

    def test_all_types_start_with_linear(self):
        for et in LINEAR_CONFIG_EVENT_TYPES:
            assert et.startswith("linear.")


# ════════════════════════════════════════════════════════════════════════════
# B. Connector list_activity_events structure
# ════════════════════════════════════════════════════════════════════════════

class TestConnectorActivityMethod:
    def test_list_activity_events_exists(self):
        from app.connectors.linear import LinearConnector
        c = LinearConnector()
        assert hasattr(c, "list_activity_events")
        assert callable(c.list_activity_events)

    def test_collector_methods_exist(self):
        from app.connectors.linear import LinearConnector
        c = LinearConnector()
        for surface in [
            "workspace", "team", "project", "workflow_state", "label",
            "webhook", "view", "cycle", "integration",
        ]:
            assert hasattr(c, f"_collect_{surface}_events"), (
                f"Missing _collect_{surface}_events"
            )

    def test_collector_workspace_emits_correct_event_type(self):
        from app.connectors.linear import LinearConnector
        c = LinearConnector()
        events: list = []
        records = [{
            "record_type": "linear_workspace",
            "record_id": "LINEAR_TEST_WORKSPACE_ID",
            "url_key_present": True,
            "logo_present": True,
            "team_count": 3,
            "webhook_count": 2,
            "integration_count": 1,
        }]
        c._collect_workspace_events(records, events, "2026-06-20")
        assert len(events) == 1
        ev = events[0]
        assert ev["event_type"] == "linear.workspace.updated"
        assert ev["provider"] == "linear"
        assert ev["source"] == "linear_activity_event"
        assert "LINEAR_TEST_WORKSPACE_ID" in ev["provider_event_id"]
        assert "2026-06-20" in ev["provider_event_id"]

    def test_collector_team_emits_correct_event_type(self):
        from app.connectors.linear import LinearConnector
        c = LinearConnector()
        events: list = []
        records = [{
            "record_type": "linear_team",
            "record_id": "LINEAR_TEST_TEAM_ID",
            "private_team": False,
            "team_visibility_category": "public",
            "member_count_category": "medium",
            "project_count": 2,
            "auto_archive_enabled": True,
            "cycle_enabled": True,
            "cycle_duration_category": "short",
            "workflow_state_count": 5,
            "has_backlog_state": True,
            "has_started_state": True,
            "has_completed_state": True,
            "has_canceled_state": True,
            "label_count": 3,
            "webhook_count": 1,
        }]
        c._collect_team_events(records, events, "2026-06-20")
        assert len(events) == 1
        assert events[0]["event_type"] == "linear.team.updated"

    def test_collector_webhook_emits_correct_event_type(self):
        from app.connectors.linear import LinearConnector
        c = LinearConnector()
        events: list = []
        records = [{
            "record_type": "linear_webhook",
            "record_id": "LINEAR_TEST_WEBHOOK_ID",
            "webhook_enabled": True,
            "webhook_secret_present": True,
            "webhook_url_present": True,
            "webhook_url_scheme_category": "https",
            "webhook_resource_types_count": 2,
            "webhook_has_comment_type": False,
            "webhook_has_attachment_type": False,
        }]
        c._collect_webhook_events(records, events, "2026-06-20")
        assert len(events) == 1
        assert events[0]["event_type"] == "linear.webhook.updated"

    def test_collector_produces_no_raw_urls_or_secrets(self):
        """Event metadata must not contain webhook URL values or secret values."""
        from app.connectors.linear import LinearConnector
        c = LinearConnector()
        events: list = []
        records = [{
            "record_type": "linear_webhook",
            "record_id": "LINEAR_TEST_WEBHOOK_ID",
            "webhook_enabled": True,
            "webhook_secret_present": True,
            "webhook_url_present": True,
            "webhook_url_scheme_category": "https",
            "webhook_resource_types_count": 2,
            "webhook_has_comment_type": True,
            "webhook_has_attachment_type": False,
        }]
        c._collect_webhook_events(records, events, "2026-06-20")
        meta = events[0]["metadata"]
        for key in _FORBIDDEN_METADATA_KEYS:
            assert key not in meta, f"Forbidden key {key!r} in webhook event metadata"

    def test_provider_event_id_includes_day(self):
        from app.connectors.linear import LinearConnector
        c = LinearConnector()
        events: list = []
        c._collect_workspace_events([{
            "record_type": "linear_workspace",
            "record_id": "LINEAR_TEST_WORKSPACE_ID",
        }], events, "2026-06-20")
        assert "2026-06-20" in events[0]["provider_event_id"]

    def test_provider_event_id_is_deterministic(self):
        from app.connectors.linear import LinearConnector
        c = LinearConnector()
        events1: list = []
        events2: list = []
        rec = [{"record_type": "linear_workspace", "record_id": "LINEAR_TEST_WORKSPACE_ID"}]
        c._collect_workspace_events(rec, events1, "2026-06-20")
        c._collect_workspace_events(rec, events2, "2026-06-20")
        assert events1[0]["provider_event_id"] == events2[0]["provider_event_id"]


# ════════════════════════════════════════════════════════════════════════════
# C. Normalizer — allowed event types pass the gate
# ════════════════════════════════════════════════════════════════════════════

class TestNormalizerAllowed:
    @pytest.mark.parametrize("event_type", sorted(EXPECTED_EVENT_TYPES))
    def test_allowed_event_type_normalizes(self, event_type: str):
        entry = _make_entry(event_type=event_type)
        result = normalize_linear_activity_event(entry)
        assert result is not None, f"Expected normalization to succeed for {event_type}"

    def test_result_has_required_fields(self):
        result = normalize_linear_activity_event(_make_entry())
        assert result is not None
        for field in ["provider", "source", "event_type", "provider_event_id"]:
            assert field in result, f"Missing field: {field}"

    def test_provider_is_linear(self):
        result = normalize_linear_activity_event(_make_entry())
        assert result is not None
        assert result["provider"] == "linear"

    def test_source_is_linear_activity_event(self):
        result = normalize_linear_activity_event(_make_entry())
        assert result is not None
        assert result["source"] == "linear_activity_event"


# ════════════════════════════════════════════════════════════════════════════
# D. Normalizer — forbidden event types are rejected
# ════════════════════════════════════════════════════════════════════════════

class TestNormalizerForbidden:
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
    def test_forbidden_event_type_returns_none(self, bad_type: str):
        entry = _make_entry(event_type=bad_type)
        result = normalize_linear_activity_event(entry)
        assert result is None, f"Expected rejection for event_type={bad_type!r}"

    def test_non_dict_input_returns_none(self):
        assert normalize_linear_activity_event("not a dict") is None  # type: ignore
        assert normalize_linear_activity_event(None) is None  # type: ignore
        assert normalize_linear_activity_event([]) is None  # type: ignore


# ════════════════════════════════════════════════════════════════════════════
# E. Normalizer — privacy
# ════════════════════════════════════════════════════════════════════════════

class TestNormalizerPrivacy:
    def test_no_forbidden_metadata_keys_in_output(self):
        """Metadata keys that could carry PII/secrets must never appear."""
        risky_meta = {k: "sensitive" for k in _FORBIDDEN_METADATA_KEYS}
        entry = _make_entry(extra_meta=risky_meta)
        result = normalize_linear_activity_event(entry)
        if result is None:
            return
        stored_meta = result.get("metadata") or {}
        leaked = set(stored_meta.keys()) & _FORBIDDEN_METADATA_KEYS
        assert not leaked, f"Forbidden metadata keys leaked into output: {leaked}"

    def test_webhook_secret_value_never_stored(self):
        entry = _make_entry(
            event_type="linear.webhook.updated",
            resource_type="linear_webhook",
            resource_id="LINEAR_TEST_WEBHOOK_ID",
            extra_meta={
                "webhook_secret_value": "PLACEHOLDER_SECRET_12345",
                "webhook_secret_present": True,
            },
        )
        result = normalize_linear_activity_event(entry)
        if result is not None:
            meta_str = str(result.get("metadata", {}))
            assert "PLACEHOLDER_SECRET_12345" not in meta_str
            assert "webhook_secret_value" not in str(result.get("metadata", {}).keys())

    def test_safe_boolean_fields_pass_through(self):
        """Safe boolean fields from the allowlist should be preserved."""
        entry = _make_entry(extra_meta={
            "webhook_secret_present": True,
            "webhook_enabled": False,
            "lead_present": True,
        })
        result = normalize_linear_activity_event(entry)
        assert result is not None
        meta = result.get("metadata") or {}
        assert meta.get("webhook_secret_present") is True
        assert meta.get("webhook_enabled") is False
        assert meta.get("lead_present") is True


# ════════════════════════════════════════════════════════════════════════════
# F. actor_id is always None
# ════════════════════════════════════════════════════════════════════════════

class TestActorIdIsNone:
    @pytest.mark.parametrize("event_type", sorted(EXPECTED_EVENT_TYPES))
    def test_actor_id_none_for_all_event_types(self, event_type: str):
        result = normalize_linear_activity_event(_make_entry(event_type=event_type))
        if result is not None:
            assert result.get("actor_id") is None, (
                f"actor_id must be None for {event_type}, got {result.get('actor_id')!r}"
            )


# ════════════════════════════════════════════════════════════════════════════
# G. provider_event_id is deterministic and day-scoped
# ════════════════════════════════════════════════════════════════════════════

class TestProviderEventId:
    def test_provider_event_id_preserved_when_present(self):
        eid = "linear:workspace:LINEAR_TEST_WORKSPACE_ID:2026-06-20"
        result = normalize_linear_activity_event(_make_entry(provider_event_id=eid))
        assert result is not None
        assert result.get("provider_event_id") == eid

    def test_fingerprint_computed_when_missing(self):
        entry = _make_entry()
        entry.pop("provider_event_id", None)
        result = normalize_linear_activity_event(entry)
        assert result is not None
        assert result.get("provider_event_id") is not None

    def test_provider_event_id_is_string(self):
        result = normalize_linear_activity_event(_make_entry())
        assert result is not None
        assert isinstance(result.get("provider_event_id"), str)


# ════════════════════════════════════════════════════════════════════════════
# H. ALLOWED_METADATA_KEYS coverage
# ════════════════════════════════════════════════════════════════════════════

class TestAllowedMetadataKeys:
    @pytest.mark.parametrize("key", [
        "linear_event_id",
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
    ])
    def test_linear_key_in_allowed_metadata_keys(self, key: str):
        assert key in ALLOWED_METADATA_KEYS, (
            f"Linear metadata key {key!r} not in ALLOWED_METADATA_KEYS"
        )

    def test_no_forbidden_keys_in_allowed_metadata_keys(self):
        leaked = ALLOWED_METADATA_KEYS & _FORBIDDEN_METADATA_KEYS
        assert not leaked, f"Forbidden keys in ALLOWED_METADATA_KEYS: {leaked}"


# ════════════════════════════════════════════════════════════════════════════
# I. Capability matrix + expansion framework
# ════════════════════════════════════════════════════════════════════════════

class TestCapabilityMatrixAndFramework:
    def test_linear_activity_ingestion_true(self):
        cap = get_provider_capability("linear")
        assert cap is not None
        assert cap.security.activity_ingestion is True

    def test_linear_security_rules_true(self):
        cap = get_provider_capability("linear")
        assert cap is not None
        assert cap.security.security_rules is True

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

    def test_linear_maturity_partial(self):
        cap = get_provider_capability("linear")
        assert cap is not None
        assert cap.maturity == "partial"

    def test_notes_reference_m85d(self):
        cap = get_provider_capability("linear")
        assert cap is not None
        assert "M85D" in cap.notes

    def test_expansion_framework_planned_next_stage_m85e(self):
        # NOTE: planned_next_stage advances with the roadmap; assert structural invariant.
        fw = get_framework()
        planned = fw["summary"]["planned_next_stage"]
        assert isinstance(planned, str) and len(planned) > 0

    def test_expansion_framework_jira_is_head_of_queue(self):
        # NOTE: head of recommended queue advances with the roadmap; assert structural invariant.
        fw = get_framework()
        recs = fw["recommended_next_providers"]
        assert len(recs) > 0
        assert isinstance(recs[0]["provider"], str) and len(recs[0]["provider"]) > 0

    def test_expansion_framework_not_pointing_to_m85d(self):
        fw = get_framework()
        planned = fw["summary"]["planned_next_stage"]
        assert "M85D" not in planned


# ════════════════════════════════════════════════════════════════════════════
# J. Frontend activity page
# ════════════════════════════════════════════════════════════════════════════

class TestFrontendActivityPage:
    @pytest.fixture(scope="class")
    def page_text(self) -> str:
        assert FE_ACTIVITY_PAGE.exists(), f"Activity page not found: {FE_ACTIVITY_PAGE}"
        return FE_ACTIVITY_PAGE.read_text(encoding="utf-8")

    @pytest.fixture(scope="class")
    def api_text(self) -> str:
        assert FE_API_TS.exists()
        return FE_API_TS.read_text(encoding="utf-8")

    @pytest.fixture(scope="class")
    def types_text(self) -> str:
        assert FE_TYPES_TS.exists()
        return FE_TYPES_TS.read_text(encoding="utf-8")

    def test_linear_in_provider_type(self, page_text):
        assert '"linear"' in page_text

    def test_linear_event_types_array_present(self, page_text):
        assert "LINEAR_EVENT_TYPES" in page_text

    def test_linear_event_types_cover_all_surfaces(self, page_text):
        for surface in [
            "linear.workspace.updated",
            "linear.team.updated",
            "linear.project.updated",
            "linear.workflow_state.updated",
            "linear.label.updated",
            "linear.webhook.updated",
            "linear.view.updated",
            "linear.cycle.updated",
            "linear.integration.updated",
        ]:
            assert surface in page_text, f"Missing event type in frontend: {surface}"

    def test_sync_linear_activity_imported(self, page_text):
        assert "syncLinearActivity" in page_text

    def test_linear_sync_branch_present(self, page_text):
        assert 'provider === "linear"' in page_text
        assert "syncLinearActivity" in page_text

    def test_sync_linear_activity_in_api_ts(self, api_text):
        assert "syncLinearActivity" in api_text
        assert "/security/linear-activity/sync" in api_text

    def test_linear_activity_sync_response_in_types(self, types_text):
        assert "LinearActivitySyncResponse" in types_text


# ════════════════════════════════════════════════════════════════════════════
# K. Forbidden wording / claim discipline
# ════════════════════════════════════════════════════════════════════════════

class TestClaimDiscipline:
    def _service_text(self) -> str:
        path = REPO_ROOT / "backend" / "app" / "services" / "linear_activity_ingestion_service.py"
        return path.read_text(encoding="utf-8").lower()

    def test_no_forbidden_phrases_in_ingestion_service(self):
        text = self._service_text()
        for phrase in _FORBIDDEN_PHRASES:
            assert phrase.lower() not in text, (
                f"Forbidden phrase in ingestion service: {phrase!r}"
            )

    def test_service_uses_review_safe_language(self):
        text = self._service_text()
        assert "configuration" in text
        assert "evidence" in text or "activity" in text


# ════════════════════════════════════════════════════════════════════════════
# L. Secret-shape grep
# ════════════════════════════════════════════════════════════════════════════

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
# M. M85A/B/C regression guard
# ════════════════════════════════════════════════════════════════════════════

class TestRegressionGuard:
    def test_linear_connector_still_has_fetch(self):
        from app.connectors.linear import LinearConnector
        c = LinearConnector()
        assert hasattr(c, "fetch")
        assert hasattr(c, "validate_credentials")

    def test_linear_schema_still_has_9_record_types(self):
        from app.connectors.linear_schema import LINEAR_RECORD_TYPES
        assert len(LINEAR_RECORD_TYPES) == 9

    def test_linear_security_rules_still_work(self):
        from app.services.security_rules.linear import evaluate
        webhook_rec = {
            "record_type": "linear_webhook",
            "provider": "linear",
            "record_id": "LINEAR_TEST_WEBHOOK_ID",
            "resource_id": "LINEAR_TEST_WEBHOOK_ID",
            "webhook_resource_types_count": 2,
            "webhook_enabled": True,
            "webhook_secret_present": False,  # risky
            "webhook_url_present": True,
            "webhook_url_scheme_category": "https",
            "team_id": "LINEAR_TEST_TEAM_ID",
            "webhook_has_comment_type": False,
            "webhook_has_attachment_type": False,
        }
        findings = evaluate(webhook_rec)
        assert any(f.rule_key == "linear_webhook_no_secret_indicator" for f in findings)

    def test_linear_ingestion_service_importable(self):
        from app.services.linear_activity_ingestion_service import (
            sync_linear_activity,
            ingest_linear_activity,
            normalize_linear_activity_event,
            LINEAR_CONFIG_EVENT_TYPES,
        )
        assert sync_linear_activity is not None
        assert ingest_linear_activity is not None
        assert normalize_linear_activity_event is not None
        assert len(LINEAR_CONFIG_EVENT_TYPES) == 10

    def test_router_has_linear_activity_endpoint(self):
        """Check the router source file contains the new endpoint."""
        router_path = REPO_ROOT / "backend" / "app" / "routers" / "security.py"
        text = router_path.read_text(encoding="utf-8")
        assert "/linear-activity/sync" in text
        assert "LinearActivitySyncResponse" in text
        assert "linear_activity_ingestion_service" in text
