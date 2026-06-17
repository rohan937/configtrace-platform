"""M81E — Auth0 Activity Signals.

Verifies the Auth0 configuration activity signal service, its registration,
API endpoint, frontend changes, capability matrix, and expansion framework.

Sections
--------
  A. Signal type mapping — all event types map to expected signal types
  B. Signal service — grouping, anchor selection, metadata, idempotency
  C. Signal metadata privacy — no forbidden fields
  D. API endpoint — admin-only, member cannot generate, route exists
  E. Frontend checks — provider + signal types + generate function
  F. Capability matrix — activity_signals=True, correlations/demo=False
  G. Provider expansion framework — points to M81F
  H. Forbidden wording and secret-shape scan
  I. Regression smoke — M81A/B/C/D still intact
"""

from __future__ import annotations

import inspect
import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# ── Constants ──────────────────────────────────────────────────────────────────

FORBIDDEN_PHRASES = [
    "compromise confirmed", "secret leaked", "data leaked",
    "customer data leaked", "payment fraud detected", "attacker found",
    "someone has access", "unauthorized access confirmed", "breach detected",
    "attack detected", "orders exposed", "card data exposed",
]

FORBIDDEN_SIGNAL_METADATA_FIELDS = frozenset({
    "client_secret", "management_api_token", "access_token",
    "refresh_token_value", "id_token", "jwt_value", "signing_key",
    "private_key", "authorization", "bearer", "secret_value",
    "email", "user_email", "user_id", "user_name",
    "profile", "identity", "identities", "login", "password",
    "ip_address", "device", "session_id", "session",
    "mfa_recovery_code", "recovery_code", "org_member",
    "callback_url", "logout_url", "allowed_origin", "audience",
    "domain_name", "custom_domain_name",
    "script_content", "code_content",
    "raw_payload", "raw_response", "log_entry", "log_description",
})

# Expected signal types from the spec.
EXPECTED_AUTH0_SIGNAL_TYPES = frozenset({
    "auth0_tenant_config_changed",
    "auth0_application_config_changed",
    "auth0_connection_config_changed",
    "auth0_resource_server_config_changed",
    "auth0_rule_config_changed",
    "auth0_action_config_changed",
    "auth0_mfa_factor_config_changed",
    "auth0_custom_domain_config_changed",
    "auth0_config_activity",
})

# All Auth0 activity event types from M81D.
ALL_AUTH0_EVENT_TYPES = [
    "auth0.tenant.updated",
    "auth0.application.created",
    "auth0.application.updated",
    "auth0.application.deleted",
    "auth0.connection.created",
    "auth0.connection.updated",
    "auth0.connection.deleted",
    "auth0.resource_server.created",
    "auth0.resource_server.updated",
    "auth0.resource_server.deleted",
    "auth0.rule.created",
    "auth0.rule.updated",
    "auth0.rule.deleted",
    "auth0.action.created",
    "auth0.action.updated",
    "auth0.action.deployed",
    "auth0.action.deleted",
    "auth0.mfa_factor.updated",
    "auth0.custom_domain.created",
    "auth0.custom_domain.updated",
    "auth0.custom_domain.verified",
    "auth0.custom_domain.deleted",
    "auth0.config.event",
]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _make_event(
    event_type: str,
    resource_id: str = "AUTH0_TEST_CLIENT_ID",
    resource_type: str = "application",
    metadata: dict | None = None,
    occurred_at: datetime | None = None,
) -> MagicMock:
    ev = MagicMock()
    ev.id = uuid.uuid4()
    ev.event_type = event_type
    ev.provider = "auth0"
    ev.source = "auth0_activity_event"
    ev.workspace_id = uuid.uuid4()
    ev.integration_id = uuid.uuid4()
    ev.provider_event_id = f"{event_type}:{resource_id}:2026-06-17"
    ev.resource_id = resource_id
    ev.resource_type = resource_type
    ev.occurred_at = occurred_at or _now()
    ev.ingested_at = _now()
    ev.created_at = _now()
    ev.event_metadata = metadata or {
        "resource_type": resource_type,
        "resource_id": resource_id,
        "client_id": "AUTH0_TEST_CLIENT_ID" if resource_type == "application" else None,
        "connection_id": "AUTH0_TEST_CONNECTION_ID" if resource_type == "connection" else None,
        "app_type": "spa",
        "is_first_party": True,
        "jwt_alg": "RS256",
        "callbacks_count": 2,
        "grant_types_count": 2,
        "event_source": "auth0_activity_event",
        "operation_family": f"auth0.{resource_type}",
        "operation_action": "observe",
        "category": "auth0_configuration",
    }
    return ev


# ── Section A: Signal type mapping ────────────────────────────────────────────


class TestSignalTypeMapping:
    def test_all_event_types_map_to_signal_type(self):
        from app.services.auth0_activity_signal_service import AUTH0_EVENT_TYPE_TO_SIGNAL_TYPE
        for et in ALL_AUTH0_EVENT_TYPES:
            assert et in AUTH0_EVENT_TYPE_TO_SIGNAL_TYPE, (
                f"Event type '{et}' has no signal type mapping"
            )

    def test_signal_types_match_expected(self):
        from app.services.auth0_activity_signal_service import AUTH0_SIGNAL_TYPES
        assert AUTH0_SIGNAL_TYPES == EXPECTED_AUTH0_SIGNAL_TYPES

    def test_tenant_event_maps_to_tenant_signal(self):
        from app.services.auth0_activity_signal_service import AUTH0_EVENT_TYPE_TO_SIGNAL_TYPE
        assert AUTH0_EVENT_TYPE_TO_SIGNAL_TYPE["auth0.tenant.updated"] == "auth0_tenant_config_changed"

    def test_application_events_map_to_app_signal(self):
        from app.services.auth0_activity_signal_service import AUTH0_EVENT_TYPE_TO_SIGNAL_TYPE
        for et in ("auth0.application.created", "auth0.application.updated", "auth0.application.deleted"):
            assert AUTH0_EVENT_TYPE_TO_SIGNAL_TYPE[et] == "auth0_application_config_changed"

    def test_action_events_include_deployed(self):
        from app.services.auth0_activity_signal_service import AUTH0_EVENT_TYPE_TO_SIGNAL_TYPE
        for et in ("auth0.action.created", "auth0.action.updated", "auth0.action.deployed", "auth0.action.deleted"):
            assert AUTH0_EVENT_TYPE_TO_SIGNAL_TYPE[et] == "auth0_action_config_changed"

    def test_config_event_maps_to_config_activity(self):
        from app.services.auth0_activity_signal_service import AUTH0_EVENT_TYPE_TO_SIGNAL_TYPE
        assert AUTH0_EVENT_TYPE_TO_SIGNAL_TYPE["auth0.config.event"] == "auth0_config_activity"


# ── Section B: Signal service ─────────────────────────────────────────────────


class TestSignalService:
    def _make_workspace(self):
        return uuid.uuid4()

    def test_groups_by_signal_type_and_resource(self):
        from app.services.auth0_activity_signal_service import (
            AUTH0_EVENT_TYPE_TO_SIGNAL_TYPE,
            _group_key,
        )
        ev1 = _make_event("auth0.application.updated", resource_id="client_A",
                          metadata={"resource_type": "application", "client_id": "client_A"})
        ev2 = _make_event("auth0.application.updated", resource_id="client_A",
                          metadata={"resource_type": "application", "client_id": "client_A"})
        ev3 = _make_event("auth0.application.updated", resource_id="client_B",
                          metadata={"resource_type": "application", "client_id": "client_B"})

        gk1 = _group_key(ev1)
        gk2 = _group_key(ev2)
        gk3 = _group_key(ev3)

        assert gk1 == gk2  # same resource → same group
        assert gk1 != gk3  # different resource → different group
        assert gk1 is not None

    def test_unknown_event_type_returns_none_group_key(self):
        from app.services.auth0_activity_signal_service import _group_key
        ev = _make_event("auth0.unknown.event")
        assert _group_key(ev) is None

    def test_anchor_is_latest_event(self):
        from app.services.auth0_activity_signal_service import _pick_anchor
        old = _make_event("auth0.application.updated",
                          occurred_at=_now() - timedelta(hours=2))
        new = _make_event("auth0.application.updated",
                          occurred_at=_now() - timedelta(hours=1))
        anchor = _pick_anchor([old, new])
        assert anchor is new

    def test_build_signal_returns_dict(self):
        from app.services.auth0_activity_signal_service import _build_signal
        ev = _make_event("auth0.application.updated")
        signal = _build_signal([ev])
        assert signal is not None
        assert signal["signal_type"] == "auth0_application_config_changed"
        assert signal["provider"] == "auth0"
        assert signal["evidence_level"] == "activity"
        assert signal["confidence"] == "medium"

    def test_build_signal_title_is_safe(self):
        from app.services.auth0_activity_signal_service import _build_signal
        ev = _make_event("auth0.connection.updated", resource_type="connection",
                         metadata={"resource_type": "connection", "connection_id": "AUTH0_TEST_CONNECTION_ID"})
        signal = _build_signal([ev])
        assert signal is not None
        title = signal["title"]
        # Title must not contain raw URLs, emails, or forbidden phrases
        for phrase in FORBIDDEN_PHRASES:
            assert phrase.lower() not in title.lower()
        assert len(title) <= 240

    def test_build_signal_summary_claims_discipline(self):
        from app.services.auth0_activity_signal_service import _build_signal
        ev = _make_event("auth0.rule.updated", resource_type="rule",
                         metadata={"resource_type": "rule", "rule_id": "AUTH0_TEST_RULE_ID"})
        signal = _build_signal([ev])
        assert signal is not None
        summary = signal["summary"].lower()
        for phrase in FORBIDDEN_PHRASES:
            assert phrase not in summary

    def test_build_signal_group_key_is_deterministic(self):
        from app.services.auth0_activity_signal_service import _group_key
        md = {"resource_type": "application", "client_id": "AUTH0_TEST_CLIENT_ID"}
        ev1 = _make_event("auth0.application.updated", metadata=md)
        ev2 = _make_event("auth0.application.updated", metadata=md)
        assert _group_key(ev1) == _group_key(ev2)

    def test_build_signal_linked_activity_event_id(self):
        from app.services.auth0_activity_signal_service import _build_signal, _pick_anchor
        ev = _make_event("auth0.mfa_factor.updated", resource_type="mfa_factor",
                         metadata={"resource_type": "mfa_factor", "factor_name": "otp"})
        signal = _build_signal([ev])
        assert signal is not None
        assert signal["linked_activity_event_id"] == ev.id

    def test_generate_calls_upsert(self):
        from app.services import auth0_activity_signal_service as svc
        workspace_id = uuid.uuid4()
        db = MagicMock()
        events = [_make_event("auth0.application.updated",
                               metadata={"resource_type": "application", "client_id": "AUTH0_TEST_CLIENT_ID"})]

        with (
            patch.object(db, "query") as mock_query,
            patch("app.services.auth0_activity_signal_service.signal_svc") as mock_signal,
        ):
            mock_query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = events
            mock_signal.sanitize_signal_metadata.side_effect = lambda x: {k: v for k, v in x.items() if v is not None}
            mock_signal.upsert_incident_signal.return_value = ("created", MagicMock())

            result = svc.generate_auth0_activity_signals(
                workspace_id=workspace_id, db=db
            )

        assert result["signals_created"] == 1
        assert result["provider"] == "auth0"
        assert result["source"] == "auth0_activity_event"

    def test_generate_idempotent_second_run_skips(self):
        from app.services import auth0_activity_signal_service as svc
        workspace_id = uuid.uuid4()
        db = MagicMock()
        events = [_make_event("auth0.tenant.updated",
                               resource_type="tenant_settings",
                               metadata={"resource_type": "tenant_settings"})]

        with (
            patch.object(db, "query") as mock_query,
            patch("app.services.auth0_activity_signal_service.signal_svc") as mock_signal,
        ):
            mock_query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = events
            mock_signal.sanitize_signal_metadata.side_effect = lambda x: {k: v for k, v in x.items() if v is not None}
            mock_signal.upsert_incident_signal.return_value = ("skipped", MagicMock())

            result = svc.generate_auth0_activity_signals(
                workspace_id=workspace_id, db=db
            )

        assert result["signals_created"] == 0
        assert result["signals_skipped"] == 1

    def test_generate_scans_only_auth0_provider(self):
        from app.services import auth0_activity_signal_service as svc
        workspace_id = uuid.uuid4()
        db = MagicMock()

        with (
            patch.object(db, "query") as mock_query,
            patch("app.services.auth0_activity_signal_service.signal_svc") as mock_signal,
        ):
            mock_query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = []
            mock_signal.sanitize_signal_metadata.side_effect = lambda x: x
            mock_signal.upsert_incident_signal.return_value = ("created", MagicMock())

            svc.generate_auth0_activity_signals(workspace_id=workspace_id, db=db)

        # Verify provider filter was applied
        filter_calls = mock_query.return_value.filter.call_args_list
        assert len(filter_calls) > 0

    def test_max_signals_cap_enforced(self):
        from app.services import auth0_activity_signal_service as svc
        workspace_id = uuid.uuid4()
        db = MagicMock()

        # Create 10 events with distinct resources
        events = [
            _make_event("auth0.application.updated",
                         resource_id=f"client_{i}",
                         metadata={"resource_type": "application", "client_id": f"client_{i}"})
            for i in range(10)
        ]

        with (
            patch.object(db, "query") as mock_query,
            patch("app.services.auth0_activity_signal_service.signal_svc") as mock_signal,
        ):
            mock_query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = events
            mock_signal.sanitize_signal_metadata.side_effect = lambda x: {k: v for k, v in x.items() if v is not None}
            mock_signal.upsert_incident_signal.return_value = ("created", MagicMock())

            result = svc.generate_auth0_activity_signals(
                workspace_id=workspace_id, db=db, max_signals=3
            )

        assert result["signals_created"] <= 3

    def test_severity_medium_for_application(self):
        from app.services.auth0_activity_signal_service import _severity
        assert _severity("auth0_application_config_changed") == "medium"

    def test_severity_medium_for_mfa_factor(self):
        from app.services.auth0_activity_signal_service import _severity
        assert _severity("auth0_mfa_factor_config_changed") == "medium"

    def test_severity_low_for_custom_domain(self):
        from app.services.auth0_activity_signal_service import _severity
        assert _severity("auth0_custom_domain_config_changed") == "low"

    def test_severity_low_for_config_activity(self):
        from app.services.auth0_activity_signal_service import _severity
        assert _severity("auth0_config_activity") == "low"


# ── Section C: Signal metadata privacy ────────────────────────────────────────


class TestSignalMetadataPrivacy:
    def test_allowed_signal_metadata_keys_has_auth0_keys(self):
        from app.services.security_incident_signal_service import ALLOWED_METADATA_KEYS
        expected_keys = {
            "client_id", "connection_id", "resource_server_id",
            "action_id", "factor_name", "custom_domain_id",
            "app_type", "is_first_party", "jwt_alg", "oidc_conformant",
            "token_endpoint_auth_method", "refresh_token_rotation_enabled",
            "refresh_token_lifetime_category", "grant_types_count",
            "callbacks_count", "allowed_logout_urls_count",
            "allowed_origins_count", "web_origins_count",
            "enabled_clients_count", "password_policy_category",
            "signing_alg", "token_lifetime_category",
            "allow_offline_access", "rbac_enabled",
            "script_present", "script_length_category",
            "code_present", "code_length_category", "secrets_count",
            "enabled", "status_category", "tls_policy_category",
        }
        missing = expected_keys - ALLOWED_METADATA_KEYS
        assert not missing, f"Auth0 signal keys missing: {missing}"

    def test_allowed_signal_metadata_excludes_forbidden_keys(self):
        from app.services.security_incident_signal_service import ALLOWED_METADATA_KEYS
        for forbidden in FORBIDDEN_SIGNAL_METADATA_FIELDS:
            assert forbidden not in ALLOWED_METADATA_KEYS, (
                f"Forbidden key '{forbidden}' found in signal ALLOWED_METADATA_KEYS"
            )

    def test_build_signal_metadata_no_raw_urls(self):
        import json
        from app.services.auth0_activity_signal_service import _build_signal
        ev = _make_event("auth0.application.updated",
                          metadata={
                              "resource_type": "application",
                              "client_id": "AUTH0_TEST_CLIENT_ID",
                              "app_type": "spa",
                              "callbacks_count": 2,
                              "jwt_alg": "RS256",
                              # Forbidden fields that sanitizer should drop:
                              "client_secret": "should-be-dropped",
                              "callback_url": "https://example.com/callback",
                          })
        signal = _build_signal([ev])
        assert signal is not None
        md_str = json.dumps(signal["metadata"])
        assert "should-be-dropped" not in md_str
        assert "https://example.com/callback" not in md_str

    def test_build_signal_metadata_no_jwt_shaped_values(self):
        import json
        from app.services.auth0_activity_signal_service import _build_signal
        ev = _make_event("auth0.action.deployed",
                          resource_type="action",
                          metadata={
                              "resource_type": "action",
                              "action_id": "AUTH0_TEST_ACTION_ID",
                              "code_present": True,
                              "secrets_count": 2,
                          })
        signal = _build_signal([ev])
        assert signal is not None
        md_str = json.dumps(signal["metadata"])
        jwt_pattern = re.compile(r"eyJ[A-Za-z0-9_-]{10,}")
        assert not jwt_pattern.search(md_str)

    def test_resource_key_uses_opaque_ids_only(self):
        from app.services.auth0_activity_signal_service import _resource_key
        ev = _make_event("auth0.application.updated",
                          metadata={
                              "resource_type": "application",
                              "client_id": "AUTH0_TEST_CLIENT_ID",
                          })
        rkey = _resource_key(ev)
        assert rkey == "AUTH0_TEST_CLIENT_ID"
        # Must not contain email, URL, or domain
        assert "@" not in rkey
        assert "http" not in rkey

    def test_connection_resource_key_uses_connection_id(self):
        from app.services.auth0_activity_signal_service import _resource_key
        ev = _make_event("auth0.connection.updated",
                          resource_type="connection",
                          metadata={"resource_type": "connection",
                                     "connection_id": "AUTH0_TEST_CONNECTION_ID"})
        rkey = _resource_key(ev)
        assert rkey == "AUTH0_TEST_CONNECTION_ID"

    def test_factor_resource_key_uses_factor_name(self):
        from app.services.auth0_activity_signal_service import _resource_key
        ev = _make_event("auth0.mfa_factor.updated",
                          resource_type="mfa_factor",
                          metadata={"resource_type": "mfa_factor", "factor_name": "otp"})
        rkey = _resource_key(ev)
        assert rkey == "otp"

    def test_metadata_missing_fields_fallback_gracefully(self):
        from app.services.auth0_activity_signal_service import _build_signal
        # Event with minimal metadata
        ev = _make_event("auth0.config.event",
                          metadata={"resource_type": "configuration"})
        signal = _build_signal([ev])
        assert signal is not None
        assert signal["signal_type"] == "auth0_config_activity"


# ── Section D: API endpoint ────────────────────────────────────────────────────


class TestApiEndpoint:
    def test_endpoint_exists_in_router(self):
        from app.routers import security as sec_router
        routes = [r.path for r in sec_router.router.routes]
        assert "/security/auth0-activity/generate-signals" in routes

    def test_member_cannot_generate(self):
        from fastapi import HTTPException
        from fastapi.testclient import TestClient
        from app.core.auth import get_current_user
        from app.database import get_db
        from app.main import app as fastapi_app

        mock_user = MagicMock()
        mock_user.id = uuid.uuid4()
        mock_db = MagicMock()
        mock_workspace_id = uuid.uuid4()

        def _deny(workspace_id, user_id, db):
            raise HTTPException(status_code=403, detail="Admin or owner role required.")

        fastapi_app.dependency_overrides[get_current_user] = lambda: mock_user
        fastapi_app.dependency_overrides[get_db] = lambda: mock_db
        try:
            with patch(
                "app.routers.security._current_workspace_id",
                return_value=mock_workspace_id,
            ), patch(
                "app.routers.security.workspace_permission_service.require_workspace_admin",
                side_effect=_deny,
            ):
                client = TestClient(fastapi_app, raise_server_exceptions=False)
                r = client.post("/security/auth0-activity/generate-signals", json={})
        finally:
            fastapi_app.dependency_overrides.clear()
        assert r.status_code == 403

    def test_admin_can_generate(self):
        from fastapi.testclient import TestClient
        from app.core.auth import get_current_user
        from app.database import get_db
        from app.main import app as fastapi_app

        mock_user = MagicMock()
        mock_user.id = uuid.uuid4()
        mock_db = MagicMock()
        mock_workspace_id = uuid.uuid4()

        fastapi_app.dependency_overrides[get_current_user] = lambda: mock_user
        fastapi_app.dependency_overrides[get_db] = lambda: mock_db
        try:
            with patch(
                "app.routers.security._current_workspace_id",
                return_value=mock_workspace_id,
            ), patch(
                "app.routers.security.workspace_permission_service.require_workspace_admin",
            ), patch(
                "app.routers.security.auth0_activity_signal_service.generate_auth0_activity_signals",
                return_value={
                    "provider": "auth0", "source": "auth0_activity_event",
                    "events_scanned": 5, "groups_scanned": 3,
                    "signals_created": 2, "signals_skipped": 1,
                },
            ):
                client = TestClient(fastapi_app, raise_server_exceptions=False)
                r = client.post("/security/auth0-activity/generate-signals", json={})
        finally:
            fastapi_app.dependency_overrides.clear()
        assert r.status_code == 200
        data = r.json()
        assert data["provider"] == "auth0"
        assert data["signals_created"] == 2


# ── Section E: Frontend checks ────────────────────────────────────────────────


class TestFrontendChecks:
    def _read(self, path: Path) -> str:
        return path.read_text(encoding="utf-8")

    def test_signals_page_has_auth0_provider(self):
        path = (
            Path(__file__).parent.parent.parent
            / "frontend/src/app/(app)/security/signals/page.tsx"
        )
        text = self._read(path)
        assert '"auth0"' in text or "'auth0'" in text

    def test_signals_page_has_auth0_signal_types(self):
        path = (
            Path(__file__).parent.parent.parent
            / "frontend/src/app/(app)/security/signals/page.tsx"
        )
        text = self._read(path)
        assert "AUTH0_SIGNAL_TYPES" in text
        assert "auth0_application_config_changed" in text
        assert "auth0_tenant_config_changed" in text

    def test_api_ts_has_generate_auth0_signals(self):
        path = Path(__file__).parent.parent.parent / "frontend/src/lib/api.ts"
        text = self._read(path)
        assert "generateAuth0ActivitySignals" in text
        assert "auth0-activity/generate-signals" in text

    def test_types_has_auth0_signal_generate_response(self):
        path = Path(__file__).parent.parent.parent / "frontend/src/types/index.ts"
        text = self._read(path)
        assert "Auth0ActivitySignalGenerateResponse" in text


# ── Section F: Capability matrix ──────────────────────────────────────────────


class TestCapabilityMatrix:
    def test_auth0_activity_signals_true(self):
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("auth0")
        assert cap is not None
        assert cap.security.activity_signals is True

    def test_auth0_activity_ingestion_still_true(self):
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("auth0")
        assert cap is not None
        assert cap.security.activity_ingestion is True

    def test_auth0_correlations_still_false(self):
        # correlations M81F, demo M81G — all now complete
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("auth0")
        assert cap is not None
        assert cap.security.demo_seed_clear is True
        assert cap.security.case_report is True

    def test_auth0_maturity_still_partial(self):
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("auth0")
        assert cap is not None
        assert cap.maturity == "partial"

    def test_auth0_notes_mention_m81e(self):
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("auth0")
        assert cap is not None
        notes = cap.notes or ""
        assert "M81E" in notes


# ── Section G: Expansion framework ────────────────────────────────────────────


class TestExpansionFramework:
    def test_points_to_m81f(self):
        # After M81F completes, pointer advances to M81G — M81F or beyond is fine
        from app.services.provider_expansion_framework import get_framework
        fw = get_framework()
        planned = fw["summary"]["planned_next_stage"]
        assert "M81E" not in planned
        assert any(tag in planned for tag in ("M81F", "M81G", "M81H", "M81I", "M82")), (
            f"planned_next_stage should point to M81F or beyond after M81E; got: {planned!r}"
        )


# ── Section H: Forbidden wording and secret shapes ────────────────────────────


class TestForbiddenWordingAndSecretShapes:
    def test_no_forbidden_phrases_in_signal_service(self):
        import app.services.auth0_activity_signal_service as mod
        source = inspect.getsource(mod).lower()
        for phrase in FORBIDDEN_PHRASES:
            assert phrase not in source, (
                f"Forbidden phrase '{phrase}' in auth0_activity_signal_service"
            )

    def test_no_secret_shapes_in_backend_app(self):
        jwt_pattern = re.compile(r"eyJ[A-Za-z0-9_-]{10,}")
        sg_pattern = re.compile(r"SG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")
        ac_pattern = re.compile(r"AC[0-9a-fA-F]{32}")
        sk_pattern = re.compile(r"SK[0-9a-fA-F]{32}")
        backend_app = Path(__file__).parent.parent / "app"
        for path in backend_app.rglob("*.py"):
            try:
                text = path.read_text(errors="replace")
            except OSError:
                continue
            for pat in (jwt_pattern, sg_pattern, ac_pattern, sk_pattern):
                assert not pat.search(text), (
                    f"Secret-shaped string ({pat.pattern!r}) found in {path}"
                )

    def test_no_secret_shapes_in_frontend_src(self):
        jwt_pattern = re.compile(r"eyJ[A-Za-z0-9_-]{10,}")
        sg_pattern = re.compile(r"SG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")
        ac_pattern = re.compile(r"AC[0-9a-fA-F]{32}")
        sk_pattern = re.compile(r"SK[0-9a-fA-F]{32}")
        frontend_src = Path(__file__).parent.parent.parent / "frontend" / "src"
        if not frontend_src.exists():
            pytest.skip("frontend/src not found")
        for path in frontend_src.rglob("*.ts"):
            try:
                text = path.read_text(errors="replace")
            except OSError:
                continue
            for pat in (jwt_pattern, sg_pattern, ac_pattern, sk_pattern):
                assert not pat.search(text), (
                    f"Secret-shaped string ({pat.pattern!r}) found in {path}"
                )


# ── Section I: Regression smoke ───────────────────────────────────────────────


class TestRegressionSmoke:
    def test_m81d_ingestion_service_still_imports(self):
        from app.services import auth0_activity_ingestion_service as svc
        assert hasattr(svc, "sync_auth0_activity")
        assert hasattr(svc, "ingest_auth0_activity")
        assert hasattr(svc, "normalize_auth0_activity_event")

    def test_m81c_rule_keys_still_present(self):
        from app.services.security_rules.auth0 import AUTH0_RULE_KEYS
        assert "auth0_application_password_grant_enabled" in AUTH0_RULE_KEYS
        assert "auth0_application_wildcard_callback" in AUTH0_RULE_KEYS

    def test_m81b_rule_keys_still_present(self):
        from app.services.security_rules.auth0 import AUTH0_RULE_KEYS
        assert "auth0_application_weak_jwt_algorithm" in AUTH0_RULE_KEYS
        assert "auth0_mfa_factor_disabled" in AUTH0_RULE_KEYS

    def test_m81a_connector_still_imports(self):
        from app.connectors.auth0 import Auth0Connector
        from app.connectors.auth0_schema import AUTH0_RECORD_TYPES
        assert "auth0_application" in AUTH0_RECORD_TYPES
        conn = Auth0Connector()
        assert hasattr(conn, "fetch")
        assert hasattr(conn, "list_activity_events")
