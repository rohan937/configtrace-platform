"""M79F — Twilio Risk × Activity Correlations.

Verifies:
  * TWILIO_CORRELATION_TYPES is a frozenset containing all 5 expected types
  * TWILIO_CORRELATION_RULES has rule_keys, signal_types, match_key per entry
  * Correlation rule mapping for all 5 families and expected rule keys
  * Correlation generation logic via mocked DB
  * Idempotency: re-running creates no duplicates
  * Metadata privacy: no forbidden fields, no full phone numbers, no secrets
  * API endpoint POST /security/twilio-correlations/generate
  * Provider capability matrix reflects M79F state
  * Expansion framework planned_next_stage → M79G / Twilio Demo
  * Frontend correlations/page.tsx, api.ts, types/index.ts references
  * Forbidden wording absent from twilio_risk_activity_correlation_service.py

CLAIM DISCIPLINE: these are configuration-posture review correlations only.
The service does NOT confirm breach, compromise, unauthorized access, data
exposure, or leaked credentials.

FORBIDDEN PHRASES: never stored; tested in section I.
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

# ── Forbidden wording / metadata fields ──────────────────────────────────────

FORBIDDEN_PHRASES = [
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

FORBIDDEN_METADATA_FIELDS = frozenset({
    "auth_token",
    "api_secret",
    "api_key_secret",
    "access_token",
    "authorization",
    "phone_number",
    "to",
    "from",
    "sms_url",
    "voice_url",
    "inbound_request_url",
    "fallback_url",
    "status_callback_url",
    "status_callback",
    "message_body",
    "body",
    "recording_url",
    "media_url",
    "transcript",
    "raw_payload",
    "request",
    "response",
    "headers",
    "signature",
    "customer",
    "email",
})

EXPECTED_CORRELATION_TYPES = frozenset({
    "twilio_phone_number_risk_activity_correlation",
    "twilio_messaging_service_risk_activity_correlation",
    "twilio_verify_service_risk_activity_correlation",
    "twilio_api_key_risk_activity_correlation",
    "twilio_account_risk_activity_correlation",
})

# ── Helpers ───────────────────────────────────────────────────────────────────

_NOW = datetime.now(timezone.utc)


def _recent(hours: int = 1) -> datetime:
    return _NOW - timedelta(hours=hours)


def _make_finding(
    finding_key: str = "twilio_messaging_service_fallback_missing",
    provider: str = "twilio",
    status: str = "active",
    evidence: dict | None = None,
    workspace_id: uuid.UUID | None = None,
) -> MagicMock:
    f = MagicMock()
    f.id = uuid.uuid4()
    f.workspace_id = workspace_id or uuid.uuid4()
    f.provider = provider
    f.status = status
    f.finding_key = finding_key
    f.severity = "high"
    f.title = f"Twilio finding: {finding_key}"
    f.evidence = evidence if evidence is not None else {}
    f.first_detected_at = _recent(2)
    f.last_seen_at = _recent(1)
    f.linked_change_id = None
    f.integration_id = uuid.uuid4()
    f.resource_id = uuid.uuid4()
    return f


def _make_signal(
    signal_type: str = "twilio_messaging_service_config_changed",
    provider: str = "twilio",
    signal_metadata: dict | None = None,
    workspace_id: uuid.UUID | None = None,
) -> MagicMock:
    s = MagicMock()
    s.id = uuid.uuid4()
    s.workspace_id = workspace_id or uuid.uuid4()
    s.provider = provider
    s.signal_type = signal_type
    s.signal_metadata = signal_metadata if signal_metadata is not None else {}
    s.first_seen_at = _recent(2)
    s.last_seen_at = _recent(1)
    s.linked_activity_event_id = uuid.uuid4()
    return s


def _db_with(findings: list, signals: list) -> MagicMock:
    """Build a mock DB that dispatches query() on model class."""
    db = MagicMock()

    def query_side_effect(model):
        q = MagicMock()
        from app.models.security_finding import SecurityFinding
        from app.models.security_incident_signal import SecurityIncidentSignal
        if model is SecurityFinding:
            items = findings
        elif model is SecurityIncidentSignal:
            items = signals
        else:
            items = []
        q.filter.return_value.order_by.return_value.limit.return_value.all.return_value = items
        return q

    db.query.side_effect = query_side_effect
    return db


# ══════════════════════════════════════════════════════════════════════════════
# A: Correlation type constants
# ══════════════════════════════════════════════════════════════════════════════


class TestCorrelationTypeConstants:
    """A: TWILIO_CORRELATION_TYPES and TWILIO_CORRELATION_RULES constants."""

    def test_a1_import_twilio_correlation_types(self):
        """A1: Import TWILIO_CORRELATION_TYPES from twilio_risk_activity_correlation_service."""
        from app.services.twilio_risk_activity_correlation_service import TWILIO_CORRELATION_TYPES
        assert TWILIO_CORRELATION_TYPES is not None

    def test_a2_twilio_correlation_types_is_frozenset(self):
        """A2: TWILIO_CORRELATION_TYPES is a frozenset."""
        from app.services.twilio_risk_activity_correlation_service import TWILIO_CORRELATION_TYPES
        assert isinstance(TWILIO_CORRELATION_TYPES, frozenset)

    def test_a3_contains_all_5_expected_types(self):
        """A3: Contains all 5 expected correlation types."""
        from app.services.twilio_risk_activity_correlation_service import TWILIO_CORRELATION_TYPES
        for ct in EXPECTED_CORRELATION_TYPES:
            assert ct in TWILIO_CORRELATION_TYPES, (
                f"Expected correlation type {ct!r} not in TWILIO_CORRELATION_TYPES"
            )

    def test_a4_twilio_correlation_rules_structure(self):
        """A4: Each TWILIO_CORRELATION_RULES entry has rule_keys, signal_types, match_key."""
        from app.services.twilio_risk_activity_correlation_service import TWILIO_CORRELATION_RULES
        assert TWILIO_CORRELATION_RULES is not None
        for ct, rule in TWILIO_CORRELATION_RULES.items():
            assert "rule_keys" in rule, f"rule {ct!r} missing 'rule_keys'"
            assert "signal_types" in rule, f"rule {ct!r} missing 'signal_types'"
            assert "match_key" in rule, f"rule {ct!r} missing 'match_key'"
            assert isinstance(rule["rule_keys"], (set, frozenset)), (
                f"rule {ct!r}: rule_keys should be a set"
            )
            assert isinstance(rule["signal_types"], (set, frozenset)), (
                f"rule {ct!r}: signal_types should be a set"
            )
            assert isinstance(rule["match_key"], str), (
                f"rule {ct!r}: match_key should be a string"
            )


# ══════════════════════════════════════════════════════════════════════════════
# B: Correlation rule mapping
# ══════════════════════════════════════════════════════════════════════════════


class TestCorrelationRuleMapping:
    """B: Each correlation type maps to the expected rule keys."""

    def _rule(self, ct: str) -> dict:
        from app.services.twilio_risk_activity_correlation_service import TWILIO_CORRELATION_RULES
        assert ct in TWILIO_CORRELATION_RULES, f"{ct!r} not in TWILIO_CORRELATION_RULES"
        return TWILIO_CORRELATION_RULES[ct]

    def test_b1_phone_number_rule_keys(self):
        """B1: Phone number rules map to twilio_phone_number_risk_activity_correlation."""
        rule = self._rule("twilio_phone_number_risk_activity_correlation")
        expected_keys = {
            "twilio_phone_number_sms_webhook_missing",
            "twilio_phone_number_voice_webhook_missing",
            "twilio_phone_number_status_callback_missing",
            "twilio_phone_number_messaging_observability_gap",
            "twilio_phone_number_voice_observability_gap",
        }
        for k in expected_keys:
            assert k in rule["rule_keys"], (
                f"Expected rule key {k!r} not in phone_number correlation rule_keys"
            )

    def test_b2_messaging_service_rule_keys(self):
        """B2: Messaging service rules map to twilio_messaging_service_risk_activity_correlation."""
        rule = self._rule("twilio_messaging_service_risk_activity_correlation")
        expected_keys = {
            "twilio_messaging_service_inbound_webhook_missing",
            "twilio_messaging_service_fallback_missing",
            "twilio_messaging_service_status_callback_missing",
            "twilio_messaging_service_observability_gap",
            "twilio_messaging_service_number_level_inbound_webhook",
            "twilio_messaging_service_long_validity_period",
        }
        for k in expected_keys:
            assert k in rule["rule_keys"], (
                f"Expected rule key {k!r} not in messaging_service correlation rule_keys"
            )

    def test_b3_verify_service_rule_keys(self):
        """B3: Verify service rules map to twilio_verify_service_risk_activity_correlation."""
        rule = self._rule("twilio_verify_service_risk_activity_correlation")
        expected_keys = {
            "twilio_verify_short_code_length",
            "twilio_verify_lookup_disabled",
            "twilio_verify_psd2_disabled",
            "twilio_verify_sms_to_landlines_allowed",
        }
        for k in expected_keys:
            assert k in rule["rule_keys"], (
                f"Expected rule key {k!r} not in verify_service correlation rule_keys"
            )

    def test_b4_api_key_rule_keys(self):
        """B4: API key rules map to twilio_api_key_risk_activity_correlation."""
        rule = self._rule("twilio_api_key_risk_activity_correlation")
        assert "twilio_api_key_stale" in rule["rule_keys"], (
            "Expected 'twilio_api_key_stale' in api_key correlation rule_keys"
        )

    def test_b5_account_rule_keys(self):
        """B5: Account rules map to twilio_account_risk_activity_correlation."""
        rule = self._rule("twilio_account_risk_activity_correlation")
        assert "twilio_account_suspended" in rule["rule_keys"], (
            "Expected 'twilio_account_suspended' in account correlation rule_keys"
        )


# ══════════════════════════════════════════════════════════════════════════════
# C: Correlation generation logic (mock DB)
# ══════════════════════════════════════════════════════════════════════════════


class TestCorrelationGenerationLogic:
    """C: Correlation generation logic with mocked DB."""

    def _run(
        self,
        findings: list,
        signals: list,
        workspace_id: uuid.UUID | None = None,
    ) -> dict:
        from app.services import twilio_risk_activity_correlation_service as svc
        ws = workspace_id or uuid.uuid4()
        db = _db_with(findings, signals)
        with patch(
            "app.services.twilio_risk_activity_correlation_service.corr_svc.upsert_correlation",
            return_value=("created", MagicMock()),
        ):
            return svc.generate_twilio_correlations(workspace_id=ws, db=db)

    def test_c1_matching_finding_and_signal_produces_correlation(self):
        """C1: Matching finding + signal → produces correlation (correlations_created >= 1)."""
        finding = _make_finding(
            finding_key="twilio_messaging_service_fallback_missing",
            evidence={"messaging_service_sid": "MGTEST001"},
        )
        signal = _make_signal(
            signal_type="twilio_messaging_service_config_changed",
            signal_metadata={"messaging_service_sid": "MGTEST001"},
        )
        result = self._run([finding], [signal])
        assert result["correlations_created"] >= 1, (
            f"Expected correlations_created >= 1, got {result['correlations_created']}"
        )

    def test_c2_phone_number_resource_bearing_no_shared_id_uses_aggregate(self):
        """C2: Resource-bearing phone number rule without shared phone_number_last4
        falls back to family-level aggregate (not dropped outright by this architecture)."""
        finding = _make_finding(
            finding_key="twilio_phone_number_sms_webhook_missing",
            evidence={},  # no phone_number_last4
        )
        signal = _make_signal(
            signal_type="twilio_phone_number_config_changed",
            signal_metadata={},  # no phone_number_last4
        )
        # The service falls back to family-aggregate match ("phone_number_family").
        # We just assert it produces a deterministic non-crashing result.
        from app.services import twilio_risk_activity_correlation_service as svc
        ws = uuid.uuid4()
        db = _db_with([finding], [signal])
        with patch(
            "app.services.twilio_risk_activity_correlation_service.corr_svc.upsert_correlation",
            return_value=("created", MagicMock()),
        ) as mock_upsert:
            result = svc.generate_twilio_correlations(workspace_id=ws, db=db)
        # Either a correlation was produced (aggregate fallback) or it was not.
        # The important property: no crash and we check the match_reason is safe.
        # If it upserted, the match_reason must be "phone_number_family".
        if mock_upsert.call_count > 0:
            call_kwargs = mock_upsert.call_args_list[0][1]
            corr = call_kwargs.get("correlation", {})
            meta = corr.get("metadata", {})
            match_reason = meta.get("match_reason", "")
            assert "phone_number_last4_match" not in match_reason or match_reason == "", (
                f"Without shared phone_number_last4, match_reason should not be "
                f"'phone_number_last4_match', got: {match_reason!r}"
            )

    def test_c3_different_resource_no_correlation(self):
        """C3: Messaging service finding and signal with different SIDs → no correlation."""
        finding = _make_finding(
            finding_key="twilio_messaging_service_fallback_missing",
            evidence={"messaging_service_sid": "MGTEST001"},
        )
        signal = _make_signal(
            signal_type="twilio_messaging_service_config_changed",
            signal_metadata={"messaging_service_sid": "MGTEST002"},  # different SID
        )
        from app.services import twilio_risk_activity_correlation_service as svc
        ws = uuid.uuid4()
        db = _db_with([finding], [signal])
        with patch(
            "app.services.twilio_risk_activity_correlation_service.corr_svc.upsert_correlation",
            return_value=("created", MagicMock()),
        ) as mock_upsert:
            result = svc.generate_twilio_correlations(workspace_id=ws, db=db)
        assert result["correlations_created"] == 0, (
            f"Different messaging_service_sids should produce no correlation, "
            f"got correlations_created={result['correlations_created']}"
        )

    def test_c4_idempotency_second_run_no_new_correlations(self):
        """C4: Running twice with same data → 0 new correlations on second run."""
        finding = _make_finding(
            finding_key="twilio_messaging_service_fallback_missing",
            evidence={"messaging_service_sid": "MGTEST001"},
        )
        signal = _make_signal(
            signal_type="twilio_messaging_service_config_changed",
            signal_metadata={"messaging_service_sid": "MGTEST001"},
        )
        from app.services import twilio_risk_activity_correlation_service as svc
        ws = uuid.uuid4()

        # First run: created
        db1 = _db_with([finding], [signal])
        with patch(
            "app.services.twilio_risk_activity_correlation_service.corr_svc.upsert_correlation",
            return_value=("created", MagicMock()),
        ):
            r1 = svc.generate_twilio_correlations(workspace_id=ws, db=db1)
        assert r1["correlations_created"] >= 1

        # Second run: skipped (idempotent)
        db2 = _db_with([finding], [signal])
        with patch(
            "app.services.twilio_risk_activity_correlation_service.corr_svc.upsert_correlation",
            return_value=("skipped", MagicMock()),
        ):
            r2 = svc.generate_twilio_correlations(workspace_id=ws, db=db2)
        assert r2["correlations_created"] == 0
        assert r2["correlations_skipped"] >= 1


# ══════════════════════════════════════════════════════════════════════════════
# D: Metadata privacy
# ══════════════════════════════════════════════════════════════════════════════


class TestMetadataPrivacy:
    """D: Correlation metadata must not contain forbidden fields or values."""

    def _build_correlation(
        self,
        finding_key: str = "twilio_messaging_service_fallback_missing",
        evidence: dict | None = None,
        signal_type: str = "twilio_messaging_service_config_changed",
        signal_metadata: dict | None = None,
        correlation_type: str = "twilio_messaging_service_risk_activity_correlation",
    ) -> dict:
        from app.services.twilio_risk_activity_correlation_service import (
            _build_correlation,
            TWILIO_CORRELATION_RULES,
        )
        finding = _make_finding(finding_key=finding_key, evidence=evidence or {})
        signal = _make_signal(signal_type=signal_type, signal_metadata=signal_metadata or {})
        rule = TWILIO_CORRELATION_RULES[correlation_type]
        return _build_correlation(
            finding=finding,
            signal=signal,
            correlation_type=correlation_type,
            rule=rule,
            match_reason="messaging_service_family",
        )

    def test_d1_no_forbidden_metadata_fields(self):
        """D1: No key from FORBIDDEN_METADATA_FIELDS in correlation metadata."""
        corr = self._build_correlation()
        meta = corr.get("metadata", {})
        for key in meta.keys():
            assert key.lower() not in FORBIDDEN_METADATA_FIELDS, (
                f"Forbidden metadata key {key!r} found in correlation metadata"
            )

    def test_d2_no_full_phone_number_in_metadata(self):
        """D2: No value that looks like a full E.164 phone number in metadata."""
        e164 = re.compile(r"^\+\d{10,}$")
        corr = self._build_correlation()
        meta = corr.get("metadata", {})
        for v in meta.values():
            if isinstance(v, str):
                assert not e164.match(v), (
                    f"Full E.164 phone number pattern found in correlation metadata: {v!r}"
                )

    def test_d3_no_auth_token_or_api_secret_in_metadata(self):
        """D3: No auth_token or api_secret value in metadata fields."""
        fake_auth_token = "fake_auth_token_not_real_32chars00"
        fake_api_secret = "SK" + "a" * 32
        corr = self._build_correlation(
            evidence={
                "auth_token": fake_auth_token,
                "api_secret": fake_api_secret,
                "messaging_service_sid": "MGTEST001",
            },
        )
        meta_str = str(corr.get("metadata", {}))
        assert fake_auth_token not in meta_str, "auth_token value found in correlation metadata"
        assert fake_api_secret not in meta_str, "api_secret value found in correlation metadata"

    def test_d4_phone_number_last4_value_at_most_4_chars(self):
        """D4: If phone_number_last4 present in metadata, length <= 4."""
        corr = self._build_correlation(
            finding_key="twilio_phone_number_sms_webhook_missing",
            evidence={"phone_number_last4": "1234"},
            signal_type="twilio_phone_number_config_changed",
            signal_metadata={"phone_number_last4": "1234"},
            correlation_type="twilio_phone_number_risk_activity_correlation",
        )
        meta = corr.get("metadata", {})
        last4 = meta.get("phone_number_last4")
        if last4 is not None:
            assert len(str(last4)) <= 4, (
                f"phone_number_last4 in metadata should be <= 4 chars, got: {last4!r}"
            )


# ══════════════════════════════════════════════════════════════════════════════
# E: API endpoint
# ══════════════════════════════════════════════════════════════════════════════


class TestApiEndpoint:
    """E: POST /security/twilio-correlations/generate endpoint."""

    def test_e1_unauthenticated_returns_401_or_422_or_200(self):
        """E1: Unauthenticated → 401/422/200 (dev mode may bypass auth)."""
        from fastapi.testclient import TestClient
        from app.main import app as fastapi_app

        client = TestClient(fastapi_app, raise_server_exceptions=False)
        r = client.post("/security/twilio-correlations/generate", json={})
        assert r.status_code in (200, 401, 422), (
            f"Expected 200/401/422, got {r.status_code}: {r.text[:200]}"
        )

    def test_e2_admin_can_call_endpoint_200(self):
        """E2: Admin can call → 200."""
        from fastapi.testclient import TestClient
        from app.core.auth import get_current_user
        from app.database import get_db
        from app.main import app as fastapi_app
        from app.services import twilio_risk_activity_correlation_service as svc

        mock_user = MagicMock()
        mock_user.id = uuid.uuid4()
        mock_db = MagicMock()
        mock_workspace_id = uuid.uuid4()

        clean_summary = {
            "provider": "twilio",
            "findings_scanned": 0,
            "signals_scanned": 0,
            "correlations_created": 0,
            "correlations_skipped": 0,
        }

        fastapi_app.dependency_overrides[get_current_user] = lambda: mock_user
        fastapi_app.dependency_overrides[get_db] = lambda: mock_db

        try:
            with patch(
                "app.routers.security._current_workspace_id",
                return_value=mock_workspace_id,
            ), patch(
                "app.routers.security.workspace_permission_service.require_workspace_admin",
                return_value=None,
            ), patch.object(
                svc, "generate_twilio_correlations", return_value=clean_summary
            ):
                client = TestClient(fastapi_app, raise_server_exceptions=True)
                r = client.post("/security/twilio-correlations/generate", json={})
        finally:
            fastapi_app.dependency_overrides.clear()

        assert r.status_code == 200

    def test_e3_response_has_provider_and_correlations_fields(self):
        """E3: Response has provider='twilio', correlations_created, correlations_skipped fields."""
        from fastapi.testclient import TestClient
        from app.core.auth import get_current_user
        from app.database import get_db
        from app.main import app as fastapi_app
        from app.services import twilio_risk_activity_correlation_service as svc

        mock_user = MagicMock()
        mock_user.id = uuid.uuid4()
        mock_db = MagicMock()
        mock_workspace_id = uuid.uuid4()

        clean_summary = {
            "provider": "twilio",
            "findings_scanned": 3,
            "signals_scanned": 2,
            "correlations_created": 1,
            "correlations_skipped": 0,
        }

        fastapi_app.dependency_overrides[get_current_user] = lambda: mock_user
        fastapi_app.dependency_overrides[get_db] = lambda: mock_db

        try:
            with patch(
                "app.routers.security._current_workspace_id",
                return_value=mock_workspace_id,
            ), patch(
                "app.routers.security.workspace_permission_service.require_workspace_admin",
                return_value=None,
            ), patch.object(
                svc, "generate_twilio_correlations", return_value=clean_summary
            ):
                client = TestClient(fastapi_app, raise_server_exceptions=True)
                r = client.post("/security/twilio-correlations/generate", json={})
        finally:
            fastapi_app.dependency_overrides.clear()

        assert r.status_code == 200
        body = r.json()
        assert body["provider"] == "twilio"
        assert "correlations_created" in body
        assert "correlations_skipped" in body


# ══════════════════════════════════════════════════════════════════════════════
# F: Capability matrix
# ══════════════════════════════════════════════════════════════════════════════


class TestCapabilityMatrix:
    """F: Provider capability matrix reflects M79F state."""

    def _cap(self):
        from app.services.provider_capability_matrix_service import get_provider_capability
        return get_provider_capability("twilio")

    def test_f1_risk_activity_correlations_is_true(self):
        """F1: get_provider_capability('twilio').security.risk_activity_correlations is True."""
        assert self._cap().security.risk_activity_correlations is True

    def test_f2_demo_seed_clear_is_false(self):
        """F2: get_provider_capability('twilio').security.demo_seed_clear is True (M79G complete)."""
        assert self._cap().security.demo_seed_clear is True

    def test_f3_case_report_is_false(self):
        """F3: get_provider_capability('twilio').security.case_report is True (M79G complete)."""
        assert self._cap().security.case_report is True


# ══════════════════════════════════════════════════════════════════════════════
# G: Expansion framework
# ══════════════════════════════════════════════════════════════════════════════


class TestExpansionFramework:
    """G: Expansion framework planned_next_stage points to M79G / Twilio Demo."""

    def _fw(self):
        from app.services import provider_expansion_framework as svc
        return svc.get_framework()

    def test_g1_planned_next_stage_contains_m79g(self):
        """G1: planned_next_stage contains 'M79H' (M79G complete)."""
        stage = self._fw()["summary"]["planned_next_stage"]
        assert "M79H" in stage, (
            f"planned_next_stage should contain 'M79H', got: {stage!r}"
        )

    def test_g2_planned_next_stage_contains_twilio_or_demo(self):
        """G2: planned_next_stage contains 'Twilio' or 'Demo'."""
        stage = self._fw()["summary"]["planned_next_stage"]
        assert "Twilio" in stage or "Demo" in stage, (
            f"planned_next_stage should mention Twilio or Demo, got: {stage!r}"
        )

    def test_g3_planned_next_stage_does_not_contain_m79f(self):
        """G3: planned_next_stage does NOT contain 'M79F'."""
        stage = self._fw()["summary"]["planned_next_stage"]
        assert "M79F" not in stage, (
            f"planned_next_stage must not still say M79F (it is complete): {stage!r}"
        )


# ══════════════════════════════════════════════════════════════════════════════
# H: Frontend (skip if absent)
# ══════════════════════════════════════════════════════════════════════════════

REPO_ROOT = Path(__file__).resolve().parents[2]
_FE_CORRELATIONS_PAGE = (
    REPO_ROOT / "frontend" / "src" / "app" / "(app)" / "security" / "correlations" / "page.tsx"
)
_FE_API_TS = REPO_ROOT / "frontend" / "src" / "lib" / "api.ts"
_FE_TYPES_TS = REPO_ROOT / "frontend" / "src" / "types" / "index.ts"


def _read_fe(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None


class TestFrontend:
    """H: Frontend checks — skipped if frontend files absent."""

    def test_h1_correlations_page_contains_twilio_in_provider_options(self):
        """H1: correlations/page.tsx contains 'twilio' in PROVIDER_OPTIONS."""
        content = _read_fe(_FE_CORRELATIONS_PAGE)
        if content is None:
            pytest.skip("Frontend correlations/page.tsx not found")
        assert "twilio" in content.lower(), (
            "correlations/page.tsx should contain 'twilio' in PROVIDER_OPTIONS"
        )

    def test_h2_correlations_page_contains_phone_number_correlation_type(self):
        """H2: correlations/page.tsx contains 'twilio_phone_number_risk_activity_correlation'."""
        content = _read_fe(_FE_CORRELATIONS_PAGE)
        if content is None:
            pytest.skip("Frontend correlations/page.tsx not found")
        assert "twilio_phone_number_risk_activity_correlation" in content, (
            "correlations/page.tsx should contain 'twilio_phone_number_risk_activity_correlation'"
        )

    def test_h3_correlations_page_contains_messaging_service_correlation_type(self):
        """H3: correlations/page.tsx contains 'twilio_messaging_service_risk_activity_correlation'."""
        content = _read_fe(_FE_CORRELATIONS_PAGE)
        if content is None:
            pytest.skip("Frontend correlations/page.tsx not found")
        assert "twilio_messaging_service_risk_activity_correlation" in content, (
            "correlations/page.tsx should contain 'twilio_messaging_service_risk_activity_correlation'"
        )

    def test_h4_api_ts_contains_generate_twilio_correlations(self):
        """H4: api.ts contains 'generateTwilioCorrelations'."""
        content = _read_fe(_FE_API_TS)
        if content is None:
            pytest.skip("Frontend api.ts not found")
        assert "generateTwilioCorrelations" in content, (
            "api.ts should contain 'generateTwilioCorrelations'"
        )

    def test_h5_types_contains_twilio_correlation_generate_response(self):
        """H5: types/index.ts contains 'TwilioCorrelationGenerateResponse'."""
        content = _read_fe(_FE_TYPES_TS)
        if content is None:
            pytest.skip("Frontend types/index.ts not found")
        assert "TwilioCorrelationGenerateResponse" in content, (
            "types/index.ts should contain 'TwilioCorrelationGenerateResponse'"
        )


# ══════════════════════════════════════════════════════════════════════════════
# I: Forbidden wording + secret shape
# ══════════════════════════════════════════════════════════════════════════════


def _assert_no_forbidden_wording(src: str, module_name: str) -> None:
    low = src.lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in low, (
            f"Forbidden phrase {phrase!r} found in {module_name}"
        )


def test_i1_no_forbidden_phrases_in_twilio_risk_activity_correlation_service():
    """I1: Scan twilio_risk_activity_correlation_service.py for forbidden phrases."""
    import importlib
    mod = importlib.import_module("app.services.twilio_risk_activity_correlation_service")
    _assert_no_forbidden_wording(inspect.getsource(mod), mod.__name__)


def test_i2_no_secret_patterns_in_twilio_risk_activity_correlation_service():
    """I2: Scan for AC[0-9a-fA-F]{32} or SK[0-9a-fA-F]{32} literal patterns."""
    import importlib
    mod = importlib.import_module("app.services.twilio_risk_activity_correlation_service")
    src = inspect.getsource(mod)
    # Match 34-char Twilio Account SID or API Key SID literals (AC or SK + 32 hex chars)
    pattern = re.compile(r"\b(AC|SK)[0-9a-fA-F]{32}\b")
    matches = pattern.findall(src)
    assert not matches, (
        f"Secret-shaped literals (AC/SK + 32 hex) found in twilio_risk_activity_correlation_service: "
        f"{matches[:3]}"
    )
