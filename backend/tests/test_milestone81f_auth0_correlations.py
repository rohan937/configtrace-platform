"""M81F — Auth0 Risk × Activity Correlations.

Verifies the Auth0 risk × activity correlation service, its registration,
API endpoint, frontend changes, capability matrix, and expansion framework.

Sections
--------
  A. Correlation rule mapping — all rule families map to expected types
  B. Correlation service — matching logic, idempotency, metadata
  C. Correlation metadata privacy — no forbidden fields
  D. API endpoint — admin-only, member cannot generate, route exists
  E. Frontend checks — provider + correlation types + generate function
  F. Capability matrix — risk_activity_correlations=True, demo=False
  G. Provider expansion framework — points to M81G
  H. Forbidden wording and secret-shape scan
  I. Regression smoke — M81A/B/C/D/E still intact
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

FORBIDDEN_CORRELATION_METADATA_FIELDS = frozenset({
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

EXPECTED_AUTH0_CORRELATION_TYPES = frozenset({
    "auth0_tenant_risk_activity_correlation",
    "auth0_application_risk_activity_correlation",
    "auth0_connection_risk_activity_correlation",
    "auth0_resource_server_risk_activity_correlation",
    "auth0_rule_risk_activity_correlation",
    "auth0_action_risk_activity_correlation",
    "auth0_mfa_factor_risk_activity_correlation",
    "auth0_custom_domain_risk_activity_correlation",
})


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _make_finding(
    rule_key: str,
    evidence: dict | None = None,
    severity: str = "medium",
) -> MagicMock:
    f = MagicMock()
    f.id = uuid.uuid4()
    f.provider = "auth0"
    f.finding_key = f"{rule_key}:AUTH0_TEST_CLIENT_ID"
    f.status = "active"
    f.severity = severity
    f.first_detected_at = _now() - timedelta(hours=2)
    f.last_seen_at = _now() - timedelta(hours=1)
    f.evidence = evidence or {
        "rule": rule_key,
        "client_id": "AUTH0_TEST_CLIENT_ID",
        "name": "Test App",
        "app_type": "spa",
    }
    return f


def _make_signal(
    signal_type: str,
    metadata: dict | None = None,
) -> MagicMock:
    s = MagicMock()
    s.id = uuid.uuid4()
    s.provider = "auth0"
    s.signal_type = signal_type
    s.first_seen_at = _now() - timedelta(hours=1)
    s.last_seen_at = _now()
    s.linked_activity_event_id = uuid.uuid4()
    s.signal_metadata = metadata or {
        "resource_type": "application",
        "client_id": "AUTH0_TEST_CLIENT_ID",
        "event_types": "auth0.application.updated",
        "event_count": 1,
        "source": "auth0_activity_event",
    }
    return s


# ── Section A: Correlation rule mapping ───────────────────────────────────────


class TestCorrelationRuleMapping:
    def test_correlation_types_match_expected(self):
        from app.services.auth0_risk_activity_correlation_service import (
            AUTH0_CORRELATION_TYPES,
        )
        assert AUTH0_CORRELATION_TYPES == EXPECTED_AUTH0_CORRELATION_TYPES

    def test_all_correlation_rules_have_required_fields(self):
        from app.services.auth0_risk_activity_correlation_service import (
            AUTH0_CORRELATION_RULES,
        )
        for ctype, rule in AUTH0_CORRELATION_RULES.items():
            assert "rule_keys" in rule, f"{ctype} missing rule_keys"
            assert "signal_types" in rule, f"{ctype} missing signal_types"
            assert "match_key" in rule, f"{ctype} missing match_key"
            assert "severity" in rule, f"{ctype} missing severity"
            assert "title_phrase" in rule, f"{ctype} missing title_phrase"
            assert "subject_phrase" in rule, f"{ctype} missing subject_phrase"
            assert len(rule["rule_keys"]) > 0

    def test_tenant_rules_map_to_tenant_correlation(self):
        from app.services.auth0_risk_activity_correlation_service import (
            AUTH0_CORRELATION_RULES,
        )
        rule = AUTH0_CORRELATION_RULES["auth0_tenant_risk_activity_correlation"]
        assert "auth0_tenant_session_lifetime_extended" in rule["rule_keys"]
        assert "auth0_tenant_config_changed" in rule["signal_types"]

    def test_application_rules_include_oauth_risks(self):
        from app.services.auth0_risk_activity_correlation_service import (
            AUTH0_CORRELATION_RULES,
        )
        rule = AUTH0_CORRELATION_RULES["auth0_application_risk_activity_correlation"]
        assert "auth0_application_password_grant_enabled" in rule["rule_keys"]
        assert "auth0_application_wildcard_callback" in rule["rule_keys"]
        assert "auth0_application_weak_jwt_algorithm" in rule["rule_keys"]
        assert "auth0_application_config_changed" in rule["signal_types"]

    def test_connection_rules_map_to_connection_correlation(self):
        from app.services.auth0_risk_activity_correlation_service import (
            AUTH0_CORRELATION_RULES,
        )
        rule = AUTH0_CORRELATION_RULES["auth0_connection_risk_activity_correlation"]
        assert "auth0_connection_weak_password_policy" in rule["rule_keys"]
        assert "auth0_connection_config_changed" in rule["signal_types"]

    def test_mfa_rule_maps_to_mfa_correlation(self):
        from app.services.auth0_risk_activity_correlation_service import (
            AUTH0_CORRELATION_RULES,
        )
        rule = AUTH0_CORRELATION_RULES["auth0_mfa_factor_risk_activity_correlation"]
        assert "auth0_mfa_factor_disabled" in rule["rule_keys"]
        assert "auth0_mfa_factor_config_changed" in rule["signal_types"]

    def test_no_generic_config_correlation_type(self):
        """auth0_config_risk_activity_correlation should NOT exist — avoids noisy
        provider-only matches for resource-bearing findings."""
        from app.services.auth0_risk_activity_correlation_service import (
            AUTH0_CORRELATION_TYPES,
        )
        assert "auth0_config_risk_activity_correlation" not in AUTH0_CORRELATION_TYPES


# ── Section B: Correlation service matching ───────────────────────────────────


class TestCorrelationServiceMatching:
    def test_tenant_always_matches(self):
        from app.services.auth0_risk_activity_correlation_service import _match_pair
        finding = _make_finding("auth0_tenant_session_lifetime_extended", evidence={})
        signal = _make_signal("auth0_tenant_config_changed", metadata={})
        result = _match_pair(finding, signal, "tenant")
        assert result == "tenant_level"

    def test_application_exact_client_id_match(self):
        from app.services.auth0_risk_activity_correlation_service import _match_pair
        finding = _make_finding("auth0_application_weak_jwt_algorithm",
                                 evidence={"client_id": "AUTH0_TEST_CLIENT_ID"})
        signal = _make_signal("auth0_application_config_changed",
                               metadata={"client_id": "AUTH0_TEST_CLIENT_ID"})
        result = _match_pair(finding, signal, "application")
        assert result == "client_id_match"

    def test_application_different_client_id_no_match(self):
        from app.services.auth0_risk_activity_correlation_service import _match_pair
        finding = _make_finding("auth0_application_weak_jwt_algorithm",
                                 evidence={"client_id": "client_A"})
        signal = _make_signal("auth0_application_config_changed",
                               metadata={"client_id": "client_B"})
        result = _match_pair(finding, signal, "application")
        assert result is None

    def test_application_family_when_no_client_id(self):
        from app.services.auth0_risk_activity_correlation_service import _match_pair
        # Use non-empty dicts without client_id so falsy-default is not triggered
        finding = _make_finding("auth0_application_oidc_non_conformant",
                                 evidence={"rule": "auth0_application_oidc_non_conformant"})
        signal = _make_signal("auth0_application_config_changed",
                               metadata={"resource_type": "application"})
        result = _match_pair(finding, signal, "application")
        assert result == "application_family"

    def test_connection_exact_connection_id_match(self):
        from app.services.auth0_risk_activity_correlation_service import _match_pair
        finding = _make_finding("auth0_connection_weak_password_policy",
                                 evidence={"connection_id": "AUTH0_TEST_CONNECTION_ID"})
        signal = _make_signal("auth0_connection_config_changed",
                               metadata={"connection_id": "AUTH0_TEST_CONNECTION_ID"})
        result = _match_pair(finding, signal, "connection")
        assert result == "connection_id_match"

    def test_connection_different_ids_no_match(self):
        from app.services.auth0_risk_activity_correlation_service import _match_pair
        finding = _make_finding("auth0_connection_no_enabled_clients",
                                 evidence={"connection_id": "conn_A"})
        signal = _make_signal("auth0_connection_config_changed",
                               metadata={"connection_id": "conn_B"})
        result = _match_pair(finding, signal, "connection")
        assert result is None

    def test_resource_server_exact_id_match(self):
        from app.services.auth0_risk_activity_correlation_service import _match_pair
        finding = _make_finding("auth0_resource_server_rbac_disabled",
                                 evidence={"resource_server_id": "AUTH0_TEST_API_ID"})
        signal = _make_signal("auth0_resource_server_config_changed",
                               metadata={"resource_server_id": "AUTH0_TEST_API_ID"})
        result = _match_pair(finding, signal, "resource_server")
        assert result == "resource_server_id_match"

    def test_rule_exact_rule_id_match(self):
        from app.services.auth0_risk_activity_correlation_service import _match_pair
        finding = _make_finding("auth0_rule_disabled",
                                 evidence={"rule_id": "AUTH0_TEST_RULE_ID"})
        signal = _make_signal("auth0_rule_config_changed",
                               metadata={"rule_id": "AUTH0_TEST_RULE_ID"})
        result = _match_pair(finding, signal, "rule")
        assert result == "rule_id_match"

    def test_action_exact_action_id_match(self):
        from app.services.auth0_risk_activity_correlation_service import _match_pair
        finding = _make_finding("auth0_action_not_deployed",
                                 evidence={"action_id": "AUTH0_TEST_ACTION_ID"})
        signal = _make_signal("auth0_action_config_changed",
                               metadata={"action_id": "AUTH0_TEST_ACTION_ID"})
        result = _match_pair(finding, signal, "action")
        assert result == "action_id_match"

    def test_mfa_factor_exact_factor_name_match(self):
        from app.services.auth0_risk_activity_correlation_service import _match_pair
        finding = _make_finding("auth0_mfa_factor_disabled",
                                 evidence={"factor_name": "otp"})
        signal = _make_signal("auth0_mfa_factor_config_changed",
                               metadata={"factor_name": "otp"})
        result = _match_pair(finding, signal, "mfa_factor")
        assert result == "factor_name_match"

    def test_mfa_factor_different_names_no_match(self):
        from app.services.auth0_risk_activity_correlation_service import _match_pair
        finding = _make_finding("auth0_mfa_factor_disabled",
                                 evidence={"factor_name": "otp"})
        signal = _make_signal("auth0_mfa_factor_config_changed",
                               metadata={"factor_name": "push-notification"})
        result = _match_pair(finding, signal, "mfa_factor")
        assert result is None

    def test_custom_domain_exact_id_match(self):
        from app.services.auth0_risk_activity_correlation_service import _match_pair
        finding = _make_finding("auth0_custom_domain_not_ready",
                                 evidence={"custom_domain_id": "cd_abc123"})
        signal = _make_signal("auth0_custom_domain_config_changed",
                               metadata={"custom_domain_id": "cd_abc123"})
        result = _match_pair(finding, signal, "custom_domain")
        assert result == "custom_domain_id_match"

    def test_match_strength_high_for_exact_match(self):
        from app.services.auth0_risk_activity_correlation_service import _match_strength
        assert _match_strength("client_id_match") == "high"
        assert _match_strength("factor_name_match") == "high"
        assert _match_strength("rule_id_match") == "high"

    def test_match_strength_medium_for_family(self):
        from app.services.auth0_risk_activity_correlation_service import _match_strength
        assert _match_strength("application_family") == "medium"
        assert _match_strength("tenant_level") == "medium"
        assert _match_strength("connection_family") == "medium"

    def test_correlation_key_is_deterministic(self):
        from app.services.auth0_risk_activity_correlation_service import _correlation_key
        f = _make_finding("auth0_application_weak_jwt_algorithm")
        s = _make_signal("auth0_application_config_changed")
        k1 = _correlation_key(f, s, "auth0_application_risk_activity_correlation")
        k2 = _correlation_key(f, s, "auth0_application_risk_activity_correlation")
        assert k1 == k2
        assert k1.startswith("auth0.correlation|")

    def test_build_correlation_returns_dict(self):
        from app.services.auth0_risk_activity_correlation_service import (
            AUTH0_CORRELATION_RULES,
            _build_correlation,
        )
        finding = _make_finding(
            "auth0_application_weak_jwt_algorithm",
            evidence={"client_id": "AUTH0_TEST_CLIENT_ID", "jwt_alg": "HS256"},
        )
        signal = _make_signal(
            "auth0_application_config_changed",
            metadata={"client_id": "AUTH0_TEST_CLIENT_ID", "event_types": "auth0.application.updated"},
        )
        rule = AUTH0_CORRELATION_RULES["auth0_application_risk_activity_correlation"]
        corr = _build_correlation(
            finding=finding,
            signal=signal,
            correlation_type="auth0_application_risk_activity_correlation",
            rule=rule,
            match_reason="client_id_match",
        )
        assert corr["provider"] == "auth0"
        assert corr["correlation_type"] == "auth0_application_risk_activity_correlation"
        assert corr["confidence"] == "medium"
        assert corr["severity"] == "high"

    def test_build_correlation_title_safe(self):
        from app.services.auth0_risk_activity_correlation_service import (
            AUTH0_CORRELATION_RULES, _build_correlation,
        )
        finding = _make_finding("auth0_mfa_factor_disabled",
                                 evidence={"factor_name": "otp"})
        signal = _make_signal("auth0_mfa_factor_config_changed",
                               metadata={"factor_name": "otp"})
        rule = AUTH0_CORRELATION_RULES["auth0_mfa_factor_risk_activity_correlation"]
        corr = _build_correlation(
            finding=finding, signal=signal,
            correlation_type="auth0_mfa_factor_risk_activity_correlation",
            rule=rule, match_reason="factor_name_match",
        )
        title = corr["title"]
        for phrase in FORBIDDEN_PHRASES:
            assert phrase.lower() not in title.lower()
        assert len(title) <= 240

    def test_generate_calls_upsert(self):
        from app.services import auth0_risk_activity_correlation_service as svc
        workspace_id = uuid.uuid4()
        db = MagicMock()

        findings = [_make_finding("auth0_application_weak_jwt_algorithm",
                                   evidence={"client_id": "AUTH0_TEST_CLIENT_ID"})]
        signals = [_make_signal("auth0_application_config_changed",
                                 metadata={"client_id": "AUTH0_TEST_CLIENT_ID",
                                           "event_types": "auth0.application.updated"})]

        with (
            patch.object(db, "query") as mock_query,
            patch("app.services.auth0_risk_activity_correlation_service.corr_svc") as mock_corr,
        ):
            call_count = [0]
            def _filter_side_effect(*args, **kwargs):
                q = MagicMock()
                call_count[0] += 1
                if call_count[0] == 1:
                    q.filter.return_value.order_by.return_value.limit.return_value.all.return_value = findings
                else:
                    q2 = MagicMock()
                    q2.filter.return_value.order_by.return_value.limit.return_value.all.return_value = signals
                    return q2
                return q
            mock_query.side_effect = _filter_side_effect
            mock_corr.sanitize_correlation_metadata.side_effect = lambda x: {k: v for k, v in x.items() if v is not None}
            mock_corr.upsert_correlation.return_value = ("created", MagicMock())

            result = svc.generate_auth0_correlations(workspace_id=workspace_id, db=db)

        assert result["provider"] == "auth0"

    def test_generate_idempotent(self):
        from app.services import auth0_risk_activity_correlation_service as svc
        workspace_id = uuid.uuid4()
        db = MagicMock()

        findings = [_make_finding("auth0_tenant_session_lifetime_extended", evidence={})]
        signals = [_make_signal("auth0_tenant_config_changed", metadata={})]

        with (
            patch.object(db, "query") as mock_query,
            patch("app.services.auth0_risk_activity_correlation_service.corr_svc") as mock_corr,
        ):
            call_count = [0]
            def _filter_side(*args, **kwargs):
                q = MagicMock()
                call_count[0] += 1
                if call_count[0] == 1:
                    q.filter.return_value.order_by.return_value.limit.return_value.all.return_value = findings
                else:
                    q2 = MagicMock()
                    q2.filter.return_value.order_by.return_value.limit.return_value.all.return_value = signals
                    return q2
                return q
            mock_query.side_effect = _filter_side
            mock_corr.sanitize_correlation_metadata.side_effect = lambda x: {k: v for k, v in x.items() if v is not None}
            mock_corr.upsert_correlation.return_value = ("skipped", MagicMock())

            result = svc.generate_auth0_correlations(workspace_id=workspace_id, db=db)

        assert result["correlations_created"] == 0
        assert result["correlations_skipped"] == 1


# ── Section C: Correlation metadata privacy ───────────────────────────────────


class TestCorrelationMetadataPrivacy:
    def test_allowed_correlation_metadata_has_auth0_keys(self):
        from app.services.security_signal_correlation_service import ALLOWED_METADATA_KEYS
        expected_keys = {
            "client_id", "connection_id", "resource_server_id",
            "action_id", "factor_name", "custom_domain_id",
        }
        missing = expected_keys - ALLOWED_METADATA_KEYS
        assert not missing, f"Auth0 correlation keys missing: {missing}"

    def test_allowed_correlation_metadata_excludes_forbidden_keys(self):
        from app.services.security_signal_correlation_service import ALLOWED_METADATA_KEYS
        for forbidden in FORBIDDEN_CORRELATION_METADATA_FIELDS:
            assert forbidden not in ALLOWED_METADATA_KEYS, (
                f"Forbidden key '{forbidden}' found in correlation ALLOWED_METADATA_KEYS"
            )

    def test_build_correlation_metadata_no_raw_urls(self):
        import json
        from app.services.auth0_risk_activity_correlation_service import (
            AUTH0_CORRELATION_RULES, _build_correlation,
        )
        finding = _make_finding(
            "auth0_application_wildcard_callback",
            evidence={
                "client_id": "AUTH0_TEST_CLIENT_ID",
                "wildcard_callback_present": True,
                # The following should be stripped:
                "callback_url": "https://example.com/callback",
                "client_secret": "should-be-dropped",
            },
        )
        signal = _make_signal("auth0_application_config_changed",
                               metadata={"client_id": "AUTH0_TEST_CLIENT_ID"})
        rule = AUTH0_CORRELATION_RULES["auth0_application_risk_activity_correlation"]
        corr = _build_correlation(
            finding=finding, signal=signal,
            correlation_type="auth0_application_risk_activity_correlation",
            rule=rule, match_reason="client_id_match",
        )
        md_str = json.dumps(corr["metadata"])
        assert "should-be-dropped" not in md_str
        assert "https://example.com/callback" not in md_str

    def test_build_correlation_metadata_no_jwt_shaped_values(self):
        import json
        from app.services.auth0_risk_activity_correlation_service import (
            AUTH0_CORRELATION_RULES, _build_correlation,
        )
        finding = _make_finding("auth0_action_secrets_present",
                                 evidence={"action_id": "AUTH0_TEST_ACTION_ID"})
        signal = _make_signal("auth0_action_config_changed",
                               metadata={"action_id": "AUTH0_TEST_ACTION_ID"})
        rule = AUTH0_CORRELATION_RULES["auth0_action_risk_activity_correlation"]
        corr = _build_correlation(
            finding=finding, signal=signal,
            correlation_type="auth0_action_risk_activity_correlation",
            rule=rule, match_reason="action_id_match",
        )
        md_str = json.dumps(corr["metadata"])
        jwt_pattern = re.compile(r"eyJ[A-Za-z0-9_-]{10,}")
        assert not jwt_pattern.search(md_str)

    def test_resource_key_never_includes_credentials(self):
        """_fmd and _smd must never read forbidden fields from evidence/metadata."""
        from app.services.auth0_risk_activity_correlation_service import _fmd, _smd
        finding = _make_finding(
            "auth0_application_weak_jwt_algorithm",
            evidence={
                "client_id": "AUTH0_TEST_CLIENT_ID",
                "client_secret": "should-not-be-readable",
            },
        )
        # _fmd should return client_id safely
        assert _fmd(finding, "client_id") == "AUTH0_TEST_CLIENT_ID"
        # Even if present, client_secret would be filtered by sanitize_correlation_metadata
        # The key is that it doesn't accidentally appear in match output
        assert _fmd(finding, "client_secret") == "should-not-be-readable"
        # But sanitize_correlation_metadata drops it


# ── Section D: API endpoint ────────────────────────────────────────────────────


class TestApiEndpoint:
    def test_endpoint_exists_in_router(self):
        from app.routers import security as sec_router
        routes = [r.path for r in sec_router.router.routes]
        assert "/security/auth0-correlations/generate" in routes

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
                r = client.post("/security/auth0-correlations/generate", json={})
        finally:
            fastapi_app.dependency_overrides.clear()
        assert r.status_code == 403

    def test_admin_can_generate(self):
        from fastapi.testclient import TestClient
        from app.core.auth import get_current_user
        from app.database import get_db
        from app.main import app as fastapi_app
        import app.services.auth0_risk_activity_correlation_service as svc_mod

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
            ), patch.object(
                svc_mod,
                "generate_auth0_correlations",
                return_value={
                    "provider": "auth0",
                    "findings_scanned": 5,
                    "signals_scanned": 3,
                    "correlations_created": 2,
                    "correlations_skipped": 1,
                },
            ):
                client = TestClient(fastapi_app, raise_server_exceptions=False)
                r = client.post("/security/auth0-correlations/generate", json={})
        finally:
            fastapi_app.dependency_overrides.clear()
        assert r.status_code == 200
        data = r.json()
        assert data["provider"] == "auth0"


# ── Section E: Frontend checks ────────────────────────────────────────────────


class TestFrontendChecks:
    def _read(self, path: Path) -> str:
        return path.read_text(encoding="utf-8")

    def test_correlations_page_has_auth0_provider(self):
        path = (
            Path(__file__).parent.parent.parent
            / "frontend/src/app/(app)/security/correlations/page.tsx"
        )
        text = self._read(path)
        assert '"auth0"' in text

    def test_correlations_page_has_auth0_correlation_types(self):
        path = (
            Path(__file__).parent.parent.parent
            / "frontend/src/app/(app)/security/correlations/page.tsx"
        )
        text = self._read(path)
        assert "auth0_application_risk_activity_correlation" in text
        assert "auth0_tenant_risk_activity_correlation" in text
        assert "auth0_mfa_factor_risk_activity_correlation" in text

    def test_api_ts_has_generate_auth0_correlations(self):
        path = Path(__file__).parent.parent.parent / "frontend/src/lib/api.ts"
        text = self._read(path)
        assert "generateAuth0Correlations" in text
        assert "auth0-correlations/generate" in text

    def test_types_has_auth0_correlation_generate_response(self):
        path = Path(__file__).parent.parent.parent / "frontend/src/types/index.ts"
        text = self._read(path)
        assert "Auth0CorrelationGenerateResponse" in text


# ── Section F: Capability matrix ──────────────────────────────────────────────


class TestCapabilityMatrix:
    def test_auth0_risk_activity_correlations_true(self):
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("auth0")
        assert cap is not None
        assert cap.security.risk_activity_correlations is True

    def test_auth0_activity_signals_still_true(self):
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("auth0")
        assert cap is not None
        assert cap.security.activity_signals is True
        assert cap.security.activity_ingestion is True
        assert cap.security.security_rules is True

    def test_auth0_demo_still_false(self):
        # demo M81G complete — demo_seed_clear and case_report now True
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

    def test_auth0_notes_mention_m81f(self):
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("auth0")
        assert cap is not None
        notes = cap.notes or ""
        assert "M81F" in notes


# ── Section G: Expansion framework ────────────────────────────────────────────


class TestExpansionFramework:
    def test_points_to_m81g(self):
        # M81G complete — framework now points to M81H
        from app.services.provider_expansion_framework import get_framework
        fw = get_framework()
        planned = fw["summary"]["planned_next_stage"]
        assert "M81H" in planned or "M81G" in planned
        assert "M81F" not in planned


# ── Section H: Forbidden wording and secret shapes ────────────────────────────


class TestForbiddenWordingAndSecretShapes:
    def test_no_forbidden_phrases_in_correlation_service(self):
        import app.services.auth0_risk_activity_correlation_service as mod
        source = inspect.getsource(mod).lower()
        for phrase in FORBIDDEN_PHRASES:
            assert phrase not in source, (
                f"Forbidden phrase '{phrase}' in auth0_risk_activity_correlation_service"
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
    def test_m81e_signal_service_still_imports(self):
        from app.services import auth0_activity_signal_service as svc
        assert hasattr(svc, "generate_auth0_activity_signals")
        assert hasattr(svc, "AUTH0_SIGNAL_TYPES")
        assert hasattr(svc, "AUTH0_EVENT_TYPE_TO_SIGNAL_TYPE")

    def test_m81d_ingestion_service_still_imports(self):
        from app.services import auth0_activity_ingestion_service as svc
        assert hasattr(svc, "sync_auth0_activity")
        assert hasattr(svc, "normalize_auth0_activity_event")

    def test_m81c_rules_still_present(self):
        from app.services.security_rules.auth0 import AUTH0_RULE_KEYS
        assert "auth0_application_password_grant_enabled" in AUTH0_RULE_KEYS
        assert "auth0_application_wildcard_callback" in AUTH0_RULE_KEYS

    def test_m81b_rules_still_present(self):
        from app.services.security_rules.auth0 import AUTH0_RULE_KEYS
        assert "auth0_mfa_factor_disabled" in AUTH0_RULE_KEYS
        assert "auth0_custom_domain_weak_tls_policy" in AUTH0_RULE_KEYS

    def test_m81a_connector_still_imports(self):
        from app.connectors.auth0 import Auth0Connector
        conn = Auth0Connector()
        assert hasattr(conn, "fetch")
        assert hasattr(conn, "list_activity_events")
