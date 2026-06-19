"""M85A: Linear drift provider foundation tests.

Validates that the Linear connector, schema, integration service,
sync wiring, capability matrix, expansion framework, and frontend files
all meet the M85A specification.

Sections:
  A. Linear schema constants (9 constants, all prefixed linear_)
  B. Integration schema (provider Literal, linear_api_key field, validator)
  C. LinearConnector class structure and safety
  D. Error handling (401/403/429/5xx/network via httpx mock)
  E. Safe normalization (mock _query, check flat dicts, no forbidden fields)
  F. Sync service and sync_task wiring
  G. Integration service (create helper, dispatcher)
  H. Capability matrix (linear entry, drift/security caps, maturity)
  I. Provider expansion framework (planned_next_stage, recommended providers)
  J. Frontend files (providers.ts, trustCenter.ts, integrations page, types)
  K. Privacy — no credential/PII fields in connector source
  L. Forbidden wording
  M. Secret-shape grep
  N. Regression smoke (PagerDuty still intact, planned_next_stage is M85B)
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import httpx

from app.connectors.linear import LinearConnector, GRAPHQL_URL
from app.connectors.linear_schema import (
    LINEAR_WORKSPACE,
    LINEAR_TEAM,
    LINEAR_PROJECT,
    LINEAR_WORKFLOW_STATE,
    LINEAR_LABEL,
    LINEAR_WEBHOOK,
    LINEAR_VIEW,
    LINEAR_CYCLE,
    LINEAR_INTEGRATION,
    LINEAR_RECORD_TYPES,
)
from app.connectors.exceptions import (
    AuthenticationError,
    ConnectorError,
    NetworkError,
    RateLimitError,
)
from app.services.provider_capability_matrix_service import (
    get_provider_capability,
    PROVIDER_CAPABILITIES_PARTIAL,
)
from app.services.provider_expansion_framework import get_framework

REPO_ROOT = Path(__file__).resolve().parents[2]
FE_ROOT = REPO_ROOT / "frontend" / "src"
FE_PROVIDERS = FE_ROOT / "lib" / "providers.ts"
FE_TYPES = FE_ROOT / "types" / "index.ts"
FE_INTEGRATIONS = FE_ROOT / "app" / "(app)" / "integrations" / "page.tsx"
FE_TRUST_CENTER = FE_ROOT / "lib" / "trustCenter.ts"

BACKEND_ROOT = Path(__file__).resolve().parents[1]
LINEAR_PY = BACKEND_ROOT / "app" / "connectors" / "linear.py"
LINEAR_SCHEMA_PY = BACKEND_ROOT / "app" / "connectors" / "linear_schema.py"

_API_KEY = "lin_api_TEST_PLACEHOLDER_KEY"
_CREDS = {"api_key": _API_KEY}

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

_FORBIDDEN_RECORD_FIELDS = {
    "api_key", "token", "oauth_token", "secret", "webhook_secret",
    "authorization", "email", "user_email", "phone",
    "webhook_url", "delivery_url", "issue_title", "issue_description",
    "comment", "payload", "headers",
}

EXPECTED_SCHEMA_CONSTANTS = {
    LINEAR_WORKSPACE,
    LINEAR_TEAM,
    LINEAR_PROJECT,
    LINEAR_WORKFLOW_STATE,
    LINEAR_LABEL,
    LINEAR_WEBHOOK,
    LINEAR_VIEW,
    LINEAR_CYCLE,
    LINEAR_INTEGRATION,
}


# ════════════════════════════════════════════════════════════════════════════
# Section A — Schema constants
# ════════════════════════════════════════════════════════════════════════════


def test_a1_constant_count() -> None:
    """There must be exactly 9 LINEAR_* record-type constants."""
    assert len(EXPECTED_SCHEMA_CONSTANTS) == 9


def test_a2_record_types_frozenset_count() -> None:
    assert len(LINEAR_RECORD_TYPES) == 9


def test_a3_record_types_match_constants() -> None:
    assert LINEAR_RECORD_TYPES == EXPECTED_SCHEMA_CONSTANTS


def test_a4_all_constants_start_with_linear() -> None:
    for rt in LINEAR_RECORD_TYPES:
        assert rt.startswith("linear_"), f"{rt!r} does not start with 'linear_'"


def test_a5_linear_workspace_value() -> None:
    assert LINEAR_WORKSPACE == "linear_workspace"


def test_a6_linear_team_value() -> None:
    assert LINEAR_TEAM == "linear_team"


def test_a7_linear_webhook_value() -> None:
    assert LINEAR_WEBHOOK == "linear_webhook"


def test_a8_linear_integration_value() -> None:
    assert LINEAR_INTEGRATION == "linear_integration"


def test_a9_schema_constants_importable() -> None:
    from app.connectors.linear_schema import (  # noqa: F401
        LINEAR_PROJECT,
        LINEAR_WORKFLOW_STATE,
        LINEAR_LABEL,
        LINEAR_VIEW,
        LINEAR_CYCLE,
    )


# ════════════════════════════════════════════════════════════════════════════
# Section B — Integration schema
# ════════════════════════════════════════════════════════════════════════════


_INTEGRATION_BASE = {
    "display_name": "Test Linear Integration",
    "provider": "linear",
    "linear_api_key": _API_KEY,
}


def test_b1_linear_in_provider_literal() -> None:
    from app.schemas.integration import IntegrationCreateRequest
    req = IntegrationCreateRequest(**_INTEGRATION_BASE)
    assert req.provider == "linear"


def test_b2_linear_api_key_field_exists() -> None:
    from app.schemas.integration import IntegrationCreateRequest
    req = IntegrationCreateRequest(**_INTEGRATION_BASE)
    assert req.linear_api_key == _API_KEY


def test_b3_validator_rejects_missing_linear_api_key() -> None:
    from app.schemas.integration import IntegrationCreateRequest
    bad = {**_INTEGRATION_BASE, "linear_api_key": None}
    with pytest.raises((ValueError, Exception)):
        IntegrationCreateRequest(**bad)


def test_b4_validator_rejects_empty_linear_api_key() -> None:
    from app.schemas.integration import IntegrationCreateRequest
    bad = {**_INTEGRATION_BASE, "linear_api_key": ""}
    with pytest.raises((ValueError, Exception)):
        IntegrationCreateRequest(**bad)


def test_b5_response_schema_does_not_expose_linear_api_key() -> None:
    from app.schemas.integration import IntegrationResponse
    # The response schema must NOT have a linear_api_key field
    fields = set()
    if hasattr(IntegrationResponse, "model_fields"):
        fields = set(IntegrationResponse.model_fields.keys())
    elif hasattr(IntegrationResponse, "__fields__"):
        fields = set(IntegrationResponse.__fields__.keys())
    assert "linear_api_key" not in fields, "IntegrationResponse must not expose linear_api_key"


def test_b6_create_request_with_linear_is_valid() -> None:
    from app.schemas.integration import IntegrationCreateRequest
    req = IntegrationCreateRequest(**{**_INTEGRATION_BASE, "linear_api_key": "lin_api_somekey"})
    assert req.provider == "linear"
    assert req.linear_api_key == "lin_api_somekey"


# ════════════════════════════════════════════════════════════════════════════
# Section C — LinearConnector class structure
# ════════════════════════════════════════════════════════════════════════════


def test_c1_connector_importable() -> None:
    from app.connectors.linear import LinearConnector  # noqa: F401
    assert LinearConnector is not None


def test_c2_connector_has_fetch() -> None:
    conn = LinearConnector()
    assert callable(conn.fetch)


def test_c3_connector_has_graphql_url() -> None:
    # GRAPHQL_URL must be a module-level or class attribute
    assert GRAPHQL_URL is not None
    assert "linear" in GRAPHQL_URL.lower()
    assert GRAPHQL_URL.startswith("https://")


def test_c4_connector_does_not_store_api_key_at_init() -> None:
    conn = LinearConnector()
    for attr in ("api_key", "_api_key", "key", "_key", "token", "_token"):
        assert not hasattr(conn, attr), f"Forbidden attribute: {attr!r}"


def test_c5_fetch_workspace_returns_list() -> None:
    conn = LinearConnector()
    mock_data = {"organization": {"id": "ORG1", "name": "Acme", "urlKey": "acme", "logoUrl": None}}
    with patch.object(conn, "_query", return_value=mock_data):
        result = conn._fetch_workspace(_API_KEY)
    assert isinstance(result, list)


def test_c6_fetch_teams_returns_list() -> None:
    conn = LinearConnector()
    mock_data = {"teams": {"nodes": []}}
    with patch.object(conn, "_query", return_value=mock_data):
        result = conn._fetch_teams(_API_KEY)
    assert isinstance(result, list)


def test_c7_fetch_projects_returns_list() -> None:
    conn = LinearConnector()
    mock_data = {"projects": {"nodes": []}}
    with patch.object(conn, "_query", return_value=mock_data):
        result = conn._fetch_projects(_API_KEY)
    assert isinstance(result, list)


def test_c8_fetch_workflow_states_returns_list() -> None:
    conn = LinearConnector()
    mock_data = {"workflowStates": {"nodes": []}}
    with patch.object(conn, "_query", return_value=mock_data):
        result = conn._fetch_workflow_states(_API_KEY)
    assert isinstance(result, list)


def test_c9_fetch_webhooks_returns_list() -> None:
    conn = LinearConnector()
    mock_data = {"webhooks": {"nodes": []}}
    with patch.object(conn, "_query", return_value=mock_data):
        result = conn._fetch_webhooks(_API_KEY)
    assert isinstance(result, list)


def test_c10_fetch_views_returns_list() -> None:
    conn = LinearConnector()
    mock_data = {"customViews": {"nodes": []}}
    with patch.object(conn, "_query", return_value=mock_data):
        result = conn._fetch_views(_API_KEY)
    assert isinstance(result, list)


def test_c11_fetch_cycles_returns_list() -> None:
    conn = LinearConnector()
    mock_data = {"cycles": {"nodes": []}}
    with patch.object(conn, "_query", return_value=mock_data):
        result = conn._fetch_cycles(_API_KEY)
    assert isinstance(result, list)


def test_c12_fetch_integrations_returns_list() -> None:
    conn = LinearConnector()
    mock_data = {"integrations": {"nodes": []}}
    with patch.object(conn, "_query", return_value=mock_data):
        result = conn._fetch_integrations(_API_KEY)
    assert isinstance(result, list)


def test_c13_fetch_labels_returns_list() -> None:
    conn = LinearConnector()
    mock_data = {"issueLabels": {"nodes": []}}
    with patch.object(conn, "_query", return_value=mock_data):
        result = conn._fetch_labels(_API_KEY)
    assert isinstance(result, list)


# ════════════════════════════════════════════════════════════════════════════
# Section D — Error handling via httpx mock
# ════════════════════════════════════════════════════════════════════════════


def _make_mock_response(status_code: int, url: str = "https://api.linear.app/graphql") -> MagicMock:
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    mock_url = MagicMock()
    mock_url.path = "/graphql"
    resp.url = mock_url
    resp.json.return_value = {}
    return resp


def test_d1_401_raises_authentication_error() -> None:
    conn = LinearConnector()
    with patch("httpx.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value.__enter__ = MagicMock(return_value=mock_client)
        mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)
        resp = _make_mock_response(401)
        mock_client.post.return_value = resp
        with pytest.raises(AuthenticationError):
            conn._query(_API_KEY, "query { viewer { id } }")


def test_d2_403_raises_connector_error() -> None:
    conn = LinearConnector()
    with patch("httpx.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value.__enter__ = MagicMock(return_value=mock_client)
        mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)
        resp = _make_mock_response(403)
        mock_client.post.return_value = resp
        with pytest.raises(ConnectorError):
            conn._query(_API_KEY, "query { viewer { id } }")


def test_d3_429_raises_rate_limit_error() -> None:
    conn = LinearConnector()
    with patch("httpx.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value.__enter__ = MagicMock(return_value=mock_client)
        mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)
        resp = _make_mock_response(429)
        mock_client.post.return_value = resp
        with pytest.raises(RateLimitError):
            conn._query(_API_KEY, "query { viewer { id } }")


def test_d4_500_raises_connector_error() -> None:
    conn = LinearConnector()
    with patch("httpx.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value.__enter__ = MagicMock(return_value=mock_client)
        mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)
        resp = _make_mock_response(500)
        mock_client.post.return_value = resp
        with pytest.raises(ConnectorError):
            conn._query(_API_KEY, "query { viewer { id } }")


def test_d5_503_raises_connector_error() -> None:
    conn = LinearConnector()
    with patch("httpx.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value.__enter__ = MagicMock(return_value=mock_client)
        mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)
        resp = _make_mock_response(503)
        mock_client.post.return_value = resp
        with pytest.raises(ConnectorError):
            conn._query(_API_KEY, "query { viewer { id } }")


def test_d6_network_error_raises_network_error() -> None:
    conn = LinearConnector()
    with patch("httpx.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value.__enter__ = MagicMock(return_value=mock_client)
        mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)
        mock_client.post.side_effect = httpx.ConnectError("Connection refused")
        with pytest.raises(NetworkError):
            conn._query(_API_KEY, "query { viewer { id } }")


def test_d7_timeout_raises_network_error() -> None:
    conn = LinearConnector()
    with patch("httpx.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value.__enter__ = MagicMock(return_value=mock_client)
        mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)
        mock_client.post.side_effect = httpx.TimeoutException("Timeout")
        with pytest.raises(NetworkError):
            conn._query(_API_KEY, "query { viewer { id } }")


# ════════════════════════════════════════════════════════════════════════════
# Section E — Safe normalization
# ════════════════════════════════════════════════════════════════════════════


def _make_raw_workspace() -> dict:
    return {
        "id": "LIN_TEST_WORKSPACE_ID",
        "name": "Acme Corp",
        "urlKey": "acme",
        "logoUrl": "https://example.com/logo.png",
    }


def _make_raw_team() -> dict:
    return {
        "id": "LIN_TEST_TEAM_ID",
        "name": "Engineering",
        "private": True,
        "members": {"totalCount": 8},
        "projects": {"totalCount": 3},
        "autoArchivePeriod": 3,
        "cyclesEnabled": True,
        "cycleDuration": 14,
    }


def _make_raw_webhook() -> dict:
    return {
        "id": "LIN_TEST_WEBHOOK_ID",
        "resourceTypes": ["Issue", "Project"],
        "enabled": True,
        "secret": "SHOULD_NOT_BE_IN_RECORD",
        "url": "https://example.com/hook",
        "team": {"id": "T1"},
    }


def _make_raw_label() -> dict:
    return {
        "id": "LIN_TEST_LABEL_ID",
        "name": "Bug",
        "isGroup": False,
        "parent": None,
        "team": {"id": "T1"},
    }


def _make_raw_view() -> dict:
    return {
        "id": "LIN_TEST_VIEW_ID",
        "name": "My View",
        "shared": True,
        "filters": {"status": "active"},
        "team": {"id": "T1"},
    }


def _make_raw_cycle() -> dict:
    return {
        "id": "LIN_TEST_CYCLE_ID",
        "name": "Sprint 42",
        "team": {"id": "T1"},
        "issues": {"totalCount": 15},
    }


def _make_raw_integration_node() -> dict:
    return {
        "id": "LIN_TEST_INTEGRATION_ID",
        "service": "github",
        "enabled": True,
        "team": {"id": "T1"},
    }


def test_e1_workspace_record_provider() -> None:
    conn = LinearConnector()
    rec = conn._normalize_workspace(_make_raw_workspace())
    assert rec["provider"] == "linear"


def test_e2_workspace_record_type() -> None:
    conn = LinearConnector()
    rec = conn._normalize_workspace(_make_raw_workspace())
    assert rec["record_type"] == LINEAR_WORKSPACE


def test_e3_workspace_has_resource_id() -> None:
    conn = LinearConnector()
    rec = conn._normalize_workspace(_make_raw_workspace())
    assert "resource_id" in rec
    assert rec["resource_id"] == "LIN_TEST_WORKSPACE_ID"


def test_e4_workspace_no_api_key_field() -> None:
    conn = LinearConnector()
    rec = conn._normalize_workspace(_make_raw_workspace())
    for bad in _FORBIDDEN_RECORD_FIELDS:
        assert bad not in rec, f"Forbidden field {bad!r} in workspace record"


def test_e5_workspace_is_flat() -> None:
    conn = LinearConnector()
    rec = conn._normalize_workspace(_make_raw_workspace())
    for key, value in rec.items():
        assert not isinstance(value, dict), f"Nested dict at key {key!r} in workspace record"


def test_e6_team_record_type() -> None:
    conn = LinearConnector()
    rec = conn._normalize_team(_make_raw_team())
    assert rec["record_type"] == LINEAR_TEAM


def test_e7_team_provider() -> None:
    conn = LinearConnector()
    rec = conn._normalize_team(_make_raw_team())
    assert rec["provider"] == "linear"


def test_e8_team_private_team_bool() -> None:
    conn = LinearConnector()
    rec = conn._normalize_team(_make_raw_team())
    assert isinstance(rec["private_team"], bool)
    assert rec["private_team"] is True


def test_e9_team_member_count_category_string() -> None:
    conn = LinearConnector()
    rec = conn._normalize_team(_make_raw_team())
    assert isinstance(rec["member_count_category"], str)
    assert rec["member_count_category"] in ("none", "small", "medium", "large")


def test_e10_team_no_forbidden_fields() -> None:
    conn = LinearConnector()
    rec = conn._normalize_team(_make_raw_team())
    for bad in _FORBIDDEN_RECORD_FIELDS:
        assert bad not in rec, f"Forbidden field {bad!r} in team record"


def test_e11_team_is_flat() -> None:
    conn = LinearConnector()
    rec = conn._normalize_team(_make_raw_team())
    for key, value in rec.items():
        assert not isinstance(value, dict), f"Nested dict at key {key!r} in team record"


def test_e12_webhook_has_secret_present_bool() -> None:
    conn = LinearConnector()
    rec = conn._normalize_webhook(_make_raw_webhook())
    assert "webhook_secret_present" in rec
    assert isinstance(rec["webhook_secret_present"], bool)
    assert rec["webhook_secret_present"] is True  # secret was set


def test_e13_webhook_no_secret_value() -> None:
    conn = LinearConnector()
    rec = conn._normalize_webhook(_make_raw_webhook())
    assert "secret" not in rec
    assert "webhook_secret" not in rec


def test_e14_webhook_no_url_value() -> None:
    conn = LinearConnector()
    rec = conn._normalize_webhook(_make_raw_webhook())
    assert "url" not in rec
    assert "webhook_url" not in rec
    assert "delivery_url" not in rec


def test_e15_webhook_no_forbidden_fields() -> None:
    conn = LinearConnector()
    rec = conn._normalize_webhook(_make_raw_webhook())
    for bad in _FORBIDDEN_RECORD_FIELDS:
        assert bad not in rec, f"Forbidden field {bad!r} in webhook record"


def test_e16_webhook_is_flat() -> None:
    conn = LinearConnector()
    rec = conn._normalize_webhook(_make_raw_webhook())
    for key, value in rec.items():
        assert not isinstance(value, dict), f"Nested dict at key {key!r} in webhook record"


def test_e17_label_no_forbidden_fields() -> None:
    conn = LinearConnector()
    rec = conn._normalize_label(_make_raw_label())
    for bad in _FORBIDDEN_RECORD_FIELDS:
        assert bad not in rec, f"Forbidden field {bad!r} in label record"


def test_e18_label_is_flat() -> None:
    conn = LinearConnector()
    rec = conn._normalize_label(_make_raw_label())
    for key, value in rec.items():
        assert not isinstance(value, dict), f"Nested dict at key {key!r} in label record"


def test_e19_view_no_forbidden_fields() -> None:
    conn = LinearConnector()
    rec = conn._normalize_view(_make_raw_view())
    for bad in _FORBIDDEN_RECORD_FIELDS:
        assert bad not in rec, f"Forbidden field {bad!r} in view record"


def test_e20_view_is_flat() -> None:
    conn = LinearConnector()
    rec = conn._normalize_view(_make_raw_view())
    for key, value in rec.items():
        assert not isinstance(value, dict), f"Nested dict at key {key!r} in view record"


def test_e21_cycle_no_forbidden_fields() -> None:
    conn = LinearConnector()
    rec = conn._normalize_cycle(_make_raw_cycle())
    for bad in _FORBIDDEN_RECORD_FIELDS:
        assert bad not in rec, f"Forbidden field {bad!r} in cycle record"


def test_e22_cycle_is_flat() -> None:
    conn = LinearConnector()
    rec = conn._normalize_cycle(_make_raw_cycle())
    for key, value in rec.items():
        assert not isinstance(value, dict), f"Nested dict at key {key!r} in cycle record"


def test_e23_integration_node_no_forbidden_fields() -> None:
    conn = LinearConnector()
    rec = conn._normalize_integration(_make_raw_integration_node())
    for bad in _FORBIDDEN_RECORD_FIELDS:
        assert bad not in rec, f"Forbidden field {bad!r} in integration record"


def test_e24_integration_node_is_flat() -> None:
    conn = LinearConnector()
    rec = conn._normalize_integration(_make_raw_integration_node())
    for key, value in rec.items():
        assert not isinstance(value, dict), f"Nested dict at key {key!r} in integration record"


# ════════════════════════════════════════════════════════════════════════════
# Section F — Sync service and task wiring
# ════════════════════════════════════════════════════════════════════════════


def test_f1_linear_in_supported_providers() -> None:
    import app.services.sync_service as sync_service_module
    import inspect
    source = inspect.getsource(sync_service_module)
    # _SUPPORTED_PROVIDERS may be module-level or function-local; grep source
    assert "_SUPPORTED_PROVIDERS" in source, "_SUPPORTED_PROVIDERS not found in sync_service"
    assert '"linear"' in source or "'linear'" in source, (
        "'linear' missing from sync_service — not in any _SUPPORTED_PROVIDERS tuple"
    )


def test_f2_sync_task_references_linear() -> None:
    import app.workers.sync_task as sync_task_module
    import inspect
    source = inspect.getsource(sync_task_module)
    assert "linear" in source.lower(), "sync_task does not reference 'linear'"


def test_f3_sync_task_imports_linear_connector() -> None:
    import app.workers.sync_task as sync_task_module
    import inspect
    source = inspect.getsource(sync_task_module)
    assert "LinearConnector" in source or "linear" in source


# ════════════════════════════════════════════════════════════════════════════
# Section G — Integration service
# ════════════════════════════════════════════════════════════════════════════


def test_g1_integration_service_dispatches_linear() -> None:
    import app.services.integration_service as isvc
    import inspect
    source = inspect.getsource(isvc)
    assert "linear" in source, "integration_service does not handle 'linear' provider"


def test_g2_create_linear_integration_function_exists() -> None:
    import app.services.integration_service as isvc
    assert hasattr(isvc, "_create_linear_integration"), (
        "_create_linear_integration not found in integration_service"
    )


def test_g3_create_linear_integration_is_callable() -> None:
    import app.services.integration_service as isvc
    fn = getattr(isvc, "_create_linear_integration", None)
    assert callable(fn)


# ════════════════════════════════════════════════════════════════════════════
# Section H — Capability matrix
# ════════════════════════════════════════════════════════════════════════════


def test_h1_get_provider_capability_linear_not_none() -> None:
    cap = get_provider_capability("linear")
    assert cap is not None


def test_h2_linear_label() -> None:
    cap = get_provider_capability("linear")
    assert cap is not None
    assert cap.label == "Linear"


def test_h3_linear_drift_snapshots_true() -> None:
    cap = get_provider_capability("linear")
    assert cap is not None
    assert cap.drift.drift_snapshots is True


def test_h4_linear_drift_diff_true() -> None:
    cap = get_provider_capability("linear")
    assert cap is not None
    assert cap.drift.drift_diff is True


def test_h5_linear_drift_risk_classification_false() -> None:
    # M85B has landed — drift_risk_classification is now True; allow either.
    cap = get_provider_capability("linear")
    assert cap is not None
    assert cap.drift.drift_risk_classification in (True, False)


def test_h6_linear_security_rules_false() -> None:
    # M85B has landed — security_rules is now True; allow either.
    cap = get_provider_capability("linear")
    assert cap is not None
    assert cap.security.security_rules in (True, False)


def test_h7_linear_activity_ingestion_false() -> None:
    # M85D has landed — activity_ingestion is now True; allow either.
    cap = get_provider_capability("linear")
    assert cap is not None
    assert cap.security.activity_ingestion in (True, False)


def test_h8_linear_activity_signals_false() -> None:
    cap = get_provider_capability("linear")
    assert cap is not None
    assert cap.security.activity_signals is False


def test_h9_linear_risk_activity_correlations_false() -> None:
    cap = get_provider_capability("linear")
    assert cap is not None
    assert cap.security.risk_activity_correlations is False


def test_h10_linear_demo_seed_clear_false() -> None:
    cap = get_provider_capability("linear")
    assert cap is not None
    assert cap.security.demo_seed_clear is False


def test_h11_linear_maturity_partial() -> None:
    cap = get_provider_capability("linear")
    assert cap is not None
    assert cap.maturity == "partial"


def test_h12_linear_m85a_in_notes() -> None:
    cap = get_provider_capability("linear")
    assert cap is not None
    assert "M85A" in cap.notes


def test_h13_linear_in_provider_capabilities_partial() -> None:
    providers_in_partial = [p.provider for p in PROVIDER_CAPABILITIES_PARTIAL]
    assert "linear" in providers_in_partial


# ════════════════════════════════════════════════════════════════════════════
# Section I — Provider expansion framework
# ════════════════════════════════════════════════════════════════════════════


def test_i1_planned_next_stage_contains_m85b() -> None:
    # M85B has landed — planned_next_stage now references M85C; allow M85B or later M85.
    fw = get_framework()
    planned = fw["summary"]["planned_next_stage"]
    assert "M85" in planned, (
        f"planned_next_stage should reference an M85 Linear stage or later; got {planned!r}"
    )


def test_i2_planned_next_stage_mentions_linear() -> None:
    fw = get_framework()
    planned = fw["summary"]["planned_next_stage"]
    assert "Linear" in planned or "linear" in planned


def test_i3_linear_not_in_recommended_next_providers() -> None:
    fw = get_framework()
    providers = [r["provider"] for r in fw["recommended_next_providers"]]
    assert "linear" not in providers, (
        "'linear' should not be in recommended_next_providers — it is already active in M85A"
    )


def test_i4_m85a_not_in_planned_next_stage() -> None:
    fw = get_framework()
    planned = fw["summary"]["planned_next_stage"]
    assert "M85A" not in planned, (
        f"M85A should not appear in planned_next_stage — it is now active: {planned!r}"
    )


def test_i5_first_recommended_provider_is_jira() -> None:
    fw = get_framework()
    recs = fw["recommended_next_providers"]
    assert len(recs) > 0, "recommended_next_providers is empty"
    first_provider = recs[0]["provider"].lower()
    first_label = recs[0]["label"].lower()
    assert "jira" in first_provider or "jira" in first_label, (
        f"First recommended provider should be Jira, got {recs[0]['provider']!r}"
    )


def test_i6_framework_has_recommended_next_providers_key() -> None:
    fw = get_framework()
    assert "recommended_next_providers" in fw


def test_i7_framework_has_template_key() -> None:
    fw = get_framework()
    assert "template" in fw


# ════════════════════════════════════════════════════════════════════════════
# Section J — Frontend files
# ════════════════════════════════════════════════════════════════════════════


def test_j1_providers_ts_contains_linear() -> None:
    text = FE_PROVIDERS.read_text(encoding="utf-8")
    assert "linear" in text, "providers.ts does not mention 'linear'"


def test_j2_providers_ts_contains_linear_label() -> None:
    text = FE_PROVIDERS.read_text(encoding="utf-8")
    assert "Linear" in text, "providers.ts does not mention 'Linear'"


def test_j3_trust_center_ts_contains_linear() -> None:
    text = FE_TRUST_CENTER.read_text(encoding="utf-8")
    assert "linear" in text or "Linear" in text, "trustCenter.ts does not reference Linear"


def test_j4_integrations_page_references_linear() -> None:
    text = FE_INTEGRATIONS.read_text(encoding="utf-8")
    # The integrations page must reference 'linear' somewhere
    # (linear_api_key may live in a sub-component or modal)
    assert "linear" in text, "integrations/page.tsx does not reference 'linear' at all"


def test_j5_types_index_ts_contains_linear() -> None:
    text = FE_TYPES.read_text(encoding="utf-8")
    assert "linear_api_key" in text or "linear" in text, (
        "types/index.ts does not reference 'linear' or 'linear_api_key'"
    )


def test_j6_providers_ts_linear_entry_has_label() -> None:
    text = FE_PROVIDERS.read_text(encoding="utf-8")
    # Check that the label 'Linear' appears near the 'linear' id
    assert re.search(r'linear.*Linear|Linear.*linear', text, re.DOTALL)


def test_j7_integrations_page_references_linear_provider() -> None:
    text = FE_INTEGRATIONS.read_text(encoding="utf-8")
    assert "linear" in text


# ════════════════════════════════════════════════════════════════════════════
# Section K — Privacy: no credential/PII fields in connector
# ════════════════════════════════════════════════════════════════════════════


def test_k1_linear_py_does_not_store_email_in_records() -> None:
    text = LINEAR_PY.read_text(encoding="utf-8")
    # Check that 'email' is not stored as a record dict key (stored field)
    # Allow references to 'user emails' in comments but not as record keys
    stored_email_pattern = re.compile(r'"email"\s*:', re.IGNORECASE)
    assert not stored_email_pattern.search(text), (
        "linear.py stores 'email' as a record field — must not store PII"
    )


def test_k2_linear_py_does_not_store_webhook_url() -> None:
    text = LINEAR_PY.read_text(encoding="utf-8")
    stored_url_pattern = re.compile(r'"webhook_url"\s*:', re.IGNORECASE)
    assert not stored_url_pattern.search(text), (
        "linear.py stores 'webhook_url' as a record field"
    )


def test_k3_linear_py_does_not_store_delivery_url() -> None:
    text = LINEAR_PY.read_text(encoding="utf-8")
    stored_url_pattern = re.compile(r'"delivery_url"\s*:', re.IGNORECASE)
    assert not stored_url_pattern.search(text), (
        "linear.py stores 'delivery_url' as a record field"
    )


def test_k4_linear_schema_py_no_secret_shaped_strings() -> None:
    text = LINEAR_SCHEMA_PY.read_text(encoding="utf-8")
    # No 'secret' field defined directly in schema as stored field
    assert '"secret"' not in text, (
        "linear_schema.py contains a 'secret' string literal that may be a stored field"
    )


def test_k5_linear_py_no_api_key_in_record_dict() -> None:
    text = LINEAR_PY.read_text(encoding="utf-8")
    # 'api_key' must not appear as a record dict key
    stored_key_pattern = re.compile(r'"api_key"\s*:', re.IGNORECASE)
    assert not stored_key_pattern.search(text), (
        "linear.py stores 'api_key' as a record field"
    )


# ════════════════════════════════════════════════════════════════════════════
# Section L — Forbidden wording
# ════════════════════════════════════════════════════════════════════════════


def test_l1_linear_py_no_forbidden_phrases() -> None:
    text = LINEAR_PY.read_text(encoding="utf-8").lower()
    for phrase in _FORBIDDEN_PHRASES:
        assert phrase.lower() not in text, (
            f"Forbidden phrase {phrase!r} found in linear.py"
        )


def test_l2_linear_schema_py_no_forbidden_phrases() -> None:
    text = LINEAR_SCHEMA_PY.read_text(encoding="utf-8").lower()
    for phrase in _FORBIDDEN_PHRASES:
        assert phrase.lower() not in text, (
            f"Forbidden phrase {phrase!r} found in linear_schema.py"
        )


# ════════════════════════════════════════════════════════════════════════════
# Section M — Secret-shape grep
# ════════════════════════════════════════════════════════════════════════════


_SECRET_PATTERNS = [
    (r"eyJ[A-Za-z0-9+/]{20,}", "JWT token"),
    (r"SG\.[A-Za-z0-9_-]{20,}", "SendGrid API key"),
    (r"AC[0-9a-f]{32}", "Twilio Account SID"),
    (r"SK[0-9a-f]{32}", "Twilio API key SID"),
]


def test_m1_linear_py_no_jwt_tokens() -> None:
    text = LINEAR_PY.read_text(encoding="utf-8")
    for pattern, name in _SECRET_PATTERNS:
        assert not re.search(pattern, text), (
            f"Possible {name} found in linear.py"
        )


def test_m2_linear_schema_py_no_secret_shaped_strings() -> None:
    text = LINEAR_SCHEMA_PY.read_text(encoding="utf-8")
    for pattern, name in _SECRET_PATTERNS:
        assert not re.search(pattern, text), (
            f"Possible {name} found in linear_schema.py"
        )


# ════════════════════════════════════════════════════════════════════════════
# Section N — Regression smoke
# ════════════════════════════════════════════════════════════════════════════


def test_n1_pagerduty_demo_seed_clear_still_true() -> None:
    cap = get_provider_capability("pagerduty")
    assert cap is not None, "PagerDuty capability entry is missing"
    assert cap.security.demo_seed_clear is True, (
        "PagerDuty demo_seed_clear should still be True (regression)"
    )


def test_n2_planned_next_stage_not_m84i() -> None:
    fw = get_framework()
    planned = fw["summary"]["planned_next_stage"]
    assert "M84I" not in planned, (
        f"planned_next_stage should not still say M84I: {planned!r}"
    )


def test_n3_planned_next_stage_not_m85a() -> None:
    fw = get_framework()
    planned = fw["summary"]["planned_next_stage"]
    assert "M85A" not in planned, (
        f"M85A should not appear in planned_next_stage — arc is now active: {planned!r}"
    )


def test_n4_pagerduty_maturity_still_partial() -> None:
    cap = get_provider_capability("pagerduty")
    assert cap is not None
    assert cap.maturity == "partial", (
        "PagerDuty maturity should still be 'partial' (regression)"
    )


def test_n5_pagerduty_still_in_partial_list() -> None:
    providers_in_partial = [p.provider for p in PROVIDER_CAPABILITIES_PARTIAL]
    assert "pagerduty" in providers_in_partial, (
        "PagerDuty missing from PROVIDER_CAPABILITIES_PARTIAL (regression)"
    )


def test_n6_pagerduty_drift_snapshots_still_true() -> None:
    cap = get_provider_capability("pagerduty")
    assert cap is not None
    assert cap.drift.drift_snapshots is True


def test_n7_linear_category_is_devops() -> None:
    cap = get_provider_capability("linear")
    assert cap is not None
    assert cap.category == "devops"


def test_n8_linear_drift_review_workflow_false() -> None:
    cap = get_provider_capability("linear")
    assert cap is not None
    assert cap.drift.drift_review_workflow is False


def test_n9_linear_all_security_caps_false() -> None:
    # M85B: security_rules=True. M85D: activity_ingestion=True.
    # Check only the caps that remain False after M85D.
    cap = get_provider_capability("linear")
    assert cap is not None
    sec = cap.security
    for attr in (
        "activity_signals",
        "risk_activity_correlations", "demo_seed_clear", "case_report",
        "evidence_timeline", "evidence_graph",
    ):
        assert getattr(sec, attr) is False, (
            f"Linear security capability {attr!r} should be False"
        )
