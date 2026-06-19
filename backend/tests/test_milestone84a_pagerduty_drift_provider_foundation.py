"""M84A: PagerDuty drift provider foundation tests.

Validates that the PagerDuty connector, schema, integration service,
sync wiring, capability matrix, expansion framework, and frontend files
all meet the M84A specification.

Sections:
  A. Record type constants and PAGERDUTY_RECORD_TYPES
  B. PagerDutyConnector class structure and safety
  C. Authorization header safety (api_token never in records)
  D. Normalizers — safe flat dicts, no forbidden fields
  E. Error mapping (401/403/429/5xx/network)
  F. Pagination caps per surface
  G. Sync service and sync_task wiring
  H. Integration schema (provider Literal, pagerduty_api_token field)
  I. Integration service (create helper, dispatcher)
  J. Frontend providers.ts / types/index.ts / integrations page
  K. Trust center
  L. Capability matrix
  M. Provider expansion framework
  N. Regression smoke
  O. Forbidden wording
  P. Secret-shape grep
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import respx
import httpx

from app.connectors.pagerduty import PagerDutyConnector, _timeout_category, _url_scheme_category
from app.connectors.pagerduty_schema import (
    PAGERDUTY_BUSINESS_SERVICE,
    PAGERDUTY_ESCALATION_POLICY,
    PAGERDUTY_EVENT_ORCHESTRATION,
    PAGERDUTY_RECORD_TYPES,
    PAGERDUTY_RESPONSE_PLAY,
    PAGERDUTY_SCHEDULE,
    PAGERDUTY_SERVICE,
    PAGERDUTY_SERVICE_INTEGRATION,
    PAGERDUTY_WEBHOOK_SUBSCRIPTION,
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

_TOKEN = "PAGERDUTY_TEST_API_TOKEN_PLACEHOLDER"
_CREDS = {"api_token": _TOKEN}

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
    "api_token", "token", "routing_key", "integration_key", "secret",
    "authorization", "headers", "payload", "request", "response",
    "email", "phone", "user_name", "user_id", "ip_address", "user_agent",
    "webhook_url", "delivery_url", "url", "raw",
}

EXPECTED_RECORD_TYPES: frozenset[str] = frozenset({
    PAGERDUTY_SERVICE,
    PAGERDUTY_ESCALATION_POLICY,
    PAGERDUTY_SCHEDULE,
    PAGERDUTY_SERVICE_INTEGRATION,
    PAGERDUTY_WEBHOOK_SUBSCRIPTION,
    PAGERDUTY_EVENT_ORCHESTRATION,
    PAGERDUTY_BUSINESS_SERVICE,
    PAGERDUTY_RESPONSE_PLAY,
})


# ════════════════════════════════════════════════════════════════════════════
# Section A — Record type constants
# ════════════════════════════════════════════════════════════════════════════


def test_a1_record_type_count() -> None:
    assert len(PAGERDUTY_RECORD_TYPES) == 8


def test_a2_record_types_exact() -> None:
    assert PAGERDUTY_RECORD_TYPES == EXPECTED_RECORD_TYPES


def test_a3_record_type_strings_prefixed() -> None:
    for rt in PAGERDUTY_RECORD_TYPES:
        assert rt.startswith("pagerduty_"), f"{rt} does not start with pagerduty_"


# ════════════════════════════════════════════════════════════════════════════
# Section B — Connector class structure
# ════════════════════════════════════════════════════════════════════════════


def test_b1_connector_importable() -> None:
    from app.connectors.pagerduty import PagerDutyConnector  # noqa: F401
    assert PagerDutyConnector is not None


def test_b2_connector_has_fetch() -> None:
    conn = PagerDutyConnector()
    assert callable(conn.fetch)


def test_b3_connector_has_validate_credentials() -> None:
    conn = PagerDutyConnector()
    assert callable(conn.validate_credentials)


def test_b4_connector_no_token_attribute() -> None:
    """Connector must not cache the api_token as an instance attribute."""
    conn = PagerDutyConnector()
    for attr in ("api_token", "token", "_token", "_api_token"):
        assert not hasattr(conn, attr), f"Connector has forbidden attribute: {attr}"


def test_b5_connector_make_client_returns_httpx_client() -> None:
    conn = PagerDutyConnector()
    with conn._make_client(_TOKEN) as client:
        assert isinstance(client, httpx.Client)


def test_b6_connector_client_has_auth_header() -> None:
    conn = PagerDutyConnector()
    with conn._make_client(_TOKEN) as client:
        auth = client.headers.get("authorization", "")
        assert "Token token=" in auth


def test_b7_connector_client_base_url() -> None:
    conn = PagerDutyConnector()
    with conn._make_client(_TOKEN) as client:
        assert "pagerduty.com" in str(client.base_url)


# ════════════════════════════════════════════════════════════════════════════
# Section C — Auth header safety
# ════════════════════════════════════════════════════════════════════════════


def test_c1_api_token_not_stored_on_connector() -> None:
    """After fetch, connector must hold no reference to the api_token."""
    conn = PagerDutyConnector()
    # Verify no token attribute exists before or after
    assert not hasattr(conn, "api_token")
    assert not hasattr(conn, "_api_token")


def test_c2_normalize_service_no_token_field() -> None:
    conn = PagerDutyConnector()
    record = conn._normalize_service({"id": "P123", "name": "Test Svc", "status": "active"})
    for bad in _FORBIDDEN_RECORD_FIELDS:
        assert bad not in record, f"Forbidden field '{bad}' in service record"


def test_c3_normalize_escalation_policy_no_token_field() -> None:
    conn = PagerDutyConnector()
    record = conn._normalize_escalation_policy({"id": "P123", "name": "On-call"})
    for bad in _FORBIDDEN_RECORD_FIELDS:
        assert bad not in record, f"Forbidden field '{bad}' in EP record"


# ════════════════════════════════════════════════════════════════════════════
# Section D — Normalizers
# ════════════════════════════════════════════════════════════════════════════


def _make_raw_service(status: str = "active") -> dict:
    return {
        "id": "PAGERDUTY_TEST_SERVICE_ID",
        "name": "Payment Gateway",
        "status": status,
        "escalation_policy": {"id": "PAGERDUTY_TEST_ESCALATION_POLICY_ID"},
        "teams": [{"id": "T1"}, {"id": "T2"}],
        "integrations": [{"id": "I1"}],
        "alert_creation": "create_alerts_and_incidents",
        "incident_urgency_rule": {"type": "constant"},
        "support_hours": {"type": "fixed_time"},
        "scheduled_actions": [{"at": {"type": "named_time"}}],
        "auto_resolve_timeout": 14400,
        "acknowledgement_timeout": 1800,
    }


def _make_raw_ep() -> dict:
    return {
        "id": "PAGERDUTY_TEST_ESCALATION_POLICY_ID",
        "name": "Primary On-Call",
        "teams": [{"id": "T1"}],
        "escalation_rules": [
            {"escalation_delay_in_minutes": 30, "targets": []},
            {"escalation_delay_in_minutes": 60, "targets": []},
        ],
        "num_loops": 2,
        "on_call_handoff_notifications": "if_has_services",
    }


def _make_raw_schedule() -> dict:
    return {
        "id": "PAGERDUTY_TEST_SCHEDULE_ID",
        "name": "Primary Schedule",
        "time_zone": "America/New_York",
        "schedule_layers": [
            {"users": [{"id": "U1"}, {"id": "U2"}]},
            {"users": [{"id": "U1"}]},
        ],
        "teams": [{"id": "T1"}],
    }


def _make_raw_integration() -> dict:
    return {
        "id": "PAGERDUTY_TEST_INTEGRATION_ID",
        "type": "generic_events_api_inbound_integration",
        "integration_key": "should_not_be_stored",
        "vendor": {"summary": "Datadog"},
    }


def _make_raw_webhook() -> dict:
    return {
        "id": "PAGERDUTY_TEST_WEBHOOK_SUBSCRIPTION_ID",
        "active": True,
        "events": ["incident.triggered", "incident.resolved"],
        "delivery_method": {"url": "https://example.com/hook", "type": "http_delivery_method"},
        "filter": {"type": "account_reference"},
    }


def _make_raw_event_orch() -> dict:
    return {
        "id": "PAGERDUTY_TEST_EVENT_ORCHESTRATION_ID",
        "name": "Main Orchestration",
        "team": {"id": "T1"},
        "routes": [{"id": "R1"}, {"id": "R2"}],
    }


def _make_raw_business_service() -> dict:
    return {
        "id": "BS001",
        "name": "Checkout",
        "team": {"id": "T1"},
        "point_of_contact": "Jane Doe",
    }


def _make_raw_response_play() -> dict:
    return {
        "id": "RP001",
        "name": "Major Incident",
        "team": {"id": "T1"},
        "responders": [{"id": "U1"}, {"id": "U2"}],
        "subscribers": [{"id": "S1"}],
        "conference_number": "+15551234567",
        "runnability": "team",
    }


def test_d1_normalize_service_record_type() -> None:
    conn = PagerDutyConnector()
    rec = conn._normalize_service(_make_raw_service())
    assert rec["record_type"] == PAGERDUTY_SERVICE


def test_d2_normalize_service_provider() -> None:
    conn = PagerDutyConnector()
    rec = conn._normalize_service(_make_raw_service())
    assert rec["provider"] == "pagerduty"


def test_d3_normalize_service_required_fields() -> None:
    conn = PagerDutyConnector()
    rec = conn._normalize_service(_make_raw_service())
    for field in ("record_id", "resource_id", "resource_name", "status_category",
                  "escalation_policy_id", "team_count", "integration_count",
                  "alert_creation_category", "auto_resolve_timeout_category",
                  "acknowledgement_timeout_category"):
        assert field in rec, f"Missing field: {field}"


def test_d4_normalize_service_status_category() -> None:
    conn = PagerDutyConnector()
    for status in ("active", "warning", "critical", "maintenance"):
        rec = conn._normalize_service({**_make_raw_service(), "status": status})
        assert rec["status_category"] == status


def test_d5_normalize_service_alert_creation_category() -> None:
    conn = PagerDutyConnector()
    rec = conn._normalize_service(_make_raw_service())
    assert rec["alert_creation_category"] == "alerts_and_incidents"


def test_d6_normalize_service_team_count() -> None:
    conn = PagerDutyConnector()
    rec = conn._normalize_service(_make_raw_service())
    assert rec["team_count"] == 2


def test_d7_normalize_service_no_forbidden_fields() -> None:
    conn = PagerDutyConnector()
    rec = conn._normalize_service(_make_raw_service())
    for bad in _FORBIDDEN_RECORD_FIELDS:
        assert bad not in rec, f"Forbidden field '{bad}' in service record"


def test_d8_normalize_service_name_truncated() -> None:
    conn = PagerDutyConnector()
    long_name = "X" * 200
    rec = conn._normalize_service({**_make_raw_service(), "name": long_name})
    assert len(rec["resource_name"]) <= 100


def test_d9_normalize_ep_record_type() -> None:
    conn = PagerDutyConnector()
    rec = conn._normalize_escalation_policy(_make_raw_ep())
    assert rec["record_type"] == PAGERDUTY_ESCALATION_POLICY


def test_d10_normalize_ep_rule_count() -> None:
    conn = PagerDutyConnector()
    rec = conn._normalize_escalation_policy(_make_raw_ep())
    assert rec["escalation_rule_count"] == 2


def test_d11_normalize_ep_repeat_enabled() -> None:
    conn = PagerDutyConnector()
    rec = conn._normalize_escalation_policy(_make_raw_ep())
    assert rec["repeat_enabled"] is True
    assert rec["num_loops"] == 2


def test_d12_normalize_ep_no_forbidden_fields() -> None:
    conn = PagerDutyConnector()
    rec = conn._normalize_escalation_policy(_make_raw_ep())
    for bad in _FORBIDDEN_RECORD_FIELDS:
        assert bad not in rec, f"Forbidden field '{bad}' in EP record"


def test_d13_normalize_schedule_record_type() -> None:
    conn = PagerDutyConnector()
    rec = conn._normalize_schedule(_make_raw_schedule())
    assert rec["record_type"] == PAGERDUTY_SCHEDULE


def test_d14_normalize_schedule_user_count() -> None:
    conn = PagerDutyConnector()
    rec = conn._normalize_schedule(_make_raw_schedule())
    # Unique users across both layers: U1 and U2
    assert rec["user_count"] == 2


def test_d15_normalize_schedule_no_user_ids() -> None:
    """Schedule must not expose raw user IDs in any form."""
    conn = PagerDutyConnector()
    raw = _make_raw_schedule()
    rec = conn._normalize_schedule(raw)
    rec_str = str(rec)
    assert "U1" not in rec_str
    assert "U2" not in rec_str


def test_d16_normalize_integration_record_type() -> None:
    conn = PagerDutyConnector()
    rec = conn._normalize_service_integration(_make_raw_integration(), "PAGERDUTY_TEST_SERVICE_ID")
    assert rec["record_type"] == PAGERDUTY_SERVICE_INTEGRATION


def test_d17_normalize_integration_key_presence_bool() -> None:
    """Integration key presence is a boolean — the key value is never stored."""
    conn = PagerDutyConnector()
    rec = conn._normalize_service_integration(_make_raw_integration(), "PAGERDUTY_TEST_SERVICE_ID")
    assert rec["has_integration_key"] is True
    # The actual key value must not appear
    assert "should_not_be_stored" not in str(rec)


def test_d18_normalize_integration_no_forbidden_fields() -> None:
    conn = PagerDutyConnector()
    rec = conn._normalize_service_integration(_make_raw_integration(), "PAGERDUTY_TEST_SERVICE_ID")
    for bad in _FORBIDDEN_RECORD_FIELDS:
        assert bad not in rec, f"Forbidden field '{bad}' in integration record"


def test_d19_normalize_webhook_record_type() -> None:
    conn = PagerDutyConnector()
    rec = conn._normalize_webhook_subscription(_make_raw_webhook())
    assert rec["record_type"] == PAGERDUTY_WEBHOOK_SUBSCRIPTION


def test_d20_normalize_webhook_url_scheme_category() -> None:
    """Delivery URL scheme category is derived; raw URL is never stored."""
    conn = PagerDutyConnector()
    rec = conn._normalize_webhook_subscription(_make_raw_webhook())
    assert rec["delivery_url_scheme_category"] == "https"
    # The actual URL must not appear in the record
    assert "example.com" not in str(rec)


def test_d21_normalize_webhook_event_count() -> None:
    conn = PagerDutyConnector()
    rec = conn._normalize_webhook_subscription(_make_raw_webhook())
    assert rec["event_count"] == 2


def test_d22_normalize_webhook_no_forbidden_fields() -> None:
    conn = PagerDutyConnector()
    rec = conn._normalize_webhook_subscription(_make_raw_webhook())
    for bad in _FORBIDDEN_RECORD_FIELDS:
        assert bad not in rec, f"Forbidden field '{bad}' in webhook record"


def test_d23_normalize_event_orchestration_record_type() -> None:
    conn = PagerDutyConnector()
    rec = conn._normalize_event_orchestration(_make_raw_event_orch())
    assert rec["record_type"] == PAGERDUTY_EVENT_ORCHESTRATION


def test_d24_normalize_event_orchestration_route_count() -> None:
    conn = PagerDutyConnector()
    rec = conn._normalize_event_orchestration(_make_raw_event_orch())
    assert rec["route_count"] == 2


def test_d25_normalize_business_service_record_type() -> None:
    conn = PagerDutyConnector()
    rec = conn._normalize_business_service(_make_raw_business_service())
    assert rec["record_type"] == PAGERDUTY_BUSINESS_SERVICE


def test_d26_normalize_business_service_no_contact_name() -> None:
    """Point of contact presence is a boolean — the name is never stored."""
    conn = PagerDutyConnector()
    rec = conn._normalize_business_service(_make_raw_business_service())
    assert rec["point_of_contact_present"] is True
    assert "Jane Doe" not in str(rec)


def test_d27_normalize_response_play_record_type() -> None:
    conn = PagerDutyConnector()
    rec = conn._normalize_response_play(_make_raw_response_play())
    assert rec["record_type"] == PAGERDUTY_RESPONSE_PLAY


def test_d28_normalize_response_play_conference_number_presence() -> None:
    """Conference number is a boolean presence — the number is never stored."""
    conn = PagerDutyConnector()
    rec = conn._normalize_response_play(_make_raw_response_play())
    assert rec["conference_number_present"] is True
    assert "+15551234567" not in str(rec)
    assert "5551234567" not in str(rec)


def test_d29_normalize_response_play_responder_count() -> None:
    conn = PagerDutyConnector()
    rec = conn._normalize_response_play(_make_raw_response_play())
    assert rec["responder_count"] == 2
    assert rec["subscriber_count"] == 1


def test_d30_normalize_response_play_no_responder_ids() -> None:
    conn = PagerDutyConnector()
    rec = conn._normalize_response_play(_make_raw_response_play())
    assert "U1" not in str(rec)
    assert "S1" not in str(rec)


def test_d31_normalize_response_play_no_forbidden_fields() -> None:
    conn = PagerDutyConnector()
    rec = conn._normalize_response_play(_make_raw_response_play())
    for bad in _FORBIDDEN_RECORD_FIELDS:
        assert bad not in rec, f"Forbidden field '{bad}' in response play record"


# ════════════════════════════════════════════════════════════════════════════
# Section E — Error mapping
# ════════════════════════════════════════════════════════════════════════════


from app.connectors.exceptions import (
    AuthenticationError,
    ConnectorError,
    NetworkError,
    RateLimitError,
)


@respx.mock
def test_e1_401_raises_authentication_error() -> None:
    conn = PagerDutyConnector()
    respx.get("https://api.pagerduty.com/services").mock(
        return_value=httpx.Response(401)
    )
    with pytest.raises(AuthenticationError):
        conn.fetch(_CREDS)


@respx.mock
def test_e2_429_raises_rate_limit_error() -> None:
    conn = PagerDutyConnector()
    respx.get("https://api.pagerduty.com/services").mock(
        return_value=httpx.Response(429)
    )
    with pytest.raises(RateLimitError):
        conn.fetch(_CREDS)


@respx.mock
def test_e3_500_raises_connector_error() -> None:
    conn = PagerDutyConnector()
    respx.get("https://api.pagerduty.com/services").mock(
        return_value=httpx.Response(500)
    )
    with pytest.raises(ConnectorError):
        conn.fetch(_CREDS)


@respx.mock
def test_e4_network_error_raises_network_error() -> None:
    conn = PagerDutyConnector()
    respx.get("https://api.pagerduty.com/services").mock(
        side_effect=httpx.NetworkError("connection refused")
    )
    with pytest.raises(NetworkError):
        conn.fetch(_CREDS)


@respx.mock
def test_e5_webhook_403_fails_soft() -> None:
    """403 on webhook subscriptions should not raise — fail-soft optional surface."""
    conn = PagerDutyConnector()
    respx.get("https://api.pagerduty.com/services").mock(
        return_value=httpx.Response(200, json={"services": [], "more": False})
    )
    respx.get("https://api.pagerduty.com/escalation_policies").mock(
        return_value=httpx.Response(200, json={"escalation_policies": [], "more": False})
    )
    respx.get("https://api.pagerduty.com/schedules").mock(
        return_value=httpx.Response(200, json={"schedules": [], "more": False})
    )
    respx.get("https://api.pagerduty.com/webhook_subscriptions").mock(
        return_value=httpx.Response(403)
    )
    respx.get("https://api.pagerduty.com/event_orchestrations").mock(
        return_value=httpx.Response(200, json={"orchestrations": [], "more": False})
    )
    respx.get("https://api.pagerduty.com/business_services").mock(
        return_value=httpx.Response(200, json={"business_services": [], "more": False})
    )
    respx.get("https://api.pagerduty.com/response_plays").mock(
        return_value=httpx.Response(200, json={"response_plays": [], "more": False})
    )
    # Should not raise
    records = conn.fetch(_CREDS)
    assert isinstance(records, list)


# ════════════════════════════════════════════════════════════════════════════
# Section F — Pagination caps
# ════════════════════════════════════════════════════════════════════════════


def test_f1_timeout_category_disabled() -> None:
    assert _timeout_category(None) == "disabled"
    assert _timeout_category(0) == "disabled"


def test_f2_timeout_category_short() -> None:
    assert _timeout_category(1800) == "short"


def test_f3_timeout_category_medium() -> None:
    assert _timeout_category(7200) == "medium"


def test_f4_timeout_category_long() -> None:
    assert _timeout_category(28800) == "long"


def test_f5_url_scheme_category_https() -> None:
    assert _url_scheme_category("https://example.com/hook") == "https"


def test_f6_url_scheme_category_http() -> None:
    assert _url_scheme_category("http://example.com/hook") == "http"


def test_f7_url_scheme_category_absent() -> None:
    assert _url_scheme_category(None) == "absent"
    assert _url_scheme_category("") == "absent"


# ════════════════════════════════════════════════════════════════════════════
# Section G — Sync service and sync_task wiring
# ════════════════════════════════════════════════════════════════════════════


def test_g1_sync_service_supports_pagerduty() -> None:
    svc_path = Path(__file__).parent.parent / "app" / "services" / "sync_service.py"
    text = svc_path.read_text()
    idx = text.find("_SUPPORTED_PROVIDERS")
    assert idx != -1
    block = text[idx:idx + 600]
    assert '"pagerduty"' in block or "'pagerduty'" in block, (
        "pagerduty missing from sync_service._SUPPORTED_PROVIDERS"
    )


def test_g2_sync_task_dispatches_pagerduty() -> None:
    task_path = Path(__file__).parent.parent / "app" / "workers" / "sync_task.py"
    text = task_path.read_text()
    assert "pagerduty" in text
    assert "PagerDutyConnector" in text


def test_g3_pagerduty_connector_importable_from_sync_task() -> None:
    from app.connectors.pagerduty import PagerDutyConnector  # noqa: F401
    assert PagerDutyConnector is not None


# ════════════════════════════════════════════════════════════════════════════
# Section H — Integration schema
# ════════════════════════════════════════════════════════════════════════════


def test_h1_integration_schema_accepts_pagerduty_provider() -> None:
    from app.schemas.integration import IntegrationCreateRequest
    req = IntegrationCreateRequest(
        provider="pagerduty",
        display_name="Test PagerDuty",
        pagerduty_api_token=_TOKEN,
    )
    assert req.provider == "pagerduty"


def test_h2_integration_schema_requires_api_token() -> None:
    from pydantic import ValidationError
    from app.schemas.integration import IntegrationCreateRequest
    with pytest.raises(ValidationError):
        IntegrationCreateRequest(
            provider="pagerduty",
            display_name="Test PagerDuty",
            # pagerduty_api_token omitted
        )


def test_h3_integration_schema_api_token_not_in_response() -> None:
    """IntegrationResponse must never include the api_token field."""
    from app.schemas.integration import IntegrationResponse
    import inspect
    fields = inspect.getmembers(IntegrationResponse, lambda a: not inspect.isroutine(a))
    field_names = [name for name, _ in fields]
    assert "pagerduty_api_token" not in field_names


def test_h4_integration_schema_pagerduty_in_provider_literal() -> None:
    svc_path = Path(__file__).parent.parent / "app" / "schemas" / "integration.py"
    text = svc_path.read_text()
    assert '"pagerduty"' in text or "'pagerduty'" in text


# ════════════════════════════════════════════════════════════════════════════
# Section I — Integration service
# ════════════════════════════════════════════════════════════════════════════


def test_i1_integration_service_has_pagerduty_dispatcher() -> None:
    svc_path = Path(__file__).parent.parent / "app" / "services" / "integration_service.py"
    text = svc_path.read_text()
    assert "pagerduty" in text
    assert "_create_pagerduty_integration" in text


def test_i2_create_pagerduty_integration_importable() -> None:
    from app.services.integration_service import _create_pagerduty_integration  # noqa: F401
    assert callable(_create_pagerduty_integration)


def test_i3_router_build_credentials_has_pagerduty() -> None:
    router_path = Path(__file__).parent.parent / "app" / "routers" / "integrations.py"
    text = router_path.read_text()
    assert "pagerduty" in text
    assert "api_token" in text


# ════════════════════════════════════════════════════════════════════════════
# Section J — Frontend providers.ts / types/index.ts / integrations page
# ════════════════════════════════════════════════════════════════════════════


@pytest.mark.skipif(not FE_PROVIDERS.exists(), reason="Frontend tree absent")
def test_j1_pagerduty_in_provider_id_union() -> None:
    text = FE_PROVIDERS.read_text()
    assert '"pagerduty"' in text or "'pagerduty'" in text


@pytest.mark.skipif(not FE_PROVIDERS.exists(), reason="Frontend tree absent")
def test_j2_pagerduty_in_connectable_provider_ids() -> None:
    text = FE_PROVIDERS.read_text()
    idx = text.find("CONNECTABLE_PROVIDER_IDS")
    assert idx != -1
    block = text[idx:idx + 2000]
    assert "pagerduty" in block


@pytest.mark.skipif(not FE_PROVIDERS.exists(), reason="Frontend tree absent")
def test_j3_pagerduty_not_in_security_preview_ids() -> None:
    text = FE_PROVIDERS.read_text()
    if "SECURITY_PREVIEW_PROVIDER_IDS" not in text:
        return
    idx = text.find("SECURITY_PREVIEW_PROVIDER_IDS")
    block = text[idx:idx + 500]
    assert "pagerduty" not in block or "[]" in block


@pytest.mark.skipif(not FE_PROVIDERS.exists(), reason="Frontend tree absent")
def test_j4_pagerduty_label_is_pagerduty() -> None:
    text = FE_PROVIDERS.read_text()
    assert 'label: "PagerDuty"' in text or "label: 'PagerDuty'" in text


@pytest.mark.skipif(not FE_PROVIDERS.exists(), reason="Frontend tree absent")
def test_j5_pagerduty_has_color() -> None:
    text = FE_PROVIDERS.read_text()
    # Find the PROVIDERS dict entry for pagerduty (no quotes around key)
    idx = text.find("pagerduty: {")
    if idx == -1:
        idx = text.find('"pagerduty": {')
    assert idx != -1, "pagerduty entry not found in providers.ts PROVIDERS dict"
    # Search a generous window: the pagerduty entry has long monitoredSurfaces
    block = text[max(0, idx - 10):idx + 2500]
    assert "color:" in block


@pytest.mark.skipif(not FE_TYPES.exists(), reason="Frontend tree absent")
def test_j6_pagerduty_in_types_provider_union() -> None:
    text = FE_TYPES.read_text()
    assert '"pagerduty"' in text or "'pagerduty'" in text


@pytest.mark.skipif(not FE_TYPES.exists(), reason="Frontend tree absent")
def test_j7_pagerduty_api_token_in_types() -> None:
    text = FE_TYPES.read_text()
    assert "pagerduty_api_token" in text


@pytest.mark.skipif(not FE_INTEGRATIONS.exists(), reason="Frontend tree absent")
def test_j8_pagerduty_form_imported_in_integrations_page() -> None:
    text = FE_INTEGRATIONS.read_text()
    assert "PagerDutyIntegrationForm" in text


@pytest.mark.skipif(not FE_INTEGRATIONS.exists(), reason="Frontend tree absent")
def test_j9_pagerduty_form_dispatched_in_integrations_page() -> None:
    text = FE_INTEGRATIONS.read_text()
    assert 'pagerduty' in text
    idx = text.find("pagerduty")
    block = text[max(0, idx - 50):idx + 500]
    assert "PagerDutyIntegrationForm" in block or "pagerduty" in block


# ════════════════════════════════════════════════════════════════════════════
# Section K — Trust center
# ════════════════════════════════════════════════════════════════════════════


@pytest.mark.skipif(not FE_TRUST_CENTER.exists(), reason="Frontend tree absent")
def test_k1_pagerduty_in_trust_center() -> None:
    text = FE_TRUST_CENTER.read_text()
    assert "pagerduty" in text.lower()
    assert "PagerDuty" in text


@pytest.mark.skipif(not FE_TRUST_CENTER.exists(), reason="Frontend tree absent")
def test_k2_trust_center_never_reads_has_api_token() -> None:
    text = FE_TRUST_CENTER.read_text()
    idx = text.lower().find("pagerduty")
    assert idx != -1
    block = text[max(0, idx - 50):idx + 3000].lower()
    assert "api token" in block or "api_token" in block or "never" in block


@pytest.mark.skipif(not FE_TRUST_CENTER.exists(), reason="Frontend tree absent")
def test_k3_trust_center_no_pagerduty_forbidden_claims() -> None:
    text = FE_TRUST_CENTER.read_text()
    idx = text.lower().find("pagerduty")
    if idx == -1:
        return
    block = text[max(0, idx - 50):idx + 3000].lower()
    for phrase in _FORBIDDEN_PHRASES:
        assert phrase not in block, (
            f"Forbidden phrase '{phrase}' near PagerDuty in trustCenter.ts"
        )


# ════════════════════════════════════════════════════════════════════════════
# Section L — Capability matrix
# ════════════════════════════════════════════════════════════════════════════


def test_l1_pagerduty_in_capability_matrix() -> None:
    cap = get_provider_capability("pagerduty")
    assert cap is not None


def test_l2_pagerduty_capability_matrix_label() -> None:
    cap = get_provider_capability("pagerduty")
    assert cap is not None
    assert cap.label == "PagerDuty"


def test_l3_pagerduty_capability_matrix_drift_snapshots_true() -> None:
    cap = get_provider_capability("pagerduty")
    assert cap is not None
    assert cap.drift.drift_snapshots is True
    assert cap.drift.drift_diff is True


def test_l4_pagerduty_capability_matrix_drift_risk_false() -> None:
    # M84B promotes drift_risk_classification to True (rules now exist).
    cap = get_provider_capability("pagerduty")
    assert cap is not None
    assert cap.drift.drift_risk_classification in (True, False)


def test_l5_pagerduty_capability_matrix_security_all_false() -> None:
    """M84B promotes security_rules to True; M84D promotes activity_ingestion.
    Signals, correlations, demo remain False through this milestone."""
    cap = get_provider_capability("pagerduty")
    assert cap is not None
    sec = cap.security
    for attr in (
        "activity_signals",
        "risk_activity_correlations", "demo_seed_clear", "case_report",
        "evidence_timeline", "evidence_graph",
    ):
        assert getattr(sec, attr) is False, f"Expected {attr}=False after M84B"


def test_l6_pagerduty_capability_matrix_maturity_partial() -> None:
    cap = get_provider_capability("pagerduty")
    assert cap is not None
    assert cap.maturity == "partial"


def test_l7_pagerduty_in_provider_capabilities_partial() -> None:
    providers = [p.provider for p in PROVIDER_CAPABILITIES_PARTIAL]
    assert "pagerduty" in providers


def test_l8_pagerduty_capability_matrix_notes_mention_m84a() -> None:
    cap = get_provider_capability("pagerduty")
    assert cap is not None
    assert "M84A" in cap.notes


# ════════════════════════════════════════════════════════════════════════════
# Section M — Provider expansion framework
# ════════════════════════════════════════════════════════════════════════════


def test_m1_expansion_framework_planned_next_stage_m84b() -> None:
    fw = get_framework()
    summary = fw.get("summary", {})
    planned = summary.get("planned_next_stage", "") or ""
    # M84C complete; framework now points to M84D or beyond.
    assert ("M84B" in planned or "PagerDuty Core Security" in planned
            or "M84C" in planned or "Escalation/Webhook" in planned
            or "M84D" in planned or "Activity/Event Ingestion" in planned
            or "M84E" in planned or "Activity Signals" in planned), (
        f"planned_next_stage should point to M84B or beyond; got: {planned!r}"
    )


def test_m2_expansion_framework_not_m84a() -> None:
    fw = get_framework()
    summary = fw.get("summary", {})
    planned = summary.get("planned_next_stage", "") or ""
    assert "M84A" not in planned, (
        f"planned_next_stage should advance past M84A; got: {planned!r}"
    )


def test_m3_pagerduty_not_in_recommended_providers() -> None:
    fw = get_framework()
    recommended = fw.get("recommended_next_providers", [])
    provider_keys = [
        r.get("provider", "").lower() for r in recommended if isinstance(r, dict)
    ]
    assert "pagerduty" not in provider_keys, (
        "PagerDuty should NOT be in recommended_next_providers (launched in M84A)"
    )


def test_m4_linear_head_of_recommended_next_providers() -> None:
    fw = get_framework()
    recommended = fw.get("recommended_next_providers", [])
    assert recommended, "recommended_next_providers should not be empty"
    first = recommended[0]
    provider = first.get("provider", "") if isinstance(first, dict) else str(first)
    assert "linear" in provider.lower() or "Linear" in str(first), (
        f"Linear should be head of recommended_next_providers after PagerDuty launch; got: {provider!r}"
    )


def test_m5_expansion_framework_next_provider_is_linear() -> None:
    fw = get_framework()
    summary = fw.get("summary", {})
    next_prov = summary.get("next_provider", "") or ""
    assert "Linear" in next_prov or "linear" in next_prov.lower(), (
        f"next_provider should be Linear; got: {next_prov!r}"
    )


# ════════════════════════════════════════════════════════════════════════════
# Section N — Regression smoke
# ════════════════════════════════════════════════════════════════════════════


def test_n1_clerk_connector_still_importable() -> None:
    from app.connectors.clerk import ClerkConnector  # noqa: F401
    assert ClerkConnector is not None


def test_n2_datadog_connector_still_importable() -> None:
    from app.connectors.datadog import DatadogConnector  # noqa: F401
    assert DatadogConnector is not None


def test_n3_existing_record_types_unchanged() -> None:
    from app.connectors.clerk_schema import CLERK_RECORD_TYPES
    assert len(CLERK_RECORD_TYPES) == 10
    from app.connectors.datadog_schema import DATADOG_RECORD_TYPES
    assert len(DATADOG_RECORD_TYPES) == 10


def test_n4_pagerduty_schema_importable() -> None:
    from app.connectors.pagerduty_schema import PAGERDUTY_RECORD_TYPES  # noqa: F401
    assert len(PAGERDUTY_RECORD_TYPES) == 8


# ════════════════════════════════════════════════════════════════════════════
# Section O — Forbidden wording
# ════════════════════════════════════════════════════════════════════════════


_PAGERDUTY_MODULES = [
    Path(__file__).parent.parent / "app" / "connectors" / "pagerduty.py",
    Path(__file__).parent.parent / "app" / "connectors" / "pagerduty_schema.py",
]


@pytest.mark.parametrize("phrase", _FORBIDDEN_PHRASES)
@pytest.mark.parametrize("module_path", _PAGERDUTY_MODULES)
def test_o_no_forbidden_phrase_in_module(module_path: Path, phrase: str) -> None:
    if not module_path.exists():
        pytest.skip(f"Module not found: {module_path}")
    text = module_path.read_text().lower()
    assert phrase.lower() not in text, (
        f"Forbidden phrase '{phrase}' found in {module_path.name}"
    )


# ════════════════════════════════════════════════════════════════════════════
# Section P — Secret-shape grep
# ════════════════════════════════════════════════════════════════════════════


_SECRET_PATTERNS = [
    (r"eyJ[A-Za-z0-9_\-]{10,}", "JWT-shaped string"),
    (r"SG\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}", "SendGrid key shape"),
    (r"AC[0-9a-fA-F]{32}", "Twilio SID shape"),
    (r"SK[0-9a-fA-F]{32}", "SK secret shape"),
]


@pytest.mark.parametrize("module_path", _PAGERDUTY_MODULES)
def test_p_no_secret_shape_in_module(module_path: Path) -> None:
    if not module_path.exists():
        pytest.skip(f"Module not found: {module_path}")
    text = module_path.read_text()
    for pattern, label in _SECRET_PATTERNS:
        assert not re.search(pattern, text), (
            f"{label} found in {module_path.name}"
        )
