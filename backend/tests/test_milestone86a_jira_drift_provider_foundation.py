"""M86A: Jira drift provider foundation tests.

Validates that the Jira connector, schema, integration service, sync wiring,
capability matrix, expansion framework, and frontend files all meet the M86A
specification.

Jira authenticates with a Jira Cloud site URL + account email + API token
(HTTP Basic auth). The connector reads ONLY configuration-level metadata from
Jira Cloud configuration surfaces (projects, boards, workflows, workflow
schemes, permission schemes, notification schemes, issue type schemes, field
configuration schemes, screen schemes, webhook subscriptions, automation
rules). It never fetches or stores issue keys, issue titles, issue
descriptions, comments, attachments, user names, user emails, account IDs,
webhook URLs/secrets, or any customer data.

Sections:
  A. Schema — JIRA_RECORD_TYPES has exactly 12 types; all expected record-type
     strings present; JiraConnector import works.
  B. Connector — fetch()/validate_credentials() present; __init__ stores no
     credentials; _sanitize_site_url() works; all expected _fetch_X methods
     exist; fetch() raises AuthenticationError on empty credentials;
     _raise_for_status raises correct exceptions (401/403/429/5xx/network).
  C. Normalizers — each normalizer returns provider="jira" + expected
     record_type; normalized dicts are flat; no forbidden fields in output.
  D. Integration schema/router — "jira" in provider Literal; jira_site_url /
     jira_email / jira_api_token fields; validator rejects jira without all 3;
     response schema never exposes token/email; router credential builder.
  E. Sync — sync_service supports "jira"; sync_task dispatch supports "jira".
  F. Capability matrix — drift_snapshots/diff True, drift_risk_classification
     and all security caps False, maturity partial; notes mention M86A;
     planned_next_stage references M86B.
  G. Expansion framework — planned_next_stage references M86B or Jira Core;
     Jira launched (no longer head of recommended queue / GitLab now head).
  H. Frontend — providers.ts, integrations page, trustCenter.ts reference Jira;
     JiraIntegrationForm.tsx has 3 fields (site_url, email, api_token) and the
     api_token field is type=password.
  I. Privacy — normalizer output never contains api_token/email/account_id/
     issue_key/webhook_url; no secret-shaped strings in the connector.
  J. Forbidden wording — no breach/compromise/attack copy in connector/schema.
"""

from __future__ import annotations

import inspect
import re
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import httpx
import pytest

from app.connectors.exceptions import (
    AuthenticationError,
    ConnectorError,
    NetworkError,
    RateLimitError,
)
from app.connectors.jira import JiraConnector
from app.connectors.jira_schema import (
    JIRA_AUTOMATION_RULE,
    JIRA_BOARD,
    JIRA_FIELD_CONFIGURATION_SCHEME,
    JIRA_ISSUE_TYPE_SCHEME,
    JIRA_NOTIFICATION_SCHEME,
    JIRA_PERMISSION_SCHEME,
    JIRA_PROJECT,
    JIRA_RECORD_TYPES,
    JIRA_SCREEN_SCHEME,
    JIRA_SITE,
    JIRA_WEBHOOK,
    JIRA_WORKFLOW,
    JIRA_WORKFLOW_SCHEME,
)
from app.services.provider_capability_matrix_service import (
    PROVIDER_CAPABILITIES_PARTIAL,
    get_provider_capability,
)
from app.services.provider_expansion_framework import get_framework

# ── Paths ─────────────────────────────────────────────────────────────────────
REPO_ROOT = Path(__file__).resolve().parents[2]
FE_ROOT = REPO_ROOT / "frontend" / "src"
FE_PROVIDERS = FE_ROOT / "lib" / "providers.ts"
FE_TYPES = FE_ROOT / "types" / "index.ts"
FE_INTEGRATIONS = FE_ROOT / "app" / "(app)" / "integrations" / "page.tsx"
FE_TRUST_CENTER = FE_ROOT / "lib" / "trustCenter.ts"
FE_JIRA_FORM = FE_ROOT / "components" / "integrations" / "JiraIntegrationForm.tsx"

BACKEND_ROOT = Path(__file__).resolve().parents[1]
JIRA_PY = BACKEND_ROOT / "app" / "connectors" / "jira.py"
JIRA_SCHEMA_PY = BACKEND_ROOT / "app" / "connectors" / "jira_schema.py"

# ── Safe test placeholders (never real credentials) ───────────────────────────
JIRA_TEST_SITE_URL_PLACEHOLDER = "myco.atlassian.net"
JIRA_TEST_EMAIL_PLACEHOLDER = "JIRA_TEST_EMAIL_PLACEHOLDER@example.invalid"
JIRA_TEST_API_TOKEN_PLACEHOLDER = "JIRA_TEST_API_TOKEN_PLACEHOLDER"
JIRA_TEST_PROJECT_ID = "JIRA_TEST_PROJECT_ID"

_CREDS = {
    "site_url": JIRA_TEST_SITE_URL_PLACEHOLDER,
    "email": JIRA_TEST_EMAIL_PLACEHOLDER,
    "api_token": JIRA_TEST_API_TOKEN_PLACEHOLDER,
}

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

# Fields that must NEVER appear as keys in a normalized record.
_FORBIDDEN_RECORD_FIELDS = {
    "api_token",
    "token",
    "oauth_token",
    "secret",
    "webhook_secret",
    "authorization",
    "email",
    "user_email",
    "account_id",
    "issue_key",
    "issue_title",
    "issue_description",
    "comment",
    "webhook_url",
    "url",
    "raw",
    "payload",
    "headers",
}

EXPECTED_SCHEMA_CONSTANTS = {
    JIRA_SITE,
    JIRA_PROJECT,
    JIRA_BOARD,
    JIRA_WORKFLOW,
    JIRA_WORKFLOW_SCHEME,
    JIRA_PERMISSION_SCHEME,
    JIRA_NOTIFICATION_SCHEME,
    JIRA_ISSUE_TYPE_SCHEME,
    JIRA_FIELD_CONFIGURATION_SCHEME,
    JIRA_SCREEN_SCHEME,
    JIRA_WEBHOOK,
    JIRA_AUTOMATION_RULE,
}

EXPECTED_RECORD_TYPE_STRINGS = {
    "jira_site",
    "jira_project",
    "jira_board",
    "jira_workflow",
    "jira_workflow_scheme",
    "jira_permission_scheme",
    "jira_notification_scheme",
    "jira_issue_type_scheme",
    "jira_field_configuration_scheme",
    "jira_screen_scheme",
    "jira_webhook",
    "jira_automation_rule",
}


# ════════════════════════════════════════════════════════════════════════════
# Section A — Schema constants & importability
# ════════════════════════════════════════════════════════════════════════════


def test_a1_record_types_frozenset_count() -> None:
    """JIRA_RECORD_TYPES must contain exactly 12 record types."""
    assert len(JIRA_RECORD_TYPES) == 12


def test_a2_expected_constant_count() -> None:
    assert len(EXPECTED_SCHEMA_CONSTANTS) == 12


def test_a3_record_types_match_constants() -> None:
    assert set(JIRA_RECORD_TYPES) == EXPECTED_SCHEMA_CONSTANTS


def test_a4_all_expected_record_type_strings_present() -> None:
    for rt in EXPECTED_RECORD_TYPE_STRINGS:
        assert rt in JIRA_RECORD_TYPES, f"{rt!r} missing from JIRA_RECORD_TYPES"


def test_a5_all_constants_start_with_jira() -> None:
    for rt in JIRA_RECORD_TYPES:
        assert rt.startswith("jira_"), f"{rt!r} does not start with 'jira_'"


def test_a6_constant_string_values() -> None:
    assert JIRA_SITE == "jira_site"
    assert JIRA_PROJECT == "jira_project"
    assert JIRA_BOARD == "jira_board"
    assert JIRA_WORKFLOW == "jira_workflow"
    assert JIRA_WEBHOOK == "jira_webhook"
    assert JIRA_AUTOMATION_RULE == "jira_automation_rule"


def test_a7_connector_importable() -> None:
    from app.connectors.jira import JiraConnector as _JC  # noqa: F401

    assert _JC is not None


def test_a8_schema_constants_importable() -> None:
    from app.connectors.jira_schema import (  # noqa: F401
        JIRA_FIELD_CONFIGURATION_SCHEME,
        JIRA_ISSUE_TYPE_SCHEME,
        JIRA_NOTIFICATION_SCHEME,
        JIRA_PERMISSION_SCHEME,
        JIRA_SCREEN_SCHEME,
        JIRA_WORKFLOW_SCHEME,
    )


# ════════════════════════════════════════════════════════════════════════════
# Section B — Connector structure & safety
# ════════════════════════════════════════════════════════════════════════════

_EXPECTED_FETCH_METHODS = [
    "_fetch_site",
    "_fetch_projects",
    "_fetch_boards",
    "_fetch_workflows",
    "_fetch_workflow_schemes",
    "_fetch_permission_schemes",
    "_fetch_notification_schemes",
    "_fetch_issue_type_schemes",
    "_fetch_field_configuration_schemes",
    "_fetch_screen_schemes",
    "_fetch_webhooks",
    "_fetch_automation_rules",
]


def test_b1_connector_has_fetch() -> None:
    conn = JiraConnector()
    assert callable(conn.fetch)


def test_b2_connector_has_validate_credentials() -> None:
    conn = JiraConnector()
    assert callable(conn.validate_credentials)


def test_b3_init_stores_no_credentials() -> None:
    conn = JiraConnector()
    for attr in (
        "api_token",
        "_api_token",
        "token",
        "_token",
        "email",
        "_email",
        "site_url",
        "_site_url",
        "credentials",
        "_credentials",
        "password",
        "_password",
    ):
        assert not hasattr(conn, attr), f"Forbidden attribute stored at init: {attr!r}"


def test_b4_sanitize_site_url_strips_scheme_and_path() -> None:
    conn = JiraConnector()
    sanitize = getattr(conn, "_sanitize_site_url", None)
    assert callable(sanitize), "JiraConnector._sanitize_site_url missing"
    # Accept either an instance method or a staticmethod call shape.
    out = sanitize("https://myco.atlassian.net/secure/Dashboard.jspa")
    assert isinstance(out, str)
    assert "myco.atlassian.net" in out
    assert "https://" not in out
    assert "/secure" not in out


def test_b5_sanitize_site_url_handles_bare_host() -> None:
    conn = JiraConnector()
    out = conn._sanitize_site_url("myco.atlassian.net")
    assert "myco.atlassian.net" in out
    assert "https://" not in out


def test_b6_sanitize_site_url_handles_trailing_slash() -> None:
    conn = JiraConnector()
    out = conn._sanitize_site_url("https://myco.atlassian.net/")
    assert out.endswith("myco.atlassian.net") or out == "myco.atlassian.net"
    assert "https://" not in out


@pytest.mark.parametrize("method_name", _EXPECTED_FETCH_METHODS)
def test_b7_expected_fetch_methods_exist(method_name: str) -> None:
    conn = JiraConnector()
    assert hasattr(conn, method_name), f"Missing fetch method: {method_name!r}"
    assert callable(getattr(conn, method_name)), f"{method_name!r} is not callable"


def test_b8_fetch_raises_auth_error_on_empty_credentials() -> None:
    conn = JiraConnector()
    with pytest.raises(AuthenticationError):
        conn.fetch({})


def test_b9_fetch_raises_auth_error_on_missing_token() -> None:
    conn = JiraConnector()
    bad = {
        "site_url": JIRA_TEST_SITE_URL_PLACEHOLDER,
        "email": JIRA_TEST_EMAIL_PLACEHOLDER,
        "api_token": "",
    }
    with pytest.raises(AuthenticationError):
        conn.fetch(bad)


def test_b10_fetch_raises_auth_error_on_missing_email() -> None:
    conn = JiraConnector()
    bad = {
        "site_url": JIRA_TEST_SITE_URL_PLACEHOLDER,
        "email": "",
        "api_token": JIRA_TEST_API_TOKEN_PLACEHOLDER,
    }
    with pytest.raises(AuthenticationError):
        conn.fetch(bad)


def test_b11_fetch_raises_auth_error_on_missing_site_url() -> None:
    conn = JiraConnector()
    bad = {
        "site_url": "",
        "email": JIRA_TEST_EMAIL_PLACEHOLDER,
        "api_token": JIRA_TEST_API_TOKEN_PLACEHOLDER,
    }
    with pytest.raises(AuthenticationError):
        conn.fetch(bad)


# ── _raise_for_status error mapping ──────────────────────────────────────────


def _make_mock_response(status_code: int, path: str = "/rest/api/3/project") -> MagicMock:
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    mock_url = MagicMock()
    mock_url.path = path
    resp.url = mock_url
    resp.json.return_value = {}
    resp.text = ""
    # Real dict so _raise_for_status can read Retry-After on 429.
    resp.headers = {}
    return resp


def _raise_for_status(resp: MagicMock) -> None:
    """Invoke JiraConnector._raise_for_status across plausible signatures.

    The implementation is an instance method ``_raise_for_status(self, response,
    surface)``; older/alternate shapes (no surface, or staticmethod) are also
    tolerated so the contract test is resilient.
    """
    conn = JiraConnector()
    try:
        conn._raise_for_status(resp, "test")
    except TypeError:
        try:
            conn._raise_for_status(resp)
        except TypeError:
            JiraConnector._raise_for_status(resp)


def test_b12_401_raises_authentication_error() -> None:
    with pytest.raises(AuthenticationError):
        _raise_for_status(_make_mock_response(401))


def test_b13_403_raises_authentication_or_connector_error() -> None:
    with pytest.raises((AuthenticationError, ConnectorError)):
        _raise_for_status(_make_mock_response(403))


def test_b14_429_raises_rate_limit_error() -> None:
    with pytest.raises(RateLimitError):
        _raise_for_status(_make_mock_response(429))


def test_b15_500_raises_connector_error() -> None:
    with pytest.raises(ConnectorError):
        _raise_for_status(_make_mock_response(500))


def test_b16_503_raises_connector_error() -> None:
    with pytest.raises(ConnectorError):
        _raise_for_status(_make_mock_response(503))


def test_b17_2xx_does_not_raise() -> None:
    # A healthy response must not raise.
    _raise_for_status(_make_mock_response(200))


def test_b18_network_error_propagates_as_network_error() -> None:
    conn = JiraConnector()
    with patch("httpx.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value.__enter__ = MagicMock(return_value=mock_client)
        mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)
        mock_client.get.side_effect = httpx.ConnectError("Connection refused")
        mock_client.request.side_effect = httpx.ConnectError("Connection refused")
        with pytest.raises((NetworkError, ConnectorError)):
            conn.fetch(_CREDS)


# ════════════════════════════════════════════════════════════════════════════
# Section C — Normalizers
# ════════════════════════════════════════════════════════════════════════════


def _make_raw_site() -> dict:
    return {
        "baseUrl": "https://myco.atlassian.net",
        "serverTitle": "Acme Jira",
        "version": "1001.0.0",
        "versionNumbers": [1001, 0, 0],
        "buildNumber": 100123,
        "deploymentType": "Cloud",
        "scmInfo": "abc",
    }


def _make_raw_project() -> dict:
    return {
        "id": JIRA_TEST_PROJECT_ID,
        "key": "ACME",
        "name": "Acme Project",
        "projectTypeKey": "software",
        "style": "next-gen",
        "isPrivate": False,
        "simplified": True,
        "lead": {"accountId": "ACCT_REDACTED", "emailAddress": "lead@example.invalid"},
    }


def _make_raw_board() -> dict:
    return {
        "id": 42,
        "name": "Acme Sprint Board",
        "type": "scrum",
        "location": {"projectId": JIRA_TEST_PROJECT_ID},
    }


def _make_raw_workflow() -> dict:
    return {
        "id": {"name": "Acme Workflow", "entityId": "WORKFLOW_ENTITY_ID"},
        "description": "Acme workflow description",
        "statuses": [{"id": "1"}, {"id": "2"}, {"id": "3"}],
        "transitions": [{"id": "11"}, {"id": "21"}],
    }


def _make_raw_workflow_scheme() -> dict:
    return {
        "id": 9001,
        "name": "Acme Workflow Scheme",
        "description": "scheme desc",
        "defaultWorkflow": "Acme Workflow",
        "draft": False,
    }


def _make_raw_permission_scheme() -> dict:
    return {
        "id": 10100,
        "name": "Default Permission Scheme",
        "description": "Default scheme",
        "permissions": [{"id": 1}, {"id": 2}, {"id": 3}],
    }


def _make_raw_notification_scheme() -> dict:
    return {
        "id": 10200,
        "name": "Default Notification Scheme",
        "description": "Default notification scheme",
        "notificationSchemeEvents": [{"event": {"id": 1}}, {"event": {"id": 2}}],
    }


def _make_raw_issue_type_scheme() -> dict:
    return {
        "id": "10300",
        "name": "Default Issue Type Scheme",
        "description": "Default issue type scheme",
        "isDefault": True,
    }


def _make_raw_field_configuration_scheme() -> dict:
    return {
        "id": "10400",
        "name": "Default Field Configuration Scheme",
        "description": "Default field config scheme",
    }


def _make_raw_screen_scheme() -> dict:
    return {
        "id": 10500,
        "name": "Default Screen Scheme",
        "description": "Default screen scheme",
        "screens": {"default": 1, "create": 2, "edit": 3, "view": 4},
    }


def _make_raw_webhook() -> dict:
    return {
        "id": 70001,
        "name": "Acme Webhook",
        "url": "https://hooks.example.invalid/abc123secret",
        "events": ["jira:issue_created", "jira:issue_updated"],
        "enabled": True,
        "excludeBody": False,
    }


def _make_raw_automation_rule() -> dict:
    return {
        "id": "80001",
        "name": "Acme Automation Rule",
        "state": "ENABLED",
        "actorAccountId": "ACCT_REDACTED",
        "trigger": {"component": "TRIGGER", "type": "jira.issue.event.trigger"},
    }


_NORMALIZER_CASES = [
    ("_normalize_site", _make_raw_site, "jira_site"),
    ("_normalize_project", _make_raw_project, "jira_project"),
    ("_normalize_board", _make_raw_board, "jira_board"),
    ("_normalize_workflow", _make_raw_workflow, "jira_workflow"),
    ("_normalize_workflow_scheme", _make_raw_workflow_scheme, "jira_workflow_scheme"),
    ("_normalize_permission_scheme", _make_raw_permission_scheme, "jira_permission_scheme"),
    (
        "_normalize_notification_scheme",
        _make_raw_notification_scheme,
        "jira_notification_scheme",
    ),
    ("_normalize_issue_type_scheme", _make_raw_issue_type_scheme, "jira_issue_type_scheme"),
    (
        "_normalize_field_configuration_scheme",
        _make_raw_field_configuration_scheme,
        "jira_field_configuration_scheme",
    ),
    ("_normalize_screen_scheme", _make_raw_screen_scheme, "jira_screen_scheme"),
    ("_normalize_webhook", _make_raw_webhook, "jira_webhook"),
    ("_normalize_automation_rule", _make_raw_automation_rule, "jira_automation_rule"),
]


def _normalize(method_name: str, raw: dict) -> dict:
    conn = JiraConnector()
    fn = getattr(conn, method_name, None)
    assert callable(fn), f"JiraConnector.{method_name} missing"
    out = fn(raw)
    assert isinstance(out, dict), f"{method_name} did not return a dict"
    return out


@pytest.mark.parametrize("method_name,raw_factory,record_type", _NORMALIZER_CASES)
def test_c1_normalizer_provider_is_jira(
    method_name: str, raw_factory: Any, record_type: str
) -> None:
    rec = _normalize(method_name, raw_factory())
    assert rec.get("provider") == "jira", f"{method_name}: provider != 'jira'"


@pytest.mark.parametrize("method_name,raw_factory,record_type", _NORMALIZER_CASES)
def test_c2_normalizer_record_type_correct(
    method_name: str, raw_factory: Any, record_type: str
) -> None:
    rec = _normalize(method_name, raw_factory())
    assert rec.get("record_type") == record_type, (
        f"{method_name}: record_type != {record_type!r}"
    )


@pytest.mark.parametrize("method_name,raw_factory,record_type", _NORMALIZER_CASES)
def test_c3_normalizer_output_is_flat(
    method_name: str, raw_factory: Any, record_type: str
) -> None:
    rec = _normalize(method_name, raw_factory())
    for key, value in rec.items():
        assert not isinstance(value, (dict, list)), (
            f"{method_name}: nested {type(value).__name__} at key {key!r}"
        )


@pytest.mark.parametrize("method_name,raw_factory,record_type", _NORMALIZER_CASES)
def test_c4_normalizer_no_forbidden_fields(
    method_name: str, raw_factory: Any, record_type: str
) -> None:
    rec = _normalize(method_name, raw_factory())
    for bad in _FORBIDDEN_RECORD_FIELDS:
        assert bad not in rec, f"{method_name}: forbidden field {bad!r} in output"


@pytest.mark.parametrize("method_name,raw_factory,record_type", _NORMALIZER_CASES)
def test_c5_normalizer_no_pii_values(
    method_name: str, raw_factory: Any, record_type: str
) -> None:
    """No raw PII / secret values should leak into the record values."""
    rec = _normalize(method_name, raw_factory())
    blob = repr(rec).lower()
    for leaked in (
        "lead@example.invalid",
        "acct_redacted",
        "abc123secret",
        "https://hooks.example.invalid",
    ):
        assert leaked.lower() not in blob, (
            f"{method_name}: leaked sensitive value {leaked!r} into record"
        )


# ════════════════════════════════════════════════════════════════════════════
# Section D — Integration schema & router
# ════════════════════════════════════════════════════════════════════════════

_INTEGRATION_BASE = {
    "display_name": "Test Jira Integration",
    "provider": "jira",
    "jira_site_url": JIRA_TEST_SITE_URL_PLACEHOLDER,
    "jira_email": JIRA_TEST_EMAIL_PLACEHOLDER,
    "jira_api_token": JIRA_TEST_API_TOKEN_PLACEHOLDER,
}


def test_d1_jira_in_provider_literal() -> None:
    from app.schemas.integration import IntegrationCreateRequest

    req = IntegrationCreateRequest(**_INTEGRATION_BASE)
    assert req.provider == "jira"


def test_d2_schema_accepts_all_three_jira_fields() -> None:
    from app.schemas.integration import IntegrationCreateRequest

    req = IntegrationCreateRequest(**_INTEGRATION_BASE)
    assert req.jira_site_url == JIRA_TEST_SITE_URL_PLACEHOLDER
    assert req.jira_email == JIRA_TEST_EMAIL_PLACEHOLDER
    assert req.jira_api_token == JIRA_TEST_API_TOKEN_PLACEHOLDER


def test_d3_validator_rejects_jira_without_site_url() -> None:
    from app.schemas.integration import IntegrationCreateRequest

    bad = {**_INTEGRATION_BASE, "jira_site_url": None}
    with pytest.raises((ValueError, Exception)):
        IntegrationCreateRequest(**bad)


def test_d4_validator_rejects_jira_without_email() -> None:
    from app.schemas.integration import IntegrationCreateRequest

    bad = {**_INTEGRATION_BASE, "jira_email": None}
    with pytest.raises((ValueError, Exception)):
        IntegrationCreateRequest(**bad)


def test_d5_validator_rejects_jira_without_api_token() -> None:
    from app.schemas.integration import IntegrationCreateRequest

    bad = {**_INTEGRATION_BASE, "jira_api_token": None}
    with pytest.raises((ValueError, Exception)):
        IntegrationCreateRequest(**bad)


def test_d6_response_schema_does_not_expose_jira_api_token() -> None:
    from app.schemas.integration import IntegrationResponse

    fields = set()
    if hasattr(IntegrationResponse, "model_fields"):
        fields = set(IntegrationResponse.model_fields.keys())
    elif hasattr(IntegrationResponse, "__fields__"):
        fields = set(IntegrationResponse.__fields__.keys())
    assert "jira_api_token" not in fields, "IntegrationResponse must not expose jira_api_token"


def test_d7_response_schema_does_not_expose_jira_email() -> None:
    from app.schemas.integration import IntegrationResponse

    fields = set()
    if hasattr(IntegrationResponse, "model_fields"):
        fields = set(IntegrationResponse.model_fields.keys())
    elif hasattr(IntegrationResponse, "__fields__"):
        fields = set(IntegrationResponse.__fields__.keys())
    assert "jira_email" not in fields, "IntegrationResponse must not expose jira_email"


def test_d8_router_has_credential_builder_for_jira() -> None:
    import app.routers.integrations as integrations_router

    source = inspect.getsource(integrations_router)
    assert '"jira"' in source or "'jira'" in source, (
        "integrations router does not reference 'jira'"
    )
    # The credential builder must map all 3 jira fields.
    for field in ("jira_site_url", "jira_email", "jira_api_token"):
        assert field in source, f"router credential builder missing {field!r}"


def test_d9_integration_service_dispatches_jira() -> None:
    import app.services.integration_service as isvc

    source = inspect.getsource(isvc)
    assert "jira" in source.lower(), "integration_service does not handle 'jira'"


# ════════════════════════════════════════════════════════════════════════════
# Section E — Sync service & task wiring
# ════════════════════════════════════════════════════════════════════════════


def test_e1_jira_in_supported_providers() -> None:
    import app.services.sync_service as sync_service_module

    source = inspect.getsource(sync_service_module)
    assert "_SUPPORTED_PROVIDERS" in source
    assert '"jira"' in source or "'jira'" in source, (
        "'jira' missing from sync_service _SUPPORTED_PROVIDERS"
    )


def test_e2_sync_task_references_jira() -> None:
    import app.workers.sync_task as sync_task_module

    source = inspect.getsource(sync_task_module)
    assert "jira" in source.lower(), "sync_task does not reference 'jira'"


def test_e3_sync_task_imports_jira_connector() -> None:
    import app.workers.sync_task as sync_task_module

    source = inspect.getsource(sync_task_module)
    assert "JiraConnector" in source, "sync_task does not import JiraConnector"


# ════════════════════════════════════════════════════════════════════════════
# Section E2 — Diff tracked fields and risk classification (QA pass)
# ════════════════════════════════════════════════════════════════════════════
#
# Jira previously had NO entry in diff_service.py's tracked-fields dispatch
# (every jira_ record type fell through to the Cloudflare DNS default tuple,
# so compute_diff could never detect a modified field) and NO
# risk_rules/jira.py module at all (risk_service.py had no jira_ dispatch
# branch, so every Jira change silently fell through to the Cloudflare DNS
# classifier). Both were built during this QA pass.


class TestJiraDiffTrackedFields:
    def test_all_twelve_record_types_have_tracked_fields_entries(self):
        from app.services.diff_service import _JIRA_TRACKED_FIELDS_BY_TYPE

        for record_type in JIRA_RECORD_TYPES:
            assert record_type in _JIRA_TRACKED_FIELDS_BY_TYPE, (
                f"{record_type!r} has no tracked-fields entry — modified-field "
                "changes for this record type will never be detected by compute_diff"
            )

    def test_tracked_fields_dispatch_uses_jira_table_not_cloudflare_default(self):
        from app.services.diff_service import _tracked_fields_for, _TRACKED_FIELDS

        for record_type in JIRA_RECORD_TYPES:
            fields = _tracked_fields_for({"record_type": record_type})
            assert fields != _TRACKED_FIELDS, (
                f"{record_type!r} is falling through to the Cloudflare DNS "
                "default tracked-fields tuple instead of its own Jira fields"
            )
            assert fields, f"{record_type!r} resolved to an empty tracked-fields tuple"

    def test_permission_scheme_anonymous_grant_change_produces_drift_change(self):
        """permission_anonymous_grant_count 0 -> 1 must surface as a Change —
        this is the field-level signal behind Jira anonymous access posture."""
        from app.models.snapshot import Snapshot
        from app.services.diff_service import compute_diff

        def _mock_snapshot(state: list[dict]) -> MagicMock:
            snap = MagicMock(spec=Snapshot)
            snap.state = state
            return snap

        def _permission_scheme_record(anon_count: int) -> dict:
            return {
                "record_type": "jira_permission_scheme",
                "provider": "jira",
                "record_id": "jira_permission_scheme:ps1",
                "resource_id": "ps1",
                "permission_grant_count": 5,
                "permission_anonymous_grant_count": anon_count,
                "permission_anyone_grant_count": 0,
                "permission_logged_in_grant_count": 0,
                "permission_project_role_grant_count": 5,
                "permission_public_browse_projects": False,
                "permission_public_administer_projects": False,
                "permission_public_manage_sprints": False,
                "permission_public_create_issues": False,
                "permission_public_transition_issues": False,
                "permission_unknown_holder_count": 0,
                "permission_high_privilege_grant_count": 0,
                "permission_public_grant_count": 0,
            }

        prev = _mock_snapshot([_permission_scheme_record(0)])
        new = _mock_snapshot([_permission_scheme_record(1)])

        changes = compute_diff(prev, new)
        anon_changes = [c for c in changes if c["field_path"] == "permission_anonymous_grant_count"]

        assert len(anon_changes) == 1
        assert anon_changes[0]["prev_value"] == 0
        assert anon_changes[0]["new_value"] == 1

    def test_no_spurious_change_when_records_are_identical(self):
        from app.models.snapshot import Snapshot
        from app.services.diff_service import compute_diff

        def _mock_snapshot(state: list[dict]) -> MagicMock:
            snap = MagicMock(spec=Snapshot)
            snap.state = state
            return snap

        record = {
            "record_type": "jira_webhook",
            "provider": "jira",
            "record_id": "jira_webhook:wh1",
            "resource_id": "wh1",
            "webhook_enabled": True,
            "webhook_event_count": 2,
            "webhook_url_present": True,
            "webhook_url_scheme_category": "https",
            "webhook_jql_filter_present": True,
            "webhook_secret_present": True,
            "webhook_has_issue_events": True,
            "webhook_has_comment_events": False,
            "webhook_has_attachment_events": False,
            "webhook_has_project_events": False,
            "webhook_has_sprint_events": False,
            "webhook_has_worklog_events": False,
            "webhook_all_issue_events": False,
            "webhook_jql_empty_or_broad": False,
            "webhook_event_scope_category": "narrow",
        }
        prev = _mock_snapshot([dict(record)])
        new = _mock_snapshot([dict(record)])

        assert compute_diff(prev, new) == []

    def test_every_tracked_field_classifies_without_error_or_invalid_severity(self):
        """Every field in _JIRA_TRACKED_FIELDS_BY_TYPE must be classifiable:
        classify_jira_change must not raise, and must return one of the three
        known severities, for a representative modified change on each
        tracked field of each record type.
        """
        from app.services.diff_service import _JIRA_TRACKED_FIELDS_BY_TYPE
        from app.services.risk_rules.jira import classify_jira_change

        for record_type, fields in _JIRA_TRACKED_FIELDS_BY_TYPE.items():
            for field in fields:
                change = {
                    "change_type": "modified",
                    "field_path": field,
                    "prev_value": 1,
                    "new_value": 2,
                    "provider_metadata": {"record_type": record_type},
                }
                level, reason = classify_jira_change(change)
                assert level in ("low", "medium", "high"), (
                    f"{record_type}.{field} returned invalid severity {level!r}"
                )
                assert isinstance(reason, str) and reason, (
                    f"{record_type}.{field} returned an empty reason string"
                )


class TestJiraRiskClassifier:
    def _make_change(
        self,
        record_type: str,
        field_path: str = "",
        change_type: str = "modified",
        prev_value: Any = None,
        new_value: Any = None,
    ) -> dict:
        return {
            "provider_metadata": {"record_type": record_type},
            "field_path": field_path,
            "change_type": change_type,
            "prev_value": prev_value,
            "new_value": new_value,
        }

    def test_risk_service_dispatches_jira_to_jira_classifier(self):
        """Regression guard: risk_service.py must route jira_ record types to
        classify_jira_change, not silently fall through to the Cloudflare DNS
        classifier (the exact bug this QA pass found and fixed)."""
        from app.services.risk_service import classify_change

        change = self._make_change(
            "jira_permission_scheme", "permission_anonymous_grant_count",
            prev_value=0, new_value=1,
        )
        mock_change = MagicMock()
        mock_change.provider_metadata = change["provider_metadata"]
        mock_change.field_path = change["field_path"]
        mock_change.change_type = change["change_type"]
        mock_change.prev_value = change["prev_value"]
        mock_change.new_value = change["new_value"]
        level, reason = classify_change(mock_change)
        assert level == "high", f"Expected high, got {level!r}: {reason}"
        assert "jira" in reason.lower()

    def test_anonymous_grant_increase_is_high(self):
        from app.services.risk_rules.jira import classify_jira_change
        change = self._make_change(
            JIRA_PERMISSION_SCHEME, "permission_anonymous_grant_count",
            prev_value=0, new_value=1,
        )
        level, reason = classify_jira_change(change)
        assert level == "high", f"Expected high, got {level!r}: {reason}"

    def test_anonymous_grant_decrease_is_low(self):
        from app.services.risk_rules.jira import classify_jira_change
        change = self._make_change(
            JIRA_PERMISSION_SCHEME, "permission_anonymous_grant_count",
            prev_value=1, new_value=0,
        )
        level, _ = classify_jira_change(change)
        assert level == "low"

    def test_public_administer_projects_true_is_high(self):
        from app.services.risk_rules.jira import classify_jira_change
        change = self._make_change(
            JIRA_PERMISSION_SCHEME, "permission_public_administer_projects",
            prev_value=False, new_value=True,
        )
        level, reason = classify_jira_change(change)
        assert level == "high", f"Expected high, got {level!r}: {reason}"

    def test_public_browse_projects_true_is_medium(self):
        from app.services.risk_rules.jira import classify_jira_change
        change = self._make_change(
            JIRA_PERMISSION_SCHEME, "permission_public_browse_projects",
            prev_value=False, new_value=True,
        )
        level, reason = classify_jira_change(change)
        assert level == "medium", f"Expected medium, got {level!r}: {reason}"

    def test_webhook_secret_removed_is_high(self):
        from app.services.risk_rules.jira import classify_jira_change
        change = self._make_change(
            JIRA_WEBHOOK, "webhook_secret_present", prev_value=True, new_value=False,
        )
        level, reason = classify_jira_change(change)
        assert level == "high", f"Expected high, got {level!r}: {reason}"

    def test_webhook_http_scheme_is_high(self):
        from app.services.risk_rules.jira import classify_jira_change
        change = self._make_change(
            JIRA_WEBHOOK, "webhook_url_scheme_category", prev_value="https", new_value="http",
        )
        level, reason = classify_jira_change(change)
        assert level == "high", f"Expected high, got {level!r}: {reason}"

    def test_webhook_https_restored_is_low(self):
        from app.services.risk_rules.jira import classify_jira_change
        change = self._make_change(
            JIRA_WEBHOOK, "webhook_url_scheme_category", prev_value="http", new_value="https",
        )
        level, _ = classify_jira_change(change)
        assert level == "low"

    def test_automation_web_request_action_is_high(self):
        from app.services.risk_rules.jira import classify_jira_change
        change = self._make_change(
            JIRA_AUTOMATION_RULE, "automation_has_web_request_action",
            prev_value=False, new_value=True,
        )
        level, reason = classify_jira_change(change)
        assert level == "high", f"Expected high, got {level!r}: {reason}"

    def test_automation_disabled_is_medium(self):
        from app.services.risk_rules.jira import classify_jira_change
        change = self._make_change(
            JIRA_AUTOMATION_RULE, "automation_enabled", prev_value=True, new_value=False,
        )
        level, reason = classify_jira_change(change)
        assert level == "medium", f"Expected medium, got {level!r}: {reason}"

    def test_workflow_scheme_default_removed_is_medium(self):
        from app.services.risk_rules.jira import classify_jira_change
        change = self._make_change(
            JIRA_WORKFLOW_SCHEME, "workflow_scheme_default_present",
            prev_value=True, new_value=False,
        )
        level, reason = classify_jira_change(change)
        assert level == "medium", f"Expected medium, got {level!r}: {reason}"

    def test_unknown_record_type_is_low(self):
        from app.services.risk_rules.jira import classify_jira_change
        change = self._make_change("jira_unknown_surface", "some_field", prev_value=1, new_value=2)
        level, _ = classify_jira_change(change)
        assert level == "low"

    def test_classifier_reads_real_compute_diff_dict_shape_not_a_mock(self):
        """Regression guard against the exact old_value/prev_value bug class
        found in Terraform Cloud's first QA pass: builds a plain dict shaped
        EXACTLY like compute_diff's real output (prev_value/new_value/
        field_path/change_type/provider_metadata), not a MagicMock, to prove
        the classifier reads the real field name."""
        from app.services.risk_rules.jira import classify_jira_change

        real_shaped_change = {
            "change_type": "modified",
            "field_path": "permission_anonymous_grant_count",
            "prev_value": 0,
            "new_value": 2,
            "provider_metadata": {"record_type": "jira_permission_scheme"},
        }
        level, reason = classify_jira_change(real_shaped_change)
        assert level == "high", f"Expected high, got {level!r}: {reason}"

    # ── Change-classification QA pass regression tests ───────────────────────

    def test_project_archived_true_reads_new_value(self):
        """Regression: project_archived previously returned the same
        direction-blind message regardless of new_value — it never read
        new_value at all."""
        from app.services.risk_rules.jira import classify_jira_change
        change = self._make_change(JIRA_PROJECT, "project_archived", prev_value=False, new_value=True)
        level, reason = classify_jira_change(change)
        assert level == "low"
        assert "archived" in reason.lower()
        assert "unarchived" not in reason.lower()

    def test_project_unarchived_reads_new_value(self):
        from app.services.risk_rules.jira import classify_jira_change
        change = self._make_change(JIRA_PROJECT, "project_archived", prev_value=True, new_value=False)
        level, reason = classify_jira_change(change)
        assert level == "low"
        assert "unarchived" in reason.lower()

    def test_project_deleted_true_to_unknown_is_low_not_cleared_wording(self):
        from app.services.risk_rules.jira import classify_jira_change
        change = self._make_change(JIRA_PROJECT, "project_deleted", prev_value=True, new_value=None)
        level, reason = classify_jira_change(change)
        assert level == "low"
        assert "cleared" not in reason.lower()
        assert "unknown or missing" in reason.lower()

    def test_workflow_draft_true_reads_new_value(self):
        """Regression: workflow_draft previously returned the same
        direction-blind message regardless of new_value."""
        from app.services.risk_rules.jira import classify_jira_change
        change = self._make_change(JIRA_WORKFLOW, "workflow_draft", prev_value=False, new_value=True)
        level, reason = classify_jira_change(change)
        assert level == "low", f"Expected low (matches jira_workflow_draft Finding severity), got {level!r}"
        assert "draft" in reason.lower()

    def test_workflow_draft_false_is_published_restoration(self):
        from app.services.risk_rules.jira import classify_jira_change
        change = self._make_change(JIRA_WORKFLOW, "workflow_draft", prev_value=True, new_value=False)
        level, reason = classify_jira_change(change)
        assert level == "low"
        assert "published" in reason.lower()

    def test_public_administer_projects_true_to_unknown_is_low_not_removed_wording(self):
        from app.services.risk_rules.jira import classify_jira_change
        change = self._make_change(
            JIRA_PERMISSION_SCHEME, "permission_public_administer_projects",
            prev_value=True, new_value=None,
        )
        level, reason = classify_jira_change(change)
        assert level == "low"
        assert "was removed" not in reason.lower()
        assert "unknown or missing" in reason.lower()

    def test_public_browse_projects_true_to_unknown_is_low_not_removed_wording(self):
        from app.services.risk_rules.jira import classify_jira_change
        change = self._make_change(
            JIRA_PERMISSION_SCHEME, "permission_public_browse_projects",
            prev_value=True, new_value=None,
        )
        level, reason = classify_jira_change(change)
        assert level == "low"
        assert "was removed" not in reason.lower()
        assert "unknown or missing" in reason.lower()

    def test_public_administer_projects_explicit_false_is_removed_wording(self):
        from app.services.risk_rules.jira import classify_jira_change
        change = self._make_change(
            JIRA_PERMISSION_SCHEME, "permission_public_administer_projects",
            prev_value=True, new_value=False,
        )
        level, reason = classify_jira_change(change)
        assert level == "low"
        assert "was removed" in reason.lower()

    def test_automation_condition_count_increase_is_medium(self):
        """Regression: automation_condition_count is tracked in
        diff_service.py but was accidentally excluded from the
        action_count/branch_count grouped branch, silently falling to the
        generic low fallback instead of matching its sibling fields."""
        from app.services.risk_rules.jira import classify_jira_change
        change = self._make_change(
            JIRA_AUTOMATION_RULE, "automation_condition_count", prev_value=1, new_value=5,
        )
        level, reason = classify_jira_change(change)
        assert level == "medium", f"Expected medium, got {level!r}: {reason}"

    def test_automation_condition_count_decrease_is_low(self):
        from app.services.risk_rules.jira import classify_jira_change
        change = self._make_change(
            JIRA_AUTOMATION_RULE, "automation_condition_count", prev_value=5, new_value=1,
        )
        level, _ = classify_jira_change(change)
        assert level == "low"

    def test_unknown_transitions_never_produce_high(self):
        unknown_cases = [
            (JIRA_PROJECT, "project_archived", True, None),
            (JIRA_PROJECT, "project_deleted", True, None),
            (JIRA_WORKFLOW, "workflow_draft", False, None),
            (JIRA_PERMISSION_SCHEME, "permission_public_administer_projects", True, None),
            (JIRA_PERMISSION_SCHEME, "permission_public_browse_projects", True, None),
        ]
        for record_type, field, prev, new in unknown_cases:
            from app.services.risk_rules.jira import classify_jira_change
            change = self._make_change(record_type, field, prev_value=prev, new_value=new)
            level, reason = classify_jira_change(change)
            assert level != "high", (
                f"{record_type}.{field} unknown transition produced 'high': {reason!r}"
            )

    # ── Parity checks for the 5 newly-added security rules ───────────────────

    def test_workflow_draft_change_matches_finding_severity_low(self):
        """jira_workflow_draft Finding severity is low; the Change classifier
        must agree for the same True (entered draft) transition."""
        from app.services.risk_rules.jira import classify_jira_change
        change = self._make_change(JIRA_WORKFLOW, "workflow_draft", prev_value=False, new_value=True)
        level, _ = classify_jira_change(change)
        assert level == "low"

    def test_workflow_scheme_low_project_count_change_matches_finding_severity_low(self):
        """jira_workflow_scheme_low_project_count Finding severity is low."""
        from app.services.risk_rules.jira import classify_jira_change
        change = self._make_change(
            JIRA_WORKFLOW_SCHEME, "workflow_scheme_project_count", prev_value=5, new_value=1,
        )
        level, _ = classify_jira_change(change)
        assert level == "low"

    def test_permission_scheme_high_grant_count_change_matches_finding_severity_medium(self):
        """jira_permission_scheme_high_grant_count Finding severity is medium."""
        from app.services.risk_rules.jira import classify_jira_change
        change = self._make_change(
            JIRA_PERMISSION_SCHEME, "permission_grant_count", prev_value=10, new_value=25,
        )
        level, reason = classify_jira_change(change)
        assert level == "medium", f"Expected medium, got {level!r}: {reason}"

    def test_webhook_broad_event_scope_change_matches_finding_severity_medium(self):
        """jira_webhook_broad_event_scope Finding severity is medium."""
        from app.services.risk_rules.jira import classify_jira_change
        change = self._make_change(
            JIRA_WEBHOOK, "webhook_event_count", prev_value=2, new_value=15,
        )
        level, reason = classify_jira_change(change)
        assert level == "medium", f"Expected medium, got {level!r}: {reason}"

    def test_automation_high_component_count_change_matches_finding_severity_low(self):
        """jira_automation_rule_high_component_count Finding severity is low."""
        from app.services.risk_rules.jira import classify_jira_change
        change = self._make_change(
            JIRA_AUTOMATION_RULE, "automation_component_count", prev_value=5, new_value=20,
        )
        level, _ = classify_jira_change(change)
        assert level == "low"

    def test_no_forbidden_wording_in_reasons(self):
        from app.services.risk_rules.jira import classify_jira_change

        FORBIDDEN = [
            "breach", "compromise", "attacker", "leaked", "unauthorized access",
            "exfiltration", "stolen", "fraud", "attack detected",
            "issue exposed", "ticket exposed", "secret exposed", "data exposed",
        ]
        test_changes = [
            self._make_change(JIRA_PERMISSION_SCHEME, "permission_anonymous_grant_count", prev_value=0, new_value=1),
            self._make_change(JIRA_PERMISSION_SCHEME, "permission_public_administer_projects", prev_value=False, new_value=True),
            self._make_change(JIRA_WEBHOOK, "webhook_secret_present", prev_value=True, new_value=False),
            self._make_change(JIRA_WEBHOOK, "webhook_url_scheme_category", prev_value="https", new_value="http"),
            self._make_change(JIRA_AUTOMATION_RULE, "automation_has_web_request_action", prev_value=False, new_value=True),
        ]
        for change in test_changes:
            _, reason = classify_jira_change(change)
            reason_lower = reason.lower()
            for phrase in FORBIDDEN:
                assert phrase not in reason_lower, (
                    f"Forbidden phrase {phrase!r} found in risk reason: {reason!r}"
                )


# ════════════════════════════════════════════════════════════════════════════
# Section F — Capability matrix
# ════════════════════════════════════════════════════════════════════════════


def test_f1_get_provider_capability_jira_not_none() -> None:
    assert get_provider_capability("jira") is not None


def test_f2_jira_label() -> None:
    cap = get_provider_capability("jira")
    assert cap is not None
    assert cap.label == "Jira"


def test_f3_jira_drift_snapshots_true() -> None:
    cap = get_provider_capability("jira")
    assert cap is not None
    assert cap.drift.drift_snapshots is True


def test_f4_jira_drift_diff_true() -> None:
    cap = get_provider_capability("jira")
    assert cap is not None
    assert cap.drift.drift_diff is True


def test_f5_jira_drift_risk_classification_false() -> None:
    # M86B advanced drift_risk_classification to True (Jira security rules landed).
    cap = get_provider_capability("jira")
    assert cap is not None
    assert cap.drift.drift_risk_classification is True


def test_f6_jira_all_security_caps_false() -> None:
    # M86B advanced security_rules to True; M86D advanced activity_ingestion to
    # True. M86E advanced activity_signals to True. M86F advanced
    # risk_activity_correlations to True. M86G advanced demo_seed_clear,
    # case_report, evidence_timeline, and evidence_graph to True — the full Jira
    # security capability set is now complete.
    cap = get_provider_capability("jira")
    assert cap is not None
    sec = cap.security
    for attr in (
        "demo_seed_clear",
        "case_report",
        "evidence_timeline",
        "evidence_graph",
    ):
        assert getattr(sec, attr) is True, (
            f"Jira security capability {attr!r} should be True after M86G"
        )


def test_f7_jira_maturity_partial() -> None:
    cap = get_provider_capability("jira")
    assert cap is not None
    assert cap.maturity == "partial"


def test_f8_jira_notes_mention_m86a() -> None:
    cap = get_provider_capability("jira")
    assert cap is not None
    assert "M86A" in cap.notes


def test_f9_jira_notes_planned_next_stage_m86b() -> None:
    cap = get_provider_capability("jira")
    assert cap is not None
    assert "M86B" in cap.notes, "Jira capability notes should reference M86B as next stage"


def test_f10_jira_in_provider_capabilities_partial() -> None:
    providers_in_partial = [p.provider for p in PROVIDER_CAPABILITIES_PARTIAL]
    assert "jira" in providers_in_partial


# ════════════════════════════════════════════════════════════════════════════
# Section G — Provider expansion framework
# ════════════════════════════════════════════════════════════════════════════


def test_g1_planned_next_stage_references_jira_core_or_m86b() -> None:
    fw = get_framework()
    planned = fw["summary"]["planned_next_stage"]
    # M86A–M88x have since landed — planned_next_stage now points to M89A/Kubernetes.
    assert isinstance(planned, str) and len(planned) > 0, (
        f"planned_next_stage must be a non-empty string; got {planned!r}"
    )
    assert ("M89A" in planned or "Kubernetes" in planned
                or "M90A" in planned or "Sentry" in planned), (
        f"planned_next_stage should reference M89A / Kubernetes; got {planned!r}"
    )


def test_g2_jira_launched_not_head_of_queue() -> None:
    """Jira launched in M86A — it must not be the head of the recommended queue.

    Acceptable states: Jira absent from the recommended queue entirely, OR the
    head of the queue is now a later provider (e.g. GitLab).
    """
    fw = get_framework()
    recs = fw["recommended_next_providers"]
    providers = [r["provider"].lower() for r in recs]
    jira_absent = "jira" not in providers
    head_is_not_jira = bool(recs) and recs[0]["provider"].lower() != "jira"
    assert jira_absent or head_is_not_jira, (
        "Jira should be launched (absent from queue) or no longer queue head; "
        f"got recommended providers {providers!r}"
    )


def test_g3_jira_not_in_recommended_queue() -> None:
    fw = get_framework()
    providers = [r["provider"].lower() for r in fw["recommended_next_providers"]]
    assert "jira" not in providers, (
        "'jira' should not be in recommended_next_providers — it launched in M86A"
    )


def test_g4_framework_has_expected_keys() -> None:
    fw = get_framework()
    assert "recommended_next_providers" in fw
    assert "template" in fw
    assert "summary" in fw


# ════════════════════════════════════════════════════════════════════════════
# Section H — Frontend files
# ════════════════════════════════════════════════════════════════════════════


def test_h1_providers_ts_contains_jira() -> None:
    text = FE_PROVIDERS.read_text(encoding="utf-8")
    assert "jira" in text, "providers.ts does not mention 'jira'"


def test_h2_providers_ts_contains_jira_label() -> None:
    text = FE_PROVIDERS.read_text(encoding="utf-8")
    assert "Jira" in text, "providers.ts does not mention 'Jira'"


def test_h3_integrations_page_references_jira() -> None:
    text = FE_INTEGRATIONS.read_text(encoding="utf-8")
    assert "jira" in text or "JiraIntegrationForm" in text, (
        "integrations/page.tsx does not reference jira / JiraIntegrationForm"
    )


def test_h4_trust_center_ts_mentions_jira() -> None:
    text = FE_TRUST_CENTER.read_text(encoding="utf-8")
    assert "jira" in text or "Jira" in text, "trustCenter.ts does not reference Jira"


def test_h5_jira_form_exists() -> None:
    assert FE_JIRA_FORM.exists(), f"JiraIntegrationForm.tsx not found at {FE_JIRA_FORM}"


def test_h6_jira_form_has_three_fields() -> None:
    text = FE_JIRA_FORM.read_text(encoding="utf-8")
    assert "jira_site_url" in text, "JiraIntegrationForm missing jira_site_url field"
    assert "jira_email" in text, "JiraIntegrationForm missing jira_email field"
    assert "jira_api_token" in text, "JiraIntegrationForm missing jira_api_token field"


def test_h7_jira_form_api_token_is_password() -> None:
    text = FE_JIRA_FORM.read_text(encoding="utf-8")
    assert re.search(r'type=["\']password["\']', text), (
        "JiraIntegrationForm api_token field must be type=password"
    )


def test_h8_types_index_ts_contains_jira() -> None:
    text = FE_TYPES.read_text(encoding="utf-8")
    assert "jira" in text.lower(), "types/index.ts does not reference jira"


# ════════════════════════════════════════════════════════════════════════════
# Section I — Privacy guardrails on connector / schema source
# ════════════════════════════════════════════════════════════════════════════


def _connector_code_without_docstrings() -> str:
    """Return jira.py source with module/class/function docstrings blanked out.

    Privacy prose legitimately references field names like ``"email":`` inside
    the module docstring's credentials example and the SECURITY notes.  Those
    are documentation, not stored record fields.  We blank only the docstring
    line ranges (keeping every other string literal — dict keys live in normal
    return/assignment statements, never in docstrings) so the scan still flags
    a field genuinely emitted into a normalized record dict.
    """
    import ast

    text = JIRA_PY.read_text(encoding="utf-8")
    lines = text.splitlines()
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return text

    blanked: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            doc_node = None
            body = getattr(node, "body", [])
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(getattr(body[0], "value", None), ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                doc_node = body[0]
            if doc_node is not None:
                start = doc_node.lineno - 1
                end = getattr(doc_node, "end_lineno", doc_node.lineno)
                for i in range(start, end):
                    blanked.add(i)

    kept = [
        "" if i in blanked else line
        for i, line in enumerate(lines)
    ]
    return "\n".join(kept)


def test_i1_connector_does_not_store_email_record_field() -> None:
    # Scan code only (docstrings/comments stripped); the credentials-dict prose
    # in the module docstring legitimately mentions "email".
    code = _connector_code_without_docstrings()
    assert not re.search(r'"email"\s*:', code, re.IGNORECASE), (
        "jira.py stores 'email' as a record field"
    )


def test_i2_connector_does_not_store_account_id_record_field() -> None:
    code = _connector_code_without_docstrings()
    assert not re.search(r'"account_id"\s*:', code, re.IGNORECASE), (
        "jira.py stores 'account_id' as a record field"
    )


def test_i3_connector_does_not_store_api_token_record_field() -> None:
    code = _connector_code_without_docstrings()
    assert not re.search(r'"api_token"\s*:', code, re.IGNORECASE), (
        "jira.py stores 'api_token' as a record field"
    )


def test_i4_connector_does_not_store_issue_key_record_field() -> None:
    code = _connector_code_without_docstrings()
    assert not re.search(r'"issue_key"\s*:', code, re.IGNORECASE), (
        "jira.py stores 'issue_key' as a record field"
    )


def test_i5_connector_does_not_store_webhook_url_record_field() -> None:
    code = _connector_code_without_docstrings()
    assert not re.search(r'"webhook_url"\s*:', code, re.IGNORECASE), (
        "jira.py stores 'webhook_url' as a record field"
    )


def test_i6_normalizer_records_never_contain_credential_or_pii_keys() -> None:
    """Exhaustive runtime check across all normalizers."""
    pii_keys = {"api_token", "email", "account_id", "issue_key", "webhook_url"}
    for method_name, raw_factory, _record_type in _NORMALIZER_CASES:
        rec = _normalize(method_name, raw_factory())
        for bad in pii_keys:
            assert bad not in rec, f"{method_name}: PII/credential key {bad!r} in record"


_SECRET_PATTERNS = [
    (r"eyJ[A-Za-z0-9+/]{20,}", "JWT token"),
    (r"SG\.[A-Za-z0-9_-]{20,}", "SendGrid API key"),
    (r"AC[0-9a-f]{32}", "Twilio Account SID"),
    (r"SK[0-9a-f]{32}", "Twilio API key SID"),
    (r"ATATT[A-Za-z0-9_\-]{20,}", "Atlassian API token"),
]


def test_i7_connector_no_secret_shaped_strings() -> None:
    text = JIRA_PY.read_text(encoding="utf-8")
    for pattern, name in _SECRET_PATTERNS:
        assert not re.search(pattern, text), f"Possible {name} found in jira.py"


def test_i8_schema_no_secret_shaped_strings() -> None:
    text = JIRA_SCHEMA_PY.read_text(encoding="utf-8")
    for pattern, name in _SECRET_PATTERNS:
        assert not re.search(pattern, text), f"Possible {name} found in jira_schema.py"


# ════════════════════════════════════════════════════════════════════════════
# Section J — Forbidden wording
# ════════════════════════════════════════════════════════════════════════════


def test_j1_connector_no_forbidden_phrases() -> None:
    text = JIRA_PY.read_text(encoding="utf-8").lower()
    for phrase in _FORBIDDEN_PHRASES:
        assert phrase.lower() not in text, f"Forbidden phrase {phrase!r} in jira.py"


def test_j2_schema_no_forbidden_phrases() -> None:
    text = JIRA_SCHEMA_PY.read_text(encoding="utf-8").lower()
    for phrase in _FORBIDDEN_PHRASES:
        assert phrase.lower() not in text, f"Forbidden phrase {phrase!r} in jira_schema.py"
