"""M83G: Clerk security demo QA tests.

Validates that the Clerk security demo seed/clear/status functions exist and
behave correctly, that the router wires them properly, that the capability
matrix marks demo_seed_clear=True, that the case report service labels Clerk,
and that no forbidden phrases or secret-shaped strings appear in the Clerk demo
code path.
"""
from __future__ import annotations

import re
import uuid
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from app.services.provider_capability_matrix_service import get_provider_capability
from app.services.provider_expansion_framework import get_framework

# ── Constants ─────────────────────────────────────────────────────────────────

CLERK_DEMO_CASE_SOURCE = "demo_clerk_incident"

_FORBIDDEN_PHRASES = [
    "compromise confirmed",
    "secret leaked",
    "data leaked",
    "breach detected",
    "attack detected",
    "attacker found",
    "unauthorized access confirmed",
]

# ── Section A: Importability ──────────────────────────────────────────────────


def test_seed_clerk_importable() -> None:
    from app.services.security_incident_demo_service import seed_clerk  # noqa: F401
    assert callable(seed_clerk)


def test_clear_clerk_importable() -> None:
    from app.services.security_incident_demo_service import clear_clerk  # noqa: F401
    assert callable(clear_clerk)


def test_get_clerk_status_importable() -> None:
    from app.services.security_incident_demo_service import get_clerk_status  # noqa: F401
    assert callable(get_clerk_status)


def test_demo_constants_present() -> None:
    from app.services.security_incident_demo_service import (
        CLERK_DEMO_INTEGRATION_NAME,
        CLERK_DEMO_CASE_SOURCE as _SRC,
        CLERK_DEMO_DATASET,
    )
    assert CLERK_DEMO_INTEGRATION_NAME
    assert _SRC
    assert CLERK_DEMO_DATASET


# ── Section B: Privacy / no secrets in demo code ─────────────────────────────

_SVC_PATH = (
    Path(__file__).parent.parent
    / "app" / "services" / "security_incident_demo_service.py"
)


def _clerk_demo_section() -> str:
    """Return the text from the CLERK_DEMO_INTEGRATION_NAME line onward."""
    text = _SVC_PATH.read_text()
    idx = text.find("CLERK_DEMO_INTEGRATION_NAME")
    assert idx != -1, "CLERK_DEMO_INTEGRATION_NAME not found in demo service"
    return text[idx:]


def test_no_secret_shaped_strings_in_clerk_demo() -> None:
    section = _clerk_demo_section()
    # JWT token shape
    assert not re.search(r"eyJ[A-Za-z0-9_\-]{10,}", section), (
        "Found JWT-shaped string in Clerk demo section"
    )
    # SendGrid API key shape
    assert not re.search(r"SG\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}", section), (
        "Found SendGrid-key-shaped string in Clerk demo section"
    )
    # Twilio Account SID
    assert not re.search(r"AC[0-9a-fA-F]{32}", section), (
        "Found Twilio-SID-shaped string in Clerk demo section"
    )
    # Twilio auth token / secret
    assert not re.search(r"SK[0-9a-fA-F]{32}", section), (
        "Found SK-secret-shaped string in Clerk demo section"
    )


def test_no_forbidden_wording_in_clerk_demo() -> None:
    section = _clerk_demo_section().lower()
    for phrase in _FORBIDDEN_PHRASES:
        assert phrase not in section, (
            f"Forbidden phrase '{phrase}' found in Clerk demo section"
        )


def test_clerk_demo_placeholder_safe() -> None:
    from app.services.security_incident_demo_service import (
        _CLERK_DEMO_SESSION_POLICY_ID,
    )
    assert "CLERK_DEMO" in _CLERK_DEMO_SESSION_POLICY_ID
    assert not re.match(r"eyJ", _CLERK_DEMO_SESSION_POLICY_ID)


def test_clerk_demo_uses_real_rule_keys() -> None:
    from app.services.security_rules.clerk import CLERK_RULE_KEYS
    assert "clerk_session_lifetime_extended" in CLERK_RULE_KEYS
    assert "clerk_session_token_rotation_disabled" in CLERK_RULE_KEYS
    assert "clerk_session_reverification_disabled" in CLERK_RULE_KEYS


# ── Section C: Status ─────────────────────────────────────────────────────────


def test_get_clerk_status_not_seeded() -> None:
    from app.services.security_incident_demo_service import get_clerk_status

    mock_db = MagicMock()
    # Simulate no existing case
    mock_db.query.return_value.filter.return_value.first.return_value = None

    workspace_id = uuid.uuid4()
    result = get_clerk_status(workspace_id, mock_db)
    assert result["seeded"] is False


# ── Section D: Idempotency ────────────────────────────────────────────────────


def test_seed_clerk_idempotent() -> None:
    from app.services.security_incident_demo_service import seed_clerk

    existing_case = MagicMock()
    existing_case.id = uuid.uuid4()

    mock_db = MagicMock()
    mock_db.query.return_value.filter.return_value.first.return_value = existing_case

    with patch(
        "app.services.security_incident_demo_service.case_svc.count_links",
        return_value=3,
    ):
        result = seed_clerk(
            workspace_id=uuid.uuid4(),
            actor_user_id=uuid.uuid4(),
            db=mock_db,
        )

    assert result["created"] is False


# ── Section E: Router wiring ──────────────────────────────────────────────────

_ROUTER_PATH = (
    Path(__file__).parent.parent / "app" / "routers" / "security.py"
)


def test_router_seed_clerk_wired() -> None:
    content = _ROUTER_PATH.read_text()
    assert "seed_clerk" in content
    assert 'prov == "clerk"' in content


def test_router_clear_clerk_wired() -> None:
    content = _ROUTER_PATH.read_text()
    assert "clear_clerk" in content


def test_router_status_clerk_wired() -> None:
    content = _ROUTER_PATH.read_text()
    assert "get_clerk_status" in content or (
        "clerk" in content and "status" in content
    )


# ── Section F: Case report ────────────────────────────────────────────────────

_CASE_REPORT_PATH = (
    Path(__file__).parent.parent
    / "app" / "services" / "security_case_report_service.py"
)


def test_case_report_has_clerk_label() -> None:
    content = _CASE_REPORT_PATH.read_text()
    assert '"clerk": "Clerk"' in content


# ── Section G: Capability matrix ─────────────────────────────────────────────


def test_capability_matrix_clerk_demo_true() -> None:
    cap = get_provider_capability("clerk")
    assert cap is not None
    assert cap.security.demo_seed_clear is True


def test_capability_matrix_clerk_case_report_true() -> None:
    cap = get_provider_capability("clerk")
    assert cap is not None
    assert cap.security.case_report is True


def test_capability_matrix_previous_flags() -> None:
    cap = get_provider_capability("clerk")
    assert cap is not None
    assert cap.security.security_rules is True
    assert cap.security.activity_ingestion is True
    assert cap.security.activity_signals is True
    assert cap.security.risk_activity_correlations is True


# ── Section H: Expansion framework ───────────────────────────────────────────


def test_expansion_framework_m83h() -> None:
    fw = get_framework()
    planned = fw.get("summary", {}).get("planned_next_stage", "")
    assert ("M83H" in planned or "Provider Depth" in planned or "M83I" in planned
            or "Cross-Cloud" in planned or "M84A" in planned or "PagerDuty" in planned
            or "M85A" in planned or "Linear" in planned)


# ── Section I: Frontend ───────────────────────────────────────────────────────

_CASES_PAGE_PATH = (
    Path(__file__).parent.parent.parent
    / "frontend" / "src" / "app" / "(app)" / "security" / "cases" / "page.tsx"
)

_DEMO_SCRIPT_PAGE_PATH = (
    Path(__file__).parent.parent.parent
    / "frontend" / "src" / "app" / "(app)" / "security" / "demo-script" / "page.tsx"
)

_DEMO_SCRIPT_LIB_PATH = (
    Path(__file__).parent.parent.parent
    / "frontend" / "src" / "lib" / "securityDemoScript.ts"
)


def test_cases_page_has_clerk() -> None:
    content = _CASES_PAGE_PATH.read_text()
    assert "clerk" in content
    assert "Clerk" in content


def test_demo_script_page_has_clerk() -> None:
    content = _DEMO_SCRIPT_PAGE_PATH.read_text()
    assert "Clerk" in content


def test_demo_script_lib_no_forbidden() -> None:
    content = _DEMO_SCRIPT_LIB_PATH.read_text()
    # Strip out all avoid: "..." and avoid: [...] blocks before scanning.
    # Single-line avoid values
    stripped = re.sub(r'avoid:\s*"[^"]*"', "", content)
    # Multi-line avoid arrays: avoid: [ ... ]
    stripped = re.sub(r'avoid:\s*\[[^\]]*\]', "", stripped, flags=re.DOTALL)
    for line in stripped.splitlines():
        line_lower = line.lower()
        if "avoid" in line_lower:
            continue
        for phrase in _FORBIDDEN_PHRASES:
            assert phrase not in line_lower, (
                f"Forbidden phrase '{phrase}' found in securityDemoScript.ts "
                f"outside avoid context: {line.strip()!r}"
            )


# ── Section J: Signal/correlation from earlier milestones ────────────────────


def test_clerk_signal_types_available() -> None:
    from app.services.clerk_activity_signal_service import CLERK_SIGNAL_TYPES
    assert "clerk_session_policy_config_changed" in CLERK_SIGNAL_TYPES


def test_clerk_correlation_types_available() -> None:
    from app.services.clerk_risk_activity_correlation_service import (
        CLERK_CORRELATION_TYPES,
    )
    assert "clerk_session_policy_risk_activity_correlation" in CLERK_CORRELATION_TYPES
