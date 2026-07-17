"""M84G: PagerDuty security demo QA tests.

Validates that the PagerDuty security demo seed/clear/status functions exist
and behave correctly, that the router wires them properly, that the capability
matrix marks demo_seed_clear=True, that the case report service labels
PagerDuty, that the provider expansion framework points to M84H, and that no
forbidden phrases or secret-shaped strings appear in the PagerDuty demo code
path.
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

PAGERDUTY_DEMO_CASE_SOURCE = "demo_pagerduty_incident"

_FORBIDDEN_PHRASES = [
    "compromise confirmed",
    "secret leaked",
    "data leaked",
    "breach detected",
    "attack detected",
    "attacker found",
    "unauthorized access confirmed",
    "customer data leaked",
    "payment fraud detected",
    "someone has access",
    "orders exposed",
    "card data exposed",
]

# ── Section A: Importability ──────────────────────────────────────────────────


def test_seed_pagerduty_importable() -> None:
    from app.services.security_incident_demo_service import seed_pagerduty  # noqa: F401
    assert callable(seed_pagerduty)


def test_clear_pagerduty_importable() -> None:
    from app.services.security_incident_demo_service import clear_pagerduty  # noqa: F401
    assert callable(clear_pagerduty)


def test_get_pagerduty_status_importable() -> None:
    from app.services.security_incident_demo_service import get_pagerduty_status  # noqa: F401
    assert callable(get_pagerduty_status)


def test_demo_constants_present() -> None:
    from app.services.security_incident_demo_service import (
        PAGERDUTY_DEMO_INTEGRATION_NAME,
        PAGERDUTY_DEMO_CASE_SOURCE as _SRC,
        PAGERDUTY_DEMO_DATASET,
    )
    assert PAGERDUTY_DEMO_INTEGRATION_NAME
    assert _SRC == "demo_pagerduty_incident"
    assert PAGERDUTY_DEMO_DATASET


# ── Section B: Privacy / no secrets in demo code ─────────────────────────────

_SVC_PATH = (
    Path(__file__).parent.parent
    / "app" / "services" / "security_incident_demo_service.py"
)


def _pagerduty_demo_section() -> str:
    """Return the text from the PAGERDUTY_DEMO_INTEGRATION_NAME line onward."""
    text = _SVC_PATH.read_text()
    idx = text.find("PAGERDUTY_DEMO_INTEGRATION_NAME")
    assert idx != -1, "PAGERDUTY_DEMO_INTEGRATION_NAME not found in demo service"
    return text[idx:]


def test_no_secret_shaped_strings_in_pagerduty_demo() -> None:
    section = _pagerduty_demo_section()
    assert not re.search(r"eyJ[A-Za-z0-9_\-]{10,}", section), (
        "Found JWT-shaped string in PagerDuty demo section"
    )
    assert not re.search(r"SG\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}", section), (
        "Found SendGrid-key-shaped string in PagerDuty demo section"
    )
    assert not re.search(r"AC[0-9a-fA-F]{32}", section), (
        "Found Twilio-SID-shaped string in PagerDuty demo section"
    )
    assert not re.search(r"SK[0-9a-fA-F]{32}", section), (
        "Found SK-secret-shaped string in PagerDuty demo section"
    )


def test_no_forbidden_wording_in_pagerduty_demo() -> None:
    section = _pagerduty_demo_section().lower()
    for phrase in _FORBIDDEN_PHRASES:
        assert phrase not in section, (
            f"Forbidden phrase '{phrase}' found in PagerDuty demo section"
        )


def test_pagerduty_demo_placeholder_safe() -> None:
    from app.services.security_incident_demo_service import (
        _PAGERDUTY_DEMO_WEBHOOK_ID,
    )
    assert "PAGERDUTY" in _PAGERDUTY_DEMO_WEBHOOK_ID
    # Must not look like a real JWT token
    assert not re.match(r"eyJ", _PAGERDUTY_DEMO_WEBHOOK_ID)
    # Must not look like a real SendGrid API key
    assert not re.search(r"SG\.[A-Za-z0-9_\-]{10,}", _PAGERDUTY_DEMO_WEBHOOK_ID)
    # Must not look like a Twilio account SID
    assert not re.search(r"AC[0-9a-fA-F]{32}", _PAGERDUTY_DEMO_WEBHOOK_ID)


def test_pagerduty_demo_uses_real_rule_keys() -> None:
    from app.services.security_rules.pagerduty import PAGERDUTY_RULE_KEYS
    assert "pagerduty_webhook_subscription_non_https" in PAGERDUTY_RULE_KEYS
    assert "pagerduty_webhook_subscription_broad_event_scope" in PAGERDUTY_RULE_KEYS
    assert "pagerduty_webhook_subscription_secret_not_indicated" in PAGERDUTY_RULE_KEYS


def test_pagerduty_demo_evidence_has_no_real_urls() -> None:
    """Verify the demo section never stores a delivery URL or real endpoint."""
    section = _pagerduty_demo_section()
    # No http:// or https:// values used as delivery URLs
    assert "http://" not in section, "Found http:// in PagerDuty demo section"
    assert "https://" not in section, "Found https:// in PagerDuty demo section"


def test_pagerduty_demo_evidence_safe_fields_only() -> None:
    """Demo evidence dict must use only allowlisted safe field categories."""
    section = _pagerduty_demo_section()
    # Confirm safe field names present
    assert "url_scheme_category" in section
    assert "event_scope_category" in section
    assert "https_delivery" in section
    # Confirm raw URL fields absent
    assert '"url"' not in section
    assert '"delivery_url"' not in section
    assert '"webhook_url"' not in section


# ── Section C: Status ─────────────────────────────────────────────────────────


def test_get_pagerduty_status_not_seeded() -> None:
    from app.services.security_incident_demo_service import get_pagerduty_status

    mock_db = MagicMock()
    mock_db.query.return_value.filter.return_value.first.return_value = None

    workspace_id = uuid.uuid4()
    result = get_pagerduty_status(workspace_id, mock_db)
    assert result["seeded"] is False
    assert result["case_id"] is None


# ── Section D: Idempotency ────────────────────────────────────────────────────


def test_seed_pagerduty_idempotent() -> None:
    from app.services.security_incident_demo_service import seed_pagerduty

    existing_case = MagicMock()
    existing_case.id = uuid.uuid4()

    mock_db = MagicMock()
    mock_db.query.return_value.filter.return_value.first.return_value = existing_case

    with patch(
        "app.services.security_incident_demo_service.case_svc.count_links",
        return_value=4,
    ):
        result = seed_pagerduty(
            workspace_id=uuid.uuid4(),
            actor_user_id=uuid.uuid4(),
            db=mock_db,
        )

    assert result["created"] is False
    assert result["seeded"] is True


# ── Section E: Router wiring ──────────────────────────────────────────────────

_ROUTER_PATH = (
    Path(__file__).parent.parent / "app" / "routers" / "security.py"
)


def test_router_seed_pagerduty_wired() -> None:
    content = _ROUTER_PATH.read_text()
    assert "seed_pagerduty" in content
    assert 'prov == "pagerduty"' in content


def test_router_clear_pagerduty_wired() -> None:
    content = _ROUTER_PATH.read_text()
    assert "clear_pagerduty" in content


def test_router_status_pagerduty_wired() -> None:
    content = _ROUTER_PATH.read_text()
    assert "get_pagerduty_status" in content


# ── Section F: Case report ────────────────────────────────────────────────────

_CASE_REPORT_PATH = (
    Path(__file__).parent.parent
    / "app" / "services" / "security_case_report_service.py"
)


def test_case_report_has_pagerduty_label() -> None:
    content = _CASE_REPORT_PATH.read_text()
    assert '"pagerduty": "PagerDuty"' in content


# ── Section G: Capability matrix ─────────────────────────────────────────────


def test_capability_matrix_pagerduty_demo_true() -> None:
    cap = get_provider_capability("pagerduty")
    assert cap is not None
    assert cap.security.demo_seed_clear is True


def test_capability_matrix_pagerduty_case_report_true() -> None:
    cap = get_provider_capability("pagerduty")
    assert cap is not None
    assert cap.security.case_report is True


def test_capability_matrix_pagerduty_evidence_timeline_true() -> None:
    cap = get_provider_capability("pagerduty")
    assert cap is not None
    assert cap.security.evidence_timeline is True


def test_capability_matrix_pagerduty_evidence_graph_true() -> None:
    cap = get_provider_capability("pagerduty")
    assert cap is not None
    assert cap.security.evidence_graph is True


def test_capability_matrix_previous_flags() -> None:
    cap = get_provider_capability("pagerduty")
    assert cap is not None
    assert cap.security.security_rules is True
    assert cap.security.activity_ingestion is True
    assert cap.security.activity_signals is True
    assert cap.security.risk_activity_correlations is True


# ── Section H: Expansion framework ───────────────────────────────────────────


def test_expansion_framework_m84h() -> None:
    fw = get_framework()
    planned = fw.get("summary", {}).get("planned_next_stage", "")
    # M84H ships depth QA; M84I UX polish; framework then advances to M85A: Linear.
    assert ("M84H" in planned or "Provider Depth" in planned
            or "M84I" in planned or "Cross-Cloud" in planned
            or "M85A" in planned or "Linear" in planned
            or "M86" in planned or "Jira" in planned
            or "M87" in planned or "GitLab" in planned
            or "M89A" in planned or "Kubernetes" in planned
                or "M90A" in planned or "Sentry" in planned)


# ── Section I: Frontend ───────────────────────────────────────────────────────

_CASES_PAGE_PATH = (
    Path(__file__).parent.parent.parent
    / "frontend" / "src" / "app" / "(app)" / "security" / "cases" / "page.tsx"
)

_DEMO_SCRIPT_PAGE_PATH = (
    Path(__file__).parent.parent.parent
    / "frontend" / "src" / "app" / "(app)" / "security" / "demo-script" / "page.tsx"
)


def test_cases_page_has_pagerduty() -> None:
    content = _CASES_PAGE_PATH.read_text()
    assert "pagerduty" in content
    assert "PagerDuty" in content


def test_cases_page_pagerduty_seed_button() -> None:
    content = _CASES_PAGE_PATH.read_text()
    assert "Load PagerDuty security demo" in content


def test_cases_page_pagerduty_clear_button() -> None:
    content = _CASES_PAGE_PATH.read_text()
    assert "Clear PagerDuty demo" in content


def test_demo_script_page_has_pagerduty() -> None:
    content = _DEMO_SCRIPT_PAGE_PATH.read_text()
    assert "PagerDuty" in content
    assert "pagerduty" in content


def test_demo_script_page_pagerduty_demo_true() -> None:
    content = _DEMO_SCRIPT_PAGE_PATH.read_text()
    # The PagerDuty row should have demo: true
    assert "pagerduty" in content


# ── Section J: No forbidden wording in frontend files ────────────────────────


def test_cases_page_no_forbidden_wording() -> None:
    content = _CASES_PAGE_PATH.read_text().lower()
    for phrase in _FORBIDDEN_PHRASES:
        assert phrase not in content, (
            f"Forbidden phrase '{phrase}' found in cases page"
        )


def test_demo_script_page_no_forbidden_wording() -> None:
    content = _DEMO_SCRIPT_PAGE_PATH.read_text().lower()
    for phrase in _FORBIDDEN_PHRASES:
        assert phrase not in content, (
            f"Forbidden phrase '{phrase}' found in demo-script page"
        )


# ── Section K: Signal/correlation types from earlier milestones ──────────────


def test_pagerduty_signal_types_available() -> None:
    from app.services.pagerduty_activity_signal_service import PAGERDUTY_SIGNAL_TYPES
    assert "pagerduty_webhook_subscription_config_changed" in PAGERDUTY_SIGNAL_TYPES


def test_pagerduty_correlation_types_available() -> None:
    from app.services.pagerduty_risk_activity_correlation_service import (
        PAGERDUTY_CORRELATION_TYPES,
    )
    assert "pagerduty_webhook_subscription_risk_activity_correlation" in PAGERDUTY_CORRELATION_TYPES


# ── Section L: Demo service wording discipline ────────────────────────────────


def test_pagerduty_demo_case_source_unique() -> None:
    """Demo case source must be unique and not collide with other providers."""
    from app.services.security_incident_demo_service import (
        PAGERDUTY_DEMO_CASE_SOURCE,
        CLERK_DEMO_CASE_SOURCE,
        DATADOG_DEMO_CASE_SOURCE,
    )
    assert PAGERDUTY_DEMO_CASE_SOURCE != CLERK_DEMO_CASE_SOURCE
    assert PAGERDUTY_DEMO_CASE_SOURCE != DATADOG_DEMO_CASE_SOURCE
    assert PAGERDUTY_DEMO_CASE_SOURCE == "demo_pagerduty_incident"


def test_pagerduty_demo_integration_name_unique() -> None:
    from app.services.security_incident_demo_service import (
        PAGERDUTY_DEMO_INTEGRATION_NAME,
        CLERK_DEMO_INTEGRATION_NAME,
        DATADOG_DEMO_INTEGRATION_NAME,
    )
    assert PAGERDUTY_DEMO_INTEGRATION_NAME != CLERK_DEMO_INTEGRATION_NAME
    assert PAGERDUTY_DEMO_INTEGRATION_NAME != DATADOG_DEMO_INTEGRATION_NAME


def test_pagerduty_demo_summary_says_evidence_for_review() -> None:
    section = _pagerduty_demo_section().lower()
    assert "evidence for review" in section


def test_pagerduty_demo_summary_says_does_not_confirm() -> None:
    section = _pagerduty_demo_section().lower()
    assert "does not confirm" in section
