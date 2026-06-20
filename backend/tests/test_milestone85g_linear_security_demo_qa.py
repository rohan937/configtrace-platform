"""M85G: Linear security demo QA tests.

Validates that the Linear security demo seed/clear/status functions exist
and behave correctly, that the router wires them properly, that the capability
matrix marks demo_seed_clear=True, that the case report service labels
Linear, that the provider expansion framework points to M85H with Jira at the
head of the recommended provider queue, and that no forbidden phrases or
secret-shaped strings appear in the Linear demo code path.

The seeded finding keys use the real Linear rule keys defined in
linear_risk_activity_correlation_service:
  linear_webhook_no_secret_indicator, linear_webhook_non_https,
  linear_webhook_broad_resource_scope.

NOTE: These tests deliberately exercise only import/structure/mock paths for
the demo seed/clear/status functions. They never call seed_linear against a
real database — db-level behavior would require a live database fixture.
"""
from __future__ import annotations

import re
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.services.provider_capability_matrix_service import get_provider_capability
from app.services.provider_expansion_framework import get_framework

# ── Constants ─────────────────────────────────────────────────────────────────

LINEAR_DEMO_CASE_SOURCE = "demo_linear_incident"

_FORBIDDEN_PHRASES = [
    "compromise confirmed",
    "secret leaked",
    "data leaked",
    "breach confirmed",
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

# The real Linear webhook rule keys the demo seeds findings for.
_LINEAR_DEMO_RULE_KEYS = [
    "linear_webhook_no_secret_indicator",
    "linear_webhook_non_https",
    "linear_webhook_broad_resource_scope",
]


# ── Section A: Importability ──────────────────────────────────────────────────


def test_seed_linear_importable() -> None:
    from app.services.security_incident_demo_service import seed_linear  # noqa: F401
    assert callable(seed_linear)


def test_clear_linear_importable() -> None:
    from app.services.security_incident_demo_service import clear_linear  # noqa: F401
    assert callable(clear_linear)


def test_get_linear_status_importable() -> None:
    from app.services.security_incident_demo_service import get_linear_status  # noqa: F401
    assert callable(get_linear_status)


def test_demo_constants_present() -> None:
    from app.services.security_incident_demo_service import (
        LINEAR_DEMO_INTEGRATION_NAME,
        LINEAR_DEMO_CASE_SOURCE as _SRC,
        LINEAR_DEMO_DATASET,
    )
    assert LINEAR_DEMO_INTEGRATION_NAME
    assert _SRC == "demo_linear_incident"
    assert LINEAR_DEMO_DATASET


# ── Section B: Privacy / no secrets in demo code ─────────────────────────────

_SVC_PATH = (
    Path(__file__).parent.parent
    / "app" / "services" / "security_incident_demo_service.py"
)


def _linear_demo_section() -> str:
    """Return the text from the LINEAR_DEMO_INTEGRATION_NAME line onward."""
    text = _SVC_PATH.read_text()
    idx = text.find("LINEAR_DEMO_INTEGRATION_NAME")
    assert idx != -1, "LINEAR_DEMO_INTEGRATION_NAME not found in demo service"
    return text[idx:]


def test_no_secret_shaped_strings_in_linear_demo() -> None:
    section = _linear_demo_section()
    assert not re.search(r"eyJ[A-Za-z0-9_\-]{10,}", section), (
        "Found JWT-shaped string in Linear demo section"
    )
    assert not re.search(r"SG\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}", section), (
        "Found SendGrid-key-shaped string in Linear demo section"
    )
    assert not re.search(r"AC[0-9a-fA-F]{32}", section), (
        "Found Twilio-SID-shaped string in Linear demo section"
    )
    assert not re.search(r"SK[0-9a-fA-F]{32}", section), (
        "Found SK-secret-shaped string in Linear demo section"
    )


def test_no_forbidden_wording_in_linear_demo() -> None:
    section = _linear_demo_section().lower()
    for phrase in _FORBIDDEN_PHRASES:
        assert phrase not in section, (
            f"Forbidden phrase '{phrase}' found in Linear demo section"
        )


def test_linear_demo_placeholder_safe() -> None:
    from app.services.security_incident_demo_service import (
        _LINEAR_DEMO_WEBHOOK_ID,
    )
    assert "LINEAR" in _LINEAR_DEMO_WEBHOOK_ID
    # Must not look like a real JWT token
    assert not re.match(r"eyJ", _LINEAR_DEMO_WEBHOOK_ID)
    # Must not look like a real SendGrid API key
    assert not re.search(r"SG\.[A-Za-z0-9_\-]{10,}", _LINEAR_DEMO_WEBHOOK_ID)
    # Must not look like a Twilio account SID
    assert not re.search(r"AC[0-9a-fA-F]{32}", _LINEAR_DEMO_WEBHOOK_ID)
    # Must not look like an SK-shaped secret
    assert not re.search(r"SK[0-9a-fA-F]{32}", _LINEAR_DEMO_WEBHOOK_ID)


def test_linear_demo_uses_real_rule_keys() -> None:
    """Seeded finding keys must be real Linear webhook rule keys."""
    from app.services.linear_risk_activity_correlation_service import (
        LINEAR_CORRELATION_RULES,
    )
    webhook_rule = LINEAR_CORRELATION_RULES["linear_webhook_risk_activity_correlation"]
    for key in _LINEAR_DEMO_RULE_KEYS:
        assert key in webhook_rule["rule_keys"], (
            f"Expected real Linear rule key '{key}' in webhook correlation rule"
        )


def test_linear_demo_section_references_real_rule_keys() -> None:
    """The demo section must seed findings using the real Linear rule keys."""
    section = _linear_demo_section()
    for key in _LINEAR_DEMO_RULE_KEYS:
        assert key in section, (
            f"Linear demo section does not reference rule key '{key}'"
        )


def test_linear_demo_evidence_has_no_real_urls() -> None:
    """Verify the demo section never stores a delivery URL or real endpoint."""
    section = _linear_demo_section()
    assert "http://" not in section, "Found http:// in Linear demo section"
    assert "https://" not in section, "Found https:// in Linear demo section"


# ── Section C: Status ─────────────────────────────────────────────────────────


def test_get_linear_status_not_seeded() -> None:
    from app.services.security_incident_demo_service import get_linear_status

    mock_db = MagicMock()
    mock_db.query.return_value.filter.return_value.first.return_value = None

    workspace_id = uuid.uuid4()
    result = get_linear_status(workspace_id, mock_db)
    assert result["seeded"] is False
    assert result["case_id"] is None


# ── Section D: Idempotency ────────────────────────────────────────────────────


def test_seed_linear_idempotent() -> None:
    from app.services.security_incident_demo_service import seed_linear

    existing_case = MagicMock()
    existing_case.id = uuid.uuid4()

    mock_db = MagicMock()
    mock_db.query.return_value.filter.return_value.first.return_value = existing_case

    with patch(
        "app.services.security_incident_demo_service.case_svc.count_links",
        return_value=4,
    ):
        result = seed_linear(
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


def test_router_seed_linear_wired() -> None:
    content = _ROUTER_PATH.read_text()
    assert "seed_linear" in content
    assert 'prov == "linear"' in content


def test_router_clear_linear_wired() -> None:
    content = _ROUTER_PATH.read_text()
    assert "clear_linear" in content


def test_router_status_linear_wired() -> None:
    content = _ROUTER_PATH.read_text()
    assert "get_linear_status" in content


def test_router_seed_endpoint_handles_linear() -> None:
    """The /incident-demo/seed endpoint dispatches the 'linear' provider."""
    content = _ROUTER_PATH.read_text()
    assert "security_incident_demo_service.seed_linear" in content


def test_router_clear_endpoint_handles_linear() -> None:
    """The /incident-demo/clear endpoint dispatches the 'linear' provider."""
    content = _ROUTER_PATH.read_text()
    assert "security_incident_demo_service.clear_linear" in content


def test_router_status_endpoint_handles_linear() -> None:
    """The /incident-demo/status endpoint dispatches the 'linear' provider."""
    content = _ROUTER_PATH.read_text()
    assert "security_incident_demo_service.get_linear_status" in content


# ── Section F: Case report ────────────────────────────────────────────────────

_CASE_REPORT_PATH = (
    Path(__file__).parent.parent
    / "app" / "services" / "security_case_report_service.py"
)


def test_case_report_has_linear_label() -> None:
    content = _CASE_REPORT_PATH.read_text()
    assert '"linear": "Linear"' in content


# ── Section G: Capability matrix ─────────────────────────────────────────────


def test_capability_matrix_linear_demo_true() -> None:
    cap = get_provider_capability("linear")
    assert cap is not None
    assert cap.security.demo_seed_clear is True


def test_capability_matrix_linear_case_report_true() -> None:
    cap = get_provider_capability("linear")
    assert cap is not None
    assert cap.security.case_report is True


def test_capability_matrix_linear_activity_ingestion_true() -> None:
    cap = get_provider_capability("linear")
    assert cap is not None
    assert cap.security.activity_ingestion is True


def test_capability_matrix_linear_activity_signals_true() -> None:
    cap = get_provider_capability("linear")
    assert cap is not None
    assert cap.security.activity_signals is True


def test_capability_matrix_linear_risk_activity_correlations_true() -> None:
    cap = get_provider_capability("linear")
    assert cap is not None
    assert cap.security.risk_activity_correlations is True


def test_capability_matrix_linear_all_m85a_f_flags() -> None:
    """All M85A-F capability flags must be True for Linear."""
    cap = get_provider_capability("linear")
    assert cap is not None
    assert cap.security.security_rules is True
    assert cap.security.activity_ingestion is True
    assert cap.security.activity_signals is True
    assert cap.security.risk_activity_correlations is True


# ── Section H: Expansion framework ───────────────────────────────────────────


def test_expansion_framework_planned_next_stage_m85h() -> None:
    # M85I complete; framework now points to M86A/Jira.
    fw = get_framework()
    planned = fw.get("summary", {}).get("planned_next_stage", "")
    assert "M86" in planned or "Jira" in planned, (
        f"Expected M86/Jira in planned_next_stage, got '{planned}'"
    )


def test_expansion_framework_jira_at_head_of_queue() -> None:
    """Jira must be the head of the recommended next-provider queue."""
    fw = get_framework()
    recs = fw.get("recommended_next_providers", [])
    assert recs, "Recommended next-provider queue is empty"
    assert recs[0]["provider"] == "jira", (
        f"Expected 'jira' at head of recommended queue, got '{recs[0]['provider']}'"
    )
    assert recs[0]["label"] == "Jira"


def test_expansion_framework_next_provider_is_jira() -> None:
    fw = get_framework()
    next_provider = fw.get("summary", {}).get("next_provider", "")
    assert next_provider == "Jira", f"Expected next_provider 'Jira', got '{next_provider}'"


# ── Section I: Frontend ───────────────────────────────────────────────────────

_DEMO_SCRIPT_TS_PATH = (
    Path(__file__).parent.parent.parent
    / "frontend" / "src" / "lib" / "securityDemoScript.ts"
)


def test_demo_script_ts_includes_linear() -> None:
    content = _DEMO_SCRIPT_TS_PATH.read_text()
    assert "linear" in content
    assert "Linear" in content


def test_demo_script_ts_no_forbidden_wording() -> None:
    # Check only the Linear demo section, excluding 'avoid:' instructional fields
    # (those explicitly list forbidden phrases as examples of what NOT to say).
    import re as _re
    content = _DEMO_SCRIPT_TS_PATH.read_text()
    idx = content.find("DEMO_SCRIPT_LINEAR_INCIDENT")
    if idx < 0:
        idx = content.find("linear-config-risk")
    section = content[idx:].lower() if idx >= 0 else content.lower()
    # Strip avoid/warning fields that teach what NOT to say (single or multi-line).
    section = _re.sub(r'avoid\s*:\s*\[[^\]]*\]', '', section, flags=_re.DOTALL)
    section = _re.sub(r'avoid\s*:\s*"[^"]*"', '', section)
    for phrase in _FORBIDDEN_PHRASES:
        assert phrase not in section, (
            f"Forbidden phrase '{phrase}' found in Linear demo section of securityDemoScript.ts"
        )


# ── Section J: Signal/correlation types from earlier milestones ──────────────


def test_linear_signal_types_available() -> None:
    from app.services.linear_activity_signal_service import LINEAR_SIGNAL_TYPES
    assert "linear_webhook_config_changed" in LINEAR_SIGNAL_TYPES


def test_linear_correlation_types_available() -> None:
    from app.services.linear_risk_activity_correlation_service import (
        LINEAR_CORRELATION_TYPES,
    )
    assert "linear_webhook_risk_activity_correlation" in LINEAR_CORRELATION_TYPES


# ── Section K: Demo service wording discipline ────────────────────────────────


def test_linear_demo_case_source_unique() -> None:
    """Demo case source must be unique and not collide with other providers."""
    from app.services.security_incident_demo_service import (
        LINEAR_DEMO_CASE_SOURCE,
        CLERK_DEMO_CASE_SOURCE,
        DATADOG_DEMO_CASE_SOURCE,
        PAGERDUTY_DEMO_CASE_SOURCE,
    )
    assert LINEAR_DEMO_CASE_SOURCE != CLERK_DEMO_CASE_SOURCE
    assert LINEAR_DEMO_CASE_SOURCE != DATADOG_DEMO_CASE_SOURCE
    assert LINEAR_DEMO_CASE_SOURCE != PAGERDUTY_DEMO_CASE_SOURCE
    assert LINEAR_DEMO_CASE_SOURCE == "demo_linear_incident"


def test_linear_demo_integration_name_unique() -> None:
    from app.services.security_incident_demo_service import (
        LINEAR_DEMO_INTEGRATION_NAME,
        CLERK_DEMO_INTEGRATION_NAME,
        DATADOG_DEMO_INTEGRATION_NAME,
        PAGERDUTY_DEMO_INTEGRATION_NAME,
    )
    assert LINEAR_DEMO_INTEGRATION_NAME != CLERK_DEMO_INTEGRATION_NAME
    assert LINEAR_DEMO_INTEGRATION_NAME != DATADOG_DEMO_INTEGRATION_NAME
    assert LINEAR_DEMO_INTEGRATION_NAME != PAGERDUTY_DEMO_INTEGRATION_NAME


def test_linear_demo_summary_says_evidence_for_review() -> None:
    section = _linear_demo_section().lower()
    assert "evidence for review" in section


def test_linear_demo_summary_says_does_not_confirm() -> None:
    section = _linear_demo_section().lower()
    assert "does not confirm" in section
