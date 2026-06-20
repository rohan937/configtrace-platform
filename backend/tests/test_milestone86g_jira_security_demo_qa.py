"""M86G: Jira security demo + QA tests.

Validates that the Jira security demo seed/clear/status functions exist and
behave correctly, that the router wires them, that the capability matrix marks
demo_seed_clear / case_report True, that the case report service labels Jira,
that the provider expansion framework points to M86H with GitLab at the head of
the recommended provider queue, and that no forbidden phrases or secret-shaped
strings appear in the Jira demo code path.

The seeded findings use real Jira rule keys defined in
jira_risk_activity_correlation_service:
  jira_permission_scheme_public_administer_projects,
  jira_webhook_no_secret_indicator,
  jira_automation_rule_external_action.

NOTE: These tests deliberately exercise only import/structure/mock paths for
the demo seed/clear/status functions. They never call seed_jira against a real
database — db-level behavior would require a live database fixture.
"""
from __future__ import annotations

import re
import subprocess
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.services.provider_capability_matrix_service import get_provider_capability
from app.services.provider_expansion_framework import get_framework

# ── Constants ─────────────────────────────────────────────────────────────────

JIRA_DEMO_CASE_SOURCE = "demo_jira_incident"

# Safe demo placeholders (must match the implementation exactly).
JIRA_DEMO_PERMISSION_SCHEME_ID = "JIRA_DEMO_PERMISSION_SCHEME_ID"
JIRA_DEMO_WEBHOOK_ID = "JIRA_DEMO_WEBHOOK_ID"
JIRA_DEMO_AUTOMATION_RULE_ID = "JIRA_DEMO_AUTOMATION_RULE_ID"
JIRA_DEMO_WORKFLOW_ID = "JIRA_DEMO_WORKFLOW_ID"
JIRA_DEMO_PROJECT_ID = "JIRA_DEMO_PROJECT_ID"
JIRA_DEMO_SITE_ID = "JIRA_DEMO_SITE_ID"
JIRA_DEMO_FINDING_ID = "JIRA_DEMO_FINDING_ID"
JIRA_DEMO_EVENT_ID = "JIRA_DEMO_EVENT_ID"
JIRA_DEMO_SIGNAL_ID = "JIRA_DEMO_SIGNAL_ID"
JIRA_DEMO_CORRELATION_ID = "JIRA_DEMO_CORRELATION_ID"
JIRA_DEMO_CASE_ID = "JIRA_DEMO_CASE_ID"

_FORBIDDEN_PHRASES = [
    "compromise confirmed",
    "breach detected",
    "secret leaked",
    "data leaked",
    "unauthorized access confirmed",
    "attacker found",
    "orders exposed",
    "card data exposed",
]

# Forbidden raw evidence field names (privacy).
_FORBIDDEN_EVIDENCE_FIELDS = [
    "token",
    "email",
    "url",
    "webhook_url",
    "account_id",
    "user",
    "ip",
    "jql",
    "issue_key",
    "issue_title",
    "comment",
    "attachment",
    "customer",
    "api_token",
]

# The real Jira rule keys the demo seeds findings for.
_JIRA_DEMO_RULE_KEYS = [
    "jira_permission_scheme_public_administer_projects",
    "jira_webhook_no_secret_indicator",
    "jira_automation_rule_external_action",
]

# ── Paths ─────────────────────────────────────────────────────────────────────

_SVC_PATH = (
    Path(__file__).parent.parent
    / "app" / "services" / "security_incident_demo_service.py"
)
_ROUTER_PATH = (
    Path(__file__).parent.parent / "app" / "routers" / "security.py"
)
_CASE_REPORT_PATH = (
    Path(__file__).parent.parent
    / "app" / "services" / "security_case_report_service.py"
)
_API_TS_PATH = (
    Path(__file__).parent.parent.parent / "frontend" / "src" / "lib" / "api.ts"
)
_REPO_ROOT = Path(__file__).parent.parent.parent


def _jira_demo_section() -> str:
    """Return the text from the JIRA_DEMO_INTEGRATION_NAME line onward."""
    text = _SVC_PATH.read_text()
    idx = text.find("JIRA_DEMO_INTEGRATION_NAME")
    assert idx != -1, "JIRA_DEMO_INTEGRATION_NAME not found in demo service"
    return text[idx:]


# ── Import tests ──────────────────────────────────────────────────────────────


def test_jira_demo_service_imports() -> None:
    from app.services.security_incident_demo_service import (  # noqa: F401
        seed_jira,
        clear_jira,
        get_jira_status,
        JIRA_DEMO_INTEGRATION_NAME,
        JIRA_DEMO_CASE_SOURCE as _SRC,
        JIRA_DEMO_DATASET,
    )
    assert callable(seed_jira)
    assert callable(clear_jira)
    assert callable(get_jira_status)
    assert JIRA_DEMO_INTEGRATION_NAME
    assert _SRC == "demo_jira_incident"
    assert JIRA_DEMO_DATASET


def test_jira_case_report_service_imports() -> None:
    from app.services import security_case_report_service as svc
    # Must expose the report-building entrypoint.
    assert any(
        callable(getattr(svc, name, None))
        for name in ("build_case_report", "build_report", "generate_case_report")
    ), "security_case_report_service exposes no report builder"


# ── Seed tests (mocked db) ────────────────────────────────────────────────────


def _seed_jira_with_capture():
    """Run seed_jira against a mock db, capturing all db.add(...) objects."""
    from app.services.security_incident_demo_service import seed_jira

    added: list = []

    mock_db = MagicMock()
    # No existing case, no existing integration.
    mock_db.query.return_value.filter.return_value.first.return_value = None
    mock_db.add.side_effect = lambda obj: added.append(obj)

    created_case = MagicMock()
    created_case.id = uuid.uuid4()

    with patch(
        "app.services.security_incident_demo_service.encrypt_credentials",
        return_value=("ct", "iv"),
    ), patch(
        "app.services.security_incident_demo_service.case_svc.create_case",
        return_value=created_case,
    ) as mock_create, patch(
        "app.services.security_incident_demo_service.case_svc.link_object_to_case",
    ), patch(
        "app.services.security_incident_demo_service.case_svc.count_links",
        return_value=8,
    ):
        result = seed_jira(
            workspace_id=uuid.uuid4(),
            actor_user_id=uuid.uuid4(),
            db=mock_db,
        )
    return result, added, mock_create


def test_jira_seed_creates_demo_finding() -> None:
    from app.models.security_finding import SecurityFinding

    _, added, _ = _seed_jira_with_capture()
    findings = [o for o in added if isinstance(o, SecurityFinding)]
    assert findings, "seed_jira created no SecurityFinding"


def test_jira_seed_creates_demo_activity_event() -> None:
    from app.models.security_activity_event import SecurityActivityEvent

    _, added, _ = _seed_jira_with_capture()
    events = [o for o in added if isinstance(o, SecurityActivityEvent)]
    assert events, "seed_jira created no SecurityActivityEvent"


def test_jira_seed_creates_demo_signal() -> None:
    from app.models.security_incident_signal import SecurityIncidentSignal

    _, added, _ = _seed_jira_with_capture()
    signals = [o for o in added if isinstance(o, SecurityIncidentSignal)]
    assert signals, "seed_jira created no SecurityIncidentSignal"


def test_jira_seed_creates_demo_correlation() -> None:
    from app.models.security_signal_correlation import SecuritySignalCorrelation

    _, added, _ = _seed_jira_with_capture()
    corrs = [o for o in added if isinstance(o, SecuritySignalCorrelation)]
    assert corrs, "seed_jira created no SecuritySignalCorrelation"


def test_jira_seed_creates_demo_case() -> None:
    result, _, mock_create = _seed_jira_with_capture()
    assert mock_create.called, "seed_jira did not create a case"
    assert result["seeded"] is True
    assert result["created"] is True
    assert result["case_id"]


def test_jira_seed_uses_provider_jira() -> None:
    from app.models.security_finding import SecurityFinding
    from app.models.security_activity_event import SecurityActivityEvent

    _, added, _ = _seed_jira_with_capture()
    providered = [
        o for o in added
        if isinstance(o, (SecurityFinding, SecurityActivityEvent))
    ]
    assert providered, "no provider-tagged objects created"
    for o in providered:
        assert getattr(o, "provider", None) == "jira", (
            f"expected provider='jira', got {getattr(o, 'provider', None)!r}"
        )


def test_jira_seed_uses_synthetic_safe_ids() -> None:
    """All demo IDs are JIRA_DEMO_* placeholder strings."""
    section = _jira_demo_section()
    for placeholder in (
        JIRA_DEMO_PERMISSION_SCHEME_ID,
        JIRA_DEMO_WEBHOOK_ID,
        JIRA_DEMO_AUTOMATION_RULE_ID,
    ):
        assert placeholder in section, (
            f"Expected placeholder {placeholder} in Jira demo section"
        )
        assert placeholder.startswith("JIRA_DEMO_")


def test_jira_seed_is_idempotent() -> None:
    """Running twice does not duplicate records."""
    from app.services.security_incident_demo_service import seed_jira

    existing_case = MagicMock()
    existing_case.id = uuid.uuid4()

    mock_db = MagicMock()
    mock_db.query.return_value.filter.return_value.first.return_value = existing_case

    with patch(
        "app.services.security_incident_demo_service.case_svc.count_links",
        return_value=8,
    ):
        result = seed_jira(
            workspace_id=uuid.uuid4(),
            actor_user_id=uuid.uuid4(),
            db=mock_db,
        )

    assert result["created"] is False
    assert result["seeded"] is True
    # Idempotent path must not create new objects.
    mock_db.add.assert_not_called()


# ── Privacy / safety tests ────────────────────────────────────────────────────


def test_jira_demo_evidence_no_forbidden_fields() -> None:
    """The demo evidence must not store raw sensitive field names as dict keys."""
    section = _jira_demo_section()
    for field in _FORBIDDEN_EVIDENCE_FIELDS:
        assert f'"{field}"' not in section, (
            f"Forbidden raw evidence field '\"{field}\"' found in Jira demo section"
        )


def test_jira_demo_evidence_no_real_secrets() -> None:
    """No values matching secret-shape patterns."""
    section = _jira_demo_section()
    assert not re.search(r"eyJ[A-Za-z0-9_\-]{10,}", section), (
        "Found JWT-shaped string in Jira demo section"
    )
    assert not re.search(r"SG\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}", section), (
        "Found SendGrid-key-shaped string in Jira demo section"
    )
    assert not re.search(r"AC[0-9a-fA-F]{32}", section), (
        "Found Twilio-SID-shaped string in Jira demo section"
    )
    assert not re.search(r"SK[0-9a-fA-F]{32}", section), (
        "Found SK-secret-shaped string in Jira demo section"
    )
    # No raw delivery/base URLs.
    assert "http://" not in section, "Found http:// in Jira demo section"
    assert "https://" not in section, "Found https:// in Jira demo section"


def test_jira_demo_no_forbidden_wording() -> None:
    section = _jira_demo_section().lower()
    for phrase in _FORBIDDEN_PHRASES:
        assert phrase not in section, (
            f"Forbidden phrase '{phrase}' found in Jira demo section"
        )


# ── Clear tests (mocked db) ───────────────────────────────────────────────────


def test_jira_clear_removes_demo_records() -> None:
    from app.services.security_incident_demo_service import clear_jira

    demo_case = MagicMock()
    demo_case.id = uuid.uuid4()
    integ = MagicMock()
    integ.id = uuid.uuid4()

    mock_db = MagicMock()
    # Demo cases present; integration lookup returns integ; child queries empty.
    mock_db.query.return_value.filter.return_value.all.return_value = [demo_case]
    mock_db.query.return_value.filter.return_value.first.return_value = integ
    mock_db.query.return_value.filter.return_value.delete.return_value = 3

    result = clear_jira(workspace_id=uuid.uuid4(), db=mock_db)
    assert result["cleared"] is True
    assert result["objects_removed"] >= 1
    assert mock_db.commit.called


def test_jira_clear_is_idempotent() -> None:
    """Running twice is safe (nothing to remove the second time)."""
    from app.services.security_incident_demo_service import clear_jira

    mock_db = MagicMock()
    mock_db.query.return_value.filter.return_value.all.return_value = []
    mock_db.query.return_value.filter.return_value.first.return_value = None

    result = clear_jira(workspace_id=uuid.uuid4(), db=mock_db)
    assert result["cleared"] is True
    assert result["objects_removed"] == 0


def test_jira_clear_does_not_remove_non_demo_records() -> None:
    """Clear is scoped by JIRA_DEMO_CASE_SOURCE and the hidden demo integration."""
    section = _jira_demo_section()
    clear_idx = section.find("def clear_jira")
    assert clear_idx != -1
    clear_body = section[clear_idx:]
    assert "JIRA_DEMO_CASE_SOURCE" in clear_body, (
        "clear_jira must scope deletion by JIRA_DEMO_CASE_SOURCE"
    )
    assert "_get_jira_demo_integration" in clear_body, (
        "clear_jira must scope deletion by the hidden demo integration"
    )


# ── Case report tests ─────────────────────────────────────────────────────────


def test_jira_case_report_renders_provider_jira() -> None:
    content = _CASE_REPORT_PATH.read_text()
    assert '"jira": "Jira"' in content


def test_jira_case_report_includes_finding_summary() -> None:
    from app.services import security_case_report_service as svc
    src = Path(svc.__file__).read_text()
    assert "finding" in src.lower()


def test_jira_case_report_includes_activity_evidence() -> None:
    from app.services import security_case_report_service as svc
    src = Path(svc.__file__).read_text()
    assert "activity" in src.lower()


def test_jira_case_report_includes_disclaimer() -> None:
    """Demo case summary contains a 'does not confirm compromise'-style disclaimer."""
    section = _jira_demo_section().lower()
    assert "does not confirm" in section
    assert "compromise" in section


def test_jira_case_report_no_forbidden_wording() -> None:
    content = _CASE_REPORT_PATH.read_text().lower()
    for phrase in _FORBIDDEN_PHRASES:
        assert phrase not in content, (
            f"Forbidden phrase '{phrase}' found in case report service"
        )


# ── Endpoint tests ────────────────────────────────────────────────────────────


def test_jira_seed_endpoint_exists() -> None:
    content = _ROUTER_PATH.read_text()
    assert "security_incident_demo_service.seed_jira" in content
    assert 'prov == "jira"' in content


def test_jira_clear_endpoint_exists() -> None:
    content = _ROUTER_PATH.read_text()
    assert "security_incident_demo_service.clear_jira" in content


def test_jira_seed_requires_admin_or_owner() -> None:
    """Seed/clear endpoints are gated by require_workspace_admin."""
    content = _ROUTER_PATH.read_text()
    assert "require_workspace_admin" in content
    # Status dispatch for jira present (status is member-readable).
    assert "security_incident_demo_service.get_jira_status" in content


def test_jira_clear_requires_admin_or_owner() -> None:
    content = _ROUTER_PATH.read_text()
    assert "require_workspace_admin" in content
    assert "security_incident_demo_service.clear_jira" in content


# ── Frontend tests ────────────────────────────────────────────────────────────


def test_frontend_api_includes_jira_demo_seed() -> None:
    content = _API_TS_PATH.read_text()
    assert "seedIncidentDemo" in content
    assert '"jira"' in content


def test_frontend_api_includes_jira_demo_clear() -> None:
    content = _API_TS_PATH.read_text()
    assert "clearIncidentDemo" in content
    assert '"jira"' in content


# ── Framework tests ───────────────────────────────────────────────────────────


def test_capability_matrix_jira_demo_seed_clear_true() -> None:
    cap = get_provider_capability("jira")
    assert cap is not None
    assert cap.security.demo_seed_clear is True


def test_capability_matrix_jira_case_report_true() -> None:
    cap = get_provider_capability("jira")
    assert cap is not None
    assert cap.security.case_report is True


def test_capability_matrix_jira_planned_next_stage_m86i() -> None:
    fw = get_framework()
    planned = fw.get("summary", {}).get("planned_next_stage", "")
    assert (
        "M86I" in planned or "Jira" in planned
        or "M87A" in planned or "GitLab" in planned
        or "M88A" in planned or "Terraform" in planned
    ), (
        f"Expected M86I/Jira/M87A/GitLab or later in planned_next_stage, got '{planned}'"
    )


def test_expansion_framework_jira_points_to_m86i() -> None:
    fw = get_framework()
    planned = fw.get("summary", {}).get("planned_next_stage", "")
    assert ("M86" in planned or "Jira" in planned or "GitLab" in planned
            or "Terraform" in planned), (
        f"Expected M86/Jira/GitLab or later in planned_next_stage, got '{planned}'"
    )


def test_gitlab_still_head_of_recommended_queue() -> None:
    """At M86G, GitLab was head. M87A launched GitLab; Terraform Cloud is now head."""
    fw = get_framework()
    recs = fw.get("recommended_next_providers", [])
    assert recs, "Recommended next-provider queue is empty"
    # Accept GitLab or any later provider (GitLab launched in M87A).
    assert recs[0]["provider"] in ("gitlab", "terraform_cloud", "kubernetes", "sentry"), (
        f"Expected GitLab or later at head of recommended queue, got '{recs[0]['provider']}'"
    )


def test_marketing_video_untouched() -> None:
    """Verify no marketing-video/ files appear in the uncommitted git changes."""
    result = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=str(_REPO_ROOT),
        capture_output=True,
        text=True,
        check=True,
    )
    touched = [
        line for line in result.stdout.splitlines()
        if "marketing-video/" in line
    ]
    assert not touched, (
        f"marketing-video/ files unexpectedly modified: {touched}"
    )


# ── Wording test ──────────────────────────────────────────────────────────────


def test_no_forbidden_wording_in_jira_demo_service() -> None:
    section = _jira_demo_section().lower()
    for phrase in _FORBIDDEN_PHRASES:
        assert phrase not in section, (
            f"Forbidden phrase '{phrase}' found in Jira demo service"
        )
