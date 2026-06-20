"""M87G: GitLab security demo + QA tests.

Validates that the GitLab security demo seed/clear/status functions exist and
behave correctly, that the router wires them, that the capability matrix marks
demo_seed_clear / case_report True, that the case report service labels GitLab,
that the provider expansion framework points to M87H, and that no forbidden
phrases or secret-shaped strings appear in the GitLab demo code path.

Demo story: "GitLab Branch Protection and CI/CD Posture Review"
  Real GitLab rule keys seeded:
    gitlab_branch_force_push_enabled
    gitlab_webhook_secret_missing
    gitlab_ci_unprotected_unmasked_variables

NOTE: these tests deliberately exercise only import/structure/mock paths for
the demo seed/clear/status functions. They never call seed_gitlab against a
real database — db-level behavior would require a live database fixture.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from app.services.provider_capability_matrix_service import get_provider_capability
from app.services.provider_expansion_framework import get_framework

# ── Constants ─────────────────────────────────────────────────────────────────

GITLAB_DEMO_CASE_SOURCE = "demo_gitlab_posture_review"

# Safe demo placeholder IDs (must match the implementation exactly).
GITLAB_DEMO_PROJECT_001 = "GITLAB_DEMO_PROJECT_001"
GITLAB_DEMO_BRANCH_RULE_001 = "GITLAB_DEMO_BRANCH_RULE_001"
GITLAB_DEMO_WEBHOOK_001 = "GITLAB_DEMO_WEBHOOK_001"
GITLAB_DEMO_CI_VARIABLE_SUMMARY_001 = "GITLAB_DEMO_CI_VARIABLE_SUMMARY_001"

# Real GitLab rule keys the demo seeds findings for.
_GITLAB_DEMO_RULE_KEYS = [
    "gitlab_branch_force_push_enabled",
    "gitlab_webhook_secret_missing",
    "gitlab_ci_unprotected_unmasked_variables",
]

_FORBIDDEN_PHRASES = [
    "compromise confirmed",
    "breach detected",
    "secret leaked",
    "data leaked",
    "unauthorized access confirmed",
    "attacker found",
    "orders exposed",
    "card data exposed",
    "repo exposed",
    "source code leaked",
    "source code exposed",
    "token leaked",
    "secrets exposed",
    "credentials exposed",
]

# Forbidden raw evidence field names (privacy).
_FORBIDDEN_EVIDENCE_FIELDS = [
    "access_token",
    "private_token",
    "oauth_token",
    "webhook_secret",
    "secret_token",
    "authorization",
    "webhook_url",
    "url",
    "ci_variable_name",
    "ci_variable_value",
    "deploy_key_material",
    "ssh_key",
    "key_material",
    "runner_token",
    "runner_ip",
    "user_email",
    "username",
    "project_name",
    "group_name",
    "branch_name",
    "namespace",
    "path",
    "commit_message",
    "merge_request_title",
    "issue_title",
    "pipeline_log",
    "artifact",
    "raw",
    "payload",
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
_CASES_PAGE_PATH = (
    Path(__file__).parent.parent.parent
    / "frontend" / "src" / "app" / "(app)" / "security" / "cases" / "page.tsx"
)
_REPO_ROOT = Path(__file__).parent.parent.parent


def _gitlab_demo_section() -> str:
    """Return the text from the GITLAB_DEMO_INTEGRATION_NAME line onward."""
    text = _SVC_PATH.read_text()
    idx = text.find("GITLAB_DEMO_INTEGRATION_NAME")
    assert idx != -1, "GITLAB_DEMO_INTEGRATION_NAME not found in demo service"
    return text[idx:]


# ── Import tests ──────────────────────────────────────────────────────────────


def test_gitlab_demo_service_imports() -> None:
    from app.services.security_incident_demo_service import (  # noqa: F401
        seed_gitlab,
        clear_gitlab,
        get_gitlab_status,
        GITLAB_DEMO_INTEGRATION_NAME,
        GITLAB_DEMO_CASE_SOURCE as _SRC,
        GITLAB_DEMO_DATASET,
    )
    assert callable(seed_gitlab)
    assert callable(clear_gitlab)
    assert callable(get_gitlab_status)
    assert GITLAB_DEMO_INTEGRATION_NAME
    assert _SRC == "demo_gitlab_posture_review"
    assert GITLAB_DEMO_DATASET


def test_gitlab_case_report_service_imports() -> None:
    from app.services import security_case_report_service as svc
    assert any(
        callable(getattr(svc, name, None))
        for name in ("build_case_report", "build_report", "generate_case_report")
    ), "security_case_report_service exposes no report builder"


# ── Seed tests (mocked db) ────────────────────────────────────────────────────


def _seed_gitlab_with_capture():
    """Run seed_gitlab against a mock db, capturing all db.add(...) objects."""
    from app.services.security_incident_demo_service import seed_gitlab

    added: list = []

    mock_db = MagicMock()
    mock_db.add.side_effect = lambda obj: added.append(obj)

    mock_integ = MagicMock()
    mock_integ.id = "MOCK_GITLAB_DEMO_INTEG_ID"

    mock_finding = MagicMock()
    mock_finding.id = "MOCK_GITLAB_FINDING_ID"

    mock_event = MagicMock()
    mock_event.id = "MOCK_GITLAB_EVENT_ID"

    mock_signal = MagicMock()
    mock_signal.id = "MOCK_GITLAB_SIGNAL_ID"
    mock_signal.signal_type = "gitlab_force_push_enabled_signal"
    mock_signal.linked_activity_event_id = None
    mock_signal.signal_metadata = {"resource_id": GITLAB_DEMO_BRANCH_RULE_001}

    mock_corr = MagicMock()
    mock_corr.id = "MOCK_GITLAB_CORR_ID"
    mock_corr.linked_signal_id = None

    mock_case = MagicMock()
    mock_case.id = "MOCK_GITLAB_CASE_ID"

    with (
        patch(
            "app.services.security_incident_demo_service._get_gitlab_demo_integration",
            return_value=mock_integ,
        ),
        patch(
            "app.services.security_incident_demo_service._existing_gitlab_demo_case",
            return_value=None,
        ),
        patch(
            "app.services.security_incident_demo_service.finding_svc.upsert_active_finding",
            return_value=mock_finding,
        ),
        patch(
            "app.services.security_incident_demo_service.activity_svc.normalize_activity_event",
            return_value={"provider": "gitlab", "source": "gitlab_activity_event",
                          "event_type": "gitlab.branch_protection.force_push_enabled",
                          "provider_event_id": "MOCK_EVT_ID",
                          "occurred_at": None, "actor_id": None, "actor_type": None,
                          "resource_type": "gitlab_branch_protection",
                          "resource_id": GITLAB_DEMO_BRANCH_RULE_001,
                          "source_ip_hash": None,
                          "metadata": {"resource_id": GITLAB_DEMO_BRANCH_RULE_001},
                          "raw_ref": None},
        ),
        patch(
            "app.services.security_incident_demo_service.activity_svc.upsert_activity_event",
            return_value=("inserted", mock_event),
        ),
        patch(
            "app.services.security_incident_demo_service.gitlab_sig._build_signal",
            return_value={"provider": "gitlab", "signal_key": "gitlab.activity|mock",
                          "signal_type": "gitlab_force_push_enabled_signal",
                          "severity": "high", "status": "open",
                          "title": "Demo force push signal",
                          "summary": "GitLab configuration evidence for review.",
                          "evidence_level": "activity", "confidence": "medium",
                          "first_seen_at": None, "last_seen_at": None,
                          "linked_activity_event_id": None, "metadata": {},
                          "integration_id": None},
        ),
        patch(
            "app.services.security_incident_demo_service.signal_svc.upsert_incident_signal",
            return_value=("created", mock_signal),
        ),
        patch(
            "app.services.security_incident_demo_service.gitlab_corr_svc._build_correlation",
            return_value={"provider": "gitlab", "correlation_key": "mock_corr_key",
                          "correlation_type": "gitlab_branch_protection_risk_with_activity",
                          "severity": "high", "confidence": "high", "status": "open",
                          "title": "GitLab branch protection risk",
                          "summary": "GitLab configuration evidence for review.",
                          "linked_finding_id": None, "linked_activity_event_id": None,
                          "window_start": None, "window_end": None,
                          "first_seen_at": None, "last_seen_at": None, "metadata": {}},
        ),
        patch(
            "app.services.security_incident_demo_service.corr_svc.upsert_correlation",
            return_value=("created", mock_corr),
        ),
        patch(
            "app.services.security_incident_demo_service.case_svc.create_case",
            return_value=mock_case,
        ),
        patch(
            "app.services.security_incident_demo_service.case_svc.link_object_to_case",
        ),
        patch(
            "app.services.security_incident_demo_service.case_svc.count_links",
            return_value=9,
        ),
    ):
        import uuid
        workspace_id = uuid.UUID("00000000-0000-0000-0000-000000000042")
        actor_user_id = uuid.UUID("00000000-0000-0000-0000-000000000001")
        result = seed_gitlab(
            workspace_id=workspace_id,
            actor_user_id=actor_user_id,
            db=mock_db,
        )
    return result, added


def test_seed_gitlab_returns_seeded_true() -> None:
    result, _ = _seed_gitlab_with_capture()
    assert result["seeded"] is True
    assert result["created"] is True
    assert result["case_id"] == "MOCK_GITLAB_CASE_ID"


def test_seed_gitlab_idempotent_returns_early() -> None:
    """Re-seeding when a demo case already exists returns the existing case."""
    from app.services.security_incident_demo_service import seed_gitlab

    mock_existing_case = MagicMock()
    mock_existing_case.id = "EXISTING_CASE_ID"

    mock_db = MagicMock()

    with (
        patch(
            "app.services.security_incident_demo_service._existing_gitlab_demo_case",
            return_value=mock_existing_case,
        ),
        patch(
            "app.services.security_incident_demo_service.case_svc.count_links",
            return_value=9,
        ),
    ):
        import uuid
        result = seed_gitlab(
            workspace_id=uuid.UUID("00000000-0000-0000-0000-000000000042"),
            actor_user_id=uuid.UUID("00000000-0000-0000-0000-000000000001"),
            db=mock_db,
        )

    assert result["seeded"] is True
    assert result["created"] is False
    assert result["case_id"] == "EXISTING_CASE_ID"


# ── Clear tests (mocked db) ───────────────────────────────────────────────────


def test_clear_gitlab_returns_cleared_true() -> None:
    from app.services.security_incident_demo_service import clear_gitlab

    mock_db = MagicMock()
    mock_db.query.return_value.filter.return_value.all.return_value = []

    with patch(
        "app.services.security_incident_demo_service._get_gitlab_demo_integration",
        return_value=None,
    ):
        import uuid
        result = clear_gitlab(
            workspace_id=uuid.UUID("00000000-0000-0000-0000-000000000042"),
            db=mock_db,
        )

    assert result["cleared"] is True
    assert "objects_removed" in result


def test_clear_gitlab_idempotent_on_missing_data() -> None:
    """clear_gitlab with no existing data should still succeed."""
    from app.services.security_incident_demo_service import clear_gitlab

    mock_db = MagicMock()
    mock_db.query.return_value.filter.return_value.all.return_value = []

    with patch(
        "app.services.security_incident_demo_service._get_gitlab_demo_integration",
        return_value=None,
    ):
        import uuid
        r1 = clear_gitlab(
            workspace_id=uuid.UUID("00000000-0000-0000-0000-000000000042"),
            db=mock_db,
        )
        r2 = clear_gitlab(
            workspace_id=uuid.UUID("00000000-0000-0000-0000-000000000042"),
            db=mock_db,
        )
    assert r1["cleared"] is True
    assert r2["cleared"] is True


# ── Demo placeholder ID tests ─────────────────────────────────────────────────


def test_gitlab_demo_ids_are_safe_placeholders() -> None:
    """All demo IDs must be obviously synthetic placeholders, never real values."""
    from app.services.security_incident_demo_service import (
        GITLAB_DEMO_PROJECT_001,
        GITLAB_DEMO_BRANCH_RULE_001,
        GITLAB_DEMO_WEBHOOK_001,
        GITLAB_DEMO_CI_VARIABLE_SUMMARY_001,
        GITLAB_DEMO_INTEGRATION_NAME,
        GITLAB_DEMO_CASE_SOURCE,
    )
    for demo_id in [
        GITLAB_DEMO_PROJECT_001,
        GITLAB_DEMO_BRANCH_RULE_001,
        GITLAB_DEMO_WEBHOOK_001,
        GITLAB_DEMO_CI_VARIABLE_SUMMARY_001,
    ]:
        assert "GITLAB_DEMO" in demo_id, f"{demo_id!r} not a safe placeholder"
        assert "token" not in demo_id.lower()
        assert "secret" not in demo_id.lower()
        assert "glpat" not in demo_id.lower()

    assert "demo" in GITLAB_DEMO_INTEGRATION_NAME.lower()
    assert "gitlab" in GITLAB_DEMO_CASE_SOURCE


def test_gitlab_demo_uses_real_rule_keys() -> None:
    """The demo must seed findings using real M87B/M87C rule keys."""
    section = _gitlab_demo_section()
    for rk in _GITLAB_DEMO_RULE_KEYS:
        assert rk in section, f"Demo must use real rule key {rk!r}"


def test_gitlab_demo_uses_m87d_event_types() -> None:
    section = _gitlab_demo_section()
    for evt in [
        "gitlab.branch_protection.force_push_enabled",
        "gitlab.webhook.secret_removed",
        "gitlab.ci_variables.unprotected_unmasked_detected",
    ]:
        assert evt in section, f"Demo must use M87D event type {evt!r}"


def test_gitlab_demo_uses_m87e_signal_types() -> None:
    section = _gitlab_demo_section()
    for sig in [
        "gitlab_force_push_enabled_signal",
        "gitlab_webhook_secret_removed_signal",
        "gitlab_ci_unprotected_unmasked_variables_signal",
    ]:
        assert sig in section, f"Demo must use M87E signal type {sig!r}"


def test_gitlab_demo_uses_m87f_correlation_types() -> None:
    section = _gitlab_demo_section()
    for ct in [
        "gitlab_branch_protection_risk_with_activity",
        "gitlab_webhook_secret_risk_with_activity",
        "gitlab_ci_variable_risk_with_activity",
    ]:
        assert ct in section, f"Demo must use M87F correlation type {ct!r}"


def test_gitlab_demo_evidence_no_forbidden_fields() -> None:
    section = _gitlab_demo_section()
    for field in _FORBIDDEN_EVIDENCE_FIELDS:
        # Check for the field as a dict key in evidence (e.g. "url": but not "url_scheme")
        if f'"{field}":' in section or f"'{field}':" in section:
            # Acceptable in comments (after #) but not in data literals
            lines_with_field = [
                ln for ln in section.splitlines()
                if f'"{field}":' in ln or f"'{field}':" in ln
            ]
            non_comment_lines = [
                ln for ln in lines_with_field if not ln.strip().startswith("#")
            ]
            assert not non_comment_lines, (
                f"Forbidden field {field!r} appears in GitLab demo evidence: "
                f"{non_comment_lines}"
            )


def test_gitlab_demo_copy_no_forbidden_phrases() -> None:
    section = _gitlab_demo_section()
    low = section.lower()
    for phrase in _FORBIDDEN_PHRASES:
        assert phrase not in low, (
            f"Forbidden phrase {phrase!r} found in GitLab demo section"
        )


def test_gitlab_demo_includes_disclaimer() -> None:
    section = _gitlab_demo_section()
    assert "does not confirm" in section.lower()
    assert "evidence for review" in section.lower() or "configuration evidence" in section.lower()


def test_gitlab_demo_no_real_token_shapes() -> None:
    """No strings matching glpat-[…] or eyJ[...] appear in the demo section."""
    import re
    section = _gitlab_demo_section()
    assert not re.search(r"glpat-[A-Za-z0-9_-]{10,}", section), (
        "Real GitLab PAT shape found in demo section"
    )
    assert not re.search(r"eyJ[A-Za-z0-9_-]{10,}", section), (
        "JWT-shape token found in demo section"
    )


# ── Case report tests ─────────────────────────────────────────────────────────


def test_case_report_labels_gitlab() -> None:
    """The case report service must map 'gitlab' -> 'GitLab'."""
    text = _CASE_REPORT_PATH.read_text()
    assert '"gitlab": "GitLab"' in text or "'gitlab': 'GitLab'" in text, (
        "security_case_report_service must map 'gitlab' -> 'GitLab'"
    )


def test_case_report_timeline_labels_gitlab() -> None:
    text = _CASE_REPORT_PATH.read_text()
    assert "gitlab" in text and "GitLab" in text


def test_case_report_no_forbidden_phrases() -> None:
    text = _CASE_REPORT_PATH.read_text().lower()
    for phrase in _FORBIDDEN_PHRASES:
        assert phrase not in text, (
            f"Forbidden phrase {phrase!r} in case report service"
        )


# ── Router wiring tests ───────────────────────────────────────────────────────


def test_router_supports_gitlab_seed() -> None:
    text = _ROUTER_PATH.read_text()
    assert 'prov == "gitlab"' in text or "prov == 'gitlab'" in text, (
        "Router must branch on provider='gitlab'"
    )
    assert "seed_gitlab" in text
    assert "clear_gitlab" in text
    assert "get_gitlab_status" in text


def test_router_seed_admin_gated() -> None:
    text = _ROUTER_PATH.read_text()
    idx = text.find("incident-demo/seed")
    assert idx != -1
    # require_workspace_admin should be in the same endpoint handler
    segment = text[idx: idx + 800]
    assert "require_workspace_admin" in segment


# ── Frontend cases page tests ─────────────────────────────────────────────────


def test_frontend_cases_page_includes_gitlab() -> None:
    if not _CASES_PAGE_PATH.exists():
        return
    text = _CASES_PAGE_PATH.read_text()
    assert "gitlab" in text, "Cases page must include gitlab provider"
    assert "GitLab" in text
    assert "Load GitLab security demo" in text


def test_frontend_cases_page_no_forbidden_gitlab_phrases() -> None:
    if not _CASES_PAGE_PATH.exists():
        return
    text = _CASES_PAGE_PATH.read_text().lower()
    for line in text.splitlines():
        if "gitlab" not in line:
            continue
        for phrase in _FORBIDDEN_PHRASES:
            assert phrase not in line, (
                f"Forbidden phrase {phrase!r} in GitLab cases page copy"
            )


# ── Capability matrix tests ───────────────────────────────────────────────────


def test_capability_matrix_demo_seed_clear_true() -> None:
    cap = get_provider_capability("gitlab")
    assert cap.security.demo_seed_clear is True


def test_capability_matrix_case_report_true() -> None:
    cap = get_provider_capability("gitlab")
    assert cap.security.case_report is True


def test_capability_matrix_evidence_timeline_true() -> None:
    cap = get_provider_capability("gitlab")
    assert cap.security.evidence_timeline is True


def test_capability_matrix_evidence_graph_true() -> None:
    cap = get_provider_capability("gitlab")
    assert cap.security.evidence_graph is True


def test_capability_matrix_notes_mention_m87g() -> None:
    cap = get_provider_capability("gitlab")
    assert "M87G" in cap.notes


def test_capability_matrix_planned_next_stage_m87h() -> None:
    cap = get_provider_capability("gitlab")
    assert "M87H" in cap.notes


# ── Expansion framework tests ─────────────────────────────────────────────────


def test_expansion_framework_planned_next_stage_m87h() -> None:
    planned = get_framework().get("summary", {}).get("planned_next_stage", "")
    assert "M87H" in planned or "Provider Depth" in planned


def test_terraform_cloud_remains_in_queue() -> None:
    recs = get_framework().get("recommended_next_providers", [])
    provider_keys = [r.get("provider") for r in recs]
    assert "terraform_cloud" in provider_keys or "terraform" in str(provider_keys)


# ── Full regression ───────────────────────────────────────────────────────────


def test_no_forbidden_phrases_in_demo_service() -> None:
    """Full demo service text must not contain affirmative breach/attack claims."""
    text = _SVC_PATH.read_text().lower()
    # We only check the GitLab section.
    idx = text.find("gitlab_demo_integration_name")
    if idx == -1:
        return
    gitlab_section = text[idx:]
    for phrase in _FORBIDDEN_PHRASES:
        assert phrase not in gitlab_section, (
            f"Forbidden phrase {phrase!r} in GitLab demo section of demo service"
        )
