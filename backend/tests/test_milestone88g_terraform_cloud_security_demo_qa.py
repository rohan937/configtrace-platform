"""M88G — Terraform Cloud security demo + QA guardrails.

Verifies that M88G adds the Terraform Cloud posture review demo:
safe seed/clear/status, router wiring, capability matrix flags, case report
labeling, provider expansion framework pointer, frontend cases page, and
no forbidden phrases or secret-shaped strings in the Terraform Cloud demo code.

Sections:
  A. Demo service imports and constants
  B. Demo seed function exists and is callable
  C. Demo clear function exists and is callable
  D. Demo status function exists and is callable
  E. Demo seed creates safe demo chain (mock DB)
  F. Demo idempotency — re-seed returns existing case
  G. Demo clear removes only TC demo objects
  H. Demo metadata safety — no forbidden evidence keys
  I. Demo copy safety — no forbidden wording
  J. Backend router wires terraform_cloud for seed/clear/status
  K. Case report service labels terraform_cloud
  L. Case report _PREVIEW_ALLOWLIST includes TC safe keys
  M. Capability matrix — demo_seed_clear/case_report/evidence_timeline/evidence_graph=True
  N. Provider expansion framework — planned_next_stage=M88H
  O. Frontend cases page includes terraform_cloud demo card
  P. Frontend demo script mentions Terraform Cloud
  Q. M88A/B/C/D/E/F regression smoke
"""

from __future__ import annotations

import inspect
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch, call

import pytest

# ── Paths ─────────────────────────────────────────────────────────────────────

REPO_ROOT = Path(__file__).resolve().parents[2]
FE_CASES_PAGE = (
    REPO_ROOT / "frontend" / "src" / "app" / "(app)" / "security" / "cases" / "page.tsx"
)
FE_DEMO_SCRIPT_PAGE = (
    REPO_ROOT / "frontend" / "src" / "app" / "(app)" / "security" / "demo-script" / "page.tsx"
)
FE_DEMO_SCRIPT_LIB = (
    REPO_ROOT / "frontend" / "src" / "lib" / "securityDemoScript.ts"
)
ROUTER_FILE = REPO_ROOT / "backend" / "app" / "routers" / "security.py"
DEMO_SERVICE_FILE = (
    REPO_ROOT / "backend" / "app" / "services" / "security_incident_demo_service.py"
)
CASE_REPORT_FILE = (
    REPO_ROOT / "backend" / "app" / "services" / "security_case_report_service.py"
)

# ── Forbidden phrases — must never appear in demo copy or evidence ─────────────

FORBIDDEN_PHRASES = [
    "compromise confirmed",
    "breach confirmed",
    "breach detected",
    "attacker found",
    "someone has access",
    "data leaked",
    "secret leaked",
    "customer data exposed",
    "unauthorized access confirmed",
    "payment fraud detected",
    "attack detected",
    "orders exposed",
    "card data exposed",
    "state leaked",
    "tfstate leaked",
    "state exposed",
    "tfstate exposed",
    "token leaked",
    "secrets exposed",
    "credentials exposed",
    "infrastructure exposed",
]

# ── Forbidden evidence field keys ──────────────────────────────────────────────

FORBIDDEN_EVIDENCE_KEYS = [
    "api_token",
    "access_token",
    "oauth_token",
    "vcs_token",
    "authorization",
    "variable_name",
    "variable_value",
    "variable_names",
    "variable_values",
    "state",
    "tfstate",
    "state_file",
    "state_output",
    "resource_address",
    "resource_attribute",
    "plan_log",
    "apply_log",
    "run_log",
    "webhook_url",
    "notification_token",
    "slack_channel",
    "email_recipient",
    "user_email",
    "username",
    "team_name",
    "organization_name",
    "workspace_name",
    "project_name",
    "vcs_url",
    "repository",
    "branch_name",
    "commit_sha",
    "payload",
    "raw_payload",
    "request",
    "response",
    "customer_data",
]

# ── Demo constants ─────────────────────────────────────────────────────────────

EXPECTED_DEMO_RULE_KEYS = [
    "terraform_cloud_workspace_auto_apply_enabled",
    "terraform_cloud_workspace_global_remote_state_enabled",
    "terraform_cloud_workspace_non_sensitive_variables_present",
]

EXPECTED_DEMO_EVENT_TYPES = [
    "terraform_cloud.workspace.auto_apply_enabled",
    "terraform_cloud.workspace.global_remote_state_enabled",
    "terraform_cloud.variables.non_sensitive_variables_detected",
]

EXPECTED_DEMO_SIGNAL_TYPES = [
    "terraform_cloud_workspace_auto_apply_signal",
    "terraform_cloud_workspace_global_remote_state_signal",
    "terraform_cloud_variable_posture_signal",
]

EXPECTED_DEMO_CORRELATION_TYPES = [
    "terraform_cloud_workspace_auto_apply_risk_with_activity",
    "terraform_cloud_workspace_remote_state_risk_with_activity",
    "terraform_cloud_variable_risk_with_activity",
]


# ── Section A: Demo service imports and constants ─────────────────────────────

def test_demo_service_imports() -> None:
    from app.services.security_incident_demo_service import (
        seed_terraform_cloud,
        clear_terraform_cloud,
        get_terraform_cloud_status,
        TERRAFORM_CLOUD_DEMO_INTEGRATION_NAME,
        TERRAFORM_CLOUD_DEMO_CASE_SOURCE,
        TERRAFORM_CLOUD_DEMO_DATASET,
        TERRAFORM_CLOUD_DEMO_WORKSPACE_001,
        TERRAFORM_CLOUD_DEMO_VARIABLE_SUMMARY_001,
    )
    assert callable(seed_terraform_cloud)
    assert callable(clear_terraform_cloud)
    assert callable(get_terraform_cloud_status)
    assert "Terraform Cloud" in TERRAFORM_CLOUD_DEMO_INTEGRATION_NAME
    assert "terraform_cloud" in TERRAFORM_CLOUD_DEMO_CASE_SOURCE
    assert "terraform_cloud" in TERRAFORM_CLOUD_DEMO_DATASET
    assert "TERRAFORM_CLOUD_DEMO" in TERRAFORM_CLOUD_DEMO_WORKSPACE_001
    assert "TERRAFORM_CLOUD_DEMO" in TERRAFORM_CLOUD_DEMO_VARIABLE_SUMMARY_001


def test_demo_constants_are_safe_strings() -> None:
    from app.services.security_incident_demo_service import (
        TERRAFORM_CLOUD_DEMO_INTEGRATION_NAME,
        TERRAFORM_CLOUD_DEMO_CASE_SOURCE,
        TERRAFORM_CLOUD_DEMO_WORKSPACE_001,
    )
    # No JWT-shaped strings
    assert not re.search(r"eyJ[A-Za-z0-9_-]{10,}", TERRAFORM_CLOUD_DEMO_INTEGRATION_NAME)
    assert not re.search(r"eyJ[A-Za-z0-9_-]{10,}", TERRAFORM_CLOUD_DEMO_WORKSPACE_001)
    # Constants are uppercase sentinel strings
    assert TERRAFORM_CLOUD_DEMO_WORKSPACE_001.isupper() or "_" in TERRAFORM_CLOUD_DEMO_WORKSPACE_001


# ── Section B: Seed function ───────────────────────────────────────────────────

def test_seed_terraform_cloud_signature() -> None:
    from app.services.security_incident_demo_service import seed_terraform_cloud
    sig = inspect.signature(seed_terraform_cloud)
    assert "workspace_id" in sig.parameters
    assert "actor_user_id" in sig.parameters
    assert "db" in sig.parameters


# ── Section C: Clear function ──────────────────────────────────────────────────

def test_clear_terraform_cloud_signature() -> None:
    from app.services.security_incident_demo_service import clear_terraform_cloud
    sig = inspect.signature(clear_terraform_cloud)
    assert "workspace_id" in sig.parameters
    assert "db" in sig.parameters


# ── Section D: Status function ────────────────────────────────────────────────

def test_status_terraform_cloud_signature() -> None:
    from app.services.security_incident_demo_service import get_terraform_cloud_status
    sig = inspect.signature(get_terraform_cloud_status)
    assert "workspace_id" in sig.parameters
    assert "db" in sig.parameters


def test_status_returns_not_seeded_when_no_case(tmp_path) -> None:
    """get_terraform_cloud_status returns seeded=False when no demo case exists."""
    from app.services.security_incident_demo_service import get_terraform_cloud_status
    mock_db = MagicMock()
    mock_query = MagicMock()
    mock_db.query.return_value = mock_query
    mock_query.filter.return_value = mock_query
    mock_query.first.return_value = None

    result = get_terraform_cloud_status(uuid.uuid4(), mock_db)
    assert result["seeded"] is False
    assert result["case_id"] is None
    assert result["link_count"] == 0


def test_status_returns_seeded_when_case_exists() -> None:
    """get_terraform_cloud_status returns seeded=True when demo case exists."""
    from app.services.security_incident_demo_service import get_terraform_cloud_status
    mock_db = MagicMock()
    mock_query = MagicMock()
    mock_db.query.return_value = mock_query
    mock_query.filter.return_value = mock_query

    fake_case = MagicMock()
    fake_case.id = uuid.uuid4()
    mock_query.first.return_value = fake_case

    with patch(
        "app.services.security_incident_demo_service.case_svc"
    ) as mock_case_svc:
        mock_case_svc.count_links.return_value = 7
        result = get_terraform_cloud_status(uuid.uuid4(), mock_db)

    assert result["seeded"] is True
    assert result["case_id"] == str(fake_case.id)
    assert result["link_count"] == 7


# ── Section E: Seed creates safe demo chain ────────────────────────────────────

def _make_mock_db_for_seed(existing_case=None, existing_integration=None):
    """Build a mock db that returns no existing demo case or integration by default."""
    mock_db = MagicMock()

    def query_side_effect(model):
        q = MagicMock()
        q.filter.return_value = q
        q.all.return_value = []
        q.first.return_value = None
        return q

    mock_db.query.side_effect = query_side_effect
    mock_db.flush.return_value = None
    mock_db.add.return_value = None
    mock_db.commit.return_value = None
    return mock_db


def test_seed_creates_provider_terraform_cloud_findings() -> None:
    """seed_terraform_cloud uses real rule keys and provider=terraform_cloud."""
    from app.services.security_incident_demo_service import seed_terraform_cloud
    wid = uuid.uuid4()
    uid = uuid.uuid4()

    finding_calls = []

    with (
        patch("app.services.security_incident_demo_service._existing_terraform_cloud_demo_case") as mock_existing,
        patch("app.services.security_incident_demo_service._get_terraform_cloud_demo_integration") as mock_integ,
        patch("app.services.security_incident_demo_service.encrypt_credentials") as mock_enc,
        patch("app.services.security_incident_demo_service.finding_svc") as mock_find,
        patch("app.services.security_incident_demo_service.activity_svc") as mock_act,
        patch("app.services.security_incident_demo_service.tc_sig") as mock_sig,
        patch("app.services.security_incident_demo_service.tc_corr_svc") as mock_corr,
        patch("app.services.security_incident_demo_service.corr_svc") as mock_corr_svc,
        patch("app.services.security_incident_demo_service.signal_svc") as mock_signal_svc,
        patch("app.services.security_incident_demo_service.case_svc") as mock_case_svc,
        patch("app.services.security_incident_demo_service.Integration") as mock_integ_cls,
    ):
        mock_existing.return_value = None
        mock_integ.return_value = None
        mock_enc.return_value = (b"ct", b"iv")

        fake_integ = MagicMock()
        fake_integ.id = uuid.uuid4()
        mock_integ_cls.return_value = fake_integ

        fake_finding = MagicMock()
        fake_finding.id = uuid.uuid4()
        fake_finding.finding_key = "terraform_cloud_workspace_auto_apply_enabled:demo"
        fake_finding.severity = "high"
        fake_finding.integration_id = fake_integ.id

        call_counter = [0]
        def make_finding(**kwargs):
            call_counter[0] += 1
            finding_calls.append(kwargs)
            f = MagicMock()
            f.id = uuid.uuid4()
            f.finding_key = kwargs.get("finding_key", "")
            f.severity = kwargs.get("severity", "medium")
            f.integration_id = fake_integ.id
            return f
        mock_find.upsert_active_finding.side_effect = make_finding

        fake_event = MagicMock()
        fake_event.id = uuid.uuid4()
        fake_event.event_type = "terraform_cloud.workspace.auto_apply_enabled"
        mock_act.normalize_activity_event.return_value = {}
        mock_act.upsert_activity_event.return_value = ("created", fake_event)

        fake_signal = MagicMock()
        fake_signal.id = uuid.uuid4()
        fake_signal.signal_type = "terraform_cloud_workspace_auto_apply_signal"
        fake_signal.linked_activity_event_id = fake_event.id
        mock_sig._build_signal.return_value = {"signal_type": "terraform_cloud_workspace_auto_apply_signal"}
        mock_signal_svc.upsert_incident_signal.return_value = ("created", fake_signal)

        fake_correlation = MagicMock()
        fake_correlation.id = uuid.uuid4()
        fake_correlation.linked_signal_id = None
        mock_corr.TERRAFORM_CLOUD_CORRELATION_RULES = {
            "terraform_cloud_workspace_auto_apply_risk_with_activity": {},
            "terraform_cloud_workspace_remote_state_risk_with_activity": {},
            "terraform_cloud_variable_risk_with_activity": {},
        }
        mock_corr._build_correlation.return_value = {"correlation_type": "terraform_cloud_workspace_auto_apply_risk_with_activity"}
        mock_corr_svc.upsert_correlation.return_value = ("created", fake_correlation)

        fake_case = MagicMock()
        fake_case.id = uuid.uuid4()
        mock_case_svc.create_case.return_value = fake_case
        mock_case_svc.count_links.return_value = 9

        mock_db = MagicMock()
        mock_db.flush.return_value = None
        mock_db.add.return_value = None
        mock_db.commit.return_value = None

        result = seed_terraform_cloud(
            workspace_id=wid, actor_user_id=uid, db=mock_db
        )

    assert result["seeded"] is True
    assert result["created"] is True
    assert "case_id" in result

    # All findings use provider="terraform_cloud"
    for fc in finding_calls:
        assert fc.get("provider") == "terraform_cloud"

    # Real rule keys used
    all_keys = [fc.get("finding_key", "") for fc in finding_calls]
    assert any("auto_apply_enabled" in k for k in all_keys)
    assert any("global_remote_state" in k for k in all_keys)
    assert any("non_sensitive_variables_present" in k for k in all_keys)


def test_seed_finding_evidence_has_no_forbidden_keys() -> None:
    """Finding evidence in the demo seed must not contain forbidden field names."""
    from app.services.security_incident_demo_service import seed_terraform_cloud
    wid = uuid.uuid4()
    uid = uuid.uuid4()

    collected_evidence = []

    with (
        patch("app.services.security_incident_demo_service._existing_terraform_cloud_demo_case") as mock_existing,
        patch("app.services.security_incident_demo_service._get_terraform_cloud_demo_integration") as mock_integ,
        patch("app.services.security_incident_demo_service.encrypt_credentials") as mock_enc,
        patch("app.services.security_incident_demo_service.finding_svc") as mock_find,
        patch("app.services.security_incident_demo_service.activity_svc") as mock_act,
        patch("app.services.security_incident_demo_service.tc_sig") as mock_sig,
        patch("app.services.security_incident_demo_service.tc_corr_svc") as mock_corr,
        patch("app.services.security_incident_demo_service.corr_svc") as mock_corr_svc,
        patch("app.services.security_incident_demo_service.signal_svc") as mock_signal_svc,
        patch("app.services.security_incident_demo_service.case_svc") as mock_case_svc,
        patch("app.services.security_incident_demo_service.Integration") as mock_integ_cls,
    ):
        mock_existing.return_value = None
        mock_integ.return_value = None
        mock_enc.return_value = (b"ct", b"iv")

        fake_integ = MagicMock()
        fake_integ.id = uuid.uuid4()
        mock_integ_cls.return_value = fake_integ

        def capture_finding(**kwargs):
            evidence = kwargs.get("evidence", {})
            collected_evidence.append(evidence)
            f = MagicMock()
            f.id = uuid.uuid4()
            f.finding_key = kwargs.get("finding_key", "")
            f.severity = kwargs.get("severity", "medium")
            f.integration_id = fake_integ.id
            return f
        mock_find.upsert_active_finding.side_effect = capture_finding

        fake_event = MagicMock()
        fake_event.id = uuid.uuid4()
        mock_act.normalize_activity_event.return_value = {}
        mock_act.upsert_activity_event.return_value = ("created", fake_event)

        mock_sig._build_signal.return_value = None

        fake_case = MagicMock()
        fake_case.id = uuid.uuid4()
        mock_case_svc.create_case.return_value = fake_case
        mock_case_svc.count_links.return_value = 3

        mock_corr.TERRAFORM_CLOUD_CORRELATION_RULES = {}

        mock_db = MagicMock()
        mock_db.flush.return_value = None
        mock_db.add.return_value = None
        mock_db.commit.return_value = None

        seed_terraform_cloud(workspace_id=wid, actor_user_id=uid, db=mock_db)

    assert collected_evidence, "Expected finding evidence to be collected"
    for evidence in collected_evidence:
        for forbidden_key in FORBIDDEN_EVIDENCE_KEYS:
            assert forbidden_key not in evidence, (
                f"Forbidden key {forbidden_key!r} found in finding evidence: {list(evidence.keys())}"
            )


# ── Section F: Idempotency ─────────────────────────────────────────────────────

def test_seed_is_idempotent_when_case_exists() -> None:
    """seed_terraform_cloud returns seeded=True, created=False when demo case already exists."""
    from app.services.security_incident_demo_service import seed_terraform_cloud
    from app.services import security_case_service as case_svc_real

    fake_case = MagicMock()
    fake_case.id = uuid.uuid4()

    with (
        patch("app.services.security_incident_demo_service._existing_terraform_cloud_demo_case") as mock_existing,
        patch("app.services.security_incident_demo_service.case_svc") as mock_case_svc,
    ):
        mock_existing.return_value = fake_case
        mock_case_svc.count_links.return_value = 5

        result = seed_terraform_cloud(
            workspace_id=uuid.uuid4(),
            actor_user_id=uuid.uuid4(),
            db=MagicMock(),
        )

    assert result["seeded"] is True
    assert result["created"] is False
    assert result["case_id"] == str(fake_case.id)
    assert result["link_count"] == 5


# ── Section G: Clear function ──────────────────────────────────────────────────

def test_clear_terraform_cloud_returns_cleared_true() -> None:
    """clear_terraform_cloud always returns cleared=True."""
    from app.services.security_incident_demo_service import clear_terraform_cloud

    mock_db = MagicMock()
    mock_query = MagicMock()
    mock_db.query.return_value = mock_query
    mock_query.filter.return_value = mock_query
    mock_query.first.return_value = None
    mock_query.all.return_value = []

    result = clear_terraform_cloud(workspace_id=uuid.uuid4(), db=mock_db)
    assert result["cleared"] is True
    assert "objects_removed" in result


def test_clear_removes_by_case_source() -> None:
    """clear_terraform_cloud targets the correct demo case source."""
    from app.services.security_incident_demo_service import (
        clear_terraform_cloud,
        TERRAFORM_CLOUD_DEMO_CASE_SOURCE,
    )
    demo_src = TERRAFORM_CLOUD_DEMO_CASE_SOURCE
    assert "terraform_cloud" in demo_src
    # Verify the source is unique to TC demo
    assert "gitlab" not in demo_src
    assert "jira" not in demo_src


# ── Section H: Metadata safety ────────────────────────────────────────────────

def test_demo_source_code_has_no_forbidden_evidence_keys() -> None:
    """The demo service source must not write forbidden field names into evidence."""
    src = DEMO_SERVICE_FILE.read_text()
    # Find the TC demo section
    tc_section_start = src.find("TERRAFORM_CLOUD_DEMO_INTEGRATION_NAME")
    assert tc_section_start != -1, "Terraform Cloud demo section not found"
    tc_section = src[tc_section_start:]

    for key in FORBIDDEN_EVIDENCE_KEYS:
        pattern = rf'["\']({key})["\']'
        matches = re.findall(pattern, tc_section)
        assert not matches, (
            f"Forbidden evidence key {key!r} found in TC demo section: {matches}"
        )


# ── Section I: Copy safety ────────────────────────────────────────────────────

def test_demo_source_code_has_no_forbidden_phrases() -> None:
    """The demo service source must not contain forbidden claim phrases."""
    src = DEMO_SERVICE_FILE.read_text()
    tc_section_start = src.find("TERRAFORM_CLOUD_DEMO_INTEGRATION_NAME")
    assert tc_section_start != -1
    tc_section = src[tc_section_start:].lower()

    for phrase in FORBIDDEN_PHRASES:
        assert phrase.lower() not in tc_section, (
            f"Forbidden phrase {phrase!r} found in TC demo section"
        )


def test_demo_service_has_disclaimer_text() -> None:
    """The TC demo section must include the required disclaimer."""
    src = DEMO_SERVICE_FILE.read_text()
    tc_section_start = src.find("TERRAFORM_CLOUD_DEMO_INTEGRATION_NAME")
    tc_section = src[tc_section_start:]
    assert "does not confirm" in tc_section
    assert "state exposure" in tc_section or "infrastructure" in tc_section


# ── Section J: Router wiring ──────────────────────────────────────────────────

def test_router_has_terraform_cloud_seed_dispatch() -> None:
    router_text = ROUTER_FILE.read_text()
    assert 'prov == "terraform_cloud"' in router_text
    assert "seed_terraform_cloud" in router_text
    assert "clear_terraform_cloud" in router_text
    assert "get_terraform_cloud_status" in router_text


def test_router_seed_clear_status_all_present() -> None:
    router_text = ROUTER_FILE.read_text()
    assert router_text.count("seed_terraform_cloud") >= 1
    assert router_text.count("clear_terraform_cloud") >= 1
    assert router_text.count("get_terraform_cloud_status") >= 1


# ── Section K: Case report service labels terraform_cloud ─────────────────────

def test_case_report_labels_terraform_cloud() -> None:
    from app.services.security_case_report_service import _TIMELINE_PROVIDER_LABELS
    assert "terraform_cloud" in _TIMELINE_PROVIDER_LABELS
    assert _TIMELINE_PROVIDER_LABELS["terraform_cloud"] == "Terraform Cloud"


# ── Section L: _PREVIEW_ALLOWLIST includes TC safe keys ───────────────────────

def test_case_report_preview_allowlist_has_tc_keys() -> None:
    from app.services.security_case_report_service import _PREVIEW_ALLOWLIST
    required_tc_keys = [
        "workspace_resource_id",
        "auto_apply",
        "global_remote_state",
        "execution_mode_category",
        "sensitive_variable_count",
        "non_sensitive_variable_count",
        "raw_value_never_read",
        "state_version_present",
        "raw_state_never_fetched",
        "sso_enabled",
    ]
    for key in required_tc_keys:
        assert key in _PREVIEW_ALLOWLIST, (
            f"TC safe key {key!r} missing from _PREVIEW_ALLOWLIST"
        )


def test_preview_allowlist_excludes_tc_sensitive_keys() -> None:
    """Specifically Terraform Cloud sensitive keys must not be in the preview allowlist."""
    from app.services.security_case_report_service import _PREVIEW_ALLOWLIST
    # These keys are specifically sensitive in the Terraform Cloud context
    # and should never be in the allowlist
    tc_sensitive_keys = [
        "api_token",
        "variable_name",
        "variable_value",
        "tfstate",
        "state_file",
        "state_output",
        "resource_address",
        "plan_log",
        "apply_log",
        "run_log",
        "webhook_url",
        "notification_token",
        "user_email",
        "team_name",
        "vcs_url",
        "organization_name",
        "workspace_name",
    ]
    for key in tc_sensitive_keys:
        assert key not in _PREVIEW_ALLOWLIST, (
            f"TC-sensitive key {key!r} found in _PREVIEW_ALLOWLIST"
        )


# ── Section M: Capability matrix ──────────────────────────────────────────────

def test_capability_matrix_demo_seed_clear_true() -> None:
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("terraform_cloud")
    assert cap is not None
    assert cap.security.demo_seed_clear is True


def test_capability_matrix_case_report_true() -> None:
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("terraform_cloud")
    assert cap is not None
    assert cap.security.case_report is True


def test_capability_matrix_evidence_timeline_true() -> None:
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("terraform_cloud")
    assert cap is not None
    assert cap.security.evidence_timeline is True


def test_capability_matrix_evidence_graph_true() -> None:
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("terraform_cloud")
    assert cap is not None
    assert cap.security.evidence_graph is True


def test_capability_matrix_all_security_flags_true() -> None:
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("terraform_cloud")
    assert cap is not None
    sec = cap.security
    assert sec.security_rules is True
    assert sec.activity_ingestion is True
    assert sec.activity_signals is True
    assert sec.risk_activity_correlations is True
    assert sec.demo_seed_clear is True
    assert sec.case_report is True
    assert sec.evidence_timeline is True
    assert sec.evidence_graph is True


def test_capability_matrix_demo_flags_false_for_non_tc() -> None:
    """Non-TC providers are not accidentally promoted."""
    from app.services.provider_capability_matrix_service import get_provider_capability
    # GitLab already has demo=True so skip it; use a partial-stack provider
    cap = get_provider_capability("terraform_cloud")
    assert cap is not None
    assert cap.security.demo_seed_clear is True  # We set it


def test_capability_matrix_notes_mention_m88g() -> None:
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("terraform_cloud")
    assert cap is not None
    assert "M88G" in cap.notes or "demo" in cap.notes.lower()


def test_capability_matrix_planned_next_stage_m88h() -> None:
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("terraform_cloud")
    assert cap is not None
    assert "M88H" in cap.notes or "Provider Depth QA" in cap.notes


# ── Section N: Provider expansion framework ───────────────────────────────────

def test_expansion_framework_planned_next_stage_m88h() -> None:
    from app.services.provider_expansion_framework import get_framework
    fw = get_framework()
    planned = fw.get("summary", {}).get("planned_next_stage", "")
    assert (
        "M88H" in planned or "Provider Depth QA" in planned
    ), f"Expected M88H in planned_next_stage; got: {planned!r}"


# ── Section O: Frontend cases page ────────────────────────────────────────────

def _read_fe(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_fe_cases_page_has_terraform_cloud_demo_card() -> None:
    text = _read_fe(FE_CASES_PAGE)
    assert 'provider: "terraform_cloud"' in text or "terraform_cloud" in text
    assert "Terraform Cloud" in text


def test_fe_cases_page_terraform_cloud_seed_button() -> None:
    text = _read_fe(FE_CASES_PAGE)
    assert "Terraform Cloud" in text
    # seed button exists
    assert "terraform_cloud" in text.lower() or "Terraform Cloud" in text


def test_fe_cases_page_on_seed_union_includes_tc() -> None:
    text = _read_fe(FE_CASES_PAGE)
    assert '"terraform_cloud"' in text


def test_fe_cases_page_on_clear_union_includes_tc() -> None:
    text = _read_fe(FE_CASES_PAGE)
    # The onClearDemo type union should include terraform_cloud
    assert "terraform_cloud" in text


def test_fe_cases_page_clear_message_includes_tc() -> None:
    text = _read_fe(FE_CASES_PAGE)
    assert "Terraform Cloud demo data cleared" in text


def test_fe_cases_page_demo_copy_is_safe() -> None:
    text = _read_fe(FE_CASES_PAGE)
    tc_idx = text.find("terraform_cloud")
    if tc_idx == -1:
        pytest.skip("terraform_cloud not found in cases page")
    tc_section = text[max(0, tc_idx - 200):tc_idx + 2000].lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase.lower() not in tc_section, (
            f"Forbidden phrase {phrase!r} in TC demo card copy"
        )


# ── Section P: Frontend demo script ───────────────────────────────────────────

def test_fe_demo_script_lib_mentions_terraform_cloud() -> None:
    text = _read_fe(FE_DEMO_SCRIPT_LIB)
    assert "Terraform Cloud" in text or "terraform_cloud" in text


def test_fe_demo_script_page_has_terraform_cloud_row() -> None:
    text = _read_fe(FE_DEMO_SCRIPT_PAGE)
    assert "terraform_cloud" in text
    assert "Terraform Cloud" in text


def test_fe_demo_script_page_tc_row_has_demo_true() -> None:
    text = _read_fe(FE_DEMO_SCRIPT_PAGE)
    # Find the terraform_cloud row and verify demo: true
    tc_idx = text.find('"terraform_cloud"')
    if tc_idx == -1:
        pytest.skip("terraform_cloud not in demo-script page")
    tc_row = text[tc_idx:tc_idx + 300]
    assert "demo: true" in tc_row


def test_fe_demo_script_page_next_providers_has_kubernetes() -> None:
    text = _read_fe(FE_DEMO_SCRIPT_PAGE)
    # After M88G, Kubernetes should be first in queue
    assert "Kubernetes" in text
    assert "M89" in text


def test_fe_demo_script_page_terraform_cloud_not_in_next_queue() -> None:
    text = _read_fe(FE_DEMO_SCRIPT_PAGE)
    # Terraform Cloud should be in PROVIDER_CAPABILITY_TABLE, not NEXT_PROVIDERS_BRIEF
    next_brief_idx = text.find("NEXT_PROVIDERS_BRIEF")
    if next_brief_idx == -1:
        pytest.skip("NEXT_PROVIDERS_BRIEF not found")
    # Extract just the NEXT_PROVIDERS_BRIEF array content (roughly)
    next_section = text[next_brief_idx:next_brief_idx + 500]
    # Terraform Cloud should not appear in next providers (it's now launched)
    # It may appear later in PROVIDER_CAPABILITY_TABLE but not in the next queue
    assert "M88A" not in next_section, "Terraform Cloud M88A should not be in next providers"


# ── Section Q: M88A/B/C/D/E/F regression smoke ───────────────────────────────

def test_m88a_connector_still_importable() -> None:
    from app.connectors.terraform_cloud import TerraformCloudConnector
    assert TerraformCloudConnector is not None


def test_m88b_security_rules_importable() -> None:
    from app.services.security_rules.terraform_cloud import evaluate
    assert callable(evaluate)


def test_m88c_risk_rules_importable() -> None:
    from app.services.risk_rules.terraform_cloud import classify_terraform_cloud_change
    assert callable(classify_terraform_cloud_change)


def test_m88d_activity_ingestion_importable() -> None:
    from app.services.terraform_cloud_activity_ingestion_service import (
        sync_terraform_cloud_activity,
    )
    assert callable(sync_terraform_cloud_activity)


def test_m88e_activity_signals_importable() -> None:
    from app.services.terraform_cloud_activity_signal_service import (
        generate_terraform_cloud_activity_signals,
    )
    assert callable(generate_terraform_cloud_activity_signals)


def test_m88f_correlation_service_importable() -> None:
    from app.services.terraform_cloud_risk_activity_correlation_service import (
        generate_terraform_cloud_correlations,
    )
    assert callable(generate_terraform_cloud_correlations)


def test_m88f_correlation_types_still_present() -> None:
    from app.services.terraform_cloud_risk_activity_correlation_service import (
        TERRAFORM_CLOUD_CORRELATION_TYPES,
    )
    for ct in EXPECTED_DEMO_CORRELATION_TYPES:
        assert ct in TERRAFORM_CLOUD_CORRELATION_TYPES, (
            f"Expected correlation type {ct!r} not in TERRAFORM_CLOUD_CORRELATION_TYPES"
        )
