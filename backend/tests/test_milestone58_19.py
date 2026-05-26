"""M58.19: Terraform Fix Suggestion Preview — unit tests.

Tests cover:
  - Permanent safety invariants (execution_enabled, pr_available, safety_level)
  - Generation mode selection (guided_only vs conceptual_preview)
  - Per-provider suggestion generators (AWS SG, Route53, Cloudflare, GitHub, Vercel)
  - Placeholder presence in conceptual diffs
  - "terraform plan" warning in all diffs
  - No IaC mappings → available=False
  - Advisory language: no overclaiming, no Terraform execution
  - Schema validators enforce hard constants

Run:
    cd backend && DATABASE_URL="sqlite:///test.db" .venv/bin/pytest tests/test_milestone58_19.py -v --noconftest

All 15 tests must pass.
"""

from __future__ import annotations

import uuid
from unittest.mock import MagicMock, patch

import pytest

from app.schemas.terraform_fix import (
    TerraformFixMappingInfo,
    TerraformFixPlaceholder,
    TerraformFixPreviewResponse,
    TerraformFixSuggestion,
)
from app.services.terraform_fix_suggestion_service import (
    _EXECUTION_ENABLED,
    _PR_AVAILABLE,
    _SAFETY_LEVEL,
    _build_suggestions,
    _build_workflow,
    get_terraform_fix_preview,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_change(
    *,
    record_identifier: str = "aws_security_group: sg-abc12345",
    provider_metadata: dict | None = None,
    change_type: str = "modified",
    risk_reason: str = "",
) -> MagicMock:
    """Minimal Change mock."""
    c = MagicMock()
    c.id = uuid.uuid4()
    c.record_identifier = record_identifier
    c.provider_metadata = provider_metadata or {}
    c.change_type = change_type
    c.risk_reason = risk_reason
    return c


def _make_mapping(
    *,
    terraform_resource_type: str = "aws_security_group_rule",
    terraform_resource_name: str = "allow_ssh",
    file_path: str = "aws/security_groups.tf",
    cloud_resource_identifier: str | None = None,
    cloud_resource_name: str | None = None,
) -> MagicMock:
    """Minimal IacResourceMapping mock."""
    m = MagicMock()
    m.id = uuid.uuid4()
    m.iac_repository_id = uuid.uuid4()
    m.workspace_id = uuid.uuid4()
    m.terraform_resource_type = terraform_resource_type
    m.terraform_resource_name = terraform_resource_name
    m.file_path = file_path
    m.cloud_resource_identifier = cloud_resource_identifier
    m.cloud_resource_name = cloud_resource_name
    m.match_reason = ""
    m.line_start = 5
    m.line_end = 20
    return m


def _make_db_with_mapping(mapping, change) -> MagicMock:
    """Return a mock DB that returns the given mapping and change."""
    mock_db = MagicMock()

    from app.models.change import Change
    from app.models.iac_resource_mapping import IacResourceMapping
    from app.models.iac_repository import IacRepository

    def _query(model_class):
        q = MagicMock()
        if model_class is Change:
            q.filter.return_value.first.return_value = change
        elif model_class is IacResourceMapping:
            q.filter.return_value.all.return_value = [mapping]
        elif model_class is IacRepository:
            mock_repo = MagicMock()
            mock_repo.id = mapping.iac_repository_id
            mock_repo.repo_full_name = "acme/infra"
            q.filter.return_value.first.return_value = mock_repo
        return q

    mock_db.query.side_effect = _query
    return mock_db


# ── 1. Hard constant: execution_enabled is always False ──────────────────────

def test_execution_enabled_constant_is_false():
    """_EXECUTION_ENABLED must be False — permanent safety constraint."""
    assert _EXECUTION_ENABLED is False


def test_response_execution_enabled_always_false():
    """TerraformFixPreviewResponse.execution_enabled is always False."""
    resp = TerraformFixPreviewResponse(
        available=False,
        summary="test",
        execution_enabled=False,
        pr_available=False,
    )
    assert resp.execution_enabled is False


def test_schema_rejects_execution_enabled_true():
    """Pydantic validator rejects execution_enabled=True."""
    with pytest.raises(Exception):
        TerraformFixPreviewResponse(
            available=True,
            execution_enabled=True,
            pr_available=False,
        )


# ── 2. Hard constant: pr_available is always False ───────────────────────────

def test_pr_available_constant_is_false():
    """_PR_AVAILABLE must be False — GitHub PR creation not available in M58.19."""
    assert _PR_AVAILABLE is False


def test_schema_rejects_pr_available_true():
    """Pydantic validator rejects pr_available=True."""
    with pytest.raises(Exception):
        TerraformFixPreviewResponse(
            available=True,
            execution_enabled=False,
            pr_available=True,
        )


# ── 3. Hard constant: safety_level is always "requires_human_review" ─────────

def test_safety_level_constant():
    """_SAFETY_LEVEL must always be 'requires_human_review'."""
    assert _SAFETY_LEVEL == "requires_human_review"


def test_schema_rejects_wrong_safety_level():
    """TerraformFixSuggestion validator rejects safety_level other than 'requires_human_review'."""
    with pytest.raises(Exception):
        TerraformFixSuggestion(
            kind="hcl_diff",
            title="test",
            description="test",
            language="diff",
            safety_level="approved",   # must be rejected
        )


# ── 4. Every suggestion diff includes "terraform plan" warning ───────────────

def test_aws_sg_ssh_diff_includes_plan_warning():
    """AWS SSH suggestion diff includes the terraform plan warning."""
    mapping = _make_mapping(terraform_resource_type="aws_security_group_rule")
    suggestions = _build_suggestions(
        record_type="aws_security_group_rule",
        change_type="modified",
        risk_reason="ssh port 22 public",
        mapping=mapping,
        mode="conceptual_preview",
    )
    assert suggestions
    for s in suggestions:
        plan_mentioned = any("terraform plan" in w.lower() for w in s.warnings)
        assert plan_mentioned, f"Suggestion '{s.title}' missing terraform plan warning"


def test_github_bp_diff_includes_plan_warning():
    """GitHub branch protection suggestion includes terraform plan warning."""
    mapping = _make_mapping(terraform_resource_type="github_branch_protection")
    suggestions = _build_suggestions(
        record_type="github_branch_protection",
        change_type="modified",
        risk_reason="enforce_admins disabled",
        mapping=mapping,
        mode="conceptual_preview",
    )
    assert suggestions
    for s in suggestions:
        plan_mentioned = any("terraform plan" in w.lower() for w in s.warnings)
        assert plan_mentioned


# ── 5. Low confidence → guided_only (no diff) ────────────────────────────────

def test_low_confidence_generates_guided_only():
    """Low confidence mappings produce guidance_only suggestions with no diff."""
    mapping = _make_mapping(terraform_resource_type="aws_security_group_rule")
    suggestions = _build_suggestions(
        record_type="aws_security_group",
        change_type="modified",
        risk_reason="public ssh",
        mapping=mapping,
        mode="guided_only",
    )
    assert suggestions
    for s in suggestions:
        assert s.kind == "guidance_only"
        assert s.diff is None


def test_guided_only_workflow_mentions_terraform_plan():
    """guided_only workflow steps always mention terraform plan."""
    workflow = _build_workflow("guided_only", "low")
    full_text = " ".join(workflow).lower()
    assert "terraform plan" in full_text


# ── 6. Medium/high confidence → conceptual_preview with placeholders ─────────

def test_medium_confidence_generates_hcl_diff():
    """Medium confidence produces an hcl_diff suggestion with a diff string."""
    mapping = _make_mapping(terraform_resource_type="aws_security_group_rule")
    suggestions = _build_suggestions(
        record_type="aws_security_group_rule",
        change_type="modified",
        risk_reason="rdp port 3389 public",
        mapping=mapping,
        mode="conceptual_preview",
    )
    hcl_suggestions = [s for s in suggestions if s.kind == "hcl_diff"]
    assert hcl_suggestions, "Expected at least one hcl_diff suggestion for medium confidence"
    for s in hcl_suggestions:
        assert s.diff is not None
        assert s.language == "diff"


def test_conceptual_diff_contains_placeholders():
    """Conceptual diffs contain ALL_CAPS placeholder values in angle brackets."""
    mapping = _make_mapping(terraform_resource_type="aws_security_group_rule")
    suggestions = _build_suggestions(
        record_type="aws_security_group_rule",
        change_type="modified",
        risk_reason="ssh port 22",
        mapping=mapping,
        mode="conceptual_preview",
    )
    hcl_suggestions = [s for s in suggestions if s.kind == "hcl_diff"]
    assert hcl_suggestions
    for s in hcl_suggestions:
        # Diffs must use <PLACEHOLDER> format, not real values
        assert "<" in (s.diff or "") and ">" in (s.diff or "")
        # Must have at least one placeholder defined
        assert len(s.placeholders) >= 1


# ── 7. AWS SSH-specific suggestion ───────────────────────────────────────────

def test_aws_ssh_suggestion_mentions_port_22():
    """AWS SSH suggestion references port 22."""
    mapping = _make_mapping(terraform_resource_type="aws_security_group_rule")
    suggestions = _build_suggestions(
        record_type="aws_security_group",
        change_type="modified",
        risk_reason="ssh port 22 accessible from 0.0.0.0/0",
        mapping=mapping,
        mode="conceptual_preview",
    )
    assert suggestions
    combined = " ".join([s.title + " " + (s.diff or "") for s in suggestions])
    assert "22" in combined or "ssh" in combined.lower()


# ── 8. AWS RDP-specific suggestion ───────────────────────────────────────────

def test_aws_rdp_suggestion_mentions_port_3389():
    """AWS RDP suggestion references port 3389."""
    mapping = _make_mapping(terraform_resource_type="aws_security_group_rule")
    suggestions = _build_suggestions(
        record_type="aws_security_group_rule",
        change_type="modified",
        risk_reason="rdp tcp/3389 open to internet",
        mapping=mapping,
        mode="conceptual_preview",
    )
    assert suggestions
    combined = " ".join([s.title + " " + (s.diff or "") for s in suggestions])
    assert "3389" in combined or "rdp" in combined.lower()


# ── 9. Cloudflare DNS suggestion ─────────────────────────────────────────────

def test_cloudflare_record_suggestion_generated():
    """Cloudflare DNS record changes produce a valid suggestion."""
    mapping = _make_mapping(
        terraform_resource_type="cloudflare_record",
        terraform_resource_name="api_dns",
    )
    suggestions = _build_suggestions(
        record_type="cloudflare_record",
        change_type="removed",
        risk_reason="DNS record removed",
        mapping=mapping,
        mode="conceptual_preview",
    )
    assert suggestions
    s = suggestions[0]
    assert s.kind == "hcl_diff"
    assert s.diff is not None
    # "Restore" language for removed records
    assert "restore" in s.title.lower() or "cloudflare" in s.title.lower()


# ── 10. GitHub branch protection suggestion ───────────────────────────────────

def test_github_branch_protection_suggestion_restores_settings():
    """GitHub branch protection suggestion mentions enforce_admins or signed commits."""
    mapping = _make_mapping(
        terraform_resource_type="github_branch_protection",
        terraform_resource_name="main_protection",
    )
    suggestions = _build_suggestions(
        record_type="github_branch_protection",
        change_type="modified",
        risk_reason="branch protection weakened",
        mapping=mapping,
        mode="conceptual_preview",
    )
    assert suggestions
    s = suggestions[0]
    assert s.kind == "hcl_diff"
    combined = (s.diff or "") + s.description
    assert any(
        kw in combined for kw in (
            "enforce_admins", "require_signed_commits", "required_status_checks",
        )
    )


# ── 11. No IaC mappings → available=False ────────────────────────────────────

def test_no_mappings_returns_unavailable():
    """get_terraform_fix_preview returns available=False when no mappings exist."""
    workspace_id = uuid.uuid4()
    change = _make_change(provider_metadata={"record_type": "aws_security_group"})

    mock_db = MagicMock()
    from app.models.change import Change
    from app.models.iac_resource_mapping import IacResourceMapping

    def _query(model_class):
        q = MagicMock()
        if model_class is Change:
            q.filter.return_value.first.return_value = change
        elif model_class is IacResourceMapping:
            q.filter.return_value.all.return_value = []
        return q

    mock_db.query.side_effect = _query

    result = get_terraform_fix_preview(change.id, workspace_id, mock_db)
    assert result.available is False
    assert result.execution_enabled is False
    assert result.pr_available is False


# ── 12. Result with mapping has all required safety fields ────────────────────

def test_result_with_mapping_has_safety_fields():
    """Response with an available fix always has execution_enabled=False, pr_available=False."""
    workspace_id = uuid.uuid4()
    change = _make_change(
        provider_metadata={"record_type": "aws_security_group"},
        risk_reason="public ssh port 22",
    )
    mapping = _make_mapping(
        terraform_resource_type="aws_security_group_rule",
        cloud_resource_identifier="sg-abc12345",
    )
    change.record_identifier = "sg-abc12345"

    mock_db = _make_db_with_mapping(mapping, change)

    result = get_terraform_fix_preview(change.id, workspace_id, mock_db)

    assert result.execution_enabled is False
    assert result.pr_available is False
    if result.available:
        for s in result.suggestions:
            assert s.safety_level == "requires_human_review"


# ── 13. Advisory language: no overclaiming ────────────────────────────────────

def test_summary_uses_advisory_language():
    """Summary text uses advisory language, not definitive ownership claims."""
    workspace_id = uuid.uuid4()
    change = _make_change(
        provider_metadata={"record_type": "github_branch_protection"},
        risk_reason="branch protection removed",
    )
    mapping = _make_mapping(
        terraform_resource_type="github_branch_protection",
        terraform_resource_name="main_protection",
    )

    mock_db = _make_db_with_mapping(mapping, change)
    result = get_terraform_fix_preview(change.id, workspace_id, mock_db)

    if result.available:
        # Advisory language: "possible", "may", "advisory"
        summary_lower = (result.summary or "").lower()
        advisory_terms = ("possible", "may", "advisory", "conceptual", "preview")
        assert any(t in summary_lower for t in advisory_terms), (
            f"Summary should use advisory language; got: {result.summary!r}"
        )


# ── 14. Vercel suggestion ─────────────────────────────────────────────────────

def test_vercel_suggestion_generated():
    """Vercel project changes produce a valid suggestion."""
    mapping = _make_mapping(
        terraform_resource_type="vercel_project",
        terraform_resource_name="my_frontend",
    )
    suggestions = _build_suggestions(
        record_type="vercel_project",
        change_type="modified",
        risk_reason="deploy hook added",
        mapping=mapping,
        mode="conceptual_preview",
    )
    assert suggestions
    s = suggestions[0]
    assert s.kind == "hcl_diff"
    assert "vercel" in s.title.lower() or "vercel_project" in (s.diff or "")


# ── 15. Recommended workflow always mentions human review ─────────────────────

def test_workflow_always_mentions_review():
    """Recommended workflow for all modes always mentions review or plan."""
    for mode in ("guided_only", "conceptual_preview"):
        for confidence in ("low", "medium", "high"):
            workflow = _build_workflow(mode, confidence)
            full_text = " ".join(workflow).lower()
            assert any(
                kw in full_text for kw in ("review", "terraform plan", "plan")
            ), (
                f"Workflow for mode={mode}, confidence={confidence} "
                "should mention review or terraform plan"
            )
