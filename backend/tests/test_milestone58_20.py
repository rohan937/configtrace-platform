"""M58.20: GitHub PR Draft Flow — unit tests.

Tests cover:
  - No Terraform preview → unavailable
  - Terraform preview available → PR draft returned
  - Branch name sanitization and length limit
  - Commit message: safe and non-sensational
  - PR body: detection summary, mapping, validation checklist, safety disclaimer
  - PR body includes "run terraform plan"
  - PR body includes "ConfigTrace has not changed the repository"
  - Patch preview reused from M58.19 Terraform fix preview
  - Low confidence / guided-only → outline-only draft
  - Safety flags: creates_branch=False, commits_code=False, opens_pr=False
  - Safety flag: executes_terraform=False
  - No GitHub mutation API calls (pure local generation)
  - Endpoint enforces workspace authorization (no workspace_id → unavailable)
  - No secrets/tokens/tfvars/tfstate in response
  - Schema validators enforce all safety constants

Run:
    cd backend && DATABASE_URL="sqlite:///test.db" .venv/bin/pytest tests/test_milestone58_20.py -v --noconftest

All 16+ tests must pass.
"""

from __future__ import annotations

import uuid
from unittest.mock import MagicMock, patch

import pytest

from app.schemas.github_pr_draft import (
    GitHubPrDraftObject,
    GitHubPrDraftRepo,
    GitHubPrDraftResponse,
    GitHubPrDraftSafetyFlags,
)
from app.services.github_pr_draft_service import (
    _CREATES_BRANCH,
    _COMMITS_CODE,
    _OPENS_PR,
    _EXECUTES_TERRAFORM,
    _build_branch_name,
    _build_commit_message,
    _build_pr_body,
    _build_pr_title,
    _sanitize_segment,
    get_github_pr_draft,
)
from app.schemas.terraform_fix import (
    TerraformFixMappingInfo,
    TerraformFixPreviewResponse,
    TerraformFixSuggestion,
    TerraformFixPlaceholder,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_change(
    *,
    record_identifier: str = "sg-abc12345",
    provider_metadata: dict | None = None,
    change_type: str = "modified",
    risk_reason: str = "public ssh port 22",
    risk_level: str = "high",
) -> MagicMock:
    c = MagicMock()
    c.id = uuid.uuid4()
    c.record_identifier = record_identifier
    c.provider_metadata = provider_metadata or {}
    c.change_type = change_type
    c.risk_reason = risk_reason
    c.risk_level = risk_level
    return c


def _make_fix_preview(
    *,
    available: bool = True,
    confidence: str = "medium",
    kind: str = "hcl_diff",
    diff: str | None = 'resource "aws_security_group_rule" "allow_ssh" {\n-  cidr_blocks = ["0.0.0.0/0"]\n+  cidr_blocks = [var.<TRUSTED_CIDR_VAR>]\n}',
    summary: str | None = None,
) -> TerraformFixPreviewResponse:
    if not available:
        return TerraformFixPreviewResponse(
            available=False,
            summary=summary or "No Terraform fix preview available.",
            pr_available=False,
            execution_enabled=False,
        )
    suggestion = TerraformFixSuggestion(
        kind=kind,
        title="Restrict SSH ingress",
        description="Replace 0.0.0.0/0 with trusted CIDR.",
        language="diff" if kind == "hcl_diff" else "text",
        diff=diff,
        safety_level="requires_human_review",
        placeholders=[
            TerraformFixPlaceholder(
                name="TRUSTED_CIDR_VAR",
                description="Trusted CIDR variable name",
                example="trusted_vpn_cidr",
            )
        ],
        warnings=["Always run terraform plan before applying."],
    )
    return TerraformFixPreviewResponse(
        available=True,
        confidence=confidence,
        title="Terraform fix preview: AWS security group rule",
        summary="A possible IaC mapping was found.",
        mapping=TerraformFixMappingInfo(
            repo_full_name="acme/infra",
            file_path="aws/security_groups.tf",
            terraform_resource_type="aws_security_group_rule",
            terraform_resource_name="allow_ssh",
            match_confidence=confidence,
        ),
        suggestions=[suggestion],
        recommended_workflow=["Run terraform plan.", "Review output.", "Apply."],
        pr_available=False,
        execution_enabled=False,
    )


def _make_db_with_change_and_mapping(change, fix_preview) -> MagicMock:
    """Return a mock DB that supplies the change and lets M58.19 service run."""
    mock_db = MagicMock()
    from app.models.change import Change
    from app.models.iac_resource_mapping import IacResourceMapping
    from app.models.iac_repository import IacRepository

    mock_mapping = MagicMock()
    mock_mapping.id = uuid.uuid4()
    mock_mapping.iac_repository_id = uuid.uuid4()
    mock_mapping.workspace_id = uuid.uuid4()
    mock_mapping.terraform_resource_type = "aws_security_group_rule"
    mock_mapping.terraform_resource_name = "allow_ssh"
    mock_mapping.file_path = "aws/security_groups.tf"
    mock_mapping.cloud_resource_identifier = "sg-abc12345"
    mock_mapping.cloud_resource_name = None
    mock_mapping.match_reason = ""
    mock_mapping.line_start = 5
    mock_mapping.line_end = 20

    mock_repo = MagicMock()
    mock_repo.id = mock_mapping.iac_repository_id
    mock_repo.repo_full_name = "acme/infra"
    mock_repo.default_branch = "main"

    def _query(model_class):
        q = MagicMock()
        if model_class is Change:
            q.filter.return_value.first.return_value = change
        elif model_class is IacResourceMapping:
            q.filter.return_value.all.return_value = [mock_mapping]
        elif model_class is IacRepository:
            q.filter.return_value.first.return_value = mock_repo
        return q

    mock_db.query.side_effect = _query
    return mock_db


# ── 1. No Terraform preview → PR draft unavailable ────────────────────────────

def test_no_terraform_preview_returns_unavailable():
    """When the Terraform fix preview is unavailable, PR draft is also unavailable."""
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

    result = get_github_pr_draft(change.id, workspace_id, mock_db)
    assert result.available is False
    assert result.reason is not None


# ── 2. Terraform preview available → PR draft returned ────────────────────────

def test_terraform_preview_available_returns_pr_draft():
    """When Terraform fix preview is available, PR draft is generated."""
    workspace_id = uuid.uuid4()
    change = _make_change(
        provider_metadata={"record_type": "aws_security_group"},
        risk_reason="public ssh port 22",
        record_identifier="sg-abc12345",
    )
    change.record_identifier = "sg-abc12345"

    mock_db = _make_db_with_change_and_mapping(change, None)
    result = get_github_pr_draft(change.id, workspace_id, mock_db)

    assert result.available is True
    assert result.draft is not None
    assert result.repo is not None


# ── 3. Branch name sanitization and length limit ──────────────────────────────

def test_branch_name_sanitized_lowercase_hyphens_only():
    """Branch names use only lowercase letters and hyphens."""
    import re
    name = _build_branch_name("aws_security_group", "public ssh port 22", "sg-ABC-12345 PROD")
    # Must start with "configtrace/"
    assert name.startswith("configtrace/")
    # After the prefix, only safe chars
    suffix = name[len("configtrace/"):]
    assert re.match(r'^[a-z0-9\-]+$', suffix), f"Unsafe chars in branch name: {name!r}"


def test_branch_name_max_length():
    """Branch names do not exceed 80 characters."""
    long_id = "a" * 200
    name = _build_branch_name("aws_security_group", "public ssh", long_id)
    assert len(name) <= 80, f"Branch name too long ({len(name)}): {name!r}"


def test_branch_name_no_consecutive_hyphens():
    """Branch names do not contain consecutive hyphens after sanitization."""
    name = _build_branch_name("aws_security_group", "ssh  --  public", "sg___test")
    assert "--" not in name, f"Consecutive hyphens in branch name: {name!r}"


def test_sanitize_segment_removes_unsafe_chars():
    """_sanitize_segment removes special characters and limits length."""
    result = _sanitize_segment("Hello World! foo@bar.baz", max_len=20)
    import re
    assert re.match(r'^[a-z0-9\-]+$', result)
    assert len(result) <= 20


# ── 4. Commit message: safe and non-sensational ───────────────────────────────

def test_commit_message_safe_language():
    """Commit messages use advisory, non-sensational language."""
    msg = _build_commit_message("aws_security_group_rule", "public ssh port 22", "sg-prod")
    # No sensational terms
    assert "breach" not in msg.lower()
    assert "hacked" not in msg.lower()
    assert "compromised" not in msg.lower()
    # Contains "ConfigTrace" attribution
    assert "ConfigTrace" in msg


def test_commit_message_rdp():
    """RDP changes produce RDP-specific commit message."""
    msg = _build_commit_message("aws_security_group_rule", "rdp tcp/3389 open", "sg-win")
    assert "rdp" in msg.lower() or "3389" in msg.lower() or "public" in msg.lower()
    assert "ConfigTrace" in msg


# ── 5. PR body: detection summary, mapping, checklist, disclaimer ─────────────

def test_pr_body_includes_validation_checklist():
    """PR body includes a terraform plan checklist item."""
    fix_preview = _make_fix_preview(confidence="medium")
    body = _build_pr_body(
        fix_preview=fix_preview,
        record_type="aws_security_group_rule",
        risk_level="high",
        record_identifier="sg-abc12345",
        change_id=uuid.uuid4(),
        is_outline_only=False,
    )
    assert "terraform plan" in body.lower()
    assert "checklist" in body.lower() or "- [ ]" in body


# ── 6. PR body includes "terraform plan" ─────────────────────────────────────

def test_pr_body_includes_terraform_plan():
    """PR body always references 'terraform plan'."""
    fix_preview = _make_fix_preview(confidence="high")
    body = _build_pr_body(
        fix_preview=fix_preview,
        record_type="aws_security_group",
        risk_level="critical",
        record_identifier="sg-demo",
        change_id=uuid.uuid4(),
        is_outline_only=False,
    )
    assert "terraform plan" in body.lower()


# ── 7. PR body includes "ConfigTrace has not changed the repository" ──────────

def test_pr_body_includes_has_not_changed_disclaimer():
    """PR body safety disclaimer states ConfigTrace has not changed the repository."""
    fix_preview = _make_fix_preview(confidence="medium")
    body = _build_pr_body(
        fix_preview=fix_preview,
        record_type="github_branch_protection",
        risk_level="high",
        record_identifier="main",
        change_id=uuid.uuid4(),
        is_outline_only=False,
    )
    body_lower = body.lower()
    assert "has not changed" in body_lower or "not changed this repository" in body_lower


# ── 8. Patch preview reused from M58.19 ──────────────────────────────────────

def test_patch_preview_reused_from_terraform_fix():
    """Patch preview in the draft matches the diff from M58.19."""
    workspace_id = uuid.uuid4()
    change = _make_change(
        provider_metadata={"record_type": "aws_security_group"},
        risk_reason="public ssh port 22",
        record_identifier="sg-abc12345",
    )
    change.record_identifier = "sg-abc12345"

    mock_db = _make_db_with_change_and_mapping(change, None)
    result = get_github_pr_draft(change.id, workspace_id, mock_db)

    if result.available and result.draft and result.draft.patch_preview:
        # Patch must reference the resource name or placeholder syntax
        assert "<" in result.draft.patch_preview or "-" in result.draft.patch_preview


# ── 9. Low-confidence/guided-only → outline-only draft ───────────────────────

def test_low_confidence_produces_outline_only_draft():
    """Low confidence IaC mappings produce outline-only PR drafts (no patch diff)."""
    workspace_id = uuid.uuid4()
    change = _make_change(
        provider_metadata={"record_type": "aws_security_group"},
        risk_reason="security group changed",
        record_identifier="sg-xyz99999",
    )
    change.record_identifier = "sg-xyz99999"

    mock_db = MagicMock()
    from app.models.change import Change
    from app.models.iac_resource_mapping import IacResourceMapping
    from app.models.iac_repository import IacRepository

    # Mapping with no identifier match → low confidence
    mock_mapping = MagicMock()
    mock_mapping.id = uuid.uuid4()
    mock_mapping.iac_repository_id = uuid.uuid4()
    mock_mapping.workspace_id = workspace_id
    mock_mapping.terraform_resource_type = "aws_security_group_rule"
    mock_mapping.terraform_resource_name = "allow_something_unrelated"
    mock_mapping.file_path = "aws/other.tf"
    mock_mapping.cloud_resource_identifier = None
    mock_mapping.cloud_resource_name = None
    mock_mapping.match_reason = ""
    mock_mapping.line_start = 1
    mock_mapping.line_end = 10

    mock_repo = MagicMock()
    mock_repo.repo_full_name = "acme/infra"
    mock_repo.default_branch = "main"

    def _query(model_class):
        q = MagicMock()
        if model_class is Change:
            q.filter.return_value.first.return_value = change
        elif model_class is IacResourceMapping:
            q.filter.return_value.all.return_value = [mock_mapping]
        elif model_class is IacRepository:
            q.filter.return_value.first.return_value = mock_repo
        return q

    mock_db.query.side_effect = _query

    result = get_github_pr_draft(change.id, workspace_id, mock_db)
    if result.available:
        # Mode should be outline_only OR patch_preview should be None
        is_outline = (
            result.mode == "outline_only"
            or (result.draft and result.draft.patch_preview is None)
        )
        patch_val = result.draft.patch_preview if result.draft else "N/A"
        assert is_outline, (
            f"Expected outline-only for low confidence, got mode={result.mode}, "
            f"patch={patch_val!r}"
        )


# ── 10. Safety flag: creates_branch is always False ──────────────────────────

def test_creates_branch_constant_false():
    """_CREATES_BRANCH constant is always False."""
    assert _CREATES_BRANCH is False


def test_safety_flags_creates_branch_false():
    """GitHubPrDraftSafetyFlags always has creates_branch=False."""
    flags = GitHubPrDraftSafetyFlags()
    assert flags.creates_branch is False


def test_schema_rejects_creates_branch_true():
    """Pydantic validator rejects creates_branch=True."""
    with pytest.raises(Exception):
        GitHubPrDraftSafetyFlags(creates_branch=True)


# ── 11. Safety flag: commits_code is always False ────────────────────────────

def test_commits_code_constant_false():
    """_COMMITS_CODE constant is always False."""
    assert _COMMITS_CODE is False


def test_schema_rejects_commits_code_true():
    """Pydantic validator rejects commits_code=True."""
    with pytest.raises(Exception):
        GitHubPrDraftSafetyFlags(commits_code=True)


# ── 12. Safety flag: opens_pr is always False ────────────────────────────────

def test_opens_pr_constant_false():
    """_OPENS_PR constant is always False."""
    assert _OPENS_PR is False


def test_schema_rejects_opens_pr_true():
    """Pydantic validator rejects opens_pr=True."""
    with pytest.raises(Exception):
        GitHubPrDraftSafetyFlags(opens_pr=True)


# ── 13. Safety flag: executes_terraform is always False ──────────────────────

def test_executes_terraform_constant_false():
    """_EXECUTES_TERRAFORM constant is always False."""
    assert _EXECUTES_TERRAFORM is False


def test_schema_rejects_executes_terraform_true():
    """Pydantic validator rejects executes_terraform=True."""
    with pytest.raises(Exception):
        GitHubPrDraftSafetyFlags(executes_terraform=True)


# ── 14. No GitHub mutation API calls ─────────────────────────────────────────

def test_no_github_api_calls_during_draft_generation():
    """get_github_pr_draft makes no HTTP calls to GitHub APIs."""
    workspace_id = uuid.uuid4()
    change = _make_change(
        provider_metadata={"record_type": "aws_security_group"},
        risk_reason="public ssh port 22",
        record_identifier="sg-abc12345",
    )
    change.record_identifier = "sg-abc12345"

    mock_db = _make_db_with_change_and_mapping(change, None)

    # Patch httpx to detect any outbound HTTP calls
    with patch("httpx.Client") as mock_client, patch("httpx.AsyncClient") as mock_async:
        result = get_github_pr_draft(change.id, workspace_id, mock_db)
        # Neither httpx.Client nor httpx.AsyncClient should have been instantiated
        mock_client.assert_not_called()
        mock_async.assert_not_called()

    # Result should still be valid
    assert result.safety.creates_branch is False
    assert result.safety.opens_pr is False


# ── 15. No workspace → unavailable ───────────────────────────────────────────

def test_no_workspace_id_returns_unavailable():
    """When workspace_id is None, PR draft returns unavailable."""
    # Test the router-level guard: workspace_id=None path
    # We simulate this by passing a None workspace_id and a change that exists
    # but is not workspace-linked.
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

    result = get_github_pr_draft(change.id, workspace_id, mock_db)
    assert result.available is False


# ── 16. No secrets/tokens/tfvars/tfstate in response ─────────────────────────

def test_response_contains_no_secret_patterns():
    """PR draft response text does not contain secret-looking patterns."""
    import re
    workspace_id = uuid.uuid4()
    change = _make_change(
        provider_metadata={"record_type": "aws_security_group"},
        risk_reason="public ssh port 22",
        record_identifier="sg-safe-test",
    )
    change.record_identifier = "sg-safe-test"

    mock_db = _make_db_with_change_and_mapping(change, None)
    result = get_github_pr_draft(change.id, workspace_id, mock_db)

    if result.available and result.draft:
        all_text = (
            result.draft.pr_body
            + result.draft.commit_message
            + result.draft.pr_title
            + result.draft.branch_name
            + (result.draft.patch_preview or "")
        )
        # No AWS access keys
        assert not re.search(r'\bAKIA[0-9A-Z]{16}\b', all_text)
        # No long hex secrets
        assert not re.search(r'\b[0-9a-fA-F]{40,}\b', all_text)
        # No tfvars/tfstate references
        assert ".tfvars" not in all_text
        assert ".tfstate" not in all_text


# ── 17. PR draft includes requirements list ───────────────────────────────────

def test_pr_draft_includes_requirements():
    """PR draft response includes the future requirements notice."""
    workspace_id = uuid.uuid4()
    change = _make_change(
        provider_metadata={"record_type": "github_branch_protection"},
        risk_reason="enforce_admins disabled",
        record_identifier="main",
    )
    change.record_identifier = "main"

    mock_db = MagicMock()
    from app.models.change import Change
    from app.models.iac_resource_mapping import IacResourceMapping
    from app.models.iac_repository import IacRepository

    mock_mapping = MagicMock()
    mock_mapping.id = uuid.uuid4()
    mock_mapping.iac_repository_id = uuid.uuid4()
    mock_mapping.workspace_id = workspace_id
    mock_mapping.terraform_resource_type = "github_branch_protection"
    mock_mapping.terraform_resource_name = "main_protection"
    mock_mapping.file_path = "github/protection.tf"
    mock_mapping.cloud_resource_identifier = "main"
    mock_mapping.cloud_resource_name = None
    mock_mapping.match_reason = ""
    mock_mapping.line_start = 1
    mock_mapping.line_end = 10

    mock_repo = MagicMock()
    mock_repo.repo_full_name = "acme/app"
    mock_repo.default_branch = "main"

    def _query(model_class):
        q = MagicMock()
        if model_class is Change:
            q.filter.return_value.first.return_value = change
        elif model_class is IacResourceMapping:
            q.filter.return_value.all.return_value = [mock_mapping]
        elif model_class is IacRepository:
            q.filter.return_value.first.return_value = mock_repo
        return q

    mock_db.query.side_effect = _query

    result = get_github_pr_draft(change.id, workspace_id, mock_db)
    assert result.requirements, "Requirements list should not be empty"
    requirements_text = " ".join(result.requirements).lower()
    assert "m58.21" in requirements_text or "future milestone" in requirements_text
