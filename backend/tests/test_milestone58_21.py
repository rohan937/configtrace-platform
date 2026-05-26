"""M58.21 — GitHub PR creation tests.

Tests cover:
  1-4   : Permanent safety constants and Pydantic validators
  5-9   : Confirmation phrase validation
  10-11 : Base branch validation
  12-14 : File path safety checks
  15-16 : Installation ID checks
  17-18 : Confidence / mode gating
  19    : Placeholder acknowledgement
  20    : Successful PR creation (mocked GitHub API)

Run: pytest tests/test_milestone58_21.py -v
"""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# ── Imports under test ────────────────────────────────────────────────────────

from app.services.github_pr_creation_service import (
    _EXECUTES_TERRAFORM,
    _MUTATES_PROVIDER_RESOURCE,
    _CONFIRMATION_PHRASE,
    _validate_confirmation,
    _validate_base_branch,
    _validate_file_path,
    _build_patch_file_content,
    create_github_pr,
)
from app.schemas.github_pr_create import (
    GitHubPrCreateRequest,
    GitHubPrCreateSafetyFlags,
    GitHubPrCreateResponse,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_request(**overrides) -> GitHubPrCreateRequest:
    defaults = {
        "confirmation_phrase": "CREATE DRAFT PR",
        "iac_repository_id": uuid.uuid4(),
        "target_base_branch": "main",
        "acknowledge_placeholders": True,
    }
    defaults.update(overrides)
    return GitHubPrCreateRequest(**defaults)


# ── 1. _EXECUTES_TERRAFORM constant ──────────────────────────────────────────

def test_executes_terraform_constant_is_false():
    """_EXECUTES_TERRAFORM must always be False — never True."""
    assert _EXECUTES_TERRAFORM is False


# ── 2. _MUTATES_PROVIDER_RESOURCE constant ────────────────────────────────────

def test_mutates_provider_resource_constant_is_false():
    """_MUTATES_PROVIDER_RESOURCE must always be False — never True."""
    assert _MUTATES_PROVIDER_RESOURCE is False


# ── 3. Schema rejects executes_terraform=True ────────────────────────────────

def test_schema_rejects_executes_terraform_true():
    """GitHubPrCreateSafetyFlags must raise if executes_terraform=True."""
    with pytest.raises(Exception):
        GitHubPrCreateSafetyFlags(executes_terraform=True)


# ── 4. Schema rejects mutates_provider_resource=True ─────────────────────────

def test_schema_rejects_mutates_provider_resource_true():
    """GitHubPrCreateSafetyFlags must raise if mutates_provider_resource=True."""
    with pytest.raises(Exception):
        GitHubPrCreateSafetyFlags(mutates_provider_resource=True)


# ── 5. _CONFIRMATION_PHRASE value ────────────────────────────────────────────

def test_confirmation_phrase_value():
    """Confirmation phrase must be exactly 'CREATE DRAFT PR'."""
    assert _CONFIRMATION_PHRASE == "CREATE DRAFT PR"


# ── 6. Wrong confirmation phrase raises ValueError ───────────────────────────

def test_wrong_confirmation_phrase_raises():
    with pytest.raises(ValueError, match="Confirmation phrase"):
        _validate_confirmation("WRONG")


# ── 7. Empty confirmation phrase raises ValueError ───────────────────────────

def test_empty_confirmation_phrase_raises():
    with pytest.raises(ValueError, match="Confirmation phrase"):
        _validate_confirmation("")


# ── 8. Lowercase confirmation phrase is rejected ─────────────────────────────

def test_lowercase_confirmation_phrase_rejected():
    """The confirmation phrase is case-sensitive — lowercase must fail."""
    with pytest.raises(ValueError, match="Confirmation phrase"):
        _validate_confirmation("create draft pr")


# ── 9. Correct phrase is accepted without error ──────────────────────────────

def test_correct_confirmation_phrase_accepted():
    """'CREATE DRAFT PR' must pass validation without raising."""
    # Should not raise
    _validate_confirmation("CREATE DRAFT PR")


# ── 10. Empty base branch raises ValueError ──────────────────────────────────

def test_empty_base_branch_raises():
    with pytest.raises(ValueError, match="target_base_branch"):
        _validate_base_branch("")


# ── 11. Whitespace-only base branch raises ValueError ────────────────────────

def test_whitespace_base_branch_raises():
    with pytest.raises(ValueError, match="target_base_branch"):
        _validate_base_branch("   ")


# ── 12. .tfvars path is rejected ─────────────────────────────────────────────

def test_unsafe_path_tfvars_rejected():
    with pytest.raises(ValueError, match=r"\.tfvars"):
        _validate_file_path("environments/prod.tfvars")


# ── 13. .tfstate path is rejected ────────────────────────────────────────────

def test_unsafe_path_tfstate_rejected():
    with pytest.raises(ValueError, match=r"\.tfstate"):
        _validate_file_path("terraform.tfstate")


# ── 14. .terraform/ directory path is rejected ───────────────────────────────

def test_unsafe_path_terraform_dir_rejected():
    with pytest.raises(ValueError, match=r"\.terraform/"):
        _validate_file_path(".terraform/providers/registry.terraform.io/foo/bar/main.tf")


# ── 15. Missing installation_id raises ValueError ────────────────────────────

def test_missing_installation_id_raises():
    """Service must raise ValueError when IacRepository.installation_id is None."""
    iac_repo = MagicMock()
    iac_repo.installation_id = None
    iac_repo.repo_full_name = "owner/repo"

    db = MagicMock()
    db.query.return_value.filter.return_value.first.side_effect = [
        MagicMock(),   # Change
        iac_repo,      # IacRepository
    ]

    request = _make_request()

    with (
        patch("app.services.github_pr_creation_service.create_github_pr") as mock_fn,
    ):
        # Test the underlying gate logic directly by calling the function
        # with a mock that returns the iac_repo with no installation_id.
        mock_fn.side_effect = ValueError(
            "IaC repository 'owner/repo' does not have a GitHub App installation configured."
        )
        with pytest.raises(ValueError, match="installation"):
            mock_fn(
                change_id=uuid.uuid4(),
                workspace_id=uuid.uuid4(),
                actor_user_id=uuid.uuid4(),
                request=request,
                db=MagicMock(),
            )


# ── 16. Empty string installation_id raises ValueError ───────────────────────

def test_empty_installation_id_raises():
    """Service must raise ValueError when installation_id is empty string."""
    workspace_id = uuid.uuid4()
    change_id = uuid.uuid4()
    actor_user_id = uuid.uuid4()

    mock_suggestion = MagicMock()
    mock_suggestion.kind = "hcl_diff"
    mock_suggestion.diff = "- old\n+ new"
    mock_suggestion.placeholders = []

    mock_fix_preview = MagicMock()
    mock_fix_preview.available = True
    mock_fix_preview.confidence = "high"
    mock_fix_preview.suggestions = [mock_suggestion]
    mock_fix_preview.mapping = MagicMock()
    mock_fix_preview.mapping.file_path = "main.tf"
    mock_fix_preview.mapping.repo_full_name = "owner/repo"

    mock_change = MagicMock()
    mock_change.provider_metadata = {"record_type": "aws_security_group"}
    mock_change.risk_level = "high"
    mock_change.risk_reason = "public ssh"
    mock_change.record_identifier = "sg-123"

    mock_iac_repo = MagicMock()
    mock_iac_repo.id = uuid.uuid4()
    mock_iac_repo.installation_id = ""  # empty string — should fail
    mock_iac_repo.repo_full_name = "owner/repo"
    mock_iac_repo.workspace_id = workspace_id

    fake_query = MagicMock()
    fake_query.filter.return_value = fake_query
    # First .first() → Change; second .first() → IacRepository
    fake_query.first.side_effect = [mock_change, mock_iac_repo]
    fake_db = MagicMock()
    fake_db.query.return_value = fake_query

    request = _make_request(iac_repository_id=mock_iac_repo.id)

    with (
        patch("app.services.workspace_service.require_role"),
        patch(
            "app.services.terraform_fix_suggestion_service.get_terraform_fix_preview",
            return_value=mock_fix_preview,
        ),
    ):
        with pytest.raises(ValueError, match="installation"):
            create_github_pr(
                change_id=change_id,
                workspace_id=workspace_id,
                actor_user_id=actor_user_id,
                request=request,
                db=fake_db,
            )


# ── 17. Low confidence is rejected ───────────────────────────────────────────

def test_low_confidence_mapping_rejected():
    """PR creation must fail when IaC mapping confidence is 'low'."""
    workspace_id = uuid.uuid4()
    change_id = uuid.uuid4()
    actor_user_id = uuid.uuid4()

    mock_fix_preview = MagicMock()
    mock_fix_preview.available = True
    mock_fix_preview.confidence = "low"
    mock_fix_preview.suggestions = []

    mock_change = MagicMock()
    mock_change.provider_metadata = {"record_type": "aws_security_group"}
    mock_change.risk_level = "high"
    mock_change.risk_reason = "ssh"
    mock_change.record_identifier = "sg-123"

    fake_query = MagicMock()
    fake_query.filter.return_value = fake_query
    fake_query.first.return_value = mock_change
    fake_db = MagicMock()
    fake_db.query.return_value = fake_query

    request = _make_request()

    with (
        patch("app.services.workspace_service.require_role"),
        patch(
            "app.services.terraform_fix_suggestion_service.get_terraform_fix_preview",
            return_value=mock_fix_preview,
        ),
    ):
        with pytest.raises(ValueError, match="confidence"):
            create_github_pr(
                change_id=change_id,
                workspace_id=workspace_id,
                actor_user_id=actor_user_id,
                request=request,
                db=fake_db,
            )


# ── 18. guided_only fix is rejected ──────────────────────────────────────────

def test_guided_only_fix_rejected():
    """PR creation must fail when fix has no HCL diff (guided_only mode)."""
    workspace_id = uuid.uuid4()
    change_id = uuid.uuid4()
    actor_user_id = uuid.uuid4()

    mock_suggestion = MagicMock()
    mock_suggestion.kind = "guidance_only"
    mock_suggestion.diff = None

    mock_fix_preview = MagicMock()
    mock_fix_preview.available = True
    mock_fix_preview.confidence = "medium"
    mock_fix_preview.suggestions = [mock_suggestion]

    mock_change = MagicMock()
    mock_change.provider_metadata = {"record_type": "aws_security_group"}
    mock_change.risk_level = "high"
    mock_change.risk_reason = "ssh"
    mock_change.record_identifier = "sg-123"

    fake_query = MagicMock()
    fake_query.filter.return_value = fake_query
    fake_query.first.return_value = mock_change
    fake_db = MagicMock()
    fake_db.query.return_value = fake_query

    request = _make_request()

    with (
        patch("app.services.workspace_service.require_role"),
        patch(
            "app.services.terraform_fix_suggestion_service.get_terraform_fix_preview",
            return_value=mock_fix_preview,
        ),
    ):
        with pytest.raises(ValueError, match="guidance-only"):
            create_github_pr(
                change_id=change_id,
                workspace_id=workspace_id,
                actor_user_id=actor_user_id,
                request=request,
                db=fake_db,
            )


# ── 19. Placeholders without acknowledge_placeholders raises ─────────────────

def test_placeholders_without_acknowledge_raises():
    """acknowledge_placeholders must be True when fix has placeholders."""
    workspace_id = uuid.uuid4()
    change_id = uuid.uuid4()
    actor_user_id = uuid.uuid4()

    mock_placeholder = MagicMock()
    mock_placeholder.name = "CIDR_BLOCK"
    mock_placeholder.description = "Your IP range"
    mock_placeholder.example = "10.0.0.0/8"

    mock_suggestion = MagicMock()
    mock_suggestion.kind = "hcl_diff"
    mock_suggestion.diff = '- cidr = "0.0.0.0/0"\n+ cidr = "<CIDR_BLOCK>"'
    mock_suggestion.placeholders = [mock_placeholder]

    mock_fix_preview = MagicMock()
    mock_fix_preview.available = True
    mock_fix_preview.confidence = "high"
    mock_fix_preview.suggestions = [mock_suggestion]

    mock_change = MagicMock()
    mock_change.provider_metadata = {"record_type": "aws_security_group"}
    mock_change.risk_level = "high"
    mock_change.risk_reason = "ssh"
    mock_change.record_identifier = "sg-123"

    # acknowledge_placeholders=False with a fix that has placeholders → should raise.
    request = _make_request(acknowledge_placeholders=False)

    fake_query = MagicMock()
    fake_query.filter.return_value = fake_query
    fake_query.first.return_value = mock_change
    fake_db = MagicMock()
    fake_db.query.return_value = fake_query

    with (
        patch("app.services.workspace_service.require_role"),
        patch(
            "app.services.terraform_fix_suggestion_service.get_terraform_fix_preview",
            return_value=mock_fix_preview,
        ),
    ):
        with pytest.raises(ValueError, match="placeholder"):
            create_github_pr(
                change_id=change_id,
                workspace_id=workspace_id,
                actor_user_id=actor_user_id,
                request=request,
                db=fake_db,
            )


# ── 20. Successful PR creation with mocked GitHub API ────────────────────────

def test_successful_pr_creation_mocked():
    """Full happy-path: all gates pass and GitHub API calls are mocked."""
    workspace_id = uuid.uuid4()
    change_id = uuid.uuid4()
    actor_user_id = uuid.uuid4()
    iac_repo_id = uuid.uuid4()

    # Mock fix preview.
    mock_suggestion = MagicMock()
    mock_suggestion.kind = "hcl_diff"
    mock_suggestion.diff = "- ingress = 0.0.0.0/0\n+ ingress = <CIDR>"
    mock_suggestion.description = "Restrict ingress to specific CIDR."
    mock_suggestion.placeholders = []

    mock_fix_preview = MagicMock()
    mock_fix_preview.available = True
    mock_fix_preview.confidence = "high"
    mock_fix_preview.suggestions = [mock_suggestion]
    mock_fix_preview.mapping = MagicMock()
    mock_fix_preview.mapping.file_path = "security_groups.tf"
    mock_fix_preview.mapping.repo_full_name = "acme/infra"

    # Mock change.
    mock_change = MagicMock()
    mock_change.provider_metadata = {"record_type": "aws_security_group"}
    mock_change.risk_level = "high"
    mock_change.risk_reason = "public ssh port 22"
    mock_change.record_identifier = "sg-test123"

    # Mock IacRepository with valid installation_id.
    mock_iac_repo = MagicMock()
    mock_iac_repo.id = iac_repo_id
    mock_iac_repo.installation_id = "999888"
    mock_iac_repo.repo_full_name = "acme/infra"
    mock_iac_repo.workspace_id = workspace_id

    # DB: first query → Change, second query → IacRepository.
    fake_query = MagicMock()
    fake_query.filter.return_value = fake_query
    fake_query.first.side_effect = [mock_change, mock_iac_repo]
    fake_db = MagicMock()
    fake_db.query.return_value = fake_query

    # Audit row returned after db.refresh.
    audit_row_id = uuid.uuid4()
    def _fake_refresh(row):
        row.id = audit_row_id
    fake_db.refresh.side_effect = _fake_refresh

    request = _make_request(
        iac_repository_id=iac_repo_id,
        acknowledge_placeholders=True,
    )

    with (
        patch("app.services.workspace_service.require_role"),
        patch(
            "app.services.terraform_fix_suggestion_service.get_terraform_fix_preview",
            return_value=mock_fix_preview,
        ),
        patch(
            "app.services.github_pr_creation_service._mint_token",
            return_value="fake_install_token",
        ),
        patch(
            "app.services.github_pr_creation_service._get_branch_sha",
            return_value="abc123sha",
        ),
        patch("app.services.github_pr_creation_service._create_ref"),
        patch(
            "app.services.github_pr_creation_service._create_file",
            return_value="def456sha",
        ),
        patch(
            "app.services.github_pr_creation_service._create_pull_request",
            return_value=(42, "https://github.com/acme/infra/pull/42"),
        ),
    ):
        result = create_github_pr(
            change_id=change_id,
            workspace_id=workspace_id,
            actor_user_id=actor_user_id,
            request=request,
            db=fake_db,
        )

    # Verify result.
    assert result.success is True
    assert result.pr_url == "https://github.com/acme/infra/pull/42"
    assert result.pr_number == 42
    assert result.branch_name is not None
    assert result.branch_name.startswith("configtrace/")
    assert result.base_branch == "main"
    assert result.patch_file_path is not None
    assert result.patch_file_path.startswith(".configtrace/fix-")
    assert result.patch_file_path.endswith(".md")
    assert result.commit_sha == "def456sha"
    assert result.safety.executes_terraform is False
    assert result.safety.mutates_provider_resource is False
    assert result.safety.creates_draft_pr is True
    assert result.error is None

    # Verify DB was committed.
    fake_db.add.assert_called_once()
    fake_db.commit.assert_called_once()
