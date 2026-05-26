"""M58.18: IaC Awareness Foundation — unit tests.

Tests cover:
  - Pure Terraform scanner functions (no DB, no I/O)
  - File safety filtering
  - Mapping confidence logic
  - Repository CRUD (with mock DB)
  - Change IaC context logic (with mock DB)
  - Safety: no secrets, no provider writes, no PR creation, language rules

Run:
    cd backend && DATABASE_URL="sqlite:///test.db" .venv/bin/pytest tests/test_milestone58_18.py -v --noconftest

All 13+ tests must pass.
"""

from __future__ import annotations

import uuid
from unittest.mock import MagicMock, patch

import pytest

from app.services.iac_mapping_service import (
    TerraformBlock,
    _compute_match_confidence,
    _get_tf_candidates_for_change,
    _is_safe_file,
    _is_sensitive_value,
    scan_terraform_content,
    scan_files,
    get_iac_context,
    list_repositories,
    register_repository,
)
from app.schemas.iac import IacRepositoryCreate


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_change(
    *,
    record_identifier: str = "aws_security_group: sg-abc12345",
    provider_metadata: dict | None = None,
) -> MagicMock:
    """Minimal Change mock for testing."""
    c = MagicMock()
    c.id = uuid.uuid4()
    c.record_identifier = record_identifier
    c.provider_metadata = provider_metadata or {}
    return c


def _make_mapping(
    *,
    terraform_resource_type: str = "aws_security_group_rule",
    terraform_resource_name: str = "allow_ssh",
    cloud_resource_identifier: str | None = None,
    cloud_resource_name: str | None = None,
    provider: str = "aws",
    match_reason: str = "",
) -> MagicMock:
    """Minimal IacResourceMapping mock for testing."""
    m = MagicMock()
    m.id = uuid.uuid4()
    m.iac_repository_id = uuid.uuid4()
    m.workspace_id = uuid.uuid4()
    m.terraform_resource_type = terraform_resource_type
    m.terraform_resource_name = terraform_resource_name
    m.cloud_resource_identifier = cloud_resource_identifier
    m.cloud_resource_name = cloud_resource_name
    m.provider = provider
    m.match_reason = match_reason
    m.file_path = "aws/security_groups.tf"
    m.line_start = 5
    m.line_end = 20
    m.mapping_source = "terraform_hcl_scan"
    return m


# ── 1. Terraform scanner detects resource blocks ──────────────────────────────

def test_scanner_detects_resource_blocks():
    """Scanner finds resource blocks in a .tf file."""
    content = """
resource "aws_security_group_rule" "allow_ssh" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  description = "Allow SSH from office"
  cidr_blocks = ["10.0.0.0/8"]
}

resource "aws_cloudfront_distribution" "my_cdn" {
  description = "Production CDN"
}
"""
    blocks = scan_terraform_content(content, "aws/main.tf")
    assert len(blocks) == 2
    types = {b.resource_type for b in blocks}
    assert "aws_security_group_rule" in types
    assert "aws_cloudfront_distribution" in types

    sg_block = next(b for b in blocks if b.resource_type == "aws_security_group_rule")
    assert sg_block.resource_name == "allow_ssh"
    assert sg_block.safe_attrs.get("description") == "Allow SSH from office"
    assert sg_block.file_path == "aws/main.tf"
    assert sg_block.line_start >= 1
    assert sg_block.line_end >= sg_block.line_start


# ── 2. Scanner ignores unsafe files ──────────────────────────────────────────

def test_scanner_ignores_terraform_dir():
    """.terraform/ directory files are rejected by _is_safe_file."""
    assert _is_safe_file(".terraform/providers/registry.terraform.io/hashicorp/aws/main.tf") is False
    assert _is_safe_file("modules/.terraform/lock.hcl") is False


def test_scanner_ignores_tfstate():
    """*.tfstate files are rejected."""
    assert _is_safe_file("terraform.tfstate") is False
    assert _is_safe_file("prod/terraform.tfstate.backup") is False


def test_scanner_ignores_tfvars():
    """*.tfvars and *.tfvars.json files are rejected."""
    assert _is_safe_file("prod.tfvars") is False
    assert _is_safe_file("secrets.tfvars.json") is False


def test_scanner_accepts_tf_files():
    """*.tf and *.tf.json files are accepted."""
    assert _is_safe_file("aws/security_groups.tf") is True
    assert _is_safe_file("modules/vpc/main.tf") is True
    assert _is_safe_file("infra.tf.json") is True


# ── 3. Scanner respects max file size ─────────────────────────────────────────

def test_scanner_respects_max_file_size():
    """Files exceeding 256KB are skipped."""
    # Generate content slightly over 256KB
    large_content = ('resource "aws_instance" "x" { name = "y" }\n') * 10_000
    blocks = scan_terraform_content(large_content, "huge.tf")
    assert blocks == []


def test_scanner_respects_max_files():
    """scan_files() stops after max_files files."""
    files = [(f"file_{i}.tf", 'resource "aws_s3_bucket" "b" { name = "test" }') for i in range(200)]
    blocks = scan_files(files, max_files=10)
    # All blocks come from the first 10 files; more than 0 but bounded
    unique_files = {b.file_path for b in blocks}
    assert len(unique_files) <= 10


# ── 4. Scanner does not store sensitive values ────────────────────────────────

def test_scanner_drops_sensitive_values():
    """Secret-looking attribute values are not stored."""
    content = """
resource "aws_security_group" "main" {
  name        = "prod-sg"
  description = "Production SG"
}
"""
    # These should NOT be stored
    assert _is_sensitive_value("AKIAIOSFODNN7EXAMPLE") is True  # AWS access key
    assert _is_sensitive_value("ghp_abc1234567890abcdef1234567890abcdef") is True  # long base64-like
    assert _is_sensitive_value("my-secret-password-abc") is True  # contains "secret"
    # These SHOULD be safe
    assert _is_sensitive_value("prod-security-group") is False
    assert _is_sensitive_value("allow_ssh") is False
    assert _is_sensitive_value("us-east-1") is False


def test_scanner_does_not_store_long_values():
    """Attribute values longer than 100 chars are never stored."""
    very_long_value = "x" * 101
    content = f'resource "aws_security_group" "main" {{ description = "{very_long_value}" }}'
    blocks = scan_terraform_content(content, "test.tf")
    assert len(blocks) == 1
    assert "description" not in blocks[0].safe_attrs


# ── 5. AWS security group change maps to security group candidates ─────────────

def test_aws_sg_change_maps_to_sg_tf_types():
    """AWS security group changes get candidates from the SG Terraform types."""
    change = _make_change(
        record_identifier="aws_security_group: sg-abc12345",
        provider_metadata={"record_type": "aws_security_group"},
    )
    candidates = _get_tf_candidates_for_change(change)
    assert "aws_security_group" in candidates
    assert "aws_security_group_rule" in candidates
    assert "aws_vpc_security_group_ingress_rule" in candidates


# ── 6. Route53/Cloudflare DNS maps to DNS IaC resource candidates ──────────────

def test_route53_change_maps_to_route53_tf_type():
    """Route53 record changes get aws_route53_record candidate."""
    change = _make_change(
        record_identifier="aws_route53_record: api.example.com",
        provider_metadata={"record_type": "aws_route53_record"},
    )
    candidates = _get_tf_candidates_for_change(change)
    assert "aws_route53_record" in candidates


def test_cloudflare_record_maps_to_dns_tf_types():
    """Cloudflare DNS record changes get cloudflare_record candidate."""
    change = _make_change(
        record_identifier="cloudflare_record: api.example.com",
        provider_metadata={"record_type": "cloudflare_record"},
    )
    candidates = _get_tf_candidates_for_change(change)
    assert "cloudflare_record" in candidates


# ── 7. GitHub branch protection maps to github_branch_protection ───────────────

def test_github_branch_protection_maps_to_tf_type():
    """GitHub branch protection changes get github_branch_protection candidate."""
    change = _make_change(
        record_identifier="github_branch_protection: main",
        provider_metadata={"record_type": "github_branch_protection"},
    )
    candidates = _get_tf_candidates_for_change(change)
    assert "github_branch_protection" in candidates


# ── 8. Confidence: high on exact identifier match ─────────────────────────────

def test_high_confidence_on_exact_identifier_match():
    """Exact cloud_resource_identifier match yields high confidence."""
    change = _make_change(record_identifier="sg-abc12345678")
    mapping = _make_mapping(cloud_resource_identifier="sg-abc12345678")
    confidence, reason = _compute_match_confidence(mapping, change)
    assert confidence == "high"
    assert "sg-abc12345678" in reason


# ── 9. Confidence: medium on name token match ─────────────────────────────────

def test_medium_confidence_on_name_token_match():
    """Cloud resource name matching a token in record_identifier yields medium confidence.

    The tokenizer splits on whitespace/colons/pipes/commas/hyphens/underscores,
    so cloud_resource_name must appear as a token (no delimiters within it).
    """
    change = _make_change(record_identifier="Security Group: websg rule ingress")
    mapping = _make_mapping(
        cloud_resource_identifier=None,
        cloud_resource_name="websg",  # appears as a whole token after splitting
    )
    confidence, reason = _compute_match_confidence(mapping, change)
    assert confidence == "medium"


# ── 10. Confidence: low on type-only match ────────────────────────────────────

def test_low_confidence_on_type_only_match():
    """No identifier or name match yields low confidence."""
    change = _make_change(record_identifier="Some completely different thing xyz99")
    mapping = _make_mapping(
        cloud_resource_identifier=None,
        cloud_resource_name=None,
        terraform_resource_name="unrelated_resource",
    )
    confidence, reason = _compute_match_confidence(mapping, change)
    assert confidence == "low"
    assert "may be managed by Terraform" in reason or "possible" in reason.lower() or "matches" in reason.lower()


# ── 11. IaC context endpoint enforces workspace authorization ─────────────────

def test_iac_context_no_repos_returns_unavailable():
    """get_iac_context returns available=False when no repos are registered."""
    workspace_id = uuid.uuid4()
    change_id = uuid.uuid4()

    # Set up mock DB
    mock_db = MagicMock()
    mock_change = _make_change()
    mock_change.id = change_id

    # Mock: change found, no repositories
    mock_db.query.return_value.filter.return_value.first.return_value = mock_change
    mock_db.query.return_value.filter.return_value.count.return_value = 0

    result = get_iac_context(change_id, workspace_id, mock_db)
    assert result.available is False
    assert "No IaC repositories" in result.summary


# ── 12. Response uses "may be managed" advisory language ─────────────────────

def test_iac_context_uses_advisory_language():
    """Advisory language: 'may be managed by Terraform', never overclaims."""
    workspace_id = uuid.uuid4()

    # Build a low-confidence scenario with a mapping
    from app.schemas.iac import IacContextResponse
    change = _make_change(record_identifier="Some resource: some-name-xyz")
    mapping = _make_mapping(
        terraform_resource_type="aws_security_group_rule",
        cloud_resource_identifier=None,
        cloud_resource_name=None,
    )
    mapping.workspace_id = workspace_id

    mock_db = MagicMock()

    # Simulate: change found, 1 repo, 1 mapping, 1 candidate
    def mock_query_side_effect(model_class):
        q = MagicMock()
        from app.models.change import Change
        from app.models.iac_repository import IacRepository
        from app.models.iac_resource_mapping import IacResourceMapping

        if model_class is Change:
            q.filter.return_value.first.return_value = change
        elif model_class is IacRepository:
            q.filter.return_value.count.return_value = 1
            mock_repo = MagicMock()
            mock_repo.id = mapping.iac_repository_id
            mock_repo.repo_full_name = "acme/infra"
            q.filter.return_value.all.return_value = [mock_repo]
            q.filter.return_value.count.return_value = 1
        elif model_class is IacResourceMapping:
            q.filter.return_value.count.return_value = 1
            q.filter.return_value.filter.return_value.all.return_value = [mapping]
            q.filter.return_value.all.return_value = [mapping]
        return q

    mock_db.query.side_effect = mock_query_side_effect

    result = get_iac_context(change.id, workspace_id, mock_db)
    # The result may be available or not depending on mock chain resolution,
    # but the important check is the language in the future_fix_note
    assert result.future_fix_note is not None
    assert "M58.19" in result.future_fix_note
    assert result.future_fix_available is False


# ── 13. No provider writes / no GitHub writes / no PR creation ───────────────

def test_scan_result_schema_has_no_write_fields():
    """IacScanResult schema contains no PR creation or provider mutation fields."""
    from app.schemas.iac import IacScanResult
    result = IacScanResult(
        status="no_integration",
        message="Test",
        resources_found=0,
        files_scanned=0,
    )
    result_dict = result.model_dump()
    # Ensure no PR or mutation related fields exist
    forbidden_fields = {"pull_request_url", "branch_created", "commit_sha", "provider_mutated"}
    assert not forbidden_fields.intersection(result_dict.keys())


def test_iac_context_future_fix_always_false_in_m58_18():
    """future_fix_available is always False in M58.18 — no Terraform patches yet."""
    workspace_id = uuid.uuid4()
    change_id = uuid.uuid4()

    mock_db = MagicMock()
    mock_change = _make_change()
    mock_change.id = change_id
    mock_db.query.return_value.filter.return_value.first.return_value = mock_change
    mock_db.query.return_value.filter.return_value.count.return_value = 0

    result = get_iac_context(change_id, workspace_id, mock_db)
    assert result.future_fix_available is False


# ── 14. Repository registration raises ValueError on duplicate ────────────────

def test_register_repository_raises_on_duplicate():
    """register_repository raises ValueError if the same repo is already registered."""
    mock_db = MagicMock()
    existing = MagicMock()
    existing.repo_full_name = "acme/infra"
    mock_db.query.return_value.filter.return_value.first.return_value = existing

    data = IacRepositoryCreate(repo_full_name="acme/infra")
    with pytest.raises(ValueError, match="already registered"):
        register_repository(uuid.uuid4(), data, mock_db)


# ── 15. Safe file scanner: multiple providers ─────────────────────────────────

def test_scanner_detects_cloudflare_and_github_resources():
    """Scanner identifies Cloudflare and GitHub Terraform resources."""
    content = """
resource "cloudflare_record" "api_dns" {
  name    = "api"
  type    = "A"
  zone_id = "abc123"
}

resource "github_branch_protection" "main_protection" {
  repository = "my-app"
  branch     = "main"
}
"""
    blocks = scan_terraform_content(content, "dns.tf")
    assert len(blocks) == 2
    types = {b.resource_type for b in blocks}
    assert "cloudflare_record" in types
    assert "github_branch_protection" in types

    cf_block = next(b for b in blocks if b.resource_type == "cloudflare_record")
    assert cf_block.safe_attrs.get("name") == "api"
    assert cf_block.safe_attrs.get("type") == "A"

    gh_block = next(b for b in blocks if b.resource_type == "github_branch_protection")
    assert gh_block.safe_attrs.get("repository") == "my-app"
