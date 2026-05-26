"""IaC Resource Mapping model — M58.18.

One row per Terraform resource block detected during an IaC repository scan
that may correspond to a monitored cloud resource.

Safety constraints (permanent):
- Full file contents are NEVER stored.
- Terraform variable values, secrets, credentials, and API tokens are NEVER stored.
- Only safe, non-sensitive metadata is stored: resource type/name, file path,
  approximate line range, and safe cloud identifiers.
"""

from __future__ import annotations

import uuid
from typing import Optional

from sqlalchemy import ForeignKey, Integer, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, BaseMixin


class IacResourceMapping(BaseMixin, Base):
    """One detected Terraform resource block that may map to a cloud resource.

    Created (or refreshed) each time a scan runs on the parent
    ``IacRepository``.  Rows for a repository are deleted and re-created on
    each scan so the data is always current.

    ``match_confidence`` values:
        "high"   — exact cloud_resource_identifier literal match
        "medium" — name/type/provider matching
        "low"    — resource-type-only match

    ``mapping_source`` values:
        "terraform_hcl_scan" — detected by the regex-based HCL scanner
        "tag_match"          — matched via Terraform tags block
        "name_match"         — matched via name attribute
        "arn_match"          — matched via ARN literal
        "manual"             — manually registered
    """

    __tablename__ = "iac_resource_mappings"

    workspace_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("workspaces.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    iac_repository_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("iac_repositories.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # ConfigTrace provider string: "aws", "cloudflare", "github", "vercel", …
    provider: Mapped[str] = mapped_column(Text, nullable=False)
    # ConfigTrace record_type that this mapping applies to, e.g. "aws_security_group"
    resource_type: Mapped[str] = mapped_column(Text, nullable=False)
    # Terraform HCL resource block type, e.g. "aws_security_group_rule"
    terraform_resource_type: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # Terraform HCL resource block name (second string in block header)
    terraform_resource_name: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # Repository-relative file path, e.g. "aws/security_groups.tf"
    file_path: Mapped[str] = mapped_column(Text, nullable=False)
    line_start: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    line_end: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    # Safe cloud identifier — never raw credentials or full ARNs containing secrets.
    # e.g. "sg-0abc12345def67890" for an AWS security group.
    cloud_resource_identifier: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # Human-readable cloud resource name, if extractable from the HCL.
    cloud_resource_name: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # "high" | "medium" | "low"
    match_confidence: Mapped[str] = mapped_column(Text, nullable=False)
    match_reason: Mapped[str] = mapped_column(Text, nullable=False)
    # "terraform_hcl_scan" | "tag_match" | "name_match" | "arn_match" | "manual"
    mapping_source: Mapped[str] = mapped_column(Text, nullable=False)

    def __repr__(self) -> str:
        return (
            f"<IacResourceMapping id={self.id}"
            f" tf_type={self.terraform_resource_type!r}"
            f" tf_name={self.terraform_resource_name!r}"
            f" confidence={self.match_confidence!r}>"
        )
