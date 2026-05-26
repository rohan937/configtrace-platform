"""IaC Repository model — M58.18.

Records which GitHub repositories a workspace has registered for Terraform
scanning.  No file contents, credentials, or secret values are stored here —
only safe metadata about the repository and the result of the last scan.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, BaseMixin


class IacRepository(BaseMixin, Base):
    """One row per IaC repository registered for a workspace.

    Tracks which GitHub repositories may contain Terraform files and the
    outcome of the last safe metadata scan.

    Safety constraints (permanent):
    - Full file contents are NEVER stored here.
    - No Terraform variable values, secret values, or credentials.
    - ``last_error`` stores only sanitised error messages — never raw
      exception tracebacks, tokens, or provider credentials.
    """

    __tablename__ = "iac_repositories"

    workspace_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("workspaces.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # Optional link to an existing GitHub integration — used to read file tree.
    # Nullable so repositories can be registered manually without an integration.
    integration_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("integrations.id", ondelete="SET NULL"),
        nullable=True,
    )
    # IaC provider type — "github" only in M58.18 MVP.
    provider: Mapped[str] = mapped_column(
        Text, nullable=False, default="github", server_default="github"
    )
    # GitHub "owner/repo" form, e.g. "acme/infra".
    repo_full_name: Mapped[str] = mapped_column(Text, nullable=False)
    default_branch: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # Reserved for future GitHub App installation ID (M58.20+).
    installation_id: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    scanning_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    # "success" | "no_integration" | "no_access" | "no_tf_files" | "error" | None
    last_scan_status: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    last_scan_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # Sanitised error description — never raw exception text or secrets.
    last_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    def __repr__(self) -> str:
        return (
            f"<IacRepository id={self.id} repo={self.repo_full_name!r}"
            f" workspace={self.workspace_id}>"
        )
