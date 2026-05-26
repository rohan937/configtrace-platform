"""GitHub PR Suggestion model — M58.21.

Audit trail for GitHub draft PRs opened via ConfigTrace.

Safety constraints (permanent):
- No Terraform state, no provider credentials, no secret values are stored.
- Only safe metadata: branch name, PR URL, commit SHA, actor user ID.
- pr_state tracks the last known state; not a real-time mirror.
"""

from __future__ import annotations

import uuid
from typing import Optional

from sqlalchemy import Integer, Text, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, BaseMixin


class GitHubPrSuggestion(BaseMixin, Base):
    """One row per ConfigTrace-opened GitHub draft PR.

    Stores only safe audit metadata — no Terraform state, no secrets,
    no raw provider credentials.
    """

    __tablename__ = "github_pr_suggestions"

    change_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("changes.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    workspace_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("workspaces.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # Nullable so the row survives if the IacRepository is deleted.
    iac_repository_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("iac_repositories.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    # Clerk user ID string — not a FK to users table (Clerk owns user data).
    actor_user_id: Mapped[str] = mapped_column(Text, nullable=False)
    # GitHub PR URL — safe to store and display.
    pr_url: Mapped[str] = mapped_column(Text, nullable=False)
    pr_number: Mapped[int] = mapped_column(Integer, nullable=False)
    branch_name: Mapped[str] = mapped_column(Text, nullable=False)
    base_branch: Mapped[str] = mapped_column(Text, nullable=False)
    # Path of the patch file created on the branch (e.g. ".configtrace/fix-abc123.md")
    patch_file_path: Mapped[str] = mapped_column(Text, nullable=False)
    # SHA of the commit that created the patch file. May be None on fetch failure.
    commit_sha: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # "open" | "closed" | "merged" — updated manually if needed; not real-time.
    pr_state: Mapped[str] = mapped_column(
        Text, nullable=False, default="open", server_default="open"
    )

    def __repr__(self) -> str:
        return (
            f"<GitHubPrSuggestion id={self.id} pr={self.pr_url!r}"
            f" change={self.change_id}>"
        )
