from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from sqlalchemy import Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, BaseMixin

if TYPE_CHECKING:
    from app.models.integration import Integration


class User(BaseMixin, Base):
    """One record per authenticated user, created on first Clerk login."""

    __tablename__ = "users"

    clerk_id: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    email: Mapped[str] = mapped_column(Text, nullable=False)
    display_name: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # ── Relationships ────────────────────────────────────────────────────────
    integrations: Mapped[list[Integration]] = relationship(
        "Integration",
        back_populates="user",
        lazy="selectin",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<User id={self.id} clerk_id={self.clerk_id!r}>"
