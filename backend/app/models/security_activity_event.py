"""SecurityActivityEvent — normalized control-plane activity events (M66.2).

The data spine for the future **Incident Signals** product. Where
``security_findings`` answers *"which current configuration is risky?"*, this
table answers *"what control-plane activity happened?"* — starting with GitHub
audit-log/control-plane events (branch-protection changes, deploy keys, webhooks,
collaborator changes, app installs, rulesets, secret-scanning alerts).

CLAIM DISCIPLINE — read before extending:
  This table only stores normalized *activity events*. It does NOT detect
  breaches, identify attackers, or confirm compromise. Correlation logic that
  turns activity + exposure into incident signals is a FUTURE milestone. Nothing
  here may be surfaced as "breach detected" / "attacker found" / "compromise
  confirmed".

PRIVACY INVARIANTS (enforced in security_activity_event_service):
  * NEVER store raw request bodies, full audit-log payloads, secrets, or tokens.
  * Source IP, if present, is stored ONLY as a salted hash (``source_ip_hash``) —
    never the raw IP.
  * ``event_metadata`` keys must be on a small allowlist; values are flat scalars,
    truncated; nested objects/arrays are dropped.
  * ``raw_ref`` is a pointer/id reference (e.g. the provider document id), never
    the raw event body.

Idempotency: a unique partial index on
``(workspace_id, provider, source, provider_event_id)`` (where
``provider_event_id`` is not null) makes re-ingesting the same event a no-op. When
the provider gives no stable id, the service supplies a deterministic
``fp:<hash>`` fingerprint so the same uniqueness guarantee still holds.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import DateTime, ForeignKey, Index, Text, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, BaseMixin


class SecurityActivityEvent(BaseMixin, Base):
    __tablename__ = "security_activity_events"
    __table_args__ = (
        # Query paths: by provider/time, by resource/time, by actor/time, by type/time.
        Index(
            "ix_sec_activity_ws_provider_occurred",
            "workspace_id",
            "provider",
            "occurred_at",
        ),
        Index(
            "ix_sec_activity_ws_resource_occurred",
            "workspace_id",
            "resource_id",
            "occurred_at",
        ),
        Index(
            "ix_sec_activity_ws_actor_occurred",
            "workspace_id",
            "actor_id",
            "occurred_at",
        ),
        Index(
            "ix_sec_activity_ws_event_type_occurred",
            "workspace_id",
            "event_type",
            "occurred_at",
        ),
        # Idempotency: at most one row per stable provider event id.
        Index(
            "uq_sec_activity_provider_event",
            "workspace_id",
            "provider",
            "source",
            "provider_event_id",
            unique=True,
            postgresql_where=text("provider_event_id IS NOT NULL"),
        ),
    )

    workspace_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("workspaces.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    integration_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("integrations.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    provider: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    # Where the event came from, e.g. "audit_log".
    source: Mapped[str] = mapped_column(
        Text, nullable=False, server_default="audit_log", default="audit_log"
    )
    # Stable provider event id, or a service-supplied "fp:<hash>" fingerprint.
    provider_event_id: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # Normalized, stable event type (e.g. "github.branch_protection.disabled").
    event_type: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    # Provider actor handle (e.g. GitHub login). Control-plane "who", not a target.
    actor_id: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    actor_type: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    resource_type: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # Provider resource identifier string (e.g. "acme/repo") — NOT a FK.
    resource_id: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # Salted hash of the source IP, if any was present. Never the raw IP.
    source_ip_hash: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    occurred_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )
    # SQLAlchemy reserves ``metadata`` on declarative classes, so the Python
    # attribute is ``event_metadata`` mapped to the DB column "metadata".
    event_metadata: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, nullable=False, server_default=text("'{}'::jsonb"), default=dict
    )
    # Pointer/id reference only (e.g. provider document id). Never raw payload.
    raw_ref: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
