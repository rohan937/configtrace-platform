"""Snooze rule service — M57.3.

Manages ``ChangeSnoozeRule`` rows and provides the alert-suppression check
used by ``alert_service`` and ``notification_service``.

Public surface
--------------
:func:`create_snooze_rule`        — create a new workspace-scoped rule
:func:`list_active_rules`         — active rules for an integration
:func:`deactivate_rule`           — manually deactivate a rule
:func:`is_change_snoozed_by_rule` — alert-suppression predicate (fail-open)

Security invariants
-------------------
* ``integration_id`` is always required — no broad workspace-wide wildcards.
* The ``reason`` field is stored as-is; callers must ensure no secrets are
  included.  This module does not inspect or redact the value.
* Matching is exact (no regex/glob) — deterministic and auditable.
* :func:`is_change_snoozed_by_rule` **never raises** — any DB error causes
  it to return ``False`` (fail-open) so alerts are never silently dropped.

Snooze rule matching
--------------------
A rule matches a Change when ALL of the following hold:
  1. ``rule.integration_id == change.integration_id``
  2. ``rule.record_identifier_pattern is None OR
         rule.record_identifier_pattern == change.record_identifier``
  3. ``rule.field_path is None OR rule.field_path == change.field_path``
  4. ``rule.risk_level is None OR rule.risk_level == change.risk_level``
  5. ``rule.snoozed_until > now``
  6. ``rule.is_active is True``
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy.orm import Session

from app.models.change_snooze_rule import ChangeSnoozeRule

logger = logging.getLogger(__name__)

# Maximum snooze rule duration (mirrors M57.2 per-change snooze limit).
_MAX_SNOOZE_DAYS = 90


# ── CRUD ──────────────────────────────────────────────────────────────────────


def create_snooze_rule(
    workspace_id: uuid.UUID,
    integration_id: uuid.UUID,
    created_by_user_id: uuid.UUID,
    snoozed_until: datetime,
    db: Session,
    *,
    record_identifier_pattern: Optional[str] = None,
    field_path: Optional[str] = None,
    risk_level: Optional[str] = None,
    reason: Optional[str] = None,
) -> ChangeSnoozeRule:
    """Create and persist a new snooze rule.

    Args:
        workspace_id:              Workspace that owns this rule.
        integration_id:            The specific integration this rule targets
                                   (required — no broad wildcards).
        created_by_user_id:        Workspace member creating the rule.
        snoozed_until:             UTC expiry.  Must be future; max 90 days.
        db:                        Active SQLAlchemy session.
        record_identifier_pattern: Exact record identifier to match (optional).
        field_path:                Exact field path to match (optional).
        risk_level:                Exact risk level to match (optional).
        reason:                    Human-readable note.  Must NOT contain secrets.

    Raises:
        ValueError: If ``snoozed_until`` is not in the future or exceeds 90 days.

    Returns:
        The persisted :class:`ChangeSnoozeRule` row.
    """
    now = datetime.now(timezone.utc)

    # Normalise naive datetimes to UTC
    if snoozed_until.tzinfo is None:
        snoozed_until = snoozed_until.replace(tzinfo=timezone.utc)

    if snoozed_until <= now:
        raise ValueError("Snooze rule 'snoozed_until' must be in the future.")
    if snoozed_until > now + timedelta(days=_MAX_SNOOZE_DAYS):
        raise ValueError(
            f"Snooze rule duration cannot exceed {_MAX_SNOOZE_DAYS} days."
        )

    rule = ChangeSnoozeRule(
        workspace_id=workspace_id,
        integration_id=integration_id,
        created_by_user_id=created_by_user_id,
        snoozed_until=snoozed_until,
        record_identifier_pattern=record_identifier_pattern or None,
        field_path=field_path or None,
        risk_level=risk_level or None,
        reason=reason or None,
    )
    db.add(rule)
    db.flush()
    db.refresh(rule)
    return rule


def list_active_rules(
    integration_id: uuid.UUID,
    db: Session,
) -> list[ChangeSnoozeRule]:
    """Return currently active (non-expired, is_active=True) rules for an integration.

    Used by the UI to display existing rules and by alert suppression checks.
    """
    now = datetime.now(timezone.utc)
    return (
        db.query(ChangeSnoozeRule)
        .filter(
            ChangeSnoozeRule.integration_id == integration_id,
            ChangeSnoozeRule.is_active.is_(True),
            ChangeSnoozeRule.snoozed_until > now,
        )
        .order_by(ChangeSnoozeRule.snoozed_until.asc())
        .all()
    )


def deactivate_rule(rule_id: uuid.UUID, db: Session) -> Optional[ChangeSnoozeRule]:
    """Manually deactivate a snooze rule (sets is_active=False).

    Returns the updated rule, or None if not found.
    """
    rule = db.get(ChangeSnoozeRule, rule_id)
    if rule is None:
        return None
    rule.is_active = False
    db.flush()
    return rule


# ── Alert suppression predicate ───────────────────────────────────────────────


def is_change_snoozed_by_rule(change, workspace_id: Optional[uuid.UUID], db: Session) -> bool:
    """Return True if *change* is suppressed by an active snooze rule.

    **Fail-open**: any exception during the DB lookup returns False so the
    change is NOT suppressed.  An alert-delivery failure is always preferable
    to silently missing a true-positive alert.

    Args:
        change:       The ``Change`` ORM row.  Must have ``integration_id``,
                      ``record_identifier``, ``field_path``, ``risk_level``.
        workspace_id: The workspace that owns the integration.  If None (not
                      yet workspace-linked), returns False immediately.
        db:           Active SQLAlchemy session.

    Returns:
        True if at least one active, unexpired rule matches *change*.
        False on no match OR on any exception (fail-open).
    """
    if workspace_id is None:
        return False

    try:
        now = datetime.now(timezone.utc)
        rules = (
            db.query(ChangeSnoozeRule)
            .filter(
                ChangeSnoozeRule.integration_id == change.integration_id,
                ChangeSnoozeRule.is_active.is_(True),
                ChangeSnoozeRule.snoozed_until > now,
            )
            .all()
        )

        for rule in rules:
            if _rule_matches(rule, change):
                logger.info(
                    "snooze_rule: suppressing alert  change_id=%s  rule_id=%s",
                    change.id,
                    rule.id,
                )
                return True

        return False

    except Exception:
        logger.exception(
            "snooze_rule: lookup error for change_id=%s — failing open (not suppressing)",
            getattr(change, "id", "unknown"),
        )
        return False


def _rule_matches(rule: ChangeSnoozeRule, change) -> bool:
    """Return True if *rule* matches *change* on all non-None dimensions."""
    if (
        rule.record_identifier_pattern is not None
        and rule.record_identifier_pattern != change.record_identifier
    ):
        return False
    if rule.field_path is not None and rule.field_path != change.field_path:
        return False
    if rule.risk_level is not None and rule.risk_level != change.risk_level:
        return False
    return True
