"""Security rule settings service — M61.7.

Workspace-scoped enable/disable for security rules. Sparse storage:
  * no row            → rule enabled (default)
  * row enabled=False → rule disabled (suppress future findings)
  * row enabled=True  → explicit re-enable (kept for who/when audit)

Re-enabling UPSERTS an ``enabled=True`` row (rather than deleting the override)
so the last actor/timestamp is retained. Disabling a rule never mutates, deletes,
or resolves existing findings — it only affects future evaluation.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.models.security_rule_setting import SecurityRuleSetting
from app.services.security_rule_registry import KNOWN_RULE_KEYS, is_known_rule_key

logger = logging.getLogger(__name__)


def get_disabled_rule_keys(workspace_id: uuid.UUID, db: Session) -> set[str]:
    """Return the set of rule keys explicitly disabled for *workspace_id*."""
    rows = (
        db.query(SecurityRuleSetting.rule_key)
        .filter(
            SecurityRuleSetting.workspace_id == workspace_id,
            SecurityRuleSetting.enabled.is_(False),
        )
        .all()
    )
    return {r[0] for r in rows}


def _rows_by_key(workspace_id: uuid.UUID, db: Session) -> dict[str, SecurityRuleSetting]:
    rows = (
        db.query(SecurityRuleSetting)
        .filter(SecurityRuleSetting.workspace_id == workspace_id)
        .all()
    )
    return {r.rule_key: r for r in rows}


def list_effective_settings(
    workspace_id: uuid.UUID, db: Session
) -> list[dict[str, Any]]:
    """Return every known rule key with its effective state for the workspace.

    A rule with no override row reports ``enabled=True`` and
    ``explicit_setting=False``.
    """
    by_key = _rows_by_key(workspace_id, db)
    items: list[dict[str, Any]] = []
    for rule_key in sorted(KNOWN_RULE_KEYS):
        row = by_key.get(rule_key)
        items.append(
            {
                "rule_key": rule_key,
                "enabled": row.enabled if row is not None else True,
                "explicit_setting": row is not None,
                "updated_at": row.updated_at if row is not None else None,
                "updated_by_user_id": row.updated_by_user_id if row is not None else None,
            }
        )
    return items


def get_effective_setting(
    workspace_id: uuid.UUID, rule_key: str, db: Session
) -> dict[str, Any]:
    """Return the effective state for a single known rule key."""
    row = (
        db.query(SecurityRuleSetting)
        .filter(
            SecurityRuleSetting.workspace_id == workspace_id,
            SecurityRuleSetting.rule_key == rule_key,
        )
        .first()
    )
    return {
        "rule_key": rule_key,
        "enabled": row.enabled if row is not None else True,
        "explicit_setting": row is not None,
        "updated_at": row.updated_at if row is not None else None,
        "updated_by_user_id": row.updated_by_user_id if row is not None else None,
    }


def set_rule_enabled(
    *,
    workspace_id: uuid.UUID,
    rule_key: str,
    enabled: bool,
    actor_user_id: Optional[uuid.UUID],
    db: Session,
) -> dict[str, Any]:
    """Upsert the enable/disable override for a rule (M61.7).

    Raises :exc:`ValueError` for an unknown rule key (router maps to 404).
    Never touches existing findings. Returns the effective setting dict.
    """
    if not is_known_rule_key(rule_key):
        raise ValueError(f"Unknown security rule key: {rule_key!r}")

    row = (
        db.query(SecurityRuleSetting)
        .filter(
            SecurityRuleSetting.workspace_id == workspace_id,
            SecurityRuleSetting.rule_key == rule_key,
        )
        .first()
    )
    if row is None:
        row = SecurityRuleSetting(
            workspace_id=workspace_id,
            rule_key=rule_key,
            enabled=enabled,
            updated_by_user_id=actor_user_id,
        )
        db.add(row)
    else:
        row.enabled = enabled
        row.updated_by_user_id = actor_user_id
        db.add(row)
    db.commit()
    db.refresh(row)
    logger.info(
        "security_rule_settings: workspace=%s rule=%s enabled=%s actor=%s",
        workspace_id,
        rule_key,
        enabled,
        actor_user_id,
    )
    return {
        "rule_key": row.rule_key,
        "enabled": row.enabled,
        "explicit_setting": True,
        "updated_at": row.updated_at,
        "updated_by_user_id": row.updated_by_user_id,
    }
