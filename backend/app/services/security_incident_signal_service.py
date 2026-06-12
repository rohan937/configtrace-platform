"""Control-plane Incident Signal generation (M66.3).

Reads normalized GitHub audit activity (``security_activity_events``, M66.2) and
produces first-pass **Incident Signals** — control-plane actions that *may
require review*.

CLAIM DISCIPLINE (do not violate):
  Incident signals are REVIEW signals based on audit activity. They do NOT
  confirm a breach, identify an attacker, or confirm compromise/access. Severity
  reflects review priority. Confidence is "high" only because the audit event
  directly states the action occurred — NOT because impact is confirmed.
  ``evidence_level`` is always "activity". Exposure×activity correlation (which
  would raise the evidence tier) is a FUTURE milestone.

Forbidden wording in any generated title/summary: "breach detected",
"attacker found", "compromise confirmed", "someone has access",
"unauthorized access confirmed".

Privacy: signal metadata is allowlisted + flat + truncated; raw audit blobs,
raw IPs, secrets, tokens, and payloads are never stored.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.security_activity_event import SecurityActivityEvent
from app.models.security_incident_signal import SecurityIncidentSignal

PROVIDER_GITHUB = "github"

# Allowlist of non-sensitive metadata keys carried onto a signal.
ALLOWED_METADATA_KEYS: frozenset[str] = frozenset(
    {
        "action",
        "repository",
        "ref",
        "hook_id",
        "permission",
        "ruleset_name",
        "alert_number",
        "actor",
        "event_type",
    }
)

MAX_STR_LEN = 200
MAX_METADATA_KEYS = 20

# A short, neutral note appended to every summary to keep claims calibrated.
_REVIEW_NOTE = (
    "This is a control-plane security signal that may require review. "
    "ConfigTrace does not confirm a breach, attacker, or unauthorized access."
)


def _rule(signal_key: str, signal_type: str, severity: str, phrase: str) -> dict[str, str]:
    return {
        "signal_key": signal_key,
        "signal_type": signal_type,
        "severity": severity,
        "phrase": phrase,  # human phrase for the title, e.g. "Branch protection disabled"
    }


# Map a normalized activity ``event_type`` → a signal rule. Only these mapped
# control-plane categories produce a signal; everything else is ignored.
# Severities reflect *review priority*, never confirmed impact.
SIGNAL_RULES: dict[str, dict[str, str]] = {
    "github.branch_protection.disabled": _rule(
        "github_branch_protection_disabled", "branch_protection_change", "high",
        "Branch protection disabled",
    ),
    "github.branch_protection.updated": _rule(
        "github_branch_protection_updated", "branch_protection_change", "medium",
        "Branch protection updated",
    ),
    "github.deploy_key.added": _rule(
        "github_deploy_key_added", "deploy_key_added", "high",
        "Deploy key added",
    ),
    "github.webhook.created": _rule(
        "github_webhook_created", "webhook_change", "medium",
        "Webhook created",
    ),
    "github.webhook.updated": _rule(
        "github_webhook_updated", "webhook_change", "medium",
        "Webhook changed",
    ),
    "github.webhook.deleted": _rule(
        "github_webhook_deleted", "webhook_change", "medium",
        "Webhook deleted",
    ),
    "github.collaborator.added": _rule(
        "github_collaborator_added", "collaborator_change", "high",
        "Repository collaborator added",
    ),
    "github.app.installed": _rule(
        "github_app_installed", "app_install", "medium",
        "GitHub App installed",
    ),
    "github.app.permissions_changed": _rule(
        "github_app_permissions_changed", "app_permissions_change", "high",
        "GitHub App permissions changed",
    ),
    "github.ruleset.changed": _rule(
        "github_ruleset_changed", "ruleset_change", "medium",
        "Repository ruleset changed",
    ),
    "github.secret_scanning_alert.created": _rule(
        "github_secret_scanning_alert_created", "secret_scanning_alert", "high",
        "Secret scanning alert created",
    ),
}


def sanitize_signal_metadata(raw: Optional[dict[str, Any]]) -> dict[str, Any]:
    """Return a safe, allowlisted, truncated copy of signal metadata.

    Drops unknown keys (secrets/tokens/payloads can never be on the allowlist),
    drops nested/complex values, and truncates strings.
    """
    if not isinstance(raw, dict):
        return {}
    out: dict[str, Any] = {}
    for key, value in raw.items():
        if key not in ALLOWED_METADATA_KEYS:
            continue
        if isinstance(value, bool):
            out[key] = value
        elif isinstance(value, (int, float)):
            out[key] = value
        elif isinstance(value, str):
            out[key] = value[:MAX_STR_LEN]
        else:
            continue
        if len(out) >= MAX_METADATA_KEYS:
            break
    return out


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def build_signal_from_activity_event(
    ev: SecurityActivityEvent,
) -> Optional[dict[str, Any]]:
    """Map one activity event → a signal dict, or None if no rule matches.

    Returns a plain dict of signal fields (not persisted). Title/summary use only
    calibrated, review-oriented wording.
    """
    rule = SIGNAL_RULES.get(ev.event_type)
    if rule is None:
        return None

    src_meta = ev.event_metadata if isinstance(ev.event_metadata, dict) else {}
    repo = src_meta.get("repository") or ev.resource_id
    actor = ev.actor_id

    # Title: neutral human phrase + target.
    title = rule["phrase"]
    if isinstance(repo, str) and repo:
        title = f"{rule['phrase']} on {repo}"

    # Summary: factual description + calibrated review note.
    who = f" by {actor}" if isinstance(actor, str) and actor else ""
    where = f" on {repo}" if isinstance(repo, str) and repo else ""
    summary = (
        f"{rule['phrase']}{where}{who}, observed in GitHub audit activity. "
        f"{_REVIEW_NOTE}"
    )

    when = ev.occurred_at or ev.ingested_at

    metadata = sanitize_signal_metadata(
        {
            "action": src_meta.get("action"),
            "repository": repo if isinstance(repo, str) else None,
            "ref": src_meta.get("ref"),
            "hook_id": src_meta.get("hook_id"),
            "permission": src_meta.get("permission"),
            "ruleset_name": src_meta.get("ruleset_name"),
            "alert_number": src_meta.get("alert_number"),
            "actor": actor if isinstance(actor, str) else None,
            "event_type": ev.event_type,
        }
    )

    return {
        "provider": ev.provider,
        "integration_id": ev.integration_id,
        "signal_key": rule["signal_key"],
        "signal_type": rule["signal_type"],
        "severity": rule["severity"],
        "status": "open",
        "title": title,
        "summary": summary,
        "evidence_level": "activity",   # NEVER "confirmed_breach"
        "confidence": "high",            # audit event states the action happened
        "first_seen_at": when,
        "last_seen_at": when,
        "linked_activity_event_id": ev.id,
        "metadata": metadata,
    }


def upsert_incident_signal(
    *,
    workspace_id: uuid.UUID,
    signal: dict[str, Any],
    db: Session,
) -> tuple[str, SecurityIncidentSignal]:
    """Idempotently persist a signal.

    Returns ``("created", row)`` for a new signal or ``("skipped", row)`` if a
    signal already exists for the same
    ``(workspace_id, provider, signal_key, linked_activity_event_id)``.
    """
    existing = _find_existing(
        db,
        workspace_id=workspace_id,
        provider=signal["provider"],
        signal_key=signal["signal_key"],
        linked_activity_event_id=signal.get("linked_activity_event_id"),
    )
    if existing is not None:
        return "skipped", existing

    row = SecurityIncidentSignal(
        workspace_id=workspace_id,
        integration_id=signal.get("integration_id"),
        provider=signal["provider"],
        signal_key=signal["signal_key"],
        signal_type=signal["signal_type"],
        severity=signal["severity"],
        status=signal.get("status", "open"),
        title=signal["title"],
        summary=signal["summary"],
        evidence_level=signal.get("evidence_level", "activity"),
        confidence=signal.get("confidence", "high"),
        first_seen_at=signal.get("first_seen_at"),
        last_seen_at=signal.get("last_seen_at"),
        linked_activity_event_id=signal.get("linked_activity_event_id"),
        signal_metadata=signal.get("metadata") or {},
    )
    db.add(row)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        existing = _find_existing(
            db,
            workspace_id=workspace_id,
            provider=signal["provider"],
            signal_key=signal["signal_key"],
            linked_activity_event_id=signal.get("linked_activity_event_id"),
        )
        if existing is not None:
            return "skipped", existing
        raise
    db.refresh(row)
    return "created", row


def _find_existing(
    db: Session,
    *,
    workspace_id: uuid.UUID,
    provider: str,
    signal_key: str,
    linked_activity_event_id: Optional[uuid.UUID],
) -> Optional[SecurityIncidentSignal]:
    if linked_activity_event_id is None:
        return None
    return (
        db.query(SecurityIncidentSignal)
        .filter(
            SecurityIncidentSignal.workspace_id == workspace_id,
            SecurityIncidentSignal.provider == provider,
            SecurityIncidentSignal.signal_key == signal_key,
            SecurityIncidentSignal.linked_activity_event_id == linked_activity_event_id,
        )
        .first()
    )


def generate_github_incident_signals(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    scan_limit: int = 1000,
) -> dict[str, Any]:
    """Generate signals from recent GitHub activity events for a workspace.

    Idempotent: re-running over the same activity events creates no duplicates.
    Returns a generation summary.
    """
    events = (
        db.query(SecurityActivityEvent)
        .filter(
            SecurityActivityEvent.workspace_id == workspace_id,
            SecurityActivityEvent.provider == PROVIDER_GITHUB,
        )
        .order_by(
            SecurityActivityEvent.occurred_at.desc().nullslast(),
            SecurityActivityEvent.created_at.desc(),
        )
        .limit(scan_limit)
        .all()
    )

    created = 0
    skipped = 0
    for ev in events:
        signal = build_signal_from_activity_event(ev)
        if signal is None:
            continue  # not a signal-producing category
        outcome, _row = upsert_incident_signal(
            workspace_id=workspace_id, signal=signal, db=db
        )
        if outcome == "created":
            created += 1
        else:
            skipped += 1

    return {
        "provider": PROVIDER_GITHUB,
        "activity_events_scanned": len(events),
        "signals_created": created,
        "signals_skipped": skipped,
    }


def list_incident_signals(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    provider: Optional[str] = None,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    signal_type: Optional[str] = None,
    page: int = 1,
    page_size: int = 50,
) -> tuple[list[SecurityIncidentSignal], int]:
    """Paginated, workspace-scoped signal list. Never crosses workspaces."""
    page = max(1, page)
    page_size = max(1, min(page_size, 100))

    q = db.query(SecurityIncidentSignal).filter(
        SecurityIncidentSignal.workspace_id == workspace_id
    )
    if provider:
        q = q.filter(SecurityIncidentSignal.provider == provider)
    if status:
        q = q.filter(SecurityIncidentSignal.status == status)
    if severity:
        q = q.filter(SecurityIncidentSignal.severity == severity)
    if signal_type:
        q = q.filter(SecurityIncidentSignal.signal_type == signal_type)

    total = q.count()
    items = (
        q.order_by(
            SecurityIncidentSignal.first_seen_at.desc().nullslast(),
            SecurityIncidentSignal.created_at.desc(),
        )
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return items, total


def get_incident_signal(
    *,
    signal_id: uuid.UUID,
    workspace_id: uuid.UUID,
    db: Session,
) -> Optional[SecurityIncidentSignal]:
    """Return a single signal scoped to the workspace, or None (→ 404)."""
    return (
        db.query(SecurityIncidentSignal)
        .filter(
            SecurityIncidentSignal.id == signal_id,
            SecurityIncidentSignal.workspace_id == workspace_id,
        )
        .first()
    )
