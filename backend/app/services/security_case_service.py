"""Investigations (Cases) workflow service (M66.8).

A case is a HUMAN-MANAGED investigation container grouping GitHub incident
evidence (signals, correlations, configuration risks, activity events).

CLAIM DISCIPLINE (do not violate):
  Cases group evidence that "may require review". No function here may
  automatically set ``status="confirmed_by_user"`` — confirmation/dismissal are
  human actions performed via the API by an authenticated user. ConfigTrace does
  not automatically confirm breaches, attackers, compromise, or unauthorized
  access.

Privacy: case/link metadata is allowlisted + flat + truncated; raw payloads/IPs/
secrets/tokens are never stored.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.security_activity_event import SecurityActivityEvent
from app.models.security_case import (
    VALID_CASE_SEVERITIES,
    VALID_CASE_STATUSES,
    VALID_LINK_TYPES,
    SecurityCase,
    SecurityCaseLink,
)
from app.models.security_finding import SecurityFinding
from app.models.security_incident_signal import SecurityIncidentSignal
from app.models.security_signal_correlation import SecuritySignalCorrelation

ALLOWED_METADATA_KEYS: frozenset[str] = frozenset({"source", "origin_id", "repository"})
MAX_STR_LEN = 200
MAX_TITLE_LEN = 200
MAX_SUMMARY_LEN = 2000
MAX_METADATA_KEYS = 20

# Map a link object_type → its model (for workspace validation).
_LINK_MODELS = {
    "signal": SecurityIncidentSignal,
    "correlation": SecuritySignalCorrelation,
    "finding": SecurityFinding,
    "activity_event": SecurityActivityEvent,
}

_REVIEW_NOTE = (
    "Evidence grouped in this case may require review. ConfigTrace does not "
    "automatically confirm compromise or unauthorized access."
)


class CaseValidationError(ValueError):
    """Raised for invalid case input (router maps to HTTP 422/400)."""


class CrossWorkspaceLinkError(LookupError):
    """Raised when a linked object is missing or in another workspace (→ 404)."""


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def sanitize_case_metadata(raw: Optional[dict[str, Any]]) -> dict[str, Any]:
    """Return a safe, allowlisted, truncated copy of case/link metadata."""
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


def _norm_severity(severity: Optional[str]) -> str:
    return severity if severity in VALID_CASE_SEVERITIES else "medium"


def count_links(case_id: uuid.UUID, db: Session) -> int:
    return (
        db.query(SecurityCaseLink)
        .filter(SecurityCaseLink.case_id == case_id)
        .count()
    )


# ── Cases ─────────────────────────────────────────────────────────────────────

def create_case(
    *,
    workspace_id: uuid.UUID,
    user_id: Optional[uuid.UUID],
    title: str,
    summary: Optional[str] = None,
    severity: Optional[str] = None,
    provider: Optional[str] = None,
    metadata: Optional[dict[str, Any]] = None,
    db: Session,
) -> SecurityCase:
    """Create an investigation case. Status starts at ``open``."""
    if not isinstance(title, str) or not title.strip():
        raise CaseValidationError("Case title is required.")
    case = SecurityCase(
        workspace_id=workspace_id,
        title=title.strip()[:MAX_TITLE_LEN],
        summary=(summary[:MAX_SUMMARY_LEN] if isinstance(summary, str) else None),
        status="open",
        severity=_norm_severity(severity),
        confidence="medium",
        provider=(provider[:MAX_STR_LEN] if isinstance(provider, str) else None),
        opened_by_user_id=user_id,
        case_metadata=sanitize_case_metadata(metadata),
    )
    db.add(case)
    db.commit()
    db.refresh(case)
    return case


def list_cases(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    status: Optional[str] = None,
    provider: Optional[str] = None,
    severity: Optional[str] = None,
    page: int = 1,
    page_size: int = 50,
) -> tuple[list[SecurityCase], int]:
    """Paginated, workspace-scoped case list. Never crosses workspaces."""
    page = max(1, page)
    page_size = max(1, min(page_size, 100))
    q = db.query(SecurityCase).filter(SecurityCase.workspace_id == workspace_id)
    if status:
        q = q.filter(SecurityCase.status == status)
    if provider:
        q = q.filter(SecurityCase.provider == provider)
    if severity:
        q = q.filter(SecurityCase.severity == severity)
    total = q.count()
    items = (
        q.order_by(SecurityCase.updated_at.desc(), SecurityCase.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return items, total


def get_case(
    *, case_id: uuid.UUID, workspace_id: uuid.UUID, db: Session
) -> Optional[SecurityCase]:
    """Return a single workspace-scoped case, or None (→ 404)."""
    return (
        db.query(SecurityCase)
        .filter(SecurityCase.id == case_id, SecurityCase.workspace_id == workspace_id)
        .first()
    )


def update_case(
    *,
    case: SecurityCase,
    actor_user_id: Optional[uuid.UUID],
    db: Session,
    title: Optional[str] = None,
    summary: Optional[str] = None,
    severity: Optional[str] = None,
    confidence: Optional[str] = None,
    status: Optional[str] = None,
) -> SecurityCase:
    """Update editable fields and apply human-only status transitions.

    ``status="confirmed_by_user"`` records the acting user as the confirmer — the
    router restricts that transition to admin/owner. ``dismissed`` / ``resolved``
    stamp the actor/time. This service never sets ``confirmed_by_user`` without an
    explicit caller-provided status.
    """
    if title is not None:
        if not title.strip():
            raise CaseValidationError("Case title cannot be empty.")
        case.title = title.strip()[:MAX_TITLE_LEN]
    if summary is not None:
        case.summary = summary[:MAX_SUMMARY_LEN]
    if severity is not None:
        case.severity = _norm_severity(severity)
    if confidence is not None and confidence in {"high", "medium", "low"}:
        case.confidence = confidence

    if status is not None:
        if status not in VALID_CASE_STATUSES:
            raise CaseValidationError(f"Invalid case status: {status!r}")
        case.status = status
        now = _utcnow()
        if status == "confirmed_by_user":
            case.confirmed_by_user_id = actor_user_id
            case.confirmed_at = now
        elif status == "dismissed":
            case.dismissed_by_user_id = actor_user_id
            case.dismissed_at = now
        elif status == "resolved":
            case.resolved_at = now

    db.commit()
    db.refresh(case)
    return case


# ── Links ─────────────────────────────────────────────────────────────────────

def _validate_object_in_workspace(
    *, object_type: str, object_id: uuid.UUID, workspace_id: uuid.UUID, db: Session
) -> None:
    """Ensure the linked object exists AND belongs to this workspace.

    Raises CrossWorkspaceLinkError (→ 404) if missing or in another workspace, so
    a case can never link another workspace's evidence.
    """
    model = _LINK_MODELS.get(object_type)
    if model is None:
        raise CaseValidationError(f"Invalid linked_object_type: {object_type!r}")
    obj = (
        db.query(model)
        .filter(model.id == object_id, model.workspace_id == workspace_id)
        .first()
    )
    if obj is None:
        raise CrossWorkspaceLinkError(
            "Linked object not found in this workspace."
        )


def link_object_to_case(
    *,
    case: SecurityCase,
    object_type: str,
    object_id: uuid.UUID,
    actor_user_id: Optional[uuid.UUID],
    db: Session,
    metadata: Optional[dict[str, Any]] = None,
) -> tuple[str, SecurityCaseLink]:
    """Attach an evidence object to a case. Idempotent per (case, type, id).

    Returns ``("created", link)`` or ``("exists", link)``. Validates the object
    is in the case's workspace (cross-workspace → CrossWorkspaceLinkError).
    """
    if object_type not in VALID_LINK_TYPES:
        raise CaseValidationError(f"Invalid linked_object_type: {object_type!r}")
    _validate_object_in_workspace(
        object_type=object_type, object_id=object_id,
        workspace_id=case.workspace_id, db=db,
    )

    existing = (
        db.query(SecurityCaseLink)
        .filter(
            SecurityCaseLink.case_id == case.id,
            SecurityCaseLink.linked_object_type == object_type,
            SecurityCaseLink.linked_object_id == object_id,
        )
        .first()
    )
    if existing is not None:
        return "exists", existing

    link = SecurityCaseLink(
        workspace_id=case.workspace_id,
        case_id=case.id,
        linked_object_type=object_type,
        linked_object_id=object_id,
        created_by_user_id=actor_user_id,
        link_metadata=sanitize_case_metadata(metadata),
    )
    db.add(link)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        existing = (
            db.query(SecurityCaseLink)
            .filter(
                SecurityCaseLink.case_id == case.id,
                SecurityCaseLink.linked_object_type == object_type,
                SecurityCaseLink.linked_object_id == object_id,
            )
            .first()
        )
        if existing is not None:
            return "exists", existing
        raise
    db.refresh(link)
    # Touch the case so list ordering reflects recent investigation activity.
    case.updated_at = _utcnow()
    db.commit()
    return "created", link


def unlink_object_from_case(
    *, case: SecurityCase, link_id: uuid.UUID, db: Session
) -> bool:
    """Remove a link from a case. Returns True if a row was deleted."""
    link = (
        db.query(SecurityCaseLink)
        .filter(
            SecurityCaseLink.id == link_id,
            SecurityCaseLink.case_id == case.id,
            SecurityCaseLink.workspace_id == case.workspace_id,
        )
        .first()
    )
    if link is None:
        return False
    db.delete(link)
    db.commit()
    return True


def list_case_links(*, case_id: uuid.UUID, db: Session) -> list[SecurityCaseLink]:
    return (
        db.query(SecurityCaseLink)
        .filter(SecurityCaseLink.case_id == case_id)
        .order_by(SecurityCaseLink.created_at.asc())
        .all()
    )


# ── Convenience builders ──────────────────────────────────────────────────────

def _safe_link(case, object_type, object_id, actor_user_id, db) -> None:
    if object_id is None:
        return
    try:
        link_object_to_case(
            case=case, object_type=object_type, object_id=object_id,
            actor_user_id=actor_user_id, db=db,
        )
    except (CrossWorkspaceLinkError, CaseValidationError):
        # Best-effort linking — a missing related object never blocks case creation.
        pass


def create_case_from_signal(
    *, workspace_id: uuid.UUID, user_id: Optional[uuid.UUID],
    signal: SecurityIncidentSignal, db: Session,
) -> SecurityCase:
    """Create a case from an incident signal, linking the signal + its evidence."""
    repo = None
    md = signal.signal_metadata if isinstance(signal.signal_metadata, dict) else {}
    if isinstance(md.get("repository"), str):
        repo = md["repository"]
    case = create_case(
        workspace_id=workspace_id, user_id=user_id,
        title=f"Investigation: {signal.title}"[:MAX_TITLE_LEN],
        summary=f"Investigation case created from an incident signal. {_REVIEW_NOTE}",
        severity=signal.severity, provider=signal.provider,
        metadata={"source": "signal", "origin_id": str(signal.id), "repository": repo},
        db=db,
    )
    _safe_link(case, "signal", signal.id, user_id, db)
    _safe_link(case, "finding", signal.linked_finding_id, user_id, db)
    _safe_link(case, "activity_event", signal.linked_activity_event_id, user_id, db)
    return case


def create_case_from_correlation(
    *, workspace_id: uuid.UUID, user_id: Optional[uuid.UUID],
    correlation: SecuritySignalCorrelation, db: Session,
) -> SecurityCase:
    """Create a case from a correlation, linking correlation + risk + activity + signal."""
    md = correlation.correlation_metadata if isinstance(correlation.correlation_metadata, dict) else {}
    repo = md.get("repository") if isinstance(md.get("repository"), str) else None
    case = create_case(
        workspace_id=workspace_id, user_id=user_id,
        title=f"Investigation: {correlation.title}"[:MAX_TITLE_LEN],
        summary=f"Investigation case created from a correlation. {_REVIEW_NOTE}",
        severity=correlation.severity, provider=correlation.provider,
        metadata={"source": "correlation", "origin_id": str(correlation.id), "repository": repo},
        db=db,
    )
    _safe_link(case, "correlation", correlation.id, user_id, db)
    _safe_link(case, "finding", correlation.linked_finding_id, user_id, db)
    _safe_link(case, "activity_event", correlation.linked_activity_event_id, user_id, db)
    _safe_link(case, "signal", correlation.linked_signal_id, user_id, db)
    return case
