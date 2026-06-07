"""Security finding service — M60.3 (data foundation).

Read helpers for the Security Exposure API plus minimal writers used by tests
and the future M60.4 evaluation engine. This module does NOT evaluate provider
state or contain any security rules — it is persistence + access scoping only.

Access model
------------
Findings are workspace-scoped. A user may read a finding only if they are a
member of its workspace (same membership rule as Changes/ChangeReview). The
list endpoint returns findings across all of the user's workspaces.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.models.security_finding import (
    SecurityFinding,
    VALID_FINDING_SEVERITIES,
    VALID_FINDING_STATUSES,
)
from app.models.workspace import WorkspaceMember


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _user_workspace_ids(user_id: uuid.UUID, db: Session) -> list[uuid.UUID]:
    """Return every workspace_id the user is a member of."""
    rows = (
        db.query(WorkspaceMember.workspace_id)
        .filter(WorkspaceMember.user_id == user_id)
        .all()
    )
    return [r[0] for r in rows]


# ── Reads ──────────────────────────────────────────────────────────────────


def list_findings(
    *,
    user_id: uuid.UUID,
    db: Session,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    provider: Optional[str] = None,
    integration_id: Optional[uuid.UUID] = None,
    resource_id: Optional[uuid.UUID] = None,
    page: int = 1,
    page_size: int = 50,
) -> tuple[list[SecurityFinding], int]:
    """Return a paginated, filtered list of findings the user may see.

    Scoped to the user's workspace memberships. Filters combine with AND.
    Ordered by severity-relevant recency: ``last_seen_at DESC``.
    """
    workspace_ids = _user_workspace_ids(user_id, db)
    if not workspace_ids:
        return [], 0

    query = db.query(SecurityFinding).filter(
        SecurityFinding.workspace_id.in_(workspace_ids)
    )

    if status is not None:
        query = query.filter(SecurityFinding.status == status)
    if severity is not None:
        query = query.filter(SecurityFinding.severity == severity)
    if provider is not None:
        query = query.filter(SecurityFinding.provider == provider)
    if integration_id is not None:
        query = query.filter(SecurityFinding.integration_id == integration_id)
    if resource_id is not None:
        query = query.filter(SecurityFinding.resource_id == resource_id)

    total = query.count()

    items = (
        query.order_by(SecurityFinding.last_seen_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return items, total


def get_finding_for_user(
    *,
    finding_id: uuid.UUID,
    user_id: uuid.UUID,
    db: Session,
) -> Optional[SecurityFinding]:
    """Return a finding only if the user is a member of its workspace.

    Returns None when the finding does not exist OR belongs to a workspace the
    user is not a member of (callers should surface 404, never 403, to avoid
    leaking existence — matching the Change endpoints).
    """
    finding = db.get(SecurityFinding, finding_id)
    if finding is None:
        return None
    member = (
        db.query(WorkspaceMember)
        .filter(
            WorkspaceMember.workspace_id == finding.workspace_id,
            WorkspaceMember.user_id == user_id,
        )
        .first()
    )
    if member is None:
        return None
    return finding


# ── Writers (foundation; used by tests and the future M60.4 engine) ──────────


def create_finding(
    *,
    db: Session,
    workspace_id: uuid.UUID,
    integration_id: uuid.UUID,
    provider: str,
    finding_key: str,
    severity: str,
    title: str,
    status: str = "active",
    resource_id: Optional[uuid.UUID] = None,
    linked_change_id: Optional[uuid.UUID] = None,
    description: Optional[str] = None,
    evidence: Optional[dict[str, Any]] = None,
    remediation: Optional[dict[str, Any]] = None,
) -> SecurityFinding:
    """Insert a new finding.

    Validates severity/status against the allowed sets. Raises on the DB-level
    partial unique constraint if an ACTIVE finding already exists for the same
    logical issue (callers wanting idempotency should use
    :func:`upsert_active_finding`).
    """
    if severity not in VALID_FINDING_SEVERITIES:
        raise ValueError(f"Invalid severity: {severity!r}")
    if status not in VALID_FINDING_STATUSES:
        raise ValueError(f"Invalid status: {status!r}")

    finding = SecurityFinding(
        workspace_id=workspace_id,
        integration_id=integration_id,
        resource_id=resource_id,
        linked_change_id=linked_change_id,
        provider=provider,
        finding_key=finding_key,
        severity=severity,
        status=status,
        title=title,
        description=description,
        evidence=evidence,
        remediation=remediation,
    )
    db.add(finding)
    db.commit()
    db.refresh(finding)
    return finding


def refresh_active_finding(
    *,
    db: Session,
    finding: SecurityFinding,
    severity: str,
    title: str,
    linked_change_id: Optional[uuid.UUID] = None,
    description: Optional[str] = None,
    evidence: Optional[dict[str, Any]] = None,
    remediation: Optional[dict[str, Any]] = None,
) -> SecurityFinding:
    """Refresh an existing ACTIVE finding from the latest evaluation.

    Lifecycle contract (M60.7):
    * ALWAYS bumps ``last_seen_at`` (the risky state is still present).
    * Updates ``severity`` and ``title`` to the latest classification, and
      updates ``description`` / ``evidence`` / ``remediation`` when the caller
      provides them (None means "leave as-is", so a transient gap never wipes
      good data).
    * ``linked_change_id`` is only SET when a new one is supplied; an existing
      link is never cleared by a later evaluation that lacks one.
    * NEVER changes ``first_detected_at`` (when the exposure first opened),
      ``status`` (stays ``active``), ``resolved_at``, or the review attribution
      fields (``reviewed_by_user_id`` / ``reviewed_at``). Those belong to the
      open/resolve and (future) review workflows, not to a routine refresh.
    """
    finding.last_seen_at = _utcnow()
    finding.severity = severity
    finding.title = title
    if description is not None:
        finding.description = description
    if evidence is not None:
        finding.evidence = evidence
    if remediation is not None:
        finding.remediation = remediation
    if linked_change_id is not None:
        finding.linked_change_id = linked_change_id
    db.add(finding)
    db.commit()
    db.refresh(finding)
    return finding


def record_active_finding(
    *,
    db: Session,
    workspace_id: uuid.UUID,
    integration_id: uuid.UUID,
    provider: str,
    finding_key: str,
    severity: str,
    title: str,
    resource_id: Optional[uuid.UUID] = None,
    linked_change_id: Optional[uuid.UUID] = None,
    description: Optional[str] = None,
    evidence: Optional[dict[str, Any]] = None,
    remediation: Optional[dict[str, Any]] = None,
) -> tuple[SecurityFinding, bool]:
    """Idempotently record an active finding, reporting whether it was created.

    Returns ``(finding, created)`` where ``created`` is True only when a NEW
    active row was inserted (a fresh exposure), and False when an existing active
    row was refreshed. The ``created`` flag is what the M60.10 event layer uses
    to emit an "opened"/"reopened" event exactly once, never on a refresh.

    Only ACTIVE rows are matched; ``accepted_risk`` / ``snoozed`` rows are never
    overwritten here (their dedicated workflows own them).
    """
    existing = (
        db.query(SecurityFinding)
        .filter(
            SecurityFinding.workspace_id == workspace_id,
            SecurityFinding.integration_id == integration_id,
            SecurityFinding.finding_key == finding_key,
            SecurityFinding.status == "active",
            (
                SecurityFinding.resource_id == resource_id
                if resource_id is not None
                else SecurityFinding.resource_id.is_(None)
            ),
        )
        .first()
    )
    if existing is not None:
        refreshed = refresh_active_finding(
            db=db,
            finding=existing,
            severity=severity,
            title=title,
            linked_change_id=linked_change_id,
            description=description,
            evidence=evidence,
            remediation=remediation,
        )
        return refreshed, False

    created = create_finding(
        db=db,
        workspace_id=workspace_id,
        integration_id=integration_id,
        provider=provider,
        finding_key=finding_key,
        severity=severity,
        title=title,
        status="active",
        resource_id=resource_id,
        linked_change_id=linked_change_id,
        description=description,
        evidence=evidence,
        remediation=remediation,
    )
    return created, True


def upsert_active_finding(
    *,
    db: Session,
    workspace_id: uuid.UUID,
    integration_id: uuid.UUID,
    provider: str,
    finding_key: str,
    severity: str,
    title: str,
    resource_id: Optional[uuid.UUID] = None,
    linked_change_id: Optional[uuid.UUID] = None,
    description: Optional[str] = None,
    evidence: Optional[dict[str, Any]] = None,
    remediation: Optional[dict[str, Any]] = None,
) -> SecurityFinding:
    """Idempotently record an active finding for a logical issue.

    Thin wrapper over :func:`record_active_finding` that returns just the
    finding (preserved for existing callers/tests). See that function for the
    create-vs-refresh contract.
    """
    finding, _created = record_active_finding(
        db=db,
        workspace_id=workspace_id,
        integration_id=integration_id,
        provider=provider,
        finding_key=finding_key,
        severity=severity,
        title=title,
        resource_id=resource_id,
        linked_change_id=linked_change_id,
        description=description,
        evidence=evidence,
        remediation=remediation,
    )
    return finding


def has_prior_resolved_finding(
    *,
    db: Session,
    workspace_id: uuid.UUID,
    integration_id: uuid.UUID,
    resource_id: Optional[uuid.UUID],
    finding_key: str,
) -> bool:
    """True if a RESOLVED finding already exists for this logical issue.

    Used by the event layer to distinguish a re-opened exposure (a fresh active
    finding after a prior resolution) from a first-time open.
    """
    query = db.query(SecurityFinding.id).filter(
        SecurityFinding.workspace_id == workspace_id,
        SecurityFinding.integration_id == integration_id,
        SecurityFinding.finding_key == finding_key,
        SecurityFinding.status == "resolved",
    )
    if resource_id is not None:
        query = query.filter(SecurityFinding.resource_id == resource_id)
    else:
        query = query.filter(SecurityFinding.resource_id.is_(None))
    return query.first() is not None


def list_active_findings_for_resource(
    *,
    db: Session,
    workspace_id: uuid.UUID,
    integration_id: uuid.UUID,
    resource_id: Optional[uuid.UUID],
) -> list[SecurityFinding]:
    """Return all currently-active findings for a single resource scope.

    Used by the evaluator to determine which previously-active findings should
    be resolved because their risky state is no longer present.
    """
    query = db.query(SecurityFinding).filter(
        SecurityFinding.workspace_id == workspace_id,
        SecurityFinding.integration_id == integration_id,
        SecurityFinding.status == "active",
    )
    if resource_id is not None:
        query = query.filter(SecurityFinding.resource_id == resource_id)
    else:
        query = query.filter(SecurityFinding.resource_id.is_(None))
    return query.all()


def resolve_finding(*, db: Session, finding: SecurityFinding) -> SecurityFinding:
    """Mark a finding resolved and stamp ``resolved_at`` (idempotent).

    Lifecycle contract (M60.7):
    * Idempotent — resolving an already-resolved finding is a no-op (the
      original ``resolved_at`` is preserved).
    * Preserves ``first_detected_at``, ``evidence``, and ``remediation`` so the
      resolved row remains a useful historical record.
    * Sets ``resolved_at`` only on the active→resolved transition.
    """
    if finding.status == "resolved":
        return finding
    finding.status = "resolved"
    finding.resolved_at = _utcnow()
    db.add(finding)
    db.commit()
    db.refresh(finding)
    return finding


def resolve_missing_findings_for_resource(
    *,
    db: Session,
    workspace_id: uuid.UUID,
    integration_id: uuid.UUID,
    resource_id: Optional[uuid.UUID],
    active_keys: set[str],
) -> list[SecurityFinding]:
    """Resolve active findings for a resource whose risky state is gone.

    Given the set of ``finding_key`` values still present in the latest
    evaluation (``active_keys``), resolve every currently-ACTIVE finding for
    this (workspace, integration, resource) scope whose key is NOT in that set.

    Only ACTIVE findings are considered — ``accepted_risk`` / ``snoozed`` rows
    are never resolved here. Returns the list of findings that were resolved
    (so the M60.10 event layer can emit a "resolved" event for each).
    """
    active = list_active_findings_for_resource(
        db=db,
        workspace_id=workspace_id,
        integration_id=integration_id,
        resource_id=resource_id,
    )
    resolved: list[SecurityFinding] = []
    for finding in active:
        if finding.finding_key not in active_keys:
            resolve_finding(db=db, finding=finding)
            resolved.append(finding)
    return resolved
