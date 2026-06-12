"""Configuration Risk × audit-activity correlation (M66.6).

The core differentiator. Joins GitHub Configuration Risk findings
(``security_findings``) to GitHub audit activity (``security_activity_events``)
on the SAME repository within a review window, producing correlation rows and a
corresponding ``security_incident_signals`` row with ``evidence_level``
="correlation".

CLAIM DISCIPLINE (do not violate):
  A correlation is EVIDENCE FOR REVIEW. It is the first step toward a "potential
  compromise signal" but does NOT confirm a breach, attacker, compromise, or
  unauthorized access. Severity = review priority; confidence = "medium" because
  this is circumstantial co-occurrence, not proof.

Matching is conservative and deterministic:
  * same workspace, same provider (github),
  * same repository (finding's resource → Resource.provider_resource_id ==
    activity event's resource_id, both "owner/repo"),
  * activity ``occurred_at`` within [finding.first_detected_at - WINDOW,
    finding.last_seen_at + WINDOW] (default WINDOW = 24h),
  * finding base rule ↔ activity event_type per CORRELATION_RULES.

No vague cross-resource correlations. Ruleset / app-permission correlations are
DEFERRED — no corresponding Configuration Risk findings exist yet (the github
ruleset/app rules are not implemented), so there is nothing to match against.

Privacy: metadata is allowlisted + flat + truncated; raw payloads/IPs/secrets/
tokens are never stored.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.resource import Resource
from app.models.security_activity_event import SecurityActivityEvent
from app.models.security_finding import SecurityFinding
from app.models.security_signal_correlation import SecuritySignalCorrelation
from app.services import security_incident_signal_service as signal_svc

PROVIDER_GITHUB = "github"

# Default review window around a finding's active period.
WINDOW = timedelta(hours=24)

# Allowlist of non-sensitive metadata keys carried onto a correlation.
ALLOWED_METADATA_KEYS: frozenset[str] = frozenset(
    {
        "repository",
        "finding_rule",
        "finding_severity",
        "event_type",
        "actor",
        "window_hours",
    }
)

MAX_STR_LEN = 200
MAX_METADATA_KEYS = 20

_REVIEW_NOTE = (
    "This is a correlation signal that may require review. ConfigTrace does not "
    "confirm compromise or unauthorized access."
)


def _rule(
    correlation_key: str,
    correlation_type: str,
    activity_types: set[str],
    severity: str,
    phrase: str,
) -> dict[str, Any]:
    return {
        "correlation_key": correlation_key,
        "correlation_type": correlation_type,
        "activity_types": activity_types,
        "severity": severity,
        "phrase": phrase,
    }


# Map a finding's BASE rule key → correlation rule. Only rules whose finding side
# actually exists today are included (webhook / branch protection / deploy key).
CORRELATION_RULES: dict[str, dict[str, Any]] = {
    "github_webhook_http": _rule(
        "github_webhook_risk_activity",
        "webhook_change",
        {"github.webhook.created", "github.webhook.updated", "github.webhook.deleted"},
        # Severity floored at medium; raised to high when the finding is high+.
        "medium",
        "Webhook configuration risk followed by webhook admin activity",
    ),
    "github_branch_protection_missing": _rule(
        "github_branch_protection_risk_activity",
        "branch_protection_change",
        {"github.branch_protection.disabled", "github.branch_protection.updated"},
        "high",
        "Branch protection risk aligned with branch-protection admin activity",
    ),
    "github_deploy_key_write_access": _rule(
        "github_deploy_key_risk_activity",
        "deploy_key_added",
        {"github.deploy_key.added"},
        "high",
        "Deploy key risk aligned with new deploy key activity",
    ),
}

_HIGH_SEVERITIES = {"critical", "high"}


def sanitize_correlation_metadata(raw: Optional[dict[str, Any]]) -> dict[str, Any]:
    """Return a safe, allowlisted, truncated copy of correlation metadata."""
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


def _base_rule(finding_key: str) -> str:
    return finding_key.split(":", 1)[0] if finding_key else ""


def _aware(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def build_correlation(
    *,
    finding: SecurityFinding,
    event: SecurityActivityEvent,
    repo: str,
    rule: dict[str, Any],
) -> dict[str, Any]:
    """Build a correlation dict (not persisted) from a matched finding + event."""
    # Webhook severity tracks the finding; others use the rule severity.
    severity = rule["severity"]
    if rule["correlation_key"] == "github_webhook_risk_activity":
        severity = "high" if finding.severity in _HIGH_SEVERITIES else "medium"

    f_start = _aware(finding.first_detected_at)
    f_end = _aware(finding.last_seen_at)
    occurred = _aware(event.occurred_at)

    window_start = (f_start - WINDOW) if f_start else None
    window_end = (f_end + WINDOW) if f_end else None

    seens = [d for d in (f_start, occurred) if d]
    first_seen = min(seens) if seens else None
    lasts = [d for d in (f_end, occurred) if d]
    last_seen = max(lasts) if lasts else None

    title = f"{rule['phrase']} on {repo}"
    summary = (
        f"Configuration risk \"{finding.title}\" and GitHub audit activity "
        f"\"{event.event_type}\" were observed for {repo} within the review "
        f"window. {_REVIEW_NOTE}"
    )

    metadata = sanitize_correlation_metadata(
        {
            "repository": repo,
            "finding_rule": _base_rule(finding.finding_key),
            "finding_severity": finding.severity,
            "event_type": event.event_type,
            "actor": event.actor_id if isinstance(event.actor_id, str) else None,
            "window_hours": int(WINDOW.total_seconds() // 3600),
        }
    )

    return {
        "provider": PROVIDER_GITHUB,
        "correlation_key": rule["correlation_key"],
        "correlation_type": rule["correlation_type"],
        "severity": severity,
        "confidence": "medium",
        "status": "open",
        "title": title,
        "summary": summary,
        "linked_finding_id": finding.id,
        "linked_activity_event_id": event.id,
        "linked_change_id": finding.linked_change_id,
        "window_start": window_start,
        "window_end": window_end,
        "first_seen_at": first_seen,
        "last_seen_at": last_seen,
        "metadata": metadata,
        # carried for signal creation (not a column):
        "_integration_id": finding.integration_id,
    }


def _find_existing(
    db: Session,
    *,
    workspace_id: uuid.UUID,
    correlation_key: str,
    linked_finding_id: Optional[uuid.UUID],
    linked_activity_event_id: Optional[uuid.UUID],
) -> Optional[SecuritySignalCorrelation]:
    if linked_finding_id is None or linked_activity_event_id is None:
        return None
    return (
        db.query(SecuritySignalCorrelation)
        .filter(
            SecuritySignalCorrelation.workspace_id == workspace_id,
            SecuritySignalCorrelation.correlation_key == correlation_key,
            SecuritySignalCorrelation.linked_finding_id == linked_finding_id,
            SecuritySignalCorrelation.linked_activity_event_id == linked_activity_event_id,
        )
        .first()
    )


def upsert_correlation(
    *,
    workspace_id: uuid.UUID,
    correlation: dict[str, Any],
    db: Session,
) -> tuple[str, SecuritySignalCorrelation]:
    """Idempotently persist a correlation (+ a linked correlation signal).

    Returns ``("created", row)`` or ``("skipped", row)``.
    """
    existing = _find_existing(
        db,
        workspace_id=workspace_id,
        correlation_key=correlation["correlation_key"],
        linked_finding_id=correlation.get("linked_finding_id"),
        linked_activity_event_id=correlation.get("linked_activity_event_id"),
    )
    if existing is not None:
        return "skipped", existing

    # Create/find the correlation incident signal (evidence_level="correlation").
    linked_signal_id = _upsert_correlation_signal(
        workspace_id=workspace_id, correlation=correlation, db=db
    )

    row = SecuritySignalCorrelation(
        workspace_id=workspace_id,
        provider=correlation["provider"],
        correlation_key=correlation["correlation_key"],
        correlation_type=correlation["correlation_type"],
        severity=correlation["severity"],
        confidence=correlation.get("confidence", "medium"),
        status=correlation.get("status", "open"),
        title=correlation["title"],
        summary=correlation["summary"],
        linked_signal_id=linked_signal_id,
        linked_finding_id=correlation.get("linked_finding_id"),
        linked_activity_event_id=correlation.get("linked_activity_event_id"),
        linked_change_id=correlation.get("linked_change_id"),
        window_start=correlation.get("window_start"),
        window_end=correlation.get("window_end"),
        first_seen_at=correlation.get("first_seen_at"),
        last_seen_at=correlation.get("last_seen_at"),
        correlation_metadata=correlation.get("metadata") or {},
    )
    db.add(row)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        existing = _find_existing(
            db,
            workspace_id=workspace_id,
            correlation_key=correlation["correlation_key"],
            linked_finding_id=correlation.get("linked_finding_id"),
            linked_activity_event_id=correlation.get("linked_activity_event_id"),
        )
        if existing is not None:
            return "skipped", existing
        raise
    db.refresh(row)
    return "created", row


def _upsert_correlation_signal(
    *,
    workspace_id: uuid.UUID,
    correlation: dict[str, Any],
    db: Session,
) -> Optional[uuid.UUID]:
    """Create/find a correlation-evidence incident signal; return its id.

    Reuses the M66.3 signal upsert (idempotent on activity event + signal_key),
    then back-fills ``linked_finding_id`` on the signal so the signal carries both
    sides of the correlation.
    """
    signal = {
        "provider": PROVIDER_GITHUB,
        "integration_id": correlation.get("_integration_id"),
        "signal_key": correlation["correlation_key"],
        "signal_type": correlation["correlation_type"],
        "severity": correlation["severity"],
        "status": "open",
        "title": correlation["title"],
        "summary": correlation["summary"],
        "evidence_level": "correlation",
        "confidence": correlation.get("confidence", "medium"),
        "first_seen_at": correlation.get("first_seen_at"),
        "last_seen_at": correlation.get("last_seen_at"),
        "linked_activity_event_id": correlation.get("linked_activity_event_id"),
        "metadata": correlation.get("metadata") or {},
    }
    try:
        _outcome, sig = signal_svc.upsert_incident_signal(
            workspace_id=workspace_id, signal=signal, db=db
        )
    except Exception:  # noqa: BLE001 — signal linkage is best-effort, never fatal
        db.rollback()
        return None
    # Back-fill the finding link on the signal (M66.3 upsert leaves it null).
    finding_id = correlation.get("linked_finding_id")
    if finding_id is not None and sig.linked_finding_id is None:
        sig.linked_finding_id = finding_id
        db.commit()
    return sig.id


def generate_github_correlations(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    scan_limit: int = 1000,
) -> dict[str, Any]:
    """Correlate active GitHub findings with GitHub activity for a workspace.

    Idempotent. Returns a generation summary.
    """
    findings = (
        db.query(SecurityFinding)
        .filter(
            SecurityFinding.workspace_id == workspace_id,
            SecurityFinding.provider == PROVIDER_GITHUB,
            SecurityFinding.status == "active",
        )
        .limit(scan_limit)
        .all()
    )
    # Keep only findings whose base rule is correlatable.
    findings = [f for f in findings if _base_rule(f.finding_key) in CORRELATION_RULES]

    # Resolve each finding's repository slug via its Resource.
    resource_ids = {f.resource_id for f in findings if f.resource_id is not None}
    repo_by_resource: dict[uuid.UUID, str] = {}
    if resource_ids:
        for r in (
            db.query(Resource).filter(Resource.id.in_(resource_ids)).all()
        ):
            repo_by_resource[r.id] = r.provider_resource_id

    events = (
        db.query(SecurityActivityEvent)
        .filter(
            SecurityActivityEvent.workspace_id == workspace_id,
            SecurityActivityEvent.provider == PROVIDER_GITHUB,
            SecurityActivityEvent.occurred_at.isnot(None),
        )
        .limit(scan_limit)
        .all()
    )
    # Index events by repo for cheap lookup.
    events_by_repo: dict[str, list[SecurityActivityEvent]] = {}
    for ev in events:
        if isinstance(ev.resource_id, str) and ev.resource_id:
            events_by_repo.setdefault(ev.resource_id, []).append(ev)

    created = 0
    skipped = 0
    for finding in findings:
        if finding.resource_id is None:
            continue  # integration-level finding — no repo to match
        repo = repo_by_resource.get(finding.resource_id)
        if not repo:
            continue
        rule = CORRELATION_RULES[_base_rule(finding.finding_key)]
        f_start = _aware(finding.first_detected_at)
        f_end = _aware(finding.last_seen_at)
        if f_start is None or f_end is None:
            continue
        window_start = f_start - WINDOW
        window_end = f_end + WINDOW

        for ev in events_by_repo.get(repo, []):
            if ev.event_type not in rule["activity_types"]:
                continue
            occurred = _aware(ev.occurred_at)
            if occurred is None or not (window_start <= occurred <= window_end):
                continue
            correlation = build_correlation(
                finding=finding, event=ev, repo=repo, rule=rule
            )
            outcome, _row = upsert_correlation(
                workspace_id=workspace_id, correlation=correlation, db=db
            )
            if outcome == "created":
                created += 1
            else:
                skipped += 1

    return {
        "provider": PROVIDER_GITHUB,
        "findings_scanned": len(findings),
        "events_scanned": len(events),
        "correlations_created": created,
        "correlations_skipped": skipped,
    }


def list_correlations(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    provider: Optional[str] = None,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    correlation_type: Optional[str] = None,
    page: int = 1,
    page_size: int = 50,
) -> tuple[list[SecuritySignalCorrelation], int]:
    """Paginated, workspace-scoped correlation list. Never crosses workspaces."""
    page = max(1, page)
    page_size = max(1, min(page_size, 100))

    q = db.query(SecuritySignalCorrelation).filter(
        SecuritySignalCorrelation.workspace_id == workspace_id
    )
    if provider:
        q = q.filter(SecuritySignalCorrelation.provider == provider)
    if status:
        q = q.filter(SecuritySignalCorrelation.status == status)
    if severity:
        q = q.filter(SecuritySignalCorrelation.severity == severity)
    if correlation_type:
        q = q.filter(SecuritySignalCorrelation.correlation_type == correlation_type)

    total = q.count()
    items = (
        q.order_by(
            SecuritySignalCorrelation.first_seen_at.desc().nullslast(),
            SecuritySignalCorrelation.created_at.desc(),
        )
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return items, total


def get_correlation(
    *,
    correlation_id: uuid.UUID,
    workspace_id: uuid.UUID,
    db: Session,
) -> Optional[SecuritySignalCorrelation]:
    """Return a single workspace-scoped correlation, or None (→ 404)."""
    return (
        db.query(SecuritySignalCorrelation)
        .filter(
            SecuritySignalCorrelation.id == correlation_id,
            SecuritySignalCorrelation.workspace_id == workspace_id,
        )
        .first()
    )
