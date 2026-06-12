"""Case Evidence Report builder (M66.9).

Joins a case's linked evidence (signals, configuration risks, activity events,
correlations) into a metadata-only investigation packet for export.

CLAIM DISCIPLINE: the report presents evidence for review. It never asserts a
breach/attacker/compromise/unauthorized-access. A case status of
"confirmed_by_user" is a human action and is rendered as such — never as a
"confirmed breach".

PRIVACY: only allowlisted safe fields are emitted. No raw audit payloads, raw
IPs, secrets, tokens, evidence/remediation blobs, or customer data. Activity
source IPs (if any) appear only as salted hashes; provider_event_id/raw_ref are
pointer ids only; activity metadata is re-sanitized through the activity
allowlist.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.models.security_activity_event import SecurityActivityEvent
from app.models.security_case import SecurityCase, SecurityCaseLink
from app.models.security_finding import SecurityFinding
from app.models.security_incident_signal import SecurityIncidentSignal
from app.models.security_signal_correlation import SecuritySignalCorrelation
from app.services import security_activity_event_service as activity_svc

CLAIM_NOTE = (
    "ConfigTrace correlates configuration risk and control-plane audit activity "
    "as evidence for review. This report does not automatically confirm "
    "compromise, attacker presence, unauthorized access, or breach."
)

LIMITATIONS = (
    "This report is generated from metadata-only evidence. It contains no raw "
    "audit payloads, raw IP addresses, secrets, tokens, webhook signing secrets, "
    "database rows, or customer data. Activity source IPs, where present, are "
    "shown only as salted hashes; provider event ids and raw references are "
    "pointer identifiers only."
)


def _base_rule(finding_key: Optional[str]) -> str:
    if not finding_key:
        return ""
    return finding_key.split(":", 1)[0]


def _ids_by_type(links: list[SecurityCaseLink]) -> dict[str, list[uuid.UUID]]:
    out: dict[str, list[uuid.UUID]] = {}
    for ln in links:
        out.setdefault(ln.linked_object_type, []).append(ln.linked_object_id)
    return out


def build_case_report(*, case: SecurityCase, db: Session) -> dict[str, Any]:
    """Build a metadata-only Case Evidence Report dict for ``case``."""
    links = (
        db.query(SecurityCaseLink)
        .filter(SecurityCaseLink.case_id == case.id)
        .all()
    )
    by_type = _ids_by_type(links)
    ws = case.workspace_id

    # ── Linked signals ────────────────────────────────────────────────────────
    signals = []
    if by_type.get("signal"):
        rows = (
            db.query(SecurityIncidentSignal)
            .filter(
                SecurityIncidentSignal.workspace_id == ws,
                SecurityIncidentSignal.id.in_(by_type["signal"]),
            )
            .all()
        )
        for s in rows:
            signals.append({
                "id": str(s.id), "title": s.title, "signal_type": s.signal_type,
                "severity": s.severity, "confidence": s.confidence, "status": s.status,
                "evidence_level": s.evidence_level,
                "first_seen_at": s.first_seen_at, "last_seen_at": s.last_seen_at,
            })

    # ── Linked configuration risks (findings) — no evidence/remediation blobs ──
    risks = []
    if by_type.get("finding"):
        rows = (
            db.query(SecurityFinding)
            .filter(
                SecurityFinding.workspace_id == ws,
                SecurityFinding.id.in_(by_type["finding"]),
            )
            .all()
        )
        for f in rows:
            risks.append({
                "id": str(f.id), "title": f.title, "rule": _base_rule(f.finding_key),
                "severity": f.severity, "status": f.status, "confidence": f.confidence,
                "first_detected_at": f.first_detected_at, "last_seen_at": f.last_seen_at,
            })

    # ── Linked activity events — pointer ids + hashed IP + allowlisted metadata ─
    activity_events = []
    if by_type.get("activity_event"):
        rows = (
            db.query(SecurityActivityEvent)
            .filter(
                SecurityActivityEvent.workspace_id == ws,
                SecurityActivityEvent.id.in_(by_type["activity_event"]),
            )
            .all()
        )
        for e in rows:
            activity_events.append({
                "id": str(e.id), "event_type": e.event_type, "provider": e.provider,
                "source": e.source, "actor_id": e.actor_id, "actor_type": e.actor_type,
                "resource_type": e.resource_type, "resource_id": e.resource_id,
                "provider_event_id": e.provider_event_id, "raw_ref": e.raw_ref,
                "source_ip_hash": e.source_ip_hash,
                "occurred_at": e.occurred_at, "ingested_at": e.ingested_at,
                # Re-sanitize defensively even though writes are already allowlisted.
                "metadata": activity_svc.sanitize_activity_metadata(
                    e.event_metadata if isinstance(e.event_metadata, dict) else {}
                ),
            })

    # ── Linked correlations ────────────────────────────────────────────────────
    correlations = []
    if by_type.get("correlation"):
        rows = (
            db.query(SecuritySignalCorrelation)
            .filter(
                SecuritySignalCorrelation.workspace_id == ws,
                SecuritySignalCorrelation.id.in_(by_type["correlation"]),
            )
            .all()
        )
        for c in rows:
            correlations.append({
                "id": str(c.id), "title": c.title, "correlation_type": c.correlation_type,
                "severity": c.severity, "confidence": c.confidence, "status": c.status,
                "first_seen_at": c.first_seen_at, "last_seen_at": c.last_seen_at,
            })

    # ── Evidence timeline ──────────────────────────────────────────────────────
    timeline: list[dict[str, Any]] = [{"at": case.created_at, "label": "Case created"}]
    for r in risks:
        timeline.append({"at": r["first_detected_at"], "label": f"Configuration risk first seen: {r['title']}"})
    for e in activity_events:
        timeline.append({"at": e["occurred_at"] or e["ingested_at"], "label": f"Audit activity: {e['event_type']}"})
    for s in signals:
        timeline.append({"at": s["first_seen_at"], "label": f"Incident signal: {s['title']}"})
    for c in correlations:
        timeline.append({"at": c["first_seen_at"], "label": f"Correlation: {c['title']}"})
    if case.confirmed_at:
        timeline.append({"at": case.confirmed_at, "label": "Case confirmed by user"})
    if case.dismissed_at:
        timeline.append({"at": case.dismissed_at, "label": "Case dismissed"})
    if case.resolved_at:
        timeline.append({"at": case.resolved_at, "label": "Case resolved"})
    timeline.sort(key=lambda x: (x["at"] is None, x["at"] or datetime.min.replace(tzinfo=timezone.utc)))

    # ── Executive summary ──────────────────────────────────────────────────────
    status_label = case.status.replace("_", " ")
    # Prefer the case's declared provider; otherwise derive the dominant provider
    # from the linked evidence so an AWS-only case reads as "AWS" even when the
    # case provider was never set.
    provider_key = (case.provider or "").lower()
    if not provider_key:
        counts: dict[str, int] = {}
        for grp in (signals, risks, activity_events, correlations):
            for item in grp:
                p = (item.get("provider") or "").lower()
                if p:
                    counts[p] = counts.get(p, 0) + 1
        if counts:
            provider_key = max(counts, key=counts.get)
    provider_label = {"github": "GitHub", "aws": "AWS"}.get(provider_key, provider_key)
    evidence_label = f"{provider_label} incident evidence".strip()
    executive_summary = (
        f"Investigation case \"{case.title}\" (status: {status_label}) groups "
        f"{len(links)} pieces of {evidence_label} for review: "
        f"{len(signals)} incident signal(s), {len(risks)} configuration risk(s), "
        f"{len(activity_events)} activity event(s), and {len(correlations)} "
        f"correlation(s). This evidence is presented for human review and does not "
        f"by itself confirm compromise or unauthorized access."
    )

    review_checklist = [
        "Review each linked configuration risk and confirm whether the current state is expected.",
        "Review the linked control-plane activity events and the actors involved.",
        "Confirm whether any correlated activity was authorized and change-managed.",
        "Record a disposition: investigating, resolved, dismissed, or confirmed by user.",
        "If escalation is needed, share this metadata-only packet with your security reviewers.",
    ]

    return {
        "title": "ConfigTrace Case Evidence Report",
        "generated_at": datetime.now(timezone.utc),
        "executive_summary": executive_summary,
        "claim_note": CLAIM_NOTE,
        "case": {
            "id": str(case.id), "title": case.title, "summary": case.summary,
            "status": case.status, "severity": case.severity, "confidence": case.confidence,
            "provider": case.provider,
            "opened_by_user_id": str(case.opened_by_user_id) if case.opened_by_user_id else None,
            "confirmed_by_user_id": str(case.confirmed_by_user_id) if case.confirmed_by_user_id else None,
            "confirmed_at": case.confirmed_at,
            "dismissed_by_user_id": str(case.dismissed_by_user_id) if case.dismissed_by_user_id else None,
            "dismissed_at": case.dismissed_at, "resolved_at": case.resolved_at,
            "created_at": case.created_at, "updated_at": case.updated_at,
        },
        "signals": signals,
        "risks": risks,
        "activity_events": activity_events,
        "correlations": correlations,
        "timeline": timeline,
        "review_checklist": review_checklist,
        "limitations": LIMITATIONS,
    }
