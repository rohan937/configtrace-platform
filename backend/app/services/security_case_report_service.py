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
from app.services import security_incident_signal_service as signal_svc
from app.services import security_signal_correlation_service as correlation_svc

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


# ── M69.7A — Cross-provider case evidence timeline ──────────────────────────
#
# A normalized chronological view across a case's linked findings, activity
# events, incident signals, and correlations. Read-only and metadata-only: each
# item carries only allowlisted SCALAR preview fields (no raw secrets, tokens,
# headers, webhook secrets, private keys, bypass-actor identities, raw API
# responses, code, file/manifest paths, advisory bodies, patches, or request/
# response bodies). It correlates evidence for review — it does NOT confirm
# compromise, attacker presence, unauthorized access, or breach.

_TIMELINE_PROVIDER_LABELS = {"github": "GitHub", "aws": "AWS", "cloudflare": "Cloudflare"}

# Item-type tie-breaker order (stable, deterministic) when timestamps are equal.
_TYPE_RANK = {"finding": 0, "activity_event": 1, "incident_signal": 2, "correlation": 3}

_MIN_DT = datetime.min.replace(tzinfo=timezone.utc)

# Strict scalar-only allowlist for the per-item metadata preview. ONLY these keys
# are ever surfaced, and only when their value is a flat scalar (bool/int/float/
# str). Everything else — including any key not listed here — is dropped.
_PREVIEW_ALLOWLIST: frozenset[str] = frozenset({
    # repository / target identity
    "repository", "repository_full_name", "branch", "target",
    # rule / classification
    "rule", "finding_rule", "rule_id", "rule_name", "tool_name",
    # severity-ish
    "severity", "advisory_severity", "security_severity_level",
    # alert evidence (pointers / classifications only)
    "alert_number", "state", "secret_type", "validity", "publicly_leaked",
    "credential_type", "scope",
    # dependency / advisory pointers
    "dependency_package_name", "dependency_ecosystem",
    "advisory_ghsa_id", "advisory_cve_id",
    # ruleset / automation / action classifications
    "ruleset_name", "enforcement", "action",
    # generic cross-provider safe classifiers
    "service", "region", "resource_type", "event_name", "finding_type",
    "zone", "zone_name", "policy_name", "setting_name",
})


def _scalar_preview(sanitized: dict[str, Any]) -> dict[str, Any]:
    """Keep only allowlisted keys whose values are flat scalars."""
    out: dict[str, Any] = {}
    for k, v in (sanitized or {}).items():
        if k in _PREVIEW_ALLOWLIST and isinstance(v, (bool, int, float, str)):
            out[k] = v
    return out


def _provider_label(provider: Optional[str]) -> str:
    key = (provider or "").lower()
    return _TIMELINE_PROVIDER_LABELS.get(key, key)


def build_case_evidence_timeline(
    *, case_id: uuid.UUID, workspace_id: uuid.UUID, db: Session
) -> dict[str, Any]:
    """Build a normalized, chronological evidence timeline for a case.

    Returns a dict with ``case_id``, dominant ``provider`` label, ``timeline_items``
    (sorted ascending by timestamp with a stable item-type/id tie-breaker),
    ``counts_by_type``, ``counts_by_provider``, and ``total``. No new tables; reuses
    the case's existing linked evidence. Metadata previews are scalar-allowlisted.
    """
    links = (
        db.query(SecurityCaseLink)
        .filter(SecurityCaseLink.case_id == case_id)
        .all()
    )
    by_type = _ids_by_type(links)
    items: list[dict[str, Any]] = []

    # ── Findings (configuration risks) ─────────────────────────────────────────
    if by_type.get("finding"):
        for f in (
            db.query(SecurityFinding)
            .filter(
                SecurityFinding.workspace_id == workspace_id,
                SecurityFinding.id.in_(by_type["finding"]),
            )
            .all()
        ):
            preview = _scalar_preview(f.evidence if isinstance(f.evidence, dict) else {})
            items.append({
                "id": str(f.id),
                "item_type": "finding",
                "provider": f.provider,
                "timestamp": f.first_detected_at or f.created_at,
                "title": f.title,
                "summary": f"Configuration risk: {f.title}",
                "severity": f.severity,
                "source": "configuration_risk",
                "rule_key": _base_rule(f.finding_key),
                "event_type": None,
                "signal_type": None,
                "correlation_type": None,
                "linked_object_id": str(f.id),
                "metadata_preview": preview,
            })

    # ── Activity events ─────────────────────────────────────────────────────────
    if by_type.get("activity_event"):
        for e in (
            db.query(SecurityActivityEvent)
            .filter(
                SecurityActivityEvent.workspace_id == workspace_id,
                SecurityActivityEvent.id.in_(by_type["activity_event"]),
            )
            .all()
        ):
            sanitized = activity_svc.sanitize_activity_metadata(
                e.event_metadata if isinstance(e.event_metadata, dict) else {}
            )
            items.append({
                "id": str(e.id),
                "item_type": "activity_event",
                "provider": e.provider,
                "timestamp": e.occurred_at or e.ingested_at or e.created_at,
                "title": e.event_type,
                "summary": f"Control-plane activity: {e.event_type}",
                "severity": None,
                "source": e.source,
                "rule_key": None,
                "event_type": e.event_type,
                "signal_type": None,
                "correlation_type": None,
                "linked_object_id": str(e.id),
                "metadata_preview": _scalar_preview(sanitized),
            })

    # ── Incident signals ────────────────────────────────────────────────────────
    if by_type.get("signal"):
        for s in (
            db.query(SecurityIncidentSignal)
            .filter(
                SecurityIncidentSignal.workspace_id == workspace_id,
                SecurityIncidentSignal.id.in_(by_type["signal"]),
            )
            .all()
        ):
            sanitized = signal_svc.sanitize_signal_metadata(
                s.signal_metadata if isinstance(s.signal_metadata, dict) else {}
            )
            items.append({
                "id": str(s.id),
                "item_type": "incident_signal",
                "provider": s.provider,
                "timestamp": s.first_seen_at or s.created_at,
                "title": s.title,
                "summary": f"Incident signal: {s.title}",
                "severity": s.severity,
                "source": "incident_signal",
                "rule_key": None,
                "event_type": None,
                "signal_type": s.signal_type,
                "correlation_type": None,
                "linked_object_id": str(s.id),
                "metadata_preview": _scalar_preview(sanitized),
            })

    # ── Correlations ──────────────────────────────────────────────────────────
    if by_type.get("correlation"):
        for c in (
            db.query(SecuritySignalCorrelation)
            .filter(
                SecuritySignalCorrelation.workspace_id == workspace_id,
                SecuritySignalCorrelation.id.in_(by_type["correlation"]),
            )
            .all()
        ):
            sanitized = correlation_svc.sanitize_correlation_metadata(
                c.correlation_metadata if isinstance(c.correlation_metadata, dict) else {}
            )
            items.append({
                "id": str(c.id),
                "item_type": "correlation",
                "provider": c.provider,
                "timestamp": c.first_seen_at or c.created_at,
                "title": c.title,
                "summary": f"Correlation: {c.title}",
                "severity": c.severity,
                "source": "correlation",
                "rule_key": None,
                "event_type": None,
                "signal_type": None,
                "correlation_type": c.correlation_type,
                "linked_object_id": str(c.id),
                "metadata_preview": _scalar_preview(sanitized),
            })

    # Sort ascending by timestamp; nulls last; stable tie-break by type then id.
    items.sort(key=lambda it: (
        it["timestamp"] is None,
        it["timestamp"] or _MIN_DT,
        _TYPE_RANK.get(it["item_type"], 9),
        it["id"],
    ))

    counts_by_type: dict[str, int] = {
        "finding": 0, "activity_event": 0, "incident_signal": 0, "correlation": 0,
    }
    counts_by_provider: dict[str, int] = {}
    for it in items:
        counts_by_type[it["item_type"]] = counts_by_type.get(it["item_type"], 0) + 1
        p = (it["provider"] or "").lower()
        if p:
            counts_by_provider[p] = counts_by_provider.get(p, 0) + 1

    dominant = max(counts_by_provider, key=counts_by_provider.get) if counts_by_provider else ""

    return {
        "case_id": str(case_id),
        "provider": _provider_label(dominant) or None,
        "timeline_items": items,
        "counts_by_type": counts_by_type,
        "counts_by_provider": counts_by_provider,
        "total": len(items),
        "claim_note": CLAIM_NOTE,
    }


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
    provider_label = {"github": "GitHub", "aws": "AWS", "cloudflare": "Cloudflare"}.get(
        provider_key, provider_key
    )
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
        # M69.7A — normalized cross-provider chronological evidence timeline.
        "evidence_timeline": build_case_evidence_timeline(
            case_id=case.id, workspace_id=case.workspace_id, db=db
        ),
        "review_checklist": review_checklist,
        "limitations": LIMITATIONS,
    }
