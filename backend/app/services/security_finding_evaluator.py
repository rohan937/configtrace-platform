"""Security findings evaluation engine — M60.4.

Turns the latest normalized snapshot for a resource into live
``security_findings``: it creates/updates active findings for risky current
states and resolves previously-active findings whose risky state is gone.

Design
------
* Deterministic and conservative — rules fire only on explicit normalized
  fields (see app/services/security_rules/*). Unknown providers/records are
  ignored safely.
* Per-resource scope. The active-finding set for a resource is reconciled
  against the candidates produced from its latest snapshot:
      - candidate present  → upsert active finding (refresh last_seen_at)
      - active finding with no matching candidate → resolved
* Evidence never includes secrets, payloads, or customer data — only the
  configuration values that make a state risky.
* This produces *security exposure findings from configuration state*. It does
  NOT detect breaches.

Lifecycle example
-----------------
A GitHub webhook flips HTTPS→HTTP: Drift Detection records the change; this
evaluator opens an active ``github_webhook_http`` finding. When it flips back to
HTTPS, the candidate disappears and the evaluator resolves the finding.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.models.integration import Integration
from app.models.resource import Resource
from app.models.snapshot import Snapshot
from app.services import security_exposure_events as exposure_events
from app.services import security_finding_service
from app.services.security_rules import aws as aws_rules
from app.services.security_rules import azure as azure_rules
from app.services.security_rules import cloudflare as cloudflare_rules
from app.services.security_rules import firebase as firebase_rules
from app.services.security_rules import github as github_rules
from app.services.security_rules import google_cloud as google_cloud_rules
from app.services.security_rules import shopify as shopify_rules
from app.services.security_rules import stripe as stripe_rules
from app.services.security_rules import supabase as supabase_rules
from app.services.security_rules import vercel as vercel_rules
from app.services.security_rules import datadog as datadog_rules
from app.services.security_rules.base import FindingCandidate

logger = logging.getLogger(__name__)

# Provider → ordered list of rule evaluators. Each evaluator self-checks the
# record_type, so unknown records simply yield nothing.
_PROVIDER_RULES = {
    "github": [github_rules.evaluate],
    "stripe": [stripe_rules.evaluate],
    "aws": [aws_rules.evaluate],
    "supabase": [supabase_rules.evaluate],
    "firebase": [firebase_rules.evaluate],
    "cloudflare": [cloudflare_rules.evaluate],
    "vercel": [vercel_rules.evaluate],
    "shopify": [shopify_rules.evaluate],
    "azure": [azure_rules.evaluate],
    "google_cloud": [google_cloud_rules.evaluate],
    # M82B: Datadog core security rules
    "datadog": [datadog_rules.evaluate],
}


def evaluate_record(record: dict[str, Any], provider: str) -> list[FindingCandidate]:
    """Evaluate one normalized snapshot record into 0+ finding candidates."""
    if not isinstance(record, dict):
        return []
    out: list[FindingCandidate] = []
    for fn in _PROVIDER_RULES.get(provider, []):
        try:
            out.extend(fn(record))
        except Exception:  # one bad record must not abort the pass
            logger.exception(
                "security_findings: rule raised on record  provider=%s rtype=%s",
                provider,
                record.get("record_type"),
            )
    return out


def _emit_event_safely(
    *,
    db: Session,
    workspace_id: uuid.UUID,
    integration_id: uuid.UUID,
    resource_id: Optional[uuid.UUID],
    finding_key: str,
    finding: Any,
    is_new: bool,
) -> Optional[exposure_events.SecurityExposureEvent]:
    """Build + log a lifecycle event; never raise (sync must not fail).

    ``is_new=True`` → opened, unless a prior resolved finding exists for the
    same logical key, in which case it's a re-open. ``is_new=False`` → resolved.
    """
    try:
        if is_new:
            reopened = security_finding_service.has_prior_resolved_finding(
                db=db,
                workspace_id=workspace_id,
                integration_id=integration_id,
                resource_id=resource_id,
                finding_key=finding_key,
            )
            event_type = (
                exposure_events.EVENT_REOPENED
                if reopened
                else exposure_events.EVENT_OPENED
            )
        else:
            event_type = exposure_events.EVENT_RESOLVED

        ev = exposure_events.event_from_finding(event_type, finding)
        logger.info(
            "security_exposure_events: %s  finding_id=%s provider=%s "
            "severity=%s alertable=%s resource_id=%s",
            ev.event_type,
            ev.finding_id,
            ev.provider,
            ev.severity,
            ev.is_alertable,
            ev.resource_id,
        )
        return ev
    except Exception:
        # Event creation/logging must never break the evaluation pass.
        logger.exception(
            "security_exposure_events: failed to build event  finding_key=%s",
            finding_key,
        )
        return None


def evaluate_security_findings_for_resource(
    *,
    db: Session,
    workspace_id: Optional[uuid.UUID],
    integration: Integration,
    resource: Resource,
    snapshot: Snapshot,
    linked_changes: Optional[list[Any]] = None,
) -> dict[str, Any]:
    """Reconcile active security findings for one resource from its snapshot.

    Returns a summary dict: ``{provider, candidates, upserted, resolved, skipped}``.
    Never raises for expected conditions (missing workspace, unknown provider).
    """
    summary: dict[str, Any] = {
        "provider": getattr(integration, "provider", None),
        "candidates": 0,
        "upserted": 0,
        "resolved": 0,
        "skipped": False,
        "events": [],
    }

    if workspace_id is None:
        # Findings are workspace-scoped; without a workspace we cannot persist.
        logger.info(
            "security_findings: skipped — integration has no workspace_id  "
            "integration_id=%s resource_id=%s",
            integration.id,
            resource.id,
        )
        summary["skipped"] = True
        return summary

    provider = getattr(integration, "provider", "") or ""
    if provider not in _PROVIDER_RULES:
        summary["skipped"] = True
        return summary

    # M61.7: rules disabled for this workspace are skipped — no create/refresh
    # and (below) their existing active findings are NOT auto-resolved.
    try:
        from app.services import security_rule_settings_service as _rule_settings
        from app.services.security_rule_registry import base_rule_key

        disabled_rule_keys = _rule_settings.get_disabled_rule_keys(workspace_id, db)
    except Exception:
        logger.exception(
            "security_findings: failed to load disabled rules  workspace=%s", workspace_id
        )
        disabled_rule_keys = set()

    state = snapshot.state if isinstance(snapshot.state, list) else []

    # Best-effort change linkage: map normalized record_id → latest change id.
    change_by_record_id: dict[str, uuid.UUID] = {}
    for ch in linked_changes or []:
        pm = getattr(ch, "provider_metadata", None) or {}
        rid = pm.get("record_id") if isinstance(pm, dict) else None
        if rid:
            change_by_record_id[str(rid)] = ch.id

    # Gather candidates from the latest snapshot.
    candidates: list[FindingCandidate] = []
    for record in state:
        candidates.extend(evaluate_record(record, provider))
    summary["candidates"] = len(candidates)

    # M60.10: collect alertable lifecycle events for the caller / future routing.
    events: list[exposure_events.SecurityExposureEvent] = []

    seen_keys: set[str] = set()
    for cand in candidates:
        if cand.finding_key in seen_keys:
            continue  # de-dupe within a single pass
        # M61.7: a disabled rule produces no new/refreshed findings.
        if base_rule_key(cand.finding_key) in disabled_rule_keys:
            continue
        seen_keys.add(cand.finding_key)

        linked_change_id = (
            change_by_record_id.get(str(cand.record_id))
            if cand.record_id
            else None
        )

        finding, created = security_finding_service.record_active_finding(
            db=db,
            workspace_id=workspace_id,
            integration_id=integration.id,
            provider=cand.provider,
            finding_key=cand.finding_key,
            severity=cand.severity,
            title=cand.title,
            resource_id=resource.id,
            linked_change_id=linked_change_id,
            description=cand.description,
            evidence=cand.evidence,
            remediation=cand.remediation,
        )
        summary["upserted"] += 1

        # Emit an event ONLY when a brand-new active finding is created — never
        # on a refresh of the same still-active risky state. A new finding that
        # follows a prior resolved finding for the same logical key is a re-open.
        if created:
            ev = _emit_event_safely(
                db=db,
                workspace_id=workspace_id,
                integration_id=integration.id,
                resource_id=resource.id,
                finding_key=cand.finding_key,
                finding=finding,
                is_new=True,
            )
            if ev is not None:
                events.append(ev)

    # Resolve previously-active findings for this resource whose risky state is
    # gone. Scoped to this resource's ACTIVE findings only — accepted_risk /
    # snoozed rows and other resources are never touched.
    resolved_findings = security_finding_service.resolve_missing_findings_for_resource(
        db=db,
        workspace_id=workspace_id,
        integration_id=integration.id,
        resource_id=resource.id,
        active_keys=seen_keys,
        disabled_rule_keys=disabled_rule_keys,
    )
    summary["resolved"] = len(resolved_findings)
    for finding in resolved_findings:
        ev = _emit_event_safely(
            db=db,
            workspace_id=workspace_id,
            integration_id=integration.id,
            resource_id=resource.id,
            finding_key=finding.finding_key,
            finding=finding,
            is_new=False,
        )
        if ev is not None:
            events.append(ev)

    summary["events"] = events

    logger.info(
        "security_findings: evaluated  provider=%s resource_id=%s "
        "candidates=%d upserted=%d resolved=%d",
        provider,
        resource.id,
        summary["candidates"],
        summary["upserted"],
        summary["resolved"],
    )
    return summary
