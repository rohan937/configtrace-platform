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
        # AWS provider-alert fields (M67.1).
        "finding_type",
        "severity_label",
        "account_id",
        "region",
        "service_name",
        # AWS IAM behavior-timeline fields (M67.6) — CloudTrail-derived summary.
        "event_types",        # comma-joined trigger event types (flat string)
        "actor_id",           # IAM principal/user identity for the chain
        "resource_id",        # anchor resource identifier
        "event_count",        # number of trigger events in the chain
        "window_start",       # ISO timestamp of the chain window start
        "window_end",         # ISO timestamp of the chain window end
        "principal_hash",     # salted hash of the IAM principalId (never raw)
        "policy_name",        # safe policy hint (e.g. "AdministratorAccess")
        "resource_name",      # safe resource identifier
        # AWS Security Hub fields (M67.7).
        "finding_title",      # ASFF Title
        "product_name",       # ASFF ProductName
        "workflow_status",    # ASFF Workflow.Status
        "compliance_status",  # ASFF Compliance.Status
        # Cloudflare audit-activity fields (M68.1).
        "zone_id",            # Cloudflare zone id
        "zone_name",          # Cloudflare zone (domain)
        "rule_id",            # WAF/firewall rule id
        "rule_name",          # WAF/firewall rule name
        "outcome",            # audit action result (success / failure)
        "severity",           # provider-reported severity label
        # Cloudflare WAF-signal aggregate fields (M68.5) — counts only.
        "host",               # request host
        "ruleset_id",         # firewall ruleset id
        "path_prefix",        # sanitized leading path segment (or omitted)
        "actions",            # comma-joined distinct actions in the group
        "client_country_count",  # distinct country count (aggregate)
        # AWS S3 object-access-spike fields (M67.9) — safe aggregate counts only.
        "bucket_name",        # S3 bucket name (resource identifier)
        "unique_object_count",  # distinct object_key_hash count
        "object_key_prefix",  # sanitized, truncated prefix (or omitted)
        "pattern",            # which spike pattern fired
        "source",             # originating activity source ("s3_data_event")
        # AWS VPC Flow Log network-signal fields (M67.11) — aggregate counts only.
        "interface_id",       # ENI id (network resource identifier)
        "dst_port",           # destination port (int)
        "protocol",           # IANA protocol number (int)
        "flow_action",        # ACCEPT / REJECT / mixed
        "bytes_total",        # summed byte count across the flows (int)
        "packets_total",      # summed packet count across the flows (int)
        # GitHub secret-scanning alert signal fields (M69.4B) — safe summary only.
        "repository_full_name",  # owner/repo (safe identifier)
        "state",                 # alert state: open / resolved
        "resolution",            # resolution reason for resolved alerts
        "secret_type",           # detector slug (e.g. "github_personal_access_token")
        "secret_type_display_name",  # human-readable detector name
        "validity",              # GitHub-reported validity: active / inactive / unknown
        "publicly_leaked",       # bool — GitHub flagged the secret as publicly leaked
        "location_count",        # safe COUNT of alert locations (never the raw paths)
        # AWS IAM privilege-chain signal fields (M69.3A) — safe summary only.
        "chain_steps",        # number of distinct chain-step events detected (int)
        "target_user",        # target IAM user name (resource identifier, not raw ARN)
        "target_role",        # target IAM role name (resource identifier, not raw ARN)
        "policy_arn",         # attached policy ARN (safe label, already stored)
        "chain_pattern",      # which chain pattern fired (e.g. user_create_privilege_grant)
        "chain_window_minutes",  # configured sequence window (int)
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


# ── AWS provider-alert signals (M67.1) ────────────────────────────────────────
#
# AWS GuardDuty / Access Analyzer findings are provider-ADJUDICATED security
# findings. They are stronger evidence than a simple configuration risk, but they
# still do NOT confirm a breach/attacker/compromise — they are "evidence for
# review" Incident Signals with evidence_level="provider_alert".

PROVIDER_AWS = "aws"
SOURCE_SECURITY_ALERT = "security_alert"
_AWS_SEVERITIES = {"critical", "high", "medium", "low", "info"}

_AWS_GD_SUMMARY = (
    "AWS GuardDuty reported a security finding that may require review. "
    "ConfigTrace surfaces this as a provider-reported Incident Signal. This does "
    "not automatically confirm compromise or unauthorized access."
)
_AWS_AA_SUMMARY = (
    "AWS IAM Access Analyzer reported a finding that may require review. "
    "ConfigTrace surfaces this as a provider-reported Incident Signal. This does "
    "not automatically confirm compromise or unauthorized access."
)


def build_aws_signal_from_activity_event(ev: SecurityActivityEvent) -> Optional[dict[str, Any]]:
    """Map an AWS security-alert activity event → a provider-alert signal dict."""
    if ev.provider != PROVIDER_AWS or ev.source != SOURCE_SECURITY_ALERT:
        return None
    md = ev.event_metadata if isinstance(ev.event_metadata, dict) else {}
    severity = md.get("severity_label")
    if severity not in _AWS_SEVERITIES:
        severity = "medium"

    is_access_analyzer = isinstance(ev.event_type, str) and ev.event_type.startswith(
        "aws.access_analyzer"
    )
    if is_access_analyzer:
        signal_key = "aws_access_analyzer_finding"
        signal_type = "aws_access_analyzer"
        label = md.get("finding_type") or "external access"
        title = f"Access Analyzer finding: {label}"
        summary = _AWS_AA_SUMMARY
    else:
        signal_key = "aws_guardduty_finding"
        signal_type = "aws_guardduty"
        label = md.get("title") or md.get("finding_type") or ev.event_type
        title = f"GuardDuty finding: {label}"
        summary = _AWS_GD_SUMMARY

    when = ev.occurred_at or ev.ingested_at
    metadata = sanitize_signal_metadata(
        {
            "event_type": ev.event_type,
            "finding_type": md.get("finding_type"),
            "severity_label": severity,
            "account_id": md.get("account_id"),
            "region": md.get("region"),
            "service_name": md.get("service_name"),
        }
    )

    return {
        "provider": PROVIDER_AWS,
        "integration_id": ev.integration_id,
        "signal_key": signal_key,
        "signal_type": signal_type,
        "severity": severity,
        "status": "open",
        "title": title[:240],
        "summary": summary,
        "evidence_level": "provider_alert",   # stronger than config risk, not proof
        "confidence": "high",                  # the provider adjudicated the finding
        "first_seen_at": when,
        "last_seen_at": when,
        "linked_activity_event_id": ev.id,
        "metadata": metadata,
    }


def generate_aws_incident_signals(
    *, workspace_id: uuid.UUID, db: Session, scan_limit: int = 1000
) -> dict[str, Any]:
    """Generate AWS Incident Signals from AWS security-alert activity events.

    Idempotent: re-running creates no duplicates. Returns a generation summary.
    """
    events = (
        db.query(SecurityActivityEvent)
        .filter(
            SecurityActivityEvent.workspace_id == workspace_id,
            SecurityActivityEvent.provider == PROVIDER_AWS,
            SecurityActivityEvent.source == SOURCE_SECURITY_ALERT,
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
        signal = build_aws_signal_from_activity_event(ev)
        if signal is None:
            continue
        outcome, _row = upsert_incident_signal(
            workspace_id=workspace_id, signal=signal, db=db
        )
        if outcome == "created":
            created += 1
        else:
            skipped += 1

    return {
        "provider": PROVIDER_AWS,
        "activity_events_scanned": len(events),
        "signals_created": created,
        "signals_skipped": skipped,
    }


# ── AWS Security Hub Incident Signals (M67.7) ──────────────────────────────────

SOURCE_SECURITY_HUB = "security_hub"

_AWS_SH_SUMMARY = (
    "AWS Security Hub reported a security finding that may require review. "
    "ConfigTrace surfaces this as provider-reported evidence. This does not "
    "automatically confirm compromise or unauthorized access."
)


def build_aws_security_hub_signal_from_activity_event(
    ev: SecurityActivityEvent,
) -> Optional[dict[str, Any]]:
    """Map an AWS Security Hub activity event → a provider-alert signal dict."""
    if ev.provider != PROVIDER_AWS or ev.source != SOURCE_SECURITY_HUB:
        return None
    md = ev.event_metadata if isinstance(ev.event_metadata, dict) else {}
    severity = md.get("severity_label")
    if severity not in _AWS_SEVERITIES:
        severity = "medium"

    label = md.get("finding_title") or md.get("finding_type") or ev.event_type
    title = f"Security Hub finding: {label}"

    when = ev.occurred_at or ev.ingested_at
    metadata = sanitize_signal_metadata(
        {
            "event_type": ev.event_type,
            "finding_type": md.get("finding_type"),
            "finding_title": md.get("finding_title"),
            "severity_label": severity,
            "product_name": md.get("product_name"),
            "account_id": md.get("account_id"),
            "region": md.get("region"),
            "workflow_status": md.get("workflow_status"),
            "compliance_status": md.get("compliance_status"),
        }
    )

    return {
        "provider": PROVIDER_AWS,
        "integration_id": ev.integration_id,
        "signal_key": "aws_security_hub_finding",
        "signal_type": "aws_security_hub_finding",
        "severity": severity,
        "status": "open",
        "title": title[:240],
        "summary": _AWS_SH_SUMMARY,
        "evidence_level": "provider_alert",   # provider-adjudicated, not proof
        "confidence": "high",
        "first_seen_at": when,
        "last_seen_at": when,
        "linked_activity_event_id": ev.id,
        "metadata": metadata,
    }


def generate_aws_security_hub_signals(
    *, workspace_id: uuid.UUID, db: Session, scan_limit: int = 1000
) -> dict[str, Any]:
    """Generate AWS Incident Signals from Security Hub activity events.

    Idempotent: re-running creates no duplicates. Returns a generation summary.
    """
    events = (
        db.query(SecurityActivityEvent)
        .filter(
            SecurityActivityEvent.workspace_id == workspace_id,
            SecurityActivityEvent.provider == PROVIDER_AWS,
            SecurityActivityEvent.source == SOURCE_SECURITY_HUB,
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
        signal = build_aws_security_hub_signal_from_activity_event(ev)
        if signal is None:
            continue
        outcome, _row = upsert_incident_signal(
            workspace_id=workspace_id, signal=signal, db=db
        )
        if outcome == "created":
            created += 1
        else:
            skipped += 1

    return {
        "provider": PROVIDER_AWS,
        "activity_events_scanned": len(events),
        "signals_created": created,
        "signals_skipped": skipped,
    }


# ── Cloudflare audit-activity Incident Signals (M68.1) ─────────────────────────

PROVIDER_CLOUDFLARE = "cloudflare"
SOURCE_AUDIT_LOG = "audit_log"

_CF_REVIEW_NOTE = (
    "This is Cloudflare audit activity surfaced as evidence for review. "
    "ConfigTrace does not confirm a breach, attacker, compromise, or "
    "unauthorized access."
)

# Normalized Cloudflare audit ``event_type`` → signal rule. Only these
# security-relevant control-plane changes produce a signal; the generic
# ``cloudflare.audit_event`` fallback is intentionally NOT signal-producing.
CLOUDFLARE_SIGNAL_RULES: dict[str, dict[str, str]] = {
    "cloudflare.dns_record.changed": _rule(
        "cloudflare_dns_record_changed", "cloudflare_audit_activity", "medium",
        "DNS record changed"),
    "cloudflare.waf_rule.changed": _rule(
        "cloudflare_waf_rule_changed", "cloudflare_audit_activity", "high",
        "WAF/firewall rule changed"),
    "cloudflare.ssl_tls.changed": _rule(
        "cloudflare_ssl_tls_changed", "cloudflare_audit_activity", "high",
        "SSL/TLS setting changed"),
    "cloudflare.access_policy.changed": _rule(
        "cloudflare_access_policy_changed", "cloudflare_audit_activity", "high",
        "Access policy changed"),
    "cloudflare.api_token.activity": _rule(
        "cloudflare_api_token_activity", "cloudflare_audit_activity", "medium",
        "API token activity observed"),
    "cloudflare.zone_setting.changed": _rule(
        "cloudflare_zone_setting_changed", "cloudflare_audit_activity", "medium",
        "Zone setting changed"),
}


def build_cloudflare_signal_from_activity_event(
    ev: SecurityActivityEvent,
) -> Optional[dict[str, Any]]:
    """Map a Cloudflare audit activity event -> a signal dict, or None."""
    if ev.provider != PROVIDER_CLOUDFLARE or ev.source != SOURCE_AUDIT_LOG:
        return None
    rule = CLOUDFLARE_SIGNAL_RULES.get(ev.event_type)
    if rule is None:
        return None

    md = ev.event_metadata if isinstance(ev.event_metadata, dict) else {}
    zone = md.get("zone_name") or md.get("zone_id") or ev.resource_id
    actor = md.get("actor") or ev.actor_id

    title = rule["phrase"]
    if isinstance(zone, str) and zone:
        title = f"{rule['phrase']} on {zone}"

    who = f" by {actor}" if isinstance(actor, str) and actor else ""
    where = f" on {zone}" if isinstance(zone, str) and zone else ""
    summary = (
        f"Cloudflare audit activity: {rule['phrase'].lower()}{where}{who}. "
        f"{_CF_REVIEW_NOTE}"
    )

    when = ev.occurred_at or ev.ingested_at
    metadata = sanitize_signal_metadata({
        "event_type": ev.event_type,
        "action": md.get("action"),
        "actor": actor if isinstance(actor, str) else None,
        "zone_id": md.get("zone_id"),
        "zone_name": md.get("zone_name"),
        "rule_id": md.get("rule_id"),
        "rule_name": md.get("rule_name"),
        "outcome": md.get("outcome"),
        "severity": md.get("severity"),
    })

    return {
        "provider": PROVIDER_CLOUDFLARE,
        "integration_id": ev.integration_id,
        "signal_key": rule["signal_key"],
        "signal_type": rule["signal_type"],
        "severity": rule["severity"],
        "status": "open",
        "title": title[:240],
        "summary": summary,
        "evidence_level": "activity",
        "confidence": "high",
        "first_seen_at": when,
        "last_seen_at": when,
        "linked_activity_event_id": ev.id,
        "metadata": metadata,
    }


def generate_cloudflare_signals(
    *, workspace_id: uuid.UUID, db: Session, scan_limit: int = 1000
) -> dict[str, Any]:
    """Generate Cloudflare Incident Signals from audit activity. Idempotent."""
    events = (
        db.query(SecurityActivityEvent)
        .filter(
            SecurityActivityEvent.workspace_id == workspace_id,
            SecurityActivityEvent.provider == PROVIDER_CLOUDFLARE,
            SecurityActivityEvent.source == SOURCE_AUDIT_LOG,
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
        signal = build_cloudflare_signal_from_activity_event(ev)
        if signal is None:
            continue
        outcome, _row = upsert_incident_signal(
            workspace_id=workspace_id, signal=signal, db=db
        )
        if outcome == "created":
            created += 1
        else:
            skipped += 1

    return {
        "provider": PROVIDER_CLOUDFLARE,
        "activity_events_scanned": len(events),
        "signals_created": created,
        "signals_skipped": skipped,
    }
