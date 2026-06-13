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
from app.models.security_incident_signal import SecurityIncidentSignal
from app.models.security_signal_correlation import SecuritySignalCorrelation
from app.services import security_incident_signal_service as signal_svc

PROVIDER_GITHUB = "github"
PROVIDER_AWS = "aws"
PROVIDER_CLOUDFLARE = "cloudflare"

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
        # AWS correlation context (M67.3) — non-sensitive resource identifiers.
        "resource",
        "region",
        "account_id",
        # Cloudflare correlation context (M68.2) — non-sensitive identifiers.
        "zone_id",
        "zone_name",
        "action",
        "resource_type",
        "resource_id",
        # Cloudflare deeper context (M68.3) — exact setting/policy match.
        "setting_name",
        "policy_name",
        # Cloudflare WAF/security-event correlation context (M68.6) — safe
        # aggregate identifiers only (never raw IP / URL / path / query).
        "source",
        "host",
        "rule_id",
        "rule_name",
        "path_prefix",
        "event_count",
        # AWS S3 exposure × object-activity correlation context (M69.2A) — safe
        # bucket name + sanitized object prefix only (NEVER a raw object key).
        "bucket_name",
        "object_key_prefix",
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
        "provider": correlation.get("provider", PROVIDER_GITHUB),
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


# ---------------------------------------------------------------------------
# AWS correlations (M67.3)
# ---------------------------------------------------------------------------
#
# AWS Configuration Risk findings (``security_findings`` provider=aws, produced
# by ``security_rules/aws.py``) are correlated with AWS provider-reported
# security alerts (``security_activity_events`` provider=aws, source=
# "security_alert" — GuardDuty / Access Analyzer, ingested in M67.1) ONLY when
# both sides reference the SAME concrete resource (an S3 bucket name or an IAM
# principal/user name). Matching is resource-driven, never account-wide.
#
# Safely matchable today (the finding's evidence carries the resource name):
#   * S3 public-policy / public-ACL findings  → ``evidence["bucket"]``
#       matched to a GuardDuty S3Bucket alert (resource_id = bucket name) or an
#       Access Analyzer finding (resource_id = bucket ARN → bucket name).
#   * IAM AdministratorAccess-attached         → ``evidence["principal_name"]``
#   * IAM unused-access-key                     → ``evidence["username"]``
#       matched to a GuardDuty AccessKey alert (resource_id = IAM user name).
#
# DEFERRED — security-group public-ingress finding → GuardDuty EC2 instance:
#   the current data CANNOT link a security group to an EC2 instance. The SG
#   rule records (``security_rules/aws.py``) carry no attachment / ENI / public-
#   IP / instance-id context, and GuardDuty Instance findings reference an
#   InstanceId. There is no safe join key, so we DO NOT correlate them — being
#   in the same AWS account is not evidence. This rule is intentionally omitted.

# Map a finding's BASE rule key → AWS correlation rule descriptor.
_AWS_S3_RULE = {
    "correlation_key": "aws_s3_public_access_alert",
    "correlation_type": "aws_s3_public_access_alert",
    "severity": "high",
    "phrase": "S3 public-access configuration risk aligned with an AWS provider security finding",
    "summary_subject": "An S3 bucket configuration risk",
    "summary_provider": "an AWS provider security finding (GuardDuty / Access Analyzer)",
}
_AWS_IAM_RULE = {
    "correlation_key": "aws_iam_credential_alert",
    "correlation_type": "aws_iam_credential_alert",
    "severity": "high",
    "phrase": "IAM configuration risk aligned with an AWS provider credential finding",
    "summary_subject": "An IAM configuration risk",
    "summary_provider": "an AWS provider credential finding (GuardDuty)",
}

# finding base rule → (AWS correlation rule, evidence key holding the resource).
AWS_CORRELATION_RULES: dict[str, tuple[dict[str, Any], str]] = {
    "aws_s3_public_policy": (_AWS_S3_RULE, "bucket"),
    "aws_s3_public_acl": (_AWS_S3_RULE, "bucket"),
    "aws_iam_admin_policy_attached": (_AWS_IAM_RULE, "principal_name"),
    "aws_access_key_unused": (_AWS_IAM_RULE, "username"),
}


def _norm_resource(value: Any) -> Optional[str]:
    """Normalize a resource identifier to a comparable bare name.

    Reduces ARNs to their final segment (``arn:aws:s3:::my-bucket`` → ``my-bucket``;
    ``arn:aws:iam::123:user/deploy`` → ``deploy``) and lower-cases. Returns None
    for empty / non-string values so empty keys never match.
    """
    if not isinstance(value, str):
        return None
    s = value.strip()
    if not s:
        return None
    if "arn:aws:" in s:
        if "/" in s:
            s = s.rsplit("/", 1)[-1]
        else:
            s = s.rsplit(":", 1)[-1]
    s = s.strip()
    return s.lower() or None


def _aws_finding_resource_key(finding: SecurityFinding) -> Optional[str]:
    """Extract the normalized resource name a finding references (from evidence)."""
    base = _base_rule(finding.finding_key)
    mapping = AWS_CORRELATION_RULES.get(base)
    if mapping is None:
        return None
    _rule_desc, evidence_key = mapping
    evidence = finding.evidence if isinstance(finding.evidence, dict) else {}
    return _norm_resource(evidence.get(evidence_key))


def build_aws_correlation(
    *,
    finding: SecurityFinding,
    event: SecurityActivityEvent,
    resource_key: str,
    rule: dict[str, Any],
) -> dict[str, Any]:
    """Build an AWS correlation dict (not persisted) from a matched finding + alert."""
    severity = rule["severity"]
    # A provider alert flagged "critical" raises the review priority.
    meta = event.event_metadata if isinstance(event.event_metadata, dict) else {}
    if meta.get("severity_label") == "critical":
        severity = "critical"

    f_start = _aware(finding.first_detected_at)
    f_end = _aware(finding.last_seen_at)
    occurred = _aware(event.occurred_at)

    window_start = (f_start - WINDOW) if f_start else None
    window_end = (f_end + WINDOW) if f_end else None

    seens = [d for d in (f_start, occurred) if d]
    first_seen = min(seens) if seens else None
    lasts = [d for d in (f_end, occurred) if d]
    last_seen = max(lasts) if lasts else None

    title = f"{rule['phrase']} ({resource_key})"
    summary = (
        f"{rule['summary_subject']} (\"{finding.title}\") and {rule['summary_provider']} "
        f"(\"{event.event_type}\") were observed for the same resource "
        f"\"{resource_key}\" within the review window. {_REVIEW_NOTE}"
    )

    metadata = sanitize_correlation_metadata(
        {
            "resource": resource_key,
            "finding_rule": _base_rule(finding.finding_key),
            "finding_severity": finding.severity,
            "event_type": event.event_type,
            "region": meta.get("region") if isinstance(meta.get("region"), str) else None,
            "account_id": meta.get("account_id")
            if isinstance(meta.get("account_id"), str)
            else None,
            "window_hours": int(WINDOW.total_seconds() // 3600),
        }
    )

    return {
        "provider": PROVIDER_AWS,
        "correlation_key": rule["correlation_key"],
        "correlation_type": rule["correlation_type"],
        "severity": severity,
        # Exact same-resource match between a config risk and a provider-
        # adjudicated alert is strong (but still circumstantial) evidence.
        "confidence": "high",
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


def _generate_aws_alert_correlations(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    scan_limit: int = 1000,
) -> dict[str, Any]:
    """Correlate active AWS findings with AWS provider alerts for a workspace.

    Conservative + resource-driven: a finding only matches an alert that
    references the SAME bucket / IAM principal name within the finding's review
    window. Idempotent. Returns a generation summary.
    """
    findings = (
        db.query(SecurityFinding)
        .filter(
            SecurityFinding.workspace_id == workspace_id,
            SecurityFinding.provider == PROVIDER_AWS,
            SecurityFinding.status == "active",
        )
        .limit(scan_limit)
        .all()
    )
    findings = [
        f for f in findings if _base_rule(f.finding_key) in AWS_CORRELATION_RULES
    ]

    events = (
        db.query(SecurityActivityEvent)
        .filter(
            SecurityActivityEvent.workspace_id == workspace_id,
            SecurityActivityEvent.provider == PROVIDER_AWS,
            SecurityActivityEvent.source == "security_alert",
            SecurityActivityEvent.occurred_at.isnot(None),
        )
        .limit(scan_limit)
        .all()
    )
    # Index alerts by normalized resource key for cheap, exact lookup.
    events_by_resource: dict[str, list[SecurityActivityEvent]] = {}
    for ev in events:
        key = _norm_resource(ev.resource_id)
        if key:
            events_by_resource.setdefault(key, []).append(ev)

    created = 0
    skipped = 0
    for finding in findings:
        resource_key = _aws_finding_resource_key(finding)
        if not resource_key:
            continue  # no safe resource name to match on
        rule, _evidence_key = AWS_CORRELATION_RULES[_base_rule(finding.finding_key)]
        f_start = _aware(finding.first_detected_at)
        f_end = _aware(finding.last_seen_at)
        if f_start is None or f_end is None:
            continue
        window_start = f_start - WINDOW
        window_end = f_end + WINDOW

        for ev in events_by_resource.get(resource_key, []):
            occurred = _aware(ev.occurred_at)
            if occurred is None or not (window_start <= occurred <= window_end):
                continue
            correlation = build_aws_correlation(
                finding=finding, event=ev, resource_key=resource_key, rule=rule
            )
            outcome, _row = upsert_correlation(
                workspace_id=workspace_id, correlation=correlation, db=db
            )
            if outcome == "created":
                created += 1
            else:
                skipped += 1

    return {
        "provider": PROVIDER_AWS,
        "findings_scanned": len(findings),
        "events_scanned": len(events),
        "correlations_created": created,
        "correlations_skipped": skipped,
    }


# ---------------------------------------------------------------------------
# AWS S3 exposure × S3 object-activity correlations (M69.2A)
# ---------------------------------------------------------------------------
#
# AWS S3 public-EXPOSURE Configuration Risk findings (``aws_s3_public_policy`` /
# ``aws_s3_public_acl`` from ``security_rules/aws.py``) are correlated with S3
# OBJECT-LEVEL activity (``security_activity_events`` provider=aws, source=
# "s3_data_event" — ingested in M67.8) ONLY when both reference the SAME bucket
# within the finding's review window.
#
# JOIN KEY: the finding's ``evidence["bucket"]`` (normalized) must equal the S3
# data event's bucket (``resource_id`` / ``metadata["bucket_name"]``, normalized).
# Same account / same provider is NEVER enough — only same bucket.
#
# OUTPUT SHAPE: one correlation per (finding, rule-category), anchored to a
# deterministic representative event, with ``event_count`` as a safe aggregate —
# so the correlation count is bounded by the number of exposure findings, never
# the (large) S3 data-event volume.
#
# CLAIM DISCIPLINE: a correlation is EVIDENCE FOR REVIEW. It NEVER asserts data
# exfiltration, a breach, an attacker, a compromise, or unauthorized access — only
# that a public-exposure risk and S3 object activity co-occurred for the same
# bucket and may require review.
#
# PRIVACY: only safe aggregate fields are stored (bucket name, sanitized object
# prefix, event type, counts, window). NEVER a raw object key, raw IP, raw
# CloudTrail JSON, requestParameters/responseElements, tokens, secrets, or keys.

_AWS_S3_EXPOSURE_RULES = frozenset({"aws_s3_public_policy", "aws_s3_public_acl"})
_AWS_S3_DATA_SOURCE = "s3_data_event"
_AWS_S3_SPIKE_SIGNAL_TYPE = "s3_object_access_spike"
_AWS_S3_GET = "aws.s3.data.get_object"
_AWS_S3_LIST = "aws.s3.data.list_bucket"

_AWS_S3_REVIEW_NOTE = (
    "This may require review. ConfigTrace does not confirm data exfiltration or "
    "unauthorized access."
)

# (correlation_key, correlation_type, event_type, activity phrase) per category.
_AWS_S3_GETOBJECT_RULE = {
    "correlation_key": "aws_s3_public_getobject_activity",
    "correlation_type": "aws_s3_public_getobject_activity",
    "event_type": _AWS_S3_GET,
    "phrase": "S3 exposure risk aligned with object-read activity",
    "activity": "S3 object-read activity",
}
_AWS_S3_LISTBUCKET_RULE = {
    "correlation_key": "aws_s3_public_listbucket_activity",
    "correlation_type": "aws_s3_public_listbucket_activity",
    "event_type": _AWS_S3_LIST,
    "phrase": "S3 exposure risk aligned with bucket-list activity",
    "activity": "S3 bucket-list activity",
}
_AWS_S3_SPIKE_RULE = {
    "correlation_key": "aws_s3_public_access_spike_activity",
    "correlation_type": "aws_s3_public_access_spike_activity",
    "phrase": "S3 exposure risk aligned with an S3 object-access spike",
    "activity": "an S3 object-access spike",
}

# Event-type → category rule for the per-event passes (GetObject / ListBucket).
_AWS_S3_EVENT_RULES = {
    _AWS_S3_GET: _AWS_S3_GETOBJECT_RULE,
    _AWS_S3_LIST: _AWS_S3_LISTBUCKET_RULE,
}


def _aws_event_bucket(ev: SecurityActivityEvent) -> Optional[str]:
    """Normalized bucket name for an S3 data event (metadata or resource_id)."""
    md = ev.event_metadata if isinstance(ev.event_metadata, dict) else {}
    return _norm_resource(md.get("bucket_name")) or _norm_resource(ev.resource_id)


def _aws_s3_anchor(events: list[SecurityActivityEvent]) -> SecurityActivityEvent:
    """Deterministically pick a representative event (latest time, then id)."""
    return max(
        events,
        key=lambda e: (
            _aware(e.occurred_at) or _aware(e.ingested_at)
            or datetime.min.replace(tzinfo=timezone.utc),
            str(e.provider_event_id or ""),
        ),
    )


def build_aws_s3_activity_correlation(
    *,
    finding: SecurityFinding,
    anchor: SecurityActivityEvent,
    matched: list[SecurityActivityEvent],
    rule: dict[str, Any],
) -> dict[str, Any]:
    """Build an S3 exposure × object-activity correlation dict (not persisted)."""
    _valid_sev = {"critical", "high", "medium", "low", "info"}
    severity = finding.severity if finding.severity in _valid_sev else "high"

    md = anchor.event_metadata if isinstance(anchor.event_metadata, dict) else {}
    bucket = (
        md.get("bucket_name") if isinstance(md.get("bucket_name"), str) else None
    ) or (anchor.resource_id if isinstance(anchor.resource_id, str) else None)

    f_start = _aware(finding.first_detected_at)
    f_end = _aware(finding.last_seen_at)
    occurred = _aware(anchor.occurred_at)

    window_start = (f_start - WINDOW) if f_start else None
    window_end = (f_end + WINDOW) if f_end else None

    seens = [d for d in (f_start, occurred) if d]
    first_seen = min(seens) if seens else None
    lasts = [d for d in (f_end, occurred) if d]
    last_seen = max(lasts) if lasts else None

    label = bucket or "an S3 bucket"
    title = f"{rule['phrase']} ({label})"
    summary = (
        f"An S3 exposure risk (\"{finding.title}\") and {rule['activity']} were "
        f"observed for the same bucket \"{label}\" within the review window. "
        f"{_AWS_S3_REVIEW_NOTE}"
    )

    metadata = sanitize_correlation_metadata({
        "source": _AWS_S3_DATA_SOURCE,
        "finding_rule": _base_rule(finding.finding_key),
        "finding_severity": finding.severity,
        "event_type": anchor.event_type,
        "bucket_name": bucket,
        "object_key_prefix": md.get("object_key_prefix")
        if isinstance(md.get("object_key_prefix"), str) else None,
        "event_count": len(matched),
        "window_hours": int(WINDOW.total_seconds() // 3600),
    })

    return {
        "provider": PROVIDER_AWS,
        "correlation_key": rule["correlation_key"],
        "correlation_type": rule["correlation_type"],
        "severity": severity,
        # Same-bucket exposure + object activity is circumstantial co-occurrence
        # (object activity is not provider-adjudicated) — calibrated to "medium".
        "confidence": "medium",
        "status": "open",
        "title": title,
        "summary": summary,
        "linked_finding_id": finding.id,
        "linked_activity_event_id": anchor.id,
        "linked_change_id": finding.linked_change_id,
        "window_start": window_start,
        "window_end": window_end,
        "first_seen_at": first_seen,
        "last_seen_at": last_seen,
        "metadata": metadata,
        # carried for signal creation (not a column):
        "_integration_id": finding.integration_id,
    }


def generate_aws_s3_exposure_activity_correlations(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    scan_limit: int = 2000,
) -> dict[str, Any]:
    """Correlate active AWS S3 public-exposure findings with S3 object activity.

    Conservative + bucket-driven: an exposure finding only matches S3 data events
    (GetObject / ListBucket) and S3 object-access-spike signals for the SAME bucket
    within the finding's review window. One correlation per (finding, category),
    anchored to a deterministic representative event. Idempotent.
    """
    findings = (
        db.query(SecurityFinding)
        .filter(
            SecurityFinding.workspace_id == workspace_id,
            SecurityFinding.provider == PROVIDER_AWS,
            SecurityFinding.status == "active",
        )
        .limit(scan_limit)
        .all()
    )
    findings = [
        f for f in findings if _base_rule(f.finding_key) in _AWS_S3_EXPOSURE_RULES
    ]

    events = (
        db.query(SecurityActivityEvent)
        .filter(
            SecurityActivityEvent.workspace_id == workspace_id,
            SecurityActivityEvent.provider == PROVIDER_AWS,
            SecurityActivityEvent.source == _AWS_S3_DATA_SOURCE,
            SecurityActivityEvent.event_type.in_(tuple(_AWS_S3_EVENT_RULES.keys())),
            SecurityActivityEvent.occurred_at.isnot(None),
        )
        .limit(scan_limit)
        .all()
    )
    # Index S3 data events by (bucket, event_type) for cheap, exact lookup.
    events_by_bucket_type: dict[tuple[str, str], list[SecurityActivityEvent]] = {}
    for ev in events:
        bucket = _aws_event_bucket(ev)
        if not bucket:
            continue  # never correlate an event without a bucket
        events_by_bucket_type.setdefault((bucket, ev.event_type), []).append(ev)

    # Index S3 object-access-spike signals by bucket for the spike pass.
    spike_signals = (
        db.query(SecurityIncidentSignal)
        .filter(
            SecurityIncidentSignal.workspace_id == workspace_id,
            SecurityIncidentSignal.provider == PROVIDER_AWS,
            SecurityIncidentSignal.signal_type == _AWS_S3_SPIKE_SIGNAL_TYPE,
            SecurityIncidentSignal.linked_activity_event_id.isnot(None),
        )
        .limit(scan_limit)
        .all()
    )
    spikes_by_bucket: dict[str, list[SecurityIncidentSignal]] = {}
    for sig in spike_signals:
        smd = sig.signal_metadata if isinstance(sig.signal_metadata, dict) else {}
        bucket = _norm_resource(smd.get("bucket_name"))
        if bucket:
            spikes_by_bucket.setdefault(bucket, []).append(sig)

    created = 0
    skipped = 0
    for finding in findings:
        if finding.integration_id is None:
            continue
        bucket_key = _aws_finding_resource_key(finding)
        if not bucket_key:
            continue  # no safe bucket name on the finding
        f_start = _aware(finding.first_detected_at)
        f_end = _aware(finding.last_seen_at)
        if f_start is None or f_end is None:
            continue
        window_start = f_start - WINDOW
        window_end = f_end + WINDOW

        # Per-event-type passes (GetObject, ListBucket).
        for event_type, rule in _AWS_S3_EVENT_RULES.items():
            matched = [
                ev for ev in events_by_bucket_type.get((bucket_key, event_type), [])
                if (occ := _aware(ev.occurred_at)) is not None
                and window_start <= occ <= window_end
            ]
            if not matched:
                continue
            anchor = _aws_s3_anchor(matched)
            correlation = build_aws_s3_activity_correlation(
                finding=finding, anchor=anchor, matched=matched, rule=rule
            )
            outcome, _row = upsert_correlation(
                workspace_id=workspace_id, correlation=correlation, db=db
            )
            if outcome == "created":
                created += 1
            else:
                skipped += 1

        # Spike pass — exposure + a detected S3 object-access spike (M67.9) for the
        # same bucket. Links the spike's anchor activity event.
        for sig in spikes_by_bucket.get(bucket_key, []):
            anchor_id = sig.linked_activity_event_id
            anchor = db.get(SecurityActivityEvent, anchor_id) if anchor_id else None
            if anchor is None:
                continue
            occ = _aware(sig.last_seen_at) or _aware(anchor.occurred_at)
            if occ is None or not (window_start <= occ <= window_end):
                continue
            smd = sig.signal_metadata if isinstance(sig.signal_metadata, dict) else {}
            count = smd.get("event_count")
            matched = [anchor] * (count if isinstance(count, int) and count > 0 else 1)
            correlation = build_aws_s3_activity_correlation(
                finding=finding, anchor=anchor, matched=matched, rule=_AWS_S3_SPIKE_RULE
            )
            outcome, _row = upsert_correlation(
                workspace_id=workspace_id, correlation=correlation, db=db
            )
            if outcome == "created":
                created += 1
            else:
                skipped += 1

    return {
        "provider": PROVIDER_AWS,
        "findings_scanned": len(findings),
        "events_scanned": len(events),
        "correlations_created": created,
        "correlations_skipped": skipped,
    }


def generate_aws_correlations(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    scan_limit: int = 1000,
) -> dict[str, Any]:
    """Generate ALL AWS correlations for a workspace (M67.3 + M69.2A).

    provider=aws now generates BOTH:
      * Configuration Risk × provider alerts (GuardDuty / Access Analyzer), and
      * S3 public-exposure risk × S3 object-level activity (GetObject / ListBucket
        / object-access spike).
    The returned summary sums both passes. Idempotent.
    """
    alerts = _generate_aws_alert_correlations(
        workspace_id=workspace_id, db=db, scan_limit=scan_limit
    )
    s3 = generate_aws_s3_exposure_activity_correlations(
        workspace_id=workspace_id, db=db
    )
    return {
        "provider": PROVIDER_AWS,
        "findings_scanned": alerts["findings_scanned"] + s3["findings_scanned"],
        "events_scanned": alerts["events_scanned"] + s3["events_scanned"],
        "correlations_created": alerts["correlations_created"] + s3["correlations_created"],
        "correlations_skipped": alerts["correlations_skipped"] + s3["correlations_skipped"],
    }


# ───────────────────────────────────────────────────────────────────────────────
# Cloudflare correlations (M68.2)
# ───────────────────────────────────────────────────────────────────────────────
#
# Cloudflare Configuration Risk findings (``security_findings`` provider=cloudflare,
# produced by ``security_rules/cloudflare.py``) are correlated with Cloudflare
# audit activity (``security_activity_events`` provider=cloudflare, source=
# "audit_log" — ingested in M68.1) ONLY when they share the SAME zone AND the SAME
# logical risk area within the finding's review window.
#
# ZONE MATCH: a Cloudflare integration is ZONE-SCOPED (one ``zone_id`` per
# credential), so a finding and an audit event that share the same
# ``integration_id`` are guaranteed to be the same zone — used here as the
# decryption-free zone gate. The event's zone_id/zone_name are stored for evidence.
#
# RISK-AREA GATE (avoids vague matching): a finding only correlates with audit
# events whose ``event_type`` is in the finding's risk area. Same zone is NOT
# enough — a TLS finding never matches a DNS event, etc.
#
# Safely matchable today (the config-risk finding rule exists):
#   * DNS  : cloudflare_dns_private_origin       ↔ cloudflare.dns_record.changed
#   * WAF  : cloudflare_waf_rule_disabled        ↔ cloudflare.waf_rule.changed
#   * TLS  : cloudflare_ssl_mode_weak /
#            cloudflare_always_https_off /
#            cloudflare_min_tls_weak             ↔ cloudflare.ssl_tls.changed
#
# DEFERRED (reported, never faked):
#   * Access policy (Candidate D) and API-token (Candidate E): NO Cloudflare
#     config-risk finding rule exists today (only drift classifiers), so there is
#     nothing to match against.
#   * cloudflare_hsts_disabled / _security_level_low / _development_mode_on: their
#     audit change is the GENERIC ``cloudflare.zone_setting.changed`` event, whose
#     event_type does not identify the specific setting — matching it would risk
#     cross-setting false positives, so these are intentionally not correlated.

_CF_DNS_RULE = {
    "correlation_key": "cloudflare_dns_risk_activity",
    "correlation_type": "cloudflare_dns_change",
    "event_types": frozenset({"cloudflare.dns_record.changed"}),
    "phrase": "Cloudflare DNS risk aligned with DNS audit activity",
    "area": "DNS",
}
_CF_WAF_RULE = {
    "correlation_key": "cloudflare_waf_risk_activity",
    "correlation_type": "cloudflare_waf_change",
    "event_types": frozenset({"cloudflare.waf_rule.changed"}),
    "phrase": "Cloudflare WAF risk aligned with WAF audit activity",
    "area": "WAF",
}
_CF_TLS_RULE = {
    "correlation_key": "cloudflare_tls_risk_activity",
    "correlation_type": "cloudflare_tls_change",
    "event_types": frozenset({"cloudflare.ssl_tls.changed"}),
    "phrase": "Cloudflare TLS risk aligned with SSL/TLS audit activity",
    "area": "TLS",
}
# M68.3 — Access-policy risk ↔ Access audit activity (Candidate D, now unlocked).
_CF_ACCESS_RULE = {
    "correlation_key": "cloudflare_access_risk_activity",
    "correlation_type": "cloudflare_access_policy_change",
    "event_types": frozenset({"cloudflare.access_policy.changed"}),
    "phrase": "Cloudflare Access policy risk aligned with Access audit activity",
    "area": "ACCESS",
}
# M68.3 — zone-setting risk ↔ zone-setting audit activity, gated on an EXACT
# setting-name match (never a generic zone_setting.changed correlation).
_CF_ZONE_RULE = {
    "correlation_key": "cloudflare_zone_setting_risk_activity",
    "correlation_type": "cloudflare_zone_setting_change",
    "event_types": frozenset({"cloudflare.zone_setting.changed"}),
    "phrase": "Cloudflare zone-setting risk aligned with zone-setting audit activity",
    "area": "ZONE_SETTING",
    "match_setting": True,
}

# finding base rule → correlation rule descriptor.
CLOUDFLARE_CORRELATION_RULES: dict[str, dict[str, Any]] = {
    "cloudflare_dns_private_origin": _CF_DNS_RULE,
    "cloudflare_waf_rule_disabled": _CF_WAF_RULE,
    "cloudflare_ssl_mode_weak": _CF_TLS_RULE,
    "cloudflare_always_https_off": _CF_TLS_RULE,
    "cloudflare_min_tls_weak": _CF_TLS_RULE,
    # M68.3 — Access policy risks.
    "cloudflare_access_policy_bypass": _CF_ACCESS_RULE,
    "cloudflare_access_policy_disabled": _CF_ACCESS_RULE,
    # M68.3 — zone-setting risks (exact setting-name gate).
    "cloudflare_hsts_disabled": _CF_ZONE_RULE,
    "cloudflare_security_level_low": _CF_ZONE_RULE,
    "cloudflare_development_mode_on": _CF_ZONE_RULE,
}

# finding base rule → expected Cloudflare zone-setting key (for the exact gate).
_CF_FINDING_SETTING: dict[str, str] = {
    "cloudflare_hsts_disabled": "security_header",
    "cloudflare_security_level_low": "security_level",
    "cloudflare_development_mode_on": "development_mode",
}


def _cf_finding_setting(finding: SecurityFinding) -> Optional[str]:
    """The Cloudflare zone-setting key a finding refers to (rule map → evidence)."""
    base = _base_rule(finding.finding_key)
    expected = _CF_FINDING_SETTING.get(base)
    if expected:
        return expected
    ev = finding.evidence if isinstance(finding.evidence, dict) else {}
    s = ev.get("setting")
    return s if isinstance(s, str) and s else None

_CF_SEVERITIES = {"critical", "high", "medium", "low", "info"}


def build_cloudflare_correlation(
    *,
    finding: SecurityFinding,
    event: SecurityActivityEvent,
    rule: dict[str, Any],
) -> dict[str, Any]:
    """Build a Cloudflare correlation dict (not persisted) from a matched pair."""
    severity = finding.severity if finding.severity in _CF_SEVERITIES else "medium"

    f_start = _aware(finding.first_detected_at)
    f_end = _aware(finding.last_seen_at)
    occurred = _aware(event.occurred_at)

    window_start = (f_start - WINDOW) if f_start else None
    window_end = (f_end + WINDOW) if f_end else None

    seens = [d for d in (f_start, occurred) if d]
    first_seen = min(seens) if seens else None
    lasts = [d for d in (f_end, occurred) if d]
    last_seen = max(lasts) if lasts else None

    meta = event.event_metadata if isinstance(event.event_metadata, dict) else {}
    zone = meta.get("zone_name") or meta.get("zone_id")

    title = rule["phrase"]
    if isinstance(zone, str) and zone:
        title = f"{rule['phrase']} ({zone})"
    summary = (
        f"A Cloudflare configuration risk (\"{finding.title}\") and related audit "
        f"activity (\"{event.event_type}\") were observed for the same zone/resource "
        f"within the review window. {_REVIEW_NOTE}"
    )

    metadata = sanitize_correlation_metadata({
        "finding_rule": _base_rule(finding.finding_key),
        "finding_severity": finding.severity,
        "event_type": event.event_type,
        "action": meta.get("action") if isinstance(meta.get("action"), str) else None,
        "actor": meta.get("actor") if isinstance(meta.get("actor"), str) else None,
        "zone_id": meta.get("zone_id") if isinstance(meta.get("zone_id"), str) else None,
        "zone_name": meta.get("zone_name") if isinstance(meta.get("zone_name"), str) else None,
        "setting_name": meta.get("setting_name") if isinstance(meta.get("setting_name"), str) else None,
        "policy_name": meta.get("policy_name") if isinstance(meta.get("policy_name"), str) else None,
        "resource_type": event.resource_type if isinstance(event.resource_type, str) else None,
        "resource_id": event.resource_id if isinstance(event.resource_id, str) else None,
        "account_id": meta.get("account_id") if isinstance(meta.get("account_id"), str) else None,
        "window_hours": int(WINDOW.total_seconds() // 3600),
    })

    return {
        "provider": PROVIDER_CLOUDFLARE,
        "correlation_key": rule["correlation_key"],
        "correlation_type": rule["correlation_type"],
        "severity": severity,
        # Same zone + same risk area + window is circumstantial co-occurrence,
        # not an exact-rule match — calibrated to "medium".
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


def _generate_cloudflare_audit_correlations(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    scan_limit: int = 1000,
) -> dict[str, Any]:
    """Correlate active Cloudflare findings with Cloudflare audit activity.

    Conservative: a finding only matches an audit event from the SAME integration
    (= same zone-scoped credential), in the SAME risk area, within the finding's
    review window. Idempotent. Returns a generation summary.
    """
    findings = (
        db.query(SecurityFinding)
        .filter(
            SecurityFinding.workspace_id == workspace_id,
            SecurityFinding.provider == PROVIDER_CLOUDFLARE,
            SecurityFinding.status == "active",
        )
        .limit(scan_limit)
        .all()
    )
    findings = [
        f for f in findings if _base_rule(f.finding_key) in CLOUDFLARE_CORRELATION_RULES
    ]

    events = (
        db.query(SecurityActivityEvent)
        .filter(
            SecurityActivityEvent.workspace_id == workspace_id,
            SecurityActivityEvent.provider == PROVIDER_CLOUDFLARE,
            SecurityActivityEvent.source == "audit_log",
            SecurityActivityEvent.occurred_at.isnot(None),
        )
        .limit(scan_limit)
        .all()
    )
    # Index audit events by integration (the zone-scoped credential).
    events_by_integ: dict[Any, list[SecurityActivityEvent]] = {}
    for ev in events:
        if ev.integration_id is not None:
            events_by_integ.setdefault(ev.integration_id, []).append(ev)

    created = 0
    skipped = 0
    for finding in findings:
        if finding.integration_id is None:
            continue  # no zone scope to match on
        rule = CLOUDFLARE_CORRELATION_RULES[_base_rule(finding.finding_key)]
        f_start = _aware(finding.first_detected_at)
        f_end = _aware(finding.last_seen_at)
        if f_start is None or f_end is None:
            continue
        window_start = f_start - WINDOW
        window_end = f_end + WINDOW

        finding_setting = _cf_finding_setting(finding) if rule.get("match_setting") else None
        for ev in events_by_integ.get(finding.integration_id, []):
            if ev.event_type not in rule["event_types"]:
                continue  # risk-area gate — never cross areas
            # Exact setting gate: zone-setting correlations only fire when the
            # audit event's setting_name matches the finding's setting key.
            if rule.get("match_setting"):
                ev_meta = ev.event_metadata if isinstance(ev.event_metadata, dict) else {}
                ev_setting = ev_meta.get("setting_name")
                if not finding_setting or ev_setting != finding_setting:
                    continue
            occurred = _aware(ev.occurred_at)
            if occurred is None or not (window_start <= occurred <= window_end):
                continue
            correlation = build_cloudflare_correlation(
                finding=finding, event=ev, rule=rule
            )
            outcome, _row = upsert_correlation(
                workspace_id=workspace_id, correlation=correlation, db=db
            )
            if outcome == "created":
                created += 1
            else:
                skipped += 1

    return {
        "provider": PROVIDER_CLOUDFLARE,
        "findings_scanned": len(findings),
        "events_scanned": len(events),
        "correlations_created": created,
        "correlations_skipped": skipped,
    }


# ───────────────────────────────────────────────────────────────────────────────
# Cloudflare WAF / security-event correlations (M68.6)
# ───────────────────────────────────────────────────────────────────────────────
#
# Cloudflare Configuration Risk findings (``security_findings`` provider=cloudflare,
# from ``security_rules/cloudflare.py``) are correlated with Cloudflare WAF /
# security activity (``security_activity_events`` provider=cloudflare, source=
# "waf_security_event" — ingested in M68.4) ONLY when they share the SAME zone AND
# a relevant, NON-VAGUE join key for the finding's risk area, within the review
# window.
#
# ZONE GATE: a Cloudflare integration is zone-scoped (one ``zone_id`` per
# credential), so a finding + WAF event with the SAME ``integration_id`` are the
# same zone — the decryption-free zone gate (as in M68.2).
#
# JOIN KEY by risk area (this is what makes a correlation specific, not vague):
#   * WAF rule disabled            → same zone + WAF/security event activity
#                                     (confidence raised when the event's ruleset
#                                     id aligns with the finding's evidence).
#   * zone security setting risk   → same zone + the event carries HOST evidence.
#   * DNS private-origin risk       → the event HOST must equal the finding's DNS
#                                     hostname (never same-zone-only).
#   * Access policy risk            → same zone + the event's ``path_prefix`` is a
#                                     sensitive prefix (admin/login/…); this is
#                                     "security activity on a sensitive path",
#                                     NOT a claim that any endpoint was accessed.
#   * TLS/HTTPS setting risk        → same zone + the event carries HOST evidence;
#                                     weaker evidence, so confidence is low.
#
# CLAIM DISCIPLINE: a correlation is EVIDENCE FOR REVIEW. It NEVER asserts a
# breach, attacker, compromise, exploit, or unauthorized access — only that a
# configuration risk and WAF/security activity co-occurred for the same
# zone/host/risk-area and may require review.
#
# OUTPUT SHAPE: one correlation per (finding, rule), anchored to a deterministic
# representative event, with ``event_count`` carried as a safe aggregate — so the
# correlation count is bounded by the number of findings, never the (large) WAF
# event volume.
#
# PRIVACY: only allowlisted, flat, safe aggregate fields are stored. The raw IP
# (hashed), raw URL/path (hashed; only a sanitized prefix), query string, headers,
# cookies, bodies, tokens, secrets, sessions, and raw GraphQL JSON are NEVER read.

_CF_WAF_SOURCE = "waf_security_event"

_CF_WAF_BLOCK = "cloudflare.waf_event.block"
_CF_WAF_CHALLENGES = frozenset({
    "cloudflare.waf_event.challenge",
    "cloudflare.waf_event.managed_challenge",
    "cloudflare.waf_event.js_challenge",
})
# "Security" events = block + any challenge (the protective-action family).
_CF_WAF_SECURITY = frozenset({_CF_WAF_BLOCK}) | _CF_WAF_CHALLENGES
_CF_WAF_LOG = "cloudflare.waf_event.log"
# The 7 concrete WAF actions (excludes the unmapped ``.event`` fallback).
_CF_WAF_ANY = _CF_WAF_SECURITY | frozenset({
    _CF_WAF_LOG, "cloudflare.waf_event.skip", "cloudflare.waf_event.allow",
})
# DNS / Access activity = security family + log (a request that was acted on).
_CF_WAF_SECURITY_OR_LOG = _CF_WAF_SECURITY | frozenset({_CF_WAF_LOG})

# Sensitive path prefixes for Access-policy correlations.
_CF_SENSITIVE_PREFIXES = frozenset({
    "admin", "login", "dashboard", "account", "auth", "api",
})

# Deterministic anchor rank — block first, then challenges, then log/skip/allow.
_CF_WAF_ANCHOR_RANK: dict[str, int] = {
    _CF_WAF_BLOCK: 60,
    "cloudflare.waf_event.managed_challenge": 52,
    "cloudflare.waf_event.challenge": 50,
    "cloudflare.waf_event.js_challenge": 48,
    _CF_WAF_LOG: 40,
    "cloudflare.waf_event.skip": 30,
    "cloudflare.waf_event.allow": 28,
    "cloudflare.waf_event.event": 20,
}

# Match modes.
_MATCH_ZONE = "zone"                 # same zone + relevant WAF activity
_MATCH_ZONE_HOST = "zone_host"       # same zone + event carries host evidence
_MATCH_HOST = "host"                 # event host == finding hostname
_MATCH_SENSITIVE_PATH = "sensitive"  # same zone + event path_prefix sensitive

_CF_WAF_DISABLED_RULE = {
    "correlation_key": "cloudflare_waf_risk_activity",
    "correlation_type": "cloudflare_waf_risk_activity",
    "event_types": _CF_WAF_ANY,
    "match": _MATCH_ZONE,
    "confidence": "medium",
    "phrase": "Cloudflare WAF risk aligned with WAF/security activity",
    "subject": "A Cloudflare WAF configuration risk",
    # block/challenge activity raises review priority; ruleset alignment raises
    # confidence (handled in the builder).
    "boost_severity_on_security": True,
    "boost_confidence_on_ruleset": True,
}
_CF_ZONE_SECURITY_RULE = {
    "correlation_key": "cloudflare_zone_security_activity",
    "correlation_type": "cloudflare_zone_security_activity",
    "event_types": _CF_WAF_ANY,
    "match": _MATCH_ZONE_HOST,
    "confidence": "medium",
    "phrase": "Cloudflare zone security setting risk aligned with WAF/security activity",
    "subject": "A Cloudflare zone security-setting risk",
}
_CF_DNS_ORIGIN_RULE = {
    "correlation_key": "cloudflare_dns_origin_activity",
    "correlation_type": "cloudflare_dns_origin_activity",
    "event_types": _CF_WAF_SECURITY_OR_LOG,
    "match": _MATCH_HOST,
    "confidence": "medium",
    "phrase": "Cloudflare DNS origin risk aligned with WAF/security activity",
    "subject": "A Cloudflare DNS origin risk",
}
_CF_ACCESS_ACTIVITY_RULE = {
    "correlation_key": "cloudflare_access_policy_activity",
    "correlation_type": "cloudflare_access_policy_activity",
    "event_types": _CF_WAF_SECURITY_OR_LOG,
    "match": _MATCH_SENSITIVE_PATH,
    "confidence": "medium",
    "phrase": "Cloudflare Access policy risk aligned with security activity on sensitive path",
    "subject": "A Cloudflare Access policy risk",
    # Discipline: report sensitive-path activity, never claim access occurred.
    "sensitive_path_note": True,
}
_CF_TLS_ACTIVITY_RULE = {
    "correlation_key": "cloudflare_tls_activity",
    "correlation_type": "cloudflare_tls_activity",
    "event_types": _CF_WAF_ANY,
    "match": _MATCH_ZONE_HOST,
    # Weaker evidence than WAF/DNS/Access — a TLS setting is zone-scoped with no
    # host to match against, so confidence stays low.
    "confidence": "low",
    "phrase": "Cloudflare TLS/HTTPS risk aligned with WAF/security activity",
    "subject": "A Cloudflare TLS/HTTPS risk",
}

# finding base rule → WAF correlation rule descriptor.
CLOUDFLARE_WAF_CORRELATION_RULES: dict[str, dict[str, Any]] = {
    "cloudflare_waf_rule_disabled": _CF_WAF_DISABLED_RULE,
    "cloudflare_security_level_low": _CF_ZONE_SECURITY_RULE,
    "cloudflare_development_mode_on": _CF_ZONE_SECURITY_RULE,
    "cloudflare_dns_private_origin": _CF_DNS_ORIGIN_RULE,
    "cloudflare_access_policy_bypass": _CF_ACCESS_ACTIVITY_RULE,
    "cloudflare_access_policy_disabled": _CF_ACCESS_ACTIVITY_RULE,
    "cloudflare_ssl_mode_weak": _CF_TLS_ACTIVITY_RULE,
    "cloudflare_always_https_off": _CF_TLS_ACTIVITY_RULE,
    "cloudflare_min_tls_weak": _CF_TLS_ACTIVITY_RULE,
    "cloudflare_hsts_disabled": _CF_TLS_ACTIVITY_RULE,
}


def _norm_host(value: Any) -> Optional[str]:
    """Normalize a hostname to a comparable form, or None for empty/non-string."""
    if not isinstance(value, str):
        return None
    s = value.strip().lower().rstrip(".")
    return s or None


def _cf_finding_host(finding: SecurityFinding) -> Optional[str]:
    """The DNS hostname a finding refers to (from its evidence ``name``)."""
    ev = finding.evidence if isinstance(finding.evidence, dict) else {}
    return _norm_host(ev.get("name"))


def _cf_waf_event_matches(
    rule: dict[str, Any],
    ev: SecurityActivityEvent,
    finding_host: Optional[str],
) -> bool:
    """Return True if a WAF event satisfies the rule's risk-area join key."""
    if ev.event_type not in rule["event_types"]:
        return False
    md = ev.event_metadata if isinstance(ev.event_metadata, dict) else {}
    host = _norm_host(md.get("host"))
    mode = rule["match"]
    if mode == _MATCH_ZONE:
        return True  # zone gate already applied by caller; risk area = WAF
    if mode == _MATCH_ZONE_HOST:
        return host is not None  # require concrete host evidence (not vague)
    if mode == _MATCH_HOST:
        return finding_host is not None and host is not None and host == finding_host
    if mode == _MATCH_SENSITIVE_PATH:
        pfx = md.get("path_prefix")
        return isinstance(pfx, str) and pfx.lower() in _CF_SENSITIVE_PREFIXES
    return False


def _cf_waf_anchor(events: list[SecurityActivityEvent]) -> SecurityActivityEvent:
    """Deterministically pick the representative event (rank, then time, then id)."""
    return max(
        events,
        key=lambda e: (
            _CF_WAF_ANCHOR_RANK.get(e.event_type, 0),
            _aware(e.occurred_at) or _aware(e.ingested_at) or datetime.min.replace(tzinfo=timezone.utc),
            str(e.provider_event_id or ""),
        ),
    )


def build_cloudflare_waf_correlation(
    *,
    finding: SecurityFinding,
    anchor: SecurityActivityEvent,
    matched: list[SecurityActivityEvent],
    rule: dict[str, Any],
) -> dict[str, Any]:
    """Build a Cloudflare WAF/security correlation dict (not persisted)."""
    severity = finding.severity if finding.severity in _CF_SEVERITIES else "medium"
    if rule.get("boost_severity_on_security") and (
        finding.severity in _HIGH_SEVERITIES or anchor.event_type in _CF_WAF_SECURITY
    ):
        severity = "high"

    md = anchor.event_metadata if isinstance(anchor.event_metadata, dict) else {}
    host = _norm_host(md.get("host"))

    confidence = rule["confidence"]
    if rule.get("boost_confidence_on_ruleset"):
        f_ev = finding.evidence if isinstance(finding.evidence, dict) else {}
        f_ruleset = f_ev.get("ruleset_id")
        e_ruleset = md.get("ruleset_id")
        if (
            isinstance(f_ruleset, str) and f_ruleset
            and isinstance(e_ruleset, str) and e_ruleset
            and f_ruleset == e_ruleset
        ):
            confidence = "high"

    f_start = _aware(finding.first_detected_at)
    f_end = _aware(finding.last_seen_at)
    occurred = _aware(anchor.occurred_at)

    window_start = (f_start - WINDOW) if f_start else None
    window_end = (f_end + WINDOW) if f_end else None

    seens = [d for d in (f_start, occurred) if d]
    first_seen = min(seens) if seens else None
    lasts = [d for d in (f_end, occurred) if d]
    last_seen = max(lasts) if lasts else None

    label = host or md.get("zone_name") or md.get("zone_id") or "a Cloudflare zone"
    title = f"{rule['phrase']} ({label})"

    scope = "host" if rule["match"] == _MATCH_HOST else "zone"
    extra = ""
    if rule.get("sensitive_path_note"):
        extra = (
            " This reflects security activity on a sensitive path prefix and does "
            "not indicate that any endpoint was accessed."
        )
    summary = (
        f"{rule['subject']} (\"{finding.title}\") and related Cloudflare WAF/security "
        f"activity (\"{anchor.event_type}\") were observed for the same {scope} within "
        f"the review window.{extra} {_REVIEW_NOTE}"
    )

    metadata = sanitize_correlation_metadata({
        "source": _CF_WAF_SOURCE,
        "finding_rule": _base_rule(finding.finding_key),
        "finding_severity": finding.severity,
        "event_type": anchor.event_type,
        "action": md.get("action") if isinstance(md.get("action"), str) else None,
        "zone_id": md.get("zone_id") if isinstance(md.get("zone_id"), str) else None,
        "zone_name": md.get("zone_name") if isinstance(md.get("zone_name"), str) else None,
        "host": host,
        "rule_id": md.get("rule_id") if isinstance(md.get("rule_id"), str) else None,
        "rule_name": md.get("rule_name") if isinstance(md.get("rule_name"), str) else None,
        "path_prefix": md.get("path_prefix") if isinstance(md.get("path_prefix"), str) else None,
        "event_count": len(matched),
        "window_hours": int(WINDOW.total_seconds() // 3600),
    })

    return {
        "provider": PROVIDER_CLOUDFLARE,
        "correlation_key": rule["correlation_key"],
        "correlation_type": rule["correlation_type"],
        "severity": severity,
        "confidence": confidence,
        "status": "open",
        "title": title,
        "summary": summary,
        "linked_finding_id": finding.id,
        "linked_activity_event_id": anchor.id,
        "linked_change_id": finding.linked_change_id,
        "window_start": window_start,
        "window_end": window_end,
        "first_seen_at": first_seen,
        "last_seen_at": last_seen,
        "metadata": metadata,
        # carried for signal creation (not a column):
        "_integration_id": finding.integration_id,
    }


def generate_cloudflare_waf_correlations(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    scan_limit: int = 2000,
) -> dict[str, Any]:
    """Correlate active Cloudflare findings with Cloudflare WAF/security activity.

    Conservative + non-vague: each finding only matches WAF events from the SAME
    zone-scoped integration that satisfy the finding's risk-area join key (host
    match for DNS, sensitive-path for Access, host-present for zone/TLS settings),
    within the review window. One correlation per (finding, rule), anchored to a
    deterministic representative event. Idempotent. Returns a generation summary.
    """
    findings = (
        db.query(SecurityFinding)
        .filter(
            SecurityFinding.workspace_id == workspace_id,
            SecurityFinding.provider == PROVIDER_CLOUDFLARE,
            SecurityFinding.status == "active",
        )
        .limit(scan_limit)
        .all()
    )
    findings = [
        f for f in findings
        if _base_rule(f.finding_key) in CLOUDFLARE_WAF_CORRELATION_RULES
    ]

    events = (
        db.query(SecurityActivityEvent)
        .filter(
            SecurityActivityEvent.workspace_id == workspace_id,
            SecurityActivityEvent.provider == PROVIDER_CLOUDFLARE,
            SecurityActivityEvent.source == _CF_WAF_SOURCE,
            SecurityActivityEvent.occurred_at.isnot(None),
        )
        .limit(scan_limit)
        .all()
    )
    events_by_integ: dict[Any, list[SecurityActivityEvent]] = {}
    for ev in events:
        if ev.integration_id is not None:
            events_by_integ.setdefault(ev.integration_id, []).append(ev)

    created = 0
    skipped = 0
    for finding in findings:
        if finding.integration_id is None:
            continue  # no zone scope to match on
        rule = CLOUDFLARE_WAF_CORRELATION_RULES[_base_rule(finding.finding_key)]
        f_start = _aware(finding.first_detected_at)
        f_end = _aware(finding.last_seen_at)
        if f_start is None or f_end is None:
            continue
        window_start = f_start - WINDOW
        window_end = f_end + WINDOW
        finding_host = _cf_finding_host(finding) if rule["match"] == _MATCH_HOST else None
        if rule["match"] == _MATCH_HOST and finding_host is None:
            continue  # DNS rule needs a hostname to match — never same-zone-only

        matched = []
        for ev in events_by_integ.get(finding.integration_id, []):
            occurred = _aware(ev.occurred_at)
            if occurred is None or not (window_start <= occurred <= window_end):
                continue
            if not _cf_waf_event_matches(rule, ev, finding_host):
                continue
            matched.append(ev)
        if not matched:
            continue

        anchor = _cf_waf_anchor(matched)
        correlation = build_cloudflare_waf_correlation(
            finding=finding, anchor=anchor, matched=matched, rule=rule
        )
        outcome, _row = upsert_correlation(
            workspace_id=workspace_id, correlation=correlation, db=db
        )
        if outcome == "created":
            created += 1
        else:
            skipped += 1

    return {
        "provider": PROVIDER_CLOUDFLARE,
        "findings_scanned": len(findings),
        "events_scanned": len(events),
        "correlations_created": created,
        "correlations_skipped": skipped,
    }


def generate_cloudflare_correlations(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    scan_limit: int = 1000,
) -> dict[str, Any]:
    """Generate ALL Cloudflare correlations for a workspace (M68.2/68.3 + M68.6).

    provider=cloudflare now generates BOTH:
      * Configuration Risk × audit activity (DNS/WAF/TLS/Access/zone-setting), and
      * Configuration Risk × WAF/security-event activity.
    The returned summary sums both passes. Idempotent.
    """
    audit = _generate_cloudflare_audit_correlations(
        workspace_id=workspace_id, db=db, scan_limit=scan_limit
    )
    waf = generate_cloudflare_waf_correlations(
        workspace_id=workspace_id, db=db
    )
    return {
        "provider": PROVIDER_CLOUDFLARE,
        "findings_scanned": audit["findings_scanned"] + waf["findings_scanned"],
        "events_scanned": audit["events_scanned"] + waf["events_scanned"],
        "correlations_created": audit["correlations_created"] + waf["correlations_created"],
        "correlations_skipped": audit["correlations_skipped"] + waf["correlations_skipped"],
    }


def list_correlations(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    provider: Optional[str] = None,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    correlation_type: Optional[str] = None,
    linked_signal_id: Optional[uuid.UUID] = None,
    linked_finding_id: Optional[uuid.UUID] = None,
    linked_activity_event_id: Optional[uuid.UUID] = None,
    page: int = 1,
    page_size: int = 50,
) -> tuple[list[SecuritySignalCorrelation], int]:
    """Paginated, workspace-scoped correlation list. Never crosses workspaces.

    The ``linked_*`` filters power evidence backlinks (M66.7): list the
    correlations attached to a given signal / finding / activity event. All
    filters compose with the mandatory workspace scope, so cross-workspace
    objects are never leaked even if a caller passes another workspace's id.
    """
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
    if linked_signal_id is not None:
        q = q.filter(SecuritySignalCorrelation.linked_signal_id == linked_signal_id)
    if linked_finding_id is not None:
        q = q.filter(SecuritySignalCorrelation.linked_finding_id == linked_finding_id)
    if linked_activity_event_id is not None:
        q = q.filter(
            SecuritySignalCorrelation.linked_activity_event_id == linked_activity_event_id
        )

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
