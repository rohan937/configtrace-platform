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
        # AWS SG exposure × VPC Flow Log correlation context (M69.2B) — safe
        # aggregate identifiers only (NEVER raw source/destination IPs, flow lines,
        # payloads, headers, tokens, or secrets).
        "security_group_id",
        "dst_port",
        "port_category",
        "interface_id",
        "flow_action",
        # AWS IAM risk × privilege-chain correlation context (M69.3B) — safe
        # IAM entity labels and chain summary only (NEVER access keys, secrets,
        # session tokens, credentials, raw CloudTrail JSON, requestParameters,
        # responseElements, raw IPs, user agents, or request bodies).
        "source_signal_type",
        "chain_pattern",
        "target_user",
        "target_role",
        # GitHub config-risk × secret-scanning alert correlation context (M69.4C)
        # — safe alert summary fields only (NEVER the raw secret, token, raw alert
        # URL, raw API response, raw locations, file contents, patch, headers, or
        # request body).
        "repository_full_name",
        "alert_number",
        "state",
        "resolution",
        "secret_type",
        "secret_type_display_name",
        "validity",
        "publicly_leaked",
        # GitHub config-risk × code-scanning alert correlation context (M69.4F)
        # — safe alert summary fields only (NEVER raw code, file contents, raw
        # SARIF, raw locations/paths, raw alert URL, raw API response, patch,
        # headers, or request body).
        "tool_name",
        "security_severity_level",
        "severity",
        # GitHub config-risk × Dependabot alert correlation context (M69.4I)
        # — safe advisory/dependency summary fields only (NEVER raw manifest/file
        # paths, advisory bodies/details, the raw dependency-graph or API
        # response, patch, headers, request body, tokens, or secrets).
        "dependency_package_name",
        "dependency_ecosystem",
        "vulnerable_version_range",
        "patched_versions",
        "advisory_ghsa_id",
        "advisory_cve_id",
        "advisory_severity",
        "cvss_score",
        "epss_percentage",
        "scope",
        # GitHub ruleset / automation-permission risk correlation context (M69.5C)
        # — safe aggregate posture fields only (NEVER tokens, headers, webhook
        # secrets, private keys, OAuth secrets, raw bypass-actor identities, or
        # the raw API response).
        "ruleset_name",
        "enforcement",
        "target",
        "bypass_actor_count",
        "required_status_checks_count",
        "targets_protected_branch",
        "credential_type",
        "broad_permission_count",
        "token_scope_count",
        "webhook_secret_configured",
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


def _generate_github_audit_correlations(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    scan_limit: int = 1000,
) -> dict[str, Any]:
    """Correlate active GitHub findings with GitHub audit activity for a workspace.

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
# GitHub config-risk × secret-scanning alert correlations (M69.4C)
# ---------------------------------------------------------------------------
#
# Correlate active GitHub repository configuration-risk findings with GitHub
# secret-scanning ALERT evidence (security_activity_events, provider=github,
# source=secret_scanning_alert — ingested in M69.4A) observed on the SAME
# repository within the review window. These are review correlations; they never
# assert secret leakage confirmed, compromise, an attacker, that someone has
# access, unauthorized access, a breach, or an attack — only "evidence for
# review" and, where GitHub itself set the flag, "marked publicly leaked" /
# "marked active".
#
# We anchor to the secret-scanning ACTIVITY EVENT directly (the preferred
# strategy) and only correlate OPEN alerts — resolved / revoked / false-positive
# / used-in-tests alerts never produce a (high-risk) correlation.

SS_SOURCE = "secret_scanning_alert"
# Only OPEN alerts are correlated (excludes resolved/revoked/false_positive/
# used_in_tests so non-actionable alerts never become correlations).
_SS_OPEN_EVENT = "github.secret_scanning.alert.open"


def _ss_rule(
    correlation_key: str,
    severity: str,
    phrase: str,
) -> dict[str, Any]:
    return {
        "correlation_key": correlation_key,
        "correlation_type": correlation_key,  # type == key for these families
        "activity_types": {_SS_OPEN_EVENT},
        "severity": severity,
        "phrase": phrase,
    }


# Map a finding's BASE rule key → secret-scanning correlation rule. Only GitHub
# repository-scoped config-risk rules that actually exist today are included.
# Three families: repository-protection risk, automation risk, and a safe
# repository-scoped generic fallback. (No public-repo visibility rule exists in
# the codebase today, so Pattern C is deferred — see the milestone report.)
_SS_PROTECTION_TYPE = "github_repo_protection_secret_alert"
_SS_AUTOMATION_TYPE = "github_automation_secret_alert"
_SS_GENERIC_TYPE = "github_repo_risk_secret_alert"

SECRET_SCANNING_CORRELATION_RULES: dict[str, dict[str, Any]] = {
    # A — repository protection risk × open secret-scanning alert.
    "github_branch_protection_missing": _ss_rule(
        _SS_PROTECTION_TYPE, "high",
        "GitHub repository protection risk aligned with secret-scanning alert evidence",
    ),
    "github_force_pushes_allowed": _ss_rule(
        _SS_PROTECTION_TYPE, "high",
        "GitHub repository protection risk aligned with secret-scanning alert evidence",
    ),
    "github_branch_deletion_allowed": _ss_rule(
        _SS_PROTECTION_TYPE, "high",
        "GitHub repository protection risk aligned with secret-scanning alert evidence",
    ),
    "github_pr_review_not_required": _ss_rule(
        _SS_PROTECTION_TYPE, "high",
        "GitHub repository protection risk aligned with secret-scanning alert evidence",
    ),
    "github_status_checks_not_required": _ss_rule(
        _SS_PROTECTION_TYPE, "high",
        "GitHub repository protection risk aligned with secret-scanning alert evidence",
    ),
    # B — automation / deploy-key / webhook risk × open secret-scanning alert.
    "github_webhook_http": _ss_rule(
        _SS_AUTOMATION_TYPE, "high",
        "GitHub automation risk aligned with secret-scanning alert evidence",
    ),
    "github_deploy_key_write_access": _ss_rule(
        _SS_AUTOMATION_TYPE, "high",
        "GitHub automation risk aligned with secret-scanning alert evidence",
    ),
    # D — safe repository-scoped generic fallback (any remaining repo-scoped
    # GitHub config risk). Severity is medium, raised to high only when GitHub
    # marked the alert publicly leaked or active.
    "github_env_protection_missing": _ss_rule(
        _SS_GENERIC_TYPE, "medium",
        "GitHub repository configuration risk aligned with secret-scanning alert evidence",
    ),
}


def _ss_meta(event: SecurityActivityEvent) -> dict[str, Any]:
    return event.event_metadata if isinstance(event.event_metadata, dict) else {}


def build_secret_scanning_correlation(
    *,
    finding: SecurityFinding,
    event: SecurityActivityEvent,
    repo: str,
    rule: dict[str, Any],
) -> dict[str, Any]:
    """Build a correlation dict (not persisted) from a finding + open alert event."""
    md = _ss_meta(event)
    publicly_leaked = md.get("publicly_leaked") is True
    active = isinstance(md.get("validity"), str) and md["validity"].strip().lower() == "active"

    # Raise to high when GitHub marked the alert publicly leaked or active.
    severity = rule["severity"]
    if publicly_leaked or active:
        severity = "high"

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
        f"Configuration risk \"{finding.title}\" and GitHub secret-scanning alert "
        f"evidence were observed for {repo} within the review window. This may "
        f"require review. ConfigTrace does not confirm secret misuse, compromise, "
        f"or unauthorized access."
    )

    metadata = sanitize_correlation_metadata(
        {
            "source": SS_SOURCE,
            "finding_rule": _base_rule(finding.finding_key),
            "finding_severity": finding.severity,
            "repository": repo,
            "repository_full_name": (
                md.get("repository_full_name") if isinstance(md.get("repository_full_name"), str)
                else repo
            ),
            "alert_number": md.get("alert_number"),
            "state": md.get("state"),
            "resolution": md.get("resolution"),
            "secret_type": md.get("secret_type"),
            "secret_type_display_name": md.get("secret_type_display_name"),
            "validity": md.get("validity"),
            "publicly_leaked": publicly_leaked,
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


def generate_github_secret_scanning_correlations(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    scan_limit: int = 1000,
) -> dict[str, Any]:
    """Correlate active GitHub config-risk findings with OPEN secret-scanning alert
    evidence on the SAME repository within the review window (M69.4C).

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
    findings = [
        f for f in findings if _base_rule(f.finding_key) in SECRET_SCANNING_CORRELATION_RULES
    ]

    # Resolve each finding's repository slug via its Resource.
    resource_ids = {f.resource_id for f in findings if f.resource_id is not None}
    repo_by_resource: dict[uuid.UUID, str] = {}
    if resource_ids:
        for r in db.query(Resource).filter(Resource.id.in_(resource_ids)).all():
            repo_by_resource[r.id] = r.provider_resource_id

    # Only secret-scanning ALERT events (source-scoped); indexed by repo slug.
    events = (
        db.query(SecurityActivityEvent)
        .filter(
            SecurityActivityEvent.workspace_id == workspace_id,
            SecurityActivityEvent.provider == PROVIDER_GITHUB,
            SecurityActivityEvent.source == SS_SOURCE,
            SecurityActivityEvent.occurred_at.isnot(None),
        )
        .limit(scan_limit)
        .all()
    )
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
        rule = SECRET_SCANNING_CORRELATION_RULES[_base_rule(finding.finding_key)]
        f_start = _aware(finding.first_detected_at)
        f_end = _aware(finding.last_seen_at)
        if f_start is None or f_end is None:
            continue
        window_start = f_start - WINDOW
        window_end = f_end + WINDOW

        for ev in events_by_repo.get(repo, []):
            if ev.event_type not in rule["activity_types"]:
                continue  # only OPEN alerts correlate
            occurred = _aware(ev.occurred_at)
            if occurred is None or not (window_start <= occurred <= window_end):
                continue
            correlation = build_secret_scanning_correlation(
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
# GitHub config-risk × code-scanning alert correlations (M69.4F)
# ---------------------------------------------------------------------------
#
# Correlate active GitHub repository configuration-risk findings with GitHub
# code-scanning (SAST) ALERT evidence (security_activity_events, provider=github,
# source=code_scanning_alert — ingested in M69.4D) observed on the SAME repository
# within the review window. These are review correlations; they never assert
# vulnerability exploitation confirmed, an exploit, a compromise, an attacker,
# that someone has access, unauthorized access, a breach, or an attack — only
# "evidence for review".
#
# We anchor to the code-scanning ACTIVITY EVENT directly (the preferred strategy)
# and only correlate OPEN or REOPENED alerts — fixed / dismissed alerts never
# produce a (high-risk) correlation. Raw code / file paths / SARIF / locations are
# never read (the source events were already sanitized in M69.4D).

CS_SOURCE = "code_scanning_alert"
# Only open / reopened alerts are correlated (excludes fixed / dismissed).
_CS_OPEN_EVENT = "github.code_scanning.alert.open"
_CS_REOPENED_EVENT = "github.code_scanning.alert.reopened"
_CS_ACTIVITY_TYPES = {_CS_OPEN_EVENT, _CS_REOPENED_EVENT}

# Code-scanning security severities that raise the correlation severity to high.
_CS_HIGH_SEVERITIES = {"critical", "high"}


def _cs_rule(
    correlation_key: str,
    severity: str,
    phrase: str,
) -> dict[str, Any]:
    return {
        "correlation_key": correlation_key,
        "correlation_type": correlation_key,  # type == key for these families
        "activity_types": set(_CS_ACTIVITY_TYPES),
        "severity": severity,
        "phrase": phrase,
    }


# Map a finding's BASE rule key → code-scanning correlation rule. Only GitHub
# repository-scoped config-risk rules that exist today are included. Three
# families fire: repository-protection risk, automation risk, environment
# protection risk. A generic repo-scoped fallback type
# (``github_repo_risk_code_alert``) is DEFERRED — every existing repo-scoped
# GitHub finding rule already maps to a specific family, so the generic rule
# would never match. See the milestone report.
_CS_PROTECTION_TYPE = "github_repo_protection_code_alert"
_CS_AUTOMATION_TYPE = "github_automation_code_alert"
_CS_ENVIRONMENT_TYPE = "github_environment_code_alert"
_CS_GENERIC_TYPE = "github_repo_risk_code_alert"  # deferred (no rule maps to it)

CODE_SCANNING_CORRELATION_RULES: dict[str, dict[str, Any]] = {
    # A — repository protection risk × open/reopened code-scanning alert.
    "github_branch_protection_missing": _cs_rule(
        _CS_PROTECTION_TYPE, "high",
        "GitHub repository protection risk aligned with code-scanning alert evidence",
    ),
    "github_force_pushes_allowed": _cs_rule(
        _CS_PROTECTION_TYPE, "high",
        "GitHub repository protection risk aligned with code-scanning alert evidence",
    ),
    "github_branch_deletion_allowed": _cs_rule(
        _CS_PROTECTION_TYPE, "high",
        "GitHub repository protection risk aligned with code-scanning alert evidence",
    ),
    "github_pr_review_not_required": _cs_rule(
        _CS_PROTECTION_TYPE, "high",
        "GitHub repository protection risk aligned with code-scanning alert evidence",
    ),
    "github_status_checks_not_required": _cs_rule(
        _CS_PROTECTION_TYPE, "high",
        "GitHub repository protection risk aligned with code-scanning alert evidence",
    ),
    # B — automation / deploy-key / webhook risk × open/reopened code-scanning alert.
    "github_webhook_http": _cs_rule(
        _CS_AUTOMATION_TYPE, "high",
        "GitHub automation risk aligned with code-scanning alert evidence",
    ),
    "github_deploy_key_write_access": _cs_rule(
        _CS_AUTOMATION_TYPE, "high",
        "GitHub automation risk aligned with code-scanning alert evidence",
    ),
    # C — environment protection risk × open/reopened code-scanning alert.
    # Base medium; raised to high when GitHub marked the alert high/critical.
    "github_env_protection_missing": _cs_rule(
        _CS_ENVIRONMENT_TYPE, "medium",
        "GitHub environment protection risk aligned with code-scanning alert evidence",
    ),
}


def build_code_scanning_correlation(
    *,
    finding: SecurityFinding,
    event: SecurityActivityEvent,
    repo: str,
    rule: dict[str, Any],
) -> dict[str, Any]:
    """Build a correlation dict (not persisted) from a finding + open/reopened alert."""
    md = _ss_meta(event)
    sev_level = md.get("security_severity_level")
    high = isinstance(sev_level, str) and sev_level.strip().lower() in _CS_HIGH_SEVERITIES

    # Raise to high when GitHub marked the alert high/critical security severity.
    severity = rule["severity"]
    if high:
        severity = "high"

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
        f"Configuration risk \"{finding.title}\" and GitHub code-scanning alert "
        f"evidence were observed for {repo} within the review window. This may "
        f"require review. ConfigTrace does not confirm exploitation, compromise, "
        f"or unauthorized access."
    )

    metadata = sanitize_correlation_metadata(
        {
            "source": CS_SOURCE,
            "finding_rule": _base_rule(finding.finding_key),
            "finding_severity": finding.severity,
            "repository": repo,
            "repository_full_name": (
                md.get("repository_full_name") if isinstance(md.get("repository_full_name"), str)
                else repo
            ),
            "alert_number": md.get("alert_number"),
            "state": md.get("state"),
            "rule_id": md.get("rule_id"),
            "rule_name": md.get("rule_name"),
            "tool_name": md.get("tool_name"),
            "severity": md.get("severity"),
            "security_severity_level": md.get("security_severity_level"),
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


def generate_github_code_scanning_correlations(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    scan_limit: int = 1000,
) -> dict[str, Any]:
    """Correlate active GitHub config-risk findings with OPEN/REOPENED code-scanning
    alert evidence on the SAME repository within the review window (M69.4F).

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
    findings = [
        f for f in findings if _base_rule(f.finding_key) in CODE_SCANNING_CORRELATION_RULES
    ]

    # Resolve each finding's repository slug via its Resource.
    resource_ids = {f.resource_id for f in findings if f.resource_id is not None}
    repo_by_resource: dict[uuid.UUID, str] = {}
    if resource_ids:
        for r in db.query(Resource).filter(Resource.id.in_(resource_ids)).all():
            repo_by_resource[r.id] = r.provider_resource_id

    # Only code-scanning ALERT events (source-scoped); indexed by repo slug.
    events = (
        db.query(SecurityActivityEvent)
        .filter(
            SecurityActivityEvent.workspace_id == workspace_id,
            SecurityActivityEvent.provider == PROVIDER_GITHUB,
            SecurityActivityEvent.source == CS_SOURCE,
            SecurityActivityEvent.occurred_at.isnot(None),
        )
        .limit(scan_limit)
        .all()
    )
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
        rule = CODE_SCANNING_CORRELATION_RULES[_base_rule(finding.finding_key)]
        f_start = _aware(finding.first_detected_at)
        f_end = _aware(finding.last_seen_at)
        if f_start is None or f_end is None:
            continue
        window_start = f_start - WINDOW
        window_end = f_end + WINDOW

        for ev in events_by_repo.get(repo, []):
            if ev.event_type not in rule["activity_types"]:
                continue  # only open / reopened alerts correlate
            occurred = _aware(ev.occurred_at)
            if occurred is None or not (window_start <= occurred <= window_end):
                continue
            correlation = build_code_scanning_correlation(
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
# GitHub config-risk × Dependabot alert correlations (M69.4I)
# ---------------------------------------------------------------------------
#
# Correlate active GitHub repository configuration-risk findings with GitHub
# Dependabot (vulnerable-dependency) ALERT evidence (security_activity_events,
# provider=github, source=dependabot_alert — ingested in M69.4G) observed on the
# SAME repository within the review window. These are review correlations; they
# never assert exploitation confirmed, that the vulnerable dependency was
# exploited, a compromise, an attacker, that someone has access, unauthorized
# access, a breach, or an attack — only "evidence for review".
#
# We anchor to the Dependabot ACTIVITY EVENT directly (the preferred strategy)
# and only correlate OPEN or REOPENED alerts — fixed / dismissed / auto-dismissed
# alerts never produce a (high-risk) correlation. Raw manifest/file paths,
# advisory bodies, and the raw dependency-graph response are never read (the
# source events were already sanitized in M69.4G).

DEP_SOURCE = "dependabot_alert"
# Only open / reopened alerts are correlated (excludes fixed/dismissed/auto).
_DEP_OPEN_EVENT = "github.dependabot.alert.open"
_DEP_REOPENED_EVENT = "github.dependabot.alert.reopened"
_DEP_ACTIVITY_TYPES = {_DEP_OPEN_EVENT, _DEP_REOPENED_EVENT}

# Advisory severities that raise the correlation severity to high.
_DEP_HIGH_SEVERITIES = {"critical", "high"}
_DEP_HIGH_CVSS = 7.0


def _dep_rule(
    correlation_key: str,
    severity: str,
    phrase: str,
) -> dict[str, Any]:
    return {
        "correlation_key": correlation_key,
        "correlation_type": correlation_key,  # type == key for these families
        "activity_types": set(_DEP_ACTIVITY_TYPES),
        "severity": severity,
        "phrase": phrase,
    }


# Map a finding's BASE rule key → Dependabot correlation rule. Only GitHub
# repository-scoped config-risk rules that exist today are included. Three
# families fire: repository-protection risk, automation risk, environment
# protection risk. A generic repo-scoped fallback type
# (``github_repo_risk_dependabot_alert``) is DEFERRED — every existing
# repo-scoped GitHub finding rule already maps to a specific family, so the
# generic rule would never match. See the milestone report.
_DEP_PROTECTION_TYPE = "github_repo_protection_dependabot_alert"
_DEP_AUTOMATION_TYPE = "github_automation_dependabot_alert"
_DEP_ENVIRONMENT_TYPE = "github_environment_dependabot_alert"
_DEP_GENERIC_TYPE = "github_repo_risk_dependabot_alert"  # deferred (no rule maps to it)

DEPENDABOT_CORRELATION_RULES: dict[str, dict[str, Any]] = {
    # A — repository protection risk × open/reopened Dependabot alert.
    "github_branch_protection_missing": _dep_rule(
        _DEP_PROTECTION_TYPE, "high",
        "GitHub repository protection risk aligned with Dependabot alert evidence",
    ),
    "github_force_pushes_allowed": _dep_rule(
        _DEP_PROTECTION_TYPE, "high",
        "GitHub repository protection risk aligned with Dependabot alert evidence",
    ),
    "github_branch_deletion_allowed": _dep_rule(
        _DEP_PROTECTION_TYPE, "high",
        "GitHub repository protection risk aligned with Dependabot alert evidence",
    ),
    "github_pr_review_not_required": _dep_rule(
        _DEP_PROTECTION_TYPE, "high",
        "GitHub repository protection risk aligned with Dependabot alert evidence",
    ),
    "github_status_checks_not_required": _dep_rule(
        _DEP_PROTECTION_TYPE, "high",
        "GitHub repository protection risk aligned with Dependabot alert evidence",
    ),
    # B — automation / deploy-key / webhook risk × open/reopened Dependabot alert.
    "github_webhook_http": _dep_rule(
        _DEP_AUTOMATION_TYPE, "high",
        "GitHub automation risk aligned with Dependabot alert evidence",
    ),
    "github_deploy_key_write_access": _dep_rule(
        _DEP_AUTOMATION_TYPE, "high",
        "GitHub automation risk aligned with Dependabot alert evidence",
    ),
    # C — environment protection risk × open/reopened Dependabot alert.
    # Base medium; raised to high when the advisory is high/critical or CVSS>=7.
    "github_env_protection_missing": _dep_rule(
        _DEP_ENVIRONMENT_TYPE, "medium",
        "GitHub environment protection risk aligned with Dependabot alert evidence",
    ),
}


def build_dependabot_correlation(
    *,
    finding: SecurityFinding,
    event: SecurityActivityEvent,
    repo: str,
    rule: dict[str, Any],
) -> dict[str, Any]:
    """Build a correlation dict (not persisted) from a finding + open/reopened alert."""
    md = _ss_meta(event)
    sev = md.get("advisory_severity")
    score = md.get("cvss_score")
    high = (
        (isinstance(sev, str) and sev.strip().lower() in _DEP_HIGH_SEVERITIES)
        or (isinstance(score, (int, float)) and not isinstance(score, bool) and score >= _DEP_HIGH_CVSS)
    )

    # Raise to high when the advisory is high/critical or CVSS >= 7.0.
    severity = rule["severity"]
    if high:
        severity = "high"

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
        f"Configuration risk \"{finding.title}\" and GitHub Dependabot alert "
        f"evidence were observed for {repo} within the review window. This may "
        f"require review. ConfigTrace does not confirm exploitation, compromise, "
        f"or unauthorized access."
    )

    metadata = sanitize_correlation_metadata(
        {
            "source": DEP_SOURCE,
            "finding_rule": _base_rule(finding.finding_key),
            "finding_severity": finding.severity,
            "repository": repo,
            "repository_full_name": (
                md.get("repository_full_name") if isinstance(md.get("repository_full_name"), str)
                else repo
            ),
            "alert_number": md.get("alert_number"),
            "state": md.get("state"),
            "dependency_package_name": md.get("dependency_package_name"),
            "dependency_ecosystem": md.get("dependency_ecosystem"),
            "vulnerable_version_range": md.get("vulnerable_version_range"),
            "patched_versions": md.get("patched_versions"),
            "advisory_ghsa_id": md.get("advisory_ghsa_id"),
            "advisory_cve_id": md.get("advisory_cve_id"),
            "advisory_severity": md.get("advisory_severity"),
            "cvss_score": md.get("cvss_score"),
            "epss_percentage": md.get("epss_percentage"),
            "scope": md.get("scope"),
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


def generate_github_dependabot_correlations(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    scan_limit: int = 1000,
) -> dict[str, Any]:
    """Correlate active GitHub config-risk findings with OPEN/REOPENED Dependabot
    alert evidence on the SAME repository within the review window (M69.4I).

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
    findings = [
        f for f in findings if _base_rule(f.finding_key) in DEPENDABOT_CORRELATION_RULES
    ]

    # Resolve each finding's repository slug via its Resource.
    resource_ids = {f.resource_id for f in findings if f.resource_id is not None}
    repo_by_resource: dict[uuid.UUID, str] = {}
    if resource_ids:
        for r in db.query(Resource).filter(Resource.id.in_(resource_ids)).all():
            repo_by_resource[r.id] = r.provider_resource_id

    # Only Dependabot ALERT events (source-scoped); indexed by repo slug.
    events = (
        db.query(SecurityActivityEvent)
        .filter(
            SecurityActivityEvent.workspace_id == workspace_id,
            SecurityActivityEvent.provider == PROVIDER_GITHUB,
            SecurityActivityEvent.source == DEP_SOURCE,
            SecurityActivityEvent.occurred_at.isnot(None),
        )
        .limit(scan_limit)
        .all()
    )
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
        rule = DEPENDABOT_CORRELATION_RULES[_base_rule(finding.finding_key)]
        f_start = _aware(finding.first_detected_at)
        f_end = _aware(finding.last_seen_at)
        if f_start is None or f_end is None:
            continue
        window_start = f_start - WINDOW
        window_end = f_end + WINDOW

        for ev in events_by_repo.get(repo, []):
            if ev.event_type not in rule["activity_types"]:
                continue  # only open / reopened alerts correlate
            occurred = _aware(ev.occurred_at)
            if occurred is None or not (window_start <= occurred <= window_end):
                continue
            correlation = build_dependabot_correlation(
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
# GitHub ruleset / automation-permission risk × evidence correlations (M69.5C)
# ---------------------------------------------------------------------------
#
# Correlate the M69.5A ruleset findings and M69.5B automation-permission findings
# with existing GitHub evidence on the SAME repository within the review window:
#   * repository-protection / automation AUDIT activity (source=audit_log), and
#   * OPEN/REOPENED security-alert evidence (secret / code / Dependabot).
# These are review correlations; they never assert compromise, a token leak, an
# attacker, that someone has access, unauthorized access, a breach, or an attack —
# only "evidence for review". Only safe aggregate posture fields are stored.

# Finding-rule families (base keys; M69.5A / M69.5B).
_RULESET_FINDING_RULES: frozenset[str] = frozenset({
    "github_ruleset_not_enforced",
    "github_ruleset_force_push_allowed",
    "github_ruleset_pr_review_missing",
    "github_ruleset_status_checks_missing",
    "github_ruleset_bypass_actors_present",
    "github_ruleset_weak_target_coverage",
})
_AUTOMATION_FINDING_RULES: frozenset[str] = frozenset({
    "github_automation_admin_permission",
    "github_automation_write_permission",
    "github_token_broad_scopes",
    "github_webhook_secret_missing",
})

# Evidence event types (audit activity) for each family.
_AUDIT_SOURCE = "audit_log"
_RULESET_PROTECTION_ACTIVITY: frozenset[str] = frozenset({
    "github.ruleset.changed",
    "github.branch_protection.disabled",
    "github.branch_protection.updated",
})
_AUTOMATION_ACTIVITY: frozenset[str] = frozenset({
    "github.deploy_key.added",
    "github.webhook.created",
    "github.webhook.updated",
    "github.webhook.deleted",
    "github.app.installed",
    "github.app.permissions_changed",
})

# OPEN/REOPENED security-alert evidence (excludes fixed / dismissed).
_SECURITY_ALERT_SOURCES: frozenset[str] = frozenset({
    "secret_scanning_alert", "code_scanning_alert", "dependabot_alert",
})
_OPEN_ALERT_EVENTS: frozenset[str] = frozenset({
    "github.secret_scanning.alert.open",
    "github.code_scanning.alert.open",
    "github.code_scanning.alert.reopened",
    "github.dependabot.alert.open",
    "github.dependabot.alert.reopened",
})
_HIGH_ALERT_SEVERITIES = {"critical", "high"}


def _finding_evidence(finding: SecurityFinding) -> dict[str, Any]:
    return finding.evidence if isinstance(finding.evidence, dict) else {}


def _build_github_finding_evidence_correlation(
    *,
    finding: SecurityFinding,
    event: SecurityActivityEvent,
    repo: str,
    correlation_type: str,
    phrase: str,
    summary_core: str,
    alert_based: bool,
) -> dict[str, Any]:
    """Build a correlation dict (not persisted) for an M69.5C finding × evidence pair."""
    fev = _finding_evidence(finding)
    md = _ss_meta(event)

    # Severity: high when the finding is high/critical; for alert-based families,
    # also high when the alert itself is high/critical / publicly leaked.
    severity = "high" if finding.severity in _HIGH_SEVERITIES else "medium"
    if alert_based:
        alert_sev = md.get("advisory_severity") or md.get("security_severity_level")
        if isinstance(alert_sev, str) and alert_sev.strip().lower() in _HIGH_ALERT_SEVERITIES:
            severity = "high"
        if md.get("publicly_leaked") is True:
            severity = "high"

    f_start = _aware(finding.first_detected_at)
    f_end = _aware(finding.last_seen_at)
    occurred = _aware(event.occurred_at)
    window_start = (f_start - WINDOW) if f_start else None
    window_end = (f_end + WINDOW) if f_end else None
    seens = [d for d in (f_start, occurred) if d]
    first_seen = min(seens) if seens else None
    lasts = [d for d in (f_end, occurred) if d]
    last_seen = max(lasts) if lasts else None

    title = f"{phrase} on {repo}"
    summary = (
        f"Configuration risk \"{finding.title}\" and {summary_core} were observed "
        f"for {repo} within the review window. This may require review. ConfigTrace "
        f"does not confirm unauthorized access or compromise."
    )

    metadata = sanitize_correlation_metadata({
        "source": event.source,
        "finding_rule": _base_rule(finding.finding_key),
        "finding_severity": finding.severity,
        "repository": repo,
        "repository_full_name": (
            md.get("repository_full_name") if isinstance(md.get("repository_full_name"), str)
            else repo
        ),
        "event_type": event.event_type,
        "window_hours": int(WINDOW.total_seconds() // 3600),
        # Ruleset finding posture (from the finding's safe evidence).
        "ruleset_name": fev.get("ruleset_name"),
        "enforcement": fev.get("enforcement"),
        "target": fev.get("target"),
        "bypass_actor_count": fev.get("bypass_actor_count"),
        "required_status_checks_count": fev.get("required_status_checks_count"),
        "targets_protected_branch": fev.get("targets_protected_branch"),
        # Automation finding posture (from the finding's safe evidence).
        "credential_type": fev.get("credential_type"),
        "broad_permission_count": fev.get("broad_permission_count"),
        "token_scope_count": fev.get("token_scope_count"),
        "webhook_secret_configured": fev.get("webhook_secret_configured"),
        # Alert evidence posture (from the event's safe metadata).
        "alert_number": md.get("alert_number"),
        "state": md.get("state"),
        "rule_id": md.get("rule_id"),
        "rule_name": md.get("rule_name"),
        "tool_name": md.get("tool_name"),
        "security_severity_level": md.get("security_severity_level"),
        "advisory_ghsa_id": md.get("advisory_ghsa_id"),
        "advisory_cve_id": md.get("advisory_cve_id"),
        "advisory_severity": md.get("advisory_severity"),
        "dependency_package_name": md.get("dependency_package_name"),
        "dependency_ecosystem": md.get("dependency_ecosystem"),
        "secret_type": md.get("secret_type"),
        "validity": md.get("validity"),
        "publicly_leaked": md.get("publicly_leaked"),
    })

    return {
        "provider": PROVIDER_GITHUB,
        "correlation_key": correlation_type,
        "correlation_type": correlation_type,
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
        "_integration_id": finding.integration_id,
    }


def _generate_github_finding_evidence_correlations(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    finding_rules: frozenset[str],
    activity_sources: frozenset[str],
    activity_types: frozenset[str],
    correlation_type: str,
    phrase: str,
    summary_core: str,
    alert_based: bool,
    scan_limit: int = 1000,
) -> dict[str, Any]:
    """Generic M69.5C pass: correlate findings (in ``finding_rules``) with GitHub
    activity events (source ∈ ``activity_sources``, type ∈ ``activity_types``) on
    the SAME repository within the review window. Idempotent."""
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
    findings = [f for f in findings if _base_rule(f.finding_key) in finding_rules]

    resource_ids = {f.resource_id for f in findings if f.resource_id is not None}
    repo_by_resource: dict[uuid.UUID, str] = {}
    if resource_ids:
        for r in db.query(Resource).filter(Resource.id.in_(resource_ids)).all():
            repo_by_resource[r.id] = r.provider_resource_id

    events = (
        db.query(SecurityActivityEvent)
        .filter(
            SecurityActivityEvent.workspace_id == workspace_id,
            SecurityActivityEvent.provider == PROVIDER_GITHUB,
            SecurityActivityEvent.source.in_(activity_sources),
            SecurityActivityEvent.occurred_at.isnot(None),
        )
        .limit(scan_limit)
        .all()
    )
    events_by_repo: dict[str, list[SecurityActivityEvent]] = {}
    for ev in events:
        if isinstance(ev.resource_id, str) and ev.resource_id:
            events_by_repo.setdefault(ev.resource_id, []).append(ev)

    created = 0
    skipped = 0
    for finding in findings:
        if finding.resource_id is None:
            continue
        repo = repo_by_resource.get(finding.resource_id)
        if not repo:
            continue
        f_start = _aware(finding.first_detected_at)
        f_end = _aware(finding.last_seen_at)
        if f_start is None or f_end is None:
            continue
        window_start = f_start - WINDOW
        window_end = f_end + WINDOW

        for ev in events_by_repo.get(repo, []):
            if ev.event_type not in activity_types:
                continue
            occurred = _aware(ev.occurred_at)
            if occurred is None or not (window_start <= occurred <= window_end):
                continue
            correlation = _build_github_finding_evidence_correlation(
                finding=finding, event=ev, repo=repo,
                correlation_type=correlation_type, phrase=phrase,
                summary_core=summary_core, alert_based=alert_based,
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


def _generate_github_5c_correlations(
    *, workspace_id: uuid.UUID, db: Session, scan_limit: int = 1000,
) -> dict[str, Any]:
    """Run all four M69.5C passes (ruleset/automation × audit-activity / alert)."""
    passes = [
        # A — ruleset risk × repository-protection audit activity.
        dict(finding_rules=_RULESET_FINDING_RULES, activity_sources=frozenset({_AUDIT_SOURCE}),
             activity_types=_RULESET_PROTECTION_ACTIVITY,
             correlation_type="github_ruleset_risk_activity",
             phrase="GitHub ruleset risk aligned with repository protection activity",
             summary_core="GitHub repository protection activity", alert_based=False),
        # B — ruleset risk × security-alert evidence.
        dict(finding_rules=_RULESET_FINDING_RULES, activity_sources=_SECURITY_ALERT_SOURCES,
             activity_types=_OPEN_ALERT_EVENTS,
             correlation_type="github_ruleset_risk_security_alert",
             phrase="GitHub ruleset risk aligned with security-alert evidence",
             summary_core="GitHub security-alert evidence", alert_based=True),
        # C — automation permission risk × automation audit activity.
        dict(finding_rules=_AUTOMATION_FINDING_RULES, activity_sources=frozenset({_AUDIT_SOURCE}),
             activity_types=_AUTOMATION_ACTIVITY,
             correlation_type="github_automation_permission_activity",
             phrase="GitHub automation permission risk aligned with automation activity",
             summary_core="GitHub automation activity", alert_based=False),
        # D — automation permission risk × security-alert evidence.
        dict(finding_rules=_AUTOMATION_FINDING_RULES, activity_sources=_SECURITY_ALERT_SOURCES,
             activity_types=_OPEN_ALERT_EVENTS,
             correlation_type="github_automation_permission_security_alert",
             phrase="GitHub automation permission risk aligned with security-alert evidence",
             summary_core="GitHub security-alert evidence", alert_based=True),
    ]
    totals = {"findings_scanned": 0, "events_scanned": 0,
              "correlations_created": 0, "correlations_skipped": 0}
    for kw in passes:
        r = _generate_github_finding_evidence_correlations(
            workspace_id=workspace_id, db=db, scan_limit=scan_limit, **kw
        )
        for k in totals:
            totals[k] += r[k]
    return totals


# Public builders for direct (non-scanning) use by the incident demo seeder
# (M69.6) — keep the M69.5C phrasing authoritative in one place.
def build_ruleset_activity_correlation(
    *, finding: SecurityFinding, event: SecurityActivityEvent, repo: str,
) -> dict[str, Any]:
    """Ruleset risk × repository-protection activity (github_ruleset_risk_activity)."""
    return _build_github_finding_evidence_correlation(
        finding=finding, event=event, repo=repo,
        correlation_type="github_ruleset_risk_activity",
        phrase="GitHub ruleset risk aligned with repository protection activity",
        summary_core="GitHub repository protection activity", alert_based=False,
    )


def build_automation_security_alert_correlation(
    *, finding: SecurityFinding, event: SecurityActivityEvent, repo: str,
) -> dict[str, Any]:
    """Automation permission risk × security-alert evidence
    (github_automation_permission_security_alert)."""
    return _build_github_finding_evidence_correlation(
        finding=finding, event=event, repo=repo,
        correlation_type="github_automation_permission_security_alert",
        phrase="GitHub automation permission risk aligned with security-alert evidence",
        summary_core="GitHub security-alert evidence", alert_based=True,
    )


def generate_github_correlations(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    scan_limit: int = 1000,
) -> dict[str, Any]:
    """Generate ALL GitHub correlations for a workspace (M66.6 + M69.4C/F/I + M69.5C).

    provider=github now generates:
      * Configuration Risk × GitHub audit activity (webhook / branch-protection /
        deploy-key), and
      * Configuration Risk × GitHub secret/code/Dependabot alert evidence (same
        repository, OPEN/REOPENED alert, within the review window), and
      * GitHub ruleset risk and automation-permission risk × repository-protection /
        automation audit activity and × OPEN/REOPENED security-alert evidence
        (M69.5C, same repository, within the review window).
    The returned summary sums all passes. Idempotent.
    """
    audit = _generate_github_audit_correlations(
        workspace_id=workspace_id, db=db, scan_limit=scan_limit
    )
    secret = generate_github_secret_scanning_correlations(
        workspace_id=workspace_id, db=db, scan_limit=scan_limit
    )
    code = generate_github_code_scanning_correlations(
        workspace_id=workspace_id, db=db, scan_limit=scan_limit
    )
    dependabot = generate_github_dependabot_correlations(
        workspace_id=workspace_id, db=db, scan_limit=scan_limit
    )
    rulesets_automation = _generate_github_5c_correlations(
        workspace_id=workspace_id, db=db, scan_limit=scan_limit
    )
    passes = (audit, secret, code, dependabot, rulesets_automation)
    return {
        "provider": PROVIDER_GITHUB,
        "findings_scanned": sum(p["findings_scanned"] for p in passes),
        "events_scanned": sum(p["events_scanned"] for p in passes),
        "correlations_created": sum(p["correlations_created"] for p in passes),
        "correlations_skipped": sum(p["correlations_skipped"] for p in passes),
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


# ---------------------------------------------------------------------------
# AWS Security Group exposure × VPC Flow Log correlations (M69.2B)
# ---------------------------------------------------------------------------
#
# AWS Security Group public-EXPOSURE Configuration Risk findings
# (``aws_public_admin_port`` / ``aws_public_database_port`` /
# ``aws_public_all_ports`` from ``security_rules/aws.py``) are correlated with
# VPC Flow Log activity (``security_activity_events`` provider=aws, source=
# "vpc_flow_log" — ingested in M67.10) when BOTH share the SAME integration
# (same AWS account/region) AND the VPC flow's destination port falls within
# the SG rule's exposed port range (from_port..to_port), within the finding's
# review window.
#
# JOIN KEY: same ``integration_id`` (same AWS account/region scope) +
# destination port overlap (flow's ``dst_port`` within finding's exposed
# ``from_port``..``to_port``) + risk-area match (admin vs datastore ports).
# This is NOT "same port only" — the integration + port range + risk area +
# window combination provides non-vague, account-scoped evidence. Raw IPs and
# raw flow lines are NEVER used; no SG→ENI mapping is attempted.
#
# OUTPUT SHAPE: one correlation per (finding, port category, action category),
# anchored to a deterministic representative event, with ``event_count`` as a
# safe aggregate. Bounded by the number of exposure findings.
#
# CLAIM DISCIPLINE: a correlation is EVIDENCE FOR REVIEW. It NEVER asserts a
# network intrusion, breach, attacker, compromise, or unauthorized access.
#
# PRIVACY: only safe aggregate identifiers are stored (security_group_id,
# dst_port, port_category, interface_id, protocol, flow_action, event_count,
# window). NEVER raw source/destination IPs, raw flow lines, payloads,
# headers, tokens, secrets, or access keys.
#
# DEFERRED:
#   * SG→ENI exact mapping: no join key exists today (SG records carry no ENI
#     attachment; VPC flow records carry no SG context). Flagged in M69.1 and
#     intentionally omitted — correlating an SG finding to a *specific* ENI
#     would require a SG→attachment side-table that does not exist yet.

_AWS_SG_EXPOSURE_RULES = frozenset({
    "aws_public_admin_port",
    "aws_public_database_port",
    "aws_public_all_ports",
})
_AWS_VPC_FLOW_SOURCE = "vpc_flow_log"
_AWS_FLOW_ACCEPT = "aws.vpc.flow.accept"
_AWS_FLOW_REJECT = "aws.vpc.flow.reject"

# Sensitive destination ports — must match aws_vpc_flow_signal_service.
_SG_ADMIN_PORTS: frozenset[int] = frozenset({22, 3389, 5985, 5986})
_SG_DB_PORTS: frozenset[int] = frozenset({3306, 5432, 6379, 27017, 9200, 1433})

# Minimum reject events required to create a reject correlation (conservative).
_SG_REJECT_THRESHOLD = 2

# Mapping: finding base rule → list of sensitive port sets to match against.
# All three rules get matched against admin and/or DB ports only — "all ports"
# findings match both, but never arbitrary other ports (too vague).
_SG_RULE_PORT_SETS: dict[str, list[frozenset[int]]] = {
    "aws_public_admin_port": [_SG_ADMIN_PORTS],
    "aws_public_database_port": [_SG_DB_PORTS],
    "aws_public_all_ports": [_SG_ADMIN_PORTS, _SG_DB_PORTS],
}

_AWS_VPC_REVIEW_NOTE = (
    "This may require review. ConfigTrace does not confirm network intrusion or "
    "unauthorized access."
)

_SG_ADMIN_ACCEPT_RULE = {
    "correlation_key": "aws_sg_public_admin_port_flow",
    "correlation_type": "aws_sg_public_admin_port_flow",
    "action_type": _AWS_FLOW_ACCEPT,
    "phrase": "Security group admin-port exposure aligned with accepted network flow",
    "activity": "accepted VPC network flow to an admin destination port",
}
_SG_DB_ACCEPT_RULE = {
    "correlation_key": "aws_sg_public_database_port_flow",
    "correlation_type": "aws_sg_public_database_port_flow",
    "action_type": _AWS_FLOW_ACCEPT,
    "phrase": "Security group datastore-port exposure aligned with accepted network flow",
    "activity": "accepted VPC network flow to a datastore destination port",
}
_SG_REJECT_RULE = {
    "correlation_key": "aws_sg_public_rejected_flow_activity",
    "correlation_type": "aws_sg_public_rejected_flow_activity",
    "action_type": _AWS_FLOW_REJECT,
    "phrase": "Security group exposure aligned with repeated rejected network flow",
    "activity": "repeated rejected VPC network flow activity to an exposed destination port",
}

# Port set → correlation rule descriptor (accept path).
_SG_PORT_SET_TO_RULE: dict[int, dict[str, Any]] = {}  # keyed by id() for O(1) lookup
_SG_PORT_SET_TO_RULE[id(_SG_ADMIN_PORTS)] = _SG_ADMIN_ACCEPT_RULE
_SG_PORT_SET_TO_RULE[id(_SG_DB_PORTS)] = _SG_DB_ACCEPT_RULE


def _sg_finding_evidence(finding: SecurityFinding) -> dict[str, Any]:
    return finding.evidence if isinstance(finding.evidence, dict) else {}


def _flow_dst_port(ev: SecurityActivityEvent) -> Optional[int]:
    md = ev.event_metadata if isinstance(ev.event_metadata, dict) else {}
    v = md.get("dst_port")
    return v if isinstance(v, int) else None


def _flow_interface(ev: SecurityActivityEvent) -> Optional[str]:
    md = ev.event_metadata if isinstance(ev.event_metadata, dict) else {}
    iface = md.get("interface_id")
    if isinstance(iface, str) and iface:
        return iface
    return ev.resource_id if isinstance(ev.resource_id, str) and ev.resource_id else None


def _port_in_sg_range(dst_port: int, evidence: dict[str, Any]) -> bool:
    """Return True if dst_port falls in the SG rule's exposed port range.

    If from_port/to_port are absent (all-ports rule), every port matches.
    """
    fp = evidence.get("from_port")
    tp = evidence.get("to_port")
    if not isinstance(fp, int) or not isinstance(tp, int):
        return True  # all-ports finding or range info absent → accept any port
    return fp <= dst_port <= tp


def _aws_vpc_flow_anchor(events: list[SecurityActivityEvent]) -> SecurityActivityEvent:
    """Deterministically select the most representative VPC flow event.

    Prefer ACCEPT over REJECT; then latest occurrence time; then id.
    """
    return max(
        events,
        key=lambda e: (
            1 if e.event_type == _AWS_FLOW_ACCEPT else 0,
            _aware(e.occurred_at) or _aware(e.ingested_at)
            or datetime.min.replace(tzinfo=timezone.utc),
            str(e.provider_event_id or ""),
        ),
    )


def build_aws_sg_vpc_flow_correlation(
    *,
    finding: SecurityFinding,
    anchor: SecurityActivityEvent,
    matched: list[SecurityActivityEvent],
    rule: dict[str, Any],
) -> dict[str, Any]:
    """Build an AWS SG exposure × VPC flow correlation dict (not persisted)."""
    _valid_sev = {"critical", "high", "medium", "low", "info"}
    severity = finding.severity if finding.severity in _valid_sev else "high"
    # Rejected flow is weaker evidence → cap severity at medium.
    if rule.get("action_type") == _AWS_FLOW_REJECT:
        if severity in {"critical", "high"}:
            severity = "medium"
        confidence = "low"
    else:
        confidence = "medium"

    md = anchor.event_metadata if isinstance(anchor.event_metadata, dict) else {}
    dst_port = _flow_dst_port(anchor)
    interface = _flow_interface(anchor)
    ev_evidence = _sg_finding_evidence(finding)
    sg_id = ev_evidence.get("group_id")

    f_start = _aware(finding.first_detected_at)
    f_end = _aware(finding.last_seen_at)
    occurred = _aware(anchor.occurred_at)

    window_start = (f_start - WINDOW) if f_start else None
    window_end = (f_end + WINDOW) if f_end else None

    seens = [d for d in (f_start, occurred) if d]
    first_seen = min(seens) if seens else None
    lasts = [d for d in (f_end, occurred) if d]
    last_seen = max(lasts) if lasts else None

    port_label = f"port {dst_port}" if dst_port is not None else "an exposed port"
    title = f"{rule['phrase']} ({port_label})"
    summary = (
        f"An AWS security group exposure risk (\"{finding.title}\") and {rule['activity']} "
        f"were observed within the same AWS account in the review window. "
        f"{_AWS_VPC_REVIEW_NOTE}"
    )

    metadata = sanitize_correlation_metadata({
        "source": _AWS_VPC_FLOW_SOURCE,
        "finding_rule": _base_rule(finding.finding_key),
        "finding_severity": finding.severity,
        "event_type": anchor.event_type,
        "security_group_id": sg_id if isinstance(sg_id, str) else None,
        "dst_port": dst_port,
        "port_category": ev_evidence.get("port_category")
        if isinstance(ev_evidence.get("port_category"), str) else None,
        "interface_id": interface,
        "protocol": md.get("protocol") if isinstance(md.get("protocol"), int) else None,
        "flow_action": md.get("action") if isinstance(md.get("action"), str) else None,
        "event_count": len(matched),
        "window_hours": int(WINDOW.total_seconds() // 3600),
    })

    return {
        "provider": PROVIDER_AWS,
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


def generate_aws_sg_vpc_flow_correlations(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    scan_limit: int = 5000,
) -> dict[str, Any]:
    """Correlate active AWS SG exposure findings with VPC Flow Log activity.

    Conservative + account-scoped: a finding only matches VPC flow events from
    the SAME integration (same AWS account/region) whose destination port falls
    within the SG rule's exposed port range AND within the review window. One
    correlation per (finding, port_category, action_category), anchored to a
    deterministic representative event. Idempotent.
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
        f for f in findings
        if _base_rule(f.finding_key) in _AWS_SG_EXPOSURE_RULES
    ]

    flow_events = (
        db.query(SecurityActivityEvent)
        .filter(
            SecurityActivityEvent.workspace_id == workspace_id,
            SecurityActivityEvent.provider == PROVIDER_AWS,
            SecurityActivityEvent.source == _AWS_VPC_FLOW_SOURCE,
            SecurityActivityEvent.event_type.in_((_AWS_FLOW_ACCEPT, _AWS_FLOW_REJECT)),
            SecurityActivityEvent.occurred_at.isnot(None),
        )
        .limit(scan_limit)
        .all()
    )
    # Only index events that carry a valid dst_port (never correlate portless flows).
    flows_by_integ_type: dict[Any, list[SecurityActivityEvent]] = {}
    for ev in flow_events:
        if ev.integration_id is not None and _flow_dst_port(ev) is not None:
            key = (ev.integration_id, ev.event_type)
            flows_by_integ_type.setdefault(key, []).append(ev)

    created = 0
    skipped = 0
    for finding in findings:
        if finding.integration_id is None:
            continue  # no account scope to match on
        base = _base_rule(finding.finding_key)
        ev_evidence = _sg_finding_evidence(finding)
        target_port_sets = _SG_RULE_PORT_SETS.get(base, [])
        if not target_port_sets:
            continue

        f_start = _aware(finding.first_detected_at)
        f_end = _aware(finding.last_seen_at)
        if f_start is None or f_end is None:
            continue
        window_start = f_start - WINDOW
        window_end = f_end + WINDOW

        # ACCEPT correlations (one per sensitive port set).
        for port_set in target_port_sets:
            rule = _SG_PORT_SET_TO_RULE[id(port_set)]
            candidates = flows_by_integ_type.get(
                (finding.integration_id, _AWS_FLOW_ACCEPT), []
            )
            matched: list[SecurityActivityEvent] = []
            for ev in candidates:
                dst = _flow_dst_port(ev)
                if dst is None or dst not in port_set:
                    continue
                if not _port_in_sg_range(dst, ev_evidence):
                    continue
                occ = _aware(ev.occurred_at)
                if occ is None or not (window_start <= occ <= window_end):
                    continue
                matched.append(ev)
            if not matched:
                continue
            anchor = _aws_vpc_flow_anchor(matched)
            correlation = build_aws_sg_vpc_flow_correlation(
                finding=finding, anchor=anchor, matched=matched, rule=rule,
            )
            outcome, _row = upsert_correlation(
                workspace_id=workspace_id, correlation=correlation, db=db
            )
            if outcome == "created":
                created += 1
            else:
                skipped += 1

        # REJECT correlation — all exposed sensitive ports, threshold-gated.
        all_exposed_ports: frozenset[int] = frozenset().union(*target_port_sets)
        reject_candidates = flows_by_integ_type.get(
            (finding.integration_id, _AWS_FLOW_REJECT), []
        )
        reject_matched: list[SecurityActivityEvent] = []
        for ev in reject_candidates:
            dst = _flow_dst_port(ev)
            if dst is None or dst not in all_exposed_ports:
                continue
            if not _port_in_sg_range(dst, ev_evidence):
                continue
            occ = _aware(ev.occurred_at)
            if occ is None or not (window_start <= occ <= window_end):
                continue
            reject_matched.append(ev)
        if len(reject_matched) >= _SG_REJECT_THRESHOLD:
            anchor = _aws_vpc_flow_anchor(reject_matched)
            correlation = build_aws_sg_vpc_flow_correlation(
                finding=finding, anchor=anchor, matched=reject_matched,
                rule=_SG_REJECT_RULE,
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
        "events_scanned": len(flow_events),
        "correlations_created": created,
        "correlations_skipped": skipped,
    }


# ---------------------------------------------------------------------------
# AWS IAM risk × privilege-chain correlations (M69.3B)
# ---------------------------------------------------------------------------
#
# AWS IAM Configuration Risk findings (``aws_iam_admin_policy_attached`` /
# ``aws_access_key_unused`` from ``security_rules/aws.py``) are correlated with
# M69.3A IAM privilege-chain Incident Signals (``signal_type=
# "aws_iam_privilege_chain"``) when BOTH reference the SAME IAM target entity
# (user/role name) within the finding's review window AND share the same
# integration (same AWS account/region).
#
# JOIN KEY:
#   * same ``integration_id`` (same AWS account/region scope), AND
#   * finding's ``evidence["principal_name"]`` (rule A) or ``evidence["username"]``
#     (rule B), normalized via ``_norm_resource``, matches the chain signal's
#     ``signal_metadata["target_user"]`` / ``signal_metadata["target_role"]`` /
#     ``signal_metadata["resource_name"]`` (already normalized in M69.3A), AND
#   * review window overlap.
#
# ANCHOR: the chain signal's ``linked_activity_event_id`` is used as the
# correlation's activity anchor (the deterministic CloudTrail event from the
# chain). This reuses the existing ``upsert_correlation`` infrastructure and
# gives the correlation a traceable, concrete activity-event link.
#
# CLAIM DISCIPLINE: these are EVIDENCE FOR REVIEW. They NEVER assert compromise,
# unauthorized access, a successful privilege escalation, or an attacker.
#
# PRIVACY: only safe aggregate identifiers are stored (IAM entity names,
# chain_pattern, source_signal_type, event_count, window). NEVER access key
# values, secret keys, session tokens, requestParameters, responseElements,
# raw IPs, user agents, raw CloudTrail JSON, or credentials.

_AWS_IAM_CHAIN_SIGNAL_TYPE = "aws_iam_privilege_chain"

# Map finding base rule → (evidence entity key, chain_pattern filter, rule descriptor).
_AWS_IAM_ADMIN_CHAIN_RULE = {
    "correlation_key": "aws_iam_admin_risk_privilege_chain",
    "correlation_type": "aws_iam_admin_risk_privilege_chain",
    "phrase": "IAM admin-risk aligned with privilege-chain activity",
    "subject": "An AWS IAM admin-policy configuration risk",
    "chain_patterns": None,  # any chain pattern
}
_AWS_IAM_KEY_CHAIN_RULE = {
    "correlation_key": "aws_iam_access_key_risk_privilege_chain",
    "correlation_type": "aws_iam_access_key_risk_privilege_chain",
    "phrase": "IAM access-key risk aligned with access-key creation chain",
    "subject": "An AWS IAM access-key configuration risk",
    "chain_patterns": frozenset({"privilege_grant_access_key"}),
}

_AWS_IAM_CHAIN_FINDING_RULES: dict[str, tuple[str, dict[str, Any]]] = {
    "aws_iam_admin_policy_attached": ("principal_name", _AWS_IAM_ADMIN_CHAIN_RULE),
    "aws_access_key_unused": ("username", _AWS_IAM_KEY_CHAIN_RULE),
}

_AWS_IAM_CHAIN_REVIEW_NOTE = (
    "This may require review. ConfigTrace does not confirm compromise or "
    "unauthorized access."
)


def _iam_signal_targets(sig_md: dict[str, Any]) -> set[str]:
    """Return the set of normalized entity names a chain signal targets."""
    out: set[str] = set()
    for k in ("target_user", "target_role", "resource_name"):
        v = sig_md.get(k)
        n = _norm_resource(v)
        if n:
            out.add(n)
    return out


def build_aws_iam_chain_correlation(
    *,
    finding: SecurityFinding,
    signal: SecurityIncidentSignal,
    rule: dict[str, Any],
) -> Optional[dict[str, Any]]:
    """Build an IAM risk × chain correlation dict (not persisted)."""
    anchor_ev_id = signal.linked_activity_event_id
    if anchor_ev_id is None:
        return None  # no anchor → cannot build a valid correlation

    _valid_sev = {"critical", "high", "medium", "low", "info"}
    severity = finding.severity if finding.severity in _valid_sev else "high"

    sig_md = signal.signal_metadata if isinstance(signal.signal_metadata, dict) else {}
    chain_pattern = sig_md.get("chain_pattern")
    target_user = sig_md.get("target_user")
    target_role = sig_md.get("target_role")
    resource_name = sig_md.get("resource_name")
    entity_label = target_user or target_role or resource_name or "an IAM entity"

    f_start = _aware(finding.first_detected_at)
    f_end = _aware(finding.last_seen_at)
    sig_time = _aware(signal.last_seen_at) or _aware(signal.first_seen_at)

    window_start = (f_start - WINDOW) if f_start else None
    window_end = (f_end + WINDOW) if f_end else None

    seens = [d for d in (f_start, sig_time) if d]
    first_seen = min(seens) if seens else None
    lasts = [d for d in (f_end, sig_time) if d]
    last_seen = max(lasts) if lasts else None

    title = f"{rule['phrase']} ({entity_label})"
    summary = (
        f"{rule['subject']} (\"{finding.title}\") and IAM privilege-chain activity "
        f"(\"{signal.title}\") were observed for the same IAM target entity "
        f"\"{entity_label}\" within the review window. {_AWS_IAM_CHAIN_REVIEW_NOTE}"
    )

    metadata = sanitize_correlation_metadata({
        "source": "cloudtrail",
        "source_signal_type": _AWS_IAM_CHAIN_SIGNAL_TYPE,
        "chain_pattern": chain_pattern,
        "finding_rule": _base_rule(finding.finding_key),
        "finding_severity": finding.severity,
        "event_type": "aws_iam_privilege_chain",
        "target_user": target_user,
        "target_role": target_role,
        "resource_id": resource_name,
        "event_count": sig_md.get("chain_steps"),
        "window_hours": int(WINDOW.total_seconds() // 3600),
    })

    return {
        "provider": PROVIDER_AWS,
        "correlation_key": rule["correlation_key"],
        "correlation_type": rule["correlation_type"],
        "severity": severity,
        # Same IAM account + matching entity name + chain signal is strong
        # circumstantial evidence — calibrated to "high" (same entity match,
        # not just account-level).
        "confidence": "high",
        "status": "open",
        "title": title,
        "summary": summary,
        "linked_finding_id": finding.id,
        "linked_activity_event_id": anchor_ev_id,
        "linked_change_id": finding.linked_change_id,
        "window_start": window_start,
        "window_end": window_end,
        "first_seen_at": first_seen,
        "last_seen_at": last_seen,
        "metadata": metadata,
        "_integration_id": finding.integration_id,
    }


def generate_aws_iam_chain_correlations(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    scan_limit: int = 2000,
) -> dict[str, Any]:
    """Correlate active AWS IAM risk findings with IAM privilege-chain signals.

    Conservative + entity-matched: a finding only matches a chain signal whose
    target IAM entity (target_user / target_role / resource_name, normalized)
    matches the finding's evidence entity (principal_name / username, normalized)
    AND shares the same integration (same AWS account/region), within the
    finding's review window. Idempotent. Returns a generation summary.
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
        f for f in findings
        if _base_rule(f.finding_key) in _AWS_IAM_CHAIN_FINDING_RULES
    ]

    chain_signals = (
        db.query(SecurityIncidentSignal)
        .filter(
            SecurityIncidentSignal.workspace_id == workspace_id,
            SecurityIncidentSignal.provider == PROVIDER_AWS,
            SecurityIncidentSignal.signal_type == _AWS_IAM_CHAIN_SIGNAL_TYPE,
            SecurityIncidentSignal.linked_activity_event_id.isnot(None),
        )
        .limit(scan_limit)
        .all()
    )
    # Index chain signals by (integration_id, normalized_target_entity) for
    # cheap exact lookup. A signal may appear under multiple keys if it has
    # both target_user and resource_name set.
    signals_by_integ_entity: dict[tuple, list[SecurityIncidentSignal]] = {}
    for sig in chain_signals:
        sig_md = sig.signal_metadata if isinstance(sig.signal_metadata, dict) else {}
        targets = _iam_signal_targets(sig_md)
        for entity in targets:
            key = (sig.integration_id, entity)
            signals_by_integ_entity.setdefault(key, []).append(sig)

    created = 0
    skipped = 0
    for finding in findings:
        if finding.integration_id is None:
            continue
        base = _base_rule(finding.finding_key)
        evidence_key, rule = _AWS_IAM_CHAIN_FINDING_RULES[base]
        ev = finding.evidence if isinstance(finding.evidence, dict) else {}
        raw_entity = ev.get(evidence_key)
        entity = _norm_resource(raw_entity)
        if not entity:
            continue  # no safe entity to match on

        f_start = _aware(finding.first_detected_at)
        f_end = _aware(finding.last_seen_at)
        if f_start is None or f_end is None:
            continue
        window_start = f_start - WINDOW
        window_end = f_end + WINDOW
        chain_patterns = rule.get("chain_patterns")

        for sig in signals_by_integ_entity.get((finding.integration_id, entity), []):
            # Chain pattern filter (None = all patterns accepted).
            if chain_patterns is not None:
                sig_md = sig.signal_metadata if isinstance(sig.signal_metadata, dict) else {}
                if sig_md.get("chain_pattern") not in chain_patterns:
                    continue
            # Window gate: signal must have been active within the review window.
            sig_time = _aware(sig.last_seen_at) or _aware(sig.first_seen_at)
            if sig_time is None or not (window_start <= sig_time <= window_end):
                continue
            correlation = build_aws_iam_chain_correlation(
                finding=finding, signal=sig, rule=rule,
            )
            if correlation is None:
                continue
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
        "events_scanned": len(chain_signals),  # signals scanned (schema compat)
        "correlations_created": created,
        "correlations_skipped": skipped,
    }


def generate_aws_correlations(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    scan_limit: int = 1000,
) -> dict[str, Any]:
    """Generate ALL AWS correlations for a workspace (M67.3 + M69.2A + M69.2B + M69.3B).

    provider=aws now generates:
      * Configuration Risk × provider alerts (GuardDuty / Access Analyzer), and
      * S3 public-exposure risk × S3 object-level activity (GetObject / ListBucket
        / object-access spike), and
      * SG public-exposure risk × VPC Flow Log network activity (accepted and
        rejected flows to admin/datastore ports), and
      * IAM configuration risk × IAM privilege-chain signals (entity-matched,
        same AWS account, within review window).
    The returned summary sums all four passes. Idempotent.
    """
    alerts = _generate_aws_alert_correlations(
        workspace_id=workspace_id, db=db, scan_limit=scan_limit
    )
    s3 = generate_aws_s3_exposure_activity_correlations(
        workspace_id=workspace_id, db=db
    )
    sg_vpc = generate_aws_sg_vpc_flow_correlations(
        workspace_id=workspace_id, db=db
    )
    iam_chain = generate_aws_iam_chain_correlations(
        workspace_id=workspace_id, db=db
    )
    return {
        "provider": PROVIDER_AWS,
        "findings_scanned": (
            alerts["findings_scanned"] + s3["findings_scanned"]
            + sg_vpc["findings_scanned"] + iam_chain["findings_scanned"]
        ),
        "events_scanned": (
            alerts["events_scanned"] + s3["events_scanned"]
            + sg_vpc["events_scanned"] + iam_chain["events_scanned"]
        ),
        "correlations_created": (
            alerts["correlations_created"] + s3["correlations_created"]
            + sg_vpc["correlations_created"] + iam_chain["correlations_created"]
        ),
        "correlations_skipped": (
            alerts["correlations_skipped"] + s3["correlations_skipped"]
            + sg_vpc["correlations_skipped"] + iam_chain["correlations_skipped"]
        ),
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
