"""Normalized security activity-event storage (M66.2).

The data spine for the future Incident Signals product. Provider-agnostic
helpers to normalize, sanitize, fingerprint, idempotently store, and list
control-plane activity events (GitHub audit-log events initially).

CLAIM DISCIPLINE: this module stores normalized *activity events* only. It does
NOT detect breaches, identify attackers, or confirm compromise. Correlation that
turns activity + configuration risk into incident signals is a future milestone.

Privacy contract (mirrors security_beta_event_service):
  * ``metadata`` keys not in ALLOWED_METADATA_KEYS are silently dropped.
  * Only scalar values (str/int/float/bool) are kept; nested objects/arrays
    dropped; strings truncated to MAX_STR_LEN.
  * Source IP, if present, is stored ONLY as a salted hash — never raw.
  * Raw request bodies / full audit payloads / secrets / tokens are never stored.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime
from typing import Any, Optional

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import settings
from app.models.security_activity_event import SecurityActivityEvent

# Small allowlist of non-sensitive metadata keys. Anything else is dropped.
ALLOWED_METADATA_KEYS: frozenset[str] = frozenset(
    {
        "action",            # raw provider action string (e.g. "protected_branch.destroy")
        "repository",        # "owner/repo"
        "visibility",        # public/private/internal
        "ref",               # branch/ref name
        "hook_id",           # webhook id
        "permission",        # permission level name
        "alert_number",      # secret-scanning alert number
        "target_login",      # affected collaborator login (control-plane)
        "ruleset_name",      # ruleset name
        "transport",         # http/https for a webhook target
        # AWS provider security-alert fields (M67.1) — GuardDuty / Access Analyzer.
        "finding_type",      # GuardDuty Type / Access Analyzer finding type
        "severity_label",    # critical/high/medium/low (derived)
        "severity_score",    # numeric provider severity
        "title",             # safe provider finding title
        "account_id",        # AWS account id
        "region",            # AWS region
        "service_name",      # GuardDuty service name
        "detector_id",       # GuardDuty detector id
        "analyzer_arn",      # Access Analyzer analyzer ARN
        "finding_status",    # ACTIVE/ARCHIVED/RESOLVED
        # AWS CloudTrail management-event fields (M67.5) — control-plane activity.
        "event_name",        # CloudTrail EventName (e.g. "CreateAccessKey")
        "event_source",      # CloudTrail eventSource (e.g. "iam.amazonaws.com")
        "aws_region",        # CloudTrail awsRegion
        "user_type",         # userIdentity.type (IAMUser / AssumedRole / Root / …)
        "principal_id_hash", # salted hash of userIdentity.principalId (never raw)
        "user_name",         # IAM user name (control-plane identity)
        "role_name",         # IAM role name (assumed-role session issuer)
        "resource_name",     # safe resource identifier from event Resources
        "resource_arn",      # safe resource ARN from event Resources
        "error_code",        # CloudTrail errorCode (e.g. "AccessDenied")
        "read_only",         # whether the API call was read-only
        "event_category",    # "Management" (data events are out of scope)
        "management_event",  # whether CloudTrail flagged this a management event
        "recipient_account_id",  # account the event was delivered to
        # AWS Security Hub (ASFF) fields (M67.7) — provider-reported findings.
        "finding_title",     # ASFF Title
        "finding_description",  # ASFF Description (truncated)
        "severity_normalized",  # ASFF Severity.Normalized (0-100)
        "workflow_status",   # ASFF Workflow.Status (NEW/NOTIFIED/RESOLVED/…)
        "record_state",      # ASFF RecordState (ACTIVE/ARCHIVED)
        "compliance_status", # ASFF Compliance.Status (PASSED/FAILED/…)
        "product_name",      # ASFF ProductName (GuardDuty/Inspector/Macie/…)
        "company_name",      # ASFF CompanyName
        "generator_id",      # ASFF GeneratorId (safe rule/control id)
        "created_at",        # ASFF CreatedAt (ISO string)
        "updated_at",        # ASFF UpdatedAt (ISO string)
    }
)

MAX_STR_LEN = 200
MAX_METADATA_KEYS = 20


def sanitize_activity_metadata(raw: Optional[dict[str, Any]]) -> dict[str, Any]:
    """Return a safe, allowlisted, truncated copy of metadata.

    Drops unknown keys, drops nested/complex values, truncates strings. This is
    the privacy gate: secrets/tokens/raw payloads are never on the allowlist, so
    they can never be stored even if a caller passes them.
    """
    if not isinstance(raw, dict):
        return {}
    out: dict[str, Any] = {}
    for key, value in raw.items():
        if key not in ALLOWED_METADATA_KEYS:
            continue  # strip unknown / forbidden keys (secrets, tokens, payloads…)
        if isinstance(value, bool):
            out[key] = value
        elif isinstance(value, (int, float)):
            out[key] = value
        elif isinstance(value, str):
            out[key] = value[:MAX_STR_LEN]
        else:
            # Drop None, dicts, lists, and anything else — keep payload flat/safe.
            continue
        if len(out) >= MAX_METADATA_KEYS:
            break
    return out


def _ip_salt() -> bytes:
    """Stable salt for IP hashing.

    Deterministic across runs so re-ingesting the same event yields the same
    hash. Tied to the app encryption key so hashes are not trivially reversible
    via a precomputed rainbow table of the small IPv4 space.
    """
    key = getattr(settings, "ENCRYPTION_KEY", "") or ""
    return ("ct_activity_ip_v1:" + str(key)).encode("utf-8")


def hash_source_ip(ip: Optional[str]) -> Optional[str]:
    """Return a salted, truncated hash of an IP — or None. Never stores raw IP."""
    if not isinstance(ip, str) or not ip.strip():
        return None
    digest = hashlib.sha256(_ip_salt() + ip.strip().encode("utf-8")).hexdigest()
    return digest[:32]


def compute_event_fingerprint(
    *,
    provider: str,
    source: str,
    event_type: str,
    actor_id: Optional[str],
    resource_id: Optional[str],
    occurred_at: Optional[datetime],
) -> str:
    """Deterministic fallback id when the provider gives no stable event id.

    Returns an ``fp:<hash>`` string so the same uniqueness/idempotency guarantee
    (unique on provider_event_id) applies whether or not the provider supplied an
    id.
    """
    occ = occurred_at.isoformat() if isinstance(occurred_at, datetime) else ""
    basis = "|".join(
        [provider, source, event_type, actor_id or "", resource_id or "", occ]
    )
    digest = hashlib.sha256(basis.encode("utf-8")).hexdigest()
    return f"fp:{digest[:40]}"


def normalize_activity_event(
    *,
    provider: str,
    source: str,
    event_type: str,
    occurred_at: Optional[datetime] = None,
    provider_event_id: Optional[str] = None,
    actor_id: Optional[str] = None,
    actor_type: Optional[str] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    source_ip: Optional[str] = None,
    metadata: Optional[dict[str, Any]] = None,
    raw_ref: Optional[str] = None,
) -> dict[str, Any]:
    """Build a clean, privacy-safe normalized event dict ready for upsert.

    Hashes the IP, sanitizes metadata, and supplies a deterministic fingerprint
    when no stable provider event id is present.
    """
    pe_id = provider_event_id if (provider_event_id and str(provider_event_id).strip()) else None
    if pe_id is None:
        pe_id = compute_event_fingerprint(
            provider=provider,
            source=source,
            event_type=event_type,
            actor_id=actor_id,
            resource_id=resource_id,
            occurred_at=occurred_at,
        )
    return {
        "provider": provider,
        "source": source,
        "event_type": event_type,
        "provider_event_id": pe_id,
        "occurred_at": occurred_at,
        "actor_id": (actor_id[:MAX_STR_LEN] if isinstance(actor_id, str) else None),
        "actor_type": (actor_type[:MAX_STR_LEN] if isinstance(actor_type, str) else None),
        "resource_type": (resource_type[:MAX_STR_LEN] if isinstance(resource_type, str) else None),
        "resource_id": (resource_id[:MAX_STR_LEN] if isinstance(resource_id, str) else None),
        "source_ip_hash": hash_source_ip(source_ip),
        "metadata": sanitize_activity_metadata(metadata),
        "raw_ref": (raw_ref[:MAX_STR_LEN] if isinstance(raw_ref, str) else None),
    }


def upsert_activity_event(
    *,
    workspace_id: uuid.UUID,
    integration_id: Optional[uuid.UUID],
    normalized: dict[str, Any],
    db: Session,
) -> tuple[str, SecurityActivityEvent]:
    """Idempotently store a normalized event.

    Returns ``("inserted", row)`` for a new event or ``("skipped", row)`` if an
    event with the same ``(workspace_id, provider, source, provider_event_id)``
    already exists. Re-ingesting the same provider event is a safe no-op.
    """
    provider = normalized["provider"]
    source = normalized["source"]
    provider_event_id = normalized.get("provider_event_id")

    existing = _find_existing(
        db,
        workspace_id=workspace_id,
        provider=provider,
        source=source,
        provider_event_id=provider_event_id,
    )
    if existing is not None:
        return "skipped", existing

    event = SecurityActivityEvent(
        workspace_id=workspace_id,
        integration_id=integration_id,
        provider=provider,
        source=source,
        provider_event_id=provider_event_id,
        event_type=normalized["event_type"],
        actor_id=normalized.get("actor_id"),
        actor_type=normalized.get("actor_type"),
        resource_type=normalized.get("resource_type"),
        resource_id=normalized.get("resource_id"),
        source_ip_hash=normalized.get("source_ip_hash"),
        occurred_at=normalized.get("occurred_at"),
        event_metadata=normalized.get("metadata") or {},
        raw_ref=normalized.get("raw_ref"),
    )
    db.add(event)
    try:
        db.commit()
    except IntegrityError:
        # Concurrent insert of the same event hit the unique index — treat as skip.
        db.rollback()
        existing = _find_existing(
            db,
            workspace_id=workspace_id,
            provider=provider,
            source=source,
            provider_event_id=provider_event_id,
        )
        if existing is not None:
            return "skipped", existing
        raise
    db.refresh(event)
    return "inserted", event


def _find_existing(
    db: Session,
    *,
    workspace_id: uuid.UUID,
    provider: str,
    source: str,
    provider_event_id: Optional[str],
) -> Optional[SecurityActivityEvent]:
    if not provider_event_id:
        return None
    return (
        db.query(SecurityActivityEvent)
        .filter(
            SecurityActivityEvent.workspace_id == workspace_id,
            SecurityActivityEvent.provider == provider,
            SecurityActivityEvent.source == source,
            SecurityActivityEvent.provider_event_id == provider_event_id,
        )
        .first()
    )


def list_activity_events(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    provider: Optional[str] = None,
    event_type: Optional[str] = None,
    page: int = 1,
    page_size: int = 50,
) -> tuple[list[SecurityActivityEvent], int]:
    """Return a paginated, workspace-scoped list of activity events.

    Newest activity first (by ``occurred_at``, then ingestion order). Strictly
    workspace-scoped — never returns another workspace's events.
    """
    page = max(1, page)
    page_size = max(1, min(page_size, 100))

    q = db.query(SecurityActivityEvent).filter(
        SecurityActivityEvent.workspace_id == workspace_id
    )
    if provider:
        q = q.filter(SecurityActivityEvent.provider == provider)
    if event_type:
        q = q.filter(SecurityActivityEvent.event_type == event_type)

    total = q.count()
    items = (
        q.order_by(
            SecurityActivityEvent.occurred_at.desc().nullslast(),
            SecurityActivityEvent.created_at.desc(),
        )
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return items, total


def get_activity_event(
    *,
    event_id: uuid.UUID,
    workspace_id: uuid.UUID,
    db: Session,
) -> Optional[SecurityActivityEvent]:
    """Return a single activity event scoped to the workspace, or None (→ 404).

    Strictly workspace-scoped — never returns another workspace's event.
    """
    return (
        db.query(SecurityActivityEvent)
        .filter(
            SecurityActivityEvent.id == event_id,
            SecurityActivityEvent.workspace_id == workspace_id,
        )
        .first()
    )
