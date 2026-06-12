"""AWS CloudTrail management-event ingestion (M67.5).

Ingests AWS CloudTrail MANAGEMENT (control-plane) events into the shared
``security_activity_events`` table (``provider="aws"``, ``source="cloudtrail"``).
This is the raw AWS activity foundation for later IAM behavior timelines and
advanced correlations (M67.6+).

CLAIM DISCIPLINE: this ingests CloudTrail control-plane ACTIVITY. It does NOT
confirm a breach, identify an attacker, or confirm unauthorized access. Events
are "evidence for review".

NON-FATAL BY DESIGN: every failure (missing permission, CloudTrail unavailable,
region unsupported, throttling, network) is captured in the returned summary —
this never raises out to break a normal AWS config sync.

PRIVACY: only allowlisted, flat, safe fields are stored (event name/source,
region, account, user type/name, role name, safe resource id, error code,
read-only/management flags). NEVER the raw CloudTrail event JSON,
requestParameters/responseElements blobs, access keys, secrets, session tokens,
or raw source IPs. A source IP, when present, is stored ONLY as a salted hash;
the IAM principalId is stored only as a salted hash.

Scope note (M67.5): CloudTrail management events only. NOT S3 trail-file
parsing, NOT data events, NOT VPC Flow Logs, NOT IAM behavior timelines, NOT
Security Hub, NOT object-access-spike detection.
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.connectors.aws import AWSConnector
from app.connectors.exceptions import (
    AuthenticationError,
    ConnectorError,
    NetworkError,
    RateLimitError,
)
from app.config import settings
from app.core.encryption import decrypt_credentials
from app.models.integration import Integration
from app.services import security_activity_event_service as activity_svc

logger = logging.getLogger(__name__)

PROVIDER = "aws"
SOURCE = "cloudtrail"

# CloudTrail EventName → normalized event_type. Only high-signal control-plane
# events are mapped; anything else falls back to ``aws.cloudtrail.event`` (we do
# NOT over-normalize unknown events).
_EVENT_NAME_MAP: dict[str, str] = {
    "ConsoleLogin": "aws.cloudtrail.console_login",
    "CreateAccessKey": "aws.iam.create_access_key",
    "DeleteAccessKey": "aws.iam.delete_access_key",
    "AttachUserPolicy": "aws.iam.attach_user_policy",
    "AttachRolePolicy": "aws.iam.attach_role_policy",
    "PutUserPolicy": "aws.iam.put_user_policy",
    "PutRolePolicy": "aws.iam.put_role_policy",
    "CreateUser": "aws.iam.create_user",
    "CreateRole": "aws.iam.create_role",
    "UpdateAssumeRolePolicy": "aws.iam.update_assume_role_policy",
    "PutBucketPolicy": "aws.s3.put_bucket_policy",
    "PutBucketAcl": "aws.s3.put_bucket_acl",
    "PutPublicAccessBlock": "aws.s3.put_public_access_block",
    "AuthorizeSecurityGroupIngress": "aws.ec2.authorize_security_group_ingress",
    "RevokeSecurityGroupIngress": "aws.ec2.revoke_security_group_ingress",
    "DisableKey": "aws.kms.disable_key",
    "ScheduleKeyDeletion": "aws.kms.schedule_key_deletion",
}

_FALLBACK_EVENT_TYPE = "aws.cloudtrail.event"


def _event_type(event_name: Any) -> str:
    if not isinstance(event_name, str) or not event_name:
        return _FALLBACK_EVENT_TYPE
    return _EVENT_NAME_MAP.get(event_name, _FALLBACK_EVENT_TYPE)


def _principal_hash(value: Any) -> Optional[str]:
    """Salted, truncated hash of an IAM principalId. Never stores the raw value."""
    if not isinstance(value, str) or not value.strip():
        return None
    key = getattr(settings, "ENCRYPTION_KEY", "") or ""
    salt = ("ct_principal_v1:" + str(key)).encode("utf-8")
    return hashlib.sha256(salt + value.strip().encode("utf-8")).hexdigest()[:32]


def _parse_ts(raw: Any) -> Optional[datetime]:
    if raw is None:
        return None
    try:
        if isinstance(raw, datetime):
            return raw if raw.tzinfo else raw.replace(tzinfo=timezone.utc)
        if isinstance(raw, (int, float)):
            return datetime.fromtimestamp(float(raw), tz=timezone.utc)
        if isinstance(raw, str):
            return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except (ValueError, OverflowError, OSError):
        return None
    return None


def _coerce_bool(value: Any) -> Optional[bool]:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        if value.lower() == "true":
            return True
        if value.lower() == "false":
            return False
    return None


def _safe_source_ip(value: Any) -> Optional[str]:
    """Return a source IP suitable for hashing, or None.

    CloudTrail's ``sourceIPAddress`` is sometimes an AWS service principal
    (e.g. "cloudformation.amazonaws.com") rather than an IP. We never store the
    raw value either way; this just avoids hashing meaningless service names.
    """
    if not isinstance(value, str) or not value.strip():
        return None
    v = value.strip()
    if v.lower().endswith("amazonaws.com"):
        return None
    return v


def _principal_name_from_arn(arn: Any) -> Optional[str]:
    if not isinstance(arn, str) or "arn:aws:" not in arn:
        return None
    tail = arn.rsplit("/", 1)[-1] if "/" in arn else arn.rsplit(":", 1)[-1]
    return tail or None


def _role_name(user_identity: dict[str, Any]) -> Optional[str]:
    """Best-effort role name for an assumed-role session (no blob traversal)."""
    sess = user_identity.get("sessionContext") or {}
    issuer = sess.get("sessionIssuer") or {}
    name = issuer.get("userName")
    if isinstance(name, str) and name:
        return name
    if user_identity.get("type") == "AssumedRole":
        return _principal_name_from_arn(issuer.get("arn"))
    return None


def _resource_fields(event: dict[str, Any]) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """Return (resource_type, resource_name, resource_arn) from event Resources."""
    resources = event.get("Resources") or []
    if not isinstance(resources, list):
        return None, None, None
    for r in resources:
        if not isinstance(r, dict):
            continue
        name = r.get("ResourceName")
        rtype = r.get("ResourceType")
        if isinstance(name, str) and name:
            arn = name if name.startswith("arn:aws:") else None
            return (rtype if isinstance(rtype, str) else None), name, arn
    return None, None, None


def normalize_cloudtrail_event(event: dict[str, Any]) -> Optional[dict[str, Any]]:
    """Map a raw CloudTrail LookupEvents item to a normalized activity-event dict.

    Parses the embedded ``CloudTrailEvent`` JSON string only to extract safe,
    flat fields — the raw JSON / requestParameters / responseElements are never
    stored. Returns None for an unusable record.
    """
    if not isinstance(event, dict):
        return None

    detail: dict[str, Any] = {}
    raw_detail = event.get("CloudTrailEvent")
    if isinstance(raw_detail, str) and raw_detail:
        try:
            parsed = json.loads(raw_detail)
            if isinstance(parsed, dict):
                detail = parsed
        except (ValueError, TypeError):
            detail = {}
    elif isinstance(raw_detail, dict):  # tolerate pre-parsed dicts (tests/mocks)
        detail = raw_detail

    event_name = event.get("EventName") or detail.get("eventName")
    event_id = event.get("EventId") or detail.get("eventID")

    user_identity = detail.get("userIdentity") or {}
    if not isinstance(user_identity, dict):
        user_identity = {}
    user_type = user_identity.get("type")
    user_name = (
        user_identity.get("userName")
        or event.get("Username")
        or _principal_name_from_arn(user_identity.get("arn"))
    )
    role_name = _role_name(user_identity)

    # A safe control-plane identity for the actor column (never a secret).
    actor_id = (
        user_name
        or role_name
        or (user_type if isinstance(user_type, str) else None)
    )

    rtype, resource_name, resource_arn = _resource_fields(event)

    read_only = _coerce_bool(detail.get("readOnly"))
    if read_only is None:
        read_only = _coerce_bool(event.get("ReadOnly"))

    metadata = {
        "event_name": event_name if isinstance(event_name, str) else None,
        "event_source": detail.get("eventSource") or event.get("EventSource"),
        "aws_region": detail.get("awsRegion") or event.get("_Region"),
        "account_id": user_identity.get("accountId") or detail.get("recipientAccountId"),
        "recipient_account_id": detail.get("recipientAccountId"),
        "user_type": user_type,
        "principal_id_hash": _principal_hash(user_identity.get("principalId")),
        "user_name": user_name,
        "role_name": role_name,
        "resource_name": resource_name,
        "resource_arn": resource_arn,
        "error_code": detail.get("errorCode"),
        "read_only": read_only,
        "event_category": detail.get("eventCategory"),
        "management_event": _coerce_bool(detail.get("managementEvent")),
    }

    return activity_svc.normalize_activity_event(
        provider=PROVIDER,
        source=SOURCE,
        event_type=_event_type(event_name),
        occurred_at=_parse_ts(event.get("EventTime") or detail.get("eventTime")),
        provider_event_id=str(event_id) if event_id else None,
        actor_id=actor_id if isinstance(actor_id, str) else None,
        actor_type=user_type if isinstance(user_type, str) else None,
        resource_type=rtype,
        resource_id=resource_name or resource_arn,
        # Hashed to source_ip_hash by normalize_activity_event — never stored raw.
        source_ip=_safe_source_ip(detail.get("sourceIPAddress")),
        metadata=metadata,
        raw_ref=str(event_id) if event_id else None,
    )


def _empty_summary(integration_id: Optional[uuid.UUID]) -> dict[str, Any]:
    return {
        "attempted": False,
        "succeeded": False,
        "provider": PROVIDER,
        "integration_id": str(integration_id) if integration_id else None,
        "source": SOURCE,
        "events_seen": 0,
        "events_inserted": 0,
        "events_skipped": 0,
        "permission_limited": False,
        "error_message": None,
    }


def _store(workspace_id, integration_id, events, db) -> tuple[int, int, int]:
    """Normalize + idempotently upsert events. Returns (seen, inserted, skipped)."""
    seen = inserted = skipped = 0
    for e in events:
        seen += 1
        normalized = normalize_cloudtrail_event(e)
        if normalized is None:
            continue
        try:
            outcome, _row = activity_svc.upsert_activity_event(
                workspace_id=workspace_id, integration_id=integration_id,
                normalized=normalized, db=db,
            )
        except Exception:  # noqa: BLE001 — one bad row never fails the batch
            logger.warning("aws_cloudtrail: failed to upsert one event; continuing")
            continue
        if outcome == "inserted":
            inserted += 1
        else:
            skipped += 1
    return seen, inserted, skipped


def ingest_aws_cloudtrail_events(
    *,
    integration: Integration,
    workspace_id: uuid.UUID,
    db: Session,
    lookback_hours: int = 24,
    max_pages: int = 2,
) -> dict[str, Any]:
    """Ingest CloudTrail management events for one AWS integration.

    Never raises. Permission/availability limits are reported via
    ``permission_limited``; other failures via ``error_message`` (safe string).
    """
    summary = _empty_summary(integration.id)
    if integration.provider != PROVIDER:
        summary["error_message"] = "Not an AWS integration."
        return summary
    summary["attempted"] = True

    try:
        credentials = decrypt_credentials(
            integration.encrypted_credentials, integration.credential_iv
        )
    except Exception:  # noqa: BLE001 — never leak credential errors
        logger.warning("aws_cloudtrail: credential resolution failed (not logged)")
        summary["error_message"] = "Could not resolve AWS credentials."
        return summary

    connector = AWSConnector()
    hard_error: Optional[str] = None

    try:
        events = connector.lookup_cloudtrail_events(
            credentials, lookback_hours=lookback_hours, max_pages=max_pages
        )
    except AuthenticationError:
        summary["permission_limited"] = True
        events = []
    except ConnectorError as exc:
        events = []
        code = getattr(exc, "status_code", None)
        if code == 403:
            summary["permission_limited"] = True
        elif code == 503:
            hard_error = "AWS CloudTrail is temporarily unavailable in this region."
        else:
            hard_error = "CloudTrail request failed (it may be unavailable in this region)."
    except RateLimitError:
        events = []
        hard_error = "AWS rate limit reached; try again later."
    except NetworkError:
        events = []
        hard_error = "Network error reaching AWS."
    except Exception:  # noqa: BLE001
        logger.exception("aws_cloudtrail: unexpected lookup error")
        events = []
        hard_error = "Unexpected error ingesting CloudTrail events."

    seen, inserted, skipped = _store(workspace_id, integration.id, events, db)
    summary["events_seen"] = seen
    summary["events_inserted"] = inserted
    summary["events_skipped"] = skipped

    if hard_error is not None:
        summary["error_message"] = hard_error
        summary["succeeded"] = False
    else:
        summary["succeeded"] = True
        if summary["permission_limited"] and seen == 0:
            summary["error_message"] = (
                "AWS CloudTrail access is limited for these credentials "
                "(cloudtrail:LookupEvents permission, or CloudTrail not available "
                "in this region)."
            )
    return summary
