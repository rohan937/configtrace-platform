"""AWS S3 object-level data-event ingestion (M67.8).

Ingests AWS S3 OBJECT-LEVEL CloudTrail DATA events into the shared
``security_activity_events`` table (``provider="aws"``, ``source="s3_data_event"``)
as the foundation for later S3 object-access-spike detection (M67.9+).

INGESTION SOURCE (deliberate): CloudTrail ``LookupEvents`` does NOT return S3
object-level data events — they are only delivered to a configured trail's S3
bucket. So this service reads a BOUNDED set of CloudTrail trail-log objects
(gzipped CloudTrail JSON) from a caller-supplied ``trail_bucket``/``trail_prefix``,
parses them, and keeps ONLY S3 data events. No CloudTrail Lake model is required.

CLAIM DISCIPLINE: these are object-level ACTIVITY events for review. They never
assert a breach, attacker, compromise, unauthorized access, or data exfiltration.

NON-FATAL BY DESIGN: every failure (missing permission, missing bucket, malformed
gzip/JSON, throttling, network) is captured in the returned summary — never
raised out to break a normal AWS sync.

PRIVACY: only allowlisted, flat, safe fields are stored. NEVER the raw object key
(stored as a salted hash; an optional sanitized prefix only), raw CloudTrail JSON,
requestParameters/responseElements, raw source IPs (hashed only), user agents,
headers, cookies, tokens, secrets, access keys, or object contents.

Scope note (M67.8): bounded S3 data-event INGESTION only. NOT object-access-spike
detection, NOT VPC Flow Logs, NOT Cloudflare, NOT new providers.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.config import settings
from app.connectors.aws import AWSConnector
from app.connectors.exceptions import (
    AuthenticationError,
    ConnectorError,
    NetworkError,
    RateLimitError,
)
from app.core.encryption import decrypt_credentials
from app.models.integration import Integration
from app.services import security_activity_event_service as activity_svc

logger = logging.getLogger(__name__)

PROVIDER = "aws"
SOURCE = "s3_data_event"
_S3_EVENT_SOURCE = "s3.amazonaws.com"

# CloudTrail S3 data-event name → normalized event type. Anything else (under the
# S3 data category) falls back to ``aws.s3.data.event`` — no over-normalization.
_EVENT_NAME_MAP: dict[str, str] = {
    "GetObject": "aws.s3.data.get_object",
    "PutObject": "aws.s3.data.put_object",
    "DeleteObject": "aws.s3.data.delete_object",
    "CopyObject": "aws.s3.data.copy_object",
    "ListBucket": "aws.s3.data.list_bucket",
    "HeadObject": "aws.s3.data.head_object",
    "PutObjectAcl": "aws.s3.data.put_object_acl",
}
_FALLBACK_EVENT_TYPE = "aws.s3.data.event"

# Safe top-level prefix pattern (we only keep a short, non-sensitive-looking
# folder name; anything else is omitted so customer data never leaks via the key).
import re  # noqa: E402

_SAFE_PREFIX_RE = re.compile(r"^[A-Za-z0-9._-]{1,32}$")


def _event_type(event_name: Any) -> str:
    if not isinstance(event_name, str) or not event_name:
        return _FALLBACK_EVENT_TYPE
    return _EVENT_NAME_MAP.get(event_name, _FALLBACK_EVENT_TYPE)


def _hash(value: Any, label: str) -> Optional[str]:
    """Salted, truncated hash. Never stores the raw value."""
    if not isinstance(value, str) or not value.strip():
        return None
    key = getattr(settings, "ENCRYPTION_KEY", "") or ""
    salt = (f"s3_data_{label}_v1:" + str(key)).encode("utf-8")
    return hashlib.sha256(salt + value.strip().encode("utf-8")).hexdigest()[:32]


def _safe_prefix(object_key: Any) -> Optional[str]:
    """Return a sanitized top-level prefix of the object key, or None.

    Only the segment before the first '/', kept ONLY if it matches a short, safe
    charset (so a key containing customer data never round-trips into metadata).
    """
    if not isinstance(object_key, str) or not object_key.strip():
        return None
    head = object_key.strip().split("/", 1)[0]
    return head if _SAFE_PREFIX_RE.match(head) else None


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
    if not isinstance(value, str) or not value.strip():
        return None
    v = value.strip()
    if v.lower().endswith("amazonaws.com"):
        return None
    return v


def _principal_name_from_arn(arn: Any) -> Optional[str]:
    if not isinstance(arn, str) or "arn:aws:" not in arn:
        return None
    return (arn.rsplit("/", 1)[-1] if "/" in arn else arn.rsplit(":", 1)[-1]) or None


def _role_name(ui: dict[str, Any]) -> Optional[str]:
    issuer = (ui.get("sessionContext") or {}).get("sessionIssuer") or {}
    name = issuer.get("userName")
    if isinstance(name, str) and name:
        return name
    if ui.get("type") == "AssumedRole":
        return _principal_name_from_arn(issuer.get("arn"))
    return None


def _bucket_name(record: dict[str, Any]) -> Optional[str]:
    """Pull a SAFE bucket name from requestParameters or resources (never a key)."""
    rp = record.get("requestParameters")
    if isinstance(rp, dict):
        b = rp.get("bucketName")
        if isinstance(b, str) and b:
            return b[:200]
    for r in record.get("resources") or []:
        if isinstance(r, dict) and r.get("type") == "AWS::S3::Bucket":
            arn = r.get("ARN")
            if isinstance(arn, str) and arn:
                return arn.rsplit(":", 1)[-1][:200]
    return None


def _object_key(record: dict[str, Any]) -> Optional[str]:
    rp = record.get("requestParameters")
    if isinstance(rp, dict):
        k = rp.get("key")
        if isinstance(k, str) and k:
            return k
    return None


def _bytes_transferred(record: dict[str, Any]) -> Optional[int]:
    aed = record.get("additionalEventData")
    if not isinstance(aed, dict):
        return None
    total = 0
    found = False
    for k in ("bytesTransferredIn", "bytesTransferredOut"):
        v = aed.get(k)
        if isinstance(v, (int, float)):
            total += int(v)
            found = True
    return total if found else None


def is_s3_data_event(record: dict[str, Any]) -> bool:
    """True only for S3 OBJECT-LEVEL data events (never management events)."""
    if not isinstance(record, dict):
        return False
    if record.get("eventSource") != _S3_EVENT_SOURCE:
        return False
    category = record.get("eventCategory")
    if category == "Data":
        return True
    # Older records may omit eventCategory — accept only known data event names.
    if category is None and record.get("eventName") in _EVENT_NAME_MAP:
        return True
    return False


def normalize_s3_data_event(record: dict[str, Any]) -> Optional[dict[str, Any]]:
    """Map one raw CloudTrail S3 data-event record → a normalized activity dict."""
    if not is_s3_data_event(record):
        return None

    event_name = record.get("eventName")
    event_id = record.get("eventID")

    ui = record.get("userIdentity") or {}
    if not isinstance(ui, dict):
        ui = {}
    user_type = ui.get("type")
    user_name = ui.get("userName") or _principal_name_from_arn(ui.get("arn"))
    role_name = _role_name(ui)
    actor_id = user_name or role_name or (user_type if isinstance(user_type, str) else None)

    bucket = _bucket_name(record)
    object_key = _object_key(record)

    metadata = {
        "bucket_name": bucket,
        "object_key_hash": _hash(object_key, "objkey"),
        "object_key_prefix": _safe_prefix(object_key),
        "event_name": event_name if isinstance(event_name, str) else None,
        "event_source": record.get("eventSource"),
        "aws_region": record.get("awsRegion"),
        "account_id": ui.get("accountId") or record.get("recipientAccountId"),
        "recipient_account_id": record.get("recipientAccountId"),
        "user_type": user_type,
        "user_name": user_name,
        "role_name": role_name,
        "read_only": _coerce_bool(record.get("readOnly")),
        "event_category": record.get("eventCategory"),
        "management_event": _coerce_bool(record.get("managementEvent")),
        "bytes_transferred": _bytes_transferred(record),
        "error_code": record.get("errorCode"),
    }

    return activity_svc.normalize_activity_event(
        provider=PROVIDER,
        source=SOURCE,
        event_type=_event_type(event_name),
        occurred_at=_parse_ts(record.get("eventTime")),
        provider_event_id=str(event_id) if event_id else None,
        actor_id=actor_id if isinstance(actor_id, str) else None,
        actor_type=user_type if isinstance(user_type, str) else None,
        resource_type="aws_s3_bucket" if bucket else None,
        resource_id=bucket,
        # Hashed to source_ip_hash by normalize_activity_event — never stored raw.
        source_ip=_safe_source_ip(record.get("sourceIPAddress")),
        metadata=metadata,
        raw_ref=str(event_id) if event_id else None,
    )


def _records_from_object(raw: bytes) -> list[dict[str, Any]]:
    """Decode a trail-log object (gzip or plain JSON) → list of CloudTrail records.

    Tolerant of malformed input: returns ``[]`` rather than raising.
    """
    if not raw:
        return []
    text: Optional[str] = None
    # Try gzip first (CloudTrail trail logs are .json.gz), then plain.
    try:
        text = gzip.decompress(raw).decode("utf-8", errors="replace")
    except (OSError, EOFError, ValueError):
        try:
            text = raw.decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            return []
    if not text:
        return []
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return []
    if isinstance(data, dict):
        recs = data.get("Records")
        return [r for r in recs if isinstance(r, dict)] if isinstance(recs, list) else []
    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)]
    return []


def _empty_summary(integration_id: Optional[uuid.UUID]) -> dict[str, Any]:
    return {
        "attempted": False,
        "succeeded": False,
        "provider": PROVIDER,
        "integration_id": str(integration_id) if integration_id else None,
        "source": SOURCE,
        "files_seen": 0,
        "files_read": 0,
        "events_seen": 0,
        "events_inserted": 0,
        "events_skipped": 0,
        "permission_limited": False,
        "error_message": None,
    }


def ingest_aws_s3_data_events(
    *,
    integration: Integration,
    workspace_id: uuid.UUID,
    db: Session,
    trail_bucket: str,
    trail_prefix: Optional[str] = None,
    max_files: int = 20,
    max_events: int = 1000,
) -> dict[str, Any]:
    """Ingest S3 data events from bounded CloudTrail trail logs for one integration.

    Never raises. Permission/availability limits → ``permission_limited``; other
    failures → ``error_message`` (safe string).
    """
    summary = _empty_summary(integration.id)
    if integration.provider != PROVIDER:
        summary["error_message"] = "Not an AWS integration."
        return summary
    if not isinstance(trail_bucket, str) or not trail_bucket.strip():
        summary["error_message"] = "A trail_bucket is required."
        return summary
    summary["attempted"] = True

    try:
        credentials = decrypt_credentials(
            integration.encrypted_credentials, integration.credential_iv
        )
    except Exception:  # noqa: BLE001 — never leak credential errors
        logger.warning("aws_s3_data: credential resolution failed (not logged)")
        summary["error_message"] = "Could not resolve AWS credentials."
        return summary

    connector = AWSConnector()
    file_cap = max(1, min(int(max_files or 20), 200))
    event_cap = max(1, min(int(max_events or 1000), 20000))

    # ── List bounded set of trail-log objects ──────────────────────────────────
    try:
        keys = connector.list_cloudtrail_log_objects(
            credentials, bucket=trail_bucket.strip(),
            prefix=trail_prefix or None, max_files=file_cap,
        )
    except AuthenticationError:
        summary["permission_limited"] = True
        return _finalize(summary, hard_error=None)
    except ConnectorError as exc:
        code = getattr(exc, "status_code", None)
        if code == 403:
            summary["permission_limited"] = True
            return _finalize(summary, hard_error=None)
        if code == 404:
            return _finalize(summary, hard_error="Trail bucket not found.")
        return _finalize(summary, hard_error="Could not list trail-log objects.")
    except RateLimitError:
        return _finalize(summary, hard_error="AWS rate limit reached; try again later.")
    except NetworkError:
        return _finalize(summary, hard_error="Network error reaching AWS.")
    except Exception:  # noqa: BLE001
        logger.exception("aws_s3_data: unexpected list error")
        return _finalize(summary, hard_error="Unexpected error listing trail logs.")

    summary["files_seen"] = len(keys)

    # ── Read + parse each object, ingest S3 data events only ───────────────────
    seen = inserted = skipped = files_read = 0
    permission_hit = False
    for key in keys:
        if seen >= event_cap:
            break
        try:
            raw = connector.read_cloudtrail_log_object(
                credentials, bucket=trail_bucket.strip(), key=key,
            )
        except (AuthenticationError, ConnectorError) as exc:
            if isinstance(exc, AuthenticationError) or getattr(exc, "status_code", None) == 403:
                permission_hit = True
            continue  # one unreadable object never fails the batch
        except (RateLimitError, NetworkError):
            continue
        except Exception:  # noqa: BLE001
            logger.warning("aws_s3_data: failed to read one trail object; continuing")
            continue

        files_read += 1
        for record in _records_from_object(raw):
            if seen >= event_cap:
                break
            normalized = normalize_s3_data_event(record)
            if normalized is None:
                continue  # not an S3 data event
            seen += 1
            try:
                outcome, _row = activity_svc.upsert_activity_event(
                    workspace_id=workspace_id, integration_id=integration.id,
                    normalized=normalized, db=db,
                )
            except Exception:  # noqa: BLE001
                logger.warning("aws_s3_data: failed to upsert one event; continuing")
                continue
            if outcome == "inserted":
                inserted += 1
            else:
                skipped += 1

    summary["files_read"] = files_read
    summary["events_seen"] = seen
    summary["events_inserted"] = inserted
    summary["events_skipped"] = skipped
    if permission_hit and files_read == 0:
        summary["permission_limited"] = True
    return _finalize(summary, hard_error=None)


def _finalize(summary: dict[str, Any], *, hard_error: Optional[str]) -> dict[str, Any]:
    if hard_error is not None:
        summary["error_message"] = hard_error
        summary["succeeded"] = False
    else:
        summary["succeeded"] = True
        if summary["permission_limited"] and summary["files_read"] == 0:
            summary["error_message"] = (
                "AWS S3 trail-log access is limited for these credentials "
                "(s3:ListBucket / s3:GetObject on the trail bucket)."
            )
    return summary
