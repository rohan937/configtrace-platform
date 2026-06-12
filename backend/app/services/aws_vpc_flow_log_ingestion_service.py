"""AWS VPC Flow Logs ingestion (M67.10).

Ingests AWS VPC Flow Logs (the default record format) into the shared
``security_activity_events`` table (``provider="aws"``, ``source="vpc_flow_log"``)
as the network-activity foundation for later network correlation.

INGESTION SOURCE (deliberate, mirrors M67.8): VPC Flow Logs are commonly
delivered to an S3 bucket. This service reads a BOUNDED set of those flow-log
objects (gzip or plaintext) from a caller-supplied ``flow_log_bucket`` /
``flow_log_prefix``, parses the default flow record format, and stores safe,
normalized network-flow activity. It reuses the generic bounded S3 log readers
on the connector (``list_log_objects`` / ``read_log_object_bytes``). No CloudWatch
Logs configuration model is required (a possible future/optional path).

CLAIM DISCIPLINE: these are NETWORK FLOW ACTIVITY events for review. They never
assert a breach, attacker, compromise, unauthorized access, or network intrusion
— only "evidence for review". An accepted flow is just an accepted flow.

NON-FATAL BY DESIGN: every failure (missing permission, missing bucket, malformed
gzip/line, throttling, network) is captured in the returned summary, never raised.

PRIVACY: raw source/destination IPs are NEVER stored — only salted hashes
(``source_ip_hash`` column + ``destination_ip_hash`` metadata). Never raw log
lines, headers, payloads, packet contents, tokens, secrets, or full object paths.

Scope note (M67.10): bounded VPC Flow Log INGESTION only. NOT advanced network
threat detection, NOT Cloudflare, NOT new providers.
"""

from __future__ import annotations

import gzip
import hashlib
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
from app.core.encryption import decrypt_credentials
from app.models.integration import Integration
from app.services import security_activity_event_service as activity_svc

logger = logging.getLogger(__name__)

PROVIDER = "aws"
SOURCE = "vpc_flow_log"

# Default VPC Flow Log v2 fields, in order:
#   version account-id interface-id srcaddr dstaddr srcport dstport protocol
#   packets bytes start end action log-status
_DEFAULT_FIELD_COUNT = 14


def _event_type(action: Optional[str]) -> str:
    if action == "ACCEPT":
        return "aws.vpc.flow.accept"
    if action == "REJECT":
        return "aws.vpc.flow.reject"
    return "aws.vpc.flow.event"


def _none_dash(value: Any) -> Optional[str]:
    """Treat the VPC Flow Log '-' placeholder (and empties) as None."""
    if not isinstance(value, str):
        return None
    v = value.strip()
    return None if (not v or v == "-") else v


def _ip_or_none(value: Any) -> Optional[str]:
    """Return the token only if it looks like an IP (so '-' / junk isn't hashed)."""
    v = _none_dash(value)
    if not v:
        return None
    if "." in v or ":" in v:  # IPv4 or IPv6
        return v
    return None


def _int_or_none(value: Any) -> Optional[int]:
    v = _none_dash(value)
    if v is None:
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _ts_from_epoch(value: Any) -> Optional[datetime]:
    v = _none_dash(value) if isinstance(value, str) else value
    try:
        return datetime.fromtimestamp(float(v), tz=timezone.utc)
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def _dst_hash(ip: Optional[str]) -> Optional[str]:
    """Salted hash of a destination IP (parity with source_ip hashing)."""
    return activity_svc.hash_source_ip(ip) if ip else None


def _fingerprint(parts: list[Optional[str]]) -> str:
    basis = "|".join(p or "" for p in parts)
    return "vpcfl:" + hashlib.sha256(basis.encode("utf-8")).hexdigest()[:40]


def normalize_flow_line(line: str) -> Optional[dict[str, Any]]:
    """Parse one default-format VPC Flow Log line → normalized activity dict.

    Returns None for headers / malformed / non-default lines (skipped safely).
    Raw IPs are hashed; raw line is never stored.
    """
    if not isinstance(line, str):
        return None
    tokens = line.split()
    if len(tokens) < _DEFAULT_FIELD_COUNT:
        return None
    # Header line ("version account-id …") or non-numeric version → skip.
    if not tokens[0].isdigit():
        return None

    (version, account_id, interface_id, srcaddr, dstaddr, srcport, dstport,
     protocol, packets, nbytes, start, end, action, log_status) = tokens[:14]

    action = _none_dash(action)
    src_ip = _ip_or_none(srcaddr)
    dst_ip = _ip_or_none(dstaddr)
    interface = _none_dash(interface_id)
    acct = _none_dash(account_id)

    start_ts = _ts_from_epoch(start)
    end_ts = _ts_from_epoch(end)
    occurred = end_ts or start_ts

    # Deterministic fingerprint from salient (already non-raw-able) fields.
    pe_id = _fingerprint([
        acct, interface,
        activity_svc.hash_source_ip(src_ip) if src_ip else None,
        _dst_hash(dst_ip),
        _none_dash(srcport), _none_dash(dstport), _none_dash(protocol),
        _none_dash(start), _none_dash(end), action,
    ])

    metadata = {
        "version": _int_or_none(version),
        "account_id": acct,
        "interface_id": interface,
        "src_port": _int_or_none(srcport),
        "dst_port": _int_or_none(dstport),
        "protocol": _int_or_none(protocol),
        "packets": _int_or_none(packets),
        "bytes": _int_or_none(nbytes),
        "action": action,
        "log_status": _none_dash(log_status),
        "start_time": start_ts.isoformat() if start_ts else None,
        "end_time": end_ts.isoformat() if end_ts else None,
        "destination_ip_hash": _dst_hash(dst_ip),
    }

    return activity_svc.normalize_activity_event(
        provider=PROVIDER,
        source=SOURCE,
        event_type=_event_type(action),
        occurred_at=occurred,
        provider_event_id=pe_id,
        actor_id=None,
        actor_type="network_flow",
        resource_type="aws_network_interface" if interface else None,
        resource_id=interface,
        # Hashed to source_ip_hash — raw source IP never stored.
        source_ip=src_ip,
        metadata=metadata,
        raw_ref=None,
    )


def _lines_from_object(raw: bytes) -> list[str]:
    """Decode a flow-log object (gzip or plaintext) → text lines. Tolerant."""
    if not raw:
        return []
    text: Optional[str] = None
    try:
        text = gzip.decompress(raw).decode("utf-8", errors="replace")
    except (OSError, EOFError, ValueError):
        try:
            text = raw.decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            return []
    if not text:
        return []
    return [ln for ln in text.splitlines() if ln.strip()]


def _empty_summary(integration_id: Optional[uuid.UUID]) -> dict[str, Any]:
    return {
        "attempted": False,
        "succeeded": False,
        "provider": PROVIDER,
        "integration_id": str(integration_id) if integration_id else None,
        "source": SOURCE,
        "files_seen": 0,
        "files_read": 0,
        "flows_seen": 0,
        "events_inserted": 0,
        "events_skipped": 0,
        "permission_limited": False,
        "error_message": None,
    }


def _finalize(summary: dict[str, Any], *, hard_error: Optional[str]) -> dict[str, Any]:
    if hard_error is not None:
        summary["error_message"] = hard_error
        summary["succeeded"] = False
    else:
        summary["succeeded"] = True
        if summary["permission_limited"] and summary["files_read"] == 0:
            summary["error_message"] = (
                "AWS VPC Flow Log access is limited for these credentials "
                "(s3:ListBucket / s3:GetObject on the flow-log bucket)."
            )
    return summary


def ingest_aws_vpc_flow_logs(
    *,
    integration: Integration,
    workspace_id: uuid.UUID,
    db: Session,
    flow_log_bucket: str,
    flow_log_prefix: Optional[str] = None,
    max_files: int = 20,
    max_events: int = 2000,
) -> dict[str, Any]:
    """Ingest VPC Flow Logs from bounded S3 objects for one AWS integration.

    Never raises. Permission/availability limits → ``permission_limited``; other
    failures → ``error_message`` (safe string).
    """
    summary = _empty_summary(integration.id)
    if integration.provider != PROVIDER:
        summary["error_message"] = "Not an AWS integration."
        return summary
    if not isinstance(flow_log_bucket, str) or not flow_log_bucket.strip():
        summary["error_message"] = "A flow_log_bucket is required."
        return summary
    summary["attempted"] = True

    try:
        credentials = decrypt_credentials(
            integration.encrypted_credentials, integration.credential_iv
        )
    except Exception:  # noqa: BLE001 — never leak credential errors
        logger.warning("aws_vpc_flow: credential resolution failed (not logged)")
        summary["error_message"] = "Could not resolve AWS credentials."
        return summary

    connector = AWSConnector()
    file_cap = max(1, min(int(max_files or 20), 200))
    event_cap = max(1, min(int(max_events or 2000), 50000))

    try:
        keys = connector.list_log_objects(
            credentials, bucket=flow_log_bucket.strip(),
            prefix=flow_log_prefix or None, max_files=file_cap,
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
            return _finalize(summary, hard_error="Flow-log bucket not found.")
        return _finalize(summary, hard_error="Could not list flow-log objects.")
    except RateLimitError:
        return _finalize(summary, hard_error="AWS rate limit reached; try again later.")
    except NetworkError:
        return _finalize(summary, hard_error="Network error reaching AWS.")
    except Exception:  # noqa: BLE001
        logger.exception("aws_vpc_flow: unexpected list error")
        return _finalize(summary, hard_error="Unexpected error listing flow logs.")

    summary["files_seen"] = len(keys)

    seen = inserted = skipped = files_read = 0
    permission_hit = False
    for key in keys:
        if seen >= event_cap:
            break
        try:
            raw = connector.read_log_object_bytes(
                credentials, bucket=flow_log_bucket.strip(), key=key,
            )
        except (AuthenticationError, ConnectorError) as exc:
            if isinstance(exc, AuthenticationError) or getattr(exc, "status_code", None) == 403:
                permission_hit = True
            continue
        except (RateLimitError, NetworkError):
            continue
        except Exception:  # noqa: BLE001
            logger.warning("aws_vpc_flow: failed to read one object; continuing")
            continue

        files_read += 1
        for line in _lines_from_object(raw):
            if seen >= event_cap:
                break
            normalized = normalize_flow_line(line)
            if normalized is None:
                continue
            seen += 1
            try:
                outcome, _row = activity_svc.upsert_activity_event(
                    workspace_id=workspace_id, integration_id=integration.id,
                    normalized=normalized, db=db,
                )
            except Exception:  # noqa: BLE001
                logger.warning("aws_vpc_flow: failed to upsert one flow; continuing")
                continue
            if outcome == "inserted":
                inserted += 1
            else:
                skipped += 1

    summary["files_read"] = files_read
    summary["flows_seen"] = seen
    summary["events_inserted"] = inserted
    summary["events_skipped"] = skipped
    if permission_hit and files_read == 0:
        summary["permission_limited"] = True
    return _finalize(summary, hard_error=None)
