"""AWS security-alert ingestion — GuardDuty / Access Analyzer (M67.1).

Ingests provider-ADJUDICATED AWS security findings (GuardDuty, IAM Access
Analyzer) into the shared ``security_activity_events`` table
(``provider="aws"``, ``source="security_alert"``), so they can become AWS
Incident Signals.

CLAIM DISCIPLINE: this ingests provider-REPORTED findings. It does NOT confirm a
breach, identify an attacker, or confirm unauthorized access. Findings become
"evidence for review" Incident Signals.

NON-FATAL BY DESIGN: every failure (missing permission, GuardDuty not enabled, no
analyzer, throttling, network) is captured in the returned summary — this never
raises out to break a normal AWS config sync.

PRIVACY: only allowlisted safe fields are stored (finding type/severity/title/
account/region/detector). NEVER the raw finding JSON, raw IPs (we do not traverse
to network payloads), access keys, secrets, or tokens.

Scope note (M67.1): GuardDuty + Access Analyzer only. NOT CloudTrail, NOT VPC
Flow Logs, NOT S3 data events, NOT AWS risk×activity correlation.
"""

from __future__ import annotations

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
SOURCE = "security_alert"

# GuardDuty Type prefix (threat purpose) → normalized event_type.
_GD_CATEGORY: dict[str, str] = {
    "UnauthorizedAccess": "aws.guardduty.unauthorized_access",
    "CredentialAccess": "aws.guardduty.credential_access",
    "Persistence": "aws.guardduty.persistence",
    "Discovery": "aws.guardduty.discovery",
    "Exfiltration": "aws.guardduty.exfiltration",
    "PrivilegeEscalation": "aws.guardduty.privilege_escalation",
    "DefenseEvasion": "aws.guardduty.defense_evasion",
    "Impact": "aws.guardduty.impact",
    "Execution": "aws.guardduty.execution",
    "InitialAccess": "aws.guardduty.initial_access",
    "Policy": "aws.guardduty.policy",
}


def _gd_event_type(type_str: Optional[str]) -> str:
    if not isinstance(type_str, str) or ":" not in type_str:
        return "aws.guardduty.finding"
    prefix = type_str.split(":", 1)[0]
    return _GD_CATEGORY.get(prefix, "aws.guardduty.finding")


def _severity_label(score: Any) -> str:
    """Map a GuardDuty numeric severity to a review-priority label."""
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "medium"
    if s >= 8.0:
        return "critical"
    if s >= 7.0:
        return "high"
    if s >= 4.0:
        return "medium"
    return "low"


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


def _gd_resource_id(resource: dict[str, Any]) -> Optional[str]:
    """Pull a SAFE resource identifier from a GuardDuty Resource (never a secret)."""
    if not isinstance(resource, dict):
        return None
    rtype = resource.get("ResourceType")
    if rtype == "Instance":
        return (resource.get("InstanceDetails") or {}).get("InstanceId")
    if rtype == "AccessKey":
        # The IAM user name is an identifier; the access key ID/secret is NOT stored.
        return (resource.get("AccessKeyDetails") or {}).get("UserName")
    if rtype == "S3Bucket":
        buckets = resource.get("S3BucketDetails") or []
        if isinstance(buckets, list) and buckets:
            return buckets[0].get("Name")
    return None


def normalize_guardduty_finding(f: dict[str, Any]) -> Optional[dict[str, Any]]:
    """Map a raw GuardDuty finding to a normalized activity-event dict, or None."""
    if not isinstance(f, dict):
        return None
    fid = f.get("Id")
    if not fid:
        return None
    ftype = f.get("Type", "")
    service = f.get("Service") or {}
    resource = f.get("Resource") or {}
    score = f.get("Severity")
    metadata = {
        "finding_type": ftype,
        "severity_label": _severity_label(score),
        "severity_score": score if isinstance(score, (int, float)) else None,
        "title": f.get("Title"),
        "account_id": f.get("AccountId"),
        "region": f.get("Region"),
        "service_name": service.get("ServiceName"),
        "detector_id": f.get("_DetectorId") or service.get("DetectorId"),
    }
    return activity_svc.normalize_activity_event(
        provider=PROVIDER,
        source=SOURCE,
        event_type=_gd_event_type(ftype),
        occurred_at=_parse_ts(f.get("UpdatedAt") or f.get("CreatedAt")),
        provider_event_id=str(fid),
        actor_id=None,
        actor_type="provider_finding",
        resource_type=resource.get("ResourceType"),
        resource_id=_gd_resource_id(resource),
        source_ip=None,  # never traverse GuardDuty network payloads for raw IPs
        metadata=metadata,
        raw_ref=str(fid),
    )


def normalize_access_analyzer_finding(f: dict[str, Any]) -> Optional[dict[str, Any]]:
    """Map a raw Access Analyzer finding to a normalized activity-event dict, or None."""
    if not isinstance(f, dict):
        return None
    fid = f.get("id")
    if not fid:
        return None
    resource = f.get("resource")
    rtype = f.get("resourceType")
    metadata = {
        "finding_type": rtype,
        # External/public access findings are higher review priority.
        "severity_label": "high" if f.get("isPublic") else "medium",
        "title": resource if isinstance(resource, str) else None,
        "region": f.get("region"),
        "analyzer_arn": f.get("_AnalyzerArn"),
        "finding_status": f.get("status"),
    }
    return activity_svc.normalize_activity_event(
        provider=PROVIDER,
        source=SOURCE,
        event_type="aws.access_analyzer.finding",
        occurred_at=_parse_ts(f.get("updatedAt") or f.get("createdAt")),
        provider_event_id=str(fid),
        actor_id=None,
        actor_type="provider_finding",
        resource_type=rtype,
        resource_id=resource if isinstance(resource, str) else None,
        metadata=metadata,
        raw_ref=str(fid),
    )


def _empty_summary(integration_id: Optional[uuid.UUID]) -> dict[str, Any]:
    return {
        "attempted": False,
        "succeeded": False,
        "provider": PROVIDER,
        "integration_id": str(integration_id) if integration_id else None,
        "source": SOURCE,
        "findings_seen": 0,
        "events_inserted": 0,
        "events_skipped": 0,
        "permission_limited": False,
        "error_message": None,
    }


def _store(workspace_id, integration_id, findings, normalizer, db) -> tuple[int, int, int]:
    """Normalize + idempotently upsert findings. Returns (seen, inserted, skipped)."""
    seen = inserted = skipped = 0
    for f in findings:
        seen += 1
        normalized = normalizer(f)
        if normalized is None:
            continue
        try:
            outcome, _row = activity_svc.upsert_activity_event(
                workspace_id=workspace_id, integration_id=integration_id,
                normalized=normalized, db=db,
            )
        except Exception:  # noqa: BLE001 — one bad row never fails the batch
            logger.warning("aws_alerts: failed to upsert one finding; continuing")
            continue
        if outcome == "inserted":
            inserted += 1
        else:
            skipped += 1
    return seen, inserted, skipped


def ingest_aws_security_alerts(
    *,
    integration: Integration,
    workspace_id: uuid.UUID,
    db: Session,
    max_findings: int = 50,
) -> dict[str, Any]:
    """Ingest GuardDuty (then Access Analyzer) findings for one AWS integration.

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
        logger.warning("aws_alerts: credential resolution failed (not logged)")
        summary["error_message"] = "Could not resolve AWS credentials."
        return summary

    connector = AWSConnector()
    seen = inserted = skipped = 0
    hard_error: Optional[str] = None

    # ── GuardDuty (primary) ────────────────────────────────────────────────────
    try:
        gd = connector.list_guardduty_findings(credentials, max_findings=max_findings)
    except AuthenticationError:
        summary["permission_limited"] = True
    except ConnectorError as exc:
        if getattr(exc, "status_code", None) == 403:
            summary["permission_limited"] = True
        elif getattr(exc, "status_code", None) == 503:
            hard_error = "AWS GuardDuty is temporarily unavailable in this region."
        else:
            hard_error = "GuardDuty request failed."
    except RateLimitError:
        hard_error = "AWS rate limit reached; try again later."
    except NetworkError:
        hard_error = "Network error reaching AWS."
    except Exception:  # noqa: BLE001
        logger.exception("aws_alerts: unexpected GuardDuty error")
        hard_error = "Unexpected error ingesting GuardDuty findings."
    else:
        s, i, k = _store(workspace_id, integration.id, gd, normalize_guardduty_finding, db)
        seen += s; inserted += i; skipped += k

    # ── Access Analyzer (optional, best-effort) ────────────────────────────────
    try:
        aa = connector.list_access_analyzer_findings(credentials, max_findings=max_findings)
    except AuthenticationError:
        summary["permission_limited"] = True
    except ConnectorError as exc:
        if getattr(exc, "status_code", None) == 403:
            summary["permission_limited"] = True
        # Other Access Analyzer errors are non-fatal (it's optional).
    except (RateLimitError, NetworkError):
        pass
    except Exception:  # noqa: BLE001
        logger.warning("aws_alerts: Access Analyzer ingestion skipped (non-fatal)")
    else:
        s, i, k = _store(workspace_id, integration.id, aa, normalize_access_analyzer_finding, db)
        seen += s; inserted += i; skipped += k

    summary["findings_seen"] = seen
    summary["events_inserted"] = inserted
    summary["events_skipped"] = skipped
    if hard_error is not None:
        summary["error_message"] = hard_error
        summary["succeeded"] = False
    else:
        summary["succeeded"] = True
        if summary["permission_limited"] and seen == 0:
            summary["error_message"] = (
                "AWS security-alert access is limited for these credentials "
                "(GuardDuty/Access Analyzer read permission or enablement)."
            )
    return summary
