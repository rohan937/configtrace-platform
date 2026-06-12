"""AWS Security Hub findings ingestion (M67.7).

Ingests provider-ADJUDICATED AWS Security Hub findings (ASFF format) into the
shared ``security_activity_events`` table (``provider="aws"``,
``source="security_hub"``), so they can become AWS Incident Signals. Security
Hub is the broader provider-reported findings layer aggregating GuardDuty,
Inspector, Macie, IAM Access Analyzer, and AWS config-control findings.

CLAIM DISCIPLINE: this ingests provider-REPORTED findings. It does NOT confirm a
breach, identify an attacker, or confirm unauthorized access. Findings become
"evidence for review" Incident Signals.

NON-FATAL BY DESIGN: every failure (missing permission, Security Hub not enabled,
throttling, network) is captured in the returned summary — never raised.

PRIVACY: only allowlisted, flat, safe fields are stored (title/description/
severity/workflow/compliance/product/account/region/resource). NEVER the raw
finding JSON, request/response payloads, secrets, tokens, access keys, raw IPs,
malware sample details, or raw vulnerability payloads.

Scope note (M67.7): Security Hub findings only. NOT VPC Flow Logs, NOT S3 data
events, NOT S3 object-access-spike detection, NOT new providers.
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
SOURCE = "security_hub"

_SEVERITIES = {"critical", "high", "medium", "low", "info"}


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


def _severity_label(finding: dict[str, Any]) -> str:
    """Map ASFF Severity.Label, else Severity.Normalized, to a review label."""
    sev = finding.get("Severity") or {}
    if isinstance(sev, dict):
        label = sev.get("Label")
        if isinstance(label, str) and label:
            low = label.lower()
            if low == "informational":
                return "info"
            if low in _SEVERITIES:
                return low
        norm = sev.get("Normalized")
        try:
            n = float(norm)
        except (TypeError, ValueError):
            n = None
        if n is not None:
            if n >= 90:
                return "critical"
            if n >= 70:
                return "high"
            if n >= 40:
                return "medium"
            if n >= 1:
                return "low"
            return "info"
    return "medium"


def _severity_normalized(finding: dict[str, Any]) -> Optional[int]:
    sev = finding.get("Severity") or {}
    if isinstance(sev, dict):
        try:
            return int(sev.get("Normalized"))
        except (TypeError, ValueError):
            return None
    return None


def _first_resource(finding: dict[str, Any]) -> dict[str, Any]:
    res = finding.get("Resources") or []
    if isinstance(res, list) and res and isinstance(res[0], dict):
        return res[0]
    return {}


def _event_type(finding: dict[str, Any]) -> str:
    """Map a Security Hub finding to a normalized event type (vendor → resource)."""
    product = (finding.get("ProductName") or "").lower()
    types = finding.get("Types") or []
    types_str = " ".join(t for t in types if isinstance(t, str)).lower()
    res0 = _first_resource(finding)
    rtype = (res0.get("Type") or "").lower() if isinstance(res0, dict) else ""

    # Vendor product first (these wrap their own detector's findings).
    if "guardduty" in product:
        return "aws.security_hub.guardduty_finding"
    if "inspector" in product:
        return "aws.security_hub.inspector_finding"
    if "macie" in product:
        return "aws.security_hub.macie_finding"

    # Otherwise classify by affected resource type / finding type.
    if "iam" in rtype or "iam" in types_str:
        return "aws.security_hub.iam_finding"
    if "s3" in rtype or "::s3" in types_str:
        return "aws.security_hub.s3_finding"
    if "ec2" in rtype:
        return "aws.security_hub.ec2_finding"
    if "kms" in rtype:
        return "aws.security_hub.kms_finding"
    return "aws.security_hub.finding"


def normalize_security_hub_finding(f: dict[str, Any]) -> Optional[dict[str, Any]]:
    """Map a raw ASFF Security Hub finding to a normalized activity-event dict."""
    if not isinstance(f, dict):
        return None
    fid = f.get("Id")
    if not fid:
        return None

    res0 = _first_resource(f)
    resource_type = res0.get("Type") if isinstance(res0, dict) else None
    resource_id = res0.get("Id") if isinstance(res0, dict) else None

    types = f.get("Types") or []
    finding_type = next((t for t in types if isinstance(t, str)), None)

    compliance = f.get("Compliance") or {}
    workflow = f.get("Workflow") or {}

    metadata = {
        "finding_type": finding_type,
        "finding_title": f.get("Title"),
        "finding_description": f.get("Description"),
        "severity_label": _severity_label(f),
        "severity_normalized": _severity_normalized(f),
        "workflow_status": workflow.get("Status") if isinstance(workflow, dict) else None,
        "record_state": f.get("RecordState"),
        "compliance_status": compliance.get("Status") if isinstance(compliance, dict) else None,
        "product_name": f.get("ProductName"),
        "company_name": f.get("CompanyName"),
        "generator_id": f.get("GeneratorId"),
        "account_id": f.get("AwsAccountId"),
        "region": f.get("Region") or f.get("_Region"),
        "created_at": f.get("CreatedAt"),
        "updated_at": f.get("UpdatedAt"),
    }

    return activity_svc.normalize_activity_event(
        provider=PROVIDER,
        source=SOURCE,
        event_type=_event_type(f),
        occurred_at=_parse_ts(f.get("UpdatedAt") or f.get("CreatedAt")),
        provider_event_id=str(fid),
        actor_id=None,
        actor_type="provider_finding",
        resource_type=resource_type if isinstance(resource_type, str) else None,
        resource_id=resource_id if isinstance(resource_id, str) else None,
        # Security Hub findings can embed network payloads; we never traverse them
        # for raw IPs (parity with the GuardDuty ingestion).
        source_ip=None,
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


def _store(workspace_id, integration_id, findings, db) -> tuple[int, int, int]:
    seen = inserted = skipped = 0
    for f in findings:
        seen += 1
        normalized = normalize_security_hub_finding(f)
        if normalized is None:
            continue
        try:
            outcome, _row = activity_svc.upsert_activity_event(
                workspace_id=workspace_id, integration_id=integration_id,
                normalized=normalized, db=db,
            )
        except Exception:  # noqa: BLE001 — one bad row never fails the batch
            logger.warning("aws_security_hub: failed to upsert one finding; continuing")
            continue
        if outcome == "inserted":
            inserted += 1
        else:
            skipped += 1
    return seen, inserted, skipped


def ingest_aws_security_hub_findings(
    *,
    integration: Integration,
    workspace_id: uuid.UUID,
    db: Session,
    max_findings: int = 50,
    max_pages: int = 2,
) -> dict[str, Any]:
    """Ingest Security Hub findings for one AWS integration.

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
        logger.warning("aws_security_hub: credential resolution failed (not logged)")
        summary["error_message"] = "Could not resolve AWS credentials."
        return summary

    connector = AWSConnector()
    hard_error: Optional[str] = None

    try:
        findings = connector.list_security_hub_findings(
            credentials, max_findings=max_findings, max_pages=max_pages
        )
    except AuthenticationError:
        summary["permission_limited"] = True
        findings = []
    except ConnectorError as exc:
        findings = []
        code = getattr(exc, "status_code", None)
        if code == 403:
            summary["permission_limited"] = True
        elif code == 503:
            hard_error = "AWS Security Hub is temporarily unavailable in this region."
        else:
            hard_error = (
                "Security Hub request failed (it may not be enabled in this region)."
            )
    except RateLimitError:
        findings = []
        hard_error = "AWS rate limit reached; try again later."
    except NetworkError:
        findings = []
        hard_error = "Network error reaching AWS."
    except Exception:  # noqa: BLE001
        logger.exception("aws_security_hub: unexpected error")
        findings = []
        hard_error = "Unexpected error ingesting Security Hub findings."

    seen, inserted, skipped = _store(workspace_id, integration.id, findings, db)
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
                "AWS Security Hub access is limited for these credentials "
                "(securityhub:GetFindings permission, or Security Hub not enabled "
                "in this region)."
            )
    return summary
