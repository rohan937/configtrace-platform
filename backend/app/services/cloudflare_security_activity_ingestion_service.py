"""Cloudflare security/audit activity ingestion (M68.1).

Ingests Cloudflare ACCOUNT audit-log activity into the shared
``security_activity_events`` table (``provider="cloudflare"``,
``source="audit_log"``) — the network/security control-plane change activity
foundation (DNS records, WAF/firewall rules, SSL/TLS + zone settings, Access
policies, API-token activity).

INGESTION SOURCE (deliberate): Cloudflare account audit logs are the broadly-
available, plan-agnostic source. WAF/firewall per-request SECURITY EVENTS are
DEFERRED — they require the GraphQL Analytics API / higher plan tiers and are
not safely reachable from the current REST connector.

CLAIM DISCIPLINE: this ingests provider audit activity. It does NOT confirm a
breach, attacker, compromise, or unauthorized access. Events are "evidence for
review".

NON-FATAL BY DESIGN: missing permission / unavailable endpoint / throttling /
network failures are captured in the returned summary, never raised.

PRIVACY: only allowlisted, flat, safe fields are stored (zone, action, actor,
rule, severity, outcome, account). NEVER raw request bodies, headers, cookies,
tokens, secrets, raw IPs (hashed only), or full raw event JSON.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.connectors.cloudflare import CloudflareConnector
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

PROVIDER = "cloudflare"
SOURCE = "audit_log"
EVENT_SOURCE = "cloudflare_audit_log"


def _event_type(resource_type: Any, action_type: Any) -> str:
    """Map a Cloudflare audit entry's resource/action → normalized event type."""
    rt = (resource_type or "").lower() if isinstance(resource_type, str) else ""
    at = (action_type or "").lower() if isinstance(action_type, str) else ""
    blob = f"{rt} {at}"
    if "dns_record" in rt or "dns" in blob:
        return "cloudflare.dns_record.changed"
    if any(k in blob for k in ("firewall", "waf", "filter", "ruleset")):
        return "cloudflare.waf_rule.changed"
    if any(k in blob for k in ("ssl", "tls", "https", "certificate", "min_tls")):
        return "cloudflare.ssl_tls.changed"
    if "access" in blob:
        return "cloudflare.access_policy.changed"
    if "token" in blob:
        return "cloudflare.api_token.activity"
    if "setting" in blob or rt.startswith("zone"):
        return "cloudflare.zone_setting.changed"
    return "cloudflare.audit_event"


def _ts(raw: Any) -> Optional[datetime]:
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


def _safe_str(value: Any) -> Optional[str]:
    return value if isinstance(value, str) and value.strip() else None


def normalize_audit_event(entry: dict[str, Any]) -> Optional[dict[str, Any]]:
    """Map one raw Cloudflare audit-log entry → a normalized activity dict.

    Only safe, flat fields are extracted; newValue/oldValue/metadata blobs and
    the actor IP (hashed only) are never stored raw.
    """
    if not isinstance(entry, dict):
        return None
    event_id = entry.get("id")
    if not event_id:
        return None

    action = entry.get("action") if isinstance(entry.get("action"), dict) else {}
    actor = entry.get("actor") if isinstance(entry.get("actor"), dict) else {}
    resource = entry.get("resource") if isinstance(entry.get("resource"), dict) else {}
    owner = entry.get("owner") if isinstance(entry.get("owner"), dict) else {}
    zone = entry.get("zone") if isinstance(entry.get("zone"), dict) else {}

    action_type = action.get("type")
    resource_type = resource.get("type")
    resource_id = resource.get("id")
    event_type = _event_type(resource_type, action_type)

    actor_label = _safe_str(actor.get("email")) or _safe_str(actor.get("id"))
    account_id = _safe_str(owner.get("id")) or _safe_str(entry.get("_account_id"))

    is_rule = event_type == "cloudflare.waf_rule.changed"
    is_setting = event_type in (
        "cloudflare.zone_setting.changed", "cloudflare.ssl_tls.changed"
    )
    is_access = event_type == "cloudflare.access_policy.changed"

    # M68.3 — preserve a SAFE setting/policy name so zone-setting and Access
    # correlations can match exactly (never the oldValue/newValue blobs).
    md_blob = entry.get("metadata") if isinstance(entry.get("metadata"), dict) else {}
    setting_name = (
        _safe_str(md_blob.get("setting_name"))
        or _safe_str(md_blob.get("setting_key"))
        or _safe_str(md_blob.get("setting_id"))
    )
    if not setting_name and is_setting:
        # For a settings change the audit resource id is the setting key.
        setting_name = _safe_str(resource_id)
    policy_name = (
        _safe_str(resource.get("name")) or _safe_str(md_blob.get("policy_name"))
    ) if is_access else None

    metadata = {
        "zone_id": _safe_str(zone.get("id")),
        "zone_name": _safe_str(zone.get("name")),
        "action": _safe_str(action_type),
        "actor": actor_label,
        "rule_id": _safe_str(resource_id) if is_rule else None,
        "rule_name": _safe_str(resource.get("name")) if isinstance(resource, dict) else None,
        "setting_name": setting_name if is_setting else None,
        "policy_id": _safe_str(resource_id) if is_access else None,
        "policy_name": policy_name,
        "event_source": EVENT_SOURCE,
        "severity": _safe_str(entry.get("severity")),
        "outcome": _safe_str(action.get("result")),
        "account_id": account_id,
    }

    return activity_svc.normalize_activity_event(
        provider=PROVIDER,
        source=SOURCE,
        event_type=event_type,
        occurred_at=_ts(entry.get("when")),
        provider_event_id=str(event_id),
        actor_id=actor_label,
        actor_type=_safe_str(actor.get("type")) or "user",
        resource_type=_safe_str(resource_type),
        resource_id=_safe_str(resource_id),
        # Hashed to source_ip_hash by normalize_activity_event — never stored raw.
        source_ip=_safe_str(actor.get("ip")),
        metadata=metadata,
        raw_ref=str(event_id),
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


def ingest_cloudflare_security_activity(
    *,
    integration: Integration,
    workspace_id: uuid.UUID,
    db: Session,
    max_events: int = 100,
) -> dict[str, Any]:
    """Ingest Cloudflare audit activity for one integration. Never raises."""
    summary = _empty_summary(integration.id)
    if integration.provider != PROVIDER:
        summary["error_message"] = "Not a Cloudflare integration."
        return summary
    summary["attempted"] = True

    try:
        credentials = decrypt_credentials(
            integration.encrypted_credentials, integration.credential_iv
        )
    except Exception:  # noqa: BLE001 — never leak credential errors
        logger.warning("cloudflare_activity: credential resolution failed (not logged)")
        summary["error_message"] = "Could not resolve Cloudflare credentials."
        return summary

    connector = CloudflareConnector()
    hard_error: Optional[str] = None

    try:
        events = connector.list_audit_events(credentials, max_events=max_events)
    except AuthenticationError:
        summary["permission_limited"] = True
        events = []
    except ConnectorError as exc:
        events = []
        code = getattr(exc, "status_code", None)
        if code in (401, 403, 404, 422):
            summary["permission_limited"] = True
        elif code == 503:
            hard_error = "Cloudflare is temporarily unavailable."
        else:
            hard_error = "Cloudflare audit-log request failed."
    except RateLimitError:
        events = []
        hard_error = "Cloudflare rate limit reached; try again later."
    except NetworkError:
        events = []
        hard_error = "Network error reaching Cloudflare."
    except Exception:  # noqa: BLE001
        logger.exception("cloudflare_activity: unexpected error")
        events = []
        hard_error = "Unexpected error ingesting Cloudflare audit activity."

    seen = inserted = skipped = 0
    for entry in events:
        seen += 1
        normalized = normalize_audit_event(entry)
        if normalized is None:
            continue
        try:
            outcome, _row = activity_svc.upsert_activity_event(
                workspace_id=workspace_id, integration_id=integration.id,
                normalized=normalized, db=db,
            )
        except Exception:  # noqa: BLE001 — one bad row never fails the batch
            logger.warning("cloudflare_activity: failed to upsert one event; continuing")
            continue
        if outcome == "inserted":
            inserted += 1
        else:
            skipped += 1

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
                "Cloudflare audit-log access is limited for this token "
                "(account-scoped Audit Logs Read permission is required)."
            )
    return summary
