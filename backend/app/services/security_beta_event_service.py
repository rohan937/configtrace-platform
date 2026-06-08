"""Beta usage instrumentation for Security Exposure (M63.1).

Records coarse, workspace-scoped usage events with an allowlisted, truncated,
metadata-only payload. First-party storage only; no third-party analytics.

Privacy contract:
  * ``event_name`` must be in EVENT_NAMES, else ValueError (the endpoint maps
    this to HTTP 422).
  * metadata keys not in ALLOWED_METADATA_KEYS are silently dropped (lenient,
    non-breaking for callers).
  * Only scalar values (str / int / float / bool) are kept; nested
    objects/arrays are dropped. Strings are truncated to MAX_STR_LEN.
  * Forbidden keys (evidence, remediation, secrets, tokens, payloads, raw
    provider/rule data, note bodies) are never on the allowlist, so they can
    never be stored.
"""

from __future__ import annotations

import uuid
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.models.security_beta_event import SecurityBetaEvent

# Stable, boring event names. Keep additions backwards-compatible.
EVENT_NAMES: frozenset[str] = frozenset(
    {
        "security_page_viewed",
        "security_demo_seed_clicked",
        "security_demo_seed_completed",
        "security_demo_clear_clicked",
        "security_walkthrough_opened",
        "security_walkthrough_step_clicked",
        "security_onboarding_cta_clicked",
        "security_exposure_opened",
        "security_exposure_action_clicked",
        "security_exposure_action_completed",
        "security_note_added",
        "security_report_exported",
        "security_rule_toggled",
        "security_coverage_viewed",
        "security_incident_review_run",
        "security_asset_expanded",
    }
)

# Small allowlist of non-sensitive metadata keys. Anything else is dropped.
ALLOWED_METADATA_KEYS: frozenset[str] = frozenset(
    {
        "provider",
        "severity",
        "status",
        "rule_key",
        "finding_id",
        "asset_type",
        "report_type",
        "demo_loaded",
        "checklist_item_id",
        "action",
        "result",
        "error_code",
        "route_group",
    }
)

MAX_STR_LEN = 200
MAX_PAGE_PATH_LEN = 300
MAX_METADATA_KEYS = 20


def sanitize_metadata(raw: Optional[dict[str, Any]]) -> dict[str, Any]:
    """Return a safe, allowlisted, truncated copy of metadata.

    Drops unknown keys, drops nested/complex values, truncates strings.
    """
    if not isinstance(raw, dict):
        return {}
    out: dict[str, Any] = {}
    for key, value in raw.items():
        if key not in ALLOWED_METADATA_KEYS:
            continue  # strip unknown / forbidden keys
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


def record_event(
    *,
    workspace_id: uuid.UUID,
    user_id: Optional[uuid.UUID],
    event_name: str,
    page_path: Optional[str],
    metadata: Optional[dict[str, Any]],
    db: Session,
) -> SecurityBetaEvent:
    """Validate + persist a single beta event. Raises ValueError on bad name."""
    if not isinstance(event_name, str) or event_name not in EVENT_NAMES:
        raise ValueError(f"Unknown event_name: {event_name!r}")

    safe_path: Optional[str] = None
    if isinstance(page_path, str) and page_path:
        safe_path = page_path[:MAX_PAGE_PATH_LEN]

    event = SecurityBetaEvent(
        workspace_id=workspace_id,
        user_id=user_id,
        event_name=event_name,
        event_category="security_beta",
        page_path=safe_path,
        event_metadata=sanitize_metadata(metadata),
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return event
