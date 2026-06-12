"""GitHub activity (audit-log) ingestion (M66.2).

For a GitHub integration, attempt to fetch recent **organization audit-log**
events, normalize the allowlisted control-plane categories, and idempotently
store them as ``SecurityActivityEvent`` rows — the data spine for the future
Incident Signals product.

CLAIM DISCIPLINE: this ingests *control-plane activity* only. It does NOT detect
breaches, identify attackers, or confirm compromise. Correlation (e.g. "branch
protection disabled" + "force push after" → potential incident signal) is a
FUTURE milestone.

NON-FATAL BY DESIGN: every failure (permission denied, endpoint unavailable,
rate limit, network) is captured in the returned summary. This function never
raises out to break a normal config sync.

Coverage note — what GitHub's org audit-log API does and does NOT give us:
  * Available (when org + permissions allow): branch-protection changes, deploy
    keys, webhooks, collaborator changes, app installs/permission changes,
    rulesets, secret-scanning alerts.
  * NOT available via this API: raw Git push / force-push events. Force-push
    correlation is therefore deferred to a later milestone with a different
    event source.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.connectors.exceptions import (
    AuthenticationError,
    ConnectorError,
    NetworkError,
    RateLimitError,
)
from app.connectors.github import GitHubConnector
from app.core.encryption import decrypt_credentials
from app.models.integration import Integration
from app.services import security_activity_event_service as activity_svc

logger = logging.getLogger(__name__)

PROVIDER = "github"
SOURCE = "audit_log"

# Map raw GitHub audit-log ``action`` strings → stable normalized event types.
# Only these allowlisted categories are stored; everything else is skipped.
GITHUB_ACTION_MAP: dict[str, str] = {
    # Branch protection
    "protected_branch.destroy": "github.branch_protection.disabled",
    "protected_branch.update": "github.branch_protection.updated",
    "protected_branch.create": "github.branch_protection.created",
    # Deploy keys
    "deploy_key.create": "github.deploy_key.added",
    "deploy_key.destroy": "github.deploy_key.removed",
    # Webhooks
    "hook.create": "github.webhook.created",
    "hook.config_changed": "github.webhook.updated",
    "hook.events_changed": "github.webhook.updated",
    "hook.destroy": "github.webhook.deleted",
    # Collaborators / membership
    "repo.add_member": "github.collaborator.added",
    "repo.remove_member": "github.collaborator.removed",
    "member.added": "github.collaborator.added",
    "member.removed": "github.collaborator.removed",
    # GitHub App installs / permission changes
    "integration_installation.create": "github.app.installed",
    "integration_installation.repositories_added": "github.app.permissions_changed",
    "integration_installation.repositories_removed": "github.app.permissions_changed",
    # Repository rulesets
    "repository_ruleset.create": "github.ruleset.changed",
    "repository_ruleset.update": "github.ruleset.changed",
    "repository_ruleset.destroy": "github.ruleset.changed",
    # Secret scanning alerts
    "secret_scanning_alert.create": "github.secret_scanning_alert.created",
    "secret_scanning_alert.reopen": "github.secret_scanning_alert.created",
    "secret_scanning_alert.resolve": "github.secret_scanning_alert.resolved",
}


def _empty_summary(integration_id: Optional[uuid.UUID]) -> dict[str, Any]:
    return {
        "attempted": False,
        "succeeded": False,
        "provider": PROVIDER,
        "integration_id": str(integration_id) if integration_id else None,
        "events_seen": 0,
        "events_inserted": 0,
        "events_updated_or_skipped": 0,
        "permission_limited": False,
        "error_message": None,
    }


def _resolve_credentials(integration: Integration) -> dict[str, Any]:
    """Decrypt integration credentials, minting a GitHub App token if needed.

    Mirrors the sync worker. Installation tokens are runtime-only — never stored
    or logged. May raise on bad/missing credentials; the caller handles it.
    """
    credentials = decrypt_credentials(
        integration.encrypted_credentials, integration.credential_iv
    )
    if credentials.get("credential_type") == "github_app":
        from app.config import settings as _settings
        from app.core.github_app import (
            decode_private_key,
            mint_app_jwt,
            mint_installation_token,
        )

        private_key = decode_private_key(_settings.GITHUB_APP_PRIVATE_KEY or "")
        app_jwt = mint_app_jwt(_settings.GITHUB_APP_ID or "", private_key)
        install_token = mint_installation_token(
            int(credentials["installation_id"]), app_jwt
        )
        return {
            "github_token": install_token,
            "repo_owner": credentials.get("repo_owner", ""),
            "repo_name": credentials.get("repo_name", ""),
        }
    return credentials


def _parse_ts(item: dict[str, Any]) -> Optional[datetime]:
    """Parse a GitHub audit-log timestamp (epoch ms or ISO) → aware datetime."""
    raw = item.get("@timestamp")
    if raw is None:
        raw = item.get("created_at")
    if raw is None:
        return None
    try:
        if isinstance(raw, bool):
            return None
        if isinstance(raw, (int, float)):
            return datetime.fromtimestamp(float(raw) / 1000.0, tz=timezone.utc)
        if isinstance(raw, str):
            s = raw.strip()
            if s.isdigit():
                return datetime.fromtimestamp(int(s) / 1000.0, tz=timezone.utc)
            return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except (ValueError, OverflowError, OSError):
        return None
    return None


def normalize_github_audit_item(item: dict[str, Any]) -> Optional[dict[str, Any]]:
    """Map a raw GitHub audit-log entry to a normalized event dict, or None.

    Returns None for entries whose ``action`` is not in the allowlist — those are
    skipped, never stored.
    """
    if not isinstance(item, dict):
        return None
    action = item.get("action")
    if not isinstance(action, str):
        return None
    event_type = GITHUB_ACTION_MAP.get(action)
    if event_type is None:
        return None  # not an allowlisted control-plane category — skip

    actor = item.get("actor")
    repo = item.get("repo") or item.get("repository")
    org = item.get("org") or item.get("business")

    if isinstance(repo, str) and repo:
        resource_type, resource_id = "repository", repo
    elif isinstance(org, str) and org:
        resource_type, resource_id = "organization", org
    else:
        resource_type, resource_id = None, None

    actor_type = "app" if event_type.startswith("github.app.") else (
        "user" if isinstance(actor, str) and actor else None
    )

    # Pointer/id only (never the raw event body).
    doc_id = item.get("_document_id") or item.get("document_id") or item.get("id")
    doc_id = str(doc_id) if doc_id is not None else None

    # Allowlisted, flat metadata. The service sanitizer is the final gate.
    metadata = {
        "action": action,
        "repository": repo if isinstance(repo, str) else None,
        "visibility": item.get("visibility"),
        "ref": item.get("ref"),
        "hook_id": str(item["hook_id"]) if item.get("hook_id") is not None else None,
        "permission": item.get("permission"),
        "alert_number": item.get("number"),
        "target_login": item.get("user") if isinstance(item.get("user"), str) else None,
        "ruleset_name": item.get("name") if "ruleset" in action else None,
    }

    return activity_svc.normalize_activity_event(
        provider=PROVIDER,
        source=SOURCE,
        event_type=event_type,
        occurred_at=_parse_ts(item),
        provider_event_id=doc_id,
        actor_id=actor if isinstance(actor, str) else None,
        actor_type=actor_type,
        resource_type=resource_type,
        resource_id=resource_id,
        source_ip=item.get("actor_ip"),
        metadata=metadata,
        raw_ref=doc_id,
    )


def ingest_github_activity(
    *,
    integration: Integration,
    workspace_id: uuid.UUID,
    db: Session,
    max_pages: int = 3,
) -> dict[str, Any]:
    """Attempt to ingest recent GitHub audit-log activity for one integration.

    Returns an ingestion summary (never raises). Permission/availability limits
    are reported via ``permission_limited``; other failures via ``error_message``
    (a short, safe string — never secrets/tokens).
    """
    summary = _empty_summary(integration.id)

    if integration.provider != PROVIDER:
        summary["error_message"] = "Not a GitHub integration."
        return summary

    summary["attempted"] = True

    # 1. Resolve credentials (may mint a GitHub App token).
    try:
        credentials = _resolve_credentials(integration)
    except Exception:  # noqa: BLE001 — never leak credential errors; stay non-fatal
        logger.warning("github_activity: credential resolution failed (not logged)")
        summary["error_message"] = "Could not resolve GitHub credentials."
        return summary

    # 2. Fetch audit-log events — permission/availability issues are non-fatal.
    connector = GitHubConnector()
    try:
        raw_events = connector.list_audit_log_events(credentials, max_pages=max_pages)
    except AuthenticationError:
        summary["succeeded"] = True
        summary["permission_limited"] = True
        summary["error_message"] = (
            "GitHub audit-log access is not permitted for this token/account."
        )
        return summary
    except ConnectorError as exc:
        if getattr(exc, "status_code", None) == 404:
            summary["succeeded"] = True
            summary["permission_limited"] = True
            summary["error_message"] = (
                "GitHub organization audit log is unavailable for this account/plan."
            )
            return summary
        summary["error_message"] = "GitHub audit-log request failed."
        return summary
    except RateLimitError:
        summary["error_message"] = "GitHub rate limit reached; try again later."
        return summary
    except NetworkError:
        summary["error_message"] = "Network error reaching GitHub."
        return summary
    except Exception:  # noqa: BLE001 — defensive; never break the caller
        logger.exception("github_activity: unexpected ingestion error")
        summary["error_message"] = "Unexpected error during audit-log ingestion."
        return summary

    summary["events_seen"] = len(raw_events)

    # 3. Normalize allowlisted categories + idempotently upsert.
    inserted = 0
    skipped = 0
    for item in raw_events:
        normalized = normalize_github_audit_item(item)
        if normalized is None:
            continue  # not an allowlisted control-plane category
        try:
            outcome, _row = activity_svc.upsert_activity_event(
                workspace_id=workspace_id,
                integration_id=integration.id,
                normalized=normalized,
                db=db,
            )
        except Exception:  # noqa: BLE001 — one bad row never fails the whole batch
            logger.warning("github_activity: failed to upsert one event; continuing")
            continue
        if outcome == "inserted":
            inserted += 1
        else:
            skipped += 1

    summary["succeeded"] = True
    summary["events_inserted"] = inserted
    summary["events_updated_or_skipped"] = skipped
    return summary
