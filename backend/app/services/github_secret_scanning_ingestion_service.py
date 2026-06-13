"""GitHub secret-scanning alert ingestion (M69.4A).

Ingests GitHub repository SECRET-SCANNING ALERTS (the
``GET /repos/{owner}/{repo}/secret-scanning/alerts`` API) into the shared
``security_activity_events`` table (``provider="github"``,
``source="secret_scanning_alert"``) — GitHub's first SECURITY-ALERT evidence
plane in ConfigTrace (the existing audit-log source is control-plane activity;
this is provider-reported alert evidence).

SCOPE (deliberate): REPO-SCOPED ingestion only, matching the existing GitHub
credential model (``repo_owner`` + ``repo_name`` + ``github_token``). Org-level
secret-scanning ingestion (``GET /orgs/{org}/secret-scanning/alerts``) is
DEFERRED — it needs org-admin scope that the repo-scoped credential model does
not guarantee.

CLAIM DISCIPLINE: these are provider-reported ALERTS for review. ConfigTrace
never asserts that a secret was misused, leaked-and-exploited, that a compromise
occurred, that an attacker is present, or that unauthorized access happened —
only "evidence for review". An open alert is an alert, not a confirmed incident.

NON-FATAL BY DESIGN: every failure (GitHub Advanced Security disabled, missing
permission/scope, private repo unavailable, 403/404, rate limit, malformed
response) is captured in the returned summary — never raised out to break a
normal GitHub sync.

PRIVACY: only allowlisted, flat, safe fields are stored. NEVER the raw secret,
token, credential value, the raw alert URL (hashed only), the raw API response,
request/response headers, commit/patch content, file contents, or raw alert
locations (only a safe count). The signal/activity allowlist is the final gate.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.config import settings
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
SOURCE = "secret_scanning_alert"
EVENT_SOURCE = "github_secret_scanning"

# Map (state, resolution) → normalized event type. ``state`` is "open" or
# "resolved"; ``resolution`` is the resolution reason for resolved alerts.
_RESOLUTION_MAP: dict[str, str] = {
    "resolved": "github.secret_scanning.alert.resolved",
    "revoked": "github.secret_scanning.alert.revoked",
    "false_positive": "github.secret_scanning.alert.false_positive",
    "used_in_tests": "github.secret_scanning.alert.used_in_tests",
    "wont_fix": "github.secret_scanning.alert.resolved",
}
_OPEN_EVENT_TYPE = "github.secret_scanning.alert.open"
_FALLBACK_EVENT_TYPE = "github.secret_scanning.alert.event"


def _event_type(state: Any, resolution: Any) -> str:
    st = state.strip().lower() if isinstance(state, str) else ""
    if st == "open":
        return _OPEN_EVENT_TYPE
    if st == "resolved":
        res = resolution.strip().lower() if isinstance(resolution, str) else ""
        return _RESOLUTION_MAP.get(res, "github.secret_scanning.alert.resolved")
    return _FALLBACK_EVENT_TYPE


def _safe_str(value: Any) -> Optional[str]:
    return value if isinstance(value, str) and value.strip() else None


def _url_hash(value: Any) -> Optional[str]:
    """Salted, truncated hash of the alert HTML URL. Never stores the raw URL."""
    if not isinstance(value, str) or not value.strip():
        return None
    key = getattr(settings, "ENCRYPTION_KEY", "") or ""
    salt = ("gh_ss_url_v1:" + str(key)).encode("utf-8")
    return hashlib.sha256(salt + value.strip().encode("utf-8")).hexdigest()[:32]


def _parse_ts(raw: Any) -> Optional[datetime]:
    if not isinstance(raw, str) or not raw.strip():
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def _location_count(alert: dict[str, Any]) -> Optional[int]:
    """Safe COUNT of locations if the alert embeds them. Never the raw locations."""
    locs = alert.get("locations")
    if isinstance(locs, list):
        return len(locs)
    return None


def normalize_secret_scanning_alert(
    alert: dict[str, Any], *, repo_full_name: Optional[str] = None
) -> Optional[dict[str, Any]]:
    """Map one raw secret-scanning alert → a normalized activity dict, or None."""
    if not isinstance(alert, dict):
        return None
    number = alert.get("number")
    if not isinstance(number, int):
        return None  # malformed — every real alert has an integer number

    state = alert.get("state")
    resolution = alert.get("resolution")
    event_type = _event_type(state, resolution)

    repo = repo_full_name
    repo_obj = alert.get("repository")
    if isinstance(repo_obj, dict):
        repo = _safe_str(repo_obj.get("full_name")) or repo

    # Deterministic provider_event_id: repo + alert number + state/resolution +
    # updated_at, so a state change creates a new evidence row (idempotent per
    # state). Never includes the secret.
    pe_basis = "|".join([
        repo or "", str(number), _safe_str(state) or "",
        _safe_str(resolution) or "", _safe_str(alert.get("updated_at")) or "",
    ])
    pe_id = "ghss:" + hashlib.sha256(pe_basis.encode("utf-8")).hexdigest()[:40]

    metadata = {
        "repository": repo,
        "repository_full_name": repo,
        "alert_number": number,
        "state": _safe_str(state),
        "resolution": _safe_str(resolution),
        "secret_type": _safe_str(alert.get("secret_type")),
        "secret_type_display_name": _safe_str(alert.get("secret_type_display_name")),
        "validity": _safe_str(alert.get("validity")),
        "publicly_leaked": alert.get("publicly_leaked")
        if isinstance(alert.get("publicly_leaked"), bool) else None,
        "created_at": _safe_str(alert.get("created_at")),
        "updated_at": _safe_str(alert.get("updated_at")),
        "resolved_at": _safe_str(alert.get("resolved_at")),
        "location_count": _location_count(alert),
        "alert_url_hash": _url_hash(alert.get("html_url")),
        "event_source": EVENT_SOURCE,
    }

    resolver = alert.get("resolved_by")
    actor = None
    if isinstance(resolver, dict):
        actor = _safe_str(resolver.get("login"))

    return activity_svc.normalize_activity_event(
        provider=PROVIDER,
        source=SOURCE,
        event_type=event_type,
        occurred_at=_parse_ts(alert.get("updated_at")) or _parse_ts(alert.get("created_at")),
        provider_event_id=pe_id,
        actor_id=actor,
        actor_type="user" if actor else None,
        resource_type="repository" if repo else None,
        resource_id=repo,
        # Never an IP source for a secret-scanning alert.
        source_ip=None,
        metadata=metadata,
        raw_ref=f"alert#{number}",
    )


def _resolve_credentials(integration: Integration) -> dict[str, Any]:
    """Decrypt credentials, minting a GitHub App installation token if needed.

    Mirrors github_activity_ingestion_service. Installation tokens are
    runtime-only — never stored or logged.
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


def _empty_summary(integration_id: Optional[uuid.UUID]) -> dict[str, Any]:
    return {
        "attempted": False,
        "succeeded": False,
        "provider": PROVIDER,
        "integration_id": str(integration_id) if integration_id else None,
        "source": SOURCE,
        "alerts_seen": 0,
        "events_inserted": 0,
        "events_skipped": 0,
        "permission_limited": False,
        "error_message": None,
    }


def ingest_github_secret_scanning_alerts(
    *,
    integration: Integration,
    workspace_id: uuid.UUID,
    db: Session,
    lookback_hours: int = 24,
    max_alerts: int = 1000,
) -> dict[str, Any]:
    """Ingest GitHub secret-scanning alerts for one integration. Never raises.

    ``lookback_hours`` is accepted for API symmetry and bounds the stored set to
    alerts created/updated within the window; permission/availability limits →
    ``permission_limited``; other failures → ``error_message`` (safe string).
    """
    summary = _empty_summary(integration.id)
    if integration.provider != PROVIDER:
        summary["error_message"] = "Not a GitHub integration."
        return summary
    summary["attempted"] = True

    try:
        credentials = _resolve_credentials(integration)
    except Exception:  # noqa: BLE001 — never leak credential errors
        logger.warning("github_secret_scanning: credential resolution failed (not logged)")
        summary["error_message"] = "Could not resolve GitHub credentials."
        return summary

    repo_full_name = None
    owner = credentials.get("repo_owner")
    name = credentials.get("repo_name")
    if isinstance(owner, str) and isinstance(name, str) and owner and name:
        repo_full_name = f"{owner}/{name}"

    connector = GitHubConnector()
    cap = max(1, min(int(max_alerts or 1000), 1000))
    hours = max(1, min(int(lookback_hours or 24), 168))
    cutoff = datetime.now(timezone.utc).timestamp() - hours * 3600

    try:
        alerts = connector.list_secret_scanning_alerts(credentials, max_alerts=cap)
    except AuthenticationError:
        summary["succeeded"] = True
        summary["permission_limited"] = True
        summary["error_message"] = (
            "GitHub secret-scanning access is not permitted for this token/repo "
            "(requires GitHub Advanced Security and secret-scanning read scope)."
        )
        return summary
    except ConnectorError as exc:
        code = getattr(exc, "status_code", None)
        if code in (403, 404):
            summary["succeeded"] = True
            summary["permission_limited"] = True
            summary["error_message"] = (
                "GitHub secret scanning is unavailable for this repository "
                "(feature disabled, private repo without Advanced Security, or "
                "insufficient token scope)."
            )
            return summary
        summary["error_message"] = "GitHub secret-scanning request failed."
        return summary
    except RateLimitError:
        summary["error_message"] = "GitHub rate limit reached; try again later."
        return summary
    except NetworkError:
        summary["error_message"] = "Network error reaching GitHub."
        return summary
    except Exception:  # noqa: BLE001 — defensive; never break the caller
        logger.exception("github_secret_scanning: unexpected ingestion error")
        summary["error_message"] = "Unexpected error during secret-scanning ingestion."
        return summary

    summary["alerts_seen"] = len(alerts)

    inserted = 0
    skipped = 0
    for alert in alerts:
        normalized = normalize_secret_scanning_alert(alert, repo_full_name=repo_full_name)
        if normalized is None:
            continue  # malformed — skipped safely
        # Lookback gate (by occurred_at, which is updated_at/created_at).
        occ = normalized.get("occurred_at")
        if isinstance(occ, datetime) and occ.timestamp() < cutoff:
            continue
        try:
            outcome, _row = activity_svc.upsert_activity_event(
                workspace_id=workspace_id, integration_id=integration.id,
                normalized=normalized, db=db,
            )
        except Exception:  # noqa: BLE001 — one bad row never fails the batch
            logger.warning("github_secret_scanning: failed to upsert one alert; continuing")
            continue
        if outcome == "inserted":
            inserted += 1
        else:
            skipped += 1

    summary["succeeded"] = True
    summary["events_inserted"] = inserted
    summary["events_skipped"] = skipped
    return summary
