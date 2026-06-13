"""GitHub Dependabot alert ingestion (M69.4G).

Ingests GitHub repository DEPENDABOT ALERTS (the
``GET /repos/{owner}/{repo}/dependabot/alerts`` API) into the shared
``security_activity_events`` table (``provider="github"``,
``source="dependabot_alert"``) — GitHub's THIRD security-alert evidence plane in
ConfigTrace (after secret-scanning in M69.4A and code-scanning in M69.4D). The
existing audit-log source is control-plane activity; this is provider-reported
vulnerable-dependency alert evidence.

SCOPE (deliberate): REPO-SCOPED ingestion only, matching the existing GitHub
credential model (``repo_owner`` + ``repo_name`` + ``github_token``). Org-level
Dependabot ingestion (``GET /orgs/{org}/dependabot/alerts``) is DEFERRED — it
needs org-admin scope that the repo-scoped credential model does not guarantee.

CLAIM DISCIPLINE: these are provider-reported ALERTS for review. ConfigTrace
never asserts that a vulnerable dependency was exploited, that exploitation is
confirmed, that a compromise occurred, that an attacker is present, or that
unauthorized access happened — only "evidence for review". An open alert is an
alert, not a confirmed incident, and ConfigTrace does not confirm exploitation.

NON-FATAL BY DESIGN: every failure (Dependabot disabled, missing permission/
scope, private repo unavailable, 403/404, rate limit, malformed response) is
captured in the returned summary — never raised out to break a normal GitHub
sync.

PRIVACY: only allowlisted, flat, safe fields are stored (package name/ecosystem,
version ranges, advisory GHSA/CVE ids + severity + short summary, CVSS/EPSS
scores, scope, state, timestamps). NEVER raw advisory bodies/descriptions, raw
manifest/file paths, the raw dependency-graph or API response, request/response
headers, patch content, tokens, or credentials. The activity allowlist is the
final gate.
"""

from __future__ import annotations

import hashlib
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
SOURCE = "dependabot_alert"
EVENT_SOURCE = "github_dependabot"

# Map alert ``state`` → normalized event type. GitHub's Dependabot alert state
# enum is open / dismissed / fixed / auto_dismissed; ``reopened`` is included for
# completeness.
_STATE_MAP: dict[str, str] = {
    "open": "github.dependabot.alert.open",
    "fixed": "github.dependabot.alert.fixed",
    "dismissed": "github.dependabot.alert.dismissed",
    "auto_dismissed": "github.dependabot.alert.auto_dismissed",
    "reopened": "github.dependabot.alert.reopened",
}
_FALLBACK_EVENT_TYPE = "github.dependabot.alert.event"


def _event_type(state: Any) -> str:
    st = state.strip().lower() if isinstance(state, str) else ""
    return _STATE_MAP.get(st, _FALLBACK_EVENT_TYPE)


def _safe_str(value: Any) -> Optional[str]:
    return value if isinstance(value, str) and value.strip() else None


def _safe_num(value: Any) -> Optional[float]:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    return None


def _parse_ts(raw: Any) -> Optional[datetime]:
    if not isinstance(raw, str) or not raw.strip():
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def normalize_dependabot_alert(
    alert: dict[str, Any], *, repo_full_name: Optional[str] = None
) -> Optional[dict[str, Any]]:
    """Map one raw Dependabot alert → a normalized activity dict, or None.

    Reads only safe, flat fields. NEVER the raw advisory body/description, raw
    manifest/file path, or the raw dependency-graph/API response.
    """
    if not isinstance(alert, dict):
        return None
    number = alert.get("number")
    if not isinstance(number, int) or isinstance(number, bool):
        return None  # malformed — every real alert has an integer number

    state = alert.get("state")
    event_type = _event_type(state)

    repo = repo_full_name
    repo_obj = alert.get("repository")
    if isinstance(repo_obj, dict):
        repo = _safe_str(repo_obj.get("full_name")) or repo

    dependency = _dict(alert.get("dependency"))
    vuln = _dict(alert.get("security_vulnerability"))
    advisory = _dict(alert.get("security_advisory"))

    # Package + ecosystem (prefer security_vulnerability.package, then dependency).
    pkg = _dict(vuln.get("package")) or _dict(dependency.get("package"))
    package_name = _safe_str(pkg.get("name"))
    ecosystem = _safe_str(pkg.get("ecosystem"))

    # Vulnerable range + first patched version (safe label only).
    vuln_range = _safe_str(vuln.get("vulnerable_version_range"))
    patched = _safe_str(_dict(vuln.get("first_patched_version")).get("identifier"))

    # CVSS score + EPSS probability (safe numeric only).
    cvss_score = _safe_num(_dict(advisory.get("cvss")).get("score"))
    epss_pct = _safe_num(_dict(advisory.get("epss")).get("percentage"))

    # Deterministic provider_event_id: repo + alert number + state + updated_at,
    # so a state change creates a new evidence row (idempotent per state).
    pe_basis = "|".join([
        repo or "", str(number), _safe_str(state) or "",
        _safe_str(alert.get("updated_at")) or "",
    ])
    pe_id = "ghdep:" + hashlib.sha256(pe_basis.encode("utf-8")).hexdigest()[:40]

    metadata = {
        "repository": repo,
        "repository_full_name": repo,
        "alert_number": number,
        "state": _safe_str(state),
        "dependency_package_name": package_name,
        "dependency_ecosystem": ecosystem,
        "vulnerable_version_range": vuln_range,
        "patched_versions": patched,
        "advisory_ghsa_id": _safe_str(advisory.get("ghsa_id")),
        "advisory_cve_id": _safe_str(advisory.get("cve_id")),
        "advisory_severity": _safe_str(advisory.get("severity"))
        or _safe_str(vuln.get("severity")),
        # Short, safe advisory summary only (sanitizer truncates to 200 chars).
        # NEVER the long advisory description/body.
        "advisory_summary": _safe_str(advisory.get("summary")),
        "cvss_score": cvss_score,
        "epss_percentage": epss_pct,
        "scope": _safe_str(dependency.get("scope")),
        "dismissed_reason": _safe_str(alert.get("dismissed_reason")),
        "created_at": _safe_str(alert.get("created_at")),
        "updated_at": _safe_str(alert.get("updated_at")),
        "fixed_at": _safe_str(alert.get("fixed_at")),
        "dismissed_at": _safe_str(alert.get("dismissed_at"))
        or _safe_str(alert.get("auto_dismissed_at")),
        "event_source": EVENT_SOURCE,
    }

    dismisser = alert.get("dismissed_by")
    actor = None
    if isinstance(dismisser, dict):
        actor = _safe_str(dismisser.get("login"))

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
        # Never an IP source for a Dependabot alert.
        source_ip=None,
        metadata=metadata,
        raw_ref=f"alert#{number}",
    )


def _resolve_credentials(integration: Integration) -> dict[str, Any]:
    """Decrypt credentials, minting a GitHub App installation token if needed.

    Mirrors github_code_scanning_ingestion_service. Installation tokens are
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


def ingest_github_dependabot_alerts(
    *,
    integration: Integration,
    workspace_id: uuid.UUID,
    db: Session,
    lookback_hours: int = 24,
    max_alerts: int = 1000,
) -> dict[str, Any]:
    """Ingest GitHub Dependabot alerts for one integration. Never raises.

    ``lookback_hours`` bounds the stored set to alerts created/updated within the
    window; permission/availability limits → ``permission_limited``; other
    failures → ``error_message`` (safe string).
    """
    summary = _empty_summary(integration.id)
    if integration.provider != PROVIDER:
        summary["error_message"] = "Not a GitHub integration."
        return summary
    summary["attempted"] = True

    try:
        credentials = _resolve_credentials(integration)
    except Exception:  # noqa: BLE001 — never leak credential errors
        logger.warning("github_dependabot: credential resolution failed (not logged)")
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
        alerts = connector.list_dependabot_alerts(credentials, max_alerts=cap)
    except AuthenticationError:
        summary["succeeded"] = True
        summary["permission_limited"] = True
        summary["error_message"] = (
            "GitHub Dependabot access is not permitted for this token/repo "
            "(requires Dependabot alerts enabled and security-events read scope)."
        )
        return summary
    except ConnectorError as exc:
        code = getattr(exc, "status_code", None)
        if code in (403, 404):
            summary["succeeded"] = True
            summary["permission_limited"] = True
            summary["error_message"] = (
                "GitHub Dependabot alerts are unavailable for this repository "
                "(feature disabled, repo unavailable, or insufficient token scope)."
            )
            return summary
        summary["error_message"] = "GitHub Dependabot request failed."
        return summary
    except RateLimitError:
        summary["error_message"] = "GitHub rate limit reached; try again later."
        return summary
    except NetworkError:
        summary["error_message"] = "Network error reaching GitHub."
        return summary
    except Exception:  # noqa: BLE001 — defensive; never break the caller
        logger.exception("github_dependabot: unexpected ingestion error")
        summary["error_message"] = "Unexpected error during Dependabot ingestion."
        return summary

    summary["alerts_seen"] = len(alerts)

    inserted = 0
    skipped = 0
    for alert in alerts:
        normalized = normalize_dependabot_alert(alert, repo_full_name=repo_full_name)
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
            logger.warning("github_dependabot: failed to upsert one alert; continuing")
            continue
        if outcome == "inserted":
            inserted += 1
        else:
            skipped += 1

    summary["succeeded"] = True
    summary["events_inserted"] = inserted
    summary["events_skipped"] = skipped
    return summary
