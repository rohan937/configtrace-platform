"""Sync failure classification — M32.

Maps Python exceptions raised during a sync to structured, machine-readable
failure categories, provider-specific error codes, and user-facing remediation
hints.

Design goals
------------
* Machine-readable: ``failure_category`` and ``error_code`` are stable
  identifiers that the frontend can use to render tailored error UIs.
* User-friendly: ``recommended_action`` is plain English shown directly in the
  UI so the user knows what to do.
* Provider-aware: the same exception type (e.g. ``AuthenticationError``) maps
  to a different error code depending on whether the integration uses a GitHub
  PAT, a GitHub App, or a Cloudflare token.
* Safe: exception messages are NOT included in returned strings — the caller
  passes the raw ``error_message`` separately so we never risk leaking a token
  or private key via the classification fields.

Failure categories (stable, machine-readable)
---------------------------------------------
  authentication        — credentials rejected (401/403)
  resource_missing      — target resource deleted/moved (404)
  provider_unavailable  — provider returned 5xx
  rate_limited          — provider enforced rate limiting (429)
  network               — transport-level failure (no HTTP response received)
  config_error          — server misconfiguration (bad private key, missing env)
  internal_error        — unexpected Python error
  unknown               — unclassified

Error codes (provider-specific, stable)
----------------------------------------
GitHub (PAT):
  github_token_revoked, github_repo_not_found, github_api_unavailable
GitHub App:
  github_app_uninstalled, github_repo_not_found, github_api_unavailable
Cloudflare:
  cloudflare_token_revoked, cloudflare_zone_not_found, cloudflare_api_unavailable
Vercel:
  vercel_token_revoked, vercel_project_not_found, vercel_api_unavailable
Generic:
  rate_limit_exceeded, network_error, config_error, internal_error, unknown
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class FailureClassification:
    """Structured description of a sync failure.

    Attributes:
        category:           Broad, stable category string.
        error_code:         Provider-specific, stable code string.
        recommended_action: Plain-English remediation hint for the user.
    """

    category: str
    error_code: str
    recommended_action: str


# Threshold above which an integration is considered to "need attention".
# Exposed here so tests and the router helper share the same constant.
NEEDS_ATTENTION_THRESHOLD = 3

# How many seconds constitute the failure-alert cooldown period (24 hours).
FAILURE_ALERT_COOLDOWN_SECONDS = 86_400


def classify_failure(
    exc: Exception,
    provider: str,
    credential_type: Optional[str] = None,
) -> FailureClassification:
    """Return a :class:`FailureClassification` for *exc*.

    Args:
        exc:             The exception that caused the sync to fail.
        provider:        ``"cloudflare"`` or ``"github"`` — used to select
                         provider-specific error codes.
        credential_type: ``"github_app"`` or ``"pat"`` (GitHub only) — used
                         to distinguish App-uninstall from token-revoke.
                         Pass ``None`` when not applicable or unknown.

    Returns:
        A :class:`FailureClassification` with stable ``category``,
        ``error_code``, and ``recommended_action`` strings.
    """
    # Import inside function to keep the module importable without the full
    # connector stack (e.g. during unit tests that mock connectors).
    from app.connectors.exceptions import (
        AuthenticationError,
        ConnectorError,
        NetworkError,
        RateLimitError,
    )

    # ── Authentication failures ───────────────────────────────────────────────
    if isinstance(exc, AuthenticationError):
        return _classify_auth(provider, credential_type)

    # ── Rate limiting ─────────────────────────────────────────────────────────
    if isinstance(exc, RateLimitError):
        return FailureClassification(
            category="rate_limited",
            error_code="rate_limit_exceeded",
            recommended_action=(
                "The provider's rate limit was reached. "
                "The next scheduled sync will retry automatically."
            ),
        )

    # ── Network errors (checked BEFORE generic ConnectorError because
    #    NetworkError is a subclass of ConnectorError) ─────────────────────────
    if isinstance(exc, NetworkError):
        return FailureClassification(
            category="network",
            error_code="network_error",
            recommended_action=(
                "A network error prevented the sync from completing. "
                "The next scheduled sync will retry automatically."
            ),
        )

    # ── Generic ConnectorError: inspect status_code ───────────────────────────
    if isinstance(exc, ConnectorError):
        return _classify_connector(exc, provider)

    # ── ValueError: typically a configuration / decoding problem ─────────────
    # Examples: decode_private_key raised ValueError, missing integration row.
    if isinstance(exc, (ValueError, KeyError)):
        return FailureClassification(
            category="config_error",
            error_code="config_error",
            recommended_action=(
                "A server configuration error occurred. "
                "Contact support if the problem persists."
            ),
        )

    # ── RuntimeError: GitHub App JWT or installation token minting ───────────
    if isinstance(exc, RuntimeError):
        # RuntimeError from mint_app_jwt / mint_installation_token
        msg = str(exc).lower()
        if "authentication failed" in msg or "401" in msg or "403" in msg:
            return _classify_auth(provider, credential_type)
        if "installation" in msg and ("not found" in msg or "404" in msg):
            return FailureClassification(
                category="authentication",
                error_code="github_app_uninstalled",
                recommended_action=(
                    "The GitHub App installation was not found. "
                    "Re-install the GitHub App from your integrations page."
                ),
            )
        # Treat remaining RuntimeErrors as provider unavailable
        return FailureClassification(
            category="provider_unavailable",
            error_code=(
                "github_api_unavailable"
                if provider == "github"
                else f"{provider}_api_unavailable"
                if provider
                else "provider_unavailable"
            ),
            recommended_action=(
                "The provider API returned an unexpected error. "
                "The next scheduled sync will retry automatically."
            ),
        )

    # ── Catch-all ─────────────────────────────────────────────────────────────
    return FailureClassification(
        category="unknown",
        error_code="unknown",
        recommended_action=(
            "An unexpected error occurred. "
            "Check the server logs or contact support."
        ),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _classify_auth(
    provider: str, credential_type: Optional[str]
) -> FailureClassification:
    """Return an authentication FailureClassification for the given provider."""
    if provider == "github":
        if credential_type == "github_app":
            return FailureClassification(
                category="authentication",
                error_code="github_app_uninstalled",
                recommended_action=(
                    "The GitHub App installation was revoked or uninstalled. "
                    "Re-install the GitHub App from your integrations page."
                ),
            )
        # PAT path (credential_type == "pat" or None)
        return FailureClassification(
            category="authentication",
            error_code="github_token_revoked",
            recommended_action=(
                "Your GitHub Personal Access Token was revoked or expired. "
                "Reconnect this integration with a new token."
            ),
        )
    if provider == "cloudflare":
        return FailureClassification(
            category="authentication",
            error_code="cloudflare_token_revoked",
            recommended_action=(
                "Your Cloudflare API token was revoked or expired. "
                "Reconnect this integration with a new token."
            ),
        )
    if provider == "vercel":
        return FailureClassification(
            category="authentication",
            error_code="vercel_token_revoked",
            recommended_action=(
                "Your Vercel API token was revoked or expired. "
                "Reconnect this integration with a new token."
            ),
        )
    # Unknown provider
    return FailureClassification(
        category="authentication",
        error_code="credentials_rejected",
        recommended_action=(
            "The provider rejected the stored credentials. "
            "Reconnect this integration with fresh credentials."
        ),
    )


def _classify_connector(exc: "ConnectorError", provider: str) -> FailureClassification:
    """Classify a generic ConnectorError by its HTTP status_code."""
    status = exc.status_code

    if status == 404:
        if provider == "github":
            return FailureClassification(
                category="resource_missing",
                error_code="github_repo_not_found",
                recommended_action=(
                    "The GitHub repository was not found. "
                    "Verify it still exists and the integration has access."
                ),
            )
        if provider == "cloudflare":
            return FailureClassification(
                category="resource_missing",
                error_code="cloudflare_zone_not_found",
                recommended_action=(
                    "The Cloudflare zone was not found. "
                    "Verify the Zone ID is correct."
                ),
            )
        if provider == "vercel":
            return FailureClassification(
                category="resource_missing",
                error_code="vercel_project_not_found",
                recommended_action=(
                    "The Vercel project was not found. "
                    "Verify the Project ID is correct."
                ),
            )
        return FailureClassification(
            category="resource_missing",
            error_code="resource_not_found",
            recommended_action=(
                "The monitored resource was not found. "
                "Verify it still exists and the integration has access."
            ),
        )

    if status is not None and status >= 500:
        if provider == "github":
            code = "github_api_unavailable"
        elif provider == "cloudflare":
            code = "cloudflare_api_unavailable"
        elif provider == "vercel":
            code = "vercel_api_unavailable"
        else:
            code = "provider_unavailable"
        return FailureClassification(
            category="provider_unavailable",
            error_code=code,
            recommended_action=(
                "The provider API is temporarily unavailable. "
                "The next scheduled sync will retry automatically."
            ),
        )

    # Other ConnectorErrors (unexpected status codes, parse errors, etc.)
    return FailureClassification(
        category="internal_error",
        error_code="internal_error",
        recommended_action=(
            "An unexpected error occurred while communicating with the provider. "
            "Check the server logs for details."
        ),
    )
