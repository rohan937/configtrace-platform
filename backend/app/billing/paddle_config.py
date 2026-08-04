"""Paddle configuration validation (Commercial Infrastructure message 2).

Fail-closed: every check here either passes cleanly or raises/returns a
typed failure — Paddle is never treated as "configured enough" on a
partial or inconsistent setup. No secret value is ever included in an
error message.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.config import Settings

# Paddle API keys and client-side tokens carry documented prefixes that
# distinguish sandbox from live — verified against Paddle's own
# documentation conventions (apikey_/pdl_ prefixes are environment-scoped
# by Paddle's dashboard, not guessed here). We validate presence of the
# expected prefix only when Paddle itself makes the distinction visible;
# we never invent a distinction Paddle doesn't document.
_SANDBOX_API_KEY_MARKERS = ("_sdbx_", "sandbox")
_LIVE_API_KEY_MARKERS = ("_live_", "live")


@dataclass(frozen=True)
class PaddleConfigurationIssue:
    field: str
    message: str


@dataclass(frozen=True)
class PaddleConfigurationResult:
    valid: bool
    issues: tuple[PaddleConfigurationIssue, ...] = field(default_factory=tuple)

    def as_dict(self) -> dict:
        return {
            "valid": self.valid,
            "issues": [{"field": i.field, "message": i.message} for i in self.issues],
        }


def _looks_sandbox(value: str) -> bool:
    lowered = value.lower()
    return any(marker in lowered for marker in _SANDBOX_API_KEY_MARKERS)


def _looks_live(value: str) -> bool:
    lowered = value.lower()
    return any(marker in lowered for marker in _LIVE_API_KEY_MARKERS)


def validate_paddle_configuration(settings: Settings) -> PaddleConfigurationResult:
    """Validate the current Paddle settings for internal consistency.

    Never includes a secret VALUE in any issue message — only field names
    and generic descriptions (message-2 spec item 4: "no secret appears in
    validation errors").
    """
    issues: list[PaddleConfigurationIssue] = []

    env = settings.paddle_environment_normalized
    if env == "not_configured":
        issues.append(
            PaddleConfigurationIssue(
                "PADDLE_ENVIRONMENT",
                "must be exactly 'sandbox' or 'production'",
            )
        )

    api_key = settings.PADDLE_API_KEY
    if not api_key:
        issues.append(PaddleConfigurationIssue("PADDLE_API_KEY", "is not set"))
    elif env in ("sandbox", "production"):
        # Only flag an api key when it looks UNAMBIGUOUSLY like the other
        # environment — an api key with no recognizable marker at all is
        # not flagged, since Paddle does not guarantee a marker exists in
        # every key format.
        if env == "sandbox" and _looks_live(api_key) and not _looks_sandbox(api_key):
            issues.append(
                PaddleConfigurationIssue(
                    "PADDLE_API_KEY", "looks like a live credential but PADDLE_ENVIRONMENT=sandbox"
                )
            )
        if env == "production" and _looks_sandbox(api_key) and not _looks_live(api_key):
            issues.append(
                PaddleConfigurationIssue(
                    "PADDLE_API_KEY", "looks like a sandbox credential but PADDLE_ENVIRONMENT=production"
                )
            )

    if not settings.PADDLE_WEBHOOK_SECRET:
        issues.append(PaddleConfigurationIssue("PADDLE_WEBHOOK_SECRET", "is not set"))

    base_price = settings.effective_paddle_team_base_price_id
    if not base_price:
        issues.append(
            PaddleConfigurationIssue(
                "PADDLE_TEAM_BASE_PRICE_ID", "is not set (no PADDLE_TEAM_BASE_PRICE_ID or PADDLE_BASE_PRICE_ID)"
            )
        )

    additional_price = settings.effective_paddle_team_additional_seat_price_id
    if not additional_price:
        issues.append(
            PaddleConfigurationIssue(
                "PADDLE_TEAM_ADDITIONAL_SEAT_PRICE_ID",
                "is not set (no PADDLE_TEAM_ADDITIONAL_SEAT_PRICE_ID or PADDLE_ADDITIONAL_SEAT_PRICE_ID)",
            )
        )

    if base_price and additional_price and base_price == additional_price:
        issues.append(
            PaddleConfigurationIssue(
                "PADDLE_TEAM_BASE_PRICE_ID",
                "must not equal PADDLE_TEAM_ADDITIONAL_SEAT_PRICE_ID — they are two distinct catalog items",
            )
        )

    if settings.BILLING_GRACE_PERIOD_DAYS < 0:
        issues.append(
            PaddleConfigurationIssue("BILLING_GRACE_PERIOD_DAYS", "must be >= 0")
        )

    return PaddleConfigurationResult(valid=not issues, issues=tuple(issues))


def requires_stripe_settings(settings: Settings) -> bool:
    """True only when Stripe is the ACTIVE checkout provider. Stripe
    settings are never required merely because Paddle is being configured
    (message-2 spec item 4)."""
    return (settings.BILLING_PROVIDER or "stripe") == "stripe"


def requires_paddle_settings(settings: Settings) -> bool:
    """True only when Paddle is the ACTIVE checkout provider."""
    return (settings.BILLING_PROVIDER or "stripe") == "paddle"
