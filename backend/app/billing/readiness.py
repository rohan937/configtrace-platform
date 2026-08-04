"""Production readiness check (Commercial Infrastructure message 2, spec item 48).

A pure, offline reporting function — never performs a live Paddle API
call, never a production transaction. Reports configuration STATUS only;
``verify_catalog`` (a separate, explicitly-invoked operation) is what
actually calls Paddle to compare catalog metadata, and only when
credentials are genuinely available (message-1 spec item 7 / message-2
spec item 7).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.billing.paddle_config import validate_paddle_configuration
from app.config import Settings


@dataclass(frozen=True)
class ReadinessCheck:
    name: str
    safe: bool
    detail: str


@dataclass(frozen=True)
class ReadinessReport:
    checks: tuple[ReadinessCheck, ...]

    @property
    def all_safe(self) -> bool:
        return all(c.safe for c in self.checks)

    @property
    def exit_code(self) -> int:
        return 0 if self.all_safe else 1

    def as_dict(self) -> dict:
        return {
            "all_safe": self.all_safe,
            "exit_code": self.exit_code,
            "checks": [{"name": c.name, "safe": c.safe, "detail": c.detail} for c in self.checks],
        }


def check_production_readiness(settings: Settings) -> ReadinessReport:
    """Report Paddle production readiness WITHOUT ever performing a live
    API call and WITHOUT ever including a secret VALUE — only presence/
    absence and format validity (message-2 spec item 48)."""
    checks: list[ReadinessCheck] = []

    env = settings.paddle_environment_normalized
    checks.append(
        ReadinessCheck("paddle_environment", env in ("sandbox", "production"), f"environment={env}")
    )

    checks.append(
        ReadinessCheck(
            "paddle_api_key_configured", bool(settings.PADDLE_API_KEY),
            "configured" if settings.PADDLE_API_KEY else "missing (value never shown)",
        )
    )
    checks.append(
        ReadinessCheck(
            "paddle_webhook_secret_configured", bool(settings.PADDLE_WEBHOOK_SECRET),
            "configured" if settings.PADDLE_WEBHOOK_SECRET else "missing (value never shown)",
        )
    )
    checks.append(
        ReadinessCheck(
            "paddle_client_token_expected",
            True,  # backend cannot see the frontend's NEXT_PUBLIC_PADDLE_CLIENT_TOKEN
            "frontend-only variable — not verifiable from the backend; confirm separately in Vercel",
        )
    )

    base_price = settings.effective_paddle_team_base_price_id
    checks.append(
        ReadinessCheck("paddle_team_base_price_configured", bool(base_price), "configured" if base_price else "missing")
    )
    additional_price = settings.effective_paddle_team_additional_seat_price_id
    checks.append(
        ReadinessCheck(
            "paddle_team_additional_seat_price_configured", bool(additional_price),
            "configured" if additional_price else "missing",
        )
    )

    checks.append(ReadinessCheck("webhook_route_enabled", True, "POST /paddle/webhook is always registered"))

    checkout_provider = settings.BILLING_PROVIDER or "stripe"
    checks.append(ReadinessCheck("checkout_provider", True, f"BILLING_PROVIDER={checkout_provider}"))

    checks.append(
        ReadinessCheck(
            "grace_period_configured", settings.BILLING_GRACE_PERIOD_DAYS >= 0,
            f"BILLING_GRACE_PERIOD_DAYS={settings.BILLING_GRACE_PERIOD_DAYS}",
        )
    )

    config_result = validate_paddle_configuration(settings)
    checks.append(
        ReadinessCheck(
            "catalog_configuration_consistent", config_result.valid,
            "no issues" if config_result.valid else f"{len(config_result.issues)} issue(s) found",
        )
    )

    # sandbox/live mismatch: an explicit cross-check beyond the generic
    # config-consistency check above.
    no_mismatch = True
    if base_price and additional_price and env in ("sandbox", "production"):
        # We cannot verify actual Paddle-side environment scoping of a
        # price ID from offline settings alone — this check only confirms
        # the two price IDs are distinct and the environment is a real
        # value; catalog_verification (live, opt-in) is what actually
        # confirms cross-environment safety against Paddle's API.
        no_mismatch = base_price != additional_price
    checks.append(
        ReadinessCheck(
            "no_sandbox_live_mismatch_detected", no_mismatch,
            "no obvious mismatch" if no_mismatch else "base and additional-seat price IDs are identical",
        )
    )

    return ReadinessReport(checks=tuple(checks))
