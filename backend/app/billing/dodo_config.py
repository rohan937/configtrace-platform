"""Dodo Payments configuration validation (Dodo Payments message 1).

Fail-closed: every check here either passes cleanly or returns a typed
failure — Dodo is never treated as "configured enough" on a partial or
inconsistent setup. No secret value is ever included in an error message
— only field names and generic descriptions.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.config import Settings

# Dodo does not document an unambiguous test/live credential-prefix
# convention the way Stripe's sk_test_/sk_live_ does (verified: the
# official docs describe test/live as two entirely separate dashboards
# with their own API keys, not a shared key-space distinguished by
# prefix). We therefore do NOT attempt prefix-sniffing for
# DODO_API_KEY — unlike Paddle's best-effort marker check, inventing a
# distinction Dodo doesn't document would be guessing, which this
# message's instructions explicitly forbid. Environment consistency is
# enforced structurally instead: DODO_ENVIRONMENT must be exactly "test"
# or "live", and the client's base URL is derived from that value alone.
_VALID_ENVIRONMENTS = ("test", "live")


@dataclass(frozen=True)
class DodoConfigurationIssue:
    field: str
    message: str


@dataclass(frozen=True)
class DodoConfigurationResult:
    valid: bool
    issues: tuple[DodoConfigurationIssue, ...] = field(default_factory=tuple)

    def as_dict(self) -> dict:
        return {
            "valid": self.valid,
            "issues": [{"field": i.field, "message": i.message} for i in self.issues],
        }


def validate_dodo_configuration(settings: Settings) -> DodoConfigurationResult:
    """Validate the current Dodo settings for internal consistency. Never
    includes a secret VALUE in any issue message — only field names and
    generic descriptions."""
    issues: list[DodoConfigurationIssue] = []

    env = settings.dodo_environment_normalized
    if env == "not_configured":
        issues.append(
            DodoConfigurationIssue("DODO_ENVIRONMENT", "must be exactly 'test' or 'live'")
        )

    if not settings.DODO_API_KEY:
        issues.append(DodoConfigurationIssue("DODO_API_KEY", "is not set"))

    if not settings.DODO_WEBHOOK_SECRET:
        issues.append(DodoConfigurationIssue("DODO_WEBHOOK_SECRET", "is not set"))
    elif not settings.DODO_WEBHOOK_SECRET.startswith("whsec_"):
        # Documented, verified requirement: the Standard Webhooks spec
        # (which Dodo's own docs say its webhooks follow) requires the
        # symmetric secret to be prefixed "whsec_" and base64-encoded.
        issues.append(
            DodoConfigurationIssue(
                "DODO_WEBHOOK_SECRET", "must start with the documented 'whsec_' prefix"
            )
        )

    pro_product = settings.DODO_PRO_PRODUCT_ID
    if not pro_product:
        issues.append(DodoConfigurationIssue("DODO_PRO_PRODUCT_ID", "is not set"))

    team_product = settings.DODO_TEAM_PRODUCT_ID
    if not team_product:
        issues.append(DodoConfigurationIssue("DODO_TEAM_PRODUCT_ID", "is not set"))

    if not settings.DODO_TEAM_ADDITIONAL_SEAT_ADDON_ID:
        issues.append(DodoConfigurationIssue("DODO_TEAM_ADDITIONAL_SEAT_ADDON_ID", "is not set"))

    if pro_product and team_product and pro_product == team_product:
        issues.append(
            DodoConfigurationIssue(
                "DODO_PRO_PRODUCT_ID",
                "must not equal DODO_TEAM_PRODUCT_ID — they are two distinct catalog products",
            )
        )

    if settings.BILLING_GRACE_PERIOD_DAYS < 0:
        issues.append(DodoConfigurationIssue("BILLING_GRACE_PERIOD_DAYS", "must be >= 0"))

    return DodoConfigurationResult(valid=not issues, issues=tuple(issues))


def requires_dodo_settings(settings: Settings) -> bool:
    """True only when Dodo is the ACTIVE checkout provider. Dodo settings
    are never required merely because other providers are configured."""
    return (settings.BILLING_PROVIDER or "stripe") == "dodo"


@dataclass(frozen=True)
class DodoReadinessCheck:
    name: str
    present: bool
    detail: str = ""


@dataclass(frozen=True)
class DodoReadinessReport:
    checks: tuple[DodoReadinessCheck, ...]

    @property
    def all_present(self) -> bool:
        return all(c.present for c in self.checks)

    @property
    def exit_code(self) -> int:
        return 0 if self.all_present else 1

    def as_dict(self) -> dict:
        return {
            "all_present": self.all_present,
            "checks": [{"name": c.name, "present": c.present, "detail": c.detail} for c in self.checks],
        }


def check_dodo_readiness(settings: Settings) -> DodoReadinessReport:
    """Pure, offline readiness report — reports FIELD PRESENCE only, never
    a value, and NEVER makes an HTTP call (proven by
    ``tests/test_commercial_dodo_config.py::TestReadinessNeverCallsLiveAPI``,
    which monkeypatches ``httpx.Client.request`` to raise if invoked during
    this function)."""
    checks = (
        DodoReadinessCheck(
            "dodo_environment", settings.dodo_environment_normalized != "not_configured",
            detail=settings.dodo_environment_normalized,
        ),
        DodoReadinessCheck("dodo_api_key_configured", bool(settings.DODO_API_KEY)),
        DodoReadinessCheck("dodo_webhook_secret_configured", bool(settings.DODO_WEBHOOK_SECRET)),
        DodoReadinessCheck("dodo_pro_product_configured", bool(settings.DODO_PRO_PRODUCT_ID)),
        DodoReadinessCheck("dodo_team_product_configured", bool(settings.DODO_TEAM_PRODUCT_ID)),
        DodoReadinessCheck(
            "dodo_team_additional_seat_addon_configured",
            bool(settings.DODO_TEAM_ADDITIONAL_SEAT_ADDON_ID),
        ),
        DodoReadinessCheck("checkout_provider", True, detail=settings.BILLING_PROVIDER or "stripe"),
        DodoReadinessCheck(
            "catalog_configuration_consistent", validate_dodo_configuration(settings).valid
        ),
        DodoReadinessCheck(
            "not_routing_production_to_dodo",
            (settings.BILLING_PROVIDER or "stripe") != "dodo",
            detail="this message never sets BILLING_PROVIDER=dodo in any deployed environment",
        ),
    )
    return DodoReadinessReport(checks=checks)
