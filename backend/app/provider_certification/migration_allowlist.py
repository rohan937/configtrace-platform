"""Migration allowlist (message 5 of N).

Every launched provider not yet certified must appear here, with a
durable reason and a planned framework message — never a silent gap.
This project tracks work by "message N" (this file, this commit
history), not calendar dates, so entries reference a planned message
number rather than a date.

Sentry/Snowflake/Okta/Entra/Kubernetes/GitHub/GitLab/Cloudflare/
Supabase/Firebase/Stripe/AWS/Vercel/Datadog/PagerDuty/Slack/Jira are
certified as of this message and MUST NOT appear here — see
``test_provider_certification_manifest_coverage.py`` for the test that
pins this.
"""

from __future__ import annotations

from app.provider_certification.models import UncertifiedProviderMigrationEntry

MIGRATION_ALLOWLIST: tuple[UncertifiedProviderMigrationEntry, ...] = (
    UncertifiedProviderMigrationEntry(
        provider_id="auth0",
        reason="Launched (backend sync + frontend connectable + capability-matrix registered) but not yet given a certification manifest.",
        planned_framework_message=6,
        evidence=("tests/test_milestone81h_auth0_provider_depth_qa.py",),
    ),
    UncertifiedProviderMigrationEntry(
        provider_id="azure",
        reason="Launched but not yet given a certification manifest.",
        planned_framework_message=6,
        evidence=(),
    ),
    UncertifiedProviderMigrationEntry(
        provider_id="clerk",
        reason="Launched but not yet given a certification manifest.",
        planned_framework_message=6,
        evidence=(),
    ),
    UncertifiedProviderMigrationEntry(
        provider_id="google_cloud",
        reason="Launched but not yet given a certification manifest.",
        planned_framework_message=6,
        evidence=(),
    ),
    UncertifiedProviderMigrationEntry(
        provider_id="linear",
        reason="Launched but not yet given a certification manifest.",
        planned_framework_message=6,
        evidence=(),
    ),
    UncertifiedProviderMigrationEntry(
        provider_id="sendgrid",
        reason="Launched but not yet given a certification manifest.",
        planned_framework_message=6,
        evidence=(),
    ),
    UncertifiedProviderMigrationEntry(
        provider_id="shopify",
        reason="Launched (maturity='complete' in the real capability matrix) but not yet given a certification manifest.",
        planned_framework_message=6,
        evidence=(),
    ),
    UncertifiedProviderMigrationEntry(
        provider_id="terraform_cloud",
        reason="Launched but not yet given a certification manifest. Also present in the future-provider recommendation queue as of message 3's freeze audit — a genuine pre-existing repository quirk (already-launched provider still recommended), not introduced by this framework.",
        planned_framework_message=6,
        evidence=(),
    ),
    UncertifiedProviderMigrationEntry(
        provider_id="twilio",
        reason="Launched but not yet given a certification manifest.",
        planned_framework_message=6,
        evidence=(),
    ),
)


def _validate_allowlist() -> None:
    from app.provider_certification import discovery as disc

    launched = disc.discover_launched_provider_ids()
    seen: set[str] = set()
    for entry in MIGRATION_ALLOWLIST:
        if entry.provider_id in seen:
            raise ValueError(f"duplicate migration allowlist entry for provider_id={entry.provider_id!r}")
        seen.add(entry.provider_id)
        if not entry.reason:
            raise ValueError(f"migration allowlist entry for {entry.provider_id!r} has an empty reason")
        if entry.planned_framework_message < 1:
            raise ValueError(
                f"migration allowlist entry for {entry.provider_id!r} has an invalid planned_framework_message"
            )
        if entry.provider_id not in launched:
            raise ValueError(
                f"migration allowlist entry for {entry.provider_id!r} does not correspond to a "
                "launched provider (real discovery found no such launched provider) — unknown "
                "provider IDs are rejected"
            )


_validate_allowlist()


def allowlisted_provider_ids() -> frozenset[str]:
    return frozenset(entry.provider_id for entry in MIGRATION_ALLOWLIST)


def get_allowlist_entry(provider_id: str) -> UncertifiedProviderMigrationEntry | None:
    for entry in MIGRATION_ALLOWLIST:
        if entry.provider_id == provider_id:
            return entry
    return None
