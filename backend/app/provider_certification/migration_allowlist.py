"""Migration allowlist (message 5 of N; emptied in message 6).

Every launched provider not yet certified must appear here, with a
durable reason and a planned framework message — never a silent gap.
This project tracks work by "message N" (this file, this commit
history), not calendar dates, so entries reference a planned message
number rather than a date.

As of message 6, ALL 26 launched providers (the 17 certified in
messages 1-5 plus auth0/azure/clerk/google_cloud/linear/sendgrid/
shopify/terraform_cloud/twilio, certified this message) have registered
certification manifests. The allowlist is intentionally empty — no
launched provider may appear here. The mechanism itself is retained
(not deleted) for any genuinely future, controlled migration of a
provider not yet launched at the time it's added; see
``test_provider_certification_manifest_coverage.py`` and
``test_provider_certification_migration_allowlist.py`` for the tests
pinning zero launched-provider entries and full validation coverage.
"""

from __future__ import annotations

from app.provider_certification.models import UncertifiedProviderMigrationEntry

MIGRATION_ALLOWLIST: tuple[UncertifiedProviderMigrationEntry, ...] = ()


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
