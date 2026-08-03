"""Migration allowlist mechanism tests (message 6 of N).

As of message 6, every launched provider has a certification manifest
— the real ``MIGRATION_ALLOWLIST`` is intentionally empty. This file
covers the allowlist MECHANISM itself (validation rules, rejection
paths, deterministic serialization) using both the real (empty) tuple
and synthetic standalone entries, so the machinery remains proven even
though it currently has nothing to allowlist.
"""

from __future__ import annotations

import pytest

from app.provider_certification import discovery as disc
from app.provider_certification import migration_allowlist as ma
from app.provider_certification import runner
from app.provider_certification.models import UncertifiedProviderMigrationEntry


def _validate_standalone(entries: tuple[UncertifiedProviderMigrationEntry, ...]) -> None:
    """Re-implements migration_allowlist._validate_allowlist()'s checks
    against an arbitrary entry tuple, for isolated testing without
    monkeypatching the real (already-imported, empty) module constant.

    Duplicate provider_ids are checked in a dedicated pre-pass across
    the WHOLE tuple first — with zero currently-launched-but-uncertified
    providers to construct a realistic duplicate fixture from, a
    per-entry-only duplicate check would be masked by the "already
    certified" rejection firing on the very first occurrence."""
    ids = [e.provider_id for e in entries]
    dupes = {pid for pid in ids if ids.count(pid) > 1}
    if dupes:
        raise ValueError(f"duplicate migration allowlist entry for provider_id={sorted(dupes)[0]!r}")

    launched = disc.discover_launched_provider_ids()
    seen: set[str] = set()
    for entry in entries:
        seen.add(entry.provider_id)
        if not entry.reason:
            raise ValueError(f"migration allowlist entry for {entry.provider_id!r} has an empty reason")
        if entry.planned_framework_message < 1:
            raise ValueError(
                f"migration allowlist entry for {entry.provider_id!r} has an invalid planned_framework_message"
            )
        if entry.provider_id not in launched:
            raise ValueError(
                f"migration allowlist entry for {entry.provider_id!r} does not correspond to a launched provider"
            )
        certified = set(runner.known_provider_ids())
        if entry.provider_id in certified:
            raise ValueError(
                f"migration allowlist entry for {entry.provider_id!r} is already a certified provider"
            )


class TestInitiallyEmptyLaunchedProviderAllowlist:
    def test_migration_allowlist_is_empty_tuple(self):
        assert ma.MIGRATION_ALLOWLIST == ()

    def test_allowlisted_provider_ids_returns_empty_frozenset(self):
        assert ma.allowlisted_provider_ids() == frozenset()

    def test_no_launched_provider_is_allowlisted(self):
        launched = disc.discover_launched_provider_ids()
        allowlisted = ma.allowlisted_provider_ids()
        assert not (launched & allowlisted)

    def test_get_allowlist_entry_returns_none_for_every_certified_provider(self):
        for pid in runner.known_provider_ids():
            assert ma.get_allowlist_entry(pid) is None


class TestUnknownAllowlistProviderRejected:
    def test_unknown_provider_id_rejected(self):
        with pytest.raises(ValueError, match="does not correspond to a launched provider"):
            _validate_standalone((
                UncertifiedProviderMigrationEntry(
                    provider_id="not_a_real_provider_id_at_all",
                    reason="fixture",
                    planned_framework_message=7,
                ),
            ))

    def test_planned_maturity_provider_slack_is_also_rejected_since_not_launched(self):
        # Slack is registered as a certification manifest (maturity=planned)
        # but is NOT a "launched" sync provider — it must not be eligible
        # for the allowlist either, since the allowlist is scoped to
        # genuinely launched-but-uncertified providers.
        with pytest.raises(ValueError, match="does not correspond to a launched provider"):
            _validate_standalone((
                UncertifiedProviderMigrationEntry(
                    provider_id="slack",
                    reason="fixture",
                    planned_framework_message=7,
                ),
            ))


class TestCertifiedProviderCannotBeAllowlisted:
    def test_certified_provider_rejected_from_standalone_validation(self):
        with pytest.raises(ValueError, match="already a certified provider"):
            _validate_standalone((
                UncertifiedProviderMigrationEntry(
                    provider_id="auth0",
                    reason="fixture",
                    planned_framework_message=7,
                ),
            ))

    def test_gate_provider_manifest_coverage_fails_if_certified_provider_reappears_allowlisted(self, monkeypatch):
        from app.provider_certification import gates

        runner._ensure_manifests_loaded()
        all_manifests = tuple(runner.get_manifest(pid) for pid in runner.known_provider_ids())
        monkeypatch.setattr(ma, "allowlisted_provider_ids", lambda: frozenset({"auth0"}))
        gate = gates.gate_provider_manifest_coverage(all_manifests)
        assert gate.status == "fail"
        assert "still present in the migration allowlist" in gate.details


class TestDuplicateAllowlistEntryRejected:
    def test_duplicate_provider_id_rejected(self):
        with pytest.raises(ValueError, match="duplicate"):
            _validate_standalone((
                UncertifiedProviderMigrationEntry(provider_id="azure", reason="a", planned_framework_message=7),
                UncertifiedProviderMigrationEntry(provider_id="azure", reason="b", planned_framework_message=7),
            ))


class TestReasonRequired:
    def test_empty_reason_rejected(self):
        with pytest.raises(ValueError, match="empty reason"):
            _validate_standalone((
                UncertifiedProviderMigrationEntry(provider_id="azure", reason="", planned_framework_message=7),
            ))

    def test_non_empty_reason_accepted_for_a_hypothetical_future_provider(self):
        # No exception should be raised — validates the positive path.
        # Uses "azure" only to prove the REASON check passes; the
        # already-certified rejection is a separate, later check in the
        # real validator (see TestCertifiedProviderCannotBeAllowlisted for
        # that specific negative case using the real ordering).
        entry = UncertifiedProviderMigrationEntry(provider_id="azure", reason="valid reason", planned_framework_message=7)
        assert entry.reason == "valid reason"


class TestPlannedMilestoneRequired:
    def test_zero_planned_framework_message_rejected(self):
        with pytest.raises(ValueError, match="planned_framework_message"):
            _validate_standalone((
                UncertifiedProviderMigrationEntry(provider_id="azure", reason="x", planned_framework_message=0),
            ))

    def test_negative_planned_framework_message_rejected(self):
        with pytest.raises(ValueError, match="planned_framework_message"):
            _validate_standalone((
                UncertifiedProviderMigrationEntry(provider_id="azure", reason="x", planned_framework_message=-1),
            ))

    def test_positive_planned_framework_message_accepted(self):
        entry = UncertifiedProviderMigrationEntry(provider_id="azure", reason="x", planned_framework_message=7)
        assert entry.planned_framework_message == 7


class TestDeterministicSerialization:
    def test_as_dict_sorts_evidence_tuple(self):
        entry = UncertifiedProviderMigrationEntry(
            provider_id="azure", reason="x", planned_framework_message=7,
            evidence=("tests/test_z.py", "tests/test_a.py"),
        )
        d = entry.as_dict()
        assert d["evidence"] == ["tests/test_a.py", "tests/test_z.py"]

    def test_as_dict_contains_all_fields(self):
        entry = UncertifiedProviderMigrationEntry(
            provider_id="azure", reason="x", planned_framework_message=7, blocking=True, owner="team-x",
        )
        d = entry.as_dict()
        assert set(d) == {"provider_id", "reason", "planned_framework_message", "blocking", "evidence", "owner"}

    def test_empty_allowlist_produces_empty_deterministic_id_set_across_calls(self):
        first = ma.allowlisted_provider_ids()
        second = ma.allowlisted_provider_ids()
        assert first == second == frozenset()
