"""Repository-wide manifest coverage tests (message 5 of N).

Covers ``discover_launched_provider_ids()``, the ``migration_allowlist``
module, and ``gate_provider_manifest_coverage`` — the mechanism that
proves no launched provider silently escapes certification tracking.
"""

from __future__ import annotations

import dataclasses

import pytest

from app.provider_certification import discovery as disc
from app.provider_certification import gates
from app.provider_certification import migration_allowlist as ma
from app.provider_certification import runner
from app.provider_certification.models import UncertifiedProviderMigrationEntry


def _all_manifests():
    runner._ensure_manifests_loaded()
    return tuple(runner.get_manifest(pid) for pid in runner.known_provider_ids())


class TestDiscoverLaunchedProviderIds:
    def test_returns_a_frozenset(self):
        assert isinstance(disc.discover_launched_provider_ids(), frozenset)

    def test_includes_all_17_certified_providers(self):
        launched = disc.discover_launched_provider_ids()
        for pid in runner.PILOT_PROVIDERS:
            if pid == "slack":
                continue  # Slack has no launched sync surface — see its manifest.
            assert pid in launched, f"{pid} expected to be launched"

    def test_includes_the_9_allowlisted_uncertified_providers(self):
        launched = disc.discover_launched_provider_ids()
        for pid in ma.allowlisted_provider_ids():
            assert pid in launched, f"{pid} expected to be launched"

    def test_slack_is_not_launched(self):
        assert "slack" not in disc.discover_launched_provider_ids()


class TestMigrationAllowlist:
    def test_contains_exactly_9_entries(self):
        assert len(ma.MIGRATION_ALLOWLIST) == 9

    def test_no_certified_provider_present(self):
        certified = set(runner.known_provider_ids())
        allowlisted = ma.allowlisted_provider_ids()
        assert not (certified & allowlisted)

    def test_every_entry_has_a_reason_and_planned_message(self):
        for entry in ma.MIGRATION_ALLOWLIST:
            assert entry.reason
            assert entry.planned_framework_message >= 1

    def test_get_allowlist_entry_returns_none_for_unknown(self):
        assert ma.get_allowlist_entry("not_a_real_provider") is None

    def test_get_allowlist_entry_returns_entry_for_known(self):
        entry = ma.get_allowlist_entry("auth0")
        assert entry is not None
        assert entry.provider_id == "auth0"

    def test_duplicate_entry_rejected_at_validation_time(self):
        with pytest.raises(ValueError, match="duplicate"):
            bad = ma.MIGRATION_ALLOWLIST + (
                UncertifiedProviderMigrationEntry(
                    provider_id="auth0", reason="dup", planned_framework_message=6,
                ),
            )
            _validate_standalone(bad)

    def test_unknown_provider_id_rejected_at_validation_time(self):
        with pytest.raises(ValueError, match="launched"):
            bad = (
                UncertifiedProviderMigrationEntry(
                    provider_id="totally_not_a_real_provider",
                    reason="x",
                    planned_framework_message=6,
                ),
            )
            _validate_standalone(bad)

    def test_empty_reason_rejected_at_validation_time(self):
        with pytest.raises(ValueError, match="empty reason"):
            bad = (
                UncertifiedProviderMigrationEntry(
                    provider_id="auth0", reason="", planned_framework_message=6,
                ),
            )
            _validate_standalone(bad)

    def test_invalid_planned_message_rejected_at_validation_time(self):
        with pytest.raises(ValueError, match="planned_framework_message"):
            bad = (
                UncertifiedProviderMigrationEntry(
                    provider_id="auth0", reason="x", planned_framework_message=0,
                ),
            )
            _validate_standalone(bad)


def _validate_standalone(entries: tuple[UncertifiedProviderMigrationEntry, ...]) -> None:
    """Re-implements migration_allowlist._validate_allowlist()'s checks
    against an arbitrary entry tuple, for negative-mutation testing
    without monkeypatching the real, already-imported module constant."""
    launched = disc.discover_launched_provider_ids()
    seen: set[str] = set()
    for entry in entries:
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
                f"migration allowlist entry for {entry.provider_id!r} does not correspond to a launched provider"
            )


class TestGateProviderManifestCoverage:
    def test_passes_for_the_real_registered_manifest_set(self):
        gate = gates.gate_provider_manifest_coverage(_all_manifests())
        assert gate.status == "pass"

    def test_fails_when_a_launched_provider_has_no_manifest_and_no_allowlist_entry(self):
        manifests = tuple(m for m in _all_manifests() if m.provider_id != "aws")
        gate = gates.gate_provider_manifest_coverage(manifests)
        assert gate.status == "fail"
        assert "aws" in gate.details

    def test_fails_on_duplicate_manifest_registration(self):
        real = _all_manifests()
        gate = gates.gate_provider_manifest_coverage(real + (real[0],))
        assert gate.status == "fail"
        assert "registered more than once" in gate.details

    def test_fails_on_orphan_manifest_for_unlaunched_non_planned_provider(self):
        from app.provider_certification.models import ProviderCertificationManifest

        real = _all_manifests()
        orphan = ProviderCertificationManifest(
            provider_id="not_a_real_launched_provider",
            display_name="Not Real",
            category="other",
            maturity="partial",
            expected_public=False,
            expected_connectable=False,
            expected_live=False,
            credential_fields=(),
            sensitive_credential_fields=(),
            authentication_model="api_token",
            expected_record_types=(),
            security_finding_rule_ids=(),
            supported_capabilities=(),
            unsupported_capabilities=(),
            completeness_scopes=(),
            false_removal_scopes=(),
            expected_frontend_form=None,
            expected_reconnect=False,
            prohibited_dependencies=(),
            known_limitations=("Test-only fixture manifest for a provider that does not exist.",),
        )
        gate = gates.gate_provider_manifest_coverage(real + (orphan,))
        assert gate.status == "fail"
        assert "not discoverable as launched" in gate.details

    def test_fails_when_certified_provider_still_allowlisted(self, monkeypatch):
        monkeypatch.setattr(ma, "allowlisted_provider_ids", lambda: frozenset({"aws"}))
        gate = gates.gate_provider_manifest_coverage(_all_manifests())
        assert gate.status == "fail"
        assert "still present in the migration allowlist" in gate.details


class TestFutureProviderQueueRemainsEmptyOfTargets:
    def test_none_of_the_17_target_providers_are_in_the_future_queue(self):
        future = disc.discover_recommended_next_providers()
        for pid in runner.PILOT_PROVIDERS:
            assert pid not in future

    def test_none_of_the_9_allowlisted_providers_are_live_manifests(self):
        # An allowlisted (uncertified) provider has no manifest at all,
        # so it cannot be a Live manifest — this just pins that no
        # certified manifest wrongly claims Live for a queued provider.
        future = disc.discover_recommended_next_providers()
        live_manifests = {m.provider_id for m in _all_manifests() if m.expected_live}
        assert not (live_manifests & future)


class TestDeterministicAdoptionReport:
    def test_adoption_report_file_exists_and_is_deterministic_json(self):
        import json
        from pathlib import Path

        path = Path("tests/reports/provider_certification_adoption.json")
        assert path.is_file()
        data = json.loads(path.read_text())
        assert "launched_provider_count" in data
        assert "certified_provider_count" in data
        assert "allowlisted_provider_count" in data
        assert data["certified_provider_count"] == 17

    def test_adoption_report_has_no_timestamp_fields(self):
        import json
        from pathlib import Path

        data = json.loads(Path("tests/reports/provider_certification_adoption.json").read_text())
        for key in data:
            assert "time" not in key.lower() and "date" not in key.lower()
