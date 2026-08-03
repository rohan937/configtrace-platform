"""Full-catalog summary tests (message 6 of N).

Proves 100% repository-wide launched-provider certification coverage:
every launched provider is certified, every manifest provider appears
exactly once, result ordering is deterministic, no provider is
silently skipped, and record/Finding totals derive from exact
discovered sets rather than hand-typed counts.
"""

from __future__ import annotations

import json

from app.provider_certification import discovery as disc
from app.provider_certification import migration_allowlist as ma
from app.provider_certification import runner

_ALL_26 = (
    "auth0", "aws", "azure", "clerk", "cloudflare", "datadog", "entra", "firebase",
    "github", "gitlab", "google_cloud", "jira", "kubernetes", "linear", "okta",
    "pagerduty", "sendgrid", "sentry", "shopify", "slack", "snowflake", "stripe",
    "supabase", "terraform_cloud", "twilio", "vercel",
)


class TestEveryManifestProviderAppearsOnce:
    def test_known_provider_ids_has_no_duplicates(self):
        ids = runner.known_provider_ids()
        assert len(ids) == len(set(ids)) == 26

    def test_known_provider_ids_matches_expected_26(self):
        assert set(runner.known_provider_ids()) == set(_ALL_26)

    def test_pilot_providers_constant_matches_known_ids(self):
        assert set(runner.PILOT_PROVIDERS) == set(runner.known_provider_ids())


class TestEveryLaunchedProviderIsCertified:
    def test_every_launched_provider_has_a_manifest(self):
        launched = disc.discover_launched_provider_ids()
        certified = set(runner.known_provider_ids())
        assert launched <= certified

    def test_no_launched_provider_remains_uncertified(self):
        launched = disc.discover_launched_provider_ids()
        certified = set(runner.known_provider_ids())
        assert launched - certified == set()

    def test_migration_allowlist_is_empty(self):
        assert ma.allowlisted_provider_ids() == frozenset()

    def test_coverage_is_exactly_100_percent(self):
        report = runner.adoption_report()
        assert report["coverage_percentage"] == 100.0

    def test_no_orphan_manifests(self):
        report = runner.adoption_report()
        assert report["orphan_manifest_count"] == 0
        assert report["orphan_manifest_provider_ids"] == []

    def test_no_unexpected_missing_providers(self):
        report = runner.adoption_report()
        assert report["missing_unexpected_count"] == 0
        assert report["unexpected_missing_provider_ids"] == []


class TestResultOrderingDeterministic:
    def test_certify_all_providers_sorted_by_id(self):
        results = runner.certify_all_providers()
        assert list(results) == sorted(results)

    def test_certify_all_providers_reproducible_across_calls(self):
        r1 = runner.certify_all_providers()
        r2 = runner.certify_all_providers()
        assert {pid: r.to_json() for pid, r in r1.items()} == {pid: r.to_json() for pid, r in r2.items()}

    def test_certification_summary_providers_sorted(self):
        summary = runner.certification_summary()
        assert list(summary["providers"]) == sorted(summary["providers"])


class TestNoProviderSilentlySkipped:
    def test_all_26_providers_certify_and_none_are_missing_from_results(self):
        results = runner.certify_all_providers()
        assert set(results) == set(_ALL_26)
        for pid in _ALL_26:
            assert pid in results, f"{pid} silently skipped from certify_all_providers()"

    def test_all_26_providers_have_a_deterministic_json_report_on_disk(self):
        reports_dir = runner._BACKEND_ROOT / "tests" / "reports" / "provider_certification"
        for pid in _ALL_26:
            path = reports_dir / f"{pid}.json"
            assert path.is_file(), f"missing report: {path}"
            data = json.loads(path.read_text())
            assert data["provider_id"] == pid


class TestAllBlockingGatesPass:
    def test_all_26_providers_certify_pass(self):
        results = runner.certify_all_providers()
        failing = {pid: r.overall_status for pid, r in results.items() if r.overall_status != "pass"}
        assert failing == {}, f"Non-passing providers: {failing}"

    def test_no_provider_has_a_failing_or_unknown_blocking_gate(self):
        results = runner.certify_all_providers()
        for pid, r in results.items():
            bad = [g.gate_id for g in r.gates if g.blocking and g.status in ("fail", "unknown")]
            assert bad == [], f"{pid} has bad blocking gates: {bad}"


class TestRecordAndFindingTotalsDeriveFromExactSets:
    def test_total_record_count_across_catalog_matches_sum_of_discovered_sets(self):
        total_from_manifests = 0
        total_from_discovery = 0
        for pid in runner.known_provider_ids():
            manifest = runner.get_manifest(pid)
            total_from_manifests += len(manifest.expected_record_types)
            total_from_discovery += len(disc.discover_schema_record_type_constants(pid))
        assert total_from_manifests == total_from_discovery

    def test_total_finding_count_across_catalog_matches_sum_of_discovered_sets(self):
        total_from_manifests = 0
        total_from_discovery = 0
        for pid in runner.known_provider_ids():
            manifest = runner.get_manifest(pid)
            total_from_manifests += len(manifest.security_finding_rule_ids)
            total_from_discovery += len(disc.discover_registry_rule_ids(pid))
        assert total_from_manifests == total_from_discovery

    def test_summary_report_record_and_finding_counts_are_internally_consistent(self):
        summary = runner.certification_summary()
        for pid, entry in summary["providers"].items():
            manifest = runner.get_manifest(pid)
            assert entry["record_count"] == len(manifest.expected_record_types)
            assert entry["finding_count"] == len(manifest.security_finding_rule_ids)


class TestDeterministicAdoptionAndSummaryReports:
    def test_adoption_report_is_byte_identical_across_two_generations(self):
        r1 = runner.adoption_report()
        r2 = runner.adoption_report()
        assert json.dumps(r1, sort_keys=True) == json.dumps(r2, sort_keys=True)

    def test_summary_report_is_byte_identical_across_two_generations(self):
        s1 = runner.certification_summary()
        s2 = runner.certification_summary()
        assert json.dumps(s1, sort_keys=True) == json.dumps(s2, sort_keys=True)

    def test_adoption_report_on_disk_matches_live_computation(self):
        path = runner._BACKEND_ROOT / "tests" / "reports" / "provider_certification_adoption.json"
        on_disk = json.loads(path.read_text())
        live = runner.adoption_report()
        assert on_disk == live
