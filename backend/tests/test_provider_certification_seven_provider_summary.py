"""Seven-provider summary tests (message 3 of N).

Covers ``certify_all_providers()`` across all 7 pilot providers, the
enhanced ``certification_summary()`` fields added in message 3
(reachability/parity evidence coverage, exemption_count, warnings,
deferred_gates), deterministic sorted-by-ID ordering, and deterministic
JSON report generation for all 7 providers plus summary.json.
"""

from __future__ import annotations

import json

from app.provider_certification import runner

_ALL_SEVEN = ("entra", "github", "gitlab", "kubernetes", "okta", "sentry", "snowflake")


class TestCertifyAllSevenProviders:
    def test_known_provider_ids_returns_exactly_seven(self):
        assert runner.known_provider_ids() == _ALL_SEVEN

    def test_certify_all_providers_returns_all_seven(self):
        results = runner.certify_all_providers()
        assert set(results) == set(_ALL_SEVEN)

    def test_all_seven_providers_pass(self):
        results = runner.certify_all_providers()
        failing = {pid: r.overall_status for pid, r in results.items() if r.overall_status != "pass"}
        assert failing == {}, f"Non-passing providers: {failing}"

    def test_pilot_providers_constant_matches_all_seven(self):
        assert set(runner.PILOT_PROVIDERS) == set(_ALL_SEVEN)


class TestEnhancedCertificationSummary:
    def test_summary_schema_version_present(self):
        summary = runner.certification_summary()
        assert summary["schema_version"] == 1

    def test_summary_all_pass_true(self):
        summary = runner.certification_summary()
        assert summary["all_pass"] is True

    def test_summary_contains_all_seven_providers(self):
        summary = runner.certification_summary()
        assert set(summary["providers"]) == set(_ALL_SEVEN)

    def test_each_provider_summary_has_enhanced_fields(self):
        summary = runner.certification_summary()
        required_keys = {
            "maturity", "overall_status", "summary", "record_count", "finding_count",
            "reachability_evidence_coverage", "parity_evidence_coverage",
            "exemption_count", "warnings", "deferred_gates",
        }
        for pid, entry in summary["providers"].items():
            assert required_keys <= set(entry), f"{pid} missing keys: {required_keys - set(entry)}"

    def test_reachability_coverage_shape(self):
        summary = runner.certification_summary()
        for pid, entry in summary["providers"].items():
            cov = entry["reachability_evidence_coverage"]
            assert set(cov) == {"covered", "exempted", "declared"}
            assert cov["covered"] + cov["exempted"] >= 0

    def test_parity_coverage_shape(self):
        summary = runner.certification_summary()
        for pid, entry in summary["providers"].items():
            cov = entry["parity_evidence_coverage"]
            assert set(cov) == {"covered", "excepted", "declared"}

    def test_gitlab_parity_coverage_is_zero_declared_zero_covered(self):
        # GitLab deliberately has no change_parity_evidence/exceptions —
        # confirm the summary reflects "deferred", not a fabricated pass.
        summary = runner.certification_summary()
        gitlab = summary["providers"]["gitlab"]
        assert gitlab["parity_evidence_coverage"]["covered"] == 0
        assert gitlab["parity_evidence_coverage"]["excepted"] == 0
        assert "finding_change_parity" in gitlab["deferred_gates"]

    def test_kubernetes_reachability_fully_covered(self):
        summary = runner.certification_summary()
        k8s = summary["providers"]["kubernetes"]
        cov = k8s["reachability_evidence_coverage"]
        assert cov["covered"] + cov["exempted"] == cov["declared"]

    def test_deferred_gates_is_sorted(self):
        summary = runner.certification_summary()
        for entry in summary["providers"].values():
            assert entry["deferred_gates"] == sorted(entry["deferred_gates"])


class TestDeterministicOrdering:
    def test_certification_summary_providers_key_order_is_sorted(self):
        summary = runner.certification_summary()
        assert list(summary["providers"]) == sorted(summary["providers"])

    def test_certification_summary_is_reproducible_across_calls(self):
        s1 = runner.certification_summary()
        s2 = runner.certification_summary()
        assert s1 == s2

    def test_certify_all_providers_is_reproducible_across_calls(self):
        r1 = runner.certify_all_providers()
        r2 = runner.certify_all_providers()
        assert {pid: r.to_json() for pid, r in r1.items()} == {pid: r.to_json() for pid, r in r2.items()}


class TestDeterministicReportsOnDisk:
    def test_all_seven_provider_reports_exist_and_are_valid_json(self):
        reports_dir = runner._BACKEND_ROOT / "tests" / "reports" / "provider_certification"
        for pid in _ALL_SEVEN:
            path = reports_dir / f"{pid}.json"
            assert path.is_file(), f"missing report: {path}"
            data = json.loads(path.read_text())
            assert data["provider_id"] == pid
            assert data["overall_status"] == "pass"

    def test_summary_report_exists_and_is_valid_json(self):
        reports_dir = runner._BACKEND_ROOT / "tests" / "reports" / "provider_certification"
        path = reports_dir / "summary.json"
        assert path.is_file()
        data = json.loads(path.read_text())
        assert data["all_pass"] is True
        assert set(data["providers"]) == set(_ALL_SEVEN)

    def test_write_report_and_write_summary_report_are_idempotent(self, tmp_path):
        results = runner.certify_all_providers()
        for pid in _ALL_SEVEN:
            path1 = runner.write_report(results[pid], output_dir=tmp_path)
            path2 = runner.write_report(results[pid], output_dir=tmp_path)
            assert path1 == path2
            assert path1.read_text() == path2.read_text()
        summary_path1 = runner.write_summary_report(output_dir=tmp_path)
        summary_path2 = runner.write_summary_report(output_dir=tmp_path)
        assert summary_path1.read_text() == summary_path2.read_text()
