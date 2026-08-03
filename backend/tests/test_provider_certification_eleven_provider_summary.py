"""Eleven-provider summary tests (message 4 of N).

Covers ``certify_all_providers()``/``certification_summary()`` across
all eleven certified providers, and the message-4 global summary
enhancements: provider_id, display_name, category, public/connectable/
live, supported/unsupported capability counts, completeness-scope
count — on top of the message-3 fields (record/finding counts,
reachability/parity coverage, exemption_count, warnings, deferred_gates).
"""

from __future__ import annotations

import json

from app.provider_certification import runner

_ALL_ELEVEN = (
    "auth0", "aws", "azure", "clerk", "cloudflare", "datadog", "entra", "firebase",
    "github", "gitlab", "google_cloud", "jira", "kubernetes", "linear", "okta",
    "pagerduty", "sendgrid", "sentry", "shopify", "slack", "snowflake", "stripe",
    "supabase", "terraform_cloud", "twilio", "vercel",
)


class TestCertifyAllElevenProviders:
    def test_known_provider_ids_returns_exactly_eleven(self):
        assert runner.known_provider_ids() == _ALL_ELEVEN

    def test_certify_all_providers_returns_all_eleven(self):
        results = runner.certify_all_providers()
        assert set(results) == set(_ALL_ELEVEN)

    def test_all_eleven_providers_pass(self):
        results = runner.certify_all_providers()
        failing = {pid: r.overall_status for pid, r in results.items() if r.overall_status != "pass"}
        assert failing == {}, f"Non-passing providers: {failing}"

    def test_pilot_providers_constant_matches_all_eleven(self):
        assert set(runner.PILOT_PROVIDERS) == set(_ALL_ELEVEN)

    def test_no_provider_forced_into_identical_capabilities(self):
        # GitLab and Stripe declare different maturity/completeness
        # shapes — proves the framework doesn't force uniformity.
        results = runner.certify_all_providers()
        maturities = {pid: r.maturity for pid, r in results.items()}
        assert maturities["gitlab"] == "partial"
        assert maturities["stripe"] == "complete"


class TestGlobalSummaryEnhancements:
    def test_each_provider_summary_has_message4_fields(self):
        summary = runner.certification_summary()
        required_keys = {
            "provider_id", "display_name", "category", "maturity", "overall_status",
            "public", "connectable", "live", "record_count", "finding_count",
            "supported_capability_count", "unsupported_capability_count",
            "completeness_scope_count", "reachability_evidence_coverage",
            "parity_evidence_coverage", "exemption_count", "warnings", "deferred_gates",
        }
        for pid, entry in summary["providers"].items():
            assert required_keys <= set(entry), f"{pid} missing keys: {required_keys - set(entry)}"

    def test_provider_id_field_matches_dict_key(self):
        summary = runner.certification_summary()
        for pid, entry in summary["providers"].items():
            assert entry["provider_id"] == pid

    def test_supported_capability_count_is_five_for_the_four_new_complete_providers(self):
        summary = runner.certification_summary()
        for pid in ("cloudflare", "supabase", "firebase", "stripe"):
            assert summary["providers"][pid]["maturity"] == "complete"
            assert summary["providers"][pid]["supported_capability_count"] == 5

    def test_completeness_scope_count_reflects_legacy_and_typed_declarations(self):
        summary = runner.certification_summary()
        assert summary["providers"]["kubernetes"]["completeness_scope_count"] >= 2
        assert summary["providers"]["cloudflare"]["completeness_scope_count"] == 0
        assert summary["providers"]["gitlab"]["completeness_scope_count"] == 0

    def test_summary_sorted_by_canonical_id(self):
        summary = runner.certification_summary()
        assert list(summary["providers"]) == sorted(summary["providers"])
        assert list(summary["providers"]) == list(_ALL_ELEVEN)


class TestDeterministicElevenProviderReports:
    def test_all_eleven_provider_reports_exist_and_pass(self):
        reports_dir = runner._BACKEND_ROOT / "tests" / "reports" / "provider_certification"
        for pid in _ALL_ELEVEN:
            path = reports_dir / f"{pid}.json"
            assert path.is_file(), f"missing report: {path}"
            data = json.loads(path.read_text())
            assert data["provider_id"] == pid
            assert data["overall_status"] == "pass"

    def test_summary_report_contains_all_eleven_sorted(self):
        reports_dir = runner._BACKEND_ROOT / "tests" / "reports" / "provider_certification"
        path = reports_dir / "summary.json"
        data = json.loads(path.read_text())
        assert data["all_pass"] is True
        assert list(data["providers"]) == list(_ALL_ELEVEN)

    def test_certification_summary_reproducible_across_calls(self):
        s1 = runner.certification_summary()
        s2 = runner.certification_summary()
        assert s1 == s2

    def test_certify_all_providers_reproducible_across_calls(self):
        r1 = runner.certify_all_providers()
        r2 = runner.certify_all_providers()
        assert {pid: r.to_json() for pid, r in r1.items()} == {pid: r.to_json() for pid, r in r2.items()}
