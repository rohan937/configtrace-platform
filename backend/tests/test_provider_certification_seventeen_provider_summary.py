"""Seventeen-provider summary tests (message 5 of N).

Dedicated new file (per this message's own file list) proving the
framework now certifies all 17 target providers as a coherent whole —
mirroring ``_ALL_SEVEN``/``_ALL_ELEVEN`` in earlier messages' summary
test files, but scoped to this message's own additions: AWS, Vercel,
Datadog, PagerDuty, Slack, Jira.
"""

from __future__ import annotations

import json

from app.provider_certification import runner

_ALL_SEVENTEEN = (
    "auth0", "aws", "azure", "clerk", "cloudflare", "datadog", "entra", "firebase",
    "github", "gitlab", "google_cloud", "jira", "kubernetes", "linear", "okta",
    "pagerduty", "sendgrid", "sentry", "shopify", "slack", "snowflake", "stripe",
    "supabase", "terraform_cloud", "twilio", "vercel",
)

_NEW_THIS_MESSAGE = ("aws", "vercel", "datadog", "pagerduty", "slack", "jira")


class TestSeventeenProvidersKnown:
    def test_known_provider_ids_returns_exactly_seventeen(self):
        assert runner.known_provider_ids() == tuple(sorted(_ALL_SEVENTEEN))
        assert len(runner.known_provider_ids()) == 26

    def test_pilot_providers_constant_matches_all_seventeen(self):
        assert set(runner.PILOT_PROVIDERS) == set(_ALL_SEVENTEEN)

    def test_six_new_providers_are_all_present(self):
        known = set(runner.known_provider_ids())
        for pid in _NEW_THIS_MESSAGE:
            assert pid in known


class TestAllSeventeenCertifyPass:
    def test_all_seventeen_providers_pass(self):
        results = runner.certify_all_providers()
        failing = {pid: r.overall_status for pid, r in results.items() if r.overall_status != "pass"}
        assert failing == {}, f"Non-passing providers: {failing}"

    def test_no_provider_has_a_failing_or_unknown_blocking_gate(self):
        results = runner.certify_all_providers()
        for pid, r in results.items():
            bad = [g.gate_id for g in r.gates if g.blocking and g.status in ("fail", "unknown")]
            assert bad == [], f"{pid} has bad blocking gates: {bad}"


class TestSummaryReflectsSeventeenProviders:
    def test_summary_contains_all_seventeen_providers(self):
        summary = runner.certification_summary()
        assert set(summary["providers"]) == set(_ALL_SEVENTEEN)

    def test_summary_all_pass_true(self):
        summary = runner.certification_summary()
        assert summary["all_pass"] is True

    def test_slack_summary_reflects_zero_records_and_capabilities(self):
        summary = runner.certification_summary()
        slack = summary["providers"]["slack"]
        assert slack["record_count"] == 0
        assert slack["finding_count"] == 0
        assert slack["supported_capability_count"] == 0
        assert slack["maturity"] == "planned"

    def test_deferred_gate_count_matches_deferred_gates_list_length(self):
        summary = runner.certification_summary()
        for pid, entry in summary["providers"].items():
            assert entry["deferred_gate_count"] == len(entry["deferred_gates"])


class TestDeterministicReportsForAllSeventeen:
    def test_all_seventeen_provider_reports_exist_and_are_valid_json(self):
        reports_dir = runner._BACKEND_ROOT / "tests" / "reports" / "provider_certification"
        for pid in _ALL_SEVENTEEN:
            path = reports_dir / f"{pid}.json"
            assert path.is_file(), f"missing report: {path}"
            data = json.loads(path.read_text())
            assert data["provider_id"] == pid
            assert data["overall_status"] == "pass"

    def test_summary_report_reflects_seventeen_providers(self):
        reports_dir = runner._BACKEND_ROOT / "tests" / "reports" / "provider_certification"
        path = reports_dir / "summary.json"
        data = json.loads(path.read_text())
        assert set(data["providers"]) == set(_ALL_SEVENTEEN)
        assert data["all_pass"] is True

    def test_adoption_report_reflects_seventeen_certified_providers(self):
        reports_dir = runner._BACKEND_ROOT / "tests" / "reports"
        path = reports_dir / "provider_certification_adoption.json"
        data = json.loads(path.read_text())
        assert data["certified_provider_count"] == 26
        assert set(data["certified_provider_ids"]) == set(_ALL_SEVENTEEN)
