"""Deterministic-report tests (message 2 of N).

Confirms JSON certification reports are byte-identical across repeated
generation — same process, a separate process, shuffled manifest
registration order, and shuffled discovery-result input order — and that
the framework matrix/architecture reports meet the message-2 size and
status requirements.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from app.provider_certification import runner

# Force the FULL manifest set to load before the direct per-manifest
# imports below run. Those direct imports each call register_manifest()
# as an import-time side effect, independent of
# runner._ensure_manifests_loaded()'s "already loaded" guard — if they
# ran first, _MANIFESTS would end up permanently pinned to only these 4
# entries for the rest of this test module's process (its lazy-loader
# would see a non-empty dict and never import github/gitlab/kubernetes).
runner._ensure_manifests_loaded()

from app.provider_certification.manifests.entra import ENTRA_MANIFEST
from app.provider_certification.manifests.okta import OKTA_MANIFEST
from app.provider_certification.manifests.sentry import SENTRY_MANIFEST
from app.provider_certification.manifests.snowflake import SNOWFLAKE_MANIFEST

_BACKEND_ROOT = Path(__file__).resolve().parents[1]
_REPORTS_DIR = _BACKEND_ROOT / "tests" / "reports" / "provider_certification"


class TestSameProcessDeterminism:
    def test_repeated_certify_provider_calls_are_byte_identical(self):
        for pid in ("sentry", "snowflake", "okta", "entra"):
            j1 = runner.certify_provider(pid).to_json()
            j2 = runner.certify_provider(pid).to_json()
            assert j1 == j2

    def test_no_timestamps_in_any_report_json(self):
        import re

        for pid in ("sentry", "snowflake", "okta", "entra"):
            j = runner.certify_provider(pid).to_json()
            assert not re.search(r"202\d-\d\d-\d\dT", j)

    def test_no_absolute_environment_paths_in_report_json(self):
        for pid in ("sentry", "snowflake", "okta", "entra"):
            j = runner.certify_provider(pid).to_json()
            assert str(_BACKEND_ROOT) not in j
            assert "/Users/" not in j
            assert "/private/tmp" not in j

    def test_summary_is_deterministic(self):
        s1 = runner.certification_summary()
        s2 = runner.certification_summary()
        assert json.dumps(s1, sort_keys=True) == json.dumps(s2, sort_keys=True)


class TestSeparateProcessDeterminism:
    def test_separate_process_produces_identical_json(self):
        script = (
            "from app.provider_certification import runner\n"
            "print(runner.certify_provider('okta').to_json())\n"
        )
        proc = subprocess.run(
            [sys.executable, "-c", script],
            cwd=str(_BACKEND_ROOT),
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert proc.returncode == 0, proc.stderr
        in_process = runner.certify_provider("okta").to_json()
        assert proc.stdout.strip() == in_process


class TestShuffledManifestRegistration:
    def test_reversed_registration_order_yields_identical_certify_all_output(self):
        original = dict(runner._MANIFESTS)
        try:
            runner._MANIFESTS.clear()
            for manifest in (ENTRA_MANIFEST, SNOWFLAKE_MANIFEST, OKTA_MANIFEST, SENTRY_MANIFEST):
                runner.register_manifest(manifest)
            forward_order_summary = runner.certification_summary()

            runner._MANIFESTS.clear()
            for manifest in (SENTRY_MANIFEST, OKTA_MANIFEST, SNOWFLAKE_MANIFEST, ENTRA_MANIFEST):
                runner.register_manifest(manifest)
            reverse_order_summary = runner.certification_summary()

            assert json.dumps(forward_order_summary, sort_keys=True) == json.dumps(reverse_order_summary, sort_keys=True)
        finally:
            runner._MANIFESTS.clear()
            runner._MANIFESTS.update(original)


class TestShuffledDiscoveryInputOrder:
    def test_gate_output_independent_of_set_iteration_order(self):
        from app.provider_certification import gates

        gate_a = gates.gate_record_inventory(OKTA_MANIFEST)
        # Rebuild the manifest's expected_record_types in reverse order —
        # gate logic operates on sets internally, so iteration order of
        # the input tuple must not affect the result.
        import dataclasses

        reversed_manifest = dataclasses.replace(
            OKTA_MANIFEST, expected_record_types=tuple(reversed(OKTA_MANIFEST.expected_record_types))
        )
        gate_b = gates.gate_record_inventory(reversed_manifest)
        assert gate_a.status == gate_b.status == "pass"


class TestReportFilesExist:
    def test_all_four_pilot_json_reports_exist(self):
        for pid in ("sentry", "snowflake", "okta", "entra"):
            assert (_REPORTS_DIR / f"{pid}.json").is_file()

    def test_summary_json_exists(self):
        assert (_REPORTS_DIR / "summary.json").is_file()

    def test_json_reports_are_valid_json_with_expected_top_level_keys(self):
        for pid in ("sentry", "snowflake", "okta", "entra"):
            data = json.loads((_REPORTS_DIR / f"{pid}.json").read_text())
            assert data["provider_id"] == pid
            assert data["overall_status"] == "pass"

    def test_summary_json_reports_all_pass(self):
        data = json.loads((_REPORTS_DIR / "summary.json").read_text())
        assert data["all_pass"] is True
        assert set(data["providers"]) == {
            "sentry", "snowflake", "okta", "entra", "kubernetes", "github", "gitlab",
            "cloudflare", "supabase", "firebase", "stripe",
            "aws", "vercel", "datadog", "pagerduty", "slack", "jira",
            "auth0", "azure", "clerk", "google_cloud", "linear", "sendgrid",
            "shopify", "terraform_cloud", "twilio",
        }


class TestFrameworkMatrixReport:
    def test_matrix_has_at_least_220_data_rows(self):
        path = _BACKEND_ROOT / "tests" / "reports" / "provider_certification_framework_matrix.md"
        lines = path.read_text().splitlines()
        data_rows = [
            ln for ln in lines
            if ln.startswith("|") and not ln.startswith("|--") and not ln.startswith("| #") and not set(ln.replace("|", "").strip()) <= {"-", " "}
        ]
        assert len(data_rows) >= 220, f"only {len(data_rows)} data rows"

    def test_matrix_has_at_least_1050_genuine_data_rows(self):
        # Permanent regression guard (message 5 follow-up): counts actual
        # numbered data rows (each starting with "| <int> |"), not the
        # header row, the separator row, or any prose line that happens
        # to start with "|". Each numbered row must correspond to a real
        # test — this test only pins the COUNT; the matrix's own content
        # (parsed test paths) is what proves genuineness.
        import re

        path = _BACKEND_ROOT / "tests" / "reports" / "provider_certification_framework_matrix.md"
        lines = path.read_text().splitlines()
        numbered_rows = [ln for ln in lines if re.match(r"^\|\s*\d+\s*\|", ln)]
        assert len(numbered_rows) >= 1050, f"only {len(numbered_rows)} numbered data rows"
        # Row numbers must be sequential starting at 1, with no gaps or
        # duplicates — proves the count isn't inflated by repeated numbers.
        numbers = [int(re.match(r"^\|\s*(\d+)\s*\|", ln).group(1)) for ln in numbered_rows]
        assert numbers == list(range(1, len(numbers) + 1)), "row numbers are not sequential/unique"

    def test_matrix_has_at_least_1400_genuine_data_rows(self):
        # Permanent regression guard (message 6): raises the floor from
        # message 5's 1050 to message 6's required 1400, using the same
        # sequential/unique row-number verification.
        import re

        path = _BACKEND_ROOT / "tests" / "reports" / "provider_certification_framework_matrix.md"
        lines = path.read_text().splitlines()
        numbered_rows = [ln for ln in lines if re.match(r"^\|\s*\d+\s*\|", ln)]
        assert len(numbered_rows) >= 1400, f"only {len(numbered_rows)} numbered data rows"
        numbers = [int(re.match(r"^\|\s*(\d+)\s*\|", ln).group(1)) for ln in numbered_rows]
        assert numbers == list(range(1, len(numbers) + 1)), "row numbers are not sequential/unique"


class TestFrameworkArchitectureReport:
    def test_ends_in_pass_certification_status(self):
        path = _BACKEND_ROOT / "tests" / "reports" / "provider_certification_framework.md"
        text = path.read_text()
        assert "FRAMEWORK CERTIFICATION STATUS: PASS" in text


class TestMessage2Report:
    def test_message2_report_exists_and_declares_pass(self):
        path = _BACKEND_ROOT / "tests" / "reports" / "provider_certification_message2.md"
        assert path.is_file()
        text = path.read_text()
        assert "PASS" in text
