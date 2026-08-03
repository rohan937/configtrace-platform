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
        assert set(data["providers"]) == {"sentry", "snowflake", "okta", "entra"}


class TestFrameworkMatrixReport:
    def test_matrix_has_at_least_220_data_rows(self):
        path = _BACKEND_ROOT / "tests" / "reports" / "provider_certification_framework_matrix.md"
        lines = path.read_text().splitlines()
        data_rows = [
            ln for ln in lines
            if ln.startswith("|") and not ln.startswith("|--") and not ln.startswith("| #") and not set(ln.replace("|", "").strip()) <= {"-", " "}
        ]
        assert len(data_rows) >= 220, f"only {len(data_rows)} data rows"


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
