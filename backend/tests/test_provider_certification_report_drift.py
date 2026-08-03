"""Generated-report drift detection tests (message 7).

Covers clean reports, stale/missing/extra file detection, schema-
version mismatch, deterministic regeneration, and the guarantee that
check-mode never writes to disk.
"""

from __future__ import annotations

import json

from app.provider_certification import report_drift


class TestCleanReports:
    def test_real_committed_reports_are_clean(self):
        report_drift.generate_reports()
        result = report_drift.check_report_drift()
        assert result.is_clean is True
        assert result.stale == ()
        assert result.missing == ()
        assert result.extra == ()


class TestOneModifiedReport:
    def test_one_modified_report_detected_as_stale(self, tmp_path, monkeypatch):
        report_drift.generate_reports()
        real_dir = report_drift._REPORTS_DIR
        # Corrupt one committed file in place, then restore afterward.
        target = real_dir / "sentry.json"
        original = target.read_text()
        try:
            target.write_text(original.replace('"pass"', '"fail"', 1))
            result = report_drift.check_report_drift()
            assert result.is_clean is False
            assert "sentry.json" in result.stale
        finally:
            target.write_text(original)


class TestOneMissingReport:
    def test_missing_provider_report_detected(self, tmp_path, monkeypatch):
        report_drift.generate_reports()
        real_dir = report_drift._REPORTS_DIR
        target = real_dir / "sentry.json"
        original = target.read_text()
        try:
            target.unlink()
            result = report_drift.check_report_drift()
            assert result.is_clean is False
            assert "sentry.json" in result.missing
        finally:
            target.write_text(original)


class TestExtraReport:
    def test_extra_unregistered_report_file_detected(self):
        report_drift.generate_reports()
        real_dir = report_drift._REPORTS_DIR
        extra_path = real_dir / "totally_removed_provider.json"
        extra_path.write_text('{"provider_id": "totally_removed_provider"}\n')
        try:
            result = report_drift.check_report_drift()
            assert result.is_clean is False
            assert "totally_removed_provider.json" in result.extra
        finally:
            extra_path.unlink()


class TestStaleSummary:
    def test_stale_summary_json_detected(self):
        report_drift.generate_reports()
        summary_path = report_drift._REPORTS_DIR / "summary.json"
        original = summary_path.read_text()
        try:
            summary_path.write_text(original.replace('"all_pass": true', '"all_pass": false', 1))
            result = report_drift.check_report_drift()
            assert result.is_clean is False
            assert "summary.json" in result.stale
        finally:
            summary_path.write_text(original)


class TestStaleAdoptionReport:
    def test_stale_adoption_report_detected(self):
        report_drift.generate_reports()
        original = report_drift._ADOPTION_PATH.read_text()
        try:
            report_drift._ADOPTION_PATH.write_text(original.replace('"coverage_percentage": 100.0', '"coverage_percentage": 50.0', 1))
            result = report_drift.check_report_drift()
            assert result.is_clean is False
            assert "provider_certification_adoption.json" in result.stale
        finally:
            report_drift._ADOPTION_PATH.write_text(original)


class TestSchemaVersionMismatch:
    def test_schema_version_field_change_is_treated_as_stale(self):
        report_drift.generate_reports()
        target = report_drift._REPORTS_DIR / "sentry.json"
        original = target.read_text()
        try:
            mutated = original.replace('"schema_version": 1', '"schema_version": 999', 1)
            assert mutated != original  # sanity: the mutation actually changed something
            target.write_text(mutated)
            result = report_drift.check_report_drift()
            assert result.is_clean is False
            assert "sentry.json" in result.stale
        finally:
            target.write_text(original)


class TestDeterministicRegeneration:
    def test_generate_reports_twice_produces_byte_identical_files(self):
        report_drift.generate_reports()
        first = {p.name: p.read_text() for p in report_drift._REPORTS_DIR.glob("*.json")}
        first_adoption = report_drift._ADOPTION_PATH.read_text()
        report_drift.generate_reports()
        second = {p.name: p.read_text() for p in report_drift._REPORTS_DIR.glob("*.json")}
        second_adoption = report_drift._ADOPTION_PATH.read_text()
        assert first == second
        assert first_adoption == second_adoption


class TestCheckModeDoesNotWrite:
    def test_check_report_drift_never_touches_mtime(self):
        report_drift.generate_reports()
        target = report_drift._REPORTS_DIR / "sentry.json"
        before_mtime = target.stat().st_mtime_ns
        before_content = target.read_text()
        report_drift.check_report_drift()
        after_mtime = target.stat().st_mtime_ns
        after_content = target.read_text()
        assert before_mtime == after_mtime
        assert before_content == after_content

    def test_check_report_drift_does_not_create_new_files(self):
        report_drift.generate_reports()
        before = set(report_drift._REPORTS_DIR.iterdir())
        report_drift.check_report_drift()
        after = set(report_drift._REPORTS_DIR.iterdir())
        assert before == after


class TestRemediationText:
    def test_remediation_is_empty_when_clean(self):
        report_drift.generate_reports()
        result = report_drift.check_report_drift()
        assert result.remediation() == ""

    def test_remediation_names_stale_missing_extra_with_correct_prefixes(self):
        from app.provider_certification.report_drift import ReportDriftResult

        result = ReportDriftResult(
            is_clean=False,
            stale=("aws.json",),
            missing=("new_provider.json",),
            extra=("removed_provider.json",),
        )
        text = result.remediation()
        assert "STALE: provider_certification/aws.json" in text
        assert "MISSING: provider_certification/new_provider.json" in text
        assert "EXTRA: provider_certification/removed_provider.json" in text


class TestAsDictJsonSerializable:
    def test_drift_result_as_dict_round_trips_through_json(self):
        report_drift.generate_reports()
        result = report_drift.check_report_drift()
        json.dumps(result.as_dict())  # must not raise
