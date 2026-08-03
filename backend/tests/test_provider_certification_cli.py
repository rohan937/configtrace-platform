"""Provider Certification Framework CLI tests (message 7).

Covers every documented command, both output formats, deterministic
JSON, exit codes, malformed arguments, and the no-secret-output
guarantee.
"""

from __future__ import annotations

import json

import pytest

from app.provider_certification import cli


def _run(argv, capsys):
    exit_code = cli.main(argv)
    captured = capsys.readouterr()
    return exit_code, captured.out, captured.err


class TestCertifyAllSuccess:
    def test_certify_all_text_exit_zero(self, capsys):
        code, out, err = _run(["certify-all"], capsys)
        assert code == cli.EXIT_PASS
        assert "Overall: PASS" in out

    def test_certify_all_json_exit_zero(self, capsys):
        code, out, err = _run(["certify-all", "--format", "json"], capsys)
        assert code == cli.EXIT_PASS
        data = json.loads(out)
        assert data["overall_status"] == "pass"
        assert data["command"] == "certify-all"

    def test_certify_all_json_contains_required_keys(self, capsys):
        code, out, err = _run(["certify-all", "--format", "json"], capsys)
        data = json.loads(out)
        for key in ("schema_version", "command", "overall_status", "providers", "failed_gates", "warnings", "deferred_gates", "remediation", "exit_code_category"):
            assert key in data

    def test_certify_all_deterministic_json_across_two_runs(self, capsys):
        code1, out1, _ = _run(["certify-all", "--format", "json"], capsys)
        code2, out2, _ = _run(["certify-all", "--format", "json"], capsys)
        assert out1 == out2

    def test_certify_all_providers_sorted(self, capsys):
        code, out, err = _run(["certify-all", "--format", "json"], capsys)
        data = json.loads(out)
        assert list(data["providers"]) == sorted(data["providers"])


class TestCertifyProviderSuccess:
    def test_certify_provider_sentry_text(self, capsys):
        code, out, err = _run(["certify-provider", "sentry"], capsys)
        assert code == cli.EXIT_PASS
        assert "Provider: sentry" in out
        assert "Overall: PASS" in out

    def test_certify_provider_sentry_json(self, capsys):
        code, out, err = _run(["certify-provider", "sentry", "--format", "json"], capsys)
        assert code == cli.EXIT_PASS
        data = json.loads(out)
        assert data["providers"]["sentry"]["overall_status"] == "pass"


class TestUnknownProvider:
    def test_unknown_provider_exit_code(self, capsys):
        code, out, err = _run(["certify-provider", "not_a_real_provider"], capsys)
        assert code == cli.EXIT_INVALID_COMMAND

    def test_unknown_provider_json_reports_error(self, capsys):
        code, out, err = _run(["certify-provider", "not_a_real_provider", "--format", "json"], capsys)
        assert code == cli.EXIT_INVALID_COMMAND
        data = json.loads(out)
        assert "error" in data

    def test_unknown_provider_message_lists_known_providers(self, capsys):
        code, out, err = _run(["certify-provider", "not_a_real_provider"], capsys)
        assert "sentry" in err


class TestMalformedArguments:
    def test_missing_subcommand_exit_code(self, capsys):
        code, out, err = _run([], capsys)
        assert code == cli.EXIT_INVALID_COMMAND

    def test_unknown_subcommand_exit_code(self, capsys):
        code, out, err = _run(["not-a-real-command"], capsys)
        assert code == cli.EXIT_INVALID_COMMAND

    def test_certify_provider_missing_argument_exit_code(self, capsys):
        code, out, err = _run(["certify-provider"], capsys)
        assert code == cli.EXIT_INVALID_COMMAND

    def test_affected_missing_base_exit_code(self, capsys):
        code, out, err = _run(["affected", "--head", "HEAD"], capsys)
        assert code == cli.EXIT_INVALID_COMMAND


class TestGenerateReports:
    def test_generate_reports_text_exit_zero(self, capsys):
        code, out, err = _run(["generate-reports"], capsys)
        assert code == cli.EXIT_PASS
        assert "Wrote" in out

    def test_generate_reports_json_lists_files(self, capsys):
        code, out, err = _run(["generate-reports", "--format", "json"], capsys)
        data = json.loads(out)
        assert len(data["files_written"]) > 0

    def test_generate_reports_then_check_reports_is_clean(self, capsys):
        _run(["generate-reports"], capsys)
        code, out, err = _run(["check-reports", "--format", "json"], capsys)
        assert code == cli.EXIT_PASS
        data = json.loads(out)
        assert data["is_clean"] is True


class TestCheckReportsClean:
    def test_check_reports_clean_exit_zero(self, capsys):
        from app.provider_certification import report_drift

        report_drift.generate_reports()
        code, out, err = _run(["check-reports"], capsys)
        assert code == cli.EXIT_PASS
        assert "clean" in out.lower()


class TestCheckReportsStale:
    def test_check_reports_stale_exit_code(self, capsys, tmp_path, monkeypatch):
        from app.provider_certification import report_drift

        monkeypatch.setattr(report_drift, "_REPORTS_DIR", tmp_path)
        monkeypatch.setattr(report_drift, "_ADOPTION_PATH", tmp_path / "provider_certification_adoption.json")
        code, out, err = _run(["check-reports"], capsys)
        assert code == cli.EXIT_REPORTS_STALE
        assert "MISSING" in out


class TestNoSecretOutput:
    def test_certify_all_output_never_contains_credential_field_values(self, capsys):
        code, out, err = _run(["certify-all", "--format", "json"], capsys)
        forbidden_substrings = ["client_secret=", "api_key=", "-----BEGIN", "AKIA"]
        for s in forbidden_substrings:
            assert s not in out

    def test_certify_all_output_contains_no_absolute_paths(self, capsys):
        code, out, err = _run(["certify-all", "--format", "json"], capsys)
        assert "/Users/" not in out
        assert "/home/" not in out
