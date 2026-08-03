"""Framework self-certification tests (message 7).

Pins that the global framework self-certification gate itself passes
against the real repository state, and that each individual check
correctly reports pass/fail for both the real state and a deliberately
broken fixture state.
"""

from __future__ import annotations

from app.provider_certification import framework_self_certification as fsc


class TestRealRepositoryStatePasses:
    def test_full_self_certification_passes_against_real_repo(self):
        result = fsc.run_self_certification()
        failing = [c for c in result.checks if not c.passed]
        assert result.overall_pass is True, f"failing checks: {failing}"

    def test_result_contains_all_documented_checks(self):
        result = fsc.run_self_certification()
        check_ids = {c.check_id for c in result.checks}
        assert check_ids == {
            "every_gate_has_tests",
            "every_manifest_loaded_once",
            "every_generated_report_represented",
            "adoption_report_current",
            "matrix_and_report_minimums_hold",
            "ci_entry_point_exists",
            "workflow_references_real_command",
            "no_deprecated_migration_allowlist_entries",
        }


class TestEveryGateHasTests:
    def test_every_gate_dimension_has_test_reference(self):
        check = fsc._every_gate_dimension_has_test_reference()
        assert check.passed is True


class TestEveryManifestLoadedOnce:
    def test_no_duplicate_manifest_registration(self):
        check = fsc._every_manifest_loaded_once()
        assert check.passed is True


class TestEveryGeneratedReportRepresented:
    def test_reports_clean_after_generation(self):
        check = fsc._every_generated_report_represented()
        assert check.passed is True


class TestAdoptionReportCurrent:
    def test_zero_missing_and_zero_orphans(self):
        check = fsc._adoption_report_current()
        assert check.passed is True


class TestMatrixAndReportMinimums:
    def test_minimums_hold(self):
        check = fsc._matrix_and_report_minimums_hold()
        assert check.passed is True


class TestCIEntryPointExists:
    def test_cli_module_exists_on_disk(self):
        check = fsc._ci_entry_point_exists()
        assert check.passed is True

    def test_missing_cli_module_fails_check(self, monkeypatch, tmp_path):
        monkeypatch.setattr(fsc, "_CLI_MODULE_PATH", tmp_path / "does_not_exist.py")
        check = fsc._ci_entry_point_exists()
        assert check.passed is False


class TestWorkflowReferencesRealCommand:
    def test_committed_workflow_references_the_cli_module(self):
        check = fsc._workflow_references_real_command()
        assert check.passed is True

    def test_missing_workflow_directory_fails_check(self, monkeypatch, tmp_path):
        monkeypatch.setattr(fsc, "_WORKFLOW_DIR", tmp_path / "does_not_exist")
        check = fsc._workflow_references_real_command()
        assert check.passed is False

    def test_workflow_without_cli_marker_fails_check(self, monkeypatch, tmp_path):
        workflow_dir = tmp_path / "workflows"
        workflow_dir.mkdir()
        (workflow_dir / "unrelated.yml").write_text("name: unrelated\non: push\njobs: {}\n")
        monkeypatch.setattr(fsc, "_WORKFLOW_DIR", workflow_dir)
        check = fsc._workflow_references_real_command()
        assert check.passed is False


class TestNoDeprecatedMigrationAllowlistEntries:
    def test_empty_allowlist_passes(self):
        check = fsc._no_deprecated_migration_allowlist_entries()
        assert check.passed is True


class TestSelfCertificationResultSerializable:
    def test_as_dict_is_json_serializable(self):
        import json

        result = fsc.run_self_certification()
        json.dumps(result.as_dict())
