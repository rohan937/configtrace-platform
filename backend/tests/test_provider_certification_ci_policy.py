"""CI enforcement policy tests (message 7).

Covers: focused-provider changes, shared changes forcing full-catalog,
uncertain impact forcing full-catalog, report drift / missing manifest /
framework test failures blocking merge, non-provider docs changes
skipping heavy certification, main-branch pushes always running full
certification, and PR runs using merge-base when available.
"""

from __future__ import annotations

from app.provider_certification import ci_policy, impact


def _impact_for(paths):
    return impact.analyze_impact(paths)


class TestFocusedProviderChange:
    def test_single_provider_connector_change_yields_focused_strategy(self):
        result = _impact_for(["backend/app/connectors/sentry.py"])
        strategy = ci_policy.decide_strategy(
            event_name="pull_request", ref_name="feature/x", impact=result, merge_base_available=True,
        )
        assert strategy.run_full_catalog is False
        assert strategy.focused_provider_ids == ("sentry",)


class TestSharedChangeForcesFull:
    def test_diff_service_change_forces_full_catalog(self):
        result = _impact_for(["backend/app/services/diff_service.py"])
        strategy = ci_policy.decide_strategy(
            event_name="pull_request", ref_name="feature/x", impact=result, merge_base_available=True,
        )
        assert strategy.run_full_catalog is True
        assert strategy.focused_provider_ids == ()


class TestUncertainImpactForcesFull:
    def test_missing_merge_base_forces_full_catalog(self):
        result = _impact_for(["backend/app/connectors/sentry.py"])
        strategy = ci_policy.decide_strategy(
            event_name="pull_request", ref_name="feature/x", impact=result, merge_base_available=False,
        )
        assert strategy.run_full_catalog is True
        assert "merge base" in strategy.reason

    def test_unknown_provider_shaped_file_forces_full_catalog(self):
        result = _impact_for(["backend/app/connectors/newcloud.py"])
        strategy = ci_policy.decide_strategy(
            event_name="pull_request", ref_name="feature/x", impact=result, merge_base_available=True,
        )
        assert strategy.run_full_catalog is True


class TestReportDriftBlocksMerge:
    def test_stale_reports_block_merge_even_if_certification_passed(self):
        gate = ci_policy.evaluate_ci_gates(
            certification_passed=True, report_drift_clean=False,
            manifest_coverage_ok=True, framework_tests_passed=True,
        )
        assert gate.blocks_merge is True
        assert any("stale" in r for r in gate.reasons)


class TestMissingManifestBlocksMerge:
    def test_missing_manifest_blocks_merge(self):
        gate = ci_policy.evaluate_ci_gates(
            certification_passed=True, report_drift_clean=True,
            manifest_coverage_ok=False, framework_tests_passed=True,
        )
        assert gate.blocks_merge is True
        assert any("manifest" in r for r in gate.reasons)


class TestFrameworkTestFailureBlocksMerge:
    def test_framework_test_failure_blocks_merge(self):
        gate = ci_policy.evaluate_ci_gates(
            certification_passed=True, report_drift_clean=True,
            manifest_coverage_ok=True, framework_tests_passed=False,
        )
        assert gate.blocks_merge is True
        assert any("framework tests" in r for r in gate.reasons)


class TestAllGatesPassingDoesNotBlock:
    def test_all_gates_passing_does_not_block_merge(self):
        gate = ci_policy.evaluate_ci_gates(
            certification_passed=True, report_drift_clean=True,
            manifest_coverage_ok=True, framework_tests_passed=True,
        )
        assert gate.blocks_merge is False
        assert gate.reasons == ()

    def test_multiple_failures_all_reported_not_short_circuited(self):
        gate = ci_policy.evaluate_ci_gates(
            certification_passed=False, report_drift_clean=False,
            manifest_coverage_ok=False, framework_tests_passed=False,
        )
        assert gate.blocks_merge is True
        assert len(gate.reasons) == 4


class TestNonProviderDocsChangeSkipsHeavyCertification:
    def test_readme_only_change_does_not_require_certification(self):
        result = _impact_for(["README.md"])
        strategy = ci_policy.decide_strategy(
            event_name="pull_request", ref_name="feature/x", impact=result, merge_base_available=True,
        )
        assert strategy.run_full_catalog is False
        assert strategy.focused_provider_ids == ()
        assert "not required" in strategy.reason


class TestMainPushAlwaysFullCertification:
    def test_push_to_main_forces_full_catalog_even_for_docs_only_change(self):
        result = _impact_for(["README.md"])
        strategy = ci_policy.decide_strategy(
            event_name="push", ref_name="main", impact=result, merge_base_available=True,
        )
        assert strategy.run_full_catalog is True
        assert "main" in strategy.reason

    def test_push_to_refs_heads_main_form_also_forces_full_catalog(self):
        result = _impact_for(["README.md"])
        strategy = ci_policy.decide_strategy(
            event_name="push", ref_name="refs/heads/main", impact=result, merge_base_available=True,
        )
        assert strategy.run_full_catalog is True

    def test_push_to_non_main_branch_does_not_force_full_catalog(self):
        result = _impact_for(["README.md"])
        strategy = ci_policy.decide_strategy(
            event_name="push", ref_name="some-other-branch", impact=result, merge_base_available=True,
        )
        assert strategy.run_full_catalog is False


class TestPRUsesMergeBaseWhenAvailable:
    def test_pr_with_merge_base_and_focused_change_is_not_full_catalog(self):
        result = _impact_for(["backend/app/connectors/aws.py"])
        strategy = ci_policy.decide_strategy(
            event_name="pull_request", ref_name="feature/aws-fix", impact=result, merge_base_available=True,
        )
        assert strategy.run_full_catalog is False
        assert strategy.focused_provider_ids == ("aws",)

    def test_pr_without_merge_base_overrides_focused_result(self):
        result = _impact_for(["backend/app/connectors/aws.py"])
        strategy = ci_policy.decide_strategy(
            event_name="pull_request", ref_name="feature/aws-fix", impact=result, merge_base_available=False,
        )
        assert strategy.run_full_catalog is True


class TestStrategyAsDictSerializable:
    def test_strategy_as_dict_is_json_serializable(self):
        import json

        result = _impact_for(["backend/app/connectors/sentry.py"])
        strategy = ci_policy.decide_strategy(
            event_name="pull_request", ref_name="feature/x", impact=result, merge_base_available=True,
        )
        json.dumps(strategy.as_dict())

    def test_gate_result_as_dict_is_json_serializable(self):
        import json

        gate = ci_policy.evaluate_ci_gates(
            certification_passed=True, report_drift_clean=True,
            manifest_coverage_ok=True, framework_tests_passed=True,
        )
        json.dumps(gate.as_dict())
