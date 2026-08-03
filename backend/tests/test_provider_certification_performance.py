"""Provider Certification Framework performance budgets (message 7).

Actually measures wall-clock time (median-of-5, warmed up once) against
generous, CI-safe upper bounds. Never asserts exact millisecond timings —
only that each operation stays comfortably under its documented budget:
  - certify one provider:  < 1s
  - certify all providers: < 5s
  - report drift check:    < 5s
  - impact analysis:       < 1s
"""

from __future__ import annotations

import statistics
import time

from app.provider_certification import impact, report_drift, runner


def _median_of_5(fn) -> float:
    fn()  # warm-up run, discarded
    samples = []
    for _ in range(5):
        start = time.perf_counter()
        fn()
        samples.append(time.perf_counter() - start)
    return statistics.median(samples)


class TestCertifyOneProviderBudget:
    def test_certify_provider_median_under_one_second(self):
        median = _median_of_5(lambda: runner.certify_provider("sentry"))
        assert median < 1.0, f"certify_provider median {median:.3f}s exceeded 1s budget"


class TestCertifyAllProvidersBudget:
    def test_certify_all_providers_median_under_five_seconds(self):
        median = _median_of_5(runner.certify_all_providers)
        assert median < 5.0, f"certify_all_providers median {median:.3f}s exceeded 5s budget"


class TestReportGenerationBudget:
    def test_generate_reports_median_under_five_seconds(self):
        median = _median_of_5(report_drift.generate_reports)
        assert median < 5.0, f"generate_reports median {median:.3f}s exceeded 5s budget"


class TestReportDriftCheckBudget:
    def test_check_report_drift_median_under_five_seconds(self):
        report_drift.generate_reports()
        median = _median_of_5(report_drift.check_report_drift)
        assert median < 5.0, f"check_report_drift median {median:.3f}s exceeded 5s budget"


class TestImpactAnalysisBudget:
    def test_analyze_impact_median_under_one_second(self):
        paths = [
            "backend/app/connectors/sentry.py",
            "backend/app/connectors/aws.py",
            "backend/app/services/diff_service.py",
            "README.md",
            "backend/app/provider_certification/manifests/aws.py",
        ]
        median = _median_of_5(lambda: impact.analyze_impact(paths))
        assert median < 1.0, f"analyze_impact median {median:.3f}s exceeded 1s budget"

    def test_classify_single_path_median_under_one_second(self):
        median = _median_of_5(lambda: impact.classify_path("backend/app/connectors/sentry.py"))
        assert median < 1.0, f"classify_path median {median:.3f}s exceeded 1s budget"
