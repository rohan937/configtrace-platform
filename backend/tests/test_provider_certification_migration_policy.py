"""Migration-policy report existence/section tests (message 3 of N).

The migration-policy document itself is a durable governance artifact
(``tests/reports/provider_certification_migration_policy.md``), not
executable logic — these tests only pin that it exists and covers the
required sections, so a future edit can't silently drop one.
"""

from __future__ import annotations

from pathlib import Path

_REPORT_PATH = Path(__file__).parent / "reports" / "provider_certification_migration_policy.md"

_REQUIRED_SECTIONS = (
    "Framework-owned static invariants",
    "Provider-owned semantic invariants",
    "Evidence requirements",
    "Deletion criteria",
    "Deprecation lifecycle",
    "Negative-mutation requirement",
    "Rollback policy",
    "Provider onboarding checklist",
)


class TestMigrationPolicyReportExists:
    def test_file_exists(self):
        assert _REPORT_PATH.is_file()

    def test_file_is_non_trivial(self):
        text = _REPORT_PATH.read_text()
        assert len(text) > 2000


class TestMigrationPolicyReportSections:
    def test_all_required_sections_present(self):
        text = _REPORT_PATH.read_text()
        missing = [s for s in _REQUIRED_SECTIONS if s not in text]
        assert missing == [], f"Missing sections: {missing}"

    def test_sections_appear_in_declared_order(self):
        text = _REPORT_PATH.read_text()
        positions = [text.index(s) for s in _REQUIRED_SECTIONS]
        assert positions == sorted(positions)


class TestMigrationPolicyReportContent:
    def test_declares_reachability_coverage_is_mandatory(self):
        text = _REPORT_PATH.read_text()
        assert "MANDATORY full" in text

    def test_declares_parity_coverage_is_not_mandatory(self):
        text = _REPORT_PATH.read_text()
        assert "NOT mandatory" in text

    def test_declares_semantic_tests_never_deletable(self):
        text = _REPORT_PATH.read_text()
        assert "never** eligible for" in text or "never eligible for" in text

    def test_declares_negative_mutation_requirement(self):
        text = _REPORT_PATH.read_text()
        assert "negative-mutation" in text.lower()

    def test_onboarding_checklist_mentions_canonical_provider_id(self):
        text = _REPORT_PATH.read_text()
        assert "canonical" in text.lower() and "provider_id" in text
