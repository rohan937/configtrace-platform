"""Evidence-model plumbing tests (message 3 of N).

Covers ``gates._count_matching_tests`` directly (the purely static,
non-pytest test-counting helper both reachability and parity gates
depend on) plus the manifest-validation-strengthening rules that don't
have a natural home in the reachability/change_parity test files:
evidence-file-must-be-under-tests/, cross-provider evidence sharing
rejection, and duplicate-evidence-identity rejection, exercised via
``_count_matching_tests`` edge cases (nonexistent file, whole-file
count via empty selector, class-scoped count, boundary at next class).
"""

from __future__ import annotations

import pytest

from app.provider_certification.gates import _count_matching_tests
from app.provider_certification.models import (
    FindingChangeParityEvidence,
    FindingReachabilityEvidence,
    ManifestValidationError,
    ProviderCertificationManifest,
)


class TestCountMatchingTestsNonexistentFile:
    def test_returns_zero_for_a_file_that_does_not_exist(self):
        assert _count_matching_tests("tests/test_this_file_does_not_exist_anywhere.py", "") == 0

    def test_returns_zero_for_a_file_outside_the_repo_root(self):
        assert _count_matching_tests("../../../etc/passwd", "") == 0


class TestCountMatchingTestsEmptySelector:
    def test_empty_selector_counts_every_test_in_the_whole_file(self):
        # This very file: count every `def test_` occurrence directly and
        # compare against the helper's own whole-file count.
        import pathlib

        this_file = pathlib.Path(__file__)
        repo_relative = f"tests/{this_file.name}"
        raw_count = sum(1 for line in this_file.read_text().splitlines() if line.strip().startswith("def test_"))
        assert _count_matching_tests(repo_relative, "") == raw_count
        assert raw_count > 0


class TestCountMatchingTestsSelectorScoped:
    def test_selector_scopes_the_count_to_its_own_class_block(self):
        assert _count_matching_tests(
            "tests/test_provider_certification_evidence.py",
            "class TestCountMatchingTestsSelectorScoped",
        ) >= 1

    def test_unmatched_selector_returns_zero(self):
        assert _count_matching_tests(
            "tests/test_provider_certification_evidence.py",
            "ThisSelectorStringAppearsNowhereInAnyRealTestFile999",
        ) == 0


class TestCountMatchingTestsSelectorBoundary:
    def test_count_does_not_bleed_into_the_next_class(self):
        # Construct a small on-disk fixture file with two adjacent classes
        # so the boundary regex is exercised directly, without depending
        # on this file's own future edits.
        import pathlib

        fixture_dir = pathlib.Path(__file__).parent / "reports"
        fixture_dir.mkdir(parents=True, exist_ok=True)
        fixture_path = fixture_dir / "_tmp_count_matching_tests_fixture.py"
        fixture_path.write_text(
            "class TestFirst:\n"
            "    def test_a(self):\n"
            "        pass\n"
            "    def test_b(self):\n"
            "        pass\n"
            "\n"
            "class TestSecond:\n"
            "    def test_c(self):\n"
            "        pass\n"
        )
        try:
            rel = f"tests/reports/{fixture_path.name}"
            assert _count_matching_tests(rel, "class TestFirst") == 2
            assert _count_matching_tests(rel, "class TestSecond") == 1
            assert _count_matching_tests(rel, "") == 3
        finally:
            fixture_path.unlink()


class TestManifestEvidenceValidationStrengthening:
    """Cross-checks that the mandatory validation rules exercised in
    test_provider_certification_reachability.py / _change_parity.py are
    consistently enforced regardless of which evidence collection they
    appear on (reachability vs parity), since both share near-identical
    validation code paths in ProviderCertificationManifest.__post_init__."""

    def _base_kwargs(self):
        return dict(
            provider_id="ghostprov2",
            display_name="Ghost Provider 2",
            category="observability",
            maturity="partial",
            expected_public=True,
            expected_connectable=True,
            expected_live=True,
            credential_fields=("ghostprov2_api_token",),
            sensitive_credential_fields=("ghostprov2_api_token",),
            authentication_model="api_token",
            expected_record_types=("ghostprov2_widget",),
            expected_frontend_form="GhostProv2IntegrationForm.tsx",
            expected_reconnect=True,
            supported_capabilities=("security_findings",),
            security_finding_rule_ids=("ghostprov2_rule_a",),
            false_removal_scopes=("account_wide",),
        )

    def test_reachability_and_parity_both_reject_evidence_outside_tests_dir(self):
        import pytest

        from app.provider_certification.models import (
            FindingChangeParityEvidence,
            FindingReachabilityEvidence,
            ManifestValidationError,
            ProviderCertificationManifest,
            ReachabilityExemption,
        )

        with pytest.raises(ManifestValidationError, match="must be inside tests/"):
            ProviderCertificationManifest(
                **self._base_kwargs(),
                reachability_evidence=(
                    FindingReachabilityEvidence(
                        provider_id="ghostprov2", test_file="app/main.py", test_selector="",
                        covered_rule_ids=("ghostprov2_rule_a",), minimum_test_count=1,
                    ),
                ),
            )

        with pytest.raises(ManifestValidationError, match="must be inside tests/"):
            ProviderCertificationManifest(
                **self._base_kwargs(),
                reachability_exemptions=(
                    ReachabilityExemption(rule_ids=("ghostprov2_rule_a",), reason="x"),
                ),
                change_parity_evidence=(
                    FindingChangeParityEvidence(
                        provider_id="ghostprov2", test_file="app/main.py", test_selector="",
                        covered_rule_ids=("ghostprov2_rule_a",), minimum_test_count=1,
                    ),
                ),
            )

    def test_reachability_evidence_from_a_different_provider_is_rejected(self):
        import pytest

        from app.provider_certification.models import (
            FindingReachabilityEvidence,
            ManifestValidationError,
            ProviderCertificationManifest,
        )

        with pytest.raises(ManifestValidationError, match="no shared-evidence allowance is configured"):
            ProviderCertificationManifest(
                **self._base_kwargs(),
                reachability_evidence=(
                    FindingReachabilityEvidence(
                        provider_id="some_totally_different_provider",
                        test_file="tests/test_provider_certification_evidence.py",
                        test_selector="",
                        covered_rule_ids=("ghostprov2_rule_a",),
                        minimum_test_count=1,
                    ),
                ),
            )

    def test_duplicate_evidence_identity_rejected_for_both_collections(self):
        import pytest

        from app.provider_certification.models import (
            FindingChangeParityEvidence,
            FindingReachabilityEvidence,
            ManifestValidationError,
            ProviderCertificationManifest,
        )

        with pytest.raises(ManifestValidationError, match="duplicate reachability_evidence"):
            ProviderCertificationManifest(
                **self._base_kwargs(),
                reachability_evidence=(
                    FindingReachabilityEvidence(
                        provider_id="ghostprov2", test_file="tests/test_provider_certification_evidence.py",
                        test_selector="", covered_rule_ids=("ghostprov2_rule_a",), minimum_test_count=1,
                    ),
                    FindingReachabilityEvidence(
                        provider_id="ghostprov2", test_file="tests/test_provider_certification_evidence.py",
                        test_selector="", covered_rule_ids=(), minimum_test_count=1,
                    ),
                ),
            )

        with pytest.raises(ManifestValidationError, match="duplicate change_parity_evidence"):
            ProviderCertificationManifest(
                **self._base_kwargs(),
                reachability_evidence=(
                    FindingReachabilityEvidence(
                        provider_id="ghostprov2", test_file="tests/test_provider_certification_evidence.py",
                        test_selector="", covered_rule_ids=("ghostprov2_rule_a",), minimum_test_count=1,
                    ),
                ),
                change_parity_evidence=(
                    FindingChangeParityEvidence(
                        provider_id="ghostprov2", test_file="tests/test_provider_certification_evidence.py",
                        test_selector="", covered_rule_ids=("ghostprov2_rule_a",), minimum_test_count=1,
                    ),
                    FindingChangeParityEvidence(
                        provider_id="ghostprov2", test_file="tests/test_provider_certification_evidence.py",
                        test_selector="", covered_rule_ids=(), minimum_test_count=1,
                    ),
                ),
            )


class TestEvidenceQuality:
    """Message 4: typed evidence-quality status (direct/grouped/
    static_only). Descriptive metadata validated against a fixed enum —
    "deferred" is intentionally not a valid value ON evidence itself,
    since deferred describes the ABSENCE of evidence."""

    def _base_kwargs(self):
        return dict(
            provider_id="ghostprov5",
            display_name="Ghost Provider 5",
            category="observability",
            maturity="partial",
            expected_public=True,
            expected_connectable=True,
            expected_live=False,
            credential_fields=("ghostprov5_api_token",),
            sensitive_credential_fields=("ghostprov5_api_token",),
            authentication_model="api_token",
            expected_record_types=("ghostprov5_widget",),
            expected_frontend_form="GhostProv5IntegrationForm.tsx",
            expected_reconnect=False,
            supported_capabilities=("security_findings",),
            security_finding_rule_ids=("ghostprov5_rule_a",),
        )

    def test_default_quality_is_direct(self):
        ev = FindingReachabilityEvidence(
            provider_id="ghostprov5", test_file="tests/test_provider_certification_evidence.py",
            test_selector="", covered_rule_ids=("ghostprov5_rule_a",), minimum_test_count=1,
        )
        assert ev.quality == "direct"

    def test_grouped_quality_accepted(self):
        m = ProviderCertificationManifest(
            **self._base_kwargs(),
            reachability_evidence=(
                FindingReachabilityEvidence(
                    provider_id="ghostprov5", test_file="tests/test_provider_certification_evidence.py",
                    test_selector="", covered_rule_ids=("ghostprov5_rule_a",), minimum_test_count=1,
                    quality="grouped",
                ),
            ),
        )
        assert m.reachability_evidence[0].quality == "grouped"

    def test_static_only_quality_accepted(self):
        m = ProviderCertificationManifest(
            **self._base_kwargs(),
            reachability_evidence=(
                FindingReachabilityEvidence(
                    provider_id="ghostprov5", test_file="tests/test_provider_certification_evidence.py",
                    test_selector="", covered_rule_ids=("ghostprov5_rule_a",), minimum_test_count=1,
                    quality="static_only",
                ),
            ),
        )
        assert m.reachability_evidence[0].quality == "static_only"

    def test_invalid_reachability_quality_rejected(self):
        with pytest.raises(ManifestValidationError, match="reachability_evidence quality must be one of"):
            ProviderCertificationManifest(
                **self._base_kwargs(),
                reachability_evidence=(
                    FindingReachabilityEvidence(
                        provider_id="ghostprov5", test_file="tests/test_provider_certification_evidence.py",
                        test_selector="", covered_rule_ids=("ghostprov5_rule_a",), minimum_test_count=1,
                        quality="deferred",
                    ),
                ),
            )

    def test_invalid_parity_quality_rejected(self):
        with pytest.raises(ManifestValidationError, match="change_parity_evidence quality must be one of"):
            ProviderCertificationManifest(
                **self._base_kwargs(),
                reachability_evidence=(
                    FindingReachabilityEvidence(
                        provider_id="ghostprov5", test_file="tests/test_provider_certification_evidence.py",
                        test_selector="", covered_rule_ids=("ghostprov5_rule_a",), minimum_test_count=1,
                    ),
                ),
                change_parity_evidence=(
                    FindingChangeParityEvidence(
                        provider_id="ghostprov5", test_file="tests/test_provider_certification_evidence.py",
                        test_selector="", covered_rule_ids=("ghostprov5_rule_a",), minimum_test_count=1,
                        quality="bogus_quality_value",
                    ),
                ),
            )

    def test_quality_appears_in_as_dict(self):
        m = ProviderCertificationManifest(
            **self._base_kwargs(),
            reachability_evidence=(
                FindingReachabilityEvidence(
                    provider_id="ghostprov5", test_file="tests/test_provider_certification_evidence.py",
                    test_selector="", covered_rule_ids=("ghostprov5_rule_a",), minimum_test_count=1,
                    quality="grouped",
                ),
            ),
        )
        d = m.as_dict()
        assert d["reachability_evidence"][0]["quality"] == "grouped"

    def test_all_eleven_providers_use_only_valid_quality_values(self):
        from app.provider_certification import runner

        valid = {"direct", "grouped", "static_only"}
        for pid in runner.known_provider_ids():
            manifest = runner.get_manifest(pid)
            for ev in manifest.reachability_evidence:
                assert ev.quality in valid, f"{pid} reachability evidence has invalid quality {ev.quality!r}"
            for ev in manifest.change_parity_evidence:
                assert ev.quality in valid, f"{pid} parity evidence has invalid quality {ev.quality!r}"

    def test_cloudflare_evidence_declared_as_direct_quality(self):
        from app.provider_certification.manifests.cloudflare import CLOUDFLARE_MANIFEST

        assert CLOUDFLARE_MANIFEST.reachability_evidence[0].quality == "direct"
        assert CLOUDFLARE_MANIFEST.change_parity_evidence[0].quality == "direct"
