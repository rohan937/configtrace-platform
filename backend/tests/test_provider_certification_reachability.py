"""Generalized Finding-reachability evidence tests (message 3 of N).

Covers the ``FindingReachabilityEvidence``/``ReachabilityExemption``
models and ``gate_security_finding_reachability`` in isolation from any
one real provider's manifest — using small synthetic manifests so every
branch (valid direct evidence, valid grouped evidence, missing file,
zero selected tests, unknown rule ID, uncovered rule, valid exemption,
exemption missing reason, evidence from another provider, deterministic
evidence ordering) is exercised directly.
"""

from __future__ import annotations

import pytest

from app.provider_certification import gates
from app.provider_certification.models import (
    FindingReachabilityEvidence,
    ManifestValidationError,
    ProviderCertificationManifest,
    ReachabilityExemption,
)

_REAL_TEST_FILE = "tests/test_provider_certification_reachability.py"


def _manifest(**overrides) -> ProviderCertificationManifest:
    fields = dict(
        provider_id="ghostprov",
        display_name="Ghost Provider",
        category="observability",
        maturity="partial",
        expected_public=True,
        expected_connectable=True,
        expected_live=True,
        credential_fields=("ghostprov_api_token",),
        sensitive_credential_fields=("ghostprov_api_token",),
        authentication_model="api_token",
        expected_record_types=("ghostprov_widget",),
        expected_frontend_form="GhostProvIntegrationForm.tsx",
        expected_reconnect=True,
        supported_capabilities=("security_findings",),
        security_finding_rule_ids=("ghostprov_rule_a", "ghostprov_rule_b"),
        false_removal_scopes=("account_wide",),
        reachability_evidence=(
            FindingReachabilityEvidence(
                provider_id="ghostprov",
                test_file=_REAL_TEST_FILE,
                test_selector="",
                covered_rule_ids=("ghostprov_rule_a", "ghostprov_rule_b"),
                minimum_test_count=1,
            ),
        ),
    )
    fields.update(overrides)
    return ProviderCertificationManifest(**fields)


class TestValidDirectEvidence:
    def test_gate_passes_with_valid_evidence(self):
        m = _manifest()
        gate = gates.gate_security_finding_reachability(m)
        assert gate.status == "pass"


class TestValidGroupedEvidence:
    def test_one_evidence_group_can_cover_multiple_rule_ids(self):
        m = _manifest(
            security_finding_rule_ids=("ghostprov_rule_a", "ghostprov_rule_b", "ghostprov_rule_c"),
            reachability_evidence=(
                FindingReachabilityEvidence(
                    provider_id="ghostprov",
                    test_file=_REAL_TEST_FILE,
                    test_selector="",
                    covered_rule_ids=("ghostprov_rule_a", "ghostprov_rule_b", "ghostprov_rule_c"),
                    minimum_test_count=1,
                ),
            ),
        )
        gate = gates.gate_security_finding_reachability(m)
        assert gate.status == "pass"
        assert "3 evidence group(s)" not in gate.details  # single group, not one-per-rule
        assert "1 evidence group(s)" in gate.details


class TestMissingEvidenceFile:
    def test_gate_fails_when_test_file_does_not_exist(self):
        m = _manifest(
            reachability_evidence=(
                FindingReachabilityEvidence(
                    provider_id="ghostprov",
                    test_file="tests/test_this_file_does_not_exist_anywhere.py",
                    test_selector="",
                    covered_rule_ids=("ghostprov_rule_a", "ghostprov_rule_b"),
                    minimum_test_count=1,
                ),
            ),
        )
        gate = gates.gate_security_finding_reachability(m)
        assert gate.status == "fail"
        assert "not found on disk" in gate.details


class TestZeroSelectedTests:
    def test_gate_fails_when_selector_matches_nothing(self):
        # Deliberately uses a DIFFERENT real test file than _REAL_TEST_FILE —
        # this file's own source text contains the sentinel selector string
        # (as this very literal), which would produce a false self-match if
        # the evidence pointed back at this file.
        m = _manifest(
            reachability_evidence=(
                FindingReachabilityEvidence(
                    provider_id="ghostprov",
                    test_file="tests/test_provider_certification_gates.py",
                    test_selector="ThisClassNameDoesNotExistAnywhereInThisFile12345",
                    covered_rule_ids=("ghostprov_rule_a", "ghostprov_rule_b"),
                    minimum_test_count=1,
                ),
            ),
        )
        gate = gates.gate_security_finding_reachability(m)
        assert gate.status == "fail"
        assert "matched 0 test(s)" in gate.details

    def test_gate_fails_when_minimum_test_count_not_met(self):
        m = _manifest(
            reachability_evidence=(
                FindingReachabilityEvidence(
                    provider_id="ghostprov",
                    test_file=_REAL_TEST_FILE,
                    test_selector="",
                    covered_rule_ids=("ghostprov_rule_a", "ghostprov_rule_b"),
                    minimum_test_count=999999,
                ),
            ),
        )
        gate = gates.gate_security_finding_reachability(m)
        assert gate.status == "fail"
        assert "below declared minimum_test_count" in gate.details


class TestUnknownRuleId:
    def test_construction_rejects_reachability_evidence_for_unknown_rule(self):
        with pytest.raises(ManifestValidationError, match="unknown rule ID"):
            _manifest(
                reachability_evidence=(
                    FindingReachabilityEvidence(
                        provider_id="ghostprov",
                        test_file=_REAL_TEST_FILE,
                        test_selector="",
                        covered_rule_ids=("ghostprov_rule_does_not_exist",),
                        minimum_test_count=1,
                    ),
                ),
            )

    def test_construction_rejects_exemption_for_unknown_rule(self):
        with pytest.raises(ManifestValidationError, match="unknown rule ID"):
            _manifest(
                reachability_evidence=(),
                reachability_exemptions=(
                    ReachabilityExemption(rule_ids=("ghostprov_rule_a", "ghostprov_rule_b", "ghostprov_nonexistent"), reason="x"),
                ),
            )


class TestUncoveredRule:
    def test_construction_rejects_a_rule_covered_by_neither_evidence_nor_exemption(self):
        with pytest.raises(ManifestValidationError, match="neither reachability evidence nor an exemption"):
            _manifest(
                security_finding_rule_ids=("ghostprov_rule_a", "ghostprov_rule_b", "ghostprov_rule_uncovered"),
                reachability_evidence=(
                    FindingReachabilityEvidence(
                        provider_id="ghostprov",
                        test_file=_REAL_TEST_FILE,
                        test_selector="",
                        covered_rule_ids=("ghostprov_rule_a", "ghostprov_rule_b"),
                        minimum_test_count=1,
                    ),
                ),
            )


class TestValidExemption:
    def test_exemption_satisfies_coverage_requirement(self):
        m = _manifest(
            reachability_evidence=(
                FindingReachabilityEvidence(
                    provider_id="ghostprov", test_file=_REAL_TEST_FILE, test_selector="",
                    covered_rule_ids=("ghostprov_rule_a",), minimum_test_count=1,
                ),
            ),
            reachability_exemptions=(
                ReachabilityExemption(rule_ids=("ghostprov_rule_b",), reason="Requires a private, unavailable API."),
            ),
        )
        gate = gates.gate_security_finding_reachability(m)
        assert gate.status == "pass"
        assert "1 via exemption" in gate.details

    def test_blocking_exemption_resolves_warning_not_pass(self):
        m = _manifest(
            reachability_evidence=(
                FindingReachabilityEvidence(
                    provider_id="ghostprov", test_file=_REAL_TEST_FILE, test_selector="",
                    covered_rule_ids=("ghostprov_rule_a",), minimum_test_count=1,
                ),
            ),
            reachability_exemptions=(
                ReachabilityExemption(rule_ids=("ghostprov_rule_b",), reason="Needs review.", blocking=True),
            ),
        )
        gate = gates.gate_security_finding_reachability(m)
        assert gate.status == "warning"


class TestExemptionMissingReason:
    def test_construction_rejects_exemption_with_empty_reason(self):
        with pytest.raises(ManifestValidationError, match="empty reason"):
            _manifest(
                reachability_evidence=(
                    FindingReachabilityEvidence(
                        provider_id="ghostprov", test_file=_REAL_TEST_FILE, test_selector="",
                        covered_rule_ids=("ghostprov_rule_a",), minimum_test_count=1,
                    ),
                ),
                reachability_exemptions=(
                    ReachabilityExemption(rule_ids=("ghostprov_rule_b",), reason=""),
                ),
            )


class TestEvidenceFromWrongProvider:
    def test_construction_rejects_evidence_declaring_a_different_provider_id(self):
        with pytest.raises(ManifestValidationError, match="differs from the manifest's own provider_id"):
            _manifest(
                reachability_evidence=(
                    FindingReachabilityEvidence(
                        provider_id="some_other_provider",
                        test_file=_REAL_TEST_FILE,
                        test_selector="",
                        covered_rule_ids=("ghostprov_rule_a", "ghostprov_rule_b"),
                        minimum_test_count=1,
                    ),
                ),
            )


class TestEvidenceOutsideTestsDir:
    def test_construction_rejects_evidence_file_outside_tests(self):
        with pytest.raises(ManifestValidationError, match="must be inside tests/"):
            _manifest(
                reachability_evidence=(
                    FindingReachabilityEvidence(
                        provider_id="ghostprov",
                        test_file="app/provider_certification/gates.py",
                        test_selector="",
                        covered_rule_ids=("ghostprov_rule_a", "ghostprov_rule_b"),
                        minimum_test_count=1,
                    ),
                ),
            )


class TestDuplicateEvidence:
    def test_construction_rejects_duplicate_test_file_selector_pair(self):
        with pytest.raises(ManifestValidationError, match="duplicate reachability_evidence"):
            _manifest(
                reachability_evidence=(
                    FindingReachabilityEvidence(
                        provider_id="ghostprov", test_file=_REAL_TEST_FILE, test_selector="",
                        covered_rule_ids=("ghostprov_rule_a",), minimum_test_count=1,
                    ),
                    FindingReachabilityEvidence(
                        provider_id="ghostprov", test_file=_REAL_TEST_FILE, test_selector="",
                        covered_rule_ids=("ghostprov_rule_b",), minimum_test_count=1,
                    ),
                ),
            )


class TestMinimumTestCountValidation:
    def test_construction_rejects_minimum_test_count_below_one(self):
        with pytest.raises(ManifestValidationError, match="minimum_test_count must be >= 1"):
            _manifest(
                reachability_evidence=(
                    FindingReachabilityEvidence(
                        provider_id="ghostprov", test_file=_REAL_TEST_FILE, test_selector="",
                        covered_rule_ids=("ghostprov_rule_a", "ghostprov_rule_b"), minimum_test_count=0,
                    ),
                ),
            )


class TestDeterministicEvidenceOrdering:
    def test_as_dict_sorts_reachability_evidence(self):
        m = _manifest(
            security_finding_rule_ids=("ghostprov_rule_a", "ghostprov_rule_b", "ghostprov_rule_z"),
            reachability_evidence=(
                FindingReachabilityEvidence(
                    provider_id="ghostprov", test_file="tests/test_z_file.py", test_selector="Z",
                    covered_rule_ids=("ghostprov_rule_z",), minimum_test_count=1,
                ),
                FindingReachabilityEvidence(
                    provider_id="ghostprov", test_file=_REAL_TEST_FILE, test_selector="",
                    covered_rule_ids=("ghostprov_rule_a", "ghostprov_rule_b"), minimum_test_count=1,
                ),
            ),
        )
        d1 = m.as_dict()
        d2 = m.as_dict()
        assert d1 == d2
        assert d1["reachability_evidence"][0]["test_file"] <= d1["reachability_evidence"][1]["test_file"]
