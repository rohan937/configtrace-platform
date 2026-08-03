"""Generalized Finding-vs-Change parity evidence tests (message 3 of N).

Covers ``FindingChangeParityEvidence``/``ParityException`` models and
``gate_finding_change_parity`` in isolation, using small synthetic
manifests. Unlike reachability, parity coverage is NOT mandatory at
construction time — a provider with zero evidence and zero exceptions
is a legitimate "deferred, not fabricated pass" state.
"""

from __future__ import annotations

import pytest

from app.provider_certification import gates
from app.provider_certification.models import (
    FindingChangeParityEvidence,
    FindingReachabilityEvidence,
    ManifestValidationError,
    ParityException,
    ProviderCertificationManifest,
)

_REAL_TEST_FILE = "tests/test_provider_certification_change_parity.py"


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
        # Reachability coverage is mandatory — always satisfy it directly
        # so tests can isolate parity-gate behavior.
        reachability_evidence=(
            ReachabilityExemptionPlaceholder := None,
        )[:0] or (
            __import__("app.provider_certification.models", fromlist=["FindingReachabilityEvidence"]).FindingReachabilityEvidence(
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


class TestFullCoverage:
    def test_gate_passes_with_full_parity_evidence_coverage(self):
        m = _manifest(
            change_parity_evidence=(
                FindingChangeParityEvidence(
                    provider_id="ghostprov",
                    test_file=_REAL_TEST_FILE,
                    test_selector="",
                    covered_rule_ids=("ghostprov_rule_a", "ghostprov_rule_b"),
                    minimum_test_count=1,
                ),
            ),
        )
        gate = gates.gate_finding_change_parity(m)
        assert gate.status == "pass"


class TestMissingEvidenceDeferred:
    def test_gate_defers_and_is_non_blocking_when_nothing_declared(self):
        m = _manifest(change_parity_evidence=(), change_parity_exceptions=())
        gate = gates.gate_finding_change_parity(m)
        assert gate.status == "deferred"
        assert gate.blocking is False


class TestMissingEvidenceFile:
    def test_gate_fails_when_evidence_file_does_not_exist(self):
        m = _manifest(
            change_parity_evidence=(
                FindingChangeParityEvidence(
                    provider_id="ghostprov",
                    test_file="tests/test_this_file_does_not_exist_anywhere.py",
                    test_selector="",
                    covered_rule_ids=("ghostprov_rule_a", "ghostprov_rule_b"),
                    minimum_test_count=1,
                ),
            ),
        )
        gate = gates.gate_finding_change_parity(m)
        assert gate.status == "fail"
        assert "not found on disk" in gate.details


class TestZeroSelectedTests:
    def test_gate_fails_when_minimum_test_count_not_met(self):
        m = _manifest(
            change_parity_evidence=(
                FindingChangeParityEvidence(
                    provider_id="ghostprov",
                    test_file=_REAL_TEST_FILE,
                    test_selector="",
                    covered_rule_ids=("ghostprov_rule_a", "ghostprov_rule_b"),
                    minimum_test_count=999999,
                ),
            ),
        )
        gate = gates.gate_finding_change_parity(m)
        assert gate.status == "fail"
        assert "below declared minimum_test_count" in gate.details


class TestUnknownRule:
    def test_construction_rejects_parity_evidence_for_unknown_rule(self):
        with pytest.raises(ManifestValidationError, match="unknown rule ID"):
            _manifest(
                change_parity_evidence=(
                    FindingChangeParityEvidence(
                        provider_id="ghostprov",
                        test_file=_REAL_TEST_FILE,
                        test_selector="",
                        covered_rule_ids=("ghostprov_rule_does_not_exist",),
                        minimum_test_count=1,
                    ),
                ),
            )

    def test_construction_rejects_exception_for_unknown_rule(self):
        with pytest.raises(ManifestValidationError, match="unknown rule ID"):
            _manifest(
                change_parity_exceptions=(
                    ParityException(
                        rule_id="ghostprov_rule_nonexistent",
                        static_severity="high",
                        transition_severity="medium",
                        rationale="x",
                        evidence_test=f"{_REAL_TEST_FILE}::TestFullCoverage",
                    ),
                ),
            )


class TestValidSeverityException:
    def test_gate_passes_with_a_documented_severity_exception(self):
        m = _manifest(
            change_parity_evidence=(),
            change_parity_exceptions=(
                ParityException(
                    rule_id="ghostprov_rule_a",
                    static_severity="high",
                    transition_severity="medium",
                    rationale="Business decision: this transition is intentionally treated more leniently.",
                    evidence_test=f"{_REAL_TEST_FILE}::TestValidSeverityException::test_gate_passes_with_a_documented_severity_exception",
                ),
                ParityException(
                    rule_id="ghostprov_rule_b",
                    static_severity="critical",
                    transition_severity="critical",
                    rationale="Direct parity, declared explicitly rather than via evidence.",
                    evidence_test=f"{_REAL_TEST_FILE}::TestValidSeverityException::test_gate_passes_with_a_documented_severity_exception",
                ),
            ),
        )
        gate = gates.gate_finding_change_parity(m)
        assert gate.status == "pass"
        assert "2 via explicit severity exception" in gate.details


class TestUndocumentedLowerSeverityTransition:
    def test_construction_rejects_invalid_severity_enum_value(self):
        with pytest.raises(ManifestValidationError, match="invalid transition_severity"):
            _manifest(
                change_parity_exceptions=(
                    ParityException(
                        rule_id="ghostprov_rule_a",
                        static_severity="high",
                        transition_severity="super-duper-severe",
                        rationale="x",
                        evidence_test=f"{_REAL_TEST_FILE}::Foo",
                    ),
                ),
            )


class TestMissingRationale:
    def test_construction_rejects_exception_with_empty_rationale(self):
        with pytest.raises(ManifestValidationError, match="empty rationale"):
            _manifest(
                change_parity_exceptions=(
                    ParityException(
                        rule_id="ghostprov_rule_a",
                        static_severity="high",
                        transition_severity="medium",
                        rationale="",
                        evidence_test=f"{_REAL_TEST_FILE}::Foo",
                    ),
                ),
            )

    def test_construction_rejects_exception_with_no_evidence_test(self):
        with pytest.raises(ManifestValidationError, match="has no evidence_test"):
            _manifest(
                change_parity_exceptions=(
                    ParityException(
                        rule_id="ghostprov_rule_a",
                        static_severity="high",
                        transition_severity="medium",
                        rationale="x",
                        evidence_test="",
                    ),
                ),
            )


class TestDuplicateException:
    def test_construction_rejects_two_exceptions_for_the_same_rule(self):
        with pytest.raises(ManifestValidationError, match="duplicate change_parity_exceptions"):
            _manifest(
                change_parity_exceptions=(
                    ParityException(
                        rule_id="ghostprov_rule_a", static_severity="high", transition_severity="medium",
                        rationale="first", evidence_test=f"{_REAL_TEST_FILE}::Foo",
                    ),
                    ParityException(
                        rule_id="ghostprov_rule_a", static_severity="high", transition_severity="low",
                        rationale="second", evidence_test=f"{_REAL_TEST_FILE}::Bar",
                    ),
                ),
            )


class TestExceptionEvidenceFileMissing:
    def test_gate_fails_when_exception_evidence_test_file_absent(self):
        m = _manifest(
            change_parity_exceptions=(
                ParityException(
                    rule_id="ghostprov_rule_a",
                    static_severity="high",
                    transition_severity="medium",
                    rationale="x",
                    evidence_test="tests/test_this_file_does_not_exist_anywhere.py::Foo",
                ),
                ParityException(
                    rule_id="ghostprov_rule_b",
                    static_severity="high",
                    transition_severity="high",
                    rationale="x",
                    evidence_test=f"{_REAL_TEST_FILE}::Foo",
                ),
            ),
        )
        gate = gates.gate_finding_change_parity(m)
        assert gate.status == "fail"
        assert "evidence_test not found on disk" in gate.details


class TestDeterministicOrdering:
    def test_as_dict_sorts_change_parity_exceptions_by_rule_id(self):
        m = _manifest(
            change_parity_exceptions=(
                ParityException(
                    rule_id="ghostprov_rule_b", static_severity="high", transition_severity="high",
                    rationale="x", evidence_test=f"{_REAL_TEST_FILE}::Foo",
                ),
                ParityException(
                    rule_id="ghostprov_rule_a", static_severity="high", transition_severity="high",
                    rationale="y", evidence_test=f"{_REAL_TEST_FILE}::Foo",
                ),
            ),
        )
        d1 = m.as_dict()
        d2 = m.as_dict()
        assert d1 == d2
        ids = [e["rule_id"] for e in d1["change_parity_exceptions"]]
        assert ids == sorted(ids)
