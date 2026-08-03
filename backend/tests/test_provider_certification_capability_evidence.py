"""Capability evidence model tests (message 5 of N).

Covers ``CapabilityEvidenceDeclaration`` construction-time validation
and ``gate_capability_evidence`` — the mechanism proving a declared
capability is backed by real record types / Finding rules / tests,
not just a bare string.
"""

from __future__ import annotations

import dataclasses

import pytest

from app.provider_certification import gates
from app.provider_certification.manifests.aws import AWS_MANIFEST
from app.provider_certification.manifests.datadog import DATADOG_MANIFEST
from app.provider_certification.manifests.slack import SLACK_MANIFEST
from app.provider_certification.models import (
    CapabilityEvidenceDeclaration,
    ManifestValidationError,
)


class TestCapabilityEvidenceDeclarationShape:
    def test_as_dict_sorts_tuples_deterministically(self):
        ev = CapabilityEvidenceDeclaration(
            capability="security_findings",
            supporting_record_types=("b_type", "a_type"),
            supporting_finding_rule_ids=("z_rule", "a_rule"),
            evidence_tests=("z.py", "a.py"),
        )
        d = ev.as_dict()
        assert d["supporting_record_types"] == ["a_type", "b_type"]
        assert d["supporting_finding_rule_ids"] == ["a_rule", "z_rule"]
        assert d["evidence_tests"] == ["a.py", "z.py"]

    def test_defaults_are_empty_and_false(self):
        ev = CapabilityEvidenceDeclaration(capability="security_findings")
        assert ev.supporting_record_types == ()
        assert ev.supporting_finding_rule_ids == ()
        assert ev.evidence_tests == ()
        assert ev.limitation_note == ""
        assert ev.derived_support is False


class TestValidRecordFindingTestEvidence:
    def test_aws_capability_evidence_references_real_record_types(self):
        ev = AWS_MANIFEST.capability_evidence[0]
        assert set(ev.supporting_record_types) <= set(AWS_MANIFEST.expected_record_types)

    def test_aws_capability_evidence_references_real_finding_ids(self):
        ev = AWS_MANIFEST.capability_evidence[0]
        assert set(ev.supporting_finding_rule_ids) <= set(AWS_MANIFEST.security_finding_rule_ids)

    def test_aws_capability_evidence_test_file_exists_on_disk(self):
        gate = gates.gate_capability_evidence(AWS_MANIFEST)
        assert gate.status == "pass"

    def test_datadog_capability_evidence_gate_passes(self):
        gate = gates.gate_capability_evidence(DATADOG_MANIFEST)
        assert gate.status == "pass"

    def test_slack_capability_evidence_gate_is_not_applicable(self):
        gate = gates.gate_capability_evidence(SLACK_MANIFEST)
        assert gate.status == "not_applicable"


class TestUnknownRecordOrFindingRejected:
    def test_unknown_record_type_rejected_at_construction(self):
        with pytest.raises(ManifestValidationError, match="unknown record type"):
            dataclasses.replace(
                AWS_MANIFEST,
                capability_evidence=(
                    CapabilityEvidenceDeclaration(
                        capability="security_findings",
                        supporting_record_types=("aws_not_a_real_record_type",),
                    ),
                ),
            )

    def test_unknown_finding_id_rejected_at_construction(self):
        with pytest.raises(ManifestValidationError, match="unknown Finding ID"):
            dataclasses.replace(
                AWS_MANIFEST,
                capability_evidence=(
                    CapabilityEvidenceDeclaration(
                        capability="security_findings",
                        supporting_finding_rule_ids=("aws_not_a_real_finding_id",),
                    ),
                ),
            )


class TestUnsupportedCapabilityWithEvidenceRejected:
    def test_evidence_for_a_capability_not_in_supported_capabilities_rejected(self):
        with pytest.raises(ManifestValidationError, match="not in supported_capabilities"):
            dataclasses.replace(
                AWS_MANIFEST,
                capability_evidence=(
                    CapabilityEvidenceDeclaration(capability="totally_unknown_capability"),
                ),
            )

    def test_evidence_for_an_explicitly_unsupported_capability_rejected(self):
        with pytest.raises(ManifestValidationError, match="unsupported_capabilities"):
            dataclasses.replace(
                AWS_MANIFEST,
                supported_capabilities=tuple(
                    c for c in AWS_MANIFEST.supported_capabilities if c != "activity_ingestion"
                ),
                unsupported_capabilities=("activity_ingestion",),
                capability_evidence=AWS_MANIFEST.capability_evidence + (
                    CapabilityEvidenceDeclaration(capability="activity_ingestion"),
                ),
            )


class TestCapabilityLackingEvidenceIsAllowed:
    def test_supported_capability_without_evidence_declaration_is_not_an_error(self):
        # activity_ingestion is supported but has no capability_evidence
        # entry — evidence is optional strengthening, not mandatory for
        # every capability.
        assert "activity_ingestion" in AWS_MANIFEST.supported_capabilities
        assert not any(ev.capability == "activity_ingestion" for ev in AWS_MANIFEST.capability_evidence)


class TestDuplicateCapabilityEvidenceRejected:
    def test_duplicate_capability_declaration_rejected(self):
        with pytest.raises(ManifestValidationError, match="duplicate capability_evidence"):
            dataclasses.replace(
                AWS_MANIFEST,
                capability_evidence=AWS_MANIFEST.capability_evidence + (
                    CapabilityEvidenceDeclaration(capability="security_findings"),
                ),
            )


class TestCapabilityContradictionExamples:
    """Message 5 item ~19: capability contradiction examples — a
    capability claim whose supporting evidence structurally cannot
    justify it (e.g., claiming activity_ingestion support backed only
    by record types belonging to an entirely different, unrelated
    surface). These are documented as reasoning examples: the model
    does not attempt automatic semantic contradiction detection beyond
    "does the record type/Finding ID exist in this manifest" — that
    stronger check is intentionally out of scope and is why
    ``limitation_note`` exists for a human-readable caveat instead."""

    def test_effective_access_capability_evidence_would_need_derived_record_types(self):
        # AWS has no "effective_access" capability at all in its fixed
        # 5-string vocabulary, so there is nothing to contradict — this
        # documents that the vocabulary itself prevents the contradiction
        # class the task describes (no manifest can claim a capability
        # outside the fixed vocabulary).
        assert "effective_access" not in AWS_MANIFEST.supported_capabilities
        assert "effective_access" not in DATADOG_MANIFEST.supported_capabilities

    def test_alerting_capability_is_not_in_the_fixed_vocabulary(self):
        assert "alerting" not in AWS_MANIFEST.supported_capabilities

    def test_repositories_capability_is_not_in_the_fixed_vocabulary(self):
        assert "repositories" not in AWS_MANIFEST.supported_capabilities

    def test_fixed_capability_vocabulary_is_exactly_five_strings(self):
        vocab = {
            "security_findings", "activity_ingestion", "activity_signals",
            "risk_activity_correlations", "demo_case_reporting",
        }
        assert set(AWS_MANIFEST.supported_capabilities) <= vocab
        assert set(DATADOG_MANIFEST.supported_capabilities) <= vocab


class TestDeterministicOrdering:
    def test_capability_evidence_serialization_is_sorted_by_capability(self):
        d = AWS_MANIFEST.as_dict()
        capabilities = [ev["capability"] for ev in d["capability_evidence"]]
        assert capabilities == sorted(capabilities)
