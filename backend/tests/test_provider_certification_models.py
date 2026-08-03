"""Model-layer tests for the Provider Certification Framework (message 1).

Covers manifest validation (valid + every documented contradiction),
gate/evidence/result serialization, deterministic JSON output, and the
schema version constant.
"""

from __future__ import annotations

import json

import pytest

from app.provider_certification.models import (
    COMPLETENESS_SCOPE_GRANULARITIES,
    SCHEMA_VERSION,
    CertificationEvidence,
    CertificationGate,
    CertificationResult,
    CompletenessScopeDeclaration,
    ManifestValidationError,
    ProviderCertificationManifest,
)


def _minimal_manifest(**overrides) -> ProviderCertificationManifest:
    fields = dict(
        provider_id="testprov",
        display_name="Test Provider",
        category="observability",
        maturity="partial",
        expected_public=True,
        expected_connectable=True,
        expected_live=True,
        credential_fields=("testprov_api_token",),
        sensitive_credential_fields=("testprov_api_token",),
        authentication_model="api_token",
        expected_record_types=("testprov_widget",),
        expected_frontend_form="TestProvIntegrationForm.tsx",
        expected_reconnect=True,
    )
    fields.update(overrides)
    return ProviderCertificationManifest(**fields)


# ════════════════════════════════════════════════════════════════════════════
# Valid manifest
# ════════════════════════════════════════════════════════════════════════════


class TestValidManifest:
    def test_minimal_valid_manifest_constructs(self):
        m = _minimal_manifest()
        assert m.provider_id == "testprov"
        assert m.maturity == "partial"

    def test_planned_manifest_allows_non_public(self):
        m = _minimal_manifest(
            maturity="planned",
            expected_public=False,
            expected_connectable=False,
            expected_live=False,
            expected_reconnect=False,
            expected_frontend_form=None,
        )
        assert m.maturity == "planned"

    def test_as_dict_contains_all_fields(self):
        m = _minimal_manifest()
        d = m.as_dict()
        assert d["provider_id"] == "testprov"
        assert d["credential_fields"] == ["testprov_api_token"]
        assert d["security_finding_rule_ids"] == []


# ════════════════════════════════════════════════════════════════════════════
# Manifest contradictions
# ════════════════════════════════════════════════════════════════════════════


class TestManifestContradictions:
    def test_live_true_connectable_false_rejected(self):
        with pytest.raises(ManifestValidationError, match="expected_connectable"):
            _minimal_manifest(expected_live=True, expected_connectable=False)

    def test_connectable_true_public_false_rejected(self):
        with pytest.raises(ManifestValidationError, match="expected_public"):
            _minimal_manifest(expected_connectable=True, expected_public=False, expected_live=False)

    def test_planned_provider_marked_public_rejected(self):
        with pytest.raises(ManifestValidationError, match="planned"):
            _minimal_manifest(maturity="planned", expected_public=True)

    def test_security_findings_true_zero_rule_ids_rejected(self):
        with pytest.raises(ManifestValidationError, match="security_finding_rule_ids"):
            _minimal_manifest(supported_capabilities=("security_findings",), security_finding_rule_ids=())

    def test_rule_ids_present_without_capability_declared_rejected(self):
        with pytest.raises(ManifestValidationError, match="security_findings"):
            _minimal_manifest(security_finding_rule_ids=("testprov_bad_rule",))

    def test_duplicate_record_types_rejected(self):
        with pytest.raises(ManifestValidationError, match="duplicates"):
            _minimal_manifest(expected_record_types=("testprov_widget", "testprov_widget"))

    def test_duplicate_finding_ids_rejected(self):
        with pytest.raises(ManifestValidationError, match="duplicates"):
            _minimal_manifest(
                supported_capabilities=("security_findings",),
                security_finding_rule_ids=("testprov_dup", "testprov_dup"),
            )

    def test_finding_id_wrong_prefix_rejected(self):
        with pytest.raises(ManifestValidationError, match="does not start with"):
            _minimal_manifest(
                supported_capabilities=("security_findings",),
                security_finding_rule_ids=("otherprov_rule",),
            )

    def test_secret_field_missing_sensitivity_rejected(self):
        with pytest.raises(ManifestValidationError, match="not marked sensitive|not in sensitive"):
            _minimal_manifest(
                credential_fields=("testprov_auth_token",),
                sensitive_credential_fields=(),
            )

    def test_sensitive_field_not_in_credential_fields_rejected(self):
        with pytest.raises(ManifestValidationError, match="sensitive_credential_fields references"):
            _minimal_manifest(
                credential_fields=("testprov_slug",),
                sensitive_credential_fields=("testprov_slug", "testprov_ghost_token"),
            )

    def test_live_without_reconnect_rejected(self):
        with pytest.raises(ManifestValidationError, match="expected_reconnect"):
            _minimal_manifest(expected_live=True, expected_reconnect=False)

    def test_connectable_without_frontend_form_rejected(self):
        with pytest.raises(ManifestValidationError, match="expected_frontend_form"):
            _minimal_manifest(expected_frontend_form=None)

    def test_capability_both_supported_and_unsupported_rejected(self):
        with pytest.raises(ManifestValidationError, match="both supported and unsupported"):
            _minimal_manifest(
                supported_capabilities=("activity_ingestion",),
                unsupported_capabilities=("activity_ingestion",),
            )

    def test_complete_maturity_with_capability_gap_rejected(self):
        with pytest.raises(ManifestValidationError, match="complete"):
            _minimal_manifest(
                maturity="complete",
                supported_capabilities=("security_findings",),
                security_finding_rule_ids=("testprov_rule",),
            )

    def test_complete_maturity_with_all_capabilities_accepted(self):
        from app.provider_certification.models import ReachabilityExemption

        m = _minimal_manifest(
            maturity="complete",
            supported_capabilities=(
                "security_findings",
                "activity_ingestion",
                "activity_signals",
                "risk_activity_correlations",
                "demo_case_reporting",
            ),
            security_finding_rule_ids=("testprov_rule",),
            reachability_exemptions=(
                ReachabilityExemption(rule_ids=("testprov_rule",), reason="Test fixture; not a real provider."),
            ),
        )
        assert m.maturity == "complete"

    def test_dependency_both_allowed_and_prohibited_rejected(self):
        with pytest.raises(ManifestValidationError, match="both allowed and prohibited"):
            _minimal_manifest(allowed_dependencies=("httpx",), prohibited_dependencies=("httpx",))

    def test_env_var_both_required_and_prohibited_rejected(self):
        with pytest.raises(ManifestValidationError, match="both required and prohibited"):
            _minimal_manifest(required_env_vars=("X",), prohibited_env_vars=("X",))

    def test_derived_record_type_not_subset_of_expected_rejected(self):
        with pytest.raises(ManifestValidationError, match="subset"):
            _minimal_manifest(derived_record_types=("testprov_ghost",))

    def test_duplicate_derived_record_types_rejected(self):
        with pytest.raises(ManifestValidationError, match="duplicates"):
            _minimal_manifest(
                expected_record_types=("testprov_widget", "testprov_gadget"),
                derived_record_types=("testprov_widget", "testprov_widget"),
            )


# ════════════════════════════════════════════════════════════════════════════
# Evidence / gate / status validation
# ════════════════════════════════════════════════════════════════════════════


class TestEvidenceModel:
    def test_valid_evidence_types(self):
        for et in (
            "discovered_symbol", "test_file", "test_node_id", "report",
            "source_grep", "capability_matrix_entry", "manifest_declaration",
        ):
            ev = CertificationEvidence(evidence_type=et)
            assert ev.evidence_type == et

    def test_invalid_evidence_type_rejected(self):
        with pytest.raises(ValueError):
            CertificationEvidence(evidence_type="vibes")

    def test_as_dict_roundtrip(self):
        ev = CertificationEvidence(evidence_type="test_file", file="tests/test_x.py", note="n")
        d = ev.as_dict()
        assert d["file"] == "tests/test_x.py"
        assert d["note"] == "n"


class TestCertificationGate:
    def test_valid_gate_constructs(self):
        g = CertificationGate(
            gate_id="identity", dimension="identity", title="t", description="d",
            required_for_maturities=("partial",), required_for_live=False,
            status="pass", details="ok",
        )
        assert g.status == "pass"

    def test_unknown_dimension_rejected(self):
        with pytest.raises(ValueError, match="Unknown certification dimension"):
            CertificationGate(
                gate_id="x", dimension="not_a_real_dimension", title="t", description="d",
                required_for_maturities=("partial",), required_for_live=False,
                status="pass", details="ok",
            )

    def test_invalid_status_rejected(self):
        with pytest.raises(ValueError):
            CertificationGate(
                gate_id="identity", dimension="identity", title="t", description="d",
                required_for_maturities=("partial",), required_for_live=False,
                status="maybe", details="ok",
            )

    def test_invalid_maturity_in_required_rejected(self):
        with pytest.raises(ValueError, match="Unknown maturity"):
            CertificationGate(
                gate_id="identity", dimension="identity", title="t", description="d",
                required_for_maturities=("legendary",), required_for_live=False,
                status="pass", details="ok",
            )

    def test_deferred_is_not_treated_as_pass_status_value(self):
        g = CertificationGate(
            gate_id="identity", dimension="identity", title="t", description="d",
            required_for_maturities=("partial",), required_for_live=False,
            status="deferred", details="ok",
        )
        assert g.status == "deferred"
        assert g.status != "pass"


# ════════════════════════════════════════════════════════════════════════════
# Result model + deterministic serialization
# ════════════════════════════════════════════════════════════════════════════


def _gate(gate_id: str, status: str) -> CertificationGate:
    return CertificationGate(
        gate_id=gate_id, dimension="identity", title="t", description="d",
        required_for_maturities=("partial",), required_for_live=False,
        status=status, details="d",
    )


class TestCertificationResult:
    def test_summary_counts(self):
        gates = (_gate("z", "pass"), _gate("a", "fail"), _gate("m", "warning"), _gate("b", "deferred"))
        result = CertificationResult(provider_id="x", maturity="partial", overall_status="fail", gates=gates)
        assert result.summary == {
            "passed": 1, "failed": 1, "warnings": 1, "not_applicable": 0, "deferred": 1, "unknown": 0,
        }

    def test_gates_sorted_deterministically_in_dict(self):
        gates = (_gate("z", "pass"), _gate("a", "pass"), _gate("m", "pass"))
        result = CertificationResult(provider_id="x", maturity="partial", overall_status="pass", gates=gates)
        ids = [g["gate_id"] for g in result.as_dict()["gates"]]
        assert ids == ["a", "m", "z"]

    def test_schema_version_is_integer_not_date(self):
        assert isinstance(SCHEMA_VERSION, int)
        assert SCHEMA_VERSION == 1

    def test_to_json_is_deterministic_across_calls(self):
        gates = (_gate("b", "pass"), _gate("a", "pass"))
        result = CertificationResult(provider_id="x", maturity="partial", overall_status="pass", gates=gates)
        assert result.to_json() == result.to_json()

    def test_to_json_sorts_keys(self):
        gates = (_gate("a", "pass"),)
        result = CertificationResult(provider_id="x", maturity="partial", overall_status="pass", gates=gates)
        parsed = json.loads(result.to_json())
        assert list(parsed.keys()) == sorted(parsed.keys())

    def test_invalid_overall_status_rejected(self):
        with pytest.raises(ValueError):
            CertificationResult(provider_id="x", maturity="partial", overall_status="vibes", gates=())


class TestCompletenessScopeDeclarationModel:
    """Model-level tests for CompletenessScopeDeclaration (message 4) —
    distinct from the manifest-integration tests in
    test_provider_certification_completeness.py, which exercise it only
    through ProviderCertificationManifest construction."""

    def test_minimal_declaration_defaults(self):
        scope = CompletenessScopeDeclaration(
            scope_id="minimal", record_types=("x_widget",), granularity="family",
        )
        assert scope.parent_record_type is None
        assert scope.status_field is None
        assert scope.suppression_symbol is None
        assert scope.derived_dependents == ()
        assert scope.note == ""

    def test_as_dict_contains_all_fields(self):
        scope = CompletenessScopeDeclaration(
            scope_id="full", record_types=("x_widget", "x_gadget"), granularity="zone",
            parent_record_type="x_widget", status_field="status", suppression_symbol="_x_removal_suppressed",
            derived_dependents=("x_widget_summary",), note="a note",
        )
        d = scope.as_dict()
        assert d["scope_id"] == "full"
        assert d["record_types"] == ["x_gadget", "x_widget"]
        assert d["granularity"] == "zone"
        assert d["parent_record_type"] == "x_widget"
        assert d["status_field"] == "status"
        assert d["suppression_symbol"] == "_x_removal_suppressed"
        assert d["derived_dependents"] == ["x_widget_summary"]
        assert d["note"] == "a note"

    def test_as_dict_sorts_record_types(self):
        scope = CompletenessScopeDeclaration(
            scope_id="sorted_test", record_types=("z_type", "a_type", "m_type"), granularity="family",
        )
        assert scope.as_dict()["record_types"] == ["a_type", "m_type", "z_type"]

    def test_multiple_record_types_accepted(self):
        scope = CompletenessScopeDeclaration(
            scope_id="multi", record_types=("a", "b", "c"), granularity="account",
        )
        assert len(scope.record_types) == 3

    def test_frozen_immutability(self):
        scope = CompletenessScopeDeclaration(scope_id="frozen", record_types=("a",), granularity="family")
        with pytest.raises(Exception):
            scope.scope_id = "changed"

    def test_all_twelve_granularities_are_distinct_strings(self):
        assert len(COMPLETENESS_SCOPE_GRANULARITIES) == 12
        assert all(isinstance(g, str) for g in COMPLETENESS_SCOPE_GRANULARITIES)
