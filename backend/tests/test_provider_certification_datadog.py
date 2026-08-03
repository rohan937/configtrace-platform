"""Datadog pilot certification tests (message 5 of N).

Proves the framework independently DISCOVERS and certifies Datadog's
real state — 10 record types, 31 Finding IDs — with generic discovery
alone (no adapter needed). Registered in PROVIDER_CAPABILITIES_PARTIAL
(maturity='partial' in the real capability matrix).
"""

from __future__ import annotations

from app.provider_certification import adapters as adapt
from app.provider_certification import discovery as disc
from app.provider_certification import gates
from app.provider_certification import runner
from app.provider_certification.manifests.datadog import DATADOG_MANIFEST


class TestDatadogManifestShape:
    def test_canonical_provider_id_is_datadog(self):
        assert DATADOG_MANIFEST.provider_id == "datadog"

    def test_manifest_declares_10_record_types(self):
        assert len(DATADOG_MANIFEST.expected_record_types) == 10

    def test_manifest_declares_31_finding_ids(self):
        assert len(DATADOG_MANIFEST.security_finding_rule_ids) == 31

    def test_manifest_declares_maturity_partial(self):
        assert DATADOG_MANIFEST.maturity == "partial"

    def test_manifest_declares_reconnect_not_required(self):
        assert DATADOG_MANIFEST.expected_reconnect is False
        assert DATADOG_MANIFEST.expected_live is False

    def test_manifest_marks_both_keys_sensitive(self):
        assert set(DATADOG_MANIFEST.sensitive_credential_fields) == {"datadog_api_key", "datadog_application_key"}

    def test_manifest_declares_capability_evidence(self):
        assert len(DATADOG_MANIFEST.capability_evidence) == 1

    def test_manifest_documents_no_metrics_logs_traces_ingestion(self):
        text = " ".join(DATADOG_MANIFEST.known_limitations)
        assert "metrics" in text.lower() and "logs" in text.lower() and "traces" in text.lower()


class TestDatadogNoAdapterNeeded:
    def test_no_adapter_registered(self):
        assert adapt.get_adapter("datadog") is None


class TestDatadogDiscoveryIndependentlyConfirmsManifest:
    def test_discovered_record_types_match_manifest_exactly(self):
        discovered = disc.discover_schema_record_type_constants("datadog")
        assert discovered == set(DATADOG_MANIFEST.expected_record_types)
        assert len(discovered) == 10

    def test_discovered_finding_ids_match_manifest_exactly(self):
        discovered = disc.discover_registry_rule_ids("datadog")
        assert discovered == set(DATADOG_MANIFEST.security_finding_rule_ids)
        assert len(discovered) == 31

    def test_capability_matrix_membership_is_partial_list(self):
        in_complete, in_partial = disc.discover_capability_matrix_membership("datadog")
        assert in_complete is False
        assert in_partial is True

    def test_no_false_removal_suppression_function_exists(self):
        assert disc.discover_removal_suppression_exists("datadog") is False

    def test_datadog_absent_from_future_provider_queue(self):
        assert "datadog" not in disc.discover_recommended_next_providers()


class TestDatadogFullCertification:
    def test_overall_status_is_pass(self):
        assert runner.certify_provider("datadog").overall_status == "pass"

    def test_no_gate_fails(self):
        result = runner.certify_provider("datadog")
        assert [g.gate_id for g in result.gates if g.status == "fail"] == []

    def test_capability_matrix_parity_gate_passes(self):
        result = runner.certify_provider("datadog")
        gate = next(g for g in result.gates if g.gate_id == "capability_matrix_parity")
        assert gate.status == "pass"

    def test_capability_evidence_gate_passes(self):
        result = runner.certify_provider("datadog")
        gate = next(g for g in result.gates if g.gate_id == "capability_evidence")
        assert gate.status == "pass"


class TestDatadogNegativeMutations:
    def test_capability_matrix_parity_fails_if_absent_from_both_lists(self, monkeypatch):
        monkeypatch.setattr(
            disc, "discover_capability_matrix_membership",
            lambda pid: (False, False) if pid == "datadog" else (True, False),
        )
        gate = gates.gate_capability_matrix_parity(DATADOG_MANIFEST)
        assert gate.status == "fail"

    def test_capability_evidence_fails_on_unsupported_capability_with_evidence(self):
        import dataclasses

        from app.provider_certification.models import CapabilityEvidenceDeclaration, ManifestValidationError
        import pytest

        with pytest.raises(ManifestValidationError, match="unsupported_capabilities"):
            dataclasses.replace(
                DATADOG_MANIFEST,
                unsupported_capabilities=("activity_ingestion",),
                capability_evidence=DATADOG_MANIFEST.capability_evidence + (
                    CapabilityEvidenceDeclaration(capability="activity_ingestion", supporting_record_types=("datadog_monitor",)),
                ),
            )
