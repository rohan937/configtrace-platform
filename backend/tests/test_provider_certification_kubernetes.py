"""Kubernetes pilot certification tests (message 3 of N).

Proves the framework independently DISCOVERS and certifies Kubernetes'
real state — 36 record types (correctly excluding 3 schema constants
never wired into the connector), 59 Finding IDs, unprefixed credential
fields resolved via the Kubernetes discovery adapter, grouped classifier
dispatch resolved via the same adapter, reachability/parity evidence,
completeness/false-removal declarations, and frontend parity.
"""

from __future__ import annotations

import pytest

from app.provider_certification import adapters as adapt
from app.provider_certification import discovery as disc
from app.provider_certification import gates
from app.provider_certification import runner
from app.provider_certification.manifests.kubernetes import KUBERNETES_MANIFEST


class TestKubernetesManifestShape:
    def test_canonical_provider_id_is_kubernetes(self):
        assert KUBERNETES_MANIFEST.provider_id == "kubernetes"

    def test_manifest_declares_36_record_types(self):
        assert len(KUBERNETES_MANIFEST.expected_record_types) == 36

    def test_manifest_declares_59_finding_ids(self):
        assert len(KUBERNETES_MANIFEST.security_finding_rule_ids) == 59

    def test_manifest_declares_unprefixed_credential_fields(self):
        assert set(KUBERNETES_MANIFEST.credential_fields) == {
            "kubeconfig", "context", "cluster_name", "namespace_allowlist",
        }

    def test_manifest_marks_kubeconfig_sensitive(self):
        assert KUBERNETES_MANIFEST.sensitive_credential_fields == ("kubeconfig",)

    def test_manifest_declares_public_connectable_live(self):
        assert KUBERNETES_MANIFEST.expected_public
        assert KUBERNETES_MANIFEST.expected_connectable
        assert KUBERNETES_MANIFEST.expected_live

    def test_manifest_declares_reconnect_required(self):
        assert KUBERNETES_MANIFEST.expected_reconnect

    def test_manifest_declares_four_derived_record_types(self):
        assert set(KUBERNETES_MANIFEST.derived_record_types) == {
            "kubernetes_workload_service_account",
            "kubernetes_rbac_permission_summary",
            "kubernetes_namespace_network_posture",
            "kubernetes_namespace_governance_posture",
        }


class TestKubernetesAdapter:
    def test_adapter_is_registered(self):
        assert adapt.get_adapter("kubernetes") is not None

    def test_adapter_credential_fields_augment_empty_generic(self):
        generic = disc.discover_credential_schema_fields("kubernetes")
        assert generic == frozenset()
        adapter = adapt.get_adapter("kubernetes")
        resolved = adapt.resolve_set(generic, adapter.discover_credential_fields)
        assert resolved.value == frozenset(KUBERNETES_MANIFEST.credential_fields)

    def test_adapter_classifier_resolves_grouped_dispatch(self):
        direct = disc.discover_classifier_record_type_dispatch("kubernetes")
        grouped = disc.discover_classifier_grouped_dispatch("kubernetes")
        assert len(grouped) > 0, "grouped dispatch resolution must find at least one grouped record type"
        combined = direct | grouped
        assert set(KUBERNETES_MANIFEST.expected_record_types) <= combined

    def test_gate_adapter_consistency_passes(self):
        gate = gates.gate_adapter_consistency(KUBERNETES_MANIFEST)
        assert gate.status in ("pass", "not_applicable")


class TestKubernetesDiscoveryIndependentlyConfirmsManifest:
    def test_discovered_record_types_match_manifest_exactly(self):
        discovered = disc.discover_schema_record_type_constants("kubernetes")
        assert discovered == set(KUBERNETES_MANIFEST.expected_record_types)
        assert len(discovered) == 36

    def test_three_phantom_schema_constants_correctly_excluded(self):
        identity = disc.discover_schema_record_type_identity_constants("kubernetes")
        discovered = disc.discover_schema_record_type_constants("kubernetes")
        phantom = set(identity.values()) - discovered
        assert phantom == {
            "kubernetes_api_server_security_posture",
            "kubernetes_config_map_metadata",
            "kubernetes_secret_metadata",
        }

    def test_discovered_finding_ids_match_manifest_exactly(self):
        discovered = disc.discover_registry_rule_ids("kubernetes")
        assert discovered == set(KUBERNETES_MANIFEST.security_finding_rule_ids)
        assert len(discovered) == 59

    def test_discovered_tracked_fields_cover_every_record_type(self):
        tracked = disc.discover_diff_tracked_fields_dict("kubernetes")
        assert tracked is not None
        for rt in KUBERNETES_MANIFEST.expected_record_types:
            assert rt in tracked

    def test_discovered_removal_suppression_exists(self):
        assert disc.discover_removal_suppression_exists("kubernetes")

    def test_kubernetes_absent_from_future_provider_queue(self):
        assert "kubernetes" not in disc.discover_recommended_next_providers()


class TestKubernetesFullCertification:
    def test_overall_status_is_pass(self):
        assert runner.certify_provider("kubernetes").overall_status == "pass"

    def test_no_gate_fails(self):
        result = runner.certify_provider("kubernetes")
        assert [g.gate_id for g in result.gates if g.status == "fail"] == []

    def test_change_classifier_coverage_gate_passes(self):
        result = runner.certify_provider("kubernetes")
        gate = next(g for g in result.gates if g.gate_id == "change_classifier_coverage")
        assert gate.status == "pass"

    def test_security_finding_reachability_gate_passes(self):
        result = runner.certify_provider("kubernetes")
        gate = next(g for g in result.gates if g.gate_id == "security_finding_reachability")
        assert gate.status == "pass"

    def test_finding_change_parity_gate_passes(self):
        result = runner.certify_provider("kubernetes")
        gate = next(g for g in result.gates if g.gate_id == "finding_change_parity")
        assert gate.status == "pass"

    def test_frontend_provider_parity_gate_passes(self):
        result = runner.certify_provider("kubernetes")
        gate = next(g for g in result.gates if g.gate_id == "frontend_provider_parity")
        assert gate.status == "pass"

    def test_false_removal_protection_gate_passes(self):
        result = runner.certify_provider("kubernetes")
        gate = next(g for g in result.gates if g.gate_id == "false_removal_protection")
        assert gate.status == "pass"


class TestKubernetesNegativeMutations:
    def test_fails_when_grouped_dispatch_resolution_drops_a_type(self, monkeypatch):
        real = disc.discover_classifier_grouped_dispatch("kubernetes")
        mutated = real - {"kubernetes_deployment"} if "kubernetes_deployment" in real else real
        monkeypatch.setattr(disc, "discover_classifier_grouped_dispatch", lambda pid: mutated if pid == "kubernetes" else real)
        gate = gates.gate_change_classifier_coverage(KUBERNETES_MANIFEST)
        assert gate.status in ("warning", "fail")

    def test_fails_when_reachability_evidence_file_missing(self, monkeypatch):
        import dataclasses
        from app.provider_certification.models import FindingReachabilityEvidence

        bad_evidence = dataclasses.replace(
            KUBERNETES_MANIFEST.reachability_evidence[0],
            test_file="tests/test_kubernetes_this_file_does_not_exist.py",
        )
        bad_manifest = dataclasses.replace(KUBERNETES_MANIFEST, reachability_evidence=(bad_evidence,))
        gate = gates.gate_security_finding_reachability(bad_manifest)
        assert gate.status == "fail"
