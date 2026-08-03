"""Microsoft Entra ID pilot certification tests (message 2 of N).

Proves the framework independently DISCOVERS and certifies Entra's real
state — 19 record types, 45 Finding IDs, public/connectable/Live parity,
three credential fields, masked client-secret field, reconnect dispatch,
security parity, completeness declaration, and absence from the
future-provider queue — rather than trusting the manifest's own
declarations. Also proves gates FAIL under negative mutation.
"""

from __future__ import annotations

import pytest

from app.provider_certification import discovery as disc
from app.provider_certification import gates
from app.provider_certification import runner
from app.provider_certification.manifests.entra import ENTRA_MANIFEST


class TestEntraManifestShape:
    def test_canonical_provider_id_is_entra(self):
        assert ENTRA_MANIFEST.provider_id == "entra"

    def test_manifest_declares_19_record_types(self):
        assert len(ENTRA_MANIFEST.expected_record_types) == 19

    def test_manifest_declares_45_finding_ids(self):
        assert len(ENTRA_MANIFEST.security_finding_rule_ids) == 45

    def test_manifest_declares_three_credential_fields(self):
        assert set(ENTRA_MANIFEST.credential_fields) == {
            "entra_tenant_id",
            "entra_client_id",
            "entra_client_secret",
        }

    def test_manifest_marks_client_secret_sensitive(self):
        assert ENTRA_MANIFEST.sensitive_credential_fields == ("entra_client_secret",)

    def test_manifest_declares_public_connectable_live(self):
        assert ENTRA_MANIFEST.expected_public
        assert ENTRA_MANIFEST.expected_connectable
        assert ENTRA_MANIFEST.expected_live

    def test_manifest_declares_reconnect_required(self):
        assert ENTRA_MANIFEST.expected_reconnect

    def test_manifest_declares_maturity_partial(self):
        assert ENTRA_MANIFEST.maturity == "partial"

    def test_manifest_declares_three_derived_record_types(self):
        assert set(ENTRA_MANIFEST.derived_record_types) == {
            "entra_privileged_identity",
            "entra_privileged_group",
            "entra_privileged_service_principal",
        }


class TestEntraDiscoveryIndependentlyConfirmsManifest:
    def test_discovered_record_types_match_manifest_exactly(self):
        discovered = disc.discover_schema_record_type_constants("entra")
        assert discovered == set(ENTRA_MANIFEST.expected_record_types)
        assert len(discovered) == 19

    def test_discovered_finding_ids_match_manifest_exactly(self):
        discovered = disc.discover_registry_rule_ids("entra")
        assert discovered == set(ENTRA_MANIFEST.security_finding_rule_ids)
        assert len(discovered) == 45

    def test_discovered_confidence_pack_coverage_match_registry(self):
        registry = disc.discover_registry_rule_ids("entra")
        assert disc.discover_confidence_rule_ids("entra") == registry
        assert disc.discover_pack_rule_ids("entra") == registry
        assert disc.discover_coverage_rule_ids("entra") == registry

    def test_discovered_credential_fields_match_manifest(self):
        discovered = disc.discover_credential_schema_fields("entra")
        assert discovered == set(ENTRA_MANIFEST.credential_fields)

    def test_discovered_reconnect_dispatch_matches_manifest_declaration(self):
        assert disc.discover_reconnect_function_exists("entra") == ENTRA_MANIFEST.expected_reconnect

    def test_discovered_capability_matrix_maturity_matches_manifest(self):
        cap = disc.discover_capability_entry("entra")
        assert cap.maturity == ENTRA_MANIFEST.maturity

    def test_discovered_tracked_fields_cover_every_record_type(self):
        tracked = disc.discover_diff_tracked_fields_dict("entra")
        assert tracked is not None
        for rt in ENTRA_MANIFEST.expected_record_types:
            assert rt in tracked

    def test_discovered_classifier_handles_every_record_type(self):
        handled = disc.discover_classifier_record_type_dispatch("entra")
        assert set(ENTRA_MANIFEST.expected_record_types) <= handled

    def test_discovered_removal_suppression_exists(self):
        assert disc.discover_removal_suppression_exists("entra")

    def test_discovered_frontend_form_masks_secret_field(self):
        if disc.frontend_root() is None:
            pytest.skip("frontend tree not mounted")
        assert disc.discover_frontend_form_uses_password_input(ENTRA_MANIFEST.expected_frontend_form)

    def test_entra_absent_from_future_provider_queue(self):
        assert "entra" not in disc.discover_recommended_next_providers()
        fe_queue = disc.discover_frontend_future_provider_queue()
        if fe_queue is not None:
            assert "Microsoft Entra ID" not in fe_queue

    def test_no_msal_or_azure_identity_dependency_present(self):
        for dep in ENTRA_MANIFEST.prohibited_dependencies:
            assert not disc.discover_prohibited_dependency_present(dep)

    def test_no_alias_provider_id_registered(self):
        """This repository has no 'microsoft_entra_id' or 'azure_ad'
        alias — 'entra' is the sole canonical ID everywhere."""
        sync_ids = disc.discover_backend_sync_provider_ids()
        assert "microsoft_entra_id" not in sync_ids
        assert "azure_ad" not in sync_ids
        fe_ids = disc.discover_frontend_provider_ids()
        if fe_ids is not None:
            assert "microsoft_entra_id" not in fe_ids
            assert "azure_ad" not in fe_ids


class TestEntraFullCertification:
    def test_overall_status_is_pass(self):
        assert runner.certify_provider("entra").overall_status == "pass"

    def test_no_gate_is_unknown(self):
        result = runner.certify_provider("entra")
        assert all(g.status != "unknown" for g in result.gates)

    def test_no_gate_fails(self):
        result = runner.certify_provider("entra")
        assert [g.gate_id for g in result.gates if g.status == "fail"] == []

    def test_security_finding_registry_parity_gate_passes(self):
        result = runner.certify_provider("entra")
        gate = next(g for g in result.gates if g.gate_id == "security_finding_registry_parity")
        assert gate.status == "pass"

    def test_record_inventory_gate_passes(self):
        result = runner.certify_provider("entra")
        gate = next(g for g in result.gates if g.gate_id == "record_inventory")
        assert gate.status == "pass"

    def test_change_classifier_coverage_gate_passes(self):
        result = runner.certify_provider("entra")
        gate = next(g for g in result.gates if g.gate_id == "change_classifier_coverage")
        assert gate.status == "pass"

    def test_completeness_model_gate_passes(self):
        result = runner.certify_provider("entra")
        gate = next(g for g in result.gates if g.gate_id == "completeness_model")
        assert gate.status == "pass"

    def test_false_removal_protection_gate_passes(self):
        result = runner.certify_provider("entra")
        gate = next(g for g in result.gates if g.gate_id == "false_removal_protection")
        assert gate.status == "pass"

    def test_frontend_provider_parity_gate_passes(self):
        result = runner.certify_provider("entra")
        gate = next(g for g in result.gates if g.gate_id == "frontend_provider_parity")
        assert gate.status == "pass"

    def test_known_limitations_gate_passes(self):
        result = runner.certify_provider("entra")
        gate = next(g for g in result.gates if g.gate_id == "known_limitations")
        assert gate.status == "pass"

    def test_provider_expansion_freeze_gate_passes(self):
        result = runner.certify_provider("entra")
        gate = next(g for g in result.gates if g.gate_id == "provider_expansion_freeze")
        assert gate.status == "pass"

    def test_summary_counts_are_internally_consistent(self):
        result = runner.certify_provider("entra")
        assert sum(result.summary.values()) == len(result.gates)


class TestEntraNegativeMutations:
    def test_fails_when_finding_missing_from_confidence_map(self, monkeypatch):
        real_registry = disc.discover_registry_rule_ids("entra")
        mutated_confidence = real_registry - {"entra_global_admin_assigned"}
        monkeypatch.setattr(
            disc, "discover_confidence_rule_ids", lambda pid: mutated_confidence if pid == "entra" else frozenset()
        )
        gate = gates.gate_security_finding_registry_parity(ENTRA_MANIFEST)
        assert gate.status == "fail"
        assert "confidence" in gate.details

    def test_fails_when_backend_connectable_but_frontend_absent(self, monkeypatch):
        monkeypatch.setattr(disc, "discover_frontend_provider_ids", lambda: frozenset({"sentry", "snowflake", "okta"}))
        gate = gates.gate_frontend_provider_parity(ENTRA_MANIFEST)
        assert gate.status == "fail"
        assert "frontend PROVIDER_IDS" in gate.details

    def test_fails_when_provider_marked_live_but_capability_matrix_reports_planned(self, monkeypatch):
        from types import SimpleNamespace

        real_entry = disc.discover_capability_entry("entra")
        planned_entry = SimpleNamespace(
            provider=real_entry.provider,
            category=real_entry.category,
            maturity="planned",
            security=real_entry.security,
        )
        monkeypatch.setattr(disc, "discover_capability_entry", lambda pid: planned_entry if pid == "entra" else real_entry)
        gate = gates.gate_capability_matrix_parity(ENTRA_MANIFEST)
        assert gate.status == "fail"
        assert "maturity mismatch" in gate.details

    def test_fails_when_completeness_scope_declared_but_no_suppression_implementation(self, monkeypatch):
        monkeypatch.setattr(disc, "discover_removal_suppression_exists", lambda pid: False)
        gate = gates.gate_false_removal_protection(ENTRA_MANIFEST)
        assert gate.status == "fail"

    def test_fails_when_reconnect_required_but_service_function_missing(self, monkeypatch):
        monkeypatch.setattr(disc, "discover_reconnect_function_exists", lambda pid: False)
        gate = gates.gate_reconnect_rotation(ENTRA_MANIFEST)
        assert gate.status == "fail"
        assert "reconnect_credentials_entra" in gate.details

    def test_fails_when_record_type_missing_from_diff_tracked_fields(self, monkeypatch):
        real = disc.discover_diff_tracked_fields_dict("entra")
        mutated = dict(real)
        del mutated["entra_conditional_access_policy"]
        monkeypatch.setattr(disc, "discover_diff_tracked_fields_dict", lambda pid: mutated if pid == "entra" else real)
        gate = gates.gate_diff_tracked_fields(ENTRA_MANIFEST)
        assert gate.status == "fail"
        assert "entra_conditional_access_policy" in gate.details
