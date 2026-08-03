"""Firebase pilot certification tests (message 4 of N).

Proves the framework independently DISCOVERS and certifies Firebase's
real state — 13 record types, 8 Finding IDs — with generic discovery
alone (no adapter needed).
"""

from __future__ import annotations

from app.provider_certification import adapters as adapt
from app.provider_certification import discovery as disc
from app.provider_certification import gates
from app.provider_certification import runner
from app.provider_certification.manifests.firebase import FIREBASE_MANIFEST


class TestFirebaseManifestShape:
    def test_canonical_provider_id_is_firebase(self):
        assert FIREBASE_MANIFEST.provider_id == "firebase"

    def test_manifest_declares_13_record_types(self):
        assert len(FIREBASE_MANIFEST.expected_record_types) == 13

    def test_manifest_declares_8_finding_ids(self):
        assert len(FIREBASE_MANIFEST.security_finding_rule_ids) == 8

    def test_manifest_declares_service_account_credential(self):
        assert FIREBASE_MANIFEST.credential_fields == ("firebase_service_account_json",)

    def test_manifest_marks_service_account_sensitive(self):
        assert FIREBASE_MANIFEST.sensitive_credential_fields == ("firebase_service_account_json",)

    def test_manifest_declares_public_connectable_live(self):
        assert FIREBASE_MANIFEST.expected_public
        assert FIREBASE_MANIFEST.expected_connectable
        assert FIREBASE_MANIFEST.expected_live

    def test_manifest_declares_reconnect_required(self):
        assert FIREBASE_MANIFEST.expected_reconnect

    def test_manifest_honestly_declares_no_completeness_model(self):
        assert FIREBASE_MANIFEST.completeness_scopes == ()
        assert FIREBASE_MANIFEST.false_removal_scopes == ()

    def test_manifest_documents_no_firestore_document_ingestion(self):
        assert any("Firestore document" in lim for lim in FIREBASE_MANIFEST.known_limitations)

    def test_manifest_documents_no_storage_object_ingestion(self):
        assert any("Storage object" in lim for lim in FIREBASE_MANIFEST.known_limitations)

    def test_manifest_documents_no_auth_user_records_ingestion(self):
        assert any("Authentication user records" in lim for lim in FIREBASE_MANIFEST.known_limitations)


class TestFirebaseNoAdapterNeeded:
    def test_no_adapter_registered(self):
        assert adapt.get_adapter("firebase") is None


class TestFirebaseDiscoveryIndependentlyConfirmsManifest:
    def test_discovered_record_types_match_manifest_exactly(self):
        discovered = disc.discover_schema_record_type_constants("firebase")
        assert discovered == set(FIREBASE_MANIFEST.expected_record_types)
        assert len(discovered) == 13

    def test_discovered_finding_ids_match_manifest_exactly(self):
        discovered = disc.discover_registry_rule_ids("firebase")
        assert discovered == set(FIREBASE_MANIFEST.security_finding_rule_ids)
        assert len(discovered) == 8

    def test_discovered_credential_fields_match_manifest_exactly(self):
        discovered = disc.discover_credential_schema_fields("firebase")
        assert discovered == set(FIREBASE_MANIFEST.credential_fields)

    def test_classifier_dispatch_covers_all_expected_record_types(self):
        direct = disc.discover_classifier_record_type_dispatch("firebase")
        assert set(FIREBASE_MANIFEST.expected_record_types) <= direct

    def test_reconnect_wired_via_named_function(self):
        assert disc.discover_reconnect_function_exists("firebase") is True

    def test_no_false_removal_suppression_function_exists(self):
        assert disc.discover_removal_suppression_exists("firebase") is False

    def test_firebase_absent_from_future_provider_queue(self):
        assert "firebase" not in disc.discover_recommended_next_providers()


class TestFirebaseFullCertification:
    def test_overall_status_is_pass(self):
        assert runner.certify_provider("firebase").overall_status == "pass"

    def test_no_gate_fails(self):
        result = runner.certify_provider("firebase")
        assert [g.gate_id for g in result.gates if g.status == "fail"] == []

    def test_reconnect_rotation_gate_passes(self):
        result = runner.certify_provider("firebase")
        gate = next(g for g in result.gates if g.gate_id == "reconnect_rotation")
        assert gate.status == "pass"

    def test_security_finding_reachability_gate_passes(self):
        result = runner.certify_provider("firebase")
        gate = next(g for g in result.gates if g.gate_id == "security_finding_reachability")
        assert gate.status == "pass"

    def test_finding_change_parity_gate_passes(self):
        result = runner.certify_provider("firebase")
        gate = next(g for g in result.gates if g.gate_id == "finding_change_parity")
        assert gate.status == "pass"

    def test_sensitive_data_controls_gate_passes(self):
        result = runner.certify_provider("firebase")
        gate = next(g for g in result.gates if g.gate_id == "sensitive_data_controls")
        assert gate.status == "pass"


class TestFirebaseNegativeMutations:
    def test_fails_when_finding_ids_discovery_drops_one(self, monkeypatch):
        real = disc.discover_registry_rule_ids("firebase")
        mutated = frozenset(real - {"firebase_database_public_write"})
        monkeypatch.setattr(disc, "discover_registry_rule_ids", lambda pid: mutated if pid == "firebase" else real)
        gate = gates.gate_security_finding_registry_parity(FIREBASE_MANIFEST)
        assert gate.status == "fail"

    def test_fails_when_parity_evidence_file_missing(self, monkeypatch):
        import dataclasses

        bad_evidence = dataclasses.replace(
            FIREBASE_MANIFEST.change_parity_evidence[0],
            test_file="tests/test_firebase_this_file_does_not_exist.py",
        )
        bad_manifest = dataclasses.replace(FIREBASE_MANIFEST, change_parity_evidence=(bad_evidence,))
        gate = gates.gate_finding_change_parity(bad_manifest)
        assert gate.status == "fail"
