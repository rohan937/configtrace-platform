"""Supabase pilot certification tests (message 4 of N).

Proves the framework independently DISCOVERS and certifies Supabase's
real state — 10 record types, 10 Finding IDs — with generic discovery
alone (no adapter needed): all credential fields, record-type
constants, and classifier dispatch already follow the standard
``<provider>_`` naming convention.
"""

from __future__ import annotations

from app.provider_certification import adapters as adapt
from app.provider_certification import discovery as disc
from app.provider_certification import gates
from app.provider_certification import runner
from app.provider_certification.manifests.supabase import SUPABASE_MANIFEST


class TestSupabaseManifestShape:
    def test_canonical_provider_id_is_supabase(self):
        assert SUPABASE_MANIFEST.provider_id == "supabase"

    def test_manifest_declares_10_record_types(self):
        assert len(SUPABASE_MANIFEST.expected_record_types) == 10

    def test_manifest_declares_10_finding_ids(self):
        assert len(SUPABASE_MANIFEST.security_finding_rule_ids) == 10

    def test_manifest_declares_prefixed_credential_fields(self):
        assert set(SUPABASE_MANIFEST.credential_fields) == {"supabase_access_token", "supabase_project_ref"}

    def test_manifest_marks_access_token_sensitive_but_not_project_ref(self):
        assert SUPABASE_MANIFEST.sensitive_credential_fields == ("supabase_access_token",)

    def test_manifest_declares_public_connectable_live(self):
        assert SUPABASE_MANIFEST.expected_public
        assert SUPABASE_MANIFEST.expected_connectable
        assert SUPABASE_MANIFEST.expected_live

    def test_manifest_declares_reconnect_required(self):
        assert SUPABASE_MANIFEST.expected_reconnect

    def test_manifest_honestly_declares_no_completeness_model(self):
        assert SUPABASE_MANIFEST.completeness_scopes == ()
        assert SUPABASE_MANIFEST.false_removal_scopes == ()

    def test_manifest_documents_no_table_row_ingestion(self):
        assert any("table-row" in lim for lim in SUPABASE_MANIFEST.known_limitations)

    def test_manifest_documents_no_auth_user_ingestion(self):
        assert any("auth-user" in lim for lim in SUPABASE_MANIFEST.known_limitations)


class TestSupabaseNoAdapterNeeded:
    def test_no_adapter_registered(self):
        assert adapt.get_adapter("supabase") is None


class TestSupabaseDiscoveryIndependentlyConfirmsManifest:
    def test_discovered_record_types_match_manifest_exactly(self):
        discovered = disc.discover_schema_record_type_constants("supabase")
        assert discovered == set(SUPABASE_MANIFEST.expected_record_types)
        assert len(discovered) == 10

    def test_discovered_finding_ids_match_manifest_exactly(self):
        discovered = disc.discover_registry_rule_ids("supabase")
        assert discovered == set(SUPABASE_MANIFEST.security_finding_rule_ids)
        assert len(discovered) == 10

    def test_discovered_credential_fields_match_manifest_exactly(self):
        discovered = disc.discover_credential_schema_fields("supabase")
        assert discovered == set(SUPABASE_MANIFEST.credential_fields)

    def test_classifier_dispatch_covers_all_expected_record_types(self):
        direct = disc.discover_classifier_record_type_dispatch("supabase")
        assert set(SUPABASE_MANIFEST.expected_record_types) <= direct

    def test_reconnect_wired_via_named_function(self):
        assert disc.discover_reconnect_function_exists("supabase") is True

    def test_no_false_removal_suppression_function_exists(self):
        assert disc.discover_removal_suppression_exists("supabase") is False

    def test_supabase_absent_from_future_provider_queue(self):
        assert "supabase" not in disc.discover_recommended_next_providers()


class TestSupabaseFullCertification:
    def test_overall_status_is_pass(self):
        assert runner.certify_provider("supabase").overall_status == "pass"

    def test_no_gate_fails(self):
        result = runner.certify_provider("supabase")
        assert [g.gate_id for g in result.gates if g.status == "fail"] == []

    def test_reconnect_rotation_gate_passes(self):
        result = runner.certify_provider("supabase")
        gate = next(g for g in result.gates if g.gate_id == "reconnect_rotation")
        assert gate.status == "pass"

    def test_security_finding_reachability_gate_passes(self):
        result = runner.certify_provider("supabase")
        gate = next(g for g in result.gates if g.gate_id == "security_finding_reachability")
        assert gate.status == "pass"

    def test_finding_change_parity_gate_passes(self):
        result = runner.certify_provider("supabase")
        gate = next(g for g in result.gates if g.gate_id == "finding_change_parity")
        assert gate.status == "pass"

    def test_false_removal_protection_gate_is_warning_not_fail(self):
        result = runner.certify_provider("supabase")
        gate = next(g for g in result.gates if g.gate_id == "false_removal_protection")
        assert gate.status == "warning"


class TestSupabaseNegativeMutations:
    def test_fails_when_reconnect_function_removed(self, monkeypatch):
        monkeypatch.setattr(disc, "discover_reconnect_function_exists", lambda pid: False)
        monkeypatch.setattr(disc, "discover_generic_reconnect_dispatch", lambda pid: False)
        gate = gates.gate_reconnect_rotation(SUPABASE_MANIFEST)
        assert gate.status == "fail"

    def test_fails_when_reachability_evidence_file_missing(self, monkeypatch):
        import dataclasses

        bad_evidence = dataclasses.replace(
            SUPABASE_MANIFEST.reachability_evidence[0],
            test_file="tests/test_supabase_this_file_does_not_exist.py",
        )
        bad_manifest = dataclasses.replace(SUPABASE_MANIFEST, reachability_evidence=(bad_evidence,))
        gate = gates.gate_security_finding_reachability(bad_manifest)
        assert gate.status == "fail"
