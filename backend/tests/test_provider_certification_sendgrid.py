"""SendGrid pilot certification tests (message 6 of N).

Proves the framework independently DISCOVERS and certifies SendGrid's real
state — 8 record types, 27 Finding IDs — with generic
discovery alone (no adapter needed).
"""

from __future__ import annotations

import dataclasses

import pytest

from app.provider_certification import adapters as adapt
from app.provider_certification import discovery as disc
from app.provider_certification import gates
from app.provider_certification import runner
from app.provider_certification.manifests.sendgrid import SENDGRID_MANIFEST


class TestSendGridManifestShape:
    def test_canonical_provider_id_is_sendgrid(self):
        assert SENDGRID_MANIFEST.provider_id == "sendgrid"

    def test_manifest_declares_maturity(self):
        assert SENDGRID_MANIFEST.maturity == "partial"

    def test_manifest_declares_8_record_types(self):
        assert len(SENDGRID_MANIFEST.expected_record_types) == 8

    def test_manifest_declares_27_finding_ids(self):
        assert len(SENDGRID_MANIFEST.security_finding_rule_ids) == 27

    def test_manifest_declares_credential_fields(self):
        assert set(SENDGRID_MANIFEST.credential_fields) == {'sendgrid_api_key'}

    def test_manifest_declares_sensitive_fields(self):
        assert set(SENDGRID_MANIFEST.sensitive_credential_fields) == {'sendgrid_api_key'}

    def test_manifest_declares_reconnect_state(self):
        assert SENDGRID_MANIFEST.expected_reconnect is False
        assert SENDGRID_MANIFEST.expected_live is False

    def test_manifest_declares_frontend_form(self):
        assert SENDGRID_MANIFEST.expected_frontend_form == "SendGridIntegrationForm.tsx"

    def test_manifest_declares_capability_evidence(self):
        assert len(SENDGRID_MANIFEST.capability_evidence) == 1

    def test_manifest_documents_known_limitations(self):
        assert len(SENDGRID_MANIFEST.known_limitations) >= 1


class TestSendGridNoAdapterNeeded:
    def test_no_adapter_registered(self):
        assert adapt.get_adapter("sendgrid") is None


class TestSendGridDiscoveryIndependentlyConfirmsManifest:
    def test_discovered_record_types_match_manifest_exactly(self):
        discovered = disc.discover_schema_record_type_constants("sendgrid")
        assert discovered == set(SENDGRID_MANIFEST.expected_record_types)
        assert len(discovered) == 8

    def test_discovered_finding_ids_match_manifest_exactly(self):
        discovered = disc.discover_registry_rule_ids("sendgrid")
        assert discovered == set(SENDGRID_MANIFEST.security_finding_rule_ids)
        assert len(discovered) == 27

    def test_capability_matrix_membership_matches_maturity(self):
        in_complete, in_partial = disc.discover_capability_matrix_membership("sendgrid")
        assert (in_complete, in_partial) == (False, True)

    def test_no_false_removal_suppression_function_exists(self):
        assert disc.discover_removal_suppression_exists("sendgrid") is False

    def test_sendgrid_absent_from_future_provider_queue(self):
        assert "sendgrid" not in disc.discover_recommended_next_providers()

    def test_sendgrid_absent_from_migration_allowlist(self):
        from app.provider_certification import migration_allowlist as ma
        assert "sendgrid" not in ma.allowlisted_provider_ids()

    def test_frontend_form_file_exists_on_disk(self):
        assert disc.discover_frontend_form_file_exists(SENDGRID_MANIFEST.expected_frontend_form)


class TestSendGridFullCertification:
    def test_overall_status_is_pass(self):
        assert runner.certify_provider("sendgrid").overall_status == "pass"

    def test_no_gate_fails(self):
        result = runner.certify_provider("sendgrid")
        assert [g.gate_id for g in result.gates if g.status == "fail"] == []

    def test_security_finding_reachability_gate_passes(self):
        result = runner.certify_provider("sendgrid")
        gate = next(g for g in result.gates if g.gate_id == "security_finding_reachability")
        assert gate.status == "pass"

    def test_finding_change_parity_gate_passes(self):
        result = runner.certify_provider("sendgrid")
        gate = next(g for g in result.gates if g.gate_id == "finding_change_parity")
        assert gate.status == "pass"

    def test_capability_evidence_gate_passes(self):
        result = runner.certify_provider("sendgrid")
        gate = next(g for g in result.gates if g.gate_id == "capability_evidence")
        assert gate.status == "pass"

    def test_completeness_model_gate_status(self):
        result = runner.certify_provider("sendgrid")
        gate = next(g for g in result.gates if g.gate_id == "completeness_model")
        assert gate.status in ("warning", "not_applicable", "pass")

    def test_false_removal_protection_gate_status(self):
        result = runner.certify_provider("sendgrid")
        gate = next(g for g in result.gates if g.gate_id == "false_removal_protection")
        assert gate.status in ("warning", "not_applicable", "pass")


class TestSendGridNegativeMutations:
    def test_fails_when_finding_ids_discovery_drops_one(self, monkeypatch):
        real = disc.discover_registry_rule_ids("sendgrid")
        mutated = frozenset(real - {next(iter(real))})
        monkeypatch.setattr(disc, "discover_registry_rule_ids", lambda pid: mutated if pid == "sendgrid" else real)
        gate = gates.gate_security_finding_registry_parity(SENDGRID_MANIFEST)
        assert gate.status == "fail"

    def test_fails_when_capability_evidence_test_file_missing(self):
        if not SENDGRID_MANIFEST.capability_evidence:
            pytest.skip("no capability_evidence declared for sendgrid")
        bad_ev = dataclasses.replace(
            SENDGRID_MANIFEST.capability_evidence[0],
            evidence_tests=("tests/test_sendgrid_this_file_does_not_exist.py",),
        )
        bad_manifest = dataclasses.replace(SENDGRID_MANIFEST, capability_evidence=(bad_ev,))
        gate = gates.gate_capability_evidence(bad_manifest)
        assert gate.status == "fail"
