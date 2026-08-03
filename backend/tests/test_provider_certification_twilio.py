"""Twilio pilot certification tests (message 6 of N).

Proves the framework independently DISCOVERS and certifies Twilio's real
state — 5 record types, 18 Finding IDs — with generic
discovery alone (no adapter needed).
"""

from __future__ import annotations

import dataclasses

import pytest

from app.provider_certification import adapters as adapt
from app.provider_certification import discovery as disc
from app.provider_certification import gates
from app.provider_certification import runner
from app.provider_certification.manifests.twilio import TWILIO_MANIFEST


class TestTwilioManifestShape:
    def test_canonical_provider_id_is_twilio(self):
        assert TWILIO_MANIFEST.provider_id == "twilio"

    def test_manifest_declares_maturity(self):
        assert TWILIO_MANIFEST.maturity == "partial"

    def test_manifest_declares_5_record_types(self):
        assert len(TWILIO_MANIFEST.expected_record_types) == 5

    def test_manifest_declares_18_finding_ids(self):
        assert len(TWILIO_MANIFEST.security_finding_rule_ids) == 18

    def test_manifest_declares_credential_fields(self):
        assert set(TWILIO_MANIFEST.credential_fields) == {'twilio_account_sid', 'twilio_auth_token'}

    def test_manifest_declares_sensitive_fields(self):
        assert set(TWILIO_MANIFEST.sensitive_credential_fields) == {'twilio_auth_token'}

    def test_manifest_declares_reconnect_state(self):
        assert TWILIO_MANIFEST.expected_reconnect is False
        assert TWILIO_MANIFEST.expected_live is False

    def test_manifest_declares_frontend_form(self):
        assert TWILIO_MANIFEST.expected_frontend_form == "TwilioIntegrationForm.tsx"

    def test_manifest_declares_capability_evidence(self):
        assert len(TWILIO_MANIFEST.capability_evidence) == 1

    def test_manifest_documents_known_limitations(self):
        assert len(TWILIO_MANIFEST.known_limitations) >= 1


class TestTwilioNoAdapterNeeded:
    def test_no_adapter_registered(self):
        assert adapt.get_adapter("twilio") is None


class TestTwilioDiscoveryIndependentlyConfirmsManifest:
    def test_discovered_record_types_match_manifest_exactly(self):
        discovered = disc.discover_schema_record_type_constants("twilio")
        assert discovered == set(TWILIO_MANIFEST.expected_record_types)
        assert len(discovered) == 5

    def test_discovered_finding_ids_match_manifest_exactly(self):
        discovered = disc.discover_registry_rule_ids("twilio")
        assert discovered == set(TWILIO_MANIFEST.security_finding_rule_ids)
        assert len(discovered) == 18

    def test_capability_matrix_membership_matches_maturity(self):
        in_complete, in_partial = disc.discover_capability_matrix_membership("twilio")
        assert (in_complete, in_partial) == (False, True)

    def test_no_false_removal_suppression_function_exists(self):
        assert disc.discover_removal_suppression_exists("twilio") is False

    def test_twilio_absent_from_future_provider_queue(self):
        assert "twilio" not in disc.discover_recommended_next_providers()

    def test_twilio_absent_from_migration_allowlist(self):
        from app.provider_certification import migration_allowlist as ma
        assert "twilio" not in ma.allowlisted_provider_ids()

    def test_frontend_form_file_exists_on_disk(self):
        assert disc.discover_frontend_form_file_exists(TWILIO_MANIFEST.expected_frontend_form)


class TestTwilioFullCertification:
    def test_overall_status_is_pass(self):
        assert runner.certify_provider("twilio").overall_status == "pass"

    def test_no_gate_fails(self):
        result = runner.certify_provider("twilio")
        assert [g.gate_id for g in result.gates if g.status == "fail"] == []

    def test_security_finding_reachability_gate_passes(self):
        result = runner.certify_provider("twilio")
        gate = next(g for g in result.gates if g.gate_id == "security_finding_reachability")
        assert gate.status == "pass"

    def test_finding_change_parity_gate_passes(self):
        result = runner.certify_provider("twilio")
        gate = next(g for g in result.gates if g.gate_id == "finding_change_parity")
        assert gate.status == "pass"

    def test_capability_evidence_gate_passes(self):
        result = runner.certify_provider("twilio")
        gate = next(g for g in result.gates if g.gate_id == "capability_evidence")
        assert gate.status == "pass"

    def test_completeness_model_gate_status(self):
        result = runner.certify_provider("twilio")
        gate = next(g for g in result.gates if g.gate_id == "completeness_model")
        assert gate.status in ("warning", "not_applicable", "pass")

    def test_false_removal_protection_gate_status(self):
        result = runner.certify_provider("twilio")
        gate = next(g for g in result.gates if g.gate_id == "false_removal_protection")
        assert gate.status in ("warning", "not_applicable", "pass")


class TestTwilioNegativeMutations:
    def test_fails_when_finding_ids_discovery_drops_one(self, monkeypatch):
        real = disc.discover_registry_rule_ids("twilio")
        mutated = frozenset(real - {next(iter(real))})
        monkeypatch.setattr(disc, "discover_registry_rule_ids", lambda pid: mutated if pid == "twilio" else real)
        gate = gates.gate_security_finding_registry_parity(TWILIO_MANIFEST)
        assert gate.status == "fail"

    def test_fails_when_capability_evidence_test_file_missing(self):
        if not TWILIO_MANIFEST.capability_evidence:
            pytest.skip("no capability_evidence declared for twilio")
        bad_ev = dataclasses.replace(
            TWILIO_MANIFEST.capability_evidence[0],
            evidence_tests=("tests/test_twilio_this_file_does_not_exist.py",),
        )
        bad_manifest = dataclasses.replace(TWILIO_MANIFEST, capability_evidence=(bad_ev,))
        gate = gates.gate_capability_evidence(bad_manifest)
        assert gate.status == "fail"
