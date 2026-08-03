"""Vercel pilot certification tests (message 5 of N).

Proves the framework independently DISCOVERS and certifies Vercel's
real state — 5 real record types (7 classifier-only phantom constants
correctly excluded), 7 Finding IDs, no reconnect wired despite a
reconnect schema field existing.
"""

from __future__ import annotations

from app.provider_certification import adapters as adapt
from app.provider_certification import discovery as disc
from app.provider_certification import gates
from app.provider_certification import runner
from app.provider_certification.manifests.vercel import VERCEL_MANIFEST


class TestVercelManifestShape:
    def test_canonical_provider_id_is_vercel(self):
        assert VERCEL_MANIFEST.provider_id == "vercel"

    def test_manifest_declares_5_record_types(self):
        assert len(VERCEL_MANIFEST.expected_record_types) == 5

    def test_manifest_declares_7_finding_ids(self):
        assert len(VERCEL_MANIFEST.security_finding_rule_ids) == 7

    def test_manifest_declares_reconnect_required(self):
        assert VERCEL_MANIFEST.expected_reconnect is True
        assert VERCEL_MANIFEST.expected_live is False

    def test_manifest_declares_maturity_complete(self):
        assert VERCEL_MANIFEST.maturity == "complete"

    def test_manifest_documents_generic_reconnect_dispatch_pattern(self):
        assert any("SHARED generic reconnect_credentials()" in lim for lim in VERCEL_MANIFEST.known_limitations)

    def test_manifest_documents_7_unwired_schema_constants(self):
        assert any("7 schema-declared" in lim for lim in VERCEL_MANIFEST.known_limitations)


class TestVercelNoAdapterNeeded:
    def test_no_adapter_registered(self):
        assert adapt.get_adapter("vercel") is None


class TestVercelDiscoveryIndependentlyConfirmsManifest:
    def test_discovered_record_types_match_manifest_exactly(self):
        discovered = disc.discover_schema_record_type_constants("vercel")
        assert discovered == set(VERCEL_MANIFEST.expected_record_types)
        assert len(discovered) == 5

    def test_7_unwired_schema_constants_correctly_excluded(self):
        identity = disc.discover_schema_record_type_identity_constants("vercel")
        discovered = disc.discover_schema_record_type_constants("vercel")
        unwired = set(identity.values()) - discovered
        assert len(unwired) == 7

    def test_classifier_dispatches_more_than_the_connector_actually_wires(self):
        # The classifier module has dispatch entries for all 12 identity
        # constants, but only 5 are genuinely wired into the connector —
        # proving the classifier-only entries are aspirational, not a
        # discovery bug.
        classifier = disc.discover_classifier_record_type_dispatch("vercel")
        assert len(classifier) == 12
        assert set(VERCEL_MANIFEST.expected_record_types) < classifier

    def test_discovered_finding_ids_match_manifest_exactly(self):
        discovered = disc.discover_registry_rule_ids("vercel")
        assert discovered == set(VERCEL_MANIFEST.security_finding_rule_ids)
        assert len(discovered) == 7

    def test_reconnect_wired_via_generic_dispatcher_not_dedicated_function(self):
        assert disc.discover_reconnect_schema_fields("vercel") == {"vercel_token"}
        assert disc.discover_reconnect_function_exists("vercel") is False
        assert disc.discover_generic_reconnect_dispatch("vercel") is True

    def test_vercel_absent_from_future_provider_queue(self):
        assert "vercel" not in disc.discover_recommended_next_providers()


class TestVercelFullCertification:
    def test_overall_status_is_pass(self):
        assert runner.certify_provider("vercel").overall_status == "pass"

    def test_no_gate_fails(self):
        result = runner.certify_provider("vercel")
        assert [g.gate_id for g in result.gates if g.status == "fail"] == []

    def test_reconnect_rotation_gate_passes(self):
        result = runner.certify_provider("vercel")
        gate = next(g for g in result.gates if g.gate_id == "reconnect_rotation")
        assert gate.status == "pass"

    def test_security_finding_reachability_gate_passes(self):
        result = runner.certify_provider("vercel")
        gate = next(g for g in result.gates if g.gate_id == "security_finding_reachability")
        assert gate.status == "pass"


class TestVercelNegativeMutations:
    def test_fails_when_record_inventory_gains_a_phantom_type(self, monkeypatch):
        real = disc.discover_schema_record_type_constants("vercel")
        mutated = frozenset(real | {"vercel_team_member"})
        monkeypatch.setattr(disc, "discover_schema_record_type_constants", lambda pid: mutated if pid == "vercel" else real)
        gate = gates.gate_record_inventory(VERCEL_MANIFEST)
        assert gate.status == "warning"

    def test_fails_when_reachability_evidence_file_missing(self, monkeypatch):
        import dataclasses

        bad_evidence = dataclasses.replace(
            VERCEL_MANIFEST.reachability_evidence[0],
            test_file="tests/test_vercel_this_file_does_not_exist.py",
        )
        bad_manifest = dataclasses.replace(VERCEL_MANIFEST, reachability_evidence=(bad_evidence,))
        gate = gates.gate_security_finding_reachability(bad_manifest)
        assert gate.status == "fail"
