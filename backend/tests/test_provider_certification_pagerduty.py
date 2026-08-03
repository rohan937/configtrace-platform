"""PagerDuty pilot certification tests (message 5 of N).

Proves the framework independently DISCOVERS and certifies PagerDuty's
real state — 8 record types, 40 Finding IDs — with generic discovery
alone (no adapter needed). Registered in PROVIDER_CAPABILITIES_PARTIAL.
"""

from __future__ import annotations

from app.provider_certification import adapters as adapt
from app.provider_certification import discovery as disc
from app.provider_certification import gates
from app.provider_certification import runner
from app.provider_certification.manifests.pagerduty import PAGERDUTY_MANIFEST


class TestPagerDutyManifestShape:
    def test_canonical_provider_id_is_pagerduty(self):
        assert PAGERDUTY_MANIFEST.provider_id == "pagerduty"

    def test_manifest_declares_8_record_types(self):
        assert len(PAGERDUTY_MANIFEST.expected_record_types) == 8

    def test_manifest_declares_40_finding_ids(self):
        assert len(PAGERDUTY_MANIFEST.security_finding_rule_ids) == 40

    def test_manifest_declares_maturity_partial(self):
        assert PAGERDUTY_MANIFEST.maturity == "partial"

    def test_manifest_declares_reconnect_not_required(self):
        assert PAGERDUTY_MANIFEST.expected_reconnect is False
        assert PAGERDUTY_MANIFEST.expected_live is False

    def test_manifest_marks_token_sensitive(self):
        assert set(PAGERDUTY_MANIFEST.sensitive_credential_fields) == {"pagerduty_api_token"}

    def test_manifest_documents_no_incident_event_ingestion(self):
        text = " ".join(PAGERDUTY_MANIFEST.known_limitations)
        assert "incident-event ingestion" in text
        assert "responder communications" in text


class TestPagerDutyNoAdapterNeeded:
    def test_no_adapter_registered(self):
        assert adapt.get_adapter("pagerduty") is None


class TestPagerDutyDiscoveryIndependentlyConfirmsManifest:
    def test_discovered_record_types_match_manifest_exactly(self):
        discovered = disc.discover_schema_record_type_constants("pagerduty")
        assert discovered == set(PAGERDUTY_MANIFEST.expected_record_types)
        assert len(discovered) == 8

    def test_discovered_finding_ids_match_manifest_exactly(self):
        discovered = disc.discover_registry_rule_ids("pagerduty")
        assert discovered == set(PAGERDUTY_MANIFEST.security_finding_rule_ids)
        assert len(discovered) == 40

    def test_capability_matrix_membership_is_partial_list(self):
        in_complete, in_partial = disc.discover_capability_matrix_membership("pagerduty")
        assert in_complete is False
        assert in_partial is True

    def test_no_false_removal_suppression_function_exists(self):
        assert disc.discover_removal_suppression_exists("pagerduty") is False

    def test_pagerduty_absent_from_future_provider_queue(self):
        assert "pagerduty" not in disc.discover_recommended_next_providers()


class TestPagerDutyFullCertification:
    def test_overall_status_is_pass(self):
        assert runner.certify_provider("pagerduty").overall_status == "pass"

    def test_no_gate_fails(self):
        result = runner.certify_provider("pagerduty")
        assert [g.gate_id for g in result.gates if g.status == "fail"] == []

    def test_security_finding_reachability_gate_passes(self):
        result = runner.certify_provider("pagerduty")
        gate = next(g for g in result.gates if g.gate_id == "security_finding_reachability")
        assert gate.status == "pass"

    def test_finding_change_parity_gate_passes(self):
        result = runner.certify_provider("pagerduty")
        gate = next(g for g in result.gates if g.gate_id == "finding_change_parity")
        assert gate.status == "pass"


class TestPagerDutyNegativeMutations:
    def test_fails_when_reachability_evidence_file_missing(self):
        import dataclasses

        bad_evidence = dataclasses.replace(
            PAGERDUTY_MANIFEST.reachability_evidence[0],
            test_file="tests/test_pagerduty_this_file_does_not_exist.py",
        )
        bad_manifest = dataclasses.replace(PAGERDUTY_MANIFEST, reachability_evidence=(bad_evidence,))
        gate = gates.gate_security_finding_reachability(bad_manifest)
        assert gate.status == "fail"

    def test_fails_when_finding_ids_discovery_drops_one(self, monkeypatch):
        real = disc.discover_registry_rule_ids("pagerduty")
        mutated = frozenset(real - {"pagerduty_service_no_escalation_policy"})
        monkeypatch.setattr(disc, "discover_registry_rule_ids", lambda pid: mutated if pid == "pagerduty" else real)
        gate = gates.gate_security_finding_registry_parity(PAGERDUTY_MANIFEST)
        assert gate.status == "fail"
