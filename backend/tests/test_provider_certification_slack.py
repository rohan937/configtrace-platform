"""Slack pilot certification tests (message 5 of N).

Slack is architecturally NOT a data-sync provider in this repository —
it has no SlackConnector, no schema/risk-rules modules, and no
capability-matrix entry. This file proves the framework certifies its
'planned' manifest honestly (zero records/capabilities/Findings) and
that it is correctly exempted from catalog-consistency checks that
apply to every other, genuinely-launched provider.
"""

from __future__ import annotations

from app.provider_certification import cross_manifest
from app.provider_certification import discovery as disc
from app.provider_certification import gates
from app.provider_certification import runner
from app.provider_certification.manifests.slack import SLACK_MANIFEST


class TestSlackManifestShape:
    def test_canonical_provider_id_is_slack(self):
        assert SLACK_MANIFEST.provider_id == "slack"

    def test_manifest_declares_maturity_planned(self):
        assert SLACK_MANIFEST.maturity == "planned"

    def test_manifest_declares_zero_record_types(self):
        assert SLACK_MANIFEST.expected_record_types == ()

    def test_manifest_declares_zero_finding_ids(self):
        assert SLACK_MANIFEST.security_finding_rule_ids == ()

    def test_manifest_declares_zero_capabilities(self):
        assert SLACK_MANIFEST.supported_capabilities == ()
        assert SLACK_MANIFEST.unsupported_capabilities == ()

    def test_manifest_declares_not_public_not_connectable_not_live(self):
        assert SLACK_MANIFEST.expected_public is False
        assert SLACK_MANIFEST.expected_connectable is False
        assert SLACK_MANIFEST.expected_live is False

    def test_manifest_declares_no_frontend_form(self):
        assert SLACK_MANIFEST.expected_frontend_form is None

    def test_manifest_documents_architectural_mismatch(self):
        text = " ".join(SLACK_MANIFEST.known_limitations)
        assert "SlackConnector" in text
        assert "OUTBOUND OAuth-based alert-routing" in text


class TestSlackDiscoveryConfirmsNoSyncSurface:
    def test_slack_absent_from_backend_sync_provider_ids(self):
        assert "slack" not in disc.discover_backend_sync_provider_ids()

    def test_slack_absent_from_capability_matrix(self):
        in_complete, in_partial = disc.discover_capability_matrix_membership("slack")
        assert in_complete is False
        assert in_partial is False

    def test_slack_absent_from_launched_provider_ids(self):
        assert "slack" not in disc.discover_launched_provider_ids()

    def test_slack_absent_from_future_provider_queue(self):
        assert "slack" not in disc.discover_recommended_next_providers()


class TestSlackFullCertification:
    def test_overall_status_is_pass(self):
        assert runner.certify_provider("slack").overall_status == "pass"

    def test_no_gate_fails(self):
        result = runner.certify_provider("slack")
        assert [g.gate_id for g in result.gates if g.status == "fail"] == []

    def test_cross_manifest_catalog_consistency_skips_planned_manifest(self):
        runner._ensure_manifests_loaded()
        all_manifests = tuple(runner.get_manifest(pid) for pid in runner.known_provider_ids())
        gate = cross_manifest.gate_cross_manifest_catalog_consistency(all_manifests)
        assert gate.status in ("pass", "not_applicable")


class TestSlackNegativeMutationsWouldExposeFabrication:
    def test_capability_evidence_not_applicable_with_no_declarations(self):
        gate = gates.gate_capability_evidence(SLACK_MANIFEST)
        assert gate.status == "not_applicable"
