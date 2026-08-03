"""Sentry pilot certification tests (message 1 of N).

Proves the framework independently DISCOVERS and certifies Sentry's real
state — 18 record types, 20 Finding IDs, public/connectable/Live parity,
credential fields, masked secret form, reconnect dispatch, security
parity, completeness declaration, and absence from the future-provider
queue — rather than trusting the manifest's own declarations.
"""

from __future__ import annotations

from app.provider_certification import discovery as disc
from app.provider_certification import runner
from app.provider_certification.manifests.sentry import SENTRY_MANIFEST


class TestSentryManifestShape:
    def test_manifest_declares_18_record_types(self):
        assert len(SENTRY_MANIFEST.expected_record_types) == 18

    def test_manifest_declares_20_finding_ids(self):
        assert len(SENTRY_MANIFEST.security_finding_rule_ids) == 20

    def test_manifest_declares_two_credential_fields(self):
        assert set(SENTRY_MANIFEST.credential_fields) == {"sentry_organization_slug", "sentry_auth_token"}

    def test_manifest_marks_auth_token_sensitive(self):
        assert SENTRY_MANIFEST.sensitive_credential_fields == ("sentry_auth_token",)

    def test_manifest_declares_public_connectable_live(self):
        assert SENTRY_MANIFEST.expected_public
        assert SENTRY_MANIFEST.expected_connectable
        assert SENTRY_MANIFEST.expected_live

    def test_manifest_declares_reconnect_required(self):
        assert SENTRY_MANIFEST.expected_reconnect

    def test_manifest_declares_maturity_partial(self):
        assert SENTRY_MANIFEST.maturity == "partial"


class TestSentryDiscoveryIndependentlyConfirmsManifest:
    """These tests deliberately re-derive Sentry's real state from the
    repository — independently of the manifest — and only THEN compare
    to the manifest, proving the framework doesn't just trust
    declarations."""

    def test_discovered_record_types_match_manifest_exactly(self):
        discovered = disc.discover_schema_record_type_constants("sentry")
        assert discovered == set(SENTRY_MANIFEST.expected_record_types)
        assert len(discovered) == 18

    def test_discovered_finding_ids_match_manifest_exactly(self):
        discovered = disc.discover_registry_rule_ids("sentry")
        assert discovered == set(SENTRY_MANIFEST.security_finding_rule_ids)
        assert len(discovered) == 20

    def test_discovered_credential_fields_match_manifest(self):
        discovered = disc.discover_credential_schema_fields("sentry")
        assert discovered == set(SENTRY_MANIFEST.credential_fields)

    def test_discovered_reconnect_dispatch_matches_manifest_declaration(self):
        assert disc.discover_reconnect_function_exists("sentry") == SENTRY_MANIFEST.expected_reconnect

    def test_discovered_capability_matrix_maturity_matches_manifest(self):
        cap = disc.discover_capability_entry("sentry")
        assert cap.maturity == SENTRY_MANIFEST.maturity

    def test_discovered_frontend_form_masks_secret_field(self):
        if disc.frontend_root() is None:
            import pytest
            pytest.skip("frontend tree not mounted")
        assert disc.discover_frontend_form_uses_password_input(SENTRY_MANIFEST.expected_frontend_form)

    def test_sentry_absent_from_future_provider_queue(self):
        assert "sentry" not in disc.discover_recommended_next_providers()
        fe_queue = disc.discover_frontend_future_provider_queue()
        if fe_queue is not None:
            assert "Sentry" not in fe_queue


class TestSentryFullCertification:
    def test_overall_status_is_pass(self):
        result = runner.certify_provider("sentry")
        assert result.overall_status == "pass"

    def test_no_gate_is_unknown(self):
        result = runner.certify_provider("sentry")
        assert all(g.status != "unknown" for g in result.gates)

    def test_no_gate_fails(self):
        result = runner.certify_provider("sentry")
        failing = [g.gate_id for g in result.gates if g.status == "fail"]
        assert failing == []

    def test_security_finding_registry_parity_gate_passes(self):
        result = runner.certify_provider("sentry")
        gate = next(g for g in result.gates if g.gate_id == "security_finding_registry_parity")
        assert gate.status == "pass"

    def test_record_inventory_gate_passes(self):
        result = runner.certify_provider("sentry")
        gate = next(g for g in result.gates if g.gate_id == "record_inventory")
        assert gate.status == "pass"

    def test_completeness_model_gate_passes(self):
        result = runner.certify_provider("sentry")
        gate = next(g for g in result.gates if g.gate_id == "completeness_model")
        assert gate.status == "pass"

    def test_false_removal_protection_gate_passes(self):
        result = runner.certify_provider("sentry")
        gate = next(g for g in result.gates if g.gate_id == "false_removal_protection")
        assert gate.status == "pass"

    def test_provider_expansion_freeze_gate_passes(self):
        result = runner.certify_provider("sentry")
        gate = next(g for g in result.gates if g.gate_id == "provider_expansion_freeze")
        assert gate.status == "pass"

    def test_summary_counts_are_internally_consistent(self):
        result = runner.certify_provider("sentry")
        summary = result.summary
        assert sum(summary.values()) == len(result.gates)
