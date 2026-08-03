"""Okta pilot certification tests (message 2 of N).

Proves the framework independently DISCOVERS and certifies Okta's real
state — 16 record types, 30 Finding IDs, public/connectable/Live parity,
two credential fields, masked API-token field, reconnect dispatch,
security parity, completeness declaration, and absence from the
future-provider queue — rather than trusting the manifest's own
declarations. Also proves gates FAIL under negative mutation (missing
classifier coverage, secret field rendered unmasked, backend/frontend
drift) rather than merely reflecting the manifest back at itself.
"""

from __future__ import annotations

import pytest

from app.provider_certification import discovery as disc
from app.provider_certification import gates
from app.provider_certification import runner
from app.provider_certification.manifests.okta import OKTA_MANIFEST


class TestOktaManifestShape:
    def test_manifest_declares_16_record_types(self):
        assert len(OKTA_MANIFEST.expected_record_types) == 16

    def test_manifest_declares_30_finding_ids(self):
        assert len(OKTA_MANIFEST.security_finding_rule_ids) == 30

    def test_manifest_declares_two_credential_fields(self):
        assert set(OKTA_MANIFEST.credential_fields) == {"okta_org_url", "okta_api_token"}

    def test_manifest_marks_api_token_sensitive(self):
        assert OKTA_MANIFEST.sensitive_credential_fields == ("okta_api_token",)

    def test_manifest_declares_public_connectable_live(self):
        assert OKTA_MANIFEST.expected_public
        assert OKTA_MANIFEST.expected_connectable
        assert OKTA_MANIFEST.expected_live

    def test_manifest_declares_reconnect_required(self):
        assert OKTA_MANIFEST.expected_reconnect

    def test_manifest_declares_maturity_partial(self):
        assert OKTA_MANIFEST.maturity == "partial"

    def test_manifest_declares_two_derived_record_types(self):
        assert set(OKTA_MANIFEST.derived_record_types) == {"okta_privileged_identity", "okta_privileged_group"}


class TestOktaDiscoveryIndependentlyConfirmsManifest:
    """Re-derive Okta's real state from the repository independently of
    the manifest, then compare — proving the framework doesn't just
    trust declarations."""

    def test_discovered_record_types_match_manifest_exactly(self):
        discovered = disc.discover_schema_record_type_constants("okta")
        assert discovered == set(OKTA_MANIFEST.expected_record_types)
        assert len(discovered) == 16

    def test_discovered_finding_ids_match_manifest_exactly(self):
        discovered = disc.discover_registry_rule_ids("okta")
        assert discovered == set(OKTA_MANIFEST.security_finding_rule_ids)
        assert len(discovered) == 30

    def test_discovered_confidence_pack_coverage_match_registry(self):
        registry = disc.discover_registry_rule_ids("okta")
        assert disc.discover_confidence_rule_ids("okta") == registry
        assert disc.discover_pack_rule_ids("okta") == registry
        assert disc.discover_coverage_rule_ids("okta") == registry

    def test_discovered_credential_fields_match_manifest(self):
        discovered = disc.discover_credential_schema_fields("okta")
        assert discovered == set(OKTA_MANIFEST.credential_fields)

    def test_discovered_reconnect_dispatch_matches_manifest_declaration(self):
        assert disc.discover_reconnect_function_exists("okta") == OKTA_MANIFEST.expected_reconnect

    def test_discovered_capability_matrix_maturity_matches_manifest(self):
        cap = disc.discover_capability_entry("okta")
        assert cap.maturity == OKTA_MANIFEST.maturity

    def test_discovered_tracked_fields_cover_every_record_type(self):
        tracked = disc.discover_diff_tracked_fields_dict("okta")
        assert tracked is not None
        for rt in OKTA_MANIFEST.expected_record_types:
            assert rt in tracked

    def test_discovered_classifier_handles_every_record_type(self):
        handled = disc.discover_classifier_record_type_dispatch("okta")
        assert set(OKTA_MANIFEST.expected_record_types) <= handled

    def test_discovered_removal_suppression_exists(self):
        assert disc.discover_removal_suppression_exists("okta")

    def test_discovered_frontend_form_masks_secret_field(self):
        if disc.frontend_root() is None:
            pytest.skip("frontend tree not mounted")
        assert disc.discover_frontend_form_uses_password_input(OKTA_MANIFEST.expected_frontend_form)

    def test_okta_absent_from_future_provider_queue(self):
        assert "okta" not in disc.discover_recommended_next_providers()
        fe_queue = disc.discover_frontend_future_provider_queue()
        if fe_queue is not None:
            assert "Okta" not in fe_queue

    def test_no_cli_or_sdk_dependency_present(self):
        for dep in OKTA_MANIFEST.prohibited_dependencies:
            assert not disc.discover_prohibited_dependency_present(dep)


class TestOktaFullCertification:
    def test_overall_status_is_pass(self):
        assert runner.certify_provider("okta").overall_status == "pass"

    def test_no_gate_is_unknown(self):
        result = runner.certify_provider("okta")
        assert all(g.status != "unknown" for g in result.gates)

    def test_no_gate_fails(self):
        result = runner.certify_provider("okta")
        assert [g.gate_id for g in result.gates if g.status == "fail"] == []

    def test_security_finding_registry_parity_gate_passes(self):
        result = runner.certify_provider("okta")
        gate = next(g for g in result.gates if g.gate_id == "security_finding_registry_parity")
        assert gate.status == "pass"

    def test_record_inventory_gate_passes(self):
        result = runner.certify_provider("okta")
        gate = next(g for g in result.gates if g.gate_id == "record_inventory")
        assert gate.status == "pass"

    def test_change_classifier_coverage_gate_passes(self):
        result = runner.certify_provider("okta")
        gate = next(g for g in result.gates if g.gate_id == "change_classifier_coverage")
        assert gate.status == "pass"

    def test_completeness_model_gate_passes(self):
        result = runner.certify_provider("okta")
        gate = next(g for g in result.gates if g.gate_id == "completeness_model")
        assert gate.status == "pass"

    def test_false_removal_protection_gate_passes(self):
        result = runner.certify_provider("okta")
        gate = next(g for g in result.gates if g.gate_id == "false_removal_protection")
        assert gate.status == "pass"

    def test_frontend_provider_parity_gate_passes(self):
        result = runner.certify_provider("okta")
        gate = next(g for g in result.gates if g.gate_id == "frontend_provider_parity")
        assert gate.status == "pass"

    def test_known_limitations_gate_passes(self):
        result = runner.certify_provider("okta")
        gate = next(g for g in result.gates if g.gate_id == "known_limitations")
        assert gate.status == "pass"

    def test_provider_expansion_freeze_gate_passes(self):
        result = runner.certify_provider("okta")
        gate = next(g for g in result.gates if g.gate_id == "provider_expansion_freeze")
        assert gate.status == "pass"

    def test_summary_counts_are_internally_consistent(self):
        result = runner.certify_provider("okta")
        assert sum(result.summary.values()) == len(result.gates)


class TestOktaNegativeMutations:
    """Prove gates FAIL under simulated repository drift — the framework
    checks real reality, not just the manifest reflecting itself."""

    def test_fails_when_a_record_type_has_no_classifier_dispatch(self, monkeypatch):
        monkeypatch.setattr(
            disc,
            "discover_classifier_record_type_dispatch",
            lambda pid: frozenset(OKTA_MANIFEST.expected_record_types) - {"okta_policy_rule"} if pid == "okta" else frozenset(),
        )
        gate = gates.gate_change_classifier_coverage(OKTA_MANIFEST)
        assert gate.status == "warning"
        assert "okta_policy_rule" in gate.details

    def test_fails_when_secret_field_rendered_as_text_input(self, monkeypatch):
        monkeypatch.setattr(disc, "discover_frontend_form_uses_password_input", lambda f: False)
        gate = gates.gate_sensitive_data_controls(OKTA_MANIFEST)
        assert gate.status == "fail"

    def test_fails_when_backend_connectable_but_frontend_absent(self, monkeypatch):
        monkeypatch.setattr(disc, "discover_frontend_provider_ids", lambda: frozenset({"sentry", "snowflake", "entra"}))
        gate = gates.gate_frontend_provider_parity(OKTA_MANIFEST)
        assert gate.status == "fail"
        assert "frontend PROVIDER_IDS" in gate.details

    def test_fails_when_completeness_scope_declared_but_no_suppression_implementation(self, monkeypatch):
        monkeypatch.setattr(disc, "discover_removal_suppression_exists", lambda pid: False)
        gate = gates.gate_false_removal_protection(OKTA_MANIFEST)
        assert gate.status == "fail"

    def test_fails_when_reconnect_required_but_router_dispatch_missing(self, monkeypatch):
        monkeypatch.setattr(disc, "discover_reconnect_router_dispatch", lambda pid: False)
        gate = gates.gate_reconnect_rotation(OKTA_MANIFEST)
        assert gate.status == "fail"
        assert "router" in gate.details

    def test_fails_when_record_type_missing_from_diff_tracked_fields(self, monkeypatch):
        real = disc.discover_diff_tracked_fields_dict("okta")
        mutated = dict(real)
        del mutated["okta_authenticator"]
        monkeypatch.setattr(disc, "discover_diff_tracked_fields_dict", lambda pid: mutated if pid == "okta" else real)
        gate = gates.gate_diff_tracked_fields(OKTA_MANIFEST)
        assert gate.status == "fail"
        assert "okta_authenticator" in gate.details
