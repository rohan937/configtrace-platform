"""Stripe pilot certification tests (message 4 of N).

Proves the framework independently DISCOVERS and certifies Stripe's
real state — 6 real record types (correctly excluding 11 schema-declared
but never-wired-into-the-connector constants), 8 Finding IDs, reconnect
via the shared generic dispatcher (not a named function) — the same
"original-era" pattern as GitHub/Cloudflare.
"""

from __future__ import annotations

from app.provider_certification import adapters as adapt
from app.provider_certification import discovery as disc
from app.provider_certification import gates
from app.provider_certification import runner
from app.provider_certification.manifests.stripe import STRIPE_MANIFEST


class TestStripeManifestShape:
    def test_canonical_provider_id_is_stripe(self):
        assert STRIPE_MANIFEST.provider_id == "stripe"

    def test_manifest_declares_6_record_types(self):
        assert len(STRIPE_MANIFEST.expected_record_types) == 6

    def test_manifest_declares_8_finding_ids(self):
        assert len(STRIPE_MANIFEST.security_finding_rule_ids) == 8

    def test_manifest_declares_api_key_credential(self):
        assert STRIPE_MANIFEST.credential_fields == ("stripe_api_key",)

    def test_manifest_marks_api_key_sensitive(self):
        assert STRIPE_MANIFEST.sensitive_credential_fields == ("stripe_api_key",)

    def test_manifest_declares_public_connectable_live(self):
        assert STRIPE_MANIFEST.expected_public
        assert STRIPE_MANIFEST.expected_connectable
        assert STRIPE_MANIFEST.expected_live

    def test_manifest_declares_reconnect_required(self):
        assert STRIPE_MANIFEST.expected_reconnect

    def test_manifest_honestly_declares_no_completeness_model(self):
        assert STRIPE_MANIFEST.completeness_scopes == ()
        assert STRIPE_MANIFEST.false_removal_scopes == ()

    def test_manifest_documents_no_payment_transaction_ingestion(self):
        assert any("payment transaction" in lim for lim in STRIPE_MANIFEST.known_limitations)

    def test_manifest_documents_no_webhook_payload_ingestion(self):
        assert any("PAYLOAD ingestion" in lim for lim in STRIPE_MANIFEST.known_limitations)

    def test_manifest_documents_the_11_unwired_schema_constants(self):
        assert any("11 of the 17" in lim for lim in STRIPE_MANIFEST.known_limitations)


class TestStripeNoAdapterNeeded:
    def test_no_adapter_registered(self):
        assert adapt.get_adapter("stripe") is None


class TestStripeDiscoveryIndependentlyConfirmsManifest:
    def test_discovered_record_types_match_manifest_exactly(self):
        discovered = disc.discover_schema_record_type_constants("stripe")
        assert discovered == set(STRIPE_MANIFEST.expected_record_types)
        assert len(discovered) == 6

    def test_11_unwired_schema_constants_correctly_excluded(self):
        identity = disc.discover_schema_record_type_identity_constants("stripe")
        discovered = disc.discover_schema_record_type_constants("stripe")
        unwired = set(identity.values()) - discovered
        assert len(unwired) == 11
        assert "stripe_price" in unwired
        assert "stripe_product" in unwired

    def test_classifier_module_has_dispatch_for_unwired_types_but_manifest_excludes_them(self):
        # The classifier module is aspirational for all 17 — the manifest
        # correctly restricts expected_record_types to what the connector
        # itself actually wires, not what the classifier merely handles.
        classifier_dispatch = disc.discover_classifier_record_type_dispatch("stripe")
        assert "stripe_price" in classifier_dispatch
        assert "stripe_price" not in STRIPE_MANIFEST.expected_record_types

    def test_discovered_finding_ids_match_manifest_exactly(self):
        discovered = disc.discover_registry_rule_ids("stripe")
        assert discovered == set(STRIPE_MANIFEST.security_finding_rule_ids)
        assert len(discovered) == 8

    def test_reconnect_wired_via_generic_dispatcher_not_named_function(self):
        assert disc.discover_reconnect_function_exists("stripe") is False
        assert disc.discover_generic_reconnect_dispatch("stripe") is True

    def test_no_false_removal_suppression_function_exists(self):
        assert disc.discover_removal_suppression_exists("stripe") is False

    def test_stripe_absent_from_future_provider_queue(self):
        assert "stripe" not in disc.discover_recommended_next_providers()


class TestStripeFullCertification:
    def test_overall_status_is_pass(self):
        assert runner.certify_provider("stripe").overall_status == "pass"

    def test_no_gate_fails(self):
        result = runner.certify_provider("stripe")
        assert [g.gate_id for g in result.gates if g.status == "fail"] == []

    def test_reconnect_rotation_gate_passes(self):
        result = runner.certify_provider("stripe")
        gate = next(g for g in result.gates if g.gate_id == "reconnect_rotation")
        assert gate.status == "pass"

    def test_security_finding_reachability_gate_passes(self):
        result = runner.certify_provider("stripe")
        gate = next(g for g in result.gates if g.gate_id == "security_finding_reachability")
        assert gate.status == "pass"

    def test_finding_change_parity_gate_passes(self):
        result = runner.certify_provider("stripe")
        gate = next(g for g in result.gates if g.gate_id == "finding_change_parity")
        assert gate.status == "pass"


class TestStripeNegativeMutations:
    def test_fails_when_reconnect_dispatcher_branch_removed(self, monkeypatch):
        monkeypatch.setattr(disc, "discover_generic_reconnect_dispatch", lambda pid: False)
        monkeypatch.setattr(disc, "discover_reconnect_function_exists", lambda pid: False)
        gate = gates.gate_reconnect_rotation(STRIPE_MANIFEST)
        assert gate.status == "fail"

    def test_fails_when_record_inventory_gains_an_unexpected_type(self, monkeypatch):
        real = disc.discover_schema_record_type_constants("stripe")
        mutated = frozenset(real | {"stripe_price"})
        monkeypatch.setattr(disc, "discover_schema_record_type_constants", lambda pid: mutated if pid == "stripe" else real)
        gate = gates.gate_record_inventory(STRIPE_MANIFEST)
        assert gate.status == "warning"
