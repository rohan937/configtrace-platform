"""Cloudflare pilot certification tests (message 4 of N).

Proves the framework independently DISCOVERS and certifies Cloudflare's
real state — 8 record types (DNS excluded since its record_type is a
dynamic raw DNS RR type, not a fixed schema constant), 12 Finding IDs,
unprefixed credential fields (api_token, zone_id) resolved via a
dedicated discovery adapter, and classifier dispatch split across two
risk_rules modules (cloudflare.py + cloudflare_dns.py) resolved via the
same adapter.
"""

from __future__ import annotations

from app.provider_certification import adapters as adapt
from app.provider_certification import discovery as disc
from app.provider_certification import gates
from app.provider_certification import runner
from app.provider_certification.manifests.cloudflare import CLOUDFLARE_MANIFEST


class TestCloudflareManifestShape:
    def test_canonical_provider_id_is_cloudflare(self):
        assert CLOUDFLARE_MANIFEST.provider_id == "cloudflare"

    def test_manifest_declares_8_record_types(self):
        assert len(CLOUDFLARE_MANIFEST.expected_record_types) == 8

    def test_manifest_declares_12_finding_ids(self):
        assert len(CLOUDFLARE_MANIFEST.security_finding_rule_ids) == 12

    def test_manifest_declares_unprefixed_credential_fields(self):
        assert set(CLOUDFLARE_MANIFEST.credential_fields) == {"api_token", "zone_id"}

    def test_manifest_marks_api_token_sensitive_but_not_zone_id(self):
        assert CLOUDFLARE_MANIFEST.sensitive_credential_fields == ("api_token",)

    def test_manifest_declares_public_connectable_live(self):
        assert CLOUDFLARE_MANIFEST.expected_public
        assert CLOUDFLARE_MANIFEST.expected_connectable
        assert CLOUDFLARE_MANIFEST.expected_live

    def test_manifest_declares_reconnect_required(self):
        assert CLOUDFLARE_MANIFEST.expected_reconnect

    def test_manifest_declares_maturity_complete(self):
        assert CLOUDFLARE_MANIFEST.maturity == "complete"

    def test_manifest_honestly_declares_no_completeness_model(self):
        assert CLOUDFLARE_MANIFEST.completeness_scopes == ()
        assert CLOUDFLARE_MANIFEST.false_removal_scopes == ()

    def test_manifest_documents_dns_dynamic_record_type_limitation(self):
        assert any("dynamically-valued" in lim or "DNS" in lim for lim in CLOUDFLARE_MANIFEST.known_limitations)


class TestCloudflareAdapter:
    def test_adapter_is_registered(self):
        assert adapt.get_adapter("cloudflare") is not None

    def test_adapter_credential_fields_augment_empty_generic(self):
        generic = disc.discover_credential_schema_fields("cloudflare")
        assert generic == frozenset()
        adapter = adapt.get_adapter("cloudflare")
        resolved = adapt.resolve_set(generic, adapter.discover_credential_fields)
        assert resolved.value == frozenset({"api_token", "zone_id"})

    def test_adapter_classifier_adds_ruleset_route(self):
        direct = disc.discover_classifier_record_type_dispatch("cloudflare")
        assert "cloudflare_ruleset" not in direct
        adapter = adapt.get_adapter("cloudflare")
        resolved = adapter.discover_classifier_record_types()
        assert "cloudflare_ruleset" in resolved

    def test_gate_adapter_consistency_passes(self):
        gate = gates.gate_adapter_consistency(CLOUDFLARE_MANIFEST)
        assert gate.status in ("pass", "not_applicable")


class TestCloudflareDiscoveryIndependentlyConfirmsManifest:
    def test_discovered_record_types_match_manifest_exactly(self):
        discovered = disc.discover_schema_record_type_constants("cloudflare")
        assert discovered == set(CLOUDFLARE_MANIFEST.expected_record_types)
        assert len(discovered) == 8

    def test_dns_record_constant_is_declared_but_never_wired(self):
        identity = disc.discover_schema_record_type_identity_constants("cloudflare")
        wired = disc.discover_schema_record_type_constants("cloudflare")
        assert set(identity.values()) - wired == {"cloudflare_dns_record"}

    def test_dns_record_type_is_dynamic_not_the_unused_constant(self):
        text = disc.discover_connector_source_text("cloudflare")
        assert '"record_type": raw["type"]' in text
        assert '"record_type": CLOUDFLARE_DNS_RECORD' not in text

    def test_discovered_finding_ids_match_manifest_exactly(self):
        discovered = disc.discover_registry_rule_ids("cloudflare")
        assert discovered == set(CLOUDFLARE_MANIFEST.security_finding_rule_ids)
        assert len(discovered) == 12

    def test_capability_matrix_maturity_matches_manifest(self):
        cap = disc.discover_capability_entry("cloudflare")
        assert cap.maturity == CLOUDFLARE_MANIFEST.maturity

    def test_no_false_removal_suppression_function_exists(self):
        assert disc.discover_removal_suppression_exists("cloudflare") is False

    def test_cloudflare_absent_from_future_provider_queue(self):
        assert "cloudflare" not in disc.discover_recommended_next_providers()


class TestCloudflareFullCertification:
    def test_overall_status_is_pass(self):
        assert runner.certify_provider("cloudflare").overall_status == "pass"

    def test_no_gate_fails(self):
        result = runner.certify_provider("cloudflare")
        assert [g.gate_id for g in result.gates if g.status == "fail"] == []

    def test_record_inventory_gate_passes(self):
        result = runner.certify_provider("cloudflare")
        gate = next(g for g in result.gates if g.gate_id == "record_inventory")
        assert gate.status == "pass"

    def test_change_classifier_coverage_gate_passes(self):
        result = runner.certify_provider("cloudflare")
        gate = next(g for g in result.gates if g.gate_id == "change_classifier_coverage")
        assert gate.status == "pass"

    def test_credential_schema_gate_passes(self):
        result = runner.certify_provider("cloudflare")
        gate = next(g for g in result.gates if g.gate_id == "credential_schema")
        assert gate.status == "pass"

    def test_security_finding_reachability_gate_passes(self):
        result = runner.certify_provider("cloudflare")
        gate = next(g for g in result.gates if g.gate_id == "security_finding_reachability")
        assert gate.status == "pass"

    def test_finding_change_parity_gate_passes(self):
        result = runner.certify_provider("cloudflare")
        gate = next(g for g in result.gates if g.gate_id == "finding_change_parity")
        assert gate.status == "pass"

    def test_false_removal_protection_gate_is_warning_not_fail(self):
        result = runner.certify_provider("cloudflare")
        gate = next(g for g in result.gates if g.gate_id == "false_removal_protection")
        assert gate.status == "warning"


class TestCloudflareNegativeMutations:
    def test_fails_when_ruleset_classifier_route_removed(self, monkeypatch):
        import dataclasses

        real = adapt.get_adapter("cloudflare")
        mutated = dataclasses.replace(
            real, discover_classifier_record_types=lambda: disc.discover_classifier_record_type_dispatch("cloudflare") or None
        )
        monkeypatch.setitem(adapt._ADAPTERS, "cloudflare", mutated)
        gate = gates.gate_change_classifier_coverage(CLOUDFLARE_MANIFEST)
        assert gate.status in ("warning", "fail")

    def test_fails_when_credential_adapter_removed(self, monkeypatch):
        import dataclasses

        real = adapt.get_adapter("cloudflare")
        mutated = dataclasses.replace(real, discover_credential_fields=lambda: None)
        monkeypatch.setitem(adapt._ADAPTERS, "cloudflare", mutated)
        gate = gates.gate_credential_schema(CLOUDFLARE_MANIFEST)
        assert gate.status == "fail"

    def test_fails_when_reachability_evidence_file_missing(self, monkeypatch):
        import dataclasses

        bad_evidence = dataclasses.replace(
            CLOUDFLARE_MANIFEST.reachability_evidence[0],
            test_file="tests/test_cloudflare_this_file_does_not_exist.py",
        )
        bad_manifest = dataclasses.replace(CLOUDFLARE_MANIFEST, reachability_evidence=(bad_evidence,))
        gate = gates.gate_security_finding_reachability(bad_manifest)
        assert gate.status == "fail"
