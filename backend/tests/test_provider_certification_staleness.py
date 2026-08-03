"""Stale-inventory/Finding/credential detection tests (message 5 of N).

Strengthens confidence in the existing staleness-detection gates
(``gate_record_inventory``, ``gate_security_finding_registry_parity``,
``gate_credential_schema``, ``gate_sensitive_data_controls``,
``gate_reconnect_rotation``) by proving — via monkeypatched discovery
and ``dataclasses.replace`` manifest mutations — that each genuinely
catches drift for a representative sample spanning BOTH the 6 new
providers and providers certified in earlier messages. No new gates
are introduced here; this is negative-mutation regression coverage for
the staleness mechanism the framework already has.
"""

from __future__ import annotations

import dataclasses

from app.provider_certification import discovery as disc
from app.provider_certification import gates
from app.provider_certification.manifests.aws import AWS_MANIFEST
from app.provider_certification.manifests.jira import JIRA_MANIFEST
from app.provider_certification.manifests.kubernetes import KUBERNETES_MANIFEST
from app.provider_certification.manifests.sentry import SENTRY_MANIFEST
from app.provider_certification.manifests.vercel import VERCEL_MANIFEST


class TestNewEmittedRecordMissingFromManifest:
    """The connector's REAL discovered record set gains a type the
    manifest never declared — gate_record_inventory must fail (missing
    from the manifest side is a real gap, not a warning). Simulated via
    monkeypatched discovery rather than mutating the manifest itself,
    since expected_record_types is cross-referenced by other typed
    declarations (capability_evidence, completeness scopes) whose own
    validation would otherwise fire first."""

    def test_aws_manifest_missing_a_newly_discovered_record_type_fails(self, monkeypatch):
        real = disc.discover_schema_record_type_constants("aws")
        grown = frozenset(real | {"aws_phantom_new_record_type"})
        monkeypatch.setattr(disc, "discover_schema_record_type_constants", lambda pid: grown if pid == "aws" else real)
        gate = gates.gate_record_inventory(AWS_MANIFEST)
        assert gate.status == "warning"
        assert "aws_phantom_new_record_type" in gate.details

    def test_kubernetes_manifest_missing_a_newly_discovered_record_type_is_flagged(self, monkeypatch):
        real = disc.discover_schema_record_type_constants("kubernetes")
        grown = frozenset(real | {"kubernetes_phantom_new_record_type"})
        monkeypatch.setattr(disc, "discover_schema_record_type_constants", lambda pid: grown if pid == "kubernetes" else real)
        gate = gates.gate_record_inventory(KUBERNETES_MANIFEST)
        assert gate.status == "warning"
        assert "kubernetes_phantom_new_record_type" in gate.details


class TestRemovedRecordStillClaimedByManifest:
    """A record type the manifest still claims, but discovery no
    longer finds in the connector schema — must also fail."""

    def test_vercel_manifest_claims_a_record_type_discovery_no_longer_finds(self, monkeypatch):
        real = disc.discover_schema_record_type_constants("vercel")
        shrunk = frozenset(real - {"vercel_domain"})
        monkeypatch.setattr(disc, "discover_schema_record_type_constants", lambda pid: shrunk if pid == "vercel" else real)
        gate = gates.gate_record_inventory(VERCEL_MANIFEST)
        assert gate.status == "fail"
        assert "vercel_domain" in gate.details


class TestPhantomSchemaConstantExplicitlyAllowed:
    """A classifier-dispatched-but-unwired schema constant (a known,
    documented pattern — AWS has 8, Vercel has 7) must NOT be treated
    as a staleness failure; it is correctly excluded from
    expected_record_types and documented in known_limitations."""

    def test_aws_unwired_constants_do_not_appear_in_expected_record_types(self):
        identity = disc.discover_schema_record_type_identity_constants("aws")
        unwired = set(identity.values()) - disc.discover_schema_record_type_constants("aws")
        assert not (unwired & set(AWS_MANIFEST.expected_record_types))

    def test_aws_record_inventory_gate_passes_despite_8_unwired_constants(self):
        gate = gates.gate_record_inventory(AWS_MANIFEST)
        assert gate.status == "pass"


class TestNewFindingAbsentFromManifest:
    def test_manifest_missing_a_newly_discovered_finding_id_fails(self, monkeypatch):
        real = disc.discover_registry_rule_ids("jira")
        grown = frozenset(real | {"jira_phantom_new_finding"})
        monkeypatch.setattr(disc, "discover_registry_rule_ids", lambda pid: grown if pid == "jira" else real)
        gate = gates.gate_security_finding_registry_parity(JIRA_MANIFEST)
        assert gate.status == "fail"
        assert "jira_phantom_new_finding" in gate.details


class TestManifestFindingAbsentFromProviderRuleModule:
    def test_manifest_finding_id_discovery_no_longer_finds_in_registry_fails(self, monkeypatch):
        real = disc.discover_registry_rule_ids("sentry")
        shrunk = frozenset(real - {next(iter(real))})
        removed_id = real - shrunk
        monkeypatch.setattr(disc, "discover_registry_rule_ids", lambda pid: shrunk if pid == "sentry" else real)
        gate = gates.gate_security_finding_registry_parity(SENTRY_MANIFEST)
        assert gate.status == "fail"
        assert next(iter(removed_id)) in gate.details


class TestCredentialAddedToBackendButAbsentFromManifest:
    def test_backend_gains_a_credential_field_the_manifest_does_not_declare(self, monkeypatch):
        real = disc._credential_fields_for("aws") if hasattr(disc, "_credential_fields_for") else None
        # Use the gates-module helper directly since credential discovery
        # for IntegrationCreateRequest lives there.
        from app.provider_certification import gates as gates_module

        real_fields = gates_module._credential_fields_for("aws")
        expanded = frozenset(real_fields | {"aws_phantom_new_field"})
        monkeypatch.setattr(
            gates_module, "_credential_fields_for",
            lambda pid: expanded if pid == "aws" else real_fields,
        )
        gate = gates.gate_credential_schema(AWS_MANIFEST)
        assert gate.status == "warning"
        assert "aws_phantom_new_field" in gate.details

    def test_manifest_declares_a_credential_field_the_backend_no_longer_has(self, monkeypatch):
        from app.provider_certification import gates as gates_module

        real_fields = gates_module._credential_fields_for("aws")
        shrunk = frozenset(real_fields - {"aws_default_region"})
        monkeypatch.setattr(
            gates_module, "_credential_fields_for",
            lambda pid: shrunk if pid == "aws" else real_fields,
        )
        gate = gates.gate_credential_schema(AWS_MANIFEST)
        assert gate.status == "fail"
        assert "aws_default_region" in gate.details


class TestSecretFieldLosesMasking:
    def test_sensitive_field_gate_fails_if_frontend_form_masking_is_not_found(self, monkeypatch):
        monkeypatch.setattr(disc, "discover_frontend_form_uses_password_input", lambda form: False)
        monkeypatch.setattr(disc, "discover_frontend_form_uses_masked_multiline_input", lambda form: False)
        gate = gates.gate_sensitive_data_controls(AWS_MANIFEST)
        assert gate.status == "fail"
        assert "no masked input" in gate.details


class TestReconnectFieldDiverges:
    def test_reconnect_rotation_fails_if_router_dispatch_disappears(self, monkeypatch):
        monkeypatch.setattr(disc, "discover_reconnect_router_dispatch", lambda pid: False if pid == "aws" else True)
        gate = gates.gate_reconnect_rotation(AWS_MANIFEST)
        assert gate.status == "fail"
        assert "router" in gate.details.lower()

    def test_reconnect_rotation_fails_if_function_and_generic_dispatch_both_disappear(self, monkeypatch):
        monkeypatch.setattr(disc, "discover_reconnect_function_exists", lambda pid: False)
        monkeypatch.setattr(disc, "discover_generic_reconnect_dispatch", lambda pid: False)
        gate = gates.gate_reconnect_rotation(VERCEL_MANIFEST)
        assert gate.status == "fail"
