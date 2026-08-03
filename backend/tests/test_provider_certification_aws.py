"""AWS pilot certification tests (message 5 of N).

Proves the framework independently DISCOVERS and certifies AWS's real
state — 87 record types (8 schema-declared-but-unwired constants
correctly excluded), 9 Finding IDs — with generic discovery alone (no
adapter needed).
"""

from __future__ import annotations

from app.provider_certification import adapters as adapt
from app.provider_certification import discovery as disc
from app.provider_certification import gates
from app.provider_certification import runner
from app.provider_certification.manifests.aws import AWS_MANIFEST


class TestAWSManifestShape:
    def test_canonical_provider_id_is_aws(self):
        assert AWS_MANIFEST.provider_id == "aws"

    def test_manifest_declares_87_record_types(self):
        assert len(AWS_MANIFEST.expected_record_types) == 87

    def test_manifest_declares_9_finding_ids(self):
        assert len(AWS_MANIFEST.security_finding_rule_ids) == 9

    def test_manifest_declares_full_credential_set(self):
        assert set(AWS_MANIFEST.credential_fields) == {
            "aws_access_key_id", "aws_secret_access_key", "aws_default_region", "aws_selected_regions",
        }

    def test_manifest_marks_both_key_fields_sensitive(self):
        assert set(AWS_MANIFEST.sensitive_credential_fields) == {"aws_access_key_id", "aws_secret_access_key"}

    def test_manifest_declares_public_connectable_live(self):
        assert AWS_MANIFEST.expected_public
        assert AWS_MANIFEST.expected_connectable
        assert AWS_MANIFEST.expected_live

    def test_manifest_declares_reconnect_required(self):
        assert AWS_MANIFEST.expected_reconnect

    def test_manifest_declares_maturity_complete(self):
        assert AWS_MANIFEST.maturity == "complete"

    def test_manifest_declares_one_capability_evidence(self):
        assert len(AWS_MANIFEST.capability_evidence) == 1
        assert AWS_MANIFEST.capability_evidence[0].capability == "security_findings"

    def test_manifest_documents_no_cloudtrail_event_ingestion(self):
        assert any("CloudTrail EVENT" in lim for lim in AWS_MANIFEST.known_limitations)

    def test_manifest_documents_8_unwired_schema_constants(self):
        assert any("8 schema-declared" in lim for lim in AWS_MANIFEST.known_limitations)


class TestAWSNoAdapterNeeded:
    def test_no_adapter_registered(self):
        assert adapt.get_adapter("aws") is None


class TestAWSDiscoveryIndependentlyConfirmsManifest:
    def test_discovered_record_types_match_manifest_exactly(self):
        discovered = disc.discover_schema_record_type_constants("aws")
        assert discovered == set(AWS_MANIFEST.expected_record_types)
        assert len(discovered) == 87

    def test_8_unwired_schema_constants_correctly_excluded(self):
        identity = disc.discover_schema_record_type_identity_constants("aws")
        discovered = disc.discover_schema_record_type_constants("aws")
        unwired = set(identity.values()) - discovered
        assert len(unwired) == 8
        assert "aws_ec2_instance" in unwired

    def test_discovered_finding_ids_match_manifest_exactly(self):
        discovered = disc.discover_registry_rule_ids("aws")
        assert discovered == set(AWS_MANIFEST.security_finding_rule_ids)
        assert len(discovered) == 9

    def test_reconnect_wired_via_named_function(self):
        assert disc.discover_reconnect_function_exists("aws") is True

    def test_no_false_removal_suppression_function_exists(self):
        assert disc.discover_removal_suppression_exists("aws") is False

    def test_aws_absent_from_future_provider_queue(self):
        assert "aws" not in disc.discover_recommended_next_providers()


class TestAWSFullCertification:
    def test_overall_status_is_pass(self):
        assert runner.certify_provider("aws").overall_status == "pass"

    def test_no_gate_fails(self):
        result = runner.certify_provider("aws")
        assert [g.gate_id for g in result.gates if g.status == "fail"] == []

    def test_security_finding_reachability_gate_passes(self):
        result = runner.certify_provider("aws")
        gate = next(g for g in result.gates if g.gate_id == "security_finding_reachability")
        assert gate.status == "pass"

    def test_finding_change_parity_gate_passes(self):
        result = runner.certify_provider("aws")
        gate = next(g for g in result.gates if g.gate_id == "finding_change_parity")
        assert gate.status == "pass"

    def test_capability_evidence_gate_passes(self):
        result = runner.certify_provider("aws")
        gate = next(g for g in result.gates if g.gate_id == "capability_evidence")
        assert gate.status == "pass"


class TestAWSNegativeMutations:
    def test_fails_when_finding_ids_discovery_drops_one(self, monkeypatch):
        real = disc.discover_registry_rule_ids("aws")
        mutated = frozenset(real - {"aws_root_mfa_disabled"})
        monkeypatch.setattr(disc, "discover_registry_rule_ids", lambda pid: mutated if pid == "aws" else real)
        gate = gates.gate_security_finding_registry_parity(AWS_MANIFEST)
        assert gate.status == "fail"

    def test_fails_when_capability_evidence_test_file_missing(self, monkeypatch):
        import dataclasses

        bad_ev = dataclasses.replace(
            AWS_MANIFEST.capability_evidence[0],
            evidence_tests=("tests/test_aws_this_file_does_not_exist.py",),
        )
        bad_manifest = dataclasses.replace(AWS_MANIFEST, capability_evidence=(bad_ev,))
        gate = gates.gate_capability_evidence(bad_manifest)
        assert gate.status == "fail"
