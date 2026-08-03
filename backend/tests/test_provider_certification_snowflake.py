"""Snowflake pilot certification tests (message 1 of N).

Proves the framework independently DISCOVERS and certifies Snowflake's
real state — 21 record types, 31 Finding IDs, four credential fields,
PAT sensitivity, public/connectable/Live parity, reconnect dispatch,
security parity, completeness declaration, and no CLI/SDK dependency —
rather than trusting the manifest's own declarations.
"""

from __future__ import annotations

from app.provider_certification import discovery as disc
from app.provider_certification import runner
from app.provider_certification.manifests.snowflake import SNOWFLAKE_MANIFEST


class TestSnowflakeManifestShape:
    def test_manifest_declares_21_record_types(self):
        assert len(SNOWFLAKE_MANIFEST.expected_record_types) == 21

    def test_manifest_declares_31_finding_ids(self):
        assert len(SNOWFLAKE_MANIFEST.security_finding_rule_ids) == 31

    def test_manifest_declares_four_credential_fields(self):
        assert set(SNOWFLAKE_MANIFEST.credential_fields) == {
            "snowflake_account_identifier",
            "snowflake_username",
            "snowflake_programmatic_access_token",
            "snowflake_role",
        }

    def test_manifest_marks_pat_sensitive(self):
        assert SNOWFLAKE_MANIFEST.sensitive_credential_fields == ("snowflake_programmatic_access_token",)

    def test_manifest_declares_public_connectable_live(self):
        assert SNOWFLAKE_MANIFEST.expected_public
        assert SNOWFLAKE_MANIFEST.expected_connectable
        assert SNOWFLAKE_MANIFEST.expected_live

    def test_manifest_declares_reconnect_required(self):
        assert SNOWFLAKE_MANIFEST.expected_reconnect

    def test_manifest_declares_cli_sdk_prohibited_dependencies(self):
        assert "snowflake-connector-python" in SNOWFLAKE_MANIFEST.prohibited_dependencies
        assert "snowflake-cli" in SNOWFLAKE_MANIFEST.prohibited_dependencies


class TestSnowflakeDiscoveryIndependentlyConfirmsManifest:
    def test_discovered_record_types_match_manifest_exactly(self):
        discovered = disc.discover_schema_record_type_constants("snowflake")
        assert discovered == set(SNOWFLAKE_MANIFEST.expected_record_types)
        assert len(discovered) == 21

    def test_discovered_finding_ids_match_manifest_exactly(self):
        discovered = disc.discover_registry_rule_ids("snowflake")
        assert discovered == set(SNOWFLAKE_MANIFEST.security_finding_rule_ids)
        assert len(discovered) == 31

    def test_discovered_credential_fields_match_manifest(self):
        discovered = disc.discover_credential_schema_fields("snowflake")
        assert discovered == set(SNOWFLAKE_MANIFEST.credential_fields)

    def test_discovered_reconnect_dispatch_matches_manifest_declaration(self):
        assert disc.discover_reconnect_function_exists("snowflake") == SNOWFLAKE_MANIFEST.expected_reconnect

    def test_discovered_capability_matrix_maturity_matches_manifest(self):
        cap = disc.discover_capability_entry("snowflake")
        assert cap.maturity == SNOWFLAKE_MANIFEST.maturity

    def test_no_cli_or_sdk_dependency_present(self):
        for dep in SNOWFLAKE_MANIFEST.prohibited_dependencies:
            assert not disc.discover_prohibited_dependency_present(dep)

    def test_snowflake_absent_from_future_provider_queue(self):
        assert "snowflake" not in disc.discover_recommended_next_providers()


class TestSnowflakeFullCertification:
    def test_overall_status_is_pass(self):
        result = runner.certify_provider("snowflake")
        assert result.overall_status == "pass"

    def test_no_gate_is_unknown(self):
        result = runner.certify_provider("snowflake")
        assert all(g.status != "unknown" for g in result.gates)

    def test_no_gate_fails(self):
        result = runner.certify_provider("snowflake")
        failing = [g.gate_id for g in result.gates if g.status == "fail"]
        assert failing == []

    def test_security_finding_registry_parity_gate_passes(self):
        result = runner.certify_provider("snowflake")
        gate = next(g for g in result.gates if g.gate_id == "security_finding_registry_parity")
        assert gate.status == "pass"

    def test_record_inventory_gate_passes(self):
        result = runner.certify_provider("snowflake")
        gate = next(g for g in result.gates if g.gate_id == "record_inventory")
        assert gate.status == "pass"

    def test_diff_tracked_fields_gate_passes(self):
        result = runner.certify_provider("snowflake")
        gate = next(g for g in result.gates if g.gate_id == "diff_tracked_fields")
        assert gate.status == "pass"

    def test_dependency_env_audit_gate_passes(self):
        result = runner.certify_provider("snowflake")
        gate = next(g for g in result.gates if g.gate_id == "dependency_env_audit")
        assert gate.status == "pass"

    def test_provider_expansion_freeze_gate_passes(self):
        result = runner.certify_provider("snowflake")
        gate = next(g for g in result.gates if g.gate_id == "provider_expansion_freeze")
        assert gate.status == "pass"
