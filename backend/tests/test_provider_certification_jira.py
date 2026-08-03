"""Jira pilot certification tests (message 5 of N).

Proves the framework independently DISCOVERS and certifies Jira's real
state — 12 record types, 81 Finding IDs — with generic discovery alone
(no adapter needed). Registered in PROVIDER_CAPABILITIES_PARTIAL.

Jira's reachability/parity minimum_test_count is 15 (not 25), reflecting
a known limitation of the gate's module-level test-counting regex
against test_jira_provider_depth_qa.py's 27 module-level (unindented)
test functions — see manifest known_limitations / message5 report.
"""

from __future__ import annotations

from app.provider_certification import adapters as adapt
from app.provider_certification import discovery as disc
from app.provider_certification import gates
from app.provider_certification import runner
from app.provider_certification.manifests.jira import JIRA_MANIFEST


class TestJiraManifestShape:
    def test_canonical_provider_id_is_jira(self):
        assert JIRA_MANIFEST.provider_id == "jira"

    def test_manifest_declares_12_record_types(self):
        assert len(JIRA_MANIFEST.expected_record_types) == 12

    def test_manifest_declares_81_finding_ids(self):
        assert len(JIRA_MANIFEST.security_finding_rule_ids) == 81

    def test_manifest_declares_maturity_partial(self):
        assert JIRA_MANIFEST.maturity == "partial"

    def test_manifest_declares_reconnect_not_required(self):
        assert JIRA_MANIFEST.expected_reconnect is False
        assert JIRA_MANIFEST.expected_live is False

    def test_manifest_marks_api_token_sensitive(self):
        assert set(JIRA_MANIFEST.sensitive_credential_fields) == {"jira_api_token"}

    def test_manifest_documents_no_issue_content_ingestion(self):
        text = " ".join(JIRA_MANIFEST.known_limitations)
        assert "comments" in text and "attachments" in text and "worklogs" in text


class TestJiraNoAdapterNeeded:
    def test_no_adapter_registered(self):
        assert adapt.get_adapter("jira") is None


class TestJiraDiscoveryIndependentlyConfirmsManifest:
    def test_discovered_record_types_match_manifest_exactly(self):
        discovered = disc.discover_schema_record_type_constants("jira")
        assert discovered == set(JIRA_MANIFEST.expected_record_types)
        assert len(discovered) == 12

    def test_discovered_finding_ids_match_manifest_exactly(self):
        discovered = disc.discover_registry_rule_ids("jira")
        assert discovered == set(JIRA_MANIFEST.security_finding_rule_ids)
        assert len(discovered) == 81

    def test_capability_matrix_membership_is_partial_list(self):
        in_complete, in_partial = disc.discover_capability_matrix_membership("jira")
        assert in_complete is False
        assert in_partial is True

    def test_no_false_removal_suppression_function_exists(self):
        assert disc.discover_removal_suppression_exists("jira") is False

    def test_jira_absent_from_future_provider_queue(self):
        assert "jira" not in disc.discover_recommended_next_providers()

    def test_depth_qa_file_has_27_module_level_test_functions(self):
        import re

        path = "tests/test_jira_provider_depth_qa.py"
        with open(path, encoding="utf-8") as fh:
            content = fh.read()
        module_level = re.findall(r"^def test_", content, flags=re.MULTILINE)
        assert len(module_level) == 27


class TestJiraFullCertification:
    def test_overall_status_is_pass(self):
        assert runner.certify_provider("jira").overall_status == "pass"

    def test_no_gate_fails(self):
        result = runner.certify_provider("jira")
        assert [g.gate_id for g in result.gates if g.status == "fail"] == []

    def test_security_finding_reachability_gate_passes(self):
        result = runner.certify_provider("jira")
        gate = next(g for g in result.gates if g.gate_id == "security_finding_reachability")
        assert gate.status == "pass"

    def test_finding_change_parity_gate_passes(self):
        result = runner.certify_provider("jira")
        gate = next(g for g in result.gates if g.gate_id == "finding_change_parity")
        assert gate.status == "pass"


class TestJiraNegativeMutations:
    def test_fails_when_minimum_test_count_raised_beyond_matched_count(self):
        import dataclasses

        bad_evidence = dataclasses.replace(
            JIRA_MANIFEST.reachability_evidence[0],
            minimum_test_count=9999,
        )
        bad_manifest = dataclasses.replace(JIRA_MANIFEST, reachability_evidence=(bad_evidence,))
        gate = gates.gate_security_finding_reachability(bad_manifest)
        assert gate.status == "fail"

    def test_fails_when_finding_ids_discovery_drops_one(self, monkeypatch):
        real = disc.discover_registry_rule_ids("jira")
        mutated = frozenset(real - {"jira_permission_scheme_anonymous_grant"})
        monkeypatch.setattr(disc, "discover_registry_rule_ids", lambda pid: mutated if pid == "jira" else real)
        gate = gates.gate_security_finding_registry_parity(JIRA_MANIFEST)
        assert gate.status == "fail"
