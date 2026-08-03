"""GitHub pilot certification tests (message 3 of N).

Proves the framework independently DISCOVERS and certifies GitHub's real
state — 11 real record types (correctly excluding 6 schema-declared but
never-wired constants), 25 Finding IDs, "complete" maturity with full
dual-stack capabilities, GitHubConnector class resolution (irregular
capitalization), reconnect via the shared generic dispatcher, and
frontend wiring via the dispatcher's implicit default case.
"""

from __future__ import annotations

from app.provider_certification import discovery as disc
from app.provider_certification import gates
from app.provider_certification import runner
from app.provider_certification.manifests.github import GITHUB_MANIFEST


class TestGitHubManifestShape:
    def test_canonical_provider_id_is_github(self):
        assert GITHUB_MANIFEST.provider_id == "github"

    def test_manifest_declares_11_record_types(self):
        assert len(GITHUB_MANIFEST.expected_record_types) == 11

    def test_manifest_declares_25_finding_ids(self):
        assert len(GITHUB_MANIFEST.security_finding_rule_ids) == 25

    def test_manifest_declares_maturity_complete(self):
        assert GITHUB_MANIFEST.maturity == "complete"

    def test_manifest_declares_all_five_capabilities(self):
        assert set(GITHUB_MANIFEST.supported_capabilities) == {
            "security_findings", "activity_ingestion", "activity_signals",
            "risk_activity_correlations", "demo_case_reporting",
        }

    def test_manifest_marks_github_token_sensitive(self):
        assert GITHUB_MANIFEST.sensitive_credential_fields == ("github_token",)

    def test_manifest_declares_public_connectable_live(self):
        assert GITHUB_MANIFEST.expected_public
        assert GITHUB_MANIFEST.expected_connectable
        assert GITHUB_MANIFEST.expected_live

    def test_manifest_declares_reconnect_required(self):
        assert GITHUB_MANIFEST.expected_reconnect


class TestGitHubDiscoveryIndependentlyConfirmsManifest:
    def test_discovered_record_types_match_manifest_exactly(self):
        discovered = disc.discover_schema_record_type_constants("github")
        assert discovered == set(GITHUB_MANIFEST.expected_record_types)
        assert len(discovered) == 11

    def test_six_unwired_schema_constants_correctly_excluded(self):
        identity = disc.discover_schema_record_type_identity_constants("github")
        discovered = disc.discover_schema_record_type_constants("github")
        unwired = set(identity.values()) - discovered
        assert unwired == {
            "github_app_installation", "github_codeowners", "github_collaborator",
            "github_oidc_trust", "github_security_features", "github_workflow_file",
        }

    def test_discovered_finding_ids_match_manifest_exactly(self):
        discovered = disc.discover_registry_rule_ids("github")
        assert discovered == set(GITHUB_MANIFEST.security_finding_rule_ids)
        assert len(discovered) == 25

    def test_discovered_capability_matrix_maturity_matches_manifest(self):
        cap = disc.discover_capability_entry("github")
        assert cap.maturity == GITHUB_MANIFEST.maturity
        assert cap.security.activity_ingestion is True

    def test_connector_class_resolves_via_capitalization_fallback(self):
        naive = disc.discover_connector_class("github", "GithubConnector")
        assert naive is None, "naive capitalization must NOT match — proves the fallback path is actually exercised"
        fallback = disc.discover_connector_class_any_capitalization("github")
        assert fallback is not None
        assert fallback.__name__ == "GitHubConnector"

    def test_reconnect_wired_via_generic_dispatcher_not_named_function(self):
        assert disc.discover_reconnect_function_exists("github") is False
        assert disc.discover_generic_reconnect_dispatch("github") is True

    def test_frontend_wired_via_implicit_default_not_explicit_branch(self):
        assert disc.discover_frontend_form_wired_into_dispatcher("github") is False
        assert disc.discover_frontend_form_wired_into_dispatcher("github", "GitHubIntegrationForm.tsx") is True

    def test_github_absent_from_future_provider_queue(self):
        assert "github" not in disc.discover_recommended_next_providers()


class TestGitHubFullCertification:
    def test_overall_status_is_pass(self):
        assert runner.certify_provider("github").overall_status == "pass"

    def test_no_gate_fails(self):
        result = runner.certify_provider("github")
        assert [g.gate_id for g in result.gates if g.status == "fail"] == []

    def test_connector_contract_gate_resolves_via_capitalization_fallback(self):
        result = runner.certify_provider("github")
        gate = next(g for g in result.gates if g.gate_id == "connector_contract")
        # "pass" if _credentials() is present, "warning" if the class
        # resolves but lacks that exact method name — either way this
        # is non-blocking (never "fail") and never "unknown".
        assert gate.status in ("pass", "warning")

    def test_reconnect_rotation_gate_passes(self):
        result = runner.certify_provider("github")
        gate = next(g for g in result.gates if g.gate_id == "reconnect_rotation")
        assert gate.status == "pass"

    def test_frontend_provider_parity_gate_passes(self):
        result = runner.certify_provider("github")
        gate = next(g for g in result.gates if g.gate_id == "frontend_provider_parity")
        assert gate.status == "pass"

    def test_security_finding_reachability_gate_passes(self):
        result = runner.certify_provider("github")
        gate = next(g for g in result.gates if g.gate_id == "security_finding_reachability")
        assert gate.status == "pass"

    def test_finding_change_parity_gate_passes(self):
        result = runner.certify_provider("github")
        gate = next(g for g in result.gates if g.gate_id == "finding_change_parity")
        assert gate.status == "pass"


class TestGitHubNegativeMutations:
    def test_fails_when_reconnect_dispatcher_branch_removed(self, monkeypatch):
        monkeypatch.setattr(disc, "discover_generic_reconnect_dispatch", lambda pid: False)
        monkeypatch.setattr(disc, "discover_reconnect_function_exists", lambda pid: False)
        gate = gates.gate_reconnect_rotation(GITHUB_MANIFEST)
        assert gate.status == "fail"

    def test_fails_when_connector_class_not_found_by_either_path(self, monkeypatch):
        monkeypatch.setattr(disc, "discover_connector_class", lambda pid, name: None)
        monkeypatch.setattr(disc, "discover_connector_class_any_capitalization", lambda pid: None)
        gate = gates.gate_connector_contract(GITHUB_MANIFEST)
        assert gate.status == "fail"
