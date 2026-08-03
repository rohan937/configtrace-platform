"""GitLab pilot certification tests (message 3 of N).

Proves the framework independently DISCOVERS and certifies GitLab's real
state — 9 record types (resolved via literal-string-value matching,
since the connector never imports its own schema constants by name), 25
Finding IDs, registration in PROVIDER_CAPABILITIES_PARTIAL (not a
"not really launched" signal — see the message-3 gate fix), inline
router-level creation dispatch (no per-provider function), no reconnect
of any kind, and a deliberately empty change_parity_evidence resolving
to "deferred" rather than a fabricated pass.
"""

from __future__ import annotations

from app.provider_certification import discovery as disc
from app.provider_certification import gates
from app.provider_certification import runner
from app.provider_certification.manifests.gitlab import GITLAB_MANIFEST


class TestGitLabManifestShape:
    def test_canonical_provider_id_is_gitlab(self):
        assert GITLAB_MANIFEST.provider_id == "gitlab"

    def test_manifest_declares_9_record_types(self):
        assert len(GITLAB_MANIFEST.expected_record_types) == 9

    def test_manifest_declares_25_finding_ids(self):
        assert len(GITLAB_MANIFEST.security_finding_rule_ids) == 25

    def test_manifest_declares_not_live_and_not_reconnect(self):
        # Honest reflection of real state — no reconnect wiring exists
        # for GitLab yet, of any kind.
        assert GITLAB_MANIFEST.expected_live is False
        assert GITLAB_MANIFEST.expected_reconnect is False

    def test_manifest_declares_public_and_connectable(self):
        assert GITLAB_MANIFEST.expected_public
        assert GITLAB_MANIFEST.expected_connectable

    def test_manifest_marks_access_token_sensitive(self):
        assert GITLAB_MANIFEST.sensitive_credential_fields == ("gitlab_access_token",)

    def test_manifest_has_no_change_parity_evidence_or_exceptions(self):
        assert GITLAB_MANIFEST.change_parity_evidence == ()
        assert GITLAB_MANIFEST.change_parity_exceptions == ()


class TestGitLabDiscoveryIndependentlyConfirmsManifest:
    def test_discovered_record_types_match_manifest_exactly(self):
        discovered = disc.discover_schema_record_type_constants("gitlab")
        assert discovered == set(GITLAB_MANIFEST.expected_record_types)
        assert len(discovered) == 9

    def test_record_types_resolved_via_literal_value_not_constant_name(self):
        # GitLab's connector uses raw string literals for record_type —
        # confirm the constant NAMES are never referenced anywhere in
        # the connector (proving value-based resolution, not name-based).
        text = disc.discover_connector_source_text("gitlab")
        assert "GITLAB_PROJECT" not in text
        assert '"gitlab_project"' in text

    def test_discovered_finding_ids_match_manifest_exactly(self):
        discovered = disc.discover_registry_rule_ids("gitlab")
        assert discovered == set(GITLAB_MANIFEST.security_finding_rule_ids)
        assert len(discovered) == 25

    def test_capability_matrix_membership_is_partial_list_not_complete(self):
        in_complete, in_partial = disc.discover_capability_matrix_membership("gitlab")
        assert in_complete is False
        assert in_partial is True

    def test_no_create_dispatch_function_but_router_inline_dispatch_exists(self):
        assert disc.discover_create_dispatch_function_exists("gitlab") is False
        assert disc.discover_router_create_dispatch("gitlab") is True

    def test_no_reconnect_wiring_of_any_kind(self):
        assert disc.discover_reconnect_function_exists("gitlab") is False
        assert disc.discover_generic_reconnect_dispatch("gitlab") is False

    def test_gitlab_absent_from_future_provider_queue(self):
        assert "gitlab" not in disc.discover_recommended_next_providers()


class TestGitLabFullCertification:
    def test_overall_status_is_pass(self):
        assert runner.certify_provider("gitlab").overall_status == "pass"

    def test_no_gate_fails(self):
        result = runner.certify_provider("gitlab")
        assert [g.gate_id for g in result.gates if g.status == "fail"] == []

    def test_creation_validation_gate_passes(self):
        result = runner.certify_provider("gitlab")
        gate = next(g for g in result.gates if g.gate_id == "creation_validation")
        assert gate.status == "pass"

    def test_reconnect_rotation_gate_not_applicable(self):
        result = runner.certify_provider("gitlab")
        gate = next(g for g in result.gates if g.gate_id == "reconnect_rotation")
        assert gate.status == "not_applicable"

    def test_public_connectable_live_consistency_not_applicable(self):
        result = runner.certify_provider("gitlab")
        gate = next(g for g in result.gates if g.gate_id == "public_connectable_live_consistency")
        assert gate.status == "not_applicable"

    def test_capability_matrix_parity_gate_passes(self):
        result = runner.certify_provider("gitlab")
        gate = next(g for g in result.gates if g.gate_id == "capability_matrix_parity")
        assert gate.status == "pass"

    def test_security_finding_reachability_gate_passes(self):
        result = runner.certify_provider("gitlab")
        gate = next(g for g in result.gates if g.gate_id == "security_finding_reachability")
        assert gate.status == "pass"

    def test_finding_change_parity_gate_is_deferred_not_fabricated_pass(self):
        result = runner.certify_provider("gitlab")
        gate = next(g for g in result.gates if g.gate_id == "finding_change_parity")
        assert gate.status == "deferred"
        assert gate.blocking is False


class TestGitLabNegativeMutations:
    def test_fails_when_router_inline_dispatch_removed(self, monkeypatch):
        monkeypatch.setattr(disc, "discover_router_create_dispatch", lambda pid: False)
        monkeypatch.setattr(disc, "discover_create_dispatch_function_exists", lambda pid: False)
        gate = gates.gate_creation_validation(GITLAB_MANIFEST)
        assert gate.status == "fail"

    def test_capability_matrix_parity_fails_if_absent_from_both_lists(self, monkeypatch):
        monkeypatch.setattr(disc, "discover_capability_matrix_membership", lambda pid: (False, False) if pid == "gitlab" else (True, False))
        gate = gates.gate_capability_matrix_parity(GITLAB_MANIFEST)
        assert gate.status == "fail"
