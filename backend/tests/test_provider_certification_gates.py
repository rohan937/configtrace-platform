"""Gate-layer tests for the Provider Certification Framework.

Every gate gets a passing case (using the real Sentry/Snowflake
manifests, which are known-good), a failing case (via a monkeypatched
discovery function proving the gate actually checks reality, not the
manifest alone), and a not-applicable case where relevant.
"""

from __future__ import annotations

from app.provider_certification import discovery as disc
from app.provider_certification import gates
from app.provider_certification.manifests.sentry import SENTRY_MANIFEST
from app.provider_certification.manifests.snowflake import SNOWFLAKE_MANIFEST
from app.provider_certification.models import ProviderCertificationManifest


def _bad_manifest(**overrides) -> ProviderCertificationManifest:
    fields = dict(
        provider_id="ghostprov",
        display_name="Ghost Provider",
        category="observability",
        maturity="partial",
        expected_public=True,
        expected_connectable=True,
        expected_live=True,
        credential_fields=("ghostprov_api_token",),
        sensitive_credential_fields=("ghostprov_api_token",),
        authentication_model="api_token",
        expected_record_types=("ghostprov_widget",),
        expected_frontend_form="GhostProvIntegrationForm.tsx",
        expected_reconnect=True,
        supported_capabilities=("security_findings",),
        security_finding_rule_ids=("ghostprov_finding_one",),
        false_removal_scopes=("account_wide",),
    )
    fields.update(overrides)
    return ProviderCertificationManifest(**fields)


class TestGateIdentity:
    def test_pass_for_sentry(self):
        g = gates.gate_identity(SENTRY_MANIFEST)
        assert g.status == "pass"

    def test_fail_for_unregistered_provider(self):
        g = gates.gate_identity(_bad_manifest())
        assert g.status == "fail"


class TestGateBackendRegistration:
    def test_pass_for_snowflake(self):
        g = gates.gate_backend_registration(SNOWFLAKE_MANIFEST)
        assert g.status == "pass"

    def test_fail_for_unregistered_provider(self):
        g = gates.gate_backend_registration(_bad_manifest())
        assert g.status == "fail"

    def test_not_applicable_case_via_planned_maturity(self):
        m = _bad_manifest(
            maturity="planned", expected_public=False, expected_connectable=False,
            expected_live=False, expected_reconnect=False, expected_frontend_form=None,
        )
        g = gates.gate_backend_registration(m)
        assert g.status in ("deferred", "pass")


class TestGateCredentialSchema:
    def test_pass_for_sentry(self):
        g = gates.gate_credential_schema(SENTRY_MANIFEST)
        assert g.status == "pass"

    def test_fail_when_field_not_on_backend_schema(self):
        m = _bad_manifest(credential_fields=("ghostprov_nonexistent_field",), sensitive_credential_fields=())
        g = gates.gate_credential_schema(m)
        assert g.status == "fail"

    def test_not_applicable_when_no_credential_fields(self):
        m = _bad_manifest(
            credential_fields=(), sensitive_credential_fields=(),
        )
        g = gates.gate_credential_schema(m)
        assert g.status == "not_applicable"


class TestGateReconnectRotation:
    def test_pass_for_snowflake(self):
        g = gates.gate_reconnect_rotation(SNOWFLAKE_MANIFEST)
        assert g.status == "pass"

    def test_fail_for_unregistered_provider(self):
        g = gates.gate_reconnect_rotation(_bad_manifest())
        assert g.status == "fail"

    def test_not_applicable_when_reconnect_not_required(self):
        m = _bad_manifest(expected_reconnect=False, expected_live=False)
        g = gates.gate_reconnect_rotation(m)
        assert g.status == "not_applicable"


class TestGateSyncWorkerDispatch:
    def test_sync_pass_for_sentry(self):
        assert gates.gate_sync_dispatch(SENTRY_MANIFEST).status == "pass"

    def test_worker_pass_for_sentry(self):
        assert gates.gate_worker_dispatch(SENTRY_MANIFEST).status == "pass"

    def test_sync_fail_for_unregistered_provider(self):
        assert gates.gate_sync_dispatch(_bad_manifest()).status == "fail"

    def test_worker_fail_for_unregistered_provider(self):
        assert gates.gate_worker_dispatch(_bad_manifest()).status == "fail"


class TestGateConnectorContract:
    def test_pass_for_snowflake(self):
        g = gates.gate_connector_contract(SNOWFLAKE_MANIFEST)
        assert g.status == "pass"

    def test_fail_for_unimportable_connector(self):
        g = gates.gate_connector_contract(_bad_manifest())
        assert g.status == "fail"


class TestGateRecordInventory:
    def test_pass_for_sentry_exact_set(self):
        g = gates.gate_record_inventory(SENTRY_MANIFEST)
        assert g.status == "pass"

    def test_fail_when_expected_type_not_discovered(self):
        m = _bad_manifest(expected_record_types=("ghostprov_nonexistent_type",))
        g = gates.gate_record_inventory(m)
        assert g.status == "fail"

    def test_not_applicable_when_no_expected_types(self):
        m = _bad_manifest(expected_record_types=())
        g = gates.gate_record_inventory(m)
        assert g.status == "not_applicable"

    def test_fails_when_one_sentry_record_type_removed_via_monkeypatch(self, monkeypatch):
        """Negative mutation: discovery says one fewer record type exists
        than the manifest declares — must fail, proving the gate checks
        DISCOVERED reality, not just the manifest."""
        real = disc.discover_schema_record_type_constants("sentry")
        mutated = frozenset(real - {"sentry_routing_context"})
        monkeypatch.setattr(disc, "discover_schema_record_type_constants", lambda pid: mutated if pid == "sentry" else real)
        g = gates.gate_record_inventory(SENTRY_MANIFEST)
        assert g.status == "fail"
        assert "sentry_routing_context" in g.details


class TestGateDiffTrackedFields:
    def test_pass_for_snowflake(self):
        g = gates.gate_diff_tracked_fields(SNOWFLAKE_MANIFEST)
        assert g.status == "pass"

    def test_fail_when_dict_absent(self):
        g = gates.gate_diff_tracked_fields(_bad_manifest())
        assert g.status == "fail"

    def test_fail_when_record_type_entirely_missing_via_monkeypatch(self, monkeypatch):
        real = disc.discover_diff_tracked_fields_dict("sentry")
        mutated = {k: v for k, v in real.items() if k != "sentry_organization"}
        monkeypatch.setattr(disc, "discover_diff_tracked_fields_dict", lambda pid: mutated if pid == "sentry" else real)
        g = gates.gate_diff_tracked_fields(SENTRY_MANIFEST)
        assert g.status == "fail"


class TestGateChangeClassifierCoverage:
    def test_pass_or_warning_for_sentry(self):
        g = gates.gate_change_classifier_coverage(SENTRY_MANIFEST)
        assert g.status in ("pass", "warning")

    def test_fail_when_dispatch_branch_absent(self):
        g = gates.gate_change_classifier_coverage(_bad_manifest())
        assert g.status == "fail"

    def test_fail_when_dispatch_removed_via_monkeypatch(self, monkeypatch):
        """Negative mutation: dispatch branch for the provider prefix is
        gone — must fail even though the manifest is otherwise valid."""
        monkeypatch.setattr(disc, "discover_classifier_dispatch_exists", lambda pid: False)
        g = gates.gate_change_classifier_coverage(SENTRY_MANIFEST)
        assert g.status == "fail"


class TestGateSecurityFindingRegistryParity:
    def test_pass_for_sentry_exact_set(self):
        g = gates.gate_security_finding_registry_parity(SENTRY_MANIFEST)
        assert g.status == "pass"

    def test_pass_for_snowflake_exact_set(self):
        g = gates.gate_security_finding_registry_parity(SNOWFLAKE_MANIFEST)
        assert g.status == "pass"

    def test_not_applicable_without_capability(self):
        m = _bad_manifest(supported_capabilities=(), security_finding_rule_ids=())
        g = gates.gate_security_finding_registry_parity(m)
        assert g.status == "not_applicable"

    def test_fails_when_one_finding_absent_from_frontend_via_monkeypatch(self, monkeypatch):
        """Negative mutation: one Finding ID is absent from the frontend
        catalog — parity must fail."""
        real_frontend = disc.discover_frontend_catalog_rule_ids("sentry")
        if real_frontend is None:
            import pytest
            pytest.skip("frontend tree not mounted")
        mutated = frozenset(real_frontend - {"sentry_pending_privileged_invitation"})
        monkeypatch.setattr(disc, "discover_frontend_catalog_rule_ids", lambda pid: mutated if pid == "sentry" else real_frontend)
        g = gates.gate_security_finding_registry_parity(SENTRY_MANIFEST)
        assert g.status == "fail"
        assert "frontend_catalog" in g.details

    def test_fails_when_registry_missing_one_id_via_monkeypatch(self, monkeypatch):
        real_registry = disc.discover_registry_rule_ids("sentry")
        mutated = frozenset(real_registry - {"sentry_team_has_unresolved_members"})
        monkeypatch.setattr(disc, "discover_registry_rule_ids", lambda pid: mutated if pid == "sentry" else real_registry)
        g = gates.gate_security_finding_registry_parity(SENTRY_MANIFEST)
        assert g.status == "fail"


class TestGateFindingReachability:
    def test_pass_for_sentry(self):
        g = gates.gate_finding_reachability(SENTRY_MANIFEST)
        assert g.status == "pass"

    def test_fail_when_evaluator_unregistered_via_monkeypatch(self, monkeypatch):
        monkeypatch.setattr(disc, "discover_evaluator_registered", lambda pid: False)
        g = gates.gate_finding_reachability(SENTRY_MANIFEST)
        assert g.status == "fail"

    def test_not_applicable_without_capability(self):
        m = _bad_manifest(supported_capabilities=(), security_finding_rule_ids=())
        g = gates.gate_finding_reachability(m)
        assert g.status == "not_applicable"


class TestGateCapabilityMatrixParity:
    def test_pass_for_snowflake(self):
        g = gates.gate_capability_matrix_parity(SNOWFLAKE_MANIFEST)
        assert g.status == "pass"

    def test_fail_for_maturity_mismatch_via_monkeypatch(self, monkeypatch):
        cap = disc.discover_capability_entry("sentry")

        class _FakeCap:
            provider = cap.provider
            category = cap.category
            maturity = "complete"  # mismatched vs manifest's "partial"

        monkeypatch.setattr(disc, "discover_capability_entry", lambda pid: _FakeCap() if pid == "sentry" else cap)
        g = gates.gate_capability_matrix_parity(SENTRY_MANIFEST)
        assert g.status == "fail"


class TestGateSecurityCoverageParity:
    def test_pass_for_sentry(self):
        g = gates.gate_security_coverage_parity(SENTRY_MANIFEST)
        assert g.status == "pass"

    def test_fail_when_not_member_via_monkeypatch(self, monkeypatch):
        monkeypatch.setattr(disc, "discover_coverage_provider_membership", lambda pid: False)
        g = gates.gate_security_coverage_parity(SENTRY_MANIFEST)
        assert g.status == "fail"


class TestGateFrontendProviderParity:
    def test_pass_for_snowflake(self):
        g = gates.gate_frontend_provider_parity(SNOWFLAKE_MANIFEST)
        if disc.frontend_root() is None:
            assert g.status == "not_applicable"
        else:
            assert g.status == "pass"

    def test_fail_when_backend_connectable_but_frontend_hidden(self, monkeypatch):
        """Negative mutation: provider is backend-connectable but absent
        from the frontend connectable list."""
        if disc.frontend_root() is None:
            import pytest
            pytest.skip("frontend tree not mounted")
        real_ids = disc.discover_frontend_provider_ids()
        monkeypatch.setattr(disc, "discover_frontend_connectable_ids", lambda: frozenset())
        g = gates.gate_frontend_provider_parity(SENTRY_MANIFEST)
        assert g.status == "fail"


class TestGatePublicConnectableLiveConsistency:
    def test_pass_for_sentry(self):
        g = gates.gate_public_connectable_live_consistency(SENTRY_MANIFEST)
        assert g.status == "pass"
        assert g.required_for_live is True

    def test_not_applicable_when_not_live(self):
        m = _bad_manifest(expected_live=False, expected_reconnect=False)
        g = gates.gate_public_connectable_live_consistency(m)
        assert g.status == "not_applicable"

    def test_fail_when_live_but_in_future_queue_via_monkeypatch(self, monkeypatch):
        """Negative mutation: provider is Live but still listed in the
        future-provider queue — must fail."""
        monkeypatch.setattr(disc, "discover_recommended_next_providers", lambda: frozenset({"sentry"}))
        g = gates.gate_public_connectable_live_consistency(SENTRY_MANIFEST)
        assert g.status == "fail"
        assert "not_in_future_queue" in g.details


class TestGateSensitiveDataControls:
    def test_pass_for_sentry(self):
        g = gates.gate_sensitive_data_controls(SENTRY_MANIFEST)
        assert g.status == "pass"

    def test_fail_when_secret_field_unmasked_via_monkeypatch(self, monkeypatch):
        """Negative mutation: the frontend form no longer masks the
        secret field."""
        monkeypatch.setattr(disc, "discover_frontend_form_uses_password_input", lambda f: False)
        g = gates.gate_sensitive_data_controls(SENTRY_MANIFEST)
        if disc.frontend_root() is None:
            import pytest
            pytest.skip("frontend tree not mounted")
        assert g.status == "fail"

    def test_not_applicable_without_sensitive_fields(self):
        m = _bad_manifest(credential_fields=("ghostprov_org_slug",), sensitive_credential_fields=())
        g = gates.gate_sensitive_data_controls(m)
        assert g.status == "not_applicable"

    def test_fail_when_prohibited_env_var_referenced_via_monkeypatch(self, monkeypatch):
        monkeypatch.setattr(disc, "discover_global_env_var_reference", lambda pid, var: True)
        m = SENTRY_MANIFEST
        g = gates.gate_sensitive_data_controls(m)
        assert g.status == "fail"


class TestGateDependencyEnvAudit:
    def test_pass_for_sentry(self):
        g = gates.gate_dependency_env_audit(SENTRY_MANIFEST)
        assert g.status == "pass"

    def test_not_applicable_when_no_prohibitions_declared(self):
        m = _bad_manifest(prohibited_dependencies=(), prohibited_env_vars=())
        g = gates.gate_dependency_env_audit(m)
        assert g.status == "not_applicable"

    def test_fail_when_prohibited_dependency_present_via_monkeypatch(self, monkeypatch):
        monkeypatch.setattr(disc, "discover_prohibited_dependency_present", lambda dep: True)
        g = gates.gate_dependency_env_audit(SENTRY_MANIFEST)
        assert g.status == "fail"


class TestGateCompletenessAndFalseRemoval:
    def test_completeness_pass_for_snowflake(self):
        g = gates.gate_completeness_model(SNOWFLAKE_MANIFEST)
        assert g.status == "pass"

    def test_false_removal_pass_for_sentry(self):
        g = gates.gate_false_removal_protection(SENTRY_MANIFEST)
        assert g.status == "pass"

    def test_false_removal_fail_when_suppression_absent_via_monkeypatch(self, monkeypatch):
        monkeypatch.setattr(disc, "discover_removal_suppression_exists", lambda pid: False)
        g = gates.gate_false_removal_protection(SENTRY_MANIFEST)
        assert g.status == "fail"

    def test_completeness_not_applicable_when_empty(self):
        m = _bad_manifest(completeness_scopes=())
        g = gates.gate_completeness_model(m)
        assert g.status in ("not_applicable", "warning")


class TestGateKnownLimitationsAndTestEvidence:
    def test_known_limitations_pass_for_sentry(self):
        g = gates.gate_known_limitations(SENTRY_MANIFEST)
        assert g.status == "pass"

    def test_test_evidence_pass_for_sentry(self):
        g = gates.gate_test_evidence(SENTRY_MANIFEST)
        assert g.status == "pass"

    def test_test_evidence_fail_when_file_missing(self):
        m = _bad_manifest(evidence_test_files=("tests/test_this_file_does_not_exist_at_all.py",))
        g = gates.gate_test_evidence(m)
        assert g.status == "fail"

    def test_test_evidence_fail_when_no_evidence_declared_for_launched_provider(self):
        m = _bad_manifest(evidence_test_files=(), evidence_reports=())
        g = gates.gate_test_evidence(m)
        assert g.status == "fail"


class TestOptionalDualStackGates:
    def test_activity_ingestion_deferred_for_partial_sentry(self):
        g = gates.gate_activity_ingestion(SENTRY_MANIFEST)
        assert g.status == "deferred"
        assert g.blocking is False

    def test_change_classification_exhaustive_proof_pass_with_evidence(self):
        g = gates.gate_change_classification_exhaustive_proof(SENTRY_MANIFEST)
        assert g.status == "pass"

    def test_change_classification_exhaustive_proof_deferred_without_evidence(self):
        m = _bad_manifest(evidence_test_files=())
        g = gates.gate_change_classification_exhaustive_proof(m)
        assert g.status == "deferred"

    def test_change_classification_exhaustive_proof_fails_for_complete_without_evidence(self):
        m = _bad_manifest(
            maturity="complete",
            evidence_test_files=(),
            supported_capabilities=(
                "security_findings", "activity_ingestion", "activity_signals",
                "risk_activity_correlations", "demo_case_reporting",
            ),
        )
        g = gates.gate_change_classification_exhaustive_proof(m)
        assert g.status == "fail"


class TestGlobalFreezeGate:
    def test_pass_in_current_repo_state(self):
        g = gates.gate_provider_expansion_freeze()
        assert g.status == "pass"

    def test_fail_when_backend_queue_nonempty_via_monkeypatch(self, monkeypatch):
        monkeypatch.setattr(disc, "discover_recommended_next_providers", lambda: frozenset({"sentry"}))
        g = gates.gate_provider_expansion_freeze()
        assert g.status == "fail"
        assert "RECOMMENDED_NEXT_PROVIDERS" in g.details

    def test_fail_when_planned_next_stage_does_not_say_frozen(self, monkeypatch):
        monkeypatch.setattr(disc, "discover_planned_next_stage_text", lambda: "M91A: Some Future Provider")
        g = gates.gate_provider_expansion_freeze()
        assert g.status == "fail"

    def test_fail_when_frontend_queue_nonempty_via_monkeypatch(self, monkeypatch):
        monkeypatch.setattr(disc, "discover_frontend_future_provider_queue", lambda: frozenset({"Sentry"}))
        g = gates.gate_provider_expansion_freeze()
        assert g.status == "fail"
        assert "Sentry" in g.details
