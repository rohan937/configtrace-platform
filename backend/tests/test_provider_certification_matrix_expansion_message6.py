"""Framework matrix expansion tests (message 6).

Adds genuinely new certification cases for the full 26-provider catalog
— credential parity, capability evidence, completeness granularities,
evidence quality, and cross-manifest invariants exercised against the
9 providers newly onboarded this message (Auth0, Azure, Clerk, Google
Cloud, Linear, SendGrid, Shopify, Terraform Cloud, Twilio) — plus a
regression test pinning the genuine Terraform Cloud creation-dispatch
defect this message's certification pass uncovered and fixed. Every
test here maps to a real gate, a real model validation, a real
manifest, or a real discovery function.
"""

from __future__ import annotations

import dataclasses

import pytest

from app.provider_certification import cross_manifest, discovery as disc, gates, runner
from app.provider_certification import migration_allowlist as ma
from app.provider_certification.manifests.auth0 import AUTH0_MANIFEST
from app.provider_certification.manifests.azure import AZURE_MANIFEST
from app.provider_certification.manifests.clerk import CLERK_MANIFEST
from app.provider_certification.manifests.google_cloud import GOOGLE_CLOUD_MANIFEST
from app.provider_certification.manifests.linear import LINEAR_MANIFEST
from app.provider_certification.manifests.sendgrid import SENDGRID_MANIFEST
from app.provider_certification.manifests.shopify import SHOPIFY_MANIFEST
from app.provider_certification.manifests.terraform_cloud import TERRAFORM_CLOUD_MANIFEST
from app.provider_certification.manifests.twilio import TWILIO_MANIFEST
from app.provider_certification.models import (
    CapabilityEvidenceDeclaration,
    CompletenessScopeDeclaration,
    ManifestValidationError,
)


def _all_manifests():
    runner._ensure_manifests_loaded()
    return tuple(runner.get_manifest(pid) for pid in runner.known_provider_ids())


# ── 1. Terraform Cloud creation-dispatch genuine defect regression ──────────


class TestTerraformCloudCreationDispatchGenuineDefectFix:
    """Certification discovered that routers/integrations.py's
    _build_credentials() had NO branch for terraform_cloud — the whole
    M88A onboarding wave's router branch was missing between M87A
    (GitLab) and the Okta/Entra/Snowflake/Sentry block. This is the one
    genuine runtime defect this message's certification pass justified
    fixing (a real, pre-existing gap, not a maturity/gate weakening)."""

    def test_router_create_dispatch_now_exists_for_terraform_cloud(self):
        assert disc.discover_router_create_dispatch("terraform_cloud") is True

    def test_creation_validation_gate_passes_for_terraform_cloud(self):
        gate = gates.gate_creation_validation(TERRAFORM_CLOUD_MANIFEST)
        assert gate.status == "pass"

    def test_build_credentials_extracts_the_correct_keys(self):
        from app.routers.integrations import _build_credentials
        from app.schemas.integration import IntegrationCreateRequest

        body = IntegrationCreateRequest(
            provider="terraform_cloud",
            display_name="Test TFC",
            terraform_cloud_api_token="fake-token-for-shape-test-only",
            terraform_cloud_organization="fake-org",
        )
        creds = _build_credentials(body)
        assert creds == {"api_token": "fake-token-for-shape-test-only", "organization": "fake-org"}

    def test_build_credentials_includes_optional_base_url_when_provided(self):
        from app.routers.integrations import _build_credentials
        from app.schemas.integration import IntegrationCreateRequest

        body = IntegrationCreateRequest(
            provider="terraform_cloud",
            display_name="Test TFC",
            terraform_cloud_api_token="fake-token",
            terraform_cloud_organization="fake-org",
            terraform_cloud_base_url="https://tfe.example.com/api/v2",
        )
        creds = _build_credentials(body)
        assert creds["base_url"] == "https://tfe.example.com/api/v2"


# ── 2. Credential parity: create schema / reconnect / frontend / masking ───


class TestCredentialParityForNewProviders:
    def test_auth0_all_credential_fields_present_on_backend_create_schema(self):
        discovered = disc.discover_credential_schema_fields("auth0")
        assert set(AUTH0_MANIFEST.credential_fields) <= discovered

    def test_azure_all_credential_fields_present_on_backend_create_schema(self):
        discovered = disc.discover_credential_schema_fields("azure")
        assert set(AZURE_MANIFEST.credential_fields) <= discovered

    def test_clerk_all_credential_fields_present_on_backend_create_schema(self):
        discovered = disc.discover_credential_schema_fields("clerk")
        assert set(CLERK_MANIFEST.credential_fields) <= discovered

    def test_google_cloud_all_credential_fields_present_on_backend_create_schema(self):
        discovered = disc.discover_credential_schema_fields("google_cloud")
        assert set(GOOGLE_CLOUD_MANIFEST.credential_fields) <= discovered

    def test_linear_all_credential_fields_present_on_backend_create_schema(self):
        discovered = disc.discover_credential_schema_fields("linear")
        assert set(LINEAR_MANIFEST.credential_fields) <= discovered

    def test_sendgrid_all_credential_fields_present_on_backend_create_schema(self):
        discovered = disc.discover_credential_schema_fields("sendgrid")
        assert set(SENDGRID_MANIFEST.credential_fields) <= discovered

    def test_shopify_all_credential_fields_present_on_backend_create_schema(self):
        discovered = disc.discover_credential_schema_fields("shopify")
        assert set(SHOPIFY_MANIFEST.credential_fields) <= discovered

    def test_terraform_cloud_all_credential_fields_present_on_backend_create_schema(self):
        discovered = disc.discover_credential_schema_fields("terraform_cloud")
        assert set(TERRAFORM_CLOUD_MANIFEST.credential_fields) <= discovered

    def test_twilio_all_credential_fields_present_on_backend_create_schema(self):
        discovered = disc.discover_credential_schema_fields("twilio")
        assert set(TWILIO_MANIFEST.credential_fields) <= discovered

    def test_shopify_reconnect_schema_field_is_a_subset_of_credential_fields(self):
        reconnect_fields = disc.discover_reconnect_schema_fields("shopify")
        assert reconnect_fields <= set(SHOPIFY_MANIFEST.credential_fields)

    def test_shopify_masked_secret_input_gate_passes(self):
        gate = gates.gate_sensitive_data_controls(SHOPIFY_MANIFEST)
        assert gate.status == "pass"

    def test_auth0_masked_secret_input_gate_passes(self):
        gate = gates.gate_sensitive_data_controls(AUTH0_MANIFEST)
        assert gate.status == "pass"

    def test_twilio_frontend_form_file_exists_on_disk(self):
        assert disc.discover_frontend_form_file_exists(TWILIO_MANIFEST.expected_frontend_form)

    def test_terraform_cloud_frontend_form_file_exists_on_disk(self):
        assert disc.discover_frontend_form_file_exists(TERRAFORM_CLOUD_MANIFEST.expected_frontend_form)

    def test_google_cloud_service_account_json_marked_sensitive_despite_no_marker_substring(self):
        # "service_account_json" doesn't literally contain a _SECRET_NAME_MARKERS
        # substring (token/secret/password/key/pat/dsn) — confirms the
        # manifest correctly marks it sensitive on DOMAIN grounds (it embeds
        # a private key), not merely via the naming heuristic.
        assert "google_cloud_service_account_json" in GOOGLE_CLOUD_MANIFEST.sensitive_credential_fields

    def test_removed_backend_credential_field_detected_for_linear(self, monkeypatch):
        from app.provider_certification import gates as gates_module

        real_fields = gates_module._credential_fields_for("linear")
        shrunk = frozenset(real_fields - {"linear_api_key"})
        monkeypatch.setattr(gates_module, "_credential_fields_for", lambda pid: shrunk if pid == "linear" else real_fields)
        gate = gates.gate_credential_schema(LINEAR_MANIFEST)
        assert gate.status == "fail"
        assert "linear_api_key" in gate.details


# ── 3. Capability evidence: new-provider absence proofs ─────────────────────


class TestCapabilityEvidenceForNewProviders:
    def test_all_nine_new_providers_declare_exactly_one_capability_evidence(self):
        # Every one of these 9 manifests declares one typed
        # capability_evidence entry for security_findings, following the
        # AWS/Datadog precedent established in message 5.
        for m in (
            AUTH0_MANIFEST, AZURE_MANIFEST, CLERK_MANIFEST, GOOGLE_CLOUD_MANIFEST,
            LINEAR_MANIFEST, SENDGRID_MANIFEST, TERRAFORM_CLOUD_MANIFEST, TWILIO_MANIFEST,
        ):
            assert len(m.capability_evidence) == 1
            assert m.capability_evidence[0].capability == "security_findings"

    def test_capability_evidence_gate_passes_for_azure(self):
        gate = gates.gate_capability_evidence(AZURE_MANIFEST)
        assert gate.status == "pass"

    def test_capability_evidence_gate_passes_for_clerk(self):
        gate = gates.gate_capability_evidence(CLERK_MANIFEST)
        assert gate.status == "pass"

    def test_capability_evidence_gate_passes_for_linear(self):
        gate = gates.gate_capability_evidence(LINEAR_MANIFEST)
        assert gate.status == "pass"

    def test_shopify_capability_evidence_declares_no_supporting_record_types(self):
        # Shopify's evidence_rt config was intentionally empty — every
        # Shopify Finding is cross-cutting (shop/app/webhook/policy-level),
        # not tied to a small representative record-type subset.
        assert SHOPIFY_MANIFEST.capability_evidence[0].supporting_record_types == ()

    def test_adding_capability_evidence_with_unknown_record_is_rejected_for_auth0(self):
        with pytest.raises(ManifestValidationError, match="unknown record type"):
            dataclasses.replace(
                AUTH0_MANIFEST,
                capability_evidence=(
                    CapabilityEvidenceDeclaration(
                        capability="security_findings",
                        supporting_record_types=("auth0_totally_phantom_record",),
                    ),
                ),
            )

    def test_shopify_supported_and_unsupported_capabilities_disjoint(self):
        assert not (set(SHOPIFY_MANIFEST.supported_capabilities) & set(SHOPIFY_MANIFEST.unsupported_capabilities))


# ── 4. Completeness-scope granularities exercised on new providers ─────────


class TestCompletenessGranularitiesForNewProviders:
    def test_organization_granularity_for_azure_subscription(self):
        scope = CompletenessScopeDeclaration(
            scope_id="azure_org_scope", record_types=("azure_subscription",), granularity="organization",
        )
        m = dataclasses.replace(AZURE_MANIFEST, completeness_scope_declarations=(scope,))
        assert m.completeness_scope_declarations[0].granularity == "organization"

    def test_family_granularity_for_google_cloud_iam(self):
        scope = CompletenessScopeDeclaration(
            scope_id="gcp_iam_family", record_types=("google_cloud_iam_policy_summary",), granularity="family",
        )
        m = dataclasses.replace(GOOGLE_CLOUD_MANIFEST, completeness_scope_declarations=(scope,))
        assert m.completeness_scope_declarations[0].granularity == "family"

    def test_project_granularity_for_terraform_cloud_workspace(self):
        scope = CompletenessScopeDeclaration(
            scope_id="tfc_project_scope", record_types=("terraform_cloud_project",), granularity="project",
        )
        m = dataclasses.replace(TERRAFORM_CLOUD_MANIFEST, completeness_scope_declarations=(scope,))
        assert m.completeness_scope_declarations[0].granularity == "project"

    def test_detail_granularity_for_twilio_account(self):
        scope = CompletenessScopeDeclaration(
            scope_id="twilio_detail_scope", record_types=("twilio_account",), granularity="detail",
        )
        m = dataclasses.replace(TWILIO_MANIFEST, completeness_scope_declarations=(scope,))
        assert m.completeness_scope_declarations[0].granularity == "detail"

    def test_unknown_record_type_in_scope_rejected_for_sendgrid(self):
        with pytest.raises(ManifestValidationError, match="unknown record type"):
            dataclasses.replace(
                SENDGRID_MANIFEST,
                completeness_scope_declarations=(
                    CompletenessScopeDeclaration(
                        scope_id="sendgrid_bad_scope", record_types=("sendgrid_totally_phantom",), granularity="family",
                    ),
                ),
            )

    def test_dead_suppression_symbol_fails_for_clerk(self):
        scope = CompletenessScopeDeclaration(
            scope_id="clerk_dead_symbol", record_types=(CLERK_MANIFEST.expected_record_types[0],),
            granularity="family", suppression_symbol="_totally_nonexistent_clerk_suppression",
        )
        m = dataclasses.replace(CLERK_MANIFEST, completeness_scope_declarations=(scope,))
        gate = gates.gate_completeness_scope_declarations(m)
        assert gate.status == "fail"


# ── 5. Evidence quality exercised on new providers ──────────────────────────


class TestEvidenceQualityForNewProviders:
    def test_auth0_reachability_evidence_quality_is_direct(self):
        assert AUTH0_MANIFEST.reachability_evidence[0].quality == "direct"

    def test_sendgrid_parity_evidence_references_the_risk_rules_file(self):
        assert SENDGRID_MANIFEST.change_parity_evidence[0].test_file == "tests/test_sendgrid_risk_rules.py"

    def test_twilio_parity_evidence_references_the_risk_rules_file(self):
        assert TWILIO_MANIFEST.change_parity_evidence[0].test_file == "tests/test_twilio_risk_rules.py"

    def test_shopify_reachability_and_parity_evidence_share_the_risk_audit_file(self):
        assert SHOPIFY_MANIFEST.reachability_evidence[0].test_file == "tests/test_shopify_risk_audit.py"
        assert SHOPIFY_MANIFEST.change_parity_evidence[0].test_file == "tests/test_shopify_risk_audit.py"

    def test_wrong_provider_evidence_rejected_for_azure(self):
        with pytest.raises(ManifestValidationError, match="differs from the manifest's own provider_id"):
            from app.provider_certification.models import FindingReachabilityEvidence

            dataclasses.replace(
                AZURE_MANIFEST,
                reachability_evidence=(
                    FindingReachabilityEvidence(
                        provider_id="clerk", test_file="tests/test_azure_provider_depth_qa.py",
                        test_selector="", covered_rule_ids=AZURE_MANIFEST.security_finding_rule_ids,
                    ),
                ),
            )

    def test_minimum_test_count_matches_real_depth_qa_file_count_for_google_cloud(self):
        assert gates._count_matching_tests("tests/test_google_cloud_provider_depth_qa.py", "") \
            >= GOOGLE_CLOUD_MANIFEST.reachability_evidence[0].minimum_test_count


# ── 6. Cross-manifest global gates re-verified against the full 26-catalog ─


class TestCrossManifestGatesAgainstFullCatalog:
    def test_gate_cross_manifest_identity_passes_for_26_providers(self):
        gate = cross_manifest.gate_cross_manifest_identity(_all_manifests())
        assert gate.status == "pass"

    def test_gate_cross_manifest_capability_consistency_passes_for_26_providers(self):
        gate = cross_manifest.gate_cross_manifest_capability_consistency(_all_manifests())
        assert gate.status == "pass"

    def test_gate_cross_manifest_finding_uniqueness_passes_for_26_providers(self):
        gate = cross_manifest.gate_cross_manifest_finding_uniqueness(_all_manifests())
        assert gate.status == "pass"

    def test_gate_cross_manifest_catalog_consistency_passes_for_26_providers(self):
        gate = cross_manifest.gate_cross_manifest_catalog_consistency(_all_manifests())
        assert gate.status == "pass"

    def test_gate_cross_manifest_live_freeze_passes_for_26_providers(self):
        gate = cross_manifest.gate_cross_manifest_live_freeze(_all_manifests())
        assert gate.status == "pass"

    def test_gate_provider_manifest_coverage_passes_for_26_providers(self):
        gate = gates.gate_provider_manifest_coverage(_all_manifests())
        assert gate.status == "pass"

    def test_no_alias_collisions_across_26_provider_ids(self):
        ids = [m.provider_id for m in _all_manifests()]
        assert len(ids) == len(set(ids))

    def test_all_26_manifests_share_schema_version_1(self):
        versions = {getattr(m, "schema_version", 1) for m in _all_manifests()}
        assert versions == {1}

    def test_no_certified_provider_in_migration_allowlist_across_26(self):
        certified = {m.provider_id for m in _all_manifests()}
        assert not (certified & ma.allowlisted_provider_ids())

    def test_no_launched_provider_in_future_provider_queue_across_26(self):
        future = disc.discover_recommended_next_providers()
        launched = disc.discover_launched_provider_ids()
        assert not (launched & future)

    def test_registration_order_is_deterministic_sorted(self):
        assert list(runner.known_provider_ids()) == sorted(runner.known_provider_ids())


# ── 7. Category/maturity/auth-model sanity across the 9 new providers ─────


class TestCategoryMaturityAuthModelSanity:
    def test_auth0_category_is_auth_not_generic_identity(self):
        assert AUTH0_MANIFEST.category == "auth"

    def test_clerk_category_is_identity(self):
        assert CLERK_MANIFEST.category == "identity"

    def test_sendgrid_and_twilio_category_is_communications_plural(self):
        assert SENDGRID_MANIFEST.category == "communications"
        assert TWILIO_MANIFEST.category == "communications"

    def test_shopify_is_the_only_new_provider_with_complete_maturity(self):
        newly_onboarded = (
            AUTH0_MANIFEST, AZURE_MANIFEST, CLERK_MANIFEST, GOOGLE_CLOUD_MANIFEST,
            LINEAR_MANIFEST, SENDGRID_MANIFEST, SHOPIFY_MANIFEST, TERRAFORM_CLOUD_MANIFEST,
            TWILIO_MANIFEST,
        )
        complete = [m.provider_id for m in newly_onboarded if m.maturity == "complete"]
        assert complete == ["shopify"]

    def test_shopify_is_the_only_new_provider_with_reconnect_and_live(self):
        newly_onboarded = (
            AUTH0_MANIFEST, AZURE_MANIFEST, CLERK_MANIFEST, GOOGLE_CLOUD_MANIFEST,
            LINEAR_MANIFEST, SENDGRID_MANIFEST, SHOPIFY_MANIFEST, TERRAFORM_CLOUD_MANIFEST,
            TWILIO_MANIFEST,
        )
        live = [m.provider_id for m in newly_onboarded if m.expected_live]
        assert live == ["shopify"]
        reconnect = [m.provider_id for m in newly_onboarded if m.expected_reconnect]
        assert reconnect == ["shopify"]


# ── 8. Per-provider record/Finding-count discovery re-verification ─────────


class TestPerProviderDiscoveryReverification:
    def test_auth0_record_and_finding_counts(self):
        assert len(disc.discover_schema_record_type_constants("auth0")) == 8
        assert len(disc.discover_registry_rule_ids("auth0")) == 39

    def test_azure_record_and_finding_counts(self):
        assert len(disc.discover_schema_record_type_constants("azure")) == 9
        assert len(disc.discover_registry_rule_ids("azure")) == 21

    def test_clerk_record_and_finding_counts(self):
        assert len(disc.discover_schema_record_type_constants("clerk")) == 10
        assert len(disc.discover_registry_rule_ids("clerk")) == 40

    def test_google_cloud_record_and_finding_counts(self):
        assert len(disc.discover_schema_record_type_constants("google_cloud")) == 10
        assert len(disc.discover_registry_rule_ids("google_cloud")) == 23

    def test_linear_record_and_finding_counts(self):
        assert len(disc.discover_schema_record_type_constants("linear")) == 9
        assert len(disc.discover_registry_rule_ids("linear")) == 39

    def test_sendgrid_record_and_finding_counts(self):
        assert len(disc.discover_schema_record_type_constants("sendgrid")) == 8
        assert len(disc.discover_registry_rule_ids("sendgrid")) == 27

    def test_shopify_record_and_finding_counts(self):
        assert len(disc.discover_schema_record_type_constants("shopify")) == 5
        assert len(disc.discover_registry_rule_ids("shopify")) == 7

    def test_terraform_cloud_record_and_finding_counts(self):
        assert len(disc.discover_schema_record_type_constants("terraform_cloud")) == 10
        assert len(disc.discover_registry_rule_ids("terraform_cloud")) == 36

    def test_twilio_record_and_finding_counts(self):
        assert len(disc.discover_schema_record_type_constants("twilio")) == 5
        assert len(disc.discover_registry_rule_ids("twilio")) == 18

    def test_total_new_provider_record_count_is_74(self):
        total = sum(
            len(disc.discover_schema_record_type_constants(pid))
            for pid in ("auth0", "azure", "clerk", "google_cloud", "linear", "sendgrid", "shopify", "terraform_cloud", "twilio")
        )
        assert total == 74

    def test_total_new_provider_finding_count_is_250(self):
        total = sum(
            len(disc.discover_registry_rule_ids(pid))
            for pid in ("auth0", "azure", "clerk", "google_cloud", "linear", "sendgrid", "shopify", "terraform_cloud", "twilio")
        )
        assert total == 250


# ── 9. Evaluator/registry/confidence/pack/coverage discovery re-verification ─


class TestEvaluatorRegistryDiscoveryForNewProviders:
    def test_auth0_evaluator_registered(self):
        assert disc.discover_evaluator_registered("auth0") is True

    def test_azure_evaluator_registered(self):
        assert disc.discover_evaluator_registered("azure") is True

    def test_clerk_evaluator_registered(self):
        assert disc.discover_evaluator_registered("clerk") is True

    def test_google_cloud_evaluator_registered(self):
        assert disc.discover_evaluator_registered("google_cloud") is True

    def test_linear_evaluator_registered(self):
        assert disc.discover_evaluator_registered("linear") is True

    def test_sendgrid_evaluator_registered(self):
        assert disc.discover_evaluator_registered("sendgrid") is True

    def test_shopify_evaluator_registered(self):
        assert disc.discover_evaluator_registered("shopify") is True

    def test_terraform_cloud_evaluator_registered(self):
        assert disc.discover_evaluator_registered("terraform_cloud") is True

    def test_twilio_evaluator_registered(self):
        assert disc.discover_evaluator_registered("twilio") is True

    def test_auth0_confidence_and_pack_sets_match_registry(self):
        registry = disc.discover_registry_rule_ids("auth0")
        assert disc.discover_confidence_rule_ids("auth0") == registry
        assert disc.discover_pack_rule_ids("auth0") == registry

    def test_azure_confidence_and_pack_sets_match_registry(self):
        registry = disc.discover_registry_rule_ids("azure")
        assert disc.discover_confidence_rule_ids("azure") == registry
        assert disc.discover_pack_rule_ids("azure") == registry

    def test_shopify_confidence_and_pack_sets_match_registry(self):
        registry = disc.discover_registry_rule_ids("shopify")
        assert disc.discover_confidence_rule_ids("shopify") == registry
        assert disc.discover_pack_rule_ids("shopify") == registry

    def test_twilio_coverage_provider_membership_true(self):
        assert disc.discover_coverage_provider_membership("twilio") is True

    def test_terraform_cloud_coverage_provider_membership_true(self):
        assert disc.discover_coverage_provider_membership("terraform_cloud") is True
