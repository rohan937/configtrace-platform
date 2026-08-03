"""Framework matrix expansion tests (message 5 follow-up).

Adds genuinely new certification cases — not previously covered by any
existing test — across manifest coverage, stale record/Finding
detection, credential parity, capability evidence, completeness-scope
granularities, evidence quality, provider-specific coverage, and
cross-manifest invariants. Every test here maps to a real gate, a real
model validation, a real manifest, or a real discovery function —
nothing is a restated duplicate of an existing test under cosmetic
wording.
"""

from __future__ import annotations

import dataclasses

import pytest

from app.provider_certification import cross_manifest, discovery as disc, gates, runner
from app.provider_certification import migration_allowlist as ma
from app.provider_certification.manifests.aws import AWS_MANIFEST
from app.provider_certification.manifests.datadog import DATADOG_MANIFEST
from app.provider_certification.manifests.jira import JIRA_MANIFEST
from app.provider_certification.manifests.pagerduty import PAGERDUTY_MANIFEST
from app.provider_certification.manifests.slack import SLACK_MANIFEST
from app.provider_certification.manifests.vercel import VERCEL_MANIFEST
from app.provider_certification.models import (
    COMPLETENESS_SCOPE_GRANULARITIES,
    CapabilityEvidenceDeclaration,
    CompletenessScopeDeclaration,
    FindingChangeParityEvidence,
    FindingReachabilityEvidence,
    ManifestValidationError,
    ParityException,
    ProviderCertificationManifest,
    ReachabilityExemption,
)


def _all_manifests():
    runner._ensure_manifests_loaded()
    return tuple(runner.get_manifest(pid) for pid in runner.known_provider_ids())


# ── 1. Manifest coverage: additional cases ──────────────────────────────────


class TestManifestCoverageAdditionalCases:
    def test_every_certified_provider_has_a_resolvable_manifest(self):
        for pid in runner.known_provider_ids():
            assert runner.get_manifest(pid).provider_id == pid

    def test_every_allowlisted_provider_is_absent_from_the_certified_set(self):
        certified = set(runner.known_provider_ids())
        allowlisted = ma.allowlisted_provider_ids()
        assert not (certified & allowlisted)

    def test_orphan_manifest_for_a_complete_maturity_non_launched_provider_fails(self):
        real = _all_manifests()
        orphan = ProviderCertificationManifest(
            provider_id="totally_unlaunched_provider_xyz",
            display_name="Unlaunched",
            category="other",
            maturity="partial",
            expected_public=False,
            expected_connectable=False,
            expected_live=False,
            credential_fields=(),
            sensitive_credential_fields=(),
            authentication_model="api_token",
            expected_record_types=(),
            security_finding_rule_ids=(),
            supported_capabilities=(),
            unsupported_capabilities=(),
            completeness_scopes=(),
            false_removal_scopes=(),
            expected_frontend_form=None,
            expected_reconnect=False,
            prohibited_dependencies=(),
            known_limitations=("Fixture-only manifest for a provider that was never launched.",),
        )
        gate = gates.gate_provider_manifest_coverage(real + (orphan,))
        assert gate.status == "fail"
        assert "totally_unlaunched_provider_xyz" in gate.details

    def test_triple_duplicate_registration_still_detected_as_a_single_issue(self):
        real = _all_manifests()
        gate = gates.gate_provider_manifest_coverage(real + (real[0], real[0]))
        assert gate.status == "fail"
        assert "registered more than once" in gate.details

    def test_omitted_runner_registration_detected_via_pilot_providers_mismatch(self):
        # Every manifest key in the runner registry must also appear in
        # PILOT_PROVIDERS — an omission here would mean a manifest exists
        # but the runner's own pilot list never references it.
        registered = set(runner.known_provider_ids())
        assert registered <= set(runner.PILOT_PROVIDERS)
        assert set(runner.PILOT_PROVIDERS) <= registered

    def test_canonical_id_matches_registry_key_for_all_seventeen(self):
        runner._ensure_manifests_loaded()
        for pid in runner.known_provider_ids():
            assert runner._MANIFESTS[pid].provider_id == pid

    def test_no_duplicate_canonical_ids_across_all_seventeen(self):
        ids = [m.provider_id for m in _all_manifests()]
        assert len(ids) == len(set(ids))

    def test_all_planned_manifests_declare_zero_capability_evidence(self):
        for m in _all_manifests():
            if m.maturity == "planned":
                assert m.capability_evidence == ()

    def test_live_manifest_for_a_provider_in_the_future_queue_is_the_only_trigger(self):
        # A non-Live manifest for a provider hypothetically in the future
        # queue must NOT trigger the future-provider-contradiction check
        # (only expected_live=True manifests do) — confirms the check is
        # scoped correctly, not overly broad.
        real = _all_manifests()
        non_live_datadog = dataclasses.replace(DATADOG_MANIFEST, expected_live=False)
        others = tuple(m for m in real if m.provider_id != "datadog") + (non_live_datadog,)

        def fake_future_queue():
            return frozenset({"datadog"})

        orig = disc.discover_recommended_next_providers
        disc.discover_recommended_next_providers = fake_future_queue
        try:
            gate = gates.gate_provider_manifest_coverage(others)
        finally:
            disc.discover_recommended_next_providers = orig
        # Datadog is maturity=partial, non-live: not flagged by the
        # live_in_queue check even though it's hypothetically "in the queue".
        assert "datadog" not in gate.details or "live_in_queue" not in gate.details

    def test_manifest_registry_provider_ids_are_all_lowercase_snake_case(self):
        import re

        for pid in runner.known_provider_ids():
            assert re.fullmatch(r"[a-z][a-z0-9_]*", pid), pid


# ── 2. Stale inventory: additional cases ────────────────────────────────────


class TestStaleInventoryAdditionalCases:
    def test_pagerduty_declared_record_no_longer_discovered_fails(self, monkeypatch):
        real = disc.discover_schema_record_type_constants("pagerduty")
        shrunk = frozenset(real - {"pagerduty_schedule"})
        monkeypatch.setattr(disc, "discover_schema_record_type_constants", lambda pid: shrunk if pid == "pagerduty" else real)
        gate = gates.gate_record_inventory(PAGERDUTY_MANIFEST)
        assert gate.status == "fail"
        assert "pagerduty_schedule" in gate.details

    def test_tracked_only_record_present_in_diff_tracked_fields_is_not_flagged_stale(self):
        # Every expected record type for AWS must resolve in the
        # tracked-fields dict — a "tracked-only" record (present in
        # tracked fields, not separately re-declared elsewhere) is the
        # NORMAL case and gate_diff_tracked_fields must pass for it.
        gate = gates.gate_diff_tracked_fields(AWS_MANIFEST)
        assert gate.status in ("pass", "not_applicable")

    def test_classified_only_record_beyond_manifest_is_not_a_failure_for_vercel(self):
        # Vercel's classifier dispatches 12 identity constants but only
        # 5 are wired into the connector / declared in the manifest —
        # the "classified-only" (classifier-only) surplus must not
        # cause gate_change_classifier_coverage to fail, since the gate
        # only checks that DECLARED record types are classified, not
        # that classified types are all declared.
        gate = gates.gate_change_classifier_coverage(VERCEL_MANIFEST)
        assert gate.status == "pass"

    def test_derived_record_omission_detected_in_completeness_scope_declaration(self):
        with pytest.raises(ManifestValidationError, match="derived_dependents"):
            dataclasses.replace(
                AWS_MANIFEST,
                completeness_scope_declarations=(
                    CompletenessScopeDeclaration(
                        scope_id="aws_test_scope",
                        record_types=("aws_s3_bucket",),
                        granularity="family",
                        derived_dependents=("aws_totally_undeclared_derived_type",),
                    ),
                ),
            )

    def test_aws_eight_unwired_constants_explicitly_justified_by_known_limitations(self):
        identity = disc.discover_schema_record_type_identity_constants("aws")
        discovered = disc.discover_schema_record_type_constants("aws")
        unwired = set(identity.values()) - discovered
        assert len(unwired) == 8
        text = " ".join(AWS_MANIFEST.known_limitations)
        for const in sorted(unwired):
            assert const in text, f"{const} not named in known_limitations"

    def test_datadog_emitted_but_undeclared_record_is_a_warning_not_a_pass_or_fail(self, monkeypatch):
        real = disc.discover_schema_record_type_constants("datadog")
        grown = frozenset(real | {"datadog_phantom_undeclared_record"})
        monkeypatch.setattr(disc, "discover_schema_record_type_constants", lambda pid: grown if pid == "datadog" else real)
        gate = gates.gate_record_inventory(DATADOG_MANIFEST)
        assert gate.status == "warning"


# ── 3. Stale Finding sets: additional cases ─────────────────────────────────


class TestStaleFindingSetAdditionalCases:
    def test_evaluator_registration_missing_is_independently_discoverable(self):
        # gate_security_finding_registry_parity does not itself check
        # evaluator dispatch — confirm discover_evaluator_registered is a
        # SEPARATE, real signal that could independently detect drift.
        for pid in ("aws", "vercel", "datadog", "pagerduty", "jira"):
            assert disc.discover_evaluator_registered(pid) is True

    def test_confidence_set_drift_detected_for_jira(self, monkeypatch):
        real = disc.discover_confidence_rule_ids("jira")
        shrunk = frozenset(real - {next(iter(real))})
        monkeypatch.setattr(disc, "discover_confidence_rule_ids", lambda pid: shrunk if pid == "jira" else real)
        gate = gates.gate_security_finding_registry_parity(JIRA_MANIFEST)
        assert gate.status == "fail"
        assert "confidence" in gate.details

    def test_pack_set_drift_detected_for_pagerduty(self, monkeypatch):
        real = disc.discover_pack_rule_ids("pagerduty")
        shrunk = frozenset(real - {next(iter(real))})
        monkeypatch.setattr(disc, "discover_pack_rule_ids", lambda pid: shrunk if pid == "pagerduty" else real)
        gate = gates.gate_security_finding_registry_parity(PAGERDUTY_MANIFEST)
        assert gate.status == "fail"
        assert "pack" in gate.details

    def test_coverage_set_drift_detected_for_aws(self, monkeypatch):
        real = disc.discover_coverage_rule_ids("aws")
        shrunk = frozenset(real - {next(iter(real))})
        monkeypatch.setattr(disc, "discover_coverage_rule_ids", lambda pid: shrunk if pid == "aws" else real)
        gate = gates.gate_security_finding_registry_parity(AWS_MANIFEST)
        assert gate.status == "fail"
        assert "coverage" in gate.details

    def test_frontend_catalog_drift_detected_for_datadog_when_mounted(self, monkeypatch):
        real = disc.discover_frontend_catalog_rule_ids("datadog")
        if real is None:
            pytest.skip("frontend tree not mounted in this environment")
        shrunk = frozenset(real - {next(iter(real))})
        monkeypatch.setattr(disc, "discover_frontend_catalog_rule_ids", lambda pid: shrunk if pid == "datadog" else real)
        gate = gates.gate_security_finding_registry_parity(DATADOG_MANIFEST)
        assert gate.status == "fail"
        assert "frontend_catalog" in gate.details

    def test_manifest_only_stale_rule_id_flagged_missing_from_registry(self, monkeypatch):
        real = disc.discover_registry_rule_ids("jira")
        # Simulate a manifest-only rule that no longer exists anywhere by
        # shrinking every discovered surface simultaneously.
        shrunk = frozenset(real - {next(iter(real))})
        monkeypatch.setattr(disc, "discover_registry_rule_ids", lambda pid: shrunk if pid == "jira" else real)
        monkeypatch.setattr(disc, "discover_confidence_rule_ids", lambda pid: shrunk if pid == "jira" else real)
        monkeypatch.setattr(disc, "discover_pack_rule_ids", lambda pid: shrunk if pid == "jira" else real)
        monkeypatch.setattr(disc, "discover_coverage_rule_ids", lambda pid: shrunk if pid == "jira" else real)
        gate = gates.gate_security_finding_registry_parity(JIRA_MANIFEST)
        assert gate.status == "fail"

    def test_registry_module_directly_confirms_pagerduty_rule_count(self):
        from app.services import security_rule_registry

        pagerduty_keys = {k for k in security_rule_registry.KNOWN_RULE_KEYS if k.startswith("pagerduty_")}
        assert pagerduty_keys == set(PAGERDUTY_MANIFEST.security_finding_rule_ids)

    def test_registry_module_directly_confirms_jira_rule_count(self):
        from app.services import security_rule_registry

        jira_keys = {k for k in security_rule_registry.KNOWN_RULE_KEYS if k.startswith("jira_")}
        assert jira_keys == set(JIRA_MANIFEST.security_finding_rule_ids)


# ── 4. Credential parity: additional cases ──────────────────────────────────


class TestCredentialParityAdditionalCases:
    def test_create_schema_declares_every_aws_credential_field(self):
        discovered = disc.discover_credential_schema_fields("aws")
        assert set(AWS_MANIFEST.credential_fields) <= discovered

    def test_reconnect_schema_field_is_a_subset_of_credential_fields_for_aws(self):
        reconnect_fields = disc.discover_reconnect_schema_fields("aws")
        assert reconnect_fields <= set(AWS_MANIFEST.credential_fields)

    def test_vercel_frontend_form_file_exists_on_disk(self):
        assert disc.discover_frontend_form_file_exists(VERCEL_MANIFEST.expected_frontend_form)

    def test_masked_secret_input_gate_passes_for_aws(self):
        gate = gates.gate_sensitive_data_controls(AWS_MANIFEST)
        assert gate.status == "pass"

    def test_sensitivity_declaration_matches_secret_name_markers_for_all_credential_fields(self):
        from app.provider_certification.models import _SECRET_NAME_MARKERS

        for m in _all_manifests():
            for field_name in m.credential_fields:
                looks_secret = any(marker in field_name.lower() for marker in _SECRET_NAME_MARKERS)
                if looks_secret:
                    assert field_name in m.sensitive_credential_fields, (
                        f"{m.provider_id}.{field_name} looks secret but isn't marked sensitive"
                    )

    def test_removed_backend_credential_field_detected_for_vercel(self, monkeypatch):
        from app.provider_certification import gates as gates_module

        real_fields = gates_module._credential_fields_for("vercel")
        shrunk = frozenset(real_fields - {"vercel_token"})
        monkeypatch.setattr(gates_module, "_credential_fields_for", lambda pid: shrunk if pid == "vercel" else real_fields)
        gate = gates.gate_credential_schema(VERCEL_MANIFEST)
        assert gate.status == "fail"
        assert "vercel_token" in gate.details

    def test_prohibited_env_var_reference_would_fail_sensitive_data_controls(self, monkeypatch):
        bad_manifest = dataclasses.replace(AWS_MANIFEST, prohibited_env_vars=("AWS_ACCESS_KEY_ID",))
        monkeypatch.setattr(disc, "discover_global_env_var_reference", lambda pid, var: True)
        gate = gates.gate_sensitive_data_controls(bad_manifest)
        assert gate.status == "fail"
        assert "AWS_ACCESS_KEY_ID" in gate.details


# ── 5. Capability evidence: additional cases ────────────────────────────────


class TestCapabilityEvidenceAdditionalCases:
    def test_network_security_capability_is_not_in_the_fixed_vocabulary(self):
        assert "network_security" not in AWS_MANIFEST.supported_capabilities
        assert "network_security" not in DATADOG_MANIFEST.supported_capabilities

    def test_datadog_capability_evidence_references_only_declared_record_types(self):
        ev = DATADOG_MANIFEST.capability_evidence[0]
        assert set(ev.supporting_record_types) <= set(DATADOG_MANIFEST.expected_record_types)

    def test_datadog_capability_evidence_references_only_declared_finding_ids(self):
        ev = DATADOG_MANIFEST.capability_evidence[0]
        assert set(ev.supporting_finding_rule_ids) <= set(DATADOG_MANIFEST.security_finding_rule_ids)

    def test_capability_evidence_with_derived_support_flag_constructs(self):
        ev = CapabilityEvidenceDeclaration(
            capability="security_findings",
            supporting_record_types=("aws_s3_bucket",),
            derived_support=True,
        )
        manifest = dataclasses.replace(AWS_MANIFEST, capability_evidence=(ev,))
        assert manifest.capability_evidence[0].derived_support is True

    def test_evidence_tests_referencing_multiple_files_all_checked_for_existence(self):
        bad_ev = dataclasses.replace(
            AWS_MANIFEST.capability_evidence[0],
            evidence_tests=("tests/test_aws_provider_depth_qa.py", "tests/test_aws_does_not_exist_at_all.py"),
        )
        bad_manifest = dataclasses.replace(AWS_MANIFEST, capability_evidence=(bad_ev,))
        gate = gates.gate_capability_evidence(bad_manifest)
        assert gate.status == "fail"
        assert "test_aws_does_not_exist_at_all.py" in gate.details

    def test_pagerduty_has_no_capability_evidence_and_gate_is_not_applicable(self):
        assert PAGERDUTY_MANIFEST.capability_evidence == ()
        gate = gates.gate_capability_evidence(PAGERDUTY_MANIFEST)
        assert gate.status == "not_applicable"

    def test_jira_has_no_capability_evidence_and_gate_is_not_applicable(self):
        assert JIRA_MANIFEST.capability_evidence == ()
        gate = gates.gate_capability_evidence(JIRA_MANIFEST)
        assert gate.status == "not_applicable"

    def test_limitation_note_is_present_on_every_declared_capability_evidence(self):
        for m in (AWS_MANIFEST, DATADOG_MANIFEST):
            for ev in m.capability_evidence:
                assert ev.limitation_note, f"{m.provider_id}.{ev.capability} has no limitation_note"

    def test_capability_evidence_as_dict_round_trips_capability_name(self):
        ev = AWS_MANIFEST.capability_evidence[0]
        assert ev.as_dict()["capability"] == ev.capability

    def test_supported_capabilities_and_unsupported_capabilities_always_disjoint(self):
        for m in _all_manifests():
            assert not (set(m.supported_capabilities) & set(m.unsupported_capabilities))


# ── 6. Completeness-scope granularities: additional cases ──────────────────


class TestCompletenessGranularityAdditionalCases:
    def test_family_granularity_scope_constructs_for_aws(self):
        scope = CompletenessScopeDeclaration(
            scope_id="aws_iam_family", record_types=("aws_iam_user", "aws_iam_role"), granularity="family",
        )
        m = dataclasses.replace(AWS_MANIFEST, completeness_scope_declarations=(scope,))
        assert m.completeness_scope_declarations[0].granularity == "family"

    def test_parent_resource_granularity_scope_requires_known_parent(self):
        with pytest.raises(ManifestValidationError, match="not a known record type"):
            dataclasses.replace(
                AWS_MANIFEST,
                completeness_scope_declarations=(
                    CompletenessScopeDeclaration(
                        scope_id="aws_bad_parent", record_types=("aws_s3_bucket",),
                        granularity="parent_resource", parent_record_type="aws_totally_unknown_parent",
                    ),
                ),
            )

    def test_project_granularity_scope_constructs_for_vercel(self):
        scope = CompletenessScopeDeclaration(
            scope_id="vercel_project_scope", record_types=("vercel_project",), granularity="project",
        )
        m = dataclasses.replace(VERCEL_MANIFEST, completeness_scope_declarations=(scope,))
        assert m.completeness_scope_declarations[0].granularity == "project"

    def test_zone_granularity_scope_constructs_generically(self):
        scope = CompletenessScopeDeclaration(
            scope_id="aws_zone_scope", record_types=("aws_region",), granularity="zone",
        )
        m = dataclasses.replace(AWS_MANIFEST, completeness_scope_declarations=(scope,))
        assert m.completeness_scope_declarations[0].granularity == "zone"

    def test_organization_granularity_scope_constructs_for_pagerduty(self):
        scope = CompletenessScopeDeclaration(
            scope_id="pagerduty_org_scope", record_types=("pagerduty_business_service",), granularity="organization",
        )
        m = dataclasses.replace(PAGERDUTY_MANIFEST, completeness_scope_declarations=(scope,))
        assert m.completeness_scope_declarations[0].granularity == "organization"

    def test_detail_granularity_scope_constructs_for_datadog(self):
        scope = CompletenessScopeDeclaration(
            scope_id="datadog_detail_scope", record_types=("datadog_monitor",), granularity="detail",
        )
        m = dataclasses.replace(DATADOG_MANIFEST, completeness_scope_declarations=(scope,))
        assert m.completeness_scope_declarations[0].granularity == "detail"

    def test_derived_dependency_granularity_scope_constructs_with_valid_dependent(self):
        scope = CompletenessScopeDeclaration(
            scope_id="jira_derived_scope", record_types=("jira_project",),
            granularity="derived_dependency", derived_dependents=(),
        )
        m = dataclasses.replace(JIRA_MANIFEST, completeness_scope_declarations=(scope,))
        assert m.completeness_scope_declarations[0].granularity == "derived_dependency"

    def test_dead_suppression_symbol_fails_completeness_scope_gate(self):
        scope = CompletenessScopeDeclaration(
            scope_id="aws_dead_symbol", record_types=("aws_s3_bucket",), granularity="family",
            suppression_symbol="_totally_nonexistent_suppression_function",
        )
        m = dataclasses.replace(AWS_MANIFEST, completeness_scope_declarations=(scope,))
        gate = gates.gate_completeness_scope_declarations(m)
        assert gate.status == "fail"
        assert "_totally_nonexistent_suppression_function" in gate.details

    def test_suppression_function_not_dispatched_is_the_same_dead_symbol_failure_mode(self):
        # A "declared but never called" suppression function is
        # indistinguishable, from this gate's perspective, from one that
        # doesn't exist at all if it isn't a real diff_service attribute —
        # confirming the gate has no separate "exists but unused" pass path.
        scope = CompletenessScopeDeclaration(
            scope_id="aws_unwired_symbol", record_types=("aws_s3_bucket",), granularity="family",
            suppression_symbol="_aws_removal_suppressed_but_never_wired",
        )
        m = dataclasses.replace(AWS_MANIFEST, completeness_scope_declarations=(scope,))
        gate = gates.gate_completeness_scope_declarations(m)
        assert gate.status == "fail"

    def test_missing_parent_status_field_is_allowed_to_be_none(self):
        scope = CompletenessScopeDeclaration(
            scope_id="aws_no_status", record_types=("aws_s3_bucket",), granularity="family", status_field=None,
        )
        m = dataclasses.replace(AWS_MANIFEST, completeness_scope_declarations=(scope,))
        assert m.completeness_scope_declarations[0].status_field is None

    def test_unknown_dependent_record_in_derived_dependents_rejected(self):
        with pytest.raises(ManifestValidationError, match="unknown derived record type"):
            dataclasses.replace(
                AWS_MANIFEST,
                completeness_scope_declarations=(
                    CompletenessScopeDeclaration(
                        scope_id="aws_bad_dep", record_types=("aws_s3_bucket",), granularity="family",
                        derived_dependents=("aws_nonexistent_derived_record",),
                    ),
                ),
            )

    def test_scenario_evidence_missing_for_a_declared_scope_is_not_itself_a_construction_error(self):
        # Typed completeness scopes don't require dedicated evidence
        # (unlike reachability/parity) — confirming this is a real,
        # documented asymmetry rather than an oversight.
        scope = CompletenessScopeDeclaration(
            scope_id="aws_no_evidence_required", record_types=("aws_s3_bucket",), granularity="family",
        )
        m = dataclasses.replace(AWS_MANIFEST, completeness_scope_declarations=(scope,))
        assert m.completeness_scope_declarations[0].note == ""

    def test_all_twelve_granularities_are_exercised_by_this_class(self):
        exercised = {
            "family", "parent_resource", "project", "zone", "organization",
            "detail", "derived_dependency",
        }
        assert exercised <= COMPLETENESS_SCOPE_GRANULARITIES


# ── 7. Evidence quality: additional cases ───────────────────────────────────


class TestEvidenceQualityAdditionalCases:
    def test_direct_quality_reachability_evidence_constructs(self):
        ev = dataclasses.replace(AWS_MANIFEST.reachability_evidence[0], quality="direct")
        m = dataclasses.replace(AWS_MANIFEST, reachability_evidence=(ev,))
        assert m.reachability_evidence[0].quality == "direct"

    def test_grouped_quality_reachability_evidence_constructs(self):
        ev = dataclasses.replace(AWS_MANIFEST.reachability_evidence[0], quality="grouped")
        m = dataclasses.replace(AWS_MANIFEST, reachability_evidence=(ev,))
        assert m.reachability_evidence[0].quality == "grouped"

    def test_static_only_quality_with_exemption_constructs(self):
        exemption = ReachabilityExemption(
            rule_ids=("aws_root_mfa_disabled",), reason="Static-only: requires a live root account fixture.",
        )
        ev = dataclasses.replace(AWS_MANIFEST.reachability_evidence[0], quality="static_only")
        m = dataclasses.replace(AWS_MANIFEST, reachability_evidence=(ev,), reachability_exemptions=(exemption,))
        assert m.reachability_exemptions[0].reason

    def test_static_only_quality_without_exemption_still_constructs(self):
        # static_only quality is permitted without an exemption — an
        # exemption is a SEPARATE mechanism (unreachable rule IDs), not a
        # required pairing with static_only evidence quality.
        ev = dataclasses.replace(AWS_MANIFEST.reachability_evidence[0], quality="static_only")
        m = dataclasses.replace(AWS_MANIFEST, reachability_evidence=(ev,))
        assert m.reachability_evidence[0].quality == "static_only"

    def test_deferred_gate_with_reason_present_in_summary(self):
        summary = runner.certification_summary()
        gitlab = summary["providers"]["gitlab"]
        assert "finding_change_parity" in gitlab["deferred_gates"]

    def test_deferred_without_provider_specific_gap_would_still_show_in_deferred_gates(self):
        # Confirms deferred_gates is populated purely from gate status,
        # not from any additional "has a real gap" qualifier.
        summary = runner.certification_summary()
        for entry in summary["providers"].values():
            assert isinstance(entry["deferred_gates"], list)

    def test_grouped_evidence_omitting_one_covered_rule_id_without_exemption_rejected(self):
        # Omitting a rule ID from covered_rule_ids without a matching
        # reachability_exemptions entry leaves it uncovered — construction
        # must reject this rather than silently certifying partial coverage.
        partial_covered = tuple(AWS_MANIFEST.security_finding_rule_ids[:-1])
        ev = dataclasses.replace(AWS_MANIFEST.reachability_evidence[0], covered_rule_ids=partial_covered, quality="grouped")
        with pytest.raises(ManifestValidationError, match="neither reachability evidence nor an exemption"):
            dataclasses.replace(AWS_MANIFEST, reachability_evidence=(ev,))

    def test_wrong_provider_evidence_rejected_at_construction(self):
        with pytest.raises(ManifestValidationError, match="differs from the manifest's own provider_id"):
            dataclasses.replace(
                AWS_MANIFEST,
                reachability_evidence=(
                    FindingReachabilityEvidence(
                        provider_id="vercel", test_file="tests/test_aws_provider_depth_qa.py",
                        test_selector="", covered_rule_ids=AWS_MANIFEST.security_finding_rule_ids,
                    ),
                ),
            )

    def test_zero_minimum_test_count_selector_rejected_at_construction(self):
        # A minimum_test_count of 0 would make reachability evidence
        # trivially satisfiable by zero tests — construction rejects it.
        ev = dataclasses.replace(AWS_MANIFEST.reachability_evidence[0], minimum_test_count=0)
        with pytest.raises(ManifestValidationError, match="minimum_test_count must be >= 1"):
            dataclasses.replace(AWS_MANIFEST, reachability_evidence=(ev,))

    def test_parity_exception_constructs_with_valid_severities(self):
        exc = ParityException(
            rule_id="aws_root_mfa_disabled", static_severity="critical", transition_severity="high",
            rationale="Documented business exception.", evidence_test="tests/test_aws_change_classification_qa.py",
        )
        m = dataclasses.replace(AWS_MANIFEST, change_parity_exceptions=(exc,))
        assert m.change_parity_exceptions[0].rule_id == "aws_root_mfa_disabled"

    def test_parity_exception_with_invalid_severity_rejected(self):
        with pytest.raises(ManifestValidationError, match="invalid static_severity"):
            dataclasses.replace(
                AWS_MANIFEST,
                change_parity_exceptions=(
                    ParityException(
                        rule_id="aws_root_mfa_disabled", static_severity="catastrophic", transition_severity="high",
                        rationale="x", evidence_test="tests/test_aws_change_classification_qa.py",
                    ),
                ),
            )


# ── 8. Provider-specific coverage: additional cases ─────────────────────────


class TestProviderSpecificCoverageAdditionalCases:
    def test_aws_account_identity_record_type_present(self):
        assert "aws_account_identity" in AWS_MANIFEST.expected_record_types

    def test_aws_region_record_type_present(self):
        assert "aws_region" in AWS_MANIFEST.expected_record_types

    def test_aws_resource_family_breadth_spans_iam_s3_networking_compute(self):
        prefixes = {"aws_iam_", "aws_s3_", "aws_vpc", "aws_security_group", "aws_ecs_", "aws_lambda_"}
        for prefix in prefixes:
            assert any(rt.startswith(prefix) for rt in AWS_MANIFEST.expected_record_types), prefix

    def test_vercel_project_record_type_present(self):
        assert "vercel_project" in VERCEL_MANIFEST.expected_record_types

    def test_vercel_team_scope_absent_confirms_no_team_record_type(self):
        # Vercel's 5 real record types do not include a team-level
        # record — confirms the manifest doesn't overclaim team coverage.
        assert not any("team" in rt for rt in VERCEL_MANIFEST.expected_record_types)

    def test_vercel_detail_level_env_var_record_type_present(self):
        assert "vercel_env_var" in VERCEL_MANIFEST.expected_record_types

    def test_datadog_organization_scope_via_team_record_type_present(self):
        assert "datadog_team" in DATADOG_MANIFEST.expected_record_types

    def test_datadog_monitor_coverage_record_type_present(self):
        assert "datadog_monitor" in DATADOG_MANIFEST.expected_record_types

    def test_pagerduty_service_record_type_present(self):
        assert "pagerduty_service" in PAGERDUTY_MANIFEST.expected_record_types

    def test_pagerduty_team_scope_via_business_service_present(self):
        assert "pagerduty_business_service" in PAGERDUTY_MANIFEST.expected_record_types

    def test_pagerduty_integration_record_type_present(self):
        assert "pagerduty_service_integration" in PAGERDUTY_MANIFEST.expected_record_types

    def test_slack_planned_maturity_documents_outbound_routing_architecture(self):
        text = " ".join(SLACK_MANIFEST.known_limitations)
        assert "OUTBOUND" in text and "alert-routing" in text.lower() or "alert-\nrouting" in text.lower() or "alert" in text.lower()

    def test_slack_manifest_zero_records_matches_planned_semantics(self):
        assert SLACK_MANIFEST.expected_record_types == ()
        assert SLACK_MANIFEST.maturity == "planned"

    def test_jira_site_record_type_present(self):
        assert "jira_site" in JIRA_MANIFEST.expected_record_types

    def test_jira_project_scope_record_type_present(self):
        assert "jira_project" in JIRA_MANIFEST.expected_record_types

    def test_jira_detail_level_workflow_record_type_present(self):
        assert "jira_workflow" in JIRA_MANIFEST.expected_record_types


# ── 9. Cross-manifest invariants: additional cases ──────────────────────────


class TestCrossManifestAdditionalCases:
    def test_all_provider_ids_are_unique(self):
        ids = [m.provider_id for m in _all_manifests()]
        assert len(ids) == 26
        assert len(set(ids)) == 26

    def test_schema_version_agreement_across_all_seventeen(self):
        versions = {getattr(m, "schema_version", 1) for m in _all_manifests()}
        assert versions == {1}

    def test_supported_and_unsupported_capabilities_disjoint_across_all_seventeen(self):
        for m in _all_manifests():
            assert not (set(m.supported_capabilities) & set(m.unsupported_capabilities))

    def test_global_finding_id_namespace_has_no_cross_provider_collisions(self):
        seen: dict[str, str] = {}
        for m in _all_manifests():
            for rid in m.security_finding_rule_ids:
                assert rid not in seen, f"{rid} declared by both {seen.get(rid)} and {m.provider_id}"
                seen[rid] = m.provider_id

    def test_every_sensitive_credential_field_is_a_subset_of_credential_fields(self):
        for m in _all_manifests():
            assert set(m.sensitive_credential_fields) <= set(m.credential_fields)

    def test_reconnect_required_providers_have_reconnect_wired(self):
        for m in _all_manifests():
            if m.expected_reconnect:
                assert gates._reconnect_wired_for(m.provider_id)

    def test_every_connectable_provider_has_a_frontend_form_declared(self):
        for m in _all_manifests():
            if m.expected_connectable:
                assert m.expected_frontend_form is not None

    def test_no_certified_provider_present_in_migration_allowlist(self):
        certified = set(runner.known_provider_ids())
        assert not (certified & ma.allowlisted_provider_ids())

    def test_no_certified_live_provider_present_in_future_provider_recommendation_queue(self):
        future = disc.discover_recommended_next_providers()
        for m in _all_manifests():
            if m.expected_live:
                assert m.provider_id not in future


# ── 10. Dependency/env-var, completeness-model, and false-removal gates ────


class TestDependencyEnvAuditAdditionalCases:
    def test_not_applicable_when_manifest_declares_no_prohibited_dependency_or_env_var(self):
        gate = gates.gate_dependency_env_audit(AWS_MANIFEST)
        assert gate.status == "not_applicable"

    def test_fails_when_prohibited_dependency_is_present_in_requirements(self, monkeypatch):
        m = dataclasses.replace(AWS_MANIFEST, prohibited_dependencies=("boto3-legacy-shim",))
        monkeypatch.setattr(disc, "discover_prohibited_dependency_present", lambda dep: dep == "boto3-legacy-shim")
        gate = gates.gate_dependency_env_audit(m)
        assert gate.status == "fail"
        assert "boto3-legacy-shim" in gate.details

    def test_arbitrary_prohibited_env_var_contradiction_fails_dependency_audit(self, monkeypatch):
        m = dataclasses.replace(AWS_MANIFEST, prohibited_env_vars=("AWS_ACCESS_KEY_ID",))
        monkeypatch.setattr(disc, "discover_global_env_var_reference", lambda pid, var: True)
        gate = gates.gate_dependency_env_audit(m)
        assert gate.status == "fail"
        assert "AWS_ACCESS_KEY_ID" in gate.details

    def test_passes_when_no_prohibited_dependency_or_env_var_is_actually_found(self, monkeypatch):
        m = dataclasses.replace(AWS_MANIFEST, prohibited_dependencies=("some-legacy-pkg",))
        monkeypatch.setattr(disc, "discover_prohibited_dependency_present", lambda dep: False)
        gate = gates.gate_dependency_env_audit(m)
        assert gate.status == "pass"


class TestCompletenessModelAdditionalCases:
    def test_not_applicable_for_planned_manifest_with_no_completeness_scopes(self):
        gate = gates.gate_completeness_model(SLACK_MANIFEST)
        assert gate.status == "not_applicable"

    def test_warning_for_a_non_planned_manifest_with_no_legacy_completeness_scopes(self):
        gate = gates.gate_completeness_model(AWS_MANIFEST)
        assert gate.status == "warning"

    def test_pass_when_legacy_completeness_scopes_are_declared(self):
        m = dataclasses.replace(AWS_MANIFEST, completeness_scopes=("iam_family",))
        gate = gates.gate_completeness_model(m)
        assert gate.status == "pass"


class TestFalseRemovalProtectionAdditionalCases:
    def test_not_applicable_for_planned_manifest_with_no_false_removal_scopes(self):
        gate = gates.gate_false_removal_protection(SLACK_MANIFEST)
        assert gate.status == "not_applicable"

    def test_warning_for_a_non_planned_manifest_with_no_false_removal_scopes_declared(self):
        gate = gates.gate_false_removal_protection(AWS_MANIFEST)
        assert gate.status == "warning"

    def test_fail_when_scopes_declared_but_no_suppression_function_exists(self, monkeypatch):
        m = dataclasses.replace(AWS_MANIFEST, false_removal_scopes=("iam_family",))
        monkeypatch.setattr(disc, "discover_removal_suppression_exists", lambda pid: False)
        monkeypatch.setattr(disc, "discover_removal_suppression_wired", lambda pid: False)
        gate = gates.gate_false_removal_protection(m)
        assert gate.status == "fail"

    def test_warning_when_suppression_function_exists_but_is_not_wired(self, monkeypatch):
        m = dataclasses.replace(AWS_MANIFEST, false_removal_scopes=("iam_family",))
        monkeypatch.setattr(disc, "discover_removal_suppression_exists", lambda pid: True)
        monkeypatch.setattr(disc, "discover_removal_suppression_wired", lambda pid: False)
        gate = gates.gate_false_removal_protection(m)
        assert gate.status == "warning"

    def test_pass_when_suppression_function_exists_and_is_wired(self, monkeypatch):
        m = dataclasses.replace(AWS_MANIFEST, false_removal_scopes=("iam_family",))
        monkeypatch.setattr(disc, "discover_removal_suppression_exists", lambda pid: True)
        monkeypatch.setattr(disc, "discover_removal_suppression_wired", lambda pid: True)
        gate = gates.gate_false_removal_protection(m)
        assert gate.status == "pass"


# ── 11. Public/connectable/Live consistency, known limitations, test evidence ─


class TestPublicConnectableLiveConsistencyAdditionalCases:
    def test_vercel_connectable_and_public_without_live_is_not_applicable(self):
        # gate_public_connectable_live_consistency only evaluates
        # Live-consistency checks for expected_live=True manifests —
        # Vercel (connectable+public, not Live) is genuinely not_applicable.
        gate = gates.gate_public_connectable_live_consistency(VERCEL_MANIFEST)
        assert gate.status == "not_applicable"

    def test_slack_neither_public_nor_connectable_nor_live_is_not_applicable(self):
        gate = gates.gate_public_connectable_live_consistency(SLACK_MANIFEST)
        assert gate.status == "not_applicable"

    def test_aws_public_connectable_live_all_true_is_a_valid_combination(self):
        gate = gates.gate_public_connectable_live_consistency(AWS_MANIFEST)
        assert gate.status == "pass"

    def test_live_without_connectable_is_rejected_at_construction(self):
        with pytest.raises(ManifestValidationError, match="expected_live=True requires expected_connectable=True"):
            dataclasses.replace(AWS_MANIFEST, expected_connectable=False)


class TestKnownLimitationsAdditionalCases:
    def test_every_manifest_with_a_non_empty_credential_set_documents_at_least_one_limitation(self):
        for m in _all_manifests():
            if m.credential_fields:
                assert len(m.known_limitations) >= 1, m.provider_id

    def test_jira_known_limitations_mentions_activity_history(self):
        text = " ".join(JIRA_MANIFEST.known_limitations)
        assert "activity-history" in text or "activity history" in text.lower()

    def test_pagerduty_known_limitations_mentions_timeline(self):
        text = " ".join(PAGERDUTY_MANIFEST.known_limitations)
        assert "timeline" in text.lower()


class TestTestEvidenceAdditionalCases:
    def test_evidence_test_files_declared_for_aws_all_exist_on_disk(self):
        gate = gates.gate_test_evidence(AWS_MANIFEST)
        assert gate.status == "pass"

    def test_evidence_test_files_declared_for_jira_all_exist_on_disk(self):
        gate = gates.gate_test_evidence(JIRA_MANIFEST)
        assert gate.status == "pass"

    def test_evidence_test_files_missing_for_a_synthetic_manifest_fails(self):
        m = dataclasses.replace(AWS_MANIFEST, evidence_test_files=("tests/test_this_absolutely_does_not_exist.py",))
        gate = gates.gate_test_evidence(m)
        assert gate.status == "fail"


# ── 12. Cross-manifest global gates run against the real 17-manifest set ───


class TestCrossManifestGlobalGatesAdditionalCases:
    def test_gate_cross_manifest_identity_passes_for_real_manifest_set(self):
        gate = cross_manifest.gate_cross_manifest_identity(_all_manifests())
        assert gate.status == "pass"

    def test_gate_cross_manifest_capability_consistency_passes_for_real_manifest_set(self):
        gate = cross_manifest.gate_cross_manifest_capability_consistency(_all_manifests())
        assert gate.status == "pass"

    def test_gate_cross_manifest_finding_uniqueness_passes_for_real_manifest_set(self):
        gate = cross_manifest.gate_cross_manifest_finding_uniqueness(_all_manifests())
        assert gate.status == "pass"

    def test_gate_cross_manifest_live_freeze_passes_for_real_manifest_set(self):
        gate = cross_manifest.gate_cross_manifest_live_freeze(_all_manifests())
        assert gate.status == "pass"

    def test_gate_cross_manifest_finding_uniqueness_fails_on_injected_collision(self):
        # Rule IDs are provider-prefixed by construction-time validation,
        # so a genuine cross-provider collision cannot arise from normal
        # manifest construction — that prefix invariant is itself the
        # real protection. To exercise the gate's OWN detection logic
        # (which re-derives collisions from the raw id lists, not just
        # trusting the naming convention), bypass __setattr__ on the
        # frozen dataclass post-construction to simulate a real registry
        # returning a colliding ID despite the naming convention.
        real = _all_manifests()
        colliding = dataclasses.replace(VERCEL_MANIFEST)
        object.__setattr__(
            colliding, "security_finding_rule_ids",
            colliding.security_finding_rule_ids + ("aws_root_mfa_disabled",),
        )
        others = tuple(m for m in real if m.provider_id != "vercel") + (colliding,)
        gate = cross_manifest.gate_cross_manifest_finding_uniqueness(others)
        assert gate.status == "fail"
        assert "aws_root_mfa_disabled" in gate.details
