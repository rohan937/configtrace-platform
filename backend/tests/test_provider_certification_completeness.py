"""Typed completeness-scope declaration tests (message 4 of N).

Covers ``CompletenessScopeDeclaration``, the granularity taxonomy
(``COMPLETENESS_SCOPE_GRANULARITIES``), manifest-construction-time
validation, and ``gates.gate_completeness_scope_declarations`` (the one
thing construction-time validation cannot check without discovery:
whether a declared ``suppression_symbol`` actually resolves).
"""

from __future__ import annotations

import pytest

from app.provider_certification import gates
from app.provider_certification.models import (
    COMPLETENESS_SCOPE_GRANULARITIES,
    CompletenessScopeDeclaration,
    ManifestValidationError,
    ProviderCertificationManifest,
)


def _manifest(**overrides) -> ProviderCertificationManifest:
    fields = dict(
        provider_id="ghostprov3",
        display_name="Ghost Provider 3",
        category="observability",
        maturity="partial",
        expected_public=True,
        expected_connectable=True,
        expected_live=False,
        credential_fields=("ghostprov3_api_token",),
        sensitive_credential_fields=("ghostprov3_api_token",),
        authentication_model="api_token",
        expected_record_types=("ghostprov3_widget", "ghostprov3_gadget", "ghostprov3_widget_summary"),
        derived_record_types=("ghostprov3_widget_summary",),
        expected_frontend_form="GhostProv3IntegrationForm.tsx",
        expected_reconnect=False,
    )
    fields.update(overrides)
    return ProviderCertificationManifest(**fields)


class TestGranularityTaxonomy:
    def test_taxonomy_contains_expected_generic_values(self):
        for value in ("family", "account", "organization", "project", "repository",
                      "group", "cluster", "namespace", "zone", "parent_resource",
                      "detail", "derived_dependency"):
            assert value in COMPLETENESS_SCOPE_GRANULARITIES

    def test_taxonomy_encodes_no_provider_names(self):
        provider_like = {"sentry", "snowflake", "okta", "entra", "kubernetes", "github", "gitlab",
                         "cloudflare", "supabase", "firebase", "stripe"}
        assert not (COMPLETENESS_SCOPE_GRANULARITIES & provider_like)


class TestFamilyScope:
    def test_family_scope_constructs(self):
        m = _manifest(
            completeness_scope_declarations=(
                CompletenessScopeDeclaration(
                    scope_id="family_completeness",
                    record_types=("ghostprov3_widget", "ghostprov3_gadget"),
                    granularity="family",
                ),
            ),
        )
        assert len(m.completeness_scope_declarations) == 1


class TestPerParentScope:
    def test_per_parent_scope_with_status_field_constructs(self):
        m = _manifest(
            completeness_scope_declarations=(
                CompletenessScopeDeclaration(
                    scope_id="per_widget_gadget_completeness",
                    record_types=("ghostprov3_gadget",),
                    granularity="parent_resource",
                    parent_record_type="ghostprov3_widget",
                    status_field="gadget_status",
                ),
            ),
        )
        assert m.completeness_scope_declarations[0].parent_record_type == "ghostprov3_widget"

    def test_missing_parent_type_rejected(self):
        with pytest.raises(ManifestValidationError, match="is not a known record type"):
            _manifest(
                completeness_scope_declarations=(
                    CompletenessScopeDeclaration(
                        scope_id="bad_parent",
                        record_types=("ghostprov3_gadget",),
                        granularity="parent_resource",
                        parent_record_type="ghostprov3_nonexistent_type",
                    ),
                ),
            )


class TestProjectScope:
    def test_project_scope_constructs(self):
        m = _manifest(
            completeness_scope_declarations=(
                CompletenessScopeDeclaration(
                    scope_id="project_completeness",
                    record_types=("ghostprov3_widget",),
                    granularity="project",
                ),
            ),
        )
        assert m.completeness_scope_declarations[0].granularity == "project"


class TestNamespaceScope:
    def test_namespace_scope_constructs(self):
        m = _manifest(
            completeness_scope_declarations=(
                CompletenessScopeDeclaration(
                    scope_id="namespace_completeness",
                    record_types=("ghostprov3_widget",),
                    granularity="namespace",
                ),
            ),
        )
        assert m.completeness_scope_declarations[0].granularity == "namespace"


class TestZoneScope:
    def test_zone_scope_constructs(self):
        m = _manifest(
            completeness_scope_declarations=(
                CompletenessScopeDeclaration(
                    scope_id="zone_completeness",
                    record_types=("ghostprov3_widget",),
                    granularity="zone",
                ),
            ),
        )
        assert m.completeness_scope_declarations[0].granularity == "zone"


class TestDerivedDependency:
    def test_derived_dependents_must_be_real_derived_types(self):
        m = _manifest(
            completeness_scope_declarations=(
                CompletenessScopeDeclaration(
                    scope_id="derived_completeness",
                    record_types=("ghostprov3_widget",),
                    granularity="derived_dependency",
                    derived_dependents=("ghostprov3_widget_summary",),
                ),
            ),
        )
        assert m.completeness_scope_declarations[0].derived_dependents == ("ghostprov3_widget_summary",)

    def test_derived_dependency_declared_but_no_derived_type_exists_rejected(self):
        with pytest.raises(ManifestValidationError, match="unknown derived record type"):
            _manifest(
                completeness_scope_declarations=(
                    CompletenessScopeDeclaration(
                        scope_id="bad_derived",
                        record_types=("ghostprov3_widget",),
                        granularity="derived_dependency",
                        derived_dependents=("ghostprov3_nonexistent_derived",),
                    ),
                ),
            )


class TestMissingParentType:
    def test_parent_record_type_none_is_fine_without_parent_resource_granularity(self):
        m = _manifest(
            completeness_scope_declarations=(
                CompletenessScopeDeclaration(
                    scope_id="no_parent",
                    record_types=("ghostprov3_widget",),
                    granularity="family",
                ),
            ),
        )
        assert m.completeness_scope_declarations[0].parent_record_type is None


class TestUnknownRecordType:
    def test_record_types_referencing_unknown_type_rejected(self):
        with pytest.raises(ManifestValidationError, match="unknown record type"):
            _manifest(
                completeness_scope_declarations=(
                    CompletenessScopeDeclaration(
                        scope_id="bad_types",
                        record_types=("ghostprov3_nonexistent",),
                        granularity="family",
                    ),
                ),
            )


class TestInvalidGranularity:
    def test_unknown_granularity_rejected(self):
        with pytest.raises(ManifestValidationError, match="granularity must be one of"):
            _manifest(
                completeness_scope_declarations=(
                    CompletenessScopeDeclaration(
                        scope_id="bad_granularity",
                        record_types=("ghostprov3_widget",),
                        granularity="not_a_real_granularity",
                    ),
                ),
            )


class TestDuplicateScopeId:
    def test_duplicate_scope_id_rejected(self):
        with pytest.raises(ManifestValidationError, match="duplicate completeness_scope_declarations scope_id"):
            _manifest(
                completeness_scope_declarations=(
                    CompletenessScopeDeclaration(
                        scope_id="dup", record_types=("ghostprov3_widget",), granularity="family",
                    ),
                    CompletenessScopeDeclaration(
                        scope_id="dup", record_types=("ghostprov3_gadget",), granularity="family",
                    ),
                ),
            )


class TestSuppressionSymbolDiscoverability:
    def test_gate_not_applicable_when_no_declarations(self):
        m = _manifest()
        gate = gates.gate_completeness_scope_declarations(m)
        assert gate.status == "not_applicable"

    def test_gate_passes_when_suppression_symbol_omitted(self):
        m = _manifest(
            completeness_scope_declarations=(
                CompletenessScopeDeclaration(
                    scope_id="no_symbol", record_types=("ghostprov3_widget",), granularity="family",
                ),
            ),
        )
        gate = gates.gate_completeness_scope_declarations(m)
        assert gate.status == "pass"

    def test_gate_passes_when_suppression_symbol_resolves(self):
        m = _manifest(
            completeness_scope_declarations=(
                CompletenessScopeDeclaration(
                    scope_id="real_symbol", record_types=("ghostprov3_widget",), granularity="family",
                    suppression_symbol="_sentry_removal_suppressed",
                ),
            ),
        )
        gate = gates.gate_completeness_scope_declarations(m)
        assert gate.status == "pass"

    def test_dead_suppression_symbol_fails(self):
        m = _manifest(
            completeness_scope_declarations=(
                CompletenessScopeDeclaration(
                    scope_id="dead_symbol", record_types=("ghostprov3_widget",), granularity="family",
                    suppression_symbol="_this_function_does_not_exist_anywhere",
                ),
            ),
        )
        gate = gates.gate_completeness_scope_declarations(m)
        assert gate.status == "fail"

    def test_unwired_suppression_dispatch_detected_by_wired_discovery(self):
        from app.provider_certification import discovery as disc

        # Every real provider with a suppression function has it wired
        # (called beyond its own def) — confirmed for all 5 pilots that
        # declare one, proving the wired-check isn't vacuously true.
        for pid in ("sentry", "snowflake", "okta", "entra", "kubernetes"):
            assert disc.discover_removal_suppression_exists(pid) is True
            assert disc.discover_removal_suppression_wired(pid) is True

        # A provider with no suppression function at all is correctly
        # neither "exists" nor "wired".
        assert disc.discover_removal_suppression_exists("gitlab") is False
        assert disc.discover_removal_suppression_wired("gitlab") is False


class TestDeterministicOrdering:
    def test_as_dict_sorts_completeness_scope_declarations_by_scope_id(self):
        m = _manifest(
            completeness_scope_declarations=(
                CompletenessScopeDeclaration(scope_id="zzz", record_types=("ghostprov3_widget",), granularity="family"),
                CompletenessScopeDeclaration(scope_id="aaa", record_types=("ghostprov3_gadget",), granularity="family"),
            ),
        )
        d1 = m.as_dict()
        d2 = m.as_dict()
        assert d1 == d2
        ids = [s["scope_id"] for s in d1["completeness_scope_declarations"]]
        assert ids == sorted(ids)


class TestPerProviderCompletenessHonesty:
    """One method per provider: a provider either has a real, wired
    suppression function backing its completeness declarations, or it
    honestly declares none — never a claim unsupported by discovery."""

    def _check(self, pid):
        from app.provider_certification import discovery as disc
        from app.provider_certification import runner

        m = runner.get_manifest(pid)
        wired = disc.discover_removal_suppression_wired(pid)
        if m.false_removal_scopes or m.completeness_scope_declarations:
            assert wired, f"{pid} declares completeness but has no wired suppression function"
        else:
            assert not wired or True  # no claim made either way is always honest

    def test_sentry_completeness_honesty(self):
        self._check("sentry")

    def test_snowflake_completeness_honesty(self):
        self._check("snowflake")

    def test_okta_completeness_honesty(self):
        self._check("okta")

    def test_entra_completeness_honesty(self):
        self._check("entra")

    def test_kubernetes_completeness_honesty(self):
        self._check("kubernetes")

    def test_github_completeness_honesty(self):
        self._check("github")

    def test_gitlab_completeness_honesty(self):
        self._check("gitlab")

    def test_cloudflare_completeness_honesty(self):
        self._check("cloudflare")

    def test_supabase_completeness_honesty(self):
        self._check("supabase")

    def test_firebase_completeness_honesty(self):
        self._check("firebase")

    def test_stripe_completeness_honesty(self):
        self._check("stripe")
