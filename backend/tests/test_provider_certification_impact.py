"""Changed-provider impact analysis tests (message 7).

Covers path classification (provider-specific / shared-global /
unknown-provider-shaped), the analyze_impact() aggregation, git-diff
parsing (adds/modifies/deletes/renames), and the conservative
full-catalog fallback when impact cannot be safely determined.
"""

from __future__ import annotations

from app.provider_certification import impact


class TestProviderConnectorChange:
    def test_sentry_connector_change_classified_as_provider_specific(self):
        c = impact.classify_path("backend/app/connectors/sentry.py")
        assert c.is_provider_specific is True
        assert c.provider_id == "sentry"
        assert c.is_global is False

    def test_sentry_connector_change_yields_only_sentry_in_impact(self):
        result = impact.analyze_impact(["backend/app/connectors/sentry.py"])
        assert result.directly_affected_providers == ("sentry",)
        assert result.full_catalog_required is False


class TestProviderSchemaChange:
    def test_aws_schema_change_classified_as_provider_specific(self):
        c = impact.classify_path("backend/app/connectors/aws_schema.py")
        assert c.provider_id == "aws"
        assert c.is_provider_specific is True


class TestProviderManifestChange:
    def test_aws_manifest_change_classified_as_provider_specific(self):
        c = impact.classify_path("backend/app/provider_certification/manifests/aws.py")
        assert c.provider_id == "aws"

    def test_aws_manifest_change_impact_includes_aws(self):
        result = impact.analyze_impact(["backend/app/provider_certification/manifests/aws.py"])
        assert "aws" in result.directly_affected_providers
        assert result.full_catalog_required is False


class TestProviderFrontendFormChange:
    def test_pagerduty_frontend_form_maps_to_correct_provider_id(self):
        c = impact.classify_path("frontend/src/components/integrations/PagerDutyIntegrationForm.tsx")
        assert c.provider_id == "pagerduty"

    def test_google_cloud_frontend_form_maps_to_correct_provider_id(self):
        c = impact.classify_path("frontend/src/components/integrations/GoogleCloudIntegrationForm.tsx")
        assert c.provider_id == "google_cloud"

    def test_terraform_cloud_frontend_form_maps_to_correct_provider_id(self):
        c = impact.classify_path("frontend/src/components/integrations/TerraformCloudIntegrationForm.tsx")
        assert c.provider_id == "terraform_cloud"


class TestSharedDiffChange:
    def test_diff_service_change_is_global(self):
        c = impact.classify_path("backend/app/services/diff_service.py")
        assert c.is_global is True
        assert c.global_dimension == "diff_tracked_fields"

    def test_diff_service_change_forces_full_catalog(self):
        result = impact.analyze_impact(["backend/app/services/diff_service.py"])
        assert result.full_catalog_required is True


class TestRegistryChange:
    def test_security_rule_registry_change_is_global(self):
        c = impact.classify_path("backend/app/services/security_rule_registry.py")
        assert c.is_global is True

    def test_security_rule_registry_change_forces_full_catalog(self):
        result = impact.analyze_impact(["backend/app/services/security_rule_registry.py"])
        assert result.full_catalog_required is True


class TestCapabilityMatrixChange:
    def test_capability_matrix_change_is_global(self):
        c = impact.classify_path("backend/app/services/provider_capability_matrix_service.py")
        assert c.is_global is True
        assert c.global_dimension == "capability_matrix_parity"


class TestFrontendProviderCatalogChange:
    def test_frontend_providers_ts_change_is_global(self):
        c = impact.classify_path("frontend/src/lib/providers.ts")
        assert c.is_global is True
        assert c.global_dimension == "frontend_provider_parity"

    def test_frontend_providers_ts_change_forces_full_catalog(self):
        result = impact.analyze_impact(["frontend/src/lib/providers.ts"])
        assert result.full_catalog_required is True


class TestUnrelatedDocsChange:
    def test_readme_change_has_no_impact(self):
        c = impact.classify_path("README.md")
        assert c.is_provider_specific is False
        assert c.is_global is False
        assert c.is_unknown_provider_shaped is False

    def test_readme_change_does_not_force_full_catalog(self):
        result = impact.analyze_impact(["README.md"])
        assert result.full_catalog_required is False
        assert result.directly_affected_providers == ()


class TestAddedProviderLikeFile:
    def test_unregistered_connector_file_is_unknown_provider_shaped(self):
        c = impact.classify_path("backend/app/connectors/newcloud.py")
        assert c.is_unknown_provider_shaped is True

    def test_unregistered_connector_file_forces_full_catalog(self):
        result = impact.analyze_impact(["backend/app/connectors/newcloud.py"])
        assert result.full_catalog_required is True
        assert "backend/app/connectors/newcloud.py" in result.unknown_provider_files

    def test_framework_test_file_pattern_is_not_misclassified_as_unknown_provider(self):
        # "runner" structurally matches the provider-test filename
        # pattern but is a framework module, not a provider — must not
        # trigger a false "unknown provider-shaped file" / full-catalog signal.
        c = impact.classify_path("backend/tests/test_provider_certification_runner.py")
        assert c.is_unknown_provider_shaped is False


class TestDeletedManifest:
    def test_deleted_manifest_path_still_classified_as_provider_specific(self):
        # A deletion is represented the same way as any other changed
        # path in this module's input contract — the git-status prefix
        # is resolved by the caller (get_changed_paths), not here.
        c = impact.classify_path("backend/app/provider_certification/manifests/aws.py")
        assert c.provider_id == "aws"


class TestRenamedConnector:
    def test_rename_contributes_both_old_and_new_paths(self):
        diff_output = "R100\tbackend/app/connectors/sentry.py\tbackend/app/connectors/sentry_v2.py\n"
        paths = impact.parse_diff_name_status(diff_output)
        assert paths == [
            "backend/app/connectors/sentry.py",
            "backend/app/connectors/sentry_v2.py",
        ]

    def test_renamed_connector_impacts_both_old_and_new_provider_ids(self):
        result = impact.analyze_impact([
            "backend/app/connectors/sentry.py",
            "backend/app/connectors/sentry_v2.py",
        ])
        assert "sentry" in result.directly_affected_providers
        # sentry_v2 has no manifest -> unknown provider-shaped, forces full catalog
        assert result.full_catalog_required is True


class TestMalformedGitDiff:
    def test_empty_diff_output_yields_empty_paths(self):
        assert impact.parse_diff_name_status("") == []

    def test_blank_lines_are_skipped(self):
        assert impact.parse_diff_name_status("\n\n\n") == []

    def test_malformed_line_without_tab_does_not_crash(self):
        # A line with only a status code, no path — must not raise.
        paths = impact.parse_diff_name_status("M\n")
        assert paths == []


class TestMissingBaseSHA:
    def test_git_diff_error_on_invalid_refs_triggers_conservative_fallback(self, tmp_path):
        result = impact.analyze_impact_from_git("not-a-real-sha-aaaa", "also-not-real-bbbb", repo_root=tmp_path)
        assert result.full_catalog_required is True

    def test_empty_real_diff_does_not_force_full_catalog(self, monkeypatch):
        monkeypatch.setattr(impact, "get_changed_paths", lambda base, head, repo_root=None: [])
        result = impact.analyze_impact_from_git("abc123", "abc123")
        assert result.full_catalog_required is False


class TestConservativeFullFallback:
    def test_git_diff_error_raises_are_caught_by_from_git_wrapper(self, monkeypatch):
        def _raise(*a, **k):
            raise impact.GitDiffError("shallow clone, no merge base")

        monkeypatch.setattr(impact, "get_changed_paths", _raise)
        result = impact.analyze_impact_from_git("base", "head")
        assert result.full_catalog_required is True
        assert "git_diff_unavailable" in result.globally_affected_dimensions

    def test_impact_result_as_dict_is_json_serializable(self):
        import json

        result = impact.analyze_impact(["backend/app/connectors/sentry.py"])
        json.dumps(result.as_dict())  # must not raise
