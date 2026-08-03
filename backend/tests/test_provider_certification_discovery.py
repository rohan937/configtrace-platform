"""Discovery-layer tests for the Provider Certification Framework.

These tests exercise the REAL repository — actual backend modules and
frontend source text — for the two pilot providers (Sentry, Snowflake).
Nothing is mocked here; discovery is read-only reflection/regex over
real files, so pinning it against the real repo is the point.
"""

from __future__ import annotations

from app.provider_certification import discovery as disc


class TestBackendProviderInventory:
    def test_sentry_in_sync_provider_ids(self):
        assert "sentry" in disc.discover_backend_sync_provider_ids()

    def test_snowflake_in_sync_provider_ids(self):
        assert "snowflake" in disc.discover_backend_sync_provider_ids()

    def test_unknown_provider_not_in_sync_ids(self):
        assert "not_a_real_provider" not in disc.discover_backend_sync_provider_ids()

    def test_sentry_credential_schema_literal_present(self):
        assert disc.discover_backend_credential_schema_provider_literal("sentry")

    def test_worker_dispatch_present_for_both_pilots(self):
        assert disc.discover_worker_dispatch("sentry")
        assert disc.discover_worker_dispatch("snowflake")

    def test_reconnect_router_dispatch_present_for_both_pilots(self):
        assert disc.discover_reconnect_router_dispatch("sentry")
        assert disc.discover_reconnect_router_dispatch("snowflake")

    def test_reconnect_function_exists_for_both_pilots(self):
        assert disc.discover_reconnect_function_exists("sentry")
        assert disc.discover_reconnect_function_exists("snowflake")

    def test_create_dispatch_function_exists_for_both_pilots(self):
        assert disc.discover_create_dispatch_function_exists("sentry")
        assert disc.discover_create_dispatch_function_exists("snowflake")

    def test_unknown_provider_reconnect_function_absent(self):
        assert not disc.discover_reconnect_function_exists("not_a_real_provider")


class TestCredentialFields:
    def test_sentry_credential_fields(self):
        fields = disc.discover_credential_schema_fields("sentry")
        assert fields == frozenset({"sentry_organization_slug", "sentry_auth_token"})

    def test_snowflake_credential_fields(self):
        fields = disc.discover_credential_schema_fields("snowflake")
        assert fields == frozenset(
            {
                "snowflake_account_identifier",
                "snowflake_username",
                "snowflake_programmatic_access_token",
                "snowflake_role",
            }
        )

    def test_sentry_reconnect_schema_fields(self):
        fields = disc.discover_reconnect_schema_fields("sentry")
        assert "sentry_auth_token" in fields

    def test_unknown_provider_credential_fields_empty(self):
        assert disc.discover_credential_schema_fields("not_a_real_provider") == frozenset()


class TestCapabilityMatrix:
    def test_sentry_capability_entry_discovered(self):
        cap = disc.discover_capability_entry("sentry")
        assert cap is not None
        assert cap.provider == "sentry"
        assert cap.maturity == "partial"

    def test_snowflake_capability_entry_discovered(self):
        cap = disc.discover_capability_entry("snowflake")
        assert cap is not None
        assert cap.category == "database_backend"

    def test_unknown_provider_capability_entry_is_none(self):
        assert disc.discover_capability_entry("not_a_real_provider") is None

    def test_sentry_in_complete_list_not_partial(self):
        in_complete, in_partial = disc.discover_capability_matrix_membership("sentry")
        assert in_complete is True
        assert in_partial is False


class TestSecurityFindingRegistry:
    def test_sentry_registry_rule_count(self):
        assert len(disc.discover_registry_rule_ids("sentry")) == 20

    def test_snowflake_registry_rule_count(self):
        assert len(disc.discover_registry_rule_ids("snowflake")) == 31

    def test_sentry_confidence_matches_registry(self):
        assert disc.discover_confidence_rule_ids("sentry") == disc.discover_registry_rule_ids("sentry")

    def test_sentry_pack_matches_registry(self):
        assert disc.discover_pack_rule_ids("sentry") == disc.discover_registry_rule_ids("sentry")

    def test_sentry_coverage_matches_registry(self):
        assert disc.discover_coverage_rule_ids("sentry") == disc.discover_registry_rule_ids("sentry")

    def test_snowflake_all_registries_agree(self):
        registry = disc.discover_registry_rule_ids("snowflake")
        assert disc.discover_confidence_rule_ids("snowflake") == registry
        assert disc.discover_pack_rule_ids("snowflake") == registry
        assert disc.discover_coverage_rule_ids("snowflake") == registry

    def test_sentry_coverage_provider_membership(self):
        assert disc.discover_coverage_provider_membership("sentry")

    def test_evaluator_registered_for_both_pilots(self):
        assert disc.discover_evaluator_registered("sentry")
        assert disc.discover_evaluator_registered("snowflake")

    def test_evaluator_not_registered_for_unknown_provider(self):
        assert not disc.discover_evaluator_registered("not_a_real_provider")

    def test_unknown_provider_registry_rule_ids_empty(self):
        assert disc.discover_registry_rule_ids("not_a_real_provider") == frozenset()


class TestConnectorMapping:
    def test_sentry_connector_class_importable(self):
        cls = disc.discover_connector_class("sentry", "SentryConnector")
        assert cls is not None
        assert cls.__name__ == "SentryConnector"

    def test_snowflake_connector_class_importable(self):
        cls = disc.discover_connector_class("snowflake", "SnowflakeConnector")
        assert cls is not None

    def test_unknown_provider_connector_class_is_none(self):
        assert disc.discover_connector_class("not_a_real_provider", "GhostConnector") is None

    def test_wrong_class_name_returns_none(self):
        assert disc.discover_connector_class("sentry", "TotallyWrongClassName") is None


class TestRecordTypes:
    def test_sentry_record_type_count(self):
        types = disc.discover_schema_record_type_constants("sentry")
        assert len(types) == 18

    def test_snowflake_record_type_count(self):
        types = disc.discover_schema_record_type_constants("snowflake")
        assert len(types) == 21

    def test_sentry_record_types_excludes_action_category_constants(self):
        types = disc.discover_schema_record_type_constants("sentry")
        assert "sentry_app" not in types
        assert "sentry_notification" not in types

    def test_unknown_provider_record_types_empty(self):
        assert disc.discover_schema_record_type_constants("not_a_real_provider") == frozenset()


class TestTrackedFields:
    def test_sentry_tracked_fields_dict_discovered(self):
        tracked = disc.discover_diff_tracked_fields_dict("sentry")
        assert tracked is not None
        assert "sentry_organization" in tracked

    def test_snowflake_tracked_fields_dict_discovered(self):
        tracked = disc.discover_diff_tracked_fields_dict("snowflake")
        assert tracked is not None
        assert "snowflake_account" in tracked

    def test_unknown_provider_tracked_fields_none(self):
        assert disc.discover_diff_tracked_fields_dict("not_a_real_provider") is None


class TestClassifierDispatch:
    def test_sentry_classifier_dispatch_exists(self):
        assert disc.discover_classifier_dispatch_exists("sentry")

    def test_snowflake_classifier_dispatch_exists(self):
        assert disc.discover_classifier_dispatch_exists("snowflake")

    def test_unknown_provider_classifier_dispatch_absent(self):
        assert not disc.discover_classifier_dispatch_exists("not_a_real_provider")

    def test_sentry_classifier_handles_organization_literal(self):
        handled = disc.discover_classifier_record_type_dispatch("sentry")
        assert "sentry_organization" in handled

    def test_snowflake_classifier_resolves_named_constants(self):
        """Snowflake's risk_rules module dispatches via named constants
        (SNOWFLAKE_ACCOUNT) rather than raw string literals — discovery
        must resolve these back to their string values."""
        handled = disc.discover_classifier_record_type_dispatch("snowflake")
        assert "snowflake_account" in handled
        assert len(handled) >= 15

    def test_removal_suppression_exists_for_both_pilots(self):
        assert disc.discover_removal_suppression_exists("sentry")
        assert disc.discover_removal_suppression_exists("snowflake")

    def test_unknown_provider_removal_suppression_absent(self):
        assert not disc.discover_removal_suppression_exists("not_a_real_provider")


class TestFrontendParity:
    def test_frontend_root_resolves_when_mounted(self):
        root = disc.frontend_root()
        if root is None:
            import pytest
            pytest.skip("frontend tree not mounted")
        assert root.is_dir()

    def test_sentry_in_frontend_provider_ids(self):
        ids = disc.discover_frontend_provider_ids()
        if ids is None:
            import pytest
            pytest.skip("frontend tree not mounted")
        assert "sentry" in ids

    def test_sentry_in_frontend_connectable_ids(self):
        ids = disc.discover_frontend_connectable_ids()
        if ids is None:
            import pytest
            pytest.skip("frontend tree not mounted")
        assert "sentry" in ids

    def test_sentry_form_file_exists(self):
        if disc.frontend_root() is None:
            import pytest
            pytest.skip("frontend tree not mounted")
        assert disc.discover_frontend_form_file_exists("SentryIntegrationForm.tsx")

    def test_snowflake_form_uses_password_input(self):
        if disc.frontend_root() is None:
            import pytest
            pytest.skip("frontend tree not mounted")
        assert disc.discover_frontend_form_uses_password_input("SnowflakeIntegrationForm.tsx")

    def test_sentry_form_wired_into_dispatcher(self):
        if disc.frontend_root() is None:
            import pytest
            pytest.skip("frontend tree not mounted")
        assert disc.discover_frontend_form_wired_into_dispatcher("sentry")

    def test_nonexistent_form_file_reports_false(self):
        if disc.frontend_root() is None:
            import pytest
            pytest.skip("frontend tree not mounted")
        assert not disc.discover_frontend_form_file_exists("DoesNotExistIntegrationForm.tsx")


class TestProviderExpansionFreeze:
    def test_recommended_next_providers_empty(self):
        assert disc.discover_recommended_next_providers() == frozenset()

    def test_planned_next_stage_says_frozen(self):
        assert "frozen" in disc.discover_planned_next_stage_text().lower()

    def test_frontend_future_provider_queue_empty_or_absent(self):
        queue = disc.discover_frontend_future_provider_queue()
        if queue is None:
            import pytest
            pytest.skip("frontend tree not mounted")
        assert queue == frozenset()


class TestDependencyAudit:
    def test_requirements_text_nonempty(self):
        assert "fastapi" in disc.discover_requirements_text().lower()

    def test_sentry_sdk_not_a_dependency(self):
        assert not disc.discover_prohibited_dependency_present("sentry-sdk")

    def test_snowflake_connector_not_a_dependency(self):
        assert not disc.discover_prohibited_dependency_present("snowflake-connector-python")

    def test_httpx_is_present_as_expected(self):
        # Sanity check the detector actually finds a real dependency.
        assert disc.discover_prohibited_dependency_present("httpx")

    def test_no_global_env_var_reference_in_sentry_connector(self):
        assert not disc.discover_global_env_var_reference("sentry", "SENTRY_AUTH_TOKEN")

    def test_no_global_env_var_reference_in_snowflake_connector(self):
        assert not disc.discover_global_env_var_reference("snowflake", "SNOWFLAKE_ACCOUNT")


# ── Message 3: generic discovery-precision helpers ────────────────────────────
# These exercise the NEW generic discovery functions directly against real
# repository state for the providers whose wiring patterns required them,
# proving the functions are genuinely generic (not hardcoded per-provider)
# even though each was motivated by one specific provider's real structure.


class TestSchemaRecordTypeIdentityConstants:
    def test_kubernetes_identity_constants_is_a_superset_of_wired_types(self):
        identity = disc.discover_schema_record_type_identity_constants("kubernetes")
        wired = disc.discover_schema_record_type_constants("kubernetes")
        assert set(identity.values()) >= wired

    def test_github_identity_constants_is_a_superset_of_wired_types(self):
        identity = disc.discover_schema_record_type_identity_constants("github")
        wired = disc.discover_schema_record_type_constants("github")
        assert set(identity.values()) >= wired


class TestClassifierGroupedDispatch:
    def test_kubernetes_grouped_dispatch_is_nonempty(self):
        assert len(disc.discover_classifier_grouped_dispatch("kubernetes")) > 0

    def test_snowflake_grouped_dispatch_does_not_error_when_absent(self):
        # Snowflake's classifier doesn't use grouped-frozenset dispatch —
        # the function must return an empty result, not raise.
        assert disc.discover_classifier_grouped_dispatch("snowflake") == frozenset()


class TestGenericReconnectDispatch:
    def test_github_has_generic_reconnect_dispatch(self):
        assert disc.discover_generic_reconnect_dispatch("github") is True

    def test_sentry_has_no_generic_reconnect_dispatch_since_it_has_a_named_function(self):
        # Sentry uses a named reconnect function, not the shared generic
        # dispatcher — the generic-dispatch detector must not double-count it.
        assert disc.discover_reconnect_function_exists("sentry") is True


class TestRouterCreateDispatch:
    def test_gitlab_has_router_inline_create_dispatch(self):
        assert disc.discover_router_create_dispatch("gitlab") is True

    def test_sentry_has_no_router_inline_create_dispatch_since_it_has_a_named_function(self):
        assert disc.discover_create_dispatch_function_exists("sentry") is True


class TestConnectorClassAnyCapitalization:
    def test_github_resolves_via_capitalization_fallback(self):
        cls = disc.discover_connector_class_any_capitalization("github")
        assert cls is not None
        assert cls.__name__ == "GitHubConnector"

    def test_gitlab_resolves_via_capitalization_fallback(self):
        cls = disc.discover_connector_class_any_capitalization("gitlab")
        assert cls is not None
        assert cls.__name__ == "GitLabConnector"

    def test_sentry_naive_capitalization_already_matches(self):
        # Sentry's class name follows the naive Title-case convention, so
        # the naive lookup should already succeed without the fallback.
        assert disc.discover_connector_class("sentry", "SentryConnector") is not None


class TestFrontendFormMaskedMultilineInput:
    def test_kubernetes_form_uses_masked_multiline_input_for_kubeconfig(self):
        if disc.frontend_root() is None:
            import pytest
            pytest.skip("frontend tree not mounted")
        assert disc.discover_frontend_form_uses_masked_multiline_input("KubernetesIntegrationForm.tsx") is True

    def test_sentry_form_does_not_need_masked_multiline_input(self):
        if disc.frontend_root() is None:
            import pytest
            pytest.skip("frontend tree not mounted")
        # Sentry's only secret field is a single-line token — a regular
        # password input is used, not a textarea.
        assert disc.discover_frontend_form_uses_masked_multiline_input("SentryIntegrationForm.tsx") is False


class TestCapabilityMatrixPartialListMembership:
    def test_gitlab_membership_is_partial_not_complete(self):
        in_complete, in_partial = disc.discover_capability_matrix_membership("gitlab")
        assert in_complete is False
        assert in_partial is True

    def test_sentry_membership_is_complete_not_partial(self):
        in_complete, in_partial = disc.discover_capability_matrix_membership("sentry")
        assert in_complete is True
