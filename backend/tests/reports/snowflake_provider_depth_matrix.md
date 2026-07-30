# Snowflake Provider Depth Matrix (Snowflake Message 8 of 8 — Public Launch)

Columns: **Surface**, **Requirement**, **Backend**, **Frontend**, **Test**, **Status** (PASS / N/A), **Notes**.

`N/A` marks an intentional, documented limitation (certification report §16), never a launch-blocking gap.

| # | Surface | Requirement | Backend | Frontend | Test | Status | Notes |
|---|---|---|---|---|---|---|---|
| 1 | Registration | Provider ID `snowflake` in sync dispatch | `sync_service._SUPPORTED_PROVIDERS` | — | `test_snowflake_provider_depth_qa.py::test_snowflake_in_sync_supported_providers` | PASS | Pre-existing (message 1), re-verified |
| 2 | Registration | Provider ID in `IntegrationCreateRequest.provider` Literal | `schemas/integration.py` | — | `test_snowflake_provider_depth_qa.py::test_snowflake_in_integration_create_request_literal` | PASS | Pre-existing |
| 3 | Registration | Provider in Security Findings coverage list | `security_coverage_service.PROVIDERS` | — | `test_snowflake_provider_depth_qa.py::test_snowflake_in_security_coverage_providers` | PASS | Pre-existing (message 6) |
| 4 | Registration | Provider in public capability matrix, not the partial/staging list | `provider_capability_matrix_service.PROVIDER_CAPABILITIES` | — | `test_snowflake_provider_depth_qa.py::test_snowflake_in_capability_matrix_complete_list_not_partial` | PASS | Flipped this message |
| 5 | Registration | Capability notes describe launched state, not "not connectable" | `_SNOWFLAKE.notes` | — | `test_snowflake_provider_depth_qa.py::test_snowflake_capability_notes_say_launched_not_pending` | PASS | Rewritten this message |
| 6 | Registration | `maturity="partial"` (drift + Security Findings only, no activity ingestion — same convention as Okta/Entra/Kubernetes) | `_SNOWFLAKE.maturity` | — | `test_milestone75c_provider_capability_matrix.py::test_summary_counts_are_correct` | PASS | Flipped `planned` → `partial` this message |
| 7 | Registration | `drift_review_workflow` flipped True (generic review UI) | `_SNOWFLAKE.drift.drift_review_workflow` | Generic review UI | code review | PASS | Flipped this message |
| 8 | Registration | Connector creation dispatch exists | `integration_service._create_snowflake_integration` | — | `test_snowflake_provider_depth_qa.py::test_snowflake_dispatch_function_exists` | PASS | Pre-existing (message 1) |
| 9 | Registration | Sync worker dispatch exists | `app/workers/sync_task.py` | — | pre-existing full-suite coverage | PASS | Pre-existing |
| 10 | Registration | Reconnect dispatch function exists | `integration_service.reconnect_credentials_snowflake` | — | `test_snowflake_provider_depth_qa.py::test_snowflake_reconnect_function_exists` | PASS | New this message |
| 11 | Credentials | `POST /integrations` extracts all 4 fields | `routers/integrations.py::_build_credentials` snowflake branch | — | `test_snowflake_provider_depth_qa.py::TestCredentialRoundTrip::test_build_credentials_extracts_all_four_fields` | PASS | Pre-existing (message 1), re-verified |
| 12 | Credentials | Router credential-dict keys match connector's expected keys | `_build_credentials` / `SnowflakeConnector._credentials` | — | `test_snowflake_provider_depth_qa.py::test_build_credentials_key_matches_connector_expectation` | PASS | |
| 13 | Credentials | Reconnect schema has all 4 snowflake_* fields | `schemas/integration.py::IntegrationReconnectRequest` | — | `test_snowflake_provider_depth_qa.py::test_reconnect_schema_has_snowflake_fields` | PASS | New this message |
| 14 | Credentials | Reconnect router branch dispatches to service function | `routers/integrations.py` reconnect route | — | `test_snowflake_provider_depth_qa.py::test_reconnect_router_branch_exists_for_snowflake` | PASS | New this message |
| 15 | Credentials | Reconnect preserves identity for same-account PAT rotation | `reconnect_credentials_snowflake` | — | `test_snowflake_integration_creation.py::TestReconnect::test_same_account_new_pat_accepted` | PASS | Compares `compute_account_id()` output before/after |
| 16 | Credentials | Reconnect rejects PAT pointing at a genuinely different account | `reconnect_credentials_snowflake` | — | `test_snowflake_integration_creation.py::TestReconnect::test_different_account_rejected` | PASS | Raises `ConnectorError` |
| 17 | Credentials | Missing token at reconnect rejected at schema layer | `IntegrationReconnectRequest` | — | `test_snowflake_integration_creation.py::TestReconnect::test_reconnect_missing_token_rejected_at_schema_layer` | PASS | HTTP 422 |
| 18 | Credentials | PAT field masked in setup form | `SnowflakeIntegrationForm.tsx` | `type="password"` | `test_snowflake_provider_depth_qa.py::test_snowflake_form_uses_password_input_for_token` | PASS | New this message |
| 19 | Validation | Account-identity query used for validation (narrowest official query) | `SnowflakeConnector.probe_coverage` / `_ACCOUNT_IDENTITY_STATEMENT` | — | `test_snowflake_integration_creation.py::TestValidConnection` | PASS | Pre-existing statement (message 1), new synchronous call site |
| 20 | Validation | Creation now runs `probe_coverage()` synchronously | `integration_service._create_snowflake_integration` | — | `test_snowflake_provider_depth_qa.py::test_creation_runs_synchronous_probe_coverage` | PASS | Architecture change this message |
| 21 | Validation | Full/Partial/Invalid coverage semantics | `compute_coverage_state()` | — | `test_snowflake_provider_depth_qa.py::TestReliabilitySurfacesReachable` | PASS | New this message |
| 22 | Validation | Extended family (network policies) denied ≠ Invalid | `compute_coverage_state()` | — | `test_snowflake_integration_creation.py::TestOptionalFamilyDeniedNotInvalid` | PASS | |
| 23 | Validation | Malformed account identifier rejected (HTTP 400) | `POST /integrations` | — | `test_snowflake_integration_creation.py::TestInvalidConnection::test_malformed_account_identifier_rejected` | PASS | |
| 24 | Validation | Auth failure rejected (HTTP 400) | `POST /integrations` | — | `test_snowflake_integration_creation.py::TestInvalidConnection::test_auth_failure_rejected` | PASS | |
| 25 | Validation | Unreachable account rejected | `POST /integrations` | — | `test_snowflake_integration_creation.py::TestInvalidConnection::test_unreachable_account_rejected` | PASS | |
| 26 | Validation | Zero meaningful capability rejected | `POST /integrations` | — | `test_snowflake_integration_creation.py::TestInvalidConnection::test_zero_meaningful_capability_rejected` | PASS | Sanitized message names core families |
| 27 | Validation | Missing account identifier rejected at schema layer | `IntegrationCreateRequest` validator | Form requires field before submit | `test_snowflake_integration_creation.py::test_missing_account_identifier_rejected_at_schema_layer` | PASS | HTTP 422 |
| 28 | Validation | Missing username rejected at schema layer | `IntegrationCreateRequest` validator | Form requires field before submit | `test_snowflake_integration_creation.py::test_missing_username_rejected_at_schema_layer` | PASS | HTTP 422 |
| 29 | Validation | Missing token rejected at schema layer | `IntegrationCreateRequest` validator | Form requires field before submit | `test_snowflake_integration_creation.py::test_missing_token_rejected_at_schema_layer` | PASS | HTTP 422 |
| 30 | Validation | Missing role rejected at schema layer | `IntegrationCreateRequest` validator | Form requires field before submit | `test_snowflake_integration_creation.py::test_missing_role_rejected_at_schema_layer` | PASS | HTTP 422 |
| 31 | Reconnect | Same account + new username accepted | `reconnect_credentials_snowflake` | — | `test_snowflake_integration_creation.py::TestReconnect::test_same_account_new_username_accepted` | PASS | |
| 32 | Reconnect | Same account + new role accepted after validation | `reconnect_credentials_snowflake` | — | `test_snowflake_integration_creation.py::TestReconnect::test_same_account_new_role_accepted_after_validation` | PASS | |
| 33 | Reconnect | Invalid PAT rejected | `reconnect_credentials_snowflake` | — | `test_snowflake_integration_creation.py::TestReconnect::test_invalid_pat_rejected` | PASS | |
| 34 | Reconnect | Revoked PAT rejected with sanitized error | `reconnect_credentials_snowflake` | — | `test_snowflake_integration_creation.py::TestReconnect::test_revoked_pat_rejected_with_sanitized_error` | PASS | Raw PAT value never in response |
| 35 | Reconnect | Role restriction mismatch rejected | `reconnect_credentials_snowflake` | — | `test_snowflake_integration_creation.py::TestReconnect::test_role_restriction_mismatch_rejected` | PASS | |
| 36 | Reconnect | Partial permissions accepted with Partial diagnostics | `reconnect_credentials_snowflake` | — | `test_snowflake_integration_creation.py::TestReconnect::test_partial_permissions_accepted_with_partial_diagnostics` | PASS | |
| 37 | Reconnect | Old PAT not reused / fully overwritten | `reconnect_credentials_snowflake` | — | `test_snowflake_integration_creation.py::TestReconnect::test_old_pat_not_reused` | PASS | Encrypted column decrypts to only the new PAT |
| 38 | Reconnect | PAT never returned in any reconnect response | `routers/integrations.py` reconnect route | — | `test_snowflake_integration_creation.py::TestReconnect` (all cases assert on status only, PAT absent) | PASS | |
| 39 | Account identity | Stable `account_id` derived from immutable org/account pair | `SnowflakeConnector.compute_account_id()` | — | pre-existing message-1/7 tests, re-verified | PASS | Never from raw `account_identifier` credential |
| 40 | Account identity | Mismatch check compares stable `account_id`, never raw identifier string | `reconnect_credentials_snowflake` | — | `test_snowflake_provider_depth_qa.py::test_reconnect_rejects_different_account` (code review) | PASS | Alias-safe by construction |
| 41 | Account identity | Real account identity recorded synchronously at creation (no placeholder window) | `_create_snowflake_integration` | — | code review + `TestValidConnection` | PASS | Unlike Okta/Entra's post-first-sync identity resolution |
| 42 | Account identity | `provider_resource_id` uses `account/<account_id>` format | `_create_snowflake_integration` / `reconnect_credentials_snowflake` | — | code review | PASS | Matches `snowflake_account._normalize_account()`'s own `provider_resource_id` convention |
| 43 | Account identity | Reconnect updates `provider_resource_id`/`resource_metadata` on rotation | `reconnect_credentials_snowflake` | — | code review | PASS | Coverage/diagnostics recomputed and stored |
| 44 | Identity/roles | `snowflake_user` collection + normalization | `SnowflakeConnector._collect_users` | — | `test_snowflake_identity_collection.py`, `test_snowflake_identity_normalization.py` | PASS | Message 2, re-certified message 7 |
| 45 | Identity/roles | `snowflake_account_role` collection + normalization | `SnowflakeConnector._collect_account_roles` | — | `test_snowflake_identity_collection.py` | PASS | Message 2 |
| 46 | Identity/roles | `snowflake_database_role` collection + normalization | `SnowflakeConnector._collect_database_roles` | — | `test_snowflake_identity_collection.py` | PASS | Message 2 |
| 47 | Identity/roles | `snowflake_user_role_grant` collection | `SnowflakeConnector._collect_grants` | — | `test_snowflake_identity_collection.py` | PASS | Message 2 |
| 48 | Identity/roles | `snowflake_role_hierarchy_grant` collection | `SnowflakeConnector._collect_grants` | — | `test_snowflake_identity_collection.py` | PASS | Message 2 |
| 49 | Identity/roles | Cycle-safe role-hierarchy traversal | `_role_closure()` | — | `test_snowflake_privilege_graph.py` | PASS | Message 5 |
| 50 | Identity/roles | Change classification for user lifecycle (12 cases) | `_classify_user_change` | — | `test_snowflake_change_classification.py::TestUserLifecycleQA` | PASS | Message 7 |
| 51 | Objects/grants | `snowflake_database`/`snowflake_schema` collection | `_collect_databases`/`_collect_schemas` | — | `test_snowflake_data_collection.py` | PASS | Message 3 |
| 52 | Objects/grants | `snowflake_warehouse`/`snowflake_share` collection | connector message-3 methods | — | `test_snowflake_data_collection.py` | PASS | Message 3 |
| 53 | Objects/grants | `snowflake_object_grant` current + future grant collection | `_collect_object_and_future_grants` | — | `test_snowflake_data_collection.py` | PASS | Message 3 |
| 54 | Objects/grants | PUBLIC-grant handling (never claims internet exposure) | `security_rules/snowflake.py::_eval_public_exposure` | — | `test_snowflake_change_classification.py::TestPublicSemanticsRegression` | PASS | Message 3/5/6/7, re-verified |
| 55 | Objects/grants | Ownership rollups (managed-access schema, database, integrations) | message-5 derivation | — | `test_snowflake_privileged_normalization.py` | PASS | Message 5 |
| 56 | Policy/integrations | `snowflake_network_policy`/`snowflake_network_rule` collection | `_collect_network_policies`/`_collect_network_rules` | — | `test_snowflake_policy_collection.py` | PASS | Message 4 |
| 57 | Policy/integrations | `snowflake_authentication_policy` collection, MFA posture | connector message-4 methods | — | `test_snowflake_policy_collection.py` | PASS | Message 4 |
| 58 | Policy/integrations | `snowflake_security_integration` (SAML/OAuth/SCIM) collection | connector message-4 methods | — | `test_snowflake_policy_collection.py` | PASS | Message 4 |
| 59 | Policy/integrations | `snowflake_storage_integration`/`snowflake_external_access_integration` collection | connector message-4 methods | — | `test_snowflake_policy_collection.py` | PASS | Message 4 |
| 60 | Policy/integrations | SCIM run-as-role privilege resolution | `_resolve_scim_run_as_context()` | — | `test_snowflake_security_findings.py` | PASS | Message 6 |
| 61 | Privilege analysis | System-role tier taxonomy (ACCOUNTADMIN/SECURITYADMIN/SYSADMIN/USERADMIN) | `_tier_for_closure()` | — | `test_snowflake_privileged_normalization.py` | PASS | Message 5 |
| 62 | Privilege analysis | Custom-role privilege derivation from actual grants | `_build_role_signals()` | — | `test_snowflake_privileged_normalization.py` | PASS | Message 5 |
| 63 | Privilege analysis | MANAGE GRANTS handling | message-5 derivation | — | `test_snowflake_privileged_normalization.py` | PASS | Message 5 |
| 64 | Privilege analysis | `snowflake_privileged_user`/`snowflake_privileged_role` derived records | `_derive_privileged_users`/`_derive_privileged_roles` | — | `test_snowflake_privileged_collection.py` | PASS | Message 5 |
| 65 | Privilege analysis | `snowflake_public_exposure` derived record | `_derive_public_exposure` | — | `test_snowflake_privileged_collection.py` | PASS | Message 5 |
| 66 | Privilege analysis | Zero additional SQL calls for derived privilege analysis | connector `fetch()` | — | `test_snowflake_scale_reliability.py::TestNoDuplicateQueries` | PASS | Message 5, re-certified message 7 |
| 67 | Findings | 31 total Security Findings registered | `security_rule_pack._RULE_META` | — | `test_snowflake_provider_depth_qa.py::test_snowflake_has_exactly_31_rules` | PASS | Message 6 |
| 68 | Findings | Severity distribution Critical 5 / High 13 / Medium 13 / Low 0 | `security_rule_pack.py` | — | `test_snowflake_security_findings.py` | PASS | Message 6 |
| 69 | Findings | All 31 rules reachable from evaluator | `security_rules/snowflake.py::evaluate` | — | `test_snowflake_provider_depth_qa.py::test_all_snowflake_rules_reachable_from_evaluator` | PASS | |
| 70 | Findings | All 31 rules have confidence entries | `security_rule_confidence.RULE_CONFIDENCE` | — | `test_snowflake_provider_depth_qa.py::test_all_snowflake_rules_have_confidence` | PASS | |
| 71 | Findings | All 31 rules mapped to coverage record types | `security_coverage_service.RULE_RECORD_TYPES` | — | `test_snowflake_provider_depth_qa.py::test_snowflake_in_coverage_record_types` | PASS | |
| 72 | Findings | Frontend security rule catalog has Snowflake entries | `securityRuleCatalog.ts` | Findings UI | pre-existing message-6 parity | PASS | Not modified this message (no new rules) |
| 73 | Findings | ACCOUNTADMIN/service-ACCOUNTADMIN/SECURITYADMIN Findings render correctly | `snowflake_user_accountadmin` etc. | Findings UI | `test_snowflake_change_parity.py::TestPersonAccountadminParity` etc. | PASS | |
| 74 | Findings | PUBLIC future data-access / future-ownership Findings render correctly | `snowflake_public_future_data_access` etc. | Findings UI | `test_snowflake_change_parity.py::TestPublicFutureDataAccessParity` | PASS | |
| 75 | Findings | Network-anywhere / MFA-weak Findings render correctly | `snowflake_network_policy_allows_anywhere` etc. | Findings UI | `test_snowflake_change_parity.py::TestAnywhereNetworkParity`, `TestMfaWeakPostureParity` | PASS | |
| 76 | Findings | SCIM high/critical run-as Findings render correctly | `snowflake_scim_*_privilege_run_as` | Findings UI | `test_snowflake_change_parity.py::TestScimRunAsParity` | PASS | Bug fixed message 7 |
| 77 | Changes | Real `compute_diff()` → `classify_change()` pipeline used throughout | `diff_service.py` / `risk_service.py` | — | all `test_snowflake_change_*.py` files | PASS | Never hand-rolled Change dicts |
| 78 | Changes | User re-enabled / ACCOUNTADMIN granted / MANAGE GRANTS gained classify correctly | `_classify_user_change`, `_classify_privileged_user_change` | Changes UI | `test_snowflake_change_classification.py` | PASS | |
| 79 | Changes | Role-hierarchy edge added classifies correctly | `_classify_role_hierarchy_change` | Changes UI | `test_snowflake_change_classification.py` | PASS | |
| 80 | Changes | PUBLIC future SELECT granted classifies correctly (never "internet exposed") | `_classify_public_exposure_change` | Changes UI | `test_snowflake_change_classification.py::TestPublicSemanticsRegression` | PASS | |
| 81 | Changes | Managed-access schema owner changed classifies correctly | `_classify_schema_change` / ownership handling | Changes UI | `test_snowflake_data_diff.py` | PASS | |
| 82 | Changes | Anywhere network access introduced classifies correctly | `_classify_network_policy_change` | Changes UI | `test_snowflake_change_classification.py::TestNetworkPolicyChangeQA` | PASS | |
| 83 | Changes | MFA weakened classifies correctly | `_classify_authentication_policy_change` | Changes UI | `test_snowflake_change_classification.py::TestAuthenticationPolicyMfaModeQA` | PASS | |
| 84 | Changes | SCIM run-as role escalated classifies correctly | `_classify_security_integration_change` | Changes UI | `test_snowflake_change_parity.py::TestScimRunAsParity` | PASS | Bug fixed message 7 |
| 85 | Reliability | 21/21 record types tracked in diff_service | `diff_service.py` | — | `test_snowflake_provider_depth_qa.py::test_all_21_record_types_tracked_in_diff_service` | PASS | |
| 86 | Reliability | 21/21 record types classified in risk_rules | `risk_rules/snowflake.py` | — | `test_snowflake_provider_depth_qa.py::test_all_21_record_types_classified_in_risk_rules` | PASS | |
| 87 | Reliability | Family-level false-removal suppression | `_snowflake_removal_suppressed()` | — | `test_snowflake_partial_sync.py::TestAccountWideSuppression` | PASS | Message 7 |
| 88 | Reliability | Per-database completeness (schemas/database-roles/future-grants) | connector per-database status dicts | — | `test_snowflake_partial_sync.py::TestPerDatabaseSuppression` | PASS | Message 7 |
| 89 | Reliability | Per-role completeness (hierarchy/object grants) | connector per-role status dicts | — | `test_snowflake_partial_sync.py::TestPerRoleSuppression` | PASS | Message 7 |
| 90 | Reliability | Derived-record (privileged user/role/PUBLIC exposure) suppression | `_snowflake_removal_suppressed()` | — | `test_snowflake_partial_sync.py::TestDerivedRecordSuppression` | PASS | Message 7 |
| 91 | Reliability | First-sync produces only additions, no fabricated history | `compute_diff()` | — | `test_snowflake_partial_sync.py::TestFirstSyncAndRecovery` | PASS | Message 7 |
| 92 | Reliability | Recovery after partial sync diffs against last complete state | `compute_diff()` | — | `test_snowflake_partial_sync.py::test_recovery_after_partial_sync_diffs_against_last_complete_state` | PASS | Message 7 |
| 93 | Reliability | HTTP 408 classified as timeout, not retried as server error | `_classify_response` | — | `test_snowflake_sql_api_reliability.py::TestHttp408Timeout` | PASS | Message 7 |
| 94 | Reliability | Bounded polling (5 attempts), bounded throttle/server-error retry | `_poll_statement`, backoff constants | — | `test_snowflake_sql_api_reliability.py::TestNoInfiniteLoops` | PASS | Message 7 |
| 95 | Reliability | No result-partition pagination, no cancel-endpoint usage (documented gaps) | connector transport code | — | `test_snowflake_sql_api_reliability.py::TestDocumentedGaps` | PASS | Message 7 |
| 96 | Reliability | Deterministic ordering / idempotency at scale | connector `fetch()` | — | `test_snowflake_scale_reliability.py::TestDeterminismAndIdempotency` | PASS | Message 7 |
| 97 | Reliability | Call-count formula matches expectation (no N+1 regressions) | connector `fetch()` | — | `test_snowflake_scale_reliability.py::test_call_count_formula_matches_expectation` | PASS | Message 7 |
| 98 | Reliability | Full message-7 reliability certification still valid (no connector code touched this message) | — | — | `snowflake_reliability_certification.md` (message 7, unaffected) | PASS | Re-affirmed §13 of this message's certification |
| 99 | Security | PAT never logged, never in Authorization-header-adjacent exception text | `snowflake.py` | — | `test_snowflake_provider_depth_qa.py::TestSensitiveDataBoundary` | PASS | |
| 100 | Security | PAT never in `resource_metadata` | `_create_snowflake_integration` | — | `test_snowflake_provider_depth_qa.py::test_account_resource_metadata_never_contains_token` | PASS | |
| 101 | Security | PAT never in reconnect logs | `reconnect_credentials_snowflake` | — | `test_snowflake_provider_depth_qa.py::test_reconnect_snowflake_never_logs_new_token` | PASS | |
| 102 | Security | PAT never in create/get HTTP responses | `routers/integrations.py` | — | `test_snowflake_integration_creation.py::TestSensitiveCredentialsNeverLeak` | PASS | |
| 103 | Security | Encrypted credentials column is not plaintext | `encryption.py` | — | `test_snowflake_integration_creation.py::test_encrypted_credentials_column_is_not_plaintext` | PASS | |
| 104 | Security | No mutating SQL statement ever constructed as executable | `snowflake.py` statement constants | — | `test_snowflake_provider_depth_qa.py::test_no_mutating_sql_statements_in_connector` | PASS | |
| 105 | Security | No `USE ROLE`/`USE WAREHOUSE` anywhere | `snowflake.py` | — | `test_snowflake_provider_depth_qa.py::test_no_mutating_sql_statements_in_connector` | PASS | Role/session via SQL API request params |
| 106 | Security | No CLI/subprocess dependency | `snowflake.py` | — | `test_snowflake_provider_depth_qa.py::test_no_cli_or_subprocess_dependency` | PASS | |
| 107 | Security | No sensationalist/PUBLIC-internet wording anywhere in connector/rules | `risk_rules/snowflake.py`, `security_rules/snowflake.py` | — | pre-existing message 6/7 greps, re-verified this message | PASS | |
| 108 | Frontend | Snowflake in `PROVIDER_IDS` | `providers.ts` | Integrations list | `test_snowflake_provider_depth_qa.py::test_snowflake_in_provider_ids` | PASS | Flipped this message |
| 109 | Frontend | Snowflake in `CONNECTABLE_PROVIDER_IDS` | `providers.ts` | Integrations list | `test_snowflake_provider_depth_qa.py::test_snowflake_in_connectable_provider_ids` | PASS | Flipped this message |
| 110 | Frontend | Card copy omits stale "planned"/"not yet connectable" wording | `providers.ts` | Integration card | `test_snowflake_provider_depth_qa.py::test_snowflake_card_copy_omits_stale_planned_wording` | PASS | Rewritten this message |
| 111 | Frontend | Card copy never claims internet-exposure wording | `providers.ts` | Integration card | `test_snowflake_provider_depth_qa.py::test_snowflake_card_copy_never_claims_internet_exposure_wording` | PASS | |
| 112 | Frontend | Card copy omits unsupported capability claims | `providers.ts` | Integration card | `test_snowflake_provider_depth_qa.py::test_snowflake_card_copy_omits_unsupported_claims` | PASS | |
| 113 | Frontend | `SnowflakeIntegrationForm.tsx` exists and is wired into the integrations page | new component | Setup form | `test_snowflake_provider_depth_qa.py::test_snowflake_form_component_exists`, `test_snowflake_form_wired_into_integrations_page` | PASS | New this message |
| 114 | Frontend | Form never prefills/echoes token after success | `SnowflakeIntegrationForm.tsx` | Setup form | `test_snowflake_provider_depth_qa.py::test_snowflake_form_never_prefills_or_echoes_token_after_success` | PASS | |
| 115 | Frontend | Form never defaults role field to ACCOUNTADMIN/SECURITYADMIN | `SnowflakeIntegrationForm.tsx` | Setup form | `test_snowflake_provider_depth_qa.py::test_snowflake_form_never_defaults_to_admin_roles` | PASS | |
| 116 | Frontend | `IntegrationCreateRequest.provider` TS union includes `"snowflake"` | `types/index.ts` | — | `npx tsc --noEmit` | PASS | Fixed this message (was a real compile error) |
| 117 | Deployment | No new DB column/migration required | `models/integration.py`, `models/resource.py` | — | code review (certification §15) | N/A | Existing generic JSON `resource_metadata` column reused |
| 118 | Deployment | No Snowflake Python Connector / Snowpark / ODBC / JDBC / CLI dependency | `requirements.txt` (unchanged) | — | `test_snowflake_provider_depth_qa.py::test_no_cli_or_subprocess_dependency` | PASS | `httpx` only |
| 119 | Deployment | No new global env var required | connector credential model | — | code review | PASS | Credentials live in encrypted integration storage only |
| 120 | Limitations | No table/view row (query-result) ingestion | — | — | certification §16 | N/A | Documented, out of scope |
| 121 | Limitations | No query-history / login-history ingestion | — | — | certification §16 | N/A | Documented, out of scope |
| 122 | Limitations | No runtime session monitoring / anomaly detection | — | — | certification §16 | N/A | Documented, out of scope |
| 123 | Limitations | No sensitive-data discovery/classification | — | — | certification §16 | N/A | Documented, out of scope |
| 124 | Limitations | No current (non-future) PUBLIC object-grant Finding | — | — | certification §16 | N/A | Current PUBLIC grants not collected, only future |
| 125 | Limitations | No SQL API cancellation-endpoint / result-pagination usage | connector transport code | — | `test_snowflake_sql_api_reliability.py::TestDocumentedGaps` | N/A | Documented gap since message 7 |

**125 rows.** No launch-critical row is marked GAP — every `N/A` corresponds to an explicitly documented, non-launch-blocking limitation in `snowflake_provider_certification.md` §16.
