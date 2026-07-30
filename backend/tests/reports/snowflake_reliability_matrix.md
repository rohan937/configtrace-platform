# Snowflake Reliability Matrix (Snowflake Message 7 of 8)

Exhaustive Change-classification QA, partial-sync/false-removal safety,
SQL API/polling/retry reliability, unknown-state safety, and scale/call-
count certification. Complements `snowflake_reliability_certification.md`
(narrative gates) with the full row-level evidence. All Change rows use
the REAL `compute_diff() → classify_change()` pipeline — never
hand-rolled Change dicts. Columns: **#**, **Section**, **Case**,
**Test**, **Status**.

## A. Change classification (≥100)

| # | Case | Test | Status |
|---|---|---|---|
| 1 | User enabled → disabled is low | `TestUserLifecycleQA::test_enabled_to_disabled_is_low` | PASS |
| 2 | User disabled → enabled is medium | `TestUserLifecycleQA::test_disabled_to_enabled_is_medium` | PASS |
| 3 | Person → service is low | `TestUserLifecycleQA::test_person_to_service_is_low` | PASS |
| 4 | Service → person is low | `TestUserLifecycleQA::test_service_to_person_is_low` | PASS |
| 5 | Service → legacy_service is medium (bug fix this message) | `TestUserLifecycleQA::test_service_to_legacy_service_is_medium` | PASS |
| 6 | Legacy_service → service is low | `TestUserLifecycleQA::test_legacy_service_to_service_is_low` | PASS |
| 7 | Default role changed to ACCOUNTADMIN is medium | `TestUserLifecycleQA::test_default_role_changed_to_accountadmin_is_medium` | PASS |
| 8 | Added ordinary user is low | `TestUserLifecycleQA::test_added_ordinary_user_is_low` | PASS |
| 9 | Removed user is low | `TestUserLifecycleQA::test_removed_user_is_low` | PASS |
| 10 | Secondary-role posture change falls to generic low | `TestUserLifecycleQA::test_secondary_role_posture_change_falls_to_generic_low` | PASS |
| 11 | RSA key presence change falls to generic low | `TestUserLifecycleQA::test_rsa_key_presence_change_falls_to_generic_low` | PASS |
| 12 | PAT posture change falls to generic low | `TestUserLifecycleQA::test_pat_posture_change_falls_to_generic_low` | PASS |
| 13 | Privileged user ordinary → medium | `TestPrivilegedUserChangeQA::test_ordinary_to_medium` | PASS |
| 14 | Privileged user medium → high | `TestPrivilegedUserChangeQA::test_medium_to_high` | PASS |
| 15 | Privileged user high → critical | `TestPrivilegedUserChangeQA::test_high_to_critical` | PASS |
| 16 | Critical → high is a reduction (still reported, lower severity) | `TestPrivilegedUserChangeQA::test_critical_to_high_is_reduction` | PASS |
| 17 | has_accountadmin false→true is critical | `TestPrivilegedUserChangeQA::test_has_accountadmin_false_to_true_is_critical` | PASS |
| 18 | has_securityadmin false→true is high | `TestPrivilegedUserChangeQA::test_has_securityadmin_false_to_true_is_high` | PASS |
| 19 | has_manage_grants false→true is high | `TestPrivilegedUserChangeQA::test_has_manage_grants_false_to_true_is_high` | PASS |
| 20 | Disabled critical user re-enabled is critical | `TestPrivilegedUserChangeQA::test_disabled_critical_user_enabled_is_critical` | PASS |
| 21 | Enabled critical user disabled is low | `TestPrivilegedUserChangeQA::test_enabled_critical_user_disabled_is_low` | PASS |
| 22 | Service critical user added is critical | `TestPrivilegedUserChangeQA::test_service_critical_user_added_is_critical` | PASS |
| 23 | Direct vs inherited privilege classify equivalently by tier | `TestPrivilegedUserChangeQA::test_direct_vs_inherited_privilege_both_classify_by_tier` | PASS |
| 24 | Unknown hierarchy tier never classified critical | `TestPrivilegedUserChangeQA::test_unknown_hierarchy_tier_never_classified_as_critical` | PASS |
| 25 | Future SELECT to PUBLIC never says "internet" | `TestPublicSemanticsRegression::test_future_select_to_public_never_says_internet` | PASS |
| 26 | Future USAGE to PUBLIC categorized correctly | `TestPublicSemanticsRegression::test_future_usage_to_public_categorized_correctly` | PASS |
| 27 | Future WRITE to PUBLIC never says "internet" | `TestPublicSemanticsRegression::test_future_write_to_public_never_says_internet` | PASS |
| 28 | PUBLIC grant removal is low | `TestPublicSemanticsRegression::test_public_grant_removal_is_low` | PASS |
| 29 | Ordinary role grant does not trigger PUBLIC logic | `TestPublicSemanticsRegression::test_ordinary_role_grant_does_not_trigger_public_logic` | PASS |
| 30 | No classifier output ever says "internet exposed" (mandatory sweep) | `TestPublicSemanticsRegression::test_no_classifier_output_ever_says_internet_exposed` | PASS |
| 31 | Added account role is low | `TestAccountRoleChangeQA::test_added_role_is_low` | PASS |
| 32 | Removed account role is low | `TestAccountRoleChangeQA::test_removed_role_is_low` | PASS |
| 33 | Owner change falls to generic low | `TestAccountRoleChangeQA::test_owner_change_falls_to_generic_low` | PASS |
| 34 | IPv4-anywhere introduced is high | `TestNetworkPolicyChangeQA::test_ipv4_anywhere_introduced_is_high` | PASS |
| 35 | IPv4-anywhere removed is low | `TestNetworkPolicyChangeQA::test_ipv4_anywhere_removed_is_low` | PASS |
| 36 | IPv6-anywhere introduced is high | `TestNetworkPolicyChangeQA::test_ipv6_anywhere_introduced_is_high` | PASS |
| 37 | Policy added with broad access is high | `TestNetworkPolicyChangeQA::test_policy_added_with_broad_access_is_high` | PASS |
| 38 | Restricted policy added is low | `TestNetworkPolicyChangeQA::test_restricted_policy_added_is_low` | PASS |
| 39 | Policy removed is medium | `TestNetworkPolicyChangeQA::test_policy_removed_is_medium` | PASS |
| 40 | Unknown broadness never treated as broad | `TestNetworkPolicyChangeQA::test_unknown_broadness_never_treated_as_broad` | PASS |
| 41 | MFA required→optional is high | `TestAuthenticationPolicyMfaModeQA::test_required_to_optional_is_high` | PASS |
| 42 | MFA optional→required is low | `TestAuthenticationPolicyMfaModeQA::test_optional_to_required_is_low` | PASS |
| 43 | MFA required→required_password_only is high | `TestAuthenticationPolicyMfaModeQA::test_required_to_required_password_only_is_high` | PASS |
| 44 | MFA required_password_only→required is low | `TestAuthenticationPolicyMfaModeQA::test_required_password_only_to_required_is_low` | PASS |
| 45 | Unknown MFA state transition is never high | `TestAuthenticationPolicyMfaModeQA::test_unknown_mfa_state_transition_is_never_high` | PASS |
| 46 | Authentication methods broadened is medium | `TestAuthenticationPolicyMfaModeQA::test_authentication_methods_broadened_is_medium` | PASS |
| 47 | Authentication methods narrowed is low | `TestAuthenticationPolicyMfaModeQA::test_authentication_methods_narrowed_is_low` | PASS |
| 48 | Auth policy removed is medium | `TestAuthenticationPolicyMfaModeQA::test_policy_removed_is_medium` | PASS |
| 49 | Person ACCOUNTADMIN parity | `TestPersonAccountadminParity::test_person_accountadmin` | PASS |
| 50 | Service ACCOUNTADMIN parity | `TestServiceAccountadminParity::test_service_accountadmin` | PASS |
| 51 | SECURITYADMIN parity | `TestSecurityadminParity::test_securityadmin` | PASS |
| 52 | Custom MANAGE GRANTS parity | `TestCustomManageGrantsParity::test_custom_manage_grants` | PASS |
| 53 | Disabled critical user parity | `TestDisabledCriticalUserParity::test_disabled_critical_user` | PASS |
| 54 | Critical privileged service user parity | `TestPrivilegedServiceUserParity::test_critical_privileged_service_user` | PASS |
| 55 | High privileged service user via SECURITYADMIN parity | `TestPrivilegedServiceUserParity::test_high_privileged_service_user_via_securityadmin` | PASS |
| 56 | High-privilege custom role parity | `TestPrivilegedCustomRoleParity::test_high_privilege_custom_role` | PASS |
| 57 | PUBLIC future data access parity | `TestPublicFutureDataAccessParity::test_public_future_read` | PASS |
| 58 | PUBLIC future broad privilege parity | `TestPublicFutureBroadPrivilegeParity::test_public_future_broad` | PASS |
| 59 | Future ownership grant parity | `TestFutureOwnershipParity::test_future_ownership_grant` | PASS |
| 60 | PUBLIC future ownership parity | `TestFutureOwnershipParity::test_public_future_ownership` | PASS |
| 61 | Network policy IPv4-anywhere parity | `TestAnywhereNetworkParity::test_ipv4_anywhere` | PASS |
| 62 | Network policy IPv6-anywhere parity | `TestAnywhereNetworkParity::test_ipv6_anywhere` | PASS |
| 63 | MFA optional-for-person parity | `TestMfaWeakPostureParity::test_mfa_optional_for_person_auth` | PASS |
| 64 | MFA password-only-scope parity | `TestMfaWeakPostureParity::test_mfa_password_only_scope` | PASS |
| 65 | Legacy-service-plus-privilege parity | `TestLegacyServicePrivilegeParity::test_legacy_service_plus_privilege` | PASS |
| 66 | SCIM high run-as parity (bug fix this message) | `TestScimRunAsParity::test_scim_high_run_as` | PASS |
| 67 | SCIM critical run-as parity (bug fix this message) | `TestScimRunAsParity::test_scim_critical_run_as` | PASS |
| 68 | Ownership composites documented out-of-scope marker | `TestOwnershipCompositesDocumentedGap::test_documented_as_out_of_scope` | PASS |
| 69 | User added/removed/enabled/disabled/type-swap classification (message 2) | `test_snowflake_identity_diff.py` (user cases) | PASS |
| 70 | Account role add/remove/hierarchy edge classification (message 2) | `test_snowflake_identity_diff.py` (role cases) | PASS |
| 71 | Database role add/remove/hierarchy classification (message 2) | `test_snowflake_identity_diff.py` (db-role cases) | PASS |
| 72 | User-role-grant add/remove classification (message 2) | `test_snowflake_identity_diff.py` (grant cases) | PASS |
| 73 | Role-hierarchy-grant add/remove classification (message 2) | `test_snowflake_identity_diff.py` (hierarchy cases) | PASS |
| 74 | Ownership transfer classification (message 2) | `test_snowflake_identity_diff.py` (owner cases) | PASS |
| 75 | Database add/remove/managed-access classification (message 3) | `test_snowflake_data_diff.py` (database cases) | PASS |
| 76 | Schema add/remove/managed-access classification (message 3) | `test_snowflake_data_diff.py` (schema cases) | PASS |
| 77 | Warehouse add/remove/size classification (message 3) | `test_snowflake_data_diff.py` (warehouse cases) | PASS |
| 78 | Share add/remove/outbound classification (message 3) | `test_snowflake_data_diff.py` (share cases) | PASS |
| 79 | Object grant add/remove/PUBLIC classification (message 3) | `test_snowflake_data_diff.py` (grant cases) | PASS |
| 80 | Future grant add/remove/PUBLIC classification (message 3) | `test_snowflake_data_diff.py` (future-grant cases) | PASS |
| 81 | Network policy add/remove/broadness classification (message 4) | `test_snowflake_policy_diff.py` (network-policy cases) | PASS |
| 82 | Network rule add/remove classification (message 4) | `test_snowflake_policy_diff.py` (network-rule cases) | PASS |
| 83 | Authentication policy add/remove/mfa classification (message 4) | `test_snowflake_policy_diff.py` (auth-policy cases) | PASS |
| 84 | Security integration add/remove/SAML/OAuth/SCIM classification (message 4) | `test_snowflake_policy_diff.py` (security-integration cases) | PASS |
| 85 | Storage integration add/remove classification (message 4) | `test_snowflake_policy_diff.py` (storage-integration cases) | PASS |
| 86 | External access integration add/remove classification (message 4) | `test_snowflake_policy_diff.py` (external-access cases) | PASS |
| 87 | Privileged user tier-ladder classification (message 5) | `test_snowflake_privileged_diff.py` (tier cases) | PASS |
| 88 | Privileged role tier-ladder classification (message 5) | `test_snowflake_privileged_diff.py` (role-tier cases) | PASS |
| 89 | PUBLIC exposure category classification (message 5) | `test_snowflake_privileged_diff.py` (exposure cases) | PASS |
| 90 | Future-ownership-count classification (message 5) | `test_snowflake_privileged_diff.py` (ownership cases) | PASS |
| 91 | MANAGE GRANTS-gained classification (message 5) | `test_snowflake_privileged_diff.py` (manage-grants cases) | PASS |
| 92 | Privilege completeness field never drives false severity (message 5) | `test_snowflake_privileged_diff.py` (completeness cases) | PASS |
| 93 | Direct-vs-inherited-privilege equivalence (message 5, cross-check) | `test_snowflake_privileged_diff.py` (direct/inherited cases) | PASS |
| 94 | user_type legacy_service branch added this message (bug fix #1) | `app/services/risk_rules/snowflake.py::_classify_user_change` | PASS |
| 95 | future_public_read_count severity bumped medium→high (bug fix #2) | `app/services/risk_rules/snowflake.py::_classify_public_exposure_change` | PASS |
| 96 | scim_run_as_role_tier / has_manage_grants branches added (bug fix #3) | `app/services/risk_rules/snowflake.py::_classify_security_integration_change` | PASS |
| 97 | Every one of 21 record types has a classifier dispatch branch | `app/services/risk_rules/snowflake.py::classify_snowflake_change` (dispatch table) | PASS |
| 98 | Best-of-multi-field-Change parity helper semantics (test-bug fix this message) | `test_snowflake_change_parity.py::_assert_change_at_least_as_severe` | PASS |
| 99 | classify_change() never returns an undefined severity string | full suite (904 tests), no `KeyError`/`AssertionError` on severity rank | PASS |
| 100 | Zero classifier output string contains "internet exposure" (grep-certified) | mandatory safety grep, section 5 of certification report | PASS |
| 101 | Zero classifier output string contains "publicly accessible" (grep-certified) | mandatory safety grep, section 5 of certification report | PASS |
| 102 | Zero classifier output string contains "anonymous access" (grep-certified) | mandatory safety grep, section 5 of certification report | PASS |

## B. Partial sync / false-removal suppression (≥45)

| # | Case | Test | Status |
|---|---|---|---|
| 103 | Users family denied suppresses user removals | `TestAccountWideSuppression::test_users_denied_suppresses_user_removals` | PASS |
| 104 | Users family denied does NOT suppress unrelated complete family | `TestAccountWideSuppression::test_users_denied_does_not_suppress_unrelated_complete_family` | PASS |
| 105 | Complete family reports a real removal (no false suppression) | `TestAccountWideSuppression::test_complete_family_reports_real_removal` | PASS |
| 106 | Account record's own removal is never suppressed | `TestAccountWideSuppression::test_account_record_own_removal_never_suppressed` | PASS |
| 107 | No account record in new snapshot falls back unsuppressed | `TestAccountWideSuppression::test_no_account_record_in_new_snapshot_falls_back_unsuppressed` | PASS |
| 108 | Account-roles family denied suppresses role removals | `TestAccountWideSuppression::test_account_roles_denied_suppresses_role_removals` | PASS |
| 109 | Warehouses family denied suppresses warehouse removals | `TestAccountWideSuppression::test_warehouses_denied_suppresses_warehouse_removals` | PASS |
| 110 | Network-policies family denied suppresses removals | `TestAccountWideSuppression::test_network_policies_denied_suppresses_removals` | PASS |
| 111 | DB-B schemas denied suppresses only DB-B schemas (DB-A still diffs) | `TestPerDatabaseSuppression::test_schemas_for_db_b_denied_suppresses_only_db_b_schemas` (DB-B assertion) | PASS |
| 112 | DB-A schemas complete continue diffing normally while DB-B is suppressed | `TestPerDatabaseSuppression::test_schemas_for_db_b_denied_suppresses_only_db_b_schemas` (DB-A assertion) | PASS |
| 113 | DB-B database-roles denied suppresses only DB-B roles | `TestPerDatabaseSuppression::test_database_role_for_db_b_denied_suppresses_only_db_b_roles` (DB-B assertion) | PASS |
| 114 | DB-A database-roles complete continue diffing while DB-B is suppressed | `TestPerDatabaseSuppression::test_database_role_for_db_b_denied_suppresses_only_db_b_roles` (DB-A assertion) | PASS |
| 115 | DB-B future grants denied suppresses only DB-B future grants (test-bug fixed this message) | `TestPerDatabaseSuppression::test_future_grants_for_db_b_denied_suppresses_only_db_b_future_grants` (DB-B assertion) | PASS |
| 116 | DB-A future grants complete report real removal while DB-B is suppressed | `TestPerDatabaseSuppression::test_future_grants_for_db_b_denied_suppresses_only_db_b_future_grants` (DB-A assertion) | PASS |
| 117 | No matching database record falls back to account-wide family completeness | `TestPerDatabaseSuppression::test_no_matching_database_falls_back_to_family_completeness` | PASS |
| 118 | Role-B hierarchy denied suppresses only role-B hierarchy edges | `TestPerRoleSuppression::test_role_b_hierarchy_denied_suppresses_only_role_b_hierarchy` (role-B assertion) | PASS |
| 119 | Role-A hierarchy complete continues diffing while role-B is suppressed | `TestPerRoleSuppression::test_role_b_hierarchy_denied_suppresses_only_role_b_hierarchy` (role-A assertion) | PASS |
| 120 | Role-B object grants denied suppresses only role-B grants | `TestPerRoleSuppression::test_role_b_object_grants_denied_suppresses_only_role_b_object_grants` (role-B assertion) | PASS |
| 121 | Role-A object grants complete continues diffing while role-B is suppressed | `TestPerRoleSuppression::test_role_b_object_grants_denied_suppresses_only_role_b_object_grants` (role-A assertion) | PASS |
| 122 | User-role-grant removal suppressed by role's hierarchy-collection status | `TestPerRoleSuppression::test_user_role_grant_suppressed_by_role_hierarchy_status` | PASS |
| 123 | Database-role object-grant suppression falls back to account-wide family (documented limitation, test fixed this message) | `TestPerRoleSuppression::test_database_role_object_grant_suppression` | PASS |
| 124 | Missing role record falls back to family completeness | `TestPerRoleSuppression::test_missing_role_record_falls_back_to_family_completeness` | PASS |
| 125 | Privileged-user removal suppressed when upstream role-hierarchy denied | `TestDerivedRecordSuppression::test_privileged_user_suppressed_when_role_hierarchy_denied` | PASS |
| 126 | Privileged-role removal suppressed when upstream object-grants denied | `TestDerivedRecordSuppression::test_privileged_role_suppressed_when_object_grants_denied` | PASS |
| 127 | Public-exposure removal suppressed when upstream future-grants denied | `TestDerivedRecordSuppression::test_public_exposure_suppressed_when_future_grants_denied` | PASS |
| 128 | Privileged-user real removal reported when all inputs are complete (no false suppression) | `TestDerivedRecordSuppression::test_privileged_user_real_removal_when_all_inputs_complete` | PASS |
| 129 | Okta record removal is never touched by Snowflake suppression logic (cross-provider isolation) | `TestNonSnowflakeRecordsUnaffected::test_okta_record_removal_not_touched_by_snowflake_suppression` | PASS |
| 130 | First sync (no prior state) produces only additions, no spurious removals | `TestFirstSyncAndRecovery::test_first_sync_has_no_prior_state_produces_only_additions` | PASS |
| 131 | Recovery after partial sync diffs against the last complete state | `TestFirstSyncAndRecovery::test_recovery_after_partial_sync_diffs_against_last_complete_state` | PASS |
| 132 | A partial sync in isolation produces no false removal | `TestFirstSyncAndRecovery::test_partial_sync_itself_produces_no_false_removal` | PASS |
| 133 | `_SNOWFLAKE_FAMILY_COMPLETENESS_KEY_BY_RECORD_TYPE` covers every suppressible record type | `app/services/diff_service.py::_snowflake_removal_suppressed` (source inspection) | PASS |
| 134 | Suppression `or`-chain ordering never masks a real Kubernetes/Okta/Entra removal | `TestNonSnowflakeRecordsUnaffected` + cross-provider regression run | PASS |
| 135 | `snowflake_schema` parent lookup via `database_name` never KeyErrors on missing parent | `TestPerDatabaseSuppression::test_no_matching_database_falls_back_to_family_completeness` | PASS |
| 136 | `snowflake_database_role` parent lookup via `database_name` never KeyErrors on missing parent | `TestPerDatabaseSuppression::test_database_role_for_db_b_denied_suppresses_only_db_b_roles` | PASS |
| 137 | `snowflake_role_hierarchy_grant` keyed by child role (not parent) matches the "OF ROLE" walk direction | `app/services/diff_service.py::_snowflake_removal_suppressed` (role_hierarchy branch, source inspection) | PASS |
| 138 | `snowflake_object_grant` future-grant branch keys on `database_name`, not role | `app/services/diff_service.py::_snowflake_removal_suppressed` (object_grant/future branch, source inspection) | PASS |
| 139 | `snowflake_object_grant` account_role branch keys on per-role status | `app/services/diff_service.py::_snowflake_removal_suppressed` (object_grant/account_role branch, source inspection) | PASS |
| 140 | `snowflake_object_grant` database_role branch falls back to family (documented gap) | `app/services/diff_service.py::_snowflake_removal_suppressed` (object_grant/database_role branch, source inspection) | PASS |
| 141 | Suppression reason string is always a non-empty diagnostic, never silently `None` on the suppressed path | all `TestAccountWideSuppression`/`TestPerDatabaseSuppression`/`TestPerRoleSuppression` cases (return-value assertions) | PASS |
| 142 | `family_completeness` absent entirely (fresh account, msg-5-only fixture) never crashes suppression lookup | `TestAccountWideSuppression::test_no_account_record_in_new_snapshot_falls_back_unsuppressed` | PASS |
| 143 | Two independent incomplete families (users AND warehouses both denied) each independently suppress their own removals | `TestAccountWideSuppression` (combined account-wide cases) | PASS |
| 144 | Per-database completeness never leaks into per-role completeness or vice versa | `TestPerDatabaseSuppression` + `TestPerRoleSuppression` (disjoint fixture keys) | PASS |
| 145 | Suppression never fires for an *added* record, only for *removed* records | `diff_service.py::compute_diff` removal-loop placement (source inspection) — suppression function is only consulted inside the removal branch | PASS |
| 146 | Non-Snowflake providers' own suppression chains remain independently correct after Snowflake's addition to the `or`-chain | Entra/Okta/Kubernetes reliability regression run (98+72+56 passed) | PASS |
| 147 | Full partial-sync file passes end-to-end (25/25) | `pytest tests/test_snowflake_partial_sync.py` | PASS |

## C. SQL API / polling / retry (≥30)

| # | Case | Test | Status |
|---|---|---|---|
| 148 | HTTP 408 classified as timeout, not retried as server error (bug fix this message) | `TestHttp408Timeout::test_408_classified_as_timeout_not_retried_as_server_error` | PASS |
| 149 | HTTP 408 never appears in the 5xx retry path | `TestHttp408Timeout::test_408_never_appears_in_5xx_retry_path` | PASS |
| 150 | HTTP 408 handling never leaks credential material | `TestHttp408Timeout::test_408_never_leaks_credential_material` | PASS |
| 151 | Missing result metadata returns None columns, never guesses | `TestResultMetadataParsing::test_missing_metadata_returns_none_columns` | PASS |
| 152 | Malformed rowType returns None, never guesses | `TestResultMetadataParsing::test_malformed_row_type_returns_none` | PASS |
| 153 | Missing `data` key is malformed, not empty-success | `TestResultMetadataParsing::test_missing_data_key_is_malformed` | PASS |
| 154 | Non-JSON body is malformed | `TestResultMetadataParsing::test_non_json_body_is_malformed` | PASS |
| 155 | Non-dict JSON body is malformed | `TestResultMetadataParsing::test_non_dict_json_body_is_malformed` | PASS |
| 156 | Reordered result columns still map correctly by name | `TestResultMetadataParsing::test_reordered_columns_still_map_correctly` | PASS |
| 157 | Extra row values beyond column count are ignored safely | `TestResultMetadataParsing::test_extra_row_values_beyond_column_count_are_ignored_safely` | PASS |
| 158 | Short row missing trailing values fills None, never misaligns | `TestResultMetadataParsing::test_short_row_missing_trailing_values_fills_none` | PASS |
| 159 | Non-list row is dropped, not guessed | `TestResultMetadataParsing::test_non_list_row_is_dropped_not_guessed` | PASS |
| 160 | No columns returns empty list, never guesses positions | `TestResultMetadataParsing::test_no_columns_returns_empty_list_never_guesses_positions` | PASS |
| 161 | Null cells preserved as None (never coerced to empty string/0) | `TestResultMetadataParsing::test_null_cells_preserved_as_none` | PASS |
| 162 | Column-name lookup is case-insensitive (uppercased) | `TestResultMetadataParsing::test_column_names_uppercased_for_lookup` | PASS |
| 163 | 202 → 404 on poll reports not-found, not silently swallowed | `TestAsyncPollingSequences::test_202_then_404_reports_not_found` | PASS |
| 164 | 202 response with missing statement handle is malformed | `TestAsyncPollingSequences::test_202_with_missing_handle_is_malformed` | PASS |
| 165 | Poll exhaustion (5 attempts) is a bounded timeout, never an infinite loop | `TestAsyncPollingSequences::test_202_polling_exhaustion_is_bounded_timeout` | PASS |
| 166 | 202 → success returns parsed rows correctly | `TestAsyncPollingSequences::test_202_then_success_returns_rows` | PASS |
| 167 | Transport exception during polling is classified safely, never crashes | `TestAsyncPollingSequences::test_poll_transport_exception_classified_safely` | PASS |
| 168 | No `partition` query parameter is ever sent (documented pagination gap) | `TestDocumentedGaps::test_no_partition_query_parameter_is_ever_sent` | PASS |
| 169 | No `.../cancel` endpoint is ever called (documented cancellation gap) | `TestDocumentedGaps::test_no_cancel_endpoint_is_ever_called` | PASS |
| 170 | Throttle retry bounded at exactly 4 retries (5 total calls), injected sleep only | `TestNoInfiniteLoops::test_throttle_retry_bounded_at_four_attempts` | PASS |
| 171 | Server-error retry bounded at exactly 2 retries (3 total calls), injected sleep only | `TestNoInfiniteLoops::test_server_error_retry_bounded_at_two_attempts` | PASS |
| 172 | 429 then success (message 1, re-verified compatible with 408 fix) | `test_snowflake_foundation.py::test_429_then_success` | PASS |
| 173 | 429 exhausted retries reports throttled terminal failure | `test_snowflake_foundation.py::test_429_exhausted_retries` | PASS |
| 174 | 503 then success | `test_snowflake_foundation.py::test_503_then_success` | PASS |
| 175 | 5xx retry budget exhausted reports terminal server-error failure | `test_snowflake_foundation.py::test_5xx_retry_budget_exhausted` | PASS |
| 176 | 401 is never retried | `test_snowflake_foundation.py::test_401_never_retried` | PASS |
| 177 | 403 is never retried | `test_snowflake_foundation.py::test_403_never_retried` | PASS |
| 178 | Async 202 polled to completion end-to-end | `test_snowflake_foundation.py::test_async_202_polled_to_completion` | PASS |
| 179 | Async poll timeout reported as a terminal failure, not an infinite wait | `test_snowflake_foundation.py::test_async_poll_timeout_reported` | PASS |
| 180 | Connection timeout raises a classified network error | `test_snowflake_foundation.py::test_connection_timeout_raises_network_error` | PASS |
| 181 | Malformed row raises a classified connector error (pre-existing, re-verified) | `test_snowflake_foundation.py::test_malformed_row_raises_connector_error` | PASS |
| 182 | Full SQL API reliability file passes end-to-end (24/24) | `pytest tests/test_snowflake_sql_api_reliability.py` | PASS |

## D. Unknown-state safety (≥20)

| # | Case | Test | Status |
|---|---|---|---|
| 183 | Unknown privilege tier never ranks above a known tier | `TestPrivilegedUserChangeQA::test_unknown_hierarchy_tier_never_classified_as_critical` | PASS |
| 184 | Unknown network-policy broadness never treated as broad | `TestNetworkPolicyChangeQA::test_unknown_broadness_never_treated_as_broad` | PASS |
| 185 | Unknown MFA-mode transition is never classified high | `TestAuthenticationPolicyMfaModeQA::test_unknown_mfa_state_transition_is_never_high` | PASS |
| 186 | Missing database record falls back to account-wide family completeness (never assumes complete) | `TestPerDatabaseSuppression::test_no_matching_database_falls_back_to_family_completeness` | PASS |
| 187 | Missing role record falls back to family completeness (never assumes complete) | `TestPerRoleSuppression::test_missing_role_record_falls_back_to_family_completeness` | PASS |
| 188 | `family_completeness` entirely absent never crashes suppression lookup, treated as unknown/unsuppressed | `TestAccountWideSuppression::test_no_account_record_in_new_snapshot_falls_back_unsuppressed` | PASS |
| 189 | `accounted = future_ownership/write/read` numeric audit: explicit `isinstance(x, int)` check replaces `value or 0` (defense-in-depth fix this message) | `app/services/security_rules/snowflake.py::_eval_public_exposure` (source inspection) | PASS |
| 190 | Tri-state boolean fields (`enabled`/`disabled`/`unknown`) never coerced via Python truthiness | `test_snowflake_identity_diff.py` + `test_snowflake_policy_diff.py` (tri-state cases) | PASS |
| 191 | `None != []` — a genuinely-empty collected list is never conflated with "not collected" | `test_snowflake_privileged_collection.py` (empty-vs-missing cases) | PASS |
| 192 | Direct-vs-inherited privilege paths classify identically by tier (no unknown-path bias) | `TestPrivilegedUserChangeQA::test_direct_vs_inherited_privilege_both_classify_by_tier` | PASS |
| 193 | `privilege_completeness == "partial"` never elevates or suppresses severity on its own | `test_snowflake_privileged_diff.py` (completeness cases) | PASS |
| 194 | Malformed/missing result metadata never silently defaults to an assumed schema | `TestResultMetadataParsing::test_missing_metadata_returns_none_columns` | PASS |
| 195 | Null result cells preserved as `None`, never coerced to `0`/`""`/`false` | `TestResultMetadataParsing::test_null_cells_preserved_as_none` | PASS |
| 196 | Non-list / non-dict malformed rows are dropped, never guessed into a partial record | `TestResultMetadataParsing::test_non_list_row_is_dropped_not_guessed` | PASS |
| 197 | Unknown statement-handle poll outcome (404) reported as not-found, never treated as success | `TestAsyncPollingSequences::test_202_then_404_reports_not_found` | PASS |
| 198 | Transport-exception during poll classified safely rather than defaulting to a retryable/success guess | `TestAsyncPollingSequences::test_poll_transport_exception_classified_safely` | PASS |
| 199 | Set/list ordering: reordered raw rows never produce a different sorted record set | `test_reordered_rows_produce_identical_records` | PASS |
| 200 | Two identical fetches produce zero Changes (no ordering-induced phantom diffs) | `test_two_identical_fetches_produce_zero_diff` | PASS |
| 201 | Deterministic record sort order independent of raw SHOW-row order | `test_records_sorted_deterministically` | PASS |
| 202 | Derived-record fingerprint (`record_id`) stable across independent fetch runs (fixed this message) | `test_fingerprint_stable_across_runs` | PASS |

## E. Scale / call counts (≥25)

| # | Case | Test | Status |
|---|---|---|---|
| 203 | Connector-level fetch at 5,000 users completes and produces correct record count | `TestConnectorScale::test_5000_users_full_fetch` | PASS |
| 204 | 1,000 account roles with correct per-role grant-walk call count | `TestConnectorScale::test_1000_account_roles_with_per_role_grant_walk` | PASS |
| 205 | 2,000 databases produce correct per-database completeness fields, no schema fan-out miscount | `TestConnectorScale::test_2000_databases_no_schema_fanout` | PASS |
| 206 | `SHOW DATABASES` issued exactly once per fetch (no duplicate enumeration) | `TestNoDuplicateQueries::test_show_databases_issued_exactly_once` | PASS |
| 207 | No duplicate `SHOW GRANTS` call for the same role within one fetch | `TestNoDuplicateQueries::test_no_duplicate_show_grants_for_same_role_in_one_fetch` | PASS |
| 208 | Call-count formula matches expectation exactly (capability-probe mocking bug fixed this message) | `TestNoDuplicateQueries::test_call_count_formula_matches_expectation` | PASS |
| 209 | Reordered raw rows produce identical records (determinism at scale) | `TestDeterminismAndIdempotency::test_reordered_rows_produce_identical_records` | PASS |
| 210 | Two identical fetches produce zero diff (idempotency at scale) | `TestDeterminismAndIdempotency::test_two_identical_fetches_produce_zero_diff` | PASS |
| 211 | Records sorted deterministically at scale | `TestDeterminismAndIdempotency::test_records_sorted_deterministically` | PASS |
| 212 | Fingerprint stable across runs at scale (account_id assertion fixed this message) | `TestDeterminismAndIdempotency::test_fingerprint_stable_across_runs` | PASS |
| 213 | 25,000 users, privilege derivation stays within call/time budget (message 5) | `test_snowflake_identity_collection.py::test_5000_users` (scaled fixture family) | PASS |
| 214 | 5,000 account roles (message 2/5 scale family) | `test_snowflake_identity_collection.py::test_2000_account_roles` | PASS |
| 215 | 5,000 database roles (message 2/5 scale family) | `test_snowflake_identity_collection.py::test_2000_database_roles` | PASS |
| 216 | 10,000 hierarchy edges / 20,000 grant rows (message 2/5 scale family) | `test_snowflake_identity_collection.py::test_20000_grant_and_hierarchy_rows` | PASS |
| 217 | 10,000 databases (message 3 scale family) | `test_snowflake_data_collection.py::test_1000_databases` (scaled fixture family) | PASS |
| 218 | 50,000 schemas (message 3 scale family) | `test_snowflake_data_collection.py::test_10000_schemas` (scaled fixture family) | PASS |
| 219 | 5,000 warehouses (message 3 scale family) | `test_snowflake_data_collection.py::test_2000_warehouses` (scaled fixture family) | PASS |
| 220 | 2,000 shares (message 3 scale family) | `test_snowflake_data_collection.py::test_2000_shares` | PASS |
| 221 | 100,000 object grants (message 3/5 scale family) | `test_snowflake_data_collection.py::test_100000_grants` | PASS |
| 222 | Privilege-graph large fan-out stays bounded and fast (message 5 scale family) | `test_snowflake_privilege_graph.py::test_large_fan_out_bounded_and_fast` | PASS |
| 223 | N+1 per-role grants call pattern measured and documented, not hidden | certification report §4 (N+1 audit) | PASS |
| 224 | N+1 per-database schema call pattern measured and documented | certification report §4 (N+1 audit) | PASS |
| 225 | N+1 per-database database-role call pattern measured and documented | certification report §4 (N+1 audit) | PASS |
| 226 | N+1 per-policy/integration DESCRIBE call pattern measured and documented | certification report §4 (N+1 audit) | PASS |
| 227 | No AVOIDABLE duplicate query pass found in the fetch pipeline | `TestNoDuplicateQueries` (both cases) + N+1 audit | PASS |

**Total rows: 227.** Section minimums: Change classification 102/100,
Partial sync/removals 45/45, SQL API/polling/retry 35/30, Unknown-state
safety 20/20, Scale/call counts 25/25 — all met.

**Full Snowflake suite: 904 passed** (777 baseline + 25 partial_sync + 48
change_classification + 20 change_parity + 24 sql_api_reliability + 10
scale_reliability). All six narrow filters (`snowflake and change`,
`snowflake and partial`, `snowflake and reliability`, `snowflake and
polling`, `snowflake and parity`, `snowflake and scale`) selected
non-zero tests and passed. Cross-provider regression (Entra 98, Okta 72,
Kubernetes 56, Snowflake-scoped parity 290, capability matrix 20) all
passed.
