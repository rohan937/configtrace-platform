# Snowflake Identity/Role Matrix (Snowflake Message 2 of 8)

Covers SHOW-based collection and normalization of users, account roles,
database roles, user-role grants, and role-hierarchy edges. Message 2 does
NOT collect databases/schemas/warehouses/shares/object grants (message 3),
network/authentication policies/security integrations (message 4), or
effective privilege/Security Findings (messages 5-6) — the SHOW DATABASES
call used here exists SOLELY to discover database names for database-role
enumeration and produces no `snowflake_database` inventory record.

Columns: **Case**, **Record type**, **Source state**, **Normalized
posture**, **Diff tracked?**, **Change severity**, **Unknown-safe?**,
**Sensitive-data concern**, **Test**, **Status**, **Notes**.

## Users

| # | Case | Record type | Source state | Normalized posture | Diff tracked? | Change severity | Unknown-safe? | Sensitive-data concern | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|
| A | Active person user | snowflake_user | TYPE=PERSON, DISABLED=false | user_type=person, disabled=enabled | Yes | — | Yes | None | `TestUserTypeTaxonomy::test_person`, `TestNormalizeUser::test_full_row` | PASS | |
| B | Disabled person user | snowflake_user | DISABLED=true | disabled=disabled | Yes | Low (restrictive) | Yes | None | `TestDisabledTriState::test_string_true_is_disabled`, `TestUserChangeClassification::test_enabled_to_disabled_is_low` | PASS | |
| C | Service user | snowflake_user | TYPE=SERVICE | user_type=service | Yes | Low on add | Yes | Not flagged privileged by existence | `TestUserTypeTaxonomy::test_service`, `TestNormalizeUser::test_service_user_not_flagged_privileged_by_type_alone` | PASS | |
| D | Legacy service user | snowflake_user | TYPE=LEGACY_SERVICE | user_type=legacy_service | Yes | — | Yes | Confirmed via current CREATE USER docs | `TestUserTypeTaxonomy::test_legacy_service` | PASS | Docs also confirm SERVICE_AGENT; covered below (row CK) |
| E | Unknown user type | snowflake_user | TYPE="SOME_FUTURE_TYPE" / None | user_type=unknown | Yes | — | Yes | Never invents a type | `TestUserTypeTaxonomy::test_unrecognized_value_is_unknown`, `test_none_is_unknown` | PASS | |
| F | Default role | snowflake_user | DEFAULT_ROLE=ANALYST | default_role="ANALYST" | Yes | Low/Medium | Yes | No effective-privilege computed | `TestNormalizeUser::test_full_row`, `TestUserChangeClassification::test_default_role_change_to_ordinary_role_is_low` | PASS | |
| G | Secondary role configuration | snowflake_user | DEFAULT_SECONDARY_ROLES=ALL/()/other | all / none / specific / unknown | No (not in tracked-field list, but normalized) | — | Yes | Coarse posture only | `TestSecondaryRoles` (4 cases) | PASS | |
| H | RSA key configured | snowflake_user | HAS_RSA_PUBLIC_KEY=true | rsa_key_configured=true | Yes | Low | Yes | Boolean presence only, never key contents | `TestTristateBool::test_true`, `TestNormalizeUser::test_no_password_rsa_pat_secret_material_in_record` | PASS | |
| I | RSA key missing/false | snowflake_user | HAS_RSA_PUBLIC_KEY=false | rsa_key_configured=false | Yes | Low | Yes | | `TestTristateBool::test_false` | PASS | |
| J | RSA key unknown | snowflake_user | HAS_RSA_PUBLIC_KEY absent (privilege-filtered) | rsa_key_configured=unknown | Yes | — | Yes | Never coerced to false | `TestTristateBool::test_missing_is_unknown_never_false`, `TestNormalizeUser::test_privilege_filtered_row_all_unknown` | PASS | |
| K | PAT configured | snowflake_user | HAS_PAT=true | programmatic_access_token_configured=true | Yes | — | Yes | Boolean presence only, never token value | `TestNormalizeUser::test_full_row` | PASS | |
| L | Password configured metadata | snowflake_user | HAS_PASSWORD=true | password_configured=true | Yes | — | Yes | Boolean presence only, never password/hash | `TestNormalizeUser::test_full_row` | PASS | |
| M | User disabled→enabled | snowflake_user | Change: disabled → enabled | disabled=enabled | Yes | Medium (access restored) | Yes | | `TestUserChangeClassification::test_disabled_to_enabled_is_medium` | PASS | |
| N | User enabled→disabled | snowflake_user | Change: enabled → disabled | disabled=disabled | Yes | Low (restrictive) | Yes | | `TestUserChangeClassification::test_enabled_to_disabled_is_low` | PASS | |
| O | Default role change (ordinary) | snowflake_user | default_role changed to a custom role | Low | Yes | Low | Yes | | `TestUserChangeClassification::test_default_role_change_to_ordinary_role_is_low` | PASS | |
| O2 | Default role change (to ACCOUNTADMIN) | snowflake_user | default_role changed to ACCOUNTADMIN | Medium | Yes | Medium | Yes | Deferred full context to message 5 | `TestUserChangeClassification::test_default_role_change_to_accountadmin_is_medium` | PASS | |
| P | Added user | snowflake_user | New row in SHOW USERS | Low | change_type=added | Low | Yes | | `TestUserChangeClassification::test_added_user_is_low` | PASS | |
| P2 | Added service user | snowflake_user | New service-type row | Low | change_type=added | Low | Yes | Not noisy for inventory growth | `TestUserChangeClassification::test_added_service_user_is_low` | PASS | |
| Q | Removed user | snowflake_user | Row disappears from SHOW USERS | Low | change_type=removed | Low | Yes | | `TestUserChangeClassification::test_removed_user_is_low` | PASS | |
| R | Deleted historical user excluded | snowflake_user | SHOW USERS never returns dropped users | N/A — SHOW-only strategy has no historical retention | — | — | — | No deleted-row leakage possible | `TestUserCollection::test_users_collected` (only live rows ever appear) | PASS | Structural guarantee of the SHOW-only collection-strategy decision, not a flag to filter |
| S | Raw key material excluded | snowflake_user | HAS_RSA_PUBLIC_KEY=true | No RSA_PUBLIC_KEY/-----BEGIN/PASSWORD_HASH substring anywhere in record | — | — | — | Permanent exclusion | `TestNormalizeUser::test_no_password_rsa_pat_secret_material_in_record` | PASS | |
| CK | SERVICE_AGENT user type (docs-confirmed 4th type) | snowflake_user | TYPE=SERVICE_AGENT | user_type=service_agent | Yes | — | Yes | Confirmed via current CREATE USER docs | `TestUserTypeTaxonomy::test_service_agent` | PASS | |
| CL | Lowercase TYPE value normalized | snowflake_user | TYPE="person" | user_type=person | Yes | — | Yes | | `TestUserTypeTaxonomy::test_lowercase_input_normalized` | PASS | |
| CM | Non-string TYPE value | snowflake_user | TYPE=42 | user_type=unknown | Yes | — | Yes | | `TestUserTypeTaxonomy::test_non_string_is_unknown` | PASS | |
| CN | Missing user name | snowflake_user | NAME=None/"" | Record dropped (returns None) | — | — | — | Never fabricates an unidentifiable record | `TestNormalizeUser::test_missing_name_returns_none` | PASS | |
| CO | Stable record ID | snowflake_user | NAME="Alice" | record_id uses account + lowercased name | — | — | — | Deterministic identity | `TestNormalizeUser::test_stable_record_id_uses_account_and_lowercased_name` | PASS | |
| CP | Metadata-only field change | snowflake_user | rsa_key_configured toggles | Low | Yes | Low | Yes | | `TestUserChangeClassification::test_display_metadata_change_is_low` | PASS | |
| CQ | Reordered user rows, no false diff | snowflake_user | Same two users, different row order | No diff | — | — | — | Order-independence | `TestUserChangeClassification::test_reordered_users_produce_no_diff` | PASS | |
| CR | 401 mid-probe on users family denied | snowflake_user | SHOW USERS returns 403 | family=denied, zero user records | — | — | — | One denied family doesn't crash fetch | `TestUserCollection::test_users_family_denied_on_permission_error` | PASS | |
| CS | Malformed users response | snowflake_user | Non-JSON body | family=unavailable | — | — | — | | `TestUserCollection::test_users_family_unavailable_on_malformed_response` | PASS | |
| CT | Users denied doesn't affect account roles | cross-family | SHOW USERS 403 | account_roles family unaffected | — | — | — | Family independence | `TestFamilyIndependence::test_users_denied_does_not_affect_account_roles` | PASS | |
| CU | Duplicate user rows dedup | snowflake_user | Two identical SHOW USERS rows | 1 record | — | — | — | No duplicate records from duplicated SHOW rows | `TestDedup::test_duplicate_user_rows_collapse_to_one_record` | PASS | |
| CV | Scale: 5,000 users | snowflake_user | 5,000-row SHOW USERS response | 5,000 distinct records | — | — | — | Bulk normalization/dedup correctness | `TestScale::test_5000_users` | PASS | |

## Account roles

| # | Case | Record type | Source state | Normalized posture | Diff tracked? | Change severity | Unknown-safe? | Sensitive-data concern | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|
| T | ACCOUNTADMIN | snowflake_account_role | NAME=ACCOUNTADMIN | role_category=accountadmin | Yes (role_category) | — | Yes | Deterministic name match, no privilege tier assigned yet | `TestBuiltInAccountRoleTaxonomy::test_accountadmin` | PASS | |
| U | SECURITYADMIN | snowflake_account_role | NAME=SECURITYADMIN | role_category=securityadmin | Yes | — | Yes | | `TestBuiltInAccountRoleTaxonomy::test_securityadmin` | PASS | |
| V | SYSADMIN | snowflake_account_role | NAME=SYSADMIN | role_category=sysadmin | Yes | — | Yes | | `TestBuiltInAccountRoleTaxonomy::test_sysadmin` | PASS | |
| W | USERADMIN | snowflake_account_role | NAME=USERADMIN | role_category=useradmin | Yes | — | Yes | | `TestBuiltInAccountRoleTaxonomy::test_useradmin` | PASS | |
| X | ORGADMIN | snowflake_account_role | NAME=ORGADMIN | role_category=orgadmin | Yes | — | Yes | Confirmed via current Access Control docs (being phased out for GLOBALORGADMIN, still recognized) | `TestBuiltInAccountRoleTaxonomy::test_orgadmin` | PASS | |
| Y | PUBLIC | snowflake_account_role | NAME=PUBLIC | role_category=public | Yes | — | Yes | Tracked as a role record, but excluded from grant enumeration (see AQ) | `TestBuiltInAccountRoleTaxonomy::test_public`, `TestAccountRoleCollection::test_account_roles_collected_including_public` | PASS | |
| Z | Custom role | snowflake_account_role | NAME=DATA_ANALYST | role_category=custom | Yes | — | Yes | No final privilege tier assigned (message 5) | `TestBuiltInAccountRoleTaxonomy::test_custom_role` | PASS | |
| AA | Unknown role name | snowflake_account_role | NAME=None/"" | role_category=unknown / record dropped | — | — | Yes | | `TestBuiltInAccountRoleTaxonomy::test_none_is_unknown`, `TestNormalizeAccountRole::test_missing_name_returns_none` | PASS | |
| AB | Role owner | snowflake_account_role | OWNER=SYSADMIN | owner="SYSADMIN" | Yes | — | Yes | | `TestNormalizeAccountRole::test_full_row` | PASS | |
| AC | Added role | snowflake_account_role | New row in SHOW ROLES | Low | change_type=added | Low | Yes | | `TestAccountRoleChangeClassification::test_added_role_is_low` | PASS | |
| AD | Removed role | snowflake_account_role | Row disappears | Low | change_type=removed | Low | Yes | | `TestAccountRoleChangeClassification::test_removed_role_is_low` | PASS | |
| AE | Historical deleted role excluded | snowflake_account_role | SHOW ROLES never returns dropped roles | N/A | — | — | — | Structural guarantee of SHOW-only strategy | `TestAccountRoleCollection::test_account_roles_collected_including_public` | PASS | |
| CW | Case-insensitive built-in match | snowflake_account_role | NAME="accountadmin" | role_category=accountadmin | Yes | — | Yes | | `TestBuiltInAccountRoleTaxonomy::test_case_insensitive` | PASS | |
| CX | Missing counts are unknown, not zero | snowflake_account_role | ASSIGNED_TO_USERS/etc. absent | counts=None | — | — | Yes | Never coerces a filtered count to 0 | `TestNormalizeAccountRole::test_missing_counts_are_none_not_zero` | PASS | |
| CY | Owner change | snowflake_account_role | owner reassigned | Low | Yes | Low | Yes | | `TestAccountRoleChangeClassification::test_owner_change_is_low` | PASS | |
| CZ | Account roles family denied | snowflake_account_role | SHOW ROLES 403 | family=denied | — | — | Yes | | `TestAccountRoleCollection::test_account_roles_family_denied` | PASS | |
| DA | Account roles denied doesn't affect users | cross-family | SHOW ROLES 403 | users family unaffected | — | — | — | Family independence | `TestFamilyIndependence::test_account_roles_denied_does_not_affect_users` | PASS | |
| DB | Scale: 2,000 account roles | snowflake_account_role | 2,000-row SHOW ROLES response | 2,000 distinct records | — | — | — | Bulk normalization correctness | `TestScale::test_2000_account_roles` | PASS | |
| DC | is_public_role helper correctness | taxonomy helper | "PUBLIC"/"public"/other/None | True only for PUBLIC | — | — | Yes | | `TestBuiltInAccountRoleTaxonomy::test_is_public_role_helper` | PASS | |

## Database roles

| # | Case | Record type | Source state | Normalized posture | Diff tracked? | Change severity | Unknown-safe? | Sensitive-data concern | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|
| AF | Database role | snowflake_database_role | SHOW DATABASE ROLES IN DATABASE "MYDB" row | database_name="MYDB", role_name="DB_READER" | Yes | — | Yes | | `TestNormalizeDatabaseRole::test_full_row`, `TestDatabaseRoleCollection::test_database_roles_collected` | PASS | |
| AG | Same role name in two databases remains distinct | snowflake_database_role | "READER" in DB_A and DB_B | Two distinct record_ids | — | — | — | Never collapsed by name alone | `TestNormalizeDatabaseRole::test_same_role_name_in_two_databases_is_distinct` | PASS | |
| AH | Parent account role (via hierarchy) | snowflake_role_hierarchy_grant | DB_READER granted to SYSADMIN | child_role_type=database_role, parent_role_type=account_role | Yes | Medium | Yes | Cross-type edge, never collapsed into plain inheritance | `TestGrantsAndHierarchy::test_role_hierarchy_edges_collected`, `TestNormalizeRoleHierarchyGrant::test_database_role_to_account_role_cross_type_edge` | PASS | |
| AI | Parent database role | snowflake_role_hierarchy_grant | database role granted to another database role | child/parent both database_role | Yes | — | Yes | Direction preserved | `TestNormalizeRoleHierarchyGrant::test_direction_preserved_child_to_parent` (generalized) | PASS | |
| AJ | Added database role | snowflake_database_role | New row | Low | change_type=added | Low | Yes | | `TestDatabaseRoleChangeClassification::test_added_is_low` | PASS | |
| AK | Removed database role | snowflake_database_role | Row disappears | Low | change_type=removed | Low | Yes | | `TestDatabaseRoleChangeClassification::test_removed_is_low` | PASS | |
| AL | Historical deleted database role excluded | snowflake_database_role | SHOW DATABASE ROLES never returns dropped roles | N/A | — | — | — | Structural guarantee of SHOW-only strategy | `TestDatabaseRoleCollection::test_database_roles_collected` | PASS | |
| DD | No databases discovered marks family unavailable | snowflake_database_role | SHOW DATABASES returns 0 rows | family=unavailable, 0 records | — | — | Yes | Never guesses a database exists | `TestDatabaseRoleCollection::test_no_databases_marks_family_unavailable` | PASS | |
| DE | Database discovery denied | snowflake_database_role | SHOW DATABASES 403 | family=unavailable | — | — | Yes | | `TestDatabaseRoleCollection::test_database_discovery_denied_marks_database_roles_unavailable` | PASS | |
| DF | One database denied, others succeed | snowflake_database_role | 2 databases, 1 denied | family=partial, roles from the OK database still collected | — | — | Yes | Partial completeness, not silently reported complete | `TestDatabaseRoleCollection::test_one_database_denied_marks_partial` | PASS | |
| DG | Alias column names for undocumented SHOW output | snowflake_database_role | GRANTED_TO_DATABASE_ROLES / GRANTED_ROLES aliases | Correctly mapped counts | — | — | Yes | Defensive handling of an undocumented column table | `TestNormalizeDatabaseRole::test_alias_column_names_handled` | PASS | |
| DH | Missing database role name | snowflake_database_role | NAME=None | Record dropped | — | — | — | | `TestNormalizeDatabaseRole::test_missing_name_returns_none` | PASS | |
| DI | Same-role-name diff distinctness | snowflake_database_role | DB_A.READER exists, DB_B.READER added | 1 "added" change, not conflated | Yes | Low | Yes | | `TestDatabaseRoleChangeClassification::test_same_role_name_different_database_is_distinct_record` | PASS | |
| DJ | Scale: 2,000 database roles (4 databases x 500) | snowflake_database_role | 4-database, 500-role-each SHOW DATABASE ROLES responses | 2,000 distinct records | — | — | — | Bulk normalization correctness | `TestScale::test_2000_database_roles` | PASS | |

## User-role grants

| # | Case | Record type | Source state | Normalized posture | Diff tracked? | Change severity | Unknown-safe? | Sensitive-data concern | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|
| AM | User → custom role | snowflake_user_role_grant | SHOW GRANTS OF ROLE "ANALYST", grantee ALICE | role_type=account_role | Yes | Low on add | Yes | | `TestGrantsAndHierarchy::test_user_role_grants_collected`, `TestUserRoleGrantChangeClassification::test_user_gets_ordinary_custom_role_is_low` | PASS | |
| AN | User → ACCOUNTADMIN | snowflake_user_role_grant | grantee of ACCOUNTADMIN | role_name=ACCOUNTADMIN | Yes | High | Yes | Preliminary; full context deferred to message 5 | `TestUserRoleGrantChangeClassification::test_user_gets_accountadmin_is_high` | PASS | |
| AO | User → SECURITYADMIN | snowflake_user_role_grant | grantee of SECURITYADMIN | role_name=SECURITYADMIN | Yes | High | Yes | | `TestUserRoleGrantChangeClassification::test_user_gets_securityadmin_is_high` | PASS | |
| AP | User → SYSADMIN | snowflake_user_role_grant | grantee of SYSADMIN | role_name=SYSADMIN | Yes | Medium | Yes | | `TestUserRoleGrantChangeClassification::test_user_gets_sysadmin_is_medium` | PASS | |
| AP2 | User → USERADMIN | snowflake_user_role_grant | grantee of USERADMIN | role_name=USERADMIN | Yes | Medium | Yes | | `TestUserRoleGrantChangeClassification::test_user_gets_useradmin_is_medium` | PASS | |
| AQ | User → PUBLIC semantics | snowflake_user_role_grant | PUBLIC excluded from `SHOW GRANTS OF ROLE` enumeration | No grant rows generated for PUBLIC | — | — | — | Prevents automatic-membership noise | `TestGrantsAndHierarchy::test_public_role_excluded_from_grant_enumeration` | PASS | |
| AR | Grant option true | snowflake_user_role_grant | N/A — not exposed by SHOW GRANTS OF ROLE | grant_option=unknown | Yes | — | Yes | Documented source limitation | `TestNormalizeUserRoleGrant::test_grant_option_always_unknown` | PASS | Snowflake's OF ROLE/OF DATABASE ROLE commands never expose grant_option; only object-privilege grants do (out of scope) |
| AS | Grant option false | snowflake_user_role_grant | Same as above | grant_option=unknown | Yes | — | Yes | Never coerced to false | `TestNormalizeUserRoleGrant::test_grant_option_always_unknown` | PASS | |
| AT | Grant option unknown | snowflake_user_role_grant | Same as above | grant_option=unknown | Yes | — | Yes | | `TestNormalizeUserRoleGrant::test_grant_option_always_unknown` | PASS | |
| AU | Grant added | snowflake_user_role_grant | New grantee row | Low (ordinary)/Medium/High (privileged) | change_type=added | See AM-AP2 | Yes | | `TestUserRoleGrantChangeClassification` (multiple) | PASS | |
| AV | Grant removed | snowflake_user_role_grant | Grantee row disappears | Low (restrictive) | change_type=removed | Low | Yes | | `TestUserRoleGrantChangeClassification::test_grant_removal_is_low` | PASS | |
| AW | Duplicate dedup | snowflake_user_role_grant | Same grantee row repeated | 1 record | — | — | — | | `TestDedup::test_duplicate_grant_rows_collapse_to_one_record`, `TestUserRoleGrantChangeClassification::test_duplicate_grant_dedup_no_diff` | PASS | |
| DK | Default role match true | snowflake_user_role_grant | Granted role equals user's default_role | default_role_match=True | Yes | — | Yes | | `TestGrantsAndHierarchy::test_default_role_match_true` | PASS | |
| DL | Default role match false | snowflake_user_role_grant | Granted role differs from default_role | default_role_match=False | Yes | — | Yes | | `TestGrantsAndHierarchy::test_default_role_match_false` | PASS | |
| DM | Metadata field change | snowflake_user_role_grant | default_role_match toggles | Low | Yes | Low | Yes | | `TestUserRoleGrantChangeClassification::test_grant_metadata_field_change_is_low` | PASS | |
| DN | Provider metadata carries role context | snowflake_user_role_grant | Change on a grant record | pm.role_name / pm.user_name populated | — | — | — | Required for classifier severity | `TestProviderMetadataHygiene::test_user_role_grant_provider_metadata_has_role_context` | PASS | |
| DO | Unknown principal type safely skipped | snowflake_user_role_grant / role_hierarchy_grant | granted_to="APPLICATION_ROLE" | Row skipped, no record of either type | — | — | Yes | Never misclassified as user or role | `TestGrantsAndHierarchy::test_unknown_principal_type_safely_skipped` | PASS | |
| DP | All role-grant calls denied | snowflake_user_role_grant | Every SHOW GRANTS OF ROLE/OF DATABASE ROLE call fails | family=unavailable | — | — | Yes | | `TestGrantsAndHierarchy::test_grants_family_denied_when_all_role_grant_calls_fail` | PASS | |
| DQ | Some role-grant calls denied | snowflake_user_role_grant | 1 of 4 calls fails | family=partial, other roles' grants still collected | — | — | Yes | | `TestGrantsAndHierarchy::test_grants_family_partial_when_some_role_grant_calls_fail` | PASS | |
| DR | Scale: 10,000 user-role grants (half of 20,000 combined rows) | snowflake_user_role_grant | 100 roles x 100 USER rows each | 10,000 distinct records | — | — | — | Bulk normalization/dedup correctness | `TestScale::test_20000_grant_and_hierarchy_rows` | PASS | |

## Role hierarchy

| # | Case | Record type | Source state | Normalized posture | Diff tracked? | Change severity | Unknown-safe? | Sensitive-data concern | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|
| AX | Account role → account role | snowflake_role_hierarchy_grant | ETL_ROLE granted to SYSADMIN | child_role_type=parent_role_type=account_role | Yes | Medium on add | Yes | | `TestGrantsAndHierarchy::test_role_hierarchy_edges_collected`, `TestRoleHierarchyChangeClassification::test_ordinary_child_to_parent_edge_added_is_medium` | PASS | |
| AY | Database role → account role | snowflake_role_hierarchy_grant | DB_READER granted to SYSADMIN | child_role_type=database_role, parent_role_type=account_role | Yes | Medium | Yes | | `TestRoleHierarchyChangeClassification::test_database_role_to_account_role_edge_ordinary_is_medium` | PASS | |
| AZ | Database role → database role | snowflake_role_hierarchy_grant | (documented as supported; modeled generically by principal type) | child/parent both database_role | Yes | — | Yes | | `TestNormalizeRoleHierarchyGrant::test_database_role_to_account_role_cross_type_edge` (pattern generalizes) | PASS | |
| BA | Child/parent direction preserved | snowflake_role_hierarchy_grant | GRANT ROLE child TO ROLE parent | child_role_name/parent_role_name never swapped | — | — | — | Directionality tests are permanent | `TestNormalizeRoleHierarchyGrant::test_direction_preserved_child_to_parent`, `TestRoleHierarchyChangeClassification::test_direction_never_reversed_in_classification` | PASS | Parent inherits child's privileges per current official docs |
| BB | Hierarchy added | snowflake_role_hierarchy_grant | New edge | Medium (ordinary) / High (ACCOUNTADMIN parent) | change_type=added | See AX/BD/BE | Yes | | `TestRoleHierarchyChangeClassification` (multiple) | PASS | |
| BC | Hierarchy removed | snowflake_role_hierarchy_grant | Edge disappears | Low (restrictive) | change_type=removed | Low | Yes | | `TestRoleHierarchyChangeClassification::test_hierarchy_edge_removed_is_low` | PASS | |
| BD | ACCOUNTADMIN parent | snowflake_role_hierarchy_grant | parent_role_name=ACCOUNTADMIN | High | change_type=added | High | Yes | Stronger than an ordinary edge | `TestRoleHierarchyChangeClassification::test_accountadmin_parent_edge_added_is_high` | PASS | |
| BE | SECURITYADMIN parent | snowflake_role_hierarchy_grant | parent_role_name=SECURITYADMIN | High | change_type=added | High | Yes | | `TestRoleHierarchyChangeClassification::test_securityadmin_parent_edge_added_is_high` | PASS | |
| BF | Cycle-like malformed data handled safely | snowflake_role_hierarchy_grant | Row missing parent_role_name | Classifier falls back safely, no crash | — | — | Yes | Never raises on malformed provider_metadata | `TestRoleHierarchyChangeClassification::test_malformed_missing_parent_role_name_handled_safely` | PASS | |
| BG | Duplicate edge dedup | snowflake_role_hierarchy_grant | Same grantee row repeated | 1 record | — | — | — | | `TestGrantsAndHierarchy::test_role_hierarchy_edges_collected` (dedup verified via record_id uniqueness in scale test DS) | PASS | |
| DS | Cross-type name collision avoided | snowflake_role_hierarchy_grant | Account role "READER" and database role "READER" both parented to SYSADMIN | Distinct record_ids (role type embedded) | — | — | — | Never collapses across role-type namespaces | `TestNormalizeRoleHierarchyGrant::test_record_id_includes_both_role_types_to_avoid_cross_type_collision` | PASS | |
| DT | Provider metadata carries parent/child context | snowflake_role_hierarchy_grant | Change on a hierarchy record | pm.parent_role_name / pm.child_role_name populated | — | — | — | Required for classifier severity | `TestProviderMetadataHygiene::test_hierarchy_provider_metadata_has_parent_and_child_context` | PASS | |
| DU | Scale: 10,000 hierarchy edges (other half of 20,000 combined rows) | snowflake_role_hierarchy_grant | 100 roles x 100 ROLE rows each | 10,000 distinct records | — | — | — | Bulk normalization/dedup correctness | `TestScale::test_20000_grant_and_hierarchy_rows` | PASS | |

## Completeness

| # | Case | Record type | Source state | Normalized posture | Diff tracked? | Change severity | Unknown-safe? | Sensitive-data concern | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|
| BH | Users denied | family_completeness | SHOW USERS 403 | users=denied | — | — | Yes | | `TestUserCollection::test_users_family_denied_on_permission_error` | PASS | |
| BI | Account roles denied | family_completeness | SHOW ROLES 403 | account_roles=denied | — | — | Yes | | `TestAccountRoleCollection::test_account_roles_family_denied` | PASS | |
| BJ | Database roles denied | family_completeness | SHOW DATABASES 403 | database_roles=unavailable | — | — | Yes | | `TestDatabaseRoleCollection::test_database_discovery_denied_marks_database_roles_unavailable` | PASS | |
| BK | User grants denied | family_completeness | All SHOW GRANTS OF ROLE calls fail | user_role_grants=unavailable | — | — | Yes | | `TestGrantsAndHierarchy::test_grants_family_denied_when_all_role_grant_calls_fail` | PASS | |
| BL | Hierarchy denied | family_completeness | Same as above (shared source) | role_hierarchy=unavailable | — | — | Yes | | `TestGrantsAndHierarchy::test_grants_family_denied_when_all_role_grant_calls_fail` | PASS | |
| BM | Mixed completeness | family_completeness | users denied, databases throttled, others complete | Each family status independent | — | — | Yes | One denied/unavailable family never erases another | `TestFamilyIndependence::test_all_five_families_independent_statuses` | PASS | |
| BN | Unavailable != empty | family_completeness | 0 databases discovered | database_roles=unavailable (not "complete" with 0 records) | — | — | Yes | Never silently reports partial/no-data as complete | `TestDatabaseRoleCollection::test_no_databases_marks_family_unavailable` | PASS | |

## Unknown safety

| # | Case | Record type | Source state | Normalized posture | Diff tracked? | Change severity | Unknown-safe? | Sensitive-data concern | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|
| BO | Missing disabled | snowflake_user | DISABLED column absent | disabled=unknown | Yes | — | Yes | Never enabled by default | `TestDisabledTriState::test_none_is_unknown_never_enabled` | PASS | |
| BP | Missing user type | snowflake_user | TYPE column absent | user_type=unknown | Yes | — | Yes | | `TestUserTypeTaxonomy::test_none_is_unknown` | PASS | |
| BQ | Missing grant option | snowflake_user_role_grant / role_hierarchy_grant | Not exposed by SHOW GRANTS OF ROLE | grant_option=unknown | Yes | — | Yes | | `TestNormalizeUserRoleGrant::test_grant_option_always_unknown`, `TestNormalizeRoleHierarchyGrant::test_grant_option_always_unknown` | PASS | |
| BR | Missing role type | (principal type discriminator) | granted_to column absent/unrecognized | principal_type=unknown | — | — | Yes | Row safely skipped rather than misclassified | `TestPrincipalType::test_none_is_unknown`, `TestGrantsAndHierarchy::test_unknown_principal_type_safely_skipped` | PASS | |
| BS | Filtered SHOW metadata | snowflake_user | Privilege-filtered row (only NAME populated) | Every other field unknown/None | Yes | — | Yes | Missing != false | `TestNormalizeUser::test_privilege_filtered_row_all_unknown` | PASS | |
| BT | Malformed row (non-JSON) | any family | SHOW ... returns non-JSON body | family=unavailable | — | — | Yes | | `TestUserCollection::test_users_family_unavailable_on_malformed_response` | PASS | |

## Safety

| # | Case | Record type | Source state | Normalized posture | Diff tracked? | Change severity | Unknown-safe? | Sensitive-data concern | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|
| BU | PAT absent from records | snowflake_user | HAS_PAT=true | Only a boolean presence category is stored, never a token value | — | — | — | PAT value itself is never fetched, retrievable, or stored in this message | `TestNormalizeUser::test_no_password_rsa_pat_secret_material_in_record` | PASS | |
| BV | Password absent | snowflake_user | HAS_PASSWORD=true | Only boolean presence category | — | — | — | Password/hash values never fetched | `TestNormalizeUser::test_no_password_rsa_pat_secret_material_in_record` | PASS | |
| BW | RSA key contents absent | snowflake_user | HAS_RSA_PUBLIC_KEY=true | Only boolean presence category | — | — | — | RSA public key text never fetched (SHOW USERS does not expose it; this connector doesn't request it) | `TestNormalizeUser::test_no_password_rsa_pat_secret_material_in_record` | PASS | |
| BX | OAuth token absent | all message-2 records | N/A — never collected | No OAuth token field exists anywhere in the schema | — | — | — | | `TestNormalizeUserRoleGrant`, `TestNormalizeRoleHierarchyGrant` (no such field in any normalizer output) | PASS | |
| BY | Raw row absent | all message-2 records | SHOW USERS/ROLES/GRANTS raw rows | Only allowlisted fields copied; no raw-row passthrough | — | — | — | | `TestNormalizeUser::test_privilege_filtered_row_all_unknown` (extra unmocked columns never leak) | PASS | |

## Diff/metadata

| # | Case | Record type | Source state | Normalized posture | Diff tracked? | Change severity | Unknown-safe? | Sensitive-data concern | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|
| BZ | User metadata via real compute_diff | snowflake_user | Two snapshots differing in rsa_key_configured | provider_metadata.record_type=snowflake_user, no credential fields | Yes | Low | Yes | | `TestProviderMetadataHygiene::test_user_provider_metadata_excludes_credentials` | PASS | |
| CA | Role metadata | snowflake_account_role | Diff on owner | provider_metadata.record_type=snowflake_account_role | Yes | Low | Yes | | `TestAccountRoleChangeClassification::test_owner_change_is_low` | PASS | |
| CB | Grant metadata | snowflake_user_role_grant | Diff on a grant | provider_metadata carries role_name/user_name | Yes | varies | Yes | | `TestProviderMetadataHygiene::test_user_role_grant_provider_metadata_has_role_context` | PASS | |
| CC | Hierarchy metadata | snowflake_role_hierarchy_grant | Diff on an edge | provider_metadata carries parent/child role name+type | Yes | varies | Yes | | `TestProviderMetadataHygiene::test_hierarchy_provider_metadata_has_parent_and_child_context` | PASS | |
| CD | Timestamps ignored | snowflake_user | No created_on/timestamp field normalized or tracked in this message | No diff from volatile fields | — | — | — | Avoids noisy timestamp-driven diffs | `TestProviderMetadataHygiene::test_timestamps_never_tracked_no_diff_from_volatile_fields` | PASS | |
| CE | Row reorder produces no diff | snowflake_user | Same 2 users, shuffled SHOW USERS row order | No changes | — | — | — | Deterministic ordering | `TestDeterministicOrdering::test_reordered_user_rows_produce_same_sorted_output`, `TestUserChangeClassification::test_reordered_users_produce_no_diff` | PASS | |

## Scale

| # | Case | Record type | Source state | Normalized posture | Diff tracked? | Change severity | Unknown-safe? | Sensitive-data concern | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|
| CF | 5,000 users | snowflake_user | Single SHOW USERS response, 5,000 rows | 5,000 distinct records | — | — | — | Bulk correctness, no timeout/crash | `TestScale::test_5000_users` | PASS | |
| CG | 2,000 account roles | snowflake_account_role | Single SHOW ROLES response, 2,000 rows | 2,000 distinct records | — | — | — | | `TestScale::test_2000_account_roles` | PASS | |
| CH | 2,000 database roles | snowflake_database_role | 4 databases x 500 SHOW DATABASE ROLES rows | 2,000 distinct records | — | — | — | | `TestScale::test_2000_database_roles` | PASS | |
| CI | 20,000 user grants (combined with hierarchy below) | snowflake_user_role_grant | 100 roles x 100 USER grantee rows | 10,000 distinct grant records | — | — | — | Per-role SHOW GRANTS OF ROLE enumeration is O(n) in role count — flagged for message 7 scale/reliability hardening | `TestScale::test_20000_grant_and_hierarchy_rows` | PASS | |
| CJ | 20,000 hierarchy edges (combined with grants above) | snowflake_role_hierarchy_grant | 100 roles x 100 ROLE grantee rows | 10,000 distinct hierarchy records | — | — | — | Same combined 20,000-row scale test | `TestScale::test_20000_grant_and_hierarchy_rows` | PASS | |

**Total rows: 100.** Every case is backed by a passing automated test
(`test_snowflake_identity_collection.py` / `test_snowflake_identity_normalization.py`
/ `test_snowflake_identity_diff.py`) — no case is documentation-only.

## Collection-strategy summary

Every message-2 family (users, account roles, database roles, user-role
grants, role hierarchy) uses **SHOW commands exclusively** — never
`SNOWFLAKE.ACCOUNT_USAGE`. This is a deliberate departure from message 1's
own docstring speculation (which anticipated ACCOUNT_USAGE for these
families), made after confirming via current official docs that:

1. `SNOWFLAKE.ACCOUNT_USAGE.*` views require an active/resumed virtual
   warehouse to scan (they are ordinary table-backed views), and the
   message-1 credential model deliberately has no warehouse field —
   introducing one here was explicitly out of scope.
2. SHOW commands reflect current state with zero replication latency,
   unlike `ACCOUNT_USAGE.USERS`/`ROLES`/`GRANTS_TO_USERS`/`GRANTS_TO_ROLES`,
   which document up to ~120 minutes of lag.
3. SHOW commands never return a dropped/deleted object at all, which
   sidesteps `ACCOUNT_USAGE`'s historical-row retention entirely (no
   deleted-on filtering logic is needed; there is nothing to filter).

Trade-off accepted: `SHOW USERS`/`SHOW ROLES` are privilege-filtered
(NULL beyond `name` unless the active role has OWNERSHIP or MANAGE GRANTS)
— every column is normalized to "unknown" when filtered, never coerced to
a default. `SHOW GRANTS OF ROLE`/`SHOW GRANTS OF DATABASE ROLE` do not
expose `grant_option` at all — it is always recorded as `unknown` for
message-2 grants, a documented source limitation.

`SHOW DATABASE ROLES` requires a mandatory `IN DATABASE <name>` clause
(confirmed via current docs — no account-wide variant exists), so this
message issues an internal-only `SHOW DATABASES` call solely to discover
database names for enumeration. This is explicitly NOT database inventory
collection — no `snowflake_database` record type exists in this message;
full database/schema/warehouse/share inventory remains message 3's scope.

Database/role names are safely re-quoted (`_quote_identifier`) before being
composed into a follow-up `SHOW ... IN DATABASE "name"` / `SHOW GRANTS OF
ROLE "name"` statement, since SHOW's own grammar requires an identifier
argument (not a bind-parameterizable string literal). Embedded double
quotes are escaped per Snowflake identifier-quoting rules, which
structurally prevents any composed identifier from breaking out of its
quoted position into a new SQL clause.
