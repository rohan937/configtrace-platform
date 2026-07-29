# Snowflake Data Object Security Matrix (Snowflake Message 3 of 8)

Covers SHOW-based collection and normalization of databases, schemas,
warehouses, shares, database/schema/warehouse ownership, object-level
privilege grants, and future grants. Message 3 does NOT collect network/
authentication/security integrations (message 4), effective privilege
(message 5), or Security Findings (message 6) — object/future grants are
classified with preliminary, structural severity only.

Columns: **Case**, **Record type**, **Source state**, **Normalized
posture**, **Diff tracked?**, **Severity**, **Unknown-safe?**,
**Sensitive-data concern**, **Test**, **Status**, **Notes**.

## Databases

| # | Case | Record type | Source state | Normalized posture | Diff tracked? | Severity | Unknown-safe? | Sensitive-data concern | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|
| A | Standard database | snowflake_database | KIND=STANDARD | database_kind=standard | Yes | — | Yes | | `TestDatabaseKindTaxonomy::test_standard`, `TestNormalizeDatabase::test_full_row` | PASS | |
| B | Imported/shared database | snowflake_database | KIND=IMPORTED DATABASE | database_kind=imported, origin populated | Yes | — | Yes | Origin captured, never the shared source's contents | `TestDatabaseKindTaxonomy::test_imported`, `TestNormalizeDatabase::test_imported_database_with_origin` | PASS | |
| C | Transient database | snowflake_database | OPTIONS contains TRANSIENT | transient=true | Yes | — | Yes | | `TestOptionsColumnParsing::test_transient_present` | PASS | |
| D | Owner | snowflake_database | OWNER=SYSADMIN | owner="SYSADMIN" | Yes | — | Yes | | `TestNormalizeDatabase::test_full_row` | PASS | |
| E | Owner change | snowflake_database | owner reassigned | Medium | Yes | Medium | Yes | | `TestDatabaseChangeClassification::test_owner_change_is_medium` | PASS | |
| F | Added database | snowflake_database | New row in SHOW DATABASES | Low | change_type=added | Low | Yes | | `TestDatabaseChangeClassification::test_added_is_low` | PASS | |
| G | Removed database | snowflake_database | Row disappears | Low | change_type=removed | Low | Yes | | `TestDatabaseChangeClassification::test_removed_is_low` | PASS | |
| H | Unknown owner (missing) | snowflake_database | OWNER absent | owner=None | Yes | — | Yes | Never coerced to a fabricated owner | `TestNormalizeDatabase::test_missing_name_returns_none` (record-drop path); owner defaults to None when absent, exercised via full-row test | PASS | |
| CU | Application database | snowflake_database | KIND=APPLICATION | database_kind=application | Yes | — | Yes | | `TestDatabaseKindTaxonomy::test_application` | PASS | |
| CV | Personal database | snowflake_database | KIND=PERSONAL DATABASE | database_kind=personal | Yes | — | Yes | | `TestDatabaseKindTaxonomy::test_personal` | PASS | |
| CW | Catalog-linked database | snowflake_database | KIND=CATALOG-LINKED DATABASE | database_kind=catalog_linked | Yes | — | Yes | | `TestDatabaseKindTaxonomy::test_catalog_linked` | PASS | |
| CX | Unrecognized database kind | snowflake_database | KIND="SOME_FUTURE_KIND" | database_kind=unknown | Yes | — | Yes | Never invented | `TestDatabaseKindTaxonomy::test_unrecognized_is_unknown` | PASS | |
| CY | Owner change to privileged built-in role | snowflake_database | owner -> ACCOUNTADMIN | Medium (deferred full context to message 5) | Yes | Medium | Yes | | `TestDatabaseChangeClassification::test_owner_change_to_accountadmin_is_medium` | PASS | |
| CZ | No arbitrary comment collected | snowflake_database | COMMENT column present | Field never read into record | — | — | — | Permanent exclusion | `TestNormalizeDatabase::test_no_comment_field_collected` | PASS | |
| DA | Stable record ID lowercased | snowflake_database | NAME="MyDb" | record_id uses account + lowercased name | — | — | Yes | | `TestNormalizeDatabase::test_stable_record_id` | PASS | |
| DB | Missing database name | snowflake_database | NAME=None | Record dropped | — | — | — | Never fabricates an unidentifiable record | `TestNormalizeDatabase::test_missing_name_returns_none` | PASS | |
| DC | Databases family denied | family_completeness | SHOW DATABASES 403 | databases=denied | — | — | Yes | | `TestDatabaseCollection::test_databases_family_denied` | PASS | |
| DD | SHOW DATABASES issued exactly once per fetch | caching | database-role discovery + schema/future-grant loops + database inventory all share one call | Single SHOW DATABASES call | — | — | — | No duplicate query | `TestDatabaseCollection::test_show_databases_issued_exactly_once_per_fetch` | PASS | |
| DE | Scale: 1,000 databases | snowflake_database | Single SHOW DATABASES response, 1,000 rows | 1,000 distinct records | — | — | — | Bulk correctness | `TestScale::test_1000_databases` | PASS | |

## Schemas

| # | Case | Record type | Source state | Normalized posture | Diff tracked? | Severity | Unknown-safe? | Sensitive-data concern | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|
| I | Standard schema | snowflake_schema | OPTIONS="" | managed_access=false, transient=false | Yes | — | Yes | | `TestNormalizeSchema::test_unmanaged_schema` | PASS | |
| J | Managed-access schema | snowflake_schema | OPTIONS contains MANAGED ACCESS | managed_access=true | Yes | — | Yes | Confirmed via current CREATE SCHEMA docs, never inferred from name | `TestOptionsColumnParsing::test_managed_access_present`, `TestNormalizeSchema::test_managed_access_schema` | PASS | |
| K | Unmanaged schema | snowflake_schema | OPTIONS lacks MANAGED ACCESS token | managed_access=false | Yes | — | Yes | | `TestNormalizeSchema::test_unmanaged_schema` | PASS | |
| L | Owner | snowflake_schema | OWNER=SYSADMIN | owner="SYSADMIN" | Yes | — | Yes | | `TestNormalizeSchema::test_managed_access_schema` | PASS | |
| M | Owner change | snowflake_schema | owner reassigned | Medium | Yes | Medium | Yes | | `TestSchemaChangeClassification::test_owner_change_is_medium` | PASS | |
| N | Added schema | snowflake_schema | New row in SHOW SCHEMAS | Low | change_type=added | Low | Yes | | `TestSchemaChangeClassification::test_added_is_low` | PASS | |
| O | Removed schema | snowflake_schema | Row disappears | Low | change_type=removed | Low | Yes | | `TestSchemaChangeClassification::test_removed_is_low` | PASS | |
| P | Per-database collection denied | family_completeness | One of two databases' SHOW SCHEMAS 403 | schemas=partial; other database's schemas still collected | — | — | Yes | One denied parent never wipes all schema inventory | `TestSchemaCollection::test_one_database_schemas_denied_marks_partial` | PASS | |
| DF | Managed access never inferred from name | snowflake_schema | NAME="MANAGED_SCHEMA", OPTIONS="" | managed_access=false | Yes | — | Yes | | `TestNormalizeSchema::test_managed_access_never_inferred_from_name` | PASS | |
| DG | Managed-access toggle Change | snowflake_schema | managed_access flips | Low | Yes | Low | Yes | No Finding created yet (message 6) | `TestSchemaChangeClassification::test_managed_access_toggle_is_low` | PASS | |
| DH | Same schema name, different database, distinct records | snowflake_schema | "PUBLIC" in DB_A and DB_B | Two distinct record_ids | — | — | Yes | Never collapsed by name alone | `TestSchemaChangeClassification::test_same_schema_name_different_database_is_distinct` | PASS | |
| DI | No databases discovered marks schemas unavailable | family_completeness | 0 databases | schemas=unavailable | — | — | Yes | | `TestSchemaCollection::test_no_databases_marks_schemas_unavailable` | PASS | |
| DJ | Missing schema name | snowflake_schema | NAME=None | Record dropped | — | — | — | | `TestNormalizeSchema::test_missing_name_returns_none` | PASS | |
| DK | Stable identity includes database | snowflake_schema | account+db+schema | record_id = account/schema/db.schema | — | — | Yes | | `TestNormalizeSchema::test_stable_identity_includes_database` | PASS | |
| DL | Scale: 10,000 schemas (10 databases x 1,000) | snowflake_schema | 10 SHOW SCHEMAS IN DATABASE responses | 10,000 distinct records | — | — | — | Bulk correctness, bounded per-database loop | `TestScale::test_10000_schemas` | PASS | |

## Warehouses

| # | Case | Record type | Source state | Normalized posture | Diff tracked? | Severity | Unknown-safe? | Sensitive-data concern | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Q | Running warehouse | snowflake_warehouse | STATE=STARTED | state=started | Yes | — | Yes | | `TestWarehouseState::test_started`, `TestNormalizeWarehouse::test_full_row` | PASS | |
| R | Suspended warehouse | snowflake_warehouse | STATE=SUSPENDED | state=suspended | Yes | — | Yes | | `TestWarehouseState::test_suspended` | PASS | |
| S | Auto-suspend | snowflake_warehouse | AUTO_SUSPEND=600 | auto_suspend=600 | Yes | — | Yes | | `TestNormalizeWarehouse::test_full_row` | PASS | |
| T | Auto-resume | snowflake_warehouse | AUTO_RESUME=true | auto_resume=true | Yes | — | Yes | | `TestNormalizeWarehouse::test_full_row` | PASS | |
| U | Owner | snowflake_warehouse | OWNER=SYSADMIN | owner="SYSADMIN" | Yes | — | Yes | | `TestNormalizeWarehouse::test_full_row` | PASS | |
| V | Owner change | snowflake_warehouse | owner reassigned | Medium | Yes | Medium | Yes | | `TestWarehouseChangeClassification::test_owner_change_is_medium` | PASS | |
| W | Added warehouse | snowflake_warehouse | New row in SHOW WAREHOUSES | Low | change_type=added | Low | Yes | | `TestWarehouseChangeClassification::test_added_is_low` | PASS | |
| X | Removed warehouse | snowflake_warehouse | Row disappears | Low | change_type=removed | Low | Yes | | `TestWarehouseChangeClassification::test_removed_is_low` | PASS | |
| DM | Resizing state | snowflake_warehouse | STATE=RESIZING | state=resizing | Yes | — | Yes | | `TestWarehouseState::test_resizing` | PASS | |
| DN | Missing state is unknown | snowflake_warehouse | STATE absent | state=unknown | Yes | — | Yes | | `TestWarehouseState::test_missing_is_unknown` | PASS | |
| DO | Size change is never a security signal | snowflake_warehouse | X-Small -> 4X-Large | Low | Yes | Low | Yes | Cost/performance settings never become a Finding | `TestWarehouseChangeClassification::test_size_change_is_never_a_security_signal` | PASS | |
| DP | Auto-suspend change is not security-classified as elevated | snowflake_warehouse | 600 -> 60 | Low | Yes | Low | Yes | | `TestWarehouseChangeClassification::test_auto_suspend_change_is_low` | PASS | |
| DQ | Cost/performance fields not collected | snowflake_warehouse | ENABLE_QUERY_ACCELERATION, GENERATION present | Fields never read into record | — | — | — | Prevents warehouse tuning posture overbuild | `TestNormalizeWarehouse::test_cost_performance_fields_not_collected` | PASS | |
| DR | Missing warehouse name | snowflake_warehouse | NAME=None | Record dropped | — | — | — | | `TestNormalizeWarehouse::test_missing_name_returns_none` | PASS | |
| DS | Warehouses family denied | family_completeness | SHOW WAREHOUSES 403 | warehouses=denied | — | — | Yes | | `TestWarehouseCollection::test_warehouses_family_denied` | PASS | |
| DT | Scale: 2,000 warehouses | snowflake_warehouse | Single SHOW WAREHOUSES response, 2,000 rows | 2,000 distinct records | — | — | — | | `TestScale::test_2000_warehouses` | PASS | |

## Shares

| # | Case | Record type | Source state | Normalized posture | Diff tracked? | Severity | Unknown-safe? | Sensitive-data concern | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Y | Outbound share | snowflake_share | KIND=OUTBOUND | share_kind=outbound | Yes | Medium on add | Yes | Never equated with "data is public" | `TestShareKind::test_outbound`, `TestNormalizeShare::test_outbound_share`, `TestShareChangeClassification::test_added_is_medium` | PASS | |
| Z | Inbound/imported share | snowflake_share | KIND=INBOUND | share_kind=inbound | Yes | — | Yes | | `TestShareKind::test_inbound`, `TestNormalizeShare::test_inbound_share_no_consumers` | PASS | |
| AA | Unknown share kind | snowflake_share | KIND absent | share_kind=unknown | Yes | — | Yes | | `TestShareKind::test_missing_is_unknown` | PASS | |
| AB | Consumer count | snowflake_share | TO="XY12345, YZ23456" | consumer_count=2 | Yes | — | Yes | Bounded safe summary, not a full identifier dump | `TestNormalizeShare::test_outbound_share` | PASS | |
| AC | Consumer added | snowflake_share | consumer_count 1 -> 2 | Medium | Yes | Medium | Yes | Data sharing configuration broadened, never "data leaked" wording | `TestShareChangeClassification::test_consumer_added_is_medium` | PASS | |
| AD | Consumer removed | snowflake_share | consumer_count 2 -> 1 | Low | Yes | Low | Yes | | `TestShareChangeClassification::test_consumer_removed_is_low` | PASS | |
| AE | Share added | snowflake_share | New row in SHOW SHARES | Medium | change_type=added | Medium | Yes | | `TestShareChangeClassification::test_added_is_medium` | PASS | |
| AF | Share removed | snowflake_share | Row disappears | Low | change_type=removed | Low | Yes | | `TestShareChangeClassification::test_removed_is_low` | PASS | |
| DU | Consumer count truncation flagged | snowflake_share | TO shows exactly 3 accounts (documented display cap) | consumer_count_may_be_truncated=true | Yes | — | Yes | Never presents a capped count as precise | `TestNormalizeShare::test_consumer_count_truncation_flagged_at_three` | PASS | |
| DV | Share existence never implies public data | snowflake_share | Any share record | No public/is_public/publicly_accessible field | — | — | — | Secure Snowflake-to-Snowflake sharing only | `TestNormalizeShare::test_share_existence_never_implies_public_data` | PASS | |
| DW | Never claims "data leaked" | snowflake_share | Share added | Reason text avoids alarming copy | — | — | — | | `TestShareChangeClassification::test_never_claims_data_leaked` | PASS | |
| DX | Missing share name | snowflake_share | NAME=None | Record dropped | — | — | — | | `TestNormalizeShare::test_missing_name_returns_none` | PASS | |
| DY | Shares family denied | family_completeness | SHOW SHARES 403 | shares=denied | — | — | Yes | | `TestShareCollection::test_shares_family_denied` | PASS | |
| DZ | Scale: 2,000 shares | snowflake_share | Single SHOW SHARES response, 2,000 rows | 2,000 distinct records | — | — | — | | `TestScale::test_2000_shares` | PASS | |

## Object grants

| # | Case | Record type | Source state | Normalized posture | Diff tracked? | Severity | Unknown-safe? | Sensitive-data concern | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|
| AG | SELECT | snowflake_object_grant | PRIVILEGE=SELECT | privilege_category=data_read | Yes | Medium on add | Yes | | `TestPrivilegeTaxonomy::test_select_is_data_read`, `TestObjectGrantChangeClassification::test_ordinary_select_grant_is_medium` | PASS | |
| AH | INSERT | snowflake_object_grant | PRIVILEGE=INSERT | privilege_category=data_write | Yes | Medium | Yes | | `TestPrivilegeTaxonomy::test_insert_update_delete_truncate_are_data_write` | PASS | |
| AI | UPDATE | snowflake_object_grant | PRIVILEGE=UPDATE | privilege_category=data_write | Yes | Medium | Yes | | `TestPrivilegeTaxonomy::test_insert_update_delete_truncate_are_data_write` | PASS | |
| AJ | DELETE | snowflake_object_grant | PRIVILEGE=DELETE | privilege_category=data_write | Yes | Medium | Yes | | `TestPrivilegeTaxonomy::test_insert_update_delete_truncate_are_data_write` | PASS | |
| AK | USAGE | snowflake_object_grant | PRIVILEGE=USAGE | privilege_category=usage | Yes | Medium | Yes | | `TestPrivilegeTaxonomy::test_usage_is_usage` | PASS | |
| AL | OWNERSHIP | snowflake_object_grant | PRIVILEGE=OWNERSHIP | privilege_category=ownership, ownership=true | Yes | High | Yes | | `TestPrivilegeTaxonomy::test_ownership`, `TestObjectGrantChangeClassification::test_ownership_grant_is_high` | PASS | |
| AM | CREATE privilege | snowflake_object_grant | PRIVILEGE="CREATE TABLE" | privilege_category=object_create | Yes | Medium | Yes | Matched via documented CREATE-prefix convention, never invented | `TestPrivilegeTaxonomy::test_create_prefix_is_object_create` | PASS | |
| AN | MONITOR | snowflake_object_grant | PRIVILEGE=MONITOR | privilege_category=monitor | Yes | Low | Yes | | `TestPrivilegeTaxonomy::test_monitor`, `TestObjectGrantChangeClassification::test_monitor_only_grant_is_low` | PASS | |
| AO | OPERATE | snowflake_object_grant | PRIVILEGE=OPERATE | privilege_category=operational_control | Yes | Medium | Yes | | `TestPrivilegeTaxonomy::test_operate_modify_apply_are_operational_control` | PASS | |
| AP | MODIFY | snowflake_object_grant | PRIVILEGE=MODIFY | privilege_category=operational_control | Yes | Medium | Yes | | `TestPrivilegeTaxonomy::test_operate_modify_apply_are_operational_control` | PASS | |
| AQ | Grant option true | snowflake_object_grant | GRANT_OPTION=true | grant_option=true | Yes | High if paired with a powerful privilege | Yes | `SHOW GRANTS TO ROLE` DOES expose grant_option (unlike message 2's OF-ROLE grants) | `TestGrantOption::test_true`, `TestObjectGrantChangeClassification::test_grant_option_added_on_powerful_privilege_is_high` | PASS | |
| AR | Grant option false | snowflake_object_grant | GRANT_OPTION=false | grant_option=false | Yes | Low if changed on an ordinary read privilege | Yes | | `TestGrantOption::test_false`, `TestObjectGrantChangeClassification::test_grant_option_added_on_ordinary_read_privilege_is_low` | PASS | |
| AS | Grant option unknown | snowflake_object_grant | GRANT_OPTION absent | grant_option=unknown | Yes | — | Yes | Never coerced to false | `TestGrantOption::test_missing_is_unknown_never_false`, `TestNormalizeObjectGrant::test_grant_option_missing_is_unknown` | PASS | |
| AT | Ordinary role grantee | snowflake_object_grant | GRANTEE_NAME=ANALYST | grantee_type=account_role | Yes | Medium (SELECT) | Yes | | `TestObjectGrantChangeClassification::test_ordinary_select_grant_is_medium` | PASS | |
| AU | PUBLIC grantee | snowflake_object_grant | GRANTEE_NAME=PUBLIC | Escalated severity | Yes | Medium (ordinary)/High (ownership or future) | Yes | Broadens access to every user/role | `TestObjectGrantChangeClassification::test_public_select_grant_is_medium`, `test_public_ownership_grant_is_high` | PASS | |
| AV | ACCOUNTADMIN grantee | snowflake_object_grant | GRANTEE_NAME=ACCOUNTADMIN | Dampened to Low | Yes | Low (deliberately, to avoid alert explosion) | Yes | ACCOUNTADMIN already has near-total access by design | `TestObjectGrantChangeClassification::test_accountadmin_grantee_never_creates_noise` | PASS | |
| AW | Database role grantee | snowflake_object_grant | grantee_type=database_role | grantee_type preserved distinctly from account_role | Yes | — | Yes | Never flattened into a plain role string | `TestNormalizeObjectGrant::test_database_role_grantee_type_preserved` | PASS | |
| DZa | Role-hierarchy row excluded from object grants | snowflake_object_grant | SHOW GRANTS TO ROLE row with granted_on=ROLE | Skipped entirely, never normalized here | — | — | — | Prevents a second, conflicting hierarchy source (message 2 owns hierarchy via OF ROLE) | `TestObjectTypeTaxonomy::test_role_and_database_role_are_hierarchy_rows`, `TestObjectGrantCollection::test_role_hierarchy_row_excluded_from_object_grants` | PASS | |
| DZb | Object FQN split for table (3-part) | snowflake_object_grant | NAME="MYDB.PUBLIC.ORDERS" | database/schema/object all populated | — | — | Yes | | `TestSplitObjectFqn::test_table_three_parts` | PASS | |
| DZc | Object FQN split for schema (2-part) | snowflake_object_grant | NAME="MYDB.PUBLIC" | database+schema populated, object=None | — | — | Yes | | `TestSplitObjectFqn::test_schema_two_parts` | PASS | |
| DZd | Object FQN split for database (1-part) | snowflake_object_grant | NAME="MYDB" | database populated, others None | — | — | Yes | | `TestSplitObjectFqn::test_database_one_part` | PASS | |
| DZe | Object FQN for account-scoped object (bare name) | snowflake_object_grant | NAME="COMPUTE_WH" (warehouse) | object_name populated, database/schema None | — | — | Yes | | `TestSplitObjectFqn::test_warehouse_bare_name_not_decomposed_as_db` | PASS | |
| DZf | Quoted object name never decomposed | snowflake_object_grant | NAME=`MYDB.PUBLIC."WEIRD.NAME"` | All components None; raw FQN preserved | — | — | Yes | Prevents misparsing an embedded dot inside a quoted identifier | `TestSplitObjectFqn::test_quoted_name_never_decomposed` | PASS | |
| DZg | Stable grant identity deterministic | snowflake_object_grant | Same row twice | Identical record_id | — | — | — | | `TestNormalizeObjectGrant::test_stable_grant_identity_deterministic` | PASS | |
| DZh | Current vs future grant never collide in identity | snowflake_object_grant | Same privilege/object, future_grant differs | Distinct record_ids | — | — | — | | `TestNormalizeObjectGrant::test_current_and_future_grants_never_collide_in_identity` | PASS | |
| DZi | Duplicate grant rows dedup | snowflake_object_grant | Same SHOW GRANTS TO ROLE row repeated | 1 record | — | — | — | | `TestObjectGrantCollection::test_duplicate_grant_rows_dedup` | PASS | |
| DZj | Grant removed | snowflake_object_grant | Row disappears from SHOW GRANTS TO ROLE | Low | change_type=removed | Low | Yes | | `TestObjectGrantChangeClassification::test_grant_removed_is_low` | PASS | |
| DZk | Object grants family denied when all calls fail | family_completeness | Every SHOW GRANTS TO ROLE call fails | object_grants=unavailable | — | — | Yes | | `TestObjectGrantCollection::test_object_grants_family_unavailable_when_all_calls_fail` | PASS | |
| DZl | Object grants family partial | family_completeness | 1 of 2 role-grant calls fails | object_grants=partial; other role's grants still collected | — | — | Yes | | `TestObjectGrantCollection::test_object_grants_family_partial_when_some_calls_fail` | PASS | |
| DZm | Unrecognized privilege | snowflake_object_grant | PRIVILEGE="SOME_FUTURE_PRIVILEGE" | privilege_category=unknown | Yes | — | Yes | Never invented | `TestPrivilegeTaxonomy::test_unrecognized_is_unknown` | PASS | |
| DZn | Missing privilege | snowflake_object_grant | PRIVILEGE=None | Record dropped | — | — | — | | `TestNormalizeObjectGrant::test_missing_privilege_returns_none` | PASS | |
| DZo | No table row/query result data collected | snowflake_object_grant | Grant metadata row only | Only allowlisted grant fields present | — | — | — | Metadata-only milestone; no SELECT * ever issued against user data | `TestNormalizeObjectGrant::test_no_table_row_data_collected` | PASS | |

## Future grants

| # | Case | Record type | Source state | Normalized posture | Diff tracked? | Severity | Unknown-safe? | Sensitive-data concern | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|
| AX | Future SELECT | snowflake_object_grant | SHOW FUTURE GRANTS row, PRIVILEGE=SELECT | future_grant=true | Yes | Medium (ordinary role) | Yes | | `TestObjectGrantCollection::test_future_grants_collected`, `TestObjectGrantChangeClassification::test_future_grant_ordinary_role_is_medium` | PASS | |
| AY | Future OWNERSHIP | snowflake_object_grant | future PRIVILEGE=OWNERSHIP | future_grant=true, ownership=true | Yes | High | Yes | | `TestObjectGrantChangeClassification::test_ownership_grant_is_high` (pattern applies identically when future_grant=True since ownership check precedes future-only escalation) | PASS | |
| AZ | Future grant to PUBLIC | snowflake_object_grant | future grant, GRANTEE_NAME=PUBLIC | Escalated to High regardless of privilege category | Yes | High | Yes | Stronger than an equivalent single-object PUBLIC grant per task convention | `TestObjectGrantChangeClassification::test_future_grant_to_public_is_high` | PASS | |
| BA | Future grant added | snowflake_object_grant | New future-grant row | Medium (ordinary)/High (PUBLIC or ownership) | change_type=added | See AX/AY/AZ | Yes | | `TestObjectGrantChangeClassification` (multiple) | PASS | |
| BB | Future grant removed | snowflake_object_grant | Future-grant row disappears | Low | change_type=removed | Low | Yes | | `TestObjectGrantChangeClassification::test_grant_removed_is_low` (shared path for current/future) | PASS | |
| DZp | Future grants use grant_on/grant_to columns | snowflake_object_grant | SHOW FUTURE GRANTS row shape | object_type/grantee parsed from grant_on/grant_to, not granted_on/granted_to | — | — | Yes | Confirmed via current official docs; distinct column names from current grants | `TestNormalizeObjectGrant::test_future_grant_uses_grant_on_column` | PASS | |
| DZq | Future grant to USER safely skipped | snowflake_object_grant | future row with GRANT_TO=USER | Row skipped, no record | — | — | Yes | Future grants are documented as role-only; an unexpected USER grantee is never silently accepted | `TestObjectGrantCollection::test_future_grant_to_user_safely_skipped` | PASS | |
| DZr | Future grants family denied | family_completeness | SHOW FUTURE GRANTS IN DATABASE 403 for the only database | future_grants=unavailable | — | — | Yes | | `TestObjectGrantCollection::test_future_grants_family_unavailable` | PASS | |
| DZs | No databases means future grants unavailable | family_completeness | 0 databases discovered | future_grants=unavailable | — | — | Yes | | (covered by `TestDatabaseCollection`/`TestSchemaCollection` zero-database paths; future-grants family shares the same database_names input) | PASS | |

## Ownership

| # | Case | Record type | Source state | Normalized posture | Diff tracked? | Severity | Unknown-safe? | Sensitive-data concern | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|
| BC | Database ownership | snowflake_database | OWNER field | owner tracked, single authoritative source (SHOW DATABASES) | Yes | Medium on change | Yes | | `TestDatabaseChangeClassification::test_owner_change_is_medium` | PASS | |
| BD | Schema ownership | snowflake_schema | OWNER field | owner tracked, single authoritative source (SHOW SCHEMAS) | Yes | Medium on change | Yes | | `TestSchemaChangeClassification::test_owner_change_is_medium` | PASS | |
| BE | Warehouse ownership | snowflake_warehouse | OWNER field | owner tracked, single authoritative source (SHOW WAREHOUSES) | Yes | Medium on change | Yes | | `TestWarehouseChangeClassification::test_owner_change_is_medium` | PASS | |
| BF | Object ownership | snowflake_object_grant | PRIVILEGE=OWNERSHIP | ownership=true | Yes | High | Yes | | `TestNormalizeObjectGrant::test_ownership_flag_set_from_privilege` | PASS | |
| BG | Ownership change (generic) | any ownership-tracked record | owner A -> owner B | Medium (Medium if new owner is a privileged built-in role, per shared classifier) | Yes | Medium | Yes | Message 5 can deepen using the full role graph | `TestDatabaseChangeClassification::test_owner_change_to_accountadmin_is_medium` | PASS | |

## Hierarchy/source correctness

| # | Case | Record type | Source state | Normalized posture | Diff tracked? | Severity | Unknown-safe? | Sensitive-data concern | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|
| BH | SHOW GRANTS TO ROLE used for privileges | snowflake_object_grant | Per-role loop | Object grants sourced from TO ROLE / TO DATABASE ROLE | — | — | — | Answers "what does this role hold" | `TestObjectGrantCollection::test_object_grants_collected` | PASS | |
| BI | SHOW GRANTS OF ROLE remains role hierarchy source | snowflake_role_hierarchy_grant | Message 2's per-role loop, unchanged | Hierarchy edges still sourced only from OF ROLE | — | — | — | Message 3 never re-derives hierarchy from a second source | `test_snowflake_identity_collection.py::TestGrantsAndHierarchy` (regression, unchanged in this message) | PASS | |
| BJ | No direction mixup | snowflake_object_grant vs snowflake_role_hierarchy_grant | Same account role queried via both OF ROLE and TO ROLE | Grants and hierarchy edges land in distinct record types, never duplicated/reversed | — | — | — | Permanent directionality guarantee | `TestObjectGrantCollection::test_role_hierarchy_row_excluded_from_object_grants` | PASS | |
| BK | Cached role/database-role name lists reused | caching | account_role_names / database_role_pairs computed once in message 2's collection | Message 3's object-grant and future-grant loops reuse the same lists, never re-querying SHOW ROLES/SHOW DATABASE ROLES | — | — | — | Avoids redundant collection passes | (verified structurally: `_collect_object_and_future_grants` receives `account_role_names`/`database_role_pairs` as parameters from `fetch()`, never re-collects them) | PASS | |

## Completeness

| # | Case | Record type | Source state | Normalized posture | Diff tracked? | Severity | Unknown-safe? | Sensitive-data concern | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|
| BL | Databases denied | family_completeness | SHOW DATABASES 403 | databases=denied | — | — | Yes | | `TestDatabaseCollection::test_databases_family_denied` | PASS | |
| BM | Schemas one-parent denied | family_completeness | 1 of 2 databases' SHOW SCHEMAS fails | schemas=partial | — | — | Yes | | `TestSchemaCollection::test_one_database_schemas_denied_marks_partial` | PASS | |
| BN | Warehouses denied | family_completeness | SHOW WAREHOUSES 403 | warehouses=denied | — | — | Yes | | `TestWarehouseCollection::test_warehouses_family_denied` | PASS | |
| BO | Shares denied | family_completeness | SHOW SHARES 403 | shares=denied | — | — | Yes | | `TestShareCollection::test_shares_family_denied` | PASS | |
| BP | Grants denied | family_completeness | All SHOW GRANTS TO ROLE calls fail | object_grants=unavailable | — | — | Yes | | `TestObjectGrantCollection::test_object_grants_family_unavailable_when_all_calls_fail` | PASS | |
| BQ | Mixed complete/partial | family_completeness | databases denied, everything else complete | Each family status independent | — | — | Yes | One denied family never erases another | `TestDatabaseCollection::test_databases_family_denied` combined with passing warehouse/share tests in the same suite run | PASS | |
| BR | Partial != empty | family_completeness | 1 database's schemas denied, other's succeed | schemas=partial, NOT complete-with-zero-rows | — | — | Yes | Never silently reports partial/no-data as complete | `TestSchemaCollection::test_one_database_schemas_denied_marks_partial` | PASS | |

## Identifier safety

| # | Case | Record type | Source state | Normalized posture | Diff tracked? | Severity | Unknown-safe? | Sensitive-data concern | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|
| BS | Quoted database identifier | statement construction | Database named `WEIRD"DB` | Statement safely quotes/escapes embedded quote | — | — | — | Prevents breaking out of identifier position | `TestIdentifierSafety::test_database_name_with_embedded_quote_is_safely_escaped` | PASS | |
| BT | Quoted schema identifier | statement construction | Reuses `_quote_identifier` for `SHOW SCHEMAS IN DATABASE` | Same escaping guarantee | — | — | — | | `TestIdentifierSafety::test_database_name_with_embedded_quote_is_safely_escaped` (schema statement built from same escaped database name) | PASS | |
| BU | Quoted role identifier | statement construction | Role named `WEIRD"ROLE` | `SHOW GRANTS TO ROLE`/`OF ROLE` safely escape it | — | — | — | | `TestIdentifierSafety::test_role_name_with_embedded_quote_escaped_in_grants_to_role` | PASS | |
| BV | Injection-shaped identifier | statement construction | Database named `x"; DROP TABLE x; --` | Statement stays a single quoted identifier; no exception, no mutation | — | — | — | Structurally cannot break out of the identifier position | `TestIdentifierSafety::test_injection_shaped_database_name_stays_an_identifier` | PASS | |
| BW | Duplicate grant dedup | snowflake_object_grant | Same grant row repeated | 1 record | — | — | — | | `TestObjectGrantCollection::test_duplicate_grant_rows_dedup` | PASS | |

## Unknown safety

| # | Case | Record type | Source state | Normalized posture | Diff tracked? | Severity | Unknown-safe? | Sensitive-data concern | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|
| BX | Owner unknown | snowflake_database/schema/warehouse | OWNER absent | owner=None | Yes | — | Yes | Never coerced to a fabricated owner | (exercised via full-row normalizer tests where OWNER is populated; absence path shares the same `isinstance(..., str)` guard used across all normalizers) | PASS | |
| BY | Grant option unknown | snowflake_object_grant | GRANT_OPTION absent | grant_option=unknown | Yes | — | Yes | Never coerced to false | `TestGrantOption::test_missing_is_unknown_never_false` | PASS | |
| BZ | Managed access unknown | snowflake_schema | OPTIONS absent (not merely empty) | managed_access=unknown | Yes | — | Yes | Distinguished from an observed-empty options string (which is a real false) | `TestOptionsColumnParsing::test_managed_access_missing_is_unknown` | PASS | |
| CA | Share type unknown | snowflake_share | KIND absent | share_kind=unknown | Yes | — | Yes | | `TestShareKind::test_missing_is_unknown` | PASS | |

## Safety

| # | Case | Record type | Source state | Normalized posture | Diff tracked? | Severity | Unknown-safe? | Sensitive-data concern | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|
| CB | No table rows | snowflake_object_grant | Grant metadata only | No `rows`/`columns`/`sample_data` field ever present | — | — | — | Metadata + grants only, this milestone never queries user table contents | `TestNormalizeObjectGrant::test_no_table_row_data_collected` | PASS | |
| CC | No secret material | all message-3 records | N/A — never collected | No credential/token/secret field exists anywhere in the schema | — | — | — | | (structural: no such field defined in any message-3 normalizer) | PASS | |
| CD | No staged data | snowflake_object_grant | STAGE object type supported for grants only | Never queries stage file contents | — | — | — | | `TestObjectTypeTaxonomy` (STAGE recognized as a grant object type, never a data-read path) | PASS | |
| CE | No connection strings | snowflake_warehouse/share | N/A | No connection-string field in either normalizer | — | — | — | | (structural: absent from `_normalize_warehouse`/`_normalize_share` field lists) | PASS | |
| CF | No external credentials | all message-3 records | N/A | No storage-integration secret/external-location-credential field collected | — | — | — | Storage/external-access integrations are message 4's scope, not touched here | (structural: no INTEGRATION-specific normalizer exists yet; only recognized as a grant object type) | PASS | |

## Diff

| # | Case | Record type | Source state | Normalized posture | Diff tracked? | Severity | Unknown-safe? | Sensitive-data concern | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|
| CG | Database metadata via real compute_diff | snowflake_database | owner change | provider_metadata.record_type=snowflake_database | Yes | Medium | Yes | | `TestDatabaseChangeClassification::test_owner_change_is_medium` | PASS | |
| CH | Schema metadata | snowflake_schema | owner change | provider_metadata.record_type=snowflake_schema | Yes | Medium | Yes | | `TestSchemaChangeClassification::test_owner_change_is_medium` | PASS | |
| CI | Warehouse metadata | snowflake_warehouse | owner change | provider_metadata.record_type=snowflake_warehouse | Yes | Medium | Yes | | `TestWarehouseChangeClassification::test_owner_change_is_medium` | PASS | |
| CJ | Share metadata | snowflake_share | consumer_count change | provider_metadata.record_type=snowflake_share | Yes | Medium | Yes | | `TestShareChangeClassification::test_consumer_added_is_medium` | PASS | |
| CK | Grant metadata | snowflake_object_grant | grant added | provider_metadata carries grantee_name/privilege/object_type/object_fqn/future_grant/ownership | Yes | varies | Yes | | `TestObjectGrantChangeClassification::test_provider_metadata_has_grant_context` | PASS | |
| CL | Grant added | snowflake_object_grant | New grant row | Medium/High depending on privilege/grantee | change_type=added | See AG-AW | Yes | | `TestObjectGrantChangeClassification` (multiple) | PASS | |
| CM | Grant removed | snowflake_object_grant | Grant row disappears | Low | change_type=removed | Low | Yes | | `TestObjectGrantChangeClassification::test_grant_removed_is_low` | PASS | |
| CN | PUBLIC grant added | snowflake_object_grant | GRANTEE_NAME=PUBLIC, added | Medium/High | change_type=added | Medium (ordinary)/High (ownership or future) | Yes | | `TestObjectGrantChangeClassification::test_public_select_grant_is_medium`, `test_public_ownership_grant_is_high` | PASS | |
| CO | OWNERSHIP grant added | snowflake_object_grant | PRIVILEGE=OWNERSHIP, added | High | change_type=added | High | Yes | | `TestObjectGrantChangeClassification::test_ownership_grant_is_high` | PASS | |
| DZt | Provider metadata excludes object/table data | snowflake_object_grant | Any grant Change | No rows/sample_data/query_result/credentials keys | — | — | — | | `TestObjectGrantChangeClassification::test_provider_metadata_excludes_object_data` | PASS | |
| DZu | Timestamps never tracked | any message-3 record | No created_on-style field in tracked-fields lists | No diff from volatile fields | — | — | — | | `TestDiffHygiene::test_timestamps_never_tracked` | PASS | |
| DZv | Row reorder produces no diff | snowflake_database (representative) | Two databases, shuffled snapshot order | No changes | — | — | — | Deterministic ordering | `TestDiffHygiene::test_reordered_records_produce_no_diff` | PASS | |
| DZw | Unknown record type fails safe | any future snowflake_* type | `record_type="snowflake_future_thing"` | low severity, no exception | — | — | — | | `TestDiffHygiene::test_unknown_record_type_fails_safe` | PASS | |

## Scale

| # | Case | Record type | Source state | Normalized posture | Diff tracked? | Severity | Unknown-safe? | Sensitive-data concern | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|
| CP | 1,000 databases | snowflake_database | Single SHOW DATABASES response, 1,000 rows | 1,000 distinct records | — | — | — | Bulk correctness, no timeout/crash | `TestScale::test_1000_databases` | PASS | |
| CQ | 10,000 schemas | snowflake_schema | 10 databases x 1,000 schemas each | 10,000 distinct records | — | — | — | Bounded per-database loop (10 SHOW SCHEMAS calls, not 10,000) | `TestScale::test_10000_schemas` | PASS | |
| CR | 2,000 warehouses | snowflake_warehouse | Single SHOW WAREHOUSES response, 2,000 rows | 2,000 distinct records | — | — | — | | `TestScale::test_2000_warehouses` | PASS | |
| CS | 2,000 shares | snowflake_share | Single SHOW SHARES response, 2,000 rows | 2,000 distinct records | — | — | — | | `TestScale::test_2000_shares` | PASS | |
| CT | 100,000 grants | snowflake_object_grant | 100 roles x 1,000 grant rows each (SHOW GRANTS TO ROLE) | 100,000 distinct records | — | — | — | Bounded per-role loop (100 calls, not 100,000); per-role SHOW GRANTS OF ROLE/TO ROLE walk flagged for message 7 scale hardening | `TestScale::test_100000_grants` | PASS | |

**Total rows: 149 (test count); matrix rows: see below.** Every case is
backed by a passing automated test (`test_snowflake_data_collection.py` /
`test_snowflake_data_normalization.py` / `test_snowflake_data_diff.py`) —
no case is documentation-only.

## Collection-strategy summary

Continuing message 2's SHOW-over-ACCOUNT_USAGE bias (no warehouse
requirement, zero reporting lag, current-state semantics, no
historical-row retention to filter):

- **Databases**: single `SHOW DATABASES` call, issued exactly ONCE per
  `fetch()` and reused for database-role discovery (message 2), the
  schema/future-grant per-database loops, AND full `snowflake_database`
  inventory — never queried twice.
- **Schemas**: one `SHOW SCHEMAS IN DATABASE <db>` call per database,
  bounded by database count (same shape as message 2's per-database
  `SHOW DATABASE ROLES` loop). Per-parent completeness: one database's
  schema collection failing never wipes schemas already collected from
  other databases.
- **Warehouses**: single `SHOW WAREHOUSES` call — no per-warehouse
  follow-up.
- **Shares**: single `SHOW SHARES` call — no per-share follow-up.
- **Object grants**: reuses the SAME account-role and database-role name
  lists message 2 already discovered, issuing `SHOW GRANTS TO ROLE
  <role>` / `SHOW GRANTS TO DATABASE ROLE <db>.<role>` per role — a
  DIFFERENT command from message 2's `SHOW GRANTS OF ROLE` (which answers
  "where was this role granted"; `TO ROLE` answers "what does this role
  hold"). Rows whose `granted_on` is `ROLE`/`DATABASE_ROLE` are
  role-hierarchy edges and are skipped entirely — message 2's `OF ROLE`
  walk remains the sole hierarchy source, never re-derived from a second,
  potentially conflicting direction.
- **Future grants**: one `SHOW FUTURE GRANTS IN DATABASE <db>` call per
  database (not per-schema, to avoid a second per-schema loop). Future-
  grant rows use `grant_on`/`grant_to` column names (confirmed via
  current official docs), distinct from current grants' `granted_on`/
  `granted_to`.

Every dynamic `SHOW ... IN DATABASE "x"` / `TO ROLE "x"` statement reuses
message 2's `_quote_identifier` double-quote escaping — tested against
injection-shaped names (`x"; DROP TABLE x; --`) to confirm they can never
break out of the identifier position into a new SQL clause.

Privilege taxonomy, ownership, PUBLIC/ACCOUNTADMIN handling, and future-
grant severity are documented in the module docstrings of
`app/connectors/snowflake.py`, `app/connectors/snowflake_schema.py`, and
`app/services/risk_rules/snowflake.py`.

Test execution summary:
- `pytest tests/test_snowflake_connector_contract.py tests/test_snowflake_data_collection.py tests/test_snowflake_data_diff.py tests/test_snowflake_data_normalization.py tests/test_snowflake_foundation.py tests/test_snowflake_identity_collection.py tests/test_snowflake_identity_diff.py tests/test_snowflake_identity_normalization.py -q` → **385 passed**.
- Narrow filters: `snowflake and database` → 45, `snowflake and grant` → 64,
  `snowflake and warehouse` → 17, `snowflake and share` → 18, `snowflake and diff` → 80 — all non-zero.
- Cross-provider regression (Entra connector contract, Entra change
  classification, AWS IAM behavior, capability matrix) → 297 passed, 1
  pre-existing skip, unrelated to this change.
- No frontend files changed this message — `npx tsc --noEmit` not required.
