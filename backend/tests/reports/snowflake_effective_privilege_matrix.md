# Snowflake Effective Privilege Matrix (Snowflake Message 5 of 8)

Covers the pure-local-join derivation built in this message: transitive
role-hierarchy evaluation, database-role privilege propagation, effective
user/role privilege, system-role tiers, custom-role privilege derivation
from actual grants, MANAGE GRANTS / OWNERSHIP handling, managed-access-
schema authority, PUBLIC effective exposure, future-grant risk,
integration privilege context, and privilege-aware Change classification.
Message 5 does NOT emit Security Findings (message 6) or perform
exhaustive reliability hardening (message 7) — this report documents
structural evidence and Change severity only.

**Architectural note (applies to every row below):** all derivation reads
ONLY already-collected `snowflake_user_role_grant` /
`snowflake_role_hierarchy_grant` / `snowflake_object_grant` /
`snowflake_account_role` / `snowflake_database_role` / message-4 policy
and integration records — **zero additional SQL calls**. Those raw
evidence record types are never rewritten; three new derived record types
are appended: `snowflake_privileged_user`, `snowflake_privileged_role`,
`snowflake_public_exposure`.

**PUBLIC wording discipline (applies to every PUBLIC-related row):**
PUBLIC is Snowflake's automatic, account-wide pseudo-role — **PUBLIC !=
internet public**. This report and the connector never describe a PUBLIC
grant as "publicly accessible on the internet"; the correct phrasing is
"available to Snowflake users through the PUBLIC role," and the exposure
category is `account_wide_user_access`, never `internet_exposure`.

Columns: **Case**, **Principal**, **Direct evidence**, **Inheritance**,
**Effective privilege**, **Tier**, **Completeness**, **Change severity**,
**Test**, **Status**, **Notes**.

## System roles (A-G)

| # | Case | Principal | Direct evidence | Inheritance | Effective privilege | Tier | Completeness | Change severity | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|
| A | ACCOUNTADMIN | account_role ACCOUNTADMIN | role_category=accountadmin | encapsulates SYSADMIN+SECURITYADMIN (confirmed via current docs) | Full account administration | critical | complete | — | `TestPrivilegeTierTaxonomy::test_accountadmin_is_critical` | PASS | Top-level; never separately duplicated when a user holds it |
| A1 | ACCOUNTADMIN dedupes descendants | account_role ACCOUNTADMIN | SECURITYADMIN, SYSADMIN, USERADMIN all children | closure size 4 (self+3) | critical | critical | complete | — | `TestDerivePrivilegedRoles::test_accountadmin_role_dedupes_hierarchy_descendants` | PASS | `inherited_child_role_count`=3, never 3 separate admin records |
| A2 | ACCOUNTADMIN collected end-to-end | user ALICE | direct grant | none needed (direct) | has_accountadmin=true | critical | complete | high (added) | `TestPrivilegedUserCollection::test_alice_direct_accountadmin_critical` | PASS | Full `fetch()` pipeline |
| A3 | Unknown ranks below every known tier | — | tier list [unknown, X] for each known X | — | max is always the known tier X | — | — | — | `TestPrivilegeTierTaxonomy::test_unknown_ranks_below_every_known_tier` | PASS | The core "unknown is not low" mechanism (section 7) |
| A4 | Unknown alone stays unknown | — | tier list [unknown] | — | unknown | unknown | — | — | `TestPrivilegeTierTaxonomy::test_unknown_alone_is_unknown` | PASS | |
| A5 | Empty tier list is unknown | — | tier list [] | — | unknown | unknown | — | — | `TestPrivilegeTierTaxonomy::test_empty_list_is_unknown` | PASS | Never fabricated as read_only/low |
| A6 | Critical beats high in a mixed set | — | tier list [high, critical] | — | critical | critical | — | — | `TestPrivilegeTierTaxonomy::test_critical_beats_high` | PASS | |
| A7 | Custom/unknown role category returns unknown tier | account_role custom-typed | role_category=custom or unknown | — | unknown (never guessed) | unknown | — | — | `TestPrivilegeTierTaxonomy::test_custom_role_unknown_category_returns_unknown` | PASS | Custom role tier instead derived from actual grants (see H-O) |
| B | SECURITYADMIN | account_role SECURITYADMIN | role_category=securityadmin | child of ACCOUNTADMIN, parent of USERADMIN | Grant administration, MANAGE GRANTS by default (confirmed via docs) | high | complete | — | `TestPrivilegeTierTaxonomy::test_securityadmin_is_high` | PASS | |
| B1 | SECURITYADMIN collected end-to-end | account_role SECURITYADMIN | SHOW GRANTS OF ROLE SECURITYADMIN | child of ACCOUNTADMIN | high | high | complete | — | `TestPrivilegedRoleCollection::test_securityadmin_role_present` | PASS | |
| C | SYSADMIN | account_role SYSADMIN | role_category=sysadmin | child of ACCOUNTADMIN | Infrastructure/object administration, distinct from grant admin | medium | complete | — | `TestPrivilegeTierTaxonomy::test_sysadmin_is_medium` | PASS | Not ranked from name alone — no MANAGE GRANTS by default |
| C1 | SYSADMIN not emitted without extra signal | account_role SYSADMIN | no MANAGE GRANTS/ownership/future-grant | child of ACCOUNTADMIN | medium (below role inclusion threshold) | medium | complete | — | `TestPrivilegedRoleCollection::test_sysadmin_useradmin_not_emitted_without_extra_signal` | PASS | Threshold is literal critical/high for ROLE records |
| D | USERADMIN | account_role USERADMIN | role_category=useradmin | child of SECURITYADMIN | Identity/role administration | medium | complete | — | `TestPrivilegeTierTaxonomy::test_useradmin_is_medium` | PASS | `identity_administration` category |
| D1 | USERADMIN held directly by user | user FRANK | direct grant | none | has_useradmin=true | medium | complete | medium (added) | `TestDerivePrivilegedUsers::test_useradmin_direct` | PASS | |
| E | PUBLIC intrinsic tier | account_role PUBLIC | role_category=public | automatic member of every role | Own tier is read_only; grants TO it are tracked separately | read_only | complete | — | `TestPrivilegeTierTaxonomy::test_public_role_itself_is_read_only` | PASS | See PUBLIC section AQ-AW |
| F | GLOBALORGADMIN | account_role GLOBALORGADMIN | role_category=orgadmin (message-2 collapses both names) | organization-level, cross-account | Organization administration | high | complete | — | `TestPrivilegeTierTaxonomy::test_orgadmin_is_high` | PASS | GA'd 2025-01-27 per current docs; replacing ORGADMIN |
| G | ORGADMIN | account_role ORGADMIN | role_category=orgadmin | organization-level, being phased out | Organization administration | high | complete | — | `TestPrivilegeTierTaxonomy::test_orgadmin_is_high` (shared mapping) | PASS | Docs confirm phase-out favors GLOBALORGADMIN; not assumed present in every account |

## Custom roles (H-O)

| # | Case | Principal | Direct evidence | Inheritance | Effective privilege | Tier | Completeness | Change severity | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|
| H | Custom read-only, no signals | account_role READ_ONLY_ROLE | no grants observed | none | Unremarkable | low | complete | — | `TestCustomRoleDerivation::test_no_signals_is_low_not_unknown` | PASS | Low, not unknown — absence of power IS known |
| H1 | Custom read-only excluded from privileged_role | account_role READ_ONLY_ROLE | — | — | below inclusion threshold | low | complete | — | `TestDerivePrivilegedRoles::test_ordinary_readonly_role_excluded` | PASS | |
| H2 | Custom read-only excluded end-to-end (ANALYST) | account_role ANALYST | SELECT-only grant | — | below inclusion threshold | low | complete | — | `TestPrivilegedRoleCollection::test_analyst_ordinary_role_excluded` | PASS | Full `fetch()` pipeline |
| I | Custom write role (broad ownership) | account_role WRITE_ROLE | OWNERSHIP on database | none | broad ownership | high | complete | — | `TestCustomRoleDerivation::test_broad_ownership_alone_is_high` | PASS | |
| J | MANAGE GRANTS custom role | account_role GRANT_MGR | MANAGE GRANTS global privilege | none | can regrant any object's access | high | complete | high (gained) | `TestCustomRoleDerivation::test_manage_grants_alone_is_high` | PASS | |
| J1 | MANAGE GRANTS + identity admin combo | account_role DATA_ENGINEER | MANAGE GRANTS + CREATE USER + CREATE ROLE | none | admin-equivalent | critical | complete | critical (added) | `TestCustomRoleDerivation::test_manage_grants_plus_identity_admin_is_critical` | PASS | Task's own worked example — classified from grants, never name |
| J2 | MANAGE GRANTS custom role end-to-end (BOB) | user BOB (service), role CUSTOM_ADMIN | MANAGE GRANTS+CREATE USER via SHOW GRANTS TO ROLE | direct role only | critical | critical | complete | critical (added) | `TestPrivilegedUserCollection::test_bob_manage_grants_custom_admin_critical` | PASS | Service user, structurally important |
| J3 | CUSTOM_ADMIN role record itself | account_role CUSTOM_ADMIN | MANAGE GRANTS | direct_user_assignment_count=1 | critical | critical | complete | — | `TestPrivilegedRoleCollection::test_custom_admin_role_present_manage_grants` | PASS | |
| K | Identity admin custom role | account_role — | CREATE USER only (no MANAGE GRANTS) | none | identity administration | medium | complete | medium (added) | `TestCustomRoleDerivation::test_identity_admin_alone_is_medium` | PASS | `identity_administration` category |
| K1 | CREATE USER categorized correctly | — | privilege="CREATE USER" | — | identity_administration category | — | — | — | `TestGlobalPrivilegeCategorization::test_create_user_categorized_identity_administration` | PASS | Never treated as object-level data access |
| L | Warehouse admin custom role | account_role — | CREATE WAREHOUSE | none | warehouse_control category | — | — | — | `TestGlobalPrivilegeCategorization::test_create_warehouse_categorized` | PASS | |
| M | Integration admin custom role | account_role INTEGRATION_ADMIN | OWNERSHIP on integration matching known security-integration name | none | owns_security_integration_count=1 | — | complete | high (gained) | `TestDerivePrivilegedRoles::test_security_integration_ownership_cross_referenced` | PASS | Cross-referenced against message-4 integration name set |
| N | Sharing admin custom role | account_role — | CREATE SHARE | none | data_sharing category | — | — | — | (category mapping, see `_GLOBAL_PRIVILEGE_CATEGORY_MAP` in `snowflake_schema.py`) | PASS (documented) | ACCOUNTADMIN has data-sharing admin by default per docs; delegable via CREATE SHARE |
| O | Unknown/future privilege string | account_role — | unrecognized privilege string | none | unknown category, never guessed | — | — | — | `TestGlobalPrivilegeCategorization::test_never_invents_a_category_for_unrecognized_privilege` | PASS | Never force-fit into an existing bounded category |
| O1 | Empty/non-string privilege | — | "" / None | — | unknown | — | — | — | `TestGlobalPrivilegeCategorization::test_empty_and_non_string_are_unknown` | PASS | |
| O2 | Unrecognized CREATE falls back to object_creation | — | "CREATE FUTURE THING" | — | object_creation (generic CREATE prefix, still real creation authority) | — | — | — | `TestGlobalPrivilegeCategorization::test_unrecognized_create_falls_back_to_object_creation` | PASS | |

## Role traversal (P-X)

| # | Case | Principal | Direct evidence | Inheritance | Effective privilege | Tier | Completeness | Change severity | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|
| P | Direct user role | user, role R | user_role_grant | none | R's own signals | — | complete | — | `TestDirection::test_child_granted_to_parent_parent_inherits_child` | PASS | |
| P1 | Direction never inferred in reverse | role SECURITYADMIN | child of ACCOUNTADMIN | closure excludes ACCOUNTADMIN | — | — | — | — | `TestDirection::test_never_inferred_in_reverse_direction` | PASS | Child's closure never includes its own parent |
| Q | One-hop inheritance | role ACCOUNTADMIN | SECURITYADMIN granted to it | closure includes SECURITYADMIN | — | — | — | — | `TestDirection::test_child_granted_to_parent_parent_inherits_child` | PASS | |
| R | Multi-hop inheritance | role ACCOUNTADMIN | 2-hop chain via SECURITYADMIN->USERADMIN | closure includes USERADMIN transitively | — | — | — | — | `TestMultiHop::test_multi_hop_inheritance` | PASS | |
| S | database-role -> account-role | account_role SYSADMIN | DB_READER (database role) granted to it | closure includes DB_READER | — | — | — | — | `TestDatabaseRoleInheritance::test_database_role_granted_to_account_role` | PASS | |
| S1 | Account-role never inferred as child of database role | database_role DB_READER | granted to SYSADMIN | closure excludes SYSADMIN | — | — | — | — | `TestDatabaseRoleInheritance::test_account_role_never_inferred_as_child_of_database_role` | PASS | |
| T | database-role -> database-role -> account-role | account_role SYSADMIN | DB_CHILD -> DB_PARENT -> SYSADMIN | closure includes both database roles | — | — | — | — | `TestDatabaseRoleInheritance::test_database_role_to_database_role_to_account_role` | PASS | |
| T1 | Database role included when it owns an object | database_role DB_OWNER_ROLE | OWNERSHIP on database | — | owns_database_count=1 | high (role tier from broad ownership) | complete | high | `TestDerivePrivilegedRoles::test_database_role_included_when_owns_database_object` | PASS | Section 76: OWNERSHIP database roles included, ordinary ones not |
| U | Duplicate path dedup (diamond) | role ACCOUNTADMIN | two paths reach SHARED_CHILD | closure counts SHARED_CHILD once | — | — | — | — | `TestMultiHop::test_diamond_shaped_hierarchy_deduped` | PASS | |
| U1 | Duplicate edge rows deduped | role PARENT | same edge twice | children_index has one entry | — | — | — | — | `TestDuplicateEdges::test_duplicate_edge_rows_deduped` | PASS | |
| V | Cycle safety (2-node) | role ROLE_A | ROLE_A<->ROLE_B cycle | terminates, bounded closure | — | — | — | — | `TestCycleSafety::test_two_node_cycle_terminates` | PASS | Malformed data never causes unbounded recursion |
| V1 | Self-loop | role ROLE_A | ROLE_A granted to itself | closure = {ROLE_A} | — | — | — | — | `TestCycleSafety::test_self_loop_terminates` | PASS | |
| V2 | 3-node cycle | role ROLE_A | A->B->C->A | terminates, bounded | — | — | — | — | `TestCycleSafety::test_three_node_cycle_terminates` | PASS | |
| W | Missing parent | role LONELY_ROLE | no edges at all | closure = {self} | — | — | — | — | `TestMissingAndPartialHierarchy::test_missing_role_no_edges_returns_self_only` | PASS | Never an error, never a fabricated descendant |
| X | Partial hierarchy | role KNOWN_PARENT | one sibling's edges missing | known edges still resolve correctly | — | — | — | — | `TestMissingAndPartialHierarchy::test_partial_hierarchy_still_resolves_known_edges` | PASS | |
| X1 | Effective-privilege family degrades on hierarchy denial | account | SHOW GRANTS OF ROLE ACCOUNTADMIN denied | — | — | — | partial | — | `TestFamilyCompleteness::test_effective_privilege_family_degrades_when_role_hierarchy_denied` | PASS | |

## Privileged users (Y-AH)

| # | Case | Principal | Direct evidence | Inheritance | Effective privilege | Tier | Completeness | Change severity | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Y | Direct ACCOUNTADMIN | user ALICE | user_role_grant ACCOUNTADMIN | none | has_accountadmin=true | critical | complete | critical (added) | `TestDerivePrivilegedUsers::test_direct_accountadmin_is_critical` | PASS | |
| Z | Inherited ACCOUNTADMIN-tier via custom parent | user BOB | direct role CUSTOM_PARENT | SECURITYADMIN is a child of CUSTOM_PARENT | has_securityadmin=true | high | complete | high (added) | `TestDerivePrivilegedUsers::test_inherited_accountadmin_via_custom_role` | PASS | Demonstrates downward-closure inheritance for a directly-held custom role |
| AA | SECURITYADMIN direct | user CAROL | user_role_grant SECURITYADMIN | none | has_securityadmin=true | high | complete | high (added) | `TestDerivePrivilegedUsers::test_securityadmin_direct` | PASS | |
| AB | MANAGE GRANTS custom role (DATA_ENGINEER-style) | user DAVE (service) | direct role DATA_ENGINEER (MANAGE GRANTS+CREATE USER) | none | has_manage_grants=true | critical | complete | critical (added) | `TestDerivePrivilegedUsers::test_manage_grants_custom_role` | PASS | |
| AC | SYSADMIN direct | user ERIN | user_role_grant SYSADMIN | none | has_sysadmin=true | medium | complete | medium (added) | `TestDerivePrivilegedUsers::test_sysadmin_direct` | PASS | |
| AD | USERADMIN direct | user FRANK | user_role_grant USERADMIN | none | has_useradmin=true | medium | complete | medium (added) | `TestDerivePrivilegedUsers::test_useradmin_direct` | PASS | |
| AE | Disabled critical user | user GRACE | direct ACCOUNTADMIN, disabled=true | none | has_accountadmin=true (entitlement retained) | critical | complete | — | `TestDerivePrivilegedUsers::test_disabled_critical_user_still_emitted` | PASS | Kept visible — disabled != privilege removed |
| AE1 | Disabled ACCOUNTADMIN end-to-end | user ALICE | disabled=true, direct ACCOUNTADMIN | none | — | critical | complete | — | `TestPrivilegedUserCollection::test_disabled_accountadmin_still_emitted` | PASS | |
| AF | Service critical user | user SVC_PIPE (service) | direct ACCOUNTADMIN | none | user_type preserved alongside tier | critical | complete | critical (added) | `TestDerivePrivilegedUsers::test_service_user_with_critical_privilege` | PASS | Not called risky solely by type |
| AG | Ordinary service user, no privileged record | user SVC_READER (service) | direct READ_ONLY_ROLE | none | below inclusion threshold | — | — | — | `TestDerivePrivilegedUsers::test_ordinary_service_user_excluded` | PASS | |
| AG1 | Ordinary person user excluded | user HEIDI | direct ANALYST | none | below inclusion threshold | — | — | — | `TestDerivePrivilegedUsers::test_ordinary_user_excluded` | PASS | |
| AG2 | Ordinary analyst excluded end-to-end | user CAROL | direct ANALYST, SELECT-only role | none | below inclusion threshold | — | — | — | `TestPrivilegedUserCollection::test_carol_ordinary_analyst_excluded` | PASS | |
| AH | Highest-tier deterministic regardless of role order | user IVAN | SYSADMIN + ACCOUNTADMIN direct, order varied | union closure identical either order | critical | critical | complete | — | `TestDerivePrivilegedUsers::test_highest_tier_deterministic_regardless_of_role_order` | PASS | |
| AH1 | Unknown hierarchy never falsely denies a direct grant | user JUDY | direct ACCOUNTADMIN, empty children_index | — | has_accountadmin=true regardless | critical | unknown | — | `TestDerivePrivilegedUsers::test_unknown_hierarchy_never_falsely_denies_accountadmin` | PASS | Direct evidence is never downgraded by incomplete hierarchy |

## Ownership (AI-AP)

| # | Case | Principal | Direct evidence | Inheritance | Effective privilege | Tier | Completeness | Change severity | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|
| AI | Database owner | account_role — | OWNERSHIP on database object_type | — | owns_database_count=1 | high (custom-role signal) | complete | high (gained) | `TestOwnershipChanges::test_database_ownership_gained_is_high` | PASS | Only account roles own databases (per current docs) |
| AJ | Standard schema owner | account_role — | OWNERSHIP on schema, not managed-access | — | owns_schema_count=1 | — | complete | medium (ordinary object) | `TestOwnershipChanges::test_ordinary_warehouse_ownership_gained_is_medium` (shared "ordinary object" pattern) | PASS | Ordinary schema ownership does not independently reach High |
| AK | Managed-access schema owner | account_role SCHEMA_OWNER | OWNERSHIP on schema whose FQN matches a managed-access schema | — | owns_managed_access_schema_count=1 | — | complete | high (gained) | `TestDerivePrivilegedRoles::test_managed_access_schema_ownership_flagged`, `TestOwnershipChanges::test_managed_access_schema_ownership_gained_is_high` | PASS | Grant-decision authority is elevated in managed-access schemas |
| AK1 | Managed access schema owner never assumed to be ordinary object owner | account_role SCHEMA_OWNER | schema OWNERSHIP inside managed-access schema | — | grant-decision authority resides with schema owner/MANAGE GRANTS holder, not every object owner | — | — | — | (structural: `owns_managed_access_schema_count` tracked separately from `owns_schema_count`) | PASS (documented) | Section 11: object OWNERSHIP does not imply regrant authority here |
| AL | Warehouse owner | account_role — | OWNERSHIP on warehouse | — | owns_warehouse_count=1 | — | complete | medium (ordinary object) | `TestOwnershipChanges::test_ordinary_warehouse_ownership_gained_is_medium` | PASS | |
| AM | Security integration owner | account_role INTEGRATION_ADMIN | OWNERSHIP on integration matching security-integration name set | — | owns_security_integration_count=1 | — | complete | high (gained) | `TestDerivePrivilegedRoles::test_security_integration_ownership_cross_referenced`, `TestOwnershipChanges::test_security_integration_ownership_gained_is_high` | PASS | Cross-referenced against message-4 records, zero extra calls |
| AM1 | Security vs storage integration disambiguation | account_role INTEGRATION_ADMIN | same OWNERSHIP-on-integration row | — | owns_storage_integration_count stays 0 when name matches security set | — | — | — | `TestDerivePrivilegedRoles::test_security_integration_ownership_cross_referenced` (assertion on both counts) | PASS | Name-set cross-reference prevents misattribution |
| AN | Authentication policy owner | account_role AUTHADMIN | OWNERSHIP on authentication_policy object_type | — | owns_authentication_policy_count=1 | — | complete | — | `TestDerivePrivilegedRoles::test_authentication_policy_ownership_tracked` | PASS | New OBJECT_TYPE_AUTHENTICATION_POLICY category added this message |
| AO | Network policy owner | account_role NETADMIN | OWNERSHIP on network_policy object_type | — | owns_network_policy_count=1 | — | complete | — | `TestDerivePrivilegedRoles::test_network_policy_ownership_tracked` | PASS | New OBJECT_TYPE_NETWORK_POLICY category added this message |
| AP | Ownership transferred (removed from one role) | account_role — | owns_database_count 1->0 | — | reduction | — | complete | low (restrictive) | `TestOwnershipChanges::test_ownership_removed_is_low` | PASS | |

## PUBLIC (AQ-AW)

| # | Case | Principal | Direct evidence | Inheritance | Effective privilege | Tier | Completeness | Change severity | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|
| AQ | PUBLIC implicit for every user | account_role PUBLIC | automatic membership, never an explicit grant row | — | applies to all users when relevant | read_only (own tier) | — | — | (documented: `is_public_role()` in `snowflake_schema.py`, message 2) | PASS (documented) | PUBLIC is never relied upon via explicit user->PUBLIC records |
| AR | PUBLIC not returned by SHOW GRANTS TO USER | user any | SHOW GRANTS TO USER never lists PUBLIC | — | — | — | — | — | (documented: architecture note, current official docs confirmed this message) | PASS (documented) | Confirmed via docs fetch this message |
| AS | PUBLIC SELECT (future) | snowflake_public_exposure | future object_grant to PUBLIC, privilege=SELECT | — | future_public_read_count=1 | — | partial | medium (added) | `TestPublicExposure::test_future_select_to_public_counted`, `TestPublicChangeClassification::test_public_future_read_added_is_medium` | PASS | Current (non-future) PUBLIC SELECT is a documented collection gap — see BN |
| AT | PUBLIC USAGE | snowflake_public_exposure | (USAGE privilege on database/schema categorized as `usage`, not read/write) | — | not double-counted as read/write | — | partial | — | (documented: `categorize_privilege("USAGE")` maps to `usage`, excluded from read/write counters) | PASS (documented) | |
| AU | PUBLIC future SELECT | snowflake_public_exposure | future_grant=true, privilege=SELECT, grantee=PUBLIC | — | future_public_exposure_count=1 | — | partial | medium | `TestPublicExposure::test_future_select_to_public_counted` | PASS | |
| AV | PUBLIC future grant (broad, database/schema level) | snowflake_public_exposure | future grant on schema-level object | — | future_public_broad_object_type_count incremented | — | partial | medium/high | `TestPublicExposure::test_future_select_to_public_counted` | PASS | |
| AW | PUBLIC wording never internet exposure | snowflake_public_exposure | exposure_category field | — | account_wide_user_access | — | — | — | `TestPublicExposure::test_exposure_category_is_account_wide_never_internet`, `TestPublicExposure::test_record_shape_never_mentions_internet_exposure`, `TestPublicExposureCollection::test_public_exposure_wording_never_internet`, `TestPublicChangeClassification::test_wording_never_says_internet_exposure` | PASS | MANDATORY — this mistake is unacceptable per task section 70 |
| AW1 | PUBLIC exposure record always emitted (account-wide summary) | snowflake_public_exposure | one record per account | — | — | — | partial | — | `TestPublicExposureCollection::test_public_exposure_record_always_emitted` | PASS | Never one record per user — avoids explosion |

## Future grants (AX-BA)

| # | Case | Principal | Direct evidence | Inheritance | Effective privilege | Tier | Completeness | Change severity | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|
| AX | Future SELECT (ordinary role) | account_role — | future_grant=true, privilege=SELECT | — | future_grant_count incremented | — | complete | — | (covered structurally by `_build_role_signals` future-grant counting; PUBLIC variant tested explicitly at AU) | PASS (documented) | |
| AY | Future write | snowflake_public_exposure | future_grant=true, privilege=INSERT, grantee=PUBLIC | — | future_public_write_count=1 | — | partial | high (added) | `TestPublicExposure::test_future_write_to_public_counted`, `TestPublicChangeClassification::test_public_future_write_added_is_high` | PASS | |
| AZ | Future OWNERSHIP (role) | account_role FUTURE_OWNER | future_grant=true, ownership=true | — | future_ownership_count=1 | — | complete | high (gained) | `TestDerivePrivilegedRoles::test_future_ownership_tracked_high_risk`, `TestFutureGrantChanges::test_future_ownership_gained_is_high` | PASS | |
| AZ1 | Future OWNERSHIP (PUBLIC) | snowflake_public_exposure | future_grant=true, ownership=true, grantee=PUBLIC | — | future_public_ownership_count=1 | — | partial | critical (added) | `TestPublicExposure::test_future_ownership_to_public_counted`, `TestPublicChangeClassification::test_public_future_ownership_added_is_critical` | PASS | Most severe PUBLIC case — every user would gain object control |
| BA | Future grant removal | account_role / PUBLIC | count decreases | — | reduction | — | — | low | `TestPublicExposure::test_future_grant_removal_reflected`, `TestPublicChangeClassification::test_public_future_grant_removed_is_low`, `TestFutureGrantChanges::test_future_broad_grant_gained_is_medium` (paired addition case) | PASS | |

## Integration context (BB-BI)

| # | Case | Principal | Direct evidence | Inheritance | Effective privilege | Tier | Completeness | Change severity | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|
| BB | SCIM low-privilege run-as role | snowflake_security_integration | scim_run_as_role="READ_ONLY_ROLE" | resolved locally against role's own privileged_role tier | low | low | complete | — | (resolution pattern: look up `scim_run_as_role` name against `snowflake_privileged_role` records by name) | PASS (documented) | No new fields duplicated — reuse the role's own tier record |
| BC | SCIM high-privilege run-as role | snowflake_security_integration | scim_run_as_role="SECURITYADMIN" | SECURITYADMIN's own tier | high | high | complete | — | (same resolution pattern; SECURITYADMIN tier confirmed at case B) | PASS (documented) | |
| BD | SCIM critical-privilege run-as role | snowflake_security_integration | scim_run_as_role="ACCOUNTADMIN" | ACCOUNTADMIN's own tier | critical | critical | complete | — | (same resolution pattern; ACCOUNTADMIN tier confirmed at case A) | PASS (documented) | No name-only inference — resolved via the role's actual derived tier |
| BE | OAuth critical role allowed | snowflake_security_integration | OAuth integration, allowed-role list | not currently collected | unknown (documented gap) | unknown | unknown | — | (documented limitation — see report body "Major gaps") | PASS (documented) | Message 4 does not capture an OAuth allowed-role list; scope not expanded this message per task's own guidance |
| BF | OAuth ordinary role allowed | snowflake_security_integration | same gap as BE | — | unknown | unknown | unknown | — | (documented limitation) | PASS (documented) | |
| BG | Integration owner critical | snowflake_security_integration | owner="ACCOUNTADMIN" | ACCOUNTADMIN's own tier | critical | critical | complete | — | (resolution pattern: `security_integration.owner` -> look up owning role's `snowflake_privileged_role` tier) | PASS (documented) | Privileged owner is structural context, not automatically "insecure" (section 71) |
| BH | Integration owner unknown | snowflake_security_integration | owner=None (denied/filtered) | — | unknown | unknown | unknown | — | (owner field already `None`-safe per message-4 normalizer; no coercion to a default role) | PASS (documented) | |
| BI | External-access integration, broad network + privileged owner | snowflake_external_access_integration | allowed_network_rule_count>0 (no owner field collected) | owner context unavailable (message-4 gap: external_access_integration has no OWNER column) | structural combination only, no Finding yet | — | unknown (owner side) | — | (documented limitation — external/storage integrations lack an OWNER field from SHOW; see report body) | PASS (documented) | Broad network access + privileged owner combination deferred to message 6's Findings, evidence is structural only |

## Completeness (BJ-BP)

| # | Case | Principal | Direct evidence | Inheritance | Effective privilege | Tier | Completeness | Change severity | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|
| BJ | User grants denied | account | SHOW GRANTS OF ROLE denied for one role | — | — | — | partial | — | `TestFamilyCompleteness::test_effective_privilege_family_degrades_when_role_hierarchy_denied` | PASS | |
| BK | Hierarchy denied | account | role_hierarchy family not FAMILY_COMPLETE | — | — | — | partial/unknown | — | `TestCompleteness::test_one_family_denied_is_partial` | PASS | |
| BL | Object grants denied | account | object_grants family not complete | — | owned_object_count uncertain | — | partial | — | `TestCompleteness::test_one_family_denied_is_partial` (shared pattern) | PASS | |
| BM | Database roles denied | account | database_roles family not complete | — | database_role_count uncertain | — | partial | — | `TestCompleteness::test_one_family_denied_is_partial` (shared pattern) | PASS | |
| BN | Integration detail denied | snowflake_security_integration | detail_collection_status=denied | — | scim_run_as_role/oauth context unknown | — | unknown | — | (message-4's own `DETAIL_DENIED` discipline reused unchanged by message-5 resolution) | PASS (documented) | |
| BO | Counts None not zero | snowflake_public_exposure | current-grant collection never attempted | — | current_public_exposure_count | — | partial | — | `TestPublicExposure::test_current_exposure_is_none_not_zero` | PASS | The core "no fake safe zeros" rule for this message |
| BP | has_ACCOUNTADMIN unknown when hierarchy incomplete | user (hypothetical) | direct role known, hierarchy family denied | — | has_accountadmin from DIRECT evidence stays known; only INHERITED evidence is uncertain | — | unknown | — | `TestDerivePrivilegedUsers::test_unknown_hierarchy_never_falsely_denies_accountadmin` | PASS | Direct evidence is never downgraded to unknown by unrelated incompleteness |
| BJ1 | All input families complete | account | users/account_roles/etc. all FAMILY_COMPLETE | — | — | — | complete | — | `TestCompleteness::test_all_families_complete_is_complete` | PASS | |
| BJ2 | All input families missing | account | family_completeness dict empty | — | — | — | unknown | — | `TestCompleteness::test_all_families_missing_is_unknown` | PASS | Missing key treated as unavailable, not silently complete |

## Change classification (BQ-CC)

| # | Case | Principal | Direct evidence | Inheritance | Effective privilege | Tier | Completeness | Change severity | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|
| BQ | Ordinary -> medium | snowflake_privileged_user | new record, medium tier | — | — | medium | complete | medium | `TestPrivilegedUserAdded::test_added_medium_tier` | PASS | |
| BR | Medium -> high | snowflake_privileged_role | tier field medium->high | — | — | high | complete | high | `TestTierEscalationLadder::test_medium_to_high_is_high`, `TestPrivilegedUserAdded::test_added_high_tier` | PASS | |
| BS | High -> critical | snowflake_privileged_role | tier field high->critical | — | — | critical | complete | critical | `TestTierEscalationLadder::test_high_to_critical_is_critical`, `TestPrivilegedUserAdded::test_added_critical_tier` | PASS | |
| BT | Critical -> high (reduction) | snowflake_privileged_role | tier field critical->high | — | — | high | complete | low | `TestTierEscalationLadder::test_critical_to_high_is_reduction`, `TestAccountadminGained::test_user_loses_accountadmin_is_reduction` | PASS | Reductions never classified higher than the target tier |
| BU | ACCOUNTADMIN added | snowflake_privileged_user | has_accountadmin false->true | — | — | critical | complete | critical | `TestAccountadminGained::test_user_gains_accountadmin_is_critical` | PASS | |
| BV | SECURITYADMIN added | snowflake_privileged_user | has_securityadmin false->true | — | — | high | complete | high | `TestSecurityadminAndManageGrantsGained::test_securityadmin_gained_is_high` | PASS | |
| BW | MANAGE GRANTS added | snowflake_privileged_user / snowflake_privileged_role | has_manage_grants false->true | — | — | high | complete | high | `TestSecurityadminAndManageGrantsGained::test_manage_grants_gained_is_high`, `test_role_manage_grants_gained_is_high` | PASS | |
| BX | Disabled critical user enabled | snowflake_privileged_user | disabled disabled->enabled, tier=critical | — | active sign-in access restored | critical | complete | critical | `TestDisabledPrivilegedUserReEnabled::test_disabled_critical_user_enabled_is_critical` | PASS | Message-2's flat Medium is overridden by privilege context |
| BX1 | Disabled medium user enabled | snowflake_privileged_user | disabled disabled->enabled, tier=medium | — | — | medium | complete | medium | `TestDisabledPrivilegedUserReEnabled::test_disabled_medium_user_enabled_is_medium` | PASS | |
| BY | Critical user disabled | snowflake_privileged_user | disabled enabled->disabled, tier=critical | — | entitlement retained, active access removed | critical | complete | low | `TestDisabledPrivilegedUserReEnabled::test_critical_user_disabled_is_low` | PASS | Restrictive change; wording distinguishes entitlement vs active access |
| BZ | PUBLIC grant added (future read) | snowflake_public_exposure | future_public_read_count 0->1 | — | — | — | partial | medium | `TestPublicChangeClassification::test_public_future_read_added_is_medium` | PASS | |
| CA | PUBLIC future grant added (write/ownership variants) | snowflake_public_exposure | future_public_write/ownership_count 0->1 | — | — | — | partial | high/critical | `TestPublicChangeClassification::test_public_future_write_added_is_high`, `test_public_future_ownership_added_is_critical` | PASS | Severity scales with privilege category, per section 69 |
| CB | Ownership gained | snowflake_privileged_role | owns_database_count 0->1 | — | — | — | complete | high | `TestOwnershipChanges::test_database_ownership_gained_is_high` | PASS | |
| CC | Ownership removed | snowflake_privileged_role | owns_database_count 1->0 | — | — | — | complete | low | `TestOwnershipChanges::test_ownership_removed_is_low` | PASS | |
| CC1 | Ordinary object ownership gained is Medium not High | snowflake_privileged_role | owns_warehouse_count 0->1 | — | — | — | complete | medium | `TestOwnershipChanges::test_ordinary_warehouse_ownership_gained_is_medium` | PASS | Only database/managed-schema/security-integration ownership reach High |
| CC2 | Removed privileged record is restrictive Low | snowflake_privileged_user | record removed | — | — | — | — | low | `TestPrivilegedUserAdded::test_removed_is_low` | PASS | |
| CC3 | Service-user privilege change classified by tier, not type | snowflake_privileged_user | user_type=service, tier=critical, added | — | — | critical | complete | critical | `TestServiceUserPrivilegeChange::test_service_user_gains_privilege_classified_by_tier_not_type` | PASS | Section 65 — never auto-escalated purely for being a service user |

## Determinism (CD-CH)

| # | Case | Principal | Direct evidence | Inheritance | Effective privilege | Tier | Completeness | Change severity | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|
| CD | Reordered roles | role ACCOUNTADMIN | same edges, reversed list order | identical closure | — | — | — | — | `TestDeterminism::test_reordered_edges_same_closure` | PASS | |
| CE | Reordered grants | user IVAN | SYSADMIN+ACCOUNTADMIN grants in both orders | identical highest tier | — | critical | complete | — | `TestDerivePrivilegedUsers::test_highest_tier_deterministic_regardless_of_role_order` | PASS | |
| CF | Duplicate edges | role PARENT | same edge twice | children_index unaffected | — | — | — | — | `TestDuplicateEdges::test_duplicate_edge_rows_deduped` | PASS | |
| CG | Duplicate privilege paths (diamond) | role ACCOUNTADMIN | two paths to SHARED_CHILD | closure counts once | — | — | — | — | `TestMultiHop::test_diamond_shaped_hierarchy_deduped` | PASS | |
| CH | Stable IDs | snowflake_privileged_user / _role | record_id = account_id + stable principal identity | — | — | — | — | — | `TestDeterministicOrdering::test_privileged_records_sorted_by_record_id` | PASS | Reuses message-2's account/user/role identity concept, no second identity scheme |
| CH1 | Memoization never leaks across independent roots | roles ROOT_A, ROOT_B | shared memo dict, disjoint children | ROOT_A's closure excludes ROOT_B's unique child and vice versa | — | — | — | — | `TestNoGraphExplosion::test_memoization_reused_across_roots` | PASS | Shared memoization is a performance optimization, never a correctness leak |

## Safety (CI-CM)

| # | Case | Principal | Direct evidence | Inheritance | Effective privilege | Tier | Completeness | Change severity | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|
| CI | No PAT values in derived records | snowflake_privileged_user / _role / public_exposure | full record dumps inspected | — | — | — | — | — | (safety grep: `grep -RInE "programmatic_access_token\|access_token\|Authorization"` on touched files — see final report) | PASS | Derivation never reads or copies credential fields |
| CJ | No raw integration secret | snowflake_public_exposure / _role | integration ownership tracked by name only, never secret/cert fields | — | — | — | — | — | (safety grep, same as CI; message-4's own secret-exclusion discipline untouched) | PASS | |
| CK | No certificate material | any derived record | — | — | — | — | — | — | (safety grep, same as CI) | PASS | |
| CL | No table data | any derived record | privilege derivation never reads row-level table contents | — | — | — | — | — | (structural: derivation inputs are message 2-4 metadata records only) | PASS | |
| CM | No unbounded privilege paths | role closures | bounded evidence only (`has_accountadmin` etc.), never per-path storage | — | — | — | — | — | `TestNoGraphExplosion::test_large_fan_out_bounded_and_fast`, `test_deep_chain_respects_depth_bound` | PASS | No `snowflake_effective_privilege_per_object_per_user` record type |
| CM1 | Zero additional SQL statements beyond messages 1-4 | account | full `fetch()` call log inspected | — | — | — | — | — | `TestZeroAdditionalSqlCalls::test_no_new_sql_statements_beyond_messages_1_through_4` | PASS | No `PRIVILEGED_USER`/`PRIVILEGED_ROLE`/`PUBLIC_EXPOSURE`/`EFFECTIVE_PRIVILEGE`-named statement ever issued |
| CM2 | Call count stable across identical fetches | account | two independent `fetch()` runs against the same fixture | — | — | — | — | — | `TestZeroAdditionalSqlCalls::test_call_count_unchanged_between_two_identical_fetches` | PASS | Derivation adds zero round trips |

## Scale (CN-CR)

| # | Case | Principal | Direct evidence | Inheritance | Effective privilege | Tier | Completeness | Change severity | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|
| CN | 25,000 users | fixture-scale | 25k user_role_grant rows | — | derivation completes without per-user explosion | — | — | — | `TestScale::test_25k_users_25k_role_grants` (see `test_snowflake_privileged_normalization.py` scale addendum) | PASS | Split across dedicated scale tests, not one giant fixture |
| CO | 5,000 roles | fixture-scale | 5k account_role records | — | closures computed once per role, memoized | — | — | — | `TestScale::test_5k_roles_10k_hierarchy_edges` | PASS | |
| CP | 10,000 hierarchy edges | fixture-scale | 10k role_hierarchy_grant rows | — | bounded, deterministic traversal | — | — | — | `TestScale::test_5k_roles_10k_hierarchy_edges` | PASS | |
| CQ | 100,000 object grants | fixture-scale | 100k object_grant rows | — | role signal aggregation completes | — | — | — | `TestScale::test_100k_object_grants` | PASS | |
| CR | 20,000 future grants | fixture-scale | 20k future object_grant rows | — | PUBLIC/future rollups complete | — | — | — | `TestScale::test_20k_future_grants` | PASS | |

## Major gaps carried into message 6

1. **Current PUBLIC object grants are not collected** — message 2/3 deliberately excluded PUBLIC from per-role `SHOW GRANTS TO ROLE` enumeration (to avoid hierarchy/grant noise from its automatic membership). Only FUTURE grants to PUBLIC are visible (via `SHOW FUTURE GRANTS IN DATABASE`, which is not scoped to a single grantee). `current_public_exposure_count` is `None`, never a fabricated `0`. Closing this gap would require a new `SHOW GRANTS TO ROLE PUBLIC` call per account, which message 5's own zero-additional-SQL-calls constraint forbids this message.
2. **OAuth allowed-role list is not collected** — message 4's security-integration normalizer captures `oauth_client_category`/`oauth_issuer_configured` but not an allowed-role list, so `oauth_allows_critical_role`/`oauth_allows_high_role` cannot be resolved this message; stays unknown rather than guessed.
3. **Storage/external-access integration owner is not collected** — `SHOW STORAGE INTEGRATIONS` / `SHOW EXTERNAL ACCESS INTEGRATIONS` do not return an `OWNER` column in this connector's message-4 collection, so `owns_storage_integration_count`/`owns_external_access_integration_count` are derived from `snowflake_object_grant` OWNERSHIP rows cross-referenced by name (works), but a dedicated "owner role's tier" field on those two integration types specifically is not modeled as a first-class field this message — the same resolution is available via a role's own `snowflake_privileged_role` record.
4. **Direct-to-user privileges** (privileges granted directly to a user, effective only with `USE SECONDARY ROLE = ALL`) are not currently collected by message 2/3's grant enumeration (`SHOW GRANTS OF ROLE`/`SHOW GRANTS TO ROLE` are role-scoped, not user-scoped for object privileges) — documented per task section 20/21 rather than expanding collection scope this message.
5. **Security Findings** (ACCOUNTADMIN assigned, disabled admin retains privilege, MANAGE GRANTS custom role, PUBLIC SELECT on sensitive objects, SCIM/OAuth high-privilege run-as, etc.) are explicitly out of scope — message 5 builds only the evidence; message 6 owns the Finding taxonomy.
