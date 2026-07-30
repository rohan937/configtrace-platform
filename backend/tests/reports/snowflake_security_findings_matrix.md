# Snowflake Security Findings Matrix (Snowflake Message 6 of 8)

Static posture Findings built in this message — "what risky Snowflake
configuration exists right now?", distinct from Change classification
(`risk_rules/snowflake.py`, "what changed?"). All 31 rules are implemented
in `app/services/security_rules/snowflake.py`.

**PUBLIC wording discipline (applies to every PUBLIC-access row below):**
Snowflake's PUBLIC role is an automatic, account-wide pseudo-role — never
"internet-exposed," "publicly accessible from the internet," or "anonymous
access." Every PUBLIC-related Finding says "available to Snowflake users
through the PUBLIC role" / "every Snowflake user in the account."

Columns: **Rule ID / Case**, **Category**, **Resource type**, **Trigger**,
**Severity**, **Confidence**, **Completeness requirement**, **Connector
reachable?**, **Change parity**, **Test**, **Status**, **Notes**.

## Implemented rules (31)

| # | Rule ID | Category | Resource type | Trigger | Severity | Confidence | Completeness requirement | Connector reachable? | Change parity | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | `snowflake_user_accountadmin` | Privileged users | snowflake_privileged_user | has_accountadmin==true, user_type not service-like | critical | high | complete preferred; direct evidence valid even if partial | Yes | Change: has_accountadmin False→True = critical (parity OK) | `TestUserAccountadmin::test_person_accountadmin_fires`, reachability `test_direct_accountadmin_reachable`, parity `test_accountadmin_gained_change_at_least_as_severe` | PASS | |
| 2 | `snowflake_service_user_accountadmin` | Privileged service identities | snowflake_privileged_user | has_accountadmin==true, user_type in (service, service_agent) | critical | high | same as above | Yes | Change: same field, service-scoped | `test_service_accountadmin_fires_service_rule_not_generic` | PASS | Mutually exclusive with rule 1 |
| 3 | `snowflake_user_securityadmin` | Privileged users | snowflake_privileged_user | has_securityadmin==true, ACCOUNTADMIN not already fired | high | high | same | Yes | Change: has_securityadmin False→True = high (parity OK) | `TestUserSecurityadminAndManageGrants::test_securityadmin_fires`, parity `test_securityadmin_gained_change_at_least_as_severe` | PASS | |
| 4 | `snowflake_user_can_manage_grants` | Grant administration & ownership | snowflake_privileged_user | has_manage_grants==true, ACCOUNTADMIN/SECURITYADMIN not already fired | high | high | same | Yes | Change: has_manage_grants False→True = high | `test_manage_grants_fires` | PASS | |
| 5 | `snowflake_user_sysadmin_or_useradmin` | Privileged users | snowflake_privileged_user | has_sysadmin or has_useradmin, tier==medium exactly | medium | medium | same | Yes | Change: medium (tier-gated) | `TestUserSysadminUseradmin::test_sysadmin_medium_tier_fires` | PASS | |
| 6 | `snowflake_disabled_privileged_user` | Identity lifecycle | snowflake_privileged_user | disabled=='disabled', tier in (critical, high) | high | high | same | Yes | Change: message-2 flat Medium overridden by tier context | `TestDisabledPrivilegedUser::test_disabled_critical_fires` | PASS | Wording distinguishes entitlement retained vs active access |
| 7 | `snowflake_legacy_service_user_privileged` | Privileged service identities | snowflake_privileged_user | user_type=='legacy_service', tier in (critical, high) | critical/high (matches tier) | medium | same | Yes | n/a (composite, no dedicated Change field) | `TestLegacyServiceUser::test_legacy_service_high_tier_fires_composite_rule` | PASS | Supersedes rule 8 for same user |
| 8 | `snowflake_legacy_service_user` | Privileged service identities | snowflake_privileged_user | user_type=='legacy_service', tier below high/critical | medium | medium | same | Yes | n/a | `test_legacy_service_ordinary_tier_fires_generic_rule` | PASS | Docs-confirmed deprecated authentication model |
| 9 | `snowflake_custom_role_manage_grants` | Grant administration & ownership | snowflake_privileged_role | role_category=='custom', has_manage_grants==true | high | high | complete | Yes | Change: high (added) | `TestCustomRoleManageGrants::test_manage_grants_alone_fires`, reachability `test_custom_role_manage_grants_reachable`, parity `test_manage_grants_gained_change_at_least_as_severe` | PASS | |
| 10 | `snowflake_custom_role_manage_grants_identity_admin` | Grant administration & ownership | snowflake_privileged_role | has_manage_grants + identity_administration category | critical | high | complete | Yes | n/a (composite) | `test_manage_grants_plus_identity_admin_fires_composite_only` | PASS | Supersedes rule 9 for same role |
| 11 | `snowflake_custom_role_high_privilege` | Privileged/custom roles | snowflake_privileged_role | role_category=='custom', tier=='high', no MANAGE GRANTS | high | medium | complete | Yes | n/a | `TestCustomRoleHighPrivilege::test_high_tier_custom_role_fires` | PASS | Never from name heuristics |
| 12 | `snowflake_role_controls_managed_access_schema` | Grant administration & ownership | snowflake_privileged_role | owns_managed_access_schema_count>0, custom role | high | high | complete | Yes | n/a | `TestRoleOwnershipComposites::test_managed_access_schema_custom_role_fires` | PASS | |
| 13 | `snowflake_role_owns_security_integration_high_privilege` | Security integrations | snowflake_privileged_role | owns_security_integration_count>0 + tier in (high,critical) + custom | high | medium | complete | Yes | n/a | `test_security_integration_ownership_requires_high_tier` | PASS | Composite avoids ordinary-admin noise |
| 14 | `snowflake_role_owns_storage_integration_high_privilege` | Storage/external access integrations | snowflake_privileged_role | owns_storage_integration_count>0 + high/critical + custom | medium | medium | complete | Yes | n/a | `test_storage_integration_ownership_composite` | PASS | |
| 15 | `snowflake_role_owns_external_access_integration_high_privilege` | Storage/external access integrations | snowflake_privileged_role | owns_external_access_integration_count>0 + high/critical + custom | medium | medium | complete | Yes | n/a | `test_external_access_integration_ownership_composite` | PASS | |
| 16 | `snowflake_role_owns_authentication_policy_high_privilege` | Authentication policies | snowflake_privileged_role | owns_authentication_policy_count>0 + high/critical + custom | medium | medium | complete | Yes | n/a | `test_authentication_policy_ownership_composite` | PASS | |
| 17 | `snowflake_role_owns_network_policy_high_privilege` | Network policies | snowflake_privileged_role | owns_network_policy_count>0 + high/critical + custom | medium | medium | complete | Yes | n/a | `test_network_policy_ownership_composite` | PASS | |
| 18 | `snowflake_high_privilege_role_owns_database` | Grant administration & ownership | snowflake_privileged_role | owns_database_count>0 + high/critical + custom | medium | medium | complete | Yes | n/a | `test_database_ownership_composite`, `test_ordinary_database_owner_not_flagged` | PASS | Routine ownership alone never flagged |
| 19 | `snowflake_future_ownership_grant` | Future grants | snowflake_privileged_role | future_ownership_count>0 (any role type) | high | high | complete | Yes | Change: high (added) | `TestFutureOwnershipGrant::test_fires_on_any_role_type`, reachability `test_future_ownership_reachable`, parity `test_future_ownership_grant_change_at_least_as_severe` | PASS | |
| 20 | `snowflake_public_future_ownership_grant` | PUBLIC access | snowflake_public_exposure | future_public_ownership_count>0 | critical | high | partial (structural gap on current-grant side) | Yes | Change: critical (added), parity OK | `TestPublicExposureFindings::test_future_ownership_critical`, reachability `test_future_ownership_to_public_reachable`, parity `test_public_future_ownership_change_at_least_as_severe` | PASS | Most severe PUBLIC case |
| 21 | `snowflake_public_future_write_access` | PUBLIC access | snowflake_public_exposure | future_public_write_count>0 | high | high | partial | Yes | Change: high | `test_future_write_high` | PASS | |
| 22 | `snowflake_public_future_data_access` | PUBLIC access | snowflake_public_exposure | future_public_read_count>0 | high | high | partial | Yes | Change: medium (single grant) — Finding is account-wide rollup, may exceed a single Change's severity | `test_future_read_high` | PASS | Current (non-future) PUBLIC SELECT deferred |
| 23 | `snowflake_public_future_broad_privilege` | PUBLIC access | snowflake_public_exposure | future_total > read+write+ownership (residual) | medium | medium | partial | Yes | Change: medium | `test_broad_residual_medium` | PASS | |
| 24 | `snowflake_network_policy_allows_anywhere` | Network policies | snowflake_network_policy | allows_anywhere_ipv4 or ipv6 == 'true' | high | high | complete (per-record detail) | Yes | Change: high (introduced), parity OK | `TestNetworkPolicyAnywhere::test_ipv4_anywhere_fires`, reachability `test_anywhere_ipv4_reachable`, parity `test_network_anywhere_change_at_least_as_severe` | PASS | |
| 25 | `snowflake_mfa_optional_with_password` | Authentication policies | snowflake_authentication_policy | set_on=='ACCOUNT', mfa_enrollment=='optional', password/all in methods | medium | medium | complete | Yes | Change: medium (weakened) | `TestAuthenticationPolicyMfa::test_optional_with_password_fires_composite` | PASS | |
| 26 | `snowflake_mfa_optional_for_person_auth` | Authentication policies | snowflake_authentication_policy | set_on=='ACCOUNT', mfa_enrollment=='optional' | medium | medium | complete | Yes | Change: medium | `test_optional_without_explicit_password_fires_generic`, reachability `test_optional_mfa_account_wide_reachable` | PASS | Never assumes service-scoped policy affects person users |
| 27 | `snowflake_mfa_password_only_scope` | Authentication policies | snowflake_authentication_policy | set_on=='ACCOUNT', mfa_enrollment=='required_password_only' | medium | medium | complete | Yes | n/a (advisory gap, not a weakening) | `test_required_password_only_fires_scope_gap` | PASS | SSO users exempt — narrower than REQUIRED |
| 28 | `snowflake_scim_critical_privilege_run_as` | Security integrations | snowflake_security_integration | integration_type=='scim', scim_run_as_role_tier=='critical' | critical | medium | complete (resolution requires role inventory) | Yes | n/a | `TestScimRunAsPrivilege::test_critical_run_as_fires` | PASS | Resolved via message-6 SCIM enrichment |
| 29 | `snowflake_scim_high_privilege_run_as` | Security integrations | snowflake_security_integration | integration_type=='scim', scim_run_as_role_tier=='high' | high | medium | complete | Yes | n/a | `test_high_run_as_fires`, reachability `test_scim_high_privilege_run_as_reachable` | PASS | |
| 30 | `snowflake_saml_integration_incomplete_config` | Security integrations | snowflake_security_integration | integration_type=='saml2', enabled=='true', any config field=='false' | medium | medium | complete (per-record detail) | Yes | n/a | `TestSamlIncompleteConfig::test_missing_certificate_fires` | PASS | Disabled SAML never flagged |
| 31 | `snowflake_user_high_risk_future_grant` | Future grants | snowflake_privileged_user | high_risk_future_grant_count>0, no stronger rule already fired | medium | medium | complete | Yes | n/a | `TestUserHighRiskFutureGrant::test_fires_when_no_stronger_rule_present` | PASS | |

## Positive/negative/completeness sub-cases

| # | Rule ID / Case | Category | Resource type | Trigger | Severity | Confidence | Completeness requirement | Connector reachable? | Change parity | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 32 | ACCOUNTADMIN unknown never fires | Privileged users | snowflake_privileged_user | has_accountadmin=None, tier=unknown | — | — | unknown-safe | Yes | — | `TestUserAccountadmin::test_unknown_accountadmin_never_fires` | PASS | Unknown-state discipline |
| 33 | ACCOUNTADMIN false never fires | Privileged users | snowflake_privileged_user | has_accountadmin=False | — | — | — | Yes | — | `test_false_accountadmin_never_fires` | PASS | |
| 34 | Service-agent ACCOUNTADMIN fires service rule | Privileged service identities | snowflake_privileged_user | user_type=='service_agent' | critical | high | — | Yes | — | `test_service_agent_accountadmin_fires_service_rule` | PASS | |
| 35 | SECURITYADMIN suppressed by ACCOUNTADMIN | Privileged users | snowflake_privileged_user | both flags true | — (only rule 1 fires) | — | — | Yes | — | `test_securityadmin_suppressed_when_accountadmin_present` | PASS | Precedence chain |
| 36 | MANAGE GRANTS suppressed by SECURITYADMIN | Grant administration & ownership | snowflake_privileged_user | both flags true | — | — | — | Yes | — | `test_manage_grants_suppressed_when_securityadmin_present` | PASS | Precedence chain |
| 37 | Unknown MANAGE GRANTS never fires | Grant administration & ownership | snowflake_privileged_user | has_manage_grants=None | — | — | unknown-safe | Yes | — | `test_unknown_manage_grants_never_fires` | PASS | |
| 38 | USERADMIN medium tier fires | Privileged users | snowflake_privileged_user | has_useradmin=true, tier=medium | medium | medium | — | Yes | — | `TestUserSysadminUseradmin::test_useradmin_medium_tier_fires` | PASS | |
| 39 | Ordinary user — no Finding | Privileged users | snowflake_privileged_user | no privilege flags | — | — | — | Yes | — | `test_ordinary_user_no_finding` | PASS | |
| 40 | SYSADMIN non-medium tier does not double-fire | Privileged users | snowflake_privileged_user | has_sysadmin=true, tier=high (SECURITYADMIN present) | high (SECURITYADMIN rule only) | — | — | Yes | — | `test_sysadmin_non_medium_tier_does_not_fire_this_rule` | PASS | |
| 41 | Disabled high fires | Identity lifecycle | snowflake_privileged_user | disabled + tier=high | high | high | — | Yes | — | `TestDisabledPrivilegedUser::test_disabled_high_fires` | PASS | |
| 42 | Disabled medium does not fire | Identity lifecycle | snowflake_privileged_user | disabled + tier=medium | — | — | — | Yes | — | `test_disabled_medium_does_not_fire` | PASS | Only critical/high gate |
| 43 | Enabled critical does not fire disabled rule | Identity lifecycle | snowflake_privileged_user | disabled='enabled' | — | — | — | Yes | — | `test_enabled_critical_does_not_fire_disabled_rule` | PASS | |
| 44 | Unknown disabled state never fires | Identity lifecycle | snowflake_privileged_user | disabled='unknown' | — | — | unknown-safe | Yes | — | `test_unknown_disabled_state_never_fires` | PASS | |
| 45 | Ordinary service type never fires legacy rules | Privileged service identities | snowflake_privileged_user | user_type='service' | — | — | — | Yes | — | `TestLegacyServiceUser::test_ordinary_service_type_never_fires_legacy_rules` | PASS | |
| 46 | High-risk future grant suppressed when ACCOUNTADMIN present | Future grants | snowflake_privileged_user | high_risk_future_grant_count>0 + has_accountadmin=true | — (rule 1 only) | — | — | Yes | — | `TestUserHighRiskFutureGrant::test_suppressed_when_accountadmin_present` | PASS | |
| 47 | High-risk future grant zero count never fires | Future grants | snowflake_privileged_user | count=0 | — | — | — | Yes | — | `test_zero_count_never_fires` | PASS | |
| 48 | High-risk future grant None count never fires | Future grants | snowflake_privileged_user | count=None | — | — | unknown-safe | Yes | — | `test_none_count_never_fires` | PASS | |
| 49 | Built-in role category never fires custom-role rules | Privileged/custom roles | snowflake_privileged_role | role_category='securityadmin' + has_manage_grants=true | — | — | — | Yes | — | `TestCustomRoleManageGrants::test_built_in_role_category_never_fires_custom_rules` | PASS | Tier classified from grants, name never assumed |
| 50 | Unknown MANAGE GRANTS on role never fires | Grant administration & ownership | snowflake_privileged_role | has_manage_grants=None | — | — | unknown-safe | Yes | — | `test_unknown_manage_grants_never_fires` (role variant) | PASS | |
| 51 | Medium-tier custom role does not fire high-privilege rule | Privileged/custom roles | snowflake_privileged_role | tier=medium | — | — | — | Yes | — | `TestCustomRoleHighPrivilege::test_medium_tier_does_not_fire` | PASS | |
| 52 | High tier + MANAGE GRANTS fires MANAGE GRANTS rule only | Grant administration & ownership | snowflake_privileged_role | tier=high + has_manage_grants=true | high (rule 9) | — | — | Yes | — | `test_high_tier_with_manage_grants_fires_manage_grants_rule_instead` | PASS | |
| 53 | Managed-access schema count zero never fires | Grant administration & ownership | snowflake_privileged_role | count=0 | — | — | — | Yes | — | `TestRoleOwnershipComposites::test_managed_access_schema_zero_never_fires` | PASS | |
| 54 | Security integration ownership low tier does not fire | Security integrations | snowflake_privileged_role | count>0, tier=medium | — | — | — | Yes | — | `test_security_integration_ownership_requires_high_tier` (low branch) | PASS | |
| 55 | Built-in role never fires ownership composites | Grant administration & ownership | snowflake_privileged_role | role_category='sysadmin', owns_database_count>0 | — | — | — | Yes | — | `test_built_in_role_never_fires_ownership_composites` | PASS | |
| 56 | Future ownership zero never fires | Future grants | snowflake_privileged_role | count=0 | — | — | — | Yes | — | `TestFutureOwnershipGrant::test_zero_never_fires` | PASS | |
| 57 | Future ownership None never fires | Future grants | snowflake_privileged_role | count=None | — | — | unknown-safe | Yes | — | `test_none_never_fires` | PASS | |
| 58 | No future PUBLIC grants — no Findings | PUBLIC access | snowflake_public_exposure | all counts 0 | — | — | — | Yes | — | `TestPublicExposureFindings::test_no_future_public_grants_no_findings` | PASS | |
| 59 | All PUBLIC categories coexist | PUBLIC access | snowflake_public_exposure | ownership+write+read+broad all >0 | critical+high+high+medium (4 findings) | — | — | Yes | — | `test_all_categories_can_coexist` | PASS | Distinct real risks, not duplicate noise |
| 60 | PUBLIC wording never mentions internet | PUBLIC access | snowflake_public_exposure | future_public_ownership_count>0 | — | — | — | Yes | — | `test_wording_never_mentions_internet` | PASS | MANDATORY guard |
| 61 | IPv6 anywhere fires | Network policies | snowflake_network_policy | allows_anywhere_ipv6=='true' | high | high | — | Yes | — | `TestNetworkPolicyAnywhere::test_ipv6_anywhere_fires` | PASS | |
| 62 | Restricted policy — no Finding | Network policies | snowflake_network_policy | both anywhere flags false | — | — | — | Yes | — | `test_restricted_policy_no_finding`, reachability `test_restricted_policy_not_reachable` | PASS | |
| 63 | Unknown broad-access state never fires | Network policies | snowflake_network_policy | flags='unknown' | — | — | unknown-safe | Yes | — | `test_unknown_broad_access_never_fires` | PASS | |
| 64 | MFA required — no Finding | Authentication policies | snowflake_authentication_policy | mfa_enrollment='required' | — | — | — | Yes | — | `TestAuthenticationPolicyMfa::test_required_no_finding`, reachability `test_required_not_reachable` | PASS | |
| 65 | Unknown MFA never fires | Authentication policies | snowflake_authentication_policy | mfa_enrollment='unknown' | — | — | unknown-safe | Yes | — | `test_unknown_mfa_never_fires` | PASS | |
| 66 | Service-scoped policy never treated as person MFA weakness | Authentication policies | snowflake_authentication_policy | set_on='SVC_ETL' (not ACCOUNT) | — | — | — | Yes | — | `test_service_scoped_policy_never_treated_as_person_mfa_weakness` | PASS | Section 31 requirement |
| 67 | Ordinary SCIM run-as — no Finding | Security integrations | snowflake_security_integration | scim_run_as_role_tier='medium' | — | — | — | Yes | — | `TestScimRunAsPrivilege::test_ordinary_run_as_no_finding` | PASS | |
| 68 | Unresolved SCIM role — no Finding | Security integrations | snowflake_security_integration | scim_run_as_role_tier='unknown' | — | — | unknown-safe | Yes | — | `test_unresolved_role_no_finding`, reachability `test_scim_unresolvable_role_not_reachable` | PASS | Unresolvable role name never guessed |
| 69 | Non-SCIM integration never fires SCIM rules | Security integrations | snowflake_security_integration | integration_type='oauth_snowflake' | — | — | — | Yes | — | `test_non_scim_integration_never_fires_scim_rules` | PASS | |
| 70 | Complete SAML config — no Finding | Security integrations | snowflake_security_integration | all config fields='true' | — | — | — | Yes | — | `TestSamlIncompleteConfig::test_complete_config_no_finding` | PASS | |
| 71 | Disabled SAML never fires | Security integrations | snowflake_security_integration | enabled='false' | — | — | — | Yes | — | `test_disabled_saml_never_fires` | PASS | May be intentionally unused |
| 72 | Unrecognized record type returns empty | — | snowflake_database | n/a | — | — | — | Yes | — | `TestUnknownRecordType::test_unrecognized_record_type_returns_empty` | PASS | Fails safe, no cross-provider fallthrough |
| 73 | Non-dict input returns empty | — | — | n/a | — | — | — | Yes | — | `test_non_dict_returns_empty` | PASS | |
| 74 | Inherited SECURITYADMIN via custom parent role | Privileged users | snowflake_privileged_user | custom role has SECURITYADMIN as hierarchy child | high | high | complete | Yes | — | reachability `test_inherited_securityadmin_reachable` | PASS | Confirms downward-closure inheritance path |
| 75 | Ordinary user not derivable end-to-end | Privileged users | snowflake_privileged_user | direct role=ANALYST only | — | — | — | Yes | — | reachability `test_ordinary_user_not_reachable` | PASS | |
| 76 | Public exposure with no future grants — no Findings end-to-end | PUBLIC access | snowflake_public_exposure | empty object_grant_records | — | — | — | Yes | — | reachability `test_no_future_public_grants_not_reachable` | PASS | |

## Parity / architecture confirmations

| # | Case | Category | Resource type | Trigger | Severity | Confidence | Completeness requirement | Connector reachable? | Change parity | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 77 | evaluate() callable | Architecture | — | module import | — | — | — | — | — | `TestModuleDispatchReachable::test_evaluate_is_callable` | PASS | |
| 78 | Dispatched in evaluator | Architecture | — | `_PROVIDER_RULES["snowflake"]` | — | — | — | — | — | `test_snowflake_dispatched_in_evaluator` | PASS | |
| 79 | Module has ≥30 rule keys | Architecture | — | count check | — | — | — | — | — | `test_module_has_at_least_thirty_rule_keys` | PASS | |
| 80 | No duplicate rule-key constants | Architecture | — | uniqueness check | — | — | — | — | — | `test_no_duplicate_rule_key_constants` | PASS | |
| 81 | Module keys subset of registry | Registry parity | — | set comparison | — | — | — | — | — | `TestRegistryParity::test_module_keys_subset_of_registry` | PASS | |
| 82 | Registry has no extra snowflake keys | Registry parity | — | set comparison | — | — | — | — | — | `test_registry_has_no_extra_snowflake_keys` | PASS | |
| 83 | Every registered rule has confidence | Confidence parity | — | set comparison | — | — | — | — | — | `TestConfidenceParity::test_every_registered_snowflake_rule_has_confidence` | PASS | |
| 84 | No extra confidence entries | Confidence parity | — | set comparison | — | — | — | — | — | `test_no_extra_confidence_entries` | PASS | |
| 85 | Confidence values high/medium only | Confidence parity | — | value check | — | — | — | — | — | `test_confidence_values_are_high_or_medium` | PASS | No low-confidence rules |
| 86 | Every confidence entry has a guard reason | Confidence parity | — | non-empty string check | — | — | — | — | — | `test_every_confidence_entry_has_a_guard_reason` | PASS | |
| 87 | Every registered rule in pack | Pack parity | — | set comparison | — | — | — | — | — | `TestPackParity::test_every_registered_snowflake_rule_in_pack` | PASS | |
| 88 | No extra pack entries | Pack parity | — | set comparison | — | — | — | — | — | `test_no_extra_pack_entries` | PASS | |
| 89 | Pack provider is snowflake for all entries | Pack parity | — | field check | — | — | — | — | — | `test_pack_provider_is_snowflake_for_all_entries` | PASS | |
| 90 | Pack severity values valid | Pack parity | — | enum check | — | — | — | — | — | `test_pack_severity_values_are_valid` | PASS | |
| 91 | Pack manifest self-check passes | Pack parity | — | `_RULE_META == KNOWN_RULE_KEYS` | — | — | — | — | — | `test_pack_manifest_self_check_passes` | PASS | Import-time assertion |
| 92 | Pack summary includes snowflake | Pack parity | — | `pack_summary()` | — | — | — | — | — | `test_pack_summary_includes_snowflake` | PASS | |
| 93 | Pack categories cover expected buckets | Pack parity | — | category set check | — | — | — | — | — | `test_pack_categories_cover_expected_buckets` | PASS | |
| 94 | Snowflake in PROVIDERS list | Coverage parity | — | membership check | — | — | — | — | — | `TestCoverageParity::test_snowflake_in_providers_list` | PASS | Since message 1 |
| 95 | Snowflake in PROVIDER_SURFACES | Coverage parity | — | membership check | — | — | — | — | — | `test_snowflake_in_provider_surfaces` | PASS | Added this message |
| 96 | Every registered rule has record types | Coverage parity | — | set comparison | — | — | — | — | — | `test_every_registered_snowflake_rule_has_record_types` | PASS | |
| 97 | No extra coverage entries | Coverage parity | — | set comparison | — | — | — | — | — | `test_no_extra_coverage_entries` | PASS | |
| 98 | provider_of() resolves correctly | Coverage parity | — | function check | — | — | — | — | — | `test_provider_of_resolves_correctly` | PASS | |
| 99 | Expected record types non-empty | Coverage parity | — | function check | — | — | — | — | — | `test_expected_record_types_non_empty` | PASS | |
| 100 | Frontend catalog file exists | Frontend parity | — | file existence | — | — | — | — | — | `TestFrontendParity::test_frontend_catalog_file_exists` | PASS | |
| 101 | Every registered rule in frontend catalog | Frontend parity | — | set comparison | — | — | — | — | — | `test_every_registered_snowflake_rule_in_frontend_catalog` | PASS | |
| 102 | No frontend-only snowflake rules | Frontend parity | — | set comparison | — | — | — | — | — | `test_no_frontend_only_snowflake_rules` | PASS | |
| 103 | Frontend entries have provider snowflake | Frontend parity | — | text pattern check | — | — | — | — | — | `test_frontend_entries_have_provider_snowflake` | PASS | |
| 104 | Frontend severity matches backend pack | Frontend parity | — | severity comparison per rule | — | — | — | — | — | `test_frontend_severity_matches_backend_pack` | PASS | |
| 105 | Frontend PUBLIC copy never claims internet exposure | Frontend parity | — | forbidden-phrase check | — | — | — | — | — | `test_no_frontend_wording_claims_internet_exposure` | PASS | MANDATORY guard |
| 106 | All layers have identical key sets | Cross-layer parity | — | module/registry/confidence/pack/coverage/frontend | — | — | — | — | — | `TestFullCrossLayerParity::test_all_layers_have_identical_snowflake_key_sets` | PASS | |
| 107 | Expected rule count pinned at 31 | Cross-layer parity | — | count assertion | — | — | — | — | — | `test_expected_rule_count_is_31` | PASS | Deliberate update required if taxonomy changes |
| 108 | ACCOUNTADMIN Change ≥ Finding severity | Finding-vs-Change | snowflake_privileged_user | has_accountadmin False→True | critical vs critical | — | — | — | Change severity ≥ Finding severity | `TestFindingVsChangeSeverityParity::test_accountadmin_gained_change_at_least_as_severe` | PASS | |
| 109 | SECURITYADMIN Change ≥ Finding severity | Finding-vs-Change | snowflake_privileged_user | has_securityadmin False→True | high vs high | — | — | — | same | `test_securityadmin_gained_change_at_least_as_severe` | PASS | |
| 110 | MANAGE GRANTS Change ≥ Finding severity | Finding-vs-Change | snowflake_privileged_role | has_manage_grants False→True | high vs high | — | — | — | same | `test_manage_grants_gained_change_at_least_as_severe` | PASS | |
| 111 | PUBLIC future ownership Change ≥ Finding severity | Finding-vs-Change | snowflake_public_exposure | count 0→1 | critical vs critical | — | — | — | same | `test_public_future_ownership_change_at_least_as_severe` | PASS | |
| 112 | Network anywhere Change ≥ Finding severity | Finding-vs-Change | snowflake_network_policy | flag false→true | high vs high | — | — | — | same | `test_network_anywhere_change_at_least_as_severe` | PASS | |
| 113 | Future ownership grant Change ≥ Finding severity | Finding-vs-Change | snowflake_privileged_role | count 0→1 | high vs high | — | — | — | same | `test_future_ownership_grant_change_at_least_as_severe` | PASS | |

## Deliberately rejected / deferred candidates

| # | Candidate | Category | Reason | Test | Status | Notes |
|---|---|---|---|---|---|---|
| 114 | PUBLIC has current (non-future) data-read access | PUBLIC access | Message 2/3 never collected current PUBLIC object grants; implementing from absent data would fabricate evidence | — | DEFERRED | Documented in module docstring + frontend DEFERRED_RULES |
| 115 | OAuth integration allows critical/high role | Security integrations | Message 4 does not capture an OAuth allowed-role list | — | DEFERRED | |
| 116 | Sensitive privilege granted with grant option | Grant administration & ownership | grant_option lives on raw object_grant record with no role-tier context; unsafe cross-record join | — | DEFERRED | Same reasoning as Okta's own deferred cross-record candidates |
| 117 | External access integration broad network + privileged context | Storage/external access integrations | Only a network-rule count is modeled, never resolved CIDR breadth | — | DEFERRED | |
| 118 | Storage integration can access many/all buckets | Storage/external access integrations | Only a location count is modeled, never resolved location scope | — | DEFERRED | |
| 119 | Network/authentication policy absence, no SSO configured | Network policies / Authentication policies | Absence-based rules require family-completeness lookup unavailable to per-record evaluator | — | DEFERRED | |
| 120 | Direct-to-user object privilege | Grant administration & ownership | Direct-to-user object grants are not currently collected | — | DEFERRED | Documented gap since message 5 |
| 121 | Share exists or was broadened | Sharing / data-access posture | Secure data sharing is legitimate; truncated consumer-count evidence insufficient for a static Finding | — | DEFERRED | |
| 122 | Every ACCOUNTADMIN role assignment as bare inventory | Privileged users | Would be pure inventory noise; only the derived-privilege rules (1-2) fire | — | DEFERRED | |
| 123 | SCIM role can manage grants (separate from tier-based rules) | Security integrations | Message 5's tier derivation guarantees has_manage_grants=True always yields ≥High tier — a separate rule would never fire on new evidence | — | DEFERRED | MANAGE GRANTS surfaced as evidence on tier-based SCIM rules instead |
| 124 | Every SYSADMIN assignment as Critical | Privileged users | SYSADMIN is infrastructure administration, distinct from grant/security administration; not automatically Critical | — | DEFERRED | Rule 5 covers it at Medium, gated to tier==medium exactly |
| 125 | Every service user flagged as risky | Privileged service identities | Service-user type alone is not risky; only privilege-tier combinations are Findings | — | DEFERRED | Section 7/25 of task guidance |
| 126 | Every SAML integration existence/disabled state | Security integrations | Legitimate, often intentionally unused; only incomplete-config-while-enabled is flagged | — | DEFERRED | |
| 127 | Every OAuth integration existence | Security integrations | Legitimate functionality; allowed-role metadata gap prevents a deeper rule | — | DEFERRED | |
| 128 | Every SCIM integration existence | Security integrations | Legitimate provisioning functionality; only run-as privilege tier is a Finding | — | DEFERRED | |
| 129 | Every storage integration existence | Storage/external access integrations | Legitimate functionality; no Finding on mere existence | — | DEFERRED | |
| 130 | Every external-access integration existence/enabled | Storage/external access integrations | Legitimate functionality; existence/enabled alone never flagged | — | DEFERRED | |

## Severity / confidence / category distribution

| # | Metric | Value | Notes |
|---|---|---|---|
| 131 | Critical-severity rule count | 5 | ACCOUNTADMIN (person+service), MANAGE GRANTS+identity-admin composite, PUBLIC future OWNERSHIP, SCIM critical run-as |
| 132 | High-severity rule count | 13 | SECURITYADMIN, MANAGE GRANTS (user+role), managed-access schema, security-integration ownership, future ownership (role+PUBLIC write/read), disabled privileged user, legacy+privileged composite, network anywhere, SCIM high run-as, custom-role high-privilege |
| 133 | Medium-severity rule count | 13 | SYSADMIN/USERADMIN, legacy service, storage/external-access/auth-policy/network-policy ownership composites, database ownership composite, PUBLIC broad residual, MFA rules (3), SAML incomplete config, high-risk future grant |
| 134 | Low-severity rule count | 0 | Not artificially populated per task guidance |
| 135 | High-confidence rule count | 13 | Direct exact-field triggers (booleans, exact tier/CIDR/mode matches) |
| 136 | Medium-confidence rule count | 18 | Composite/derived/multi-step-resolution triggers |
| 137 | Low-confidence rule count | 0 | None implemented; architecture reserves Low for future deferred candidates only |
| 138 | Category: Privileged users | 3 rules | |
| 139 | Category: Privileged service identities | 3 rules | |
| 140 | Category: Grant administration & ownership | 5 rules | |
| 141 | Category: Identity lifecycle | 1 rule | |
| 142 | Category: Privileged/custom roles | 1 rule | |
| 143 | Category: Security integrations | 4 rules | |
| 144 | Category: Storage/external access integrations | 2 rules | |
| 145 | Category: Authentication policies | 4 rules | |
| 146 | Category: Network policies | 2 rules | |
| 147 | Category: Future grants | 2 rules | |
| 148 | Category: PUBLIC access | 4 rules | |

## Safety

| # | Case | Category | Check | Status | Notes |
|---|---|---|---|---|---|
| 149 | No PAT/token values in Finding evidence | Safety | Manual code review of all `evidence={...}` dicts in security_rules/snowflake.py | PASS | Only safe labels/counts/booleans/tiers |
| 150 | No certificate material in evidence | Safety | Manual code review | PASS | Only boolean *_configured flags, never cert bytes |
| 151 | No raw IP/CIDR values in evidence | Safety | Manual code review | PASS | Only the boolean allows_anywhere_* check result |
| 152 | No SQL/table data in evidence | Safety | Manual code review | PASS | Evidence sourced only from message 1-5 metadata records |
| 153 | Safety grep: no PAT/secret patterns in touched files | Safety | `grep -RInE "programmatic_access_token\|password\|private_key\|client_secret\|...\|Authorization\|secret_value"` | PASS | See final report |
| 154 | Safety grep: no sensationalist/breach wording | Safety | `grep -RInE "breached\|compromised\|attacker\|exfiltrat\|...\|internet exposed\|anonymous access"` | PASS | See final report |
| 155 | Safety grep: no SQL mutation verbs in connector | Safety | `grep -RInE "\b(CREATE\|ALTER\|DROP\|GRANT\|REVOKE\|...)\b"` on snowflake.py/snowflake_schema.py | PASS | Only documentation/category-map strings match |
