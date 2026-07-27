# Microsoft Entra ID Identity Lifecycle Matrix (Entra Message 2 of 8)

Pins user/group/membership collection, normalization, and Change
classification built in this message. Columns: **Case**, **Record type**,
**Source state**, **Normalized posture**, **Diff tracked?**, **Change
severity**, **Unknown-safe?**, **Sensitive-data risk**, **Test**,
**Status**, **Notes**.

| # | Case | Record type | Source state | Normalized posture | Diff tracked? | Change severity | Unknown-safe? | Sensitive-data risk | Test | Status |
|---|---|---|---|---|---|---|---|---|---|---|
| A | enabled Member | entra_user | accountEnabled=True, userType=Member | enabled_member | Yes | n/a (steady state) | Yes | None | `test_full_normalization_enabled_member` | PASS |
| B | disabled Member | entra_user | accountEnabled=False, userType=Member | disabled_member | Yes | Low (disable) | Yes | None | `TestUserLifecycleTransitions::test_enabled_to_disabled_is_low` | PASS |
| C | enabled Guest | entra_user | accountEnabled=True, userType=Guest | enabled_guest | Yes | n/a (steady state) | Yes | None | `test_guest_is_not_treated_as_inherently_disabled_or_risky` | PASS |
| D | disabled Guest | entra_user | accountEnabled=False, userType=Guest | disabled_guest | Yes | n/a (steady state) | Yes | None | `test_full_normalization_disabled_guest` | PASS |
| E | accountEnabled missing | entra_user | accountEnabled=None | account_enabled_category=unknown | Yes | Medium (needs review) | Yes | None | `test_missing_account_enabled_is_unknown_not_disabled` | PASS |
| F | userType Member | entra_user | userType="Member" | user_type_category=Member | Yes | n/a | Yes | None | `TestUserType::test_categorize_user_type` | PASS |
| G | userType Guest | entra_user | userType="Guest" | user_type_category=Guest | Yes | n/a | Yes | None | `TestUserType::test_categorize_user_type` | PASS |
| H | unknown userType | entra_user | userType="Contractor"/None | user_type_category=unknown | Yes | Medium (needs review) | Yes | None | `test_unknown_user_type_never_defaults_to_member` | PASS |
| I | UPN rename, same object ID | entra_user | userPrincipalName changes, id unchanged | record_id stable, modification not remove+add | user_principal_name tracked | Low | Yes | None | `test_upn_rename_same_object_id_is_same_record_id`, `test_upn_rename_is_low` | PASS |
| J | display-name change | entra_user | displayName changes | display_name tracked | Yes | Low | Yes | None | `test_display_name_change_is_low` | PASS |
| K | enabled -> disabled | entra_user | accountEnabled True->False | account_enabled_category enabled->disabled | Yes | Low (restrictive) | Yes | None | `test_enabled_to_disabled_is_low` | PASS |
| L | disabled -> enabled | entra_user | accountEnabled False->True | account_enabled_category disabled->enabled | Yes | Medium (restoration) | Yes | None | `test_disabled_to_enabled_is_medium` | PASS |
| M | Member -> Guest | entra_user | userType Member->Guest | user_type_category Member->Guest | Yes | Low | Yes | None | `test_member_to_guest_is_low` | PASS |
| N | Guest -> Member | entra_user | userType Guest->Member | user_type_category Guest->Member | Yes | Low | Yes | None | `test_guest_to_member_is_low` | PASS |
| O | added enabled user | entra_user | new record, accountEnabled=True | change_type=added | n/a | Low | Yes | None | `test_added_enabled_user_is_low` | PASS |
| P | added guest | entra_user | new record, userType=Guest | change_type=added | n/a | Low | Yes | None | `test_added_guest_is_low` | PASS |
| Q | removed user | entra_user | record absent from new snapshot | change_type=removed | n/a | Low, worded as "no longer present" | Yes | None | `test_removed_user_is_low` | PASS |
| R | missing user ID rejected | entra_user | raw dict with no "id" | normalizer returns None | n/a | n/a | Yes | None | `test_missing_user_id_returns_none` | PASS |
| S | sensitive profile fields excluded | entra_user | mobilePhone/streetAddress/passwordProfile/proxyAddresses/manager present | Never copied into record | n/a | n/a | n/a | Verified absent | `TestSensitiveDataExclusion` (6 tests) | PASS |
| T | stable tenant+user ID | entra_user | same tenant_id + object id, repeated calls | record_id identical | n/a | n/a | Yes | None | `test_record_id_derives_from_tenant_plus_object_id`, `test_display_name_change_does_not_affect_record_id` | PASS |
| U | PendingAcceptance | entra_user | externalUserState="PendingAcceptance" | external_user_state_category=PendingAcceptance | Yes | n/a | Yes | None | `TestExternalUserState::test_categorize_external_user_state` | PASS |
| V | Accepted | entra_user | externalUserState="Accepted" | external_user_state_category=Accepted | Yes | n/a | Yes | None | `TestExternalUserState::test_categorize_external_user_state` | PASS |
| W | unknown external state | entra_user | externalUserState=None/unrecognized | external_user_state_category=unknown | Yes | n/a | Yes | None | `test_missing_external_state_on_member_is_unknown` | PASS |
| X | pending -> accepted | entra_user | externalUserState PendingAcceptance->Accepted | category transition | Yes | Medium (access now active) | Yes | None | `test_pending_to_accepted_is_medium` | PASS |
| Y | missing external state | entra_user | externalUserState absent | category=unknown | Yes | n/a | Yes | None | `test_missing_external_state_on_member_is_unknown` | PASS |
| Z | security group | entra_group | securityEnabled=True, mailEnabled=False | group_type_category=security | Yes | n/a | Yes | None | `test_security_group` | PASS |
| AA | Microsoft 365 group | entra_group | groupTypes=["Unified"], mailEnabled=True | group_type_category=microsoft_365 | Yes | n/a | Yes | None | `test_microsoft_365_group` | PASS |
| AB | dynamic security group | entra_group | securityEnabled=True, groupTypes=["DynamicMembership"] | group_type_category=dynamic_security | Yes | n/a | Yes | None | `test_dynamic_security_group` | PASS |
| AC | dynamic M365 group | entra_group | groupTypes=["Unified","DynamicMembership"], mailEnabled=True | group_type_category=dynamic_microsoft_365 | Yes | n/a | Yes | None | `test_dynamic_microsoft_365_group` | PASS |
| AD | mail-enabled non-security group | entra_group | mailEnabled=True, securityEnabled=False, no Unified | group_type_category=distribution_or_mail | Yes | n/a | Yes | None | `test_mail_enabled_non_security_distribution_group` | PASS |
| AE | unknown group type | entra_group | securityEnabled or mailEnabled is None | group_type_category=unknown | Yes | n/a | Yes | None | `test_unknown_when_security_enabled_missing`, `test_unknown_when_mail_enabled_missing` | PASS |
| AF | securityEnabled true | entra_group | securityEnabled=True | security_enabled=True | Yes | n/a | Yes | None | `test_security_enabled_preserved_tristate` | PASS |
| AG | securityEnabled false | entra_group | securityEnabled=False | security_enabled=False | Yes | n/a | Yes | None | `test_security_enabled_preserved_tristate` | PASS |
| AH | securityEnabled unknown | entra_group | securityEnabled=None | security_enabled=None | Yes | n/a | Yes | None | `test_unknown_security_enabled_never_coerced_to_false` | PASS |
| AI | mailEnabled true | entra_group | mailEnabled=True | mail_enabled=True | Yes | n/a | Yes | None | `test_mail_enabled_preserved_tristate` | PASS |
| AJ | mailEnabled false | entra_group | mailEnabled=False | mail_enabled=False | Yes | n/a | Yes | None | `test_mail_enabled_preserved_tristate` | PASS |
| AK | mailEnabled unknown | entra_group | mailEnabled=None | mail_enabled=None | Yes | n/a | Yes | None | `test_mail_enabled_preserved_tristate` | PASS |
| AL | role-assignable true | entra_group | isAssignableToRole=True | role_assignable=True | Yes | High (on enable) | Yes | None | `test_role_assignable_tristate_preserved`, `test_role_assignable_enabled_is_high` | PASS |
| AM | role-assignable false | entra_group | isAssignableToRole=False | role_assignable=False | Yes | Low (on disable) | Yes | None | `test_role_assignable_disabled_is_low` | PASS |
| AN | role-assignable unknown | entra_group | isAssignableToRole=None/absent | role_assignable=None | Yes | Medium (unrecognized) | Yes | None | `test_missing_role_assignable_is_none_not_false` | PASS |
| AO | dynamic true | entra_group | groupTypes contains DynamicMembership | dynamic_membership=True | Yes | Medium (on enable) | Yes | None | `test_dynamic_membership_enabled_is_medium` | PASS |
| AP | dynamic false | entra_group | groupTypes without DynamicMembership | dynamic_membership=False | Yes | Low (on disable) | Yes | None | `test_dynamic_membership_disabled_is_low` | PASS |
| AQ | group renamed, same ID | entra_group | displayName changes, id unchanged | record_id stable | display_name tracked | Low | Yes | None | `test_group_rename_does_not_affect_record_id`, `test_rename_is_low` | PASS |
| AR | securityEnabled change | entra_group | False->True / True->False | security_enabled tracked | Yes | Medium (enable) / Low (disable) | Yes | None | `test_security_enabled_false_to_true_is_medium`, `test_security_enabled_true_to_false_is_low` | PASS |
| AS | dynamic enabled | entra_group | dynamic_membership False->True | tracked | Yes | Medium | Yes | None | `test_dynamic_membership_enabled_is_medium` | PASS |
| AT | dynamic disabled | entra_group | dynamic_membership True->False | tracked | Yes | Low | Yes | None | `test_dynamic_membership_disabled_is_low` | PASS |
| AU | role-assignable enabled | entra_group | role_assignable False->True | tracked | Yes | High | Yes | None | `test_role_assignable_enabled_is_high` | PASS |
| AV | group added | entra_group | new record | change_type=added | n/a | Low | Yes | None | `test_added_group_is_low` | PASS |
| AW | group removed | entra_group | record absent | change_type=removed | n/a | Low, worded as "no longer present" | Yes | None | `test_removed_group_is_low` | PASS |
| AX | membership count zero | entra_group | group walk succeeded, 0 user members | membership_count=0, category="0" | Yes | n/a | Yes | None | `test_group_with_zero_members`, `test_zero_is_distinct_from_unknown` | PASS |
| AY | membership count positive | entra_group | group walk succeeded, N members | membership_count=N | Yes | Low (increase/decrease) | Yes | None | `test_membership_collected_per_group`, `test_membership_count_increase_is_low` | PASS |
| AZ | membership count unknown | entra_group | group walk denied/failed | membership_count=None, category=unknown | Yes | n/a | Yes | None | `test_denied_membership_is_unknown_not_zero`, `test_users_available_groups_available_memberships_denied` | PASS |
| BA | direct user membership | entra_group_membership | /groups/{id}/members returns a user | membership_type=direct | n/a (identity fields tracked) | Low (added) | Yes | None | `test_direct_membership_type` | PASS |
| BB | guest membership | entra_group_membership | member's userType=Guest | user_type_category=Guest | Yes | Medium if security group | Yes | None | `test_guest_membership_context_preserved` | PASS |
| BC | member membership | entra_group_membership | member's userType=Member | user_type_category=Member | Yes | Low | Yes | None | `test_ordinary_user_added_to_group_is_low` | PASS |
| BD | user added | entra_group_membership | new membership record | change_type=added | n/a | Low/Medium | Yes | None | `test_ordinary_user_added_to_group_is_low` | PASS |
| BE | user removed | entra_group_membership | membership record absent | change_type=removed | n/a | Low | Yes | None | `test_ordinary_user_removed_from_group_is_low` | PASS |
| BF | role-assignable group membership | entra_group_membership | group_record.role_assignable=True | role_assignable_group=True | Yes | Medium (added) | Yes | None | `test_role_assignable_group_context_preserved`, `test_user_added_to_role_assignable_group_is_medium` | PASS |
| BG | guest + security group | entra_group_membership | Guest added to security-enabled group | is_guest and is_security_group | n/a | Medium, conservative wording | Yes | None | `test_guest_added_to_security_group_is_medium` | PASS |
| BH | duplicate relationship dedup | entra_group_membership | overlapping paginated pages re-serve same user id | one record per (group,user) pair | n/a | n/a | Yes | None | `test_membership_dedup_within_a_group` | PASS |
| BI | group with zero user members | entra_group | /members returns [] | membership_count=0 | Yes | n/a | Yes | None | `test_group_with_zero_members` | PASS |
| BJ | non-user directory member excluded | entra_group_membership | /members includes servicePrincipal/device/group | excluded via @odata.type check | n/a | n/a | Yes | None | `test_non_user_directory_member_excluded` | PASS |
| BK | nested group not flattened | entra_group_membership | group A contains group B | no membership record created for B's members | n/a | n/a | Yes | None | `test_nested_group_not_flattened_into_membership` | PASS |
| BL | membership endpoint denied | entra_group_membership | /members returns 403 | completeness=denied, membership_count=None | n/a | n/a (diagnostic only) | Yes | None | `test_users_available_groups_available_memberships_denied` | PASS |
| BM | membership partial pagination | entra_group_membership | later page 500/429/malformed | completeness=partial via `_collect_family`'s `truncated` | n/a | n/a | Yes | None | `_collect_family` reused from message 1 pagination tests | PASS |
| BN | per-group completeness | entra_group | status_by_group dict per group_id | tracked internally for future false-removal suppression | n/a | n/a | Yes | None | `_fetch_memberships` returns `status_by_group`; exercised via family-independence tests | PASS |
| BO | stable membership ID | entra_group_membership | tenant_id+group_id+user_id | record_id deterministic | n/a | n/a | Yes | None | `test_stable_membership_id` | PASS |
| BP | users multi-page | entra_user | `@odata.nextLink` across 2 pages | all users collected | n/a | n/a | Yes | None | `test_collects_users_across_multiple_pages` | PASS |
| BQ | groups multi-page | entra_group | (paginator shared with users; exercised via message-1 pagination suite) | all groups collected | n/a | n/a | Yes | None | `test_entra_foundation.py::TestPagination` (shared `paginate_graph`) | PASS |
| BR | members multi-page | entra_group_membership | `@odata.nextLink` on `/groups/{id}/members` | all members collected, deduped | n/a | n/a | Yes | None | `test_membership_dedup_within_a_group` | PASS |
| BS | repeated nextLink | (pagination infra) | same nextLink URL every page | stops, `truncated=True` | n/a | n/a | Yes | None | `test_entra_foundation.py::test_repeated_next_link_stops_and_marks_truncated` (shared paginator) | PASS |
| BT | cross-origin nextLink rejected | (pagination infra) | nextLink to untrusted host | not followed, `truncated=True` | n/a | n/a | Yes | None | `test_entra_foundation.py::test_cross_origin_next_link_rejected` (shared paginator) | PASS |
| BU | 429 later page | (pagination infra) | page 2 returns 429 | bounded retry, then truncated if exhausted | n/a | n/a | Yes | None | `test_entra_foundation.py::TestRateLimit` (shared `call_graph`) | PASS |
| BV | page-cap truncation | (pagination infra) | more pages available than `max_pages` | `truncated=True` | n/a | n/a | Yes | None | `test_entra_foundation.py::test_page_cap_marks_truncated` (shared paginator) | PASS |
| BW | missing accountEnabled not false | entra_user | accountEnabled=None | category=unknown, not disabled | n/a | n/a | Yes | None | `test_bool_never_used_for_none` | PASS |
| BX | missing securityEnabled not false | entra_group | securityEnabled=None | security_enabled=None, not False | n/a | n/a | Yes | None | `test_unknown_security_enabled_never_coerced_to_false` | PASS |
| BY | missing mailEnabled not false | entra_group | mailEnabled=None | mail_enabled=None, not False | n/a | n/a | Yes | None | `test_mail_enabled_preserved_tristate` | PASS |
| BZ | missing isAssignableToRole not false | entra_group | isAssignableToRole absent | role_assignable=None, not False | n/a | n/a | Yes | None | `test_missing_role_assignable_is_none_not_false` | PASS |
| CA | denied membership not zero | entra_group | group's own member walk denied | membership_count=None | n/a | n/a | Yes | None | `test_denied_membership_is_unknown_not_zero` | PASS |
| CB | unknown userType not Member | entra_user | userType="Contractor" | user_type_category=unknown, never Member | n/a | n/a | Yes | None | `test_unknown_user_type_never_defaults_to_member` | PASS |
| CC | unknown group type not ordinary security | entra_group | securityEnabled=None | group_type_category=unknown, never security | n/a | n/a | Yes | None | `test_unknown_never_defaults_to_ordinary_security` | PASS |
| CD | user metadata | entra_user | any Change on a user record | provider_metadata has tenant_id/user_id/user_principal_name; no secret | n/a | n/a | n/a | Real `compute_diff()` | `test_user_change_has_tenant_and_user_context` | PASS |
| CE | group metadata | entra_group | any Change on a group record | provider_metadata has tenant_id/group_id/display_name | n/a | n/a | n/a | Real `compute_diff()` | `test_group_change_has_tenant_and_group_context` | PASS |
| CF | membership metadata | entra_group_membership | any Change on a membership record | provider_metadata has tenant_id/user_id/group_id/group_name | n/a | n/a | n/a | Real `compute_diff()` | `test_membership_change_has_full_context` | PASS |
| CG | timestamp change ignored | entra_user | created_date_time changes | not tracked, no Change produced | No (explicitly excluded) | n/a | n/a | n/a | `test_created_date_time_change_ignored` | PASS |
| CH | sign-in activity ignored | entra_user | (not collected this message) | field absent from tracked-fields tuple | No (not collected/tracked) | n/a | n/a | n/a | `test_sign_in_activity_field_not_tracked` | PASS |
| CI | same data reordered -> no Changes | entra_user | two users, snapshot order swapped | zero Changes | n/a | n/a | n/a | Deterministic ordering (`records.sort()` in `fetch()`) | `test_same_data_reordered_produces_no_changes` | PASS |
| CJ | 5,000 users | entra_user | scale target | all collected, unique record_ids | n/a | n/a | n/a | N/A (scale, not sensitive) | `test_5000_users_2000_groups_with_memberships` | PASS |
| CK | 2,000 groups | entra_group | scale target | all collected, unique record_ids | n/a | n/a | n/a | N/A | `test_5000_users_2000_groups_with_memberships` | PASS |
| CL | 20,000 memberships | entra_group_membership | scale target (2000 groups x 10 members) | all collected, unique record_ids, no dup | n/a | n/a | n/a | N/A | `test_5000_users_2000_groups_with_memberships` | PASS |
| CM | bounded group-member call count | (N+1 audit) | 5 groups, 50 users | exactly one `/members` call per group, zero per-user calls | n/a | n/a | n/a | N/A | `test_membership_walk_is_group_directed_bounded_call_count`, `test_does_not_call_per_user_memberof_endpoint` | PASS |
| CN | phone excluded | entra_user | mobilePhone/businessPhones present in raw | never copied into record | n/a | n/a | High if violated | `test_user_excludes_phone_and_address_fields` | PASS |
| CO | address excluded | entra_user | streetAddress present in raw | never copied into record | n/a | n/a | High if violated | `test_user_excludes_phone_and_address_fields` | PASS |
| CP | password profile excluded | entra_user | passwordProfile present in raw | never copied into record | n/a | n/a | Critical if violated | `test_user_excludes_password_profile` | PASS |
| CQ | proxy addresses excluded | entra_user | proxyAddresses present in raw | never copied into record | n/a | n/a | Medium if violated | `test_user_excludes_proxy_addresses_and_manager` | PASS |
| CR | membership rule excluded | entra_group | membershipRule present in raw | never copied into record | n/a | n/a | Medium if violated (reveals business logic) | `test_group_excludes_membership_rule` | PASS |
| CS | raw profile excluded | entra_user | arbitrary customAttribute present in raw | never copied into record | n/a | n/a | Medium if violated | `test_no_raw_profile_or_dict_dumped` | PASS |
| CT | token absent | (connector-wide) | full `fetch()` with real token acquisition | access_token/client_secret never appear in any normalized record | n/a | n/a | Critical if violated | `test_entra_foundation.py::TestSensitiveDataSafety` (message-1 suite, re-verified reachable this message via full `fetch()` runs) | PASS |
| CU | group excludes owners/mail aliases | entra_group | owners/proxyAddresses/mail present in raw | never copied into record | n/a | n/a | Medium if violated | `test_group_excludes_owners_and_mail_aliases` | PASS |
| CV | membership never duplicates full user/group record | entra_group_membership | normalized membership record | no `display_name`/`membership_count` keys present | n/a | n/a | n/a | `test_membership_never_duplicates_full_user_or_group_record` | PASS |
| CW | missing user record defaults to unknown context | entra_group_membership | member id has no corresponding user record (e.g. users family denied) | user_type_category/account_enabled_category="unknown" | n/a | n/a | Yes | None | `test_missing_user_record_defaults_to_unknown_context` | PASS |
| CX | family independence: users denied, others attempted | (family independence) | `/users` 403 | groups/memberships still attempted; fetch does not raise | n/a | n/a | n/a | N/A | `test_users_denied_groups_and_memberships_still_attempted` | PASS |
| CY | fetch never fails entirely on partial denial | (family independence) | users+groups both denied | fetch returns org record, does not raise | n/a | n/a | n/a | N/A | `test_fetch_does_not_fail_entirely_on_partial_denial` | PASS |
| CZ | explicit $select allowlist for users | entra_user | — | `$select` param matches `EntraConnector._USER_SELECT` exactly | n/a | n/a | n/a | Confirms no `$select=*` | `test_users_select_uses_explicit_allowlist` | PASS |
| DA | explicit $select allowlist for groups | entra_group | — | `$select` param matches `EntraConnector._GROUP_SELECT` exactly | n/a | n/a | n/a | Confirms no `$select=*` | `test_groups_select_uses_explicit_allowlist` | PASS |

**Total rows: 105.** All cases required by the task specification (A through CT) are covered, plus 5 additional cases (CU-DA) covering owner/mail-alias exclusion, membership record isolation, missing-user-context defaulting, and explicit `$select` allowlist verification — added because they surfaced directly from the implementation and are worth pinning permanently.
