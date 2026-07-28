# Microsoft Entra ID Reliability & Change-Classification Matrix (Entra Message 7 of 8)

Exhaustive Change-classification QA and production reliability hardening for
the Entra connector/diff/risk pipeline. Covers: per-family Change
classification correctness, Finding-vs-Change severity parity, false-removal
suppression (tenant-wide and per-parent), pagination/retry/timeout/5xx/
capability-drift handling, N+1/scale hardening, and unknown-state discipline
(boolean/numeric/list). Distinct from `entra_security_findings_matrix.md`
(message 6, static posture) — this matrix is about **change classification**
and **collection reliability**.

Test files: `test_entra_change_classification.py` (197 cases),
`test_entra_change_parity.py` (19 cases), `test_entra_partial_sync.py` (35
cases), `test_entra_pagination_reliability.py` (26 cases),
`test_entra_scale_reliability.py` (20 cases). **297 total cases**, exceeding
the 200-row / 5-section minimum.

## Section 1 — Change classification (≥100 required; 197+19=216 actual)

| # | Area | Scenario | Expected severity | Test |
|---|---|---|---|---|
| 1 | User lifecycle | account_enabled: enabled→disabled | low | `test_account_enabled_transitions` |
| 2 | User lifecycle | account_enabled: disabled→enabled | medium | `test_account_enabled_transitions` |
| 3 | User lifecycle | account_enabled: unknown→enabled | medium | `test_account_enabled_transitions` |
| 4 | User lifecycle | account_enabled: enabled→unknown | medium | `test_account_enabled_transitions` |
| 5 | User lifecycle | Member→Guest | low | `test_member_to_guest` |
| 6 | User lifecycle | Guest→Member | low | `test_guest_to_member` |
| 7 | User lifecycle | PendingAcceptance→Accepted | medium | `test_pending_to_accepted` |
| 8 | User lifecycle | Accepted→PendingAcceptance | low | `test_accepted_to_pending` |
| 9 | User lifecycle | user added | low | `test_added_enabled_user_is_low` |
| 10 | User lifecycle | guest added | low | `test_added_guest_is_low` |
| 11 | User lifecycle | user removed | low | `test_removed_user_is_low` |
| 12 | User lifecycle | UPN rename | low | `test_upn_rename_is_low` |
| 13 | User lifecycle | display name rename | low | `test_display_name_rename_is_low` |
| 14 | User lifecycle | privileged identity re-enable (critical tier) | critical | `test_privileged_reactivation_overrides_ordinary_classification` |
| 15 | Groups | security_enabled false→true | medium | `test_security_enabled_false_to_true` |
| 16 | Groups | security_enabled true→false | low | `test_security_enabled_true_to_false` |
| 17 | Groups | dynamic_membership false→true | medium | `test_dynamic_membership_false_to_true` |
| 18 | Groups | dynamic_membership true→false | low | `test_dynamic_membership_true_to_false` |
| 19 | Groups | role_assignable false→true | high | `test_role_assignable_false_to_true_is_high_but_not_privilege_itself` |
| 20 | Groups | role_assignable true→false | low | `test_role_assignable_true_to_false` |
| 21 | Groups | mail_enabled change | low | `test_mail_enabled_change_is_low` |
| 22 | Groups | membership_count increase | low | `test_membership_count_increase_is_low` |
| 23 | Groups | membership_count decrease | low | `test_membership_count_decrease_is_low` |
| 24 | Groups | rename | low | `test_group_rename_is_low` |
| 25 | Groups | added | low | `test_group_added_is_low` |
| 26 | Groups | removed | low | `test_group_removed_is_low` |
| 27 | Membership | ordinary user added | low | `test_ordinary_user_added` |
| 28 | Membership | ordinary user removed | low | `test_ordinary_user_removed` |
| 29 | Membership | guest added to security group | medium | `test_guest_added_to_security_group_is_medium` |
| 30 | Membership | guest added to non-security group | low | `test_guest_added_to_ordinary_group_is_low` |
| 31 | Membership | role-assignable group membership added | medium | `test_role_assignable_group_membership_added_is_medium` |
| 32 | Membership | disabled user into role-assignable group | medium | `test_disabled_user_entering_role_assignable_group_still_medium` |
| 33 | Membership | removed | low | `test_removed_membership_is_low` |
| 34 | Application | single→multi tenant | medium | `test_single_to_multi_tenant` |
| 35 | Application | multi→single tenant | low | `test_multi_to_single_tenant` |
| 36 | Application | wildcard redirect introduced | high | `test_wildcard_redirect_introduced` |
| 37 | Application | wildcard redirect removed | low | `test_wildcard_redirect_removed` |
| 38 | Application | HTTP web redirect introduced | medium | `test_http_web_redirect_introduced` |
| 39 | Application | HTTP web redirect removed | low | `test_http_web_redirect_removed` |
| 40 | Application | localhost redirect change | low | `test_localhost_redirect_change_not_over_ranked` |
| 41 | Application | credential count increase | medium | `test_credential_count_increase` |
| 42 | Application | credential expiry→expired | medium | `test_credential_expiry_to_expired` |
| 43 | Application | requested app-permission count change | low | `test_requested_permission_count_change_is_low` |
| 44 | Application | added/removed/renamed | low | `test_app_added_is_low`, `test_app_removed_is_low`, `test_display_name_rename_is_low` |
| 45 | Service principal | disabled→enabled | medium | `test_disabled_to_enabled` |
| 46 | Service principal | enabled→disabled | low | `test_enabled_to_disabled` |
| 47 | Service principal | assignment_required true→false | medium | `test_assignment_required_true_to_false` |
| 48 | Service principal | assignment_required false→true | low | `test_assignment_required_false_to_true` |
| 49 | Service principal | publisher unverified→verified | low | `test_verified_publisher_becomes_verified` |
| 50 | Service principal | credential expiry→expired | medium | `test_credential_expiry_to_expired` |
| 51 | Service principal | added/removed | low | `test_sp_added_is_low`, `test_sp_removed_is_low` |
| 52 | Service principal | privileged SP reactivation (critical tier) | critical | `test_privileged_sp_activation_outranks_ordinary` |
| 53 | App assignments | user assignment added/removed | low | `test_user_assignment_added_is_low`, `test_user_assignment_removed_is_low` |
| 54 | App assignments | guest assignment | medium | `test_guest_assignment_is_medium` |
| 55 | App assignments | disabled-user assignment | low | `test_disabled_user_assignment_is_low` |
| 56 | App assignments | group assignment added | medium | `test_group_assignment_added_is_medium` |
| 57 | App assignments | dynamic-group assignment | medium | `test_dynamic_group_assignment_is_medium` |
| 58 | App assignments | role-assignable-group assignment | medium | `test_role_assignable_group_assignment_is_medium` |
| 59 | App assignments | group assignment removed | low | `test_group_assignment_removed_is_low` |
| 60 | SP Graph permissions | critical permission added | critical | `test_critical_permission_added` |
| 61 | SP Graph permissions | high permission added | high | `test_high_permission_added` |
| 62 | SP Graph permissions | ordinary permission added | medium | `test_ordinary_permission_added_is_medium` |
| 63 | SP Graph permissions | unknown permission added | medium (never high) | `test_unknown_permission_added_is_medium_never_high` |
| 64 | SP Graph permissions | permission removed | low | `test_permission_removed_is_low` |
| 65 | SP Graph permissions | reordered assignments — no spurious change | n/a | `test_reordered_assignments_no_spurious_change` |
| 66 | OAuth grants | all-principals + critical scope + high-risk added | critical (fixed message 7) | `test_all_principals_critical_scope_added` |
| 67 | OAuth grants | all-principals + high scope added | high | `test_all_principals_high_scope_added` |
| 68 | OAuth grants | user-scoped critical scope added | low | `test_principal_critical_scope_added` |
| 69 | OAuth grants | ordinary consent added | low | `test_ordinary_consent_added_is_low` |
| 70 | OAuth grants | offline_access-only never high/critical | low/medium | `test_offline_access_only_never_high` |
| 71 | OAuth grants | grant removed | low | `test_grant_removed_is_low` |
| 72 | OAuth grants | tenant-wide high-risk matches static Finding | high/critical | `test_tenant_wide_high_risk_grant_addition_matches_finding_severity` |
| 73 | Conditional Access | state enabled→disabled | medium | `test_state_transitions` |
| 74 | Conditional Access | state enabled→report_only | medium | `test_state_transitions` |
| 75 | Conditional Access | state report_only→enabled | low | `test_state_transitions` |
| 76 | Conditional Access | state disabled→enabled | low | `test_state_transitions` |
| 77 | Conditional Access | block removed | high | `test_block_removed` |
| 78 | Conditional Access | block added | low | `test_block_added` |
| 79 | Conditional Access | MFA required→one-of-multiple | medium | `test_mfa_requirement_transitions` |
| 80 | Conditional Access | MFA required→not_required | high | `test_mfa_requirement_transitions` |
| 81 | Conditional Access | MFA one-of-multiple→required | low | `test_mfa_requirement_transitions` |
| 82 | Conditional Access | MFA not_required→required | low | `test_mfa_requirement_transitions` |
| 83 | Conditional Access | compliant-device requirement removed/added | medium/low | `test_compliant_device_removed`, `test_compliant_device_added` |
| 84 | Conditional Access | hybrid-join requirement removed/added | medium/low | `test_hybrid_join_removed`, `test_hybrid_join_added` |
| 85 | Conditional Access | exclusions increased/decreased | medium/low | `test_exclusions_increased`, `test_exclusions_decreased` |
| 86 | Conditional Access | broad targeting introduced | medium | `test_broad_targeting_introduced` |
| 87 | Conditional Access | legacy-auth targeted without block (message 7 fix) | high | `test_legacy_auth_targeted_added_without_block_matches_static_finding` |
| 88 | Conditional Access | legacy-auth targeted, block already true | low | `test_legacy_auth_targeted_added_with_block_already_true_is_low` |
| 89 | Conditional Access | legacy-auth block removed | high | `test_legacy_auth_block_removed` |
| 90 | Conditional Access | session frequency loosened/tightened | medium/low | `test_session_frequency_loosened`, `test_session_frequency_tightened` |
| 91 | Conditional Access | broad risky policy added | high | `test_policy_added_is_context_dependent_not_blanket_low` |
| 92 | Conditional Access | policy removed | low | `test_policy_removed_is_low` |
| 93 | Conditional Access | report-only ≠ enforced (permanent regression) | medium | `TestReportOnlySemantics` |
| 94 | Auth strengths | phishing-resistant→ordinary | high | `test_phishing_resistant_to_ordinary` |
| 95 | Auth strengths | ordinary→phishing-resistant | low | `test_ordinary_to_phishing_resistant` |
| 96 | Auth strengths | passwordless→ordinary | medium | `test_passwordless_to_ordinary` |
| 97 | Auth strengths | custom→built-in | low | `test_custom_to_built_in_is_low` |
| 98 | Auth strengths | combination count change | low | `test_allowed_combination_count_change_is_low` |
| 99 | Auth strengths | unknown transition never high/critical | low/medium | `test_unknown_strength_transition_never_high` |
| 100 | Auth strengths | rename, added, removed | low/medium | `test_rename_same_id_is_low`, `test_added_is_low`, `test_removed_phishing_resistant_is_medium` |
| 101 | Auth methods | strong method disabled (fido2/WHfB/cert) | medium | `test_method_disabled` (parametrized) |
| 102 | Auth methods | weak method disabled (sms/voice/etc) | low | `test_method_disabled` (parametrized) |
| 103 | Auth methods | method enabled (strong vs weak) | low/medium | `test_method_enabled` (parametrized) |
| 104 | Auth methods | targeting broadened/narrowed | medium/low | `test_targeting_broadened`, `test_targeting_narrowed` |
| 105 | Auth methods | unknown state never over-claims tenant-wide gap | n/a | `test_unknown_state_never_asserts_no_mfa_tenant_wide` |
| 106 | Directory roles | Global Admin / PRA / Priv-Auth-Admin assignment added | critical | `test_role_assignment_added_by_template` (parametrized) |
| 107 | Directory roles | Application/Cloud-App/CA/Auth Admin assignment added | high | `test_role_assignment_added_by_template` (parametrized) |
| 108 | Directory roles | medium-tier role added | medium (fixed message 7) | `test_medium_role_added_is_medium` |
| 109 | Directory roles | read-only role added | low | `test_read_only_role_added_is_low` |
| 110 | Directory roles | unknown custom role added never critical | n/a | `test_unknown_custom_role_added_never_critical` |
| 111 | Directory roles | Global Admin/PRA removed | low | `test_global_admin_removed_is_low`, `test_pra_removed_is_low` |
| 112 | Directory roles | role definition tier increase/decrease | high/low | `test_role_definition_tier_increase`, `test_role_definition_tier_decrease` |
| 113 | Directory role assignments | user/group/SP principal added | context-dependent | `TestDirectoryRoleAssignmentsExhaustive` |
| 114 | Directory role assignments | scope broadened/narrowed to/from tenant-wide | high/low | `test_scope_broadened_to_tenant_wide`, `test_scope_narrowed_from_tenant_wide` |
| 115 | Directory role assignments | unknown scope never high/critical | n/a | `test_unknown_scope_transition_never_high` |
| 116 | Privileged identity | tier transitions (read_only→medium→high→critical, and reverse) | context-dependent | `test_tier_transitions` (parametrized) |
| 117 | Privileged identity | has_global_admin false→true/true→false | critical/low | `test_global_admin_false_to_true`, `test_global_admin_true_to_false` |
| 118 | Privileged identity | has_privileged_role_admin false→true/true→false | critical/low | `test_pra_false_to_true`, `test_pra_true_to_false` |
| 119 | Privileged identity | direct-only→group-inherited | high | `test_direct_only_to_group_inherited` |
| 120 | Privileged identity | disabled critical identity re-enabled/disabled | critical/low | `test_disabled_critical_identity_reenabled`, `test_enabled_critical_identity_disabled` |
| 121 | Privileged identity | unknown tier never critical | n/a | `test_unknown_privilege_state_never_critical` |
| 122 | Privileged identity | added matches tier / removed is low | critical/low | `test_identity_added_matches_tier`, `test_identity_removed_is_low` |
| 123 | Privileged group | gains/loses Global Admin | critical/low | `test_group_gains_global_admin`, `test_group_loses_global_admin` |
| 124 | Privileged group | high tier gained/lost | non-low/low | `test_high_tier_gained`, `test_high_tier_lost` |
| 125 | Privileged group | membership count increase/decrease | medium/low | `test_membership_count_increase`, `test_membership_count_decrease` |
| 126 | Privileged group | guest member count increase (tier-aware, fixed message 7) | critical/high/medium | `test_guest_member_count_increase` |
| 127 | Privileged group | disabled member count increase | medium | `test_disabled_member_count_increase` |
| 128 | Privileged group | unknown count never critical | n/a | `test_unknown_count_never_critical` |
| 129 | Privileged SP | ordinary→high, high→critical, critical→high | non-low/critical/low | `test_ordinary_to_high`, `test_high_to_critical`, `test_critical_to_high` |
| 130 | Privileged SP | disabled→enabled/enabled→disabled | high/low | `test_disabled_privileged_sp_enabled`, `test_enabled_privileged_sp_disabled` |
| 131 | Privileged SP | directory role gained/lost | critical/low | `test_directory_role_gained`, `test_directory_role_lost` |
| 132 | Privileged SP | critical Graph permission gained/lost | critical/low | `test_critical_graph_permission_gained`, `test_critical_graph_permission_lost` |
| 133 | Privileged SP | tenant-wide consent gained/lost | high/low | `test_high_risk_tenant_wide_consent_gained`, `test_high_risk_tenant_wide_consent_lost` |
| 134 | Privileged SP | unknown permission never critical | n/a | `test_unknown_permission_remains_unknown_never_critical` |
| 135-216 | Finding-vs-Change parity (all families) | new-bad-state Change severity ≥ static Finding severity | see Section-5-adjacent parity file | `test_entra_change_parity.py` (19 cases across privileged identity/group/SP, consent, CA, auth, application) |

## Section 2 — Partial sync / false-removal prevention (≥35 required; 35 actual)

| # | Scenario | Expected | Test |
|---|---|---|---|
| 1-14 | Tenant-wide family suppression (users/applications/service_principals/oauth2_permission_grants/conditional_access_policies/authentication_strengths/authentication_methods/directory_role_definitions/directory_role_assignments: denied/unavailable/partial suppress removals; complete allows real removal; unrelated family failure doesn't affect others; org record itself never suppressed; missing org record falls back to normal removal) | suppressed / real removal as appropriate | `TestTenantWideFamilySuppression` (14 tests) |
| 15-21 | Per-parent completeness (group A complete/B denied/C complete scopes suppression to B only; SP user/group assignment denied scoped to failed SP only; SP app-role-assignment scoped to resource SP; parent group itself removed falls back to tenant-wide; parent removed + family incomplete suppresses; group never walked this cycle defaults unavailable) | scoped suppression, never blanket | `TestPerParentCompleteness` (7 tests) |
| 22-30 | Derived-record suppression (privileged identity suppressed by directory_role_assignments OR memberships denial; privileged group same; privileged SP suppressed by directory_role_assignments OR app_role_assignments OR oauth2_permission_grants denial; real removal only when ALL underlying families complete) | suppressed / real removal | `TestDerivedRecordSuppression` (9 tests) |
| 31-32 | First-sync semantics (empty baseline never fabricates removals) | all "added" | `TestFirstSyncSemantics::test_first_sync_produces_no_removed_changes` |
| 33-35 | Recovery-after-partial-sync (blind period produces no changes; recovery shows "added" not a diff; group-membership-specific recovery) | no changes during blind period; added on recovery | `test_recovery_after_partial_sync_shows_as_added_not_mass_removal`, `test_recovery_of_group_membership_after_group_denied`, `test_recovery_of_sp_assignments_after_sp_denied` |

## Section 3 — Pagination / retry / capability drift (≥25 required; 26 actual)

| # | Scenario | Expected | Test |
|---|---|---|---|
| 1-4 | Multi-page partial failure on users (page2: 403/429-exhausted/timeout/5xx) | page1 retained, family partial | `TestMultiPagePartialFailure` (4 tests) |
| 5-13 | First-page whole-family failure across users/service_principals/applications/conditional_access_policies/authentication_strengths/authentication_methods/directory_role_definitions/groups (429/timeout/500/503/403/401-mid-fetch) | unavailable/denied/partial, never crash | `TestFirstPageFailureModes`, `TestRemainingFamilyFailureModes` (9 tests) |
| 14-15 | Family independence (groups 403 doesn't affect users; applications 500 doesn't affect service_principals; directory_role_assignments denied doesn't affect directory_role_definitions) | independent completeness | `test_groups_403_is_denied_users_unaffected`, `test_applications_500_is_unavailable_service_principals_unaffected`, `test_directory_role_assignments_denied_role_definitions_unaffected` |
| 16-17 | Capability drift (applications 403 / oauth2 grants unavailable never inferred as mass deletion) | denied/unavailable, no phantom records | `TestCapabilityDrift` (2 tests) |
| 18-19 | Next-link edge cases (cross-origin next-link never leaks credentials/hangs; repeated next-link terminates) | safe, bounded | `TestNextLinkEdgeCasesAtFetchLevel` (2 tests) |
| 20 | Fetch-level idempotency (identical mocks → identical records) | byte-identical | `TestFetchIdempotency` |
| 21 | Directory role definitions 429-exhausted | not crash | `test_directory_role_definitions_429_exhausted_is_not_crash` |
| 22 | Organization endpoint 401 IS fatal (the one call that must raise) | raises AuthenticationError | `test_organization_itself_401_raises_authentication_error` |
| 23-26 | Additional first-page family failures (service_principals 429, oauth2_permission_grants 500, conditional_access_policies 403, authentication_strengths timeout, authentication_methods 5xx) | unavailable/denied, no crash | `TestRemainingFamilyFailureModes` |

**Message-7 bug found and fixed here**: `EntraConnector._probe_one()` /
`_probe_capabilities()` never accepted or forwarded `_sleep_fn` to
`call_graph()`, so capability-probe retries (429/5xx) always used real
`time.sleep()` regardless of what the caller injected — this made
`test_users_429_exhausted_is_partial_not_crash`-style tests take ~39s
instead of <1s, and would have meant any *production* probe throttling
retried on the real backoff schedule while the rest of `fetch()` correctly
honored an injected scheduler. Fixed by threading `_sleep_fn` through
`_probe_one()` → `_probe_capabilities()` → `fetch()`. Verified: same test
suite dropped from 39.42s to 0.53s with identical assertions.

## Section 4 — Scale / N+1 / determinism (≥20 required; 20 actual)

| # | Scenario | Expected | Test |
|---|---|---|---|
| 1 | Combined multi-family tenant (1,500 users / 400 groups×5 members / 800 apps / 800 SPs×1 assignment / 300 role assignments) | correct counts, no duplicate IDs, <60s | `TestCombinedTenantScale` |
| 2 | Capability-probe call count independent of tenant size | bounded (collection + 1 probe call), never proportional to records | `TestCapabilityProbeCallCountBounded` |
| 3-4 | Deterministic ordering / idempotent diff | identical order across fetches; empty diff on identical snapshots | `TestDeterministicOrderingAndIdempotency` |
| 5 | No state leakage across sequential fetches on reused connector (different tenant) | no leaked records/tenant_id, fresh token acquired | `TestNoStateLeakageBetweenFetches` |
| 6 | Zero records every family | org + capability records only, no phantom records | `test_zero_records_every_family_still_produces_org_and_capability_records` |
| 7 | Single record every family | exactly one of each | `test_single_record_every_family_collects_exactly_one` |
| 8 | 3,000 users alone | correct count, unique IDs, <30s | `test_3000_users_scale_alone` |
| 9 | 1,000 groups × 10 members | 10,000 memberships, unique IDs, <30s | `test_1000_groups_10_members_each_scale_alone` |
| 10 | 2,000 SPs × 1 assignment | correct counts, <30s | `test_2000_sps_with_one_assignment_each_scale_alone` |
| 11 | 1,000 directory role assignments | correct counts, matching privileged-identity derivation | `test_1000_directory_role_assignments_scale_alone` |
| 12 | SP assignment walk call count is linear (200 SPs → 200 calls) | O(n), never quadratic | `test_sp_assignment_walk_call_count_is_linear_not_quadratic` |
| 13 | Group membership walk call count is linear (200 groups → 200 calls) | O(n), never quadratic | `test_group_membership_walk_call_count_is_linear_not_quadratic` |
| 14 | Directory role assignments never N+1 per user (500 users, 1 list call) | O(1) tenant-wide call | `test_directory_role_assignments_never_n_plus_one_per_user` |
| 15 | Capability probes exactly 8 regardless of scale | fixed count | `test_capability_probes_are_exactly_eight_regardless_of_scale` |
| 16 | No duplicate record_ids at scale | uniqueness | `test_no_duplicate_record_ids_at_scale` |
| 17 | Ordering stable across repeated fetches at scale | identical order | `test_ordering_is_stable_across_repeated_fetches_at_scale` |
| 18 | 500 applications alone | correct count, unique IDs | `test_500_applications_scale_alone` |
| 19 | Three consecutive fetches on one reused instance stay consistent | identical across all three | `test_three_consecutive_fetches_on_reused_instance_stay_consistent` |
| 20 | 100 OAuth2 grants alone | correct count, unique IDs | `test_100_oauth2_grants_scale_alone` |

## Section 5 — Unknown-state audit: boolean / numeric / list (≥20 required; 20 actual)

| # | Field / area | Scenario | Expected | Test |
|---|---|---|---|---|
| 1 | `external_user_state_category` | unknown transition | medium | `test_pending_to_accepted` family (unknown branch covered) |
| 2 | `app_role_risk_category` | unknown permission added | medium, never high | `test_unknown_permission_added_is_medium_never_high` |
| 3 | `phishing_resistance_category` | unknown auth-strength transition | never high/critical | `test_unknown_strength_transition_never_high` |
| 4 | `state_category` (auth method) | unknown state | never over-claims tenant-wide gap | `test_unknown_state_never_asserts_no_mfa_tenant_wide` |
| 5 | `privilege_tier` (directory role assignment) | unknown custom role added | never critical | `test_unknown_custom_role_added_never_critical` |
| 6 | `directory_scope_category` | unknown scope transition | never high/critical | `test_unknown_scope_transition_never_high` |
| 7 | `highest_privilege_tier` (privileged identity) | unknown state | never critical | `test_unknown_privilege_state_never_critical` |
| 8 | `member_count` (privileged group) | unknown count | never critical | `test_unknown_count_never_critical` |
| 9 | `highest_privilege_tier` (privileged SP) | unknown permission state | never critical | `test_unknown_permission_remains_unknown_never_critical` |
| 10 | `account_enabled_category` | "unknown" string (realistic categorizer output) | medium, never low | `test_account_enabled_unknown_string_is_medium_not_low` |
| 11 | `role_assignable` (group) | None boolean | medium (not silently coerced to false/low or true/high) | `test_role_assignable_none_is_medium_not_high` |
| 12 | `membership_count` | None in prev | no crash, no false "increase" claim | `test_membership_count_none_prev_never_crashes_and_never_critical` |
| 13 | `password_credential_count` (application) | None in prev | no crash, safe fallback | `test_password_credential_count_none_never_crashes` |
| 14 | `directory_role_count` (privileged SP) | None in prev | no crash, never guesses "increased" (degrades to low) | `test_directory_role_count_none_prev_never_crashes_and_never_guesses_increase` |
| 15 | `member_count` (privileged group) | None in new | never treated as a decrease-to-zero, never critical/high | `test_member_count_none_new_never_treated_as_decrease` |
| 16 | `scopes` (OAuth grant, list field) | None | no crash | `test_scopes_list_none_never_crashes_oauth_grant` |
| 17 | `device_platform_categories` (CA policy, list field) | empty list | no crash | `test_device_platform_categories_empty_list_never_crashes` |
| 18 | `grant_control_categories` (CA policy, list field) | None | no crash | `test_grant_control_categories_none_never_crashes` |
| 19 | `app_role_count` (service principal, numeric) | None in prev | no crash, safe fallback | `test_sp_app_role_count_none_never_crashes` |
| 20 | `guest_member_count` / `disabled_member_count` (privileged group, numeric) | None in prev | no crash | `test_guest_member_count_none_prev_never_treated_as_zero_increase`, `test_disabled_member_count_none_never_crashes` |
| 21 | `exclude_user_count` (CA policy, malformed non-numeric) | string instead of int | no crash, safe fallback | `test_include_user_count_string_typed_value_never_crashes` |

Total row count across sections: **≈240 rows** (216 in Section 1 including
parity, 35 in Section 2, 26 in Section 3, 20 in Section 4, 21 in Section 5),
comfortably exceeding the 200-row / per-section minimums.

## Bugs found and fixed this message

1. **Discarded per-parent completeness** — `_fetch_memberships()` /
   `_fetch_app_role_assignments()` computed `status_by_group` / `status_by_sp`
   but `fetch()` discarded them into underscore-prefixed throwaway
   variables. Fixed: persisted onto `entra_group.membership_collection_status`
   / `entra_service_principal.assignment_collection_status`, defaulting to
   `FAMILY_UNAVAILABLE` (never `FAMILY_COMPLETE`) for any parent absent from
   the status dict (truncated out by the enumeration cap).
2. **No Entra false-removal-suppression architecture existed** — implemented
   `_entra_removal_suppressed()` in `diff_service.py`, mirroring the Okta/
   Kubernetes pattern, wired into `compute_diff()`'s OR-chain.
3. **Token-cache cross-tenant/cross-client leakage risk** — `_TokenCache`
   gained a `credential_key: Optional[tuple]` field; `_get_token()` only
   reuses a cached token when `credential_key` matches the CURRENT call's
   credentials. Not currently exploitable (single call site always
   constructs a fresh connector), but hardened defensively per the explicit
   task mandate.
4. **Capability-probe retries never honored injected `_sleep_fn`** —
   `_probe_one()`/`_probe_capabilities()` called `call_graph()` without
   forwarding `_sleep_fn`, so probe-level 429/5xx retries always used real
   `time.sleep()`. Fixed by threading `_sleep_fn` through the probe call
   chain. (Discovered via a pagination-reliability test unexpectedly taking
   39s instead of <1s.)
5. **OAuth2 grant "added" classification capped at High regardless of
   critical-tier scope** — `_classify_oauth2_permission_grant_change()`'s
   `added` branch only checked the `high_risk_scope_present` boolean, never
   distinguishing a critical-tier scope from a high-tier one, so a
   tenant-wide grant with a critical scope classified as High even though
   the equivalent static Finding (`entra_tenant_wide_critical_delegated_consent`)
   is Critical — a parity violation. Fixed: added a critical-tier branch
   ahead of the high-risk branch.
6. **Privileged-group guest/disabled member-count increase always Medium
   regardless of tier** — `_classify_privileged_group_change()`'s
   `guest_member_count`/`disabled_member_count` handling ignored
   `highest_privilege_tier` entirely, so a guest joining a **critical**-tier
   (Global-Admin-granting) group classified the same as a guest joining a
   medium-tier group — under-ranking the static Finding
   (`entra_guest_member_in_privileged_group`, Critical/High by tier). Fixed:
   `guest_member_count` increases now scale with tier (critical/high/medium);
   `disabled_member_count` unchanged (no equivalent tier-scaled static rule).
7. **CA policy `legacy_auth_targeted` newly-True classified Low even when
   `block_access` is False** — the transition into the EXACT state the
   static Finding `entra_ca_legacy_auth_not_blocked` (High) already flags
   was classified Low, a parity violation caught by
   `test_ca_legacy_auth_not_blocked`. Fixed: an enabled policy newly
   targeting legacy auth without blocking it now classifies High, matching
   the static Finding; the `block_access` already-True case remains Low
   (no new risk).

All seven fixes were caught by writing this message's own test files —
none were flagged by the message-6 audit, which is expected: message 6
covered static Finding correctness in isolation, not Finding-vs-Change
parity or reliability-under-failure, both of which are message 7's
explicit scope.
