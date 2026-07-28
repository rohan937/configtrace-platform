# Microsoft Entra ID Authentication Policy Matrix (Entra Message 4 of 8)

Pins Conditional Access policy / authentication strength / authentication
method configuration collection, normalization, and Change classification
built in this message. Columns: **Case**, **Record type**, **Source
state**, **Normalized posture**, **Diff tracked?**, **Severity**,
**Unknown-safe?**, **Sensitive-data risk**, **Test**, **Status**.

| # | Case | Record type | Source state | Normalized posture | Diff tracked? | Severity | Unknown-safe? | Sensitive-data risk | Test | Status |
|---|---|---|---|---|---|---|---|---|---|---|
| A | Enabled state | entra_conditional_access_policy | state=enabled | state_category=enabled | Yes | n/a | Yes | None | `TestConditionalAccessState::test_enabled_state` | PASS |
| B | Disabled state | entra_conditional_access_policy | state=disabled | state_category=disabled | Yes | n/a | Yes | None | `test_disabled_state` | PASS |
| C | Report-only never enforced | entra_conditional_access_policy | state=enabledForReportingButNotEnforced | state_category=report_only (never enabled) | Yes | n/a | Yes | None | `test_report_only_state_never_treated_as_enforced` | PASS |
| D | Missing state | entra_conditional_access_policy | state absent | state_category=unknown | Yes | Medium | Yes | None | `test_missing_state_is_unknown` | PASS |
| E | Malformed state (non-string) | entra_conditional_access_policy | state=12345 | state_category=unknown | Yes | Medium | Yes | None | `test_malformed_state_is_unknown` | PASS |
| F | Unrecognized state string | entra_conditional_access_policy | state="somethingNew" | state_category=unknown | Yes | Medium | Yes | None | `test_unrecognized_state_string_is_unknown` | PASS |
| G | Stable record ID | entra_conditional_access_policy | tenant+policy id | record_id=`{tenant}/conditional_access_policy/{id}` | n/a | n/a | Yes | None | `test_stable_record_id_uses_tenant_and_policy_id` | PASS |
| H | Missing policy id | entra_conditional_access_policy | id absent | normalizer returns None | n/a | n/a | Yes | None | `test_missing_id_returns_none` | PASS |
| I | Rename preserves stable ID | entra_conditional_access_policy | displayName changes, id unchanged | record_id stable, display_name tracked | Yes | Low | Yes | None | `test_rename_preserves_stable_id` | PASS |
| J | All-users targeting | entra_conditional_access_policy | conditions.users.includeUsers=["All"] | user_target_category=all_users | Yes | n/a | Yes | None | `TestConditionalAccessTargeting::test_all_users_targeting` | PASS |
| K | Selected users targeting | entra_conditional_access_policy | includeUsers=[u1,u2] | user_target_category=selected_users, count=2 | Yes | n/a | Yes | None | `test_selected_users_targeting` | PASS |
| L | Selected groups targeting | entra_conditional_access_policy | includeGroups=[g1] | user_target_category=selected_groups | Yes | n/a | Yes | None | `test_selected_groups_targeting` | PASS |
| M | Directory roles targeting | entra_conditional_access_policy | includeRoles=[r1] | user_target_category=directory_roles | Yes | n/a | Yes | None | `test_directory_roles_targeting` | PASS |
| N | Guests/external targeting | entra_conditional_access_policy | includeGuestsOrExternalUsers present | user_target_category=guests_external_users | Yes | n/a | Yes | None | `test_guests_targeting` | PASS |
| O | Missing users block | entra_conditional_access_policy | conditions.users absent | user_target_category=unknown (never all_users) | Yes | Medium | Yes | None | `test_missing_users_block_is_unknown_not_all_users` | PASS |
| P | Exclusions counted | entra_conditional_access_policy | excludeUsers=[u1,u2], excludeGroups=[g1] | exclude_user_count=2, exclude_group_count=1 | Yes | n/a | Yes | None | `test_exclusions_counted` | PASS |
| Q | Guests excluded flag | entra_conditional_access_policy | excludeGuestsOrExternalUsers present | guests_excluded=True | Yes | n/a | Yes | None | `test_guests_excluded_flag` | PASS |
| R | Break-glass naming not inferred | entra_conditional_access_policy | excludeUsers=["emergency-access-1"] | count only; ID never persisted | n/a | n/a | Critical if violated | `test_break_glass_naming_not_inferred_as_safe` | PASS |
| S | All cloud apps targeting | entra_conditional_access_policy | includeApplications=["All"] | app_target_category=all_cloud_apps | Yes | n/a | Yes | None | `test_app_targeting_all_cloud_apps` | PASS |
| T | Selected apps targeting | entra_conditional_access_policy | includeApplications=[app1] | app_target_category=selected_apps | Yes | n/a | Yes | None | `test_app_targeting_selected_apps` | PASS |
| U | User-actions targeting | entra_conditional_access_policy | includeUserActions present | app_target_category=user_actions | Yes | n/a | Yes | None | `test_app_targeting_user_actions` | PASS |
| V | Authentication-context targeting | entra_conditional_access_policy | includeAuthenticationContextClassReferences present | app_target_category=authentication_context | Yes | n/a | Yes | None | `test_app_targeting_authentication_context` | PASS |
| W | Coverage all-users-all-apps | entra_conditional_access_policy | all users + all apps | coverage_category=all_users_all_apps | Yes | n/a | Yes | None | `test_coverage_all_users_all_apps` | PASS |
| X | Coverage selected/selected | entra_conditional_access_policy | selected group + selected app | coverage_category=selected_principals_selected_apps | Yes | n/a | Yes | None | `test_coverage_selected_principals_selected_apps` | PASS |
| Y | Coverage guests category | entra_conditional_access_policy | guests targeting | coverage_category=guests | Yes | n/a | Yes | None | `test_coverage_guests_category` | PASS |
| Z | Device platform categories | entra_conditional_access_policy | includePlatforms=[android,iOS] | device_platform_categories=[android,iOS] | Yes | n/a | Yes | None | `test_device_platform_categories` | PASS |
| AA | Missing platforms | entra_conditional_access_policy | conditions.platforms absent | device_platform_categories=[unknown] | Yes | Low | Yes | None | `test_missing_platforms_is_unknown` | PASS |
| AB | Location targeting all | entra_conditional_access_policy | includeLocations=["All"] | location_target_category=all | Yes | n/a | Yes | None | `test_location_targeting_all` | PASS |
| AC | Location targeting all-trusted | entra_conditional_access_policy | includeLocations=["AllTrusted"] | location_target_category=all_trusted | Yes | n/a | Yes | None | `test_location_targeting_all_trusted` | PASS |
| AD | Named-location IDs never exposed as IP ranges | entra_conditional_access_policy | includeLocations=[guid] | location_target_category=selected; guid excluded from record text | n/a | n/a | Critical if violated | `test_location_targeting_never_exposes_ip_ranges` | PASS |
| AE | Legacy auth via ExchangeActiveSync | entra_conditional_access_policy | clientAppTypes=[exchangeActiveSync] | legacy_auth_targeted=True | Yes | n/a | Yes | None | `TestClientAppTypesAndLegacyAuth::test_legacy_auth_targeted_via_exchange_activesync` | PASS |
| AF | Legacy auth via "other" | entra_conditional_access_policy | clientAppTypes=[other] | legacy_auth_targeted=True | Yes | n/a | Yes | None | `test_legacy_auth_targeted_via_other` | PASS |
| AG | Browser-only not legacy | entra_conditional_access_policy | clientAppTypes=[browser] | legacy_auth_targeted=False | Yes | n/a | Yes | None | `test_browser_only_is_not_legacy_auth_targeted` | PASS |
| AH | Missing clientAppTypes never inferred legacy | entra_conditional_access_policy | clientAppTypes absent | legacy_auth_targeted=False (not inferred True) | Yes | Medium | Yes | None | `test_missing_client_app_types_never_inferred_as_legacy_targeted` | PASS |
| AI | MFA required, AND operator | entra_conditional_access_policy | operator=AND, controls=[mfa,compliantDevice] | mfa_requirement_category=required | Yes | n/a | Yes | None | `TestGrantControlsAndMfaSemantics::test_mfa_required_with_and_operator` | PASS |
| AJ | MFA one-of-multiple, OR operator (never flattened) | entra_conditional_access_policy | operator=OR, controls=[mfa,compliantDevice] | mfa_requirement_category=one_of_multiple_controls | Yes | n/a | Yes | None | `test_mfa_one_of_multiple_with_or_operator_never_flattened_to_required` | PASS |
| AK | MFA required, single control | entra_conditional_access_policy | operator=OR, controls=[mfa] | mfa_requirement_category=required | Yes | n/a | Yes | None | `test_mfa_required_single_control` | PASS |
| AL | MFA not required | entra_conditional_access_policy | controls=[compliantDevice] (no mfa) | mfa_requirement_category=not_required | Yes | n/a | Yes | None | `test_mfa_not_required_when_absent` | PASS |
| AM | MFA unknown, operator missing + multiple controls | entra_conditional_access_policy | operator absent, controls=[mfa,compliantDevice] | mfa_requirement_category=unknown | Yes | Medium | Yes | None | `test_mfa_unknown_when_operator_unknown_and_multiple_controls` | PASS |
| AN | MFA unknown, grantControls missing | entra_conditional_access_policy | grantControls absent | mfa_requirement_category=unknown | Yes | Medium | Yes | None | `test_mfa_unknown_when_grant_controls_missing` | PASS |
| AO | Block access | entra_conditional_access_policy | controls=[block] | block_access=True, mfa_requirement_category=blocked | Yes | n/a | Yes | None | `test_block_access_true` | PASS |
| AP | Authentication strength referenced | entra_conditional_access_policy | grantControls.authenticationStrength.id=s1 | authentication_strength_id=s1, referenced=True | Yes | n/a | Yes | None | `test_authentication_strength_reference_captured` | PASS |
| AQ | No authentication strength reference | entra_conditional_access_policy | grantControls absent | authentication_strength_id=None, referenced=False | Yes | n/a | Yes | None | `test_no_authentication_strength_reference` | PASS |
| AR | Hybrid-joined device required | entra_conditional_access_policy | controls=[domainJoinedDevice] | hybrid_joined_device_required=True | Yes | n/a | Yes | None | `test_hybrid_joined_device_required` | PASS |
| AS | Approved/compliant application required | entra_conditional_access_policy | controls=[approvedApplication,compliantApplication] | both flags True | Yes | n/a | Yes | None | `test_approved_and_compliant_application_required` | PASS |
| AT | Raw grantControls never persisted | entra_conditional_access_policy | grantControls with customAuthenticationFactors | raw block absent from record | n/a | n/a | Critical if violated | `test_raw_grant_controls_never_persisted` | PASS |
| AU | User risk levels normalized | entra_conditional_access_policy | userRiskLevels=[high,medium] | user_risk_level_categories=[high,medium] | Yes | n/a | Yes | None | `TestRiskLevels::test_user_risk_levels_normalized` | PASS |
| AV | Missing risk levels | entra_conditional_access_policy | signInRiskLevels absent | sign_in_risk_level_categories=[unknown] | Yes | n/a | Yes | None | `test_missing_risk_levels_is_unknown` | PASS |
| AW | Unrecognized risk value stays unknown | entra_conditional_access_policy | userRiskLevels=["totallyNewValue"] | categories=[unknown] | Yes | n/a | Yes | None | `test_unrecognized_risk_value_stays_unknown` | PASS |
| AX | Sign-in frequency hours | entra_conditional_access_policy | signInFrequency isEnabled=True,type=hours,value=4 | sign_in_frequency_category=short | Yes | n/a | Yes | None | `TestSessionControls::test_sign_in_frequency_hours` | PASS |
| AY | Sign-in frequency every-time | entra_conditional_access_policy | frequencyInterval=everyTime | sign_in_frequency_category=every_time | Yes | n/a | Yes | None | `test_sign_in_frequency_every_time` | PASS |
| AZ | Sign-in frequency disabled | entra_conditional_access_policy | isEnabled=False | sign_in_frequency_category=unknown, enabled=False | Yes | n/a | Yes | None | `test_sign_in_frequency_disabled_is_unknown` | PASS |
| BA | Persistent browser always | entra_conditional_access_policy | persistentBrowser.mode=always | persistent_browser_category=always | Yes | n/a | Yes | None | `test_persistent_browser_always` | PASS |
| BB | Persistent browser missing | entra_conditional_access_policy | sessionControls absent | persistent_browser_category=unknown | Yes | n/a | Yes | None | `test_persistent_browser_missing_is_unknown` | PASS |
| BC | CAE strict enforcement | entra_conditional_access_policy | continuousAccessEvaluation.mode=strictEnforcement | continuous_access_evaluation_category=strict_enforcement | Yes | n/a | Yes | None | `test_cae_strict_enforcement` | PASS |
| BD | App-enforced restrictions missing | entra_conditional_access_policy | block absent | app_enforced_restrictions_enabled=None (not False) | Yes | n/a | Yes | None | `test_app_enforced_restrictions_missing_is_none` | PASS |
| BE | App-enforced restrictions true | entra_conditional_access_policy | isEnabled=True | app_enforced_restrictions_enabled=True | Yes | n/a | Yes | None | `test_app_enforced_restrictions_true` | PASS |
| BF | Raw sessionControls never persisted | entra_conditional_access_policy | signInFrequency present | raw block absent from record | n/a | n/a | Critical if violated | `test_raw_session_controls_never_persisted` | PASS |
| BG | Built-in via policyType | entra_authentication_strength | policyType=builtIn | kind_category=built_in | Yes | n/a | Yes | None | `TestAuthenticationStrengthNormalization::test_built_in_via_policy_type` | PASS |
| BH | Custom via policyType | entra_authentication_strength | policyType=custom | kind_category=custom | Yes | n/a | Yes | None | `test_custom_via_policy_type` | PASS |
| BI | Built-in via well-known ID fallback | entra_authentication_strength | id=00000000-...-000004, policyType absent | kind_category=built_in | Yes | n/a | Yes | None | `test_built_in_via_well_known_id_fallback` | PASS |
| BJ | Kind unknown when both signals absent | entra_authentication_strength | policyType and id both unrecognized | kind_category=unknown | Yes | Low | Yes | None | `test_missing_policy_type_and_unknown_id_is_unknown` | PASS |
| BK | Phishing-resistant, all combos qualify | entra_authentication_strength | allowedCombinations=[fido2,windowsHelloForBusiness] | phishing_resistance_category=phishing_resistant | Yes | n/a | Yes | None | `test_phishing_resistant_when_all_combos_qualify` | PASS |
| BL | Not phishing-resistant, one weak combo | entra_authentication_strength | allowedCombinations=[fido2,password+sms] | phishing_resistance_category=not_phishing_resistant | Yes | n/a | Yes | None | `test_not_phishing_resistant_when_any_combo_is_weak` | PASS |
| BM | Phishing resistance unknown when combos missing | entra_authentication_strength | allowedCombinations absent | phishing_resistance_category=unknown | Yes | Medium | Yes | None | `test_phishing_resistance_unknown_when_combos_missing` | PASS |
| BN | SMS never phishing-resistant | entra_authentication_strength | allowedCombinations=[sms] | phishing_resistance_category=not_phishing_resistant | Yes | n/a | Yes | None | `test_sms_never_classified_phishing_resistant` | PASS |
| BO | Passwordless category | entra_authentication_strength | allowedCombinations=[fido2] | passwordless_category=passwordless | Yes | n/a | Yes | None | `test_passwordless_category` | PASS |
| BP | Combination count bounded | entra_authentication_strength | 3 allowedCombinations | allowed_combination_count=3 | Yes | n/a | Yes | None | `test_combination_count_bounded` | PASS |
| BQ | Raw combinations never persisted | entra_authentication_strength | allowedCombinations=[fido2] | raw list absent from record | n/a | n/a | Critical if violated | `test_raw_combinations_never_persisted` | PASS |
| BR | MFA capability category | entra_authentication_strength | non-empty allowedCombinations | mfa_capability_category=mfa_capable | Yes | n/a | Yes | None | `test_mfa_capability_category` | PASS |
| BS | Missing strength id | entra_authentication_strength | id absent | normalizer returns None | n/a | n/a | Yes | None | `test_missing_id_returns_none` | PASS |
| BT | Stable record id | entra_authentication_strength | tenant+strength id | record_id=`{tenant}/authentication_strength/{id}` | n/a | n/a | Yes | None | `test_stable_record_id` | PASS |
| BU | FIDO2 type + phishing-resistant | entra_authentication_method | id=Fido2 | method_type_category=fido2, phishing_resistance=phishing_resistant | Yes | n/a | Yes | None | `TestAuthenticationMethodNormalization::test_fido2_type_and_phishing_resistant` | PASS |
| BV | SMS type never phishing-resistant | entra_authentication_method | id=Sms | method_type_category=sms, phishing_resistance=not_phishing_resistant | Yes | n/a | Yes | None | `test_sms_type_never_phishing_resistant` | PASS |
| BW | Voice type | entra_authentication_method | id=Voice | method_type_category=voice | Yes | n/a | Yes | None | `test_voice_type` | PASS |
| BX | Microsoft Authenticator type | entra_authentication_method | id=MicrosoftAuthenticator | method_type_category=microsoft_authenticator | Yes | n/a | Yes | None | `test_microsoft_authenticator_type` | PASS |
| BY | Temporary Access Pass type | entra_authentication_method | id=TemporaryAccessPass | method_type_category=temporary_access_pass | Yes | n/a | Yes | None | `test_temporary_access_pass_type` | PASS |
| BZ | Software OATH type | entra_authentication_method | id=SoftwareOath | method_type_category=software_oath | Yes | n/a | Yes | None | `test_software_oath_type` | PASS |
| CA | Certificate-based auth, phishing-resistant | entra_authentication_method | id=X509Certificate | method_type_category=certificate_based_auth, phishing_resistant | Yes | n/a | Yes | None | `test_certificate_based_auth_type_is_phishing_resistant` | PASS |
| CB | Email OTP type | entra_authentication_method | id=Email | method_type_category=email_otp | Yes | n/a | Yes | None | `test_email_otp_type` | PASS |
| CC | Unrecognized config ID | entra_authentication_method | id=SomeFutureMethod | method_type_category=unknown, phishing_resistance=unknown | Yes | Low | Yes | None | `test_unrecognized_config_id_is_unknown` | PASS |
| CD | Method state enabled | entra_authentication_method | state=enabled | state_category=enabled | Yes | n/a | Yes | None | `test_state_enabled` | PASS |
| CE | Method state disabled | entra_authentication_method | state=disabled | state_category=disabled | Yes | n/a | Yes | None | `test_state_disabled` | PASS |
| CF | Method state missing not disabled | entra_authentication_method | state absent | state_category=unknown | Yes | Medium | Yes | None | `test_state_missing_is_unknown_not_disabled` | PASS |
| CG | Targeting all users | entra_authentication_method | includeTargets id=all_users | target_category=all_users, count=1 | Yes | n/a | Yes | None | `test_targeting_all_users` | PASS |
| CH | Targeting selected groups | entra_authentication_method | includeTargets id=group-guid-1 | target_category=selected_groups | Yes | n/a | Yes | None | `test_targeting_selected_groups` | PASS |
| CI | Targeting missing | entra_authentication_method | includeTargets absent | target_category=unknown | Yes | Low | Yes | None | `test_targeting_missing_is_unknown` | PASS |
| CJ | Target IDs never persisted raw | entra_authentication_method | includeTargets/excludeTargets with group GUIDs | GUIDs absent from record; counts only | n/a | n/a | Critical if violated | `test_target_ids_never_persisted_raw` | PASS |
| CK | Missing method config id | entra_authentication_method | id absent | normalizer returns None | n/a | n/a | Yes | None | `test_missing_id_returns_none` | PASS |
| CL | Stable record id | entra_authentication_method | tenant+config id | record_id=`{tenant}/authentication_method/{id}` | n/a | n/a | Yes | None | `test_stable_record_id` | PASS |
| CM | CA policy never persists secrets/tokens | entra_conditional_access_policy | full policy with grantControls | no secret/certificate/phone/token substrings | n/a | n/a | Critical if violated | `TestSensitiveDataExclusion::test_ca_policy_never_persists_secrets_or_tokens` | PASS |
| CN | TAP method never persists lifetime/secret fields | entra_authentication_method | id=TemporaryAccessPass | no TAP value/lifetime substrings | n/a | n/a | Critical if violated | `test_authentication_method_never_persists_secrets` | PASS |
| CO | Identical CA policy produces no Change | entra_conditional_access_policy | same record, re-diffed | compute_diff()==[] | n/a | n/a | Yes | None | `TestNoSpuriousChangeWhenIdentical::test_identical_ca_policy_produces_no_change` | PASS |
| CP | Identical strength produces no Change | entra_authentication_strength | same record, re-diffed | compute_diff()==[] | n/a | n/a | Yes | None | `test_identical_strength_produces_no_change` | PASS |
| CQ | Identical method produces no Change | entra_authentication_method | same record, re-diffed | compute_diff()==[] | n/a | n/a | Yes | None | `test_identical_method_produces_no_change` | PASS |
| CR | enabled -> report_only | entra_conditional_access_policy | state_category enabled->report_only | weakening, no longer enforces | Yes | Medium | Yes | None | `TestConditionalAccessStateTransitions::test_enabled_to_report_only_is_medium` | PASS |
| CS | report_only -> enabled | entra_conditional_access_policy | state_category report_only->enabled | strengthening | Yes | Low | Yes | None | `test_report_only_to_enabled_is_low` | PASS |
| CT | enabled -> disabled | entra_conditional_access_policy | state_category enabled->disabled | policy disabled | Yes | Medium | Yes | None | `test_enabled_to_disabled_is_medium` | PASS |
| CU | disabled -> enabled | entra_conditional_access_policy | state_category disabled->enabled | policy enabled | Yes | Low | Yes | None | `test_disabled_to_enabled_is_low` | PASS |
| CV | Unknown state transition never High | entra_conditional_access_policy | state_category enabled->unknown | never ranked as known weakening | Yes | Medium | Yes | None | `test_unknown_state_transition_never_ranked_high` | PASS |
| CW | New broad enabled no-MFA policy added | entra_conditional_access_policy | added, all_users_all_apps, mfa=not_required, block=False | potential High | n/a | High | Yes | None | `test_policy_added_enabled_broad_no_mfa_is_high` | PASS |
| CX | New enforced MFA policy added | entra_conditional_access_policy | added, mfa_requirement=required | improvement | n/a | Low | Yes | None | `test_policy_added_enforced_mfa_is_low` | PASS |
| DA | New report-only policy added | entra_conditional_access_policy | added, state=report_only | Low | n/a | Low | Yes | None | `test_policy_added_report_only_is_low` | PASS |
| DB | Enforced protective policy removed | entra_conditional_access_policy | removed, state=enabled, mfa=required | High/Medium | n/a | High/Medium | Yes | None | `test_enforced_policy_removed_is_high_or_medium` | PASS |
| DC | Report-only policy removed | entra_conditional_access_policy | removed, state=report_only | Low | n/a | Low | Yes | None | `test_report_only_policy_removed_is_low` | PASS |
| DD | Enforced block removed | entra_conditional_access_policy | block_access True->False, state=enabled | High | Yes | High | Yes | None | `TestBlockAccessChanges::test_enforced_block_removed_is_high` | PASS |
| DE | Block added | entra_conditional_access_policy | block_access False->True | Low/improvement | Yes | Low | Yes | None | `test_block_added_is_low` | PASS |
| DF | MFA required -> not_required (enforced) | entra_conditional_access_policy | mfa_requirement_category required->not_required | complete removal | Yes | High | Yes | None | `TestMfaRequirementChanges::test_required_to_not_required_on_enforced_policy_is_high` | PASS |
| DG | MFA required -> one_of_multiple | entra_conditional_access_policy | required->one_of_multiple_controls | partial weakening (OR) | Yes | Medium | Yes | None | `test_required_to_one_of_multiple_is_medium` | PASS |
| DH | MFA not_required -> required | entra_conditional_access_policy | strengthening | Yes | Low | Yes | None | `test_not_required_to_required_is_low` | PASS |
| DI | MFA unknown transition never High | entra_conditional_access_policy | required->unknown | never High | Yes | Medium | Yes | None | `test_unknown_mfa_transition_never_high` | PASS |
| DJ | Compliant-device requirement removed | entra_conditional_access_policy | True->False | Medium | Yes | Medium | Yes | None | `TestDeviceRequirementChanges::test_compliant_device_requirement_removed_is_medium` | PASS |
| DK | Compliant-device requirement added | entra_conditional_access_policy | False->True | Low | Yes | Low | Yes | None | `test_compliant_device_requirement_added_is_low` | PASS |
| DL | Hybrid-joined requirement removed | entra_conditional_access_policy | True->False | Medium | Yes | Medium | Yes | None | `test_hybrid_joined_requirement_removed_is_medium` | PASS |
| DM | Legacy-auth block removed (enforced) | entra_conditional_access_policy | legacy_auth_targeted True->False, block_access=True | High | Yes | High | Yes | None | `TestLegacyAuthBlock::test_legacy_auth_targeting_removed_from_enforced_block_policy_is_high` | PASS |
| DN | Legacy-auth targeting added | entra_conditional_access_policy | False->True | Low | Yes | Low | Yes | None | `test_legacy_auth_targeting_added_is_low` | PASS |
| DO | Exclusions broadened | entra_conditional_access_policy | exclude_user_count 1->10 | Medium | Yes | Medium | Yes | None | `TestExclusionChanges::test_exclusions_broadened_is_medium` | PASS |
| DP | Exclusions narrowed | entra_conditional_access_policy | exclude_user_count 10->1 | Low | Yes | Low | Yes | None | `test_exclusions_narrowed_is_low` | PASS |
| DQ | Guests exclusion removed | entra_conditional_access_policy | guests_excluded True->False | Medium | Yes | Medium | Yes | None | `test_guests_exclusion_removed_is_medium` | PASS |
| DR | Sign-in frequency loosened | entra_conditional_access_policy | short->extended | Medium | Yes | Medium | Yes | None | `TestSessionControlChanges::test_sign_in_frequency_loosened_is_medium` | PASS |
| DS | Sign-in frequency tightened | entra_conditional_access_policy | extended->short | Low | Yes | Low | Yes | None | `test_sign_in_frequency_tightened_is_low` | PASS |
| DT | Sign-in frequency unknown transition never High | entra_conditional_access_policy | short->unknown | never High | Yes | Low | Yes | None | `test_unknown_sign_in_frequency_transition_never_high` | PASS |
| DU | CAE loosened | entra_conditional_access_policy | strict_enforcement->disabled | Medium | Yes | Medium | Yes | None | `test_cae_loosened_is_medium` | PASS |
| DV | Phishing-resistant -> ordinary MFA | entra_authentication_strength | phishing_resistant->not_phishing_resistant | High | Yes | High | Yes | None | `TestAuthenticationStrengthChanges::test_phishing_resistant_to_ordinary_mfa_is_high` | PASS |
| DW | Ordinary MFA -> phishing-resistant | entra_authentication_strength | not_phishing_resistant->phishing_resistant | Low | Yes | Low | Yes | None | `test_ordinary_mfa_to_phishing_resistant_is_low` | PASS |
| DX | Passwordless -> ordinary MFA | entra_authentication_strength | passwordless->not_passwordless | Medium | Yes | Medium | Yes | None | `test_passwordless_to_ordinary_mfa_is_medium` | PASS |
| DY | Combination count change | entra_authentication_strength | count 2->3 | Low | Yes | Low | Yes | None | `test_combination_count_change_is_low` | PASS |
| DZ | Strength renamed, same ID | entra_authentication_strength | display_name changed | Low | Yes | Low | Yes | None | `test_renamed_same_id_is_low` | PASS |
| EA | Custom strength added | entra_authentication_strength | added, kind_category=custom | Low | n/a | Low | Yes | None | `test_custom_strength_added_is_low` | PASS |
| EB | Phishing-resistant strength removed | entra_authentication_strength | removed, phishing_resistant | Medium (not confirmed in-use) | n/a | Medium | Yes | None | `test_phishing_resistant_strength_removed_is_medium` | PASS |
| EC | Unknown phishing-resistance transition never High | entra_authentication_strength | phishing_resistant->unknown | never High | Yes | Medium | Yes | None | `test_unknown_phishing_resistance_transition_never_high` | PASS |
| ED | FIDO2 disabled | entra_authentication_method | state enabled->disabled, fido2 | Medium (not "no MFA" claim) | Yes | Medium | Yes | None | `TestAuthenticationMethodChanges::test_fido2_disabled_is_medium` | PASS |
| EE | FIDO2 enabled | entra_authentication_method | disabled->enabled, fido2 | Low | Yes | Low | Yes | None | `test_fido2_enabled_is_low` | PASS |
| EF | SMS enabled | entra_authentication_method | disabled->enabled, sms | Medium (weak method enabled) | Yes | Medium | Yes | None | `test_sms_enabled_is_medium` | PASS |
| EG | SMS disabled | entra_authentication_method | enabled->disabled, sms | Low (improvement) | Yes | Low | Yes | None | `test_sms_disabled_is_low` | PASS |
| EH | Voice enabled | entra_authentication_method | disabled->enabled, voice | Medium | Yes | Medium | Yes | None | `test_voice_enabled_is_medium` | PASS |
| EI | Microsoft Authenticator enabled | entra_authentication_method | disabled->enabled | Medium | Yes | Medium | Yes | None | `test_microsoft_authenticator_enabled_is_medium` | PASS |
| EJ | Temporary Access Pass enabled | entra_authentication_method | disabled->enabled | Medium | Yes | Medium | Yes | None | `test_temporary_access_pass_enabled_is_medium` | PASS |
| EK | Certificate-based auth disabled | entra_authentication_method | enabled->disabled | Medium | Yes | Medium | Yes | None | `test_certificate_based_auth_disabled_is_medium` | PASS |
| EL | Unknown method state never High | entra_authentication_method | enabled->unknown | Medium (never High) | Yes | Medium | Yes | None | `test_unknown_method_state_is_medium_never_high` | PASS |
| EM | Method targeting broadened | entra_authentication_method | selected_groups->all_users | Medium | Yes | Medium | Yes | None | `test_method_targeting_broadened_is_medium` | PASS |
| EN | Method targeting narrowed | entra_authentication_method | all_users->selected_groups | Low | Yes | Low | Yes | None | `test_method_targeting_narrowed_is_low` | PASS |
| EO | Single method disabled never claims tenant-wide MFA loss | entra_authentication_method | fido2 enabled->disabled | reason text scoped to one method | n/a | Medium | Yes | None | `test_single_method_disabled_never_claims_no_mfa_tenant_wide` | PASS |
| EP | Method added | entra_authentication_method | added | Low | n/a | Low | Yes | None | `test_method_added_is_low` | PASS |
| EQ | Method removed | entra_authentication_method | removed | Low | n/a | Low | Yes | None | `test_method_removed_is_low` | PASS |
| ER | CA policy provider_metadata has tenant/policy id | entra_conditional_access_policy | any field change | metadata.policy_id, tenant_id present | n/a | n/a | Yes | None | `TestProviderMetadata::test_ca_policy_metadata_has_tenant_and_policy_id` | PASS |
| ES | Strength provider_metadata has strength id | entra_authentication_strength | any field change | metadata.strength_id present | n/a | n/a | Yes | None | `test_strength_metadata_has_strength_id` | PASS |
| ET | Method provider_metadata has config id + type | entra_authentication_method | any field change | metadata.method_config_id, method_type_category present | n/a | n/a | Yes | None | `test_method_metadata_has_method_config_id_and_type` | PASS |
| EU | Provider metadata never contains raw conditions/grantControls | entra_conditional_access_policy | any field change | no "conditions"/"grantControls" keys in metadata | n/a | n/a | Critical if violated | `test_provider_metadata_never_contains_raw_conditions` | PASS |
| EV | CA policy collected single page | entra_conditional_access_policy | 2 policies, one page | both collected, FAMILY_COMPLETE | n/a | n/a | Yes | None | `TestConditionalAccessPolicyCollection::test_collects_all_policies_single_page` | PASS |
| EW | CA policy collected across pages | entra_conditional_access_policy | @odata.nextLink pagination | both pages collected | n/a | n/a | Yes | None | `test_collects_policies_across_multiple_pages` | PASS |
| EX | CA policy dedup within a page | entra_conditional_access_policy | duplicate id in one page | single record | n/a | n/a | Yes | None | `test_dedups_repeated_policy_id_within_a_page` | PASS |
| EY | CA policy family denied (403) | entra_conditional_access_policy | 403 on first page | FAMILY_DENIED, other families unaffected | n/a | n/a | Yes | None | `test_denied_ca_family_reports_denied_completeness_and_does_not_abort` | PASS |
| EZ | CA policy pagination truncated by later-page failure | entra_conditional_access_policy | page 2 5xx after retries exhausted | FAMILY_PARTIAL | n/a | n/a | Yes | None | `test_ca_policy_truncated_pagination_is_partial` | PASS |
| FA | Authentication strengths collected | entra_authentication_strength | 2 strengths | both collected | n/a | n/a | Yes | None | `TestAuthenticationStrengthCollection::test_collects_all_strengths` | PASS |
| FB | Strength family denied, others unaffected | entra_authentication_strength | 403 | FAMILY_DENIED; CA/method families still complete | n/a | n/a | Yes | None | `test_denied_strength_family_reports_denied_and_does_not_abort` | PASS |
| FC | Authentication method configs collected | entra_authentication_method | 2 configs | both collected | n/a | n/a | Yes | None | `TestAuthenticationMethodCollection::test_collects_all_method_configurations` | PASS |
| FD | Method collection uses nested list endpoint, not singleton | entra_authentication_method | authenticationMethodConfigurations endpoint hit; singleton only probed once | confirms no singleton-array parsing | n/a | n/a | Yes | None | `test_uses_nested_collection_endpoint_not_singleton` | PASS |
| FE | Method family denied, others unaffected | entra_authentication_method | 403 | FAMILY_DENIED; CA/strength families still complete | n/a | n/a | Yes | None | `test_denied_method_family_reports_denied_and_does_not_abort` | PASS |
| FF | All three new families independent | entra_* (all 3) | CA ok, strength denied, method ok | each family's completeness independent | n/a | n/a | Yes | None | `TestFamilyIndependence::test_all_three_new_families_independent_of_each_other_and_prior_families` | PASS |
| FG | Deterministic ordering includes new record types | entra_conditional_access_policy | unsorted API response order | sorted by (record_type, record_id) | n/a | n/a | Yes | None | `test_deterministic_ordering_includes_new_record_types` | PASS |
| FH | Scale: 500 CA policies | entra_conditional_access_policy | 500 policies, single page | all 500 collected, FAMILY_COMPLETE | n/a | n/a | Yes | None | `TestScale::test_many_conditional_access_policies_collected` | PASS |

**Total cases: 137** (A through FH). All PASS as of this message's test run.
