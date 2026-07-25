# Okta Authentication Policy Matrix (Okta message 4 of 8)

Columns: **Case**, **Record type**, **Source state**, **Normalized posture**, **Diff tracked?**, **Change severity**, **Unknown-safe?**, **Sensitive-data risk**, **Test coverage**, **Status**, **Notes**.

| # | Case | Record type | Source state | Normalized posture | Diff tracked? | Change severity | Unknown-safe? | Sensitive-data risk | Test coverage | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|
| A | OKTA_SIGN_ON type | okta_policy | `type=OKTA_SIGN_ON` | `policy_type=okta_sign_on` | Yes | n/a | Yes | None | `TestPolicyTypeTaxonomy::test_every_known_type` | PASS | |
| B | PASSWORD type | okta_policy | `type=PASSWORD` | `policy_type=password` | Yes | n/a | Yes | None | same (parametrized) | PASS | |
| C | MFA_ENROLL type | okta_policy | `type=MFA_ENROLL` | `policy_type=mfa_enroll` | Yes | n/a | Yes | None | same | PASS | |
| D | ACCESS_POLICY type | okta_policy | `type=ACCESS_POLICY` | `policy_type=access_policy` | Yes | n/a | Yes | None | same | PASS | |
| E | PROFILE_ENROLLMENT type | okta_policy | `type=PROFILE_ENROLLMENT` | `policy_type=profile_enrollment` | Yes | n/a | Yes | None | same | PASS | |
| F | IDP_DISCOVERY type | okta_policy | `type=IDP_DISCOVERY` | `policy_type=idp_discovery` | Yes | n/a | Yes | None | same | PASS | |
| G | unknown policy type | okta_policy | `type="SOME_FUTURE_TYPE"` | `policy_type=unknown` | Yes | n/a | Yes — never fabricated | None | `test_unknown_policy_type` | PASS | Never guesses a known type |
| H | null policy type | okta_policy | `type=None` | `policy_type=unknown` | Yes | n/a | Yes | None | `test_none_policy_type` | PASS | |
| I | unknown type has no password fields | okta_policy | `type="SOME_FUTURE_TYPE"` | `password_min_length` key absent | n/a | n/a | Yes | None | `test_unknown_type_not_fabricated_password_fields` | PASS | Password posture only merged for `PASSWORD` type |
| J | policy renamed same ID | okta_policy | `name` changes, `id` unchanged | modification, not add+remove | Yes (`policy_name`) | Low | n/a | None | `TestPolicyRename::test_policy_renamed_same_id` | PASS | Stable `record_id = tenant_id+policy_id` |
| K | policy activated (status field) | okta_policy | `status=ACTIVE` | `active=True` | Yes | n/a | Yes | None | `test_policy_activated` | PASS | |
| L | policy deactivated (status field) | okta_policy | `status=INACTIVE` | `active=False` | Yes | n/a | Yes | None | `test_policy_deactivated` | PASS | |
| M | missing policy id | okta_policy | `id` absent | normalizer returns `None` | n/a | n/a | n/a | None | `test_missing_policy_id_returns_none` | PASS | |
| N | ALLOW access | okta_policy_rule | `actions.signon.access=ALLOW` | `access_category=ALLOW` | Yes | n/a | Yes | None | `TestAccessCategory::test_allow` | PASS | |
| O | DENY access | okta_policy_rule | `actions.signon.access=DENY` | `access_category=DENY` | Yes | n/a | Yes | None | `test_deny` | PASS | |
| P | unrecognized access | okta_policy_rule | `access="SOMETHING_NEW"` | `access_category=unknown` | Yes | n/a | Yes | None | `test_unknown` | PASS | |
| Q | null access | okta_policy_rule | `access=None` | `access_category=unknown` | Yes | n/a | Yes | None | `test_none` | PASS | |
| R | MFA required every sign-in | okta_policy_rule | `requireFactor=True, factorPromptMode=ALWAYS` | `mfa_requirement_category=required_every_signin` | Yes | n/a | Yes | None | `TestMfaRequirementTaxonomy::test_mfa_required_every_signin` | PASS | |
| S | MFA required per session | okta_policy_rule | `requireFactor=True, factorPromptMode=SESSION` | `mfa_requirement_category=required_per_session` | Yes | n/a | Yes | None | `test_mfa_required_per_session` | PASS | |
| T | MFA required per device | okta_policy_rule | `requireFactor=True, factorPromptMode=DEVICE` | `mfa_requirement_category=required_per_session` | Yes | n/a | Yes | None | `test_mfa_required_per_device` | PASS | Device-scoped prompt collapses to per-session |
| U | MFA required, no prompt mode | okta_policy_rule | `requireFactor=True`, no `factorPromptMode` | `mfa_requirement_category=required` | Yes | n/a | Yes | None | `test_mfa_required_no_prompt_mode` | PASS | |
| V | MFA none | okta_policy_rule | `requireFactor=False` | `mfa_requirement_category=none` | Yes | n/a | Yes | None | `test_mfa_none` | PASS | |
| W | MFA unknown, requireFactor absent | okta_policy_rule | `signon={}` | `mfa_requirement_category=unknown` | Yes | n/a | Yes — never becomes `none` | None | `test_mfa_unknown_when_require_factor_absent` | PASS | |
| X | MFA unknown, signon absent | okta_policy_rule | `actions={}` | `mfa_requirement_category=unknown` | Yes | n/a | Yes | None | `test_mfa_unknown_when_signon_absent` | PASS | |
| Y | MFA unknown, non-bool requireFactor | okta_policy_rule | `requireFactor="yes"` | `mfa_requirement_category=unknown` | Yes | n/a | Yes — malformed never coerced | None | `test_mfa_unknown_when_require_factor_not_bool` | PASS | |
| Z | verification method 2FA | okta_policy_rule | `factorMode=2FA` | `mfa_requirement_category=required` | Yes | n/a | Yes | None | `TestMfaRequirementTaxonomy::test_verification_method_2fa` | PASS | Modern Identity Engine shape |
| AA | verification method 1FA | okta_policy_rule | `factorMode=1FA` | `mfa_requirement_category=none` | Yes | n/a | Yes | None | `test_verification_method_1fa` | PASS | |
| AB | verification method unknown mode | okta_policy_rule | `factorMode="3FA"` | `mfa_requirement_category=unknown` | Yes | n/a | Yes | None | `test_verification_method_unknown` | PASS | |
| AC | verification method absent | okta_policy_rule | `{}` | `mfa_requirement_category=unknown` | Yes | n/a | Yes | None | `test_verification_method_unknown` (2nd assertion) | PASS | |
| AD | full-rule ALLOW normalization | okta_policy_rule | classic signon shape, `access=ALLOW` | `access_category=ALLOW` | Yes | n/a | Yes | None | `TestSignOnRuleFullNormalization::test_allow` | PASS | |
| AE | full-rule DENY normalization | okta_policy_rule | classic signon shape, `access=DENY` | `access_category=DENY` | Yes | n/a | Yes | None | `test_deny` | PASS | |
| AF | full-rule MFA required | okta_policy_rule | classic shape, `requireFactor=True` | `mfa_requirement_category=required` | Yes | n/a | Yes | None | `test_mfa_required` | PASS | |
| AG | full-rule MFA none | okta_policy_rule | classic shape, `requireFactor=False` | `mfa_requirement_category=none` | Yes | n/a | Yes | None | `test_mfa_none` | PASS | |
| AH | possession+knowledge from modern shape | okta_policy_rule | `appSignOn.verificationMethod` with `constraints[0].possession/knowledge` | `possession_required=True`, `knowledge_required=True`, `required_factor_count=2` | Yes | n/a | Yes | None | `test_possession_and_knowledge_from_verification_method` | PASS | Classic shape falls back to modern shape only when undeterminable |
| AI | phishing-resistant required (rule) | okta_policy_rule | `possession.phishingResistant=REQUIRED` | `phishing_resistant_category=phishing_resistant` | Yes | n/a | Yes | None | `test_phishing_resistant_required` | PASS | |
| AJ | password min length strong | okta_policy (PASSWORD) | `minLength=14` | `password_min_length_category=strong` | Yes (via `password_min_length`) | n/a | Yes | None | `TestPasswordPosture::test_minimum_length_strong` | PASS | 14 = CIS "strong" tier |
| AK | password min length weak | okta_policy (PASSWORD) | `minLength=6` | `password_min_length_category=weak` | Yes | n/a | Yes | None | `test_minimum_length_weak` | PASS | |
| AL | boundary 7 vs 8 | okta_policy (PASSWORD) | `minLength=7` then `8` | `weak` then `baseline` | Yes | Medium if decrease, Low if increase | Yes | None | `test_minimum_reduced` | PASS | 8 = Okta's own historical default |
| AM | boundary 13 vs 14 | okta_policy (PASSWORD) | `minLength=13` then `14` | `baseline` then `strong` | Yes | Low (increase) | Yes | None | `test_minimum_increased_boundary` | PASS | |
| AN | password history present | okta_policy (PASSWORD) | `historyCount=4` | `password_history_present=True`, `password_history_count=4` | Yes | True=Low, False=Medium | Yes | Count only, no history contents | `test_history_present` | PASS | |
| AO | password history absent | okta_policy (PASSWORD) | `historyCount=0` | `password_history_present=False` | Yes | Medium (removed) | Yes | None | `test_history_absent` | PASS | |
| AP | password lockout present | okta_policy (PASSWORD) | `maxAttempts=5` | `password_lockout_present=True`, `password_lockout_max_attempts=5` | Yes | True=Low, False=Medium | Yes | None | `test_lockout_present` | PASS | |
| AQ | password lockout absent | okta_policy (PASSWORD) | `maxAttempts=0` | `password_lockout_present=False` | Yes | Medium (removed) | Yes | None | `test_lockout_absent` | PASS | |
| AR | password complexity present | okta_policy (PASSWORD) | complexity fields set | `password_complexity_required=True` | Yes | True=Low, False=Medium | Yes | None | `test_complexity_present` | PASS | |
| AS | password complexity missing | okta_policy (PASSWORD) | all complexity fields 0 | `password_complexity_required=False` | Yes | Medium (removed) | Yes | None | `test_complexity_missing` | PASS | |
| AT | password lifetime bounded | okta_policy (PASSWORD) | `maxAgeDays=90` | `password_lifetime_bounded=True` | Yes | True=Low, False=Medium | Yes | None | `test_password_lifetime_bounded` | PASS | |
| AU | password lifetime unbounded | okta_policy (PASSWORD) | `maxAgeDays=0` | `password_lifetime_bounded=False` | Yes | Medium | Yes | None | `test_password_lifetime_broad_unknown` | PASS | |
| AV | malformed numeric setting | okta_policy (PASSWORD) | `minLength="eight"` (string) | `password_min_length=None`, category=unknown | Yes | n/a | Yes — never coerced | None | `test_malformed_numeric_setting` | PASS | |
| AW | password fields only on PASSWORD type | okta_policy | `type=OKTA_SIGN_ON` | `password_min_length` key absent | n/a | n/a | Yes | None | `test_only_applies_to_password_type_policies` | PASS | |
| AX | password authenticator key | okta_authenticator | `key=password` | `AUTHENTICATOR_KEY_PASSWORD` | Yes | n/a | Yes | None | `TestAuthenticatorTaxonomy::test_every_known_key` | PASS | |
| AY | security_question key | okta_authenticator | `key=security_question` | `AUTHENTICATOR_KEY_SECURITY_QUESTION` | Yes | n/a | Yes | None | same (parametrized) | PASS | |
| AZ | email key | okta_authenticator | `key=email` | `AUTHENTICATOR_KEY_EMAIL` | Yes | n/a | Yes | None | same | PASS | |
| BA | phone_number key | okta_authenticator | `key=phone_number` | `AUTHENTICATOR_KEY_PHONE_NUMBER` | Yes | n/a | Yes | None | same | PASS | |
| BB | okta_verify key | okta_authenticator | `key=okta_verify` | `AUTHENTICATOR_KEY_OKTA_VERIFY` | Yes | n/a | Yes | None | same | PASS | |
| BC | webauthn key | okta_authenticator | `key=webauthn` | `AUTHENTICATOR_KEY_WEBAUTHN` | Yes | n/a | Yes | None | same | PASS | |
| BD | smart_card_idp key | okta_authenticator | `key=smart_card_idp` | `AUTHENTICATOR_KEY_SMART_CARD_IDP` | Yes | n/a | Yes | None | same | PASS | |
| BE | unknown authenticator key | okta_authenticator | `key="some_future_authenticator"` | `AUTHENTICATOR_KEY_UNKNOWN` | Yes | n/a | Yes — never guessed from name | None | `test_unknown_authenticator` | PASS | |
| BF | hardware-backed (security_key) | okta_authenticator | `type=security_key` | `hardware_backed_category=hardware_backed` | Yes | n/a | Yes | None | `test_security_key_type` | PASS | Regression test for the fixed `"true"`-literal bug |
| BG | WebAuthn phishing-resistant | okta_authenticator | `key=webauthn` | `phishing_resistance=phishing_resistant` | Yes | removed=Medium, added=Low | Yes | None | `TestPhishingResistance::test_webauthn_true` | PASS | |
| BH | smart card phishing-resistant | okta_authenticator | `key=smart_card_idp` | `phishing_resistance=phishing_resistant` | Yes | same | Yes | None | `test_smart_card_true` | PASS | |
| BI | SMS not phishing-resistant | okta_authenticator | `key=phone_number` | `not_phishing_resistant` (deterministic negative) | Yes | n/a | Yes | None | `test_sms_false` | PASS | |
| BJ | email not phishing-resistant | okta_authenticator | `key=email` | `not_phishing_resistant` | Yes | n/a | Yes | None | `test_email_false` | PASS | |
| BK | Okta Verify (TOTP-like) not phishing-resistant | okta_authenticator | `key=okta_verify` | `not_phishing_resistant` | Yes | n/a | Yes | None | `test_totp_like_false` | PASS | |
| BL | unknown authenticator phishing-resistance | okta_authenticator | `key=unknown` | `PHISHING_RESISTANCE_UNKNOWN` | Yes | Medium (never a known weakening) | Yes — never treated as false | None | `test_unknown_authenticator_unknown_resistance` | PASS | |
| BM | unknown never becomes false | okta_authenticator | `key="custom_app"` | resistance != `not_phishing_resistant` | n/a | n/a | Yes | None | `test_never_treats_unknown_as_false` | PASS | |
| BN | possession constraint REQUIRED | okta_policy_rule | `possession.phishingResistant=REQUIRED` | `phishing_resistant_category=phishing_resistant` | Yes | n/a | Yes | None | `test_from_possession_constraint_required` | PASS | |
| BO | possession constraint DISALLOWED | okta_policy_rule | `possession.phishingResistant=DISALLOWED` | `not_phishing_resistant` | Yes | n/a | Yes | None | `test_from_possession_constraint_disallowed` | PASS | |
| BP | possession constraint absent | okta_policy_rule | `possession=None`/`{}` | `PHISHING_RESISTANCE_UNKNOWN` | Yes | n/a | Yes | None | `test_from_possession_constraint_absent` | PASS | |
| BQ | password is knowledge factor | okta_authenticator | `key=password` | `is_knowledge_authenticator=True`, `is_possession_authenticator=False` | Yes | n/a | Yes | None | `TestFactorCategories::test_password_is_knowledge` | PASS | |
| BR | email is possession factor | okta_authenticator | `key=email` | `is_possession_authenticator=True`, `is_knowledge_authenticator=False` | Yes | n/a | Yes | None | `test_email_is_possession` | PASS | |
| BS | unknown authenticator factor category | okta_authenticator | `key=unknown` | both `is_knowledge_authenticator`/`is_possession_authenticator=None` | Yes | n/a | Yes | None | `test_unknown_authenticator_both_none` | PASS | |
| BT | inherence factor always unknown | okta_authenticator | any authenticator | `inherence_factor=None` | Never tracked (always constant) | n/a | Yes — permanently unfabricated | None | `TestFactorCategories::test_inherence_always_none_never_fabricated` | PASS | Okta's API exposes no distinct biometric authenticator type |
| BU | policies collected across all 6 types | okta_policy (family) | 6 policy types, one page each | 6 records, each type queried with explicit `type` param | n/a | n/a | n/a | None | `TestPolicyCollection::test_collects_policies_across_all_types` | PASS | No "list all policies" endpoint exists |
| BV | each type queried with explicit param | okta_policy (family) | route call-count assertions | 6 distinct `type=` query calls | n/a | n/a | n/a | None | `test_each_policy_type_queried_with_explicit_type_param` | PASS | |
| BW | multi-page policy collection | okta_policy (family) | 2 Link-paginated pages per type | all pages collected | n/a | n/a | n/a | None | `test_collects_policies_across_multiple_pages` | PASS | |
| BX | rules collected per policy | okta_policy_rule (family) | `/policies/{id}/rules` per policy | one `okta_policy_rule` per rule | n/a | n/a | n/a | None | `TestRuleCollection::test_rules_collected_per_policy` | PASS | |
| BY | policies collected once, not refetched for rules | okta_policy_rule (family) | policy list + per-policy rule walk | policy list endpoint hit exactly once | n/a | n/a | n/a | None | `test_policies_collected_once_not_refetched_for_rules` | PASS | route `call_count` assertion |
| BZ | policy with zero rules | okta_policy_rule (family) | `rules=[]` | `rule_count=0` (real zero, not unknown) | n/a | n/a | Yes | None | `test_policy_with_zero_rules` | PASS | |
| CA | no policies at all is complete not denied | okta_policy (family) | empty policy list, 200 OK | `family_completeness.policies=complete` | n/a | n/a | Yes | None | `test_no_policies_at_all_is_complete_not_denied` | PASS | Empty != denied |
| CB | all authenticators collected | okta_authenticator (family) | `/api/v1/authenticators`, no `limit` param | all records collected | n/a | n/a | n/a | None | `TestAuthenticatorCollection::test_collects_all_authenticators` | PASS | Matches message-1 probe convention (no pagination param) |
| CC | policies available, rules denied, authenticators available | okta (family independence) | mixed per-family outcomes | `rule_count=None` (never fabricated as 0) | n/a | n/a | Yes | None | `TestFamilyIndependence::test_policies_available_rules_denied_authenticators_available` | PASS | |
| CD | full denial doesn't crash whole fetch | okta (family independence) | policies/rules/authenticators all denied | `fetch()` completes, empty families | n/a | n/a | Yes | None | `test_sync_does_not_fail_entirely_on_full_denial` | PASS | |
| CE | rule dedup within a policy | okta_policy_rule | overlapping Link pages re-serve a rule | single record after dedup | n/a | n/a | n/a | None | `TestDedupAndStableIds::test_rule_dedup_within_a_policy` | PASS | |
| CF | stable record IDs (all 3 new types) | okta_policy / okta_policy_rule / okta_authenticator | re-fetch with same source IDs | identical `record_id`s across fetches | n/a | n/a | n/a | None | `test_stable_record_ids_prefer_tenant_plus_okta_id` | PASS | `tenant_id+policy_id`, `+rule_id`, `+authenticator_id` |
| CG | repeated Link stops pagination | okta_policy (family) | Link header repeats same URL | pagination halts, no infinite loop | n/a | n/a | n/a | None | `TestPaginationEdgeCases::test_repeated_link_stops_pagination` | PASS | |
| CH | cross-origin Link rejected | okta_policy (family) | Link header points to a different origin | link not followed | n/a | n/a | n/a | None | `test_cross_origin_link_rejected` | PASS | Reuses message-1 same-origin enforcement |
| CI | partial second page still returns first-page results | okta_policy (family) | second page fails mid-fetch | first-page records still returned | n/a | n/a | Yes | None | `test_partial_second_page_still_returns_first_page_results` | PASS | |
| CJ | group targeting scope | okta_policy_rule | `conditions.people.groups.include=[g1,g2]` | `scope_category=scoped_groups`, `group_include_count=2` | Yes (`scope_category` only) | Low | Yes | Counts only, no group IDs | `TestScopeCategorization::test_scoped_group_target_full_normalization` | PASS | |
| CK | user targeting scope | okta_policy_rule | `conditions.people.users.include=[u1,u2]` | `scope_category=scoped_users` | Yes | Low | Yes | Counts only | `test_scoped_users` (unit) | PASS | |
| CL | all-users targeting scope | okta_policy_rule | no group/user includes | `scope_category=all_users` | Yes | Low | Yes | None | `test_broad_target_full_normalization` | PASS | |
| CM | scope unknown | okta_policy_rule | both counts `None` (conditions absent/malformed) | `scope_category=unknown` | Yes | n/a | Yes | None | `test_unknown_when_both_none` | PASS | |
| CN | group exclusion targeting | okta_policy_rule | `groups.exclude=[g2,g3]` | `group_exclude_count=2` | No (targeting detail, not tracked — `scope_category` is) | n/a | Yes | Counts only | `test_exclusion_target` | PASS | |
| CO | group IDs never persisted | okta_policy_rule | `groups.include=["super-secret-group-id"]` | raw group ID absent from record | n/a | n/a | n/a | Excluded — verified | `test_group_ids_never_stored_only_counts` | PASS | |
| CP | session lifetime very_short | okta_policy_rule | `maxSessionLifetimeMinutes=30` | `session_lifetime_category=very_short` | Yes | Low | Yes | None | `TestSessionLifetimeCategorization::test_very_short` | PASS | |
| CQ | session lifetime short | okta_policy_rule | `120` min | `short` | Yes | Low | Yes | None | `test_short` | PASS | |
| CR | session lifetime standard | okta_policy_rule | `48h` | `standard` | Yes | Low | Yes | None | `test_standard` | PASS | |
| CS | session lifetime extended | okta_policy_rule | `365d` | `extended` | Yes | Low | Yes | None | `test_extended` | PASS | Reuses Auth0's `_session_category` threshold philosophy |
| CT | session lifetime unknown (None) | okta_policy_rule | `maxSessionLifetimeMinutes=None` | `unknown` | Yes | n/a | Yes | None | `test_unknown_when_none` | PASS | |
| CU | session lifetime unknown (negative) | okta_policy_rule | `-1` | `unknown` | Yes | n/a | Yes — malformed never coerced | None | `test_unknown_when_negative` | PASS | |
| CV | session lifetime bool rejected | okta_policy_rule | `True` (bool, not int) | `unknown` | Yes | n/a | Yes | None | `test_unknown_when_bool` | PASS | `bool` is a subtype of `int` in Python — explicitly excluded |
| CW | ISO8601 duration hours | okta_policy_rule | `reauthenticateIn="PT2H"` | `120` minutes | via `re_authentication_category` | n/a | Yes | None | `TestIso8601DurationParsing::test_hours` | PASS | |
| CX | ISO8601 duration minutes | okta_policy_rule | `"PT30M"` | `30` minutes | via `re_authentication_category` | n/a | Yes | None | `test_minutes` | PASS | |
| CY | ISO8601 duration days | okta_policy_rule | `"P1D"` | `1440` minutes | via `re_authentication_category` | n/a | Yes | None | `test_days` | PASS | |
| CZ | ISO8601 unparseable | okta_policy_rule | `"garbage"` | `None` | n/a | n/a | Yes — never guessed | None | `test_unparseable` | PASS | |
| DA | ISO8601 null/empty | okta_policy_rule | `None` / `""` | `None` | n/a | n/a | Yes | None | `test_none`, `test_empty_string` | PASS | |
| DB | required factor count decrease | okta_policy_rule | `2 -> 1` | Medium | Yes | Medium | n/a | None | `TestFactorCountAndAssuranceTransitions::test_factor_count_decrease_is_medium` | PASS | Real `compute_diff()`/`classify_okta_change()` |
| DC | required factor count increase | okta_policy_rule | `1 -> 2` | Low | Yes | Low | n/a | None | `test_factor_count_increase_is_low` | PASS | |
| DD | possession requirement removed | okta_policy_rule | `True -> False` | Medium | Yes | Medium | n/a | None | `test_possession_required_removed_is_medium` | PASS | |
| DE | possession requirement -> unknown | okta_policy_rule | `True -> None` | Low, not High | Yes | Low | Yes — unknown never a known weakening | None | `test_possession_required_to_unknown_is_low_not_high` | PASS | |
| DF | knowledge requirement removed | okta_policy_rule | `True -> False` | Medium | Yes | Medium | n/a | None | `test_knowledge_required_removed_is_medium` | PASS | |
| DG | device-bound requirement removed | okta_policy_rule | `True -> False` | Medium | Yes | Medium | n/a | None | `test_device_bound_removed_is_medium` | PASS | |
| DH | rule added | okta_policy_rule | new record | `change_type=added` | n/a | Low | n/a | None | `TestRuleAddedRemoved::test_rule_added_is_low` | PASS | |
| DI | rule removed | okta_policy_rule | record absent | `change_type=removed` | n/a | Medium | n/a | None | `test_rule_removed_is_medium` | PASS | Does not by itself confirm deletion |
| DJ | rule deactivated | okta_policy_rule | `status: ACTIVE -> INACTIVE` | Medium | Yes | Medium | n/a | None | `test_rule_status_deactivated_is_medium` | PASS | Conservative — full effective-policy resolution deferred |
| DK | rule priority change | okta_policy_rule | `priority: 5 -> 1` | Medium | Yes | Medium | n/a | None | `test_rule_priority_change_is_medium` | PASS | First-match order can broaden/narrow access |
| DL | MFA required -> none is High | okta_policy_rule | `mfa_requirement_category: required -> none` | High | Yes | High | n/a | None | `TestMfaRequirementTransitions::test_required_to_none_is_high` | PASS | Explicit weakening — MFA no longer required |
| DM | MFA required_every_signin -> none is High | okta_policy_rule | same, from a stronger start state | High | Yes | High | n/a | None | `test_required_every_signin_to_none_is_high` | PASS | |
| DN | MFA required -> optional is Medium | okta_policy_rule | rank decrease, not to none | Medium | Yes | Medium | n/a | None | `test_required_to_optional_is_medium` | PASS | |
| DO | MFA optional -> required is Low | okta_policy_rule | rank increase | Low | Yes | Low | n/a | None | `test_optional_to_required_is_low` | PASS | |
| DP | MFA none -> required is Low | okta_policy_rule | rank increase from none | Low | Yes | Low | n/a | None | `test_none_to_required_is_low` | PASS | |
| DQ | MFA -> unknown is Medium, not ignored | okta_policy_rule | `required -> unknown` | Medium | Yes | Medium | Yes — unknown surfaced, not silently dropped | None | `test_unknown_new_value_is_medium_not_ignored` | PASS | |
| DR | MFA required_per_session -> step_up is Low | okta_policy_rule | rank tie/increase | Low | Yes | Low | n/a | None | `test_required_per_session_to_step_up_is_low` | PASS | |
| DS | DENY -> ALLOW is High | okta_policy_rule | `access_category: DENY -> ALLOW` | High | Yes | High | n/a | None | `TestAccessCategoryTransitions::test_deny_to_allow_is_high` | PASS | Broadens access explicitly |
| DT | ALLOW -> DENY is Low | okta_policy_rule | `access_category: ALLOW -> DENY` | Low | Yes | Low | n/a | None | `test_allow_to_deny_is_low` | PASS | |
| DU | access -> unknown is Medium | okta_policy_rule | `ALLOW -> unknown` | Medium | Yes | Medium | Yes | None | `test_unknown_access_transition_is_medium` | PASS | |
| DV | phishing-resistant requirement removed is High | okta_policy_rule | `phishing_resistant -> not_phishing_resistant` | High | Yes | High | n/a | None | `TestPhishingResistanceTransitions::test_required_removed_is_high` | PASS | |
| DW | phishing-resistant requirement added is Low | okta_policy_rule | `not_phishing_resistant -> phishing_resistant` | Low | Yes | Low | n/a | None | `test_added_is_low` | PASS | |
| DX | phishing-resistant -> unknown is Medium, not High | okta_policy_rule | `phishing_resistant -> unknown` | Medium | Yes | Medium | Yes — unknown never treated as "removed" | None | `test_to_unknown_is_medium_not_ignored` | PASS | Bug found+fixed: unknown-check now runs before the removed-check |
| DY | policy activated is Medium | okta_policy | `status: INACTIVE -> ACTIVE` | Medium | Yes | Medium | n/a | None | `TestPolicyActivation::test_inactive_to_active_is_medium` | PASS | Both directions conservative — effective-policy resolution deferred to a later message |
| DZ | policy deactivated is Medium | okta_policy | `status: ACTIVE -> INACTIVE` | Medium | Yes | Medium | n/a | None | `test_active_to_inactive_is_medium` | PASS | |
| EA | policy unknown status is Medium | okta_policy | `status="SOME_FUTURE_STATUS"` | Medium | Yes | Medium | Yes | None | `test_unknown_new_status_is_medium` | PASS | |
| EB | policy priority change is Medium | okta_policy | `priority: 3 -> 1` | Medium | Yes | Medium | n/a | None | `test_priority_change_is_medium` | PASS | |
| EC | policy added is Low | okta_policy | new record | `change_type=added` | n/a | Low | n/a | None | `TestPolicyAddedRemoved::test_policy_added` | PASS | |
| ED | policy removed is Medium | okta_policy | record absent | `change_type=removed` | n/a | Medium | n/a | None | `test_policy_removed` | PASS | Does not by itself confirm a protective control is gone |
| EE | password min length reduced is Medium | okta_policy | `14 -> 8` | Medium | Yes | Medium | n/a | None | `TestPasswordPostureTransitions::test_min_length_reduced_is_medium` | PASS | Directional only — matches AWS/Supabase precedent |
| EF | password min length increased is Low | okta_policy | `8 -> 14` | Low | Yes | Low | n/a | None | `test_min_length_increased_is_low` | PASS | |
| EG | password complexity removed is Medium | okta_policy | `True -> False` | Medium | Yes | Medium | n/a | None | `test_complexity_removed_is_medium` | PASS | |
| EH | password complexity added is Low | okta_policy | `False -> True` | Low | Yes | Low | n/a | None | `test_complexity_added_is_low` | PASS | |
| EI | password history removed is Medium | okta_policy | `True -> False` | Medium | Yes | Medium | n/a | None | `test_history_removed_is_medium` | PASS | |
| EJ | password lockout removed is Medium | okta_policy | `True -> False` | Medium | Yes | Medium | n/a | None | `test_lockout_removed_is_medium` | PASS | |
| EK | lockout max-attempts loosened is Medium | okta_policy | `3 -> 10` | Medium | Yes | Medium | n/a | None | `test_lockout_max_attempts_loosened_is_medium` | PASS | |
| EL | lockout max-attempts tightened is Low | okta_policy | `10 -> 3` | Low | Yes | Low | n/a | None | `test_lockout_max_attempts_tightened_is_low` | PASS | |
| EM | password lifetime unbounded is Medium | okta_policy | `bounded: True -> False` | Medium | Yes | Medium | n/a | None | `test_lifetime_unbounded_is_medium` | PASS | |
| EN | authenticator added is Low | okta_authenticator | new record | `change_type=added` | n/a | Low | n/a | None | `TestAuthenticatorTransitions::test_authenticator_added_is_low` | PASS | |
| EO | authenticator removed is Medium | okta_authenticator | record absent | `change_type=removed` | n/a | Medium | n/a | None | `test_authenticator_removed_is_medium` | PASS | Never assumes MFA globally disabled |
| EP | ordinary authenticator deactivated is Low | okta_authenticator | `status: ACTIVE -> INACTIVE`, not phishing-resistant | Low | Yes | Low | n/a | None | `test_ordinary_authenticator_deactivated_is_low` | PASS | |
| EQ | phishing-resistant authenticator deactivated is Medium | okta_authenticator | same transition, `phishing_resistant_category=phishing_resistant` | Medium | Yes | Medium | n/a | None | `test_phishing_resistant_authenticator_deactivated_is_medium` | PASS | Bug found+fixed: provider_metadata now carries `phishing_resistant_category` so this branch is reachable |
| ER | authenticator activated is Low | okta_authenticator | `status: INACTIVE -> ACTIVE` | Low | Yes | Low | n/a | None | `test_authenticator_activated_is_low` | PASS | |
| ES | authenticator phishing-resistance lost is Medium | okta_authenticator | `phishing_resistant -> not_phishing_resistant` | Medium | Yes | Medium | n/a | None | `test_authenticator_phishing_resistance_lost_is_medium` | PASS | |
| ET | policy provider metadata | okta_policy | any tracked-field change | `tenant_id`, `policy_id`, `policy_name`, `policy_type` present | n/a | n/a | n/a | Excluded — verified | `TestProviderMetadata::test_policy_provider_metadata` | PASS | |
| EU | rule provider metadata | okta_policy_rule | added | `policy_id`, `rule_id`, `rule_name` present | n/a | n/a | n/a | Excluded — verified | `test_rule_provider_metadata` | PASS | |
| EV | authenticator provider metadata | okta_authenticator | added | `authenticator_id`, `key` present | n/a | n/a | n/a | Excluded — verified | `test_authenticator_provider_metadata` | PASS | |
| EW | provider metadata never includes secrets | okta_authenticator | added | `settings`/`otp`/`sharedSecret` absent from metadata | n/a | n/a | n/a | Excluded — verified | `test_provider_metadata_never_includes_secrets` | PASS | |
| EX | creation timestamp not tracked (policy) | okta_policy | `created`/`lastUpdated` differ | no Change emitted | No (deliberately) | n/a | n/a | None | `TestIgnoredTimestamps::test_creation_timestamp_not_tracked_for_policy` | PASS | |
| EY | targeting detail not tracked (rule) | okta_policy_rule | `network_zone_category`/group/user counts differ | no Change from these fields alone | No (deliberately — `scope_category` is tracked instead) | n/a | n/a | None | `test_targeting_detail_counts_not_tracked_for_rule` | PASS | Avoids noisy per-ID targeting churn |
| EZ | inherence_factor not tracked (authenticator) | okta_authenticator | always `None` | never diffed | No (deliberately — constant) | n/a | n/a | None | `test_inherence_factor_not_tracked_for_authenticator` | PASS | |
| FA | no change from untracked fields alone | okta_policy | only `created` differs | `compute_diff()` returns `[]` | n/a | n/a | n/a | None | `test_no_change_from_untracked_fields_alone` | PASS | |
| FB | unmapped policy subtype returns empty | okta_policy_totally_unknown_future_subtype | n/a | `_tracked_fields_for()` returns `()` | n/a | n/a | n/a | None | `test_unmapped_policy_subtype_returns_empty` | PASS | |
| FC | 200 policies / 2,000 rules / 50 authenticators | okta (scale) | 200 policies × 10 rules each + 50 authenticators | all records collected, unique `record_id`s, `elapsed < 30s` | n/a | n/a | n/a | None | `TestScale::test_200_policies_2000_rules_50_authenticators` | PASS | No Cartesian explosion, bounded per-policy rule calls |
| FD | OTP seed excluded | okta_authenticator | `settings.otpSeed="..."` in raw | absent from normalized record | n/a | n/a | n/a | Excluded — verified | `TestSensitiveDataExclusion::test_otp_seed_excluded` | PASS | |
| FE | password value excluded (rule conditions) | okta_policy_rule | `conditions.people.password="..."` | absent from normalized record | n/a | n/a | n/a | Excluded — verified | `test_password_excluded` | PASS | |
| FF | recovery codes excluded | okta_authenticator | `settings.recoveryCodes=[...]` | absent | n/a | n/a | n/a | Excluded — verified | `test_recovery_code_excluded` | PASS | |
| FG | private key excluded | okta_authenticator | `settings.privateKey="-----BEGIN..."` | absent | n/a | n/a | n/a | Excluded — verified | `test_private_key_excluded` | PASS | |
| FH | challenge/nonce data excluded | okta_policy_rule | `actions.signon.challenge={nonce:"..."}` | absent | n/a | n/a | n/a | Excluded — verified | `test_challenge_data_excluded` | PASS | |
| FI | raw condition map excluded | okta_policy_rule | `conditions.network.include=["nz_secret..."]` | `conditions` key absent from record entirely | n/a | n/a | n/a | Excluded — verified | `test_raw_condition_map_excluded` | PASS | Field-by-field allowlist, not wholesale copy |
| FJ | raw action map excluded | okta_policy_rule | `actions.signon.extraSecretField="..."` | `actions` key absent from record entirely | n/a | n/a | n/a | Excluded — verified | `test_raw_action_map_excluded` | PASS | |
| FK | phone number excluded | okta_authenticator | `settings.phoneNumber="+1555..."` | absent | n/a | n/a | n/a | Excluded — verified | `test_phone_excluded` | PASS | |
| FL | shared secret excluded | okta_authenticator | `settings.sharedSecret="..."` | absent | n/a | n/a | n/a | Excluded — verified | `test_shared_secret_excluded` | PASS | |
| FM | factor secret excluded | okta_authenticator | top-level `factorSecret="..."` | absent | n/a | n/a | n/a | Excluded — verified | `test_factor_secret_excluded` | PASS | |
| FN | password policy recovery/settings excluded | okta_policy | `settings.recovery={...}` | `settings`/`recovery` keys absent | n/a | n/a | n/a | Excluded — verified | `test_password_policy_never_stores_password_values` | PASS | |

**Total: 96 rows** (task requirement: ≥90).

## Category legend

- **Policy** (A–M): policy-type taxonomy, unknown-type discipline, rename/activation, missing-ID handling.
- **Sign-on rule** (N–AI): access/MFA taxonomy (classic + modern shapes), full-rule normalization.
- **Password** (AJ–AW): password-strength categorization, history/lockout/complexity/lifetime posture, malformed input.
- **Authenticator** (AX–BT): authenticator-key taxonomy, phishing-resistance mapping, factor categories, status.
- **Collection** (BU–CI): per-type policy collection, per-policy rule enumeration, authenticator collection, family independence, dedup, pagination edge cases.
- **Targeting/session/duration** (CJ–DA): scope categorization, session-lifetime bucketing, ISO8601 duration parsing.
- **Diff/classification** (DB–ES): real `compute_diff()` → `classify_okta_change()` for MFA/access/phishing-resistance/password/policy/rule/authenticator transitions, all via the actual risk-classification pipeline (no hand-built Change stand-ins).
- **Metadata/timestamps** (ET–FB): provider metadata correctness and secret-exclusion, ignored-timestamp discipline, untracked-field verification.
- **Scale** (FC): 200 policies / 2,000 rules / 50 authenticators.
- **Safety** (FD–FN): sensitive-data exclusion boundary (OTP seeds, passwords, recovery codes, private keys, challenge data, phone numbers, shared/factor secrets, raw condition/action maps).
