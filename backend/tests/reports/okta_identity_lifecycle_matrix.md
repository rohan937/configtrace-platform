# Okta Identity Lifecycle Matrix (Okta message 2 of 8)

Columns: **Case**, **Record type**, **Source state**, **Normalized posture**, **Diff tracked?**, **Change severity**, **Unknown-safe?**, **Sensitive-data risk**, **Test coverage**, **Status**, **Notes**.

| # | Case | Record type | Source state | Normalized posture | Diff tracked? | Change severity | Unknown-safe? | Sensitive-data risk | Test coverage | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|
| A | ACTIVE | okta_user | `status=ACTIVE` | `lifecycle_posture=active`, `active=True` | Yes (status, lifecycle_posture) | n/a (state, not transition) | Yes | None | `TestEveryLifecycleStatus` | PASS | |
| B | STAGED | okta_user | `status=STAGED` | `lifecycle_posture=pre_active`, `staged=True` | Yes | n/a | Yes | None | `TestEveryLifecycleStatus` | PASS | |
| C | PROVISIONED | okta_user | `status=PROVISIONED` | `lifecycle_posture=pre_active`, `provisioned=True` | Yes | n/a | Yes | None | `TestEveryLifecycleStatus` | PASS | STAGED and PROVISIONED both collapse to `pre_active` |
| D | RECOVERY | okta_user | `status=RECOVERY` | `lifecycle_posture=recovery`, `recovery=True` | Yes | n/a | Yes | None | `TestEveryLifecycleStatus` | PASS | |
| E | LOCKED_OUT | okta_user | `status=LOCKED_OUT` | `lifecycle_posture=locked`, `locked_out=True` | Yes | n/a | Yes | None | `TestEveryLifecycleStatus` | PASS | |
| F | PASSWORD_EXPIRED | okta_user | `status=PASSWORD_EXPIRED` | `lifecycle_posture=password_expired`, `password_expired=True` | Yes | n/a | Yes | None | `TestEveryLifecycleStatus` | PASS | |
| G | SUSPENDED | okta_user | `status=SUSPENDED` | `lifecycle_posture=suspended`, `suspended=True` | Yes | n/a | Yes | None | `TestEveryLifecycleStatus` | PASS | Never conflated with DEPROVISIONED |
| H | DEPROVISIONED | okta_user | `status=DEPROVISIONED` | `lifecycle_posture=deprovisioned`, `deprovisioned=True` | Yes | n/a | Yes | None | `TestEveryLifecycleStatus` | PASS | Never conflated with SUSPENDED |
| I | unknown status | okta_user | `status="SOME_FUTURE_STATUS"` | `status=UNKNOWN`, `lifecycle_posture=unknown`, all booleans False | Yes | Medium (on transition to unknown) | Yes — never coerced to active | None | `TestUnknownAndMalformedStatus` | PASS | |
| J | malformed status | okta_user | `status={"nested": "value"}` (dict, not string) | `status=UNKNOWN`, `lifecycle_posture=unknown` | Yes | n/a | Yes | None | `test_malformed_status_is_dict` | PASS | |
| K | active -> suspended | okta_user | status transition | `active -> suspended` | Yes | Low | Yes | None | `test_active_to_suspended_is_low` | PASS | Restrictive, not a weakening claim |
| L | suspended -> active | okta_user | status transition | `suspended -> active` | Yes | Medium | Yes | None | `test_suspended_to_active_is_medium` | PASS | Access restored, not "unauthorized" |
| M | active -> deprovisioned | okta_user | status transition | `active -> deprovisioned` | Yes | Low | Yes | None | `test_active_to_deprovisioned_is_low` | PASS | |
| N | deprovisioned -> active | okta_user | status transition | `deprovisioned -> active` | Yes | Medium | Yes | None | `test_deprovisioned_to_active_is_medium` | PASS | |
| O | active -> locked | okta_user | status transition | `active -> locked` | Yes | Low | Yes | None | `test_active_to_locked_is_low` | PASS | |
| P | locked -> active | okta_user | status transition | `locked -> active` | Yes | Medium | Yes | None | `test_locked_to_active_is_medium` | PASS | |
| Q | active -> password-expired | okta_user | status transition | `active -> password_expired` | Yes | Low | Yes | None | `test_active_to_password_expired_is_low` | PASS | |
| R | password-expired -> active | okta_user | status transition | `password_expired -> active` | Yes | Low | Yes | None | `test_password_expired_to_active_is_low` | PASS | |
| S | active -> recovery | okta_user | status transition | `active -> recovery` | Yes | Low | Yes | None | `test_active_to_recovery_is_low` | PASS | |
| T | recovery -> active | okta_user | status transition | `recovery -> active` | Yes | Low | Yes | None | `test_recovery_to_active_is_low` | PASS | |
| U | login change, same user ID | okta_user | `login` changes, `id` unchanged | modification, not add+remove | Yes (login) | Low | n/a | None | `test_login_change_same_user_id_is_modification_not_replacement` | PASS | Stable `record_id = tenant_id+user_id` |
| V | added active user | okta_user | new record, `status=ACTIVE` | `change_type=added` | n/a | Low | n/a | None | `test_added_active_user_is_low` | PASS | Never automatically High |
| W | removed user | okta_user | record absent from new snapshot | `change_type=removed` | n/a | Low | n/a | None | `test_removed_user_is_low_and_not_a_deletion_claim` | PASS | Does not claim deletion confirmed |
| X | ordinary Okta group | okta_group | `type=OKTA_GROUP` | `group_type=OKTA_GROUP`, `built_in=False` | Yes | n/a | Yes | None | `TestGroupTypeTaxonomy` | PASS | |
| Y | app group | okta_group | `type=APP_GROUP` | `group_type=APP_GROUP` | Yes | n/a | Yes | None | `test_app_group` | PASS | |
| Z | built-in/system group | okta_group | `type=BUILT_IN` | `group_type=BUILT_IN`, `built_in=True` | Yes | Medium (on transition to built-in) | Yes | None | `test_built_in_group` | PASS | |
| AA | Everyone group | okta_group | `type=BUILT_IN`, `name="Everyone"` | `everyone_group=True` | n/a (derived) | n/a | Yes | None | `TestEveryoneGroupDetection` | PASS | Requires BOTH signals |
| AB | unknown group type | okta_group | `type="SOME_FUTURE_TYPE"` | `group_type=unknown` | Yes | n/a | Yes — never assumed ordinary | None | `test_unknown_group_type` / `test_unknown_type_never_becomes_ordinary_group` | PASS | |
| AC | group renamed | okta_group | `group_name` changes | modification | Yes | Low | n/a | None | `test_group_renamed` | PASS | |
| AD | group created | okta_group | new record | `change_type=added` | n/a | Low | n/a | None | `test_group_created_is_low` | PASS | |
| AE | group removed | okta_group | record absent | `change_type=removed` | n/a | Low | n/a | None | `test_group_removed_is_low` | PASS | |
| AF | membership count increase | okta_group | `membership_count` increases | modification | Yes | Low | n/a | None | `test_membership_count_increase` | PASS | |
| AG | membership count decrease | okta_group | `membership_count` decreases | modification | Yes | Low | n/a | None | `test_membership_count_decrease` | PASS | |
| AH | missing count -> known | okta_group | `membership_count: None -> 5` | modification | Yes | Low, phrased as "became known", not "increased from 0" | Yes | None | `test_missing_count_becoming_known_is_not_a_fabricated_decrease` | PASS | |
| AI | user added to group | okta_group_membership | new record | `change_type=added` | n/a | Low | n/a | None | `test_user_added_to_group` | PASS | |
| AJ | user removed | okta_group_membership | record absent | `change_type=removed` | n/a | Low | n/a | None | `test_user_removed_from_group` | PASS | |
| AK | duplicate membership dedup | okta_group_membership | overlapping paginated pages re-serve a user | single record after dedup | n/a | n/a | n/a | None | `test_membership_dedup_within_a_group`, `test_duplicate_membership_dedup_in_record_index` | PASS | dedup by `id` in `paginate()` + `build_record_index` |
| AL | suspended user membership | okta_group_membership | `user_status=SUSPENDED` | `change_type=added`, informational | n/a | Low | n/a | None | `test_suspended_user_membership_change` | PASS | No privilege claims yet |
| AM | active user membership | okta_group_membership | `user_status=ACTIVE` | `change_type=added`, informational | n/a | Low | n/a | None | `test_active_user_membership_change` | PASS | |
| AN | built-in group membership | okta_group_membership | `built_in_group=True` | distinct wording | n/a | Low | n/a | None | `test_built_in_group_membership_noted` | PASS | |
| AO | membership collection denied | okta_group_membership (family) | `/groups/{id}/users` returns 403 | `family_completeness.memberships=denied` | n/a | n/a | Yes — never inferred as zero | None | `test_users_available_groups_available_memberships_denied` | PASS | |
| AP | users readable/groups readable/membership denied | okta_organization | mixed family outcomes | users=complete, groups=complete, memberships=denied; users/groups retained | n/a | Medium (permission-loss diagnostic, via capability classifier precedent) | Yes | None | `test_users_available_groups_available_memberships_denied` | PASS | Sync does not fail entirely |
| AQ | pagination | okta_user / okta_group | multi-page Link-header response | all pages collected | n/a | n/a | n/a | None | `test_collects_users_across_multiple_pages` | PASS | |
| AR | repeated Link | okta_group_membership (via `paginate()`) | server always returns same `next` URL | pagination stops, no infinite loop | n/a | n/a | n/a | None | (message-1 `paginate()` coverage, reused here) `test_okta_foundation.py::TestPagination::test_repeated_next_link_detected_and_stopped` | PASS | Shared helper, re-exercised via message-2 collection paths |
| AS | cross-origin Link rejected | okta_group_membership (via `paginate()`) | `next` points to a different origin | link dropped, pagination stops cleanly | n/a | n/a | n/a | None | (message-1 coverage, shared helper) | PASS | |
| AT | group with zero users | okta_group | `/groups/{id}/users` returns `[]` | `membership_count=0` (a real, known zero — not "unknown") | Yes | n/a | Yes | None | `test_group_with_zero_users` | PASS | Distinct from AO's "denied -> unknown" |
| AU | group with large membership | okta_group_membership | many members in one group | all collected up to `_MAX_MEMBERS_PER_GROUP` | n/a | n/a | n/a | None | `TestScale::test_2000_users_500_groups_10000_memberships` | PASS | |
| AV | password excluded | okta_user | `credentials.password` present in raw | absent from record | n/a | n/a | n/a | Excluded — verified | `test_password_excluded` | PASS | |
| AW | credentials excluded | okta_user | `credentials` object present | not copied wholesale; only `provider.type` read | n/a | n/a | n/a | Excluded — verified | `test_credentials_object_excluded` | PASS | |
| AX | phone excluded | okta_user | `profile.mobilePhone`/`primaryPhone` present | absent from record | n/a | n/a | n/a | Excluded — verified | `test_phone_excluded` | PASS | |
| AY | custom attributes excluded | okta_user | arbitrary `profile.customField1` present | absent from record | n/a | n/a | n/a | Excluded — verified | `test_custom_attributes_excluded` | PASS | |
| AZ | recovery answer excluded | okta_user | `credentials.recovery_question.answer` present | absent from record | n/a | n/a | n/a | Excluded — verified | `test_recovery_answer_excluded` | PASS | |
| BA | MFA secrets excluded | okta_user | `factors[].secret` present | absent from record | n/a | n/a | n/a | Excluded — verified | `test_mfa_secrets_excluded` | PASS | |
| BB | session token excluded | okta_user | `sessionToken` present | absent from record | n/a | n/a | n/a | Excluded — verified | `test_session_token_excluded` | PASS | |
| BC | 2,000 users | okta_user (scale) | 2,000 synthetic users | all 2,000 collected, stable unique IDs | n/a | n/a | n/a | None | `TestScale::test_2000_users_500_groups_10000_memberships` | PASS | |
| BD | 500 groups | okta_group (scale) | 500 synthetic groups | all 500 collected, stable unique IDs | n/a | n/a | n/a | None | same test | PASS | |
| BE | 10,000 memberships | okta_group_membership (scale) | 500 groups x 20 members | all 10,000 collected | n/a | n/a | n/a | None | same test | PASS | Non-flaky 30s wall-clock bound, not millisecond-tight |
| BF | real user provider metadata | okta_user | real `compute_diff()` output | `provider_metadata` has `tenant_id`/`user_id`/`login` | n/a | n/a | n/a | No profile leakage — verified | `test_user_provider_metadata` | PASS | |
| BG | real group provider metadata | okta_group | real `compute_diff()` output | `provider_metadata` has `tenant_id`/`group_id`/`group_name` | n/a | n/a | n/a | None | `test_group_provider_metadata` | PASS | |
| BH | real membership provider metadata | okta_group_membership | real `compute_diff()` output | `provider_metadata` has tenant/user/login/group id+name | n/a | n/a | n/a | None | `test_membership_provider_metadata` | PASS | |
| BI | lastLogin ignored | okta_user | `last_login_category` changes alone | no Change produced | No (explicitly excluded) | n/a | n/a | None | `test_last_login_change_alone_produces_no_change` | PASS | |
| BJ | statusChanged/created/activated ignored | okta_user | `created`/`activated` change alone | no Change produced | No (explicitly excluded) | n/a | n/a | None | `test_created_activated_change_alone_produces_no_change` | PASS | `statusChanged` and `passwordChanged` are never even stored (stronger than "not tracked") |
| BK | unknown not converted to active | okta_user | `status` transitions to an unrecognized value | `new_value != "ACTIVE"`, `lifecycle_posture=unknown` | Yes | Medium | Yes | None | `test_unknown_status_never_converted_to_active_in_diff` | PASS | |
| BL | missing membership list not zero | okta_group | `membership_count=None` (denied/unavailable) | stays `None`, never coerced to 0 | Yes | n/a | Yes | None | `test_missing_membership_list_not_treated_as_zero_in_tracked_fields`, `categorize_membership_count(None)` | PASS | |
| BM | missing user ID rejected | okta_user | raw record with no `id` | normalizer returns `None` (record dropped) | n/a | n/a | Yes | None | `test_missing_user_id_returns_none` | PASS | |
| BN | missing group ID rejected | okta_group | raw record with no `id` | normalizer returns `None` | n/a | n/a | Yes | None | `test_missing_group_id_returns_none` | PASS | |
| BO | display name absent when no name parts | okta_user | `profile` has no `firstName`/`lastName` | `display_name=None` | Yes | n/a | Yes | None | `test_display_name_none_when_no_name_parts` | PASS | |
| BP | credential provider category extracted | okta_user | `credentials.provider.type="OKTA"` | `credential_provider_category="OKTA"` | Yes | Low | Yes | Scoped access only — verified | `test_credential_provider_category_extracted` | PASS | |
| BQ | user_type_id extracted | okta_user | `type.id="typ1"` | `user_type_id="typ1"` | Yes | Low | Yes | None | `test_user_type_id_extracted` | PASS | |
| BR | address excluded | okta_user | `profile.streetAddress`/`city` present | absent from record | n/a | n/a | n/a | Excluded — verified | `test_address_excluded` | PASS | |
| BS | manager excluded unless needed | okta_user | `profile.manager`/`managerId` present | absent from record | n/a | n/a | n/a | Excluded — verified | `test_manager_excluded_unless_needed` | PASS | Not needed for message 2 |
| BT | group rule/embedded payloads excluded | okta_group | `_embedded.stats.rules` present | absent from record | n/a | n/a | n/a | Excluded — verified | `test_group_rule_payloads_excluded` | PASS | |
| BU | group description truncated | okta_group | `profile.description` 500 chars | truncated to 200 chars | Yes (via group_name only; description itself not tracked) | n/a | n/a | Bounded | `test_description_extracted_and_truncated` | PASS | |
| BV | arbitrary group profile fields excluded | okta_group | `profile.customAttribute` present | absent from record | n/a | n/a | n/a | Excluded — verified | `test_arbitrary_group_profile_fields_never_copied` | PASS | |
| BW | last-login recent | okta_user | `lastLogin` 5 days ago | `last_login_category=recent` | No (not tracked) | n/a | n/a | None | `test_recent` | PASS | |
| BX | last-login stale | okta_user | `lastLogin` 90 days ago | `last_login_category=stale` | No | n/a | n/a | None | `test_stale` | PASS | |
| BY | last-login never | okta_user | `lastLogin` absent (`None`) | `last_login_category=never` | No | n/a | Yes — distinct from unknown | None | `test_none_is_never` | PASS | |
| BZ | last-login unparseable | okta_user | `lastLogin="not-a-timestamp"` | `last_login_category=unknown` | No | n/a | Yes | None | `test_unparseable_is_unknown` | PASS | |
| CA | membership normalization does not duplicate full records | okta_group_membership | — | membership record excludes user/group-only fields (`credential_provider_category`, `description`, `membership_count`) | n/a | n/a | n/a | Minimized footprint | `test_does_not_duplicate_full_user_or_group_record` | PASS | |
| CB | missing user record in membership walk degrades gracefully | okta_group_membership | member ID absent from collected user index | `user_login=None`, `user_status="UNKNOWN"`, no crash | n/a | n/a | Yes | None | `test_missing_user_record_degrades_gracefully` | PASS | |
| CC | users denied, groups/memberships still attempted | okta_organization | `/users` 403 | `family_completeness.users=denied`; groups still collected | n/a | n/a | Yes | None | `test_users_denied_groups_and_memberships_still_attempted` | PASS | |
| CD | sync does not fail entirely on partial denial | okta_organization | users+groups both denied | `fetch()` still returns the org record, does not raise | n/a | n/a | n/a | None | `test_sync_does_not_fail_entirely_on_partial_denial` | PASS | |
| CE | no groups at all is complete, not denied | okta_organization | zero groups in tenant | `family_completeness.memberships=complete`, zero membership records | n/a | n/a | Yes — trivial completeness, not inferred failure | None | `test_no_groups_at_all_is_complete_not_denied` | PASS | |
| CF | membership strategy is group-based, not per-user | okta_group_membership (collection) | — | `/api/v1/users/{id}/groups` never called | n/a | n/a | n/a | None | `test_does_not_call_per_user_groups_endpoint` | PASS | Fewer top-level requests (groups << users in real tenants) |
| CG | stable record IDs prefer tenant+Okta ID | okta_user / okta_group | — | `record_id = f"{tenant_id}/user/{id}"` / `.../group/{id}` | n/a | n/a | n/a | None | `test_stable_record_ids_prefer_tenant_plus_okta_id` | PASS | Never email/login-derived |
| CH | okta_group_membership unmapped subtype | okta_group_membership | unrecognized future `record_type` string | `_tracked_fields_for()` returns `()` | n/a | n/a | Yes | None | `test_okta_group_membership_unmapped_field_returns_empty` | PASS | Never falls through to Cloudflare's generic tuple |
| CI | provider metadata never includes arbitrary profile fields | okta_user | full `compute_diff()` on an "added" user | `provider_metadata` has no `mobilePhone`/`credentials`/`profile` keys | n/a | n/a | n/a | Excluded — verified | `test_provider_metadata_never_includes_arbitrary_profile_fields` | PASS | |
| CJ | identical status produces no Change | okta_user | same status on both sides of diff | `compute_diff()` returns `[]` | n/a | n/a | n/a | None | `TestNoSpuriousChangeWhenIdentical` (parametrized, all 8 statuses) | PASS | |

**Matrix rows: 88** (exceeds the required minimum of 70).
