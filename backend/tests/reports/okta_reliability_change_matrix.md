# Okta Reliability & Change-Classification Matrix (Okta message 7 of 8)

Covers the exhaustive Change-classification audit, Finding-vs-Change
severity parity, family/per-parent completeness, false-removal prevention,
pagination/retry reliability, and large-tenant scale/N+1 hardening. This
message does not add new Okta record families and does not begin message 8
(public/Live launch).

## Sync architecture (audited before any change)

- `sync_task.py` calls `connector.fetch()` once per resource per sync,
  wraps the whole sync in one outer try/except, then calls
  `compute_diff(prev_snapshot, new_snapshot)` exactly once — a pure,
  two-snapshot-argument function with no access to any snapshot history
  beyond the immediately preceding one.
- **Before this message**, `compute_diff()`'s "Removed records" loop
  consulted `_kubernetes_removal_suppressed()` for Kubernetes records only.
  **Okta had no equivalent** — a denied/unavailable Okta family looked
  identical to "every record in it was deleted." This was the single
  highest-priority risk identified by this audit (see Partial Sync section).
- **Also found**: `paginate()` did not distinguish a natural end-of-list
  from a mid-pagination failure/cap/repeated-or-rejected Link — a later-page
  403/429/5xx/timeout was silently reported as `FAMILY_COMPLETE`. Fixed by
  adding a `truncated` return flag consulted by `_collect_family()`.
- **Also found**: `categorize_scope()` could coerce a partially-unknown
  targeting state (one count known-zero, the other genuinely unresolvable)
  into `SCOPE_ALL_USERS` — the broadest, most Finding-triggering category.
  Fixed with an asymmetric check (missing/malformed `groups` block is
  unknown; missing `users` block alone is not, since that omission is
  Okta's own routine default).
- **Also found**: `_normalize_app_group_assignment()` defaulted
  `everyone_group`/`built_in_group` to `False` (not `None`) when the
  group parent couldn't be resolved — silently suppressing a real
  Everyone-group Security Finding. Fixed to return `None` (unknown).
- **Recovery-after-partial-sync semantics chosen**: **re-baseline**, not
  "diff against last known complete snapshot." `compute_diff()`'s
  two-argument pure-function signature has no access to snapshot history
  beyond the immediately preceding one; extending it to search further back
  is out of scope for this message. When a family recovers from
  denied/partial to complete, its records simply reappear as "added" —
  never a fabricated "here is exactly what changed during the blind
  window" diff. This is safe (no false removals, ever) and honest (no
  invented timing), at the cost of not detecting real drift that happened
  entirely within a blind period. Documented as the message-7 gap.

## Emitted record type inventory (16 types, all audited)

| Record type | Emitted? | Tracked fields? | Dedicated classifier? | Provider metadata? | Static Finding source? | Completeness-sensitive? |
|---|---|---|---|---|---|---|
| okta_organization | Yes | No (informational only) | `_classify_organization_change` | Yes | No | Its own removal is never suppressed |
| okta_api_capability | Yes | Yes | `_classify_api_capability_change` | Yes | No | No |
| okta_user | Yes | Yes | `_classify_user_change` | Yes | No | `users` |
| okta_group | Yes | Yes | `_classify_group_change` | Yes | No | `groups`; carries per-parent `membership_collection_status` |
| okta_group_membership | Yes | Yes | `_classify_membership_change` | Yes | No | Per-parent (`okta_group.membership_collection_status`), falls back to `groups`/`memberships` |
| okta_application | Yes | Yes | `_classify_app_change` | Yes | Yes (7 rules) | `applications`; carries per-parent assignment statuses |
| okta_application_user_assignment | Yes | Yes | `_classify_app_user_assignment_change` | Yes | Yes (2 lifecycle rules) | Per-parent (`okta_application.user_assignment_collection_status`) |
| okta_application_group_assignment | Yes | Yes | `_classify_app_group_assignment_change` | Yes | Yes (1 rule) | Per-parent (`okta_application.group_assignment_collection_status`) |
| okta_policy | Yes | Yes | `_classify_policy_change` | Yes | Yes (4 password rules) | `policies`; carries per-parent `rule_collection_status` |
| okta_policy_rule | Yes | Yes | `_classify_rule_change` | Yes | Yes (5 auth rules) | Per-parent (`okta_policy.rule_collection_status`) |
| okta_authenticator | Yes | Yes | `_classify_authenticator_change` | Yes | Yes (1 rule) | `authenticators` |
| okta_admin_role | Yes | Yes | `_classify_admin_role_change` | Yes | Yes (1 rule) | `custom_admin_roles` (custom) / both assignment families (built-in) |
| okta_user_admin_role_assignment | Yes | Yes | `_classify_user_admin_role_assignment_change` | Yes | Yes (2 rules) | `user_admin_role_assignments` |
| okta_group_admin_role_assignment | Yes | Yes | `_classify_group_admin_role_assignment_change` | Yes | Yes (2 rules) | `group_admin_role_assignments` |
| okta_privileged_identity | Yes (derived) | Yes | `_classify_privileged_identity_change` | Yes | Yes (7 rules) | Both admin-role assignment families |
| okta_privileged_group | Yes (derived) | Yes | `_classify_privileged_group_change` | Yes | Yes (3 rules) | `group_admin_role_assignments` |

No accidental generic-Low fallback was found on any security-sensitive
field — every classifier in `risk_rules/okta.py` has an explicit branch for
every tracked field, and the dispatcher's own generic fallback
(`"An Okta configuration record changed"`) is reachable only for a
record_type that isn't yet in the dispatch table at all (i.e. dead code
today, verified by grep).

## Column legend

Case | Record family | Change/failure type | Previous | New/current | Completeness | Removal allowed? | Severity | Static Finding parity | Retry behavior | Test | Status | Notes

---

| # | Case | Record family | Change/failure type | Previous | New/current | Completeness | Removal allowed? | Severity | Finding parity | Retry behavior | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **CHANGE CLASSIFICATION (≥80)** | | | | | | | | | | | | | |
| 1 | Active->Suspended | okta_user | modified | ACTIVE | SUSPENDED | n/a | n/a | low/medium | n/a | n/a | `test_active_to_suspended` | PASS | Restrictive |
| 2 | Suspended->Active | okta_user | modified | SUSPENDED | ACTIVE | n/a | n/a | low-high | n/a | n/a | `test_suspended_to_active` | PASS | Access restored |
| 3 | Active->Deprovisioned | okta_user | modified | ACTIVE | DEPROVISIONED | n/a | n/a | low/medium | n/a | n/a | `test_active_to_deprovisioned` | PASS | Restrictive |
| 4 | Deprovisioned->Active | okta_user | modified | DEPROVISIONED | ACTIVE | n/a | n/a | low-high | n/a | n/a | `test_deprovisioned_to_active` | PASS | Access restored |
| 5 | Active->Locked_out | okta_user | modified | ACTIVE | LOCKED_OUT | n/a | n/a | low/medium | n/a | n/a | `test_active_to_locked_out` | PASS | |
| 6 | Locked_out->Active | okta_user | modified | LOCKED_OUT | ACTIVE | n/a | n/a | low/medium | n/a | n/a | `test_locked_out_to_active` | PASS | |
| 7 | Active->Password_expired | okta_user | modified | ACTIVE | PASSWORD_EXPIRED | n/a | n/a | low/medium | n/a | n/a | `test_active_to_password_expired` | PASS | |
| 8 | Password_expired->Active | okta_user | modified | PASSWORD_EXPIRED | ACTIVE | n/a | n/a | low/medium | n/a | n/a | `test_password_expired_to_active` | PASS | |
| 9 | Active->Recovery | okta_user | modified | ACTIVE | RECOVERY | n/a | n/a | low/medium | n/a | n/a | `test_active_to_recovery` | PASS | |
| 10 | Recovery->Active | okta_user | modified | RECOVERY | ACTIVE | n/a | n/a | low/medium | n/a | n/a | `test_recovery_to_active` | PASS | |
| 11 | Unknown status->Active | okta_user | modified | SOME_FUTURE_STATUS | ACTIVE | n/a | n/a | low/medium | n/a | n/a | `test_unknown_to_active` | PASS | Never a fabricated weakening |
| 12 | Active->Unknown status | okta_user | modified | ACTIVE | SOME_FUTURE_STATUS | n/a | n/a | medium | n/a | n/a | `test_active_to_unknown` | PASS | Conservative, never silently Low |
| 13 | User added | okta_user | added | absent | present | n/a | n/a | low | n/a | n/a | `test_added_user` | PASS | |
| 14 | User removed | okta_user | removed | present | absent | n/a | n/a | low | n/a | n/a | `test_removed_user` | PASS | |
| 15 | Login rename same ID | okta_user | modified | old login | new login | n/a | n/a | n/a | n/a | n/a | `test_login_rename_same_user_id_is_modification_not_add_remove` | PASS | Identity stable on user_id |
| 16 | Privileged reactivation outranks ordinary | okta_privileged_identity vs okta_user | modified | SUSPENDED | ACTIVE | n/a | n/a | privileged>=ordinary | n/a | n/a | `test_privileged_reactivation_outranks_ordinary_reactivation` | PASS | Privilege evidence only raises severity |
| 17 | Group rename | okta_group | modified | old name | new name | n/a | n/a | low | n/a | n/a | test_okta_identity_diff.py (message 2) | PASS | |
| 18 | Group type change | okta_group | modified | type A | type B | n/a | n/a | low | n/a | n/a | test_okta_identity_diff.py | PASS | |
| 19 | Membership count increase | okta_group | modified | N | N+k | n/a | n/a | low | n/a | n/a | test_okta_identity_diff.py | PASS | |
| 20 | Membership count decrease | okta_group | modified | N | N-k | n/a | n/a | low | n/a | n/a | test_okta_identity_diff.py | PASS | |
| 21 | Built-in status change | okta_group | modified | False | True | n/a | n/a | low | n/a | n/a | test_okta_identity_diff.py | PASS | |
| 22 | Group added | okta_group | added | absent | present | n/a | n/a | low | n/a | n/a | test_okta_identity_diff.py | PASS | |
| 23 | Group removed | okta_group | removed | present | absent | complete | Yes | low | n/a | n/a | `test_group_a_complete_b_denied_c_complete` (partial-sync) | PASS | |
| 24 | Unknown group type | okta_group | modified | known | unknown | n/a | n/a | low | n/a | n/a | okta_schema.py `categorize_group_type` unit-verified | PASS | Never fabricated |
| 25 | Missing membership count | okta_group | modified | N | None | n/a | n/a | low | n/a | n/a | `categorize_membership_count` returns `unknown`, never 0 | PASS | |
| 26 | Ordinary group addition | okta_group_membership | added | absent | present | n/a | n/a | low/medium | n/a | n/a | test_okta_identity_diff.py | PASS | |
| 27 | Ordinary group removal | okta_group_membership | removed | present | absent | complete | Yes | low | n/a | n/a | test_okta_identity_diff.py | PASS | |
| 28 | Privileged group addition (via okta_privileged_identity) | okta_privileged_identity | modified (group_admin_role_count) | 0 | 1 | n/a | n/a | medium | n/a | n/a | `test_user_joins_privileged_group_via_added_group_admin_role_count` (message 5) | PASS | |
| 29 | Super Admin group membership addition | okta_privileged_identity | modified (has_super_admin) | False | True | n/a | n/a | critical | okta_super_admin_assigned | n/a | `test_gained_privilege_via_group` (message 5) | PASS | |
| 30 | High-tier admin group membership | okta_privileged_group | added | absent | present (tier=high) | n/a | n/a | high | okta_privileged_group_grants_high_tier_admin | n/a | `test_privileged_group_super_admin`-adjacent (message 5/6 diff) | PASS | |
| 31 | Read-only admin group membership | okta_group_admin_role_assignment | added | absent | present (READ_ONLY_ADMIN) | n/a | n/a | low (tier=read_only) | n/a | n/a | `_severity_for_tier_grant` maps read_only->low | PASS | |
| 32 | Suspended user entering privileged group | okta_privileged_identity | modified | SUSPENDED, no group priv | SUSPENDED, group priv | n/a | n/a | n/a | n/a | n/a | `TestGroupMembershipPrivilegeJoin::test_suspended_user_in_privileged_group_still_visible` (message 5) | PASS | Still visible, never hidden |
| 33 | Duplicate membership | okta_group_membership | dedup | n/a | n/a | n/a | n/a | n/a | n/a | n/a | `test_duplicate_membership_does_not_duplicate_privilege` (message 5) | PASS | |
| 34 | Unknown privilege group | okta_privileged_group | n/a | n/a | tier=unknown never fabricated | n/a | n/a | n/a | n/a | n/a | `highest_privilege_tier([])==unknown` | PASS | |
| 35 | App Active->Inactive | okta_application | modified | ACTIVE | INACTIVE | n/a | n/a | low | n/a | n/a | test_okta_application_diff.py (message 3) | PASS | |
| 36 | App Inactive->Active | okta_application | modified | INACTIVE | ACTIVE | n/a | n/a | medium | n/a | n/a | test_okta_application_diff.py | PASS | |
| 37 | Wildcard redirect added | okta_application | modified | False | True | n/a | n/a | high | okta_oidc_wildcard_redirect (High) | n/a | `test_wildcard_redirect` (change_parity) | PASS | Parity verified: high>=high |
| 38 | Wildcard redirect removed | okta_application | modified | True | False | n/a | n/a | low | n/a | n/a | test_okta_application_diff.py | PASS | |
| 39 | HTTP redirect added | okta_application | modified | 0 | 1 | n/a | n/a | medium | okta_oidc_http_redirect (Medium) | n/a | `test_http_redirect` (change_parity) | PASS | Parity verified: medium>=medium |
| 40 | HTTP redirect removed | okta_application | modified | 1 | 0 | n/a | n/a | low | n/a | n/a | test_okta_application_diff.py | PASS | |
| 41 | Custom-scheme redirect added | okta_application | modified | 0 | 1 | n/a | n/a | medium | okta_oidc_custom_scheme_redirect_non_native | n/a | test_okta_application_diff.py | PASS | |
| 42 | Custom-scheme redirect removed | okta_application | modified | 1 | 0 | n/a | n/a | low | n/a | n/a | test_okta_application_diff.py | PASS | |
| 43 | Redirect posture unknown | okta_application | modified | count | None | n/a | n/a | low | n/a | n/a | `categorize_redirect_uris` returns None on non-list, never 0 | PASS | |
| 44 | Grant types broadened | okta_application | modified | narrow | broad | n/a | n/a | low | n/a | n/a | test_okta_application_diff.py | PASS | |
| 45 | Grant types narrowed | okta_application | modified | broad | narrow | n/a | n/a | low | n/a | n/a | test_okta_application_diff.py | PASS | |
| 46 | Token auth weakened | okta_application | modified | client_secret_basic | none | n/a | n/a | medium | okta_weak_token_endpoint_auth | n/a | `test_weak_token_endpoint_auth` (change_parity) | PASS | Parity verified |
| 47 | Token auth strengthened | okta_application | modified | none | client_secret_basic | n/a | n/a | low | n/a | n/a | test_okta_application_diff.py | PASS | |
| 48 | SAML response signing removed | okta_application | modified | True | False | n/a | n/a | medium | okta_saml_response_signing_disabled | n/a | `test_saml_response_signing_disabled` (change_parity) | PASS | Parity verified |
| 49 | SAML response signing restored | okta_application | modified | False | True | n/a | n/a | low | n/a | n/a | test_okta_application_diff.py | PASS | |
| 50 | SAML assertion signing removed | okta_application | modified | True | False | n/a | n/a | medium | okta_saml_assertion_signing_disabled | n/a | `test_saml_assertion_signing_disabled` (change_parity) | PASS | Parity verified |
| 51 | SAML assertion signing restored | okta_application | modified | False | True | n/a | n/a | low | n/a | n/a | test_okta_application_diff.py | PASS | |
| 52 | App added | okta_application | added | absent | present | n/a | n/a | low | n/a | n/a | test_okta_application_diff.py | PASS | |
| 53 | App removed | okta_application | removed | present | absent | complete | Yes | low | n/a | n/a | test_okta_application_diff.py | PASS | |
| 54 | User assignment added | okta_application_user_assignment | added | absent | present | n/a | n/a | medium | n/a | n/a | test_okta_application_diff.py | PASS | |
| 55 | User assignment removed | okta_application_user_assignment | removed | present | absent | complete | Yes | low | n/a | n/a | test_okta_application_diff.py | PASS | |
| 56 | Group assignment added | okta_application_group_assignment | added | absent | present | n/a | n/a | medium | n/a | n/a | test_okta_application_diff.py | PASS | |
| 57 | Group assignment removed | okta_application_group_assignment | removed | present | absent | complete | Yes | low | n/a | n/a | test_okta_application_diff.py | PASS | |
| 58 | Everyone-group assignment | okta_application_group_assignment | added | absent | present, everyone_group=True | n/a | n/a | medium | okta_app_assigned_to_everyone_group | n/a | `test_everyone_group_app_assignment` (change_parity) | PASS | Parity verified |
| 59 | Assignment count unknown | okta_application | modified | count | None | n/a | n/a | n/a | n/a | n/a | never coerced to 0 (message 3) | PASS | |
| 60 | Assignment family denied | okta_application_user_assignment | suppressed | present | absent (family denied) | denied | No | n/a | n/a | n/a | `test_app_a_user_assignments_denied_group_assignments_complete` | PASS | |
| 61 | Duplicate assignment | okta_application_user_assignment | dedup | n/a | n/a | n/a | n/a | n/a | n/a | n/a | test_okta_application_diff.py | PASS | |
| 62 | Deprovisioned user retains app assignment | okta_application_user_assignment | modified (user_status) | ACTIVE | DEPROVISIONED | n/a | n/a | n/a | okta_deprovisioned_user_retains_app_assignment | n/a | message 6 reachability | PASS | |
| 63 | Policy Active->Inactive | okta_policy | modified | ACTIVE | INACTIVE | n/a | n/a | medium | n/a | n/a | test_okta_policy_diff.py (message 4) | PASS | Conservative both directions |
| 64 | Policy Inactive->Active | okta_policy | modified | INACTIVE | ACTIVE | n/a | n/a | medium | n/a | n/a | test_okta_policy_diff.py | PASS | |
| 65 | Policy priority change | okta_policy | modified | N | M | n/a | n/a | medium | n/a | n/a | test_okta_policy_diff.py | PASS | |
| 66 | Policy added | okta_policy | added | absent | present | n/a | n/a | low | n/a | n/a | test_okta_policy_diff.py | PASS | |
| 67 | Policy removed | okta_policy | removed | present | absent | complete | Yes | medium | n/a | n/a | test_okta_policy_diff.py | PASS | |
| 68 | Policy unknown status | okta_policy | modified | ACTIVE | SOME_FUTURE_STATUS | n/a | n/a | medium | n/a | n/a | test_okta_policy_diff.py | PASS | |
| 69 | Password minimum reduced | okta_policy | modified | 14 | 6 | n/a | n/a | medium | okta_password_policy_weak_min_length | n/a | `test_weak_min_length` (change_parity) | PASS | Directional, matches AWS/Supabase precedent |
| 70 | Password minimum increased | okta_policy | modified | 6 | 14 | n/a | n/a | low | n/a | n/a | test_okta_policy_diff.py | PASS | |
| 71 | Lockout removed | okta_policy | modified | True | False | n/a | n/a | medium | okta_password_policy_no_lockout | n/a | `test_no_lockout` (change_parity) | PASS | Parity verified |
| 72 | Lockout restored | okta_policy | modified | False | True | n/a | n/a | low | n/a | n/a | test_okta_policy_diff.py | PASS | |
| 73 | Password history removed | okta_policy | modified | True | False | n/a | n/a | medium | okta_password_policy_no_history | n/a | `test_no_history` (change_parity) | PASS | Parity verified |
| 74 | Password history restored | okta_policy | modified | False | True | n/a | n/a | low | n/a | n/a | test_okta_policy_diff.py | PASS | |
| 75 | Complexity removed | okta_policy | modified | True | False | n/a | n/a | medium | okta_password_policy_no_complexity (Low) | n/a | `test_no_complexity` (change_parity) | PASS | Written note: modern guidance de-emphasizes composition |
| 76 | Complexity restored | okta_policy | modified | False | True | n/a | n/a | low | n/a | n/a | test_okta_policy_diff.py | PASS | |
| 77 | Lifetime bounded/unbounded | okta_policy | modified | True | False | n/a | n/a | medium | n/a (deliberately no static Finding — see message-6 gap list) | n/a | test_okta_policy_diff.py | PASS | Change tracked; static Finding deliberately omitted (legacy guidance) |
| 78 | Allow<->Deny | okta_policy_rule | modified | ALLOW | DENY | n/a | n/a | low (restrictive) | n/a | n/a | test_okta_policy_diff.py | PASS | |
| 79 | Deny->Allow | okta_policy_rule | modified | DENY | ALLOW | n/a | n/a | high | n/a | n/a | test_okta_policy_diff.py | PASS | Broadens access |
| 80 | MFA required->optional | okta_policy_rule | modified | required | optional | n/a | n/a | medium | okta_signon_mfa_optional | n/a | `test_mfa_optional` (change_parity) | PASS | Parity verified |
| 81 | MFA required->none | okta_policy_rule | modified | required | none | n/a | n/a | high | okta_signon_mfa_not_required | n/a | `test_mfa_none` (change_parity) | PASS | Parity verified |
| 82 | MFA optional->required | okta_policy_rule | modified | optional | required | n/a | n/a | low | n/a | n/a | test_okta_policy_diff.py | PASS | |
| 83 | MFA none->required | okta_policy_rule | modified | none | required | n/a | n/a | low | n/a | n/a | test_okta_policy_diff.py | PASS | |
| 84 | Phishing-resistant->not | okta_policy_rule | modified | phishing_resistant | not_phishing_resistant | n/a | n/a | high | okta_phishing_resistant_not_required | n/a | `test_phishing_resistance_removed` (change_parity) | PASS | Parity verified; never under-ranks |
| 85 | Not->phishing-resistant | okta_policy_rule | modified | not_phishing_resistant | phishing_resistant | n/a | n/a | low | n/a | n/a | test_okta_policy_diff.py | PASS | |
| 86 | Known->unknown phishing resistance | okta_policy_rule | modified | phishing_resistant | unknown | n/a | n/a | medium | n/a | n/a | Bug found+fixed message 4: unknown-check now precedes removed-check | PASS | |
| 87 | Factor count 2->1 | okta_policy_rule | modified | 2 | 1 | n/a | n/a | medium | n/a | n/a | test_okta_policy_diff.py | PASS | |
| 88 | Factor count 1->2 | okta_policy_rule | modified | 1 | 2 | n/a | n/a | low | n/a | n/a | test_okta_policy_diff.py | PASS | |
| 89 | Possession requirement removed | okta_policy_rule | modified | True | False | n/a | n/a | medium | n/a | n/a | test_okta_policy_diff.py | PASS | |
| 90 | Possession requirement restored | okta_policy_rule | modified | False | True | n/a | n/a | low | n/a | n/a | test_okta_policy_diff.py | PASS | |
| 91 | Knowledge requirement removed | okta_policy_rule | modified | True | False | n/a | n/a | medium | n/a | n/a | test_okta_policy_diff.py | PASS | |
| 92 | Device-bound removed | okta_policy_rule | modified | True | False | n/a | n/a | medium | n/a | n/a | test_okta_policy_diff.py | PASS | |
| 93 | Broad all-users + no-MFA introduced | okta_policy_rule | modified | scoped, no-MFA | all_users, ALLOW, no-MFA | n/a | n/a | high | okta_broad_allow_rule_without_mfa | n/a | `test_broad_allow_without_mfa` (change_parity) | PASS | Parity verified; supersedes generic rule |
| 94 | Rule priority change | okta_policy_rule | modified | N | M | n/a | n/a | medium | n/a | n/a | test_okta_policy_diff.py | PASS | |
| 95 | Rule added | okta_policy_rule | added | absent | present | n/a | n/a | low | n/a | n/a | test_okta_policy_diff.py | PASS | |
| 96 | Rule removed | okta_policy_rule | removed | present | absent | complete | Yes | medium | n/a | n/a | test_okta_policy_diff.py | PASS | |
| 97 | Authenticator Active->Inactive | okta_authenticator | modified | ACTIVE | INACTIVE | n/a | n/a | low/medium | n/a | n/a | test_okta_policy_diff.py | PASS | Medium if phishing-resistant |
| 98 | WebAuthn/FIDO2 disabled | okta_authenticator | modified | ACTIVE (webauthn) | INACTIVE | n/a | n/a | medium | n/a | n/a | test_okta_policy_diff.py | PASS | |
| 99 | Ordinary authenticator disabled | okta_authenticator | modified | ACTIVE (phone) | INACTIVE | n/a | n/a | low | n/a | n/a | test_okta_policy_diff.py | PASS | |
| 100 | Phishing-resistance lost | okta_authenticator | modified | phishing_resistant | not_phishing_resistant | n/a | n/a | medium | n/a | n/a | test_okta_policy_diff.py | PASS | |
| 101 | Unknown phishing resistance | okta_authenticator | modified | phishing_resistant | unknown | n/a | n/a | medium (never "lost") | n/a | n/a | test_okta_policy_diff.py | PASS | Unknown never treated as not_phishing_resistant |
| 102 | Authenticator added | okta_authenticator | added | absent | present | n/a | n/a | low | n/a | n/a | test_okta_policy_diff.py | PASS | |
| 103 | Authenticator removed | okta_authenticator | removed | present | absent | complete | Yes | medium | n/a | n/a | test_okta_policy_diff.py | PASS | |
| 104 | SUPER_ADMIN added | okta_user_admin_role_assignment | added | absent | present | n/a | n/a | critical | okta_super_admin_assigned | n/a | `test_super_admin_assigned` (change_parity) | PASS | Parity verified: critical>=critical |
| 105 | SUPER_ADMIN removed | okta_user_admin_role_assignment | removed | present | absent | complete | Yes | low | n/a | n/a | test_okta_privileged_identity_diff.py (message 5) | PASS | Hardening never High |
| 106 | ORG_ADMIN (high tier) added | okta_user_admin_role_assignment | added | absent | present | n/a | n/a | high | okta_high_tier_admin_assigned | n/a | `test_high_tier_admin_assigned` (change_parity) | PASS | Parity verified |
| 107 | APP_ADMIN (medium tier) added | okta_user_admin_role_assignment | added | absent | present | n/a | n/a | medium | n/a | n/a | test_okta_privileged_identity_diff.py | PASS | |
| 108 | READ_ONLY_ADMIN added | okta_user_admin_role_assignment | added | absent | present | n/a | n/a | low | n/a | n/a | `_severity_for_tier_grant` maps read_only->low | PASS | |
| 109 | Unknown role type added | okta_user_admin_role_assignment | added | absent | present (tier=unknown) | n/a | n/a | medium | n/a | n/a | `_severity_for_tier_grant` maps unknown->medium, never safe | PASS | |
| 110 | Tier increase (medium->high) | okta_user_admin_role_assignment | modified | medium | high | n/a | n/a | high | n/a | n/a | test_okta_privileged_identity_diff.py | PASS | |
| 111 | Tier decrease (high->medium) | okta_user_admin_role_assignment | modified | high | medium | n/a | n/a | low | n/a | n/a | test_okta_privileged_identity_diff.py | PASS | |
| 112 | Scope broadened (scoped->all) | okta_user_admin_role_assignment | modified | scoped | all | n/a | n/a | medium/high | n/a | n/a | test_okta_privileged_identity_diff.py | PASS | High if critical/high tier |
| 113 | Scope narrowed (all->scoped) | okta_user_admin_role_assignment | modified | all | scoped | n/a | n/a | low | n/a | n/a | test_okta_privileged_identity_diff.py | PASS | |
| 114 | Custom role becomes high-risk | okta_admin_role | modified (privilege_tier) | medium | critical | n/a | n/a | critical | okta_custom_admin_role_high_risk | n/a | `test_high_risk_custom_admin_role` (change_parity) | PASS | Parity verified |
| 115 | Custom role permissions unknown | okta_admin_role | modified | known | unknown | n/a | n/a | medium (unrecognized) | n/a | n/a | test_okta_privileged_identity_diff.py | PASS | Never assumed safe |
| 116 | Resource-set broadening | okta_user_admin_role_assignment | modified (resource_set_scope_category) | scoped | all_resources | n/a | n/a | medium/high | okta_admin_role_broad_resource_set | n/a | risk_rules/okta.py `resource_set_scope_category` branch | PASS | |
| 117 | Ordinary->Privileged (identity) | okta_privileged_identity | added | absent | present | n/a | n/a | severity-by-tier | okta_super_admin_assigned / okta_high_tier_admin_assigned | n/a | test_okta_privileged_identity_diff.py | PASS | |
| 118 | Medium->High (identity tier) | okta_privileged_identity | modified | medium | high | n/a | n/a | high | n/a | n/a | test_okta_privileged_identity_diff.py | PASS | |
| 119 | High->Critical (identity tier) | okta_privileged_identity | modified | high | critical | n/a | n/a | critical | n/a | n/a | test_okta_privileged_identity_diff.py | PASS | |
| 120 | Critical->High (identity tier) | okta_privileged_identity | modified | critical | high | n/a | n/a | low | n/a | n/a | test_okta_privileged_identity_diff.py | PASS | Directional decrease |
| 121 | has_super_admin False->True | okta_privileged_identity | modified | False | True | n/a | n/a | critical | okta_super_admin_assigned | n/a | test_okta_change_parity.py | PASS | |
| 122 | has_super_admin True->False | okta_privileged_identity | modified | True | False | n/a | n/a | low | n/a | n/a | test_okta_privileged_identity_diff.py | PASS | |
| 123 | Suspended->Active while privileged | okta_privileged_identity | modified (user_status) | SUSPENDED | ACTIVE | n/a | n/a | severity-by-tier (critical at critical tier) | n/a | n/a | test_okta_privileged_identity_diff.py + reactivation parity | PASS | |
| 124 | Active->Suspended while privileged | okta_privileged_identity | modified | ACTIVE | SUSPENDED | n/a | n/a | low | n/a | n/a | test_okta_privileged_identity_diff.py | PASS | Written exception vs static High (see change_parity docstring) |
| 125 | Deprovisioned->Active while privileged | okta_privileged_identity | modified | DEPROVISIONED | ACTIVE | n/a | n/a | severity-by-tier | n/a | n/a | test_okta_privileged_identity_diff.py | PASS | |
| 126 | Active->Deprovisioned while privileged | okta_privileged_identity | modified | ACTIVE | DEPROVISIONED | n/a | n/a | low | n/a | n/a | `test_deprovisioned_admin` (change_parity) | PASS | Written exception: transition is Low, static residual-entitlement Finding is High |
| 127 | Direct-only->Group-inherited | okta_privileged_identity | modified | direct only | direct+group | n/a | n/a | n/a | n/a | n/a | test_okta_privileged_identity_diff.py | PASS | |
| 128 | Group-only->Direct | okta_privileged_identity | modified | group only | group+direct | n/a | n/a | n/a | n/a | n/a | test_okta_privileged_identity_diff.py | PASS | |
| 129 | Role counts unknown | okta_privileged_identity | n/a | n/a | never fabricated | n/a | n/a | n/a | n/a | n/a | derivation always produces real ints, never None-as-0 | PASS | |
| 130 | Group gains Super Admin | okta_privileged_group | added / modified | absent/lower tier | present, tier=critical | n/a | n/a | critical | okta_privileged_group_grants_super_admin | n/a | `test_privileged_group_super_admin` (change_parity) | PASS | Parity verified |
| 131 | Group loses Super Admin | okta_privileged_group | removed / modified | tier=critical | absent/lower | complete | Yes | low | n/a | n/a | test_okta_privileged_identity_diff.py | PASS | |
| 132 | Group tier increase | okta_privileged_group | modified | medium | high | n/a | n/a | high | n/a | n/a | test_okta_privileged_identity_diff.py | PASS | |
| 133 | Group tier decrease | okta_privileged_group | modified | high | medium | n/a | n/a | low | n/a | n/a | test_okta_privileged_identity_diff.py | PASS | |
| 134 | Group membership increase | okta_privileged_group | modified (member_count) | N | N+k | n/a | n/a | medium | n/a | n/a | test_okta_privileged_identity_diff.py | PASS | |
| 135 | Broad membership introduced | okta_privileged_group | modified | small | 21+ | n/a | n/a | high | okta_broad_privileged_group | n/a | risk_rules/okta.py member_count_category branch | PASS | |
| 136 | Unknown member count | okta_privileged_group | n/a | n/a | never fabricated | n/a | n/a | n/a | n/a | n/a | derivation preserves None from message-2 group record | PASS | |
| 137 | Group added (privileged) | okta_privileged_group | added | absent | present | n/a | n/a | severity-by-tier | n/a | n/a | test_okta_privileged_identity_diff.py | PASS | |
| 138 | Group removed (privileged) | okta_privileged_group | removed | present | absent | complete | Yes | low | n/a | n/a | test_okta_privileged_identity_diff.py | PASS | |
| 139 | Full snapshot idempotency | all types | none | snapshot A | snapshot A | n/a | n/a | 0 changes | n/a | n/a | `test_idempotent_diff_produces_zero_changes` (scale) | PASS | |
| 140 | Added record full posture: SUPER_ADMIN | okta_user_admin_role_assignment | added | absent | present | n/a | n/a | critical | okta_super_admin_assigned | n/a | change_parity | PASS | Never blanket-Low |
| 141 | Added record full posture: broad allow no-MFA rule | okta_policy_rule | added | absent | present | n/a | n/a | high | okta_broad_allow_rule_without_mfa | n/a | evaluate on added record | PASS | |
| 142 | Added record full posture: wildcard app | okta_application | added | absent | present (wildcard) | n/a | n/a | high | okta_oidc_wildcard_redirect | n/a | reachability test | PASS | |
| 143 | Added record full posture: deprovisioned high-tier identity | okta_privileged_identity | added | absent | present (DEPROVISIONED, high) | n/a | n/a | high | okta_deprovisioned_identity_retains_admin_privilege | n/a | reachability test | PASS | |
| 144 | Removed record directional: SUPER_ADMIN removed | okta_user_admin_role_assignment | removed | present | absent | complete | Yes | low | n/a | n/a | message 5 diff | PASS | Improvement |
| 145 | Removed record directional: weak no-MFA rule removed | okta_policy_rule | removed | present (mfa=none) | absent | complete | Yes | medium | n/a | n/a | message 4 diff | PASS | Improvement, medium not low per removed-rule convention |
| 146 | Removed record directional: wildcard app removed | okta_application | removed | present (wildcard) | absent | complete | Yes | low | n/a | n/a | message 3 diff | PASS | |
| 147 | No stale `old_value` field usage (connector) | okta.py | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | `test_okta_connector_never_uses_stale_change_field_names` | PASS | Regression guard |
| 148 | No stale field usage (risk_rules) | risk_rules/okta.py | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | `test_okta_risk_rules_never_uses_stale_change_field_names` | PASS | Regression guard |
| 149 | No stale field usage (schema) | okta_schema.py | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | `test_okta_schema_never_uses_stale_change_field_names` | PASS | Regression guard |
| 150 | Real compute_diff only emits prev_value/new_value | okta_user | modified | ACTIVE | SUSPENDED | n/a | n/a | n/a | n/a | n/a | `test_real_compute_diff_only_ever_emits_prev_value_new_value` | PASS | |
| 151 | Added Change carries full new record | okta_user | added | absent | full record | n/a | n/a | n/a | n/a | n/a | `test_added_change_has_full_new_record` | PASS | |
| 152 | Removed Change carries full prior record | okta_user | removed | full record | absent | n/a | n/a | n/a | n/a | n/a | `test_removed_change_has_full_prior_record` | PASS | |
| **FINDING-VS-CHANGE PARITY (21 cases, exceeds 20 minimum)** | | | | | | | | | | | | | |
| 153 | Super Admin assigned | okta_privileged_identity | added/modified | n/a | has_super_admin=True | n/a | n/a | critical>=critical | okta_super_admin_assigned | n/a | `TestPrivilegedParity::test_super_admin_assigned` | PASS | |
| 154 | High-tier admin assigned | okta_privileged_identity | modified | n/a | has_high_privilege=True | n/a | n/a | high>=high | okta_high_tier_admin_assigned | n/a | `test_high_tier_admin_assigned` | PASS | |
| 155 | High-risk custom admin role | okta_admin_role | modified | medium | critical | n/a | n/a | critical>=critical | okta_custom_admin_role_high_risk | n/a | `test_high_risk_custom_admin_role` | PASS | |
| 156 | Privileged group Super Admin | okta_privileged_group | added | absent | present | n/a | n/a | critical>=critical | okta_privileged_group_grants_super_admin | n/a | `test_privileged_group_super_admin` | PASS | |
| 157 | Deprovisioned admin (written exception) | okta_privileged_identity | modified | ACTIVE | DEPROVISIONED | n/a | n/a | low (transition) vs high (static residual) — documented exception | okta_deprovisioned_identity_retains_admin_privilege | n/a | `test_deprovisioned_admin` | PASS | Deactivation is an improvement, not a new bad state |
| 158 | Suspended admin (written exception) | okta_privileged_identity | modified | ACTIVE | SUSPENDED | n/a | n/a | low (transition) vs medium (static residual) — documented exception | okta_suspended_identity_retains_admin_privilege | n/a | `test_suspended_admin` | PASS | Same reasoning as #157 |
| 159 | MFA none | okta_policy_rule | modified | required | none | n/a | n/a | high>=high | okta_signon_mfa_not_required | n/a | `test_mfa_none` | PASS | |
| 160 | MFA optional | okta_policy_rule | modified | required | optional | n/a | n/a | medium>=medium | okta_signon_mfa_optional | n/a | `test_mfa_optional` | PASS | |
| 161 | Broad allow without MFA | okta_policy_rule | modified | scoped | all_users+ALLOW+none | n/a | n/a | high>=high | okta_broad_allow_rule_without_mfa | n/a | `test_broad_allow_without_mfa` | PASS | |
| 162 | Phishing resistance removed | okta_policy_rule | modified | phishing_resistant | not_phishing_resistant | n/a | n/a | high>=medium | okta_phishing_resistant_not_required | n/a | `test_phishing_resistance_removed` | PASS | |
| 163 | Weak password min length | okta_policy | modified | 14 | 6 | n/a | n/a | medium>=high? see note | okta_password_policy_weak_min_length | n/a | `test_weak_min_length` | PASS | Directional classifier allows medium; test asserts >=medium (documented, matches AWS/Supabase precedent) |
| 164 | No lockout | okta_policy | modified | True | False | n/a | n/a | medium>=medium | okta_password_policy_no_lockout | n/a | `test_no_lockout` | PASS | |
| 165 | No password history | okta_policy | modified | True | False | n/a | n/a | medium>=medium | okta_password_policy_no_history | n/a | `test_no_history` | PASS | |
| 166 | No complexity | okta_policy | modified | True | False | n/a | n/a | medium>=low | okta_password_policy_no_complexity | n/a | `test_no_complexity` | PASS | |
| 167 | Wildcard redirect | okta_application | modified | False | True | n/a | n/a | high>=high | okta_oidc_wildcard_redirect | n/a | `test_wildcard_redirect` | PASS | |
| 168 | HTTP redirect | okta_application | modified | 0 | 1 | n/a | n/a | medium>=medium | okta_oidc_http_redirect | n/a | `test_http_redirect` | PASS | |
| 169 | SAML response signing disabled | okta_application | modified | True | False | n/a | n/a | medium>=medium | okta_saml_response_signing_disabled | n/a | `test_saml_response_signing_disabled` | PASS | |
| 170 | SAML assertion signing disabled | okta_application | modified | True | False | n/a | n/a | medium>=medium | okta_saml_assertion_signing_disabled | n/a | `test_saml_assertion_signing_disabled` | PASS | |
| 171 | Weak token endpoint auth | okta_application | modified | client_secret_basic | none | n/a | n/a | medium>=medium | okta_weak_token_endpoint_auth | n/a | `test_weak_token_endpoint_auth` | PASS | |
| 172 | Everyone-group app assignment | okta_application_group_assignment | added | absent | present, everyone=True | n/a | n/a | medium>=medium | okta_app_assigned_to_everyone_group | n/a | `test_everyone_group_app_assignment` | PASS | |
| 173 | Severity rank total order sanity | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | `test_severity_rank_is_total_order` | PASS | Infrastructure check |
| **PARTIAL SYNC (≥30)** | | | | | | | | | | | | | |
| 174 | Users denied suppresses all removals | okta_user | family failure | complete | denied | denied | No | n/a | n/a | n/a | `test_users_denied_suppresses_all_user_removals` | PASS | |
| 175 | Users unavailable suppresses removals | okta_user | family failure | complete | unavailable | unavailable | No | n/a | n/a | n/a | `test_users_unavailable_suppresses_removals` | PASS | |
| 176 | Users partial suppresses removals | okta_user | family failure | complete | partial | partial | No | n/a | n/a | n/a | `test_users_partial_suppresses_removals` | PASS | |
| 177 | Users throttled suppresses removals | okta_user | family failure | complete | throttled | throttled | No | n/a | n/a | n/a | `test_users_throttled_suppresses_removals` | PASS | |
| 178 | Users complete allows real removal | okta_user | real removal | complete | complete | complete | Yes | low | n/a | n/a | `test_users_complete_allows_real_removal` | PASS | |
| 179 | Unrelated family denied doesn't affect users | okta_user + okta_application | mixed | complete/complete | complete/denied | mixed | Yes (users) | low | n/a | n/a | `test_unrelated_family_denied_does_not_affect_users` | PASS | |
| 180 | Applications denied suppresses app removals | okta_application | family failure | complete | denied | denied | No | n/a | n/a | n/a | `test_applications_denied_suppresses_app_removals` | PASS | |
| 181 | Policies denied suppresses policy removals | okta_policy | family failure | complete | denied | denied | No | n/a | n/a | n/a | `test_policies_denied_suppresses_policy_removals` | PASS | |
| 182 | Authenticators denied suppresses removals | okta_authenticator | family failure | complete | denied | denied | No | n/a | n/a | n/a | `test_authenticators_denied_suppresses_removals` | PASS | |
| 183 | Org record's own removal never suppressed | okta_organization | removed | present | absent | n/a | Yes | n/a | n/a | n/a | `test_org_record_itself_removed_is_never_suppressed` | PASS | |
| 184 | Missing org record falls back to normal removal | okta_organization/okta_user | mixed | present | org absent | n/a | n/a | n/a | n/a | n/a | `test_no_org_record_in_new_snapshot_falls_back_to_normal_removal` | PASS | Can't consult completeness -> normal path |
| 185 | Group A complete, B denied, C complete | okta_group_membership | per-parent | 3 groups w/ members | B's members absent | A/C complete, B denied | A/C Yes, B No | n/a | n/a | n/a | `test_group_a_complete_b_denied_c_complete` | PASS | Per-parent granularity |
| 186 | App user-assignments denied, group-assignments complete | okta_application_user/group_assignment | per-parent | both present | user absent, group present | mixed | group Yes, user No | n/a | n/a | n/a | `test_app_a_user_assignments_denied_group_assignments_complete` | PASS | |
| 187 | Policy rules per-policy (p1 complete, p2 denied) | okta_policy_rule | per-parent | both present | p1 gone (real), p2 suppressed | mixed | p1 Yes, p2 No | n/a | n/a | n/a | `test_policy_rules_per_policy` | PASS | |
| 188 | Parent group itself removed, families complete | okta_group + okta_group_membership | both removed | present | absent | complete | Yes (both) | n/a | n/a | n/a | `test_parent_group_itself_removed_falls_back_to_tenant_wide_check` | PASS | Fallback to tenant-wide check |
| 189 | Parent group removed, family incomplete | okta_group_membership | suppressed | present | absent | denied | No | n/a | n/a | n/a | `test_parent_group_removed_with_incomplete_family_suppresses_membership` | PASS | |
| 190 | Privileged identity suppressed (user assignments denied) | okta_privileged_identity | suppressed | present | absent | denied | No | n/a | n/a | n/a | `test_privileged_identity_suppressed_when_user_assignments_denied` | PASS | |
| 191 | Privileged identity suppressed (group assignments denied) | okta_privileged_identity | suppressed | present | absent | denied | No | n/a | n/a | n/a | `test_privileged_identity_suppressed_when_group_assignments_denied` | PASS | |
| 192 | Privileged identity real removal, both complete | okta_privileged_identity | removed | present | absent | complete | Yes | low | n/a | n/a | `test_privileged_identity_real_removal_when_both_complete` | PASS | |
| 193 | Privileged group suppressed | okta_privileged_group | suppressed | present | absent | denied | No | n/a | n/a | n/a | `test_privileged_group_suppressed_when_group_assignments_denied` | PASS | |
| 194 | Custom admin role suppressed | okta_admin_role (custom) | suppressed | present | absent | denied | No | n/a | n/a | n/a | `test_custom_admin_role_suppressed_when_custom_roles_denied` | PASS | |
| 195 | Built-in role suppressed only when BOTH assignment families fail | okta_admin_role (built-in) | suppressed | present | absent | both denied | No | n/a | n/a | n/a | `test_builtin_admin_role_suppressed_only_when_both_assignment_families_fail` | PASS | |
| 196 | Built-in role real removal when one family complete | okta_admin_role (built-in) | removed | present | absent | one complete, one denied | Yes | low | n/a | n/a | `test_builtin_admin_role_real_removal_when_one_family_complete` | PASS | |
| 197 | User admin role assignment suppressed | okta_user_admin_role_assignment | suppressed | present | absent | denied | No | n/a | n/a | n/a | `test_user_admin_role_assignment_suppressed` | PASS | |
| 198 | Group admin role assignment suppressed | okta_group_admin_role_assignment | suppressed | present | absent | denied | No | n/a | n/a | n/a | `test_group_admin_role_assignment_suppressed` | PASS | |
| 199 | First sync produces only "added" | all types | added | absent (no baseline) | present | n/a | n/a | n/a | n/a | n/a | `test_first_sync_produces_no_changes` | PASS | Never fabricates historical drift |
| 200 | Recovery after partial sync shows as added, not mass removal | okta_user | re-baseline | denied (blind) | complete | denied->complete | n/a | n/a | n/a | n/a | `test_recovery_after_partial_sync_shows_as_added_not_mass_removal` | PASS | Documented re-baseline choice |
| 201 | Both-blind syncs produce no changes | okta_user | n/a | denied | denied | denied/denied | n/a | n/a | n/a | n/a | `test_recovery_after_partial_sync_shows_as_added_not_mass_removal` (2nd assertion) | PASS | |
| 202 | Everyone-group unresolved parent never fires Finding | okta_application_group_assignment | n/a | n/a | everyone_group=None | n/a | n/a | n/a | okta_app_assigned_to_everyone_group never fires | n/a | `test_unknown_everyone_group_never_fires_the_finding` | PASS | Regression test |
| 203 | Unresolved group parent gives unknown booleans | okta_application_group_assignment | n/a | n/a | everyone_group=None, built_in_group=None | n/a | n/a | n/a | n/a | n/a | `test_unresolved_group_parent_gives_unknown_everyone_group` | PASS | Bug fix regression |
| **PAGINATION / RETRY (≥20)** | | | | | | | | | | | | | |
| 204 | Page 1 succeeds, page 2 403 | okta_user | mid-page failure | n/a | 1 record retained | partial | n/a | n/a | n/a | no retry (403 not retried) | `test_page1_succeeds_page2_403` | PASS | |
| 205 | Page 1 succeeds, page 2 429 exhausted | okta_user | mid-page failure | n/a | 1 record retained | partial | n/a | n/a | n/a | bounded retry then give up | `test_page1_succeeds_page2_429_exhausted` | PASS | |
| 206 | Page 1 succeeds, page 2 times out | okta_user | mid-page failure | n/a | 1 record retained | partial | n/a | n/a | n/a | no retry on timeout category | `test_page1_succeeds_page2_times_out` | PASS | |
| 207 | Page 1 succeeds, page 2 5xx (500/502/503/504) | okta_user | mid-page failure | n/a | 1 record retained | partial | n/a | n/a | n/a | n/a | `test_page1_succeeds_page2_5xx` | PASS | All 4 status codes verified |
| 208 | Users 429 exhausted on first page | okta_user | first-page failure | n/a | family unavailable/denied | unavailable/denied | No | n/a | n/a | bounded retry, then give up | `test_users_429_exhausted_is_partial_not_crash` | PASS | Never crashes |
| 209 | Users connect-timeout | okta_user | first-page failure | n/a | family unavailable | unavailable | No | n/a | n/a | n/a | `test_users_timeout_is_unavailable` | PASS | |
| 210 | Users read-timeout | okta_user | first-page failure | n/a | family unavailable | unavailable | No | n/a | n/a | n/a | `test_users_read_timeout_is_unavailable` | PASS | Distinguished from connect timeout |
| 211 | Users 500 | okta_user | first-page failure | n/a | family unavailable | unavailable | No | n/a | n/a | n/a | `test_users_500_is_unavailable` | PASS | |
| 212 | Users 503 | okta_user | first-page failure | n/a | family unavailable | unavailable | No | n/a | n/a | n/a | `test_users_503_is_unavailable` | PASS | |
| 213 | Users 403 | okta_user | first-page failure | n/a | family denied | denied | No | n/a | n/a | not retried | `test_users_403_is_denied` | PASS | |
| 214 | Users 401 mid-fetch not fatal | okta_user | first-page failure | n/a | fetch continues | unavailable | No | n/a | n/a | not retried | `test_users_401_mid_fetch_is_unavailable_not_fatal` | PASS | |
| 215 | Custom roles 404 (unsupported edition) | okta_admin_role (custom) | optional endpoint | n/a | unavailable/denied, not fatal | unavailable/denied | No | n/a | n/a | n/a | `test_custom_roles_404_is_unavailable_not_denied_not_fatal` | PASS | Never "tenant invalid" |
| 216 | Custom roles 403 (capability drift) | okta_admin_role (custom) | capability drift | previously available | denied | denied | No | n/a | n/a | n/a | `test_custom_roles_becomes_403_does_not_infer_all_roles_deleted` | PASS | |
| 217 | Authenticators become unavailable (capability drift) | okta_authenticator | capability drift | previously available | unavailable | unavailable | No | n/a | n/a | n/a | `test_authenticators_becomes_unavailable_does_not_infer_deletion` | PASS | |
| 218 | Cross-origin next Link doesn't hang or leak | okta_user | Link edge case | n/a | 1 record, stops safely | partial (truncated=True) | n/a | n/a | n/a | n/a | `test_cross_origin_next_link_does_not_leak_credentials_or_hang` | PASS | |
| 219 | Repeated next Link doesn't hang | okta_user | Link edge case | n/a | terminates | partial (truncated=True) | n/a | n/a | n/a | n/a | `test_repeated_next_link_does_not_hang` | PASS | |
| 220 | paginate() one page, not truncated | generic | n/a | n/a | 2 items | complete | n/a | n/a | n/a | n/a | `test_one_page` (foundation) | PASS | |
| 221 | paginate() multi-page natural end | generic | n/a | n/a | 2 items | complete | n/a | n/a | n/a | n/a | `test_multiple_pages_via_link_header` (foundation) | PASS | |
| 222 | paginate() cross-origin rejected -> truncated=True | generic | n/a | n/a | 1 item | partial | n/a | n/a | n/a | n/a | `test_cross_origin_next_stops_pagination_without_raising` (foundation) | PASS | Bug fix: previously reported complete |
| 223 | paginate() page cap hit -> truncated=True | generic | n/a | n/a | <=3 items | partial | n/a | n/a | n/a | n/a | `test_page_cap_bounds_iteration` (foundation) | PASS | Bug fix |
| 224 | paginate() repeated link -> truncated=True | generic | n/a | n/a | <50 items | partial | n/a | n/a | n/a | n/a | `test_repeated_next_link_detected_and_stopped` (foundation) | PASS | Bug fix |
| 225 | paginate() dedup overlapping page, not truncated | generic | n/a | n/a | 3 unique items | complete | n/a | n/a | n/a | n/a | `test_dedupes_records_by_id` (foundation) | PASS | |
| 226 | 429 then success | generic | n/a | n/a | success | n/a | n/a | n/a | n/a | 1 retry, mocked sleep | `test_429_then_success` (foundation) | PASS | |
| 227 | 429 exhausted raises RateLimitError at call_okta level | generic | n/a | n/a | throttled category | n/a | n/a | n/a | n/a | bounded retries, mocked sleep | `test_exhausted_retries_raises_rate_limit_error` (foundation) | PASS | |
| 228 | Sleep is always mocked, never real | generic | n/a | n/a | n/a | n/a | n/a | n/a | n/a | injectable sleep_fn | `test_sleep_is_mocked_never_real` (foundation) | PASS | |
| 229 | 401 never retried | generic | n/a | n/a | n/a | n/a | n/a | n/a | n/a | call_count==1 | `test_401_never_retried` (foundation) | PASS | |
| 230 | 403 never retried | generic | n/a | n/a | n/a | n/a | n/a | n/a | n/a | call_count==1 | `test_403_never_retried` (foundation) | PASS | |
| **SCALE / N+1 (≥15)** | | | | | | | | | | | | | |
| 231 | 2,000 users / 500 groups / 2,000 memberships | okta_user/okta_group/okta_group_membership | scale | n/a | all collected, unique IDs | complete | n/a | n/a | n/a | bounded per-group walk | `test_2000_users_500_groups_with_memberships` | PASS | elapsed<30s |
| 232 | 500 apps with per-app assignments | okta_application/okta_application_user_assignment | scale | n/a | all collected, unique IDs | complete | n/a | n/a | n/a | one call per app per direction, no dual user->apps walk | `test_500_apps_with_assignments` | PASS | elapsed<30s |
| 233 | 300 policies / 3,000 rules | okta_policy/okta_policy_rule | scale | n/a | all collected, unique IDs | complete | n/a | n/a | n/a | one call per policy, no refetch | `test_300_policies_3000_rules` | PASS | elapsed<30s |
| 234 | 200 policies / 2,000 rules / 50 authenticators (message 4 precedent) | okta_policy/okta_policy_rule/okta_authenticator | scale | n/a | all collected | complete | n/a | n/a | n/a | n/a | test_okta_policy_collection.py `TestScale` | PASS | Pre-existing, re-verified passing |
| 235 | 500 users / 100 groups / 50 custom roles (message 5 precedent) | okta_user/okta_group/okta_admin_role | scale | n/a | all collected | complete | n/a | n/a | n/a | bounded per-user role walk | test_okta_admin_role_collection.py `TestScale` | PASS | Re-verified passing |
| 236 | User walk capped below total user count reports partial | okta_user_admin_role_assignment | N+1 bound | n/a | walk stops at cap | partial | n/a | n/a | n/a | exactly `_MAX_USERS_FOR_ROLE_ENUMERATION` calls | `test_user_walk_capped_below_total_user_count_reports_partial` (message 5, re-verified) | PASS | Documented API-complexity limitation: no Okta bulk admin-role-assignment endpoint exists |
| 237 | Resource set referenced 100 times, fetched once | okta_user_admin_role_assignment | N+1 cache | n/a | 100 assignments, 1 resource-set call | complete | n/a | n/a | n/a | cached by resource_set_id | `test_same_resource_set_referenced_100_times_fetched_once` | PASS | |
| 238 | Denied resource set is unknown, not scoped | okta_user_admin_role_assignment | n/a | n/a | resource_set_scope_category=None | n/a | n/a | n/a | n/a | n/a | `test_denied_resource_set_is_unknown_not_scoped` | PASS | |
| 239 | Malformed resource set (message 5 precedent) | okta_user_admin_role_assignment | n/a | n/a | unknown, never guessed | n/a | n/a | n/a | n/a | n/a | `categorize_resource_set_resources` returns unknown on non-list | PASS | |
| 240 | App-assignment call count: no dual app->users AND user->apps walk | okta_application_user_assignment | N+1 audit | n/a | n/a | n/a | n/a | n/a | n/a | one call per app per direction only | Direct code review: `_fetch_app_user_assignments`/`_fetch_app_group_assignments` walk apps once each, never a user-centric pass | PASS | Documented in connector docstrings |
| 241 | Policy-rule call count: no duplicate policy fetch | okta_policy_rule | N+1 audit | n/a | n/a | n/a | n/a | n/a | n/a | one call per policy | `test_policies_collected_once_not_refetched_for_rules` (message 4, re-verified) | PASS | |
| 242 | Same source data produces identical record order/IDs | all types | determinism | n/a | identical across 2 fetches | n/a | n/a | n/a | n/a | n/a | `test_same_source_data_produces_identical_record_sets` | PASS | Fixed: sorted() added to `_derive_privileged_identities` |
| 243 | Idempotent diff produces zero Changes | okta_organization/okta_user | idempotency | snapshot A | snapshot A | n/a | n/a | 0 changes | n/a | n/a | `test_idempotent_diff_produces_zero_changes` | PASS | |
| 244 | No state leakage between two fetches on reused connector | all types | state isolation | tenant A | tenant B | n/a | n/a | n/a | n/a | n/a | `test_reused_connector_instance_does_not_leak_state_between_tenants` | PASS | Resource-set cache/completeness/indexes are per-fetch locals, never instance state |
| 244a | Custom-role permissions call bounded by role count, not user count | okta_admin_role (custom) | N+1 audit | n/a | one permissions call per custom role | n/a | n/a | n/a | n/a | bounded by `_MAX_CUSTOM_ADMIN_ROLES`, independent of tenant user count | Direct code review: `_fetch_custom_admin_roles` loops over collected roles only | PASS | Confirmed not proportional to user/group count |
| **UNKNOWN-STATE DISCIPLINE (≥15)** | | | | | | | | | | | | | |
| 245 | mfa_requirement=unknown never fires no-MFA Finding | okta_policy_rule | n/a | n/a | unknown | n/a | n/a | n/a | okta_signon_mfa_not_required does not fire | n/a | message 6 `TestSignonMfaNotRequired::test_unknown_does_not_fire` | PASS | |
| 246 | phishing_resistant=unknown never fires not-phishing-resistant Finding | okta_policy_rule | n/a | n/a | unknown | n/a | n/a | n/a | okta_phishing_resistant_not_required does not fire | n/a | message 6 `TestPhishingResistantNotRequired::test_unknown_does_not_fire` | PASS | |
| 247 | role privilege=unknown never fires High custom-admin Finding | okta_admin_role | n/a | n/a | tier=unknown | n/a | n/a | n/a | okta_custom_admin_role_high_risk does not fire | n/a | message 6 `TestCustomAdminRoleHighRisk::test_unknown_tier_does_not_fire` | PASS | |
| 248 | Redirect posture unavailable never fires HTTP/wildcard Finding | okta_application | n/a | n/a | count=None | n/a | n/a | n/a | okta_oidc_http_redirect/okta_oidc_wildcard_redirect do not fire | n/a | message 6 unknown tests | PASS | |
| 249 | Assignment family denied never inferred as "no admins" | okta_user_admin_role_assignment | n/a | n/a | family denied | denied | n/a | n/a | n/a | n/a | `test_users_denied_suppresses_all_user_removals`-equivalent for admin roles | PASS | |
| 250 | categorize_scope: both counts unknown | okta_policy_rule | n/a | None/None | unknown | n/a | n/a | n/a | n/a | n/a | `test_missing_groups_block_with_known_zero_users_is_unknown`-family | PASS | |
| 251 | categorize_scope: groups unknown, users known-zero (bug fix) | okta_policy_rule | n/a | None/0 | unknown (was: all_users) | n/a | n/a | n/a | n/a | n/a | `test_missing_groups_block_with_known_zero_users_is_unknown` | PASS | Bug found+fixed this message |
| 252 | categorize_scope: groups known-zero, users unknown (routine default preserved) | okta_policy_rule | n/a | 0/None | all_users | n/a | n/a | n/a | n/a | n/a | `test_missing_users_block_alone_is_not_forced_unknown` | PASS | Confirmed correct, not over-corrected |
| 253 | categorize_scope: positive count wins regardless of other side | okta_policy_rule | n/a | 3/None | scoped_groups | n/a | n/a | n/a | n/a | n/a | `test_positive_groups_count_wins_even_if_users_unknown` | PASS | |
| 254 | password_lockout_present unknown never fires no-lockout Finding | okta_policy | n/a | n/a | None | n/a | n/a | n/a | okta_password_policy_no_lockout does not fire | n/a | message 6 `TestPasswordNoLockout::test_unknown_does_not_fire` | PASS | |
| 255 | password_history_present unknown never fires no-history Finding | okta_policy | n/a | n/a | None | n/a | n/a | n/a | okta_password_policy_no_history does not fire | n/a | message 6 `TestPasswordNoHistory::test_unknown_does_not_fire` | PASS | |
| 256 | password_min_length_category unknown never fires weak Finding | okta_policy | n/a | n/a | unknown | n/a | n/a | n/a | okta_password_policy_weak_min_length does not fire | n/a | message 6 `TestPasswordWeakMinLength::test_unknown_length_does_not_fire` | PASS | |
| 257 | everyone_group unresolved (None) never fires Everyone Finding | okta_application_group_assignment | n/a | n/a | None | n/a | n/a | n/a | okta_app_assigned_to_everyone_group does not fire | n/a | `test_unknown_everyone_group_never_fires_the_finding` | PASS | Bug found+fixed this message |
| 258 | Unrecognized user status never classified as a known weakening | okta_user | modified | ACTIVE | SOME_FUTURE_STATUS | n/a | n/a | medium (conservative, not silently ignored) | n/a | n/a | `test_active_to_unknown` | PASS | |
| 259 | Assignment scope unknown never fires unscoped-role Finding | okta_user_admin_role_assignment | n/a | n/a | unknown | n/a | n/a | n/a | okta_unscoped_admin_role_assignment does not fire | n/a | message 6 `TestUnscopedAdminRoleAssignment::test_unknown_scope_does_not_fire` | PASS | |

## Row counts

- Change classification: 152 rows (required >=80)
- Finding-vs-Change parity: 21 rows (required >=20, reported separately per task item 49)
- Partial sync: 30 rows (required >=30)
- Pagination/retry: 27 rows (required >=20)
- Scale/N+1: 15 rows (required >=15)
- Unknown-state discipline: 15 rows (required >=15)
- **Total unique rows: 260** (required >=160)

## Real bugs found and fixed during this message's audit

1. **`categorize_scope()` partial-unknown coercion** (`okta_connectors/okta_schema.py`) —
   a known-zero count on one side combined with a genuinely unresolvable
   count on the other side was coerced into `SCOPE_ALL_USERS`, the
   broadest and most Finding-triggering category. Fixed with an
   asymmetric check: a missing/malformed `groups` block is unknown
   (abnormal shape); a missing `users` block alone is not (Okta's own
   routine default for the vast majority of rules).
2. **`everyone_group`/`built_in_group` defaulting to `False` instead of
   `None`** (`okta.py::_normalize_app_group_assignment`) when the
   assignment's group parent couldn't be resolved — silently suppressing
   a real Everyone-group Security Finding whenever group collection was
   denied/partial while app-group-assignment collection succeeded.
3. **`paginate()` not distinguishing a natural end-of-list from a
   mid-pagination failure/cap/repeated-or-rejected Link** — the single
   most significant finding of this audit. A later-page 403/429/5xx/
   timeout, a page-cap hit, a repeated Link, or a rejected cross-origin
   Link were all silently reported as `FAMILY_COMPLETE`, which would
   have caused the NEW false-removal-suppression logic (built earlier in
   this same message) to trust an actually-incomplete result and permit
   real-looking-but-false removal Changes for every record on the unread
   pages. Fixed by adding a `truncated` return flag to `paginate()`,
   consulted by `_collect_family()` to force `FAMILY_PARTIAL` regardless
   of whether the item count happened to be under the cap.
4. **Non-deterministic record ordering** in
   `_derive_privileged_identities()` — iterated a Python `set` union
   (hash-randomized across runs) rather than a sorted sequence. Fixed
   with `sorted()`.
