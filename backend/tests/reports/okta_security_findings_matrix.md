# Okta Security Findings Matrix (Okta message 6 of 8)

Columns: **Rule ID**, **Title**, **Category**, **Resource type**, **Trigger**, **Severity**, **Confidence**, **Rule pack(s)**, **Connector-reachable?**, **Completeness requirement**, **Change parity**, **Test**, **Status**, **Notes**.

30 implemented rules + 13 deliberately-rejected GAP/N/A candidates = 43 rows.

| # | Rule ID | Title | Category | Resource type | Trigger | Severity | Confidence | Connector-reachable? | Completeness requirement | Change parity | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | okta_super_admin_assigned | Super Administrator privilege assigned | Privileged identities & admin roles | okta_privileged_identity | has_super_admin==True | Critical | High | Yes — `TestPrivilegedIdentityReachability::test_super_admin_reachable_via_real_derivation` | None (record only derived when evidence exists) | Matches message-5 Change (grant=Critical) — `TestFindingChangeSeverityParity::test_super_admin_assigned_matches_super_admin_grant_change` | `TestSuperAdminAssigned` | PASS | |
| 2 | okta_high_tier_admin_assigned | High-privilege administrator assigned | Privileged identities & admin roles | okta_privileged_identity | has_high_privilege==True AND has_super_admin==False | High | High | Yes | None | Matches message-5 Change (high-tier grant=High) | `TestHighTierAdminAssigned` | PASS | Excludes Super Admin (exclusion hierarchy) |
| 3 | okta_custom_admin_role_high_risk | High-risk custom administrator role | Privileged identities & admin roles | okta_admin_role | custom==True AND privilege_tier in {critical,high} | Critical/High (dynamic) | High | Yes — `test_custom_admin_role_high_risk_reachable` | None | n/a (no per-role-catalog Change severity defined in message 5 beyond generic tier change) | `TestCustomAdminRoleHighRisk` | PASS | Never fires on unknown permission-derived tier |
| 4 | okta_admin_role_broad_resource_set | Custom administrator role assigned with an all-resources scope | Privileged identities & admin roles | okta_user/group_admin_role_assignment | custom==True AND resource_set_scope_category==all_resources AND tier known | High/Medium (dynamic) | Medium | Yes | None | n/a | `TestAdminRoleBroadResourceSet` | PASS | |
| 5 | okta_unscoped_admin_role_assignment | Scoped administrator role assigned without any scoping | Privileged identities & admin roles | okta_user/group_admin_role_assignment | role_type in {APP,USER,GROUP}_ADMIN AND assignment_scope_category==all | Medium | Medium | Yes — `test_unscoped_admin_role_assignment_reachable` | None | n/a | `TestUnscopedAdminRoleAssignment` | PASS | Fires on both user- and group-level assignment records |
| 6 | okta_privileged_group_grants_super_admin | Group grants Super Administrator privilege | Privileged identities & admin roles | okta_privileged_group | highest_privilege_tier==critical | Critical | High | Yes — `test_group_grants_super_admin_reachable` | None | Matches message-5 group Change (Critical) | `TestPrivilegedGroupGrantsSuperAdmin` | PASS | |
| 7 | okta_privileged_group_grants_high_tier_admin | Group grants high-tier administrator privilege | Privileged identities & admin roles | okta_privileged_group | highest_privilege_tier==high | High | High | Yes | None | Matches message-5 Change | `TestPrivilegedGroupGrantsHighTier` | PASS | Excludes critical |
| 8 | okta_broad_privileged_group | Privileged group has broad membership | Privileged identities & admin roles | okta_privileged_group | tier in {critical,high} AND member_count bucket in {21-100,100+} | High | Medium | Yes | None | n/a | `TestBroadPrivilegedGroup` | PASS | Reuses message-2 membership-count bucket semantics; documented threshold |
| 9 | okta_deprovisioned_identity_retains_admin_privilege | Deprovisioned identity retains administrative privilege | Identity lifecycle | okta_privileged_identity | user_status==DEPROVISIONED AND tier known (>=medium) | High/Medium (dynamic) | High | Yes — `test_deprovisioned_super_admin_reachable` | None | Directionally consistent with message-5 (never lower than Medium) | `TestDeprovisionedRetainsAdmin` | PASS | Never fires on unknown/read_only tier |
| 10 | okta_suspended_identity_retains_admin_privilege | Suspended identity retains administrative privilege | Identity lifecycle | okta_privileged_identity | user_status==SUSPENDED AND tier known (>=medium) | Medium | High | Yes | None | Directionally consistent | `TestSuspendedRetainsAdmin` | PASS | Never claims active access |
| 11 | okta_dormant_privileged_identity | Privileged identity has stale sign-in activity | Identity lifecycle | okta_privileged_identity | dormant_privileged_category==privileged_stale_login AND tier known | Medium/Low (dynamic) | Medium | Yes | None | n/a | `TestDormantPrivilegedIdentity` | PASS | Never fires on unknown last-login |
| 12 | okta_never_used_privileged_identity | Privileged identity has never signed in | Identity lifecycle | okta_privileged_identity | dormant_privileged_category==privileged_never_logged_in | Medium | Medium | Yes | None | n/a | `TestNeverUsedPrivilegedIdentity` | PASS | Distinct from unknown |
| 13 | okta_signon_mfa_not_required | Sign-on policy does not require MFA | Authentication & MFA | okta_policy_rule | mfa_requirement_category==none | High | High | Yes — `test_mfa_optional_reachable` (1FA path) | None | Matches message-4 Change (required->none=High) | `TestSignonMfaNotRequired` | PASS | Superseded by rule 15 when scope==all_users AND access==ALLOW |
| 14 | okta_signon_mfa_optional | Sign-on policy makes MFA optional | Authentication & MFA | okta_policy_rule | mfa_requirement_category==optional | Medium | High | Yes | None | Matches message-4 Change (required->optional=Medium) | `TestSignonMfaOptional` | PASS | |
| 15 | okta_broad_allow_rule_without_mfa | Broad sign-on rule allows access without MFA | Authentication & MFA | okta_policy_rule | access==ALLOW AND scope==all_users AND mfa==none | High | High | Yes — `test_mfa_not_required_reachable` | None | Matches message-4 Change | `TestBroadAllowWithoutMfa` | PASS | Supersedes rule 13 for the same record — no duplicate finding |
| 16 | okta_phishing_resistant_not_required | Sign-on policy does not require phishing-resistant authentication | Authentication & MFA | okta_policy_rule | phishing_resistant_category==not_phishing_resistant | Medium | Medium | Yes — `test_phishing_resistant_not_required_reachable` | None | Matches message-4 Change | `TestPhishingResistantNotRequired` | PASS | Never fires on unknown |
| 17 | okta_weak_authenticator_enabled | SMS, phone, or email authenticator is enabled | Authentication & MFA | okta_authenticator | active==True AND key in {phone_number,email} | Low | Medium | Yes — `test_weak_authenticator_reachable` | None | n/a | `TestWeakAuthenticatorEnabled` | PASS | Deliberately low severity — often legitimate for recovery |
| 18 | okta_password_policy_weak_min_length | Password policy minimum length is weak | Password policy | okta_policy (PASSWORD) | password_min_length_category==weak | High | High | Yes — `test_weak_min_length_reachable` | None | Directional match with message-4 Change | `TestPasswordWeakMinLength` | PASS | Bug found+fixed: policy_type check used lowercase "password" instead of actual "PASSWORD" — caught by reachability test |
| 19 | okta_password_policy_no_lockout | Password policy has no lockout control | Password policy | okta_policy (PASSWORD) | password_lockout_present==False | Medium | High | Yes | None | Matches message-4 Change | `TestPasswordNoLockout` | PASS | |
| 20 | okta_password_policy_no_history | Password policy has no password history requirement | Password policy | okta_policy (PASSWORD) | password_history_present==False | Medium | High | Yes | None | Matches message-4 Change | `TestPasswordNoHistory` | PASS | |
| 21 | okta_password_policy_no_complexity | Password policy does not require character complexity | Policy governance | okta_policy (PASSWORD) | password_complexity_required==False | Low | Medium | Yes | None | n/a | `TestPasswordNoComplexity` | PASS | Deliberately Low per 2026 NIST SP 800-63B guidance de-emphasizing composition rules |
| 22 | okta_oidc_wildcard_redirect | OIDC application allows a wildcard redirect URI | Applications & SSO | okta_application | wildcard_redirect_present==True | High | High | Yes — `test_wildcard_redirect_reachable` | None | Matches message-3 Change (High) | `TestOidcWildcardRedirect` + `TestFindingChangeSeverityParity::test_wildcard_redirect_matches_change_severity` | PASS | |
| 23 | okta_oidc_http_redirect | OIDC application allows an HTTP redirect URI | Applications & SSO | okta_application | http_redirect_count>0 | Medium | High | Yes — `test_http_redirect_reachable` | None | Matches message-3 Change | `TestOidcHttpRedirect` | PASS | |
| 24 | okta_oidc_custom_scheme_redirect_non_native | Non-native OIDC application uses a custom-scheme redirect | Applications & SSO | okta_application | custom_scheme_redirect_count>0 AND app_type_category not native | Medium | Medium | Yes | None | n/a | `TestOidcCustomSchemeNonNative` | PASS | Never fires when app type unknown or native |
| 25 | okta_saml_response_signing_disabled | SAML application does not sign responses | Applications & SSO | okta_application | saml_response_signed==False | Medium | High | Yes — `test_saml_signing_disabled_reachable` | None | n/a | `TestSamlResponseSigningDisabled` | PASS | |
| 26 | okta_saml_assertion_signing_disabled | SAML application does not sign assertions | Applications & SSO | okta_application | saml_assertion_signed==False | Medium | High | Yes | None | n/a | `TestSamlAssertionSigningDisabled` | PASS | |
| 27 | okta_weak_token_endpoint_auth | OIDC application uses no client authentication at the token endpoint | Applications & SSO | okta_application | token_endpoint_auth_method_category==none | Medium | High | Yes | None | n/a | `TestWeakTokenEndpointAuth` | PASS | |
| 28 | okta_app_assigned_to_everyone_group | Application is assigned to the Everyone group | Applications & SSO | okta_application_group_assignment | everyone_group==True | Medium | High | Yes — `test_everyone_group_assignment_reachable` | None | Matches message-3 Change (Medium) | `TestAppAssignedToEveryoneGroup` | PASS | |
| 29 | okta_deprovisioned_user_retains_app_assignment | Deprovisioned user retains an application assignment | Identity lifecycle | okta_application_user_assignment | user_status==DEPROVISIONED | Medium | High | Yes — `test_deprovisioned_user_retains_app_assignment_reachable` | None | n/a | `TestDeprovisionedRetainsAppAssignment` | PASS | |
| 30 | okta_suspended_user_retains_app_assignment | Suspended user retains an application assignment | Identity lifecycle | okta_application_user_assignment | user_status==SUSPENDED | Low | High | Yes | None | n/a | `TestSuspendedRetainsAppAssignment` | PASS | Never claims active access |

## GAP / N/A — deliberately rejected or deferred candidates

| # | Candidate | Reason rejected | Where documented |
|---|---|---|---|
| G1 | Generic "scoped administrator privilege assigned" (App/User/Group/Mobile/Help Desk Admin) | Normal enterprises legitimately have many scoped admins; bare inventory would be noise. The risky combination (unscoped grant) is covered by rule 5 instead. | `security_rules/okta.py` module docstring; frontend `DEFERRED_RULES` |
| G2 | Unknown custom role privilege / unknown built-in role type | Unknown coverage is diagnostic, never a risk claim. | same |
| G3 | Read-only administrator assigned | READ_ONLY_ADMIN/REPORT_ADMIN are explicitly non-write-capable — pure inventory noise. | same |
| G4 | Locked identity retains administrative privilege | LOCKED_OUT is transient/self-resolving; suspended/deprovisioned rules cover durable cases. | same |
| G5 | Policy is inactive | Many inactive policies are normal; only weak CURRENT posture is flagged. | same |
| G6 | Password lifetime is unbounded | 2026 NIST SP 800-63B guidance does not recommend forced periodic expiration; would be misleading legacy pressure. | same |
| G7 | SAML assertion encryption disabled | Not universally required given transport-layer TLS; would overclaim without deployment context. | same |
| G8 | Application-assignment inventory findings (user assigned to app) | Normal inventory, not risk. Everyone-group case (rule 28) is the one deterministic exception. | same |
| G9 | Tenant-wide "no phishing-resistant authenticator exists" / "no MFA policy found" absence rules | Only meaningful with known-complete family collection; the per-record evaluator interface cannot access `okta_organization.family_completeness` from a policy/authenticator record without a connector-side aggregate record this message does not add. | same |
| G10 | All-users sign-on policy allows no-MFA access while Super Administrators exist | The single highest-value composite candidate raised for this message. Requires a genuine cross-record join; the evaluator only ever sees one record at a time. Needs connector-side pre-derivation (collection scope, not Findings scope) — deferred to a future message. | same |
| G11 | Ordinary group membership / suspended-or-deprovisioned identity with only ordinary memberships | Not security-significant; only privilege/entitlement combinations are treated as findings. | same |
| G12 | Network-zone ("any network") / default session-lifetime posture | Okta's own common defaults for most tenants; would be high-noise, low-signal. | same |
| G13 | Multiple Super Administrators configured (tenant-level count) | No existing ConfigTrace cross-provider precedent for an arbitrary tenant-wide count threshold (e.g. ">=3"); per-identity Super Admin findings (rule 1) already surface every instance without inventing an unjustified threshold. | message-6 final report |

## Severity distribution (implemented rules)

- Critical: 3 (super_admin_assigned, privileged_group_grants_super_admin, custom_admin_role_high_risk-worst-case)
- High: 9 (high_tier_admin_assigned, admin_role_broad_resource_set-worst-case, privileged_group_grants_high_tier_admin, broad_privileged_group, deprovisioned_identity_retains_admin_privilege-worst-case, signon_mfa_not_required, broad_allow_rule_without_mfa, password_policy_weak_min_length, oidc_wildcard_redirect)
- Medium: 15
- Low: 3 (weak_authenticator_enabled, password_policy_no_complexity, suspended_user_retains_app_assignment)

## Category distribution

- Privileged identities & admin roles: 8
- Identity lifecycle: 6
- Authentication & MFA: 5
- Password policy: 3
- Policy governance: 1
- Applications & SSO: 7

## Confidence distribution

- High: 20
- Medium: 10
- Low: 0 (per architecture convention — low-confidence rules are deferred, never emitted)
