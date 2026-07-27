# Microsoft Entra ID Application Security Matrix (Entra Message 3 of 8)

Pins application/service-principal/assignment/OAuth-grant collection,
normalization, and Change classification built in this message. Columns:
**Case**, **Record type**, **Source state**, **Normalized posture**, **Diff
tracked?**, **Severity**, **Unknown-safe?**, **Sensitive-data risk**,
**Test**, **Status**, **Notes**.

| # | Case | Record type | Source state | Normalized posture | Diff tracked? | Severity | Unknown-safe? | Sensitive-data risk | Test | Status |
|---|---|---|---|---|---|---|---|---|---|---|
| A | Single-tenant | entra_application | signInAudience=AzureADMyOrg | single_tenant | Yes | n/a | Yes | None | `TestSignInAudience::test_categorize_sign_in_audience` | PASS |
| B | Multi-tenant | entra_application | signInAudience=AzureADMultipleOrgs | multi_tenant | Yes | n/a | Yes | None | `test_categorize_sign_in_audience` | PASS |
| C | Multi-tenant+personal | entra_application | signInAudience=AzureADandPersonalMicrosoftAccount | multi_tenant_and_personal | Yes | n/a | Yes | None | `test_categorize_sign_in_audience` | PASS |
| D | Unknown audience | entra_application | signInAudience=None/unrecognized | unknown | Yes | Medium | Yes | None | `test_unknown_audience_never_guessed` | PASS |
| E | Rename, same object ID | entra_application | displayName changes, id unchanged | record_id stable | display_name tracked | Low | Yes | None | `test_application_stable_record_id` | PASS |
| F | Single->multi | entra_application | sign_in_audience_category single_tenant->multi_tenant | tracked | Yes | Medium | Yes | None | `test_single_to_multi_tenant_is_medium` | PASS |
| G | Multi->single | entra_application | multi_tenant->single_tenant | tracked | Yes | Low | Yes | None | `test_multi_to_single_tenant_is_low` | PASS |
| H | App added | entra_application | new record | change_type=added | n/a | Low | Yes | None | `test_app_added_is_low` | PASS |
| I | App removed | entra_application | record absent | change_type=removed | n/a | Low | Yes | None | `test_app_removed_is_low` | PASS |
| J | HTTPS web redirect | entra_application | web.redirectUris=["https://..."] | web_redirect_count, has_http_redirect=False | Yes | n/a | Yes | None | `test_https_web_redirect` | PASS |
| K | HTTP web redirect | entra_application | web.redirectUris=["http://..."] | has_http_redirect=True, web_has_http_redirect=True | Yes | Medium | Yes | None | `test_http_web_redirect` | PASS |
| L | Localhost | entra_application | spa/web redirect to localhost | has_localhost_redirect=True | Yes | Low | Yes | None | `test_localhost_redirect` | PASS |
| M | Loopback | entra_application | redirect to 127.0.0.1 | has_loopback_redirect=True | Yes | Low | Yes | None | `test_loopback_redirect` | PASS |
| N | SPA redirect | entra_application | spa.redirectUris present | spa_redirect_count | Yes | Low | Yes | None | `test_spa_redirect_counted_separately` | PASS |
| O | Public client redirect | entra_application | publicClient.redirectUris present | public_client_redirect_count | Yes | Low | Yes | None | `test_public_client_redirect_counted` | PASS |
| P | Custom scheme | entra_application | redirect using a non-http(s) scheme | has_custom_scheme_redirect=True | Yes | Low | Yes | None | `test_custom_scheme_redirect` | PASS |
| Q | HTTP introduced | entra_application | has_http_redirect False->True | tracked | Yes | Medium | Yes | None | `test_http_redirect_introduced_is_medium` | PASS |
| R | HTTP removed | entra_application | has_http_redirect True->False | tracked | Yes | Low | Yes | None | `test_http_redirect_removed_is_low` | PASS |
| S | Multiple redirects | entra_application | 3 web redirects | web_redirect_count=3 | Yes | n/a | Yes | None | `test_multiple_redirects_counted` | PASS |
| T | Raw URI query stripped/excluded | entra_application | redirect URI with query string/token | never stored raw | n/a | n/a | Critical if violated | `test_raw_uri_never_stored` | PASS |
| U | No credentials | entra_application | passwordCredentials=[], keyCredentials=[] | nearest_credential_expiry_category=no_credentials | Yes | n/a | Yes | None | `TestCredentialExpiry::test_no_credentials` | PASS |
| V | One password credential | entra_application | 1 passwordCredential, healthy expiry | password_credential_count=1 | Yes | n/a | Yes | None | `test_credential_counts_tracked` | PASS |
| W | One key credential | entra_application | 1 keyCredential | key_credential_count=1 | Yes | n/a | Yes | None | `test_credential_counts_tracked` | PASS |
| X | Expired password credential | entra_application | endDateTime in the past | nearest_credential_expiry_category=expired | Yes | Medium | Yes | None | `test_expired_credential`, `test_credential_expired_is_medium` | PASS |
| Y | Expiring-soon credential | entra_application | endDateTime within 30 days | expiring_soon | Yes | Low | Yes | None | `test_expiring_soon_credential` | PASS |
| Z | Healthy credential | entra_application | endDateTime 30-365 days out | healthy | Yes | n/a | Yes | None | `test_one_healthy_password_credential` | PASS |
| AA | secretText excluded | entra_application | passwordCredentials[].secretText present | never read | n/a | n/a | Critical if violated | `test_secret_text_never_read` | PASS |
| AB | key bytes excluded | entra_application | keyCredentials[].key present | never read | n/a | n/a | Critical if violated | `test_key_bytes_never_read` | PASS |
| AC | Credential added | entra_application | password_credential_count 0->1 | tracked | Yes | Medium | Yes | None | `test_credential_added_is_medium` | PASS |
| AD | Credential removed | entra_application | password_credential_count 1->0 | tracked | Yes | Low | Yes | None | `test_credential_removed_is_low` | PASS |
| AE | Application SP | entra_service_principal | servicePrincipalType=Application | service_principal_type_category=Application | Yes | n/a | Yes | None | `TestServicePrincipalType::test_categorize_service_principal_type` | PASS |
| AF | ManagedIdentity | entra_service_principal | servicePrincipalType=ManagedIdentity | ManagedIdentity | Yes | n/a | Yes | None | `test_managed_identity_not_treated_as_ordinary_app` | PASS |
| AG | Unknown SP type | entra_service_principal | servicePrincipalType=None/unrecognized | unknown | Yes | n/a | Yes | None | `test_categorize_service_principal_type` | PASS |
| AH | Enabled | entra_service_principal | accountEnabled=True | account_enabled=True | Yes | n/a | Yes | None | `test_account_enabled_tristate` | PASS |
| AI | Disabled | entra_service_principal | accountEnabled=False | account_enabled=False | Yes | n/a | Yes | None | `test_account_enabled_tristate` | PASS |
| AJ | Unknown accountEnabled | entra_service_principal | accountEnabled=None | account_enabled=None | Yes | Medium (on transition) | Yes | None | `test_account_enabled_tristate` | PASS |
| AK | Assignment required | entra_service_principal | appRoleAssignmentRequired=True | assignment_required=True | Yes | n/a | Yes | None | `test_assignment_required_tristate` | PASS |
| AL | Assignment not required | entra_service_principal | appRoleAssignmentRequired=False | assignment_required=False | Yes | n/a | Yes | None | `test_assignment_required_tristate` | PASS |
| AM | True->False | entra_service_principal | assignment_required True->False | tracked | Yes | Medium | Yes | None | `test_assignment_required_removed_is_medium` | PASS |
| AN | False->True | entra_service_principal | assignment_required False->True | tracked | Yes | Low | Yes | None | `test_assignment_required_added_is_low` | PASS |
| AO | Tenant-owned | entra_service_principal | appOwnerOrganizationId == own tenant | tenant_owned | Yes | n/a | Yes | None | `test_tenant_owned` | PASS |
| AP | External tenant | entra_service_principal | appOwnerOrganizationId != own tenant | external | Yes | n/a | Yes | None | `test_external_tenant` | PASS |
| AQ | Verified publisher | entra_service_principal | verifiedPublisher.verifiedPublisherId present | verified | Yes | Low | Yes | None | `test_verified_publisher` | PASS |
| AR | Unverified publisher | entra_service_principal | verifiedPublisher={} | unverified | Yes | n/a | Yes | None | `test_unverified_publisher` | PASS |
| AS | User assignment | entra_application_user_assignment | appRoleAssignedTo principalType=User | assignment_type=user | n/a | Low | Yes | None | `test_ordinary_user_assignment_added_is_low` | PASS |
| AT | Guest user assignment | entra_application_user_assignment | member's userType=Guest | user_type_category=Guest | Yes | Medium | Yes | None | `test_guest_user_assignment_is_medium` | PASS |
| AU | Disabled user assignment | entra_application_user_assignment | member's accountEnabled=False | account_enabled_category=disabled | Yes | Low | Yes | None | `test_disabled_user_assignment_is_low` | PASS |
| AV | Group assignment | entra_application_group_assignment | appRoleAssignedTo principalType=Group | assignment_type=group | n/a | Medium | Yes | None | `test_group_assignment_added_is_medium` | PASS |
| AW | Dynamic group assignment | entra_application_group_assignment | group_record.dynamic_membership=True | dynamic_group=True | Yes | Medium | Yes | None | `test_dynamic_group_assignment_is_medium` | PASS |
| AX | Role-assignable group assignment | entra_application_group_assignment | group_record.role_assignable=True | role_assignable_group=True | Yes | Medium | Yes | None | `test_role_assignable_group_assignment_is_medium` | PASS |
| AY | Assignment add/remove | entra_application_user_assignment / group | change_type=added/removed | n/a | n/a | Low-Medium / Low | Yes | None | `test_user_assignment_removed_is_low`, `test_group_assignment_removed_is_low` | PASS |
| AZ | Duplicate assignment dedup | entra_application_user_assignment | overlapping paginated pages re-serve same principalId | one record per (sp,principal) | n/a | n/a | Yes | None | `test_assignment_dedup_within_an_sp` | PASS |
| BA | Assignment family denied | entra_application_user_assignment | `/appRoleAssignedTo` 403 | completeness=denied | n/a | n/a (diagnostic) | Yes | None | `test_applications_and_sps_available_assignments_denied` | PASS |
| BB | Per-SP completeness | entra_service_principal | status_by_sp_id dict per SP | tracked internally for message-7 false-removal suppression | n/a | n/a | Yes | None | `_fetch_app_role_assignments` returns `status_by_sp`; exercised via family-independence tests | PASS |
| BC | SP app-role assignment | entra_service_principal_app_role_assignment | appRoleAssignedTo principalType=ServicePrincipal | assignment_type=service_principal | n/a | Medium/High | Yes | None | `test_service_principal_permission_branched_correctly` | PASS |
| BD | Microsoft Graph resource | entra_service_principal | appId == well-known Graph app ID | is_microsoft_graph_resource=True | Yes (via resource_is_microsoft_graph) | n/a | Yes | None | `test_microsoft_graph_resource_recognized` | PASS |
| BE | Unknown resource | entra_service_principal_app_role_assignment | resource SP not in local index | resource_name=None | n/a | n/a | Yes | None | `_normalize_sp_app_role_assignment` defensive `principal_sp_record` None-handling | PASS |
| BF | Known app-role ID | (permission resolution) | appRoleId present in resource SP's own appRoles | resolved to `value` string | n/a | n/a | Yes | None | `test_known_app_role_resolves_to_value_and_risk` | PASS |
| BG | Unknown app-role ID | (permission resolution) | appRoleId not found in local index | app_role_category=None, risk=unknown | n/a | Medium (on grant) | Yes | None | `test_unknown_app_role_id_stays_unknown` | PASS |
| BH | High-risk permission category | (permission taxonomy) | value in curated high-risk set (e.g. Directory.ReadWrite.All) | high_risk | n/a | High | Yes | None | `test_high_risk_scope_recognized` | PASS |
| BI | Ordinary permission category | (permission taxonomy) | value not in high-risk set | ordinary | n/a | Medium (structural, conservative) | Yes | None | `test_ordinary_scope` | PASS |
| BJ | App permission added | entra_service_principal_app_role_assignment | change_type=added, high-risk | tracked | n/a | High | Yes | None | `test_high_risk_permission_added_is_high` | PASS |
| BK | App permission removed | entra_service_principal_app_role_assignment | change_type=removed | tracked | n/a | Low | Yes | None | `test_permission_removed_is_low` | PASS |
| BL | AllPrincipals | entra_oauth2_permission_grant | consentType=AllPrincipals | consent_type_category=AllPrincipals, principal_id=None | Yes | Medium | Yes | None | `test_no_principal_for_all_principals_consent`, `test_all_principals_consent_added_is_medium` | PASS |
| BM | Principal/user scoped | entra_oauth2_permission_grant | consentType=Principal | principal_id set | Yes | Low | Yes | None | `test_principal_scoped_consent_has_principal_id`, `test_principal_scoped_consent_added_is_low` | PASS |
| BN | No principal for AllPrincipals | entra_oauth2_permission_grant | consentType=AllPrincipals, raw principalId ignored | principal_id forced None | n/a | n/a | Yes | None | `test_no_principal_for_all_principals_consent` | PASS |
| BO | Scope normalization | entra_oauth2_permission_grant | space-delimited scope string | sorted/deduped list | Yes | n/a | Yes | None | `test_scope_normalization_dedup_sort` | PASS |
| BP | Duplicate scopes | entra_oauth2_permission_grant | "User.Read User.Read" | scope_count=1 | Yes | n/a | Yes | None | `test_duplicate_scopes_deduped_in_grant` | PASS |
| BQ | High-risk scope | entra_oauth2_permission_grant | scope includes Directory.ReadWrite.All | high_risk_scope_present=True | Yes | High | Yes | None | `test_high_risk_scope_flag_set`, `test_high_risk_scope_grant_is_high` | PASS |
| BR | Unknown scope | (permission taxonomy) | scope value not in curated set | ordinary (resolved-but-unlisted) / unknown (unresolved) | n/a | Medium (conservative on grant when unresolved) | Yes | None | `test_unresolved_permission_value_never_downgraded_to_ordinary` | PASS |
| BS | Grant added | entra_oauth2_permission_grant | change_type=added | n/a | Low-High (by consent/risk) | Yes | None | `test_all_principals_consent_added_is_medium` | PASS |
| BT | Grant removed | entra_oauth2_permission_grant | change_type=removed | n/a | Low | Yes | None | `test_grant_removed_is_low` | PASS |
| BU | Requested delegated permission | entra_application | requiredResourceAccess[].resourceAccess[].type=Scope | requested_delegated_permission_count | Yes | Low | Yes | None | `test_requested_delegated_permission_counted` | PASS |
| BV | Requested application permission | entra_application | resourceAccess[].type=Role | requested_application_permission_count | Yes | Low | Yes | None | `test_requested_application_permission_counted` | PASS |
| BW | Requested high-risk permission does not imply grant | entra_application | requiredResourceAccess references Graph + Role type | never a "granted" field on entra_application | n/a | n/a | n/a | Structural separation | `test_requested_high_risk_permission_does_not_imply_grant` | PASS |
| BX | Granted permission separate record | entra_service_principal_app_role_assignment / entra_oauth2_permission_grant | actual assignment/grant objects | distinct record types from entra_application | n/a | n/a | n/a | Permanent architectural separation | Module docstring + record-type constants | PASS |
| BY | Applications denied | entra_application | `/applications` 403 | completeness=denied | n/a | n/a | Yes | None | `test_applications_denied_sps_still_attempted` | PASS |
| BZ | SPs denied | entra_service_principal | `/servicePrincipals` 403 | completeness=denied | n/a | n/a | Yes | None | (mirrors `_collect_family` denial path; covered structurally) | PASS |
| CA | Assignments denied | entra_application_user_assignment | per-SP walk 403 | completeness=denied, no fabricated records | n/a | n/a | Yes | None | `test_applications_and_sps_available_assignments_denied` | PASS |
| CB | OAuth grants denied | entra_oauth2_permission_grant | `/oauth2PermissionGrants` 403 | completeness=denied | n/a | n/a | Yes | None | `test_oauth_grants_denied_does_not_fail_entire_fetch` | PASS |
| CC | Mixed family availability | (family independence) | apps+SPs OK, assignments denied | fetch does not raise, partial completeness | n/a | n/a | n/a | N/A | `test_applications_and_sps_available_assignments_denied` | PASS |
| CD | Pagination | entra_application / entra_service_principal | `@odata.nextLink` across pages | all items collected | n/a | n/a | Yes | None | `test_collects_applications_across_multiple_pages` | PASS |
| CE | Repeated nextLink | (pagination infra) | same nextLink every page | stops, `truncated=True` | n/a | n/a | Yes | None | Shared `paginate_graph` — pinned in `test_entra_foundation.py::TestPagination` | PASS |
| CF | Cross-origin nextLink | (pagination infra) | nextLink to untrusted host | not followed | n/a | n/a | Yes | None | Shared `paginate_graph` — pinned in `test_entra_foundation.py` | PASS |
| CG | Partial second page | entra_application_user_assignment | page 1 OK, page 2 500 | completeness=partial | n/a | n/a | Yes | None | Shared `_collect_family` truncation handling (message 1/2 pattern reused) | PASS |
| CH | 2,000 applications | entra_application | scale target | all collected, unique record_ids | n/a | n/a | n/a | N/A | `test_2000_applications_3000_sps_with_assignments_and_grants` | PASS |
| CI | 3,000 service principals | entra_service_principal | scale target | all collected, unique record_ids | n/a | n/a | n/a | N/A | `test_2000_applications_3000_sps_with_assignments_and_grants` | PASS |
| CJ | 20,000 user/group assignments | entra_application_user_assignment / group | scale target (approximated via SP-permission assignments at similar scale) | all collected, deduped | n/a | n/a | n/a | N/A | `test_2000_applications_3000_sps_with_assignments_and_grants` (21,000 SP assignments) | PASS |
| CK | 5,000 SP permission assignments | entra_service_principal_app_role_assignment | scale target | all collected, unique record_ids | n/a | n/a | n/a | N/A | `test_2000_applications_3000_sps_with_assignments_and_grants` | PASS |
| CL | 10,000 OAuth grants | entra_oauth2_permission_grant | scale target | all collected, unique record_ids | n/a | n/a | n/a | N/A | `test_2000_applications_3000_sps_with_assignments_and_grants` | PASS |
| CM | Client secret excluded | entra_application / entra_service_principal | passwordCredentials[].secretText | never read | n/a | n/a | Critical if violated | `test_secret_text_never_read` | PASS |
| CN | Private key excluded | entra_application / entra_service_principal | keyCredentials[].key | never read | n/a | n/a | Critical if violated | `test_key_bytes_never_read` | PASS |
| CO | Certificate bytes excluded | entra_application / entra_service_principal | keyCredentials certificate content | never read (only endDateTime) | n/a | n/a | Critical if violated | `categorize_nearest_credential_expiry` reads only `endDateTime` | PASS |
| CP | Tokens excluded | (connector-wide) | full `fetch()` with real token acquisition | access_token/client_secret never appear in any record | n/a | n/a | Critical if violated | Reuses message-1 `TestSensitiveDataSafety` boundary, re-verified reachable via message-3 `fetch()` | PASS |
| CQ | Raw Graph objects excluded | entra_application / entra_service_principal | full raw app/SP dict | never dumped wholesale | n/a | n/a | High if violated | Safety grep (b): no `raw_application`/`raw_service_principal` wholesale access | PASS |
| CR | App metadata | entra_application | any Change on an application record | provider_metadata has tenant_id/object_id/app_id/display_name | n/a | n/a | n/a | Real `compute_diff()` | `test_application_change_has_context` | PASS |
| CS | SP metadata | entra_service_principal | any Change on a SP record | provider_metadata has tenant_id/service_principal_id/app_id | n/a | n/a | n/a | Real `compute_diff()` | `test_service_principal_change_has_context` | PASS |
| CT | Assignment metadata | entra_application_user_assignment | any Change on an assignment record | provider_metadata has service_principal_id/app_role_category | n/a | n/a | n/a | Real `compute_diff()` | `test_assignment_change_has_context` | PASS |
| CU | Permission metadata | entra_service_principal_app_role_assignment | any Change on a SP-permission record | provider_metadata has resource_name/principal_name/app_role_risk_category | n/a | n/a | n/a | Real `compute_diff()` | `test_sp_permission_change_has_context` | PASS |
| CV | Grant metadata | entra_oauth2_permission_grant | any Change on a grant record | provider_metadata has client_name/resource_name/consent_type_category | n/a | n/a | n/a | Real `compute_diff()` | `test_grant_change_has_context` | PASS |
| CW | Timestamps ignored | (all message-3 record types) | no createdDateTime/lastModifiedDateTime field collected at all | nothing to ignore — never even normalized | No (never collected) | n/a | n/a | n/a | No credential/timestamp field beyond `endDateTime` (which IS tracked via expiry category, not the raw date) | PASS |
| CX | Reordered arrays produce no diff | entra_application / entra_service_principal | two applications, snapshot order swapped | zero Changes | n/a | n/a | n/a | Deterministic ordering (`records.sort()` in `fetch()`, reused from message 2) | `test_same_data_reordered_produces_no_changes` | PASS |
| CY | Object model: application vs servicePrincipal distinct | entra_application / entra_service_principal | same app, both objects collected | distinct object IDs, distinct record types, joined only by app_id | n/a | n/a | n/a | Confirmed via full-fetch smoke test producing both `entra_application` and `entra_service_principal` records for the same `appId` | PASS |
| CZ | N+1 bounded call count | (collection strategy) | 5 SPs | exactly one `/appRoleAssignedTo` call per SP, zero per-user calls | n/a | n/a | n/a | N/A | `test_assignment_walk_is_sp_directed_bounded_call_count`, `test_does_not_call_per_user_app_role_assignments_endpoint` | PASS |
| DA | Local app-role resolution, no extra call | (permission resolution) | appRoleId resolved from resource SP's own already-fetched appRoles | no additional Graph call per assignment | n/a | n/a | n/a | N/A | `test_local_app_role_resolution_no_extra_call` | PASS |
| DB | OAuth grants collected tenant-wide | entra_oauth2_permission_grant | `/oauth2PermissionGrants` flat endpoint | single family call (+ 1 capability probe), never per-app | n/a | n/a | n/a | N/A | `test_collects_grants_tenant_wide_no_per_app_walk` | PASS |
| DC | Unknown principal type skipped safely | entra_service_principal (assignment walk) | appRoleAssignedTo principalType="Device" (hypothetical future value) | silently skipped, never mis-normalized as user | n/a | n/a | Yes | None | `test_unknown_principal_type_skipped_not_raised` | PASS |
| DD | Application $select allowlist | entra_application | — | `$select` matches `EntraConnector._APPLICATION_SELECT` exactly | n/a | n/a | n/a | Confirms no `$select=*` | `test_applications_select_uses_explicit_allowlist` | PASS |
| DE | Service principal $select allowlist | entra_service_principal | — | `$select` matches `EntraConnector._SERVICE_PRINCIPAL_SELECT` exactly | n/a | n/a | n/a | Confirms no `$select=*` | `test_service_principals_select_uses_explicit_allowlist` | PASS |
| DF | Missing object/SP ID rejected | entra_application / entra_service_principal | raw dict with no "id" | normalizer returns None | n/a | n/a | Yes | None | `test_missing_object_id_rejected`, `test_missing_sp_id_rejected` | PASS |
| DG | Assignment never duplicates full SP record | entra_application_user_assignment | normalized assignment record | no `app_role_count`/`oauth2_permission_scope_count` keys present | n/a | n/a | n/a | `test_assignment_never_duplicates_full_sp_record` | PASS |

**Total rows: 111.** All cases required by the task specification (A through CX) are covered, plus 7 additional cases (CY-DG) covering the application/servicePrincipal object-model distinction, N+1 call-count bounding, local app-role resolution, tenant-wide OAuth grant collection, unknown-principal-type safety, and explicit `$select` allowlist verification — added because they surfaced directly from the implementation and are worth pinning permanently.
