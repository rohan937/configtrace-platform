# Microsoft Entra ID Provider-Depth Matrix (Entra Message 8 of 8 — Public Launch)

Columns: **Surface**, **Requirement**, **Backend**, **Frontend**, **Test**, **Status**, **Notes**.

## Registration

| # | Surface | Requirement | Backend | Frontend | Test | Status | Notes |
|---|---|---|---|---|---|---|---|
| 1 | Sync dispatch | `sync_task.py` dispatches `entra` to `EntraConnector` | ✅ (message 1) | N/A | `test_sync_task_dispatches_entra` | PASS | Unchanged since message 1 |
| 2 | Sync service supported providers | `entra` in `_SUPPORTED_PROVIDERS` | ✅ | N/A | `test_entra_in_sync_supported_providers` | PASS | |
| 3 | Integration create dispatch | `provider == "entra"` routes to `_create_entra_integration` | ✅ | N/A | `test_integration_service_dispatches_entra` | PASS | |
| 4 | Reconnect dispatch | `provider == "entra"` routes to `reconnect_credentials_entra` | ✅ (new) | N/A | `test_reconnect_router_branch_exists_for_entra` | PASS | New this message |
| 5 | Capability matrix list | `entra` in `PROVIDER_CAPABILITIES` (not `_PARTIAL`) | ✅ (moved) | N/A | `test_entra_in_capability_matrix_complete_list_not_partial` | PASS | Moved this message |
| 6 | Capability matrix notes | Notes say "launched"/"expansion is complete", not "not yet connectable" | ✅ | N/A | `test_entra_capability_notes_say_launched_not_pending` | PASS | |
| 7 | Security coverage providers | `entra` in `security_coverage_service.PROVIDERS` | ✅ (added) | N/A | `test_entra_in_security_coverage_providers` | PASS | Added this message |
| 8 | Security coverage surfaces | `entra` in `PROVIDER_SURFACES` | ✅ (added) | N/A | `test_entra_in_provider_surfaces` | PASS | Added this message |
| 9 | Frontend PROVIDER_IDS | `entra` present | N/A | ✅ (added) | `test_entra_in_provider_ids` | PASS | |
| 10 | Frontend CONNECTABLE_PROVIDER_IDS | `entra` present | N/A | ✅ (added) | `test_entra_in_connectable_provider_ids` | PASS | |
| 11 | Frontend provider map entry | `entra: {...}` exists with full metadata | N/A | ✅ | `test_entra_has_a_providers_map_entry` | PASS | |
| 12 | Category consistency | `identity` (frontend) / `auth` (backend) both pre-existing valid values | ✅ | ✅ | `test_entra_category_is_valid` | PASS | No new category invented |
| 13 | Icon rendering | Uses generic `getProviderMeta().color`/`shortLabel` — no per-provider icon code needed | N/A | ✅ | Manual (IntegrationList.tsx audit) | PASS | No hardcoded icon map exists for any provider |
| 14 | Global capability matrix count | `PROVIDER_CAPABILITIES` grows 10→11 | ✅ | N/A | `test_matrix_has_exactly_eleven_providers` | PASS | Pre-existing fixture updated |

## Credentials

| # | Surface | Requirement | Backend | Frontend | Test | Status | Notes |
|---|---|---|---|---|---|---|---|
| 15 | Credential schema fields | `entra_tenant_id`/`entra_client_id`/`entra_client_secret` on `IntegrationCreateRequest` | ✅ (message 1) | ✅ | `test_entra_in_integration_create_request_literal` | PASS | |
| 16 | Required-field validation | All 3 required for `provider=entra` | ✅ | ✅ | `test_entra_requires_tenant_client_secret` | PASS | |
| 17 | `_build_credentials()` extraction | Router builds `{tenant_id, client_id, client_secret}` | ✅ | N/A | `test_build_credentials_extracts_tenant_client_secret` | PASS | |
| 18 | Credential shape matches connector | `_build_credentials()` output matches `EntraConnector._credentials()` expectation | ✅ | N/A | `test_build_credentials_key_matches_connector_expectation` | PASS | |
| 19 | Tenant ID GUID validation | Malformed/multi-tenant-audience rejected before HTTP | ✅ (message 1) | N/A | `test_create_integration_rejects_malformed_tenant_id`, `test_multi_tenant_audience_rejected` | PASS | |
| 20 | Client ID GUID validation | Malformed rejected | ✅ (message 1) | N/A | test_entra_foundation.py (message 1) | PASS | |
| 21 | Frontend field labels | "Microsoft Entra tenant ID" / "Application (client) ID" / "Client secret" | N/A | ✅ | Manual (EntraIntegrationForm.tsx) | PASS | Matches task spec exactly |
| 22 | Frontend helper text | "Enter the directory (tenant) ID..." | N/A | ✅ | Manual | PASS | |
| 23 | Frontend type definitions | `entra_tenant_id`/`entra_client_id`/`entra_client_secret` on `IntegrationCreateRequest` (TS) | N/A | ✅ (added) | `test_entra_create_request_type_has_credential_fields` | PASS | Was missing before this message |
| 24 | Secret input masking | `type="password"` | N/A | ✅ | `test_entra_form_uses_password_input_for_secret` | PASS | |
| 25 | No secret redisplay | Cleared from state + generic "configured" message after success | N/A | ✅ | `test_entra_form_never_prefills_or_echoes_secret_after_success` | PASS | |
| 26 | No localStorage/URL leakage | Secret never persisted client-side or placed in a URL | N/A | ✅ | Manual code review (EntraIntegrationForm.tsx) | PASS | |

## Validation

| # | Surface | Requirement | Backend | Frontend | Test | Status | Notes |
|---|---|---|---|---|---|---|---|
| 27 | Synchronous validation at creation | `_create_entra_integration()` calls `validate_credentials()` before persistence | ✅ (new) | N/A | `test_creation_runs_synchronous_validate_credentials` | PASS | Was deferred-to-first-sync before this message |
| 28 | Valid credentials → 201 | Full valid tenant/client/secret creates integration | ✅ | ✅ | `test_create_integration_succeeds_when_tenant_reachable` | PASS | |
| 29 | Auth failure → 400 | `AuthenticationError` (invalid_client) rejected | ✅ | ✅ | `test_auth_failure_rejected` | PASS | |
| 30 | Network failure → 400 | `NetworkError` (unreachable Graph) rejected (ConnectorError branch ordered first) | ✅ | ✅ | `test_unreachable_tenant_rejected` | PASS | |
| 31 | Missing tenant_id → 422 | Schema-layer rejection | ✅ | N/A | `test_missing_tenant_id_rejected_at_schema_layer` | PASS | |
| 32 | Missing client_id → 422 | Schema-layer rejection | ✅ | N/A | `test_missing_client_id_rejected_at_schema_layer` | PASS | |
| 33 | Missing client_secret → 422 | Schema-layer rejection | ✅ | N/A | `test_missing_client_secret_rejected_at_schema_layer` | PASS | |
| 34 | Zero-meaningful-capability rejection | `build_entra_permission_diagnostics()` reports `invalid` when 0 families readable | ✅ (new) | N/A | `test_zero_readable_families_is_invalid` | PASS | |
| 35 | Optional-family denial does not block creation | Conditional Access denied still → 201 | ✅ | ✅ | `test_conditional_access_unavailable_does_not_block_creation` | PASS | |
| 36 | Sanitized error messages | No raw Graph body/token/secret in HTTP error responses | ✅ | ✅ | `test_auth_failure_rejected` (asserts secret absent) | PASS | |

## Reconnect

| # | Surface | Requirement | Backend | Frontend | Test | Status | Notes |
|---|---|---|---|---|---|---|---|
| 37 | `reconnect_credentials_entra()` exists | New function, mirrors Okta pattern | ✅ (new) | N/A | `test_entra_reconnect_function_exists` | PASS | |
| 38 | Reconnect schema fields | `entra_tenant_id`/`entra_client_id`/`entra_client_secret` optional/required on `IntegrationReconnectRequest` | ✅ (new) | N/A | `test_reconnect_schema_has_entra_fields` | PASS | |
| 39 | Router branch | `POST /integrations/{id}/reconnect` dispatches on `provider == "entra"` | ✅ (new) | N/A | `test_reconnect_router_branch_exists_for_entra` | PASS | |
| 40 | Same-tenant secret rotation | New secret, same tenant/client → 200 | ✅ | N/A | `test_same_tenant_secret_rotation_succeeds` | PASS | |
| 41 | Same-tenant client rotation | New client_id + secret, same tenant → 200 | ✅ | N/A | `test_same_tenant_new_client_rotation_succeeds` | PASS | |
| 42 | Different-tenant rejection | New tenant_id → 400, existing credentials untouched | ✅ | N/A | `test_different_tenant_rejected` | PASS | |
| 43 | Invalid new secret rejection | `AuthenticationError` on reconnect → 400 | ✅ | N/A | `test_invalid_new_secret_rejected` | PASS | |
| 44 | Graph unavailable during reconnect | `NetworkError` → safe 400, no partial write | ✅ | N/A | `test_graph_unavailable_during_reconnect_is_safe_failure` | PASS | |
| 45 | Reconnect before first sync | Same tenant accepted even though org resource still has creation-time placeholder ID | ✅ | N/A | `test_reconnect_before_first_sync_does_not_falsely_reject_same_tenant` | PASS | Okta message-8 edge case re-verified for Entra |
| 46 | Missing secret on reconnect → 422 | Schema-layer rejection | ✅ | N/A | `test_reconnect_missing_secret_rejected_at_schema_layer` | PASS | |
| 47 | Tenant-mismatch detection mechanism | `compute_tenant_id()` comparison, no extra Graph round-trip needed (tenant GUID is user-supplied, immutable) | ✅ | N/A | `test_reconnect_rejects_different_tenant` (source-scan) | PASS | Simpler than Okta's org-lookup approach |
| 48 | Token cache invalidation on reconnect | New credentials never reuse cached token for old client_id | ✅ | N/A | `test_token_cache_does_not_leak_across_reconnect_to_new_client` | PASS | Direct behavioral regression test, not just source-scan |
| 49 | Secret never returned by reconnect | `entra_client_secret` absent from reconnect response | ✅ | N/A | `TestSensitiveCredentialsNeverLeak` suite | PASS | |
| 50 | Reconnect never logs new secret | Source-scan of `reconnect_credentials_entra()` body | ✅ | N/A | `test_reconnect_entra_never_logs_new_secret` | PASS | |

## Identity (users/groups/memberships)

| # | Surface | Requirement | Backend | Frontend | Test | Status | Notes |
|---|---|---|---|---|---|---|---|
| 51 | `entra_user` collection | `GET /users`, paginated | ✅ (message 2) | N/A | test_entra_identity_collection.py | PASS | |
| 52 | `entra_group` collection | `GET /groups`, paginated | ✅ (message 2) | N/A | test_entra_identity_collection.py | PASS | |
| 53 | `entra_group_membership` collection | Per-group `GET /groups/{id}/members` walk | ✅ (message 2) | N/A | test_entra_identity_collection.py | PASS | |
| 54 | Member/Guest taxonomy | `userType` normalization | ✅ (message 2) | N/A | test_entra_identity_normalization.py | PASS | |
| 55 | Enabled/disabled posture | `accountEnabled` boolean-discipline | ✅ (message 2) | N/A | test_entra_identity_normalization.py | PASS | |
| 56 | Role-assignable groups | `isAssignableToRole` tracked + Change classified | ✅ (message 2) | N/A | test_entra_identity_diff.py | PASS | |
| 57 | Identity Findings | 6+ identity-lifecycle rules | ✅ (message 6) | N/A | entra_security_findings_matrix.md | PASS | |

## Applications

| # | Surface | Requirement | Backend | Frontend | Test | Status | Notes |
|---|---|---|---|---|---|---|---|
| 58 | `entra_application` collection | `GET /applications` | ✅ (message 3) | N/A | test_entra_application_collection.py | PASS | |
| 59 | `entra_service_principal` collection | `GET /servicePrincipals` | ✅ (message 3) | N/A | test_entra_application_collection.py | PASS | |
| 60 | App-role assignments | Per-SP `appRoleAssignedTo` walk, user/group/SP branched | ✅ (message 3) | N/A | test_entra_application_collection.py | PASS | Confirmed no per-user N+1 |
| 61 | OAuth delegated grants | `GET /oauth2PermissionGrants`, consent-risk categorization | ✅ (message 3) | N/A | test_entra_application_collection.py | PASS | |
| 62 | Redirect posture | Wildcard/HTTP/localhost/custom-scheme categorization | ✅ (message 3) | N/A | test_entra_application_normalization.py | PASS | |
| 63 | Credential metadata | Password/key credential counts + nearest-expiry category | ✅ (message 3) | N/A | test_entra_application_normalization.py | PASS | |
| 64 | Application/consent Findings | 18+ rules across applications/SPs/consent | ✅ (message 6) | N/A | entra_security_findings_matrix.md | PASS | |

## Policy (Conditional Access / authentication)

| # | Surface | Requirement | Backend | Frontend | Test | Status | Notes |
|---|---|---|---|---|---|---|---|
| 65 | Conditional Access collection | `GET /identity/conditionalAccess/policies` | ✅ (message 4) | N/A | test_entra_policy_collection.py | PASS | |
| 66 | Enabled/report-only/disabled semantics | `state` categorization + report-only ≠ enforced discipline | ✅ (message 4/7) | N/A | `TestReportOnlySemantics` (message 7) | PASS | Permanent regression pin |
| 67 | MFA AND/OR semantics | `grant_operator_category`/`mfa_requirement_category` | ✅ (message 4) | N/A | test_entra_policy_diff.py | PASS | |
| 68 | Authentication strengths | `GET /policies/authenticationStrengthPolicies` | ✅ (message 4) | N/A | test_entra_policy_collection.py | PASS | |
| 69 | Authentication methods | `GET /policies/authenticationMethodsPolicy` | ✅ (message 4) | N/A | test_entra_policy_collection.py | PASS | |
| 70 | Phishing-resistant posture | Strength/method phishing-resistance categorization | ✅ (message 4) | N/A | test_entra_policy_normalization.py | PASS | |
| 71 | Legacy-auth posture | `legacy_auth_targeted` + block-access classification (message 7 parity fix) | ✅ (message 4/7) | N/A | `test_legacy_auth_targeted_added_without_block_matches_static_finding` | PASS | Bug fixed in message 7 |
| 72 | Policy/auth Findings | 10+ CA/auth rules | ✅ (message 6) | N/A | entra_security_findings_matrix.md | PASS | |

## Privilege / consent

| # | Surface | Requirement | Backend | Frontend | Test | Status | Notes |
|---|---|---|---|---|---|---|---|
| 73 | Directory role definitions | `GET /roleManagement/directory/roleDefinitions` | ✅ (message 5) | N/A | test_entra_privileged_collection.py | PASS | |
| 74 | Directory role assignments | `GET /roleManagement/directory/roleAssignments`, tenant-wide, no N+1 | ✅ (message 5) | N/A | test_entra_privileged_collection.py | PASS | |
| 75 | Global Admin/PRA/Priv-Auth-Admin taxonomy | Role-template GUID matching | ✅ (message 5) | N/A | test_entra_privileged_diff.py | PASS | |
| 76 | Privileged identity/group/SP derivation | Pure local joins, no extra Graph calls | ✅ (message 5) | N/A | test_entra_privileged_collection.py | PASS | |
| 77 | Graph app-permission privilege tiers | `app_role_privilege_tier` categorization | ✅ (message 5) | N/A | test_entra_privileged_normalization.py | PASS | |
| 78 | PIM eligible-role modeling | **NOT implemented** — active assignments only | N/A | N/A | N/A | **DEFERRED (documented limitation)** | Explicitly listed in certification report |
| 79 | Privilege/consent Findings | 15+ rules | ✅ (message 6) | N/A | entra_security_findings_matrix.md | PASS | |

## Findings

| # | Surface | Requirement | Backend | Frontend | Test | Status | Notes |
|---|---|---|---|---|---|---|---|
| 80 | Exact rule count | 45 rules | ✅ | N/A | `test_entra_has_exactly_45_rules` | PASS | |
| 81 | Severity distribution | Critical 9 / High 18 / Medium 16 / Low 2 | ✅ | N/A | entra_security_findings_matrix.md | PASS | Unchanged since message 6 |
| 82 | Evaluator reachability | `security_rules/entra.py::evaluate()` callable, all rules reachable | ✅ | N/A | `test_all_entra_rules_reachable_from_evaluator` | PASS | |
| 83 | Registry parity | All 45 keys in `KNOWN_RULE_KEYS` | ✅ | N/A | test_entra_security_finding_parity.py | PASS | |
| 84 | Confidence parity | All 45 keys in `RULE_CONFIDENCE` | ✅ | N/A | `test_all_entra_rules_have_confidence` | PASS | |
| 85 | Pack parity | Rule pack registration verified message 6 | ✅ | N/A | test_entra_security_finding_parity.py | PASS | |
| 86 | Coverage record-type parity | All 45 keys in `RULE_RECORD_TYPES` | ✅ | N/A | `test_entra_in_coverage_record_types` | PASS | |
| 87 | Frontend rule catalog parity | 45 entries retained | N/A | ✅ | Manual (securityRuleCatalog.ts, message 6) | PASS | No new entries needed this message |
| 88 | Findings render correctly | Provider icon/name, severity, evidence, remediation, resource identity | N/A | ✅ (generic) | Manual (Findings UI is provider-agnostic) | PASS | No Entra-specific frontend code required |

## Changes

| # | Surface | Requirement | Backend | Frontend | Test | Status | Notes |
|---|---|---|---|---|---|---|---|
| 89 | Change classification coverage | 197+19 cases across all 16 record types | ✅ (message 7) | N/A | test_entra_change_classification.py | PASS | |
| 90 | Finding-vs-Change parity | New-bad-state Change severity ≥ static Finding severity | ✅ (message 7, 2 bugs fixed) | N/A | test_entra_change_parity.py | PASS | |
| 91 | Changes render correctly | Context/severity/resource identity | N/A | ✅ (generic) | Manual (Changes UI is provider-agnostic) | PASS | |

## Partial sync / pagination

| # | Surface | Requirement | Backend | Frontend | Test | Status | Notes |
|---|---|---|---|---|---|---|---|
| 92 | Tenant-wide false-removal suppression | `_entra_removal_suppressed()` | ✅ (message 7) | N/A | test_entra_partial_sync.py | PASS | |
| 93 | Per-parent completeness (groups) | `membership_collection_status` on `entra_group` | ✅ (message 7) | N/A | test_entra_partial_sync.py | PASS | |
| 94 | Per-parent completeness (SPs) | `assignment_collection_status` on `entra_service_principal` | ✅ (message 7) | N/A | test_entra_partial_sync.py | PASS | |
| 95 | 429/5xx retry | Bounded exponential backoff | ✅ (message 1/7) | N/A | test_entra_pagination_reliability.py | PASS | |
| 96 | `@odata.nextLink` origin protection | Cross-origin next-link never followed with credentials | ✅ (message 1) | N/A | `TestNextLinkEdgeCasesAtFetchLevel` | PASS | |
| 97 | Capability drift handling | Denied/unavailable family never inferred as deletion | ✅ (message 7) | N/A | `TestCapabilityDrift` | PASS | |
| 98 | Recovery-after-partial-sync | Re-baseline shows "added", never fabricated history | ✅ (message 7) | N/A | `TestFirstSyncSemantics` | PASS | |
| 99 | Scale/N+1 hardening | Linear SP/group walk call counts, bounded capability probes | ✅ (message 7) | N/A | test_entra_scale_reliability.py | PASS | |

## Security / sensitive data

| # | Surface | Requirement | Backend | Frontend | Test | Status | Notes |
|---|---|---|---|---|---|---|---|
| 100 | Client secret never logged/raised | Source-scan for forbidden patterns | ✅ | N/A | `test_connector_never_logs_or_raises_with_raw_secret` | PASS | |
| 101 | Client secret excluded from resource_metadata | Source-scan of `_create_entra_integration()` | ✅ | N/A | `test_org_resource_metadata_never_contains_client_secret` | PASS | |
| 102 | No CLI/subprocess dependency | Source-scan of `entra.py` | ✅ | N/A | `test_no_cli_or_subprocess_dependency` | PASS | |
| 103 | No Graph SDK/MSAL dependency | Source-scan of `entra.py` | ✅ | N/A | `test_no_graph_sdk_or_msal_dependency` | PASS | |
| 104 | Token cache credential-bound | `credential_key` field on `_TokenCache` | ✅ (message 7) | N/A | `test_token_cache_is_credential_bound` | PASS | |
| 105 | Access tokens never persisted | Connector-instance-memory only | ✅ | N/A | Manual + `test_client_secret_not_logged_by_validate_credentials` | PASS | |
| 106 | Trusted Graph/token hosts | `login.microsoftonline.com`/`graph.microsoft.com` fixed | ✅ (message 1) | N/A | test_entra_foundation.py | PASS | |
| 107 | Safety greps (this message's diff) | No secret/token leakage, no CLI dependency, no incident-claim language | ✅ | ✅ | Manual grep (see final report) | PASS | |

## Frontend (form/card/setup)

| # | Surface | Requirement | Backend | Frontend | Test | Status | Notes |
|---|---|---|---|---|---|---|---|
| 108 | `EntraIntegrationForm.tsx` exists | New component | N/A | ✅ (new) | `test_entra_form_component_exists` | PASS | |
| 109 | Form wired into integrations page | Import + `selectedProvider === "entra"` branch | N/A | ✅ (new) | `test_entra_form_wired_into_integrations_page` | PASS | |
| 110 | Setup guidance inline | App registration → API permissions → admin consent → secret → copy IDs | N/A | ✅ | Manual (EntraIntegrationForm.tsx) | PASS | |
| 111 | Least-privilege framing | Never suggests Directory.ReadWrite.All or Global Admin | N/A | ✅ | Manual (EntraIntegrationForm.tsx / providers.ts trustNote) | PASS | |
| 112 | Card copy omits stale wording | No "(planned)"/"foundation stage" | N/A | ✅ | `test_entra_card_copy_omits_stale_planned_wording` | PASS | |
| 113 | Card copy omits unsupported claims | No threat-detection/session-monitoring/device-telemetry claims | N/A | ✅ | `test_entra_card_copy_omits_unsupported_claims` | PASS | |
| 114 | TypeScript compiles | `npx tsc --noEmit` zero errors | N/A | ✅ | Manual (`npx tsc --noEmit`) | PASS | |
| 115 | Frontend production build | `npm run build` — compilation + type-check pass | N/A | ⚠️ | Manual (`npm run build`) | **PASS (compile) / KNOWN SANDBOX LIMIT (prerender)** | Fails only at static-page prerender due to missing `CLERK_PUBLISHABLE_KEY` env secret in this sandbox — pre-existing, unrelated to Entra changes |

## Deployment

| # | Surface | Requirement | Backend | Frontend | Test | Status | Notes |
|---|---|---|---|---|---|---|---|
| 116 | Database migration | `Integration.provider` is plain `Text`, no constraint | ✅ (confirmed, no change) | N/A | Manual model inspection | PASS | No migration required |
| 117 | No new environment variables | Credentials are per-integration, encrypted | ✅ | N/A | Manual audit | PASS | |
| 118 | No new production dependency | Uses existing `httpx` only | ✅ | N/A | `test_no_cli_or_subprocess_dependency`, `test_no_graph_sdk_or_msal_dependency` | PASS | |

## Limitations (explicitly accepted, non-launch-critical)

| # | Surface | Requirement | Status | Notes |
|---|---|---|---|---|
| 119 | Runtime sign-in-event ingestion | Not implemented | N/A / deferred | Documented limitation |
| 120 | Identity Protection risk-event ingestion | Not implemented | N/A / deferred | Documented limitation |
| 121 | Per-user authentication-method enumeration | Not implemented (tenant-wide policy only) | N/A / deferred | Documented limitation |
| 122 | Exact effective CA evaluation per sign-in | Not implemented (policy config only) | N/A / deferred | Documented limitation |
| 123 | Nested/transitive group flattening | Not implemented (direct memberships only) | N/A / deferred | Documented since message 2 |
| 124 | PIM eligible-role schedules | Not implemented (active assignments only) | N/A / deferred | Documented limitation (see row 78) |
| 125 | Certificate-based ConfigTrace auth | Not implemented (client secret only) | N/A / deferred | Documented future enhancement |
| 126 | GCC/GCC High/DoD/China cloud support | Not implemented (commercial/global only) | N/A / deferred | Documented since message 1 |
| 127 | Runtime token/session telemetry | Not implemented | N/A / deferred | Documented limitation |
| 128 | Reconnect UI multi-field support | Not implemented (backend-only reconnect for now) | N/A / deferred | Shared gap with most non-original-8 providers |

**Total rows: 128.** No launch-critical GAP — every non-PASS row above is an explicitly accepted, documented limitation or a known external sandbox constraint unrelated to code correctness.
