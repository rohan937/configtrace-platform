# Microsoft Entra ID Foundation Contract (Entra Message 1 of 8)

Pins the connector architecture built in this message: OAuth 2.0
client_credentials app-only authentication, stable tenant identity, Graph
HTTP behavior (pagination/retry/failure classification), capability
probing, sensitive-data exclusion, provider registration, and diff/
provider-metadata parity. No users, groups, applications, service
principals, Conditional Access policies, authentication methods, directory
roles, or consent-grant collection exists yet — that begins in Entra
message 2 and onward.

Columns: **Case**, **Area**, **Input/state**, **Expected behavior**,
**Security concern**, **Test**, **Status**, **Notes**.

| # | Case | Area | Input/state | Expected behavior | Security concern | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|
| 1 | Valid GUID tenant_id accepted | Credentials | `11111111-1111-1111-1111-111111111111` | Normalized, lowercased GUID returned | None | `TestValidateTenantId::test_valid_guid_accepted` | PASS | |
| 2 | Uppercase GUID lowercased | Credentials | Mixed-case GUID | Returned lowercased | Deterministic identity | `test_uppercase_guid_lowercased` | PASS | |
| 3 | `common` rejected | Credentials | `"common"` | `EntraCredentialError` raised | Prevents multi-tenant audience impersonating a concrete tenant | `test_common_rejected` | PASS | |
| 4 | `organizations` rejected | Credentials | `"organizations"` | `EntraCredentialError` raised | Same as above | `test_organizations_rejected` | PASS | |
| 5 | `consumers` rejected | Credentials | `"consumers"` | `EntraCredentialError` raised | Same as above | `test_consumers_rejected` | PASS | |
| 6 | Embedded URL rejected | Credentials | `https://evil.example/<guid>` | `EntraCredentialError` raised | Prevents SSRF-style host injection via tenant_id | `test_embedded_url_rejected` | PASS | |
| 7 | Non-GUID string rejected | Credentials | `"not-a-guid"` | `EntraCredentialError` raised | Deterministic identity requires canonical GUID | `test_non_guid_string_rejected` | PASS | |
| 8 | Empty string rejected | Credentials | `""` | `EntraCredentialError` raised | | `test_empty_string_rejected` | PASS | |
| 9 | Non-string rejected | Credentials | `None` | `EntraCredentialError` raised | | `test_non_string_rejected` | PASS | |
| 10 | Query/fragment rejected | Credentials | `<guid>?x=1` | `EntraCredentialError` raised | Prevents query-string injection into the token URL path segment | `test_query_fragment_rejected` | PASS | |
| 11 | Valid client_id GUID accepted | Credentials | GUID | Normalized GUID returned | | `TestValidateClientId::test_valid_guid_accepted` | PASS | |
| 12 | Non-GUID client_id rejected | Credentials | `"not-a-guid"` | `EntraCredentialError` raised | | `test_non_guid_rejected` | PASS | |
| 13 | Empty client_id rejected | Credentials | `""` | `EntraCredentialError` raised | | `test_empty_rejected` | PASS | |
| 14 | Embedded URL in client_id rejected | Credentials | `https://evil.example/<guid>` | `EntraCredentialError` raised | | `test_embedded_url_rejected` | PASS | |
| 15 | Valid client credentials succeed | Authentication | Valid tenant/client/secret | `validate_credentials()` returns `True` | | `TestAuthentication::test_valid_client_credentials_succeeds` | PASS | |
| 16 | Invalid client secret | Authentication | Token endpoint 401 `invalid_client` | `AuthenticationError` raised | Never propagate raw error body | `test_invalid_client_secret_raises_authentication_error` | PASS | |
| 17 | Invalid tenant | Authentication | Token endpoint 400 `invalid_request` | `AuthenticationError` raised | | `test_invalid_tenant_raises_authentication_error` | PASS | |
| 18 | Permission denied on org probe | Authentication | Token OK, `/organization` 403 | `ConnectorError` raised (not `AuthenticationError`) | Distinguishes accepted-but-insufficient-permission from rejected token | `test_permission_denied_on_organization_probe_raises_connector_error` | PASS | |
| 19 | Token response missing `access_token` | Authentication | 200 with no `access_token` key | `EntraTokenError` raised | Never silently proceed with an empty/missing token | `test_token_response_missing_access_token_raises` | PASS | |
| 20 | Token endpoint timeout | Authentication | `httpx.ConnectTimeout` | `NetworkError` raised | | `test_token_endpoint_timeout_raises_network_error` | PASS | |
| 21 | Graph timeout | Authentication | `httpx.ReadTimeout` on `/organization` | `NetworkError` raised | | `test_graph_timeout_raises_network_error` | PASS | |
| 22 | Missing client_secret | Authentication | credentials dict without `client_secret` | `AuthenticationError` raised before any request | | `test_missing_client_secret_raises_authentication_error` | PASS | |
| 23 | Malformed tenant_id | Authentication | `tenant_id="not-a-guid"` | `AuthenticationError` raised before any request | | `test_malformed_tenant_id_raises_before_any_request` | PASS | |
| 24 | `common` tenant_id at validate time | Authentication | `tenant_id="common"` | `AuthenticationError` raised | | `test_common_tenant_id_rejected` | PASS | |
| 25 | Authorization header uses Bearer scheme | Authentication | — | `Authorization: Bearer <token>` | Never SSWS/Basic/other scheme | `test_authorization_header_uses_bearer_scheme` | PASS | |
| 26 | Secret never in exception text | Sensitive data | Auth failure | `client_secret` value absent from exception `str()` | Prevents secret leakage via error surfaces/logs | `test_secret_never_appears_in_exception_text` | PASS | |
| 27 | Secret never logged | Sensitive data | Successful validate | `client_secret` absent from captured logs | | `test_secret_never_logged` | PASS | |
| 28 | First call acquires token | Token caching | Fresh connector instance | Token endpoint called exactly once | | `TestTokenCaching::test_first_call_acquires_token` | PASS | |
| 29 | Multiple Graph calls reuse cached token | Token caching | `fetch()` (1 org + 8 probes = 9 Graph calls) | Token endpoint called exactly once | Avoids unnecessary secret transmission per call | `test_multiple_graph_calls_reuse_cached_token` | PASS | |
| 30 | Expired token refreshes | Token caching | Cached token TTL 60s, clock advances 10,000s | `_acquire_token` called twice, new token returned | | `test_expired_token_refreshes` | PASS | |
| 31 | Unexpired token not refreshed | Token caching | Clock advances 5s within a 3600s TTL | `_acquire_token` called once | | `test_unexpired_token_not_refreshed` | PASS | |
| 32 | Token cache is a dedicated dataclass | Sensitive data | — | `_token_cache` is a `_TokenCache` instance, starts empty | Never an arbitrary dict attribute that could be accidentally serialized | `test_token_never_stored_as_plain_instance_dict_key` | PASS | |
| 33 | Fresh instance starts with empty cache | Token caching | New `EntraConnector()` | `_token_cache.access_token is None` | Confirms no cross-instance token leakage | `test_fresh_instance_starts_with_empty_cache` | PASS | |
| 34 | Stable tenant identity | Tenant identity | Same tenant_id, repeated calls | Identical id returned | | `TestTenantIdentity::test_stable_tenant_identity` | PASS | |
| 35 | Token rotation does not change identity | Tenant identity | Same tenant_id | Identical id regardless of token | | `test_token_rotation_does_not_change_identity` | PASS | |
| 36 | Different tenants are distinct | Tenant identity | Two different GUIDs | Distinct ids | | `test_different_tenants_are_distinct` | PASS | |
| 37 | Display-name change does not alter id | Tenant identity | Same tenant_id, different `displayName` | Identical id | Prevents cosmetic tenant renames from breaking diff correlation | `test_display_name_change_does_not_alter_id` | PASS | |
| 38 | Identity derived from credential tenant_id | Tenant identity | — | `id:<tenant_id>` format | | `test_identity_derived_from_credential_tenant_id` | PASS | |
| 39 | `fetch()` uses tenant_id as identity | Tenant identity | Full fetch with mocked Graph | `entra_organization.tenant_id == "id:<tenant_id>"` | | `test_fetch_uses_tenant_id_as_identity` | PASS | |
| 40 | Pagination: one page | Pagination | Single page, no nextLink | All items returned, `truncated=False` | | `TestPagination::test_one_page` | PASS | |
| 41 | Pagination: multiple pages via nextLink | Pagination | 2 pages, `@odata.nextLink` | All items across both pages returned | | `test_multiple_pages_follows_next_link` | PASS | |
| 42 | Repeated nextLink stops and marks truncated | Pagination | Same nextLink URL every page | Stops looping, `truncated=True` | Prevents infinite loop from a misbehaving/malicious server | `test_repeated_next_link_stops_and_marks_truncated` | PASS | |
| 43 | Cross-origin nextLink rejected | Pagination | nextLink to `https://evil.example/...` | Not followed, `truncated=True` | Prevents redirect to attacker-controlled host | `test_cross_origin_next_link_rejected` | PASS | |
| 44 | Malformed nextLink ignored | Pagination | Non-string/absent `@odata.nextLink` | Returns `None`, no exception | | `test_malformed_next_link_ignored` | PASS | |
| 45 | Non-HTTPS nextLink rejected | Pagination | `http://` nextLink | Rejected (returns `None`) | Prevents downgrade to unencrypted transport | `test_non_https_next_link_rejected` | PASS | |
| 46 | Page cap enforced | Pagination | 5 available pages, `max_pages=3` | Exactly 3 pages read, `truncated=True` | Bounds worst-case request volume | `test_page_cap_marks_truncated` | PASS | |
| 47 | Partial later-page failure | Pagination | Page 1 OK, page 2 HTTP 500 | Page-1 items returned, `truncated=True`, no exception | Never silently reports partial data as complete | `test_partial_later_page_failure_marks_truncated_not_raised` | PASS | |
| 48 | First-page failure raises | Pagination | Page 1 HTTP 403 | `ConnectorError` raised | A fully broken credential/permission should fail loudly | `test_first_page_failure_raises` | PASS | |
| 49 | Dedup by id across overlapping pages | Pagination | Page 2 re-serves an id from page 1 | Each id appears once | Defends against a server re-serving an overlapping page | `test_dedupes_records_by_id` | PASS | |
| 50 | 429 then success | Rate limiting | 429 (Retry-After: 0) then 200 | Bounded retry succeeds | | `TestRateLimit::test_429_then_success` | PASS | |
| 51 | 429 exhausted | Rate limiting | Always 429 | Returns `CallOutcome(ok=False, category="throttled")` after bounded attempts | Never fabricates a fake empty-success state | `test_429_exhausted_retries` | PASS | |
| 52 | 503 then success | Rate limiting | 503 then 200 | Bounded 5xx retry succeeds | | `test_503_then_success` | PASS | |
| 53 | 5xx retry budget exhausted | Rate limiting | Always 503 | Returns `category="server_error"` after bounded attempts | | `test_5xx_retry_budget_exhausted` | PASS | |
| 54 | Sleep is mocked, never real | Rate limiting | Injected `_sleep_fn` | Sleep function invoked, no real delay | Test-suite performance/determinism | `test_sleep_is_mocked_never_real` | PASS | |
| 55 | 401 never retried | Rate limiting | Always 401 | Exactly 1 request made | Permanent auth failures are never treated as transient | `test_401_never_retried` | PASS | |
| 56 | 403 never retried | Rate limiting | Always 403 | Exactly 1 request made | Permanent permission failures are never treated as transient | `test_403_never_retried` | PASS | |
| 57 | Token endpoint 429 retried | Rate limiting | Token endpoint 429 then success | Retry succeeds, token returned | | `test_token_endpoint_429_retried_with_backoff` | PASS | |
| 58 | Token endpoint 429 exhausted | Rate limiting | Always 429 | `RateLimitError` raised | | `test_token_endpoint_429_exhausted_raises_rate_limit_error` | PASS | |
| 59 | Mixed available/denied capability probes | Capability probing | `/users` 200, `/groups` 403 | `users=available`, `groups=denied` | | `TestCapabilityProbes::test_mixed_available_and_denied` | PASS | |
| 60 | Unsupported optional family (404) | Capability probing | Conditional Access endpoint 404 | `conditional_access=unsupported`, not `invalid` | A missing optional API must never block foundation validation | `test_unsupported_optional_family_reports_unsupported` | PASS | |
| 61 | Throttled family | Capability probing | Directory roles probe 429 | `directory_roles=throttled` | | `test_throttled_family_reports_throttled` | PASS | |
| 62 | Probes use minimal `$top=1` | Capability probing | — | Every applicable probe sets `$top=1` | Never a broad enumeration | `test_probes_use_minimal_top_1` | PASS | |
| 63 | Exactly 8 families probed | Capability probing | — | `len(_CAPABILITY_PROBES) == 8` | | `test_eight_families_probed` | PASS | |
| 64 | client_secret absent from records | Sensitive data | Full `fetch()` | Secret value not present in any record | | `TestSensitiveDataSafety::test_client_secret_absent_from_records` | PASS | |
| 65 | access_token absent from records | Sensitive data | Full `fetch()` | Token value not present in any record | | `test_access_token_absent_from_records` | PASS | |
| 66 | Authorization header absent from records | Sensitive data | Full `fetch()` | No "Authorization"/"Bearer" substring in any record | | `test_authorization_header_absent_from_records` | PASS | |
| 67 | Raw token response body absent from records | Sensitive data | Full `fetch()` | No "token_type"/"expires_in" substring in any record | Never propagate the raw OAuth response into a normalized record | `test_raw_token_response_body_absent_from_records` | PASS | |
| 68 | Sync task dispatches Entra | Provider registration | — | `integration.provider == "entra"` branch present, imports `EntraConnector` | | `TestProviderDispatchWiring::test_sync_task_dispatches_entra` | PASS | |
| 69 | integration_service dispatches Entra | Provider registration | — | `_create_entra_integration` present and wired | | `test_integration_service_dispatches_entra` | PASS | |
| 70 | sync_service supported providers contains Entra | Provider registration | — | `"entra"` in `_SUPPORTED_PROVIDERS` tuple | | `test_sync_service_supported_providers_contains_entra` | PASS | |
| 71 | Create integration does not leak secret | Provider registration | Real `create_integration()` call | `client_secret` absent from resource metadata and API response | | `test_create_integration_creates_row_without_leaking_secret` | PASS | |
| 72 | Create integration rejects malformed tenant_id | Provider registration | `tenant_id="not-a-guid"` | `ValueError` raised, no row written | | `test_create_integration_rejects_malformed_tenant_id` | PASS | |
| 73 | Create integration rejects multi-tenant audience | Provider registration | `tenant_id="common"` | `ValueError` raised | | `test_create_integration_rejects_multi_tenant_audience` | PASS | |
| 74 | Entra in `IntegrationCreateRequest` Literal | Credentials | — | `provider="entra"` accepted | | `TestCredentialSchema::test_entra_in_provider_literal` | PASS | |
| 75 | Missing tenant_id rejected at schema layer | Credentials | — | `ValidationError` raised | | `test_missing_tenant_id_rejected` | PASS | |
| 76 | Missing client_id rejected at schema layer | Credentials | — | `ValidationError` raised | | `test_missing_client_id_rejected` | PASS | |
| 77 | Missing client_secret rejected at schema layer | Credentials | — | `ValidationError` raised | | `test_missing_client_secret_rejected` | PASS | |
| 78 | `_build_credentials` extracts Entra fields | Credentials | — | Returns `tenant_id`/`client_id`/`client_secret` dict | | `test_build_credentials_extracts_entra_fields` | PASS | |
| 79 | Organization change routes to Entra classifier | Diff/risk dispatch | `record_type="entra_organization"` | Reason text mentions "Entra" | Never falls through to unrelated (Cloudflare DNS) classifier | `TestDiffRiskDispatch::test_organization_change_routes_to_entra_classifier` | PASS | |
| 80 | Capability change routes to Entra classifier | Diff/risk dispatch | `record_type="entra_api_capability"`, status available→denied | `medium` severity, reason mentions "Entra" | | `test_capability_change_routes_to_entra_classifier` | PASS | |
| 81 | Unknown Entra record type fails safe | Diff/risk dispatch | `record_type="entra_future_thing"` | `low` severity returned, no exception | Future record types never crash classification | `test_unknown_entra_record_type_fails_safe` | PASS | |
| 82 | Real `compute_diff()` produces Entra provider metadata | Diff/provider metadata | Two snapshots differing in `display_name` | `provider_metadata["record_type"] == "entra_organization"`, no secret/token fields | | `test_real_compute_diff_produces_entra_provider_metadata` | PASS | |
| 83 | Entra registered in partial/staging capability list | Provider registration | — | In `PROVIDER_CAPABILITIES_PARTIAL`, not `PROVIDER_CAPABILITIES` | Not yet publicly connectable | `TestCapabilityMatrix::test_entra_registered_in_partial_list_not_complete_list` | PASS | |
| 84 | Capability flags: drift True, security False | Provider registration | — | `drift_snapshots/diff/risk_classification=True`; all `security.*=False` | Security Findings are message 6, not message 1 | `test_entra_drift_snapshots_true_security_rules_false` | PASS | |
| 85 | Category is valid | Provider registration | — | `cap.category in CATEGORIES` | | `test_entra_category_is_valid` | PASS | |
| 86 | Maturity is valid | Provider registration | — | `cap.maturity in MATURITY_LEVELS` | | `test_entra_maturity_is_valid` | PASS | |
| 87 | Public matrix endpoint excludes Entra | Provider registration | `get_matrix()` | Entra absent from `matrix["providers"]` | Never surfaced publicly before launch | `test_get_matrix_does_not_include_entra_yet` | PASS | |
| 88 | Security coverage service excludes Entra | Provider registration | — | `"entra" not in PROVIDERS` | Security Findings coverage begins at message 6 | `test_entra_not_in_security_coverage_providers_yet` | PASS | |
| 89 | Entra present in frontend `ProviderId` type | Frontend | `providers.ts` | `"entra"` string present | | `TestFrontendCatalogState::test_entra_present_in_provider_id_type` | PASS | |
| 90 | Entra has a `PROVIDERS` map entry | Frontend | `providers.ts` | `entra: {` present | | `test_entra_has_a_providers_map_entry` | PASS | |
| 91 | Entra excluded from `CONNECTABLE_PROVIDER_IDS` | Frontend | `providers.ts` | `"entra"` absent from that array | Must not be user-connectable yet | `test_entra_not_in_connectable_provider_ids` | PASS | |
| 92 | Entra excluded from `PROVIDER_IDS` | Frontend | `providers.ts` | `"entra"` absent from that array | Must not appear in the public integrations list | `test_entra_not_in_provider_ids_display_order` | PASS | |
| 93 | Trust note discloses foundation stage | Frontend | `providers.ts` | Contains "foundation" or "planned" | Avoids implying full coverage before it exists | `test_entra_trust_note_does_not_claim_live_coverage` | PASS | |
| 94 | Display name is "Microsoft Entra ID", not "Azure AD" | Frontend | `providers.ts` `label` field | Label line contains "Microsoft Entra ID", not "Azure AD" | Accurate branding per task requirement | `test_entra_display_name_is_microsoft_entra_id_not_azure_ad` | PASS | |
| 95 | Card copy omits unsupported-capability claims | Frontend | `providers.ts` description/monitoredSurfaces | No "client_secret"/"otp seed"/"session token"/"private key" substrings (trustNote exempt) | | `test_entra_card_copy_does_not_claim_unsupported_features` | PASS | |
| 96 | Card copy does not silently claim national-cloud support | Frontend | `providers.ts` | Mentions GCC High/national cloud exclusion explicitly | Prevents overclaiming unsupported sovereign-cloud coverage | `test_entra_does_not_claim_national_cloud_support` | PASS | |
| 97 | Entra connector never imports AzureConnector | Provider separation | `entra.py` source | No `AzureConnector`/`app.connectors.azure` reference | Confirms the two providers are never merged | `TestDistinctFromAzureProvider::test_entra_connector_does_not_import_azure_connector` | PASS | |
| 98 | Entra record types never collide with Azure prefix | Provider separation | `ENTRA_RECORD_TYPES` | Every type starts with `entra_`, none with `azure_` | | `test_entra_record_types_do_not_collide_with_azure_record_types` | PASS | |
| 99 | Existing Azure provider untouched | Provider separation | `get_provider_capability("azure")` | Still registered, label `"Azure"` | This message must not weaken the existing Azure infrastructure provider | `test_azure_connector_untouched_still_registered` | PASS | |
| 100 | Connector docstring documents commercial-cloud-only scope | Cloud scope | `entra.py.__doc__` | Mentions commercial/global cloud; GCC High/not-supported language present | Never silently claims national-cloud support | `TestCloudScopeDocumented::test_connector_docstring_documents_commercial_cloud_only` | PASS | |
| 101 | Connector docstring documents certificate auth as future | Cloud scope | `entra.py.__doc__` | Mentions "certificate" + "future enhancement"/"not implemented" | Sets accurate expectations for message 1 scope | `test_connector_docstring_documents_certificate_auth_as_future` | PASS | |
| 102 | Graph scope is `.default`, not delegated | Cloud scope | `_GRAPH_SCOPE` constant | Equals `"https://graph.microsoft.com/.default"` | Confirms app-only, never delegated, scope construction | `test_graph_scope_is_default_not_delegated` | PASS | |

**Total rows: 102.** Every case is backed by a passing automated test (`test_entra_foundation.py` / `test_entra_connector_contract.py`) — no case is documentation-only.
