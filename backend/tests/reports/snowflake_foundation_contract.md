# Snowflake Foundation Contract (Snowflake Message 1 of 8)

Pins the connector architecture built in this message: Programmatic Access
Token (PAT) authentication over the Snowflake SQL API, account
identifier/username/role validation, stable account identity derived from
`CURRENT_ORGANIZATION_NAME()`/`CURRENT_ACCOUNT_NAME()`, the fail-soft
API-call wrapper (bounded 429/5xx retry, async 202 polling), read-only
capability probing across 13 future record families, sensitive-data
exclusion, provider registration, and diff/provider-metadata parity. No
users, roles, grants, databases, schemas, warehouses, shares, network
policies, authentication policies, or security/storage/external-access
integrations are collected yet — that begins in Snowflake message 2 and
onward.

Columns: **Case**, **Area**, **Input/state**, **Expected behavior**,
**Security concern**, **Test**, **Status**, **Notes**.

## Provider identity

| # | Case | Area | Input/state | Expected behavior | Security concern | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|
| 1 | Record type constants are `snowflake_`-prefixed | Provider identity | `ALL_SNOWFLAKE_RECORD_TYPES` | Every value starts with `snowflake_` | Prevents cross-provider record-type collision | `TestModuleImportSanity::test_record_types_are_snowflake_prefixed` | PASS | |
| 2 | Schema module imports cleanly | Provider identity | — | `import app.connectors.snowflake_schema` succeeds | | `test_snowflake_schema_module_imports` | PASS | |
| 3 | Connector module imports cleanly | Provider identity | — | `import app.connectors.snowflake` succeeds | | `test_snowflake_connector_module_imports` | PASS | |
| 4 | Risk rules module imports cleanly | Provider identity | — | `import app.services.risk_rules.snowflake` succeeds | | `test_snowflake_risk_rules_module_imports` | PASS | |
| 5 | Exactly 13 capability families, all unique | Provider identity | `CAPABILITY_FAMILIES` | `len == 13`, no duplicates | Matches the task's own enumerated 13-family list exactly | `test_all_thirteen_capability_families_are_unique` | PASS | |

## Authentication

| # | Case | Area | Input/state | Expected behavior | Security concern | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|
| 6 | Valid PAT credentials succeed | Authentication | Valid account_identifier/username/token/role | `validate_credentials()` returns `True` | | `TestAuthentication::test_valid_credentials_succeed` | PASS | |
| 7 | Invalid token (401) | Authentication | SQL API returns 401 | `AuthenticationError` raised | Rejected token never silently ignored | `test_invalid_token_raises_authentication_error` | PASS | |
| 8 | Permission denied (403) | Authentication | SQL API returns 403 | `AuthenticationError` raised | Token accepted but insufficient privilege still fails safely | `test_permission_denied_raises_authentication_error` | PASS | |
| 9 | Missing token | Authentication | Credentials dict without `programmatic_access_token` | `AuthenticationError` raised before any request | Never silently proceed with an empty token | `test_missing_token_raises_authentication_error` | PASS | |
| 10 | Malformed account_identifier at auth time | Authentication | `account_identifier="https://evil.example"` | `SnowflakeCredentialError` raised before any request | Prevents SSRF-style host injection | `test_malformed_account_identifier_raises_before_any_request` | PASS | |
| 11 | Missing role at auth time | Authentication | `role=""` | `SnowflakeCredentialError` raised before any request | ConfigTrace never defaults to an elevated role | `test_missing_role_raises_before_any_request` | PASS | |
| 12 | Connection timeout | Authentication | `httpx.ConnectTimeout` | `NetworkError` raised | | `test_connection_timeout_raises_network_error` | PASS | |
| 13 | TLS failure | Authentication | `ssl.SSLError` | `NetworkError` raised | Certificate verification failures never silently swallowed | `test_tls_failure_raises_network_error` | PASS | |
| 14 | Authorization header uses Bearer + token-type header | Authentication | — | `Authorization: Bearer <token>` and `X-Snowflake-Authorization-Token-Type: PROGRAMMATIC_ACCESS_TOKEN` both sent | Confirms the documented PAT header contract, not an ad hoc scheme | `test_authorization_header_uses_bearer_and_token_type` | PASS | |
| 15 | Token never in exception text | Credential redaction | Auth failure | PAT value absent from exception `str()` | Prevents secret leakage via error surfaces/logs | `test_token_never_appears_in_exception_text` | PASS | |
| 16 | Token never logged | Credential redaction | Successful validate, DEBUG logging | PAT value absent from captured logs | | `test_token_never_logged` | PASS | |

## Account identifiers

| # | Case | Area | Input/state | Expected behavior | Security concern | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|
| 17 | `orgname-accountname` form accepted | Account identifiers | `"myorg-myaccount"` | Returned lowercased/unchanged | | `TestValidateAccountIdentifier::test_orgname_accountname_form_accepted` | PASS | |
| 18 | Legacy locator form accepted | Account identifiers | `"xy12345.us-east-2.aws"` | Returned unchanged | Preserves support for the documented legacy identifier form | `test_legacy_locator_form_accepted` | PASS | |
| 19 | Uppercase lowercased | Account identifiers | Mixed-case identifier | Returned lowercased | Deterministic hostname construction | `test_uppercase_lowercased` | PASS | |
| 20 | Full hostname rejected | Account identifiers | `"myorg-myaccount.snowflakecomputing.com"` | `SnowflakeCredentialError` raised | Must be the bare identifier, never a full hostname | `test_full_hostname_rejected` | PASS | |
| 21 | URL scheme rejected | Account identifiers | `"https://myorg-myaccount.snowflakecomputing.com"` | `SnowflakeCredentialError` raised | Prevents this field from being treated as an arbitrary target URL | `test_url_scheme_rejected` | PASS | |
| 22 | Path rejected | Account identifiers | `"myorg-myaccount/evil"` | `SnowflakeCredentialError` raised | | `test_path_rejected` | PASS | |
| 23 | Query fragment rejected | Account identifiers | `"myorg-myaccount?x=1"` | `SnowflakeCredentialError` raised | | `test_query_fragment_rejected` | PASS | |
| 24 | Whitespace rejected | Account identifiers | `"myorg myaccount"` | `SnowflakeCredentialError` raised | | `test_whitespace_rejected` | PASS | |
| 25 | Empty string rejected | Account identifiers | `""` | `SnowflakeCredentialError` raised | | `test_empty_string_rejected` | PASS | |
| 26 | Non-string rejected | Account identifiers | `None` | `SnowflakeCredentialError` raised | | `test_non_string_rejected` | PASS | |
| 27 | Valid username accepted | Account identifiers | `"CONFIGTRACE_MONITOR"` | Returned unchanged | | `TestValidateUsername::test_valid_username_accepted` | PASS | |
| 28 | Empty username rejected | Account identifiers | `""` | `SnowflakeCredentialError` raised | | `test_empty_rejected` | PASS | |
| 29 | Non-string username rejected | Account identifiers | `None` | `SnowflakeCredentialError` raised | | `test_non_string_rejected` (username) | PASS | |
| 30 | Whitespace-only username rejected | Account identifiers | `"   "` | `SnowflakeCredentialError` raised | | `test_whitespace_only_rejected` | PASS | |
| 31 | Embedded SQL in username rejected | Account identifiers | `"user'; DROP TABLE users; --"` | `SnowflakeCredentialError` raised | Defense-in-depth even though username is never interpolated into SQL | `test_embedded_sql_rejected` | PASS | |
| 32 | Valid role accepted and uppercased | Account identifiers | `"configtrace_monitoring_role"` | Returned as `"CONFIGTRACE_MONITORING_ROLE"` | | `TestValidateRole::test_valid_role_accepted_and_uppercased` | PASS | |
| 33 | Empty role rejected | Account identifiers | `""` | `SnowflakeCredentialError` raised | Role is a required field, never silently defaulted | `test_empty_role_rejected` | PASS | |
| 34 | `None` role rejected | Account identifiers | `None` | `SnowflakeCredentialError` raised | | `test_none_role_rejected` | PASS | |
| 35 | Real role value never silently upgraded | Account identifiers | `"read_only_role"` | Returned as `"READ_ONLY_ROLE"`, unchanged content | | `test_accountadmin_not_defaulted` | PASS | |
| 36 | Missing-role error names both forbidden defaults | Account identifiers | `role=""` | Error text mentions `ACCOUNTADMIN` and `SECURITYADMIN` | Documents the exact security invariant being enforced | `test_missing_role_error_mentions_never_defaulting` | PASS | |
| 37 | Embedded symbol in role rejected | Account identifiers | `"ROLE; DROP TABLE x"` | `SnowflakeCredentialError` raised | | `test_embedded_symbol_rejected` | PASS | |

## Account identity (stable identity)

| # | Case | Area | Input/state | Expected behavior | Security concern | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|
| 38 | Stable identity computed | Account identity | `("ACME", "PROD")` twice | Identical `id:acme-prod` both times | | `TestAccountIdentity::test_stable_identity_computed` | PASS | |
| 39 | Identity is case-insensitive on input | Account identity | `("Acme", "Prod")` | `id:acme-prod` | Prevents casing drift from appearing as an account change | `test_identity_case_insensitive_on_input` | PASS | |
| 40 | Different accounts are distinct | Account identity | `("ACME","PROD")` vs `("ACME","DEV")` | Distinct ids | | `test_different_accounts_are_distinct` | PASS | |
| 41 | Missing organization returns `None` | Account identity | `(None, "PROD")` | `None` | Caller must treat this as "identity could not be established" | `test_missing_organization_returns_none` | PASS | |
| 42 | Missing account name returns `None` | Account identity | `("ACME", None)` | `None` | | `test_missing_account_name_returns_none` | PASS | |
| 43 | Empty strings return `None` | Account identity | `("", "")` | `None` | | `test_empty_strings_return_none` | PASS | |
| 44 | Identity never derived from the `account_identifier` credential | Account identity | Same underlying org/account pair | Identity computation never even reads the credential string | Rotating/retyping the account_identifier credential can never change stable identity | `test_identity_never_derived_from_account_identifier_credential` | PASS | |
| 45 | `fetch()` uses computed account_id as identity | Account identity | Full mocked fetch | `snowflake_account.account_id == "id:acme-prod"` | | `test_fetch_uses_computed_account_id_as_identity` | PASS | |
| 46 | Locator and role preserved on record | Account identity | Full mocked fetch | `account_locator`/`monitoring_role` match the mocked identity row | | `test_account_locator_and_role_preserved_on_record` | PASS | |
| 47 | account_identifier credential stored separately from stable id | Account identity | Full mocked fetch | `account_identifier != account_id` on the record | Never conflates the raw credential string with computed identity | `test_account_identifier_credential_stored_separately_from_stable_id` | PASS | |

## Account probe

| # | Case | Area | Input/state | Expected behavior | Security concern | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|
| 48 | Identity query returns all four fields | Account probe | Mocked identity row | `organization_name`/`account_name`/`account_locator`/`monitoring_role` all populated | | `TestAccountProbe::test_identity_query_returns_all_four_fields` | PASS | |
| 49 | Malformed (empty) row raises | Account probe | `{"data": []}` | `ConnectorError` raised | Never silently proceeds with a null identity | `test_malformed_row_raises_connector_error` | PASS | |
| 50 | Missing `data` key raises | Account probe | `{}` response body | `ConnectorError` raised | | `test_missing_data_key_raises_connector_error` | PASS | |
| 51 | Missing organization/account fields raises | Account probe | Row with `None` org/account | `ConnectorError` raised (identity computation fails) | Never stores a partial/null stable identity | `test_missing_organization_field_raises_connector_error` | PASS | |
| 52 | Identity statement is a read-only SELECT | Account probe | `_ACCOUNT_IDENTITY_STATEMENT` | Starts with `SELECT` | | `test_identity_statement_is_read_only_select` | PASS | |
| 53 | Session role sent matches credential role | Account probe | Full mocked fetch | POST body `role` field equals the validated credential role | Confirms the connector never silently substitutes a different role | `test_session_role_sent_matches_credential_role` | PASS | |

## Query safety / read-only discipline

| # | Case | Area | Input/state | Expected behavior | Security concern | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|
| 54 | Identity statement has no mutation keywords | Query safety | `_ACCOUNT_IDENTITY_STATEMENT` | None of CREATE/ALTER/DROP/GRANT/REVOKE/INSERT/UPDATE/DELETE/MERGE/COPY/PUT/GET/CALL present | Read-only session discipline | `TestQuerySafety::test_identity_statement_has_no_mutation_keywords` | PASS | |
| 55 | All capability probes are SELECT or SHOW | Query safety | All 13 `_CAPABILITY_PROBES` statements | Every statement starts with `SELECT` or `SHOW` | | `test_all_capability_probe_statements_are_select_or_show` | PASS | |
| 56 | All capability probes have no mutation keywords | Query safety | All 13 statements | None contain a mutating keyword (GRANT excluded as a legitimate view-name substring, e.g. `GRANTS_TO_USERS`) | | `test_all_capability_probe_statements_have_no_mutation_keywords` | PASS | |
| 57 | Exactly 13 families probed, matching the schema's family set | Query safety | `_CAPABILITY_PROBES` | `len == 13`; family set equals `CAPABILITY_FAMILIES` | Probe set can never silently drift from the declared taxonomy | `test_thirteen_families_probed` | PASS | |
| 58 | Every probe is bounded with `LIMIT 1` | Query safety | All 13 statements | Every statement contains `LIMIT 1` | Never a broad enumeration | `test_every_probe_is_bounded_with_limit_1` | PASS | |
| 59 | No `execute_arbitrary_sql` surface exists | Query safety | `SnowflakeConnector`, module source | No such method/string present anywhere | No generic SQL-injection surface is ever exposed | `test_no_execute_arbitrary_sql_surface_exists` | PASS | |
| 60 | No CLI/subprocess usage in executable code | Query safety | Module source, docstring stripped | No `subprocess`/`os.system`/`snowsql`/`shell=True` in code | Confirms no SnowSQL CLI dependency, only the documented prose mentions it | `test_no_cli_subprocess_usage` | PASS | |
| 61 | Every POSTed statement is one of the fixed allowlisted constants | Query safety | Full mocked fetch (14 calls: identity + 13 probes) | Every `statement` field matches a fixed constant; never contains the account_identifier or username values | Proves no user-controlled string is ever interpolated into a query | `test_statement_body_never_contains_user_controlled_fragment` | PASS | |

## Capabilities

| # | Case | Area | Input/state | Expected behavior | Security concern | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|
| 62 | All 13 families available | Capabilities | All probes succeed | 13 `snowflake_api_capability` records, all `status="available"` | | `TestCapabilityProbes::test_all_available` | PASS | |
| 63 | Mixed available/denied | Capabilities | `users` probe returns 403 | `users=denied`, `roles=available` | | `test_mixed_available_and_denied` | PASS | |
| 64 | Unsupported family (404) | Capabilities | `authentication_policies` probe returns 404 | `authentication_policies=unsupported` | A missing optional API must never block foundation validation | `test_unsupported_family_reports_unsupported` | PASS | |
| 65 | Throttled family | Capabilities | `warehouses` probe returns 429 | `warehouses=throttled` | | `test_throttled_family_reports_throttled` | PASS | |
| 66 | Malformed response family | Capabilities | `shares` probe returns non-JSON body | `shares=malformed` | | `test_malformed_response_reports_malformed` | PASS | |
| 67 | One denied optional family never invalidates the connection | Capabilities | `security_integrations` probe returns 403 | Account record still produced; all 13 capability records still present | A single family's permission gap must never abort the whole fetch | `test_one_denied_optional_family_does_not_invalidate_connection` | PASS | |
| 68 | Family statuses are independent | Capabilities | `users`=403, `databases`=404, `warehouses`=429 | Each family reports its own distinct status; unaffected families remain `available` | | `test_family_statuses_are_independent` | PASS | |
| 69 | `family_completeness` reflects capability status | Capabilities | `schemas` probe returns 403 | `family_completeness["schemas"]=="unavailable"`, `family_completeness["roles"]=="complete"` | | `test_family_completeness_reflects_capability_status` | PASS | |

## Error handling / retry

| # | Case | Area | Input/state | Expected behavior | Security concern | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|
| 70 | 429 then success | Error handling | 429 (Retry-After: 0) then 200 | Bounded retry succeeds | | `TestRateLimit::test_429_then_success` | PASS | |
| 71 | 429 exhausted | Error handling | Always 429 | `CallOutcome(ok=False, category="throttled")` after bounded attempts | Never fabricates a fake empty-success state | `test_429_exhausted_retries` | PASS | |
| 72 | 503 then success | Error handling | 503 then 200 | Bounded 5xx retry succeeds | | `test_503_then_success` | PASS | |
| 73 | 5xx retry budget exhausted | Error handling | Always 503 | `category="server_error"` after bounded attempts | | `test_5xx_retry_budget_exhausted` | PASS | |
| 74 | 401 never retried | Error handling | Always 401 | Exactly 1 request made | Permanent auth failures are never treated as transient | `test_401_never_retried` | PASS | |
| 75 | 403 never retried | Error handling | Always 403 | Exactly 1 request made | Permanent permission failures are never treated as transient | `test_403_never_retried` | PASS | |
| 76 | Sleep is mocked, never real | Error handling | Injected `_sleep_fn` | Sleep function invoked, no real delay | Test-suite performance/determinism | `test_sleep_is_mocked_never_real` | PASS | |
| 77 | Async 202 polled to completion | Error handling | Initial 202 + `statementHandle`, poll returns 202 then 200 | Outcome succeeds after polling | Correctly implements the SQL API's documented async contract | `test_async_202_polled_to_completion` | PASS | |
| 78 | Async poll timeout reported | Error handling | Poll endpoint always returns 202 | `category="timeout"` after bounded poll attempts | Never blocks indefinitely on a stuck async statement | `test_async_poll_timeout_reported` | PASS | |

## Credential redaction

| # | Case | Area | Input/state | Expected behavior | Security concern | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|
| 79 | Token absent from records | Credential redaction | Full `fetch()` | PAT value not present in any record | | `TestSensitiveDataSafety::test_token_absent_from_records` | PASS | |
| 80 | Authorization header absent from records | Credential redaction | Full `fetch()` | No "Authorization"/"Bearer" substring in any record | | `test_authorization_header_absent_from_records` | PASS | |
| 81 | Raw SQL API response body absent from records | Credential redaction | Full `fetch()` | No "statementHandle" substring in any record | Never propagate the raw HTTP response into a normalized record | `test_raw_sql_api_response_body_absent_from_records` | PASS | |
| 82 | Credential dict never copied wholesale into a record | Credential redaction | Full `fetch()` | No record contains a `programmatic_access_token` or `username` key | Confirms per-field normalization, never a raw credential passthrough | `test_credential_dict_never_copied_wholesale_into_a_record` | PASS | |
| 83 | PAT absent from a leaked-secret integration-creation check | Credential redaction | Real `create_integration()` call | Token value absent from resource metadata and API response | | `test_create_integration_creates_row_without_leaking_secret` | PASS | |

## Diff / provider metadata

| # | Case | Area | Input/state | Expected behavior | Security concern | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|
| 84 | Account metadata change is Low | Diff/risk | `monitoring_role` changes | Real `compute_diff()` -> `classify_change()` returns `low`, reason mentions "Snowflake" | | `TestDiff::test_account_metadata_change_is_low` | PASS | |
| 85 | Account removed is Medium | Diff/risk | Account disappears between snapshots | `medium` severity | Account no longer visible is a diagnostic signal, not routine | `test_account_removed_is_medium` | PASS | |
| 86 | Capability lost is Medium | Diff/risk | `status` available -> denied | `medium` severity | Losing read access to a metadata family is a diagnostic signal | `test_capability_lost_is_medium` | PASS | |
| 87 | Capability restored is Low | Diff/risk | `status` denied -> available | `low` severity | | `test_capability_restored_is_low` | PASS | |
| 88 | Diff provider metadata excludes credentials | Diff/provider metadata | Two snapshots differing in `account_name` | `provider_metadata["record_type"]=="snowflake_account"`; no `programmatic_access_token`/`username`/`password`/`private_key` fields | | `test_diff_provider_metadata_excludes_credentials` | PASS | |
| 89 | Account change routes to Snowflake classifier | Diff/risk dispatch | `record_type="snowflake_account"` | Reason text mentions "Snowflake" | Never falls through to an unrelated provider's classifier | `TestDiffRiskDispatch::test_account_change_routes_to_snowflake_classifier` | PASS | |
| 90 | Capability change routes to Snowflake classifier | Diff/risk dispatch | `record_type="snowflake_api_capability"`, available->denied | `medium` severity, reason mentions "Snowflake" | | `test_capability_change_routes_to_snowflake_classifier` | PASS | |
| 91 | Unknown Snowflake record type fails safe | Diff/risk dispatch | `record_type="snowflake_future_thing"` | `low` severity returned, no exception | Future record types (messages 2-7) never crash classification | `test_unknown_snowflake_record_type_fails_safe` | PASS | |
| 92 | Real `compute_diff()` produces Snowflake provider metadata | Diff/provider metadata | Two snapshots via `integration_service`-independent path | `provider_metadata["record_type"]=="snowflake_account"`, no credential fields | | `test_real_compute_diff_produces_snowflake_provider_metadata` | PASS | |

## Internal registration

| # | Case | Area | Input/state | Expected behavior | Security concern | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|
| 93 | Sync task dispatches Snowflake | Internal registration | — | `integration.provider == "snowflake"` branch present, imports `SnowflakeConnector` | | `TestProviderDispatchWiring::test_sync_task_dispatches_snowflake` | PASS | |
| 94 | integration_service dispatches Snowflake | Internal registration | — | `_create_snowflake_integration` present and wired | | `test_integration_service_dispatches_snowflake` | PASS | |
| 95 | sync_service supported providers contains Snowflake | Internal registration | — | `"snowflake"` in `_SUPPORTED_PROVIDERS` tuple | | `test_sync_service_supported_providers_contains_snowflake` | PASS | |
| 96 | Create integration rejects malformed account_identifier | Internal registration | `account_identifier="https://evil.example"` | `ValueError` raised, no row written | | `test_create_integration_rejects_malformed_account_identifier` | PASS | |
| 97 | Create integration never contacts Snowflake | Internal registration | Real `create_integration()` call | `SnowflakeConnector.validate_credentials` never called | Message 1 defers live credential validation to first sync — creation must never make an outbound call | `test_create_integration_does_not_contact_snowflake` | PASS | |
| 98 | Snowflake in `IntegrationCreateRequest` Literal | Credential schema | — | `provider="snowflake"` accepted | | `TestCredentialSchema::test_snowflake_in_provider_literal` | PASS | |
| 99 | Missing account_identifier rejected at schema layer | Credential schema | — | `ValidationError` raised | | `test_missing_account_identifier_rejected` | PASS | |
| 100 | Missing username rejected at schema layer | Credential schema | — | `ValidationError` raised | | `test_missing_username_rejected` | PASS | |
| 101 | Missing token rejected at schema layer | Credential schema | — | `ValidationError` raised | | `test_missing_token_rejected` | PASS | |
| 102 | Missing role rejected at schema layer | Credential schema | — | `ValidationError` raised | | `test_missing_role_rejected` | PASS | |
| 103 | `_build_credentials` extracts Snowflake fields | Credential schema | — | Returns `account_identifier`/`username`/`programmatic_access_token`/`role` dict | | `test_build_credentials_extracts_snowflake_fields` | PASS | |
| 104 | Snowflake registered in partial/staging capability list | Capability matrix | — | In `PROVIDER_CAPABILITIES_PARTIAL`, not `PROVIDER_CAPABILITIES` | Not yet publicly connectable | `TestCapabilityMatrix::test_snowflake_registered_in_partial_list_not_complete_list` | PASS | |
| 105 | Capability flags: drift True, security False | Capability matrix | — | `drift_snapshots/diff/risk_classification=True`; all `security.*=False` | Security Findings are message 6, not message 1 | `test_snowflake_drift_true_security_rules_false` | PASS | |
| 106 | Category is valid and is `database_backend` | Capability matrix | — | `cap.category in CATEGORIES`; equals `"database_backend"` | Matches the Supabase/Firebase precedent for a data-platform category | `test_snowflake_category_is_valid` | PASS | |
| 107 | Maturity is valid | Capability matrix | — | `cap.maturity in MATURITY_LEVELS` | | `test_snowflake_maturity_is_valid` | PASS | |
| 108 | Public matrix endpoint excludes Snowflake | Capability matrix | `get_matrix()` | Snowflake absent from `matrix["providers"]` | Never surfaced publicly before launch — same as GitLab/Terraform Cloud at their own message 1 | `test_get_matrix_excludes_snowflake_until_complete` | PASS | |
| 109 | Snowflake present in security-coverage providers list | Capability matrix | — | `"snowflake" in PROVIDERS` | Consistent with every other foundation-stage provider (GitLab/Terraform Cloud) already in this list | `test_snowflake_in_security_coverage_providers` | PASS | |

## Deployment (frontend catalog state)

| # | Case | Area | Input/state | Expected behavior | Security concern | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|
| 110 | Snowflake present in frontend `ProviderId` type | Frontend | `providers.ts` | `"snowflake"` string present | | `TestFrontendCatalogState::test_snowflake_present_in_provider_id_type` | PASS | |
| 111 | Snowflake has a `PROVIDERS` map entry | Frontend | `providers.ts` | `snowflake: {` present | Required for `Record<ProviderId, ProviderMeta>` to type-check | `test_snowflake_has_a_providers_map_entry` | PASS | |
| 112 | Snowflake excluded from `CONNECTABLE_PROVIDER_IDS` | Frontend | `providers.ts` | `"snowflake"` absent from that array | Must not be user-connectable yet | `test_snowflake_not_in_connectable_provider_ids` | PASS | |
| 113 | Snowflake excluded from `PROVIDER_IDS` | Frontend | `providers.ts` | `"snowflake"` absent from that array | Must not appear in the public integrations list | `test_snowflake_not_in_provider_ids_display_order` | PASS | |
| 114 | Card copy is truthful about not-yet-connectable status | Frontend | `providers.ts` | Contains "not yet" or "planned" | Avoids implying full/live coverage before it exists | `test_snowflake_card_copy_is_truthful_about_not_yet_connectable` | PASS | |
| 115 | Card copy does not claim credential storage | Frontend | `providers.ts` | No "stores the token value"/"stores your password" substrings | Prevents overclaiming what the (not-yet-built) integration will do | `test_snowflake_card_copy_does_not_claim_credential_storage` | PASS | |

**Total rows: 115.** Every case is backed by a passing automated test
(`test_snowflake_foundation.py` / `test_snowflake_connector_contract.py`) —
no case is documentation-only.

Test execution summary:
- `pytest tests/test_snowflake_foundation.py tests/test_snowflake_connector_contract.py -q` → **115 passed**.
- Narrow filter `snowflake and foundation` → 82 selected, passed.
- Narrow filter `snowflake and credential` → 13 selected, passed.
- Narrow filter `snowflake and capability` → 20 selected, passed.
- Narrow filter `snowflake and account` → 33 selected, passed.
- Cross-provider regression (`test_entra_connector_contract.py`,
  `test_okta_connector_contract.py`,
  `test_milestone75c_provider_capability_matrix.py`) → 81 passed, 1 skipped
  (pre-existing frontend-tree-not-found guard, unrelated to this change).
- `npx tsc --noEmit` (frontend) → clean, no errors.
