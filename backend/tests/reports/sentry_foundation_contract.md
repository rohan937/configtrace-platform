# Sentry Foundation Contract (Sentry Message 1 of 8)

Pins the connector architecture built in this message: bearer organization
auth-token authentication over the Sentry SaaS REST API (fixed
`https://sentry.io/api/0` origin), organization slug/token validation,
stable organization identity derived from the organization detail
response's immutable `id` field, the fail-soft API-call wrapper (bounded
429/5xx retry), trusted-origin-constrained cursor pagination, read-only
capability probing across 10 future record families, sensitive-data
exclusion, telemetry-vs-provider separation, provider registration, and
diff/provider-metadata parity. No projects, teams, members, alert rules,
integrations, webhooks, repositories, ownership rules, or releases are
collected yet — that begins in Sentry message 2 and onward.

Columns: **Case**, **Area**, **Input/state**, **Expected behavior**,
**Security concern**, **Test**, **Status**, **Notes**.

## Provider identity

| # | Case | Area | Input/state | Expected behavior | Security concern | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|
| 1 | Record type constants are `sentry_`-prefixed | Provider identity | `ALL_SENTRY_RECORD_TYPES` | Every value starts with `sentry_` | Prevents cross-provider record-type collision | `test_record_types_are_sentry_prefixed` | PASS | |
| 2 | Schema module imports cleanly | Provider identity | — | `import app.connectors.sentry_schema` succeeds | | `test_sentry_schema_module_imports` | PASS | |
| 3 | Connector module imports cleanly | Provider identity | — | `import app.connectors.sentry` succeeds | | `test_sentry_connector_module_imports` | PASS | |
| 4 | Risk rules module imports cleanly | Provider identity | — | `import app.services.risk_rules.sentry` succeeds | | `test_sentry_risk_rules_module_imports` | PASS | |
| 5 | Exactly 10 capability families, all unique | Provider identity | `CAPABILITY_FAMILIES` | `len == 10`, no duplicates | Matches this message's own enumerated 10-family taxonomy | `test_all_ten_capability_families_are_unique` | PASS | |
| 6 | Category is a valid, existing enum value | Provider identity | `get_provider_capability("sentry").category` | `"observability"`, present in `CATEGORIES` | Never invents a new category | `test_sentry_category_is_valid` | PASS | Same category as Datadog |
| 7 | Maturity is `"planned"` | Provider identity | `get_provider_capability("sentry").maturity` | `"planned"`, present in `MATURITY_LEVELS` | | `test_sentry_maturity_is_valid` | PASS | |

## Authentication

| # | Case | Area | Input/state | Expected behavior | Security concern | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|
| 8 | Valid credentials succeed | Authentication | Valid organization_slug/auth_token | `validate_credentials()` returns `True` | | `TestAuthentication::test_valid_credentials_succeed` | PASS | |
| 9 | Invalid token (401) | Authentication | API returns 401 | `AuthenticationError` raised | Rejected token never silently ignored | `test_invalid_token_raises_authentication_error` | PASS | |
| 10 | Permission denied (403) | Authentication | API returns 403 | `AuthenticationError` raised | Token accepted but insufficient scope still fails safely | `test_permission_denied_raises_authentication_error` | PASS | |
| 11 | Organization not found (404) | Authentication | API returns 404 | `ConnectorError` raised | Distinguishes "wrong org" from "bad token" | `test_organization_not_found_raises_connector_error` | PASS | |
| 12 | Missing token | Authentication | Credentials dict without `auth_token` | `SentryCredentialError` raised before any request | Never silently proceed with an empty token | `test_missing_token_raises_before_any_request` | PASS | |
| 13 | Malformed organization_slug at auth time | Authentication | `organization_slug="https://evil.example"` | `SentryCredentialError` raised before any request | Prevents SSRF-style host injection via slug | `test_malformed_organization_slug_raises_before_any_request` | PASS | |
| 14 | Connection timeout | Authentication | `httpx.ConnectTimeout` | `NetworkError` raised | | `test_timeout_raises_network_error` | PASS | |
| 15 | 429 raises RateLimitError after exhausted retries | Authentication | Sustained 429 | `RateLimitError` raised | Bounded retry, never an infinite loop | `test_429_raises_rate_limit_error_after_exhausted_retries` | PASS | |
| 16 | 503 retried then succeeds | Authentication | 503 then 200 | Bounded retry recovers | Transient 5xx never treated as fatal on first failure | `test_503_retried_then_succeeds` | PASS | |
| 17 | 401 never retried | Authentication | Sustained 401 | Exactly 1 call made | Auth failures are not transient — retrying wastes time and risks lockout | `test_401_never_retried` | PASS | |
| 18 | 403 never retried | Authentication | Sustained 403 | Exactly 1 call made | | `test_403_never_retried` | PASS | |
| 19 | 429 bounded retry exhausted | Authentication | Sustained 429 | Exactly 5 total calls (1 + 4 retries) | Bound matches `_MAX_THROTTLE_RETRIES` exactly | `test_429_bounded_retry_exhausted` | PASS | |
| 20 | Authorization header uses Bearer scheme | Authentication | — | `Authorization: Bearer <token>`, `Accept: application/json` | Confirms the documented bearer-token header contract | code review (`_make_client`) | PASS | Matches current docs.sentry.io/api/auth/ |

## Organization slug / auth token validation

| # | Case | Area | Input/state | Expected behavior | Security concern | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|
| 21 | Valid slug accepted | Slug validation | `"my-organization"` | Returned lowercased/unchanged | | `TestValidateOrganizationSlug::test_valid_slug_accepted` | PASS | |
| 22 | Uppercase lowercased | Slug validation | Mixed-case slug | Returned lowercased | Deterministic path-segment construction | `test_uppercase_lowercased` | PASS | |
| 23 | URL scheme rejected | Slug validation | `"https://evil.example"` | `SentryCredentialError` raised | Slug must never control the request host | `test_url_scheme_rejected` | PASS | |
| 24 | Path rejected | Slug validation | `"my-organization/evil"` | `SentryCredentialError` raised | | `test_path_rejected` | PASS | |
| 25 | Query fragment rejected | Slug validation | `"my-organization?x=1"` | `SentryCredentialError` raised | | `test_query_fragment_rejected` | PASS | |
| 26 | Dot rejected | Slug validation | `"my.organization"` | `SentryCredentialError` raised | Sentry slugs never contain dots; conservative allowlist | `test_dot_rejected` | PASS | |
| 27 | Whitespace rejected | Slug validation | `"my organization"` | `SentryCredentialError` raised | | `test_whitespace_rejected` | PASS | |
| 28 | Empty string rejected | Slug validation | `""` | `SentryCredentialError` raised | | `test_empty_string_rejected` | PASS | |
| 29 | Non-string rejected | Slug validation | `None` | `SentryCredentialError` raised | | `test_non_string_rejected` | PASS | |
| 30 | Valid auth token accepted | Slug validation | Non-empty string | Returned unchanged | | `TestValidateAuthToken::test_valid_token_accepted` | PASS | |
| 31 | Empty token rejected | Slug validation | `""` | `SentryCredentialError` raised | | `test_empty_rejected` (token) | PASS | |
| 32 | Non-string token rejected | Slug validation | `None` | `SentryCredentialError` raised | | `test_non_string_rejected` (token) | PASS | |
| 33 | Whitespace-only token rejected | Slug validation | `"   "` | `SentryCredentialError` raised | | `test_whitespace_only_rejected` | PASS | |
| 34 | No token-prefix format enforced | Slug validation | Arbitrary non-empty string | Accepted | Current docs do not confirm a stable prefix contract (`sntrys_`/`sntryu_` seen only in source/mirrors, never docs.sentry.io) — do not guess | `test_no_prefix_format_enforced` | PASS | Documented ambiguity |

## Organization identity

| # | Case | Area | Input/state | Expected behavior | Security concern | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|
| 35 | Stable ID computed from string | Organization identity | `raw_id="123456"` | `"id:123456"` | | `test_compute_organization_id_from_string` | PASS | |
| 36 | Stable ID computed from int | Organization identity | `raw_id=123456` | `"id:123456"` | Sentry's `id` field type not fully pinned by docs — both accepted | `test_compute_organization_id_from_int` | PASS | |
| 37 | Missing ID returns None | Organization identity | `raw_id=None` | `None` — never a coerced partial identity | Missing identity must fail loudly, not silently substitute the slug | `test_compute_organization_id_none_for_missing` | PASS | |
| 38 | Empty string ID returns None | Organization identity | `raw_id=""` | `None` | | `test_compute_organization_id_none_for_empty_string` | PASS | |
| 39 | fetch() establishes stable identity | Organization identity | Real organization detail response | `organization_id == "id:999"`, `record_id == "id:999"` | | `test_fetch_establishes_stable_identity` | PASS | |
| 40 | Slug rename preserves identity | Organization identity | Org detail response returns a NEW slug (`"renamed-org"`) for the SAME `id` | `organization_id` unchanged; `slug` field reflects the new value | Confirms current docs: slugs can be renamed, `id` is the stable key | `test_slug_rename_preserves_identity` | PASS | Real bug found+fixed this message — see notes below |
| 41 | Missing `id` field raises ConnectorError | Organization identity | Response has `slug`/`name` but no `id` | `ConnectorError` raised — never a silently degraded identity | | `test_missing_id_field_raises_connector_error` | PASS | |
| 42 | Non-dict response raises ConnectorError | Organization identity | Response body is a JSON array | `ConnectorError` raised | | `test_non_dict_response_raises_connector_error` | PASS | |
| 43 | Malformed JSON raises ConnectorError | Organization identity | Response body is not valid JSON | `ConnectorError` raised | | `test_malformed_json_raises_connector_error` | PASS | |
| 44 | Organization record excludes billing/avatar/feature payload | Organization identity | Full org detail response (avatar, `hasAuthProvider`, `require2FA`, etc.) | Only `organization_id`/`slug`/`name`/`status_category`/`date_created`/`family_completeness` are ever extracted | Never a raw payload dump | code review (`_normalize_organization`) | PASS | Allowlist normalizer, no `.copy()`/wholesale dump |

## Trusted host

| # | Case | Area | Input/state | Expected behavior | Security concern | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|
| 45 | Fixed API origin used for every request | Trusted host | Any credentials | Every request targets `https://sentry.io/api/0` | Slug/credentials can never redirect requests to another host | code review (`_BASE_URL`, `_make_client`) | PASS | |
| 46 | Slug cannot alter host | Trusted host | Slug validated as a bare path segment (no `://`, `/`, `?`, `#`, `.`, spaces) | Slug is only ever interpolated as a path segment | | `TestValidateOrganizationSlug` (all cases) | PASS | |
| 47 | No `links.regionUrl` following | Trusted host | Org detail response includes `links.regionUrl` (not modeled in tests, but never read by the connector) | Connector never reads or follows a server-supplied region URL | A server-controlled "go here next" URL is exactly the SSRF-adjacent pattern this codebase avoids | code review (`_normalize_organization` never touches `raw["links"]`) | PASS | Documented foundation limitation |
| 48 | Cross-origin pagination `next` link rejected | Trusted host | `rel="next"` URL on `https://evil.example` | URL dropped (`entry["url"] is None`); pagination stops, marked truncated | Pagination must never redirect to an attacker-controlled host | `TestLinkHeaderParsing::test_cross_origin_next_rejected`, `TestPagination::test_untrusted_next_url_rejected_and_truncated` | PASS | |
| 49 | HTTP-scheme (non-HTTPS) `next` link rejected | Trusted host | `rel="next"` URL using `http://` on the correct host | URL dropped | Prevents a scheme-downgrade pagination redirect | `test_http_scheme_next_rejected` | PASS | |
| 50 | Self-hosted Sentry explicitly unsupported | Trusted host | N/A | No configurable base URL exists in the credential model | Self-hosted is a genuinely different trust boundary (operator-controlled host/CA) — never silently assumed compatible | code review (module docstring, `_credentials()` has no host field) | PASS | Documented foundation limitation |

## Pagination

| # | Case | Area | Input/state | Expected behavior | Security concern | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|
| 51 | `next`/`previous` relations parsed with `results` flag | Pagination | Documented example Link header | Both relations parsed; `results` boolean extracted per-relation | | `TestLinkHeaderParsing::test_next_and_previous_parsed` | PASS | Matches current docs.sentry.io/api/pagination/ exactly |
| 52 | `results="false"` means natural end | Pagination | `rel="next"; results="false"` | Recognized as the documented end-of-list signal | Never treated as truncation | `test_results_false_means_natural_end` | PASS | |
| 53 | Malformed Link header returns empty | Pagination | Garbage string | `_parse_link_header` returns `{}`, never raises | | `test_malformed_header_returns_empty` | PASS | |
| 54 | Single page, no next | Pagination | One page, `results="false"` | `truncated=False`, all items returned | | `TestPagination::test_single_page_no_next` | PASS | |
| 55 | Multiple pages followed | Pagination | 2 pages, `results="true"` then `"false"` | Both pages' items accumulated, `truncated=False` | | `test_multiple_pages_followed` | PASS | |
| 56 | Repeated cursor detected and stopped | Pagination | Same page/cursor served twice | Pagination stops, `truncated=True` | Defends against a misbehaving/malicious server looping forever | `test_repeated_cursor_stops_and_marks_truncated` | PASS | |
| 57 | Malformed Link header on a later page is truncated | Pagination | Page 1 has `next`, page 2 has NO Link header at all | `truncated=True`, page-1 items still returned | A later-page anomaly must not silently claim completeness | `test_malformed_link_header_on_later_page_is_truncated` | PASS | |
| 58 | Untrusted `next` URL rejected and truncated | Pagination | Page 1's `next` is cross-origin | `truncated=True`, page-1 items still returned | | `test_untrusted_next_url_rejected_and_truncated` | PASS | |
| 59 | Later-page 403 stops but returns partial | Pagination | Page 1 OK, page 2 returns 403 | `truncated=True`, page-1 items preserved | A transient/permission failure mid-pagination degrades to partial results, never loses everything already fetched | `test_later_page_403_stops_but_returns_partial` | PASS | |
| 60 | Later-page 429 retried then succeeds, not truncated | Pagination | Page 1 OK, page 2 429-then-200 | Retry succeeds, `truncated=False`, both pages' items returned | | `test_later_page_429_retried_then_succeeds_not_truncated` | PASS | |
| 61 | First-page failure raises | Pagination | Page 1 returns 401 | Raises `AuthenticationError` — a fully broken credential fails loudly | | `test_first_page_failure_raises` | PASS | |
| 62 | Deterministic ordering, no duplicate IDs | Pagination | Page 2 re-serves an ID from page 1 | Items deduplicated by `id`, stable order preserved | Defends against a server re-serving an overlapping page | `test_deterministic_ordering_and_no_duplicate_ids` | PASS | |
| 63 | `max_pages` bound prevents infinite loop | Pagination | Server ALWAYS advertises another `results="true"` next page | Stops at exactly `max_pages`, `truncated=True` | Hard bound — never an infinite loop even against an adversarial/buggy server | `test_max_pages_bound_marks_truncated` | PASS | |
| 64 | Pagination helper is production-ready though unused by message-1 probes | Pagination | — | `paginate_sentry()` fully implemented and tested now | Later messages reuse this unmodified rather than writing pagination twice | code review + all `TestPagination` cases | PASS | Capability probes never call it — page 1 only |

## Rate limiting

| # | Case | Area | Input/state | Expected behavior | Security concern | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|
| 65 | 429 triggers bounded backoff retry | Rate limiting | Sustained 429 | Retried up to `_MAX_THROTTLE_RETRIES`, then `RateLimitError` | | `test_429_bounded_retry_exhausted` | PASS | |
| 66 | `Retry-After` honored defensively though undocumented for this API | Rate limiting | — | `_retry_after_seconds()` checks `Retry-After` first | Costs nothing to honor if present even though current docs don't guarantee it for the REST management API specifically (only for the separate SDK/ingestion transport contract) | code review (`_retry_after_seconds`) | PASS | Documented ambiguity |
| 67 | `X-Sentry-Rate-Limit-Reset` used as fallback | Rate limiting | `Retry-After` absent, reset header present | Delay computed from the documented reset-epoch header | This header IS documented by current official docs | code review (`_retry_after_seconds`) | PASS | |
| 68 | Rate-limited capability probe never aborts whole fetch | Rate limiting | `/members/` returns 429 | Family reports `throttled`; organization + other families still returned | One rate-limited family must not fail the entire foundation fetch | `TestCapabilityProbes::test_rate_limited_family` | PASS | |
| 69 | No real sleeps in tests | Rate limiting | All retry/backoff tests | `_sleep_fn=_noop_sleep` injected everywhere | Test suite runtime bounded; no flaky real-time waits | code review (every retry test passes `_sleep_fn`) | PASS | |

## Capability probes

| # | Case | Area | Input/state | Expected behavior | Security concern | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|
| 70 | All families available | Capability probes | All 7 real-probe endpoints return 200 | All report `available`; 3 structurally-unsupported families report `unsupported` | | `TestCapabilityProbes::test_all_families_available` | PASS | |
| 71 | Mixed available/denied | Capability probes | `teams` returns 403 | `teams=denied`, `projects=available`, organization still emitted | One denied optional family never invalidates the whole connector | `test_mixed_available_denied` | PASS | |
| 72 | Unsupported family via 404 | Capability probes | `repos` returns 404 | `repositories=unsupported` | | `test_unsupported_family_via_404` | PASS | |
| 73 | Rate-limited family | Capability probes | `members` returns 429 | `members=throttled` | | `test_rate_limited_family` | PASS | |
| 74 | Timed-out family | Capability probes | `integrations` raises `ConnectTimeout` | `integrations=timed_out` | | `test_timed_out_family` | PASS | |
| 75 | Malformed family via unclassified transport failure | Capability probes | `releases` raises an unclassified exception | `releases=malformed` | | `test_malformed_family` | PASS | |
| 76 | 200-with-invalid-JSON body still `available` | Capability probes | `releases` returns 200 with non-JSON body | `releases=available` — probes are status-only, never parse the body | Keeps probes lightweight; body validity is a real-collection (later message) concern | `test_200_with_invalid_json_body_still_available` | PASS | |
| 77 | Structurally-unsupported families never call HTTP | Capability probes | `issue_alerts`/`webhooks`/`ownership_rules` | All three report `unsupported` with zero HTTP calls made | Never guesses at an unconfirmed/project-scoped endpoint | `test_structurally_unsupported_families_never_call_http` | PASS | These 3 are project-scoped; no project inventory exists until message 2 |
| 78 | Independent statuses, organization still emitted | Capability probes | 3 different simultaneous failure modes across 3 families | Organization record present regardless; each family's status independent | Capability independence — no cascading failure | `test_independent_statuses_organization_still_emitted` | PASS | |
| 79 | No `per_page`/`limit` parameter guessed | Capability probes | — | Probes send no page-size parameter at all | Current docs do not confirm a generically-supported page-size param name across all 7 endpoints — bounding via page-1-only instead of guessing | code review (`_CAPABILITY_PROBES`, no params) | PASS | Documented design decision |
| 80 | Probes never enumerate beyond page 1 | Capability probes | — | `_probe_one` calls `call_sentry` directly, never `paginate_sentry` | Bounded cost per probe | code review (`_probe_one`) | PASS | |

## Error handling

| # | Case | Area | Input/state | Expected behavior | Security concern | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|
| 81 | 401 classified as auth failure | Error handling | HTTP 401 | `CATEGORY_AUTH_FAILED` | | code review (`_classify_response`) | PASS | |
| 82 | 403 classified as permission denied | Error handling | HTTP 403 | `CATEGORY_PERMISSION_DENIED` | | code review (`_classify_response`) | PASS | |
| 83 | 404 classified as not found | Error handling | HTTP 404 | `CATEGORY_NOT_FOUND` | | code review (`_classify_response`) | PASS | |
| 84 | 429 classified as throttled | Error handling | HTTP 429 | `CATEGORY_THROTTLED` | | code review (`_classify_response`) | PASS | |
| 85 | 5xx classified as server error | Error handling | HTTP 500/502/503/504 | `CATEGORY_SERVER_ERROR` | | code review (`_classify_response`) | PASS | |
| 86 | TLS failure classified distinctly | Error handling | `ssl.SSLError` | `CATEGORY_TLS_ERROR` → `NetworkError` | Certificate failures never silently swallowed | code review (`_classify_transport_exception`) | PASS | |
| 87 | DNS failure produces a clear message | Error handling | `getaddrinfo failed` in exception text | `CATEGORY_CONNECTION_ERROR` with a hostname-resolution-specific message | | code review (`_classify_transport_exception`) | PASS | |
| 88 | Unclassified exception falls back to malformed | Error handling | Generic `RuntimeError` | `CATEGORY_MALFORMED_RESPONSE` | Never an uncaught exception escaping the wrapper | `TestCapabilityProbes::test_malformed_family` | PASS | |
| 89 | Organization not found (404) distinct from auth failure | Error handling | 404 vs 401 | `ConnectorError` vs `AuthenticationError` — distinguishable by callers | Lets future message-8 UX show "org not found" vs "bad token" | `TestAuthentication::test_organization_not_found_raises_connector_error` | PASS | |
| 90 | Read-only discipline — GET only | Error handling | Full connector source | Zero `.post(`/`.put(`/`.patch(`/`.delete(` calls | ConfigTrace never mutates a connected Sentry organization | `test_no_mutating_http_methods_in_connector` | PASS | |

## Credential redaction

| # | Case | Area | Input/state | Expected behavior | Security concern | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|
| 91 | Token absent from Resource metadata | Credential redaction | Real `create_integration()` call | `_TOKEN not in metadata_blob` | Token never persisted outside encrypted credentials column | `test_create_integration_creates_row_without_leaking_secret` | PASS | |
| 92 | Token absent from `IntegrationResponse` JSON | Credential redaction | Same as above | `_TOKEN not in response_blob` | Token never returned in any API response | `test_create_integration_creates_row_without_leaking_secret` | PASS | |
| 93 | Token absent from Change `provider_metadata` | Credential redaction | Real `compute_diff()` | `"auth_token" not in pm` | | `test_real_compute_diff_produces_sentry_provider_metadata` | PASS | |
| 94 | Token never in `CallOutcome.detail` | Credential redaction | Every failure category | `detail` is always a fixed, category-specific string | No raw request/response/header ever surfaces | code review (`_classify_response`/`_classify_transport_exception`) | PASS | |
| 95 | Token never in raised exception text | Credential redaction | `_raise_for_outcome` | Exception message never includes `outcome.detail`'s source beyond the fixed category string | | code review (`_raise_for_outcome`) | PASS | |
| 96 | DSNs/client keys/webhook secrets never fetched | Credential redaction | — | Connector never requests or stores these fields (no such fields exist in message-1 records) | Explicit permanent exclusion | code review (`_normalize_organization`, `_normalize_capability`) | PASS | |

## Telemetry vs monitored-provider separation

| # | Case | Area | Input/state | Expected behavior | Security concern | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|
| 97 | No `sentry_sdk` import anywhere in the connector | Telemetry separation | Full connector source | Zero `import sentry_sdk`/`from sentry_sdk`/`sentry_sdk.init(` | ConfigTrace's own error-monitoring SDK (if ever added) must never be coupled to this connector | `test_connector_never_imports_sentry_sdk` | PASS | |
| 98 | No `SENTRY_DSN`/`SENTRY_AUTH_TOKEN` environment-variable ACCESS | Telemetry separation | Full connector source | No `os.environ`/`os.getenv` call anywhere | Customer credentials never sourced from a global env var | `test_connector_never_reads_sentry_dsn_env_var`, `test_connector_never_reads_sentry_auth_token_env_var` | PASS | Bare-string mentions in the module's own explanatory docstring are expected and are not access patterns |
| 99 | Customer token comes only from the `credentials` dict argument | Telemetry separation | `validate_credentials`/`fetch` source | Both derive the token exclusively via `self._credentials(credentials)` | | `test_customer_token_comes_only_from_credentials_dict` | PASS | |
| 100 | No new global Sentry env vars added to `Settings`/`config.py` | Telemetry separation | `app/config.py` | No `SENTRY_AUTH_TOKEN`/`SENTRY_ORG` setting exists | Customer credentials belong to encrypted integration storage, never deployment config | `test_no_global_sentry_env_vars_added_to_settings` | PASS | |
| 101 | No `sentry_sdk.init()` call anywhere in `app/connectors` or `app/services` | Telemetry separation | Broad grep | Zero matches | Connector never (re)initializes global SDK state | safety grep (§ report deliverable) | PASS | |

## Diff / provider metadata

| # | Case | Area | Input/state | Expected behavior | Security concern | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|
| 102 | Organization change routes to Sentry classifier | Diff/risk dispatch | `record_type="sentry_organization"` | `classify_change()` returns a Sentry-specific reason string | Never falls through to an unrelated provider's classifier | `test_organization_change_routes_to_sentry_classifier` | PASS | |
| 103 | Capability change routes to Sentry classifier | Diff/risk dispatch | `record_type="sentry_api_capability"` | `medium` severity, Sentry-specific reason | | `test_capability_change_routes_to_sentry_classifier` | PASS | |
| 104 | Unknown future `sentry_*` record type fails safe | Diff/risk dispatch | `record_type="sentry_future_thing"` | `low` severity — never raises, never falls through | Dispatcher stays correct as later messages add record types incrementally | `test_unknown_sentry_record_type_fails_safe` | PASS | |
| 105 | Real `compute_diff()` produces correct provider_metadata | Diff/risk dispatch | Real `Snapshot`-shaped before/after state | `pm["record_type"] == "sentry_organization"`, no `auth_token` key | | `test_real_compute_diff_produces_sentry_provider_metadata` | PASS | |
| 106 | Slug change IS tracked (observable Change) | Diff/risk dispatch | `slug` differs between snapshots | Exactly 1 Change, `field_path == "slug"` | Confirms slug renames are detectable drift, not silently ignored | `test_slug_change_is_tracked` | PASS | |
| 107 | `family_completeness` change is NOT tracked | Diff/risk dispatch | Only `family_completeness` differs | Zero Changes produced | A permission change alone must never produce a noisy Change | `test_family_completeness_not_tracked` | PASS | |
| 108 | Capability `status` field is tracked | Diff/risk dispatch | `_SENTRY_TRACKED_FIELDS_BY_TYPE["sentry_api_capability"]` | `("status",)` | | code review (`diff_service.py`) | PASS | |
| 109 | Organization tracked fields are `slug`/`name`/`status_category` only | Diff/risk dispatch | `_SENTRY_TRACKED_FIELDS_BY_TYPE["sentry_organization"]` | Exactly those 3 fields | Transient/noisy fields (dates, completeness) intentionally excluded | code review (`diff_service.py`) | PASS | |
| 110 | Capability available→denied classifies as Medium | Diff/risk dispatch | `prev="available"`, `new="denied"` | `medium`, reason mentions reviewing token scopes | Loss of access is a real diagnostic signal, not a false "incident" | `test_capability_change_routes_to_sentry_classifier` | PASS | |
| 111 | Capability denied→available classifies as Low | Diff/risk dispatch | `prev="denied"`, `new="available"` | `low` | Regaining access is not itself risky | code review (`_classify_api_capability_change`) | PASS | |

## Internal registration

| # | Case | Area | Input/state | Expected behavior | Security concern | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|
| 112 | `sync_task.py` dispatches Sentry | Internal registration | — | `integration.provider == "sentry"` branch present, imports `SentryConnector` | | `test_sync_task_dispatches_sentry` | PASS | |
| 113 | `integration_service.py` dispatches Sentry | Internal registration | — | `provider == "sentry"` branch present, calls `_create_sentry_integration` | | `test_integration_service_dispatches_sentry` | PASS | |
| 114 | `sync_service.py` includes Sentry in supported providers | Internal registration | `_SUPPORTED_PROVIDERS` | `"sentry"` present | Scheduled syncs pick up Sentry integrations automatically | `test_sync_service_supported_providers_contains_sentry` | PASS | |
| 115 | Integration row created without leaking the token | Internal registration | Real `create_integration()` | Row created, `encrypted_credentials`/`credential_iv` populated, token absent from Resource metadata and API response | | `test_create_integration_creates_row_without_leaking_secret` | PASS | |
| 116 | Malformed organization slug rejected at creation | Internal registration | `organization_slug="https://evil.example"` | `ValueError` raised before any DB write | | `test_create_integration_rejects_malformed_organization_slug` | PASS | |
| 117 | Creation defers live validation to first sync | Internal registration | Real `create_integration()`, `validate_credentials` patched | Never called during creation | Avoids leaking organization-reachability details via a synchronous create-time error — same pattern as every provider's own message 1 | `test_create_integration_does_not_contact_sentry` | PASS | Message-8 concern, not message-1 |
| 118 | `sentry` present in `IntegrationCreateRequest.provider` Literal | Internal registration | — | `IntegrationCreateRequest(provider="sentry", ...)` validates | | `test_sentry_in_provider_literal` | PASS | |
| 119 | Missing `sentry_organization_slug` rejected at schema layer | Internal registration | — | `ValidationError` raised | | `test_missing_organization_slug_rejected` | PASS | |
| 120 | Missing `sentry_auth_token` rejected at schema layer | Internal registration | — | `ValidationError` raised | | `test_missing_auth_token_rejected` | PASS | |
| 121 | `_build_credentials` extracts both Sentry fields correctly | Internal registration | Real `IntegrationCreateRequest` | `creds["organization_slug"]`/`creds["auth_token"]` match input | Router-to-connector credential-dict shape matches exactly | `test_build_credentials_extracts_sentry_fields` | PASS | |
| 122 | Sentry staged in `PROVIDER_CAPABILITIES_PARTIAL`, not the complete list | Internal registration | — | `"sentry" in PARTIAL`, `"sentry" not in PROVIDER_CAPABILITIES` | Foundation-only providers never appear in the canonical launched list | `test_sentry_registered_in_partial_list_not_complete_list` | PASS | |
| 123 | `get_matrix()` excludes Sentry until launched | Internal registration | — | `"sentry" not in` the public matrix endpoint's provider IDs | | `test_get_matrix_excludes_sentry_until_complete` | PASS | |
| 124 | Sentry present in Security Findings coverage provider inventory | Internal registration | `security_coverage_service.PROVIDERS` | `"sentry"` present | Consistent with every other foundation provider (no rule mappings added yet) | `test_sentry_in_security_coverage_providers` | PASS | |
| 125 | Drift capabilities true, Security Findings false | Internal registration | `get_provider_capability("sentry")` | `drift_snapshots/diff/risk_classification=True`; `security_rules=False` | No Security Findings exist until Sentry message 6 | `test_sentry_drift_true_security_rules_false` | PASS | |

## Frontend catalog state

| # | Case | Area | Input/state | Expected behavior | Security concern | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|
| 126 | `"sentry"` present in the `ProviderId` type union | Frontend catalog | `providers.ts` | Present | | `test_sentry_present_in_provider_id_type` | PASS | |
| 127 | Sentry has a `PROVIDER_META` map entry | Frontend catalog | `providers.ts` | `sentry: { ... }` present | | `test_sentry_has_a_providers_map_entry` | PASS | |
| 128 | Sentry absent from `CONNECTABLE_PROVIDER_IDS` | Frontend catalog | `providers.ts` | Not present | Must not appear connectable until message 8 | `test_sentry_not_in_connectable_provider_ids` | PASS | |
| 129 | Sentry absent from `PROVIDER_IDS` display order | Frontend catalog | `providers.ts` | Not present | Must not appear on the public integrations list yet | `test_sentry_not_in_provider_ids_display_order` | PASS | |
| 130 | Card copy is truthful about "not yet connectable" | Frontend catalog | `providers.ts` `sentry` entry | Contains "not yet"/"planned" wording | Never implies a working connection exists | `test_sentry_card_copy_is_truthful_about_not_yet_connectable` | PASS | |
| 131 | Card copy never claims credential storage it doesn't do | Frontend catalog | `providers.ts` `sentry` entry | No "stores the token value"/"stores your password" phrasing | | `test_sentry_card_copy_does_not_claim_credential_storage` | PASS | |
| 132 | Card description/monitoredSurfaces never claim event-data monitoring | Frontend catalog | `providers.ts` `sentry` entry (excluding trustNote) | No "stack trace"/"error event"/"breadcrumb"/"issue message" | The trustNote may legitimately *disclaim* these; the active-monitoring copy must never claim them | `test_sentry_card_copy_never_claims_event_data_monitoring` | PASS | |

## Deployment

| # | Case | Area | Input/state | Expected behavior | Security concern | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|
| 133 | No new production dependency | Deployment | `requirements.txt` | Unchanged — `httpx` already sufficient | Zero new dependency surface for REST metadata collection | code review (no `sentry-sdk`/other package added) | PASS | |
| 134 | No Sentry CLI / `sentry-cli` dependency | Deployment | Full connector + services source | Zero matches for `sentry-cli`/`subprocess`/`os.system`/`shell=True` | | safety grep (§ report deliverable) | PASS | |
| 135 | No DB migration required | Deployment | `Integration.provider` column | Plain text column, no enum/CHECK constraint | | code review (`app/models/integration.py`) | PASS | Same conclusion as every prior provider's message 1 |
| 136 | `IntegrationCreateRequest.provider` Literal is the only schema-level enum touched | Deployment | `schemas/integration.py` | New `"sentry"` literal value added, no DB-level constraint | | code review | PASS | |
| 137 | ConfigTrace's own future Sentry telemetry (if added) uses a separate trust boundary | Deployment | — | This connector's credential model has no shared field/env-var with any hypothetical ConfigTrace-own `SENTRY_DSN` | Permanent architectural separation, not just an absence-today observation | `TestTelemetrySeparation` (all cases) | PASS | |

**137 rows.** Exceeds the required minimum of 75.

## Real bug found and fixed this message

`_normalize_organization()` initially echoed back the credential-supplied
`organization_slug` verbatim as the record's tracked `slug` field, instead
of reading Sentry's own current `slug` from the organization detail
response body. Since `slug` is a diff-tracked field specifically so that
a real organization rename is observable as a Change, this would have
made slug renames permanently invisible to drift detection — the record
would always show the ORIGINAL request-time slug, never the current one.
Caught by `test_slug_rename_preserves_identity` (which asserted the
record's `slug` should reflect a simulated rename in the mocked API
response) failing with `'my-organization' != 'renamed-org'`. Fixed by
reading `raw.get("slug")` from the actual response body (falling back to
the credential slug only if the response omitted it, which should not
normally happen).
