# Okta Provider Foundation Contract (Okta message 1 of 8)

This report documents the secure, read-only Okta connector foundation built
in this message: authentication, tenant identity, URL validation,
pagination, rate-limit behavior, capability probes, sensitive-data
boundaries, the emitted record taxonomy, provider registration state, and
what is explicitly deferred to messages 2-8.

## Authentication design

**Chosen method: Okta API token (`Authorization: SSWS <token>`).**

This is the officially-supported, minimal-privilege authentication mode
for a trusted backend service reading org configuration — no OAuth
authorization-code redirect flow is needed, and it mirrors the
direct-token mode both Auth0 (`management_api_token`) and Clerk
(`secret_key`) already use as their primary/simplest authentication path
in this codebase.

**OAuth 2.0 service-app authentication (client_credentials with a private
key / DPoP) is a documented future enhancement, not implemented here.**
Rationale for deferral: it requires generating and rotating a JWK keypair,
constructing a signed client-assertion JWT, and a token-exchange round
trip before every sync — meaningfully more complexity than an API token
for the same read-only outcome, and no existing ConfigTrace connector
implements this pattern yet to copy from safely. If a future message needs
broader/finer-grained scopes than an API token's implicit admin-role scope
allows, OAuth service-app auth should be added as an additional
credential mode (mirroring Auth0's dual-mode `management_api_token` OR
`client_id`+`client_secret` pattern), not a replacement.

## Credential fields

| Field (schema) | Field (connector credentials dict) | Secret? |
|---|---|---|
| `okta_org_url` | `org_url` | No — user-supplied host, no credential material |
| `okta_api_token` | `api_token` | Yes — encrypted at rest, never returned/logged |

## Tenant identity strategy

`OktaConnector.compute_tenant_id(org_hostname, raw_org)`:
1. Prefers the Okta org's immutable `id` field (`GET /api/v1/org` →
   `id`) — format `id:<org_id>`.
2. Falls back to `host:<normalized_org_hostname>` only if the API did not
   return an `id` field.

Survives token rotation (identity never reads the token), display-name
changes (`companyName` is never part of the ID), and integration rename
(the user-supplied `display_name` is never part of the ID). Two distinct
tenants always produce distinct IDs (either different immutable org IDs,
or different hostnames in the fallback path). Known limitation: if a
tenant's `id` were ever unavailable (never observed in practice, but
defensively handled) AND that tenant later migrated to a different custom
domain, the hostname-fallback ID would change — documented, not silently
hidden.

## URL normalization / security

`normalize_org_url()` enforces, in order:
- HTTPS only (`http://` rejected).
- No embedded credentials (`user:pass@host` rejected).
- No query string, no fragment.
- No path component (org_url must be a bare host).
- Hostname required, ≤253 chars.
- Rejects `localhost`/loopback/private-IP/link-local (including the cloud
  metadata IP `169.254.169.254`) hostnames — SSRF guard, curated network
  list mirrors `app/services/notification_service.py`'s existing webhook
  SSRF guard.
- Custom Okta domains fully supported — no hardcoded `.okta.com` suffix
  requirement anywhere in the validator.
- Live DNS-rebinding resolution (the notification service's
  `_assert_hostname_resolves_public`) is intentionally NOT applied here —
  no other user-supplied-API-host connector in this codebase applies it
  either (Auth0 `domain`, GitLab `base_url`, Jira `site_url`), and
  `validate_credentials()` immediately makes a real HTTPS request to the
  host, which would surface a connection failure for a genuinely
  unreachable/bogus target through the normal failure-classification path.

## HTTP client behavior

- `httpx.Client(base_url=org_url, headers={"Authorization": "SSWS <token>", "Accept": "application/json"}, timeout=30s)`.
- Every request routes through `call_okta()`, which returns a
  `CallOutcome` (never raises internally) so callers choose whether to
  raise or degrade.
- The Authorization header value and raw `api_token` never appear in any
  `CallOutcome.detail`, exception message, or log line — only a fixed,
  category-specific message plus the HTTP status code.

## Pagination behavior

RFC5988 Link-header (`rel="next"`) pagination via `paginate()`:
- Bounded by `max_pages` (default 50).
- Only follows a `next` link whose resolved absolute URL's
  `scheme://netloc` exactly matches the trusted origin — any cross-origin
  `next` link is silently dropped (pagination just stops at the current
  page, never raises, never follows it).
- Repeated-next-URL detection (a misbehaving/malicious server serving the
  same page forever) stops pagination rather than looping.
- Deduplicates items by their `id` field when present, defending against
  an overlapping/re-served page.
- First-page failure raises (a fully broken credential should fail
  loudly); a later page's failure degrades to partial results (the first
  page already proved the credential works).

## 429 / rate-limit behavior

- Bounded exponential backoff with jitter (`call_okta()`), capped at
  `_MAX_THROTTLE_RETRIES` (4) attempts and `_THROTTLE_MAX_DELAY_SECONDS`
  (30s) per wait.
- Honors `Retry-After` (falls back to `X-Rate-Limit-Reset` if present).
- `_sleep_fn` is injectable — all tests inject a no-op / list-appending
  function, so no test ever really sleeps.
- 401 and 403 are NEVER retried as if transient — only 429 triggers a
  retry.

## Failure classification

`_classify_response()` / `_classify_transport_exception()` map every
outcome to one of: `auth_failed` (401), `permission_denied` (403),
`not_found` (404), `throttled` (429), `server_error` (5xx),
`connection_error` (DNS/refused), `tls_error` (SSL/TLS), `timeout`
(connect/read timeout), `malformed_response` (unparseable JSON / bad
transport error). These map to the existing `AuthenticationError` /
`ConnectorError` / `RateLimitError` / `NetworkError` hierarchy at the
`validate_credentials()`/`fetch()` boundary via `_raise_for_outcome()`.

## Capability probes

Seven single, minimal, read-only GET probes (never a broad enumeration —
`limit=1` where Okta accepts a limit param):

| Family | Endpoint | Notes |
|---|---|---|
| users | `GET /api/v1/users?limit=1` | |
| groups | `GET /api/v1/groups?limit=1` | |
| applications | `GET /api/v1/apps?limit=1` | |
| policies | `GET /api/v1/policies?type=OKTA_SIGN_ON&limit=1` | `type` required by the Policy API; narrowest single policy type probed |
| authenticators | `GET /api/v1/authenticators` | No `limit` param on this endpoint |
| admin_roles | `GET /api/v1/iam/roles?limit=1` | |
| system_log | `GET /api/v1/logs?limit=1` | Response body is never read — only the HTTP outcome is recorded; a tight `limit=1` with no historical time-range widening |

Each probe result maps to one of: `available`, `denied`, `unsupported`,
`unavailable`, `throttled`, `unknown` — never the raw response body, never
partial user/application/policy data.

## Foundation record taxonomy

| Record type | Fields | Notes |
|---|---|---|
| `okta_organization` | `tenant_id`, `org_hostname`, `org_display_name` (truncated ≤100 chars, optional), `status_category` | One record per connected org |
| `okta_api_capability` | `tenant_id`, `family`, `status` | One record per probed family (7 per org) |

## Sensitive-data boundary (permanent)

Never collected, stored, or logged by this connector at this or any future
stage: passwords, password hashes, recovery answers, MFA secrets, OTP
seeds, API tokens, session tokens, refresh tokens, access tokens, private
keys, raw authentication factors, raw System Log payloads, arbitrary user
profile data. At this stage specifically, the `/api/v1/org` response's
`phoneNumber`, `supportPhoneNumber`, `address1`/`address2`/`city`/`state`/
`country`/`postalCode`, `technicalContactName`/`technicalContactEmail`,
and `expiresAt` fields are read by Okta's API but deliberately never
extracted into the `okta_organization` record — verified in
`test_okta_foundation.py::TestSensitiveDataExclusion::test_raw_org_response_never_stored_verbatim`.

## Provider registration state

Registered internally: `sync_service._SUPPORTED_PROVIDERS`,
`schemas/integration.py` (`IntegrationCreateRequest.provider` Literal +
credential fields + validator branch), `routers/integrations.py`
(`_build_credentials` branch), `integration_service.py`
(`create_integration` dispatch + `_create_okta_integration`),
`workers/sync_task.py` (fetch dispatch), `diff_service.py` (tracked
fields), `risk_service.py` (classifier dispatch to
`risk_rules/okta.py`), `provider_capability_matrix_service.py`
(`PROVIDER_CAPABILITIES_PARTIAL`, maturity=`"partial"`), and
`frontend/src/lib/providers.ts` (`ProviderId` type + `PROVIDERS` map
entry, foundation-stage copy).

**NOT publicly connectable.** Excluded from
`frontend/src/lib/providers.ts`'s `PROVIDER_IDS` and
`CONNECTABLE_PROVIDER_IDS` (so no card renders on `/integrations`),
excluded from `provider_capability_matrix_service.PROVIDER_CAPABILITIES`
(the public/complete matrix list — Okta stays in the internal
`PROVIDER_CAPABILITIES_PARTIAL` staging list until a later message
promotes it), and excluded from `get_matrix()`'s reported provider set.
This matches the exact pattern the Kubernetes provider used in its own
message 1.

## Deferred to messages 2-8

- **Message 2**: users, groups, memberships, lifecycle posture.
- **Message 3**: applications, assignments, SSO configuration.
- **Message 4**: policies, MFA, authenticators, sign-on controls.
- **Message 5**: privileged/admin roles and identity-risk posture.
- **Message 6**: Security Findings (none exist yet — `security_rules=False`
  in the capability matrix).
- **Message 7**: exhaustive Change-classification QA, reliability/
  partial-sync hardening (mirroring the Kubernetes message 7-8 arc).
- **Message 8**: final provider-depth certification and public launch
  (moving Okta into `PROVIDER_IDS`/`CONNECTABLE_PROVIDER_IDS` and
  `PROVIDER_CAPABILITIES`).

## Case matrix (65 rows)

| # | Case | Area | Input/state | Expected behavior | Security concern | Test coverage | Status | Notes |
|---|---|---|---|---|---|---|---|---|
| 1 | Trailing slash stripped | URL | `https://example.okta.com/` | Normalized to no trailing slash | Consistent API URL construction | `TestNormalizeOrgUrl::test_strips_trailing_slash` | PASS | |
| 2 | Host lowercased | URL | `https://EXAMPLE.OKTA.COM` | Normalized to lowercase host | Consistent tenant-hostname identity | `test_lowercases_host` | PASS | |
| 3 | HTTP rejected | URL | `http://example.okta.com` | Raises `OktaURLError` | Credentials must never transit plaintext | `test_http_rejected` | PASS | |
| 4 | Embedded credentials rejected | URL | `https://user:pass@example.okta.com` | Raises `OktaURLError` | Prevents credential leakage via URL | `test_embedded_credentials_rejected` | PASS | |
| 5 | Query string rejected | URL | `https://example.okta.com?foo=bar` | Raises `OktaURLError` | org_url must be a bare host | `test_query_string_rejected` | PASS | |
| 6 | Fragment rejected | URL | `https://example.okta.com#frag` | Raises `OktaURLError` | org_url must be a bare host | `test_fragment_rejected` | PASS | |
| 7 | Path rejected | URL | `https://example.okta.com/api/v1` | Raises `OktaURLError` | org_url must be a bare host, not a deep link | `test_path_rejected` | PASS | |
| 8 | Custom domain accepted | URL | `https://sso.mycompany.example` | Normalizes successfully | No hardcoded tenant suffix | `test_custom_domain_accepted` | PASS | |
| 9 | Localhost rejected | URL | `https://localhost` | Raises `OktaURLError` | SSRF guard | `test_localhost_rejected` | PASS | |
| 10 | Loopback IP rejected | URL | `https://127.0.0.1` | Raises `OktaURLError` | SSRF guard | `test_loopback_ip_rejected` | PASS | |
| 11 | Private IP rejected | URL | `https://10.0.0.5` | Raises `OktaURLError` | SSRF guard | `test_private_ip_rejected` | PASS | |
| 12 | Cloud metadata IP rejected | URL | `https://169.254.169.254` | Raises `OktaURLError` | SSRF guard against cloud metadata service | `test_link_local_ip_rejected` | PASS | |
| 13 | Empty org_url rejected | URL | `""` | Raises `OktaURLError` | Fail closed on missing input | `test_empty_string_rejected` | PASS | |
| 14 | Non-string org_url rejected | URL | `None` | Raises `OktaURLError` | Type safety | `test_non_string_rejected` | PASS | |
| 15 | Port preserved | URL | `https://example.okta.com:8443` | Normalized with port intact | Correct API URL construction | `test_port_preserved` | PASS | |
| 16 | Malformed URL rejected | URL | `"not a url at all"` | Raises `OktaURLError` | Fail closed on garbage input | `test_malformed_url_rejected` | PASS | |
| 17 | No hostname rejected | URL | `"https://"` | Raises `OktaURLError` | Fail closed | `test_no_hostname_rejected` | PASS | |
| 18 | Valid token succeeds | Auth | 200 from `/api/v1/org` | `validate_credentials()` returns `True` | — | `TestAuthentication::test_valid_token_succeeds` | PASS | |
| 19 | 401 raises AuthenticationError | Auth | 401 from `/api/v1/org` | `AuthenticationError` raised | Credential rejection surfaced clearly | `test_401_raises_authentication_error` | PASS | |
| 20 | 403 raises ConnectorError, not AuthenticationError | Auth | 403 from `/api/v1/org` | `ConnectorError` raised | Distinguishes "token accepted, insufficient scope" from "token rejected" | `test_403_raises_connector_error_not_authentication_error` | PASS | |
| 21 | Malformed org_url fails before any request | Auth | invalid org_url | `OktaURLError` raised, zero HTTP calls | No network call with an unvalidated URL | `test_malformed_org_url_raises_before_any_request` | PASS | |
| 22 | Missing api_token rejected | Auth | credentials without `api_token` | `AuthenticationError` raised | Fail closed on missing credential | `test_missing_api_token_raises_authentication_error` | PASS | |
| 23 | Empty api_token rejected | Auth | `api_token=""` | `AuthenticationError` raised | Fail closed on empty credential | `test_empty_api_token_raises_authentication_error` | PASS | |
| 24 | SSWS scheme used | Auth | — | `Authorization: SSWS <token>` header | Correct Okta auth scheme | `test_authorization_header_uses_ssws_scheme` | PASS | |
| 25 | Token never in exception text | Auth | 401 response | Exception message excludes token | Credential never leaks via error message | `test_token_never_appears_in_exception_text` | PASS | |
| 26 | Token never logged | Auth | Successful validate | Token absent from captured logs | Credential never leaks via logs | `test_token_never_logged` | PASS | |
| 27 | Stable across token rotation | Identity | Same org, called twice | Same tenant ID both times | Identity independent of credential | `TestTenantIdentity::test_stable_across_token_rotation` | PASS | |
| 28 | Different tenants distinct | Identity | Two different orgs | Distinct tenant IDs | No cross-tenant collision | `test_different_tenants_are_distinct` | PASS | |
| 29 | Display-name change doesn't alter ID | Identity | Same org id, different companyName | Same tenant ID | Identity independent of mutable display name | `test_display_name_change_does_not_alter_id` | PASS | |
| 30 | Prefers org id over hostname | Identity | org with `id` present | ID prefixed `id:` | Immutable-ID-first strategy | `test_prefers_org_id_over_hostname` | PASS | |
| 31 | Falls back to hostname without id | Identity | org missing `id` | ID prefixed `host:` | Fallback strategy works | `test_falls_back_to_hostname_when_no_id` | PASS | |
| 32 | Non-string id falls back to hostname | Identity | `id: 12345` (int) | ID prefixed `host:` | Type safety on fallback | `test_falls_back_to_hostname_when_id_not_a_string` | PASS | |
| 33 | fetch() uses org id as tenant_id | Identity | Full fetch() call | `okta_organization.tenant_id == "id:<id>"` | End-to-end identity wiring | `test_fetch_uses_org_id_as_tenant_id` | PASS | |
| 34 | One page | Pagination | Single-page response, no Link header | All items returned | — | `TestPagination::test_one_page` | PASS | |
| 35 | Multiple pages via Link | Pagination | `rel="next"` Link header present | Items from both pages returned | Correct multi-page collection | `test_multiple_pages_via_link_header` | PASS | |
| 36 | Extract rel="next" | Pagination | Link header with `rel="next"` | Correct next URL parsed | — | `test_extract_next_link_parses_rel_next` | PASS | |
| 37 | Ignore rel="self" | Pagination | Link header with only `rel="self"` | `None` returned | Doesn't misinterpret non-next links | `test_extract_next_link_ignores_rel_self` | PASS | |
| 38 | No Link header | Pagination | No `Link` header | `None` returned | Graceful termination | `test_extract_next_link_absent` | PASS | |
| 39 | Cross-origin next rejected | Pagination | `next` points to `evil.example.com` | `None` returned (link dropped) | Prevents pagination-driven SSRF/exfiltration | `test_cross_origin_next_link_rejected` | PASS | |
| 40 | Cross-origin next stops pagination without raising | Pagination | Same as above, via `paginate()` | Pagination stops cleanly, partial results kept | Fail-safe, not fail-loud, for this case | `test_cross_origin_next_stops_pagination_without_raising` | PASS | |
| 41 | Page cap bounds iteration | Pagination | Server always links to itself | Iteration stops at `max_pages` | Prevents unbounded loop | `test_page_cap_bounds_iteration` | PASS | |
| 42 | Repeated next link detected | Pagination | Server always returns same `next` URL | Pagination stops early | Prevents infinite loop from misbehaving/malicious server | `test_repeated_next_link_detected_and_stopped` | PASS | |
| 43 | Malformed Link header ignored | Pagination | Garbage `Link` header value | `None` returned, no crash | Fail closed on malformed input | `test_malformed_link_header_ignored` | PASS | |
| 44 | Dedup by id | Pagination | Overlapping pages re-serve an id | Duplicate excluded from results | Data integrity across pagination | `test_dedupes_records_by_id` | PASS | |
| 45 | 429 then success | Rate limit | First call 429, second 200 | Succeeds after one retry | Correct bounded-retry behavior | `TestRateLimit::test_429_then_success` | PASS | |
| 46 | Exhausted retries | Rate limit | Always 429 | `CallOutcome.category == "throttled"` | Bounded, never infinite | `test_exhausted_retries_raises_rate_limit_error` | PASS | |
| 47 | Sleep is mocked, never real | Rate limit | 429 then 200 | Injected sleep fn called, test completes instantly | Test suite never actually sleeps | `test_sleep_is_mocked_never_real` | PASS | |
| 48 | 401 never retried | Rate limit | 401 response | Exactly 1 HTTP call made | 401 is not transient — must not retry | `test_401_never_retried` | PASS | |
| 49 | 403 never retried | Rate limit | 403 response | Exactly 1 HTTP call made | 403 is not transient — must not retry | `test_403_never_retried` | PASS | |
| 50 | All probes available | Capability | All 7 endpoints return 200 | 7 `okta_api_capability` records, all `available` | — | `TestCapabilityProbes::test_all_available` | PASS | |
| 51 | Denied family | Capability | `/users` returns 403 | `users` probe status = `denied` | Correct 403→denied mapping | `test_denied_family` | PASS | |
| 52 | Unsupported family | Capability | `/iam/roles` returns 404 | `admin_roles` probe status = `unsupported` | Correct 404→unsupported mapping | `test_unsupported_family` | PASS | |
| 53 | Mixed outcomes | Capability | Each family returns a different status code/error | Each family maps to its own correct status | Independent per-family classification | `test_mixed_outcomes` | PASS | |
| 54 | Capability probe failure never aborts fetch | Capability | All 7 probes return 500 | `fetch()` still returns the org record | One family's failure doesn't block the others | `test_capability_probe_failure_never_raises` | PASS | |
| 55 | Probes never fetch more than one page | Capability | — | Every probe with a `limit` param sets `limit=1` | Never a broad enumeration | `test_probes_never_fetch_more_than_one_page` | PASS | |
| 56 | Probes cover all 7 families | Capability | — | `users, groups, applications, policies, authenticators, admin_roles, system_log` | Complete future-family coverage | `test_probes_cover_all_seven_families` | PASS | |
| 57 | 401 classification | Failure | 401 response | `category == "auth_failed"` | — | `TestFailureClassification::test_401` | PASS | |
| 58 | 403 classification | Failure | 403 response | `category == "permission_denied"` | — | `test_403` | PASS | |
| 59 | 404 classification | Failure | 404 response | `category == "not_found"` | — | `test_404` | PASS | |
| 60 | 429 classification | Failure | 429 response | `category == "throttled"` | — | `test_429` | PASS | |
| 61 | 5xx classification | Failure | 503 response | `category == "server_error"` | — | `test_5xx` | PASS | |
| 62 | Timeout classification | Failure | `httpx.ConnectTimeout` | `category == "timeout"` | — | `test_timeout` | PASS | |
| 63 | TLS error classification | Failure | `ssl.SSLError` | `category == "tls_error"` | — | `test_tls_error` | PASS | |
| 64 | DNS failure classification | Failure | `httpx.ConnectError` (DNS phrasing) | `category == "connection_error"` | — | `test_dns_failure_classified_as_connection_error` | PASS | |
| 65 | Malformed JSON raises ConnectorError | Failure | 200 with invalid JSON body | `ConnectorError` raised from `fetch()` | Fail closed on unparseable response | `test_malformed_json_raises_connector_error_on_fetch` | PASS | |
| 66 | Org response not a dict | Failure | 200 with a JSON array body | `ConnectorError` raised | Fail closed on unexpected shape | `test_org_response_not_a_dict_raises_connector_error` | PASS | |
| 67 | Real compute_diff detects status change | Diff | prev `status_category=active`, new `=suspended` | A Change with `field_path="status_category"` produced | Real diff pipeline, not a mock | `TestDiffAndProviderMetadata::test_real_compute_diff_detects_org_status_change` | PASS | |
| 68 | Foundation record modification produces Change | Diff | `okta_api_capability.status` changes | Exactly one Change produced | Correct field-level diff granularity | `test_foundation_record_modification_produces_change` | PASS | |
| 69 | Transient fields absent from tracked fields | Diff | — | `request_id`/`fetched_at`/etc. never in tracked-field tuples | No spurious Changes from non-durable fields | `test_transient_fields_absent_from_tracked_fields` | PASS | |
| 70 | Unmapped okta subtype returns empty tuple | Diff | Unknown future `okta_*` type | `_tracked_fields_for()` returns `()` | Never falls through to an unrelated provider's fields | `test_unmapped_okta_subtype_returns_empty_tuple` | PASS | |
| 71 | Token absent from records | Sensitive data | Full fetch() | Token string not in `str(records)` | Credential never leaks into snapshot data | `TestSensitiveDataExclusion::test_token_absent_from_records` | PASS | |
| 72 | Token absent from errors | Sensitive data | 401 during fetch() | Token string not in exception text | Credential never leaks via errors | `test_token_absent_from_errors` | PASS | |
| 73 | Raw org response never stored verbatim | Sensitive data | Org response with phone/address/contact/expiry fields | None of those values appear in output records | PII/contact data never persisted | `test_raw_org_response_never_stored_verbatim` | PASS | |
| 74 | Organization record has no forbidden keys | Sensitive data | Normalized org record | No `password`/`token`/`secret`/`phoneNumber`/etc. keys present | Structural guarantee, not just value-absence | `test_okta_organization_record_has_no_forbidden_keys` | PASS | |
| 75 | Capability record has exactly the expected keys | Sensitive data | Normalized capability record | Key set is exactly `{record_type, record_id, provider_resource_id, tenant_id, family, status}` | No accidental response-body leakage into the record | `test_capability_probe_record_never_includes_response_body` | PASS | |

**Matrix rows: 75** (exceeds the required minimum of 45).

## Test results

```
cd backend
DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests/test_okta_foundation.py tests/test_okta_connector_contract.py -q
# 101 passed

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests -q -k "okta and foundation"
# 75 passed, 18660 deselected

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests -q -k "okta and pagination"
# 11 passed, 18724 deselected

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests -q -k "okta and credential"
# 6 passed, 18729 deselected

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests -q -k "okta and capability"
# 14 passed, 18721 deselected

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests -q -k "okta"
# 101 passed, 18634 deselected — no zero-selection filters, no regressions
```

## Notes on pre-existing, unrelated findings

While reading `integration_service.py` and adjacent files to find the
correct dispatch pattern, three pre-existing issues (none caused by this
message, none touched by this message) were found and flagged separately
for follow-up rather than fixed here, to keep this message's diff scoped
to Okta foundation only:
- `integration_service.create_integration()` has no dispatch branch for
  `shopify`, `gitlab`, or `terraform_cloud` — those providers currently
  cannot actually be created via `POST /integrations` despite having
  credential schemas and connectors.
- Clerk's capability-matrix entry uses `category="identity"`, which is
  not a member of the matrix's own `CATEGORIES` validation set (Okta uses
  `"auth"` instead to avoid the same bug).
- `test_milestone82_pre_1_provider_credential_connect_parity.py`'s
  `test_schema_provider_literal_includes_all_thirteen` has a stale
  hardcoded provider list that predates several already-shipped providers
  (kubernetes, gitlab, jira, linear, pagerduty, terraform_cloud) — it was
  already failing before this message's Okta changes.
