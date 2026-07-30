# Snowflake Reliability Certification (Snowflake Message 7 of 8)

Exhaustive Change-classification QA, partial-sync safety, retry/polling
reliability, scale hardening, secret-redaction certification, and backend
production-readiness validation for the Snowflake connector. This message
performs no new collection, no new Findings, and no launch/registration
work — those belong to messages 6 (done) and 8 (not started).

## 1. Record-type inventory

Derived directly from `app/connectors/snowflake_schema.py` constant
definitions (not assumed from any suggested list). **21 record types**:

| # | Record type | Source | Tracked in `diff_service.py` | Classified in `risk_rules/snowflake.py` | Finding-source |
|---|---|---|---|---|---|
| 1 | `snowflake_account` | collected (identity) | yes | yes | no (root/family-completeness anchor only) |
| 2 | `snowflake_api_capability` | derived (probe) | yes | yes | no |
| 3 | `snowflake_user` | collected | yes | yes | yes |
| 4 | `snowflake_account_role` | collected | yes | yes | yes |
| 5 | `snowflake_database_role` | collected | yes | yes | yes |
| 6 | `snowflake_user_role_grant` | collected | yes | yes | no (evidence only) |
| 7 | `snowflake_role_hierarchy_grant` | collected | yes | yes | no (evidence only) |
| 8 | `snowflake_database` | collected | yes | yes | yes |
| 9 | `snowflake_schema` | collected | yes | yes | yes |
| 10 | `snowflake_warehouse` | collected | yes | yes | yes |
| 11 | `snowflake_share` | collected | yes | yes | yes |
| 12 | `snowflake_object_grant` | collected | yes | yes | yes (future-grant subset) |
| 13 | `snowflake_network_policy` | collected | yes | yes | yes |
| 14 | `snowflake_network_rule` | collected | yes | yes | no (context only) |
| 15 | `snowflake_authentication_policy` | collected | yes | yes | yes |
| 16 | `snowflake_security_integration` | collected + SCIM enrichment | yes | yes | yes |
| 17 | `snowflake_storage_integration` | collected | yes | yes | yes |
| 18 | `snowflake_external_access_integration` | collected | yes | yes | yes |
| 19 | `snowflake_privileged_user` | derived (message 5) | yes | yes | yes |
| 20 | `snowflake_privileged_role` | derived (message 5) | yes | yes | yes |
| 21 | `snowflake_public_exposure` | derived (message 5) | yes | yes | yes |

21/21 tracked, 21/21 classified. No record type was found untracked or
unclassified — the inventory suggested in the task text (~18-21) is
confirmed accurate at the upper bound, not blindly trusted.

## 2. SQL API reliability

Verified against current official Snowflake SQL API documentation
(WebFetch) before any transport change:

- **Status semantics**: 200 (sync success), 202 (async, poll via
  `GET .../statements/{handle}`), 408 (execution timeout, statement
  already cancelled server-side — **was previously unhandled and fell
  into the generic 5xx-retryable bucket; fixed this message** with an
  explicit `CATEGORY_TIMEOUT` branch in `_classify_response`), 422
  (execution failed), 401/403 (auth/permission, never retried), 429
  (throttled, bounded exponential backoff + jitter honoring
  `Retry-After`), 5xx (bounded retry).
- **Bounded retry budgets**: throttle capped at `_MAX_THROTTLE_RETRIES=4`
  (5 total attempts), server error capped at `_MAX_SERVER_ERROR_RETRIES=2`
  (3 total attempts) — certified via
  `TestNoInfiniteLoops::test_throttle_retry_bounded_at_four_attempts` and
  `::test_server_error_retry_bounded_at_two_attempts` with injected
  (never real) sleep.
- **Bounded polling**: `_MAX_POLL_ATTEMPTS=5`, `_POLL_INTERVAL_SECONDS=1.0`
  — certified via
  `TestAsyncPollingSequences::test_202_polling_exhaustion_is_bounded_timeout`.
- **Documented gaps** (present since message 1, re-verified this message
  against current docs, not implemented and not required for this
  connector's metadata-only query shape): result-set pagination via
  `partitionInfo`/`Link` headers is never consumed (every query here
  returns a small metadata result set); the dedicated
  `POST .../statements/{handle}/cancel` endpoint is never called (no
  code path holds a statement open across a cancellable timeout).
  Certified never-invoked via
  `TestDocumentedGaps::test_no_partition_query_parameter_is_ever_sent`
  and `::test_no_cancel_endpoint_is_ever_called`.
- **PAT lifecycle** (confirmed via current docs): service-user PATs
  require explicit `ROLE_RESTRICTION`; secondary roles are never
  consulted; PAT rotation preserves user/role identity; auth failures
  (401) have no documented retry guidance, matching this connector's
  existing never-retry-401 behavior.

## 3. Completeness / false-removal suppression

No false-removal suppression existed for Snowflake before this message
(confirmed via `grep -n "family_completeness" app/services/diff_service.py`
returning zero Snowflake matches, contrasted with the existing Kubernetes/
Okta/Entra sections). This was the single largest gap closed this
message.

Implemented `_snowflake_removal_suppressed()` in `diff_service.py`,
wired into the existing suppression `or`-chain, consulting:

- **Account-wide families** (via `snowflake_account.family_completeness`):
  users, account_roles, database_roles, warehouses, shares,
  network_policies, and (as a coarse fallback) object_grants.
- **Per-database completeness** (new fields on `snowflake_database`):
  `schema_collection_status`, `database_role_collection_status`,
  `future_grant_collection_status` — populated in `fetch()` from new
  per-database status dicts, zero additional SQL calls.
- **Per-role completeness** (new fields on `snowflake_account_role` /
  `snowflake_database_role`): `role_hierarchy_collection_status`,
  `object_grant_collection_status`.
- **Derived-record dependencies**: `snowflake_privileged_user` /
  `snowflake_privileged_role` / `snowflake_public_exposure` removals are
  suppressed if any of their upstream input families were incomplete.

**Documented limitation**: `snowflake_object_grant` records for
`grantee_type == "database_role"` carry only the bare role name (no
database qualifier), so precise per-role suppression is impossible for
that specific combination — it falls back to the coarser account-wide
`object_grants` family status. This is safe (a real sync always marks
the family partial whenever any one role's grant query fails) but less
precise than the account-role case. Documented in both
`diff_service.py` and `test_snowflake_partial_sync.py`.

Recovery-after-partial-sync and first-sync semantics certified via
`TestFirstSyncAndRecovery` (no prior state produces only additions;
recovery diffs against the last complete state; a partial sync in
isolation produces no false removal).

## 4. Scale

Connector-level (full `fetch()`) scale certified via
`test_snowflake_scale_reliability.py`: 5,000 users, 1,000 account roles
with per-role grant-walk call verification, 2,000 databases with
per-database completeness verification. Complements the larger
per-family unit-level scale tests already in place from messages 2/3/5
(25,000 users, 5,000 account roles, 2,000 database roles, 20,000
grant/hierarchy rows, 1,000 databases, 10,000 schemas, 2,000 warehouses,
2,000 shares, 100,000 object grants).

**N+1 audit** (intentional, measured, not hidden): per-role grants (one
`SHOW GRANTS` call per account role + per database role), per-database
schemas (one `SHOW SCHEMAS IN DATABASE` call per database), per-database
database-roles (one `SHOW DATABASE ROLES IN DATABASE` call per
database), per-policy/integration `DESCRIBE` calls (one per network
policy, authentication policy, and integration). No *avoidable*
duplicate passes were found — `TestNoDuplicateQueries` certifies
`SHOW DATABASES` issued exactly once per fetch and no duplicate
`SHOW GRANTS` call for the same role within one fetch.

**Call-count formula** (certified via
`test_call_count_formula_matches_expectation`):
`1 (identity) + 13 (capability probes) + 1 (users) + 1 (account roles) +
1 (databases) + 1 (warehouses) + 1 (shares) + 6 (message-4 SHOWs) +
n_roles * 2 (grants + hierarchy per role)`.

**Determinism / idempotency**: reordering raw SHOW-result rows before
`_fetch()` produces an identical sorted `record_id` set
(`test_reordered_rows_produce_identical_records`); two independent
`_fetch()` calls against identical source data, diffed through the real
`compute_diff()`, yield zero Changes
(`test_two_identical_fetches_produce_zero_diff`); record ordering and
derived-record fingerprints are stable across runs
(`test_records_sorted_deterministically`,
`test_fingerprint_stable_across_runs`).

## 5. Safety

- **Read-only discipline**: enforced by construction — every statement
  issued by this connector is a fixed module-level string constant (see
  `_ACCOUNT_IDENTITY_STATEMENT`, `_CAPABILITY_PROBES`, and the
  collection-method statement constants); none is built from
  interpolated or user-controlled SQL. Grepped for
  `CREATE|ALTER|DROP|GRANT |REVOKE|INSERT|UPDATE|DELETE|MERGE|COPY INTO|
  PUT |GET |CALL |TRUNCATE|USE ROLE|USE WAREHOUSE` as executable
  statements in `app/connectors/snowflake.py` and
  `app/connectors/snowflake_schema.py` — zero matches (the only hits are
  privilege-name string labels categorizing observed `SHOW GRANTS`
  output, e.g. `"INSERT": PRIVILEGE_CATEGORY_DATA_WRITE`, not executed
  SQL). No `USE ROLE` / `USE WAREHOUSE` exists anywhere — role/session
  context is established via SQL API request parameters, not session
  statements.
- **Query logging**: only two `logger.warning` call sites in the
  connector, both emitting attempt counters and computed delay seconds
  — never SQL text, PAT, or `Authorization` header values.
- **Error sanitization**: `_classify_response` / `_classify_transport_exception`
  return category + a fixed human-readable detail string, never echoing
  request bodies or headers back into the detail. Certified via
  `TestHttp408Timeout::test_408_never_leaks_credential_material` and the
  existing message-1 sanitization tests.
- **Secret persistence**: grepped for
  `programmatic_access_token|Authorization: Bearer|session_token`
  literal-value patterns across every file touched this message
  (connector, diff_service, risk_rules, security_rules, all five new
  test files) — zero matches for real-looking secret values (test files
  use clearly-fake placeholder tokens only, e.g.
  `"fake-snowflake-pat-value"`).
- **PUBLIC wording discipline**: grepped for
  `internet-expos|publicly-access|anonymous-access` — the only matches
  are in code comments *explaining the prohibition* ("never 'internet
  exposure'"), never a violation of it.

## 6. Certification

| Gate | Result |
|---|---|
| Record-type inventory (21/21 tracked + classified) | PASS |
| SQL API status/retry/polling semantics match current docs | PASS |
| False-removal suppression (account, per-database, per-role, derived) | PASS |
| Recovery / first-sync semantics | PASS |
| Scale (connector-level + per-family) | PASS |
| Determinism / idempotency | PASS |
| N+1 measured, no avoidable duplication | PASS |
| Read-only statement discipline (no mutation keywords, no USE) | PASS |
| Query logging / error sanitization / secret persistence | PASS |
| PUBLIC wording discipline | PASS |
| Full Snowflake suite (904 tests) | PASS |
| Cross-provider regression (Entra, Okta, Kubernetes, shared diff paths) | PASS |

**CERTIFICATION: PASS.**

Three real Change-classification bugs were found and fixed during this
message (not pre-existing defects carried forward silently):

1. `user_type` transition to `legacy_service` had no classifier branch
   (fell to generic low), violating parity with the message-6
   `snowflake_legacy_service_user*` Findings.
2. `future_public_read_count` Change severity was `medium`, weaker than
   the `snowflake_public_future_data_access` Finding's `high`.
3. `scim_run_as_role_tier` / `scim_run_as_role_has_manage_grants` (new
   message-6 SCIM fields) had zero classifier branches, violating parity
   with the SCIM run-as Findings.

All three are fixed in `app/services/risk_rules/snowflake.py`. No new
Security Finding rules were added this message — 31/31 from message 6
remain registered with full registry/pack/coverage parity.
