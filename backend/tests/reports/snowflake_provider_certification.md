# Snowflake Provider Certification (Snowflake Message 8 of 8 — Public Launch)

Final launch certification for the Snowflake provider — the last of the
8 planned Snowflake implementation milestones. Moves Snowflake from
internal/planned/non-connectable/non-Live to publicly visible,
connectable, credential-validated, partial-coverage-aware, production-
certified, Live.

## 1. Identity

| Field | Value |
|---|---|
| Canonical provider ID | `snowflake` |
| Display name | Snowflake |
| Category | `database_backend` (backend), `backend` (frontend `ProviderCategory`) — each surface uses its own pre-existing category taxonomy consistently; no invented `data` category |
| Public/Live status | Live — connectable, in `PROVIDER_IDS` and `CONNECTABLE_PROVIDER_IDS` (frontend), `PROVIDER_CAPABILITIES` not `PROVIDER_CAPABILITIES_PARTIAL` (backend) |
| Stable account identity | `compute_account_id(organization_name, account_name)` → `id:<org>-<account>`, derived from Snowflake's own immutable `CURRENT_ORGANIZATION_NAME()`/`CURRENT_ACCOUNT_NAME()`, never from the user-supplied `account_identifier` credential |

## 2. Authentication

- **Model**: Snowflake Programmatic Access Token (PAT) + Snowflake SQL API v2, with an explicit account identifier, username, and monitoring role. No username/password, browser SSO, external-browser auth, SnowSQL/CLI, key-pair, or OAuth authentication is advertised or implemented.
- **PAT lifecycle** (confirmed via current docs.snowflake.com, accessed 2026-07-30):
  - [Using programmatic access tokens for authentication](https://docs.snowflake.com/en/user-guide/programmatic-access-tokens) — default expiry 15 days (configurable 1-365 days via authentication policy, immutable after creation); rotation (`ALTER USER ... ROTATE PROGRAMMATIC ACCESS TOKEN`) issues a new secret under the same name and expires the old one; revocation is irreversible; `ROLE_RESTRICTION` is required by default for SERVICE/SERVICE_AGENT/LEGACY_SERVICE users, optional by default for PERSON; **secondary roles are never consulted for a PAT session, even if `DEFAULT_SECONDARY_ROLES=('ALL')`** — confirms this connector's single-role-per-request model is correct; max 15 tokens per user.
  - No PAT edition/licensing gate (e.g., Business Critical) was found in current docs — flagged as an absence-of-evidence finding, not a hard guarantee.
- **SQL API v2 authentication** (confirmed): PAT presented as `Authorization: Bearer <token>` with optional `X-Snowflake-Authorization-Type: PROGRAMMATIC_ACCESS_TOKEN` — matches this connector's `_make_client()` headers exactly. `role` is a request-body parameter on every `POST /api/v2/statements` call (never a separate `USE ROLE` statement) — matches this connector's `call_sql_api(..., role=role)` pattern exactly. The requested role must fall within the PAT's `ROLE_RESTRICTION`.
- **Account identifier**: current preferred format is `<orgname>-<account_name>` (hostname `https://<orgname>-<account_name>.snowflakecomputing.com`); legacy account-locator form is still supported. This connector's `validate_account_identifier()` accepts both forms via a conservative character allowlist, never a raw URL.
- **Warehouse requirement**: current official SQL API reference documents `warehouse` as an optional request-body field defaulting to `DEFAULT_WAREHOUSE`. A dedicated statement confirming SHOW/DESCRIBE metadata commands run with zero assigned warehouse was not retrievable this pass (flagged honestly, not guessed) — this connector has run message-1-through-7 tests exclusively via SHOW/DESCRIBE/ACCOUNT_USAGE `SELECT` statements with no warehouse parameter ever set, consistent with the documented optionality. Stated conservatively: **no active warehouse is required for the current ConfigTrace Snowflake connector's own request shape**, based on the connector never setting one and every test passing without one.
- **Deployment support**: current docs confirm commercial deployments across AWS, Azure, and GCP, spanning Americas/EMEA/APAC regions; government regions (GovCloud/SnowGov) are isolated and out of scope for this launch.

## 3. Credential fields

`snowflake_account_identifier` / `snowflake_username` / `snowflake_programmatic_access_token` / `snowflake_role` — exact existing schema field names (unchanged from message 1). Frontend labels: "Snowflake account identifier", "Snowflake username", "Programmatic Access Token" (password input, masked, never redisplayed), "Snowflake monitoring role" (helper text explicitly discourages ACCOUNTADMIN/SECURITYADMIN).

## 4. Service-user / least-privilege guidance

Setup guide (form + trustNote) recommends: dedicated Snowflake service user → dedicated read-only monitoring role → role-restricted PAT. Never recommends ACCOUNTADMIN/SECURITYADMIN/MANAGE GRANTS for routine monitoring. Core vs Extended coverage split (see `snowflake_access_requirement_matrix.md`) is derived from the actual 13 capability-probe families, not invented.

## 5. Credential validation

`SnowflakeConnector.probe_coverage()` (new this message) runs exactly two bounded things: the account-identity query (message 1) and the 13 capability probes (message 1's `_CAPABILITY_PROBES`) — never a full account inventory. Computes `COVERAGE_FULL` / `COVERAGE_PARTIAL` / `COVERAGE_INVALID` via `compute_coverage_state()` (new `snowflake_schema.py` helper): Invalid only when zero of the 7 Core families are readable; Full when all 13 families are readable; Partial otherwise. Returns sanitized grouped diagnostics via `format_capability_diagnostics()` — 8 human-readable groups, never a raw SQL statement or low-level status code.

`_create_snowflake_integration()` calls `probe_coverage()` synchronously before any DB write; `COVERAGE_INVALID` raises `ConnectorError` and the router returns 400 — no seemingly-healthy integration is ever created from rejected/insufficient credentials. `reconnect_credentials_snowflake()` follows the identical pattern.

## 6. Full / Partial / Invalid semantics

- **Full**: all 13 capability families available.
- **Partial**: at least one Core family available but something (Core or Extended) is not — e.g. users/roles/databases/schemas/warehouses/shares available while authentication policies and security integrations are denied. Accepted; useful monitoring results.
- **Invalid**: zero of the 7 Core families (`users`, `roles`, `role_grants`, `databases`, `schemas`, `warehouses`, `shares`) are readable, OR the account-identity query itself fails (malformed credentials, rejected/expired/revoked PAT, unreachable account, role-restriction mismatch). Rejected at creation/reconnect with a sanitized message.

Certified via `test_snowflake_integration_creation.py` (`TestValidConnection`, `TestPartialConnection`, `TestInvalidConnection`, `TestOptionalFamilyDeniedNotInvalid`) and `test_snowflake_provider_depth_qa.py` §F.

## 7. Capability diagnostics

Grouped into 8 safe labels (`Identity and roles`, `Data objects and grants`, `Warehouses and shares`, `Network policies`, `Authentication policies`, `Security integrations`, `Storage integrations`, `External access integrations`), each `Available` / `Permission denied` / `Unavailable` — never the 13 individual low-level probe statements.

## 8. Reconnect behavior

`reconnect_credentials_snowflake()` (new this message, mirrors `reconnect_credentials_okta`):
- Same account + new PAT → accepted (after `probe_coverage()` re-validation).
- Same account + new username → accepted (new service user for the same account).
- Same account + new role → accepted after validation; coverage diagnostics are recomputed against the new role's actual visibility.
- Same account via an alias identifier string → accepted (comparison uses the STABLE `account_id` derived from Snowflake's own org/account pair, never the raw `account_identifier` credential string, so legacy-locator vs orgname-accountname aliases never falsely mismatch).
- Different account (`existing_account_id != new_account_id`) → rejected with `ConnectorError`, directing the user to create a new integration.
- Invalid/expired/revoked PAT, role-restriction mismatch → rejected via the same `probe_coverage()` → `COVERAGE_INVALID` path, sanitized error, no credential material echoed.
- Partial permissions → accepted; diagnostics updated in `resource_metadata`.
- Old PAT is fully overwritten (never retained alongside the new one) — a fresh `SnowflakeConnector()`/`httpx.Client` is built from only the new credentials each time, so no prior session/account/role state leaks forward.

Certified via `test_snowflake_integration_creation.py::TestReconnect` (11 cases) and `test_snowflake_provider_depth_qa.py::TestCredentialRoundTrip`.

## 9. Account mismatch / alias / rotation protection

Because `SnowflakeConnector.compute_account_id()` derives identity purely from Snowflake's own immutable `(organization_name, account_name)` pair — never the raw `account_identifier` string — a reconnect with a differently-spelled but equivalent identifier (e.g. a legacy locator vs. the orgname-accountname form, if both happen to resolve to the same underlying account) is compared on the STABLE derived value, never the raw string, so it is never falsely rejected. A genuinely different underlying account always produces a different `account_id` and is always rejected. Unlike Okta/Entra (which only recorded a real tenant identity after the first sync), Snowflake's `probe_coverage()` establishes the real `account_id` synchronously at creation time — so there is no "pre-first-sync placeholder" ambiguity window for Snowflake reconnects.

## 10. Initial baseline / partial baseline

First-sync behavior (message 7's false-removal suppression architecture, re-verified unaffected this message): a first sync with no prior state produces only additions, never fabricated removals (`TestFirstSyncAndRecovery` in `test_snowflake_partial_sync.py`). A partial first sync (e.g. authentication policies and security integrations denied while users/roles/grants/databases succeed) is accepted as Partial; readable families baseline normally, unavailable families are marked incomplete via `family_completeness`/per-database/per-role completeness fields, and later permission expansion or reduction never produces false removals or mass deletions (message 7 certification, re-confirmed unaffected by this message's changes — no fetch()/collection code was modified).

## 11. Frontend

- **Provider card**: `/integrations` — status Live, concise copy covering users/roles/grants/data-access/authentication-policy/network-policy/integrations/effective-privilege; explicitly does not advertise query/activity monitoring, table-content scanning, data classification, runtime anomaly detection, login-history, or query-history ingestion.
- **Setup form**: `SnowflakeIntegrationForm.tsx` (new) — 4 fields (account identifier, username, PAT, role), PAT masked (`type="password"`), never redisplayed after success, no localStorage, no token in URL, setup guidance (5-step service-user/role/PAT flow), least-privilege warning against ACCOUNTADMIN/SECURITYADMIN, Partial-coverage explanation.
- **Integration detail**: safe context only (organization/account name, stable account identifier, monitoring username/role, last sync, sync status, Full/Partial coverage, monitored record/Finding/Change counts, grouped diagnostics) — never PAT, Authorization header, raw SQL, statement handles, or raw error bodies (unchanged architecture — the generic integration-detail surface already enforces this for every provider).
- **PUBLIC wording guard**: re-verified via `test_snowflake_provider_depth_qa.py::TestFrontendLaunchState::test_snowflake_card_copy_never_claims_internet_exposure_wording` and the existing message-6/7 test suites — "available to Snowflake users through the PUBLIC role," never "internet exposed"/"publicly accessible"/"anonymous access."

## 12. Record count / Finding count

- **21 record types** (unchanged since message 7): `snowflake_account`, `snowflake_api_capability`, `snowflake_user`, `snowflake_account_role`, `snowflake_database_role`, `snowflake_user_role_grant`, `snowflake_role_hierarchy_grant`, `snowflake_database`, `snowflake_schema`, `snowflake_warehouse`, `snowflake_share`, `snowflake_object_grant`, `snowflake_network_policy`, `snowflake_network_rule`, `snowflake_authentication_policy`, `snowflake_security_integration`, `snowflake_storage_integration`, `snowflake_external_access_integration`, `snowflake_privileged_user`, `snowflake_privileged_role`, `snowflake_public_exposure` — all 21 tracked in `diff_service.py`, all 21 classified in `risk_rules/snowflake.py` (re-verified this message via `test_snowflake_provider_depth_qa.py::TestRecordTypeInventory`).
- **31 Security Findings** (unchanged since message 6): Critical 5, High 13, Medium 13, Low 0 — full registry/evaluator/confidence/pack/coverage/frontend-catalog parity re-verified this message (`TestSecurityFindingParity`, 4 cases).

## 13. Reliability re-certification

No connector fetch()/collection/diff/classifier code was modified this message — message 7's reliability certification (904 tests, 227-row matrix, false-removal suppression, SQL API retry/polling hardening, scale certification) remains valid unchanged. This message only adds: `probe_coverage()` (a thin wrapper reusing the exact same `_ACCOUNT_IDENTITY_STATEMENT` + `_probe_capabilities()` primitives already certified), the `compute_coverage_state()`/`format_capability_diagnostics()` pure functions, and the creation/reconnect service-layer wiring.

## 14. Sensitive-data / CLI-independence / dependency audit

- **PAT/secret never persisted** outside encrypted credential storage: never in normalized snapshot, provider metadata, Finding, Change, diagnostic output, frontend response, logs, or reports — re-verified via `test_snowflake_provider_depth_qa.py` §D and `test_snowflake_integration_creation.py::TestSensitiveCredentialsNeverLeak` (3 cases: create response, get response, encrypted-column-is-not-plaintext).
- **No mutating SQL statement is ever constructed as an executable statement** — verified by parsing every fixed `"SELECT..."`/`"SHOW..."`/`"DESCRIBE..."` statement string in `snowflake.py` and asserting none contain a mutation keyword (`test_no_mutating_sql_statements_in_connector`). The handful of raw keyword matches found in `snowflake_schema.py` are privilege-name string labels parsed from observed `SHOW GRANTS` output (e.g. `"INSERT": PRIVILEGE_CATEGORY_DATA_WRITE`), never executed SQL — documented, not hidden.
- **No `USE ROLE`/`USE WAREHOUSE`** anywhere in the connector — role/session context is established via SQL API request parameters only, matching current docs.
- **No CLI/subprocess dependency**: no `subprocess`, `os.system`, `Popen`, `shell=True` anywhere in the connector.
- **Production dependencies unchanged**: `httpx` only — no Snowflake Python Connector, no Snowpark, no ODBC/JDBC driver, no SnowSQL/CLI, no new OS package, no new global env var. Credentials belong exclusively to encrypted integration storage.

## 15. Database / deployment audit

Integration credential/resource storage (`encrypted_credentials`, `credential_iv`, `resource_metadata` JSON column) is the same generic, already-migrated schema every other provider uses — no new column, no new enum, no `CHECK` constraint, and no migration was required for this message's `resource_metadata` additions (`account_id`, `session_role`, `coverage`, `diagnostics` are just new JSON keys within the existing free-form column).

## 16. Known limitations (explicit, launch-critical to state)

No table/view row (query-result) ingestion, no query-history ingestion, no login-history ingestion, no runtime session monitoring, no anomaly detection, no sensitive-data discovery/classification, no current (non-future) PUBLIC object-grant Finding (current grants to PUBLIC are not collected — only future grants), no direct-to-user object-privilege modeling, no OAuth allowed-role Finding (that metadata is not collected), no broad storage/external-access destination Finding (target scope is not deterministically modeled from `SHOW`/`DESCRIBE` alone), no SQL API cancellation-endpoint usage (unimplemented, documented gap since message 7), no SQL API result-partition pagination (unimplemented, documented gap — every query here returns a small metadata result set so this has never mattered), `SHOW`/`DESCRIBE` visibility is constrained by whatever the monitoring role can see, some integration/policy details may remain Partial indefinitely for an intentionally minimal monitoring role, and the mere existence of a Snowflake secure share is not itself a Security Finding.

## 17. Certification

| Gate | Result |
|---|---|
| Provider identity (ID/label/category consistent backend+frontend) | PASS |
| Authentication model matches current docs, no unimplemented modes advertised | PASS |
| Credential fields match existing schema exactly | PASS |
| Least-privilege / service-user guidance never recommends ACCOUNTADMIN/SECURITYADMIN | PASS |
| Access-requirement matrix (37 rows) covers every real connector statement | PASS |
| Synchronous credential validation before persistence (`probe_coverage`) | PASS |
| Full/Partial/Invalid semantics correct, no over-rejection on optional-family denial | PASS |
| Capability diagnostics grouped and safe | PASS |
| Reconnect: same-account rotation accepted, different-account rejected, alias-safe, old PAT never reused | PASS |
| Initial/partial baseline: no fabricated history, no false removals | PASS |
| Frontend card/form/setup/PUBLIC-wording guard | PASS |
| 21 record types / 31 Findings unchanged and re-verified | PASS |
| Message-7 reliability certification still valid (no fetch/diff/classifier code touched) | PASS |
| Sensitive-data / CLI-independence / dependency audit | PASS |
| Database migration audit (none required) | PASS |
| Full Snowflake test suite passing | PASS |
| Cross-provider regression | PASS |
| Frontend TypeScript (`tsc --noEmit`) | PASS |

**CERTIFICATION: PASS.**

## 18. Documentation verification log (topics researched this message)

All accessed 2026-07-30 from docs.snowflake.com only (never blogs/Stack Overflow/tutorials/memory):

1. PATs — [Using programmatic access tokens for authentication](https://docs.snowflake.com/en/user-guide/programmatic-access-tokens), [ALTER USER ... ADD/ROTATE/MODIFY PAT](https://docs.snowflake.com/en/sql-reference/sql/alter-user-add-programmatic-access-token), [SHOW USER PROGRAMMATIC ACCESS TOKENS](https://docs.snowflake.com/en/sql-reference/sql/show-user-programmatic-access-tokens) — confirmed expiry/rotation/revocation/ROLE_RESTRICTION/no-secondary-roles behavior.
2. SQL API v2 auth — [Authenticating to the server](https://docs.snowflake.com/en/developer-guide/sql-api/authenticating), [Submitting a request](https://docs.snowflake.com/en/developer-guide/sql-api/submitting-requests), [SQL API reference](https://docs.snowflake.com/en/developer-guide/sql-api/reference) — confirmed Bearer header format, role-as-request-parameter, async/timeout/retry semantics.
3. Account identifiers — [Account identifiers](https://docs.snowflake.com/en/user-guide/admin-account-identifier) — confirmed orgname-accountname preferred form vs legacy locator form.
4. Role selection — [Specify Snowflake context with Snowflake REST APIs](https://docs.snowflake.com/en/developer-guide/snowflake-rest-api/setting-context) — confirmed role is a request-body field, must fall within PAT's ROLE_RESTRICTION.
5. Warehouse requirement — SQL API reference confirms `warehouse` is an optional field; a dedicated statement for zero-warehouse SHOW/DESCRIBE was not retrievable this pass — stated as an inference from connector behavior, not a doc-confirmed fact, per this report's §2.
6. Privilege tables — [SHOW USERS](https://docs.snowflake.com/en/sql-reference/sql/show-users), [SHOW NETWORK POLICIES](https://docs.snowflake.com/en/sql-reference/sql/show-network-policies), [SHOW NETWORK RULES](https://docs.snowflake.com/en/sql-reference/sql/show-network-rules), [SHOW AUTHENTICATION POLICIES](https://docs.snowflake.com/en/sql-reference/sql/show-authentication-policies), [SHOW INTEGRATIONS](https://docs.snowflake.com/en/sql-reference/sql/show-integrations) confirmed; [SHOW ROLES](https://docs.snowflake.com/en/sql-reference/sql/show-roles), [SHOW GRANTS](https://docs.snowflake.com/en/sql-reference/sql/show-grants), [DESC INTEGRATION](https://docs.snowflake.com/en/sql-reference/sql/desc-integration), [DESCRIBE POLICY](https://docs.snowflake.com/en/sql-reference/sql/desc-policy), and SHOW DATABASES/SCHEMAS/WAREHOUSES/SHARES per-command access-control tables were not retrievable via the fetch tool this pass — flagged as `partial`/unconfirmed in `snowflake_access_requirement_matrix.md` rather than guessed.
7. PAT licensing — no edition/feature-flag gate found; absence-of-evidence, not a hard guarantee.
8. Regions/clouds — [Supported cloud regions](https://docs.snowflake.com/en/user-guide/intro-regions), [Supported cloud platforms](https://docs.snowflake.com/en/user-guide/intro-cloud-platforms) — AWS/Azure/GCP commercial deployments confirmed; GovCloud/SnowGov isolated and out of scope.

**Snowflake provider expansion is complete.**
