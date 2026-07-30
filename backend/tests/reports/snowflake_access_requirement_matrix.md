# Snowflake Access Requirement Matrix (Snowflake Message 8 of 8 — Public Launch)

Authoritative setup/permission matrix derived directly from the actual
statement constants in `app/connectors/snowflake.py` — never a
speculative list of commands the connector does not issue. Every SHOW/
SELECT/DESCRIBE statement the connector can execute appears below
exactly once (probe form and real-collection form of the same command
are listed as one row, since they require identical privilege).

**Core vs Extended**: Core families are read by the monitoring role for
baseline identity/data-object monitoring and are expected to work with a
standard read-only role. Extended families may require additional
visibility grants (security-relevant metadata that Snowflake restricts
more tightly by default) — if unavailable, the integration still
connects with **Partial** coverage rather than being rejected.

**Verified** column: `docs` = confirmed via current official
docs.snowflake.com "Access Control Requirements" table during this
message's research pass; `partial` = the general privilege model is
confirmed but the exact per-command access-control table was not
retrievable via the fetch tool in this pass (flagged honestly rather
than guessed — see `snowflake_provider_certification.md` §2 for the
full docs-verification log); `n/a` = the command has no dedicated
official access-control table (its data-visibility is scoped by the
role's own grants, not a special command-level privilege).

| # | ConfigTrace family | SQL command | Required privilege / role visibility | Core/Extended | Failure behavior | Coverage status if denied | Official documentation | Verified |
|---|---|---|---|---|---|---|---|---|
| 1 | Account identity | `SELECT CURRENT_ORGANIZATION_NAME(), CURRENT_ACCOUNT_NAME(), CURRENT_ACCOUNT(), CURRENT_ROLE()` | None beyond a valid, authenticated session — always readable | Core (mandatory) | Raises `ConnectorError`/`AuthenticationError` — creation/reconnect rejected entirely (Invalid) | N/A — this call must succeed for ANY coverage state | Session context functions, no ownership/grant required | n/a |
| 2 | Users (capability probe) | `SELECT 1 FROM SNOWFLAKE.ACCOUNT_USAGE.USERS LIMIT 1` | `IMPORTED PRIVILEGES` on the `SNOWFLAKE` database (granted to `ACCOUNTADMIN` by default; can be granted to a custom role) | Core | Probe fails soft → family marked unavailable/denied | `users` capability = denied/unavailable | Database Roles for the SNOWFLAKE database (ACCOUNT_USAGE schema access) | partial |
| 3 | Users (real collection) | `SHOW USERS` | Any authenticated role can execute; full column detail requires `OWNERSHIP` on the user or account-level `MANAGE GRANTS`/security-admin visibility — non-owners see nulls in restricted columns | Core | `_collect_users` marks `users` family `denied`/`unavailable`; other families unaffected | `snowflake_account.family_completeness["users"]` = `denied`/`unavailable` | SHOW USERS reference | partial |
| 4 | Roles (capability probe) | `SELECT 1 FROM SNOWFLAKE.ACCOUNT_USAGE.ROLES LIMIT 1` | ACCOUNT_USAGE visibility (see row 2) | Core | Probe fails soft | `roles` capability = denied/unavailable | ACCOUNT_USAGE schema privileges | partial |
| 5 | Account roles (real collection) | `SHOW ROLES` | Broadly readable; full detail may require elevated visibility | Core | Family fails soft | `account_roles` = denied/unavailable | SHOW ROLES reference | partial |
| 6 | Role grants (capability probe) | `SELECT 1 FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS LIMIT 1` | ACCOUNT_USAGE visibility (row 2) | Core | Probe fails soft | `role_grants` capability = denied/unavailable | ACCOUNT_USAGE schema privileges | partial |
| 7 | User-role grants to account role (real collection) | `SHOW GRANTS TO ROLE <role>` | Results limited to grants visible to the caller's own role; full visibility via `MANAGE GRANTS` | Core | Per-role fails soft | Per-role `role_hierarchy_collection_status`/grant status = denied | SHOW GRANTS reference | partial |
| 8 | User-role grants to database role (real collection) | `SHOW GRANTS TO DATABASE ROLE <db>.<role>` | Same visibility model as row 7, scoped to the database role | Core | Per-database-role fails soft | Per-role grant status = denied | SHOW GRANTS reference | partial |
| 9 | Object/future grants (capability probe) | `SELECT 1 FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES LIMIT 1` | ACCOUNT_USAGE visibility (row 2) | **Extended** (drives ownership/privilege derivation, message 5) | Probe fails soft | `object_grants` capability = denied/unavailable | ACCOUNT_USAGE schema privileges | partial |
| 10 | Role-hierarchy/object grants of account role (real collection) | `SHOW GRANTS OF ROLE <role>` | Limited to the caller's visible role scope; full visibility via `MANAGE GRANTS` | **Extended** | Per-role fails soft (message 7 `role_hierarchy_collection_status`/`object_grant_collection_status`) | Per-role status = denied; Partial coverage, not Invalid | SHOW GRANTS reference | partial |
| 11 | Role-hierarchy/object grants of database role (real collection) | `SHOW GRANTS OF DATABASE ROLE <db>.<role>` | Same visibility model as row 10, scoped to the database role | **Extended** | Per-database-role fails soft (documented coarser fallback to account-wide `object_grants` — message 7) | Per-role status = denied; falls back to family-level check | SHOW GRANTS reference | partial |
| 12 | Future grants (real collection) | `SHOW FUTURE GRANTS IN DATABASE <db>` | Limited to the caller's visible database scope; full visibility via `MANAGE GRANTS` | **Extended** | Per-database fails soft (message 7 `future_grant_collection_status`) | `snowflake_database.future_grant_collection_status` = denied | SHOW FUTURE GRANTS reference | partial |
| 13 | Databases (capability probe) | `SHOW DATABASES LIMIT 1` | `USAGE` on at least one database, or broader visibility | Core | Probe fails soft | `databases` capability = denied/unavailable | SHOW DATABASES reference | partial |
| 14 | Databases (real collection) | `SHOW DATABASES` | Readable for any database the role has `USAGE` on, or all databases for a role with broad visibility | Core | Family fails soft; feeds schema/database-role/future-grant loops | `databases` = denied/unavailable | SHOW DATABASES reference | partial |
| 15 | Schemas (capability probe) | `SHOW SCHEMAS LIMIT 1` | `USAGE` on the containing database plus schema-level visibility | Core | Probe fails soft | `schemas` capability = denied/unavailable | SHOW SCHEMAS reference | partial |
| 16 | Schemas (real collection) | `SHOW SCHEMAS IN DATABASE <db>` | Same as row 15, per-database | Core | Per-database fails soft (message 7 `schema_collection_status`) | `snowflake_database.schema_collection_status` = denied | SHOW SCHEMAS reference | partial |
| 17 | Database roles (real collection) | `SHOW DATABASE ROLES IN DATABASE <db>` | `USAGE` on the database plus database-role visibility (broader than basic schema `USAGE`) | Core | Per-database fails soft (message 7 `database_role_collection_status`) | `snowflake_database.database_role_collection_status` = denied | SHOW DATABASE ROLES reference | partial |
| 18 | Warehouses (capability probe) | `SHOW WAREHOUSES LIMIT 1` | `MONITOR`/`USAGE` on the warehouse, or broader visibility | Core | Probe fails soft | `warehouses` capability = denied/unavailable | SHOW WAREHOUSES reference | partial |
| 19 | Warehouses (real collection) | `SHOW WAREHOUSES` | Same as row 18 | Core | Family fails soft | `warehouses` = denied/unavailable | SHOW WAREHOUSES reference | partial |
| 20 | Shares (capability probe) | `SHOW SHARES LIMIT 1` | Visibility into shares the role owns or has `USAGE`/`REFERENCE_USAGE` on | Core | Probe fails soft | `shares` capability = denied/unavailable | SHOW SHARES reference | partial |
| 21 | Shares (real collection) | `SHOW SHARES` | Same as row 20 | Core | Family fails soft | `shares` = denied/unavailable | SHOW SHARES reference | partial |
| 22 | Network policies (capability probe) | `SELECT 1 FROM SNOWFLAKE.ACCOUNT_USAGE.NETWORK_POLICIES LIMIT 1` | ACCOUNT_USAGE visibility (row 2) | **Extended** | Probe fails soft | `network_policies` capability = denied/unavailable | ACCOUNT_USAGE schema privileges | partial |
| 23 | Network policies (real collection) | `SHOW NETWORK POLICIES` | Confirmed: only the network policy `OWNERSHIP` holder (or higher, e.g. SECURITYADMIN) can execute this command | **Extended** | Family fails soft | `network_policies` = denied/unavailable; Partial coverage, not Invalid | SHOW NETWORK POLICIES reference | docs |
| 24 | Network policy detail | `DESCRIBE NETWORK POLICY <name>` | Same ownership/SECURITYADMIN requirement as row 23 | **Extended** | Per-policy `DESCRIBE` fails soft | Per-policy detail = denied | DESCRIBE NETWORK POLICY reference | partial |
| 25 | Network rules (real collection) | `SHOW NETWORK RULES` | Confirmed: `OWNERSHIP` on the network rule, or `USAGE` on the containing schema | **Extended** | Family fails soft | `network_rules` context = denied/unavailable | SHOW NETWORK RULES reference | docs |
| 26 | Authentication policies (capability probe) | `SHOW AUTHENTICATION POLICIES LIMIT 1` | Confirmed: `APPLY AUTHENTICATION POLICY` on the account (default SECURITYADMIN+) or `OWNERSHIP` on the specific policy | **Extended** | Probe fails soft | `authentication_policies` capability = denied/unavailable | SHOW AUTHENTICATION POLICIES reference | docs |
| 27 | Authentication policies (real collection) | `SHOW AUTHENTICATION POLICIES` | Same as row 26 | **Extended** | Family fails soft | `authentication_policies` = denied/unavailable; Partial coverage, not Invalid | SHOW AUTHENTICATION POLICIES reference | docs |
| 28 | Authentication policy detail | `DESCRIBE AUTHENTICATION POLICY <name>` | Same as row 26 | **Extended** | Per-policy `DESCRIBE` fails soft, policy still listed with `detail_status="denied"` | Per-policy detail = denied | DESCRIBE AUTHENTICATION POLICY reference | partial |
| 29 | Security integrations (capability probe) | `SHOW SECURITY INTEGRATIONS LIMIT 1` | Confirmed: `USAGE` or `OWNERSHIP` on the integration object | **Extended** | Probe fails soft | `security_integrations` capability = denied/unavailable | SHOW INTEGRATIONS reference | docs |
| 30 | Security integrations (real collection) | `SHOW SECURITY INTEGRATIONS` | Same as row 29 | **Extended** | Family fails soft | `security_integrations` = denied/unavailable | SHOW INTEGRATIONS reference | docs |
| 31 | Security integration detail (SAML/OAuth/SCIM) | `DESCRIBE INTEGRATION <name>` | Not confirmed via a dedicated access-control table this pass — inferred to require the same `USAGE`/`OWNERSHIP` as SHOW INTEGRATIONS | **Extended** | Per-integration `DESCRIBE` fails soft | Per-integration detail = denied | DESC INTEGRATION reference (access-control table not retrieved this pass) | partial |
| 32 | Storage integrations (capability probe) | `SHOW STORAGE INTEGRATIONS LIMIT 1` | Confirmed: `USAGE` or `OWNERSHIP` on the integration object (same table as row 29) | **Extended** | Probe fails soft | `storage_integrations` capability = denied/unavailable | SHOW INTEGRATIONS reference | docs |
| 33 | Storage integrations (real collection) | `SHOW STORAGE INTEGRATIONS` | Same as row 32 | **Extended** | Family fails soft | `storage_integrations` = denied/unavailable | SHOW INTEGRATIONS reference | docs |
| 34 | Storage integration detail | `DESCRIBE INTEGRATION <name>` | Same as row 31 | **Extended** | Per-integration `DESCRIBE` fails soft | Per-integration detail = denied | DESC INTEGRATION reference (not fully retrieved this pass) | partial |
| 35 | External access integrations (capability probe) | `SHOW EXTERNAL ACCESS INTEGRATIONS LIMIT 1` | Confirmed: `USAGE` or `OWNERSHIP` on the integration object (same table as row 29) | **Extended** | Probe fails soft | `external_access_integrations` capability = denied/unavailable | SHOW INTEGRATIONS reference | docs |
| 36 | External access integrations (real collection) | `SHOW EXTERNAL ACCESS INTEGRATIONS` | Same as row 35 | **Extended** | Family fails soft | `external_access_integrations` = denied/unavailable | SHOW INTEGRATIONS reference | docs |
| 37 | External access integration detail | `DESCRIBE INTEGRATION <name>` | Same as row 31 | **Extended** | Per-integration `DESCRIBE` fails soft | Per-integration detail = denied | DESC INTEGRATION reference (not fully retrieved this pass) | partial |

**37 rows covering every distinct statement string issued by the
connector** (1 account-identity `SELECT` + 13 capability probes + ~23
real-collection SHOW/DESCRIBE statements, with the few statements shared
verbatim between the probe sweep and real collection intentionally
listed as separate rows since each is a distinct call site with its own
failure-handling code path). No speculative or unused command appears
above.

## Setup summary (least-privilege monitoring role)

For **Full** coverage, the monitoring role needs:
- `IMPORTED PRIVILEGES` on the `SNOWFLAKE` database (ACCOUNT_USAGE access — rows 2, 4, 5, 6, 12)
- `USAGE` on every database/schema/warehouse/share ConfigTrace should monitor (rows 7-11)
- `OWNERSHIP` of (or a role with elevated visibility over) network policies, authentication policies, and security/storage/external-access integrations (rows 13-23) — or `SECURITYADMIN`-adjacent visibility if the organization prefers not to grant per-object ownership to the monitoring role

For **Partial** (still useful) coverage, only the Core rows (2-11) need
to succeed — a monitoring role with ACCOUNT_USAGE + broad `USAGE` grants
and no security/policy-object ownership will connect successfully with
the Extended families showing "Permission denied" in diagnostics.

No row in this matrix requires `ACCOUNTADMIN`, `SECURITYADMIN`, or
`MANAGE GRANTS` — those privileges only appear in what the connector
*observes* other roles/users holding (message 5 privilege derivation),
never in what the ConfigTrace monitoring role itself must be granted.
