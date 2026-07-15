# Supabase Detection-QA Matrix

Scope: **detection only** — connector normalization, diff reachability,
classifier routing, Security Finding reachability, registry/frontend
parity, provider metadata, sensitive-data minimization, and fail-soft
behavior. Exhaustive transition-severity, restoration, and numeric/list
edge-case review is reserved for the dedicated Supabase change-
classification pass (message 2) and is **not** covered here.

## Graphify note

Per the task's explicit instruction, Graphify's freshness was **not**
assumed even though all four required queries succeeded via the full path
(`/Users/rohan/.local/bin/graphify`). The graph confirmed `SupabaseConnector`,
`risk_rules/supabase.py` ("Supabase risk classification rules — M54"),
`security_rules/supabase.py` ("Supabase security exposure rules — M60.4 /
M60.4.4 / M71A"), and a "Supabase provider depth QA" node ("durable
guardrails that pin the full Supabase rule taxonomy"). Useful hints
surfaced: "RLS disabled = supabase_rls_disabled fires, NOT public_write"
and "mfa_required=None (not set) must NOT fire — evaluator checks 'is
False'" (confirmed accurate on direct read). The graph is coarse
(class/docstring-level) and could not answer "which tracked field maps to
which classifier branch" — that required direct reads of `diff_service.py`,
`risk_rules/supabase.py`, and `security_rules/supabase.py`, which are
authoritative for everything in this report.

## Record-type inventory — all 10 schema types are reachable

Unlike every other provider audited this session (GitHub 6/16 reachable,
Stripe 6/17, Vercel 5/12), **Supabase's connector emits all 10 of its
schema-defined record types** — confirmed by reading `fetch()` end to end
and matching every `_fetch_*` helper call against the schema's
`SUPABASE_RECORD_TYPES`-equivalent constant list.

| # | Record type | Endpoint | Scope | Pagination |
|---|---|---|---|---|
| 1 | `supabase_project` | `GET /v1/projects/{ref}` | project (singleton) | n/a |
| 2 | `supabase_auth_config` | `GET /v1/projects/{ref}/config/auth` | project (singleton) | n/a |
| 3 | `supabase_oauth_provider` | derived from auth config's `external` map | project, one per provider | n/a (map, not paginated) |
| 4 | `supabase_database_config` | `GET /v1/projects/{ref}/config/database/pooler` (+ `db_version` from project metadata) | project (singleton) | n/a |
| 5 | `supabase_storage_config` | `GET /v1/projects/{ref}/config/storage` | project (singleton) | n/a |
| 6 | `supabase_edge_function` | `GET /v1/projects/{ref}/functions` | project, one per function | none (Management API returns full list) |
| 7 | `supabase_rls_status` | `GET /v1/projects/{ref}/database/tables?included_schemas=public` (+ `pg_policies` metadata query merged in) | project, one per public-schema table | none |
| 8 | `supabase_api_config` | `GET /v1/projects/{ref}/config/postgrest` | project (singleton) | n/a |
| 9 | `supabase_network_restriction` | `GET /v1/projects/{ref}/network-restrictions` | project, one per CIDR (or one "unrestricted" sentinel) | n/a |
| 10 | `supabase_custom_domain` | `GET /v1/projects/{ref}/custom-hostname` | project, at most one | n/a |

**Side-channel activity ingestion**: `list_activity_events()` (M71B) reads
`GET /v1/organizations/{org}/audit` (organization-scoped, requires an
organization slug) — a separate pipeline from `fetch()`/`compute_diff()`,
feeding `supabase_activity_ingestion_service.py` /
`supabase_activity_signal_service.py` / correlation services directly.
Covers table/RLS/policy/storage-bucket/Edge-Function/auth-config *events*
(including storage-bucket create/update/delete activity, which has no
static record type — see below). Never becomes a drift `Change` row.
Documented, not a gap.

**Storage buckets are NOT modeled as a static record type** (no
`supabase_storage_bucket` schema type exists) — this is a deliberate,
documented decision (`security_rules/supabase.py`'s "Deferred Supabase
rules" docstring): listing buckets and their public/private status
requires the project's service-role/anon key, which ConfigTrace
deliberately never stores or uses, and the Management API exposes no safe
bucket-list endpoint. `supabase_storage_config` only models
account-wide settings (file size limit, MIME allow-list, S3 protocol
flag) — never per-bucket posture. Confirmed via the capability matrix's
notes, which correctly scope "storage-bucket... events" to the
activity/audit-log pipeline only, not drift. GAP, not invented, consistent
with instructions.

## Root-cause bugs found and fixed this pass

1. **`supabase_rls_status`'s M71A per-table public-policy fields
   (`policy_count`, `has_public_select_policy`, `has_public_insert_policy`,
   `has_public_update_policy`, `has_public_delete_policy`,
   `exposed_to_anon`) had NO entry in `_SUPABASE_TRACKED_FIELDS_BY_TYPE`**,
   despite being emitted by the connector (merged in from
   `_fetch_database_policies`'s `pg_policies` query) and evaluated by the
   `supabase_public_select_sensitive_table` / `supabase_public_write_policy`
   Security Findings. A table gaining a public SELECT or write policy —
   arguably the most security-critical transition this provider models —
   produced **zero Change rows**, confirmed via a direct `compute_diff()`
   call before the fix. **Fixed**: added the 6 fields to the tracked-fields
   tuple and added matching classifier branches to
   `_classify_rls_status_change` (high severity for a new public
   select/write policy, low for removal, medium/low for
   `exposed_to_anon`/`policy_count`).
2. **`_build_provider_metadata()` had NO Supabase-specific stanza at all**
   — five classifiers read identifying context directly from
   `provider_metadata` that the generic `record_name`/`record_content`
   stanza never populates (these record types don't carry a `"name"`
   field): `_classify_rls_status_change` (`table_name`/`schema_name`),
   `_classify_edge_function_change` (`function_name`/`slug`),
   `_classify_network_restriction_change` (`cidr`),
   `_classify_custom_domain_change` (`custom_domain`),
   `_classify_oauth_provider_change` (`provider_name`). Confirmed live via
   direct `compute_diff()`: the **critical** "RLS disabled" Change's own
   copy read *"Row Level Security was disabled on table 'public'"* — the
   table name was silently dropped, leaving only the schema, on the single
   highest-severity Change this provider can produce. **Fixed**: added a
   Supabase-specific stanza populating all 5 fields.
3. **`_fetch_rls_status`, `_fetch_network_restrictions`, and
   `_fetch_edge_functions` each injected a synthetic `"_access_denied"`
   placeholder record on HTTP 403** whose `record_id` was a **new,
   fabricated ID** distinct from every real per-item record's ID (unlike
   the safe singleton pattern used by `_fetch_auth_config` /
   `_fetch_database_config` / `_fetch_storage_config` / `_fetch_api_config`,
   which reuse the exact same stable `record_id` on failure so the fallback
   just becomes a "modified"/unchanged event on one record, not a mass
   removal). Because these three are per-item **list** endpoints, a mere
   permission hiccup made `compute_diff()` report **every previously-known
   table/CIDR/function as "removed"** (their IDs vanish from the new
   snapshot) plus the placeholder itself as spurious "added" noise — and
   then another burst of noise (real items "reappearing", placeholder
   "removed") once the token was fixed. **Fixed**: all three now return an
   empty list on 403, matching the already-safer pattern used by
   `_fetch_custom_domain`. This does not fully eliminate the underlying
   "prior items look removed on failure" limitation (a codebase-wide
   snapshot-diffing tradeoff shared by every provider's optional per-item
   endpoints — e.g. GitHub's `_fetch_environments` has the identical
   theoretical exposure, and fixing it fully would require a
   partial-snapshot-merge capability that doesn't exist anywhere in this
   codebase, well out of scope for a single-provider pass), but it removes
   the confusing add/remove/re-add churn cycle the fabricated placeholder
   ID caused on top of that.

## Confirmed correct, no fix needed

- Numeric field handling in `risk_rules/supabase.py` (`oauth_provider_count`,
  `password_min_length`, `jwt_exp`, `additional_redirect_urls_count`,
  `max_rows`, `file_size_limit`, `policy_count`) all use `int(x)` wrapped in
  `try/except (TypeError, ValueError)` with explicit `is not None` guards
  where comparing two values — **no `int(x or 0)`-style unknown-as-zero
  coercion exists anywhere in this file**, unlike the pattern found and
  fixed in GitHub's message-2 pass. `int(None)` naturally raises and is
  caught, falling to a safe generic-copy branch without claiming a
  direction.
- `classify_supabase_change()`'s dispatcher correctly routes all 10 record
  types to dedicated classifiers with a safe, Supabase-specific
  (`f"A Supabase configuration record changed ({record_type})."`) — NOT a
  Cloudflare or other-provider fallback — for any unrecognised type.
- `security_rules/supabase.py`'s `evaluate()` dispatches on exactly the 3
  record types it has Finding logic for (`supabase_rls_status`,
  `supabase_auth_config`, `supabase_edge_function`) — no dead
  Finding-dispatch branches for the other 7 reachable-but-not-Finding-
  eligible types.
- `_eval_rls`'s RLS-disabled check (`"rls_enabled" in record and
  record.get("rls_enabled") is False`) and `_eval_edge_function`'s
  verify_jwt check (`"verify_jwt" not in record or record.get("verify_jwt")
  is not False`) both correctly require an explicit `False` — confirmed via
  regression test that an RLS/verify_jwt-unknown record does not fire
  either Finding.
- No `old_value`/`previous_value`/`prior_value` usage anywhere in Supabase
  production code or tests (full grep across connector, schema,
  risk_rules, security_rules, and all `test_*supabase*`/milestone71*/
  milestone60_4_4 files).

## Flagged for the Supabase message-2 pass (not fixed here — severity/copy nuance, not a routing defect)

Consistent with this session's established message-1/message-2 boundary
(the identical class of issue was deferred from GitHub's and Stripe's
detection-QA passes to their classification-QA passes):

- **Connector-level boolean defaulting**: `_fetch_auth_config` coerces
  `email_enabled`/`phone_enabled`/`anonymous_enabled`/`mfa_totp_enabled`/
  `leaked_password_protection_enabled`/`captcha_enabled`/
  `require_reauthentication_for_password_update`/
  `refresh_token_rotation_enabled` via `bool(data.get(x))` — if the
  Management API ever omits one of these fields, it's silently coerced to
  `False` rather than preserved as unknown. `_fetch_rls_status` does the
  same for `rls_enabled`/`rls_forced` via `bool(table.get(x, False))` — the
  riskier direction, since unknown-as-False on `rls_enabled` would trigger
  the **critical** "RLS disabled" Change/the **high** `supabase_rls_disabled`
  Finding for a table whose real status was never actually confirmed.
  `_fetch_edge_functions`'s `verify_jwt` defaults missing to `True` (the
  safe direction) via `bool(fn.get("verify_jwt", True))` — asymmetric with
  the RLS case.
- Multiple classifiers use an `if new_v is False: <risky>; else:
  <assumes restored/enabled>` unconditional-else pattern (e.g.
  `anonymous_enabled`, `mfa_totp_enabled`, `email_enabled`, `leaked_
  password_protection_enabled`, `captcha_enabled`, `require_
  reauthentication_for_password_update`, `refresh_token_rotation_enabled`,
  `s3_protocol_enabled`, `verify_jwt`, `rls_enabled`, `rls_forced`) — an
  unknown value would fall into the "else" branch and be reported as an
  explicit restoration/improvement claim. This is the identical bug class
  fixed in GitHub's and Stripe's message-2 passes; fixing the connector's
  boolean coercion without also fixing the classifier's unconditional-else
  (or vice versa) would produce an inconsistent half-fix, so both halves
  are deferred together to Supabase message 2.

## Diff tracking — tracked vs. emitted vs. classified

| Record type | Tracked fields | Gap found | Status |
|---|---|---|---|
| `supabase_project` | 6 fields (name, region, cloud_provider, status, plan_id, has_custom_domain) + config_fetch_warnings | none | full parity, all dedicated branches |
| `supabase_auth_config` | 15 fields + config_fetch_warnings | none | full parity, all dedicated branches |
| `supabase_database_config` | 5 fields + config_fetch_warnings | none | full parity |
| `supabase_storage_config` | 3 fields + config_fetch_warnings | none | full parity |
| `supabase_edge_function` | 4 fields + config_fetch_warnings | none | full parity (`function_name`/`slug` correctly live in provider_metadata, not tracked — identity, not a change-worthy field) |
| `supabase_rls_status` | **was 2 fields → fixed to 8** (added 6 M71A policy fields) | **FIXED this pass** | see root-cause #1 |
| `supabase_api_config` | 3 fields + config_fetch_warnings | none | full parity |
| `supabase_network_restriction` | 2 fields + config_fetch_warnings | none | full parity |
| `supabase_custom_domain` | 2 fields + config_fetch_warnings | none | full parity |
| `supabase_oauth_provider` | 2 fields + config_fetch_warnings | none | full parity (`provider_name` correctly lives in provider_metadata as identity, not tracked) |

**Normalized-but-untracked fields**: none beyond the now-fixed RLS policy
fields — every other normalized field across all 10 types is tracked.
**Tracked-but-not-emitted fields**: none found — every tracked field name
matches a field the corresponding `_fetch_*` method actually populates.
**Stale/confusing field names**: none found (e.g. `rls_enabled` vs.
`rls_forced` are distinct, well-named Postgres RLS concepts, not a
collision).

## Security Finding reachability (10 rules, all confirmed reachable)

| Rule key | Record type | Trigger | Severity | Reachable? | Registry/pack/confidence/coverage/frontend parity |
|---|---|---|---|---|---|
| `supabase_rls_disabled` | rls_status | `rls_enabled is False` (key present) | high | Yes | full |
| `supabase_anonymous_access_enabled` | auth_config | `anonymous_enabled is True` | medium | Yes | full |
| `supabase_jwt_expiry_long` | auth_config | `jwt_exp` is a real int `> 86400` | medium | Yes | full |
| `supabase_public_select_sensitive_table` | rls_status | RLS on + public SELECT policy + sensitive-looking table name | high | Yes | full |
| `supabase_public_write_policy` | rls_status | RLS on + public insert/update/delete policy | high | Yes | full |
| `supabase_edge_function_jwt_disabled` | edge_function | `verify_jwt is False` | high (sensitive fn name) / medium | Yes | full — dynamic severity confirmed consistent with the established "pack records the higher/typical value" convention (matches `github_ruleset_not_enforced`'s precedent) |
| `supabase_auth_protection_missing` | auth_config | `leaked_password_protection_enabled is False` | medium | Yes | full |
| `supabase_refresh_token_rotation_disabled` | auth_config | `refresh_token_rotation_enabled is False` | medium | Yes | full |
| `supabase_captcha_disabled` | auth_config | `captcha_enabled is False` | low | Yes | full |
| `supabase_password_update_reauth_disabled` | auth_config | `require_reauthentication_for_password_update is False` | medium | Yes | full |

All 10 keys verified present with matching severity/category across
`security_rule_registry.py` (`KNOWN_RULE_KEYS`), `security_rule_pack.py`,
`security_rule_confidence.py`, `security_coverage_service.py` (correct
record-type mapping for every key), and
`frontend/src/lib/securityRuleCatalog.ts`.

**Deliberately deferred rules** (documented in `security_rules/
supabase.py`'s own docstring, reconfirmed accurate this pass, not gaps to
fix):
- A separate "RLS disabled on public schema table" key — would double-flag
  the same state `supabase_rls_disabled` already covers (RLS is only
  fetched for the `public` schema).
- Public storage bucket — Management API exposes no safe bucket-list
  endpoint without storing a service-role/anon key, which ConfigTrace
  deliberately never does.
- Auth redirect URL too broad — connector only stores
  `additional_redirect_urls_count` (a count), never the raw URLs, so
  wildcard/localhost patterns cannot be evaluated without inventing new
  storage of raw URLs.

**Records with no Security Finding**: `supabase_project`,
`supabase_database_config`, `supabase_storage_config`,
`supabase_api_config`, `supabase_network_restriction`,
`supabase_custom_domain`, `supabase_oauth_provider` — all Change-only,
consistent with these being operational/business-configuration surfaces
(project region, pooler mode, PostgREST schema, custom domain, etc.)
without a single unambiguous "this state is inherently risky" signal, or
(for network restrictions) already covered by the Change classifier's
critical/high severity for unrestricted access without a separate static
Finding needed.

## Registry/evaluator/frontend/provider-capability parity

Confirmed via `tests/test_supabase_provider_depth_qa.py` (42 tests, all
passing) — durable guardrails pinning the exact 10-key taxonomy,
severities, categories, and dispatch. `provider_capability_matrix_service.py`'s
`_SUPABASE` entry's notes ("Supabase drift covers RLS status, anonymous
access, JWT expiry, public-select policies, and public-write policies.
Security investigation covers organization audit activity, table/RLS/
policy/storage-bucket/Edge-Function/auth-config events...") accurately
scope storage-bucket coverage to the activity/audit pipeline only, not
drift — matching the connector's actual capabilities, no overclaiming.

## Fail-soft and partial-sync behavior

- 401 → `AuthenticationError` (hard fail, correct — invalid token).
- 403 → `ConnectorError(status_code=403)`, caught individually by every
  optional `_fetch_*` method; singleton records reuse their stable
  `record_id` with `config_fetch_warnings` populated (no mass-removal
  risk); the 3 per-item-list endpoints now return `[]` (fixed this pass,
  see root-cause #3).
- 404 → distinguished from 403 (`_fetch_custom_domain` explicitly treats
  404 as "no custom domain configured," not a permission failure).
- 429 → retried with `_MAX_RETRIES` bounded attempts, raises
  `RateLimitError` after exhaustion.
- 5xx → retried, then raises `ConnectorError` with the status code
  preserved.
- One optional endpoint's failure never suppresses unrelated records —
  each `_fetch_*` call is independent and appended to `records` regardless
  of other calls' outcomes; confirmed by reading `fetch()`'s structure
  (each step wrapped in its own method with its own try/except).
- `_fetch_database_policies` (the `pg_policies` metadata query) is
  explicitly fail-soft on *any* exception (`except Exception` — broad by
  design since policy posture is optional), returning `{}` so RLS status
  records are still collected without policy flags rather than losing the
  whole RLS surface.

## Sensitive-data minimization

Confirmed via direct source read and grep: `credentials["access_token"]`
is used only for the `Authorization: Bearer` header, never persisted in
any record. OAuth `client_secret` is never accessed; `client_id` is
SHA-256 hashed to 16 hex chars before storage. Edge Function source code,
environment variable *values*, and secrets are never fetched — only
`env_var_key_count`. Storage file contents and object names are never
accessed. Database row data is never read — the only SQL query the
connector runs (`_POLICIES_QUERY`) selects exclusively
`schemaname, tablename, cmd, roles` from `pg_policies` (catalog metadata),
never `USING`/`WITH CHECK` expressions or any row data. Database
passwords, connection strings, and JWT secrets are never fetched.

## Copy safety

No forbidden phrases (breach, compromise, database exposed, user data
leaked, etc.) found in any Supabase evidence/copy across
`risk_rules/supabase.py`, `security_rules/supabase.py`, or the connector.
Every Security Finding description includes an explicit "does not confirm
data exposure or unauthorized access" (or equivalent) disclaimer.

## Detection matrix (lettered cases A–AO)

| Case | Category | Record type | Field(s) | Emits evidence? | Detected by `compute_diff`? | Classifier route | Finding key | Reachable? | Parity | Status |
|---|---|---|---|---|---|---|---|---|---|---|
| A | Project status | project | status | Yes | Yes | `_classify_project_change` | n/a | n/a | n/a | PASS |
| B | Database SSL | database_config | n/a — not modeled (Management API pooler config endpoint doesn't expose an SSL-enforcement field; the connector doesn't invent one) | No | No | n/a | n/a | n/a | n/a | GAP (documented, not invented) |
| C | Database network restriction | network_restriction | is_unrestricted | Yes | Yes | `_classify_network_restriction_change` | n/a (Change-only, critical/high already covers it) | n/a | n/a | PASS |
| D | Exposed schema added/removed | api_config | db_schema | Yes | Yes | `_classify_api_config_change` | n/a | n/a | n/a | PASS |
| E | API max rows | api_config | max_rows | Yes | Yes | same | n/a | n/a | n/a | PASS |
| F | JWT expiry | auth_config | jwt_exp | Yes | Yes | `_classify_auth_config_change` | `supabase_jwt_expiry_long` | Yes | full | PASS |
| G | Email signup | auth_config | email_enabled | Yes | Yes | same | n/a | n/a | n/a | PASS |
| H | Phone signup | auth_config | phone_enabled | Yes | Yes | same | n/a | n/a | n/a | PASS |
| I | Anonymous signup | auth_config | anonymous_enabled | Yes | Yes | same | `supabase_anonymous_access_enabled` | Yes | full | PASS |
| J | Email confirmation required | auth_config | n/a — not modeled (connector doesn't fetch `mailer_autoconfirm`/confirmation-required fields) | No | No | n/a | n/a | n/a | n/a | GAP (documented, not invented) |
| K | Password min length | auth_config | password_min_length | Yes | Yes | same | n/a | n/a | n/a | PASS |
| L | MFA posture | auth_config | mfa_totp_enabled | Yes | Yes | same | n/a (no static Finding — Change-only) | n/a | n/a | PASS |
| M | CAPTCHA | auth_config | captcha_enabled | Yes | Yes | same | `supabase_captcha_disabled` | Yes | full | PASS |
| N | Redirect URL wildcard | auth_config | n/a — only `additional_redirect_urls_count` (a count) is emitted; raw URLs/wildcard patterns are never stored | No (by design) | Yes (count only) | same | none (deliberately deferred, documented) | n/a | n/a | GAP (documented, intentional — raw URLs would need to be stored to evaluate) |
| O | Site URL HTTP/HTTPS | auth_config | site_url | Yes | Yes | same | n/a | n/a | n/a | PASS |
| P | OAuth provider enabled/disabled | oauth_provider | enabled | Yes | Yes | `_classify_oauth_provider_change` | n/a | n/a | n/a | PASS |
| Q | SMTP posture | auth_config | n/a — not modeled (connector doesn't fetch SMTP config fields) | No | No | n/a | n/a | n/a | n/a | GAP (documented, not invented) |
| R | Table RLS enabled/disabled | rls_status | rls_enabled | Yes | Yes | `_classify_rls_status_change` | `supabase_rls_disabled` | Yes | full | PASS |
| S | Table with no RLS policy | rls_status | policy_count=0 while rls_enabled=True | Yes | **Was No → Fixed** | same | n/a (no dedicated "0 policies" Finding) | n/a | n/a | **FIXED** (detection now works via policy_count tracking) |
| T | Broad anonymous policy | rls_status | has_public_select_policy / has_public_insert_policy / etc. | Yes | **Was No → Fixed** | same | `supabase_public_select_sensitive_table` / `supabase_public_write_policy` | Yes | full | **FIXED** |
| U | Policy added/removed | rls_status | policy_count | Yes | **Was No → Fixed** | same | n/a | n/a | n/a | **FIXED** |
| V | Public storage bucket | n/a | n/a — no bucket record type exists (Management API exposes no safe bucket list without a service-role/anon key) | No | No | n/a | none (deliberately deferred) | n/a | n/a | GAP (documented, not invented) |
| W | Bucket public → private | n/a | same as V | No | No | n/a | none | n/a | n/a | GAP |
| X | Storage policy changed | storage_config | (only account-wide MIME/size/S3 settings exist, not per-bucket policies) | Yes (account-wide only) | Yes | `_classify_storage_config_change` | none | n/a | n/a | PASS (account-wide), GAP (per-bucket) |
| Y | Edge Function JWT verification changed | edge_function | verify_jwt | Yes | Yes | `_classify_edge_function_change` | `supabase_edge_function_jwt_disabled` | Yes | full | PASS |
| Z | Edge Function added/removed | edge_function | whole record | Yes | Yes | same | n/a | n/a | n/a | PASS |
| AA | Edge Function secret count only | edge_function | env_var_key_count | Yes (count only, never values) | Yes | same | n/a | n/a | n/a | PASS |
| AB | Realtime anonymous access | n/a | n/a — no Realtime record type exists; not modeled by the connector at all | No | No | n/a | n/a | n/a | n/a | GAP (documented, not invented — no Realtime API surface is fetched) |
| AC | Unknown Boolean | rls_status | rls_enabled unknown | n/a (connector always emits a real bool today) | n/a | `_eval_rls`'s `"rls_enabled" in record` guard correctly skips | n/a | n/a | n/a | PASS (Finding side); connector-level default-to-False flagged for message 2 |
| AD | Unknown numeric count | auth_config | jwt_exp / oauth_provider_count / etc. | n/a (connector always emits int or None) | Yes | all use safe `int(x)` + try/except, no `or 0` coercion | n/a | n/a | n/a | PASS |
| AE | Unknown list vs. empty list | storage_config | allowed_mime_types | Yes | Yes | `_classify_storage_config_change` distinguishes `None` (never configured→ "high", any type allowed) from `[]` (explicit removal→ same "high" branch, intentional: both mean "no restriction") | n/a | n/a | n/a | PASS |
| AF | Optional endpoint 403/404 | rls_status, network_restriction, edge_function, custom_domain | — | Fail-soft confirmed; 3 endpoints' placeholder-record bug fixed this pass | n/a | n/a | n/a | n/a | n/a | **FIXED** |
| AG | Unsupported plan response | any singleton config | — | Treated identically to 403 (warning + empty data, real record_id kept) — Management API doesn't distinguish plan-gating from permission failure in the connector's current handling, documented as a known limitation (both surface as HTTP 403/404 from the API) | n/a | n/a | n/a | n/a | n/a | GAP (documented — API doesn't expose a distinguishable error) |
| AH | Real `compute_diff()` provider metadata | rls_status, edge_function, network_restriction, custom_domain, oauth_provider | table_name/schema_name, function_name/slug, cidr, custom_domain, provider_name | Yes | **Was missing → Fixed** | all 5 classifiers | n/a | n/a | n/a | **FIXED** |
| AI | Normalized-but-untracked field | rls_status | policy_count + 5 boolean policy fields | Yes | **Was No → Fixed** | `_classify_rls_status_change` | see T | Yes | full | **FIXED** |
| AJ | Tracked-but-not-emitted field | n/a | none found across all 10 types | n/a | n/a | n/a | n/a | n/a | n/a | PASS |
| AK | Unreachable Security Finding | n/a | none — all 10 rules confirmed reachable | n/a | n/a | n/a | n/a | n/a | n/a | PASS |
| AL | Record with no Finding | project, database_config, storage_config, api_config, network_restriction, custom_domain, oauth_provider | — | Yes | Yes | dedicated classifiers | none (intentional) | n/a | n/a | PASS (intentional, not a gap) |
| AM | Registry/evaluator/frontend parity | all 10 rule keys | n/a | n/a | n/a | n/a | all 10 | Yes | **full — reconfirmed this pass** | PASS |
| AN | Sensitive-data minimization | all 10 live types | tokens/secrets/keys/rows/PII | Never stored (verified) | n/a | n/a | n/a | n/a | n/a | PASS |
| AO | Runtime/activity data separated from static drift | n/a | organization audit-log events (M71B) | Yes (separate pipeline) | n/a — feeds signals/correlations, not compute_diff | n/a | n/a | n/a | n/a | PASS |

## Test results

- Exact Supabase test files (8 pre-existing files, 166 tests) → **all pass**
- New `test_supabase_detection_qa.py` → **17 passed**
- Combined exact-file run (9 files) → **183 passed**
- `pytest -k "supabase"` against the full `tests/` directory repeatedly
  hung/timed out (both the bare `-k "supabase"` filter and `-k "supabase
  and auth"`), despite every individual exact Supabase file running in
  well under 4 seconds. Per the task's explicit instruction ("If `-k
  supabase` is slow, stop it and rely on exact files as authoritative. Do
  not replace it with broader filters"), these broad-suite filters were
  stopped and the exact-file run above was treated as authoritative.
  `-k "supabase and rls"` (a filter still scoped to `tests/` broadly) did
  complete quickly (28 passed in 2.01s), suggesting the slowness is
  specific to certain filter/collection combinations against the full
  17,000+ test suite rather than anything in the Supabase test files
  themselves — flagged as a pre-existing test-suite performance
  characteristic, not a Supabase-specific defect.

No zero-selection filters were encountered among the filters that did
complete. Frontend was not touched this pass — no new/changed Security
Finding rules — `npx tsc --noEmit` was not run (not required).

## Files changed this pass

- `backend/app/connectors/supabase.py` — removed the `_access_denied`
  synthetic-placeholder pattern from `_fetch_rls_status`,
  `_fetch_network_restrictions`, and `_fetch_edge_functions` (now return
  `[]` on 403, matching `_fetch_custom_domain`'s safer precedent).
- `backend/app/services/diff_service.py` — added the 6 missing M71A
  policy-posture fields to `_SUPABASE_TRACKED_FIELDS_BY_TYPE["supabase_
  rls_status"]`; added a Supabase-specific provider_metadata stanza for 5
  record types.
- `backend/app/services/risk_rules/supabase.py` — added classifier
  branches for the 6 newly-tracked RLS policy fields.
- `backend/tests/test_supabase_detection_qa.py` — new, 17 regression
  tests.
- `backend/tests/reports/supabase_detection_matrix.md` — this report
  (new).

## Safe to push?

Not evaluated (push explicitly out of scope). All exact Supabase test
files pass; no unrelated files touched or staged. Live Supabase
Management API validation remains advisable to confirm the actual API
response shapes assumed by the connector (particularly whether
`rls_enabled` is genuinely always present for real tables, and whether
`/database/tables` ever omits fields for view-like objects), since this
audit could only verify behavior against constructed test fixtures, not a
live project.
