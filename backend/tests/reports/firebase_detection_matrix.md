# Firebase Detection-QA Matrix

Scope: **detection only** — connector normalization, diff reachability,
classifier routing, Security Finding reachability, registry/frontend
parity, provider metadata, sensitive-data minimization, and fail-soft
behavior. Exhaustive transition-severity, restoration, and numeric/list
edge-case review is reserved for the dedicated Firebase change-
classification pass (message 2) and is **not** covered here.

## Graphify summary

All four required queries ran successfully via
`/Users/rohan/.local/bin/graphify`. Per the task's instruction, success was
**not** treated as evidence the graph has refreshed. The graph confirmed
`FirebaseConnector` (backend/app/connectors/firebase.py:395),
`risk_rules/firebase.py` ("Firebase risk classification rules — M53"), a
Firebase security-rules module ("M60.4 / fixed + expanded in M60.4.4"), a
"Firebase provider depth QA" node, and schema nodes
`FirebaseAppCheckConfigRecord`/`FirebaseRemoteConfigTemplateRecord`. Useful
hints surfaced: `firebase_no_public_writes`-style rule-key naming, "Password
protection added — security hardening — Low" (a restoration-direction
convention), and test-assertion nodes "Firestore document read/list/query
APIs must not appear in the connector" / "Storage rules that require auth
must NOT be classified as public." The graph is coarse (class/docstring-
level, not field/diff-level) and did not surface either of the two
headline bugs found in this pass (the unreachable `firebase_auth_provider`
record type, or the completely undispatched `firebase_database_ruleset`
classifier) — direct source reads and real `compute_diff()` execution were
authoritative for everything in this report.

## Record-type inventory

**13 record types are defined in `firebase_schema.py`. All 13 are
reachable from `FirebaseConnector.fetch()`** — unlike GitHub (6/16),
Stripe (6/17), and Vercel (5/12) in earlier passes this session, Firebase
matches Supabase's pattern of full schema-to-connector coverage. However,
one of the 13 (`firebase_auth_provider`) was schema-defined, fully
classified, and diff-tracked, yet the connector never actually *built* a
record for it (see root-cause bug #1 below) — now fixed.

| # | Record type | Endpoint | Scope |
|---|---|---|---|
| 1 | `firebase_project` | `GET firebase.googleapis.com/v1beta1/projects/{id}` | project (singleton, required) |
| 2 | `firebase_auth_config` | `GET identitytoolkit.googleapis.com/admin/v2/projects/{id}/config` | project (singleton, optional) |
| 3 | `firebase_auth_provider` | derived from `inboundSamlConfigs` + `oauthIdpConfigs` list responses (same calls the count fields already used) | project, one per SAML/OIDC provider — **fixed this pass, was never emitted** |
| 4 | `firebase_authorized_domain` | derived from auth config's `authorizedDomains` list | project, one per domain |
| 5 | `firebase_firestore_ruleset` | `GET firebaserules.googleapis.com/v1/projects/{id}/releases` (+ ruleset content) | project, one per active release |
| 6 | `firebase_database_ruleset` | `GET firebasedatabase.googleapis.com/v1beta/projects/{id}/locations/-/instances` (+ `.settings/rules.json` per instance) | project, one per RTDB instance (M72A, only attempted when `has_realtime_db`) |
| 7 | `firebase_storage_bucket` | `GET storage.googleapis.com/storage/v1/b?project={id}` | project, one per GCS bucket |
| 8 | `firebase_storage_ruleset` | same `releases` endpoint as Firestore, filtered to `firebase.storage` | project, one per active release |
| 9 | `firebase_hosting_site` | `GET firebasehosting.googleapis.com/v1beta1/projects/{id}/sites` | project, one per site |
| 10 | `firebase_hosting_domain` | `GET .../sites/{site}/domains` | project, one per custom domain |
| 11 | `firebase_function_metadata` | `GET cloudfunctions.googleapis.com/v1/projects/{id}/locations/-/functions` | project, one per function |
| 12 | `firebase_remote_config_template` | `GET firebaseremoteconfig.googleapis.com/v1/projects/{id}/remoteConfig` | project (singleton, M57.8) |
| 13 | `firebase_app_check_config` | `GET firebaseappcheck.googleapis.com/v1beta/projects/{id}/services` | project (singleton, M57.8) |

**Side-channel activity ingestion** (M72B): `list_audit_log_events`-
equivalent Cloud Logging `entries:list` POST call feeds
`app/services/firebase_activity_ingestion_service.py` — a separate
pipeline from `fetch()`/`compute_diff()`, never becomes a drift `Change`.
Documented, not a gap.

## Root-cause bugs found and fixed this pass

1. **`firebase_auth_provider` was schema-defined with a full classifier
   (`_classify_auth_provider_change`) and diff-tracked fields, but the
   connector never built a record for it.** `_fetch_auth_config()` called
   the `inboundSamlConfigs`/`oauthIdpConfigs` list endpoints only to count
   the results (`saml_count`/`oidc_count`), discarding the actual
   per-provider objects. **No new endpoint call was needed** — the data was
   already in scope. **Fixed**: build one `firebase_auth_provider` record
   per SAML/OIDC entry, storing only `provider_id` (parsed from the
   resource `name`), `provider_type` ("saml"/"oidc"), and `enabled` — never
   `clientSecret`/`clientId`/IdP certificate material (confirmed via a
   regression test that inspects the emitted record's exact key set).
2. **`firebase_database_ruleset` (Realtime Database rules, M72A) is
   connector-emitted, and its Security Findings
   (`firebase_database_public_read`/`firebase_database_public_write`)
   already fire correctly — but it had NO entry in `_FIREBASE_TRACKED_
   FIELDS_BY_TYPE` and NO dispatch branch in `classify_firebase_change()`
   at all.** Every Change for this record type — including a transition to
   public read/write, one of the most security-critical events this
   provider can detect — silently fell to the generic `"A Firebase
   configuration record changed (...)"` low-severity fallback. Confirmed
   live via `compute_diff()` before fixing (0 changes detected for a
   `public_write_detected` transition). **Fixed**: added tracked fields and
   a dedicated classifier (`_classify_database_ruleset_change`) mirroring
   `_classify_firestore_ruleset_change`/`_classify_storage_ruleset_change`'s
   structure, plus dispatch wiring. Confirmed the Security Finding side was
   already correct — no registry/pack/confidence/coverage/frontend changes
   were needed for `firebase_database_public_read`/`_write`.
3. **`_build_provider_metadata()` had no Firebase-specific stanza** — four
   classifiers read identifying fields directly from `provider_metadata`
   that the generic `record_name`/`record_content` stanza never populates
   (these records don't carry a `"name"` field usable for this purpose):
   `_classify_auth_provider_change` (`provider_id`), `_classify_authorized_
   domain_change` (`domain`/`is_default_firebase_domain`/`is_localhost`),
   `_classify_hosting_domain_change` (`domain`/`domain_type`),
   `_classify_function_metadata_change` (`function_name`). **Fixed**: added
   a Firebase-specific stanza for all four record types.

## Confirmed correct, no fix needed

- `classify_firebase_change()`'s dispatcher correctly routes all (now) 13
  record types to dedicated classifiers with a safe, Firebase-specific
  fallback (`f"A Firebase configuration record changed ({record_type})."`)
  — never a Supabase/Cloudflare/other-provider fallback.
- No `_access_denied`-style synthetic-placeholder-record pattern (the mass-
  false-removal bug found and fixed in Supabase's detection-QA pass) exists
  anywhere in the Firebase connector — every optional per-item-list
  endpoint (`_fetch_firebase_rules`, `_fetch_storage_buckets`,
  `_fetch_hosting`, `_fetch_cloud_functions`, `_fetch_database_rules`)
  returns a plain `[]` on 403/404, never a fabricated record with a
  mismatched ID.
- All 401/403 handling is correctly split (`AuthenticationError` for 401,
  `ConnectorError(status_code=403)` for permission-denied), consistently
  caught per-surface so one subsystem's failure never suppresses another's
  records (confirmed by reading `fetch()`'s structure — each of the 8
  optional surfaces is wrapped in its own `try`/`except`).
- No `int(x or 0)` unknown-as-zero numeric coercion exists anywhere in
  `risk_rules/firebase.py` — all count comparisons (parameter/condition
  counts, custom domain counts, etc.) use direct value access without
  arithmetic-unsafe defaults.
- Raw rules source, Firestore/RTDB/Storage contents, function source,
  environment variable values, and OAuth/SAML client secrets are
  confirmed never fetched or stored (verified via source read + grep;
  see Sensitive-Data section below).

## Flagged for the Firebase message-2 pass (not fixed here — matches this session's established message-1/message-2 boundary)

Consistent with how the identical class of issue was deferred in every
other provider's detection-QA pass this session (GitHub, Stripe, Supabase):

- **Connector-level boolean defaulting**: `sign_in_email_enabled`,
  `sign_in_phone_enabled`, `anonymous_enabled` (`_fetch_auth_config`), and
  the newly-added `firebase_auth_provider.enabled` all coerce a missing API
  field to `False` via `bool(x.get("enabled", False))` — the same pattern
  found and fixed (connector + classifier together) in Supabase's message-2
  pass. Fixing only the connector side here (without also auditing every
  classifier's `if new_v is False: ...; else: ...` unconditional-else
  branches) would risk the same "half-fix creates a worse inconsistency"
  problem documented in the Supabase report, so both sides are deferred
  together to Firebase message 2.
- **`_fetch_firebase_rules`'s ruleset-content-fetch-failure default**: when
  the release *list* succeeds but an individual ruleset's *content* fetch
  fails, `public_read_detected`/`public_write_detected`/`authenticated_
  only_detected` fall back to their initial `False` values (with
  `parser_confidence` correctly set to `"low"`). The Security Finding side
  already guards against this (`_eval_ruleset`/`_eval_database_ruleset`
  skip firing when `parser_confidence == "low"`), but the Change
  classifier does not check `parser_confidence` at all — a transition to
  these default-`False` values under a fetch failure could be reported as
  "security improved" when the true rules content is actually unknown.
  This is a classifier-severity/copy nuance (the connector's `False`
  default here reflects a real inability to determine the rules' content,
  parallel to the auth-boolean case above), deferred to message 2 for the
  same reason.

## Diff tracking — tracked vs. emitted vs. classified

| Record type | Tracked fields | Gap found | Status |
|---|---|---|---|
| `firebase_project` | 5 fields + config_fetch_warnings | none | full parity |
| `firebase_auth_config` | 8 fields + config_fetch_warnings | none | full parity |
| `firebase_auth_provider` | `enabled`, `provider_type` + config_fetch_warnings | **was unreachable (0 records ever emitted) → fixed** | **FIXED** |
| `firebase_authorized_domain` | 3 fields + config_fetch_warnings | none | full parity |
| `firebase_firestore_ruleset` | 8 fields + config_fetch_warnings | none | full parity |
| `firebase_database_ruleset` | **was empty (no entry at all) → fixed to 8 fields** | **FIXED this pass** | see root-cause #2 |
| `firebase_storage_bucket` | 5 fields + config_fetch_warnings | none | full parity |
| `firebase_storage_ruleset` | 8 fields + config_fetch_warnings | none | full parity |
| `firebase_hosting_site` | 3 fields + config_fetch_warnings | none | full parity (`site_id` correctly excluded — part of record_id) |
| `firebase_hosting_domain` | `domain_type`, `status` + config_fetch_warnings | none | full parity (`domain` correctly excluded — part of record_id, now in provider_metadata) |
| `firebase_function_metadata` | 4 fields + config_fetch_warnings | none | full parity (`region` correctly excluded — part of record_id) |
| `firebase_remote_config_template` | 8 fields + config_fetch_warnings | none | full parity |
| `firebase_app_check_config` | 3 fields (+ `enforced_service_names` intentionally untracked — see below) | intentional | see below |

**Normalized-but-intentionally-untracked field**: `firebase_app_check_
config.enforced_service_names` (a list of service API name strings) is
normalized by the connector but not in the tracked-fields tuple — the
aggregate counts (`enforced_service_count`/`unenforced_service_count`,
both tracked) already capture the security-relevant signal; tracking the
list itself would only add reordering-sensitivity noise without a clear
additional detection benefit. Documented as intentional, not a gap.

**Tracked-but-not-emitted fields**: none found — every tracked field name
matches a field the corresponding `_fetch_*` method actually populates,
across all 13 record types.

**Stale/confusing field names**: none found.

## Security Finding reachability (8 rules, all confirmed reachable)

| Rule key | Record type | Trigger | Severity | Reachable? | Registry/pack/confidence/coverage/frontend parity |
|---|---|---|---|---|---|
| `firebase_rules_public` | firestore_ruleset | `public_read_detected` or `public_write_detected` is True, confidence != low | critical (write) / high (read) | Yes | full |
| `firebase_storage_rules_public` | storage_ruleset | same | critical (write) / high (read) | Yes | full |
| `firebase_database_public_read` | database_ruleset | `public_read_detected is True`, confidence != low | high | Yes (Change side newly fixed this pass — Finding side already worked) | full |
| `firebase_database_public_write` | database_ruleset | `public_write_detected is True`, confidence != low | critical | Yes (same) | full |
| `firebase_anonymous_auth_enabled` | auth_config | `anonymous_enabled is True` | medium | Yes | full |
| `firebase_auth_protection_missing` | auth_config | `mfa_enabled is False` | medium | Yes | full |
| `firebase_storage_public_access_prevention_disabled` | storage_bucket | `public_access_prevention == "inherited"` (explicit, not missing) | high | Yes | full |
| `firebase_app_check_unenforced_services` | app_check_config | `unenforced_service_count > 0` | medium | Yes | full |

All 8 keys verified present with matching severity/category across
`security_rule_registry.py`, `security_rule_pack.py`,
`security_rule_confidence.py`, `security_coverage_service.py`, and
`frontend/src/lib/securityRuleCatalog.ts`. `test_firebase_provider_depth_
qa.py::test_stripe_rule_key_count`-equivalent guardrail
(`len(ALL_FIREBASE_RULE_KEYS) == 8`) reconfirmed accurate — no drift.

**Deliberately deferred rules** (documented in `security_rules/
firebase.py`'s own docstring, reconfirmed accurate this pass, not gaps to
fix): "unsafe auth provider" (provider_type/enabled alone aren't inherently
unsafe — `anonymous_enabled` is the clear signal already used), and API-key
restriction ("there is no `firebase_api_key` / web-app-config record type,
so this cannot be evaluated" — confirmed accurate, no such record type is
modeled).

**Records with no Security Finding**: `firebase_project`,
`firebase_auth_provider`, `firebase_authorized_domain`, `firebase_hosting_
site`, `firebase_hosting_domain`, `firebase_function_metadata`,
`firebase_remote_config_template` — all Change-only, consistent with these
being operational/business-configuration surfaces without a single
unambiguous "this state is inherently risky" signal (or, for authorized
domains, deliberately deferred per the schema docstring since raw
wildcard/localhost redirect patterns aren't stored in a form that could be
safely evaluated beyond the boolean flags already present).

## Fail-soft and partial-sync behavior

- 401 → hard `AuthenticationError` (invalid/revoked service account token).
- 403 → `ConnectorError(status_code=403)`, caught individually by every
  optional surface's own `try`/`except` in `fetch()` — one subsystem's
  permission failure never suppresses another's records.
- 404 → distinguished from 403 for Remote Config (`"Remote Config not
  enabled for this project"` returns `[]` without a warning, versus 403
  which logs a permission warning).
- 429 → retried with bounded `_MAX_RETRIES` attempts honoring
  `Retry-After`, then raises `RateLimitError`.
- 5xx → retried, then raises `ConnectorError` with the status code
  preserved.
- `_fetch_database_rules` is only attempted when `project_record.get(
  "has_realtime_db")` is true — avoids a spurious 404 storm for the common
  case of projects without a Realtime Database instance.
- Optional per-instance/per-ruleset sub-fetch failures (e.g. one RTDB
  instance's rules can't be read) are caught individually per-item and
  skipped with a warning, not propagated to fail the whole surface.

## Sensitive-data minimization

Confirmed via direct source read and grep: `credentials["private_key"]`/
`access_token` are used only for signing the OAuth2 JWT and the
`Authorization: Bearer` header, never persisted in any record. OAuth/SAML
`clientSecret`/`clientId`/IdP certificate material are never read from the
newly-added `firebase_auth_provider` normalization (confirmed via a
regression test asserting the exact key set of an emitted record). Raw
Firestore/Storage/RTDB security-rules source is fetched only transiently
to compute a SHA-256 hash and a conservative public/private classification
— the raw source is never stored (confirmed: `_analyze_rules`/
`_analyze_rtdb_rules` return only hash/booleans/summary, never the source
string itself, and the connector never assigns the raw source to any
record field). Cloud Function environment variable values, Remote Config
parameter values and condition expressions, project numbers (hashed),
ruleset names (hashed), and bucket names (hashed) are never stored raw.
Firestore documents, RTDB data, and Storage objects are never read, listed,
or downloaded.

## Copy safety

No forbidden phrases (breach, compromise, database exposed, user data
leaked, etc.) found anywhere in Firebase evidence/copy across
`risk_rules/firebase.py`, `security_rules/firebase.py`, or the connector.
Every Security Finding description includes an explicit "does not confirm
data exposure, unauthorized access, or compromise" (or equivalent)
disclaimer.

## Detection matrix (lettered cases A–AQ)

| Case | Category | Record type | Field(s) | Emits evidence? | Detected by `compute_diff`? | Classifier route | Finding key | Reachable? | Parity | Status |
|---|---|---|---|---|---|---|---|---|---|---|
| A | Project state | project | lifecycle_state | Yes | Yes | `_classify_project_change` | n/a | n/a | n/a | PASS |
| B | Firebase app added/removed | n/a | no `firebase_app`/Web-App record type is modeled — connector doesn't fetch `/webApps`/`/androidApps`/`/iosApps` | No (by design) | No | n/a | n/a | n/a | n/a | GAP (documented, not invented — matches schema, which has no such type) |
| C | Anonymous Auth changed | auth_config | anonymous_enabled | Yes | Yes | `_classify_auth_config_change` | `firebase_anonymous_auth_enabled` | Yes | full | PASS |
| D | Email/password provider changed | auth_config | sign_in_email_enabled | Yes | Yes | same | n/a | n/a | n/a | PASS |
| E | Phone provider changed | auth_config | sign_in_phone_enabled | Yes | Yes | same | n/a | n/a | n/a | PASS |
| F | MFA enabled/disabled | auth_config | mfa_enabled | Yes | Yes | same | `firebase_auth_protection_missing` | Yes | full | PASS |
| G | Password minimum length | n/a | not modeled — Identity Toolkit admin/v2 config endpoint used here doesn't expose a password-policy sub-object in this connector's current scope | No (by design) | No | n/a | n/a | n/a | n/a | GAP (documented, not invented) |
| H | Email-enumeration protection | n/a | not modeled — same rationale as G | No | No | n/a | n/a | n/a | n/a | GAP (documented) |
| I | Authorized domain added/removed | authorized_domain | whole record | Yes | Yes | `_classify_authorized_domain_change` | n/a | n/a | n/a | PASS |
| J | Wildcard/localhost domain posture | authorized_domain | is_localhost, is_default_firebase_domain | Yes | Yes | same | n/a (deferred, documented) | n/a | n/a | PASS (Change-only, intentional) |
| K | Firestore public read | firestore_ruleset | public_read_detected | Yes | Yes | `_classify_firestore_ruleset_change` | `firebase_rules_public` (high) | Yes | full | PASS |
| L | Firestore public write | firestore_ruleset | public_write_detected | Yes | Yes | same | `firebase_rules_public` (critical) | Yes | full | PASS |
| M | Firestore rule hash changed | firestore_ruleset | rules_hash | Yes | Yes | same | n/a | n/a | n/a | PASS |
| N | Firestore rules unavailable | firestore_ruleset | (fetch failure → parser_confidence="low", public_*_detected=False) | Yes (fail-soft) | Yes (as a Change, but see message-2 flag re: parser_confidence) | same | Finding correctly skips low-confidence | n/a | n/a | GAP/flagged for message 2 |
| O | RTDB public read | database_ruleset | public_read_detected | Yes | **Was No → Fixed** | `_classify_database_ruleset_change` (new) | `firebase_database_public_read` (already worked) | Yes | full | **FIXED** |
| P | RTDB public write | database_ruleset | public_write_detected | Yes | **Was No → Fixed** | same | `firebase_database_public_write` (already worked) | Yes | full | **FIXED** |
| Q | RTDB rules unavailable | database_ruleset | same as N | Yes | Yes (now, post-fix) | same | Finding correctly skips low-confidence | n/a | n/a | GAP/flagged for message 2 (same as N) |
| R | Storage public access | storage_bucket | public_access_prevention | Yes | Yes | `_classify_storage_bucket_change` | `firebase_storage_public_access_prevention_disabled` | Yes | full | PASS |
| S | Storage public → private | storage_bucket | same | Yes | Yes | same | n/a (Finding only fires on the disabled direction) | n/a | n/a | PASS |
| T | Storage rules changed | storage_ruleset | public_read_detected/public_write_detected/rules_hash | Yes | Yes | `_classify_storage_ruleset_change` | `firebase_storage_rules_public` | Yes | full | PASS |
| U | Function authentication changed | n/a | not modeled — connector doesn't fetch IAM invoker bindings for functions in current scope | No (by design) | No | n/a | n/a | n/a | n/a | GAP (documented, not invented) |
| V | Function ingress changed | n/a | not modeled — same rationale as U | No | No | n/a | n/a | n/a | n/a | GAP (documented) |
| W | Function added/removed | function_metadata | whole record | Yes | Yes | `_classify_function_metadata_change` | n/a | n/a | n/a | PASS |
| X | Function secret/env counts only | function_metadata | env_var_key_count (values never stored) | Yes | Yes | same | n/a | n/a | n/a | PASS |
| Y | Hosting HTTPS/domain posture | hosting_domain | domain_type, status | Yes | Yes | `_classify_hosting_domain_change` | n/a | n/a | n/a | PASS |
| Z | App Check enforcement changed | app_check_config | unenforced_service_count | Yes | Yes | `_classify_app_check_change` | `firebase_app_check_unenforced_services` | Yes | full | PASS |
| AA | Remote Config version/hash changed | remote_config_template | version_number, parameter_keys_hash | Yes | Yes | `_classify_remote_config_change` | n/a | n/a | n/a | PASS |
| AB | API key restriction posture | n/a | no `firebase_api_key` record type exists (documented deferral in security_rules/firebase.py) | No (by design) | No | n/a | none (deliberately deferred) | n/a | n/a | GAP (documented, not invented) |
| AC | Unknown Boolean | auth_config, auth_provider | sign_in_email_enabled, enabled | n/a (connector currently always emits a real bool; missing→False coercion flagged for message 2) | n/a | n/a | n/a | n/a | n/a | GAP/flagged for message 2 |
| AD | Unknown numeric count | remote_config_template | parameter_count | n/a (connector always emits len() of a real dict/list) | n/a | already safe | n/a | n/a | n/a | PASS |
| AE | Unknown list vs. empty | app_check_config | enforced_service_names | Yes (intentionally untracked, see above) | n/a | n/a | n/a | n/a | n/a | PASS (intentional) |
| AF | Added risky record | database_ruleset, auth_provider | whole record with a risky posture from creation | Yes | Yes (post-fix) | dedicated classifiers | see O/P | n/a | n/a | PASS (post-fix; message-2 will audit whether "added" branches inspect posture as thoroughly as GitHub/Stripe/Supabase's fixes did) |
| AG | Removed protective record | firestore_ruleset, database_ruleset, storage_ruleset | whole record | Yes | Yes | dedicated classifiers (all use "high — investigate" on removal) | n/a | n/a | n/a | PASS |
| AH | Optional endpoint 403/404 | all 8 optional surfaces | — | Fail-soft confirmed; no `_access_denied` sentinel pattern anywhere | n/a | n/a | n/a | n/a | n/a | PASS |
| AI | Disabled API response | remote_config_template | 404 = "not enabled" (distinct from 403 permission-denied) | Yes | n/a | n/a | n/a | n/a | n/a | PASS |
| AJ | Real provider metadata | auth_provider, authorized_domain, hosting_domain, function_metadata | provider_id, domain/is_default/is_localhost, domain/domain_type, function_name | Yes | **Was missing → Fixed** | all 4 classifiers | n/a | n/a | n/a | **FIXED** |
| AK | Normalized-but-untracked field | app_check_config | enforced_service_names | Yes | n/a (intentional) | n/a | n/a | n/a | n/a | PASS (intentional) |
| AL | Tracked-but-not-emitted field | n/a | none found across all 13 types | n/a | n/a | n/a | n/a | n/a | n/a | PASS |
| AM | Unreachable Finding | n/a | none — all 8 rules confirmed reachable | n/a | n/a | n/a | n/a | n/a | n/a | PASS |
| AN | Record with no Finding | project, auth_provider, authorized_domain, hosting_site, hosting_domain, function_metadata, remote_config_template | — | Yes | Yes | dedicated classifiers | none (intentional) | n/a | n/a | PASS (intentional, not a gap) |
| AO | Registry/evaluator/frontend parity | all 8 rule keys | n/a | n/a | n/a | n/a | all 8 | Yes | **full — reconfirmed this pass** | PASS |
| AP | Sensitive-data minimization | all 13 live types | tokens/secrets/keys/rows/PII/rules source | Never stored (verified) | n/a | n/a | n/a | n/a | n/a | PASS |
| AQ | Runtime/activity data separated from static drift | n/a | Cloud Logging entries:list (M72B) | Yes (separate pipeline) | n/a — feeds signals/correlations, not compute_diff | n/a | n/a | n/a | n/a | PASS |

## Test results

- Exact Firebase test files (8 pre-existing files, 145 tests) → **all pass**
- New `test_firebase_detection_qa.py` → **12 passed**
- Combined exact-file run (9 files) → **157 passed**
- Narrow filters (foreground, with timeout guards, none timed out):
  - `-k "firebase and auth"` → 31 passed (2.24s)
  - `-k "firebase and firestore"` → 17 passed (1.70s)
  - `-k "firebase and storage"` → 14 passed (1.71s)
  - `-k "firebase and function"` → 8 passed (1.68s)
  - `-k "firebase and diff"` → 15 passed (1.72s)
  - `-k "firebase and risk"` → 116 passed (2.22s)
- Two pre-existing, unrelated-to-this-pass stale test failures were
  discovered while checking for hidden stale tests outside the exact-file
  glob (matching the pattern that caught similar issues in Supabase's
  passes):
  - `tests/test_milestone53.py::TestNoForbiddenApiReferences::
    test_connector_module_does_not_call_data_write_apis` — asserted exactly
    one `httpx.post` call (OAuth2 token exchange), but a second, legitimate,
    read-only `httpx.post` call was added later for Cloud Logging's
    `entries:list` API (M72B activity ingestion). Confirmed via `git stash`
    that this failure predates this pass's changes entirely. **Fixed** —
    the assertion now correctly expects and verifies both calls are safe
    (token exchange + read-only log query), not a data-mutating API.
  - `tests/test_milestone57_8.py::TestSupabaseAuthSecurityDepth::
    test_missing_m578_fields_default_to_false` — a **Supabase** test
    (unrelated to Firebase) broken by the prior Supabase change-
    classification QA session's intentional fix (missing auth fields now
    preserve `None` instead of defaulting to `False`). Out of scope for
    this Firebase-only pass and left untouched to avoid staging unrelated
    Supabase files; flagged via a spawned follow-up task instead.

No zero-selection or timed-out filters. Frontend was not touched this
pass — no new/changed Security Finding rules — `npx tsc --noEmit` was not
run (not required).

## Files changed this pass

- `backend/app/connectors/firebase.py` — build `firebase_auth_provider`
  records from already-fetched SAML/OIDC list data (no new endpoint calls).
- `backend/app/services/diff_service.py` — added `firebase_database_
  ruleset` tracked-fields entry; added a Firebase-specific provider_
  metadata stanza for 4 record types.
- `backend/app/services/risk_rules/firebase.py` — added `_classify_
  database_ruleset_change()` and its dispatch wiring.
- `backend/tests/test_firebase_detection_qa.py` — new, 12 regression
  tests.
- `backend/tests/test_milestone53.py` — fixed 1 pre-existing stale
  assertion (unrelated to this pass's Firebase fixes, discovered during
  testing).
- `backend/tests/reports/firebase_detection_matrix.md` — this report
  (new).

## Safe to push?

Not evaluated (push explicitly out of scope). All exact and narrow
Firebase test filters pass; the one unrelated Supabase test failure
discovered was left untouched and flagged separately, per hygiene
instructions to stage only Firebase-scoped files. Live Firebase/GCP
validation remains advisable to confirm the real Management API response
shapes assumed by this pass's fixes (in particular, the exact `name` field
format for `inboundSamlConfigs`/`oauthIdpConfigs` list entries, which this
pass's provider_id parsing assumes ends in `/{provider_id}`).
