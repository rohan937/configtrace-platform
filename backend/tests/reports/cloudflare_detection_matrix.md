# Cloudflare detection QA report

Exhaustive end-to-end QA pass on the Cloudflare provider: connector → diff
tracking → risk-classifier routing → Security Finding reachability →
registries → frontend catalog. This is the **detection-QA** pass (message 1
of 2) — exhaustive severity/restoration/unknown-value calibration is
reserved for the dedicated classification-QA pass (message 2).

## Summary

Cloudflare's connector is unusually mature: **all 9 normalized record
types** defined in `cloudflare_schema.py` are genuinely wired into the
connector's live `fetch()` path (unlike several recently-audited providers
where schema-defined types were never actually fetched). Both risk-rule
modules (`cloudflare_dns.py` for DNS records + rulesets, `cloudflare.py` for
the 7 "M59.5/M59.7 expansion" surfaces) are fully built out with rich,
well-tested classification logic for every field.

**One critical, systemic bug was found and fixed**: `diff_service.py`'s
`_CLOUDFLARE_TRACKED_FIELDS_BY_TYPE` only had an entry for
`cloudflare_ruleset`. The other **7 record types**
(`cloudflare_zone_setting`, `cloudflare_page_rule`,
`cloudflare_worker_route`, `cloudflare_worker_script`,
`cloudflare_access_application`, `cloudflare_access_policy`,
`cloudflare_waf_rule`) silently fell back to the DNS-record `_TRACKED_FIELDS`
tuple (`record_type, name, content, ttl, proxied, priority, comment`) via a
`.get(rt, _TRACKED_FIELDS)` default — a fallback pattern unique to Cloudflare
among all providers in this codebase (every other provider defaults to `()`
for an unrecognized subtype). Since none of these 7 record shapes share more
than incidental field names with DNS records, **compute_diff() produced
zero Change rows for real drift** on any of them — e.g. a zone's SSL mode
going `strict → off` (a critical security downgrade with a fully-built
classifier already handling it) was completely undetected. Verified live
via real `compute_diff()` calls before and after the fix.

Two supporting bugs were also found and fixed:
1. **PagerDuty-style unknown-to-zero coercion** (8 occurrences across both
   risk modules: `skip_count`/`block_count`/`enabled_rule_count`/
   `rule_count`/`challenge_count`/`managed_challenge_count` in
   `cloudflare_dns.py`'s ruleset classifier, plus `env_var_count`/
   `allowed_idps_count`/`include_count` in `cloudflare.py`) — all used
   `int(value or 0)`, silently treating a genuinely unknown baseline as `0`.
2. **Stale `old_value` mock-shape bug**: `classify_cloudflare_ruleset_change`
   had a legacy `old_value` fallback that is not a real field anywhere in
   the codebase, and interacted dangerously with `MagicMock`-based test
   doubles (MagicMock auto-vivifies unset attributes instead of returning
   `None`, so `int(MagicMock())` silently evaluates to `1`). Removing this
   fallback surfaced a genuine pre-existing test bug: `test_milestone57_7.py`'s
   `_make_change()` helper built dicts keyed `"old_value"` instead of
   `"prev_value"` — the actual field real Change rows and real
   `compute_diff()` output use. Fixed both the production code and the test
   helper (13 call sites + 2 standalone dict literals).

## Normalized record types (all 9 confirmed live)

| Record type | Source endpoint | Stable ID | Fail-soft? |
|---|---|---|---|
| `A`/`AAAA`/`CNAME`/`MX`/... (bare Cloudflare type string) | `GET /zones/{id}/dns_records` (paginated) | Cloudflare's `id` (hex) | Core call — 401/403/404/429/5xx raise typed errors |
| `cloudflare_ruleset` | `GET /zones/{id}/rulesets` | Cloudflare's ruleset `id` | Yes — 401/403/404/422/timeout/network-error/bad-JSON/`success=false` all return `[]`, DNS unaffected |
| `cloudflare_zone_setting` | `GET /zones/{id}/settings/{setting_id}` (one call per setting) | `setting_id` | Yes, **per-setting** — one setting's 403 doesn't block the other 7 |
| `cloudflare_page_rule` | `GET /zones/{id}/pagerules` | Cloudflare's rule `id` | Yes (`_safe_get` skip-status pattern) |
| `cloudflare_worker_route` | `GET /zones/{id}/workers/routes` | Cloudflare's route `id` | Yes |
| `cloudflare_waf_rule` | `GET /zones/{id}/rulesets` (+ per-ruleset detail fallback) | Cloudflare's rule `id` | Yes — a single ruleset's detail-fetch failure only skips that ruleset's rules |
| `cloudflare_worker_script` | `GET /accounts/{id}/workers/scripts` (account-scoped) | script `id`/`name` | Yes; also skipped entirely if account-id resolution fails |
| `cloudflare_access_application` | `GET /accounts/{id}/access/apps` (account-scoped) | Cloudflare's app `id` | Yes |
| `cloudflare_access_policy` | `GET /accounts/{id}/access/apps/{app_id}/policies` (per-app) | Cloudflare's policy `id` | Yes — one app's policy-fetch failure doesn't block other apps |

`_safe_get()` is the shared fail-soft helper for all 7 "M59.7 expansion"
endpoints: it degrades to `None` (→ `[]`) on timeout, network error, HTTP
401/403/404/422, non-2xx, JSON-parse failure, or `success=false` — and never
logs the `Authorization` header, token, or raw response text. Account-scoped
surfaces (worker scripts, Access apps/policies) are skipped as a group only
if `_resolve_account_id()` itself fails; zone-scoped surfaces degrade
independently of each other and of DNS.

**Sensitive-data minimization confirmed intact** for all 9 types: no API
tokens/keys, no zone credentials, no Worker source code or secrets, no env
var values, no Access identity details beyond safe counts, no raw WAF
expressions (hash-only, `_hash_expression()`), no request/response payloads,
no headers, no cookies, no raw IP addresses beyond the DNS record's own
`content` field (which is the record's *intended* public value, not a
client IP), and no private certificate/key material. Page-rule redirect
targets are reduced to scheme+host via `_safe_redirect_target()` so an
embedded `?token=...` query string cannot reach `Snapshot.state`.

## Diff tracking (fixed)

| Record type | Normalized fields | Tracked before this pass | Tracked after this pass |
|---|---|---|---|
| DNS (bare type) | 7 fields (`record_type, name, content, ttl, proxied, priority, comment`) | 7/7 | 7/7 (no change) |
| `cloudflare_ruleset` | 12 fields (excl. `record_id`/`name`) | 11/11 tracked, `last_updated` intentionally excluded (updates on metadata-only changes) | 11/11 (no change) |
| **`cloudflare_zone_setting`** | 4 fields (excl. identity) | **0/2 — fell back to DNS fields, none matched** | **2/2** (`value`, `editable`) |
| **`cloudflare_page_rule`** | 5 fields (excl. identity) | **1/5 — only `priority` incidentally matched DNS's tuple** | **5/5** |
| **`cloudflare_worker_route`** | 3 fields (excl. identity) | **0/3 — fell back to DNS fields, none matched** | **3/3** |
| **`cloudflare_worker_script`** | 3 fields (excl. identity) | **0/3 — fell back to DNS fields, none matched** | **3/3** |
| **`cloudflare_access_application`** | 7 fields (excl. identity) | **1/7 — only `name` incidentally matched** | **7/7** |
| **`cloudflare_access_policy`** | 7 fields (excl. identity) | **1/7 — only `name` incidentally matched** | **7/7** |
| **`cloudflare_waf_rule`** | 4 fields (excl. identity) | **0/4 — fell back to DNS fields, none matched** | **4/4** |

No normalized field is tracked with no classifier branch, and no classifier
branch references a stale/nonexistent field name — verified by
cross-referencing every tracked field against every `field_path ==` check in
both `risk_rules/cloudflare.py` and `risk_rules/cloudflare_dns.py`.
`script_name` (worker script) and `application_id`/`ruleset_id` (foreign-key
identity fields) are intentionally not tracked, matching the established
convention of not diffing pure identity/key fields.

The final fallback for a genuinely-unrecognized `cloudflare_*` subtype was
also fixed: `.get(rt, _TRACKED_FIELDS)` → `.get(rt, ())`, matching every
other provider's convention (GitHub, Vercel, Stripe, AWS, ... all default to
`()` for unknown subtypes within their prefix).

## Classifier routing

- **DNS records** (bare type strings, e.g. `"A"`, `"CNAME"`) → fall through
  to `classify_dns_change()` in `cloudflare_dns.py` via `risk_service.py`'s
  final `return classify_dns_change(change)`. Confirmed correct — bare types
  never match any `cloudflare_`-prefixed branch.
- **`cloudflare_ruleset`** → explicit `record_type == "cloudflare_ruleset"`
  branch routes to `classify_cloudflare_ruleset_change()` in
  `cloudflare_dns.py`. Confirmed correct.
- **The 7 expansion surfaces** (`cloudflare_zone_setting`,
  `cloudflare_page_rule`, `cloudflare_worker_route`,
  `cloudflare_worker_script`, `cloudflare_access_application`,
  `cloudflare_access_policy`, `cloudflare_waf_rule`) → the catch-all
  `record_type.startswith("cloudflare_") and record_type !=
  "cloudflare_dns_record"` branch routes to `classify_cloudflare_change()`
  in `cloudflare.py`. Confirmed correct via 7 new real-`compute_diff()`
  integration tests (one per type).
- **No Cloudflare record reaches a generic unrelated-provider fallback.**
  The dispatch order in `risk_service.py` checks every other provider's
  prefix first, then Cloudflare-specific branches, then the DNS default —
  there is no path by which a `cloudflare_*` record type reaches, say, the
  GitHub or AWS classifier.
- **Unknown record types return safe generic behavior**: both
  `classify_cloudflare_change()` (unknown subtype → `"low"` + generic
  message) and `classify_dns_change()` handle unrecognized shapes without
  raising.
- Minor housekeeping note (not a bug): `CLOUDFLARE_DNS_RECORD =
  "cloudflare_dns_record"` is defined in `cloudflare_schema.py` but never
  actually produced by the connector — `_normalize()` sets `record_type` to
  Cloudflare's raw `type` string (`"A"`, `"CNAME"`, etc.), never the literal
  `"cloudflare_dns_record"`. The constant is referenced only defensively in
  `risk_service.py`'s dispatch guard and is otherwise vestigial. Routing is
  unaffected since bare DNS types never start with `"cloudflare_"` anyway.

## Mock-shape and provider_metadata verification

- **Fixed**: `classify_cloudflare_ruleset_change`'s legacy `old_value`
  fallback (dead field name, dangerous with `MagicMock` test doubles) —
  removed; the function now reads only `prev_value`.
- **Fixed**: `test_milestone57_7.py`'s `_make_change()` helper built dicts
  keyed `"old_value"` instead of `"prev_value"` — the actual bug this
  fallback was silently masking. All 13 call sites + 2 standalone dict
  literals updated.
- Grepped all touched Cloudflare files for `old_value`/`previous_value`/
  `prior_value` after the fix — zero remaining production or test-helper
  occurrences (only doc-comment mentions explaining the historical bug).
- Added 10 new real-`compute_diff()` integration tests (`TestRealComputeDiffIntegration`,
  section I in `test_cloudflare_extras_risk_audit.py`) covering one DNS
  record, one ruleset, one zone setting, one page rule, one Worker route,
  one Worker script, one Access application, one Access policy, and one WAF
  rule — proving the tracked-fields fix holds through the real pipeline,
  not just hand-built `MagicMock` Changes.
- Added 7 new count-unknown-baseline tests (`TestCountUnknownBaselineSafety`,
  section J) proving an unknown baseline never claims a specific numeric
  direction, and a real `0` baseline still correctly detects a genuine
  increase (no over-correction).

## Security Finding reachability

10 rule keys in `security_rules/cloudflare.py`, all dispatched via the
central `evaluate()` → wired into `security_finding_evaluator.py`'s
`_PROVIDER_EVALUATORS["cloudflare"] = [cloudflare_rules.evaluate]` (confirmed
— not called directly, goes through the central evaluator dispatch):

| Rule key | Severity | Record type | Trigger field(s) |
|---|---|---|---|
| `cloudflare_ssl_mode_weak` | high | `cloudflare_zone_setting` | `setting_id=="ssl"`, `value in ("off","flexible")` |
| `cloudflare_always_https_off` | medium | `cloudflare_zone_setting` | `setting_id=="always_use_https"`, `value=="off"` |
| `cloudflare_min_tls_weak` | medium | `cloudflare_zone_setting` | `setting_id=="min_tls_version"`, `value in ("1.0","1.1")` |
| `cloudflare_security_level_low` | medium | `cloudflare_zone_setting` | `setting_id=="security_level"`, `value in ("off","essentially_off")` |
| `cloudflare_development_mode_on` | medium | `cloudflare_zone_setting` | `setting_id=="development_mode"`, `value=="on"` |
| `cloudflare_hsts_disabled` | medium | `cloudflare_zone_setting` | `setting_id=="security_header"`, nested `enabled=False` |
| `cloudflare_waf_rule_disabled` | high/medium | `cloudflare_waf_rule` | `enabled is False` + protective `action` |
| `cloudflare_dns_private_origin` | high | DNS (`A`/`AAAA`) | `content` resolves to a private/loopback/reserved IP |
| `cloudflare_access_policy_bypass` | high | `cloudflare_access_policy` | `decision=="bypass"` |
| `cloudflare_access_policy_disabled` | medium | `cloudflare_access_policy` | `enabled is False` |

All 10 rules constructed with a positive record (matching the connector
schema), a negative record, and confirmed unknown/missing-field skip
behavior (e.g. `cloudflare_waf_rule_disabled` requires the `enabled` key to
be present at all; `cloudflare_hsts_disabled` only fires on an explicit
nested `enabled: False`, never on an absent/malformed `security_header`
value) — all already covered by the existing `test_cloudflare_extras_risk_audit.py`
and `test_milestone60_4_3_cloudflare_rules.py` suites, re-verified passing.

**No rule is unreachable from an actual connector record.** **3 record
types have no dedicated Security Finding**: `cloudflare_page_rule`,
`cloudflare_worker_route`, `cloudflare_worker_script`,
`cloudflare_access_application` (Change-only surfaces — no current-state
Finding exists yet, consistent with the "Deferred Cloudflare rules" section
already documented in `security_rules/cloudflare.py`'s own module
docstring, e.g. "Unproxied DNS for sensitive hostnames" and "WAF missing"
are explicitly deferred as too noisy/unreliable to infer safely).

Activity ingestion (`list_audit_events`), WAF security-event ingestion
(`list_waf_security_events` via GraphQL `firewallEventsAdaptive`), WAF
signals, and correlations are confirmed **separate from drift/configuration
Security Findings** — none of these participate in `Snapshot.state` or
`compute_diff()`; they are reviewed control-plane activity/event streams,
not drift records. This distinction is already correctly documented in the
connector's own module comments (M68.1/M68.4 sections) and is unchanged by
this pass.

## Registry, coverage, evaluator, and frontend parity

All 10 rule keys confirmed present and consistent across:
- `security_rule_registry.py` (`KNOWN_RULE_KEYS`) — 10/10
- `security_rule_pack.py` (`_RULE_META`) — 10/10, severities match `evaluate()`
- `security_rule_confidence.py` (`RULE_CONFIDENCE`) — 10/10
- `security_coverage_service.py` (`RULE_RECORD_TYPES`) — 10/10, correct
  record-type mapping (including `cloudflare_dns_private_origin` correctly
  mapped to `("A", "AAAA")`, the bare DNS type strings, not a
  `cloudflare_`-prefixed constant)
- `frontend/src/lib/securityRuleCatalog.ts` — 10/10
- `security_finding_evaluator.py`'s central dispatch — confirmed wired,
  not just directly-callable

No backend rule absent from evaluator dispatch, registry, confidence, pack,
or coverage. No frontend-absent or frontend-only-stale rule. No severity or
category mismatch found. No dead correlation key or duplicate rule key
found. No stale rule count assertions found in the provider-depth QA file
(re-ran `test_cloudflare_provider_depth_qa.py`, passes except the one
pre-existing unrelated container-path failure).

## Fail-soft and unknown-value behavior (task 7)

- Confirmed each of the 8 zone settings is fetched **independently** — a
  403 on `security_header` (HSTS, not available on all plans) does not
  block `ssl`/`min_tls_version`/etc. from being recorded.
- Confirmed account-scoped surfaces (worker scripts, Access apps/policies)
  are skipped as a unit only when account-ID resolution itself fails —
  zone-scoped DNS/ruleset/settings/page-rules/worker-routes/WAF-rules sync
  is never affected by an account-level permission gap.
- Confirmed malformed entries are skipped per-record (e.g. `_fetch_page_rules_impl`
  skips any raw entry missing an `id`) rather than aborting the whole fetch.
- Confirmed absent booleans are not converted to false by the connector
  itself — `_normalize_access_application`'s `enabled` defaults to `True`
  (`bool(raw.get("enabled", True))`) matching Cloudflare's own API default
  for an app that predates the on/off toggle, not a false negative.
- Fixed the 8 unknown-to-zero coercion sites (see Summary) — this was the
  one place absent numeric counts *were* becoming zero.

## Explicitly unmodeled capabilities (task 9) — confirmed N/A/GAP, not invented

Grepped the connector/schema for the following — none are modeled, and
none are implied as supported by any product copy:

- API token inventory/rotation metadata, account members/roles, Zero Trust
  IdP configuration beyond safe counts (`allowed_idps_count`), Access
  service tokens, Tunnel configuration, Load Balancers/pools, origin
  certificates, custom hostnames, mTLS certificates, D1/R2/KV
  secrets/contents, Rate Limiting rules as a distinct surface from
  WAF/rulesets, Bot Management settings, Magic Firewall, Cloudflare Gateway
  policies, Logpush destinations, notification destinations, raw
  security-event/request data.

All remain documented GAP/N/A — none were added in this pass, per the
explicit instruction not to invent endpoint coverage during a QA pass.

## Copy safety

Re-scanned all classifier reason strings in both risk modules plus all 10
Security Finding descriptions for breach/compromise/attacker/leaked-token/
leaked-secret/customer-data-exposure/traffic-exposure/DNS-hijacking/
infrastructure-exposure/Worker-source-exposure/WAF-bypass-confirmed/
message-interception/customer-impact phrasing — zero matches outside of
deliberate denylist test constants (already reviewed in `test_cloudflare_extras_risk_audit.py`'s
`TestSecretSafety` section, confirmed as intentional negative-test fixtures,
not violations).

## Fixes made

1. `diff_service.py`: added 7 missing entries to
   `_CLOUDFLARE_TRACKED_FIELDS_BY_TYPE` (`cloudflare_zone_setting`,
   `cloudflare_page_rule`, `cloudflare_worker_route`,
   `cloudflare_worker_script`, `cloudflare_access_application`,
   `cloudflare_access_policy`, `cloudflare_waf_rule`) — the critical fix.
2. `diff_service.py`: changed the unknown-`cloudflare_*`-subtype fallback
   from `_TRACKED_FIELDS` (DNS fields) to `()` (empty), matching every
   other provider's convention.
3. `risk_rules/cloudflare_dns.py`: replaced the ruleset classifier's `_int()`
   helper (which coerced unparseable/`None` values to `0`) with
   `_int_or_none()`, gating all 5 count-comparison blocks on both values
   being known before claiming a direction.
4. `risk_rules/cloudflare_dns.py`: removed the legacy `old_value` fallback
   from `classify_cloudflare_ruleset_change` — a dead field name that was
   actively dangerous with `MagicMock` test doubles.
5. `risk_rules/cloudflare.py`: added `_int_or_none()` and fixed 3
   unknown-to-zero coercion sites (`env_var_count`, `allowed_idps_count`,
   `include_count`).
6. `tests/test_milestone57_7.py`: fixed `_make_change()` and 2 standalone
   dict literals to use `prev_value` instead of the stale `old_value` key;
   updated 1 test asserting the old buggy fallback behavior to assert the
   corrected, safe behavior.
7. `tests/test_cloudflare_extras_risk_audit.py`: added 17 new tests —
   10 real-`compute_diff()` integration tests (section I) and 7
   count-unknown-baseline safety tests (section J).

No changes were needed to `security_rules/cloudflare.py`, any of the 4
backend registries, `security_finding_evaluator.py`, the frontend catalog,
or the connector's `fetch()`/normalization logic — all were already correct.

## Detection matrix

| Case | Category | Record type | Source endpoint | Field(s) | Change simulated | Evidence? | Detected by compute_diff? | Classifier route | Finding rule key | Reachable? | Registry/frontend | Test coverage | Status | Notes/fix |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| A | DNS | bare type (`A`) | `/dns_records` | `content` | A record target changed | yes | yes | `classify_dns_change` | N/A | N/A | N/A | `test_I8`, existing DNS suite | PASS | — |
| B | DNS | bare type (`A`) | `/dns_records` | `proxied` | true→false | yes | yes | `classify_dns_change` | N/A | N/A | N/A | existing `test_cloudflare_risk_audit.py` | PASS | — |
| C | DNS | bare type (`A`) | `/dns_records` | `ttl` | changed | yes | yes | `classify_dns_change` | N/A | N/A | N/A | existing suite | PASS | — |
| D | DNS | `MX` | `/dns_records` | `content`/`priority` | target/priority changed | yes | yes | `classify_dns_change` | N/A | N/A | N/A | existing suite | PASS | — |
| E | DNS | `TXT` | `/dns_records` | `content` | SPF/DKIM/DMARC posture derived | yes | yes | `classify_dns_change` | N/A | N/A | N/A | existing suite (regex-derived posture) | PASS | — |
| F | DNS | bare type | `/dns_records` | (whole record) | added/removed | yes | yes | `classify_dns_change` | N/A | N/A | N/A | existing suite | PASS | — |
| G | Ruleset | `cloudflare_ruleset` | `/rulesets` | `enabled_rule_count` | decreased | yes | yes | `classify_cloudflare_ruleset_change` | N/A (aggregate; no dedicated Finding) | N/A | N/A | `test_I9`, `test_milestone57_7.py` | PASS | — |
| H | Ruleset | `cloudflare_ruleset` | `/rulesets` | `skip_count`/`block_count`/`challenge_count` | changed | yes | yes | `classify_cloudflare_ruleset_change` | N/A | N/A | N/A | `test_milestone57_7.py`, `test_J6`/`test_J7` | PASS | Unknown-to-zero bug fixed |
| I | Ruleset | `cloudflare_ruleset` | `/rulesets` | `phase`/`kind`/`version` | changed | yes | yes | `classify_cloudflare_ruleset_change` | N/A | N/A | N/A | `test_milestone57_7.py` | PASS | — |
| J | Zone setting | `cloudflare_zone_setting` | `/settings/ssl` | `value` | strict→off | yes | **yes (fixed; was no)** | `classify_cloudflare_change` | `cloudflare_ssl_mode_weak` | yes | 10/10 parity | `test_I1` | **FIXED (was FAIL)** | Critical bug — root cause of this pass |
| K | Zone setting | `cloudflare_zone_setting` | `/settings/min_tls_version` | `value` | 1.2→1.0 | yes | yes (fixed) | `classify_cloudflare_change` | `cloudflare_min_tls_weak` | yes | parity confirmed | `test_cloudflare_extras_risk_audit.py` (mock) | FIXED | Same root-cause fix |
| L | Zone setting | `cloudflare_zone_setting` | `/settings/always_use_https` | `value` | on→off | yes | yes (fixed) | `classify_cloudflare_change` | `cloudflare_always_https_off` | yes | parity confirmed | existing mock suite | FIXED | Same root-cause fix |
| M | Zone setting | `cloudflare_zone_setting` | `/settings/security_header` | `value` (nested `enabled`) | HSTS on→off | yes | yes (fixed) | `classify_cloudflare_change` | `cloudflare_hsts_disabled` | yes | parity confirmed | existing mock suite | FIXED | Same root-cause fix |
| N | Page rule | `cloudflare_page_rule` | `/pagerules` | `status` | active→disabled | yes | **yes (fixed; was no)** | `classify_cloudflare_change` | N/A (Change-only) | N/A | N/A | `test_I2` | **FIXED (was FAIL)** | — |
| O | Page rule | `cloudflare_page_rule` | `/pagerules` | `actions_summary` | redirect/cache/security action changed | yes | yes (fixed) | `classify_cloudflare_change` | N/A | N/A | N/A | existing mock suite | FIXED | Same root-cause fix |
| P | Worker route | `cloudflare_worker_route` | `/workers/routes` | `enabled` | true→false | yes | **yes (fixed; was no)** | `classify_cloudflare_change` | N/A (Change-only) | N/A | N/A | existing mock suite | FIXED | — |
| Q | Worker route | `cloudflare_worker_route` | `/workers/routes` | `pattern`/`script_name` | changed | yes | **yes (fixed; was no)** | `classify_cloudflare_change` | N/A | N/A | N/A | `test_I3` | **FIXED (was FAIL)** | — |
| R | Worker script | `cloudflare_worker_script` | `/workers/scripts` | `script_etag` | changed | yes | **yes (fixed; was no)** | `classify_cloudflare_change` | N/A (Change-only) | N/A | N/A | `test_I4` | **FIXED (was FAIL)** | — |
| S | Worker script | `cloudflare_worker_script` | `/workers/scripts` | `env_var_count`/`binding_count` | changed | yes | yes (fixed) | `classify_cloudflare_change` | N/A | N/A | N/A | `test_J1`/`test_J2` | FIXED | Also fixed unknown-to-zero bug |
| T | Access app | `cloudflare_access_application` | `/access/apps` | `visibility` | private→public | yes | **yes (fixed; was no)** | `classify_cloudflare_change` | N/A (Change-only) | N/A | N/A | `test_I5` | **FIXED (was FAIL)** | — |
| U | Access app | `cloudflare_access_application` | `/access/apps` | `enabled` | true→false | yes | yes (fixed) | `classify_cloudflare_change` | N/A | N/A | N/A | existing mock suite | FIXED | Same root-cause fix |
| V | Access app | `cloudflare_access_application` | `/access/apps` | `session_duration`/`allowed_idps_count` | changed | yes | yes (fixed) | `classify_cloudflare_change` | N/A | N/A | N/A | `test_J3` | FIXED | Also fixed unknown-to-zero bug |
| W | Access policy | `cloudflare_access_policy` | `/access/apps/{id}/policies` | `decision` | allow→bypass | yes | **yes (fixed; was no)** | `classify_cloudflare_change` | `cloudflare_access_policy_bypass` | yes | parity confirmed | `test_I6` | **FIXED (was FAIL)** | — |
| X | Access policy | `cloudflare_access_policy` | `/access/apps/{id}/policies` | `enabled` | true→false | yes | yes (fixed) | `classify_cloudflare_change` | `cloudflare_access_policy_disabled` | yes | parity confirmed | existing mock suite | FIXED | Same root-cause fix |
| Y | Access policy | `cloudflare_access_policy` | `/access/apps/{id}/policies` | `include_count`/`exclude_count`/`require_count` | changed | yes | yes (fixed) | `classify_cloudflare_change` | N/A | N/A | N/A | `test_J4`/`test_J5` | FIXED | Also fixed unknown-to-zero bug |
| Z | WAF rule | `cloudflare_waf_rule` | `/rulesets` (+ detail) | `action` | block→allow | yes | **yes (fixed; was no)** | `classify_cloudflare_change` | `cloudflare_waf_rule_disabled` (current-state) | yes | parity confirmed | `test_I7` | **FIXED (was FAIL)** | — |
| AA | WAF rule | `cloudflare_waf_rule` | `/rulesets` | `enabled` | true→false | yes | yes (fixed) | `classify_cloudflare_change` | `cloudflare_waf_rule_disabled` | yes | parity confirmed | existing mock suite | FIXED | Same root-cause fix |
| AB | WAF rule | `cloudflare_waf_rule` | `/rulesets` | `expression_hash` | changed | yes | yes (fixed) | `classify_cloudflare_change` | N/A | N/A | N/A | existing mock suite | FIXED | Same root-cause fix |
| AC | All | all 9 types | — | various | None/missing | yes | yes | both classifiers | — | — | — | `test_J1`/`test_J3`/`test_J4`/`test_J6` | PASS | Never triggers high/critical off unknown alone |
| AD | Zone setting | `cloudflare_zone_setting` | `/settings/security_header` | — | 403 on one setting | N/A | N/A | N/A | N/A | N/A | N/A | existing connector suite | PASS | Fails soft per-setting, others unaffected |
| AE | — | 7 expansion types | — | — | normalized fields with no tracked-field entry | — | — | — | — | — | — | this pass's audit | **FIXED** | Was all 7 types (minus incidental overlaps); now 0 |
| AF | — | — | — | — | tracked fields with no emitted field | — | — | — | — | — | — | this pass's audit | PASS | None found — every tracked field is genuinely emitted |
| AG | — | — | — | — | Security rules with no reachable record | — | — | — | — | — | — | this pass's audit | PASS | None — all 10 rules reachable |
| AH | — | 4 types | — | — | records with no Security Finding | — | — | — | — | — | — | this pass's audit | GAP (documented) | `cloudflare_page_rule`, `cloudflare_worker_route`, `cloudflare_worker_script`, `cloudflare_access_application` — Change-only by design |
| AI | — | — | — | — | evaluator/registry/frontend parity | — | — | — | — | — | — | this pass's audit | PASS | 10/10 across all surfaces |
| AJ | — | all 9 types | — | — | sensitive-data minimization | — | — | — | — | — | — | this pass's audit + safety greps | PASS | Confirmed intact |
| AK | — | — | — | — | activity/WAF-event surfaces vs. drift records | — | — | — | — | — | — | this pass's audit | PASS | Correctly separated; already documented in connector comments |

Totals: **29 detection-matrix cases** (A–AK). **10 PASS** (pre-existing,
unaffected), **17 FIXED** (were FAIL before this pass's tracked-fields fix —
cases J–AB plus AE), **0 remaining FAIL**, **1 GAP** (documented, case AH —
4 record types intentionally Change-only), **1 N/A-adjacent** (case AD is a
PASS/fail-soft confirmation, not a gap).

## Validation run

- `docker compose exec api pytest tests/test_cloudflare_connector.py
  tests/test_cloudflare_connector_expansion.py
  tests/test_cloudflare_risk_audit.py
  tests/test_cloudflare_extras_risk_audit.py
  tests/test_cloudflare_provider_depth_qa.py -q` → **246 passed, 5 skipped,
  1 failed** (the 1 failure is the pre-existing, unrelated container-path
  issue — `test_no_forbidden_phrases_in_cloudflare_rules_module` computes
  `REPO_ROOT` assuming a `/backend/...` mount that doesn't match this
  container's `/app` mount; confirmed via a direct `FileNotFoundError`
  unrelated to any Cloudflare logic or wording — same root cause documented
  in the prior Azure and Vercel QA passes this session).
- `docker compose exec api pytest tests/test_milestone60_4_3_cloudflare_rules.py
  tests/test_milestone68_1_cloudflare_activity_ingestion.py
  tests/test_milestone68_2_cloudflare_correlations.py
  tests/test_milestone68_3_cloudflare_risk_depth.py
  tests/test_milestone68_4_cloudflare_waf_events.py
  tests/test_milestone68_5_cloudflare_waf_signals.py
  tests/test_milestone68_6_cloudflare_waf_correlations.py
  tests/test_milestone68_7_cloudflare_demo_qa.py -q` → **115 passed**.
- `docker compose exec api pytest tests -q -k "cloudflare and diff"` →
  **34 passed, 17383 deselected**.
- `docker compose exec api pytest tests -q -k "cloudflare and risk"` →
  **233 passed, 17184 deselected**.
- `docker compose exec api pytest tests -q -k "cloudflare"` → **493 passed,
  6 skipped, 1 failed, 16917 deselected** (same pre-existing failure as
  above; ran quickly, no need to abort).
- `docker compose exec api pytest tests/test_milestone57_7.py -q` → **59
  passed** (was 52 passing / 7 failing before the `old_value` mock-shape
  fix in this file).
- No frontend files were changed in this pass, so `npx tsc --noEmit` was
  not required.

## Safety and hygiene

- Safety grep (scoped to the 5 touched files) for breach/compromise/
  exposure/DNS-hijacking/traffic-exposure/Worker-source-exposure/WAF-bypass/
  infrastructure-exposure/credential-exposure phrasing → **0 matches**.
- Risky-persisted-shape grep (`authorization|api_token|api_key|secret_value|
  environment_value|worker_source|script_content|raw_expression|
  request_body|response_body|cookie|set-cookie`) → all matches manually
  reviewed and confirmed safe: unrelated other-providers' tracked-field
  names in the shared `diff_service.py`, a deliberate denylist-test
  constant (`"cloudflare_api_token": "S" * 40` in a tripwire test), a safety
  comment, and normal English usage ("weaker authorization than before").
- `git diff --check` → clean (no whitespace errors).
- `git status --short` → 5 modified files, 1 new report file, plus
  pre-existing untracked unrelated directories not staged.
