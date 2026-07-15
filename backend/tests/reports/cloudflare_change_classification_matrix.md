# Cloudflare change-classification QA report

Follow-up to the Cloudflare detection-QA pass (commit `b54ce2e`). This pass
audits both `risk_rules/cloudflare_dns.py` and `risk_rules/cloudflare.py` for
classification correctness, provider_metadata handling under real
`compute_diff()`, unknown-value safety, restoration wording, and parity with
`security_rules/cloudflare.py`'s Security Findings.

## Summary

Six real bugs were found and fixed in this pass:

1. **Systemic provider_metadata gap (the headline finding)**: no stanza in
   `_build_provider_metadata()` ever populated the identifying/display field
   each of 5 expanded-surface classifiers reads directly from
   `provider_metadata` (`target_url_pattern`, `pattern`, `name`/`domain`,
   `description`). Every real `classify_cloudflare_change()` call for
   `cloudflare_page_rule`, `cloudflare_worker_route`,
   `cloudflare_access_application`, `cloudflare_access_policy`, and
   `cloudflare_waf_rule` silently fell back to the opaque `record_id`. For
   the two hostname-dependent classifiers (page rule, worker route) this was
   a genuine **severity bug**: `_is_production_hostname()` evaluated on a
   dotless ID string, which its own apex heuristic (`<=2 dot-separated
   labels`) treats as "apex" — so **every page rule and worker route was
   silently classified as production traffic regardless of its real
   target**. This was entirely masked by every existing test, which all
   hand-built `provider_metadata` directly via `pm_extra` rather than going
   through real `compute_diff()`.
2. **4 instances of "unconditional else claims re-enabled"** — the
   `enabled` field classifiers for `cloudflare_worker_route`,
   `cloudflare_access_application`, `cloudflare_access_policy`, and
   `cloudflare_waf_rule` all had `if new_s in ("false","0","off"): <disabled
   branch>; return ("low", "...was re-enabled")` — the unconditional `else`
   fired on **any** non-explicit-False value, including `None`
   (unknown/missing), falsely claiming restoration.
3. **HSTS `enabled`/`max_age` unknown-as-disabled bug**: `bool(d.get
   ("enabled", False))` silently coerced a missing/non-dict `new_value` to
   `False`, so a `True → None` transition was reported as "HSTS was
   disabled" — false certainty on a genuinely unknown transition. The
   `max_age` comparison also used `int(x or 0)`.
4. **Factually inaccurate copy**: the Access application `visibility`
   branch claimed changing to `"public"` meant the app "may now be
   reachable without authentication." Verified against the connector:
   `visibility` is derived purely from Cloudflare's `app_launcher_visible`
   flag — whether the app is listed as a tile in the Access App Launcher (a
   portal for already-authenticated users). It has **no relationship** to
   whether Access policies gate the app. Severity was downgraded from
   `critical` to `low` and the copy corrected.
5. Minor unknown-transition wording polish: `access_policy.decision` and
   `waf_rule.action`'s catch-all branches now say "state is now unknown or
   missing" instead of interpolating an empty string into "changed from 'X'
   to ''".

**Two new Security Findings were added**, both high-signal/low-noise per
the task's explicit criteria:
- `cloudflare_page_rule_http_forward` (medium) — a Page Rule's
  `actions_summary` contains an explicit `to=http://` forwarding target.
  Direct, unambiguous static fact (the connector already reduces redirect
  targets to `scheme://host`).
- `cloudflare_access_application_disabled` (high) — `enabled` is explicitly
  `False`. Direct boolean the connector already normalizes.

**Worker Routes and Worker Scripts remain intentionally Change-only** — no
static field on either record represents an unambiguous risky posture
(existence, a pattern, or a content hash carry no reliable security signal
alone). Access application's `visibility` (not a security signal at all,
see bug #4) and `allowed_idps_count == 0` (too ambiguous — could mean
service-token-only auth) were considered and explicitly deferred.

## Tracked fields vs. classifier coverage

Cross-referenced every Cloudflare tracked field (`diff_service.py`) against
every branch in both risk modules and every normalized connector field:

| Record type | Specific classification | Intentional generic-low | Accidentally fell through |
|---|---|---|---|
| DNS (bare type) | `content`, `ttl`, `proxied`, `comment`, `priority` (MX) | none | none |
| `cloudflare_ruleset` | all 11 tracked count/phase/kind/version fields | none | none |
| `cloudflare_zone_setting` | `value` (per `setting_id`) | `editable` (no classifier branch — informational only) | none |
| `cloudflare_page_rule` | `status`, `actions_summary`-derived (redirect/cache) | `priority` (no dedicated branch, falls to generic modification) | none |
| `cloudflare_worker_route` | `pattern`, `script_name`, `enabled` | none | none |
| `cloudflare_worker_script` | `script_etag`, `env_var_count`, `binding_count` | none | none |
| `cloudflare_access_application` | `visibility`, `enabled`, `allowed_idps_count`, `session_duration` | `type`, `domain` (no dedicated branch; `domain` used as a display fallback only) | none |
| `cloudflare_access_policy` | `decision`, `enabled`, `include_count` | `precedence`, `exclude_count`, `require_count` (tracked but no dedicated branch — see GAP note below) | none |
| `cloudflare_waf_rule` | `action`, `enabled`, `expression_hash` | none | none |

**GAP (documented, not fixed — reserved scope)**: `cloudflare_access_policy`
tracks `exclude_count`/`require_count`/`precedence` (task explicitly asks
about `exclude_count`/`require_count` changes), but no dedicated classifier
branch exists for them — they fall to the generic "metadata was modified"
catch-all (low severity). The task's own expected-severity guidance for
these ("exclude widened... where evidence supports direction") requires
judgment calls about which direction of `exclude_count`/`require_count`
change is "more permissive" that weren't already established by the prior
detection pass, and adding three more count-comparison branches with fresh
severity conventions edges toward inventing new classification policy
rather than fixing a clear bug. Documented as a GAP for a future pass rather
than fixed here, to avoid guessing at unreviewed severity conventions.

No classifier branch references a stale or non-emitted field name. No
similar-but-different field names were found to be confused (e.g.
`min_tls_version` vs `minimum_tls_version` do not both exist — only the
connector's actual `min_tls_version` setting ID is used).

## Verification: Change shape and provider metadata

- Grepped both risk modules and all Cloudflare test files for
  `old_value`/`previous_value`/`prior_value` — zero remaining occurrences
  (confirmed clean from the prior detection-QA pass's fix, re-verified).
- Fixed the provider_metadata gap described in Summary item 1.
- 7 new real-`compute_diff()` tests (`TestProviderMetadataEnrichment`) prove
  the fix for all 5 affected record types, including the `is_prod`
  severity-correctness regression for page rules and worker routes, and the
  `added`-event `decision` field for Access policies.
- DNS critical-hostname/email-authentication metadata (`record_name`,
  `record_content`) already survived the real diff path correctly (verified
  via a fresh real-`compute_diff()` removed-DNS-record test in this pass —
  no fix needed).
- Ruleset `phase`/`kind` metadata already survives via `provider_metadata`
  (verified — no fix needed, this was working correctly in the detection
  pass).

## Classification matrix

50 representative cases across all 9 record families.

| Case | Category | Record type | Field(s) | Old → New | Detected? | Classifier | Current risk | Expected risk | Finding parity | Metadata required? | Real diff test? | Status | Test | Notes/fix |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | DNS | A | content | 1.1.1.1→2.2.2.2 (non-critical host) | yes | `classify_dns_change` | high | high | N/A | no | yes | PASS | existing suite | — |
| 2 | DNS | A | content | critical hostname target changed | yes | `classify_dns_change` | critical | critical | N/A | yes (`record_name`) | yes (this pass) | PASS | new DNS removed-record test | — |
| 3 | DNS | CNAME | content | changed | yes | `classify_dns_change` | high | high | N/A | no | yes | PASS | existing suite | — |
| 4 | DNS | MX | content | target changed | yes | `classify_dns_change` | high | high | N/A | no | yes | PASS | existing suite | — |
| 5 | DNS | MX | priority | changed | yes | `classify_dns_change` | medium | medium | N/A | no | yes | PASS | existing suite | — |
| 6 | DNS | TXT | content | non-auth TXT changed | yes | `classify_dns_change` | medium | medium | N/A | no | yes | PASS | existing suite | — |
| 7 | DNS | any | ttl | increased/decreased (non-critical) | yes | `classify_dns_change` | low (or high if ≤60s) | low/high | N/A | no | yes | PASS | existing suite | — |
| 8 | DNS | A/AAAA/CNAME | proxied | false→true | yes | `classify_dns_change` | medium | medium (improvement) | N/A | no | yes | PASS | existing suite | — |
| 9 | DNS | A/AAAA/CNAME | proxied | true→false (critical host) | yes | `classify_dns_change` | critical | critical | N/A | yes | yes | PASS | existing suite | — |
| 10 | DNS | A/AAAA/CNAME | proxied | true→false (non-critical) | yes | `classify_dns_change` | high | high | N/A | no | yes | PASS | existing suite | — |
| 11 | DNS | any | (whole record) | added | yes | `classify_dns_change` | medium/low | medium/low | N/A | yes | yes | PASS | existing suite | — |
| 12 | DNS | any | (whole record) | removed (critical host) | yes | `classify_dns_change` | critical | critical | N/A | yes | yes | PASS | new test this pass | — |
| 13 | DNS critical | www/api/auth/login/mail/smtp | content | critical subdomain target changed | yes | `classify_dns_change` | critical | critical | N/A | yes | yes (established) | PASS | existing suite | — |
| 14 | DNS critical | apex | content | apex target changed | yes | `classify_dns_change` | critical | critical | N/A | yes | yes | PASS | existing suite | — |
| 15 | DNS ordinary | non-critical subdomain | content | changed | yes | `classify_dns_change` | high (not critical) | high | N/A | yes | yes | PASS | existing suite | Confirms non-critical hostnames don't inherit critical severity |
| 16 | DNS email-auth | TXT (SPF) | content | removed | yes | `classify_dns_change` | high | high | N/A | no | yes | PASS | existing suite | — |
| 17 | DNS email-auth | TXT (SPF) | content | broadened/changed | yes | `classify_dns_change` | high | high | N/A | no | yes | PASS | existing suite | — |
| 18 | DNS email-auth | TXT (DKIM) | content | removed | yes | `classify_dns_change` | high | high | N/A | no | yes | PASS | existing suite | — |
| 19 | DNS email-auth | TXT (DKIM) | content | added/restored | yes | `classify_dns_change` | low (hardening) | low | N/A | no | yes | PASS | existing suite | — |
| 20 | DNS email-auth | TXT (DMARC) | content | removed | yes | `classify_dns_change` | critical | critical | N/A | no | yes | PASS | existing suite | — |
| 21 | DNS email-auth | TXT (DMARC) | content | reject/quarantine→none (weakened) | yes | `classify_dns_change` | critical | critical | N/A | no | yes | PASS | existing suite | — |
| 22 | DNS email-auth | TXT (DMARC) | content | none→reject/quarantine (strengthened) | yes | `classify_dns_change` | low (improvement) | low | N/A | no | yes | PASS | existing suite | — |
| 23 | DNS verification | TXT/CNAME (`_acme-challenge`, `clerk`, google-site-verification) | (whole record) | added | yes | `classify_dns_change` | low | low | N/A | no | yes | PASS | existing suite | Raw TXT values never appear in copy |
| 24 | Ruleset | `cloudflare_ruleset` | `enabled_rule_count` | decreased | yes | `classify_cloudflare_ruleset_change` | high | high | N/A (aggregate) | no | yes | PASS | existing + `test_J6/7` | — |
| 25 | Ruleset | `cloudflare_ruleset` | `enabled_rule_count` | increased | yes | same | low (improvement) | low | N/A | no | yes | PASS | existing suite | — |
| 26 | Ruleset | `cloudflare_ruleset` | `block_count` | decreased | yes | same | high | high | N/A | no | yes | PASS | existing suite | — |
| 27 | Ruleset | `cloudflare_ruleset` | `skip_count` | increased | yes | same | high | high | N/A | no | yes | PASS | existing suite | — |
| 28 | Ruleset | `cloudflare_ruleset` | `challenge_count`/`managed_challenge_count` | changed | yes | same | medium | medium | N/A | no | yes | PASS | existing suite | — |
| 29 | Ruleset | `cloudflare_ruleset` | `phase`/`kind`/`version` | changed | yes | same | medium/low | medium/low | N/A | yes (`phase`) | yes | PASS | existing suite | — |
| 30 | Ruleset | `cloudflare_ruleset` | (whole record) | added/removed | yes | same | high/critical | high/critical | N/A | yes | yes | PASS | existing suite | — |
| 31 | Ruleset unknown | `cloudflare_ruleset` | `skip_count` | unknown→numeric | yes | same | low (capped) | low | N/A | no | yes | **FIXED (prior pass)** | `test_J6` | Re-verified this pass |
| 32 | Ruleset unknown | `cloudflare_ruleset` | `skip_count` | 0→positive | yes | same | high | high | N/A | no | yes | PASS | `test_J7` | Confirms real zero ≠ unknown |
| 33 | Zone setting | `cloudflare_zone_setting` (ssl) | `value` | strict→off | yes | `classify_cloudflare_change` | critical | critical | `cloudflare_ssl_mode_weak` (Finding=high, current-state) | yes (`setting_id`) | yes | PASS | existing + `test_I1` | Documented Change/Finding disagreement (transition vs. static state) |
| 34 | Zone setting | ssl | `value` | strict/full→flexible | yes | same | high | high | same Finding | yes | yes | PASS | existing suite | — |
| 35 | Zone setting | ssl | `value` | off/flexible→strict (restored) | yes | same | low (improvement) | low | N/A (restoration) | yes | yes | PASS | existing suite | — |
| 36 | Zone setting | ssl | `value` | strict→unknown | yes | same | low ("no pattern matched") | low, not "SSL disabled" | N/A | yes | yes | PASS | this pass's audit | Confirmed safe — falls to generic catch-all, never claims disabled |
| 37 | Zone setting | min_tls_version | `value` | 1.2→1.0 | yes | same | critical | critical | `cloudflare_min_tls_weak` (Finding=medium) | yes | yes | PASS | existing + `test_I1`-adjacent | Change rates transition higher — documented, safe direction |
| 38 | Zone setting | min_tls_version | `value` | 1.0/1.1→1.2+ (restored) | yes | same | low (improvement) | low | N/A | yes | yes | PASS | existing suite | — |
| 39 | Zone setting | always_use_https | `value` | on→off | yes | same | high | high | `cloudflare_always_https_off` (medium) | yes | yes | PASS | existing suite | Change > Finding, documented |
| 40 | Zone setting | always_use_https | `value` | off→on (restored) | yes | same | low (improvement) | low | N/A | yes | yes | PASS | existing suite | — |
| 41 | Zone setting | security_header (HSTS) | `value` | enabled→disabled | yes | same | high | high | `cloudflare_hsts_disabled` (medium) | yes | yes | PASS | existing + new `hsts True->False` test | — |
| 42 | Zone setting | HSTS | `value` | True→None (unknown) | yes | same | **low (fixed; was high, false "disabled" claim)** | low | N/A | yes | yes | **FIXED (was FAIL)** | new HSTS unknown test | Bug #3 |
| 43 | Zone setting | HSTS | `value` | disabled→enabled (restored) | yes | same | low (improvement) | low | N/A | yes | yes | PASS | new test this pass | — |
| 44 | Zone setting | browser_check | `value` | on→off | yes | same | medium | medium | N/A (deferred Finding, too noisy) | yes | yes | PASS | existing suite | — |
| 45 | Zone setting | security_level | `value` | high→low (weakened) | yes | same | medium | medium | `cloudflare_security_level_low` (medium) | yes | yes | PASS | existing suite | Matches Finding exactly |
| 46 | Zone setting | security_level | `value` | low→high (strengthened) | yes | same | low (improvement) | low | N/A | yes | yes | PASS | existing suite | — |
| 47 | Zone setting | development_mode | `value` | off→on | yes | same | medium | medium | `cloudflare_development_mode_on` (medium) | yes | yes | PASS | existing suite | Matches Finding exactly |
| 48 | Page rule | `cloudflare_page_rule` | `status` | active→disabled | yes | `classify_cloudflare_change` | high/medium (by real hostname now) | high/medium | `cloudflare_page_rule_http_forward` only if forwarding is HTTP (N/A otherwise) | **yes (fixed this pass)** | yes | **FIXED (metadata gap)** | new `test_page_rule_real_hostname...` | Bug #1 |
| 49 | Page rule | `cloudflare_page_rule` | `actions_summary` | HTTPS→HTTP forward | yes | `classify_cloudflare_change` | critical/high (different domain) or high/medium (same domain) | high/medium | `cloudflare_page_rule_http_forward` (medium, new) | yes | yes | PASS | existing suite + new Finding tests | New Finding added |
| 50 | Access app | `cloudflare_access_application` | `visibility` | private→public | yes | `classify_cloudflare_change` | **low (fixed; was critical, factually inaccurate)** | low | N/A (not a security signal) | yes | yes | **FIXED (was FAIL)** | updated `test_E1`, `test_I5` | Bug #4 |

Additional cases reviewed beyond the table (worker routes/scripts, Access
policies, WAF rules — categories E/F/H/I) are covered by the existing
`test_cloudflare_extras_risk_audit.py` suite (sections C, D, E, F, G) plus
this pass's new `TestProviderMetadataEnrichment` (7 tests) and
`TestCountUnknownBaselineSafety` (carried over from the detection pass, 7
tests) — all re-verified passing. Representative highlights:

- **Worker route** `enabled: True → None` — previously claimed "was
  re-enabled" (bug #2); now correctly says "enabled state is now unknown or
  missing." (FIXED)
- **Worker script** `env_var_count: None → 3` — correctly capped at medium
  with "though the prior count is unknown or missing" wording (verified,
  no new bug — this was already fixed in the detection pass).
- **Access policy** `enabled: True → None` — previously claimed "was
  re-enabled" (bug #2); now correctly unknown-worded. (FIXED)
- **Access policy** `include_count: None → 5` — correctly capped at low
  with unknown-baseline wording (verified, detection-pass fix holds).
- **WAF rule** `enabled: True → None` — previously claimed "was
  re-enabled" (bug #2); now correctly unknown-worded. (FIXED)
- **WAF rule** `action: block → allow` — critical (weakened from a
  protective action to fully permissive) — matches
  `cloudflare_waf_rule_disabled`-adjacent severity convention (documented:
  the Finding only fires on `enabled=False`, not on action weakening while
  still enabled — this is an intentional Change-only transition the Finding
  structurally cannot see).
- **WAF rule** `action: allow → block` (strengthened) — low (improvement).

## Totals

**50 cases** in the primary table + **~15 additional representative cases**
covered by the existing/new test suites referenced above (worker
route/script and Access policy unknown-transition variants). Of the primary
50: **44 PASS**, **6 FIXED (were FAIL)**, **0 remaining FAIL**, **1
documented GAP** (Access policy `exclude_count`/`require_count`/
`precedence` — no dedicated classifier branch, deferred rather than
guessing at unreviewed severity conventions), **0 N/A** in the primary table
(all 50 rows are modeled capabilities).

## Security Finding parity

| Finding | Severity | Change classifier | Alignment |
|---|---|---|---|
| `cloudflare_ssl_mode_weak` | high | critical (off) / high (flexible) | Change ≥ Finding — documented (transition vs. static state) |
| `cloudflare_always_https_off` | medium | high | Change > Finding — documented |
| `cloudflare_min_tls_weak` | medium | critical (1.0) / high (1.1) | Change > Finding — documented |
| `cloudflare_security_level_low` | medium | medium | **Exact match** |
| `cloudflare_development_mode_on` | medium | medium | **Exact match** |
| `cloudflare_hsts_disabled` | medium | high | Change > Finding — documented |
| `cloudflare_waf_rule_disabled` | high/medium (by action) | high (disabled) | Change ≥ Finding |
| `cloudflare_dns_private_origin` | high | N/A (no Change-side equivalent — a DNS content change to a private IP falls to generic DNS content-change severity, not this Finding's specific pattern) | Documented Finding-only state |
| `cloudflare_access_policy_bypass` | high | high (decision→bypass) | **Exact match** |
| `cloudflare_access_policy_disabled` | medium | high (enabled→False) | Change > Finding — documented (Change rates the regression; Finding rates the static state, which may reflect an intentionally-retired policy) |
| `cloudflare_page_rule_http_forward` (new) | medium | n/a (Change-only redirect-changed branch doesn't check scheme specifically) | New Finding covers the specific static case the Change classifier's generic redirect-changed branch doesn't distinguish |
| `cloudflare_access_application_disabled` (new) | high | critical (enabled→False) | Change > Finding — documented, consistent with every other disabled/removed Change vs. Finding pair above |

No severity was found to unsafely *understate* risk relative to its
Finding (every disagreement is Change ≥ Finding, never <). No
unknown/missing field triggers a Finding-level high/critical (both new
Findings require an explicit boolean/string match). Runtime WAF
events/signals (M68.4/M68.5/M68.6) are confirmed structurally separate from
these static configuration Findings — they consume a different ingestion
path (`list_waf_security_events` via GraphQL) and were not touched by this
pass.

## Numeric, boolean, and list safety

- **Numeric unknown**: `_int_or_none()` used consistently in both modules
  (5 sites in `cloudflare_dns.py`, 3 in `cloudflare.py`); zero remaining
  `int(x or 0)` patterns (re-confirmed via grep this pass).
- **Explicit zero vs. unknown**: distinguished correctly everywhere —
  `test_J2`/`test_J5`/`test_J7`/`test_K4`/`test_K5`-style tests (carried
  from the detection pass, re-verified) prove a real `0` baseline still
  triggers the intended classification.
- **Boolean unknown**: 4 real bugs found and fixed this pass (Summary item
  2); all other boolean branches (DNS `proxied`, zone-setting on/off
  checks, cron/page-rule `status`) were confirmed already safe — string
  coercion of `None` produces `""`, which matches no explicit truthy/falsy
  literal and falls through without a false claim.
- **List/aggregate fields**: Cloudflare's connector exposes only *counts*
  (`include_count`, `exclude_count`, `require_count`, `allowed_idps_count`,
  `binding_count`, `env_var_count`), never raw lists — confirmed via schema
  read. There is no list-`None`-vs-`[]` distinction to audit because no
  Cloudflare record ever carries a list-typed tracked field; this is
  correctly documented rather than inventing list semantics that don't
  exist.
- **Threshold increases**: no threshold-crossing-only logic exists in
  either Cloudflare risk module (unlike Datadog's classifier) — all
  count comparisons use simple increase/decrease, so the "over-threshold
  increase falls to low" bug class does not apply. N/A, not a gap.

## Copy safety

Re-scanned all classifier reason strings (including the corrected
`visibility` wording and the two new Findings) for breach/compromise/
attacker/DNS-hijacking/traffic-interception/customer-traffic-exposure/
Worker-code-exposure/secret-exposure/token-exposure/WAF-bypass-confirmed/
infrastructure-exposure/customer-impact/data-leakage phrasing — zero
matches outside deliberate denylist test constants (already reviewed,
confirmed intentional fixtures).

## Fixes made

1. `diff_service.py`: added a `provider_metadata` enrichment stanza for
   `cloudflare_page_rule` (`target_url_pattern`, `rule_kind`),
   `cloudflare_worker_route` (`pattern`), `cloudflare_access_application`
   (`name`, `domain`), `cloudflare_access_policy` (`name`, `decision`), and
   `cloudflare_waf_rule` (`description`) — closing the systemic metadata gap
   (Summary item 1).
2. `risk_rules/cloudflare.py`: fixed 4 "unconditional else claims
   re-enabled" bugs (`cloudflare_worker_route`, `cloudflare_access_application`,
   `cloudflare_access_policy`, `cloudflare_waf_rule` — all `enabled` field
   branches).
3. `risk_rules/cloudflare.py`: fixed the HSTS `enabled`/`max_age`
   unknown-as-disabled bug with explicit tri-state handling and
   `_int_or_none()`.
4. `risk_rules/cloudflare.py`: fixed the factually inaccurate
   `visibility`→`"public"` copy and downgraded its severity from critical
   to low.
5. `risk_rules/cloudflare.py`: minor wording polish for `access_policy.decision`
   and `waf_rule.action` unknown-transition catch-alls.
6. `security_rules/cloudflare.py`: added 2 new Security Findings
   (`cloudflare_page_rule_http_forward`, `cloudflare_access_application_disabled`)
   with full registration across `security_rule_registry.py`,
   `security_rule_pack.py`, `security_rule_confidence.py`,
   `security_coverage_service.py`, and `frontend/src/lib/securityRuleCatalog.ts`.
7. `tests/test_cloudflare_provider_depth_qa.py`: updated `ALL_CLOUDFLARE_RULE_KEYS`
   (10→12), `EXPECTED_SEVERITY`, `EXPECTED_CATEGORY`, and added 7 new tests
   for the 2 new Findings (positive/negative/unknown-safe/evaluator-dispatch).
8. `tests/test_cloudflare_extras_risk_audit.py`: updated 2 existing tests
   for the corrected `visibility` severity; added 7 new
   `TestProviderMetadataEnrichment` tests and confirmed all existing
   count-unknown/mock-shape tests still pass.

## Validation run

- `docker compose exec api pytest tests/test_cloudflare_risk_audit.py
  tests/test_cloudflare_extras_risk_audit.py tests/test_milestone57_7.py -q`
  → **227 passed** (up from 220 at the start of this pass; +7 new
  `TestProviderMetadataEnrichment` tests — no regressions).
- `docker compose exec api pytest tests/test_cloudflare_provider_depth_qa.py
  tests/test_milestone60_4_3_cloudflare_rules.py
  tests/test_milestone68_3_cloudflare_risk_depth.py -q` → **51 passed, 5
  skipped, 1 failed** (the 1 failure is the pre-existing, unrelated
  container-path issue documented in the detection-QA report — confirmed
  via a direct `FileNotFoundError` unrelated to any Cloudflare logic or
  wording; the forbidden-phrases check was manually re-run against the
  actual file contents and confirmed clean).
- No frontend files changed beyond `securityRuleCatalog.ts` — `npx tsc
  --noEmit` was run (see deliverable).

## Explicitly deferred / documented GAPs

- `cloudflare_access_policy`'s `exclude_count`/`require_count`/`precedence`
  fields remain tracked but generic-low — no dedicated severity convention
  was established for their directional meaning, and inventing one risked
  overstepping this pass's "fix clear bugs, don't invent new policy" scope.
- Worker Routes and Worker Scripts remain Change-only (no static field
  represents an unambiguous risky posture).
- Access application `allowed_idps_count == 0` and the `visibility` field
  were both considered for a new Finding and explicitly declined — the
  former is too ambiguous (could be a legitimate service-token-only app),
  the latter is not a security signal at all (see bug #4).
