# Shopify change-classification QA report

Follow-up to the Shopify detection-QA pass (commit `e3c984e`). This pass
audits `risk_rules/shopify.py`'s classification correctness, provider_metadata
handling under real `compute_diff()`, count/boolean unknown-value safety, and
parity with `security_rules/shopify.py`'s Security Findings.

## Summary

The prior detection-QA pass's fixes (provider_metadata for `topic`/
`policy_type`/`is_https`/`endpoint_scheme`, `shopify_domain` tracking,
`_classify_domain_change`, `_int_or_none()`, `_is_explicit_bool()`) were all
re-verified against real `compute_diff()` output and found correct. **One
new real bug was found and fixed** in this pass:

**Same-sync context-field timing bug.** `_build_provider_metadata()` always
read context fields (`topic`, `policy_type`, `primary`) from the OLD (`prev`)
record, even for "modified" Changes. If the context field itself changed in
the *same* sync round as the field being classified, the classifier scored
severity against the stale context instead of the current one:

- A domain that became primary **and** lost SSL in the same sync was scored
  `low` ("non-primary domain") instead of `high` — because `primary` context
  came from the old record (`False`), not the new one (`True`).
- A webhook whose topic changed to `orders/create` **and** downgraded to
  HTTP in the same sync was scored `high` instead of `critical` — same root
  cause with `topic`.

Fixed by preferring `alt_record` (the new record, available on "modified"
Changes) for these three context fields, falling back to `record` for
"added"/"removed" (which have no `alt_record`). Verified against real
`compute_diff()` output before and after the fix; 4 new regression tests
added (`TestSameSyncContextTiming`, section L).

No other misclassification was found. All classifications from the prior
pass (webhook HTTP/HTTPS by topic sensitivity, legal-vs-operational policy
removal, sensitive/write/general scope-count transitions, domain SSL/
verification scoped to primary, all 8 boolean unknown-transition fixes) were
re-verified correct under real `compute_diff()`, not just hand-built mocks.

## Classification matrix

| Case | Record type | Field(s) | Old value | New value | Detected? | Current risk | Expected risk | Current copy | Expected copy | Finding parity | Metadata required? | Real compute_diff test? | Status | Test | Notes/fix |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | shopify_shop_metadata | password_enabled | True | False | yes | high | high | "storefront password protection was disabled" | same | N/A (no Finding for shop metadata) | no | yes (D1) | PASS | test_D1 | — |
| 2 | shopify_shop_metadata | password_enabled | False | True | yes | low | low (improvement) | "was enabled" | same | N/A | no | yes (D2) | PASS | test_D2 | — |
| 3 | shopify_shop_metadata | password_enabled | True | None | yes | low | low | "state is now unknown or missing" | same | N/A | no | yes (J1) | PASS | test_J1 | Fixed in prior pass |
| 4 | shopify_shop_metadata | eligible_for_payments | True | False | yes | high | high | "no longer eligible for payments" | same | N/A | no | yes (D3) | PASS | test_D3 | — |
| 5 | shopify_shop_metadata | requires_extra_payments_agreement | False | True | yes | high | high | "now requires an extra payments provider agreement" | same | N/A | no | yes (D4) | PASS | test_D4 | — |
| 6 | shopify_shop_metadata | has_storefront | True | False | yes | high | high | "storefront was disabled" | same | N/A | no | yes (D5) | PASS | test_D5 | — |
| 7 | shopify_shop_metadata | checkout_api_supported | True | False | yes | medium | medium | "Checkout API support was disabled" | same | N/A | no | yes (D6) | PASS | test_D6 | — |
| 8 | shopify_shop_metadata | taxes_included | — | True | yes | medium | medium | "tax configuration changed" | same | N/A | no | yes (D11) | PASS | test_D11 | — |
| 9 | shopify_shop_metadata | currency | — | "EUR" | yes | medium | medium | "store currency changed" | same | N/A | no | yes (D7) | PASS | test_D7 | — |
| 10 | shopify_webhook_subscription | is_https / endpoint_scheme | https/True | http/False (critical topic) | yes | critical | critical | "downgraded ... payloads transmitted unencrypted" | same | shopify_webhook_http (critical) — matches | **yes** (topic) | yes (H1) | PASS | test_A9, test_H1 | Requires real-metadata fix from prior pass |
| 11 | shopify_webhook_subscription | is_https / endpoint_scheme | https/True | http/False (non-critical topic) | yes | high | high | "changed to use plain HTTP" | same | shopify_webhook_http fires critical regardless of topic — **documented intentional Finding/Change disagreement** (Finding = worst-case current-state; Change scales by topic evidence, matching this task's own stated convention: "HTTP webhook on less sensitive topic: high/medium") | **yes** (topic) | yes (H2) | PASS | test_A10, test_H2 | — |
| 12 | shopify_webhook_subscription | is_https | False | True | yes | low | low (improvement) | "upgraded to HTTPS" | same | N/A | no | not yet (mock only) | PASS | (none — see gap below) | Minor GAP: no real-compute_diff test for the restoration direction; classifier logic identical to the downgrade path already covered, low risk |
| 13 | shopify_webhook_subscription | topic + endpoint_scheme (same sync) | products/update, https | orders/create, http | yes | **critical (fixed; was high)** | critical | "downgraded ... critical topic" | same | matches shopify_webhook_http | **yes** (topic, same-sync) | **yes (L3)** | **FIXED (was FAIL)** | test_L3 | Same-sync context timing bug — fixed this pass |
| 14 | shopify_webhook_subscription | topic + endpoint_scheme (same sync, reverse) | orders/create, https | products/update, http | yes | high | high | "downgraded ... plain HTTP" | same | — | yes (same-sync) | yes (L4) | PASS | test_L4 | Symmetric case confirms no over-correction |
| 15 | shopify_webhook_subscription | (added) orders/create, http | — | new record | yes | critical | critical | "new ... critical topic ... plain HTTP endpoint" | same | matches | yes (added-record) | yes (H5) | PASS | test_H5 | — |
| 16 | shopify_store_policy | present (privacy_policy) | True | False | yes | high | high | "legal/compliance policy was cleared or removed" | same | shopify_policy_missing Finding = low (uniform, current-state) — **documented intentional disagreement**: Change rates the *removal transition* as high (a regression), Finding rates the *static missing state* as low (may predate the integration) | **yes** (policy_type) | yes (H3) | PASS | test_C2, test_H3 | — |
| 17 | shopify_store_policy | present (shipping_policy) | True | False | yes | medium | medium | "store policy record was removed" | same | see above | yes | yes (H4) | PASS | test_C3, test_H4 | — |
| 18 | shopify_store_policy | present | True | None | yes | low | low | "presence state is now unknown or missing" | same | N/A | yes | yes (J4) | PASS | test_J4 | — |
| 19 | shopify_app_scope_summary | sensitive_scope_count | 1 | 3 | yes | high | high | "increased from 1 to 3" | same | no direct Finding on this raw count (Findings use curated write-scope/customer-scope name sets — see parity notes) | no | yes (B4) | PASS | test_B4 | — |
| 20 | shopify_app_scope_summary | sensitive_scope_count | None | 2 | yes | medium | medium (unknown baseline, capped) | "now has 2 sensitive scope(s) ... prior count is unknown" | same | — | no | yes (K1) | PASS | test_K1 | Fixed in prior pass |
| 21 | shopify_app_scope_summary | scope_count | 0 | 5 | yes | medium | medium | "increased from 0 to 5" | same | — | no | yes (K4) | PASS | test_K4 | Confirms real-zero baseline still detected (not conflated with unknown) |
| 22 | shopify_app_scope_summary | payment_scope_present | False | True | yes | critical | critical | "may now access payment data" | same | N/A (no Finding on payment_scope_present specifically) | no | yes (B1) | PASS | test_B1 | — |
| 23 | shopify_domain | ssl_enabled (primary) | True | False | yes | high | high | "primary domain no longer has SSL enabled" | same | shopify_domain_ssl_missing (high) — matches | **yes** (primary) | yes (I8) | PASS | test_I1, test_I8 | — |
| 24 | shopify_domain | ssl_enabled (non-primary) | True | False | yes | low | low | "non-primary domain no longer has SSL enabled" | same | Finding only evaluates primary domain — matches | yes | not yet (mock only) | PASS | test_I2 | — |
| 25 | shopify_domain | verified (primary) | True | False | yes | medium | medium | "primary domain is now unverified" | same | shopify_domain_unverified (medium) — matches | yes | not yet (mock only) | PASS | test_I4 | — |
| 26 | shopify_domain | ssl_enabled | True | None | yes | low | low | "SSL state is now unknown or missing" | same | N/A | yes | yes (I6) | PASS | test_I6 | — |
| 27 | shopify_domain | ssl_enabled + primary (same sync) | non-primary/SSL-on | primary/SSL-off | yes | **high (fixed; was low)** | high | "primary domain no longer has SSL enabled" | same | matches shopify_domain_ssl_missing | **yes (same-sync)** | **yes (L1)** | **FIXED (was FAIL)** | test_L1 | Same-sync context timing bug — fixed this pass |
| 28 | shopify_domain | ssl_enabled + primary (same sync, reverse) | primary/SSL-on | non-primary/SSL-off | yes | low | low | "non-primary domain no longer has SSL enabled" | same | — | yes | yes (L2) | PASS | test_L2 | Symmetric case confirms no over-correction |
| 29 | shopify_domain | primary | False | True | yes | low | low (informational) | "primary-domain status was granted" | same | N/A (Finding doesn't fire on the primary transition itself) | no | not yet (mock only) | PASS | test_I7-adjacent | — |
| 30 | shopify_unknown_future_type | — | — | — | yes | low | low | "unknown record type" fallback | same | N/A | no | yes (E1) | PASS | test_E1 | — |

Totals: **30 cases reviewed** (matching the prior pass's case count for
continuity). **28 PASS**, **2 FIXED (were FAIL)**, **0 remaining FAIL**, **0
GAP** (1 minor documented low-priority test-coverage gap noted in case 12,
not a classification defect).

## Tracked fields vs. classifier coverage

Cross-referenced every field in `_SHOPIFY_TRACKED_FIELDS_BY_TYPE`
(`diff_service.py`) against every branch in `risk_rules/shopify.py`:

| Record type | Specific classification | Grouped generic-low (`fp in (...)`) | Falls through to bottom catch-all |
|---|---|---|---|
| shopify_shop_metadata | shop_name, currency, country_code, password_enabled, checkout_api_supported, has_storefront, eligible_for_payments, requires_extra_payments_agreement | plan_name/plan_display_name (medium), timezone/iana_timezone (low), primary_locale (low), taxes_included/tax_shipping (medium) | none |
| shopify_webhook_subscription | topic, endpoint_domain, endpoint_scheme, is_https, format, api_version | endpoint_path_hash/endpoint_path_length (medium) | none |
| shopify_store_policy | present, body_hash, body_length | none | **policy_type** (falls to bottom catch-all — see note) |
| shopify_app_scope_summary | scope_count, write_scope_count, sensitive_scope_count, payment_scope_present | customer_scope_present/order_scope_present (grouped with payment_scope_present), scope_hash/scope_names (medium) | none |
| shopify_domain | ssl_enabled, primary, verified | host/managed_by_shopify (low) | none |

**One field intentionally falls through to the bottom catch-all**:
`shopify_store_policy.policy_type`. In practice a policy's `policy_type` is
part of its identity/record key (`{shop_domain}:{policy_type}` — see
`shopify_schema.py`), so a standalone `policy_type` change on the same
record is not a realistic transition the connector would ever produce; the
bottom catch-all (`low`, "Shopify store policy field 'policy_type' changed")
is a safe, harmless default for this practically-unreachable case. No
classifier branch references a stale or nonexistent field name, and no
similarly-named fields are confused with each other (verified manually:
`endpoint_scheme` vs `endpoint_domain` vs `endpoint_path_*`, `is_https` vs
`ssl_enabled` (domain) — distinct fields on distinct record types, no
cross-record-type confusion found).

**Metadata keys required by the classifier vs. built by `compute_diff`**: all
5 keys the classifier reads from `provider_metadata` (`topic`, `is_https`,
`endpoint_scheme`, `policy_type`, `primary`) are built by
`_build_provider_metadata()` for their respective record types — confirmed
by direct inspection and by the real-`compute_diff` integration tests
(sections H and L). No metadata key is read by the classifier without a
corresponding builder stanza.

## Mock-shape and provider_metadata verification

- Grepped `risk_rules/shopify.py` and all Shopify test files for
  `old_value`/`previous_value`/`prior_value` — clean; only `prev_value` is
  used, correctly, everywhere.
- `TestRealComputeDiffIntegration` (section H, 5 tests) and
  `TestSameSyncContextTiming` (section L, 4 new tests this pass) call the
  real `compute_diff()` with plain snapshot dicts — not `MagicMock` — and
  assert on the classifier's output. These tests would fail if
  `provider_metadata` construction regressed (verified: reverting the
  `context_record` fix locally reproduces the `low`/`high` misclassifications
  in cases 13 and 27 above).
- `TestDomainClassification`'s `test_I8` and the webhook `test_H1`–`H5`
  cover the "added"/"modified" real-compute_diff paths for all 5 metadata
  keys except the pure-restoration direction (SSL/verified/HTTPS turning
  back on) and non-primary-domain SSL/verified, which are still mock-only
  (cases 12, 24, 25, 29 above) — these are lower-priority since the
  classification logic path is identical to the already-covered directions
  and no metadata-dependent branching differs.

## Parity with Security Findings

| Finding | Severity | Change classifier | Alignment |
|---|---|---|---|
| shopify_webhook_http | critical (any HTTP scheme, any topic) | critical (critical topic) / high (other) | Documented intentional disagreement — Finding is worst-case current-state; Change scales by topic evidence per this task's own convention |
| shopify_webhook_high_risk_topic | medium | N/A (Change classifies HTTP/topic-change transitions, not topic-presence itself) | Finding-only state, documented |
| shopify_app_broad_write_scopes | medium (≥3 curated)/high (≥4 curated) | write_scope_count increase → high (any write scope, not curated-intersection-scoped) | Documented granularity difference: Change uses the raw count as a coarser signal; the curated-scope-name Finding is the authoritative check. Not a bug — no unsafe overstatement (both cap at high, never critical) |
| shopify_app_customer_data_scope | high | customer_scope_present/order_scope_present newly True → high | Matches |
| shopify_domain_ssl_missing | high (primary only) | ssl_enabled primary→False → high | Matches (and now correctly scoped even in same-sync timing edge cases) |
| shopify_domain_unverified | medium (primary only) | verified primary→False → medium | Matches |
| shopify_policy_missing | low (uniform, current-state) | present→False → high (legal) / medium (operational) | Documented intentional disagreement — Change rates the removal *transition* (a regression) higher than the Finding rates the static *missing* state (may predate the integration), consistent with the established pattern from every other provider's classification-QA pass this session |

No severity was found to unsafely *understate* risk relative to its
Finding (the two disagreements above are always Change ≥ Finding, never <).
No unknown/missing value triggers a Finding-level high/critical.

## Count and threshold handling

- Grepped `risk_rules/shopify.py` for `int(.*or 0)` and `(x or 0)` patterns —
  zero matches; `_int_or_none()` is used correctly for all three count
  fields (`sensitive_scope_count`, `write_scope_count`, `scope_count`).
- `test_K1`–`test_K3` prove an unknown (`None`) baseline is never coerced to
  `0` and never claims a specific "increased from X to Y" — capped at
  medium/low with "prior count is unknown" wording.
- `test_K4`/`test_K5` prove a *real* `0` baseline still correctly triggers
  the intended increase classification (medium/high respectively) — the
  fix does not overcorrect into treating real zeroes as unknown.
- No threshold-crossing-only logic exists in `risk_rules/shopify.py` (no
  `THRESHOLD` constant, unlike Datadog's classifier) — Shopify's count
  fields use simple increase/decrease comparison, so the "over-threshold
  increase falls to low" bug class does not apply here. N/A, not a gap.

## Boolean unknown handling

All 8 boolean branches (`password_enabled`, `eligible_for_payments`,
`has_storefront`, `checkout_api_supported`,
`requires_extra_payments_agreement`, webhook `is_https`, webhook
`endpoint_scheme`, store-policy `present`) plus the 3 new domain boolean
branches (`ssl_enabled`, `verified`, `primary`) were re-verified via
`_is_explicit_bool()`:

- Explicit `True`/`False` (or the string equivalents `"true"`/`"false"`)
  are the only values that trigger a directional claim.
- `None`/missing always returns a `low` "...state is now unknown or
  missing" result — never a high/critical, and never claims the opposite
  explicit state.
- `test_J1`–`test_J4` (11 parametrized cases) and `test_I6` cover this
  directly; all pass.

## Copy safety

Re-scanned all classifier reason strings (via `test_G1`/`test_G2` plus a
manual read of every `return` statement in `risk_rules/shopify.py`) for
`breach`, `compromise`, `attacker`, `leak`, `unauthorized access`, `order(s)
exposed`, `customer data exposure`, `payment fraud`, `card exposure`,
`credential exposure`, `token exposure`, `secret exposure`, `data exposure`,
`customer impact` — zero matches. All copy uses "may require review", "may
affect ... operations", "verify this change is intentional", or similar
advisory framing.

## Fixes made

1. `diff_service.py`: `_build_provider_metadata()` now prefers `alt_record`
   (the new record) over `record` (the old record) for the `topic`,
   `policy_type`, and `primary` context fields on "modified" Changes —
   fixing the same-sync context-timing bug (cases 13 and 27 above). Falls
   back to `record` when `alt_record` is `None` (added/removed events).
2. `tests/test_shopify_risk_audit.py`: added `TestSameSyncContextTiming`
   (4 new tests, section L) proving the fix and its symmetric case.
3. `tests/reports/shopify_change_classification_matrix.md`: this report
   (new).

No changes were needed to `risk_rules/shopify.py`, `security_rules/
shopify.py`, any of the 4 backend registries, the correlation-rules dict, or
the frontend catalog — all were already correct from the prior detection-QA
pass.

## Validation run

- `docker compose exec api pytest tests/test_shopify_risk_audit.py -q` →
  **78 passed, 1 skipped** (was 74 passed, 1 skipped before this pass; +4
  new tests, 0 regressions).
- `docker compose exec api pytest tests -q -k "shopify and risk"` → **151
  passed, 1 skipped, 17230 deselected**.
- `docker compose exec api pytest tests -q -k "shopify and diff"` → **16
  passed, 17366 deselected**.
- `docker compose exec api pytest tests -q -k "shopify"` → **295 passed, 1
  skipped, 17086 deselected**.
- `docker compose exec api pytest tests/test_shopify_risk_audit.py
  tests/test_milestone57_5.py tests/test_milestone57_9.py
  tests/test_milestone60_4_5_stripe_vercel_shopify_rules.py
  tests/test_milestone74a_shopify_security_provider_foundation.py
  tests/test_milestone74b_shopify_activity_ingestion.py
  tests/test_milestone74c_shopify_activity_signals.py
  tests/test_milestone74d_shopify_correlations.py
  tests/test_milestone74e_shopify_demo_qa.py -q` → **365 passed, 1
  skipped**.
- `test_*shopify*` glob → **166 passed, 1 skipped**.
- No frontend files were changed in this pass, so `npx tsc --noEmit` was not
  required.
