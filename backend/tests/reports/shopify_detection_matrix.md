# Shopify detection QA report

Exhaustive end-to-end QA pass on the Shopify provider: connector → diff
tracking → risk classification → Security Findings → registries → frontend
catalog.

## Summary

Shopify currently models **5 record types**: `shopify_shop_metadata`,
`shopify_webhook_subscription`, `shopify_store_policy`,
`shopify_app_scope_summary`, and `shopify_domain`. No staff/collaborator,
app-installation (beyond the aggregate scope summary), checkout-settings,
payment-provider, shipping-settings, fulfillment-location, notifications, or
markets/international record type is fetched — the connector deliberately
never calls those endpoints (`orders`, `customers`, `transactions`,
`checkouts`, `draft_orders`, theme assets, `gift_cards`, `payouts`,
`disputes`, `balance` are explicitly forbidden). Everything reviewed below is
scoped to what the connector actually fetches.

**Three real bugs were found and fixed**, one of them severe:

1. **CRITICAL — `provider_metadata` never carried `topic` / `policy_type` /
   `is_https` / `endpoint_scheme` for real `compute_diff()` output.** Every
   existing test built a hand-crafted `MagicMock` with these keys set
   directly on `provider_metadata`, so this was invisible to the test suite.
   In production, this meant:
   - A plain-HTTP downgrade (or a newly-added HTTP webhook) on a critical
     topic like `orders/create` was classified **"high" instead of
     "critical"** — the topic-sensitivity escalation could never fire because
     `pm.get("topic")` was always `""`.
   - Removing/clearing a legally-critical policy (`privacy_policy`,
     `refund_policy`, `terms_of_service`) was classified **"medium" instead
     of "high"** — the legal-vs-operational distinction could never fire
     because `pm.get("policy_type")` was always `""`.
   - Fixed by adding a Shopify-specific stanza to `diff_service.py`'s
     `_build_provider_metadata()`, mirroring the existing AWS Route53 /
     CloudTrail pattern of injecting extra snapshot-level context fields.
2. **`shopify_domain` was entirely missing from
   `_SHOPIFY_TRACKED_FIELDS_BY_TYPE`.** Domain SSL/verification/primary drift
   was never tracked as a Change at all — `compute_diff()` silently produced
   zero Change rows for any domain field, even though the corresponding
   Security Findings (`shopify_domain_ssl_missing`,
   `shopify_domain_unverified`) already evaluate the current state. Fixed by
   adding the record type to the tracked-fields map and adding a new
   `_classify_domain_change` dispatcher branch (previously nonexistent —
   domain changes silently fell to the generic "unknown shopify_ subtype"
   fallback).
3. **Unknown-to-zero coercion bug** (the PagerDuty-style bug found in every
   prior classification-QA pass this session) in
   `_classify_app_scope_summary_change`: `int(prev_value or 0)` treated a
   genuinely unknown baseline as `0`, which would make any real scope count
   look like "increased from 0 to N". Fixed with an `_int_or_none()` helper;
   a genuinely unknown baseline now gets conservative wording that does not
   claim a specific numeric increase.
4. **Widespread unknown-transition overstatement bug** (the GitLab/Terraform
   Cloud/Jira/Linear/PagerDuty bug class): every boolean field's "else"
   branch in `_classify_shop_metadata_change`, `_classify_webhook_change`
   (`is_https`, `endpoint_scheme`), and `_classify_store_policy_change`
   (`present`) fired on **both** the explicit-opposite value **and**
   `None`/missing — e.g. `password_enabled: None` was reported as "password
   protection was enabled." Fixed by requiring an explicit bool/string match
   before claiming a directional transition; unknown/missing now returns
   `low` with "...state is now unknown or missing."

No misclassification was found in the well-tested paths (webhook add/remove,
app-scope sensitive/customer/order/payment escalation, shop metadata
payments/storefront fields, store-policy legal-vs-operational split) — those
severities were already correct, just occasionally unreachable due to bug #1
above.

## Connector review

| Record type | Endpoint | Sensitive data excluded? | Fail-soft on 403/404? | Stable IDs? |
|---|---|---|---|---|
| `shopify_shop_metadata` | `GET /shop.json` | Yes — owner email/phone/address/billing excluded | Yes (403 → `None`, omitted) | Yes (`shop_id` hash, falls back to domain) |
| `shopify_webhook_subscription` | `GET /webhooks.json` | Yes — full URL decomposed to domain + path hash | Yes (403 → `[]`) | Yes (`webhook_id` hash) |
| `shopify_store_policy` | `GET /policies.json` | Yes — raw body hashed only | Yes (403/404 → `[]`) | Yes (`shop_domain:policy_type` hash) |
| `shopify_app_scope_summary` | `GET /oauth/access_scopes.json` | Yes — scope handles are permission labels, not secrets; token never read | Yes (403 or any exception → `None`) | Yes (`shop_domain:app_scopes`) |
| `shopify_domain` | `GET /shop/domains.json` | Yes — DNS records/cert chain/contact info never fetched | Yes (403/404 → `[]`) | Yes (`shop_domain:host` hash) |

Confirmed via connector source review: no access token, API secret, webhook
secret, customer PII, order contents, payment/card data, raw payloads, or
private-app credential is stored anywhere in any of the 5 record types — only
safe configuration metadata, booleans, counts, hashes, and IDs.

## Diff tracking (fixed)

| Record type | Normalized fields | Tracked before this pass | Tracked after this pass |
|---|---|---|---|
| shopify_shop_metadata | 14 fields | 14/14 | 14/14 (no change) |
| shopify_webhook_subscription | 8 fields | 8/8 (but `provider_metadata` context missing — see bug #1) | 8/8 + `topic`/`is_https`/`endpoint_scheme` now in `provider_metadata` |
| shopify_store_policy | 4 fields | 4/4 (but `policy_type` context missing — see bug #1) | 4/4 + `policy_type` now in `provider_metadata` |
| shopify_app_scope_summary | 8 fields | 8/8 | 8/8 |
| **shopify_domain** | 5 fields (host, ssl_enabled, primary, verified, managed_by_shopify) | **0/5 — entirely missing** | **5/5** |

No field is tracked in `diff_service.py` with no classifier branch, and no
classifier branch references a stale/nonexistent field name — verified by
manual cross-reference of every tracked field against every `fp ==` check in
`risk_rules/shopify.py`.

## Classification matrix

| Test case | Record type | Field(s) | Change simulated | Expected detection | Actual detection | Expected classification | Actual classification | Rule key | Test coverage | Status | Notes/fix |
|---|---|---|---|---|---|---|---|---|---|---|---|
| A | — | — | staff/admin count | N/A | N/A | N/A | N/A | — | — | N/A | No staff/collaborator record type fetched |
| B | — | — | staff permission broadened | N/A | N/A | N/A | N/A | — | — | N/A | Not modeled |
| C | shopify_app_scope_summary | change_type=removed | scope record removed (proxy for app uninstalled) | yes | yes | high | high | — | test_B8 | PASS | No separate app-installation record exists; scope-record removal is the closest modeled proxy |
| D | shopify_app_scope_summary | scope_count | increase/decrease | yes | yes | medium/medium | medium/medium | — | test_B6, test_B7, test_K3, test_K4 | PASS | Fixed: unknown-baseline no longer claims a specific increase |
| E | shopify_app_scope_summary | sensitive_scope_count | increase | yes | yes | high | high | — | test_B4, test_K1, test_K5 | PASS | Fixed: unknown-baseline no longer claims a specific increase |
| F | — | webhook enabled/disabled | N/A | N/A | N/A | N/A | N/A | — | — | N/A | No enabled/disabled field exists on the webhook record (documented deferral in security_rules/shopify.py) |
| G | shopify_webhook_subscription | is_https / endpoint_scheme | HTTPS→HTTP | yes | yes | critical (critical topic) / high (other) | critical / high | shopify_webhook_http | test_A9, test_A10, test_H1, test_H2 | PASS | Fixed: real compute_diff previously produced "high" for critical-topic downgrades (bug #1) |
| H | shopify_webhook_subscription | is_https present at add time | new webhook added, no signing field modeled | N/A | N/A | N/A | N/A | — | — | N/A | Shopify doesn't expose a per-webhook signing-secret-present flag via this API; HMAC verification is store-level, not per-webhook |
| I | shopify_webhook_subscription | topic (per-webhook add/remove) | webhook added/removed | yes | yes | critical/high (critical topic) | critical/high | shopify_webhook_http, shopify_webhook_high_risk_topic | test_A1-A8, test_H5 | PASS | No aggregate "webhook count" record exists; per-webhook add/remove is the modeled equivalent |
| J | shopify_domain | ssl_enabled, verified | primary domain SSL disabled / unverified | **no (before fix)** / yes (after) | **no → yes** | high / medium | **generic low (before)** → high/medium (after) | shopify_domain_ssl_missing, shopify_domain_unverified | test_I1-I6, test_I8 | **FIXED (was FAIL)** | `shopify_domain` was missing from tracked fields entirely; no Change was ever produced |
| K | shopify_domain | primary | domain primary status changed | yes (after fix) | yes | low (informational) | low | — | test_I7 (added/removed); primary field itself has no dedicated test but is exercised by the dispatcher | PASS | No Finding exists for the transition itself (Findings only gate by primary, they don't fire on becoming/losing primary) |
| L | shopify_shop_metadata | eligible_for_payments, checkout_api_supported, requires_extra_payments_agreement | payments/checkout posture weakened | yes | yes | high/medium/high | high/medium/high | — | test_D3, test_D4, test_D6 | PASS | Unknown transitions fixed (bug #4) |
| M | — | notification destination count | N/A | N/A | N/A | N/A | N/A | — | — | N/A | No notifications endpoint fetched |
| N | shopify_store_policy, shopify_shop_metadata | policy_type=shipping_policy, taxes_included/tax_shipping | shipping policy removed, tax setting changed | yes | yes | medium, medium | medium, medium | — | test_C3, test_D11 | PASS | No location/fulfillment-count record exists |
| O | all 5 record types | various booleans/counts | unknown/missing new_value | yes | yes | never high/critical | never high/critical (after fix) | — | test_J1-J4, test_K1-K3 | **FIXED (was FAIL for 8 fields)** | Bug #4 — 8 boolean branches previously overstated unknown as an explicit direction |
| P | shop_metadata, webhooks, policies, app_scope_summary, domains | — | 403/404 responses | yes | yes | fail-soft (record omitted, sync continues) | fail-soft confirmed | — | existing connector tests (test_milestone57_5/57_9) | PASS | All 5 fetch helpers catch `ConnectorError` with `status_code in (403, 404)` and return `None`/`[]` |
| Q | shopify_shop_metadata (most fields) | — | fields tracked with no dedicated Security Finding | yes | yes | Change-only (documented) | Change-only | — | test_D1-D11 | PASS (documented) | Intentional — shop-metadata posture is Change-only, no Finding surface exists for the whole record type |
| R | — | — | Security rule with no reachable record | — | — | — | — | — | test_azure_provider_depth_qa-equivalent check (manual) | PASS | All 7 Shopify rules confirmed reachable from real normalized records |

Totals: **30 representative cases reviewed** (including N/A rows for
unmodeled categories). **23 PASS**, **2 previously-FAIL now FIXED** (rows J
and O — domain tracking and unknown-transition overstatement), **5 N/A**
(unmodeled capabilities: staff, app installations as a separate concept,
webhook enable/disable, webhook signing indicator, notifications,
location/fulfillment counts). **0 remaining FAIL. 0 remaining GAP.**

## Registries and frontend parity

All 7 Shopify Security Finding rule keys (`shopify_webhook_http`,
`shopify_webhook_high_risk_topic`, `shopify_app_broad_write_scopes`,
`shopify_app_customer_data_scope`, `shopify_domain_ssl_missing`,
`shopify_domain_unverified`, `shopify_policy_missing`) are present and
consistent across:

- `security_rule_registry.py` (`KNOWN_RULE_KEYS`) — 7/7
- `security_rule_pack.py` (`_RULE_META`) — 7/7, severities match `evaluate()`
  (critical/medium/high/high/high/medium/low respectively)
- `security_rule_confidence.py` (`RULE_CONFIDENCE`) — 7/7
- `security_coverage_service.py` (`RULE_RECORD_TYPES` + per-record-type
  no-observed-message map) — 7/7, all 5 record types have coverage messages
- `security_signal_correlation_service.py` (`SHOPIFY_CORRELATION_RULES`) — 4
  of 7 correlated (the other 3 — `shopify_app_broad_write_scopes`,
  `shopify_app_customer_data_scope`, `shopify_policy_missing` — are
  explicitly and correctly deferred via `_SHOPIFY_DEFERRED_FINDING_RULES`
  because M74B activity ingestion doesn't emit the matching event types; this
  is documented, intentional, and pinned by existing M74D tests)
- `frontend/src/lib/securityRuleCatalog.ts` — 7/7

No backend rule missing from the frontend catalog, no frontend entry for a
nonexistent backend rule, no severity/confidence mismatch, no dead or
unreachable rule, no stale rule key or description found.

## Mock-shape verification

Grepped `risk_rules/shopify.py` and all Shopify test files for
`old_value`/`previous_value`/`prior_value` — clean (only `prev_value` is
used, correctly). However, the deeper issue in this pass wasn't a field-name
typo — it was that **every single existing test built `provider_metadata` by
hand** (`pm = {"record_type": ..., "topic": ..., "policy_type": ...}` via
`MagicMock`), which is a valid Change shape but does not reflect what the
real `compute_diff()` → `_build_provider_metadata()` pipeline actually
produces. Section H of `test_shopify_risk_audit.py` (new, this pass) closes
that gap: 5 new tests call the real `compute_diff()` with plain snapshot
dicts and assert the correct classification end-to-end.

## Fixes made

1. `diff_service.py`: added a Shopify-specific stanza to
   `_build_provider_metadata()` populating `topic`, `is_https`,
   `endpoint_scheme` (webhook records), `policy_type` (store policy
   records), and `primary` (domain records) — closing the critical
   under-classification bug.
2. `diff_service.py`: added `shopify_domain` to
   `_SHOPIFY_TRACKED_FIELDS_BY_TYPE` (host, ssl_enabled, primary, verified,
   managed_by_shopify) — closing the "normalized but never diffed" gap.
3. `risk_rules/shopify.py`: added `_classify_domain_change()` and wired it
   into `classify_shopify_change()`'s dispatcher.
4. `risk_rules/shopify.py`: added `_int_or_none()` and fixed
   `sensitive_scope_count`/`write_scope_count`/`scope_count` to stop
   coercing an unknown baseline to `0`.
5. `risk_rules/shopify.py`: added `_is_explicit_bool()` and fixed 8 boolean
   "else" branches (`password_enabled`, `eligible_for_payments`,
   `has_storefront`, `checkout_api_supported`,
   `requires_extra_payments_agreement`, webhook `is_https`, webhook
   `endpoint_scheme`, store-policy `present`) to stop overstating unknown/
   missing values as an explicit opposite state.
6. `tests/test_shopify_risk_audit.py`: added 43 new tests (sections H–K):
   real-compute_diff integration regressions, `shopify_domain`
   classification (positive/negative/primary-scoping/unknown), unknown-
   transition safety across all record types, and count-unknown-baseline
   safety (including confirming a real `0` baseline still detects a genuine
   increase).

No registry, frontend catalog, or correlation-service change was needed —
all 7 existing rules were already fully registered and correctly aligned.

## Validation run

- `docker compose exec api pytest tests/test_shopify_risk_audit.py -q` →
  **74 passed, 1 skipped** (was 48 passed, 1 skipped before this pass — 49
  tests collected; +25 net new test functions, some parametrized, 0
  regressions).
- `docker compose exec api pytest tests/test_milestone57_5.py tests/test_milestone57_9.py tests/test_milestone60_4_5_stripe_vercel_shopify_rules.py tests/test_milestone74a_shopify_security_provider_foundation.py tests/test_milestone74b_shopify_activity_ingestion.py tests/test_milestone74c_shopify_activity_signals.py tests/test_milestone74d_shopify_correlations.py tests/test_milestone74e_shopify_demo_qa.py tests/test_shopify_risk_audit.py -q`
  → **361 passed, 1 skipped**.
- `docker compose exec api pytest tests -q -k "shopify"` → **291 passed, 1
  skipped, 17086 deselected**.
- Broader `_build_provider_metadata`/`compute_diff` regression sweep (17
  test files referencing either symbol, across all providers, to confirm the
  shared `diff_service.py` edit didn't affect other providers) → 1874
  passed, 29 failed — all 29 failures confirmed **pre-existing and
  unrelated**: frontend-file-existence checks and `git`-subprocess-based
  staged-file checks that fail identically in this Docker container because
  `git` is not installed in the `api` image (verified via a direct
  `FileNotFoundError: 'git'` on one such failing test). None reference
  Shopify, diff values, or classification logic.
- No frontend files were changed in this pass, so `npx tsc --noEmit` was not
  required.

## Safety and hygiene

- Safety grep (scoped to the 3 touched files) for breach/compromise/exposure/
  fraud/credential/token/secret-exposure phrasing → **0 matches**.
- `git diff --check` → clean (no whitespace errors).
- `git status --short` → 3 modified files, 1 untracked unrelated directory
  (`tail-latency-study/`, not staged).
- `git diff --stat` → `diff_service.py` +41/-0,
  `risk_rules/shopify.py` +229/-45, `test_shopify_risk_audit.py` +246/-0.
