# Stripe Detection-QA Matrix

Scope: **detection only** — connector normalization, diff reachability,
classifier routing, Security Finding reachability, registry/frontend parity,
and sensitive-data minimization. Exhaustive transition-severity, restoration,
and numeric/list edge-case QA is reserved for the dedicated Stripe
change-classification pass (message 2) and is **not** covered here.

## Graphify summary

All four required queries ran successfully via
`/Users/rohan/.local/bin/graphify`. The graph's node granularity is
class/module-level, not field-level, so it surfaced generic cross-provider
neighbors (every connector class, `Change`, `SecurityFinding`) alongside a
few genuinely useful leads: `StripeConnector`, `risk_rules/stripe.py`
("Stripe risk classification rules — M35"), a Stripe security-rules module
("M60.4 / M73A"), a "Stripe provider depth QA" node describing itself as
durable guardrails pinning the Stripe rule taxonomy, `StripePaymentMethod
ConfigurationRecord`/`StripePaymentMethodDomainRecord`, and "Stripe Part 1 —
catalog (Products + Prices) + Payment Links + Checkout configuration" — the
last of which correctly hinted that more record types exist than the prior
context's summary mentioned. The graph did not surface
`test_stripe_provider_depth_qa.py`, `BROAD_WEBHOOK_EVENT_THRESHOLD`, or this
new report by name — it is stale relative to the most recent Stripe
provider-depth commit. Proceeded via direct reads of the connector, schema,
diff_service, risk_rules, and security_rules files as authoritative.

## Record-type inventory

**17 record types are defined in `stripe_schema.py`. Only 6 are ever
produced by `StripeConnector.fetch()`** — confirmed via the connector's
import block (only imports `STRIPE_ACCOUNT_SETTINGS`,
`STRIPE_BILLING_PORTAL_CONFIG`, `STRIPE_PAYMENT_LINK`,
`STRIPE_PAYMENT_METHOD_CONFIGURATION`, `STRIPE_PAYMENT_METHOD_DOMAIN`,
`STRIPE_WEBHOOK_ENDPOINT`) and a full read of `fetch()`, which calls exactly
6 `_fetch_*` helpers. This is the same "classifier built ahead of the
connector" pattern found in every other provider's detection-QA pass this
session (Vercel 7/12 unreachable, GitHub 6/16 unreachable) — here it's the
largest gap yet: **11 of 17 (65%) are schema-defined and have full
`risk_rules/stripe.py` classifier logic, but are never fetched.**

| # | Record type | Emitted? | Endpoint | Scope |
|---|---|---|---|---|
| 1 | `stripe_account_settings` | Yes | `GET /v1/account` | account (optional — 403-skippable for restricted keys) |
| 2 | `stripe_webhook_endpoint` | Yes | `GET /v1/webhook_endpoints` | account |
| 3 | `stripe_payment_method_configuration` | Yes | `GET /v1/payment_method_configurations` | account |
| 4 | `stripe_payment_method_domain` | Yes | `GET /v1/payment_method_domains` | account |
| 5 | `stripe_billing_portal_config` | Yes (M57.9) | `GET /v1/billing_portal/configurations` | account |
| 6 | `stripe_payment_link` | Yes (M73A) | `GET /v1/payment_links` | account |
| 7 | `stripe_product` | **No — unreachable** | schema-defined only | — |
| 8 | `stripe_price` | **No — unreachable** | schema-defined only | — |
| 9 | `stripe_checkout_configuration` | **No — unreachable** | schema-defined only | — |
| 10 | `stripe_tax_settings` | **No — unreachable** | schema-defined only | — |
| 11 | `stripe_radar_rule` | **No — unreachable** | schema-defined only | — |
| 12 | `stripe_restricted_api_key` | **No — unreachable** | schema-defined only | — |
| 13 | `stripe_subscription_invoice_settings` | **No — unreachable** | schema-defined only | — |
| 14 | `stripe_dunning_settings` | **No — unreachable** | schema-defined only | — |
| 15 | `stripe_external_account` | **No — unreachable** | schema-defined only | — |
| 16 | `stripe_coupon` | **No — unreachable** | schema-defined only | — |
| 17 | `stripe_promotion_code` | **No — unreachable** | schema-defined only | — |

Per instructions, no endpoint support was added for the 11 unreachable
types — documented as GAP, consistent with the Vercel/GitHub precedent
where unreachable-but-classified types were left unimplemented rather than
invented.

**Side-channel activity ingestion**: `list_activity_events()` (M73B) reads
`/v1/events` filtered to a strict configuration-only allowlist
(`webhook_endpoint.*`, `payment_link.*`, `billing_portal.configuration.*`,
`account.updated`, `capability.updated`) — a separate pipeline from
`fetch()`/`compute_diff()`, feeding activity/signal/correlation services
directly, never becoming drift `Change` rows through the standard
evaluator. Documented, not a gap.

**Field-level gap within a reachable type**: `stripe_payment_link`'s
TypedDict schema defines `line_item_count`, `line_item_price_ids`,
`transfer_destination_present`, and `subscription_data_trial_period_days` —
none of these are ever populated by `_fetch_payment_links()` (line items
aren't expanded). `risk_rules/stripe.py`'s `_classify_payment_link_change`
has dead sub-branches reading `line_item_price_ids`/`line_item_count`/
`subscription_data_trial_period_days` that can never fire (always `None`).
Documented as GAP; not tracked in `diff_service.py` and not invented,
consistent with "do not invent new Stripe endpoints merely to increase
coverage."

## Lettered detection matrix (A–AE)

| Case | Category | Record type | Source endpoint | Field(s) | Posture simulated | Emits evidence? | Detected by `compute_diff`? | Classifier route | Finding key | Reachable? | Registry/frontend parity | Test coverage | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| A | Account charges enabled/disabled | account_settings | GET /v1/account | charges_enabled | true→false | Yes | Yes | `_classify_account_settings_change` | `stripe_account_capability_incomplete` | Yes | full | test_stripe_risk_audit.py | PASS |
| B | Account payouts enabled/disabled | account_settings | GET /v1/account | payouts_enabled | true→false | Yes | Yes | same | same | Yes | full | test_stripe_risk_audit.py | PASS |
| C | Account restriction/status changed | account_settings | GET /v1/account | details_submitted | true→false | Yes | Yes | same | same | Yes | full | test_stripe_risk_audit.py | PASS |
| D | Webhook HTTP/HTTPS | webhook_endpoint | GET /v1/webhook_endpoints | url | https→http | Yes | Yes | `_classify_webhook_endpoint_change` | `stripe_webhook_http` | Yes | full | test_stripe_risk_audit.py | PASS |
| E | Webhook enabled/disabled | webhook_endpoint | same | status | enabled→disabled | Yes | Yes | same | `stripe_webhook_disabled` | Yes | full | test_stripe_detection_qa.py (real diff) | PASS |
| F | Wildcard event posture | webhook_endpoint | same | enabled_events | ["a"]→["*"] | Yes | Yes | same | `stripe_webhook_broad_events` | Yes | full | test_stripe_risk_audit.py | PASS |
| G | Broad event-count threshold | webhook_endpoint | same | enabled_events count | 10→50 | Yes | Yes | same | `stripe_webhook_broad_events` (named constant `BROAD_WEBHOOK_EVENT_THRESHOLD=50`) | Yes | full | test_stripe_provider_depth_qa.py | PASS |
| H | Event count increase/decrease | webhook_endpoint | same | enabled_events | count changed, no critical event dropped | Yes | Yes | same | n/a (Change-only) | n/a | n/a | test_stripe_risk_audit.py | PASS |
| I | Event count unknown vs. zero | webhook_endpoint | same | enabled_events | `None` vs `[]` | Connector always emits a list (never None) | n/a in practice | same | n/a | n/a | n/a | not applicable — connector guarantees a list | N/A |
| J | Webhook API version changed | webhook_endpoint | same | api_version | "2023-01-01"→"2024-06-20" | Yes | Yes | same | n/a (Change-only) | n/a | n/a | test_stripe_risk_audit.py | PASS |
| K | Webhook added/removed | webhook_endpoint | same | whole record | present↔absent | Yes | Yes | same | Finding evaluated on add (current-state) | Yes | full | test_stripe_risk_audit.py | PASS |
| L | API-key broad permissions | restricted_api_key | N/A — not fetched | permissions_count/has_write_permission | — | No (unreachable) | No | dead `_classify_restricted_api_key_change` | none | No | n/a | mock-only (dead) | GAP |
| M | API-key active/disabled | restricted_api_key | N/A — not fetched | — | — | No | No | dead branch | none | No | n/a | none | GAP |
| N | Payment-method config enabled/disabled | payment_method_configuration | GET /v1/payment_method_configurations | is_default | true→false | Yes | Yes | `_classify_payment_method_configuration_change` | none (intentionally deferred) | n/a | n/a (no Finding by design) | test_stripe_risk_audit.py | PASS |
| O | Individual payment method changed | payment_method_configuration | same | enabled_payment_methods | dict value toggled | Yes | Yes | same | none (deferred) | n/a | n/a | test_stripe_risk_audit.py | PASS |
| P | Payment-method domain enabled/disabled | payment_method_domain | GET /v1/payment_method_domains | enabled | true→false | Yes | Yes | `_classify_payment_method_domain_change` | none (deferred) | n/a | n/a | test_stripe_detection_qa.py (real diff) | PASS |
| Q | Payment-method domain validation changed | payment_method_domain | same | apple_pay_enabled/google_pay_enabled | active→inactive | Yes | Yes | same | none (deferred) | n/a | n/a | test_stripe_risk_audit.py | PASS |
| R | Checkout/capture posture | checkout_configuration | N/A — not fetched | — | — | No (unreachable) | No | dead `_classify_checkout_configuration_change` | none | No | n/a | mock-only (dead) | GAP |
| S | Automatic tax changed | payment_link | GET /v1/payment_links | automatic_tax_enabled | true→false | Yes | **Was No → Fixed** | `_classify_payment_link_change` | `stripe_payment_link_tax_disabled` (current-state Finding) | Yes | full | test_stripe_detection_qa.py (new) | **FIXED** |
| T | Radar/fraud-protection posture | radar_rule | N/A — not fetched | — | — | No (unreachable) | No | dead `_classify_radar_rule_change` | none | No | n/a | mock-only (dead) | GAP |
| U | Optional endpoint 403/404 | all 6 live types | various | — | 403 on one endpoint | Fail-soft confirmed: each `_fetch_*` catches its own `ConnectorError`/`AuthenticationError` independently; one endpoint's 403 never suppresses another's records | n/a | n/a | n/a | n/a | test_stripe_provider_depth_qa.py, test_milestone57_9.py | PASS |
| V | Unknown Boolean | webhook_endpoint | same | status | missing/`None` | Connector always emits `""` default, never `None`, for a present record | n/a in practice for the 6 live types via fresh fetch; latent risk only for pre-existing snapshots missing the key entirely | `_classify_webhook_endpoint_change`'s `status` check could misfire on `None` (falls to "else" → false "re-enabled" claim) | n/a | n/a | not covered | GAP (documented — flagged for Stripe message 2, a classification-severity nuance, not a routing defect) |
| W | Unknown numeric count | (dead types only) | N/A | various counts | `None`→coerced to 0 via `int(x or 0)` | No (all 5 occurrences are inside the 11 dead classifier branches) | n/a | n/a | n/a | n/a | none | GAP (documented, no live path) |
| X | Real provider metadata | payment_link | GET /v1/payment_links | livemode | missing→now populated | Yes | Yes | `_classify_payment_link_change` via `_is_production_payment_link` | n/a | n/a | n/a | test_stripe_detection_qa.py (new) | **FIXED** |
| Y | Normalized-but-untracked field | payment_link | same | active, allow_promotion_codes, automatic_tax_enabled, etc. (11 fields) | — | Yes | **Was No → Fixed** (empty tracked-fields tuple) | `_classify_payment_link_change` | n/a | n/a | n/a | test_stripe_detection_qa.py (new) | **FIXED** |
| Z | Tracked-but-not-emitted field | payment_link | same | line_item_count, line_item_price_ids, subscription_data_trial_period_days | — | No (connector never populates) | No | dead sub-branches within `_classify_payment_link_change` | n/a | n/a | n/a | none | GAP (documented, not invented) |
| AA | Unreachable Security Finding | n/a | N/A | — | — | No | No | n/a | none exists for the 11 unreachable types | No | n/a | n/a | GAP (documented) |
| AB | Record with no Finding | payment_method_configuration, payment_method_domain | live endpoints | — | — | Yes | Yes | classified for Change, no Finding by design | none (intentional) | n/a | n/a — frontend confirmed not to overclaim | test_stripe_risk_audit.py | PASS (intentional, not a gap) |
| AC | Registry/evaluator/frontend parity | all 8 live rule keys | n/a | n/a | n/a | n/a | n/a | n/a | all 8 | Yes | **full — verified this pass** | test_stripe_provider_depth_qa.py | PASS |
| AD | Sensitive-data minimization | all 6 live types | n/a | secrets/keys/PII/card data | never stored | Never stored (verified) | n/a | n/a | n/a | n/a | test_stripe_provider_depth_qa.py + greps this pass | PASS |
| AE | Activity/runtime events separated from drift records | n/a | GET /v1/events (M73B) | allowlisted event types only | — | Yes (separate pipeline) | n/a — feeds signals/correlations, not compute_diff | n/a | n/a | n/a | test_milestone73b/c/d_stripe_*.py | PASS |

## Root-cause bugs found and fixed this pass

1. **`stripe_payment_link` had no entry in `_STRIPE_TRACKED_FIELDS_BY_TYPE`**
   (`diff_service.py`) despite being a live, connector-emitted, fully
   classified record type. The safe `.get(rt, ())` fallback meant
   `compute_diff()` used an empty tracked-fields tuple, so real field-level
   drift (a link disabled, promotion codes toggled, redirect changed) was
   never detected as a "modified" Change — only whole-record added/removed
   events worked. **Fixed**: added a tracked-fields tuple covering every
   field the connector actually populates (`active`,
   `allow_promotion_codes`, `automatic_tax_enabled`, `after_completion_type`,
   `after_completion_redirect_origin`, `success_url_origin`,
   `customer_creation`, `payment_method_collection`,
   `payment_method_types_count`, `application_fee_amount`,
   `application_fee_percent`).
2. **`_classify_payment_link_change`'s `_is_production_payment_link()` reads
   `pm.get("livemode")`, but `_build_provider_metadata()` had no
   Stripe-specific stanza** — only the generic `record_name`/`record_content`
   keys were populated. In production, `livemode` was always missing, so the
   classifier's "assume production when missing" fallback made every
   payment link — test-mode or live — always classify as production. Not an
   under-classification (the fallback is conservative and safe), but the
   test/live severity distinction never actually worked. **Fixed**: added a
   `stripe_payment_link` stanza populating `livemode` from the record.
3. **`_classify_billing_portal_config_change` read `prev_value`/`new_value`
   as whole prev/new record dicts** (`old.get("active")`,
   `new.get("subscription_cancel_enabled")`, etc.), but real
   `compute_diff()` "modified" Changes always carry SCALAR field values (one
   Change per changed field) — only "added"/"removed" changes carry whole
   records. The function's own `isinstance(..., dict)` guard reset both
   `old`/`new` to `{}` for every real field-level Change, so **the entire
   12-branch severity-differentiation chain documented in the function's own
   docstring was dead code in production** — every real billing-portal field
   change silently fell to the generic "low" fallback regardless of what
   actually changed (e.g. disabling the customer portal's login page, which
   should be "medium", was actually returning "low" with generic copy).
   Confirmed live via a direct `compute_diff()` call before fixing. **Fixed**:
   rewrote the function to dispatch on `field_path` with scalar
   `prev_value`/`new_value`, matching every other classifier in the module.
   Two pre-existing test files
   (`test_milestone57_9.py::TestStripeBillingPortalRisk`,
   `test_stripe_risk_audit.py::TestBillingPortalConfig`) had hand-built the
   same wrong (whole-dict) Change shape, which is exactly why this was never
   caught — both were updated to use the real scalar shape, and a new real
   `compute_diff()` regression test was added.

Bug #3 is the headline finding of this pass — a completely dead
classification chain for a live, frequently-relevant record type
(subscription-cancellation and login-page posture in the customer billing
portal), masked entirely by test helpers using an unrealistic Change shape.

## Confirmed dead/unreachable, not fixed (out of scope per instructions)

- `risk_rules/stripe.py`'s `classify_stripe_change()` dispatches on all 17
  schema record types; 11 of those branches (`_classify_product_change`,
  `_classify_price_change`, `_classify_checkout_configuration_change`,
  `_classify_tax_settings_change`, `_classify_radar_rule_change`,
  `_classify_restricted_api_key_change`,
  `_classify_subscription_invoice_settings_change`,
  `_classify_dunning_settings_change`, `_classify_external_account_change`,
  `_classify_coupon_change`, `_classify_promotion_code_change`) are dead —
  the connector never emits these record types. `security_rules/stripe.py`,
  by contrast, only dispatches on the 4 record types it actually evaluates
  (`stripe_webhook_endpoint`, `stripe_payment_link`,
  `stripe_billing_portal_config`, `stripe_account_settings`) — no dead
  Finding-dispatch branches, a clean design already correctly scoped to
  reachable+Finding-eligible types.
- The same `int(value or 0)` unknown-as-zero pattern found in this session's
  GitHub message-2 pass also exists in `risk_rules/stripe.py` at 5 call
  sites (lines within `_classify_checkout_configuration_change`,
  `_classify_tax_settings_change`, `_classify_restricted_api_key_change`,
  `_classify_dunning_settings_change`, `_classify_coupon_change`) — but
  **all 5 are entirely inside the 11 dead/unreachable classifier branches
  above**, so none are currently exploitable. Not fixed in this pass (no
  live path exercises them); flagged for attention if/when any of these 11
  endpoints are ever wired up.
- A structurally similar "unknown boolean overstated as an explicit state"
  risk exists in `_classify_webhook_endpoint_change`'s `status` field check
  (`new_v in ("disabled", False, "false")` — if `status` were ever `None`
  for a live record, the `else` branch would falsely claim "re-enabled").
  This is a classification-severity nuance (not a routing/reachability/
  Change-shape defect), so per this session's established message-1/
  message-2 boundary it is documented here for the Stripe message-2 pass,
  not fixed now.

## Diff tracking — tracked vs. emitted vs. classified

| Record type | Tracked fields | Emitted-but-untracked (before this pass) | Notes |
|---|---|---|---|
| `stripe_account_settings` | 14 fields, all with dedicated classifier branches | none | full parity |
| `stripe_webhook_endpoint` | url, status, enabled_events, api_version, description — all dedicated | none | full parity |
| `stripe_payment_method_configuration` | config_name, is_default, enabled_payment_methods — all dedicated | none | full parity |
| `stripe_payment_method_domain` | enabled, apple_pay_enabled, google_pay_enabled, link_enabled, domain_name — all dedicated | none | full parity |
| `stripe_billing_portal_config` | 13 fields (added `return_url_domain` handling this pass — previously fell to the generic fallback due to bug #3, now has its own low-severity branch) | none | classifier shape bug fixed (see above) |
| `stripe_payment_link` | **was empty — fixed this pass** to 11 fields matching what the connector emits | `line_item_count`, `line_item_price_ids`, `subscription_data_trial_period_days`, `transfer_destination_present` remain untracked (never emitted by connector; classifier branches for the first three are dead) | tracked-fields gap fixed; connector-gap fields intentionally left untracked |

No stale field names or confusable near-duplicates were found among the 6
live record types' tracked-field lists.

## Security Finding reachability (8 rules, all confirmed reachable)

| Rule key | Record type | Trigger | Severity | Reachable from connector? | Registry/pack/confidence/coverage/frontend parity |
|---|---|---|---|---|---|
| `stripe_webhook_http` | webhook_endpoint | enabled + `url` starts `http://` | critical | Yes | full |
| `stripe_webhook_disabled` | webhook_endpoint | `status == "disabled"` | medium | Yes | full |
| `stripe_webhook_broad_events` | webhook_endpoint | wildcard `"*"` or `len(enabled_events) >= BROAD_WEBHOOK_EVENT_THRESHOLD (50)` | medium | Yes | full |
| `stripe_payment_link_tax_disabled` | payment_link | `active is True` and `automatic_tax_enabled is False` | medium | Yes | full |
| `stripe_payment_link_promo_codes_enabled` | payment_link | `active is True` and `allow_promotion_codes is True` | low | Yes | full |
| `stripe_portal_subscription_cancel_enabled` | billing_portal_config | `active is True` and `subscription_cancel_enabled is True` | low | Yes | full |
| `stripe_portal_login_enabled` | billing_portal_config | `active is True` and `login_page_enabled is True` | medium | Yes | full |
| `stripe_account_capability_incomplete` | account_settings | any of charges/payouts/details_submitted explicitly False | medium | Yes | full |

All 8 keys verified present with matching severity/category across
`security_rule_registry.py` (`KNOWN_RULE_KEYS`), `security_rule_pack.py`,
`security_rule_confidence.py`, `security_coverage_service.py` (with correct
record-type mapping), and `frontend/src/lib/securityRuleCatalog.ts`. This
matches the durable pin already enforced by
`tests/test_stripe_provider_depth_qa.py::test_stripe_rule_key_count`
(asserts `len(ALL_STRIPE_RULE_KEYS) == 8`) — confirmed still accurate; no
drift since that pass.

**Records with no Security Finding**: `stripe_payment_method_configuration`
and `stripe_payment_method_domain` — confirmed intentionally deferred (per
prior context) due to noise risk from operational toggles; verified the
frontend catalog's Stripe surfaces list ("Webhook HTTPS", "Webhook posture",
"Payment links", "Customer portal", "Account payments readiness") correctly
excludes any claim of static security coverage for these two record types.
No Security Finding was added for them in this pass, consistent with "Do
not add a Security Finding simply because a payment method is disabled."

**Provider-capability-matrix parity**: `provider_capability_matrix_service.py`'s
`_STRIPE` entry's notes ("Stripe drift covers webhook endpoints, payment
links, billing-portal configuration, and account capability posture...")
accurately reflects the 6 reachable record types and does not overclaim
coverage of products/prices/tax/Radar/keys/etc.

## Basic classifier routing

- `risk_service.classify_change()` dispatches `stripe_` prefix records to
  `classify_stripe_change()` — confirmed via direct read (`risk_service.py`
  lines 95-97). No Stripe record type reaches Cloudflare/generic fallback.
- Unknown/unrecognised Stripe record types fall to a safe `("low", "…")`
  default in `classify_stripe_change()`.
- No `old_value`/`previous_value`/`prior_value` production usage anywhere in
  Stripe connector/schema/risk_rules/security_rules code. Test-helper
  parameter names `old_value=...` exist in two files (mapped internally to
  the correct `"prev_value"` dict key) and one MagicMock `.old_value`
  attribute alias (never read by production code) — both are the
  established safe pattern, not violations.
- Added/removed records retain sufficient metadata for all 6 live record
  types — confirmed via direct `compute_diff()` calls for account_settings,
  webhook_endpoint, payment_method_configuration, payment_method_domain,
  and payment_link (add/remove both exercised for payment_link).
- No MagicMock-based test hides a missing field: the `test_stripe_risk_audit.py`
  `_change()` helper explicitly sets every attribute the classifiers read
  (`field_path`, `change_type`, `new_value`, `prev_value`,
  `provider_metadata`) rather than relying on MagicMock auto-attribute
  fallback.

## Fail-soft and error handling

- `_get()`'s 401/403 split is correct and load-bearing: 401 → hard
  `AuthenticationError` (invalid key), 403 → `ConnectorError(status_code=403)`
  that every `_fetch_*` helper catches and treats as "skip this optional
  resource," never conflated with an invalid key.
- `validate_credentials()`'s multi-probe strategy (webhook_endpoints → PM
  configs → PM domains → events → account) correctly supports restricted
  keys lacking the broad "Account" permission; only fails hard on 401 or if
  every probe returns 403.
- 429 handling honors Stripe's `Retry-After` header with capped retries
  (`_MAX_RETRIES = 3`); 5xx retried with fixed backoff.
- `_resolve_account_id()` falls back to a SHA-256 key fingerprint
  (non-reversible, stable) when `/v1/account` is inaccessible — a safe,
  stable identifier for restricted keys without Account permission.
- No optional-endpoint 404/403 produces a false "removal" for unrelated
  records — each `_fetch_*` helper catches its own errors independently and
  returns `[]`/`None` without affecting other resources' fetch calls.

## Sensitive-data minimization

Confirmed via direct source read and grep: the connector never accesses
`endpoint["secret"]` (webhook signing secret), never logs
`credentials["stripe_api_key"]`, never fetches `/v1/customers`,
`/v1/charges`, `/v1/invoices`, or `/v1/payment_intents`. Payment-link URLs
are reduced to scheme+host (`_url_origin()`) before persistence; billing
portal return URLs are reduced to domain-only. The Radar-rule schema (never
emitted) documents storing only a sha256 hash of rule expressions, never the
raw expression — consistent with the pattern used elsewhere. Restricted-key
schema (never emitted) documents storing only id-prefix/permission
summary/timestamps, never the key value. No card numbers, CVC, bank account
numbers (beyond schema-documented last4 — never emitted), customer PII, or
raw event/webhook payloads are ever fetched or stored by the live 6-type
surface.

## Copy safety

No forbidden phrases (breach, compromise, attacker access, payment fraud
detected, card data exposed, etc.) found in any Stripe evidence/copy across
`risk_rules/stripe.py`, `security_rules/stripe.py`, or the frontend catalog.
Every Security Finding description includes an explicit "does not confirm
fraud, compromise, or unauthorized access" disclaimer.

## Test results

- Exact Stripe files (12 files, including the two pre-existing files with
  fixed tests and the new `test_stripe_detection_qa.py`) → **503 passed**
- `pytest -k "stripe and webhook"` → 93 passed
- `pytest -k "stripe and diff"` → 19 passed
- `pytest -k "stripe and risk"` → 436 passed
- `pytest -k "stripe"` → **657 passed** (650 pre-existing + 7 new)
- No zero-selection filters, no slow runs, no unexpected failures after
  fixes.

## Files changed this pass

- `backend/app/services/diff_service.py` — added `stripe_payment_link`
  tracked-field entry; added `livemode` provider_metadata stanza for
  `stripe_payment_link`.
- `backend/app/services/risk_rules/stripe.py` — rewrote
  `_classify_billing_portal_config_change` to use the real scalar
  `field_path`/`prev_value`/`new_value` Change shape instead of whole
  prev/new record dicts.
- `backend/tests/test_milestone57_9.py` — fixed
  `TestStripeBillingPortalRisk`'s hand-built Change shape (whole dicts →
  scalars matching real `compute_diff()`), added a real-`compute_diff()`
  regression test.
- `backend/tests/test_stripe_risk_audit.py` — fixed
  `TestBillingPortalConfig`'s D3–D7 hand-built Change shape the same way.
- `backend/tests/test_stripe_detection_qa.py` — new, 7 regression tests
  for the payment-link tracked-fields/provider-metadata fixes and the
  confirmed-unreachable record-type list.
- `backend/tests/reports/stripe_detection_matrix.md` — this report (new).

## Safe to push?

Not evaluated as part of this pass (push explicitly out of scope). All
narrow and exact Stripe test filters pass; no unrelated files touched or
staged. Live Stripe validation (a real restricted-key sync against a test
account) remains advisable before relying on the payment-link and
billing-portal fixes in production, though all fixes are covered by real
`compute_diff()`-based regression tests here.
