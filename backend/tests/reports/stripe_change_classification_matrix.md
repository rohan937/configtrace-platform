# Stripe Change-Classification Matrix (message-2 pass)

Scope: **classification correctness** for the 6 currently emitted and
tracked Stripe record types — severity, copy accuracy, restoration/
weakening direction, unknown-value safety, added-record inspection, and
Change/Security Finding severity parity. Builds on the detection-QA pass
(`e6d3a41`, `backend/tests/reports/stripe_detection_matrix.md`), which
established which of the 17 schema-defined record types are emitted (6 of
17) and fixed the `stripe_payment_link` tracked-fields/provider-metadata
reachability gaps and the billing-portal whole-record-vs-scalar shape bug.

## Graphify summary

All four required queries ran successfully via
`/Users/rohan/.local/bin/graphify`. The graph is coarse (class/function-
level, not field/diff-level) and confirmed indexed: `StripeConnector`,
`classify_stripe_change()`, the billing-portal risk-rules docstring node,
and `_is_production_payment_link`'s "Hint: a Payment Link is production if
livemode is True" docstring. `TestStripeBillingPortalRisk` (the test class
fixed in the message-1 pass) surfaced by name, but the graph can't confirm
from a class-name node alone whether it reflects the post-fix scalar-shape
version. `test_stripe_detection_qa.py` and `stripe_detection_matrix.md`
(both added in `e6d3a41`) did not surface by name in any of the 4 queries —
the graph appears not refreshed since that commit. No node exists for
`stripe_change_classification_matrix.md` (expected — it didn't exist yet).
The graph did not itself surface any specific classification gap beyond
generic cross-provider "unknown/generic fallback" test nodes. Proceeded via
direct reads of `risk_rules/stripe.py`, `security_rules/stripe.py`,
`diff_service.py`, and the connector/schema as authoritative.

## Root-cause bugs found and fixed this pass

1. **Seven boolean-field checks across three live classifiers used an
   `if new_v is False: ...critical/high/medium; else: <assumes restored/
   promoted/enabled>` pattern** — an unconditional "else" branch with no
   explicit unknown case:
   - `_classify_account_settings_change`: `charges_enabled`,
     `payouts_enabled`
   - `_classify_payment_method_configuration_change`: `is_default`
   - `_classify_payment_method_domain_change`: `apple_pay_enabled`,
     `google_pay_enabled`, `link_enabled`, `enabled`

   If any of these fields were ever `None` (unknown — e.g. a pre-existing
   snapshot predating the field's addition to the schema), the classifier
   would falsely report an explicit restoration/promotion/enablement claim
   ("Charges were re-enabled... Payment acceptance has been restored")
   about a value that was never actually confirmed. **Fixed**: added an
   explicit `new_v is None` branch to each of the 7 sites with cautious,
   non-committal "medium" copy that doesn't assert a direction.

2. **`_classify_billing_portal_config_change`'s `subscription_cancel_
   enabled` branch used a truthy check** (`'enabled' if nv else
   'disabled'`) instead of `is True`/`is False` — an unknown value would be
   reported as "disabled", a false explicit-state claim. **Fixed**: added an
   explicit `nv is None` branch before the truthy check.

3. **`_classify_webhook_endpoint_change`'s `status` field had the same
   issue**, flagged but explicitly deferred to this pass in the message-1
   detection report (a severity/copy nuance, not a routing defect):
   `new_v in ("disabled", False, "false")` with an unconditional "else"
   claiming "re-enabled... restored." **Fixed**: added an explicit
   `new_v in (None, "")` branch.

4. **`_classify_webhook_endpoint_change`'s "added" branch never inspected
   the newly added webhook's own record** for risky posture — every new
   webhook was flatly "high" regardless of whether it used plain `http://`
   or subscribed to a wildcard/very broad event set from creation, unlike
   `_classify_payment_link_change`'s "removed" branch (which already
   correctly scopes severity by `is_live`). **Fixed**: added inspects
   with the connector shape carrying the full new record for "added"
   changes; escalates to "critical" for `http://` (matching the "modified
   to http://" branch) and "high" with specific copy for wildcard/broad
   event subscriptions. Uses the existing named constant
   `BROAD_WEBHOOK_EVENT_THRESHOLD` imported from `security_rules/
   stripe.py` — no duplicated magic number.

All four bug classes are the "unknown value silently treated as a
confirmed/opposite state" pattern found repeatedly this session (GitHub
message 2's `_to_bool`/`_to_int` fixes are the closest precedent). None of
these were reachable via a fresh connector fetch today (every live field is
always populated with a real bool by the connector), but are real risks for
snapshot rows predating a schema field addition, and are explicitly the
kind of latent correctness gap this message's audit asks to close.

## Confirmed correct, no fix needed

- `_classify_payment_link_change`'s `active` field uses sequential `if pv
  is True and nv is False:` / `if nv is True:` checks (not an if/else pair)
  — `None` correctly fails both and falls through to the generic bucket
  without a false claim. No fix needed; used as the reference-safe pattern
  when designing the other 7 fixes.
- `_classify_billing_portal_config_change`'s `active`,
  `payment_method_update_enabled`, and `login_page_enabled` checks use
  `fp == X and nv is False` (not if/else) — `None` correctly falls through
  to the generic low fallback, no false claim.
- `webhook_endpoint`'s `url` field: `str(new_v or "").lower()` on `None`
  produces `""`, which doesn't match `http://`, so it correctly falls to
  the generic "URL changed" copy without claiming HTTP or HTTPS
  specifically.
- `enabled_events`'s `isinstance(x, (list, tuple, set))` guards correctly
  treat a non-list (including `None`) as an empty set for the
  "dropped-critical-events" diff — conservative (never fires a false
  critical-drop claim), and the connector always emits a real list in
  practice (`sorted(ep.get("enabled_events") or [])`), so this is not
  currently reachable as a live gap.
- No `int(value or 0)`-style numeric coercion exists anywhere in the 6 live
  classifiers — the 5 occurrences found via grep are all confined to the 11
  dead/unreachable classifier branches (checkout_configuration,
  tax_settings, restricted_api_key, dunning_settings, coupon), matching the
  message-1 detection pass's findings; not fixed here (no live path).

## Payment-method configuration/domain: Change-only decision confirmed

Both `stripe_payment_method_configuration` and `stripe_payment_method_domain`
remain **intentionally Change-only** (no Security Finding), reconfirmed this
pass:
- `stripe_payment_method_domain` has **no validation/verification-status
  field at all** in the schema or connector (`grep` confirms only `enabled`,
  `apple_pay_enabled`, `google_pay_enabled`, `link_enabled`,
  `domain_name`) — task D's "domain validation valid → invalid" scenario
  cannot be modeled without inventing new connector coverage, which is out
  of scope for this pass. No Finding added.
- `stripe_payment_method_configuration`'s toggles (`is_default`,
  `enabled_payment_methods`) are operational choices without an
  unambiguous "this is a security weakening" direction — disabling a
  payment method is a business decision, not evidence of compromise. No
  Finding added, consistent with "Do not add a Security Finding simply
  because a payment method is unavailable or disabled."

No new Security Finding rules were added in this pass.

## Security Finding parity (re-verified)

| Change | Change severity | Equivalent Finding | Finding severity | Relationship |
|---|---|---|---|---|
| webhook `url`→http:// | critical | `stripe_webhook_http` | critical | equal |
| webhook added w/ http:// (fixed this pass) | critical | same | critical | equal |
| webhook `status`→disabled | high | `stripe_webhook_disabled` | medium | Change > Finding, justified (transition vs. static) |
| webhook `enabled_events` broadened (fixed: added-record case) | high/critical | `stripe_webhook_broad_events` | medium | Change ≥ Finding, justified |
| account `charges_enabled`→false | critical | `stripe_account_capability_incomplete` | medium | Change > Finding, justified |
| billing portal `login_page_enabled`→true | (no dedicated branch — generic low) | `stripe_portal_login_enabled` | medium | intentional: Finding evaluates static "portal already has login page on" risk; Change doesn't escalate simply enabling it, consistent with "restoration/expansion of self-service isn't inherently risky" |
| billing portal `subscription_cancel_enabled`→true | medium | `stripe_portal_subscription_cancel_enabled` | low | Change > Finding, satisfies "not lower than equivalent risky state" |
| payment link `automatic_tax_enabled`→false | medium | `stripe_payment_link_tax_disabled` | medium | equal |
| payment link `allow_promotion_codes`→true | medium | `stripe_payment_link_promo_codes_enabled` | low | Change > Finding, satisfies rule |

No case was found where a Change classification was rated *below* its
equivalent Finding — the one apparent gap (`login_page_enabled` enabling
having no dedicated Change branch) is intentional: enabling the hosted
login page is a business/UX expansion, not inherently a weakening event,
so the Change correctly falls to the generic low bucket while the Finding
(evaluating the ongoing state) is medium as a review item. Documented, not
changed.

## Numeric and threshold handling

- `BROAD_WEBHOOK_EVENT_THRESHOLD` (defined once in `security_rules/
  stripe.py`, value 50) is now also used by `risk_rules/stripe.py`'s
  webhook "added" branch (imported, not duplicated) to escalate a newly
  added webhook that already subscribes to a wildcard or ≥50 events.
- Increasing an already-broad event set further (e.g. 60 → 80 events) does
  not fall to "low" — the "modified" `enabled_events` branch is flat "high"
  (or "critical" if a critical event was dropped) for any event-set change,
  independent of the exact count, satisfying "above-threshold increases
  must not fall to low."
- No numeric field among the 6 live record types performs unsafe `int(x or
  0)`-style coercion; `payout_schedule_delay_days`, `application_fee_amount`,
  `application_fee_percent`, and `payment_method_types_count` are reported
  via flat "changed" copy without arithmetic comparison, so there's no
  unknown-as-zero risk for them.

## Boolean unknown safety — final state

All boolean fields across the 6 live classifiers now correctly distinguish
`True`/`False`/`None` via explicit `is True`/`is False`/`is None` checks (or
structurally safe sequential `if` statements that fall through on `None`).
No remaining case overstates an unknown value as an explicit enabled,
disabled, restored, or promoted state.

## Payment-link live/test mode

Confirmed via real `compute_diff()`: `livemode` (fixed in the message-1
pass to be populated in `provider_metadata`) correctly differentiates
severity — a live-mode payment link disable is "high", the identical
test-mode disable is "medium". Missing `livemode` (e.g. a
`provider_metadata` dict genuinely lacking the key) still conservatively
defaults to "assume production" via `_is_production_payment_link()`'s
existing `"livemode" not in pm → True` fallback — this is the safer
direction (never *under*-classifies), and is unchanged from message 1.

## Classification matrix (44 representative cases)

| # | Category | Record type | Field(s) | Old → New | Detected? | Classifier branch | Current→Expected severity | Finding parity | Provider metadata required? | Real-diff test? | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | Account charges | account_settings | charges_enabled | true→false | Yes | `_classify_account_settings_change` | critical→critical | Change > Finding (medium), justified | No | test_stripe_risk_audit.py | PASS | — |
| 2 | Account charges restore | account_settings | charges_enabled | false→true | Yes | same | medium→medium | n/a | No | test_stripe_risk_audit.py | PASS | improvement |
| 3 | Account charges unknown | account_settings | charges_enabled | true→None | Yes | same | (was: falsely "restored"→now: medium, no restore claim) | n/a | No | test_stripe_change_classification_qa.py (new) | **FIXED** | boolean-unknown-as-restore |
| 4 | Account payouts | account_settings | payouts_enabled | true→false | Yes | same | critical→critical | Change > Finding, justified | No | test_stripe_risk_audit.py | PASS | — |
| 5 | Account payouts unknown | account_settings | payouts_enabled | true→None | Yes | same | (was: falsely "restored"→now: medium) | n/a | No | test_stripe_change_classification_qa.py (new) | **FIXED** | — |
| 6 | Account details_submitted | account_settings | details_submitted | true→false | Yes | same | (generic medium)→medium | Change/Finding both medium via `stripe_account_capability_incomplete` | No | test_stripe_risk_audit.py | PASS | — |
| 7 | Account payout schedule | account_settings | payout_schedule_interval | daily→manual | Yes | same | high→high | n/a | No | test_stripe_risk_audit.py | PASS | — |
| 8 | Account controller type | account_settings | controller_type | application→platform | Yes | same | high→high | n/a | No | test_stripe_risk_audit.py | PASS | platform-ownership signal |
| 9 | Account branding | account_settings | branding_icon | file_a→file_b | Yes | same | low→low | n/a | No | test_stripe_risk_audit.py | PASS | cosmetic, intentional generic-low |
| 10 | Webhook HTTP | webhook_endpoint | url | https→http | Yes | `_classify_webhook_endpoint_change` | critical→critical | equal to `stripe_webhook_http` | No | test_stripe_risk_audit.py | PASS | — |
| 11 | Webhook HTTPS restore | webhook_endpoint | url | http→https | Yes | same | high→high | n/a | No | test_stripe_risk_audit.py | PASS | still "high" (URL changed) not "low" — documented, appropriate since destination changed regardless of scheme direction |
| 12 | Webhook disabled | webhook_endpoint | status | enabled→disabled | Yes | same | high→high | Change > Finding (medium), justified | No | test_stripe_risk_audit.py | PASS | — |
| 13 | Webhook re-enabled | webhook_endpoint | status | disabled→enabled | Yes | same | low→low | n/a | No | test_stripe_risk_audit.py | PASS | improvement |
| 14 | Webhook status unknown | webhook_endpoint | status | enabled→None | Yes | same | (was: falsely "re-enabled"→now: medium) | n/a | No | test_stripe_change_classification_qa.py (new) | **FIXED** | — |
| 15 | Webhook wildcard events | webhook_endpoint | enabled_events | [a]→[*] | Yes | same | high→high (critical if critical event dropped) | Change ≥ Finding (medium) | No | test_stripe_risk_audit.py | PASS | — |
| 16 | Webhook broad count threshold | webhook_endpoint | enabled_events | 10→50 | Yes | same | high→high | Finding fires at exactly 50 (named constant) | No | test_stripe_provider_depth_qa.py | PASS | — |
| 17 | Webhook count above-threshold increase | webhook_endpoint | enabled_events | 60→80 | Yes | same | high→high (not downgraded) | n/a | No | test_stripe_risk_audit.py | PASS | satisfies "must not fall to low" |
| 18 | Webhook count unknown | webhook_endpoint | enabled_events | list→None | n/a (connector always emits a list) | same | isinstance guard treats as empty set, safe | n/a | No | N/A | N/A | not reachable via live fetch |
| 19 | Webhook API version | webhook_endpoint | api_version | old→new | Yes | same | medium→medium | n/a | No | test_stripe_risk_audit.py | PASS | — |
| 20 | Webhook added (secure) | webhook_endpoint | whole record | absent→present | Yes | same | high→high | n/a | No | test_stripe_change_classification_qa.py (new) | PASS | unchanged |
| 21 | Webhook added w/ http:// | webhook_endpoint | whole record | absent→present, url=http:// | Yes | same | (was: flat high→now: critical) | equal to `stripe_webhook_http` | No | test_stripe_change_classification_qa.py (new) | **FIXED** | added-record inspection gap |
| 22 | Webhook added w/ wildcard | webhook_endpoint | whole record | absent→present, events=["*"] | Yes | same | (was: flat high→now: high w/ specific copy) | equal to `stripe_webhook_broad_events` | No | test_stripe_change_classification_qa.py (new) | **FIXED** | — |
| 23 | Webhook removed | webhook_endpoint | whole record | present→absent | Yes | same | critical→critical | n/a | No | test_stripe_risk_audit.py | PASS | — |
| 24 | PM config enabled_payment_methods | payment_method_configuration | enabled_payment_methods | dict changed | Yes | `_classify_payment_method_configuration_change` | high→high | none (Change-only, intentional) | No | test_stripe_risk_audit.py | PASS | — |
| 25 | PM config is_default unset | payment_method_configuration | is_default | true→false | Yes | same | high→high | none | No | test_stripe_risk_audit.py | PASS | — |
| 26 | PM config is_default unknown | payment_method_configuration | is_default | true→None | Yes | same | (was: falsely "set as new default"→now: medium) | none | No | test_stripe_change_classification_qa.py (new) | **FIXED** | — |
| 27 | PM config added/removed | payment_method_configuration | whole record | absent↔present | Yes | same | low/high→low/high | none | No | test_stripe_risk_audit.py | PASS | — |
| 28 | PM domain Apple Pay disabled | payment_method_domain | apple_pay_enabled | true→false | Yes | `_classify_payment_method_domain_change` | high→high | none (Change-only, intentional) | No | test_stripe_risk_audit.py | PASS | — |
| 29 | PM domain Apple Pay unknown | payment_method_domain | apple_pay_enabled | true→None | Yes | same | (was: falsely "was enabled"→now: medium) | none | No | test_stripe_change_classification_qa.py (new) | **FIXED** | — |
| 30 | PM domain enabled | payment_method_domain | enabled | true→false | Yes | same | high→high | none | No | test_stripe_detection_qa.py (real diff) | PASS | — |
| 31 | PM domain enabled restore | payment_method_domain | enabled | false→true | Yes | same | low→low | none | No | test_stripe_change_classification_qa.py (new) | PASS | — |
| 32 | PM domain "validation" state | payment_method_domain | n/a — no such field is emitted | — | No (not modeled) | n/a | n/a | none (cannot be modeled) | n/a | n/a | N/A | field doesn't exist in schema/connector; documented, not invented |
| 33 | PM domain added/removed | payment_method_domain | whole record | absent↔present | Yes | same | high/critical→high/critical | none | No | test_stripe_risk_audit.py | PASS | — |
| 34 | Billing portal removed | billing_portal_config | whole record | present→absent | Yes | `_classify_billing_portal_config_change` | high→high | n/a | No | test_stripe_risk_audit.py | PASS | — |
| 35 | Billing portal login page disabled | billing_portal_config | login_page_enabled | true→false | Yes | same | medium→medium | Finding fires on the opposite (enabled) state, intentional divergence | No | test_milestone57_9.py (real diff) | PASS | — |
| 36 | Billing portal cancel enabled | billing_portal_config | subscription_cancel_enabled | false→true | Yes | same | medium→medium | Change(medium) > Finding(low), satisfies rule | No | test_stripe_risk_audit.py | PASS | — |
| 37 | Billing portal cancel unknown | billing_portal_config | subscription_cancel_enabled | true→None | Yes | same | (was: falsely "disabled" via truthy check→now: medium, no claim) | n/a | No | test_stripe_change_classification_qa.py (new) | **FIXED** | — |
| 38 | Billing portal cancel mode | billing_portal_config | subscription_cancel_mode | at_period_end→immediately | Yes | same | low→low | n/a | No | test_stripe_risk_audit.py | PASS | — |
| 39 | Billing portal all-14-tracked-fields synchronization | billing_portal_config | all 14 | representative pairs | Yes | same | every field reaches a specific or documented generic branch | n/a | No | test_stripe_change_classification_qa.py (new, synchronization test) | PASS | — |
| 40 | Payment link disabled (live) | payment_link | active | true→false, livemode=true | Yes | `_classify_payment_link_change` | high→high | n/a | Yes (`livemode`) | test_stripe_change_classification_qa.py (new) | PASS | — |
| 41 | Payment link disabled (test) | payment_link | active | true→false, livemode=false | Yes | same | medium→medium | n/a | Yes | test_stripe_change_classification_qa.py (new) | PASS | live/test distinction confirmed working |
| 42 | Payment link promo codes | payment_link | allow_promotion_codes | false→true | Yes | same | medium→medium | Change(medium) > Finding(low), satisfies rule | No | test_stripe_detection_qa.py | PASS | — |
| 43 | Payment link automatic tax | payment_link | automatic_tax_enabled | true→false | Yes | same | medium→medium | equal to `stripe_payment_link_tax_disabled` | No | test_stripe_risk_audit.py | PASS | — |
| 44 | Payment link redirect changed | payment_link | success_url_origin | origin_a→origin_b | Yes | same | high→high | n/a | No | test_stripe_detection_qa.py | PASS | destination-shift detection confirmed |

## Test results

```
pytest tests/test_stripe_detection_qa.py tests/test_stripe_provider_depth_qa.py \
  tests/test_stripe_part1_risk_audit.py tests/test_milestone35.py -q
  -> 268 passed

pytest tests/test_milestone60_4_5_stripe_vercel_shopify_rules.py \
  tests/test_milestone73a_stripe_security_provider_foundation.py \
  tests/test_milestone73b_stripe_activity_ingestion.py \
  tests/test_milestone73c_stripe_activity_signals.py \
  tests/test_milestone73d_stripe_correlations.py \
  tests/test_milestone73e_stripe_demo_qa.py \
  tests/test_stripe_change_classification_qa.py tests/test_stripe_detection_qa.py \
  tests/test_stripe_part1_risk_audit.py tests/test_stripe_part2_risk_audit.py \
  tests/test_stripe_provider_depth_qa.py tests/test_stripe_risk_audit.py \
  tests/test_milestone57_9.py tests/test_milestone35.py -q
  -> 661 passed

pytest -k "stripe and webhook"      -> 98 passed
pytest -k "stripe and billing"      -> 37 passed
pytest -k "stripe and payment_link" -> 26 passed
pytest -k "stripe and diff"         -> 21 passed
pytest -k "stripe and risk"         -> 436 passed
pytest -k "stripe"                  -> 673 passed (657 + 16 new)
```

No zero-selection filters, no unexpectedly slow runs. Frontend was not
touched this pass — no new/changed Security Finding rules — `npx tsc
--noEmit` was not run (not required).

## Files changed this pass

- `backend/app/services/risk_rules/stripe.py` — 7 boolean-unknown-safety
  fixes (account_settings ×2, payment_method_configuration ×1,
  payment_method_domain ×4), billing-portal truthy-check fix, webhook
  status-unknown fix, webhook "added"-record risk inspection (imports
  `BROAD_WEBHOOK_EVENT_THRESHOLD` from `security_rules/stripe.py`).
- `backend/tests/test_stripe_change_classification_qa.py` — new, 16
  regression tests.
- `backend/tests/reports/stripe_change_classification_matrix.md` — this
  report (new).

## Safe to push?

Not evaluated (push explicitly out of scope). All exact and narrow Stripe
test filters pass; no unrelated files touched or staged. No new/changed
Security Finding rules were added, so no registry/frontend/provider-depth
re-verification was required beyond what message 1 already confirmed.
