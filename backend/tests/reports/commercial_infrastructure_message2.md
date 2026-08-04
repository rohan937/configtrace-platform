# Commercial Infrastructure — Message 2: Paddle Billing Integration

## Scope

This message implements a real, provider-neutral-compatible Paddle
Billing v2 integration on top of message 1's provider abstraction:
checkout, Paddle.js frontend integration, webhook signature verification
and processing, subscription/entitlement lifecycle, seat reconciliation,
customer management, cancellation, payment-failure/grace handling,
sandbox deployment configuration, and production-cutover readiness. It
does **not** migrate any existing Stripe customer, does **not** remove
any Stripe code/field/variable, does **not** begin Commercial
Infrastructure message 3 ("Stripe Retirement and Billing Operations
Hardening" — reserved), and does **not** execute any production Paddle
transaction.

## Graphify results

The knowledge graph (`graphify-out/`) was stale by one commit (built from
`6fdbd278`, one behind `c395c464`). `graphify update .` was run first
(AST-only, no API cost), then four scoped queries were run against the
refreshed graph confirming message 1's architecture — `BillingProvider`,
`StripeBillingAdapter`, `PaddleBillingAdapter`, `PaddlePriceMapping`,
`CheckoutRequest`, `BillingProviderAdapter`, `decide_entitlements()`,
`BillingWebhookEvent`, `billable_seats.py`, `entitlements.py` — were all
indexed and queryable, giving a smaller, targeted context for this
message's design work than grepping the full `app/billing/` tree.

## Paddle API architecture

A bounded `httpx.Client`-based `PaddleAPIClient`
(`app/billing/paddle_client.py`) — no Paddle SDK was added, matching
message 1's decision for Stripe (raw HTTP calls, small surface, easier
to audit). Base URL resolves per environment
(`https://sandbox-api.paddle.com` / `https://api.paddle.com`). Bearer
auth. Typed error hierarchy (`PaddleAuthenticationError`,
`PaddleValidationError`, `PaddleRateLimitedError`, `PaddleServerError`,
`PaddleNetworkError`) never surfaces the API key or full response body —
only status code, `paddle-request-id`, and `error.code` when present.
Retries are bounded (max 3), apply only to idempotent GETs on
429/500/502/503/504, honor `Retry-After`, and never retry non-idempotent
(mutating) calls or 4xx.

## Dependencies added

None. No Paddle SDK (`paddle-python-sdk` or similar) was added to
`requirements.txt`. No `@paddle/paddle-js` npm package was added to
`frontend/package.json`. Paddle.js is loaded client-side via the
official CDN script tag (`https://cdn.paddle.com/paddle/v2/paddle.js`).

## Checkout flow

`POST /workspaces/{id}/billing/checkout/team` computes `plan_id`,
`billing_interval`, and `billable_seat_count` entirely server-side
(no client-submitted price/seat data), routes via
`provider_for_checkout` (always the currently configured global
provider for a NEW checkout), and — when Paddle — calls
`PaddleBillingAdapter.create_checkout`, which builds a base item
(quantity 1, always present) plus an additional-seat item (present only
when `calculate_desired_additional_quantity() > 0`), attaches
`custom_data` (`workspace_id`, `plan_id`, `billable_seat_count`,
`pricing_version`, `idempotency_reference`), and calls
`POST /transactions`. The response's `checkout.url` and transaction `id`
are returned to the frontend as `checkout_url` and `external_reference`.

## Paddle.js integration

`frontend/src/lib/paddle.ts` provides an idempotent CDN script loader
(`loadPaddleScript`), `initPaddle(environment, clientToken, eventCallback)`,
and `openPaddleCheckout(transactionId)`. The billing page
(`settings/workspace/billing/page.tsx`) opens the hosted Paddle overlay
via `Paddle.Checkout.open({ transactionId })` using the backend-provided
`external_reference` — the client never receives or chooses a price ID.
`checkout.completed` and `checkout.closed` events are handled to refresh
billing state or clear the in-flight guard. If Paddle.js fails to load or
initialize, the flow falls back to a `window.location.href` redirect to
the backend-provided `checkout_url`.

## Raw-body webhook architecture

`app/routers/paddle_webhook.py` reads `await request.body()` before any
JSON parsing — signature verification always operates on Paddle's exact
original bytes, proven byte-exact by
`test_commercial_paddle_signature.py::TestExactRawBodyPreservation`. The
route mirrors `stripe_webhook.py`'s pattern exactly: always returns HTTP
200 even when internal processing raises (to avoid Paddle retry storms
on a transient internal error), 503 if `PADDLE_WEBHOOK_SECRET` is unset,
400 for a missing/invalid signature.

## Signature verification

`Paddle-Signature: ts=<unix_ts>;h1=<hex_hmac>` where
`hex_hmac = HMAC-SHA256(webhook_secret, f"{ts}:{raw_body}")`. Implemented
from Paddle's publicly documented scheme; constant-time comparison
(`hmac.compare_digest`) against every candidate `h1` (supports secret
rotation via multiple values, any match succeeds); default 300s
timestamp tolerance, configurable. 19 offline tests. **Honest
limitation**: not verified against a real live Paddle sandbox delivery
in this message (no sandbox credentials available) — flagged explicitly
in the security review report and in
`test_commercial_paddle_sandbox_optional.py::TestSandboxSignatureRoundTrip`'s
skip message.

## Normalized events

9 Paddle event names (`subscription.created/updated/canceled/paused/resumed/past_due`,
`transaction.completed/payment_failed`, `customer.updated`) map into
message 1's existing `WebhookEventType` taxonomy via
`_PADDLE_EVENT_TYPE_MAP` in `app/billing/paddle_webhooks.py`. Unknown
event names map to `UNKNOWN` and are safely acknowledged (never dropped
silently, never crash processing).

## Idempotency

Reuses message 1's `(provider, external_event_id)` unique-constraint
architecture unchanged. Paddle webhooks write into the SAME
`commercial_webhook_events` table Stripe uses, keyed by
`provider="paddle"` — no new table, no Paddle-specific idempotency
mechanism.

## Event ordering

Reuses message 1's `is_stale_subscription_update`, comparing the
incoming event's `occurred_at` against the stored
`NormalizedSubscription.updated_at`. Proven by
`TestOlderActiveEventAfterCancellation::test_stale_active_event_after_newer_cancellation_is_ignored`:
an "active" event delivered out of order after a newer cancellation is
correctly ignored.

## Customer/subscription correlation

Paddle `custom_data` on the transaction (set at checkout time) carries
`workspace_id`; incoming webhooks are correlated to a local
`NormalizedSubscription` row via
`_find_subscription_by_paddle_reference` in
`paddle_webhook_service.py`. An event referencing an unresolvable
subscription reference is a safe no-op
(`TestWrongWorkspaceCustomData::test_event_for_unknown_subscription_reference_is_a_safe_no_op`),
never a crash and never a state mutation on the wrong workspace.

## Subscription item model

Exactly one base item (quantity always 1) plus, conditionally, one
additional-seat item. `update_subscription` fetches current live items,
validates exactly one base item exists (raises
`PaddleBaseItemMissingError`/`PaddleDuplicateBaseItemError` otherwise),
preserves any unrelated/unrecognized item unchanged, and computes the
desired additional-seat quantity from `calculate_desired_additional_quantity`.

## Zero-additional-seat behavior

Documented, unverified-against-live-Paddle choice: when the desired
additional-seat quantity is 0, the additional-seat line item is **omitted
entirely** from the subscription's item list rather than retained at
quantity 0. Verified across all 6 required seat transitions in
`TestZeroAdditionalSeatsOmitted`.

## Proration policy

Seat ADDED → `prorated_immediately`. Seat REMOVED →
`prorated_next_billing_period`. Every subscription-item PATCH carries an
explicit `proration_billing_mode` — never Paddle's implicit default.
Documented as this message's policy choice, not verified against a real
live Paddle billing cycle.

## Seat reconciliation

`plan_seat_reconciliation` (pure function) compares
`current_billable_members` against `observed_additional_quantity` and
returns a `SeatReconciliationPlan`. `reconcile_workspace_subscription`
(stateful) fetches the live Paddle snapshot, detects
`WorkspaceCustomerMismatchError` if the stored customer reference
doesn't match, applies the plan via `adapter.update_subscription` when
needed, and always records a `PROVIDER_RECONCILIATION` audit event
(plus `SEAT_COUNT_CHANGED` when an update was actually made).

## Race protection

The reconciliation plan is proven to be a pure, deterministic function
of its inputs (`TestConcurrentChangeSafety::test_plan_is_a_pure_function_of_its_inputs`) —
concurrent reconciliation attempts converge on the same plan rather than
diverging. Combined with webhook staleness protection
(`is_stale_subscription_update`), a race between a live webhook delivery
and a manual reconciliation call cannot apply an event older than the
locally stored state.

## Entitlement behavior

Paddle status normalization (`normalize_paddle_status` in
`paddle_webhook_service.py`) is kept deliberately SEPARATE from Stripe's
mapping in `entitlements.py` — both feed the SAME provider-neutral
`NormalizedSubscriptionStatus` enum and the SAME `decide_entitlements()`
logic from message 1, so entitlement behavior (active/grace/expired/
recovered/paused-with-management-available/canceled-at-period-end) is
identical regardless of which provider produced the status.

## Management URL

`create_portal` calls Paddle's customer-portal-session endpoint and
validates the returned URL's host against an allowlist
(`customer-portal.paddle.com` / `sandbox-customer-portal.paddle.com`) —
`PaddleManagementUrlHostError` is raised for any unexpected host, closing
off a hypothetical open-redirect if a future Paddle response shape
changes unexpectedly.

## Cancellation behavior

`cancel_subscription` sets `effective_from="next_billing_period"` when
`cancel_at_period_end` is requested, `"immediately"` otherwise. Paddle is
the only provider currently exposing a dedicated cancel route
(`POST /workspaces/{id}/billing/cancel`) — Stripe callers are redirected
to the existing customer portal (400 response pointing there), matching
Stripe's existing self-service cancellation model.

## Payment-failure / grace-period behavior

`transaction.payment_failed` and `subscription.past_due` both set the
subscription to `past_due` and set
`grace_period_end = now + settings.BILLING_GRACE_PERIOD_DAYS` (default 7
days), recording 2 audit events. A subsequent `transaction.completed`
recovers the subscription to `active` and clears `grace_period_end`.
Verified end-to-end against a real Postgres-backed row in
`TestPaymentFailureAndRecovery`.

## Stripe compatibility result

Zero Stripe code, database field, or environment variable was removed or
modified. `StripeBillingAdapter` remains fully functional and is the
default (`BILLING_PROVIDER=stripe` unchanged in this message's test
defaults). The provider-routing invariant
(`test_commercial_provider_routing.py::TestExistingSubscriptionUsesStoredProvider`)
proves an existing Stripe subscription is never reinterpreted as Paddle
even if the global default setting is flipped.

## Sandbox readiness

Not deployed. `check_production_readiness` and
`validate_paddle_configuration` are both pure, offline functions —
proven to never call `httpx` in
`test_commercial_paddle_readiness.py::TestProductionReadinessReport::test_report_never_calls_a_live_paddle_api`.
Exact sandbox environment variable names for Render and Vercel, plus the
full manual dashboard/deployment procedure, are documented in
`commercial_infrastructure_paddle_sandbox_runbook.md`.

### Exact sandbox Render variables

```
BILLING_PROVIDER=paddle
PADDLE_ENVIRONMENT=sandbox
PADDLE_API_KEY=<sandbox backend API key>
PADDLE_WEBHOOK_SECRET=<sandbox notification destination secret>
PADDLE_TEAM_BASE_PRICE_ID=<sandbox base price ID>
PADDLE_TEAM_ADDITIONAL_SEAT_PRICE_ID=<sandbox additional-seat price ID>
BILLING_GRACE_PERIOD_DAYS=7
```

### Exact sandbox Vercel variables

```
NEXT_PUBLIC_PADDLE_ENVIRONMENT=sandbox
NEXT_PUBLIC_PADDLE_CLIENT_TOKEN=<sandbox client-side token>
```

## Sandbox/production API calls made by this message

**Zero.** No Paddle sandbox call and no Paddle production call was made
by any test, script, or manual step in this message. All 341 passing
tests mock Paddle HTTP via `httpx.MockTransport`. The 2 skipped tests
(`test_commercial_paddle_sandbox_optional.py`) are gated behind
`RUN_PADDLE_SANDBOX_TESTS=1` and real credentials, neither of which were
present, and additionally hard-refuse to run at all if
`PADDLE_ENVIRONMENT=production`.

## Production cutover readiness

Not executed; a 15-step gated checklist with explicit preconditions and
a rollback plan is documented in
`commercial_infrastructure_paddle_production_cutover.md`. `BILLING_PROVIDER`
remains `stripe` by default; nothing in this message flips it in any
deployed environment.

## Rollback plan

At any point after a hypothetical cutover, setting `BILLING_PROVIDER`
back to `stripe` is sufficient — Stripe code/fields/variables are fully
intact, and the provider-routing invariant means any subscription
already created under Paddle continues to be served by the Paddle
adapter via its stored `provider` field, so rollback does not orphan an
in-flight Paddle subscription.

## Test totals

**341 passed, 2 skipped** for the full `-k "commercial"` filter (up from
message 1's baseline; the increase is entirely message-2 additions: 157
new/updated Paddle-specific test node IDs across 11 new test files plus
2 updated message-1 test files for real-adapter compatibility).

## Narrow-filter results (all 11 required filters, non-zero)

| Filter | Count |
|---|---|
| `paddle_client` | 16 |
| `paddle_checkout` | 13 |
| `paddle_webhook` | 24 |
| `paddle_signature` | 19 |
| `subscription_items` | 17 |
| `seat_reconciliation` | 16 |
| `paddle_entitlements` | 14 |
| `paddle_management` | 6 |
| `paddle_readiness` | 22 |
| `provider_routing` | 10 |
| `message2_reports` | see `test_commercial_message2_reports.py` (non-zero, added by this message) |

## Focused regressions

Message-1 pricing, billable-seats, provider-registry, entitlements,
webhook-idempotency, and Stripe-adapter test files; billing-service;
billing-API; workspace-membership; invitation-acceptance; Stripe-checkout;
Stripe-portal; Stripe-webhook; frontend-billing-page — all run explicitly
by exact file path (never a broad filter) and all pass with zero
regressions attributable to this message's changes. (Two message-1 test
files, `test_commercial_paddle_contract.py` and
`test_commercial_provider_registry.py`, required intentional updates —
documented above and in this message's implementation history — because
message 1's Paddle adapter was contract-only and message 2 replaced it
with a real implementation; this is an expected, deliberate update, not
a regression.)

## Frontend validation

`npx tsc --noEmit` passes with zero errors after all frontend edits
(`paddle.ts`, `api.ts`, `types/index.ts`,
`settings/workspace/billing/page.tsx`). No frontend test framework
exists in this repository (consistent with message 1's finding);
`tsc` remains the sole automated frontend gate, supplemented by direct
code review of the checkout/fallback logic.

## Migration validation

No new Alembic migration was required for message 2 — message 1's
`036_commercial_infrastructure_billing.py` schema (`NormalizedSubscription`,
`BillingWebhookEvent`, `BillingAuditEvent`, `BillingProviderReference`,
all provider-neutral with a `provider` discriminator column) is already
sufficient to store Paddle data distinctly from Stripe data. This was
confirmed by direct inspection of the migration and the models it
creates, and by the fact that every message-2 end-to-end test
successfully creates/reads/updates Paddle-provider rows in that same
schema without any schema change.

## Report matrix row count

`commercial_infrastructure_message2_test_matrix.md` contains 260+ rows
mapped to real, currently-passing test node IDs (see that file for the
exact count and full listing).

## Files changed

New backend modules: `paddle_config.py`, `paddle_client.py`,
`paddle_webhooks.py`, `seat_reconciliation.py`, `provider_routing.py`,
`paddle_webhook_service.py`, `reconciliation_service.py`, `readiness.py`,
`catalog_verification.py`, `routers/paddle_webhook.py`. Rewritten:
`adapters/paddle.py`, `registry.py`. Extended: `config.py`,
`routers/billing.py`, `main.py`. New frontend module: `lib/paddle.ts`.
Extended frontend: `lib/api.ts`, `types/index.ts`,
`settings/workspace/billing/page.tsx`. 11 new backend test files, 2
updated backend test files. 8 new reports (this one plus 7 others).

## Commit hash

Recorded after commit — see the final deliverable message accompanying
this report for the exact hash (message text: "Implement Paddle billing
integration").

## Message-3 recommendation

Commercial Infrastructure message 3 ("Stripe Retirement and Billing
Operations Hardening") is reserved and NOT started by this message, per
explicit instruction. When undertaken, it should address: safe migration
or explicit closure path for any live Stripe customers once Paddle is
proven in production; eventual removal of Stripe secrets and code only
after a full rollback window with zero incidents; hardening the
sandbox-signature-verification gap flagged honestly in this message's
security review (a genuine live-sandbox round-trip test); and load/scale
testing of the webhook pipeline under realistic Paddle event volume.

## Safe to push?

**No.** Per explicit instruction, this message's work must be committed
locally only and never pushed, regardless of gate status.
