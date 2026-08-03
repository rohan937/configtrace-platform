# Commercial Infrastructure — Paddle Cutover Sequence (message 2+ plan)

This document is a PLAN only. No step in it is executed by Commercial
Infrastructure message 1 — no Paddle API is called, no Paddle product or
price is created, no hosted environment variable is added or changed.

## Phase A — Paddle account readiness

1. Complete Paddle business verification for the ConfigTrace legal entity
   (India-based, selling global B2B SaaS subscriptions — Paddle acts as
   merchant of record, which simplifies India-origin global tax/compliance
   versus Stripe's model where ConfigTrace would remain the merchant of
   record).
2. Verify ConfigTrace and its Team pricing ($30 base + $5/seat) are
   approved under Paddle's review process.
3. Create the Paddle sandbox catalog (separate from live — Phase C).
4. Configure the sandbox notification (webhook) destination pointing at a
   reachable sandbox/staging backend URL.

## Phase B — Sandbox implementation (message 2)

1. Create the Team base monthly product/price in the Paddle sandbox
   catalog ($30/month, recurring). Record the resulting sandbox price ID.
2. Create the Team additional-seat monthly product/price in the Paddle
   sandbox catalog ($5/month, recurring, quantity-based). Record the
   resulting sandbox price ID.
3. Add `PADDLE_ENVIRONMENT=sandbox`, the sandbox `PADDLE_API_KEY`, and the
   sandbox `PADDLE_WEBHOOK_SECRET` to Render (backend) — this message does
   NOT do this; message 2 does.
4. Add the sandbox `NEXT_PUBLIC_PADDLE_CLIENT_TOKEN` to Vercel (frontend).
5. Populate `PADDLE_BASE_PRICE_ID` / `PADDLE_ADDITIONAL_SEAT_PRICE_ID` with
   the sandbox price IDs from steps 1-2.
6. Deploy with `BILLING_PROVIDER` still `stripe` in production but with the
   Paddle adapter now genuinely implemented (message 2 code) and testable
   via `provider_override=BillingProvider.PADDLE` in a controlled path
   (e.g. an internal-only sandbox toggle, exact mechanism to be designed
   in message 2 — not decided here).
7. Test: checkout creates a real sandbox transaction; the sandbox webhook
   fires and is verified/parsed/normalized; `NormalizedSubscription` is
   created/updated correctly; a seat-count change updates the
   additional-seat item quantity; entitlements reflect the new state.

## Phase C — Production preparation

1. Create the LIVE Paddle catalog separately from sandbox (Team base +
   additional-seat prices, live mode) — never reuse a sandbox price ID in
   live mode.
2. Create the live notification (webhook) destination pointing at the
   production backend URL.
3. Add live `PADDLE_API_KEY` / `PADDLE_WEBHOOK_SECRET` /
   `PADDLE_BASE_PRICE_ID` / `PADDLE_ADDITIONAL_SEAT_PRICE_ID` to the
   production Render environment (additively — `STRIPE_*` variables are
   NOT removed at this point).
4. Verify Paddle's domain approval and checkout settings for the
   production domain (`app.configtrace.org` or equivalent).
5. Keep the existing Stripe rollback configuration fully intact and
   functional — `BILLING_PROVIDER` remains `stripe` in production through
   this entire phase.

## Phase D — Cutover

1. Flip `BILLING_PROVIDER=paddle` in the production Render environment —
   this is the single, reversible switch (set it back to `stripe` to roll
   back instantly, since Stripe credentials and code remain fully intact).
2. Enable Paddle checkout in the frontend (message 2+ UI work, not built
   in message 1).
3. Verify ONE real production transaction end-to-end (checkout →
   transaction.completed webhook → NormalizedSubscription updated →
   entitlements reflect paid access).
4. Verify webhook delivery and entitlement state for that transaction
   specifically, not just that "a webhook arrived."
5. Disable creation of NEW Stripe checkouts (existing Stripe subscribers
   are NOT migrated or force-canceled by this step — see Phase E).
6. Retain Stripe read/reconciliation compatibility — `StripeBillingAdapter`
   stays fully functional for any existing Stripe subscriber's portal
   access, webhook processing, and entitlement sync.

## Phase E — Retirement (only after a full rollback window with zero
## incidents, and only after confirming no live Stripe subscriber remains
## unmigrated)

1. Remove the Stripe webhook endpoint registration in the Stripe Dashboard
   (stop new deliveries) — but do not delete `app/routers/stripe_webhook.py`
   yet.
2. Remove Stripe hosted secrets (`STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`)
   from Render — only after step 1 and after confirming zero remaining
   active Stripe subscriptions requiring portal/webhook access.
3. Remove the Stripe SDK/HTTP-call code path and `StripeBillingAdapter`
   only after the rollback window has fully elapsed with no incidents.
4. Migrate or explicitly close any residual Stripe customer/subscription
   records — never silently orphan a paying customer's billing state.

## Rollback strategy (any phase after B)

Set `BILLING_PROVIDER` back to `stripe`. Because message 1 never removes
or rewires the existing Stripe code path, and message 2+ is required to
keep it functional through Phase E, this rollback is a single
configuration change with no code deploy required, at any point up to the
start of Phase E's secret removal.
