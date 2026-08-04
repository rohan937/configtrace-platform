# Commercial Infrastructure — Paddle Production Cutover Checklist (message 2)

This supersedes/extends `commercial_infrastructure_paddle_cutover.md`
(message 1's forward-looking plan) now that message 2 has implemented the
real Paddle adapter, webhook pipeline, and reconciliation logic. This
document is still a PLAN ONLY — no step below was executed by this
message. No live Paddle API call was made. No production Paddle
credential exists in this repository or any committed file.

## Preconditions (must ALL be true before starting cutover)

- [ ] Sandbox end-to-end flow has been manually verified per
      `commercial_infrastructure_paddle_sandbox_runbook.md` (checkout →
      transaction.completed webhook → `NormalizedSubscription` updated →
      entitlements reflect paid access) — at least once, with a human
      operator watching.
- [ ] `check_production_readiness(settings)` (offline, `app/billing/readiness.py`)
      reports `all_safe=True` against the PRODUCTION environment's actual
      configuration (run this as a management command in the target
      environment, never against a copy of production secrets locally).
- [ ] Live Paddle catalog created SEPARATELY from sandbox — live price IDs
      are provably distinct from sandbox price IDs (`no_sandbox_live_mismatch_detected`
      readiness check passes).
- [ ] Live Paddle notification (webhook) destination created, pointed at
      the production backend's `/paddle/webhook` route, with the correct
      event set selected (see sandbox runbook, step 8, live-mode
      equivalent).
- [ ] Live Render environment variables added (see below) — additively;
      no existing `STRIPE_*` variable removed or modified.
- [ ] Live Vercel environment variables added (`NEXT_PUBLIC_PADDLE_*`) to
      the Vercel **Production** environment specifically — additively.
- [ ] `BILLING_PROVIDER` in production is STILL `stripe` at this point —
      it does not flip until step 10 below.
- [ ] At least one team member (operator) has explicitly approved
      executing a real production Paddle transaction, per the explicit
      "do not run production Paddle transactions without explicit
      operator approval" constraint governing this work.
- [ ] Rollback plan (below) has been read and understood by the operator
      performing the cutover.

## Cutover sequence (15 steps)

1. Confirm all preconditions above are checked off.
2. In the Paddle live dashboard, create the Team base monthly price
   ($30.00 USD/month) — record the live price ID.
3. In the Paddle live dashboard, create the Team additional-seat monthly
   price ($5.00 USD/month, quantity-based) — record the live price ID.
4. Add `PADDLE_ENVIRONMENT=production`, live `PADDLE_API_KEY`, live
   `PADDLE_WEBHOOK_SECRET`, live `PADDLE_TEAM_BASE_PRICE_ID`, live
   `PADDLE_TEAM_ADDITIONAL_SEAT_PRICE_ID` to the production Render
   environment. Do NOT set `BILLING_PROVIDER=paddle` yet.
5. Deploy the backend with these new variables present (Render requires
   a new deploy to pick up env changes).
6. Run `check_production_readiness` against the deployed production
   environment (e.g., via a one-off management shell) — require
   `all_safe=True` before proceeding.
7. Add `NEXT_PUBLIC_PADDLE_ENVIRONMENT=production` and the live
   `NEXT_PUBLIC_PADDLE_CLIENT_TOKEN` to Vercel Production. Deploy.
8. Configure the live Paddle notification destination URL to point at
   the now-deployed production backend.
9. Trigger a Paddle "send test event" from the live dashboard and
   confirm it is received, signature-verified, and persisted (check
   `commercial_webhook_events`, never raw logs).
10. Flip `BILLING_PROVIDER=paddle` in the production Render environment.
    This is the single, reversible switch.
11. With explicit operator approval already secured (precondition
    above), perform exactly ONE real production checkout end-to-end
    (an operator-owned test workspace, not a real customer) and verify
    the full chain: checkout → `transaction.completed` webhook →
    `NormalizedSubscription` created → entitlements reflect paid access.
12. Verify the seat-reconciliation path against that same test
    subscription (add/remove a member, confirm the additional-seat
    quantity updates with the correct proration mode).
13. Verify the customer-management-portal URL opens correctly and its
    host passes `_validate_management_url`.
14. Verify subscription cancellation end-to-end for that same test
    subscription (cancel → webhook → local status → entitlements revoke
    at the correct time per `cancel_at_period_end`).
15. Only after steps 11–14 all pass: announce Paddle as the live
    checkout provider for new customers. Existing Stripe subscribers are
    NOT migrated — they continue to be served by `StripeBillingAdapter`
    per the provider-routing invariant (stored provider always wins for
    existing subscriptions).

## Rollback plan

At any point after step 10, set `BILLING_PROVIDER` back to `stripe` in
the production Render environment and redeploy (or rely on Render's
env-var-only redeploy if no code changed). This is safe because:

- Stripe compatibility code, database fields, and environment variables
  were never removed or modified by this message.
- The provider-routing invariant (`provider_for_management`,
  `provider_for_reconciliation`) means any subscription already created
  under Paddle remains served by the Paddle adapter even after the
  global default flips back to Stripe — rollback stops NEW Paddle
  checkouts, it does not orphan an in-flight Paddle subscription.
- No destructive migration was run — message 2 added no new tables or
  columns; message 1's schema is provider-neutral and already stores a
  `provider` discriminator per subscription/webhook-event row.

If a rollback is executed, any Paddle subscription created between step
10 and the rollback continues to be reconciled and managed via the
Paddle adapter (`provider_for_management`/`provider_for_reconciliation`
resolve from the stored `provider` field on that row, not from the
global `BILLING_PROVIDER` setting).

## Explicitly out of scope for this cutover (reserved for message 3+)

Per the explicit "do not" constraints governing this work: this document
does not plan or authorize migrating existing Stripe customers to
Paddle, removing Stripe database fields or environment variables, or
retiring Stripe read/webhook compatibility. Those are explicitly
reserved for a future "Stripe Retirement and Billing Operations
Hardening" milestone (Commercial Infrastructure message 3), which this
message does not begin.
