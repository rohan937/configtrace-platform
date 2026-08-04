# Commercial Infrastructure — Paddle Sandbox Runbook (message 2)

This is an OPERATOR runbook. No step in it was executed by this message —
no Paddle account, sandbox or otherwise, was accessed. It documents
exactly what a human operator must do to stand up sandbox Paddle billing.

## Operator readiness checklist

### Sandbox prerequisites

- [ ] Paddle sandbox account accessible
- [ ] Business/application information entered in the Paddle dashboard
- [ ] Default payment link / domain configured where Paddle requires it
- [ ] Sandbox client-side token created (Developer Tools → Authentication)
- [ ] Sandbox API key created (Developer Tools → Authentication)
- [ ] Sandbox notification destination created (Developer Tools → Notifications)
- [ ] Team base monthly product/price created ($30/month, USD, recurring)
- [ ] Additional-seat monthly product/price created ($5/month per unit, USD, recurring)

### Live prerequisites (for message-3+ cutover — not required for sandbox work)

- [ ] Paddle account approved for live transactions
- [ ] Production domain approved
- [ ] Live client-side token created
- [ ] Live API key created
- [ ] Live notification destination created
- [ ] Live Team base monthly product/price created SEPARATELY from sandbox
- [ ] Live additional-seat monthly product/price created SEPARATELY from sandbox

## Paddle sandbox catalog procedure (dashboard steps)

Using Paddle's current dashboard terminology:

1. **Catalog → Products → Create product.** Name it "ConfigTrace Team"
   (or similar) — this is the parent product both prices attach to.
2. **Create a monthly recurring price** on that product: $30.00 USD,
   billing cycle "Monthly", quantity fixed at 1 in normal use (Paddle
   still allows a quantity field; ConfigTrace always sends 1 for this
   price). Verify the tax category matches ConfigTrace's actual tax
   treatment (typically "Standard"/SaaS — confirm with Paddle's current
   tax-category list, do not guess).
3. **Create a second monthly recurring price** on the SAME product (or a
   second product, per current Paddle catalog conventions — verify
   whichever the Paddle dashboard presents): $5.00 USD per unit, billing
   cycle "Monthly", quantity variable (this is the item whose quantity
   ConfigTrace sets to `max(0, seats - 20)`).
4. **Verify USD** is the price currency for both prices — ConfigTrace's
   pricing contract (`app/billing/pricing.py`) assumes USD only.
5. **Create a client-side token** (Developer Tools → Authentication →
   Client-side tokens). This is the ONLY Paddle credential ever placed in
   a frontend/Vercel environment variable.
6. **Create an API key** (Developer Tools → Authentication → API keys).
   Backend/Render only.
7. **Create a notification destination** (Developer Tools →
   Notifications). Point it at `https://<render-backend-host>/paddle/webhook`.
8. **Select the required webhook events** on that destination:
   `subscription.created`, `subscription.updated`, `subscription.canceled`,
   `subscription.paused`, `subscription.resumed`, `transaction.completed`,
   `transaction.payment_failed`, `customer.updated` (verify the exact
   current event names in the Paddle dashboard's event picker — this
   message's mapping in `app/billing/paddle_webhooks.py` is based on
   Paddle's publicly documented event names and has not been cross-checked
   against a live dashboard in this message).
9. **Copy ONLY the identifiers/secrets** into their correct hosted
   environment (see below) — never into a committed file, test fixture,
   or this report.

## Render sandbox variables (exact names to add manually)

```
BILLING_PROVIDER=paddle
PADDLE_ENVIRONMENT=sandbox
PADDLE_API_KEY=<sandbox backend API key>
PADDLE_WEBHOOK_SECRET=<sandbox notification destination secret>
PADDLE_TEAM_BASE_PRICE_ID=<sandbox base price ID>
PADDLE_TEAM_ADDITIONAL_SEAT_PRICE_ID=<sandbox additional-seat price ID>
BILLING_GRACE_PERIOD_DAYS=7
```

## Render application procedure

1. Open the correct backend service in the Render dashboard
   (`configtrace-api`, per `render.yaml`).
2. Open the service's **Environment** tab.
3. Add the sandbox variables listed above.
4. Save changes and trigger (or wait for) a new deployment — **Render
   only applies changed environment variables on a new deploy**, an
   existing running instance does not pick them up live.
5. After deploy completes, verify startup succeeded (no crash-loop in
   the Render logs — a misconfigured `PADDLE_ENVIRONMENT` value would
   fail `paddle_environment_normalized` validation at readiness-check
   time, not at import time, so a bad value will NOT crash startup by
   itself; check the readiness command's output instead).
6. Verify the health endpoint (`GET /health`) returns healthy.
7. Verify the checkout endpoint
   (`POST /workspaces/{id}/billing/checkout/team`, as an authenticated
   admin) returns Paddle-shaped data (`provider: "paddle"`, a
   `checkout_url`, and an `external_reference` transaction ID).
8. Configure the Paddle sandbox notification destination's URL to the
   deployed backend's `/paddle/webhook` route (step 7 of the catalog
   procedure above, now pointed at the real deployed host).
9. Trigger a Paddle test notification from the dashboard (Paddle
   provides a "Send test event" action on notification destinations).
10. Verify in the Render logs (or the `commercial_webhook_events` table)
    that the event was received, signature-verified, and persisted —
    never verify by reading a raw logged body (none is ever logged).

## Vercel sandbox variables (exact names to add manually)

```
NEXT_PUBLIC_PADDLE_ENVIRONMENT=sandbox
NEXT_PUBLIC_PADDLE_CLIENT_TOKEN=<sandbox client-side token>
```

`PADDLE_API_KEY` and `PADDLE_WEBHOOK_SECRET` must NEVER be added to
Vercel — they are backend-only secrets.

## Vercel application procedure

1. Open the correct frontend project in the Vercel dashboard.
2. Open **Project Settings → Environment Variables**.
3. Add the two Paddle sandbox public variables above, scoped to
   **Preview only** initially — never Production yet.
4. Redeploy the Preview environment (Vercel applies env vars only to
   NEW deployments, same as Render).
5. Confirm the variables are present in the new deployment's build logs
   or via the deployed preview's runtime (`process.env.NEXT_PUBLIC_*`
   values are baked into the client bundle at build time).
6. Test Paddle.js initialization and checkout end-to-end against the
   Preview deployment: open the billing page, click Upgrade to Team,
   confirm the Paddle checkout overlay opens (via
   `frontend/src/lib/paddle.ts::initPaddle`/`openPaddleCheckout`).
7. Do NOT add live/production Paddle variables to Preview unless
   intentionally testing live mode against a real charge risk.
8. Add production variables to Vercel **Production** only during the
   message-3+ production-cutover phase — never during sandbox testing.

## Cleanup

Sandbox transactions and subscriptions created during this testing carry
no real financial consequence — Paddle sandbox never charges real money.
Periodically review the sandbox dashboard's Customers/Subscriptions lists
and remove test objects if the sandbox catalog becomes cluttered; this is
housekeeping, not a security requirement.
