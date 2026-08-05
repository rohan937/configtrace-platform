# ConfigTrace Dodo Payments — Operator Handbook (no Claude Code required)

This handbook is self-contained. It assumes you have only: Git, macOS
Terminal, the Render dashboard + shell, the Vercel dashboard, the Dodo
dashboard, ConfigTrace admin access, and PostgreSQL access via the Render
shell. It does not assume access to an AI coding assistant.

**State as of this handbook**: Dodo is implemented and passes Test Mode
readiness. Test Mode products exist. A signed Test Mode webhook delivery
returns HTTP 200. The live-cutover code package is committed.
`BILLING_PROVIDER=stripe` everywhere. No Dodo Live object exists. Stripe
and Paddle remain fully active and must stay that way throughout.

Every command below is annotated **[READ-ONLY]** or **[MUTATING]**, and
**[TEST-SAFE]** or **[LIVE-SENSITIVE]**. Never run a Live-sensitive
mutating command without deliberately intending its effect.

---

## Table of contents

1. Deployment state verification
2. Credential inventory
3. macOS Keychain operations
4. Dodo Test Mode catalog
5. Dodo Live catalog
6. API keys
7. Webhook endpoints
8. Readiness commands
9. Controlled Test Mode Pro checkout
10. Controlled Test Mode Team checkout
11. Live pilot rollout
12. Global cutover
13. Rollback
14. Database inspection
15. Troubleshooting decision tree
16. Launch-day checklist
17. First 24 hours
18. First week
19. Credential and object inventory templates
20. Final "no Claude" quick reference

---

## 1. Deployment state verification

### 1.1 Local branch and commit

```bash
cd /path/to/ConfigTrace
git status
git branch --show-current
git log -1 --format="%H %s"
```
Expected: branch `main`, clean working tree (or only expected in-flight changes), and the commit subject line matching what you expect to be deployed.

### 1.2 Origin/main comparison

```bash
git fetch origin
git log HEAD..origin/main --oneline     # commits on origin not yet local
git log origin/main..HEAD --oneline     # commits local not yet pushed
```
Expected for a normal operator session: the second command may show unpushed local commits (you push manually); the first should be empty unless someone else has pushed.

### 1.3 Render deployment health

Render Dashboard → `configtrace-api` service → **Events** tab: confirm the latest deploy is `Live` (green), not `Failed` or `Build in progress`.

```bash
curl -i https://api.configtrace.org/health
```
Expected: `HTTP/1.1 200 OK` with a small JSON body. A `502`/`503` means the service isn't up; check Render → **Logs** for a crash on boot (commonly a missing/invalid environment variable — see section 2).

### 1.4 Deployed Dodo webhook route

```bash
curl -i -X POST https://api.configtrace.org/dodo/webhook \
  -H "Content-Type: application/json" \
  -d '{"type":"ping"}'
```

Interpreting the response:

| Response | Meaning |
|---|---|
| `400 {"detail":"Missing required webhook signature headers."}` | **Expected/healthy.** The route exists, the app is up, and it correctly rejects an unsigned request. |
| `404 Not Found` | The route is not deployed — you are either hitting the wrong host/path, or the deployed commit predates the Dodo webhook router (`app/routers/dodo_webhook.py`) being wired into `app/main.py`. Check the deployed commit (section 1.1) against `git log -- backend/app/routers/dodo_webhook.py`. |
| `503 {"detail":"Dodo webhooks are not configured on this server."}` | The route exists but `DODO_WEBHOOK_SECRET` is unset in Render. Not an error at this stage if you're still on Stripe-only — expected until Stage D/C of the rollout. |
| Any `5xx` other than the two above, or a connection error/timeout | The service itself is unhealthy — check `/health` (1.3) and Render logs first; this is not a Dodo-specific problem. |

### 1.5 Frontend deployment (Vercel)

Vercel Dashboard → your ConfigTrace project → **Deployments** tab: confirm the latest production deployment is `Ready` and matches the commit you expect.

```bash
curl -i https://app.configtrace.org
```
Expected: `HTTP/1.1 200 OK`. Then, in a browser, load `https://app.configtrace.org/settings/workspace/billing` while signed in as an admin and confirm the page renders without a client-side error (open the browser console).

---

## 2. Credential inventory

All Dodo variables live on **Render**, on the `configtrace-api` service only (Environment tab). **Nothing Dodo-related is ever set on Vercel** — the frontend never talks to Dodo directly; it only redirects to a `checkout_url` the backend already created, exactly like the existing Stripe path (`frontend/src/app/(app)/settings/workspace/billing/page.tsx`, `handleDodoCheckout`).

| Variable | Location | Secret? | Test vs Live | Rotation | Keep during rollback? |
|---|---|---|---|---|---|
| `DODO_ENVIRONMENT` | Render, `configtrace-api` | No | `test`/`test_mode` in Test, `live`/`live_mode` in Live (both spellings accepted — see `Settings.dodo_environment_normalized`) | N/A | Yes — needed for any remaining Dodo management/reconciliation calls. |
| `DODO_API_KEY` | Render, `configtrace-api` | **Yes** | Completely different value between Test and Live — never share one | Create a new key in the Dodo dashboard, update Render, redeploy, then revoke the old key in Dodo once confirmed working | Yes, if any Dodo subscription still exists (needed to manage it). |
| `DODO_WEBHOOK_SECRET` | Render, `configtrace-api` | **Yes** | Different per environment; generated fresh per webhook endpoint | Create a new Live webhook endpoint (a new secret is issued), update Render, confirm signed delivery, then delete the old endpoint in Dodo | Yes, while any Dodo subscription still exists — webhook events must keep verifying. |
| `DODO_PRO_PRODUCT_ID` | Render, `configtrace-api` | No (treat as operationally sensitive — see section 4) | Different ID per environment | N/A — recreate the product to change price | Yes. |
| `DODO_TEAM_PRODUCT_ID` | Render, `configtrace-api` | No | Different ID per environment | N/A | Yes. |
| `DODO_TEAM_ADDITIONAL_SEAT_ADDON_ID` | Render, `configtrace-api` | No | Different ID per environment | N/A | Yes. |
| `DODO_PILOT_WORKSPACE_ID` | Render, `configtrace-api` | No (plain workspace UUID) | Same mechanism in either environment; only meaningful once Dodo is fully configured | N/A — set/unset freely | **No** — remove during rollback (section 13) unless you specifically want the pilot workspace to keep using Dodo. |
| `BILLING_PROVIDER` | Render, `configtrace-api` | No | `stripe` \| `paddle` \| `dodo` | N/A | Set back to `stripe` on rollback (section 13). |
| `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, and every other existing `STRIPE_*` variable | Render, `configtrace-api` | **Yes** | Already Live in production | Existing Stripe rotation process — unaffected by Dodo | **Always keep** — Stripe subscriptions never leave Stripe. |
| `PADDLE_API_KEY`, `PADDLE_WEBHOOK_SECRET`, `PADDLE_ENVIRONMENT`, and every other existing `PADDLE_*` variable | Render, `configtrace-api` | **Yes** | Already Live in production | Existing Paddle rotation process — unaffected by Dodo | **Always keep.** |
| `NEXT_PUBLIC_BILLING_CHECKOUT_DISABLED` (existing kill switch, if set) | Vercel, ConfigTrace frontend project (build-time) | No | Same in both | N/A | Independent of Dodo — leave as-is unless you specifically want to pause all checkout globally. |

Do not invent any variable not in this table. If a step later in this document seems to require a new variable, stop and check `backend/app/config.py` directly rather than guessing.

---

## 3. macOS Keychain operations

Use the macOS `security` CLI (built in, no install needed) as your local secret store while handling Dodo credentials before pasting them into Render. Every command below never echoes the secret value to the terminal unless you explicitly ask it to with `-w`.

**Storing a Test API key:**
```bash
security add-generic-password -a "$USER" -s "dodo-test-api-key" -w "PASTE_KEY_HERE"
```
(Your shell history may retain the plaintext command — see the clipboard note in 3.9 for a safer paste-based alternative.)

**Storing a Live API key** (only after Live Mode is approved and a Live key exists):
```bash
security add-generic-password -a "$USER" -s "dodo-live-api-key" -w "PASTE_KEY_HERE"
```

**Storing the Test webhook secret:**
```bash
security add-generic-password -a "$USER" -s "dodo-test-webhook-secret" -w "PASTE_SECRET_HERE"
```

**Storing the Live webhook secret:**
```bash
security add-generic-password -a "$USER" -s "dodo-live-webhook-secret" -w "PASTE_SECRET_HERE"
```

**Reading a value into an environment variable (value never printed to the terminal):**
```bash
export DODO_API_KEY=$(security find-generic-password -a "$USER" -s "dodo-test-api-key" -w)
```

**Confirming presence without printing the value:**
```bash
security find-generic-password -a "$USER" -s "dodo-test-api-key" >/dev/null 2>&1 && echo "present" || echo "absent"
```

**Checking a prefix without exposing the full value** (useful to confirm you copied a webhook secret with the `whsec_` prefix intact, without ever displaying the rest):
```bash
security find-generic-password -a "$USER" -s "dodo-test-webhook-secret" -w | cut -c1-6; echo
# Expect: whsec_
```

**Replacing a stored value** (add `-U` to update in place instead of erroring on a duplicate):
```bash
security add-generic-password -a "$USER" -s "dodo-test-api-key" -w "NEW_KEY_HERE" -U
```

**Deleting a retired value safely:**
```bash
security delete-generic-password -a "$USER" -s "dodo-test-api-key"
```
Do this only after you've confirmed the corresponding Render variable is already updated to a different value and redeployed successfully — don't delete your only copy of a still-in-use secret.

**Clearing the clipboard** (after pasting a secret into Render's dashboard):
```bash
pbcopy < /dev/null
```

---

## 4. Dodo Test Mode catalog

You've stated Test Mode products already exist. Use this section to verify them (or recreate if needed).

### 4.1 ConfigTrace Pro
Dodo Dashboard (Test Mode toggle ON) → **Products** → find or create:
- Name: `ConfigTrace Pro`
- Price: `$10.00 USD`, **Monthly**, recurring
- Tax category: **SaaS**
- Add-ons: none

### 4.2 ConfigTrace Team
- Name: `ConfigTrace Team`
- Price: `$30.00 USD`, **Monthly**, recurring
- Tax category: **SaaS**
- Includes up to 20 members (informational only — Dodo doesn't enforce seat counts; ConfigTrace's backend does, via the add-on below)

### 4.3 ConfigTrace Additional Team Member (add-on)
- Name: `ConfigTrace Additional Team Member`
- Price: `$5.00 USD`, recurring, per unit
- Associated with: **Team only** — open the Team product's edit page and confirm this add-on is listed under it; it must not appear under Pro.

### 4.4 Finding IDs
Click into each product/add-on — the ID is shown in the dashboard (and in the URL, typically `.../products/<id>`). Record these as `DODO_PRO_PRODUCT_ID`, `DODO_TEAM_PRODUCT_ID`, `DODO_TEAM_ADDITIONAL_SEAT_ADDON_ID` in your Test-mode inventory (section 19).

### 4.5 Avoiding duplicates / Test vs Live confirmation
- Before creating anything, search the **Test Mode** product list by name — if `ConfigTrace Pro` already exists, use it; do not create a second one.
- Confirm the dashboard's mode toggle reads **Test Mode** before touching anything in this section — this is the single most common mistake.
- Cross-check locally: `python scripts/dodo_live_cutover.py catalog-verify` (no `--live` flag) refuses to run if your Render environment resolves to `live`, so running it locally against your Test values is safe by design (see section 8).

---

## 5. Dodo Live catalog

Do this only after Dodo has approved Live Mode access. **Do not perform this section before approval — no Live object may exist yet.**

1. Switch the Dodo dashboard to **Live Mode**.
2. Search the Live product list by name first — confirm nothing named `ConfigTrace Pro` / `ConfigTrace Team` / `ConfigTrace Additional Team Member` already exists (this can happen if someone else on the team started this process).
3. Recreate the exact same three objects as section 4, with the exact same fields:
   - ConfigTrace Pro — $10.00 USD, monthly, SaaS, no add-ons.
   - ConfigTrace Team — $30.00 USD, monthly, SaaS.
   - ConfigTrace Additional Team Member — $5.00 USD, recurring add-on, associated with Team only.
4. Verify: price and currency exact, interval Monthly (not annual/one-time), status Active (not draft), add-on associated with Team only.
5. **Never reuse a Test Mode ID as a Live ID.** Test and Live are different object spaces in Dodo — a Test product ID is not a valid Live product ID and vice versa; using one where the other belongs will fail at checkout time (or, worse, silently resolve to nothing).
6. Record the three Live IDs in section 19's Live inventory template — never in a commit, ticket, or chat message.

---

## 6. API keys

### 6.1 Test API key (already exists per your stated state — steps for reference/rotation)
Dodo Dashboard → Test Mode → **Developers → API Keys** → Create key. Grant it whatever the dashboard's default/full permission set is for a server-side integration key — Dodo does not document a narrower read-only key type for this integration's needs (checkout creation, subscription read/update, portal-session creation, product read).

### 6.2 Live API key
Same path, dashboard switched to **Live Mode**. Create the key, copy it immediately (Dodo may not show it again).

### 6.3 Safe storage and Render placement
1. Store it in Keychain immediately (section 3).
2. Paste into Render Dashboard → `configtrace-api` → **Environment** → `DODO_API_KEY` → Save.
3. Clear your clipboard (section 3.9).
4. Never commit it, never paste it into a ticket/Slack/chat.

### 6.4 Verifying Test cannot reach Live and vice versa
Dodo's Test and Live environments are separate base URLs (`test.dodopayments.com` vs `live.dodopayments.com` — see `backend/app/billing/dodo_client.py`). A Test API key against the Live base URL (or vice versa) fails authentication rather than silently working. You do not need to test this manually — `catalog-verify` (section 8) already refuses to run against `live` unless `DODO_ENVIRONMENT` is actually `live`, and a mismatched key/environment pair surfaces as a `401`/`403` from the one real GET call it makes.

### 6.5 Rotation procedure
1. Create the new key in the Dodo dashboard (Test or Live, matching what you're rotating).
2. Update `DODO_API_KEY` in Render, redeploy.
3. Run `python scripts/dodo_live_cutover.py readiness` and, if in Live, `catalog-verify --live` to confirm the new key works.
4. Only after confirming: revoke the old key in the Dodo dashboard.
5. Delete the old key from Keychain (section 3.8).

---

## 7. Webhook endpoints

Endpoint (same URL for both Test and Live — Dodo distinguishes by which mode's signing secret was issued): `https://api.configtrace.org/dodo/webhook`

### 7.1 Events to subscribe to

Subscribe to exactly the events this codebase's normalization map understands (`backend/app/billing/dodo_webhooks.py::_DODO_EVENT_TYPE_MAP`):

```
subscription.active
subscription.renewed
subscription.updated
subscription.plan_changed
subscription.on_hold
subscription.paused
subscription.cancelled
subscription.failed
subscription.expired
subscription.update_payment_method
payment.succeeded
payment.failed
dunning.started
dunning.recovered
```
If the Dodo dashboard offers "subscribe to all events" instead of per-event selection, that's also fine — any event this codebase doesn't recognize is safely acknowledged (`HTTP 200`) and never mutates state.

### 7.2 Creating the Test webhook (reference — already done per your stated state)
Dodo Dashboard → Test Mode → **Developers → Webhooks** → Add endpoint → `https://api.configtrace.org/dodo/webhook` → select the events above → Save.

### 7.3 Creating the Live webhook (approval day)
Same path with the dashboard switched to **Live Mode**. This produces a brand-new signing secret — different from the Test one.

### 7.4 Retrieving and storing the signing secret
Copy the secret shown once at creation time (`whsec_...`). Store it in Keychain (section 3) before pasting into Render as `DODO_WEBHOOK_SECRET`.

### 7.5 Render configuration
Render Dashboard → `configtrace-api` → Environment → `DODO_WEBHOOK_SECRET` → paste → Save → redeploy.

### 7.6 Unsigned reachability check
```bash
curl -i -X POST https://api.configtrace.org/dodo/webhook \
  -H "Content-Type: application/json" \
  -d '{"type":"ping"}'
```
Expected: `400 Bad Request`, `{"detail":"Missing required webhook signature headers."}`. See section 1.4 for other response meanings.

### 7.7 Signed dashboard test event
In the Dodo dashboard's webhook detail page, use its "Send test event" / "Resend" feature if offered, targeting the endpoint above. Expected: `HTTP 200 {"status":"ok"}` shown in the dashboard's delivery log.

### 7.8 Webhook log inspection (dashboard side)
Dodo Dashboard → Webhooks → click the endpoint → **Delivery log** / **Logs** tab — shows each attempt's response code and timestamp.

### 7.9 Expected HTTP 200
Any successfully signature-verified delivery returns `200`, even for an event type this codebase doesn't specifically handle (`{"status":"ok"}`) or one that failed internal processing (`{"status":"error"}` — still `200`, so Dodo doesn't hammer retries; see 7.13).

### 7.10 Replay test
Trigger the exact same event delivery a second time (dashboard "Resend", or wait for Dodo's natural retry). Expected: still `HTTP 200`.

### 7.11 Duplicate-event behavior
```bash
cd backend
python scripts/dodo_live_cutover.py webhook-events --provider dodo --limit 5
```
**[READ-ONLY] [TEST-SAFE, LIVE-SAFE]** — the replayed event's row should show `processing_status: duplicate_ignored`, not a second `processed` row. This is enforced at the database level (unique constraint on `(provider, external_event_id)` in `commercial_webhook_events`), not by application logic alone.

### 7.12 Render log inspection
Render Dashboard → `configtrace-api` → **Logs** → search for `Dodo webhook`. Success logs `Dodo webhook processed: <type> (<status>)`; failures log a warning or exception with `Error processing Dodo webhook event: ...`.

### 7.13 Database verification
See section 8.4 and section 14 for exact commands/SQL.

### 7.14 Secret rotation
1. Create a new webhook endpoint in the Dodo dashboard (issues a new secret) rather than trying to "regenerate" the existing one, unless Dodo's dashboard explicitly offers in-place regeneration.
2. Update `DODO_WEBHOOK_SECRET` in Render, redeploy.
3. Confirm with 7.6–7.10.
4. Delete the old endpoint in Dodo only after confirming the new one works.

---

## 8. Readiness commands

Run all of these from `/backend` with the venv active and `DATABASE_URL` reachable — either your local Postgres (via Docker Compose) or, for a definitive production check, the Render shell (Render Dashboard → `configtrace-api` → **Shell** tab, which already has the production `DATABASE_URL` set).

```bash
cd backend
# Local: point DATABASE_URL at your own Postgres, e.g. via Docker Compose:
set -a && source ../.env && set +a && export DATABASE_URL="postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@localhost:5432/${POSTGRES_DB}"
```

### 8.1 `check_dodo_readiness`
```bash
python scripts/dodo_live_cutover.py readiness
```
**[READ-ONLY] [TEST-SAFE, LIVE-SAFE]** — offline, no HTTP call. Expected: a checklist with `all_present=True` once every Dodo variable is set and internally consistent. Failure → one or more `present: False` rows naming exactly which variable is missing.

### 8.2 Backend health
```bash
curl -i https://api.configtrace.org/health
```
**[READ-ONLY]**. See section 1.3.

### 8.3 Webhook reachability
```bash
curl -i -X POST https://api.configtrace.org/dodo/webhook -H "Content-Type: application/json" -d '{"type":"ping"}'
```
**[READ-ONLY]** (creates no state — signature verification fails before any DB write). See section 1.4.

### 8.4 Masked environment presence
```bash
python scripts/dodo_live_cutover.py env-check
```
**[READ-ONLY] [TEST-SAFE, LIVE-SAFE]** — never prints a secret value, only `True`/`False` for `DODO_API_KEY`/`DODO_WEBHOOK_SECRET`/Stripe/Paddle secrets, and real values for `BILLING_PROVIDER`, `DODO_ENVIRONMENT`, and the catalog IDs. Failure interpretation: any secret showing `False` when you expect it configured means the Render variable is unset or the deploy hasn't picked it up yet (redeploy after setting a Render env var).

### 8.5 Catalog verification
```bash
python scripts/dodo_live_cutover.py catalog-verify            # Test — refuses if DODO_ENVIRONMENT resolves to live
python scripts/dodo_live_cutover.py catalog-verify --live     # Live — refuses if DODO_ENVIRONMENT resolves to test
```
**[READ-ONLY — one GET per product] [refuses the wrong mode by design]**. Expected: raw JSON for the Pro and Team product IDs, plus a `duplicate_product_ids` flag. Failure: `REFUSED: ...` (environment/flag mismatch — fix the flag, not the environment), or an `error` field per product (bad ID, or auth failure — check `DODO_API_KEY`).

### 8.6 Subscription/provider counts
```bash
python scripts/dodo_live_cutover.py subscription-counts
```
**[READ-ONLY] [TEST-SAFE, LIVE-SAFE]** — groups `commercial_subscriptions` by `(provider, status)`. Expected before cutover: no `dodo` rows, or only the pilot workspace's. Failure interpretation: an unexpectedly large `dodo` count before Stage M means checkouts are being routed to Dodo when they shouldn't be — check `BILLING_PROVIDER` and `DODO_PILOT_WORKSPACE_ID` immediately (section 13).

### 8.7 Webhook-event inspection
```bash
python scripts/dodo_live_cutover.py webhook-events --provider dodo --status failed --limit 20
```
**[READ-ONLY]**. Lists recent rows with processing status/error category. Expected empty or all `processed`/`duplicate_ignored`. Failure: `failed` rows — check Render logs (7.12) for the corresponding timestamp.

### 8.8 Duplicate subscription detection
```bash
python scripts/dodo_live_cutover.py duplicate-subscriptions
```
**[READ-ONLY]**. Exit code 1 if any finding exists. Expected: empty list. A finding here is a genuine data-integrity anomaly (two workspaces sharing one provider reference) — do not ignore it; see section 15.

### 8.9 Stuck webhook detection
```bash
python scripts/dodo_live_cutover.py stuck-webhooks --older-than-minutes 60
```
**[READ-ONLY]**. Expected: empty. A non-empty result after Dodo's ~10-hour retry window has passed means manual reconciliation is needed (section 13.8).

### 8.10 Normalized subscription inspection
```bash
python scripts/dodo_live_cutover.py subscription "<workspace name or UUID>"
```
**[READ-ONLY]**. Full non-secret snapshot: provider, plan, status, seats, period, grace period, version. Expected: matches what you did in the Dodo dashboard for that workspace.

### 8.11 Post-cutover health check
```bash
python scripts/dodo_live_cutover.py health-check
```
**[READ-ONLY] [fully offline — no Dodo API call, safe anytime]**. Exit code 0 only if readiness passes AND zero stuck webhooks AND zero duplicate-subscription findings. Run this periodically after Stage M (section 17).

---

## 9. Controlled Test Mode Pro checkout

### 9.1 Select a designated workspace
Pick a non-production-critical workspace you control. Get its UUID:
```bash
python scripts/dodo_live_cutover.py subscription "<workspace name>"
```
(if it prints "No NormalizedSubscription row exists yet", that's fine — note the workspace's UUID from the ConfigTrace admin UI or your own records instead.)

### 9.2 Set the pilot override safely
```bash
python scripts/dodo_live_cutover.py pilot-override print "<workspace name or UUID>" --yes
```
**[READ-ONLY — prints, does not mutate anything]**. This prints the exact line to set:
```
DODO_PILOT_WORKSPACE_ID=<uuid>
```

### 9.3 Deploy the override, keeping BILLING_PROVIDER=stripe
Render Dashboard → `configtrace-api` → Environment → set `DODO_PILOT_WORKSPACE_ID` to the printed UUID. **Do not touch `BILLING_PROVIDER`.** Redeploy.

Confirm:
```bash
python scripts/dodo_live_cutover.py pilot-override status
python scripts/dodo_live_cutover.py env-check
```
Expected: override reports `ACTIVE` for that workspace; `BILLING_PROVIDER` still `stripe`.

### 9.4 Create the Pro checkout
As an admin of the pilot workspace, in the app: Settings → Workspace → Billing → **Upgrade to Pro**. This calls `POST /workspaces/{id}/billing/checkout/pro`.

### 9.5 Confirm a Dodo Test Mode checkout URL
The browser should redirect to a `test.dodopayments.com`-hosted checkout page (not `live.dodopayments.com`, and not a Stripe URL). If it redirects to Stripe instead, the pilot override isn't active for this workspace — recheck 9.3.

### 9.6 Use the documented Dodo Test Mode payment method
Use whatever test card/payment method Dodo's own Test Mode documentation currently specifies (check the checkout page itself, which typically states this, or the Dodo dashboard's Test Mode docs) — this codebase does not hardcode a Dodo test card number anywhere, so do not guess one.

### 9.7 Confirm `payment.succeeded`
```bash
python scripts/dodo_live_cutover.py webhook-events --provider dodo --limit 5
```
Expected: a row with `event_type` reflecting the payment, `processing_status: processed`.

### 9.8 Confirm `subscription.active`
Same command — expect a `subscription_created`/`subscription_updated`-mapped row shortly after.

### 9.9 Check NormalizedSubscription
```bash
python scripts/dodo_live_cutover.py subscription "<workspace>"
```
Expected: `provider: dodo`, `plan_id: pro`, `status: active`.

### 9.10 Check paid entitlement
```bash
curl -s https://api.configtrace.org/workspaces/<id>/billing/subscription \
  -H "Authorization: Bearer <a valid admin session token>" | python3 -m json.tool
```
Expected: `"has_paid_access": true`.

### 9.11 Verify billing page state
In the app, Settings → Workspace → Billing should show Pro as the active plan, with a working "Manage billing" / portal link.

### 9.12 Open the customer portal
Click that link (calls `POST /workspaces/{id}/billing/management`, which for a Dodo subscription calls `adapter.create_portal`). Confirm it opens Dodo's real Test Mode customer portal.

### 9.13 Cancel at period end
In the portal, or via:
```bash
curl -X POST https://api.configtrace.org/workspaces/<id>/billing/cancel \
  -H "Authorization: Bearer <admin session token>"
```
Expected: `{"provider":"dodo","state":"..."}`; `subscription "<workspace>"` now shows `cancel_at_period_end: true`.

### 9.14 Remove the pilot override
```bash
python scripts/dodo_live_cutover.py pilot-override clear --yes
```
**[READ-ONLY — prints the instruction only]**. Then in Render, unset `DODO_PILOT_WORKSPACE_ID`, redeploy. Confirm with `pilot-override status`.

---

## 10. Controlled Test Mode Team checkout

Re-apply the pilot override (9.2–9.3) for the same or a second pilot workspace, then create a Team checkout (Upgrade to Team → `POST /workspaces/{id}/billing/checkout/team`).

Seat math (`app/billing/seat_reconciliation.py::calculate_desired_additional_quantity` = `max(0, members - 20)`):

| Billable members | Additional-seat add-on quantity | Expected monthly price |
|---|---|---|
| 20 | 0 | $30 |
| 21 | 1 | $35 |
| 25 | 5 | $55 |
| back to 20 | 0 | $30 |

For each step:
1. Add/remove workspace members to reach the target count (via the app's Members page).
2. Check the reconciled state:
   ```bash
   python scripts/dodo_live_cutover.py subscription "<workspace>"
   ```
   Expected: `additional_seat_quantity` matches the table above.
3. Cross-check the real Dodo Test Mode subscription in the Dodo dashboard: **Subscriptions** → the pilot workspace's subscription → confirm the add-on line item's quantity matches, and note whatever proration Dodo actually applies (this codebase has not independently verified Dodo's exact proration behavior for add-on quantity changes — this stage IS that verification; see `adapters/dodo.py`'s module docstring).
4. After the full 20→21→25→20 cycle:
   ```bash
   python scripts/dodo_live_cutover.py duplicate-subscriptions
   ```
   Expected: empty — exactly one `commercial_subscriptions` row for this workspace throughout, only its `additional_seat_quantity` and `version` changing.

Rollback this workspace to Stripe: remove the pilot override (9.14) — the workspace's *existing* Dodo subscription keeps being managed by Dodo (stored-provider-wins), but any *future* checkout for this workspace (if this subscription is later canceled and a new one started) would go to Stripe.

---

## 11. Live pilot rollout

Perform only after Dodo has approved Live Mode. Each stage lists preconditions, the action, expected result, stop conditions, and rollback.

### Stage A — Create Live catalog
- **Preconditions**: Live Mode approved; section 5 read.
- **Action**: Create the three Live objects (section 5).
- **Expected**: All three visible in the Live product list, correct price/interval/tax category/add-on association.
- **Stop if**: any duplicate exists, or you can't confirm Live Mode is actually selected.
- **Rollback**: archive/delete the created object(s); nothing else depends on them yet.

### Stage B — Create Live API key
- **Preconditions**: Stage A done (or independent — order between A and B doesn't matter).
- **Action**: Section 6.2.
- **Expected**: Key visible in Dodo's Live key list.
- **Stop if**: dashboard shows you're still in Test Mode.
- **Rollback**: revoke the key in Dodo; nothing in Render references it yet.

### Stage C — Create Live webhook
- **Action**: Section 7.3–7.4.
- **Expected**: Secret captured, endpoint visible in Dodo's Live webhook list.
- **Rollback**: delete the endpoint in Dodo.

### Stage D — Add Live variables while `BILLING_PROVIDER` stays `stripe`
- **Action**: Set `DODO_ENVIRONMENT=live`, `DODO_API_KEY`, `DODO_WEBHOOK_SECRET`, `DODO_PRO_PRODUCT_ID`, `DODO_TEAM_PRODUCT_ID`, `DODO_TEAM_ADDITIONAL_SEAT_ADDON_ID` in Render. Redeploy.
- **Expected**: `env-check` shows all Dodo secrets present, `DODO_ENVIRONMENT` resolves to `live`; `BILLING_PROVIDER` still `stripe`.
- **Stop if**: `BILLING_PROVIDER` shows anything other than `stripe` after this step — you have not authorized that change yet.
- **Rollback**: unset the Live Dodo variables in Render, redeploy. No customer-facing effect (`BILLING_PROVIDER` never changed).

### Stage E — Run readiness
- **Action**: `python scripts/dodo_live_cutover.py readiness`.
- **Expected**: `all_present=True`; the `not_routing_production_to_dodo` check is `True`.
- **Stop if**: any check fails — fix before proceeding.

### Stage F — Read-only Live catalog verification
- **Action**: `python scripts/dodo_live_cutover.py catalog-verify --live`.
- **Expected**: raw JSON for Pro and Team; manually re-confirm against section 5's checklist.
- **Stop if**: `duplicate_product_ids: true`, or either product's raw JSON doesn't match what you created.

### Stage G — Verify signed Live webhook delivery
- **Action**: Sections 7.6–7.10 against the Live secret now in Render.
- **Expected**: `HTTP 200` on a real/dashboard-triggered signed delivery; replay shows `duplicate_ignored`.
- **Stop if**: `400` (secret mismatch — re-check you pasted the Live secret, not the Test one).

### Stage H — Set `DODO_PILOT_WORKSPACE_ID`
- **Action**: Section 9.1–9.3, using the Live pilot workspace.
- **Expected**: `pilot-override status` shows active for that workspace only; a different workspace's checkout still shows `provider: stripe`.
- **Rollback**: `pilot-override clear --yes`, unset in Render.

### Stage I — Complete one real Pro checkout
- **Action**: Section 9.4–9.6, with a real card, real charge.
- **Expected**: real Dodo hosted checkout page (`live.dodopayments.com`), real payment completes.
- **Stop if**: the checkout page is under `test.dodopayments.com` — your `DODO_ENVIRONMENT`/pilot config is still pointed at Test.

### Stage J — Verify transaction, subscription, portal, cancellation
- **Action**: Sections 9.7–9.13.
- **Expected**: all as documented; a real cancellation processes correctly.

### Stage K — Complete one real Team checkout
- **Action**: Section 9 pattern, Team plan.
- **Expected**: `provider: dodo`, `plan_id: team`, `billable_seats: 20`.

### Stage L — Verify seat billing
- **Action**: Section 10's 20/21/25/20 cycle, on the real Live subscription.
- **Expected**: matches the pricing table in section 10; no duplicate subscription created.

### Stage M — Remove the pilot override, or proceed to global cutover
- **Action**: Either `pilot-override clear --yes` (stay pilot-only for now) or proceed directly to section 12 (global cutover).
- **Expected**: your explicit choice, recorded in section 19's inventory template.

---

## 12. Global cutover

### 12.1 Final preflight
```bash
python scripts/dodo_live_cutover.py readiness
python scripts/dodo_live_cutover.py health-check
python scripts/dodo_live_cutover.py duplicate-subscriptions
python scripts/dodo_live_cutover.py stuck-webhooks
```
All must be clean before proceeding.

### 12.2 Deployment order
1. In Render, set `BILLING_PROVIDER=dodo`.
2. Redeploy `configtrace-api`.
3. Do **not** touch the frontend deployment — no Vercel change is needed for this switch.

### 12.3 Health checks
```bash
curl -i https://api.configtrace.org/health
python scripts/dodo_live_cutover.py env-check
```
Expected: `200`; `BILLING_PROVIDER: dodo`.

### 12.4 Test checkout
As a brand-new (or a second, non-pilot) workspace's admin, click Upgrade — confirm it now redirects to Dodo's Live checkout by default, with no pilot override needed.

### 12.5 Monitoring
See section 17.

### 12.6 Validation: existing subscriptions keep their own provider
```bash
python scripts/dodo_live_cutover.py subscription-counts
```
Expected: existing Stripe and Paddle subscription counts are **unchanged** from before the cutover — `provider_for_management`/`provider_for_reconciliation` read the stored provider on each row, never `BILLING_PROVIDER`, so flipping the global default cannot move an existing subscription between providers.

### 12.7 Emergency rollback
See section 13.1 — this is the fastest possible undo (one Render variable, no code change, no data migration).

---

## 13. Rollback

### 13.1 Returning to Stripe globally
1. Render → `configtrace-api` → Environment → `BILLING_PROVIDER=stripe` → Save → redeploy.
2. This immediately stops routing NEW checkouts to Dodo.
3. Any workspace with an existing `provider=dodo` subscription is **unaffected** — it keeps being managed by Dodo (stored-provider-wins).

### 13.2 Removing `DODO_PILOT_WORKSPACE_ID`
```bash
python scripts/dodo_live_cutover.py pilot-override clear --yes
```
Then delete the Render variable (or set it empty), redeploy.

### 13.3 Keep Dodo webhook processing active
**Do not delete the Dodo webhook endpoint in the Dodo dashboard**, and **do not unset any `DODO_*` variable in Render**, as long as any `commercial_subscriptions` row still has `provider=dodo`. Deleting either silently stops that subscription's status from ever updating again.

### 13.4 Keep Dodo credentials for existing Dodo subscriptions
Same reasoning as 13.3 — `DODO_API_KEY` is still needed for portal-session creation and cancellation on any existing Dodo subscription, independent of `BILLING_PROVIDER`.

### 13.5 Stored-provider routing is automatic — nothing to "preserve" manually
`provider_for_management`/`provider_for_reconciliation` (`backend/app/billing/provider_routing.py`) are never touched by any rollback step above; this is by construction, not something you need to separately configure.

### 13.6 Disabling new Dodo checkout creation without a global flip
If `BILLING_PROVIDER` was never flipped to `dodo` (still mid-rollout): remove `DODO_PILOT_WORKSPACE_ID` (13.2) — that alone stops any new Dodo checkout.

### 13.7 Handling an in-progress checkout during rollback
A customer already on Dodo's hosted checkout page when you flip `BILLING_PROVIDER` back is unaffected — that session and its resulting webhook still complete normally as a `provider=dodo` subscription (the provider was decided at checkout-creation time). Only the *next* "Upgrade" click is affected by the reverted setting.

### 13.8 Handling failed/stuck webhooks
```bash
python scripts/dodo_live_cutover.py stuck-webhooks --older-than-minutes 60
python scripts/dodo_live_cutover.py webhook-events --provider dodo --status failed --limit 50
```
Cross-check each stuck/failed row's `external_event_id` against the Dodo dashboard's delivery log (7.8) to see if Dodo already gave up retrying (its documented retry window is ~8 attempts over ~10 hours). If Dodo has stopped retrying and the local row is still `pending`/`failed`, the underlying subscription's local state may be stale — compare `subscription "<workspace>"` against the real state in the Dodo dashboard and correct manually if they disagree (there is no automated resync command in this handbook's script — this is a manual reconciliation).

### 13.9 Handling duplicate subscriptions
```bash
python scripts/dodo_live_cutover.py duplicate-subscriptions
```
A finding here means two workspaces' `commercial_subscriptions` rows share one provider-side reference — a data-integrity bug, not expected behavior. Do not attempt an automated fix; identify which workspace's row is correct by cross-referencing the Dodo dashboard's customer/subscription record, and manually correct the other workspace's row via direct SQL (section 14) only after you are certain which one is wrong.

### 13.10 Handling a Dodo outage
If Dodo itself is down: checkouts for workspaces routed to Dodo will fail at `adapter.create_checkout()` — this raises before any local DB write happens (`_create_plan_checkout` only commits after the provider call succeeds), so no partial/orphaned state is created. Use 13.1/13.6 to route new checkouts back to Stripe until Dodo recovers; existing Dodo subscriptions simply won't receive webhook updates until Dodo's own service recovers (webhooks will retry and catch up automatically once it does).

### 13.11 What must never be deleted
- The Live Dodo webhook endpoint, while any `provider=dodo` subscription exists.
- Any `DODO_*` Render variable, while any `provider=dodo` subscription exists.
- Any row in `commercial_subscriptions`, `commercial_webhook_events`, or `commercial_audit_events`.
- Stripe or Paddle configuration, ever — regardless of Dodo's state.

---

## 14. Database inspection

Run via the Render shell (Render Dashboard → `configtrace-api` → **Shell**) with `psql "$DATABASE_URL"`, or via the operational script where noted. All queries below are read-only `SELECT`s — nothing here mutates data.

**Provider counts:**
```sql
SELECT provider, status, COUNT(*) FROM commercial_subscriptions GROUP BY provider, status ORDER BY provider, status;
```
(equivalent: `python scripts/dodo_live_cutover.py subscription-counts`)

**Subscriptions by workspace:**
```sql
SELECT w.name, cs.provider, cs.plan_id, cs.status, cs.billable_seats
FROM commercial_subscriptions cs
JOIN workspaces w ON w.id = cs.workspace_id
ORDER BY w.name;
```

**Active Dodo subscriptions:**
```sql
SELECT workspace_id, provider_subscription_reference, plan_id, status, billable_seats, additional_seat_quantity
FROM commercial_subscriptions
WHERE provider = 'dodo' AND status = 'active';
```

**Duplicate external subscription IDs** (should return zero rows):
```sql
SELECT provider_subscription_reference, COUNT(*)
FROM commercial_subscriptions
WHERE provider_subscription_reference IS NOT NULL
GROUP BY provider_subscription_reference
HAVING COUNT(*) > 1;
```
(equivalent: `python scripts/dodo_live_cutover.py duplicate-subscriptions`)

**Webhook processing status:**
```sql
SELECT provider, processing_status, COUNT(*)
FROM commercial_webhook_events
GROUP BY provider, processing_status
ORDER BY provider, processing_status;
```

**Failed/stuck webhooks:**
```sql
SELECT id, external_event_id, event_type, processing_status, error_category, attempt_count, received_at
FROM commercial_webhook_events
WHERE provider = 'dodo' AND processing_status IN ('pending', 'failed')
ORDER BY received_at ASC;
```
(equivalent: `python scripts/dodo_live_cutover.py stuck-webhooks` / `webhook-events`)

**Last Dodo webhook time:**
```sql
SELECT MAX(received_at) FROM commercial_webhook_events WHERE provider = 'dodo';
```

**Pilot workspace audit events:**
```sql
SELECT workspace_id, event_type, provider, details, created_at
FROM commercial_audit_events
WHERE event_type = 'pilot_override_applied'
ORDER BY created_at DESC
LIMIT 50;
```

**Plan and entitlement state for a specific workspace:**
```sql
SELECT cs.provider, cs.plan_id, cs.status, cs.billable_seats, cs.additional_seat_quantity,
       cs.cancel_at_period_end, cs.grace_period_end, cs.current_period_end
FROM commercial_subscriptions cs
WHERE cs.workspace_id = '<workspace-uuid>';
```

No `UPDATE`, `DELETE`, or `INSERT` statement is provided in this handbook — any data correction identified via section 13.9 must be made deliberately, by hand, with a full understanding of which row is authoritative, not from a canned script.

---

## 15. Troubleshooting decision tree

| Symptom | Likely cause | Check |
|---|---|---|
| Checkout URL missing / empty | `create_checkout` failed before returning a URL — provider-side error | Render logs for the checkout request; `catalog-verify` to confirm product IDs resolve |
| Wrong environment (Live checkout hits Test catalog, or vice versa) | `DODO_ENVIRONMENT` doesn't match the product/API-key IDs actually configured | `env-check`; confirm `DODO_ENVIRONMENT` and the three catalog IDs were all updated together, not partially |
| Invalid product ID | Typo, or a Test ID pasted where a Live ID belongs (or vice versa) | `catalog-verify` (or `--live`) — an invalid ID surfaces as an `error` per-product in the output |
| Add-on missing from a Team checkout | `DODO_TEAM_ADDITIONAL_SEAT_ADDON_ID` unset, or the add-on isn't actually associated with the Team product in Dodo | `env-check` for the variable; section 4.3/5's dashboard association check |
| Webhook `400` | Signature mismatch — wrong secret, or `webhook-id`/`webhook-timestamp` missing | Confirm `DODO_WEBHOOK_SECRET` matches the endpoint that actually delivered it (Test secret ≠ Live secret) |
| Webhook `401`/`403` | Not applicable to this endpoint — Dodo webhooks carry no bearer auth, only the Standard Webhooks signature; a `401`/`403` here means something else is intercepting the request (e.g. a proxy/WAF) before it reaches the app | Check Cloudflare/Render routing in front of `api.configtrace.org` |
| Webhook `500` | Should never happen — the route always returns `200` even on internal processing failure (`{"status":"error"}`) or `400` on bad signature; a real `500` means an unhandled exception in FastAPI itself | Render logs, full traceback |
| Signature mismatch | Wrong secret pasted, or secret has stray whitespace/missing `whsec_` prefix | `security find-generic-password ... \| cut -c1-6` (section 3.6) to confirm the prefix without exposing the rest |
| Duplicate event | Expected under retry — verify `processing_status: duplicate_ignored`, not a second `processed` row | `webhook-events` |
| Workspace not upgraded after payment | Webhook didn't arrive, or arrived but failed processing, or the subscription row wasn't found by reference | `webhook-events --status failed`; `subscription "<workspace>"`; confirm `provider_customer_reference`/`provider_subscription_reference` actually got set at checkout time |
| Portal URL missing | `provider_customer_reference` not yet set (no successful checkout/webhook yet) | `subscription "<workspace>"` — if `provider_customer_reference` is null, no portal session can be created yet |
| Cancellation not reflected | Webhook for the cancellation event hasn't arrived yet, or arrived and failed | `webhook-events`; re-check the Dodo dashboard's own subscription status |
| Seat quantity wrong | Reconciliation hasn't run yet, or member count changed but no reconciliation trigger fired | `POST /workspaces/{id}/billing/reconcile`; `subscription "<workspace>"` |
| Proration unexpected | Dodo's own proration behavior for add-on quantity changes — not independently verified by this codebase (see section 10) | Compare against the actual Dodo dashboard invoice/line-item detail, not assumptions |
| Billing provider still Stripe after intended cutover | Render env var not actually saved, or deploy didn't pick it up | `env-check`; confirm the Render deploy that followed the variable change is the one currently live (section 1.3) |
| Pilot override affecting the wrong workspace | Wrong UUID pasted into `DODO_PILOT_WORKSPACE_ID` | `pilot-override status` reports the exact configured UUID — cross-check against `pilot-override print "<intended workspace>"`'s output |
| Live checkout accidentally using Test catalog | `DODO_ENVIRONMENT=live` but `DODO_PRO_PRODUCT_ID`/`DODO_TEAM_PRODUCT_ID` still hold Test IDs | `catalog-verify --live` — a Test-mode product ID queried against the Live base URL returns an error, surfacing this immediately |
| Test checkout accidentally using Live credentials | `DODO_ENVIRONMENT=test` but `DODO_API_KEY` is actually a Live key | `catalog-verify` (no `--live`) — Live key against the Test base URL fails auth, surfacing as an `error` in the result |

---

## 16. Launch-day checklist

- [ ] `git log -1` confirms the intended commit is deployed (section 1.1–1.3)
- [ ] `/health` returns 200
- [ ] `/dodo/webhook` unsigned check returns 400 (not 404/503)
- [ ] `readiness` → `all_present=True`
- [ ] `env-check` → all Dodo secrets present, `BILLING_PROVIDER` at the value you intend for this exact step
- [ ] `catalog-verify` (correct mode flag) → no errors, no duplicate IDs
- [ ] Signed webhook delivery → 200, replay → `duplicate_ignored`
- [ ] `duplicate-subscriptions` → empty
- [ ] `stuck-webhooks` → empty
- [ ] Stripe and Paddle checkouts independently confirmed still working (a quick manual click-through, not just "unchanged code")
- [ ] Rollback steps (section 13) re-read and understood by whoever is on call
- [ ] Credential inventory (section 19) filled in with real IDs, stored only in a secrets manager

---

## 17. First 24 hours

Monitor, at minimum hourly:

- **Checkout success**: `subscription-counts` — is the `dodo` count growing as expected, with no unexplained plateau?
- **Webhook success rate**: `webhook-events --status failed` — should stay near-empty.
- **Duplicate subscriptions**: `duplicate-subscriptions` — must stay empty.
- **Payment failures**: `webhook-events` filtered by event types mapping to `payment.failed`/`dunning.started` — a small nonzero rate is normal; a spike is not.
- **Entitlement mismatches**: spot-check a few real workspaces' `has_paid_access` (section 9.10) against what they actually paid for.
- **Portal failures**: manually attempt the portal link on one real Dodo subscription.
- **Render errors**: Render → Logs, filtered for `5xx` or unhandled exceptions.
- **Dodo dashboard errors**: check Dodo's own dashboard for any account-level alert/error banner.

Run the composite check periodically:
```bash
python scripts/dodo_live_cutover.py health-check
```

---

## 18. First week

- **Subscription reconciliation**: run `POST /workspaces/{id}/billing/reconcile` (or wait for its scheduled equivalent, if one exists in this deployment) against a sample of Dodo workspaces and confirm no drift.
- **Payout status**: check the Dodo dashboard's payouts/settlement section — confirm funds are actually settling as expected.
- **Refund handling**: if a refund is issued in the Dodo dashboard, confirm the corresponding webhook event arrives and is acknowledged (`webhook-events`) — note that this codebase's `_DODO_EVENT_TYPE_MAP` does not map any `refund.*` event to a specific normalized type (it falls to `UNKNOWN`, safely acknowledged but not state-changing) — a refund does NOT automatically revoke entitlement in this implementation; treat refund-driven access changes as a manual step for now.
- **Webhook retries**: confirm Dodo's documented retry behavior (~8 attempts over ~10 hours) matches what you observe for any transient failure.
- **Cancellation behavior**: confirm at least one real cancel-at-period-end actually transitions to `canceled` at the real period end (not just at request time).
- **Seat changes**: confirm at least one real mid-cycle seat change reconciles correctly with Dodo's real proration.
- **Provider distribution**: `subscription-counts` — sanity-check the Stripe/Paddle/Dodo split matches your expectations for this stage of rollout.
- **Rollback readiness**: re-confirm section 13 is still accurate and that whoever is on call has practiced it at least once (e.g., in Test Mode).

---

## 19. Credential and object inventory templates

Placeholders only — fill in and store in a secrets manager, never in git, a ticket, or chat.

```
# Dodo Payments — TEST MODE inventory. NOT a real credential file.

DODO_ENVIRONMENT=test
DODO_API_KEY=<REPLACE_WITH_TEST_API_KEY>
DODO_WEBHOOK_SECRET=<REPLACE_WITH_TEST_WEBHOOK_SIGNING_SECRET>

DODO_PRO_PRODUCT_ID=<REPLACE_WITH_TEST_PRO_PRODUCT_ID>
DODO_TEAM_PRODUCT_ID=<REPLACE_WITH_TEST_TEAM_PRODUCT_ID>
DODO_TEAM_ADDITIONAL_SEAT_ADDON_ID=<REPLACE_WITH_TEST_ADDON_ID>

DODO_PILOT_WORKSPACE_ID=<REPLACE_WITH_TEST_PILOT_WORKSPACE_UUID>
```

```
# Dodo Payments — LIVE MODE inventory. NOT a real credential file.

DODO_ENVIRONMENT=live
DODO_API_KEY=<REPLACE_WITH_LIVE_API_KEY>
DODO_WEBHOOK_SECRET=<REPLACE_WITH_LIVE_WEBHOOK_SIGNING_SECRET>

DODO_PRO_PRODUCT_ID=<REPLACE_WITH_LIVE_PRO_PRODUCT_ID>
DODO_TEAM_PRODUCT_ID=<REPLACE_WITH_LIVE_TEAM_PRODUCT_ID>
DODO_TEAM_ADDITIONAL_SEAT_ADDON_ID=<REPLACE_WITH_LIVE_ADDON_ID>

DODO_PILOT_WORKSPACE_ID=<REPLACE_WITH_LIVE_PILOT_WORKSPACE_UUID>   # remove after global cutover unless intentionally kept

# Stage tracking:
Stage A completed: [ ] date: __________  by: __________
Stage B completed: [ ] date: __________  by: __________
Stage C completed: [ ] date: __________  by: __________
Stage D completed: [ ] date: __________  by: __________
Stage E (readiness) result: __________
Stage F (catalog-verify --live) result: __________
Stage G (signed webhook) result: __________
Stage H pilot workspace: __________
Stage I first real Pro checkout — transaction ref: __________
Stage J lifecycle verification notes: __________
Stage K first real Team checkout — subscription ref: __________
Stage L seat verification (20/21/25) notes: __________
Stage M decision (pilot-only vs global cutover) + date: __________
```

---

## 20. Final "no Claude" quick reference

**Most important commands** (run from `/backend`, venv active, `DATABASE_URL` set):
```bash
python scripts/dodo_live_cutover.py readiness
python scripts/dodo_live_cutover.py env-check
python scripts/dodo_live_cutover.py catalog-verify [--live]
python scripts/dodo_live_cutover.py subscription-counts
python scripts/dodo_live_cutover.py health-check
python scripts/dodo_live_cutover.py pilot-override status
curl -i https://api.configtrace.org/health
curl -i -X POST https://api.configtrace.org/dodo/webhook -H "Content-Type: application/json" -d '{"type":"ping"}'
```

**Most important dashboard paths:**
- Render → `configtrace-api` → Environment (all `DODO_*`/`BILLING_PROVIDER` variables)
- Render → `configtrace-api` → Logs (webhook processing, crashes)
- Render → `configtrace-api` → Shell (`psql "$DATABASE_URL"` for section 14)
- Dodo Dashboard → Products (catalog)
- Dodo Dashboard → Developers → API Keys
- Dodo Dashboard → Developers → Webhooks (delivery log)
- Vercel → ConfigTrace project → Deployments

**Emergency rollback (single fastest action):**
```
Render → configtrace-api → Environment → BILLING_PROVIDER=stripe → Save → redeploy
```
This alone stops all new Dodo checkouts immediately, with zero code change and zero effect on any existing Stripe, Paddle, or Dodo subscription.

**When billing breaks, check in this order:**
1. `curl -i https://api.configtrace.org/health` — is the API even up?
2. `env-check` — are the variables you expect actually set?
3. `readiness` — internally consistent?
4. `webhook-events --status failed` — is a webhook silently failing?
5. Render Logs — the actual exception, if any of the above didn't explain it.
6. Dodo dashboard's own status/incident page — is Dodo itself degraded?
