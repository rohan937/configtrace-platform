# ConfigTrace — Production Deployment Guide

This document describes how to deploy ConfigTrace to production at
`app.configtrace.org` (frontend) and `api.configtrace.org` (backend).

---

## Current production status

**Production deployment is complete.**  All services are live and the core MVP
loop (connect integration → sync → detect changes → display in UI) has been
verified end-to-end in production.

| Service | URL / host | Status |
|---|---|---|
| Marketing / landing page | `https://configtrace.org` | ✅ Live (GitHub Pages) |
| Next.js frontend | `https://app.configtrace.org` | ✅ Live (Vercel) |
| FastAPI backend | `https://api.configtrace.org` | ✅ Live (Render Starter) |
| PostgreSQL | Neon | ✅ Connected |
| Redis / Celery broker | Render Key Value, Oregon | ✅ Running |
| DNS + SSL | Cloudflare | ✅ HTTPS on both subdomains |

**Production smoke test passed:**

- `GET https://api.configtrace.org` → `{"service":"ConfigTrace API","version":"0.1.0","status":"ok","environment":"production"}`
- `GET https://api.configtrace.org/health` → `{"status":"ok",...}`
- `GET https://api.configtrace.org/health/db` → `{"status":"ok","database":"connected",...}`
- `https://app.configtrace.org/dashboard` loads successfully
- Cloudflare integration created; first sync → "1 snapshot, 0 changes detected" (baseline)
- Second sync after adding test TXT record → 1 added low-risk TXT change detected in timeline

> **Auth state — multi-user (Milestone 21 shipped).**
> Production now enforces Clerk JWT verification on every protected route via
> the JWKS endpoint set in `CLERK_JWKS_URL`.  Missing or placeholder JWKS in
> production causes every route to return HTTP 503; missing/invalid tokens
> return 401.  See [Authentication setup (Milestone 21)](#authentication-setup-milestone-21).

---

## render.yaml — Render infrastructure-as-code

`render.yaml` in the repo root declares the three Render services that make
up the backend:

| Service | Type | Plan | `dockerCommand` |
|---|---|---|---|
| `configtrace-api` | Web service | Starter | `uvicorn app.main:app --host 0.0.0.0 --port $PORT` |
| `configtrace-worker` | Background worker | Starter | `celery -A app.workers.celery_app worker --loglevel=info` |
| `configtrace-beat` | Background worker | Starter | `celery -A app.workers.celery_app beat --loglevel=info` |

All three services use the same `backend/Dockerfile`.  The API service
overrides the Dockerfile `CMD` via `dockerCommand` so Render's router can
inject `$PORT` at runtime (the Dockerfile hardcodes `8000` for local Docker
use).  The worker and beat services use the same image but run different
Celery roles.

> **`configtrace-beat` was added in Milestone 23.**  It fires the
> `enqueue_scheduled_syncs` task at minute 0 of every hour.  Beat does not
> execute sync work itself — it sends a Redis message that the worker
> picks up.  See the "Scheduled Syncs (Milestone 23)" section of the
> README for the full pipeline.

> **Note:** `dockerCommand` is the correct Blueprint field for Docker runtime
> services.  `startCommand` is only valid for native runtimes (Node, Python,
> etc.) and will cause a Blueprint validation error if used with
> `runtime: docker`.

### Service plan and cost

All three services run on the **Render Starter** plan (`plan: starter`).

| Service | Plan | Cost |
|---|---|---|
| `configtrace-api` | Starter | ~$7 / month |
| `configtrace-worker` | Starter | ~$7 / month |
| `configtrace-beat` | Starter | ~$7 / month |
| **Total** | | **~$21 / month** |

`configtrace-beat` is a separate Background Worker (rather than running
`--beat` inside `configtrace-worker`) so beat's failure domain is isolated
from the worker's. If the worker container is recycled by Render mid-sync,
the schedule keeps ticking. If beat crashes, in-flight syncs still complete.

Starter is used instead of Free for the production MVP because:

- **No cold starts** — Free-tier web services sleep after inactivity; Starter
  instances stay warm so the API responds immediately.
- **Reliable worker** — Free-tier background workers can be suspended; on
  Starter the Celery worker runs continuously so every sync task completes.
- **`preDeployCommand` support** — Render only runs `preDeployCommand` on paid
  plans (Starter and above). This is what triggers `alembic upgrade head`
  automatically before each deploy, eliminating the need for manual migration
  steps.
- **Better demo experience** — a production MVP should respond without a
  multi-second wake-up delay on the first request.

### How Render picks up render.yaml

1. Connect your GitHub repository to Render (Dashboard → New → Blueprint).
2. Render detects `render.yaml` at the repo root and creates both services
   automatically.
3. On the first deploy, Render prompts for every `sync: false` envVar — paste
   in the secret values from your secrets manager.
4. Subsequent `git push` triggers a redeploy of both services.

### Pre-deploy migrations

`render.yaml` sets `preDeployCommand: alembic upgrade head` on the API
service.  Render runs this inside the container before routing traffic to the
new deploy.  It is safe to run on every deploy — Alembic skips already-applied
migrations.

### Secrets

`render.yaml` never contains secret values.  All sensitive variables
(`DATABASE_URL`, `REDIS_URL`, `SECRET_KEY`, `ENCRYPTION_KEY`,
`CLERK_SECRET_KEY`) are declared with `sync: false`.  Set them in the Render
dashboard (service → Environment) or via the Render CLI:

```bash
render env set DATABASE_URL="postgresql://..." --service configtrace-api
```

Only non-secret values (`ENVIRONMENT=production`,
`BACKEND_CORS_ORIGINS=https://app.configtrace.org,...`) are committed in
`render.yaml`.

### Redis and PostgreSQL

Redis and PostgreSQL are **not** declared in `render.yaml` — they are
provisioned separately (Upstash / Neon / Render Postgres) and their connection
strings are pasted into the environment variables above.  This avoids Render
creating a second redundant database on every Blueprint re-sync.

---

## Domain layout

| Subdomain | Purpose | Hosted on |
|---|---|---|
| `configtrace.org` | Marketing / landing page | GitHub Pages (separate static repo) |
| `www.configtrace.org` | Marketing / landing page | GitHub Pages (redirect) |
| `app.configtrace.org` | Next.js frontend app | Vercel |
| `api.configtrace.org` | FastAPI backend | Render |

DNS and SSL are managed through Cloudflare (appropriate for a DNS-monitoring product).

> **Note:** `configtrace.org` / `www.configtrace.org` are hosted in a separate
> GitHub repository from the platform repo (`rohan937/configtrace-platform`).
> Do not confuse the two repos.

---

## Recommended infrastructure

| Component | Recommended provider | Currently in use |
|---|---|---|
| Frontend | Vercel | ✅ Vercel |
| Backend API | Render, Railway, or Fly.io | ✅ Render (Docker, Starter plan) |
| PostgreSQL | Neon, Supabase, or Render Postgres | ✅ Neon |
| Redis | Upstash or Render Key Value | ✅ Render Key Value (same region as API — see note below) |
| DNS + SSL | Cloudflare | ✅ Cloudflare |

---

## Cloudflare SSL settings

For `api.configtrace.org` and `app.configtrace.org`:

- **SSL/TLS mode:** Full (strict)
- **Always Use HTTPS:** On
- **Automatic HTTPS Rewrites:** On
- **HTTP/2:** On (default)

Do not commit Origin Certificate private keys to the repository.
Do not paste certificate private keys into frontend environment variables.

---

## Required environment variables

### Backend (set in hosting platform)

| Variable | Description |
|---|---|
| `ENVIRONMENT` | Must be `production` |
| `DATABASE_URL` | PostgreSQL connection string |
| `REDIS_URL` | Redis connection string |
| `SECRET_KEY` | 64-char hex random string (`openssl rand -hex 32`) |
| `ENCRYPTION_KEY` | base64-encoded 32-byte AES-GCM key |
| `CLERK_JWKS_URL` | **Required after Milestone 21.**  JWKS endpoint Clerk publishes its RS256 public keys at.  Missing → HTTP 503 on every protected route. |
| `CLERK_SECRET_KEY` | Clerk backend secret key (`sk_live_...`). Reserved for the future Clerk management API — not used by JWT verification. |
| `BACKEND_CORS_ORIGINS` | `https://app.configtrace.org,https://configtrace.org` |

### Frontend (set in Vercel project settings)

| Variable | Description |
|---|---|
| `NEXT_PUBLIC_API_BASE_URL` | `https://api.configtrace.org` |
| `NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY` | **Required after Milestone 21.**  Clerk frontend publishable key (`pk_live_...`).  Missing → Clerk throws during initialization and the app fails to render. |

---

## Generating secrets

```bash
# SECRET_KEY
openssl rand -hex 32

# ENCRYPTION_KEY
python3 -c "import secrets, base64; print(base64.b64encode(secrets.token_bytes(32)).decode())"
```

Store these in a secrets manager (Doppler, Infisical, or your hosting platform's
built-in secrets store). Do not write them to any file in the repository.

---

## Deployment order

Follow this order on every first deployment and after infrastructure changes.

### 1. Push to private GitHub repository

```bash
git push origin main
```

Ensure the repository is private. Confirm `.env`, `*.db`, and credential
files are not tracked (`git ls-files | grep -E ".env$|.db$"`).

### 2. Provision hosted PostgreSQL

Create a database named `configtrace` (or your chosen name). Note the
connection string — it becomes `DATABASE_URL`.

### 3. Provision hosted Redis

Create a Redis instance. Note the connection string — it becomes `REDIS_URL`.

> **⚠️ Region must match the API and worker (Render Key Value only).**
> Render's internal Redis hostnames are only resolvable within the same private
> network.  If your `configtrace-api` and `configtrace-worker` services are in
> Oregon, your Render Key Value instance **must** also be in Oregon.
>
> A cross-region Redis instance causes `POST /syncs` to fail with:
> `kombu.exceptions.OperationalError: Error -2 connecting to red-xxxxx:6379. Name or service not known.`
>
> Render blocks external traffic to Key Value instances by default, so using the
> external URL as a workaround is not straightforward.  The reliable fix is
> same-region provisioning.  If you hit this error: delete the Redis instance,
> recreate it in the correct region, update `REDIS_URL` in both the API and
> worker environment settings, and redeploy both services.

### 4. Deploy the backend

Set all required backend environment variables in your hosting platform's
dashboard, then deploy from the `/backend` directory.

The Dockerfile runs without `--reload` by default (production-safe):

```
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

If your platform uses a Procfile or start command, use the same command.

### 5. Run database migrations

**If using the Render Blueprint (`render.yaml`)** — migrations run
automatically.  `preDeployCommand: alembic upgrade head` is set on the
`configtrace-api` service and executes inside the container before Render
routes traffic to each new deploy.  No manual step is required.

**If deploying manually** (Railway, Fly.io, or without the Blueprint):

```bash
# Run as a one-off job or pre-deploy command:
alembic upgrade head

# Via Docker:
docker run --env-file .env your-image alembic upgrade head
```

### 6. Verify health endpoints

```bash
curl https://api.configtrace.org/health
# → {"status":"ok","timestamp":"...","version":"0.1.0","environment":"production"}

curl https://api.configtrace.org/health/db
# → {"status":"ok","database":"connected","timestamp":"..."}
```

If `/health/db` returns 503, the DATABASE_URL is wrong or migrations have not run.

### 7. Deploy the frontend

In your Vercel project:

- Set **Framework Preset** → `Next.js` (this is required — do not leave it as "Other")
- Set **Root Directory** → `frontend/`
- Do **not** manually override the Output Directory — Next.js preset handles `.next/` automatically
- Set `NEXT_PUBLIC_API_BASE_URL=https://api.configtrace.org`
- Set `NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=pk_live_...` (**required** since
  Milestone 21 — the build will succeed without it but the app crashes on
  load because `<ClerkProvider>` throws during initialization)

Vercel automatically runs `npm run build` and serves `npm run start`.

> **Common error — "No Output Directory named public found":**  If Vercel shows
> this error after a successful build, the Framework Preset is wrong (e.g. set
> to "Other" instead of "Next.js").  Set the preset to Next.js and redeploy.
> Do not add a manual Output Directory override.

### 8. Add DNS records

In Cloudflare, add CNAME records pointing to your hosting platforms:

```
app.configtrace.org  →  CNAME  →  cname.vercel-dns.com
api.configtrace.org  →  CNAME  →  configtrace-api.onrender.com
```

**Cloudflare proxy settings:**

- `api.configtrace.org` — enable Cloudflare proxy (orange cloud).  Render
  provides a valid TLS certificate so Full (strict) SSL mode works.
- `app.configtrace.org` — Vercel may require this record to be **DNS only
  (grey cloud / proxy disabled)** during its domain verification step.  Once
  Vercel accepts the domain, you can re-enable the proxy if desired, but
  DNS-only works fine for production and avoids certificate conflicts.

> **Vercel domain verification warning:** Vercel may display a "DNS Change
> Recommended" notice even after the domain works correctly.  As long as
> `https://app.configtrace.org` loads the frontend, the warning can be
> disregarded.

### 9. Verify CORS

Open `https://app.configtrace.org` in a browser. Open DevTools → Network.
Confirm API calls to `https://api.configtrace.org` succeed (no CORS errors).

If CORS errors appear, check that `BACKEND_CORS_ORIGINS` on the backend
exactly matches the frontend origin (no trailing slash, correct scheme).

### 10. Connect Cloudflare integration and run first sync

1. Open `https://app.configtrace.org/integrations`
2. Connect your Cloudflare zone
3. Click **Sync Now** → verify a baseline snapshot is created
   - Expected result: "Sync complete — 1 snapshot, 0 changes detected."
   - This is the baseline.  Zero changes on a first sync is correct.
4. Open `https://app.configtrace.org/dashboard`
5. Make a safe, reversible DNS change in Cloudflare (e.g. add a TXT record)
6. Click **Sync Now** again → expect "1 snapshot, 1 change detected."
7. Open `https://app.configtrace.org/timeline` → change row appears with the
   correct type, record identifier, and risk level

---

## Deployment issues encountered

The following issues were encountered during the initial production deployment.
They are documented here so future deploys avoid repeating them.

### Issue 1 — Render Blueprint: `startCommand` rejected for Docker runtime

**Symptom:** Blueprint apply fails immediately with:

```
services[0] docker runtime must not have startCommand
services[1] docker runtime must not have startCommand
```

**Cause:** `startCommand` is only valid for Render's native runtimes (Node,
Python, etc.).  For `runtime: docker`, the command that overrides the
Dockerfile `CMD` must be specified as `dockerCommand`.

**Fix:** Replaced `startCommand` with `dockerCommand` in `render.yaml` for
both services.  The Blueprint now applies without error.

---

### Issue 2 — Vercel: "No Output Directory named public found"

**Symptom:** The Vercel build log shows a successful `npm run build`, but the
deploy step fails with:

```
No Output Directory named "public" found after the Build completed.
```

**Cause:** The Framework Preset was not set to `Next.js`.  Without it, Vercel
looked for a `public/` directory instead of Next.js's `.next/` output.

**Fix:** In Vercel project settings, set:
- **Framework Preset:** `Next.js`
- **Root Directory:** `frontend/`
- No manual Output Directory override

The deploy succeeded on the next attempt.

---

### Issue 3 — Render Redis region mismatch (POST /syncs → 500)

**Symptom:** Integration creation succeeds, but clicking Sync Now returns
Internal Server Error.  Render API logs show:

```
kombu.exceptions.OperationalError: Error -2 connecting to red-xxxxx:6379. Name or service not known.
```

**Cause:** The Render Key Value (Redis) instance was created in Ohio; the API
and worker services were deployed in Oregon.  Render's internal Redis hostnames
(`red-xxxxx.render.com`) only resolve within the same region's private network.
Using the external Redis URL was not viable because Render blocks external
traffic to Key Value instances by default.

**Fix:** Created a new Render Key Value instance (`configtrace-redis-prod`) in
the same region as `configtrace-api` and `configtrace-worker` (Oregon).
Updated `REDIS_URL` in both services' environment settings and redeployed.
Sync completed successfully after that.

---

## Production smoke test checklist

Run these checks after the initial deployment and after any infrastructure
change.

### API health

```bash
# Root — confirms the service is live and in production mode
curl https://api.configtrace.org
# → {"service":"ConfigTrace API","version":"0.1.0","status":"ok","environment":"production"}

# Liveness
curl https://api.configtrace.org/health
# → {"status":"ok","timestamp":"...","version":"0.1.0"}

# Database connectivity (503 means DATABASE_URL is wrong or migrations haven't run)
curl https://api.configtrace.org/health/db
# → {"status":"ok","database":"connected","timestamp":"..."}
```

### Frontend pages

- [ ] `https://app.configtrace.org/dashboard` — loads, no console errors
- [ ] `https://app.configtrace.org/integrations` — loads, no console errors
- [ ] `https://app.configtrace.org/timeline` — loads, no console errors
- [ ] `https://app.configtrace.org/resources` — loads, no console errors

### End-to-end sync test

- [ ] Create a Cloudflare integration from `https://app.configtrace.org/integrations`
- [ ] Click **Sync Now** → "Sync complete — 1 snapshot, 0 changes detected." (baseline)
- [ ] Add a safe Cloudflare DNS record (e.g., TXT `_test` with any content)
- [ ] Click **Sync Now** again → "1 snapshot, 1 change detected."
- [ ] `https://app.configtrace.org/timeline` — change row appears with correct risk level
- [ ] Click the change row → change detail page shows record info and risk explanation
- [ ] *(Optional)* Delete the test record and sync again — deletion appears as its own change

---

## Authentication setup (Milestone 21)

Production now enforces Clerk JWT verification.  Every protected route on
`api.configtrace.org` requires a valid `Authorization: Bearer <token>` header
issued by Clerk; missing or invalid tokens return HTTP 401.

### How the backend verifies tokens

`backend/app/core/auth.py`:

1. On startup the auth module reserves a process-local cache for Clerk's
   JWKS.  No network call yet.
2. On the first authenticated request it fetches `CLERK_JWKS_URL`
   (`.well-known/jwks.json`), caches the keys for 5 minutes, and verifies the
   incoming JWT's RS256 signature locally.
3. If a token's `kid` is not in the cache, the JWKS is force-refreshed once.
   This handles Clerk key rotation transparently.
4. If the JWKS endpoint is unreachable on cold start (no cached keys), every
   protected route returns **HTTP 503**.  Once a JWKS is cached, transient
   fetch failures fall back to the stale cache for up to 1 hour before 503.
5. Valid tokens are mapped to a local `User` row via the `sub` claim.  The
   user is created on first sign-in; existing users are looked up by
   `clerk_id`.

### Production fail-closed guarantee

If `ENVIRONMENT=production` but `CLERK_JWKS_URL` is missing or still a
placeholder, every protected route returns **HTTP 503** before any token
parsing.  The dev-mode branch is unreachable in production regardless of
other env vars or request headers.  There is no override.

### Configuring Clerk

1. In Clerk → API Keys, find your application's JWKS URL.  It looks like:
   ```
   https://<your-frontend-api>.clerk.accounts.dev/.well-known/jwks.json
   ```
   (For a production Clerk instance, the host is your custom Clerk frontend
   API domain rather than `clerk.accounts.dev`.)

2. Set the following env vars on **both** Render services
   (`configtrace-api` and `configtrace-worker`):
   - `CLERK_JWKS_URL` — the JWKS URL from step 1
   - `CLERK_SECRET_KEY` — your Clerk `sk_live_...` (reserved for future use)

3. Set the publishable key on Vercel:
   - `NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY` — your Clerk `pk_live_...`

4. In Clerk → Domains, add `app.configtrace.org` (and `configtrace.org` if
   you want sign-in to also work from the marketing domain).

### Local development requirements after M21

| Layer | Requirement |
|---|---|
| Backend (local) | **No Clerk needed.**  With `ENVIRONMENT=development` (default) and no `CLERK_JWKS_URL`, the backend keeps the existing dev-mode auth: auto-creates `dev@configtrace.local`, accepts `X-Dev-User-Email` for multi-user simulation. |
| Frontend (local) | **Clerk required.**  `@clerk/nextjs` throws during initialization if `NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY` is missing.  Create a free Clerk **development** application (~2 min at [dashboard.clerk.com](https://dashboard.clerk.com)) and copy the `pk_test_...` value into your local `.env`. |

To exercise the real JWT path locally (catches token-threading bugs), set
both the frontend publishable key AND the backend `CLERK_JWKS_URL` — the
backend then verifies tokens for real instead of falling back to dev mode.

### Failure modes — what to check first

| Symptom | Likely cause | Fix |
|---|---|---|
| Every API route returns 503 | `CLERK_JWKS_URL` missing or contains `replace-with` / `CHANGE_ME` | Set the real JWKS URL in Render env vars and redeploy. |
| Every API route returns 401 even when signed in | Frontend not sending `Authorization` header, or wrong Clerk instance | Verify `NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY` matches the backend's `CLERK_JWKS_URL` (same Clerk app). |
| Frontend crashes immediately on load | `NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY` not set in Vercel | Add it to the Vercel project's environment, redeploy. |
| Sign-in redirects loop | Clerk → Domains doesn't include `app.configtrace.org` | Add the production frontend origin to Clerk's allowed domains. |
| User signs in but sees no data | Pre-M21 data belongs to the old dev user | Re-create your Cloudflare integration in the authenticated session (no automatic reassignment). |

---

## Seed script warning

`backend/scripts/seed_dev_data.py` is **local development only**.

- It creates fake data in the database.
- It deletes existing seed rows on each run.
- It uses placeholder credentials that cannot decrypt real integrations.

The script checks `ENVIRONMENT` at startup and **refuses to run** if
`ENVIRONMENT=production` is set:

```
ERROR: seed_dev_data.py refused to run.

  ENVIRONMENT=production was detected.
  This script is for LOCAL DEVELOPMENT ONLY.
```

Never run this script against a production database.

---

## Celery worker in production

The Celery worker (`app.workers.celery_app`) processes sync tasks triggered
by the `/syncs` API endpoint. It must be running for syncs to complete.

Start it alongside the API (as a separate process/container):

```bash
celery -A app.workers.celery_app worker --loglevel=info
```

On Render, this is a separate "Background Worker" service (`configtrace-worker`)
pointing to the same Docker image with a different `dockerCommand`.

Celery Beat (scheduled syncs) is not active in the MVP — the `beat` container
in `docker-compose.yml` exists as a placeholder for a future milestone.

---

## Rolling back

To roll back the database migration:

```bash
alembic downgrade -1        # one step back
alembic downgrade base      # all the way back (drops all tables)
```

`downgrade base` is destructive — all data is lost. Only use it for a full
reset, never in a running production system.

---

## Local development after production prep

Local development is unchanged:

```bash
# Backend + infra
docker compose --profile celery up --build
docker compose exec api alembic upgrade head

# Frontend
cd frontend && npm run dev

# Seed data
docker compose exec api python scripts/seed_dev_data.py

# Health check
curl http://localhost:8000/health
```

The `.env` file (copied from `.env.example`) should have:
- `ENVIRONMENT=development` (or omit it — development is the default)
- `NEXT_PUBLIC_API_BASE_URL=http://localhost:8000`
- `BACKEND_CORS_ORIGINS=http://localhost:3000,http://localhost:3001`
- `NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=pk_test_...` (required since M21 —
  use a free Clerk dev application; the backend still runs in dev-mode auth
  unless you ALSO set `CLERK_JWKS_URL`)
