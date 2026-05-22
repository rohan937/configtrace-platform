# ConfigTrace — Production Deployment Guide

This document describes how to deploy ConfigTrace to production at
`app.configtrace.org` (frontend) and `api.configtrace.org` (backend).

---

## render.yaml — Render infrastructure-as-code

`render.yaml` in the repo root declares the two Render services that make up
the backend:

| Service | Type | `dockerCommand` |
|---|---|---|
| `configtrace-api` | Web service | `uvicorn app.main:app --host 0.0.0.0 --port $PORT` |
| `configtrace-worker` | Background worker | `celery -A app.workers.celery_app worker --loglevel=info` |

Both services use the same `backend/Dockerfile`.  The API service overrides the
Dockerfile `CMD` via `dockerCommand` so Render's router can inject `$PORT` at
runtime (the Dockerfile hardcodes `8000` for local Docker use).

> **Note:** `dockerCommand` is the correct Blueprint field for Docker runtime
> services.  `startCommand` is only valid for native runtimes (Node, Python,
> etc.) and will cause a Blueprint validation error if used with
> `runtime: docker`.

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
| `configtrace.org` | Marketing site | Vercel / static |
| `www.configtrace.org` | Marketing site (redirect) | Vercel / static |
| `app.configtrace.org` | Next.js frontend app | Vercel |
| `api.configtrace.org` | FastAPI backend | Render / Railway / Fly.io |

DNS and SSL are managed through Cloudflare (appropriate for a DNS-monitoring product).

---

## Recommended infrastructure

| Component | Recommended provider |
|---|---|
| Frontend | Vercel |
| Backend API | Render, Railway, or Fly.io |
| PostgreSQL | Neon, Supabase, or Render Postgres |
| Redis | Upstash or Render Redis |
| DNS + SSL | Cloudflare |

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
| `CLERK_SECRET_KEY` | Clerk backend secret key (`sk_live_...`) |
| `BACKEND_CORS_ORIGINS` | `https://app.configtrace.org,https://configtrace.org` |

### Frontend (set in Vercel project settings)

| Variable | Description |
|---|---|
| `NEXT_PUBLIC_API_BASE_URL` | `https://api.configtrace.org` |
| `NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY` | Clerk frontend public key (`pk_live_...`) |

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

### 4. Deploy the backend

Set all required backend environment variables in your hosting platform's
dashboard, then deploy from the `/backend` directory.

The Dockerfile runs without `--reload` by default (production-safe):

```
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

If your platform uses a Procfile or start command, use the same command.

### 5. Run database migrations

**Run migrations before serving any production traffic.**

```bash
# On Render/Railway — run as a one-off job or pre-deploy command:
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

- Set `NEXT_PUBLIC_API_BASE_URL=https://api.configtrace.org`
- Set `NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=pk_live_...`
- Set the root directory to `frontend/`
- Framework preset: Next.js

Vercel automatically runs `npm run build` and serves `npm run start`.

### 8. Add DNS records

In Cloudflare, add CNAME records pointing to your hosting platforms:

```
app.configtrace.org  →  CNAME  →  cname.vercel-dns.com
api.configtrace.org  →  CNAME  →  your-service.onrender.com  (or equivalent)
```

Enable Cloudflare proxying (orange cloud) for both.

### 9. Verify CORS

Open `https://app.configtrace.org` in a browser. Open DevTools → Network.
Confirm API calls to `https://api.configtrace.org` succeed (no CORS errors).

If CORS errors appear, check that `BACKEND_CORS_ORIGINS` on the backend
exactly matches the frontend origin (no trailing slash, correct scheme).

### 10. Connect Cloudflare integration and run first sync

1. Open `https://app.configtrace.org/integrations`
2. Connect your Cloudflare zone
3. Click **Sync Now** → verify a baseline snapshot is created
4. Open `https://app.configtrace.org/dashboard`

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

On Render, this is a separate "Background Worker" service pointing to the
same Docker image with a different start command.

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
