# ConfigTrace

Configuration change intelligence for production systems. ConfigTrace snapshots critical configuration across cloud providers and SaaS tools, detects changes between snapshots, classifies risk, and surfaces a timeline that engineers can use to diagnose production incidents.

## Quick start (Docker Compose)

```bash
cp .env.example .env   # only POSTGRES_DB/USER/PASSWORD are strictly required to start
docker compose up --build
```

| Service  | URL / address       |
|----------|---------------------|
| Frontend | http://localhost:3000 |
| API      | http://localhost:8000 |
| Postgres | localhost:5432        |
| Redis    | localhost:6379        |

The first build takes ~60 seconds (downloading base images, installing packages).
Subsequent starts reuse the build cache and are much faster.

**Run database migrations** (after `docker compose up --build`)
```bash
docker compose exec api alembic upgrade head
# INFO  [alembic.runtime.migration] Running upgrade  -> 001, Initial schema
```

**Verify each service**
```bash
# API liveness
curl http://localhost:8000/health
# → {"status":"ok","timestamp":"...","version":"0.1.0"}

# Database connectivity
curl http://localhost:8000/health/db
# → {"status":"ok","database":"connected","timestamp":"..."}

# Confirm all seven tables exist
docker compose exec db psql -U configtrace -d configtrace -c '\dt'
# users | integrations | resources | sync_runs | snapshots | changes | alerts

# Redis
docker compose exec redis redis-cli ping
# → PONG

# Frontend — open http://localhost:3000 in a browser
```

**Roll back the migration** (drops all tables)
```bash
docker compose exec api alembic downgrade base
```

**Stop without wiping data**
```bash
docker compose down        # keeps the postgres_data volume
```

**Full reset (wipes database)**
```bash
docker compose down -v     # removes the postgres_data named volume
```

**Start Celery worker + Beat (Milestone 3+)**
```bash
docker compose --profile celery up --build
```

## Environment variables

Copy `.env.example` to `.env`. For local Docker development, the defaults in `.env.example` work out of the box — only replace the `replace-with-*` values when you're ready to wire in Clerk auth and credential encryption.

| Variable | Required for Docker | Description |
|---|---|---|
| `POSTGRES_DB` | Yes | Database name |
| `POSTGRES_USER` | Yes | Database user |
| `POSTGRES_PASSWORD` | Yes | Database password |
| `DATABASE_URL` | Local dev only | Overridden by Docker Compose (uses `db` hostname) |
| `REDIS_URL` | Local dev only | Overridden by Docker Compose (uses `redis` hostname) |
| `SECRET_KEY` | Milestone 3+ | Random 64-char hex string |
| `CLERK_SECRET_KEY` | Milestone 3+ | Clerk dashboard secret key |
| `NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY` | Milestone 3+ | Clerk publishable key |
| `ENCRYPTION_KEY` | Milestone 7+ | Base64-encoded 32-byte AES-GCM key |
| `NEXT_PUBLIC_API_BASE_URL` | Yes | Browser-facing backend URL (default: http://localhost:8000) |

Generate secret values:
```bash
# SECRET_KEY
openssl rand -hex 32

# ENCRYPTION_KEY (32-byte base64)
python3 -c "import secrets, base64; print(base64.b64encode(secrets.token_bytes(32)).decode())"
```

## Local development without Docker

**Backend**
```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
# Set DATABASE_URL to postgresql://configtrace:configtrace@localhost:5432/configtrace
uvicorn app.main:app --reload --port 8000
```

**Frontend**
```bash
cd frontend
npm install
npm run dev          # http://localhost:3000
```

## Dev seed data (Milestone 12+)

To populate realistic sample data for frontend development without a real Cloudflare
account, run the dev seed script after starting the stack:

```bash
# Start the stack first (API + DB must be running)
docker compose up --build

# In a second terminal, run migrations if you haven't already
docker compose exec api alembic upgrade head

# Seed sample data for the dev user
docker compose exec api python scripts/seed_dev_data.py
```

The script creates:
- **1 Cloudflare integration** (`Production Cloudflare Zone [seed]`, status: active)
- **1 DNS zone resource** (`example.com`)
- **3 snapshots** spanning the last 3 days showing a realistic change history
- **5 changes** covering all four risk levels (critical, high ×2, medium, low)

The seed data belongs to the same dev user automatically returned by the API in
dev mode (`dev@configtrace.local`), so all read endpoints return it immediately:

```bash
# All changes (should return 5 rows)
curl http://localhost:8000/changes | python3 -m json.tool

# All resources (should return 1 row)
curl http://localhost:8000/resources | python3 -m json.tool

# Only critical changes
curl "http://localhost:8000/changes?risk_level=critical" | python3 -m json.tool

# Snapshots for the resource
RESOURCE_ID=$(curl -s http://localhost:8000/resources | python3 -m json.tool | grep '"id"' | head -1 | awk -F'"' '{print $4}')
curl "http://localhost:8000/resources/${RESOURCE_ID}/snapshots" | python3 -m json.tool
```

**Verify directly in the database:**
```bash
# All changes with risk levels (newest first)
docker compose exec db psql -U configtrace -d configtrace -c \
  "select change_type, record_identifier, field_path, risk_level from changes order by created_at desc;"

# All resources
docker compose exec db psql -U configtrace -d configtrace -c \
  "select display_name, provider_resource_type, last_snapshot_at from resources;"

# Snapshot count
docker compose exec db psql -U configtrace -d configtrace -c \
  "select count(*) as snapshots from snapshots;"
```

**Reset / re-seed** (the script is idempotent — safe to run multiple times):
```bash
docker compose exec api python scripts/seed_dev_data.py
```

Each run deletes the previous seed data and recreates it cleanly.  No duplicate
rows accumulate.

## Project layout

```
/
├── backend/                  FastAPI application
│   ├── app/
│   │   ├── main.py           FastAPI entry point
│   │   ├── config.py         Settings via pydantic-settings
│   │   ├── routers/          Route handlers (one module per resource group)
│   │   ├── services/         Business logic (snapshot, diff, risk, encryption)
│   │   ├── connectors/       Provider connectors (Cloudflare, future: Stripe, GitHub)
│   │   ├── models/           SQLAlchemy ORM models
│   │   ├── schemas/          Pydantic request/response schemas
│   │   ├── workers/          Celery tasks
│   │   └── middleware/       Auth and request middleware
│   ├── scripts/              Dev-only tooling (seed_dev_data.py)
│   ├── alembic/              Database migrations (added in Milestone 5)
│   ├── requirements.txt
│   └── Dockerfile
│
├── frontend/                 Next.js + TypeScript + Tailwind CSS
│   ├── src/
│   │   ├── app/              Next.js App Router pages
│   │   ├── components/       Shared UI components
│   │   └── lib/              API client and type definitions
│   └── Dockerfile
│
├── docs/                     Planning and design documents
│   ├── Vision.txt
│   ├── Architecture.txt
│   ├── Roadmap.txt
│   ├── ProductSpec.txt
│   ├── DatabaseSchema.txt
│   ├── UIDesignSystem.txt
│   └── MVPBuildPlan.txt
│
├── docker-compose.yml        Full local environment (added in Milestone 2)
├── render.yaml               Render infrastructure-as-code (API + Celery worker)
├── .env.example              All required environment variables, documented
├── .env.production.example   Production-specific template (fill in, never commit)
└── .gitignore
```

## Environment variables

Copy `.env.example` to `.env` and fill in every value before running. See `.env.example` for descriptions of each variable. Never commit `.env`.

| Variable | Required | Description |
|---|---|---|
| `DATABASE_URL` | Yes | PostgreSQL connection string |
| `REDIS_URL` | Yes | Redis connection string (Celery broker) |
| `SECRET_KEY` | Yes | Random 64-char hex string |
| `CLERK_SECRET_KEY` | Yes | Clerk dashboard secret key |
| `NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY` | Yes | Clerk publishable key (frontend) |
| `ENCRYPTION_KEY` | Yes | Base64-encoded 32-byte AES-GCM key |
| `NEXT_PUBLIC_API_BASE_URL` | Yes | Backend URL seen by the browser |
| `POSTGRES_DB/USER/PASSWORD` | Yes | PostgreSQL service credentials (Docker) |

## Planning documents

All product planning documents live in [`docs/`](docs/):

- [`Vision.txt`](docs/Vision.txt) — Product vision and mission
- [`Architecture.txt`](docs/Architecture.txt) — System architecture and component design
- [`Roadmap.txt`](docs/Roadmap.txt) — Eight-phase development roadmap
- [`ProductSpec.txt`](docs/ProductSpec.txt) — MVP feature specification and user stories
- [`DatabaseSchema.txt`](docs/DatabaseSchema.txt) — Full PostgreSQL schema with field notes
- [`UIDesignSystem.txt`](docs/UIDesignSystem.txt) — Design system: colors, typography, interaction
- [`MVPBuildPlan.txt`](docs/MVPBuildPlan.txt) — Milestone-by-milestone build plan (18 milestones)

## Cloudflare connector

The Cloudflare DNS connector (`backend/app/connectors/cloudflare.py`) is a
self-contained, database-independent module that fetches all DNS records for a
zone and returns them as normalised dicts.

**Quick test against a live zone**
```bash
export CLOUDFLARE_API_TOKEN=your_token_here
export CLOUDFLARE_ZONE_ID=your_zone_id_here

# Validate credentials only (no full fetch):
VALIDATE_ONLY=1 python scripts/test_connector.py

# Fetch all records and print a summary:
python scripts/test_connector.py

# Print every record:
VERBOSE=1 python scripts/test_connector.py
```

**Run the unit tests**
```bash
# Inside Docker (recommended — matches the production Python environment):
docker compose run --rm api pytest backend/tests/ -v

# Locally (requires dev dependencies):
cd backend
pip install -r requirements.txt -r requirements-dev.txt
pytest tests/ -v
```

**Connector architecture**

```
credentials dict
    │
    ▼
CloudflareConnector.fetch()
    │  ├─ paginates GET /zones/{zone_id}/dns_records
    │  ├─ retries on 429 (max 3, honours Retry-After header)
    │  └─ raises AuthenticationError / ConnectorError / RateLimitError / NetworkError
    │
    ▼
list[CloudflareDNSRecord]   ← stored verbatim in Snapshot.state (JSONB)
```

Each `CloudflareDNSRecord` dict contains: `record_id`, `record_type`, `name`,
`content`, `ttl`, `proxied`, `priority`, `comment`, `modified_on`.

## Integration and sync API (Milestone 7)

**Dev mode** — Clerk auth is not required yet.  All endpoints automatically
create a dev user on first request (using `dev@configtrace.local`).

### Create a Cloudflare integration

```bash
# The API validates the token against Cloudflare before saving anything.
curl -s -X POST http://localhost:8000/integrations \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "cloudflare",
    "display_name": "My Production Zone",
    "api_token": "<your_cf_api_token>",
    "zone_id": "<your_cf_zone_id>"
  }' | jq .
# → {"id": "...", "provider": "cloudflare", "display_name": "My Production Zone",
#    "status": "active", "last_synced_at": null, "created_at": "..."}
# Credentials are never returned.
```

### List integrations

```bash
curl -s http://localhost:8000/integrations | jq .
# → {"integrations": [...], "total": 1}
```

### Trigger a manual sync

```bash
INTEGRATION_ID="<uuid from POST /integrations>"

curl -s -X POST http://localhost:8000/syncs \
  -H "Content-Type: application/json" \
  -d "{\"integration_id\": \"${INTEGRATION_ID}\"}" | jq .
# → {"id": "...", "status": "pending", "triggered_by": "manual", ...}
```

### Poll sync status

```bash
SYNC_RUN_ID="<id from POST /syncs>"

curl -s http://localhost:8000/syncs/${SYNC_RUN_ID} | jq .
# Poll until "status" is "completed" or "failed"
# → {"id": "...", "status": "completed", "snapshot_count": 0, "change_count": 0, ...}
```

> **Note:** `snapshot_count` and `change_count` are `0` in Milestone 7 — the
> Celery task is a placeholder.  Milestone 8 (snapshot service) wires in real
> connector calls.

### Start the Celery worker

The Celery worker is required for sync tasks to execute.  It is not started
by `docker compose up` by default.

```bash
# Start worker alongside the other services:
docker compose --profile celery up --build

# Or, in a second terminal against a running stack:
docker compose run --rm worker
```

### Run the test suite

```bash
docker compose run --rm api pytest tests/ -v
```

## Snapshot service (Milestone 8)

After a sync completes, snapshots are stored in the `snapshots` table and can
be inspected directly via `psql`:

```bash
# Connect to the running Postgres container
docker compose exec db psql -U configtrace -d configtrace

# List all snapshots (most-recent first)
SELECT id, resource_id, content_hash, triggered_by, created_at
FROM snapshots
ORDER BY created_at DESC;

# Inspect the full DNS state of the latest snapshot
SELECT state
FROM snapshots
ORDER BY created_at DESC
LIMIT 1;
```

**Deduplication** — if the Cloudflare DNS state has not changed since the last
sync, no new Snapshot row is written.  The SyncRun still completes with
`"status": "completed"` but `snapshot_count` will be `0`.

**Hash algorithm** — SHA-256 of a canonical JSON serialisation of all DNS
records sorted by `record_id`.  Records are order-invariant: fetching them in
any sequence from the Cloudflare API produces the same hash.

**Run the Milestone 8 tests**

```bash
docker compose run --rm api pytest tests/test_milestone8.py -v
```

## Diff service (Milestone 9)

After a sync stores a new snapshot, the diff service compares it against the
previous snapshot for the same resource and writes one `Change` row per
detected difference.

**Change types**

| `change_type` | Meaning | `field_path` | `prev_value` | `new_value` |
|---|---|---|---|---|
| `added` | DNS record appeared | `null` | `null` | full record dict |
| `removed` | DNS record disappeared | `null` | full record dict | `null` |
| `modified` | A tracked field changed | field name | old value | new value |

**Tracked DNS fields** — the diff compares these seven fields per record:
`record_type`, `name`, `content`, `ttl`, `proxied`, `priority`, `comment`.

**Ignored fields** — `modified_on`, `created_on`, `created_at`, `updated_at`
are explicitly excluded.  These are provider-managed timestamps that change on
every API response regardless of whether the configuration actually changed.
Including them would create false-positive change records on every sync.

**Deduplication interaction** — the diff service only runs when `store_snapshot`
writes a new row.  If the snapshot hash matches (no change), the diff is
skipped entirely.

**Baseline sync** — the first sync for a resource creates a snapshot with no
previous to compare against.  `change_count = 0`.  Subsequent syncs detect
changes relative to this baseline.

**Risk levels** — all `Change` rows are written by the diff service with
`risk_level = "unknown"`. The risk classification service (Milestone 10)
immediately updates these to `low` / `medium` / `high` / `critical` within
the same sync pipeline.

**Inspect Change rows**

```bash
# Start the stack with the Celery worker (required for syncs to run)
docker compose --profile celery up --build

# After triggering a sync, inspect detected changes
docker compose exec db psql -U configtrace -d configtrace -c \
  "SELECT id, change_type, record_identifier, field_path,
          prev_value, new_value, risk_level, created_at
   FROM changes
   ORDER BY created_at DESC;"

# Count changes per type
docker compose exec db psql -U configtrace -d configtrace -c \
  "SELECT change_type, count(*) FROM changes GROUP BY change_type;"
```

**Run the Milestone 9 tests**

```bash
docker compose run --rm api sh -lc "pip install -r requirements-dev.txt && pytest tests/ -v"
```

## Risk classification service (Milestone 10)

After the diff service writes `Change` rows, the risk service immediately
classifies each one with a `risk_level` and `risk_reason`.  Classification
runs synchronously inside the Celery sync task — no additional worker needed.

**Risk levels**

| Level | Meaning |
|---|---|
| `critical` | Can take services completely offline |
| `high` | Likely to disrupt traffic or degrade service |
| `medium` | Alters behaviour but generally reversible |
| `low` | Cosmetic or low-impact changes |

**Cloudflare DNS rules**

| Rule | Level |
|---|---|
| Apex A / AAAA / CNAME record deleted | `critical` |
| Any MX record deleted | `critical` |
| NS or SOA record modified | `critical` |
| Any other record deleted | `high` |
| CNAME or MX target (`content`) changed | `high` |
| MX `priority` changed | `high` |
| Cloudflare proxy disabled (True→False) | `high` |
| TTL reduced to ≤ 60 seconds | `high` |
| Cloudflare proxy enabled (False→True) | `medium` |
| TTL changed (above 60 s threshold) | `medium` |
| TXT record `content` changed | `medium` |
| Subdomain A / AAAA record added | `medium` |
| `comment` field changed | `low` |
| All other changes | `low` |

**Apex detection** — a record is considered apex when its name has ≤ 2
dot-separated labels (e.g. `example.com`).  If `zone_name` is present in
`provider_metadata`, an exact string match is used instead (more accurate for
multi-part TLDs such as `.co.uk`).

**Inspect risk levels after a sync**

```bash
docker compose exec db psql -U configtrace -d configtrace -c \
  "SELECT change_type, risk_level, record_identifier, risk_reason
   FROM changes
   ORDER BY created_at DESC;"

# Breakdown by risk level
docker compose exec db psql -U configtrace -d configtrace -c \
  "SELECT risk_level, count(*) FROM changes GROUP BY risk_level ORDER BY risk_level;"
```

**Run the Milestone 10 tests**

```bash
docker compose run --rm api sh -lc "pip install -r requirements-dev.txt && pytest tests/test_milestone10.py -v"
```

## Changes API and Resources API (Milestone 11)

Milestone 11 exposes the read APIs that the frontend dashboard will use to
fetch the change timeline, change detail view, resource list, resource
snapshots, and resource-specific change history.  All routes are read-only,
paginated, and scoped to the authenticated user.  Frontend implementation
begins in Milestone 12.

### Endpoint overview

| Method | Path | Description |
|---|---|---|
| `GET` | `/changes` | Paginated change timeline with optional filters |
| `GET` | `/changes/{change_id}` | Single change with full snapshot context |
| `GET` | `/resources` | Paginated list of monitored resources |
| `GET` | `/resources/{resource_id}` | Resource detail with snapshot/change counts |
| `GET` | `/resources/{resource_id}/snapshots` | Paginated snapshot history |
| `GET` | `/resources/{resource_id}/changes` | Paginated change history for a resource |

### Query parameters

**`GET /changes`**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `integration_id` | UUID | — | Filter to one integration |
| `resource_id` | UUID | — | Filter to one resource |
| `risk_level` | string | — | `low`, `medium`, `high`, or `critical` |
| `change_type` | string | — | `added`, `removed`, or `modified` |
| `since` | ISO 8601 datetime | — | Changes at or after this time |
| `until` | ISO 8601 datetime | — | Changes at or before this time |
| `page` | int | `1` | 1-based page number |
| `page_size` | int | `50` | Results per page (max 100) |

**`GET /resources`**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `integration_id` | UUID | — | Filter to one integration |
| `page` | int | `1` | 1-based page number |
| `page_size` | int | `50` | Results per page (max 100) |

**`GET /resources/{resource_id}/snapshots`** — `page`, `page_size` (default 20)

**`GET /resources/{resource_id}/changes`** — `page`, `page_size` (default 50)

### Example curl commands

```bash
# All changes, newest first
curl -s http://localhost:8000/changes | jq .

# Only critical changes
curl -s "http://localhost:8000/changes?risk_level=critical" | jq .

# Changes in the last day using ISO 8601 timestamps
curl -s "http://localhost:8000/changes?since=2026-05-20T00:00:00Z" | jq .

# Change detail with full snapshot states
CHANGE_ID="<uuid from GET /changes>"
curl -s "http://localhost:8000/changes/${CHANGE_ID}" | jq .

# All resources
curl -s http://localhost:8000/resources | jq .

# Resource detail with counts
RESOURCE_ID="<uuid from GET /resources>"
curl -s "http://localhost:8000/resources/${RESOURCE_ID}" | jq .

# Snapshot history for a resource (includes full DNS state per snapshot)
curl -s "http://localhost:8000/resources/${RESOURCE_ID}/snapshots" | jq .

# Change history for a resource
curl -s "http://localhost:8000/resources/${RESOURCE_ID}/changes" | jq .
```

### Pagination

All list endpoints return:
```json
{
  "items": [...],
  "total": 42,
  "page": 1,
  "page_size": 50
}
```

`total` is the count of matching rows before pagination so the frontend can
render "Showing 50 of 142 changes."  Page size is clamped to 100 server-side
regardless of what the caller requests.

### Filtering (`GET /changes`)

All filters are optional and combined with AND.  The `risk_level` and
`change_type` filters match exact strings.  `since` / `until` accept
timezone-aware ISO 8601 datetimes and filter on `created_at`.

### User scoping

Every query is filtered by the authenticated user's `user_id`.  A missing
record and a record belonging to another user both return `404` — callers
cannot determine whether an object exists for a different user.

### Change detail snapshot states

`GET /changes/{change_id}` returns the full snapshot states:
```json
{
  "id": "...",
  "change_type": "modified",
  "field_path": "content",
  "prev_value": "1.2.3.4",
  "new_value": "5.6.7.8",
  "risk_level": "low",
  "risk_reason": "...",
  "prev_snapshot_id": "...",
  "new_snapshot_id": "...",
  "prev_snapshot_state": [{ "record_id": "...", "content": "1.2.3.4", ... }],
  "new_snapshot_state":  [{ "record_id": "...", "content": "5.6.7.8", ... }],
  "prev_snapshot_created_at": "2026-05-21T10:00:00Z",
  "new_snapshot_created_at": "2026-05-21T11:00:00Z"
}
```

This powers the change detail page without a second request to the snapshots
endpoint.

### Inspect data with psql

```bash
# All changes with risk levels
docker compose exec db psql -U configtrace -d configtrace -c \
  "SELECT change_type, risk_level, record_identifier, created_at
   FROM changes ORDER BY created_at DESC LIMIT 20;"

# Count changes by risk level
docker compose exec db psql -U configtrace -d configtrace -c \
  "SELECT risk_level, count(*) FROM changes GROUP BY risk_level;"

# All resources
docker compose exec db psql -U configtrace -d configtrace -c \
  "SELECT id, display_name, provider_resource_type, last_snapshot_at FROM resources;"
```

**Run the Milestone 11 tests**

```bash
docker compose run --rm api sh -lc "pip install -r requirements-dev.txt && pytest tests/test_milestone11.py -v"
```

**Run the full test suite**

```bash
docker compose run --rm api sh -lc "pip install -r requirements-dev.txt && pytest tests/ -v"
```

## Frontend shell (Milestone 12)

Milestone 12 creates the Next.js application shell — routing, layout, API
client infrastructure, TypeScript types, and placeholder pages.  No real data
is fetched yet; the dashboard and timeline pages render empty states until
Milestone 13 wires up API calls.

### Route structure

| Route | Page |
|---|---|
| `/` | Redirects to `/dashboard` |
| `/dashboard` | Dashboard overview (placeholder) |
| `/timeline` | Change timeline (placeholder) |
| `/integrations` | Integration management (placeholder) |
| `/resources` | Resource list (placeholder) |
| `/settings` | Settings (placeholder) |

### Layout

All pages are wrapped in `AppShell` (sidebar + main content area).  The
sidebar is 240 px wide with a `#13151a` background and a `#2a2d38` right
border.  The active nav link is highlighted with a 2 px left border in
`#4f80f7` (accent blue).

### Key files

| File | Purpose |
|---|---|
| `src/types/index.ts` | TypeScript types: `PaginatedResponse<T>`, `ChangeListItem`, `ChangeDetail`, `ResourceListItem`, `ResourceDetail`, `SnapshotListItem`, `Integration`, `SyncRun` |
| `src/lib/api.ts` | Typed API client — `getChanges`, `getChange`, `getResources`, `getResource`, `getResourceSnapshots`, `getResourceChanges`, `getIntegrations`, `triggerSync`, `getSyncStatus` |
| `src/components/layout/Sidebar.tsx` | Left navigation (client component, uses `usePathname`) |
| `src/components/layout/AppShell.tsx` | Root layout wrapper — Sidebar + `<main>` |
| `src/components/common/PageHeader.tsx` | Section title + description |
| `src/components/common/EmptyState.tsx` | Empty list / placeholder panel |
| `src/components/common/RiskBadge.tsx` | Coloured badge for `critical` / `high` / `medium` / `low` / `unknown` / `healthy` |
| `src/components/common/StatusBadge.tsx` | Coloured badge for `active` / `error` / `paused` / `unknown` |

### Start the dev server

```bash
cd frontend
npm install
npm run dev      # http://localhost:3000  →  redirects to /dashboard
```

### Build

```bash
cd frontend
npm run build
```

All 7 routes (`/`, `/_not-found`, `/dashboard`, `/timeline`, `/integrations`,
`/resources`, `/settings`) generate as static pages with no API calls on load.

## Frontend data rendering (Milestone 13)

Milestone 13 replaces all placeholder pages with real data fetched from the
backend API.  Every data-fetching page is a client component that loads its
data in a `useEffect` hook and shows a `LoadingState` while the request is
in flight, an `ErrorState` on failure, or the real content on success.

### Pages updated

| Route | Data fetched | Behaviour |
|---|---|---|
| `/dashboard` | `GET /changes?page_size=10`, `GET /resources?page_size=100` | Summary bar with 4 stats + recent change list |
| `/timeline` | `GET /changes` (paginated, 50/page) | Full change history with prev/next pagination |
| `/resources` | `GET /resources` | Table of all monitored resources |
| `/integrations` | `GET /integrations` | List with per-row **Sync Now** button |

### New components

| File | Purpose |
|---|---|
| `src/lib/utils.ts` | `formatRelativeTime`, `formatDate`, `formatDateTime`, `formatValue`, `formatValueChange`, `changeTypeLabel` |
| `src/components/common/LoadingState.tsx` | Centered "Loading…" text |
| `src/components/common/ErrorState.tsx` | Centered error message in red |
| `src/components/common/StatBlock.tsx` | Large number + small label for summary bar |
| `src/components/changes/ChangeRow.tsx` | Single change row: timestamp · record · type · field · risk badge |
| `src/components/changes/ChangeList.tsx` | Bordered table of change rows with column header |
| `src/components/resources/ResourceList.tsx` | Table of resources: name · type · last snapshot · status |
| `src/components/integrations/IntegrationList.tsx` | Table with per-row **Sync Now** button and inline feedback |

### Type corrections

The following mismatches between frontend types and actual backend schemas were
fixed in `src/types/index.ts`:

| Type | Fix |
|---|---|
| `Integration` | Removed `user_id` and `updated_at` (not returned by backend) |
| `IntegrationListResponse` | Added — backend returns `{ integrations: [...], total: N }`, not paginated `items` |
| `SyncRun.finished_at` → `completed_at` | Renamed to match `SyncRunResponse` |
| `SyncRun.status` | Changed `"success"` → `"completed"` to match backend |
| `SyncRun` | Added `user_id`, `triggered_by`, `change_count`, `snapshot_count` |

### Build

```bash
cd frontend
npm run build
# ✓ Compiled successfully — 7 routes, 0 TypeScript errors
```

## Cloudflare Integration Setup (Milestone 14)

Milestone 14 makes the Integrations page fully operational: connect a
Cloudflare account from the UI, trigger manual syncs, and watch live sync
status without leaving the page.

### What it adds

- **Integration creation form** — inline Cloudflare connection form with Display
  Name, API Token (masked), and Zone ID fields.  Credentials are validated
  against the live Cloudflare API server-side before anything is saved.
- **Sync Now with polling** — clicking Sync Now triggers a Celery task and polls
  `GET /syncs/{id}` every 2 seconds until the run reaches a terminal state
  (`completed` or `failed`), then shows snapshot and change counts inline.
- **List refresh** — the integrations list refreshes automatically after a
  successful connection or after any sync completes.
- **Credential hygiene** — the API token is sent to the backend once over HTTPS,
  cleared from React state on success, never logged, never stored in
  localStorage or sessionStorage, and never returned by any API response.

### How to connect a Cloudflare integration from the UI

1. Start the full stack with the Celery worker:

```bash
docker compose --profile celery up --build
docker compose exec api alembic upgrade head
```

2. Open http://localhost:3000/integrations

3. Click **Add New Integration**. Fill in:

   | Field | Value |
   |---|---|
   | Display Name | Any label, e.g. `Production Zone` |
   | Cloudflare API Token | A restricted token with **Zone.DNS:Read** permission |
   | Zone ID | The 32-character hex Zone ID from the Cloudflare dashboard |

4. Click **Connect Cloudflare**.  The backend validates the token against the
   Cloudflare API.  Invalid tokens are rejected with a clear error; valid
   credentials are encrypted (AES-256-GCM) and stored.  The token is never
   returned in any response.

5. After the integration appears in the list, click **Sync Now**. The button
   shows `Syncing…` while the Celery worker fetches DNS records, stores a
   snapshot, and runs the diff and risk pipeline.  On completion the result
   shows inline: `Sync complete — 1 snapshot, 0 changes detected.`

### Minimum Cloudflare API token permissions

Create a restricted API token at https://dash.cloudflare.com/profile/api-tokens:

- **Zone → DNS → Read** (required)
- Scope: the specific zone you want to monitor

The token does not need write access.  ConfigTrace only reads DNS records.

### Verify via backend APIs

```bash
# Confirm the integration was created
curl http://localhost:8000/integrations | python3 -m json.tool
# → { "integrations": [{ "id": "...", "provider": "cloudflare", ... }], "total": 1 }

# Confirm resources were discovered (zone appears after first sync)
curl http://localhost:8000/resources | python3 -m json.tool

# Confirm changes were recorded (after a second sync with DNS changes)
curl http://localhost:8000/changes | python3 -m json.tool

# Filter to only critical changes
curl "http://localhost:8000/changes?risk_level=critical" | python3 -m json.tool
```

### What's not implemented yet

- Change detail page (post-MVP)
- Scheduled sync (post-MVP)

## Change Timeline (Milestone 15)

Milestone 15 turns `/timeline` into an operational change investigation
surface with filter controls, load-more pagination, and improved change
value display.

### What it adds

- **Filter controls** — three pill-bar rows above the list:
  - **Risk** — All / Critical / High / Medium / Low / Unknown
  - **Type** — All / Added / Removed / Modified
  - **Since** — All time / Last 24h / Last 7 days / Last 30 days
- **Load More** — replaces previous/next paging. Clicking appends the next
  page (20 rows) to the existing list. Shows `"Showing N of M"` count and
  `"Load more (R remaining)"` label.
- **Improved empty states** — separate messages for "no data at all" vs
  "no results for active filters", each with a clear call to action.
- **Improved ChangeRow** — better secondary line per change type:
  - Added: `→ {content of new record}`
  - Removed: `{content of old record} → removed`
  - Modified: `{prev field value} → {new field value}`
  - Risk reason always shown in italic below the value line.
- **Exact timestamp on hover** — each relative timestamp shows the full
  UTC datetime in a native tooltip.

### How to use the timeline

1. Open http://localhost:3000/timeline
2. Click a risk pill to filter (e.g. **Critical** shows only critical changes)
3. Change the time range to **Last 24h** to focus on recent activity
4. Scroll down and click **Load more** to see older results

### Verify with seed data or Cloudflare

```bash
# Seed realistic sample data first (creates 5 changes across all risk levels)
docker compose exec api python scripts/seed_dev_data.py

# Then open the frontend
open http://localhost:3000/timeline

# Filter to critical only  
open "http://localhost:3000/timeline"  # use Risk → Critical pill in the UI

# Backend API equivalents
curl "http://localhost:8000/changes?risk_level=critical" | python3 -m json.tool
curl "http://localhost:8000/changes?change_type=modified" | python3 -m json.tool
curl "http://localhost:8000/changes?risk_level=high&change_type=modified" | python3 -m json.tool
curl "http://localhost:8000/changes?since=2026-05-20T00:00:00Z" | python3 -m json.tool
curl "http://localhost:8000/changes?page=1&page_size=20" | python3 -m json.tool
```

### Backend compatibility

No backend changes were required. `GET /changes` already supports all
filter parameters: `risk_level`, `change_type`, `since`, `until`, `page`,
`page_size`. The frontend generates ISO 8601 `since` timestamps client-side
from the selected time range.

## Resource History (Milestone 16)

Milestone 16 makes every resource in the Resources list clickable, leading to
a detail page that shows the full snapshot history and lets you inspect the
exact DNS state at any point in time, plus a feed of every change recorded
for that resource.

### What it adds

- **Clickable resource rows** — each row in `/resources` is now a `<Link>`
  to `/resources/{id}`. Cursor changes to pointer on hover.
- **Resource detail page** (`/resources/[resourceId]`) with:
  - **Header** — display name or provider resource ID as the page title,
    provider resource type as the subtitle.
  - **Metadata bar** — Type, provider ID, Active/Inactive status, last
    snapshot time, total snapshot count, total change count.
  - **Snapshot history panel** (left column, 240 px) — all snapshots newest
    first, each showing relative timestamp (exact UTC on hover), first 10 chars
    of the content hash, and the `triggered_by` label. Clicking a row selects
    it and updates the DNS state panel.
  - **DNS state panel** (right column, flex) — renders the DNS records from
    the selected snapshot as a table with columns: Type, Name, Content, TTL,
    Proxied, Priority, Comment. Booleans display as Yes / No; null as —.
    Proxied = Yes is highlighted in amber. Long values truncate with ellipsis
    and expose the full value in a native tooltip.
  - **Changes feed** — reuses `<ChangeList>` showing all changes for this
    resource, newest first.
- **New utility helpers** — `shortId(id)` (first 8 chars) and
  `formatSnapshotHash(hash)` (first 10 chars) added to `lib/utils.ts`.
- **Fixed `DnsRecord` type** — fields updated to match actual Cloudflare
  connector output: `record_type`, `content`, `proxied`, `priority`,
  `comment`, `record_id`, `modified_on` (all optional; index signature kept).
- **Fixed `SnapshotListItem.triggered_by`** — aligned with backend schema
  (`string`, not `string | null`).

### How to use

1. Open http://localhost:3000/resources — rows are now clickable links.
2. Click any resource to open its detail page.
3. The newest snapshot is pre-selected; its DNS records appear in the right
   panel immediately.
4. Click an older snapshot in the left list to compare DNS state at that point
   in time.
5. Scroll down to see all changes recorded for this resource.

### Verify with seed data

```bash
# Seed data first if not already done
docker compose exec api python scripts/seed_dev_data.py

# Open resources list
open http://localhost:3000/resources

# Backend API equivalents
curl "http://localhost:8000/resources" | python3 -m json.tool
curl "http://localhost:8000/resources/{id}" | python3 -m json.tool
curl "http://localhost:8000/resources/{id}/snapshots" | python3 -m json.tool
curl "http://localhost:8000/resources/{id}/changes" | python3 -m json.tool
```

## Change Detail Page (Milestone 17)

Milestone 17 makes every change in the system fully inspectable. Clicking any
change row — from the Timeline, Dashboard, or a Resource detail page — opens
`/changes/{change_id}` which shows the full change context without requiring a
second API call.

### What it adds

- **Clickable change rows** — `ChangeRow` is now a `<Link>` to
  `/changes/{id}`. Works from `/dashboard`, `/timeline`, and
  `/resources/{resourceId}`. The hover style and column layout are preserved.
- **Change detail page** (`/changes/[changeId]`):
  - **Change header** — `record_identifier` in monospace with risk badge;
    change type, field path, relative + absolute timestamp, and the resource
    and integration IDs as muted debug metadata.
  - **Risk explanation panel** — risk badge with the `risk_reason` string
    shown in prose. Tinted background matches the risk level (red-ish for
    critical, amber for medium, etc.). A "Context" block below surfaces any
    provider/record metadata from `provider_metadata` (record type, name,
    content, zone, etc.).
  - **Field-level diff panel**:
    - *Modified* — "Before" block (faint red tint) and "After" block (faint
      green tint), each in monospace with a label. For multi-line JSON values
      the block wraps; for simple scalars it stays compact.
    - *Added* — "Record Added" label in green; the full DNS record rendered via
      `DnsRecordView` (key-value rows, not raw JSON).
    - *Removed* — "Record Removed" label in red; the full DNS record via
      `DnsRecordView`.
  - **Snapshot context** — two timestamp cards (Before / After snapshot) with
    relative time (exact UTC on hover) and the first 10 chars of the snapshot
    UUID. For *modified* changes the page additionally shows the matched DNS
    record from each snapshot side-by-side.
  - **Raw change data** — collapsed `<details>` section that exposes
    `prev_value`, `new_value`, and `provider_metadata` as formatted JSON for
    debugging. Hidden by default; never dominates the view.
- **New `DnsRecordView` component** —
  `frontend/src/components/changes/DnsRecordView.tsx`. Renders a single DNS
  record as labelled key-value rows (Type, Name, Content, TTL, Proxied,
  Priority, Comment). Accepts a `tint` prop (`"add"` / `"remove"` /
  `"neutral"`) for the before/after context.
- **`formatDiffValue` utility** — like `formatValue` but returns full
  pretty-printed JSON for objects instead of the 60-char truncation. Used in
  the diff panel where engineers need to read the complete value.

### No backend changes required

`GET /changes/{change_id}` already returns everything needed:
- All list-view fields (`change_type`, `field_path`, `prev_value`,
  `new_value`, `risk_level`, `risk_reason`, `provider_metadata`, ...)
- Snapshot IDs, timestamps, and full `state` arrays (so no second request is
  needed to render the snapshot context).

### How to use

1. Open http://localhost:3000/timeline
2. Click any change row → opens `/changes/{id}`
3. Read the risk explanation, inspect the before/after diff
4. Expand "Raw change data" for full JSON if needed

```bash
# Seed data
docker compose exec api python scripts/seed_dev_data.py

# List changes
open http://localhost:3000/timeline

# Direct API access
curl "http://localhost:8000/changes" | python3 -m json.tool
curl "http://localhost:8000/changes/{change_id}" | python3 -m json.tool
```

## MVP Demo Polish (Milestone 18)

Milestone 18 makes ConfigTrace demo-ready: the dashboard is now aware of
where you are in the setup flow, the integration form tells you exactly which
Cloudflare permissions to grant, and every list surface highlights alarming
changes at a glance.

### What it adds

- **Dashboard empty-state intelligence** — the dashboard now fetches
  integrations, resources, and changes in parallel and shows a contextual
  next-step prompt at each stage of the setup flow:
  - *No integrations* → "Connect a Cloudflare zone to start monitoring…"
  - *Integration exists, no resources yet* → "Run your first sync to create
    a baseline…"
  - *Baseline exists, no changes yet* → "Make a DNS change in Cloudflare,
    then sync again…"
  - *Changes exist* → the normal ChangeList, with a "View all N →" link to
    the full Timeline.
- **Dashboard stat improvements** — "Changes detected" now shows the total
  from the API (`data.total`), not just the count of the loaded page.
  Critical and High stats render in their risk colours when non-zero.
  "Last change" time appears in the stat bar once any changes exist.
- **Integration form — required permissions block** — a compact inline box
  below the API token field lists the exact Cloudflare permission scopes
  needed (`Zone → DNS → Read`, `Zone → Zone → Read`, specific zone scope).
  The Zone ID field now explains where to find it (domain Overview sidebar).
- **Risk-level row indicator** — Critical and High change rows across the
  Dashboard, Timeline, and Resource detail page now show a 2 px coloured
  left edge (red for critical, orange-red for high) via inset `box-shadow`.
  Layout and padding are unaffected; the indicator is purely additive.
- **`StatBlock` `valueColor` prop** — allows individual stats to render their
  value in a custom colour without duplicating the component.
- **`.gitignore` hardening** — added `*.db` catch-all alongside the existing
  `backend/test.db` entry so stray SQLite test databases are never staged.

---

## MVP Demo Runbook

Use this runbook to walk through the full ConfigTrace demo end-to-end, from
a clean start to inspecting a detected DNS change.

### A. Start the backend stack

```bash
# Start API + Postgres + Redis + Celery worker
docker compose --profile celery up --build

# In a separate terminal — run database migrations
docker compose exec api alembic upgrade head
```

Verify the stack is healthy:

```bash
curl http://localhost:8000/health
# → {"status":"ok","timestamp":"...","version":"0.1.0"}

curl http://localhost:8000/health/db
# → {"status":"ok","database":"connected","timestamp":"..."}
```

### B. Start the frontend

```bash
cd frontend
npm install
npm run dev
# → http://localhost:3000
```

### C. (Optional) Load seed data for instant demo content

```bash
docker compose exec api python scripts/seed_dev_data.py
```

This creates one Cloudflare integration (with fake credentials), one DNS zone
resource (`example.com`), three historical snapshots, and five changes across
all risk levels — enough to demonstrate every UI surface without needing a
real Cloudflare account.

```bash
# Confirm seed data is visible
curl http://localhost:8000/changes | python3 -m json.tool
curl http://localhost:8000/resources | python3 -m json.tool
```

### D. Real Cloudflare end-to-end flow

**Step 1 — Create a Cloudflare API token**

1. Log in to [dash.cloudflare.com](https://dash.cloudflare.com)
2. Go to **My Profile → API Tokens → Create Token**
3. Use **Create Custom Token**
4. Add these permission rows:
   - `Zone` → `DNS` → `Read`
   - `Zone` → `Zone` → `Read`
5. Under **Zone Resources**, select **Specific zone** → pick your domain
6. Click **Continue to summary** → **Create Token**
7. Copy the token — you will not see it again

**Step 2 — Find your Zone ID**

1. In the Cloudflare dashboard, select your domain
2. On the **Overview** page, scroll to the right sidebar
3. Copy the **Zone ID** (32-character hex string)

**Step 3 — Connect in ConfigTrace**

1. Open http://localhost:3000/integrations
2. Click **Add New Integration**
3. Fill in:
   - Display Name: e.g. `Production Zone`
   - API Token: paste from Step 1
   - Zone ID: paste from Step 2
4. Click **Connect Cloudflare**

**Step 4 — Take a baseline snapshot**

1. On the Integrations page, click **Sync Now** for your new integration
2. Wait for "Sync complete — N snapshots, 0 changes detected."
   *(First sync always shows 0 changes — this is the baseline)*
3. Open http://localhost:3000/resources to confirm the zone appeared

**Step 5 — Make a DNS change in Cloudflare**

Make a safe, reversible change such as:
- Add a new TXT record (e.g. `_test.yourdomain.com`)
- Change the TTL on an existing A record
- Add a comment to any record

**Step 6 — Sync again**

1. Return to http://localhost:3000/integrations
2. Click **Sync Now** again
3. Wait for "Sync complete — N snapshots, M changes detected."
4. Open http://localhost:3000/dashboard — the change appears in the stat bar
   and the Recent Changes list

**Step 7 — Inspect the change**

| URL | What you see |
|---|---|
| http://localhost:3000/timeline | All changes, filterable by risk / type / time |
| http://localhost:3000/changes/{id} | Full change detail: risk explanation, before/after diff, snapshot context |
| http://localhost:3000/resources | All monitored zones — click to open resource history |
| http://localhost:3000/resources/{id} | Snapshot history + DNS state table + resource-specific changes |

**Step 8 — Revert and re-sync (optional)**

Undo the Cloudflare change, then run Sync Now a third time to see the
reversion appear as its own change row in the timeline.

### E. Useful API checks during a demo

```bash
# Health
curl http://localhost:8000/health
curl http://localhost:8000/health/db

# Data
curl http://localhost:8000/integrations | python3 -m json.tool
curl http://localhost:8000/resources | python3 -m json.tool
curl http://localhost:8000/changes | python3 -m json.tool
curl "http://localhost:8000/changes?risk_level=critical" | python3 -m json.tool
curl "http://localhost:8000/changes?risk_level=high" | python3 -m json.tool

# Detail (replace {id} with real UUID from the above)
curl http://localhost:8000/changes/{id} | python3 -m json.tool
curl http://localhost:8000/resources/{id}/snapshots | python3 -m json.tool
```

### F. Files that must never be committed

| Path | Why |
|---|---|
| `.env` | Contains real credentials and secrets |
| `backend/test.db` / `*.db` | SQLite test artefact, not production data |
| `node_modules/` | Rebuilt by `npm install` |
| `frontend/.next/` | Built by `npm run build` |
| `backend/.venv/` | Rebuilt by `pip install` |

All of the above are covered by `.gitignore`. Run `git status` before every
commit to confirm no secrets or build artefacts are staged.

---

## MVP Demo Checklist

Run through this list before every demo or handoff:

- [ ] `npm run build` passes with zero TypeScript errors
- [ ] `curl http://localhost:8000/health` returns `{"status":"ok",...}`
- [ ] `curl http://localhost:8000/health/db` returns `{"status":"ok","database":"connected",...}`
- [ ] Dashboard empty state shows "Connect Cloudflare" when no integrations exist
- [ ] Cloudflare integration can be created via the form
- [ ] First sync completes and shows "0 changes detected" (baseline)
- [ ] Dashboard empty state updates to "Baseline captured" after first sync
- [ ] A DNS change in Cloudflare is detected on the second sync
- [ ] Dashboard stat bar shows the correct change count and risk counts
- [ ] Timeline shows the change with the correct risk badge and row indicator
- [ ] Clicking a change row opens `/changes/{id}` with full detail
- [ ] Change detail shows Before/After diff (modified) or record table (added/removed)
- [ ] Resource list shows the zone; clicking it opens the resource detail page
- [ ] Resource detail shows snapshot history and DNS state table
- [ ] No `.env`, `*.db`, or credential files are staged (`git status` is clean)

---

## Production Deployment Preparation (Milestone 19)

Milestone 19 makes ConfigTrace safe and configurable for deployment to
`app.configtrace.org` and `api.configtrace.org`.

### What it adds

- **`ENVIRONMENT` variable** — new field in `backend/app/config.py`.
  Defaults to `"development"` so production is never reached accidentally.
  Setting `ENVIRONMENT=production` is an explicit, deliberate act.
- **Environment-driven CORS** — `backend/app/main.py` now reads allowed
  origins from `BACKEND_CORS_ORIGINS` (comma-separated, parsed by
  `settings.cors_origins`). Local default is `http://localhost:3000` and
  `:3001`. Production value:
  `https://app.configtrace.org,https://configtrace.org`.
- **Seed script production guard** — `seed_dev_data.py` checks
  `ENVIRONMENT` before any database import and exits with a clear error if
  `ENVIRONMENT=production` is set. Locally it behaves identically to before.
- **Updated `.env.example`** — adds `ENVIRONMENT` and `BACKEND_CORS_ORIGINS`
  with explanatory comments for every variable.
- **New `.env.production.example`** — a production-specific template showing
  the exact shape of production values. Committed to the repo; the filled-in
  copy must never be committed.
- **`.gitignore` hardening** — `.env.production` and `.env.staging` are now
  explicitly ignored alongside the existing `.env` and `.env.local` patterns.
- **`render.yaml`** — Render infrastructure-as-code declaring the API web
  service and Celery background worker. Both use `backend/Dockerfile`; the API
  start command overrides the Dockerfile `CMD` with `$PORT` so Render can
  inject the port at runtime. Migrations run automatically as a
  `preDeployCommand` before each deploy. Secrets are declared `sync: false`
  — set them in the Render dashboard, never in this file.
- **`docs/deployment.md`** — detailed production deployment guide covering:
  domain layout, recommended infrastructure, how `render.yaml` works, required
  env vars, secret generation commands, step-by-step deployment order,
  Cloudflare SSL settings, CORS verification, and local development after this
  milestone.
- **`GET /`** now includes `"environment"` in the response so it's easy to
  confirm which environment a running API instance belongs to.

### What did not change

- Local Docker Compose workflow is identical.
- The Dockerfile already ran without `--reload` by default; docker-compose
  overrides it for development. No change needed.
- `frontend/package.json` already had `"start": "next start"`. No change.
- `frontend/src/lib/api.ts` already reads `NEXT_PUBLIC_API_BASE_URL`. No
  change.
- `GET /health` and `GET /health/db` already existed and are unchanged.

### Target domain layout

| Subdomain | Purpose |
|---|---|
| `configtrace.org` | Marketing site |
| `app.configtrace.org` | Next.js frontend |
| `api.configtrace.org` | FastAPI backend |

Full deployment guide: [`docs/deployment.md`](docs/deployment.md)

---

## Production Deployment (Milestone 20)

Milestone 20 completed the initial production deployment and verified the full
MVP core loop end-to-end in production.

### Live production URLs

| URL | Service |
|---|---|
| `https://app.configtrace.org` | Frontend (Vercel) |
| `https://api.configtrace.org` | Backend API (Render) |
| `https://configtrace.org` | Marketing / landing page (GitHub Pages) |

### What happened

- **`render.yaml`** — Render Blueprint deployed `configtrace-api` (FastAPI) and
  `configtrace-worker` (Celery) to Render Starter.  Alembic migrations ran
  automatically via `preDeployCommand: alembic upgrade head`.
- **Neon** — Production PostgreSQL provisioned.  `/health/db` confirmed
  `database: connected`.
- **Render Key Value (Oregon)** — Production Redis provisioned in the **same
  region** as the API and worker.  A cross-region Redis instance was the root
  cause of an initial sync failure; see `docs/deployment.md` for details.
- **Vercel** — Frontend deployed with Framework Preset: Next.js, Root Directory:
  `frontend/`, and `NEXT_PUBLIC_API_BASE_URL=https://api.configtrace.org`.
- **Cloudflare** — DNS CNAMEs set (`app` → Vercel, `api` → Render).  SSL/TLS
  Full (strict) working on both subdomains.
- **Production smoke test passed** — Cloudflare integration created, first sync
  produced a baseline snapshot, second sync after a test TXT record addition
  detected 1 low-risk added change in the timeline.

### Deployment issues encountered and fixed

Three non-trivial issues were diagnosed and resolved during deployment:

1. **Render `startCommand` → `dockerCommand`** — Blueprint rejected
   `startCommand` on Docker-runtime services; fixed in `render.yaml`.
2. **Vercel "No Output Directory"** — Framework Preset must be set to Next.js
   (not "Other"); Root Directory must be `frontend/`.
3. **Render Redis region mismatch** — Internal Redis URLs only resolve within
   the same Render region.  Creating a new Key Value instance in the same
   region as the API and worker fixed sync failures.

Full notes: [`docs/deployment.md`](docs/deployment.md)

---

## Authentication and User Isolation (Milestone 21)

Milestone 21 replaces the placeholder dev-mode auth with real Clerk JWT
verification on the backend and a Clerk-hosted sign-in / sign-up flow on the
frontend.  Every protected route now scopes data to the authenticated user.

### What it adds

- **Clerk JWKS verification (backend)** — `backend/app/core/auth.py` rewritten
  to verify RS256 JWTs locally against Clerk's JWKS endpoint.  No Clerk SDK
  required; uses the existing `python-jose` and `httpx` dependencies.  The
  JWKS is cached for 5 minutes; a token with an unknown `kid` forces a refresh
  to handle key rotation.  Stale cache is used as a fallback for up to 1 hour
  on transient JWKS fetch failures.
- **Production fail-closed guarantee** — when `ENVIRONMENT=production` and
  `CLERK_JWKS_URL` is missing or a placeholder, every protected route returns
  **HTTP 503** before any token parsing.  The dev-mode branch is unreachable
  in production regardless of other env vars or headers.
- **Local dev-mode preserved** — when `ENVIRONMENT != production` AND
  `CLERK_JWKS_URL` is not set, the backend behaves exactly as before:
  auto-creates `dev@configtrace.local`, accepts the `X-Dev-User-Email` header
  override.  No Clerk account needed to run the backend locally.
- **Worker ownership guard** — `backend/app/workers/sync_task.py` now verifies
  that `integration.user_id` matches the `user_id` task argument before
  fetching any data.  Refuses to run on mismatch with a clear `ValueError`,
  even if the API path was somehow bypassed.
- **Frontend Clerk integration** — `@clerk/nextjs` v6.10.x added.
  `<ClerkProvider>` wraps the root layout; `middleware.ts` protects every
  route except `/sign-in/*`, `/sign-up/*`, and static assets.  Sign-in and
  sign-up are handled by Clerk's hosted components at
  `/sign-in/[[...sign-in]]` and `/sign-up/[[...sign-up]]`.  A `<UserButton>`
  in the sidebar footer surfaces account/sign-out actions.
- **Token-aware API client** — every function in `frontend/src/lib/api.ts`
  accepts an optional `token` parameter and sends it as
  `Authorization: Bearer <token>`.  Pages call `useAuth().getToken()` in
  effects before each fetch; sub-components (`IntegrationList`,
  `CloudflareIntegrationForm`) call it directly.
- **Backend test suite for M21** — `backend/tests/test_milestone21.py` covers
  production fail-closed, missing/malformed/expired/invalid-key tokens,
  valid-token user upsert, JWKS cache reuse, dev-mode preservation, and the
  worker ownership guard.  All 14 tests pass; the full backend suite is 165
  tests, also passing.

### Local development setup after M21

Local **backend** still works without any Clerk env vars — dev mode is
unchanged.  Local **frontend** requires a Clerk development application:

1. Create a free dev application at [dashboard.clerk.com](https://dashboard.clerk.com)
2. Copy the `pk_test_...` value into your `.env`:

   ```
   NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=pk_test_...
   ```

3. (Optional) If you want to test the production auth path locally, also set:

   ```
   CLERK_JWKS_URL=https://<your-dev-frontend-api>.clerk.accounts.dev/.well-known/jwks.json
   ```

   With both set, the backend verifies the JWT for real instead of falling
   back to dev-mode auth — useful for catching token-threading bugs.

### Environment variables added

| Variable | Required where | Description |
|---|---|---|
| `CLERK_JWKS_URL` | Production backend | JWKS endpoint Clerk publishes its RS256 public keys at.  Missing in production → HTTP 503 on every route. |
| `CLERK_ISSUER` | Optional | If set, the JWT `iss` claim must match exactly. |
| `NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY` | Frontend (local + prod) | Required for `<ClerkProvider>` to initialize.  Missing → app fails to render. |

`CLERK_SECRET_KEY` is **not** used by the M21 verification path (it would
be for Clerk's management API in a future milestone).

### Behaviour matrix

| Environment | `CLERK_JWKS_URL` set? | Result |
|---|---|---|
| `development` | No | Dev mode — auto-creates `dev@configtrace.local`. |
| `development` | Yes | Real JWT verification; requires Authorization header. |
| `production` | No | **503** on every protected route. |
| `production` | Yes | Real JWT verification; **401** on missing/invalid/expired token. |

### Production roll-out steps

1. In Clerk → API Keys, copy:
   - the **JWKS URL** → set as `CLERK_JWKS_URL` on both Render services
   - the **publishable key** → set as `NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY` in Vercel
2. Add the production frontend origin(s) to Clerk → Domains
   (`app.configtrace.org`).
3. Deploy backend then frontend.  Smoke test:
   - `curl https://api.configtrace.org/integrations` → 401 (unauthenticated)
   - Sign in at `https://app.configtrace.org/sign-in` → integrations page loads
4. Re-create your Cloudflare integration in the new authenticated session.
   The pre-existing integration created under the old dev user is now
   invisible (intentional — no automatic reassignment).

---

Production now enforces Clerk JWT authentication on every protected route.
Each authenticated user only ever sees their own integrations, resources,
snapshots, and changes — see the Milestone 21 section below for the full
behaviour matrix.

---

## Build milestones

The MVP is built across 18 milestones defined in [`docs/MVPBuildPlan.txt`](docs/MVPBuildPlan.txt). Current status:

- [x] Milestone 1: Repository setup
- [x] Milestone 2: Docker Compose
- [x] Milestone 3: FastAPI backend setup (partial — health endpoint + CORS; Clerk auth deferred)
- [x] Milestone 4: PostgreSQL and SQLAlchemy models
- [x] Milestone 5: Alembic migrations
- [x] Milestone 6: Cloudflare connector
- [x] Milestone 7: Manual sync endpoint
- [x] Milestone 8: Snapshot service
- [x] Milestone 9: Diff service
- [x] Milestone 10: Risk classification service
- [x] Milestone 11: Changes API and Resources API
- [x] Milestone 12: Next.js frontend setup
- [x] Milestone 13: Frontend Dashboard Data Rendering
- [x] Milestone 14: Cloudflare Integration Setup UI
- [x] Milestone 15: Change Timeline Page
- [x] Milestone 16: Resource History Page
- [x] Milestone 17: Change Detail Page
- [x] Milestone 18: MVP Demo Polish
- [x] Milestone 19: Production Deployment Preparation
- [x] Milestone 20: Production deployment — all services live, smoke test passed
- [x] Milestone 21: Authentication and User Isolation — Clerk JWTs, production fail-closed, multi-user data scoping
