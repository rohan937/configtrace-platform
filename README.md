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
├── .env.example              All required environment variables, documented
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
- [x] Milestone 11: Changes API and Resources API ← **you are here**
- [ ] Milestone 12: Next.js frontend setup
- [ ] Milestone 13: Dashboard page
- [ ] Milestone 14: Integrations page
- [ ] Milestone 15: Change timeline page
- [ ] Milestone 16: Resource history page
- [ ] Milestone 17: Basic testing
- [ ] Milestone 18: MVP demo script
