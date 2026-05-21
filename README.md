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

**Verify each service**
```bash
# API health
curl http://localhost:8000/
# → {"service":"ConfigTrace API","status":"ok"}

# PostgreSQL
docker compose exec db psql -U configtrace -d configtrace -c '\dt'

# Redis
docker compose exec redis redis-cli ping
# → PONG

# Frontend — open http://localhost:3000 in a browser
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

## Build milestones

The MVP is built across 18 milestones defined in [`docs/MVPBuildPlan.txt`](docs/MVPBuildPlan.txt). Current status:

- [x] Milestone 1: Repository setup
- [x] Milestone 2: Docker Compose ← **you are here**
- [ ] Milestone 3: FastAPI backend setup
- [ ] Milestone 4: PostgreSQL and SQLAlchemy models
- [ ] Milestone 5: Alembic migrations
- [ ] Milestone 6: Cloudflare connector
- [ ] Milestone 7: Manual sync endpoint
- [ ] Milestone 8: Snapshot service
- [ ] Milestone 9: Diff service
- [ ] Milestone 10: Risk classification service
- [ ] Milestone 11: Changes API
- [ ] Milestone 12: Next.js frontend setup
- [ ] Milestone 13: Dashboard page
- [ ] Milestone 14: Integrations page
- [ ] Milestone 15: Change timeline page
- [ ] Milestone 16: Resource history page
- [ ] Milestone 17: Basic testing
- [ ] Milestone 18: MVP demo script
