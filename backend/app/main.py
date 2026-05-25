from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.routers import health
from app.routers.changes import router as changes_router
from app.routers.dashboard import router as dashboard_router
from app.routers.integrations import router as integrations_router
from app.routers.integrations_github_app import router as github_app_router
from app.routers.invites import router as invites_router
from app.routers.resources import router as resources_router
from app.routers.settings import router as settings_router
from app.routers.syncs import router as syncs_router
from app.routers.workspaces import router as workspaces_router

app = FastAPI(
    title="ConfigTrace API",
    version="0.1.0",
    description="Configuration change intelligence for production systems.",
)

# ── CORS ──────────────────────────────────────────────────────────────────────
# Origins are driven by the BACKEND_CORS_ORIGINS environment variable (a
# comma-separated list).  Locally this defaults to the Next.js dev server.
# In production, set it to the exact frontend origin(s):
#
#   BACKEND_CORS_ORIGINS=https://app.configtrace.org,https://configtrace.org
#
# Never use the wildcard "*" in production with allow_credentials=True —
# browsers reject credentialled wildcard CORS.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(health.router, prefix="/health", tags=["health"])
app.include_router(workspaces_router)     # prefix="/workspaces"          (M50)
app.include_router(invites_router)        # prefix="/invites"              (M50)
app.include_router(dashboard_router)      # prefix="/dashboard"           (M34)
app.include_router(settings_router)       # prefix="/settings"            (M34)
app.include_router(github_app_router)     # prefix="/integrations/github/app" (M31)
app.include_router(integrations_router)   # prefix="/integrations"
app.include_router(syncs_router)          # prefix="/syncs"
app.include_router(changes_router)        # prefix="/changes"
app.include_router(resources_router)      # prefix="/resources"


# ── Root ──────────────────────────────────────────────────────────────────────
@app.get("/", tags=["root"])
def root() -> dict:
    return {
        "service": "ConfigTrace API",
        "version": "0.1.0",
        "status": "ok",
        "environment": settings.ENVIRONMENT,
    }
