import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.routers import health
from app.routers.billing import router as billing_router
from app.routers.changes import router as changes_router
from app.routers.dashboard import router as dashboard_router
from app.routers.integrations import router as integrations_router
from app.routers.integrations_github_app import router as github_app_router
from app.routers.invites import router as invites_router
from app.routers.me import router as me_router
from app.routers.resources import router as resources_router
from app.routers.security import router as security_router
from app.routers.settings import router as settings_router
from app.routers.slack_oauth import router as slack_oauth_router
from app.routers.stripe_webhook import router as stripe_webhook_router
from app.routers.paddle_webhook import router as paddle_webhook_router
from app.routers.dodo_webhook import router as dodo_webhook_router
from app.routers.syncs import router as syncs_router
from app.routers.workspaces import router as workspaces_router

logger = logging.getLogger(__name__)


def _validate_production_config() -> None:
    """Fail fast on startup rather than serving traffic in a broken state.

    ENCRYPTION_KEY has no safe fallback (see app/core/encryption.py — it
    deliberately never derives a substitute key). Without this check,
    production can start and pass every health check while every single
    "connect a provider" request 500s, because credential encryption
    raises only when first exercised, not at boot. Restricted to
    production so local/dev/CI can keep running without every optional
    secret configured.
    """
    if not settings.is_production:
        return
    from app.core.encryption import EncryptionKeyError, _load_key

    try:
        _load_key()
    except EncryptionKeyError as exc:
        raise RuntimeError(
            "Refusing to start: ENVIRONMENT=production but ENCRYPTION_KEY "
            f"is missing or invalid ({exc}). Every credential-encrypting "
            "request would fail at runtime instead of at startup."
        ) from exc


_validate_production_config()

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
app.include_router(billing_router)        # prefix="/workspaces/{id}/billing" (M52)
app.include_router(invites_router)        # prefix="/invites"              (M50)
app.include_router(dashboard_router)      # prefix="/dashboard"           (M34)
app.include_router(settings_router)       # prefix="/settings"            (M34)
app.include_router(me_router)             # prefix="/me"                  (M59.13)
app.include_router(github_app_router)     # prefix="/integrations/github/app" (M31)
app.include_router(integrations_router)   # prefix="/integrations"
app.include_router(syncs_router)          # prefix="/syncs"
app.include_router(changes_router)        # prefix="/changes"
app.include_router(resources_router)      # prefix="/resources"
app.include_router(stripe_webhook_router) # prefix="/stripe"              (M52)
app.include_router(paddle_webhook_router) # prefix="/paddle"              (Commercial Infra M2)
app.include_router(dodo_webhook_router)   # prefix="/dodo"                (Dodo Payments M1, Test Mode)
app.include_router(slack_oauth_router)    # prefix="/slack"               (M58.5)
app.include_router(security_router)        # prefix="/security"            (M60.3)


# ── Root ──────────────────────────────────────────────────────────────────────
@app.get("/", tags=["root"])
def root() -> dict:
    return {
        "service": "ConfigTrace API",
        "version": "0.1.0",
        "status": "ok",
        "environment": settings.ENVIRONMENT,
    }
