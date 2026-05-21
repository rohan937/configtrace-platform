from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routers import health

app = FastAPI(
    title="ConfigTrace API",
    version="0.1.0",
    description="Configuration change intelligence for production systems.",
)

# ── CORS ─────────────────────────────────────────────────────────────────────
# Allow the Next.js dev server to call the API from the browser.
# Tighten origins for staging / production deployments.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:3001",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(health.router, prefix="/health", tags=["health"])


# ── Root ──────────────────────────────────────────────────────────────────────
@app.get("/", tags=["root"])
def root() -> dict:
    return {"service": "ConfigTrace API", "version": "0.1.0", "status": "ok"}
