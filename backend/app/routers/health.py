from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db

router = APIRouter()

APP_VERSION = "0.1.0"


@router.get("")
def health() -> dict:
    """Lightweight liveness check — no database required.

    Called by load balancers, Docker healthchecks, and CI smoke tests.
    Returns HTTP 200 as long as the Python process is alive.
    """
    return {
        "status": "ok",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": APP_VERSION,
    }


@router.get("/db")
def health_db(db: Session = Depends(get_db)):
    """Database connectivity check.

    Executes a trivial query against PostgreSQL.
    Returns HTTP 200 when the connection is healthy, 503 otherwise.
    """
    try:
        db.execute(text("SELECT 1"))
        return {
            "status": "ok",
            "database": "connected",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as exc:  # noqa: BLE001
        return JSONResponse(
            status_code=503,
            content={
                "status": "error",
                "database": "disconnected",
                "detail": str(exc),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        )


@router.get("/redis")
def health_redis():
    """Broker connectivity check.

    Without this, ``/health`` and ``/health/db`` can both report healthy
    while Redis is unreachable — every sync enqueue (manual or scheduled)
    fails at that point, but nothing operator-visible says so until someone
    notices syncs aren't running. A short PING with a tight timeout so this
    check itself can't hang a load balancer probe.
    """
    try:
        import redis as redis_lib

        client = redis_lib.from_url(
            settings.REDIS_URL, socket_connect_timeout=2, socket_timeout=2
        )
        client.ping()
        return {
            "status": "ok",
            "redis": "connected",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as exc:  # noqa: BLE001
        return JSONResponse(
            status_code=503,
            content={
                "status": "error",
                "redis": "disconnected",
                "detail": str(exc),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        )
