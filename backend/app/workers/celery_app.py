import os

from celery import Celery

# Read broker URL from the environment.  Defaults allow the module to be
# imported outside Docker (e.g. during unit tests) without crashing.
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

celery_app = Celery(
    "configtrace",
    broker=REDIS_URL,
    backend=REDIS_URL,
    # Explicit task discovery — avoids autodiscover scanning the whole package.
    include=["app.workers.sync_task"],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    # ── Memory-safety settings for Render Starter (512 MB cap) ──────────────────
    # Celery defaults ``worker_concurrency`` to ``os.cpu_count()``.  On Render's
    # shared hardware that returns the host's CPU count (often 8), so the
    # prefork pool spawns 8 child processes by default — each one a full Python
    # interpreter that re-imports the app (~70 MB resident).  Master + 8
    # children ≈ 600 MB, well over the Starter plan's 512 MB ceiling.
    #
    # Pinning concurrency to 1 keeps the worker fleet to a master + a single
    # child (~150 MB total).  With one user / one Cloudflare zone in the MVP,
    # syncs are infrequent and short, so serialising them is fine.  When we
    # need parallel execution (multi-tenant, scheduled syncs) we'll move to a
    # larger Render plan and raise concurrency at that time.
    worker_concurrency=1,
    # Prefetch=1 means each child reserves exactly one task at a time instead
    # of buffering 4 tasks ahead (Celery's default ``worker_prefetch_multiplier
    # = 4``).  Keeps queued payloads off the worker's heap.
    worker_prefetch_multiplier=1,
    # Recycle the worker child after every 50 tasks.  Bounds memory growth from
    # any slow leak in long-lived workers (e.g. SQLAlchemy connection state,
    # httpx client caches).  At our current sync rate this triggers at most
    # once a day.
    worker_max_tasks_per_child=50,
)
