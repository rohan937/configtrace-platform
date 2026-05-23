import os

from celery import Celery
from celery.schedules import crontab

# Read broker URL from the environment.  Defaults allow the module to be
# imported outside Docker (e.g. during unit tests) without crashing.
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

celery_app = Celery(
    "configtrace",
    broker=REDIS_URL,
    backend=REDIS_URL,
    # Explicit task discovery — avoids autodiscover scanning the whole package.
    # ``scheduled_tasks`` is imported alongside ``sync_task`` so the task name
    # ``enqueue_scheduled_syncs`` resolves on both worker and beat processes.
    include=[
        "app.workers.sync_task",
        "app.workers.scheduled_tasks",
    ],
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
    #
    # NOTE (M23): these settings apply only to the worker process.  The
    # separate ``configtrace-beat`` service runs ``celery beat``, which does
    # not spawn prefork children — it idles between schedule ticks at
    # ~50-80 MB resident.
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
    # ── Periodic schedule (Milestone 29) ────────────────────────────────────────
    # Beat fires ``enqueue_scheduled_syncs`` every 5 minutes.  The task itself
    # decides which integrations are *due* based on their ``sync_interval_minutes``
    # setting and ``last_synced_at`` timestamp — so the 5-minute tick is just
    # the finest scheduling granularity, not the actual sync cadence.
    #
    # Supported per-integration intervals: 5, 10, 15, 30, 60 minutes.
    # Default (when ``sync_interval_minutes`` is NULL): 60 minutes.
    #
    # ``crontab(minute="*/5")`` is preferred over ``timedelta(minutes=5)`` so
    # ticks land at predictable wall-clock times (:00, :05, :10, …) regardless
    # of when beat last restarted.  After a deploy that bounces beat, the next
    # tick is still the next multiple-of-5 minute rather than ~5 min after
    # restart drift.
    #
    # worker_concurrency is intentionally kept at 1 (Render Starter cap).
    # The in-flight guard in the task prevents pile-up when a single sync runs
    # longer than the tick interval.
    beat_schedule={
        "enqueue-scheduled-syncs-every-5-min": {
            "task": "enqueue_scheduled_syncs",
            "schedule": crontab(minute="*/5"),
        },
    },
)
