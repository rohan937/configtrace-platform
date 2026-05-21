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
)
