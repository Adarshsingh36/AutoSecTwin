"""
Celery application for AutoSecTwin's background orchestration work.

This is the concrete implementation of what core/config.py's
TASK_QUEUE_BACKEND documentation describes: when TASK_QUEUE_BACKEND is
"celery", POST /orchestration/run sends work here instead of running it
in the same process as the HTTP request.

CELERY_TASK_ALWAYS_EAGER makes tasks execute synchronously, in-process,
with no broker required -- this is what the test suite and local/demo runs
use so a live Redis instance is never a hard requirement to exercise the
orchestration route.
"""

from celery import Celery

from core.config import settings

celery_app = Celery(
    "autosectwin",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
)

celery_app.conf.update(
    task_always_eager=settings.CELERY_TASK_ALWAYS_EAGER,
    task_eager_propagates=settings.CELERY_TASK_ALWAYS_EAGER,
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
)

# Import task modules so they register with this app instance.
celery_app.autodiscover_tasks(["services.orchestration", "services.remediation"])
