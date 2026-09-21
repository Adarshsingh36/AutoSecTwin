from celery import Celery

from core.config import settings

celery_app = Celery(
    "autosectwin",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=["services.tasks.orchestration_tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_always_eager=settings.CELERY_TASK_ALWAYS_EAGER,
    task_eager_propagates=settings.CELERY_TASK_ALWAYS_EAGER,
    # Long-running closed-loop jobs (twin provisioning + Metasploit
    # execution + remediation + revalidation) can legitimately take
    # minutes; don't let the broker consider the worker dead prematurely.
    broker_transport_options={"visibility_timeout": 3600},
    task_acks_late=True,
    worker_prefetch_multiplier=1,
)
