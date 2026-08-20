"""
Periodic Twin Monitor loop.

A plain asyncio loop rather than a Celery task or FastAPI BackgroundTasks
job by itself -- per the tech stack ("Celery OR FastAPI BackgroundTasks"),
whichever the rest of AutoSecTwin already uses for background workers can
schedule `run_monitor_once()` (single pass, easy to wrap in either) or call
`run_monitor_loop()` directly as a long-lived task at application startup.
Nothing here assumes or redefines that choice.
"""

from __future__ import annotations

import time
from threading import Event
from typing import TYPE_CHECKING, Callable, Optional

import structlog

from twin_generator.monitor.config import MonitorSettings
from twin_generator.monitor.service import TwinMonitorService
from twin_generator.services.twin_repository import TwinRepository
from twin_generator.utils.enums import TwinStatus

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

logger = structlog.get_logger(__name__)

_ACTIVE_STATUSES = (TwinStatus.RUNNING.value, TwinStatus.DEGRADED.value)


def run_monitor_once(session: "Session", monitor: TwinMonitorService) -> int:
    """Check every currently-active twin once. Returns the number checked.

    Failures on individual twins are logged and skipped rather than
    aborting the whole pass, so one bad twin doesn't stop monitoring for
    the rest.
    """
    repo = TwinRepository(session)
    twins = repo.list_all()
    checked = 0

    for twin in twins:
        if twin.status not in _ACTIVE_STATUSES:
            continue
        try:
            monitor.check_twin(twin)
            checked += 1
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "twin_monitor_pass_skipped_twin",
                twin_id=twin.id,
                error=str(exc),
            )

    return checked


def run_monitor_loop(
    session_factory: Callable[[], "Session"],
    monitor_factory: Callable[["Session"], TwinMonitorService],
    settings: Optional[MonitorSettings] = None,
    stop_event: Optional[Event] = None,
) -> None:
    """Run run_monitor_once() forever (or until stop_event is set), sleeping
    `poll_interval_seconds` between passes. Intended to be launched as a
    single long-lived background task at application startup.
    """
    settings = settings or MonitorSettings()
    stop_event = stop_event or Event()

    while not stop_event.is_set():
        with session_factory() as session:
            monitor = monitor_factory(session)
            checked = run_monitor_once(session, monitor)
            logger.debug(
                "twin_monitor_pass_complete",
                twins_checked=checked,
            )

        # Wait until either the stop event is set or the timeout expires.
        stop_event.wait(timeout=settings.poll_interval_seconds)