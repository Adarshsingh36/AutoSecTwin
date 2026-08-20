"""
Periodic Twin Cleanup Manager sweep loop.

Same shape as monitor/scheduler.py: a plain blocking loop that whichever
background-worker mechanism the rest of AutoSecTwin already uses (Celery or
FastAPI BackgroundTasks) can schedule `run_cleanup_once()` on, or run
`run_cleanup_loop()` directly as a long-lived startup task.
"""

from __future__ import annotations

import time
from threading import Event
from typing import Callable, Iterable, Optional, TYPE_CHECKING

import structlog

from twin_generator.cleanup.config import CleanupSettings
from twin_generator.cleanup.schemas import CleanupReport
from twin_generator.cleanup.service import CleanupManager

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

logger = structlog.get_logger(__name__)


def run_cleanup_once(
    manager: CleanupManager,
    vm_names: Optional[Iterable[str]] = None,
) -> CleanupReport:
    """Run a single cleanup sweep."""
    return manager.run_sweep(vm_names=vm_names)


def run_cleanup_loop(
    session_factory: Callable[[], "Session"],
    manager_factory: Callable[["Session"], CleanupManager],
    vm_names_provider: Optional[Callable[[], Iterable[str]]] = None,
    settings: Optional[CleanupSettings] = None,
    stop_event: Optional[Event] = None,
) -> None:
    """
    Run run_cleanup_once() forever (or until stop_event is set), sleeping
    `sweep_interval_seconds` between passes.
    """
    settings = settings or CleanupSettings()
    stop_event = stop_event or Event()

    while not stop_event.is_set():
        try:
            with session_factory() as session:
                manager = manager_factory(session)
                vm_names = vm_names_provider() if vm_names_provider else None

                report = run_cleanup_once(manager, vm_names=vm_names)

                logger.debug(
                    "cleanup_sweep_pass_complete",
                    expired=report.expired_twins_destroyed,
                    errors=len(report.errors),
                )

        except Exception:
            logger.exception("cleanup_sweep_failed")

        # Wait until either the stop event is set or the timeout expires.
        stop_event.wait(timeout=settings.sweep_interval_seconds)