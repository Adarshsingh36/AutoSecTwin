"""
Twin Cleanup Manager.

Automatically destroys, per spec:
    - stopped containers (orphaned twin-generator containers left exited/dead)
    - expired twins (TTL passed -- reuses TwinOrchestrator.destroy_twin(),
      so the same teardown path runs whether a twin is destroyed on-demand
      via the API or automatically here)
    - unused networks
    - unused volumes
    - old snapshots (see cleanup/vm_cleanup.py for the documented caveat
      around what "old" can mean given VBoxManage's limitations)

TTL is configurable per-twin at creation time (TwinCreateRequest.ttl_seconds,
defaulting to CleanupSettings.default_ttl_seconds) -- this manager only
acts once that deadline has passed.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Iterable, Optional

import structlog

from twin_generator.cleanup.config import CleanupSettings
from twin_generator.cleanup.docker_cleanup import (
    prune_unused_networks,
    prune_unused_volumes,
    remove_orphaned_stopped_containers,
)
from twin_generator.cleanup.schemas import CleanupReport
from twin_generator.cleanup.vm_cleanup import prune_non_baseline_snapshots
from twin_generator.services.orchestrator import TwinOrchestrator
from twin_generator.services.twin_repository import TwinRepository
from twin_generator.vm_engine.config import VMEngineSettings

if TYPE_CHECKING:
    from docker import DockerClient
    from sqlalchemy.orm import Session

logger = structlog.get_logger(__name__)


class CleanupManager:
    def __init__(
        self,
        session: "Session",
        orchestrator: TwinOrchestrator,
        docker_client: "DockerClient",
        vm_settings: Optional[VMEngineSettings] = None,
        settings: Optional[CleanupSettings] = None,
    ) -> None:
        self._repo = TwinRepository(session)
        self._orchestrator = orchestrator
        self._docker_client = docker_client
        self._vm_settings = vm_settings or VMEngineSettings()
        self._settings = settings or CleanupSettings()

    def run_sweep(self, vm_names: Optional[Iterable[str]] = None) -> CleanupReport:
        """Run one full cleanup pass. Each step is best-effort: a failure in
        one step is recorded in the report and does not stop the others.
        """
        report = CleanupReport()

        self._destroy_expired_twins(report)

        if self._settings.remove_orphaned_stopped_containers:
            self._safe_step(
                report, "orphaned_containers", self._remove_orphaned_containers, report
            )
        if self._settings.prune_unused_networks:
            self._safe_step(report, "unused_networks", self._prune_networks, report)
        if self._settings.prune_unused_volumes:
            self._safe_step(report, "unused_volumes", self._prune_volumes, report)
        if self._settings.enable_snapshot_cleanup and vm_names:
            self._safe_step(report, "old_snapshots", self._prune_snapshots, report, vm_names)

        logger.info(
            "cleanup_sweep_complete",
            expired=report.expired_twins_destroyed,
            containers=report.orphaned_containers_removed,
            networks=report.networks_pruned,
            volumes=report.volumes_pruned,
            snapshots=report.snapshots_removed,
            errors=len(report.errors),
        )
        return report

    def _destroy_expired_twins(self, report: CleanupReport) -> None:
        expired = self._repo.list_expired(datetime.now(timezone.utc))
        for twin in expired:
            try:
                self._orchestrator.destroy_twin(twin.id)
                report.expired_twins_destroyed += 1
            except Exception as exc:  # pragma: no cover - one bad twin shouldn't stop the sweep
                logger.warning("expired_twin_destroy_failed", twin_id=twin.id, error=str(exc))
                report.errors.append(f"twin {twin.id}: {exc}")

    def _remove_orphaned_containers(self, report: CleanupReport) -> None:
        report.orphaned_containers_removed = remove_orphaned_stopped_containers(
            self._docker_client
        )

    def _prune_networks(self, report: CleanupReport) -> None:
        report.networks_pruned = prune_unused_networks(self._docker_client)

    def _prune_volumes(self, report: CleanupReport) -> None:
        report.volumes_pruned = prune_unused_volumes(self._docker_client)

    def _prune_snapshots(self, report: CleanupReport, vm_names: Iterable[str]) -> None:
        total = 0
        for vm_name in vm_names:
            total += prune_non_baseline_snapshots(vm_name, self._vm_settings, self._settings)
        report.snapshots_removed = total

    @staticmethod
    def _safe_step(report: CleanupReport, name: str, fn, *args) -> None:
        try:
            fn(*args)
        except Exception as exc:  # pragma: no cover - best-effort, logged not raised
            logger.warning("cleanup_step_failed", step=name, error=str(exc))
            report.errors.append(f"{name}: {exc}")
