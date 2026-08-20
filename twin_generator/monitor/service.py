"""
Twin Monitor.

Tracks CPU, RAM, container/VM status, disk, network, and health for a
running twin, and auto-restarts failed Docker containers -- exactly the two
responsibilities specified. VM twins are reported on but never
auto-restarted (the spec only calls for restarting "failed containers").

This service works on data already available from a TwinInstance row plus
the Docker/VM collectors; it does not decide *when* to run -- that's
monitor/scheduler.py's job (a periodic loop, wired into the project's
existing FastAPI BackgroundTasks/Celery setup).
"""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING, Optional

import structlog
from sqlalchemy.orm import Session
from twin_generator.models.twin_instance import TwinInstance
from twin_generator.monitor.config import MonitorSettings
from twin_generator.monitor.docker_collector import DockerStatsCollector
from twin_generator.monitor.schemas import TwinMetrics
from twin_generator.monitor.vm_collector import VMStatsCollector
from twin_generator.services.twin_repository import TwinRepository
from twin_generator.utils.enums import EnvironmentType, HealthStatus, TwinLogEvent, TwinStatus
from twin_generator.utils.exceptions import ContainerRestartError, MetricsCollectionError
from twin_generator.vm_engine.manager import VMTwinEngine

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

logger = structlog.get_logger(__name__)


class TwinMonitorService:
    def __init__(
        self,
        session: "Session",
        docker_collector: DockerStatsCollector,
        vm_collector: VMStatsCollector,
        vm_engine: Optional[VMTwinEngine] = None,
        settings: Optional[MonitorSettings] = None,
    ) -> None:
        self._repo = TwinRepository(session)
        self._docker_collector = docker_collector
        self._vm_collector = vm_collector
        self._vm_engine = vm_engine or VMTwinEngine()
        self._settings = settings or MonitorSettings()

    def check_twin(self, twin: TwinInstance) -> TwinMetrics:
        """Collect a snapshot for one twin, auto-restarting it first if it's
        a Docker container found in a failed state and auto-restart is on.
        """
        if twin.environment == EnvironmentType.DOCKER.value:
            return self._check_docker_twin(twin)
        return self._check_vm_twin(twin)

    def _check_docker_twin(self, twin: TwinInstance) -> TwinMetrics:
        container_name = f"twin-{twin.uuid}"
        restarted = False

        try:
            metrics = self._docker_collector.collect(container_name, str(twin.uuid))
        except MetricsCollectionError as exc:
            logger.warning("twin_monitor_collect_failed", twin_id=twin.id, error=str(exc))
            self._repo.add_log(twin.id, TwinLogEvent.ERROR, f"monitor_collect_failed: {exc}")
            raise

        if (
            self._settings.auto_restart_failed_containers
            and metrics.container_or_vm_status in self._settings.unhealthy_docker_statuses
        ):
            try:
                self._docker_collector.restart(container_name)
                restarted = True
                self._repo.add_log(
                    twin.id, TwinLogEvent.AUTO_RESTARTED, f"container={container_name}"
                )
                metrics = self._docker_collector.collect(container_name, str(twin.uuid))
            except ContainerRestartError as exc:
                logger.warning("twin_auto_restart_failed", twin_id=twin.id, error=str(exc))
                self._repo.add_log(twin.id, TwinLogEvent.ERROR, f"auto_restart_failed: {exc}")

        if restarted:
            metrics = replace(metrics, was_auto_restarted=True)

        self._sync_twin_health(twin, metrics)
        return metrics

    def _check_vm_twin(self, twin: TwinInstance) -> TwinMetrics:
        vm_name = twin.vm_name or f"twin-vm-{twin.uuid}"
        status = self._vm_engine.get_vm_status(vm_name)
        metrics = self._vm_collector.collect(vm_name, str(twin.uuid), status)
        self._sync_twin_health(twin, metrics)
        return metrics

    def _sync_twin_health(self, twin: TwinInstance, metrics: TwinMetrics) -> None:
        new_health = metrics.health.value
        if twin.health != new_health:
            twin.health = new_health
            twin.status = (
                TwinStatus.RUNNING if metrics.health == HealthStatus.HEALTHY else TwinStatus.DEGRADED
            ).value
            self._repo.save(twin)
            self._repo.add_log(
                twin.id,
                TwinLogEvent.HEALTH_CHECK_PASSED
                if metrics.health == HealthStatus.HEALTHY
                else TwinLogEvent.HEALTH_CHECK_FAILED,
                f"monitor_status={metrics.container_or_vm_status}",
            )
