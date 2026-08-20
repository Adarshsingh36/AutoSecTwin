"""
Docker resource metrics collection, via docker-sdk-python only (no shell
commands, consistent with the Docker Twin Engine's constraint).
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

import structlog

from twin_generator.monitor.schemas import TwinMetrics
from twin_generator.utils.enums import HealthStatus
from twin_generator.utils.exceptions import ContainerRestartError, MetricsCollectionError

if TYPE_CHECKING:
    from docker import DockerClient

logger = structlog.get_logger(__name__)


def _cpu_percent(stats: dict) -> float:
    """Standard `docker stats` CPU% formula."""
    cpu_stats = stats.get("cpu_stats", {})
    precpu_stats = stats.get("precpu_stats", {})

    cpu_delta = cpu_stats.get("cpu_usage", {}).get("total_usage", 0) - precpu_stats.get(
        "cpu_usage", {}
    ).get("total_usage", 0)
    system_delta = cpu_stats.get("system_cpu_usage", 0) - precpu_stats.get("system_cpu_usage", 0)

    if system_delta <= 0 or cpu_delta < 0:
        return 0.0

    num_cpus = cpu_stats.get("online_cpus") or len(
        cpu_stats.get("cpu_usage", {}).get("percpu_usage") or [1]
    )
    return (cpu_delta / system_delta) * num_cpus * 100.0


def _network_totals(stats: dict) -> tuple[int, int]:
    networks = stats.get("networks", {}) or {}
    rx = sum(iface.get("rx_bytes", 0) for iface in networks.values())
    tx = sum(iface.get("tx_bytes", 0) for iface in networks.values())
    return rx, tx


def _disk_io_total(stats: dict) -> int:
    entries = stats.get("blkio_stats", {}).get("io_service_bytes_recursive") or []
    return sum(entry.get("value", 0) for entry in entries)


class DockerStatsCollector:
    """Collects a one-shot resource snapshot for a running Docker twin."""

    def __init__(self, docker_client: "DockerClient") -> None:
        self._client = docker_client

    def collect(self, container_name: str, twin_uuid: str) -> TwinMetrics:
        try:
            container = self._client.containers.get(container_name)
            stats = container.stats(stream=False)
        except Exception as exc:
            raise MetricsCollectionError(container_name, str(exc)) from exc

        rx_bytes, tx_bytes = _network_totals(stats)
        memory_stats = stats.get("memory_stats", {})

        status = container.status
        health_label = container.attrs.get("State", {}).get("Health", {}).get("Status")
        if health_label == "healthy":
            health = HealthStatus.HEALTHY
        elif health_label == "unhealthy":
            health = HealthStatus.UNHEALTHY
        else:
            health = HealthStatus.HEALTHY if status == "running" else HealthStatus.UNHEALTHY

        return TwinMetrics(
            twin_uuid=twin_uuid,
            environment="docker",
            container_or_vm_status=status,
            health=health,
            cpu_percent=round(_cpu_percent(stats), 2),
            memory_usage_bytes=memory_stats.get("usage"),
            memory_limit_bytes=memory_stats.get("limit"),
            disk_io_bytes=_disk_io_total(stats),
            network_rx_bytes=rx_bytes,
            network_tx_bytes=tx_bytes,
        )

    def restart(self, container_name: str) -> None:
        try:
            container = self._client.containers.get(container_name)
            container.restart()
            logger.info("container_auto_restarted", container_name=container_name)
        except Exception as exc:
            raise ContainerRestartError(container_name, str(exc)) from exc
