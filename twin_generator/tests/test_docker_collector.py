"""
Unit tests for DockerStatsCollector. No real Docker daemon involved.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from twin_generator.monitor.docker_collector import DockerStatsCollector
from twin_generator.utils.enums import HealthStatus
from twin_generator.utils.exceptions import ContainerRestartError, MetricsCollectionError


def _raw_stats(
    cpu_delta: int = 20,
    system_delta: int = 200,
    online_cpus: int = 2,
) -> dict:
    return {
        "cpu_stats": {
            "cpu_usage": {"total_usage": 1000 + cpu_delta},
            "system_cpu_usage": 100000 + system_delta,
            "online_cpus": online_cpus,
        },
        "precpu_stats": {
            "cpu_usage": {"total_usage": 1000},
            "system_cpu_usage": 100000,
        },
        "memory_stats": {
            "usage": 52428800,
            "limit": 209715200,
        },
        "networks": {
            "eth0": {
                "rx_bytes": 1000,
                "tx_bytes": 2000,
            }
        },
        "blkio_stats": {
            "io_service_bytes_recursive": [
                {"value": 4096},
                {"value": 8192},
            ]
        },
    }


@pytest.fixture
def docker_client() -> MagicMock:
    return MagicMock()


def test_collect_healthy_container_with_healthcheck(
    docker_client: MagicMock,
) -> None:
    container = MagicMock(status="running")
    container.attrs = {"State": {"Health": {"Status": "healthy"}}}
    container.stats.return_value = _raw_stats()
    docker_client.containers.get.return_value = container

    collector = DockerStatsCollector(docker_client)
    metrics = collector.collect("twin-abc", "abc-uuid")

    assert metrics.health == HealthStatus.HEALTHY
    assert metrics.container_or_vm_status == "running"
    assert metrics.cpu_percent == pytest.approx(20.0)
    assert metrics.memory_usage_bytes == 52428800
    assert metrics.network_rx_bytes == 1000
    assert metrics.network_tx_bytes == 2000
    assert metrics.disk_io_bytes == 12288


def test_collect_falls_back_to_status_when_no_healthcheck(
    docker_client: MagicMock,
) -> None:
    container = MagicMock(status="exited")
    container.attrs = {"State": {}}
    container.stats.return_value = _raw_stats()
    docker_client.containers.get.return_value = container

    collector = DockerStatsCollector(docker_client)
    metrics = collector.collect("twin-abc", "abc-uuid")

    assert metrics.health == HealthStatus.UNHEALTHY


def test_collect_raises_on_docker_error(
    docker_client: MagicMock,
) -> None:
    docker_client.containers.get.side_effect = RuntimeError(
        "no such container"
    )

    collector = DockerStatsCollector(docker_client)

    with pytest.raises(MetricsCollectionError):
        collector.collect("twin-missing", "abc-uuid")


def test_restart_calls_docker_restart(
    docker_client: MagicMock,
) -> None:
    container = MagicMock()
    docker_client.containers.get.return_value = container

    collector = DockerStatsCollector(docker_client)
    collector.restart("twin-abc")

    container.restart.assert_called_once()


def test_restart_raises_on_failure(
    docker_client: MagicMock,
) -> None:
    docker_client.containers.get.side_effect = RuntimeError("gone")

    collector = DockerStatsCollector(docker_client)

    with pytest.raises(ContainerRestartError):
        collector.restart("twin-abc")