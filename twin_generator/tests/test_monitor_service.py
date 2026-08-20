"""
Unit tests for TwinMonitorService. Collectors and the VM engine are
mocked; the DB session is real (in-memory) so TwinInstance/TwinLog
persistence is verified for real.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
from sqlalchemy.orm import Session

from twin_generator.models.twin_instance import TwinInstance
from twin_generator.monitor.config import MonitorSettings
from twin_generator.monitor.schemas import TwinMetrics
from twin_generator.monitor.service import TwinMonitorService
from twin_generator.utils.enums import EnvironmentType, HealthStatus, TwinStatus


def _make_twin(
    environment: EnvironmentType,
    health: HealthStatus = HealthStatus.HEALTHY,
) -> TwinInstance:
    return TwinInstance(
        uuid=uuid.uuid4(),
        cve="CVE-2021-44228",
        status=TwinStatus.RUNNING.value,
        environment=environment.value,
        health=health.value,
        created_at=datetime.now(timezone.utc),
        destroy_at=datetime.now(timezone.utc) + timedelta(hours=1),
        vm_name="twin-vm-abc" if environment == EnvironmentType.VM else None,
    )


@pytest.fixture
def docker_collector() -> MagicMock:
    return MagicMock()


@pytest.fixture
def vm_collector() -> MagicMock:
    return MagicMock()


@pytest.fixture
def vm_engine() -> MagicMock:
    return MagicMock()


@pytest.fixture
def monitor(
    session: Session,
    docker_collector: MagicMock,
    vm_collector: MagicMock,
    vm_engine: MagicMock,
) -> TwinMonitorService:
    return TwinMonitorService(
        session,
        docker_collector,
        vm_collector,
        vm_engine,
        MonitorSettings(auto_restart_failed_containers=True),
    )


def test_check_docker_twin_no_restart_when_healthy(
    monitor: TwinMonitorService,
    docker_collector: MagicMock,
    session: Session,
) -> None:
    twin = TwinInstance(
        uuid=uuid.uuid4(),
        cve="CVE-2021-44228",
        status=TwinStatus.RUNNING.value,
        environment=EnvironmentType.DOCKER.value,
        health=HealthStatus.HEALTHY.value,
        created_at=datetime.now(timezone.utc),
        destroy_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )

    session.add(twin)
    session.flush()

    docker_collector.collect.return_value = TwinMetrics(
        twin_uuid=str(twin.uuid),
        environment="docker",
        container_or_vm_status="running",
        health=HealthStatus.HEALTHY,
    )

    metrics = monitor.check_twin(twin)

    assert metrics.was_auto_restarted is False
    docker_collector.restart.assert_not_called()


def test_check_docker_twin_auto_restarts_exited_container(
    monitor: TwinMonitorService,
    docker_collector: MagicMock,
    session: Session,
) -> None:
    twin = TwinInstance(
        uuid=uuid.uuid4(),
        cve="CVE-2021-44228",
        status=TwinStatus.RUNNING.value,
        environment=EnvironmentType.DOCKER.value,
        health=HealthStatus.HEALTHY.value,
        created_at=datetime.now(timezone.utc),
        destroy_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )

    session.add(twin)
    session.flush()

    failed_metrics = TwinMetrics(
        twin_uuid=str(twin.uuid),
        environment="docker",
        container_or_vm_status="exited",
        health=HealthStatus.UNHEALTHY,
    )

    recovered_metrics = TwinMetrics(
        twin_uuid=str(twin.uuid),
        environment="docker",
        container_or_vm_status="running",
        health=HealthStatus.HEALTHY,
    )

    docker_collector.collect.side_effect = [
        failed_metrics,
        recovered_metrics,
    ]

    metrics = monitor.check_twin(twin)

    docker_collector.restart.assert_called_once_with(
        f"twin-{twin.uuid}"
    )
    assert metrics.was_auto_restarted is True
    assert metrics.health == HealthStatus.HEALTHY


def test_check_docker_twin_does_not_restart_when_disabled(
    session: Session,
    docker_collector: MagicMock,
    vm_collector: MagicMock,
    vm_engine: MagicMock,
) -> None:
    settings = MonitorSettings(
        auto_restart_failed_containers=False
    )

    monitor = TwinMonitorService(
        session,
        docker_collector,
        vm_collector,
        vm_engine,
        settings,
    )

    twin = TwinInstance(
        uuid=uuid.uuid4(),
        cve="CVE-1",
        status=TwinStatus.RUNNING.value,
        environment=EnvironmentType.DOCKER.value,
        health=HealthStatus.HEALTHY.value,
        created_at=datetime.now(timezone.utc),
        destroy_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )

    session.add(twin)
    session.flush()

    docker_collector.collect.return_value = TwinMetrics(
        twin_uuid=str(twin.uuid),
        environment="docker",
        container_or_vm_status="exited",
        health=HealthStatus.UNHEALTHY,
    )

    monitor.check_twin(twin)

    docker_collector.restart.assert_not_called()


def test_check_vm_twin_uses_vm_engine_status(
    monitor: TwinMonitorService,
    vm_collector: MagicMock,
    vm_engine: MagicMock,
    session: Session,
) -> None:
    twin = TwinInstance(
        uuid=uuid.uuid4(),
        cve="CVE-1",
        status=TwinStatus.RUNNING.value,
        environment=EnvironmentType.VM.value,
        health=HealthStatus.HEALTHY.value,
        vm_name="twin-vm-abc",
        created_at=datetime.now(timezone.utc),
        destroy_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )

    session.add(twin)
    session.flush()

    vm_engine.get_vm_status.return_value = "running"

    vm_collector.collect.return_value = TwinMetrics(
        twin_uuid=str(twin.uuid),
        environment="vm",
        container_or_vm_status="running",
        health=HealthStatus.HEALTHY,
    )

    monitor.check_twin(twin)

    vm_engine.get_vm_status.assert_called_once_with(
        "twin-vm-abc"
    )

    vm_collector.collect.assert_called_once_with(
        "twin-vm-abc",
        str(twin.uuid),
        "running",
    )


def test_sync_updates_twin_status_when_health_degrades(
    monitor: TwinMonitorService,
    docker_collector: MagicMock,
    session: Session,
) -> None:
    twin = TwinInstance(
        uuid=uuid.uuid4(),
        cve="CVE-1",
        status=TwinStatus.RUNNING.value,
        environment=EnvironmentType.DOCKER.value,
        health=HealthStatus.HEALTHY.value,
        created_at=datetime.now(timezone.utc),
        destroy_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )

    session.add(twin)
    session.flush()

    docker_collector.collect.return_value = TwinMetrics(
        twin_uuid=str(twin.uuid),
        environment="docker",
        container_or_vm_status="running",
        health=HealthStatus.UNHEALTHY,
    )

    monitor.check_twin(twin)

    assert twin.health == HealthStatus.UNHEALTHY.value
    assert twin.status == TwinStatus.DEGRADED.value