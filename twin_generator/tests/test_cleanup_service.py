"""
Unit tests for CleanupManager.run_sweep(). Uses the real in-memory DB (so
expired-twin lookup is exercised for real) with the orchestrator and Docker
client mocked out.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

from sqlalchemy.orm import Session
import pytest


from twin_generator.cleanup.config import CleanupSettings
from twin_generator.cleanup.service import CleanupManager
from twin_generator.models.twin_instance import TwinInstance
from twin_generator.utils.enums import EnvironmentType, HealthStatus, TwinStatus


def _make_twin(destroy_at: datetime, status: str = TwinStatus.RUNNING.value) -> TwinInstance:
    return TwinInstance(
        uuid=uuid.uuid4(),
        cve="CVE-2021-44228",
        status=status,
        environment=EnvironmentType.DOCKER.value,
        health=HealthStatus.HEALTHY.value,
        created_at=datetime.now(timezone.utc) - timedelta(hours=2),
        destroy_at=destroy_at,
    )


@pytest.fixture
@pytest.fixture
def manager(
    session: Session,
    orchestrator: MagicMock,
    docker_client: MagicMock,
) -> CleanupManager:
    settings = CleanupSettings(enable_snapshot_cleanup=False)
    return CleanupManager(session, orchestrator, docker_client, settings=settings)

@pytest.fixture
def docker_client() -> MagicMock:
    client = MagicMock()
    client.containers.list.return_value = []
    client.networks.prune.return_value = {}
    client.volumes.prune.return_value = {}
    return client


@pytest.fixture
@pytest.fixture
def manager(
    session: Session,
    orchestrator: MagicMock,
    docker_client: MagicMock,
) -> CleanupManager:
    settings = CleanupSettings(enable_snapshot_cleanup=False)
    return CleanupManager(
        session,
        orchestrator,
        docker_client,
        settings=settings,
    )


def test_sweep_destroys_expired_twins(
    manager: CleanupManager,
    orchestrator: MagicMock,
    session: Session,
) -> None:
    expired = _make_twin(
        destroy_at=datetime.now(timezone.utc) - timedelta(minutes=5)
    )
    still_active = _make_twin(
        destroy_at=datetime.now(timezone.utc) + timedelta(hours=1)
    )

    session.add_all([expired, still_active])
    session.flush()

    report = manager.run_sweep()

    assert report.expired_twins_destroyed == 1
    orchestrator.destroy_twin.assert_called_once_with(expired.id)


def test_sweep_skips_already_destroyed_twins(
    manager: CleanupManager,
    orchestrator: MagicMock,
    session: Session,
) -> None:
    already_gone = _make_twin(
        destroy_at=datetime.now(timezone.utc) - timedelta(days=1),
        status=TwinStatus.DESTROYED.value,
    )

    session.add(already_gone)
    session.flush()

    report = manager.run_sweep()

    assert report.expired_twins_destroyed == 0
    orchestrator.destroy_twin.assert_not_called()


def test_sweep_records_error_and_continues_when_one_twin_fails(
    manager: CleanupManager,
    orchestrator: MagicMock,
    session: Session,
) -> None:
    expired_a = _make_twin(
        destroy_at=datetime.now(timezone.utc) - timedelta(minutes=5)
    )
    expired_b = _make_twin(
        destroy_at=datetime.now(timezone.utc) - timedelta(minutes=5)
    )

    session.add_all([expired_a, expired_b])
    session.flush()

    orchestrator.destroy_twin.side_effect = [
        RuntimeError("docker daemon unreachable"),
        None,
    ]

    report = manager.run_sweep()

    assert report.expired_twins_destroyed == 1
    assert len(report.errors) == 1
    assert orchestrator.destroy_twin.call_count == 2


def test_sweep_prunes_docker_resources(
    manager: CleanupManager,
    docker_client: MagicMock,
    session: Session,
) -> None:
    stopped_container = MagicMock()
    docker_client.containers.list.return_value = [stopped_container]
    docker_client.networks.prune.return_value = {
        "NetworksDeleted": ["twin-net-a"]
    }
    docker_client.volumes.prune.return_value = {
        "VolumesDeleted": ["vol-a"]
    }

    report = manager.run_sweep()

    assert report.orphaned_containers_removed == 1
    assert report.networks_pruned == 1
    assert report.volumes_pruned == 1

    stopped_container.remove.assert_called_once_with(force=True)


def test_sweep_respects_disabled_toggles(
    session: Session,
    orchestrator: MagicMock,
    docker_client: MagicMock,
) -> None:
    settings = CleanupSettings(
        remove_orphaned_stopped_containers=False,
        prune_unused_networks=False,
        prune_unused_volumes=False,
    )

    manager = CleanupManager(
        session,
        orchestrator,
        docker_client,
        settings=settings,
    )

    manager.run_sweep()

    docker_client.containers.list.assert_not_called()
    docker_client.networks.prune.assert_not_called()
    docker_client.volumes.prune.assert_not_called()


def test_sweep_prunes_snapshots_when_enabled_and_vm_names_given(
    session: Session,
    orchestrator: MagicMock,
    docker_client: MagicMock,
) -> None:
    settings = CleanupSettings(enable_snapshot_cleanup=True)

    manager = CleanupManager(
        session,
        orchestrator,
        docker_client,
        settings=settings,
    )

    with patch(
        "twin_generator.cleanup.service.prune_non_baseline_snapshots",
        new=MagicMock(return_value=3),
    ) as mocked_prune:
        report = manager.run_sweep(vm_names=["vuln-vm-1"])

    assert report.snapshots_removed == 3
    mocked_prune.assert_called_once()


def test_sweep_skips_snapshot_cleanup_when_disabled(
    session: Session,
    orchestrator: MagicMock,
    docker_client: MagicMock,
) -> None:
    settings = CleanupSettings(enable_snapshot_cleanup=False)

    manager = CleanupManager(
        session,
        orchestrator,
        docker_client,
        settings=settings,
    )

    with patch(
        "twin_generator.cleanup.service.prune_non_baseline_snapshots",
        new=MagicMock(),
    ) as mocked_prune:
        report = manager.run_sweep(vm_names=["vuln-vm-1"])

    assert report.snapshots_removed == 0
    mocked_prune.assert_not_called()