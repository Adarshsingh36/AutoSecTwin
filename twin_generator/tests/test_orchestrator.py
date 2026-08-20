"""
Unit tests for TwinOrchestrator's coordination logic. All of its
dependencies (registry, docker engine, vm engine, legacy service) are
mocked out; only the orchestrator's own decisions are under test.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from sqlalchemy.orm import Session

from twin_generator.docker_engine.schemas import DockerProvisionResult
from twin_generator.schemas.legacy_profile import LegacyCheckResponse
from twin_generator.schemas.twin_instance import TwinCreateRequest
from twin_generator.services.orchestrator import TwinOrchestrator
from twin_generator.utils.enums import (
    EnvironmentType,
    HealthStatus,
    LegacyFlag,
    TwinStatus,
)
from twin_generator.utils.exceptions import (
    NoRegistryEntryForCveError,
    TwinProvisioningError,
)
from twin_generator.vm_engine.schemas import VMProvisionResult


def _docker_result(healthy: bool = True) -> DockerProvisionResult:
    return DockerProvisionResult(
        container_id="c123",
        container_name="twin-abc",
        image="vulhub/log4j",
        hostname="twin-abc",
        network_name="twin-net-abc",
        network_id="net123",
        ip_address="172.20.0.5",
        healthy=healthy,
        status="running",
    )


def _vm_result(healthy: bool = True) -> VMProvisionResult:
    return VMProvisionResult(
        vm_name="twin-vm-abc",
        snapshot_name="clean",
        network_name="twin-vm-net-abc",
        ip_address="10.10.0.5",
        status="running",
        healthy=healthy,
    )


@pytest.fixture
def registry_service() -> MagicMock:
    return MagicMock()


@pytest.fixture
def docker_engine() -> MagicMock:
    return MagicMock()


@pytest.fixture
def vm_engine() -> MagicMock:
    return MagicMock()


@pytest.fixture
def legacy_service() -> MagicMock:
    return MagicMock()


@pytest.fixture
def orchestrator(
    db_session: Session,
    registry_service: MagicMock,
    docker_engine: MagicMock,
    vm_engine: MagicMock,
    legacy_service: MagicMock,
) -> TwinOrchestrator:
    return TwinOrchestrator(
        db_session,
        registry_service,
        docker_engine,
        vm_engine,
        legacy_service=legacy_service,
    )


def test_create_twin_docker_path_when_registry_has_image(
    orchestrator: TwinOrchestrator,
    registry_service: MagicMock,
    docker_engine: MagicMock,
    vm_engine: MagicMock,
) -> None:
    registry_service.resolve_image_for_cve.return_value = MagicMock(
        image="vulhub/log4j"
    )
    docker_engine.provision_twin.return_value = _docker_result(healthy=True)

    twin = orchestrator.create_twin(
        TwinCreateRequest(cve="CVE-2021-44228")
    )

    assert twin.environment == EnvironmentType.DOCKER.value
    assert twin.status == TwinStatus.RUNNING.value
    assert twin.health == HealthStatus.HEALTHY.value
    assert twin.ip_address == "172.20.0.5"
    vm_engine.provision_twin.assert_not_called()


def test_create_twin_falls_back_to_vm_when_no_registry_entry(
    orchestrator: TwinOrchestrator,
    registry_service: MagicMock,
    vm_engine: MagicMock,
) -> None:
    registry_service.resolve_image_for_cve.side_effect = (
        NoRegistryEntryForCveError("CVE-UNKNOWN")
    )
    vm_engine.provision_twin.return_value = _vm_result(healthy=True)

    twin = orchestrator.create_twin(
        TwinCreateRequest(cve="CVE-UNKNOWN")
    )

    assert twin.environment == EnvironmentType.VM.value
    assert twin.status == TwinStatus.RUNNING.value
    assert twin.vm_name is not None


def test_create_twin_forced_vm_environment_skips_registry(
    orchestrator: TwinOrchestrator,
    registry_service: MagicMock,
    vm_engine: MagicMock,
) -> None:
    vm_engine.provision_twin.return_value = _vm_result(healthy=True)

    twin = orchestrator.create_twin(
        TwinCreateRequest(
            cve="CVE-2021-44228",
            environment=EnvironmentType.VM,
        )
    )

    assert twin.environment == EnvironmentType.VM.value
    registry_service.resolve_image_for_cve.assert_not_called()


def test_create_twin_marks_degraded_when_unhealthy(
    orchestrator: TwinOrchestrator,
    registry_service: MagicMock,
    docker_engine: MagicMock,
) -> None:
    registry_service.resolve_image_for_cve.return_value = MagicMock(
        image="vulhub/log4j"
    )
    docker_engine.provision_twin.return_value = _docker_result(
        healthy=False
    )

    twin = orchestrator.create_twin(
        TwinCreateRequest(cve="CVE-2021-44228")
    )

    assert twin.status == TwinStatus.DEGRADED.value
    assert twin.health == HealthStatus.UNHEALTHY.value


def test_create_twin_applies_legacy_flag_when_software_given(
    orchestrator: TwinOrchestrator,
    registry_service: MagicMock,
    docker_engine: MagicMock,
    legacy_service: MagicMock,
) -> None:
    registry_service.resolve_image_for_cve.return_value = MagicMock(
        image="vulhub/log4j"
    )
    docker_engine.provision_twin.return_value = _docker_result(
        healthy=True
    )

    legacy_service.check.return_value = LegacyCheckResponse(
        software="Windows Server",
        version="2003",
        classification=LegacyFlag.LEGACY,
        matched_profile_id=1,
    )

    twin = orchestrator.create_twin(
        TwinCreateRequest(
            cve="CVE-2021-44228",
            software="Windows Server",
            version="2003",
        )
    )

    assert twin.legacy_flag == LegacyFlag.LEGACY.value
    legacy_service.check.assert_called_once_with(
        "Windows Server",
        "2003",
    )
    assert twin.status == TwinStatus.RUNNING.value


def test_create_twin_failure_marks_failed_and_raises(
    orchestrator: TwinOrchestrator,
    registry_service: MagicMock,
    docker_engine: MagicMock,
) -> None:
    registry_service.resolve_image_for_cve.return_value = MagicMock(
        image="vulhub/log4j"
    )
    docker_engine.provision_twin.side_effect = RuntimeError(
        "docker daemon unreachable"
    )

    with pytest.raises(TwinProvisioningError):
        orchestrator.create_twin(
            TwinCreateRequest(cve="CVE-2021-44228")
        )


def test_destroy_twin_calls_docker_teardown(
    orchestrator: TwinOrchestrator,
    registry_service: MagicMock,
    docker_engine: MagicMock,
) -> None:
    registry_service.resolve_image_for_cve.return_value = MagicMock(
        image="vulhub/log4j"
    )
    docker_engine.provision_twin.return_value = _docker_result(True)

    twin = orchestrator.create_twin(
        TwinCreateRequest(cve="CVE-2021-44228")
    )

    destroyed = orchestrator.destroy_twin(twin.id)

    assert destroyed.status == TwinStatus.DESTROYED.value
    docker_engine.destroy_twin.assert_called_once_with(
        str(twin.uuid),
        "twin-net-abc",
    )


def test_destroy_twin_calls_vm_poweroff(
    orchestrator: TwinOrchestrator,
    vm_engine: MagicMock,
) -> None:
    vm_engine.provision_twin.return_value = _vm_result(True)

    twin = orchestrator.create_twin(
        TwinCreateRequest(
            cve="CVE-2021-44228",
            environment=EnvironmentType.VM,
        )
    )

    orchestrator.destroy_twin(twin.id)

    vm_engine.power_off.assert_called_once_with(twin.vm_name)