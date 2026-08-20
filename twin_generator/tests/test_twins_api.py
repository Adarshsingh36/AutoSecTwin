"""
Integration tests for the Twin Orchestrator's HTTP API. Runs against the
real registry/legacy services and a real in-memory DB; only the Docker and
VM engines are mocked (no daemon or VirtualBox available in this
environment).
"""

from __future__ import annotations

from typing import Generator
from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from twin_generator.api.deps import get_orchestrator
from twin_generator.docker_engine.schemas import DockerProvisionResult
from twin_generator.legacy.service import LegacyProfilerService
from twin_generator.models.twin_registry import TwinRegistry
from twin_generator.registry.service import RegistryService
from twin_generator.services.orchestrator import TwinOrchestrator


@pytest.fixture
def mock_docker_engine() -> MagicMock:
    engine = MagicMock()

    engine.provision_twin.return_value = DockerProvisionResult(
        container_id="c123",
        container_name="twin-abc",
        image="vulhub/log4j",
        hostname="twin-abc",
        network_name="twin-net-abc",
        network_id="net123",
        ip_address="172.20.0.5",
        healthy=True,
        status="running",
    )

    return engine


@pytest.fixture
def client_with_mocked_engines(
    app: FastAPI,
    db_session: Session,
    mock_docker_engine: MagicMock,
) -> Generator[TestClient, None, None]:

    def _override_get_orchestrator() -> TwinOrchestrator:
        return TwinOrchestrator(
            db_session,
            RegistryService(db_session),
            mock_docker_engine,
            MagicMock(),
            legacy_service=LegacyProfilerService(db_session),
        )

    app.dependency_overrides[get_orchestrator] = _override_get_orchestrator

    with TestClient(app) as client:
        yield client


def test_create_twin_end_to_end(
    client_with_mocked_engines: TestClient,
    db_session: Session,
) -> None:
    db_session.add(
        TwinRegistry(
            cve="CVE-2021-44228",
            image="vulhub/log4j",
        )
    )
    db_session.flush()

    response = client_with_mocked_engines.post(
        "/twins/create",
        json={"cve": "CVE-2021-44228"},
    )

    assert response.status_code == 201

    body = response.json()
    assert body["status"] == "running"
    assert body["environment"] == "docker"
    assert body["ip_address"] == "172.20.0.5"


def test_get_and_list_twins(
    client_with_mocked_engines: TestClient,
    db_session: Session,
) -> None:
    db_session.add(
        TwinRegistry(
            cve="CVE-X",
            image="img/x",
        )
    )
    db_session.flush()

    created = client_with_mocked_engines.post(
        "/twins/create",
        json={"cve": "CVE-X"},
    )

    twin_id = created.json()["id"]

    get_response = client_with_mocked_engines.get(
        f"/twins/{twin_id}"
    )

    assert get_response.status_code == 200
    assert get_response.json()["id"] == twin_id

    list_response = client_with_mocked_engines.get("/twins")

    assert list_response.status_code == 200
    assert any(
        twin["id"] == twin_id
        for twin in list_response.json()
    )


def test_get_twin_health(
    client_with_mocked_engines: TestClient,
    db_session: Session,
) -> None:
    db_session.add(
        TwinRegistry(
            cve="CVE-Y",
            image="img/y",
        )
    )
    db_session.flush()

    created = client_with_mocked_engines.post(
        "/twins/create",
        json={"cve": "CVE-Y"},
    )

    twin_id = created.json()["id"]

    response = client_with_mocked_engines.get(
        f"/twins/{twin_id}/health"
    )

    assert response.status_code == 200
    assert response.json()["health"] == "healthy"


def test_destroy_twin(
    client_with_mocked_engines: TestClient,
    db_session: Session,
    mock_docker_engine: MagicMock,
) -> None:
    db_session.add(
        TwinRegistry(
            cve="CVE-Z",
            image="img/z",
        )
    )
    db_session.flush()

    created = client_with_mocked_engines.post(
        "/twins/create",
        json={"cve": "CVE-Z"},
    )

    twin_id = created.json()["id"]

    response = client_with_mocked_engines.post(
        f"/twins/{twin_id}/destroy"
    )

    assert response.status_code == 200
    assert response.json()["status"] == "destroyed"

    mock_docker_engine.destroy_twin.assert_called_once()


def test_get_missing_twin_returns_404(
    client_with_mocked_engines: TestClient,
) -> None:
    response = client_with_mocked_engines.get(
        "/twins/999999"
    )

    assert response.status_code == 404


def test_create_twin_falls_back_to_vm_without_registry_entry(
    app: FastAPI,
    db_session: Session,
) -> None:
    from twin_generator.vm_engine.schemas import VMProvisionResult

    mock_vm_engine = MagicMock()

    mock_vm_engine.provision_twin.return_value = VMProvisionResult(
        vm_name="twin-vm-x",
        snapshot_name="clean",
        network_name="twin-vm-net-x",
        ip_address="10.10.0.9",
        status="running",
        healthy=True,
    )

    def _override_get_orchestrator() -> TwinOrchestrator:
        return TwinOrchestrator(
            db_session,
            RegistryService(db_session),
            MagicMock(),
            mock_vm_engine,
            legacy_service=LegacyProfilerService(db_session),
        )

    app.dependency_overrides[get_orchestrator] = _override_get_orchestrator

    with TestClient(app) as client:
        response = client.post(
            "/twins/create",
            json={"cve": "CVE-NO-MAPPING"},
        )

    assert response.status_code == 201
    assert response.json()["environment"] == "vm"