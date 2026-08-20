import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from fastapi.testclient import TestClient

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from database.base import Base
from database.models.asset import Asset
from database.models.twin import Twin
from database.models.vulnerability import Vulnerability

from api.dependencies import get_db

import main


# ---------------------------------------------------------
# SQLite Test Database
# ---------------------------------------------------------

engine = create_engine(
    "sqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
    future=True,
)

TestingSessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
)


@pytest.fixture(scope="function")
def db():

    Base.metadata.create_all(bind=engine)

    session = TestingSessionLocal()

    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def client(db):

    def override_get_db():
        yield db

    main.app.dependency_overrides[get_db] = override_get_db

    with TestClient(main.app) as c:
        yield c

    main.app.dependency_overrides.clear()


# ---------------------------------------------------------
# Helpers
# ---------------------------------------------------------

def create_asset(db):

    asset = Asset(
        name="Apache Server",
        asset_type="Server",
        hostname="10.0.0.10",
        software="Apache",
        version="2.4.57",
        environment="production",
    )

    db.add(asset)

    db.commit()

    db.refresh(asset)

    return asset


def create_vulnerability(db, asset):

    vulnerability = Vulnerability(
        asset_id=asset.id,
        cve_id="CVE-2025-1111",
        title="Apache Test CVE",
        description="Test vulnerability",
        severity="HIGH",
    )

    db.add(vulnerability)

    db.commit()

    db.refresh(vulnerability)

    return vulnerability


# ---------------------------------------------------------
# Mock Twin Generator Response
# ---------------------------------------------------------

SUCCESS_RESPONSE = {
    "id": 100,
    "uuid": "uuid-1234",
    "status": "running",
    "environment": "docker",
    "ip_address": "172.18.0.5",
    "network": "bridge",
    "twin_image": "ubuntu:22.04",
    "vm_name": "autosectwin",
    "health": "healthy",
    "legacy_flag": "false",
}
# ---------------------------------------------------------
# Provision Success
# ---------------------------------------------------------

def test_provision_success(client, db):

    asset = create_asset(db)
    vulnerability = create_vulnerability(db, asset)

    with patch(
        "integrations.digital_twin.twin_client.DigitalTwinClient.create_twin",
        new_callable=AsyncMock,
    ) as mock_create:

        mock_create.return_value = SUCCESS_RESPONSE
        
        response = client.post(
            "/twins/provision",
            json={
                "vulnerability_id": vulnerability.id,
                "ttl_seconds": 3600,
            },
        )

    assert response.status_code == 200

    body = response.json()

    assert body["status"] == "running"
    assert body["external_twin_id"] == 100
    assert body["external_uuid"] == "uuid-1234"

    twins = db.query(Twin).all()

    assert len(twins) == 1

    twin = twins[0]

    assert twin.asset_id == asset.id
    assert twin.external_twin_id == 100
    assert twin.external_uuid == "uuid-1234"
    assert twin.environment == "docker"
    assert twin.ip_address == "172.18.0.5"
    assert twin.network == "bridge"
    assert twin.twin_image == "ubuntu:22.04"
    assert twin.vm_name == "autosectwin"
    assert twin.health == "healthy"
    assert twin.status == "running"

    mock_create.assert_awaited_once()


# ---------------------------------------------------------
# Twin Generator Failure
# ---------------------------------------------------------

def test_generator_failure(client, db):

    asset = create_asset(db)
    vulnerability = create_vulnerability(db, asset)

    with patch(
        "integrations.digital_twin.twin_client.DigitalTwinClient.create_twin",
        new_callable=AsyncMock,
    ) as mock_create:

        mock_create.side_effect = RuntimeError(
            "Digital twin creation failed"
        )

        response = client.post(
            "/twins/provision",
            json={
                "vulnerability_id": vulnerability.id,
                "ttl_seconds": 3600,
            },
        )

    assert response.status_code == 502

    assert db.query(Twin).count() == 0


# ---------------------------------------------------------
# Unknown Vulnerability
# ---------------------------------------------------------

def test_unknown_vulnerability(client):

    with patch(
        "integrations.digital_twin.twin_client.DigitalTwinClient.create_twin",
        new_callable=AsyncMock,
    ) as mock_create:
        
        response = client.post(
            "/twins/provision",
            json={
                "vulnerability_id": 9999,
                "ttl_seconds": 3600,
            },
        )

    assert response.status_code == 404

    mock_create.assert_not_called()


# ---------------------------------------------------------
# Persisted Topology
# ---------------------------------------------------------

def test_topology_saved(client, db):

    asset = create_asset(db)
    vulnerability = create_vulnerability(db, asset)

    topology = SUCCESS_RESPONSE.copy()

    topology["extra"] = {
        "services": [
            "apache",
            "ssh",
        ]
    }

    with patch(
        "integrations.digital_twin.twin_client.DigitalTwinClient.create_twin",
        new_callable=AsyncMock,
    ) as mock_create:

        mock_create.return_value = topology

        response = client.post(
            "/twins/provision",
            json={
                "vulnerability_id": vulnerability.id,
            },
        )

    assert response.status_code == 200

    twin = db.query(Twin).first()

    assert twin is not None

    assert twin.topology["uuid"] == "uuid-1234"

    assert twin.topology["extra"]["services"] == [
        "apache",
        "ssh",
    ]


# ---------------------------------------------------------
# Twin Naming
# ---------------------------------------------------------

def test_generated_name(client, db):

    asset = create_asset(db)
    vulnerability = create_vulnerability(db, asset)

    with patch(
        "integrations.digital_twin.twin_client.DigitalTwinClient.create_twin",
        new_callable=AsyncMock,
    ) as mock_create:

        mock_create.return_value = SUCCESS_RESPONSE

        client.post(
            "/twins/provision",
            json={
                "vulnerability_id": vulnerability.id,
            },
        )

    twin = db.query(Twin).first()

    assert twin.name == f"{asset.name}-{vulnerability.cve_id}"
    # ---------------------------------------------------------
# Destroy Success
# ---------------------------------------------------------

def test_destroy_twin_success(client, db):

    asset = create_asset(db)
    vulnerability = create_vulnerability(db, asset)

    with patch(
        "integrations.digital_twin.twin_client.DigitalTwinClient.create_twin",
        new_callable=AsyncMock,
    ) as mock_create:

        mock_create.return_value = SUCCESS_RESPONSE

        client.post(
            "/twins/provision",
            json={
                "vulnerability_id": vulnerability.id,
            },
        )

    twin = db.query(Twin).first()

    assert twin.status == "running"

    with patch(
        "integrations.digital_twin.twin_client.DigitalTwinClient.destroy_twin",
        new_callable=AsyncMock,
    ) as mock_destroy:

        mock_destroy.return_value = {
            "success": True
        }

        response = client.delete(
            f"/twins/{twin.id}"
        )

    assert response.status_code == 200

    body = response.json()

    assert body["status"] == "destroyed"

    db.refresh(twin)

    assert twin.status == "destroyed"

    mock_destroy.assert_awaited_once()


# ---------------------------------------------------------
# Destroy Unknown Twin
# ---------------------------------------------------------

def test_destroy_unknown_twin(client):

    response = client.delete(
        "/twins/9999"
    )

    assert response.status_code == 404


# ---------------------------------------------------------
# Destroy Generator Failure
# ---------------------------------------------------------

def test_destroy_generator_failure(client, db):

    asset = create_asset(db)
    vulnerability = create_vulnerability(db, asset)

    with patch(
        "integrations.digital_twin.twin_client.DigitalTwinClient.create_twin",
        new_callable=AsyncMock,
    ) as mock_create:

        mock_create.return_value = SUCCESS_RESPONSE

        client.post(
            "/twins/provision",
            json={
                "vulnerability_id": vulnerability.id,
            },
        )

    twin = db.query(Twin).first()

    with patch(
        "integrations.digital_twin.twin_client.DigitalTwinClient.destroy_twin",
        new_callable=AsyncMock,
    ) as mock_destroy:

        mock_destroy.side_effect = RuntimeError(
            "Digital twin destruction failed"
        )

        response = client.delete(
            f"/twins/{twin.id}"
        )

    assert response.status_code == 502

    db.refresh(twin)

    assert twin.status == "running"


# ---------------------------------------------------------
# Database Commit Failure
# ---------------------------------------------------------

def test_database_commit_failure(client, db):

    asset = create_asset(db)
    vulnerability = create_vulnerability(db, asset)

    with patch(
        "integrations.digital_twin.twin_client.DigitalTwinClient.create_twin",
        new_callable=AsyncMock,
    ) as mock_create:

        mock_create.return_value = SUCCESS_RESPONSE

        with patch.object(
            db,
            "commit",
            side_effect=Exception("DB Failure"),
        ):

            response = client.post(
                "/twins/provision",
                json={
                    "vulnerability_id": vulnerability.id,
                },
            )

    assert response.status_code >= 500

    assert db.query(Twin).count() == 0


# ---------------------------------------------------------
# Verify Endpoint Stored
# ---------------------------------------------------------

def test_endpoint_saved(client, db):

    asset = create_asset(db)
    vulnerability = create_vulnerability(db, asset)

    response_data = SUCCESS_RESPONSE.copy()

    response_data["ip_address"] = "10.10.10.10"

    with patch(
        "integrations.digital_twin.twin_client.DigitalTwinClient.create_twin",
        new_callable=AsyncMock,
    ) as mock_create:

        mock_create.return_value = response_data

        client.post(
            "/twins/provision",
            json={
                "vulnerability_id": vulnerability.id,
            },
        )

    twin = db.query(Twin).first()

    assert twin.endpoint == "10.10.10.10"

    assert twin.ip_address == "10.10.10.10"


# ---------------------------------------------------------
# Verify Provider
# ---------------------------------------------------------

def test_provider_saved(client, db):

    asset = create_asset(db)
    vulnerability = create_vulnerability(db, asset)

    with patch(
        "integrations.digital_twin.twin_client.DigitalTwinClient.create_twin",
        new_callable=AsyncMock,
    ) as mock_create:

        mock_create.return_value = SUCCESS_RESPONSE

        client.post(
            "/twins/provision",
            json={
                "vulnerability_id": vulnerability.id,
            },
        )

    twin = db.query(Twin).first()

    assert twin.provider == "TwinGenerator"


# ---------------------------------------------------------
# Verify Notes
# ---------------------------------------------------------

def test_notes_saved(client, db):

    asset = create_asset(db)
    vulnerability = create_vulnerability(db, asset)

    with patch(
        "integrations.digital_twin.twin_client.DigitalTwinClient.create_twin",
        new_callable=AsyncMock,
    ) as mock_create:

        mock_create.return_value = SUCCESS_RESPONSE

        client.post(
            "/twins/provision",
            json={
                "vulnerability_id": vulnerability.id,
            },
        )

    twin = db.query(Twin).first()

    assert twin.notes == f"Provisioned for {vulnerability.cve_id}"