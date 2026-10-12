import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from database.base import Base
from database.models.asset import Asset
from database.models.vulnerability import Vulnerability
from integrations.digital_twin.twin_client import DigitalTwinClient
from services.twin_provisioning_service import TwinProvisioningService


engine = create_engine(
    "sqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
    future=True,
)

TestingSessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


@pytest.fixture(scope="function")
def db():
    Base.metadata.create_all(bind=engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)


def _create_asset_and_vulnerability(db, version="5.17.3"):
    asset = Asset(
        name="ActiveMQ Server",
        asset_type="Server",
        hostname="activemq-host",
        software="ActiveMQ",
        version=version,
        environment="docker",
    )
    db.add(asset)
    db.commit()
    db.refresh(asset)

    vulnerability = Vulnerability(
        asset_id=asset.id,
        cve_id="CVE-2023-46604",
        title="Apache ActiveMQ OpenWire RCE",
        severity="CRITICAL",
    )
    db.add(vulnerability)
    db.commit()
    db.refresh(vulnerability)

    return asset, vulnerability


SUCCESS_RESPONSE = {
    "id": 200,
    "uuid": "uuid-fixed",
    "status": "running",
    "environment": "docker",
    "ip_address": "172.18.0.9",
    "network": "bridge",
    "twin_image": "apache/activemq-classic:5.17.6",
    "health": "healthy",
    "legacy_flag": "false",
}


# ---------------------------------------------------------
# TwinProvisioningService.version_override
# ---------------------------------------------------------


@pytest.mark.asyncio
async def test_provision_without_override_uses_asset_version(db):
    asset, vulnerability = _create_asset_and_vulnerability(db, version="5.17.3")

    with patch(
        "integrations.digital_twin.twin_client.DigitalTwinClient.create_twin",
        new_callable=AsyncMock,
    ) as mock_create:
        mock_create.return_value = SUCCESS_RESPONSE

        service = TwinProvisioningService(db)
        await service.provision(vulnerability.id)

    _, kwargs = mock_create.call_args
    assert kwargs["version"] == "5.17.3"


@pytest.mark.asyncio
async def test_provision_with_override_requests_fixed_version_not_asset_version(db):
    """asset.version still says 5.17.3 (the real asset hasn't been
    re-scanned yet) -- remediation must still be able to request the
    fixed version explicitly, without that depending on the asset record
    already reflecting it.
    """
    asset, vulnerability = _create_asset_and_vulnerability(db, version="5.17.3")

    with patch(
        "integrations.digital_twin.twin_client.DigitalTwinClient.create_twin",
        new_callable=AsyncMock,
    ) as mock_create:
        mock_create.return_value = SUCCESS_RESPONSE

        service = TwinProvisioningService(db)
        await service.provision(vulnerability.id, version_override="5.17.6")

    _, kwargs = mock_create.call_args
    assert kwargs["version"] == "5.17.6"


# ---------------------------------------------------------
# DigitalTwinClient.destroy_twin HTTP method fix
# ---------------------------------------------------------


@pytest.mark.asyncio
async def test_destroy_twin_posts_to_destroy_endpoint_not_delete():
    """Regression test for the DELETE /twins/{id} bug: Twin Generator only
    ever exposed POST /twins/{id}/destroy. Every real (non-mock) destroy
    call was silently failing before this fix.
    """
    client = DigitalTwinClient(base_url="http://twin-generator.test")
    client.mock_mode = False

    mock_response = AsyncMock()
    mock_response.raise_for_status = lambda: None
    mock_response.json = lambda: {"id": 42, "status": "destroyed"}

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post, patch(
        "httpx.AsyncClient.delete", new_callable=AsyncMock
    ) as mock_delete:
        mock_post.return_value = mock_response

        result = await client.destroy_twin("42")

    mock_delete.assert_not_called()
    mock_post.assert_awaited_once_with("http://twin-generator.test/twins/42/destroy")
    assert result["status"] == "destroyed"
    assert result["simulated"] is False
