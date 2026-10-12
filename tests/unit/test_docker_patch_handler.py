"""
Tests for DockerPatchHandler. TwinProvisioningService is fully mocked --
these verify the destroy-then-provision sequence and PatchResult
construction, not real Docker/Twin Generator behavior.
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from services.remediation.handlers.docker_patch_handler import DockerPatchHandler


def _make_old_twin():
    return SimpleNamespace(
        id=1,
        twin_image="autosectwin/activemq:5.17.3",
        endpoint="172.18.0.5:61616",
        external_uuid="old-uuid-123",
    )


def _make_new_twin(health="healthy"):
    return SimpleNamespace(
        id=2,
        twin_image="apache/activemq-classic:5.17.6",
        endpoint="172.18.0.9:61616",
        external_uuid="new-uuid-456",
        health=health,
    )


def _make_vulnerability():
    return SimpleNamespace(id=5, asset_id=3, cve_id="CVE-2023-46604")


@pytest.mark.asyncio
async def test_apply_destroys_old_twin_before_provisioning_new_one():
    provisioning_service = AsyncMock()
    provisioning_service.destroy.return_value = None
    provisioning_service.provision.return_value = _make_new_twin()
    provisioning_service.wait_until_ready.return_value = _make_new_twin()

    handler = DockerPatchHandler(provisioning_service)
    old_twin = _make_old_twin()

    await handler.apply(old_twin, _make_vulnerability(), fixed_version="5.17.6")

    provisioning_service.destroy.assert_awaited_once_with(1)
    provisioning_service.provision.assert_awaited_once_with(
        vulnerability_id=5, version_override="5.17.6"
    )


@pytest.mark.asyncio
async def test_apply_returns_correct_patch_result():
    provisioning_service = AsyncMock()
    provisioning_service.destroy.return_value = None
    new_twin = _make_new_twin(health="healthy")
    provisioning_service.provision.return_value = new_twin
    provisioning_service.wait_until_ready.return_value = new_twin

    handler = DockerPatchHandler(provisioning_service)
    old_twin = _make_old_twin()

    result = await handler.apply(old_twin, _make_vulnerability(), fixed_version="5.17.6")

    assert result.target_modified is True
    assert result.healthy is True
    assert result.old_twin_id == 1
    assert result.new_twin_id == 2
    assert result.old_image == "autosectwin/activemq:5.17.3"
    assert result.new_image == "apache/activemq-classic:5.17.6"
    assert result.old_version == "5.17.3"
    assert result.new_version == "5.17.6"
    assert result.old_endpoint == "172.18.0.5:61616"
    assert result.new_endpoint == "172.18.0.9:61616"
    assert result.old_container_id == "old-uuid-123"
    assert result.new_container_id == "new-uuid-456"


@pytest.mark.asyncio
async def test_apply_reports_unhealthy_when_new_twin_not_healthy():
    provisioning_service = AsyncMock()
    provisioning_service.destroy.return_value = None
    new_twin = _make_new_twin(health="unhealthy")
    provisioning_service.provision.return_value = new_twin
    provisioning_service.wait_until_ready.return_value = new_twin

    handler = DockerPatchHandler(provisioning_service)

    result = await handler.apply(_make_old_twin(), _make_vulnerability(), fixed_version="5.17.6")

    assert result.target_modified is True  # the swap happened
    assert result.healthy is False  # but it isn't healthy


@pytest.mark.asyncio
async def test_apply_propagates_destroy_failure_without_provisioning():
    provisioning_service = AsyncMock()
    provisioning_service.destroy.side_effect = RuntimeError("Twin Generator unreachable")

    handler = DockerPatchHandler(provisioning_service)

    with pytest.raises(RuntimeError, match="Twin Generator unreachable"):
        await handler.apply(_make_old_twin(), _make_vulnerability(), fixed_version="5.17.6")

    provisioning_service.provision.assert_not_called()


@pytest.mark.asyncio
async def test_apply_propagates_provision_failure():
    provisioning_service = AsyncMock()
    provisioning_service.destroy.return_value = None
    provisioning_service.provision.side_effect = RuntimeError("No registry entry for version")

    handler = DockerPatchHandler(provisioning_service)

    with pytest.raises(RuntimeError, match="No registry entry for version"):
        await handler.apply(_make_old_twin(), _make_vulnerability(), fixed_version="5.17.6")

    # Destroy already happened by the time provisioning fails -- this is a
    # known, documented limitation (see PatchExecutor's FAILED status
    # handling): the old twin may already be gone even though the new one
    # never came up.
    provisioning_service.destroy.assert_awaited_once()
