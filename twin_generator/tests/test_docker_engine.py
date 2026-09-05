"""
Unit tests for DockerTwinEngine. The docker-sdk-python client and the
network manager are both mocked -- these tests verify the provisioning
sequence and error handling, not real Docker behavior (no daemon available
in CI/sandbox contexts; that's covered by manual/integration testing against
a real Docker host).
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from twin_generator.docker_engine.config import DockerEngineSettings
from twin_generator.docker_engine.manager import DockerTwinEngine
from twin_generator.network.docker_network_manager import IsolatedNetworkInfo
from twin_generator.utils.exceptions import (
    DockerImagePullError,
    DockerProvisioningError,
    HealthCheckTimeoutError,
)


@pytest.fixture
def fast_settings() -> DockerEngineSettings:
    return DockerEngineSettings(
        health_check_timeout_seconds=5,
        health_check_poll_interval_seconds=0.01,
        ungracious_grace_period_seconds=0.01,
        image_pull_timeout_seconds=5,
    )


@pytest.fixture
def network_info() -> IsolatedNetworkInfo:
    return IsolatedNetworkInfo(
        network_id="net123",
        name="twin-net-abc",
        driver="bridge",
        internal=True,
    )


def _make_container(
    status: str = "running",
    healthcheck: bool = False,
    health_status: str = "healthy",
):
    container = MagicMock()
    container.id = "container123"
    container.name = "twin-abc"
    container.status = status

    config = (
        {"Healthcheck": {"Test": ["CMD", "curl", "-f", "http://localhost"]}}
        if healthcheck
        else {}
    )

    container.attrs = {
        "Config": config,
        "State": {"Health": {"Status": health_status}} if healthcheck else {},
        "NetworkSettings": {
            "Networks": {
                "twin-net-abc": {
                    "IPAddress": "172.20.0.5"
                }
            }
        },
    }

    return container


def test_provision_twin_happy_path_no_healthcheck(
    fast_settings: DockerEngineSettings,
    network_info: IsolatedNetworkInfo,
) -> None:
    docker_client = MagicMock()
    container = _make_container(status="running", healthcheck=False)

    docker_client.containers.create.return_value = container
    docker_client.images.get.return_value = MagicMock(
        attrs={"Config": {"ExposedPorts": {"8080/tcp": {}}}}
    )

    network_manager = MagicMock()
    network_manager.create_isolated_network.return_value = network_info

    engine = DockerTwinEngine(
        docker_client,
        network_manager,
        fast_settings,
    )

    result = engine.provision_twin(
        twin_uuid="abc",
        image="vulhub/log4j:2.15.0",
    )

    assert result.container_id == "container123"
    assert result.network_name == "twin-net-abc"
    assert result.ip_address == "172.20.0.5"
    assert result.exposed_ports == [8080]
    assert result.healthy is True

    assert docker_client.images.get.call_count >= 1
    docker_client.images.pull.assert_not_called()
    docker_client.images.pull.assert_not_called()
    container.start.assert_called_once()


def test_provision_twin_waits_for_real_healthcheck(
    fast_settings: DockerEngineSettings,
    network_info: IsolatedNetworkInfo,
) -> None:
    docker_client = MagicMock()
    container = _make_container(
        status="running",
        healthcheck=True,
        health_status="healthy",
    )

    docker_client.containers.create.return_value = container
    docker_client.images.get.return_value = MagicMock(
        attrs={"Config": {"ExposedPorts": {}}}
    )

    network_manager = MagicMock()
    network_manager.create_isolated_network.return_value = network_info

    engine = DockerTwinEngine(
        docker_client,
        network_manager,
        fast_settings,
    )

    result = engine.provision_twin(
        twin_uuid="abc",
        image="some/image",
    )

    assert result.healthy is True


def test_provision_twin_health_check_timeout_raises_and_cleans_up(
    fast_settings: DockerEngineSettings,
    network_info: IsolatedNetworkInfo,
) -> None:
    docker_client = MagicMock()

    container = _make_container(
        status="running",
        healthcheck=True,
        health_status="unhealthy",
    )

    docker_client.containers.create.return_value = container
    docker_client.images.get.return_value = MagicMock(
        attrs={"Config": {"ExposedPorts": {}}}
    )

    network_manager = MagicMock()
    network_manager.create_isolated_network.return_value = network_info

    engine = DockerTwinEngine(
        docker_client,
        network_manager,
        fast_settings,
    )

    with pytest.raises(HealthCheckTimeoutError):
        engine.provision_twin(
            twin_uuid="abc",
            image="some/image",
        )

    container.remove.assert_called_once_with(force=True)
    network_manager.destroy_network.assert_called_once_with(
        "twin-net-abc"
    )


def test_provision_twin_image_pull_failure_raises_before_network_creation(
    fast_settings: DockerEngineSettings,
) -> None:
    docker_client = MagicMock()

    docker_client.images.get.side_effect = RuntimeError(
        "image not found locally"
    )

    docker_client.images.pull.side_effect = RuntimeError(
        "no such image"
    )

    network_manager = MagicMock()

    engine = DockerTwinEngine(
        docker_client,
        network_manager,
        fast_settings,
    )

    with pytest.raises(DockerImagePullError):
        engine.provision_twin(
            twin_uuid="abc",
            image="nonexistent/image",
        )

    docker_client.images.get.assert_called_once_with(
        "nonexistent/image"
    )
    docker_client.images.pull.assert_called_once_with(
        "nonexistent/image"
    )
    network_manager.create_isolated_network.assert_not_called()


def test_provision_twin_container_creation_failure_cleans_up_network(
    fast_settings: DockerEngineSettings,
    network_info: IsolatedNetworkInfo,
) -> None:
    docker_client = MagicMock()

    docker_client.containers.create.side_effect = RuntimeError(
        "invalid config"
    )

    docker_client.images.get.return_value = MagicMock(
        attrs={"Config": {"ExposedPorts": {}}}
    )

    network_manager = MagicMock()
    network_manager.create_isolated_network.return_value = network_info

    engine = DockerTwinEngine(
        docker_client,
        network_manager,
        fast_settings,
    )

    with pytest.raises(DockerProvisioningError):
        engine.provision_twin(
            twin_uuid="abc",
            image="some/image",
        )

    network_manager.destroy_network.assert_called_once_with(
        "twin-net-abc"
    )