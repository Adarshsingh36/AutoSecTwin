"""
Unit tests for IsolatedNetworkManager. No real Docker daemon involved --
the docker-sdk-python client is mocked so these tests run anywhere.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from twin_generator.network.docker_network_manager import IsolatedNetworkManager
from twin_generator.utils.exceptions import NetworkIsolationError


@pytest.fixture
def docker_client() -> MagicMock:
    return MagicMock()


def test_create_isolated_network_is_internal(docker_client: MagicMock) -> None:
    fake_network = MagicMock(id="net123")
    docker_client.networks.create.return_value = fake_network

    manager = IsolatedNetworkManager(docker_client)
    result = manager.create_isolated_network("abc-uuid")

    assert result.internal is True
    assert result.name == "twin-net-abc-uuid"
    assert result.network_id == "net123"

    _, kwargs = docker_client.networks.create.call_args
    assert kwargs["internal"] is True
    assert kwargs["driver"] == "bridge"
    assert "exploit-engine" in kwargs["labels"]["twin.allowed_services"]


def test_create_isolated_network_wraps_docker_errors(
    docker_client: MagicMock,
) -> None:
    docker_client.networks.create.side_effect = RuntimeError("daemon unreachable")

    manager = IsolatedNetworkManager(docker_client)

    with pytest.raises(NetworkIsolationError):
        manager.create_isolated_network("abc-uuid")


def test_destroy_network_removes_existing(docker_client: MagicMock) -> None:
    fake_network = MagicMock()
    docker_client.networks.get.return_value = fake_network

    manager = IsolatedNetworkManager(docker_client)
    manager.destroy_network("twin-net-abc-uuid")

    fake_network.remove.assert_called_once()


def test_destroy_network_treats_not_found_as_success(
    docker_client: MagicMock,
) -> None:
    from docker.errors import NotFound

    docker_client.networks.get.side_effect = NotFound("no such network")

    manager = IsolatedNetworkManager(docker_client)
    manager.destroy_network("twin-net-missing")  # should not raise