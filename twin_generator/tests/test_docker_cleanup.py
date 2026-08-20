"""
Unit tests for cleanup/docker_cleanup.py. No real Docker daemon involved.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from twin_generator.cleanup.docker_cleanup import (
    TWIN_LABEL_FILTER,
    prune_unused_networks,
    prune_unused_volumes,
    remove_orphaned_stopped_containers,
)


@pytest.fixture
def docker_client() -> MagicMock:
    return MagicMock()


def test_remove_orphaned_stopped_containers_removes_each_match(
    docker_client: MagicMock,
) -> None:
    c1 = MagicMock(name="twin-a")
    c2 = MagicMock(name="twin-b")
    docker_client.containers.list.return_value = [c1, c2]

    removed = remove_orphaned_stopped_containers(docker_client)

    assert removed == 2
    c1.remove.assert_called_once_with(force=True)
    c2.remove.assert_called_once_with(force=True)

    _, kwargs = docker_client.containers.list.call_args
    assert kwargs["filters"]["label"] == TWIN_LABEL_FILTER["label"]
    assert kwargs["filters"]["status"] == ["exited", "dead"]


def test_remove_orphaned_stopped_containers_tolerates_individual_failures(
    docker_client: MagicMock,
) -> None:
    good = MagicMock()
    bad = MagicMock()
    bad.remove.side_effect = RuntimeError("already gone")

    docker_client.containers.list.return_value = [good, bad]

    removed = remove_orphaned_stopped_containers(docker_client)

    assert removed == 1  # only the successful removal is counted


def test_prune_unused_networks_returns_count(
    docker_client: MagicMock,
) -> None:
    docker_client.networks.prune.return_value = {
        "NetworksDeleted": ["twin-net-a", "twin-net-b"]
    }

    count = prune_unused_networks(docker_client)

    assert count == 2
    docker_client.networks.prune.assert_called_once_with(
        filters=TWIN_LABEL_FILTER
    )


def test_prune_unused_volumes_returns_count(
    docker_client: MagicMock,
) -> None:
    docker_client.volumes.prune.return_value = {
        "VolumesDeleted": ["vol-a"]
    }

    count = prune_unused_volumes(docker_client)

    assert count == 1


def test_prune_functions_handle_empty_results(
    docker_client: MagicMock,
) -> None:
    docker_client.networks.prune.return_value = {}
    docker_client.volumes.prune.return_value = {}

    assert prune_unused_networks(docker_client) == 0
    assert prune_unused_volumes(docker_client) == 0