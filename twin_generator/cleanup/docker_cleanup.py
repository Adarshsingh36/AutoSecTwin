"""
Docker-side cleanup: stopped containers, unused networks, unused volumes.

Every twin-related Docker resource is labeled `twin.generator=true` (see
DockerTwinEngine and IsolatedNetworkManager), so this sweep only ever
touches resources this module created -- never anything else running on
the same Docker host.
"""

from __future__ import annotations

import time 
from typing import TYPE_CHECKING

import structlog

from twin_generator.cleanup.config import CleanupSettings

if TYPE_CHECKING:
    from docker import DockerClient

logger = structlog.get_logger(__name__)

TWIN_LABEL_FILTER = {"label": "twin.generator=true"}


def remove_orphaned_stopped_containers(client: "DockerClient") -> int:
    """Remove twin-generator containers that are exited/dead.

    These are ones that never got cleaned up through the normal twin
    lifecycle (e.g. the process crashed between the container failing and
    the Twin Monitor/Orchestrator marking it destroyed).
    """
    containers = client.containers.list(
        all=True,
        filters={**TWIN_LABEL_FILTER, "status": ["exited", "dead"]},
    )

    removed = 0

    for container in containers:
        try:
            container.remove(force=True)
            removed += 1

            logger.info(
                "orphaned_container_removed",
                container_name=container.name,
            )

        except Exception as exc:  # pragma: no cover - best-effort cleanup
            logger.warning(
                "orphaned_container_removal_failed",
                container_name=container.name,
                error=str(exc),
            )

    return removed


def prune_unused_networks(client: "DockerClient") -> int:
    """Remove twin-generator networks with no containers attached."""
    result = client.networks.prune(filters=TWIN_LABEL_FILTER)
    deleted = result.get("NetworksDeleted") or []
    if deleted:
        logger.info("unused_networks_pruned", count=len(deleted), names=deleted)
    return len(deleted)


def prune_unused_volumes(client: "DockerClient") -> int:
    """Remove twin-generator volumes with no containers referencing them."""
    result = client.volumes.prune(filters=TWIN_LABEL_FILTER)
    deleted = result.get("VolumesDeleted") or []
    if deleted:
        logger.info("unused_volumes_pruned", count=len(deleted), names=deleted)
    return len(deleted)
