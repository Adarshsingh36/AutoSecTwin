from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, List, Optional

import structlog

from twin_generator.utils.exceptions import NetworkIsolationError

if TYPE_CHECKING:
    from docker import DockerClient
    from docker.models.networks import Network

logger = structlog.get_logger(__name__)

DEFAULT_ALLOWED_SERVICES = ("exploit-engine", "validator")


@dataclass(frozen=True)
class IsolatedNetworkInfo:
    """Result of creating an isolated twin network."""

    network_id: str
    name: str
    driver: str
    internal: bool
    allowed_services: List[str] = field(
        default_factory=lambda: list(DEFAULT_ALLOWED_SERVICES)
    )


class IsolatedNetworkManager:
    """Creates and tears down dedicated, internet-isolated Docker bridge networks."""

    def __init__(self, docker_client: "DockerClient") -> None:
        self._client = docker_client

    def create_isolated_network(
        self,
        twin_uuid: str,
        allowed_services: Optional[List[str]] = None,
    ) -> IsolatedNetworkInfo:
        """Create a dedicated, internet-isolated bridge network for one twin."""

        name = f"twin-net-{twin_uuid}"
        services = allowed_services or list(DEFAULT_ALLOWED_SERVICES)

        try:
            network: "Network" = self._client.networks.create(
                name=name,
                driver="bridge",
                internal=True,
                check_duplicate=True,
                labels={
                    "twin.generator": "true",
                    "twin.uuid": twin_uuid,
                    "twin.allowed_services": ",".join(services),
                },
            )
        except Exception as exc:
            logger.error(
                "network_creation_failed",
                twin_uuid=twin_uuid,
                error=str(exc),
            )
            raise NetworkIsolationError(
                f"Failed to create isolated network for twin {twin_uuid}: {exc}"
            ) from exc

        logger.info(
            "isolated_network_created",
            name=name,
            network_id=network.id,
            twin_uuid=twin_uuid,
        )

        return IsolatedNetworkInfo(
            network_id=network.id,
            name=name,
            driver="bridge",
            internal=True,
            allowed_services=services,
        )

    def destroy_network(self, name: str) -> None:
        """Remove a twin's network. Safe to call on an already-removed network."""

        try:
            network = self._client.networks.get(name)
            network.remove()
            logger.info("isolated_network_destroyed", name=name)
        except Exception as exc:
            from docker.errors import NotFound

            if isinstance(exc, NotFound):
                logger.debug("network_already_removed", name=name)
                return

            logger.error(
                "network_destroy_failed",
                name=name,
                error=str(exc),
            )
            raise NetworkIsolationError(
                f"Failed to destroy network {name}: {exc}"
            ) from exc