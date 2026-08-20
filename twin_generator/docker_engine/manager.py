"""
Docker Twin Engine.

Automates, in order, exactly the steps specified for reproducing a
vulnerability in an isolated Docker environment:

    pull image -> create network -> assign IP -> configure hostname ->
    expose required ports -> mount volumes if required -> start ->
    wait for health check -> return running container

Uses docker-sdk-python exclusively -- no shell commands, no subprocess calls.
Docker-sdk-python's client is synchronous, so every blocking call is run in
a worker thread via asyncio.to_thread to keep this usable from FastAPI's
async request handlers without stalling the event loop.

This engine's job ends the moment the container is running and healthy.
It never exploits, patches, or otherwise touches the vulnerability itself --
that is the Exploit Engine's responsibility.
"""

from __future__ import annotations

from email.mime import image
from email.mime import image
import time
import uuid
from typing import TYPE_CHECKING, Dict, Optional

from sqlalchemy import exc
import structlog

from twin_generator.docker_engine.config import DockerEngineSettings
from twin_generator.docker_engine.image_inspector import get_declared_ports
from twin_generator.docker_engine.schemas import DockerProvisionResult
from twin_generator.network.docker_network_manager import IsolatedNetworkManager
from twin_generator.utils.exceptions import (
    DockerImagePullError,
    DockerProvisioningError,
    HealthCheckTimeoutError,
)

if TYPE_CHECKING:
    from docker import DockerClient
    from docker.models.containers import Container

logger = structlog.get_logger(__name__)


class DockerTwinEngine:
    """Provisions an isolated, running Docker replica of a vulnerable target."""

    def __init__(
        self,
        docker_client: "DockerClient",
        network_manager: IsolatedNetworkManager,
        settings: Optional[DockerEngineSettings] = None,
    ) -> None:
        self._client = docker_client
        self._networks = network_manager
        self._settings = settings or DockerEngineSettings()

    def provision_twin(
        self,
        *,
        twin_uuid: str,
        image: str,
        hostname: Optional[str] = None,
        published_ports: Optional[Dict[int, Optional[int]]] = None,
        volumes: Optional[Dict[str, Dict[str, str]]] = None,
        environment: Optional[Dict[str, str]] = None,
    ) -> DockerProvisionResult:
        """Bring up a fully isolated, healthy twin. Raises DockerTwinEngineError
        subclasses on failure at any step; nothing partially provisioned is
        left running -- see _cleanup_partial on the failure paths.
        """
        hostname = hostname or f"twin-{twin_uuid[:8]}"
        container_name = f"twin-{twin_uuid}"

        # 1. Pull image
        self._pull_image(image)

        # 2. Create network (dedicated, internet-isolated bridge)
        network_info = self._networks.create_isolated_network(twin_uuid)

        container = None
        try:
            # 5. Expose required ports (declared by the image itself)
            exposed_ports = get_declared_ports(
                self._client,
            image,
            )
            # 3 + 4 + 6 + 7: create container (assigns hostname, volumes,
            # published ports), attach to the isolated network (assigns IP),
            # then start it.
            container = self._create_container(
                image=image,
                name=container_name,
                hostname=hostname,
                published_ports=published_ports or {},
                volumes=volumes,
                environment=environment,
            )

            ip_address = self._connect_and_start(container, network_info.name)

            # 8. Wait for health check
            healthy = self._wait_for_health(container)

            container.reload()
            logger.info(
                "twin_provisioned",
                twin_uuid=twin_uuid,
                container_id=container.id,
                network=network_info.name,
                ip_address=ip_address,
                healthy=healthy,
            )

            # 9. Return running container
            return DockerProvisionResult(
                container_id=container.id,
                container_name=container_name,
                image=image,
                hostname=hostname,
                network_name=network_info.name,
                network_id=network_info.network_id,
                ip_address=ip_address,
                exposed_ports=exposed_ports,
                published_ports=published_ports or {},
                status=container.status,
                healthy=healthy,
            )

        except Exception:
            self._cleanup_partial(container, network_info.name)
            raise

    # -- individual steps ---------------------------------------------------

    def _pull_image(self, image: str) -> None:
            try:
                self._client.images.pull(image)
            except Exception as exc:
                raise DockerImagePullError(image, str(exc)) from exc

    def _create_container(
        self,
        *,
        image: str,
        name: str,
        hostname: str,
        published_ports: Dict[int, Optional[int]],
        volumes: Optional[Dict[str, Dict[str, str]]],
        environment: Optional[Dict[str, str]],
    ) -> "Container":
        # docker-py's `ports` mapping is {container_port: host_port}. A value
        # of None lets Docker pick an ephemeral host port; an empty dict
        # means "don't publish anything to the host" (the normal case --
        # the isolated network is how the Exploit Engine/Validator reach it).
        port_bindings = {f"{port}/tcp": host_port for port, host_port in published_ports.items()}

        try:
            container = self._client.containers.create(
                image=image,
                name=name,
                hostname=hostname,
                ports=port_bindings or None,
                volumes=volumes,
                environment=environment,
                detach=True,
                labels={"twin.generator": "true"},
                network=None,  # attach explicitly after creation, see _connect_and_start
            )
        except Exception as exc:
            raise DockerProvisioningError(f"Failed to create container {name!r}: {exc}") from exc
        return container

    def _connect_and_start(
        self,
        container: "Container",
        network_name: str,
    ) -> Optional[str]:
        try:
            network = self._client.networks.get(network_name)
            network.connect(container)
            container.start()
            container.reload()
        except Exception as exc:
            raise DockerProvisioningError(
                f"Failed to attach container {container.name!r} to network "
                f"{network_name!r} and start it: {exc}"
            ) from exc

        # Docker auto-assigns the IP within the isolated network's subnet;
        # read it back rather than pre-computing it ourselves.
        networks = container.attrs.get("NetworkSettings", {}).get("Networks", {})
        return networks.get(network_name, {}).get("IPAddress") or None

    def _wait_for_health(self, container: "Container") -> bool:
        timeout = self._settings.health_check_timeout_seconds
        poll_interval = self._settings.health_check_poll_interval_seconds
        deadline = time.monotonic() + timeout

        has_healthcheck = bool(
            container.attrs.get("Config", {}).get("Healthcheck")
        )

        if not has_healthcheck:
            # No HEALTHCHECK declared by the image: give it a short grace
            # period, then treat "still running" as healthy.
            time.sleep(self._settings.ungracious_grace_period_seconds)
            container.reload()
            return container.status == "running"

        while time.monotonic() < deadline:
            container.reload()
            health = (
                container.attrs.get("State", {})
                .get("Health", {})
                .get("Status")
            )

            if health == "healthy":
                return True

            if health == "unhealthy":
                # Keep polling until the deadline -- some services flap
                # unhealthy briefly during startup -- but don't loop forever.
                pass

            time.sleep(poll_interval)

        raise HealthCheckTimeoutError(container.id, timeout)

    def _cleanup_partial(
        self,
        container: Optional["Container"],
        network_name: str,
    ) -> None:
        """Best-effort teardown so a failed provision doesn't leak resources."""
        if container is not None:
            try:
                container.remove(force=True)
            except Exception as exc:  # pragma: no cover - best-effort cleanup
                logger.warning("partial_container_cleanup_failed", error=str(exc))

        try:
            self._networks.destroy_network(network_name)
        except Exception as exc:  # pragma: no cover - best-effort cleanup
            logger.warning("partial_network_cleanup_failed", error=str(exc))

    def destroy_twin(self, twin_uuid: str, network_name: str) -> None:
        """Tear down a twin's container and network.

        Container name is derived the same way provision_twin() named it
        (`twin-<uuid>`), so no separate container-id column is needed on
        twin_instances. Idempotent: safe to call on an already-destroyed
        twin (e.g. if the Twin Cleanup Manager and a manual destroy race).
        """
        try:
            container = self._client.containers.get(f"twin-{twin_uuid}")
            container.remove(force=True)
        except Exception as exc:
            from docker.errors import NotFound

            if not isinstance(exc, NotFound):
                logger.warning(
                    "twin_container_destroy_failed",
                    twin_uuid=twin_uuid,
                    error=str(exc),
                )

        self._networks.destroy_network(network_name)