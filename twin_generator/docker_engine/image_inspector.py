"""
Reads the ports an image declares via EXPOSE, so the Docker Twin Engine can
satisfy "expose required ports" automatically without needing a new database
field for port metadata (registry entries only track the image, not ports).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Dict, List

if TYPE_CHECKING:
    from docker import DockerClient


def get_declared_ports(client: "DockerClient", image: str) -> List[int]:
    """Return the container ports the image's Dockerfile declares via EXPOSE.

    Docker's image inspect data has ExposedPorts formatted like
    {"8080/tcp": {}, "9000/udp": {}}; this extracts just the port numbers.
    """
    image_obj = client.images.get(image)
    exposed: Dict[str, object] = image_obj.attrs.get("Config", {}).get("ExposedPorts", {}) or {}
    ports: List[int] = []
    for spec in exposed:
        port_str = spec.split("/")[0]
        if port_str.isdigit():
            ports.append(int(port_str))
    return sorted(ports)
