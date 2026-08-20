"""
Result type returned by DockerTwinEngine.provision_twin().

Kept as a plain dataclass (not a Pydantic schema) since this is an internal
hand-off between the engine and the Twin Orchestrator, not an API payload --
the Orchestrator is what maps this onto TwinInstance and the API schemas.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass(frozen=True)
class DockerProvisionResult:
    container_id: str
    container_name: str
    image: str
    hostname: str
    network_name: str
    network_id: str
    ip_address: Optional[str]
    exposed_ports: List[int] = field(default_factory=list)
    published_ports: Dict[int, Optional[int]] = field(default_factory=dict)
    status: str = "running"
    healthy: bool = False
