"""
Result type returned by VMTwinEngine.provision_twin().
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class VMProvisionResult:
    vm_name: str
    snapshot_name: str
    network_name: str
    ip_address: Optional[str]
    status: str  # e.g. "running", "poweroff", "saved" (VirtualBox VMState values)
    healthy: bool
