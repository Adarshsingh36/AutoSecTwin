"""
Result type returned by the Docker/VM stats collectors and TwinMonitor.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from twin_generator.utils.enums import HealthStatus


@dataclass(frozen=True)
class TwinMetrics:
    """A single point-in-time resource/health snapshot for one twin."""

    twin_uuid: str
    environment: str  # "docker" or "vm"
    container_or_vm_status: str
    health: HealthStatus
    cpu_percent: Optional[float] = None
    memory_usage_bytes: Optional[int] = None
    memory_limit_bytes: Optional[int] = None
    disk_io_bytes: Optional[int] = None
    network_rx_bytes: Optional[int] = None
    network_tx_bytes: Optional[int] = None
    was_auto_restarted: bool = False
    collected_at: Optional[datetime] = None  # set in __post_init__ if not provided

    def __post_init__(self) -> None:
        if self.collected_at is None:
            object.__setattr__(self, "collected_at", datetime.now(timezone.utc))
