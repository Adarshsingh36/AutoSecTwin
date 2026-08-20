"""Result type for a single Twin Cleanup Manager sweep."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List


@dataclass
class CleanupReport:
    expired_twins_destroyed: int = 0
    orphaned_containers_removed: int = 0
    networks_pruned: int = 0
    volumes_pruned: int = 0
    snapshots_removed: int = 0
    errors: List[str] = field(default_factory=list)
