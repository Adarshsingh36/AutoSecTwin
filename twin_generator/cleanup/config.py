"""
Configuration for the Twin Cleanup Manager, loaded from the project's .env.
"""

from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class CleanupSettings(BaseSettings):
    """Tunables for the automatic cleanup sweep."""

    model_config = SettingsConfigDict(env_prefix="TWIN_CLEANUP_", env_file=".env", extra="ignore")

    sweep_interval_seconds: float = Field(
        default=300.0, ge=10.0, description="How often the cleanup sweep runs."
    )
    default_ttl_seconds: int = Field(
        default=3600,
        ge=60,
        description="Fallback TTL for twins created without an explicit ttl_seconds.",
    )
    remove_orphaned_stopped_containers: bool = Field(
        default=True,
        description="Remove Docker containers labeled twin.generator=true that are exited/dead.",
    )
    prune_unused_networks: bool = Field(default=True)
    prune_unused_volumes: bool = Field(default=True)
    keep_snapshot_names: tuple[str, ...] = Field(
        default=("clean-snapshot",),
        description=(
            "VirtualBox snapshot names never deleted by the sweep -- the baseline(s) "
            "the VM Twin Engine restores from. Must match VMEngineSettings.default_snapshot_name."
        ),
    )
    enable_snapshot_cleanup: bool = Field(
        default=False,
        description=(
            "Off by default: VBoxManage does not reliably expose snapshot creation "
            "timestamps, so this only prunes non-baseline snapshots by name, not "
            "true age. Review keep_snapshot_names carefully before enabling."
        ),
    )
