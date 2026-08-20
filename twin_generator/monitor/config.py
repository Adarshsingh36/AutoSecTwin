"""
Configuration for the Twin Monitor, loaded from the project's .env.
"""

from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class MonitorSettings(BaseSettings):
    """Tunables for periodic twin health/resource monitoring."""

    model_config = SettingsConfigDict(env_prefix="TWIN_MONITOR_", env_file=".env", extra="ignore")

    poll_interval_seconds: float = Field(
        default=30.0, ge=1.0, description="How often the monitor loop checks running twins."
    )
    auto_restart_failed_containers: bool = Field(
        default=True, description="Whether to automatically restart Docker twins found exited/dead."
    )
    unhealthy_docker_statuses: tuple[str, ...] = Field(
        default=("exited", "dead"),
        description="Docker container statuses treated as failed for auto-restart purposes.",
    )
    vm_metrics_period_seconds: int = Field(default=1, ge=1)
    vm_metrics_settle_seconds: float = Field(
        default=1.2, ge=0.1, description="Delay between `metrics setup` and `metrics query` for VMs."
    )
