"""
Configuration for the VM Twin Engine, loaded from the project's .env.
"""

from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class VMEngineSettings(BaseSettings):
    """Tunables for restoring, booting, and heartbeat-checking VM twins."""

    model_config = SettingsConfigDict(env_prefix="VM_TWIN_", env_file=".env", extra="ignore")

    vboxmanage_path: str = Field(default="VBoxManage", description="Path/name of the VBoxManage binary.")
    default_snapshot_name: str = Field(default="clean-snapshot")
    default_isolated_intnet: str = Field(
        default="twin-intnet",
        description="VirtualBox internal network name used to isolate VM twins (no host/internet route).",
    )
    boot_type: str = Field(default="headless", description="'headless', 'gui', or 'sdl'.")
    heartbeat_timeout_seconds: int = Field(default=120, ge=1)
    heartbeat_poll_interval_seconds: float = Field(default=3.0, ge=0.01)
    command_timeout_seconds: int = Field(
        default=60, ge=1, description="Per-command timeout for VBoxManage invocations."
    )
