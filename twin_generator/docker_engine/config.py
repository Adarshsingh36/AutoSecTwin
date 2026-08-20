"""
Configuration for the Docker Twin Engine, loaded from the project's
existing .env per the module's Configuration requirement.
"""

from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class DockerEngineSettings(BaseSettings):
    """Tunables for provisioning and health-checking Docker twins."""

    model_config = SettingsConfigDict(env_prefix="DOCKER_TWIN_", env_file=".env", extra="ignore")

    health_check_timeout_seconds: int = Field(
        default=60, ge=5, description="Max time to wait for a container to report healthy."
    )
    health_check_poll_interval_seconds: float = Field(
        default=2.0, ge=0.01, description="Delay between health check polls."
    )
    ungracious_grace_period_seconds: float = Field(
        default=3.0,
        ge=0.0,
        description=(
            "Settle time before checking status on images with no HEALTHCHECK "
            "defined, so we don't declare 'running but crashing' as healthy."
        ),
    )
    image_pull_timeout_seconds: int = Field(default=300, ge=1)
    default_network_driver: str = Field(default="bridge")
