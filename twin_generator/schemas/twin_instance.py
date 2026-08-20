"""
Pydantic schemas for twin_instances.

TwinCreateRequest is the payload the Twin Orchestrator accepts from the
Classifier (POST /twins/create). Everything else is derived/system-managed
and only ever appears in responses.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field

from twin_generator.utils.enums import EnvironmentType, HealthStatus, LegacyFlag, TwinStatus


class TwinCreateRequest(BaseModel):
    """Input for POST /twins/create."""

    model_config = ConfigDict(str_strip_whitespace=True)

    cve: str = Field(..., min_length=4, max_length=32, description="CVE identifier, e.g. CVE-2021-44228.")
    host: Optional[str] = Field(None, max_length=255, description="Originating host/asset, if known.")
    environment: Optional[EnvironmentType] = Field(
        None,
        description=(
            "Force a specific environment (docker/vm). If omitted, the Twin "
            "Orchestrator selects Docker first and falls back to VM."
        ),
    )
    ttl_seconds: Optional[int] = Field(
        None,
        ge=60,
        description="Time-to-live before the Twin Cleanup Manager destroys this twin. Uses the configured default if omitted.",
    )
    software: Optional[str] = Field(
        None,
        max_length=255,
        description="Software the Classifier detected on the original host, for the Legacy Profiler check.",
    )
    version: Optional[str] = Field(
        None,
        max_length=64,
        description="Version of `software`, for the Legacy Profiler check. Ignored if `software` is omitted.",
    )


class TwinRead(BaseModel):
    """Full representation of a twin instance, returned by GET endpoints."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    uuid: uuid.UUID
    host: Optional[str]
    cve: str
    status: TwinStatus
    environment: EnvironmentType
    twin_image: Optional[str]
    vm_name: Optional[str]
    ip_address: Optional[str]
    network: Optional[str]
    health: HealthStatus
    legacy_flag: LegacyFlag
    created_at: datetime
    destroy_at: Optional[datetime]


class TwinListItem(BaseModel):
    """Condensed representation for GET /twins list responses."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    uuid: uuid.UUID
    cve: str
    status: TwinStatus
    environment: EnvironmentType
    health: HealthStatus
    created_at: datetime


class TwinHealthResponse(BaseModel):
    """Response for GET /twins/{id}/health."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    uuid: uuid.UUID
    status: TwinStatus
    health: HealthStatus
    checked_at: datetime = Field(..., description="Timestamp the health check was performed.")


class TwinDestroyResponse(BaseModel):
    """Response for POST /twins/{id}/destroy."""

    id: int
    uuid: uuid.UUID
    status: TwinStatus
    destroyed_at: datetime
