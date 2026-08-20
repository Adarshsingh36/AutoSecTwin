"""
Pydantic schemas for twin_registry (CVE Image Registry CRUD).
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, ConfigDict, Field

from twin_generator.utils.enums import EnvironmentType


class RegistryEntryCreate(BaseModel):
    """Input for POST /registry."""

    model_config = ConfigDict(str_strip_whitespace=True)

    cve: str = Field(..., min_length=4, max_length=32)
    image: str = Field(..., min_length=1, max_length=255, description="e.g. vulhub/log4j:2.15.0")
    environment: Optional[EnvironmentType] = Field(None, description="Preferred reproduction environment.")
    version: Optional[str] = Field(None, max_length=64)
    notes: Optional[str] = Field(None, max_length=4000)


class RegistryEntryUpdate(BaseModel):
    """Partial-update input for PUT /registry/{id}. Unset fields are left unchanged."""

    model_config = ConfigDict(str_strip_whitespace=True)

    image: Optional[str] = Field(None, min_length=1, max_length=255)
    environment: Optional[EnvironmentType] = None
    version: Optional[str] = Field(None, max_length=64)
    notes: Optional[str] = Field(None, max_length=4000)


class RegistryEntryRead(BaseModel):
    """Response representation for GET /registry, GET /registry/{id}."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    cve: str
    image: str
    environment: Optional[EnvironmentType]
    version: Optional[str]
    notes: Optional[str]
