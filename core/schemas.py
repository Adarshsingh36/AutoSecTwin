"""
Shared/base Pydantic schemas for AutoSecTwin ASDE.

Domain-specific request/response schemas (VulnerabilityOut, ExploitOut,
ValidationResultOut, RecommendationOut, etc.) belong alongside their
respective routers and are added in Phase 2/3 as each module is
implemented. This module holds only the generic building blocks that
every domain schema and route response will reuse, so they're defined
once.
"""

from datetime import datetime
from typing import Generic, TypeVar
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

T = TypeVar("T")


class ORMBaseSchema(BaseModel):
    """Base schema for any model returned directly from the ORM."""

    model_config = ConfigDict(from_attributes=True)


class TimestampedSchema(ORMBaseSchema):
    """Base schema for ORM models using UUIDPrimaryKeyMixin + TimestampMixin
    (see database/base.py)."""

    id: UUID
    created_at: datetime
    updated_at: datetime


class PaginationParams(BaseModel):
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=20, ge=1, le=200)

    @property
    def offset(self) -> int:
        return (self.page - 1) * self.page_size


class PaginatedResponse(BaseModel, Generic[T]):
    items: list[T]
    total: int
    page: int
    page_size: int

    @property
    def total_pages(self) -> int:
        return max(1, -(-self.total // self.page_size))  # ceil division without importing math


class ErrorDetail(BaseModel):
    code: str
    message: str
    details: dict = Field(default_factory=dict)


class ErrorResponse(BaseModel):
    error: ErrorDetail


class HealthCheckResponse(BaseModel):
    status: str
    app_name: str
    version: str
    environment: str
    database_connected: bool
