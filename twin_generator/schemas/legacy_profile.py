"""
Pydantic schemas for legacy_profiles and POST /legacy/check.
"""

from __future__ import annotations

from datetime import date
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field

from twin_generator.utils.enums import LegacyFlag


class LegacyProfileCreate(BaseModel):
    """Input for adding a new EOL reference entry."""

    model_config = ConfigDict(str_strip_whitespace=True)

    software: str = Field(..., min_length=1, max_length=255)
    version: str = Field(..., min_length=1, max_length=64)
    eol_date: Optional[date] = None
    vendor: Optional[str] = Field(None, max_length=255)
    supported: Optional[bool] = None


class LegacyProfileRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    software: str
    version: str
    eol_date: Optional[date]
    vendor: Optional[str]
    supported: Optional[bool]


class LegacyCheckRequest(BaseModel):
    """Input for POST /legacy/check: what a twin was found to be running."""

    model_config = ConfigDict(str_strip_whitespace=True)

    software: str = Field(..., min_length=1, max_length=255)
    version: str = Field(..., min_length=1, max_length=64)


class LegacyCheckResponse(BaseModel):
    """Output of the Legacy Profiler's comparison against reference data."""

    software: str
    version: str
    classification: LegacyFlag
    eol_date: Optional[date] = None
    matched_profile_id: Optional[int] = Field(
        None, description="legacy_profiles.id matched, if any. Null when classification is 'unknown'."
    )
