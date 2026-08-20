"""Digital Twin Generator - Pydantic schemas."""

from __future__ import annotations

from twin_generator.schemas.legacy_profile import (
    LegacyCheckRequest,
    LegacyCheckResponse,
    LegacyProfileCreate,
    LegacyProfileRead,
)
from twin_generator.schemas.twin_instance import (
    TwinCreateRequest,
    TwinDestroyResponse,
    TwinHealthResponse,
    TwinListItem,
    TwinRead,
)
from twin_generator.schemas.twin_log import TwinLogRead
from twin_generator.schemas.twin_registry import (
    RegistryEntryCreate,
    RegistryEntryRead,
    RegistryEntryUpdate,
)

__all__ = [
    "TwinCreateRequest",
    "TwinRead",
    "TwinListItem",
    "TwinHealthResponse",
    "TwinDestroyResponse",
    "RegistryEntryCreate",
    "RegistryEntryUpdate",
    "RegistryEntryRead",
    "LegacyProfileCreate",
    "LegacyProfileRead",
    "LegacyCheckRequest",
    "LegacyCheckResponse",
    "TwinLogRead",
]
