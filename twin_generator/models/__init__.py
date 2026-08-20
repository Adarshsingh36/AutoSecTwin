"""
Digital Twin Generator - SQLAlchemy models.

Importing this package registers all four tables (twin_instances,
twin_registry, legacy_profiles, twin_logs) on the shared declarative Base,
so Alembic autogenerate and application startup both see the complete
metadata regardless of import order elsewhere in the project.
"""

from __future__ import annotations

from twin_generator.models.base import Base
from twin_generator.models.legacy_profile import LegacyProfile
from twin_generator.models.twin_instance import TwinInstance
from twin_generator.models.twin_log import TwinLog
from twin_generator.models.twin_registry import TwinRegistry

__all__ = [
    "Base",
    "TwinInstance",
    "TwinRegistry",
    "LegacyProfile",
    "TwinLog",
]
