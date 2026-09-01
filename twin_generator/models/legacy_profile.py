"""
Compatibility export for the project's authoritative LegacyProfile model.

The AutoSecTwin database layer already owns the legacy_profiles table.
Do not define a second SQLAlchemy model for the same table here.
"""

from database.models.legacy import LegacyProfile

__all__ = ["LegacyProfile"]
