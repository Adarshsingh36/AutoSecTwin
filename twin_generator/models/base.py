"""
Binds the Digital Twin Generator's models to the AutoSecTwin project's
existing SQLAlchemy infrastructure (core/database.py).

This module intentionally does NOT define a new declarative Base, engine,
or session factory. Per module scope, the database layer already exists
elsewhere in the project; this file only re-exports what twin_generator
needs so every model/router in this module imports from one place.
"""

from __future__ import annotations

from database.base import Base
from database.session import get_db
__all__ = ["Base", "get_db"]
