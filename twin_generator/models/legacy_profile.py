"""
SQLAlchemy model: legacy_profiles

Reference data consulted by the Legacy Profiler to classify a twin's
OS/software stack as Legacy, Supported, or Unknown by comparing against
End-of-Life dates. This table is metadata only -- the Legacy Profiler
never blocks twin creation, it only annotates.
"""

from __future__ import annotations

from datetime import date
from typing import Optional

from sqlalchemy import Boolean, Date, Index, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from twin_generator.models.base import Base


class LegacyProfile(Base):
    """End-of-Life reference entry for a piece of software/OS at a given version."""

    __tablename__ = "legacy_profiles"
    __table_args__ = (
        Index("ix_legacy_profiles_software", "software"),
        UniqueConstraint("software", "version", name="uq_legacy_profiles_software_version"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    software: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        doc="Software or OS name, e.g. 'Ubuntu', 'Apache Struts'.",
    )

    version: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        doc="Version string this EOL record applies to.",
    )

    eol_date: Mapped[Optional[date]] = mapped_column(
        Date,
        nullable=True,
        doc="Vendor-published End-of-Life date, if known.",
    )

    vendor: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        doc="Vendor or maintaining organization.",
    )

    supported: Mapped[Optional[bool]] = mapped_column(
        Boolean,
        nullable=True,
        doc="Whether the vendor currently supports this software/version, if known.",
    )

    def __repr__(self) -> str:  # pragma: no cover - debug aid only
        return f"<LegacyProfile software={self.software!r} version={self.version!r}>"
