"""
SQLAlchemy model: twin_registry

Backs the CVE Image Registry: a maintained mapping between a CVE and the
Docker image capable of reproducing it (e.g. CVE-2021-44228 -> vulhub/log4j).
Supports multiple image/version entries per CVE so new reproductions can be
added over time without overwriting prior ones.
"""

from __future__ import annotations

from typing import Optional

from sqlalchemy import Index, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from twin_generator.models.base import Base


class TwinRegistry(Base):
    """A single CVE -> Docker image mapping entry."""

    __tablename__ = "twin_registry"
    __table_args__ = (
        Index("ix_twin_registry_cve", "cve"),
        UniqueConstraint("cve", "image", "version", name="uq_twin_registry_cve_image_version"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    cve: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        doc="CVE identifier, e.g. CVE-2021-44228.",
    )

    image: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        doc="Docker image reference capable of reproducing the CVE, e.g. vulhub/log4j.",
    )

    environment: Mapped[Optional[str]] = mapped_column(
        String(10),
        nullable=True,
        doc="Preferred reproduction environment for this entry (docker or vm).",
    )

    version: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
        doc="Image tag/version this mapping applies to.",
    )

    notes: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        doc="Free-text notes: known caveats, required env vars, reproduction quirks.",
    )

    def __repr__(self) -> str:  # pragma: no cover - debug aid only
        return f"<TwinRegistry id={self.id} cve={self.cve!r} image={self.image!r}>"
