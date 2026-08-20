"""
SQLAlchemy model: twin_instances

Central record for every digital twin created by the Twin Orchestrator,
regardless of whether it was produced by the Docker Twin Engine or the
VM Twin Engine. Rows are written on creation and updated as the twin
progresses through its lifecycle, ending in DESTROYED.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Index, String, func
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from twin_generator.models.base import Base
from twin_generator.utils.enums import EnvironmentType, HealthStatus, LegacyFlag, TwinStatus


class TwinInstance(Base):
    """A single isolated digital twin (Docker container or VM)."""

    __tablename__ = "twin_instances"
    __table_args__ = (
        Index("ix_twin_instances_cve", "cve"),
        Index("ix_twin_instances_status", "status"),
        Index("ix_twin_instances_uuid", "uuid", unique=True),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    uuid: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        default=uuid.uuid4,
        nullable=False,
        unique=True,
        doc="Public-facing identifier returned to the Exploit Engine/Validator.",
    )

    host: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        doc="Original host/asset the twin is replicating, as reported by the Classifier.",
    )

    cve: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        doc="CVE identifier this twin was created to reproduce, e.g. CVE-2021-44228.",
    )

    status: Mapped[TwinStatus] = mapped_column(
        String(20),
        nullable=False,
        default=TwinStatus.PENDING,
        doc="Lifecycle status of the twin.",
    )

    environment: Mapped[EnvironmentType] = mapped_column(
        String(10),
        nullable=False,
        doc="Whether this twin is a Docker container or a VM.",
    )

    twin_image: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        doc="Docker image reference used, if environment == docker.",
    )

    vm_name: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        doc="VirtualBox VM/snapshot name used, if environment == vm.",
    )

    ip_address: Mapped[Optional[str]] = mapped_column(
        String(45),
        nullable=True,
        doc="Assigned IP address on the isolated twin network (IPv4 or IPv6).",
    )

    network: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        doc="Name/ID of the dedicated isolated bridge network for this twin.",
    )

    health: Mapped[HealthStatus] = mapped_column(
        String(10),
        nullable=False,
        default=HealthStatus.UNKNOWN,
        doc="Result of the most recent health check.",
    )

    legacy_flag: Mapped[LegacyFlag] = mapped_column(
        String(10),
        nullable=False,
        default=LegacyFlag.UNKNOWN,
        doc="Legacy Profiler classification for this twin's OS/software stack.",
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    destroy_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        doc="TTL expiry timestamp; the Twin Cleanup Manager destroys twins past this time.",
    )

    logs: Mapped[list["TwinLog"]] = relationship(
        "TwinLog",
        back_populates="twin",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    def __repr__(self) -> str:  # pragma: no cover - debug aid only
        return (
            f"<TwinInstance id={self.id} uuid={self.uuid} cve={self.cve!r} "
            f"status={self.status} environment={self.environment}>"
        )
