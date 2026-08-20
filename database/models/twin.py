from sqlalchemy import Column, DateTime, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from database.base import Base


class Twin(Base):
    """Digital twin environment descriptor."""

    __tablename__ = "twins"

    id = Column(Integer, primary_key=True, index=True)

    asset_id = Column(
        Integer,
        ForeignKey("assets.id"),
        nullable=True,
        index=True,
    )

    name = Column(String(255), nullable=False)

    provider = Column(String(80), nullable=False)

    status = Column(
        String(40),
        default="requested",
        nullable=False,
    )

    topology = Column(JSON, nullable=True)

    endpoint = Column(String(500), nullable=True)

    notes = Column(Text, nullable=True)

    # --------------------------------------------------
    # Twin Generator Metadata
    # --------------------------------------------------

    external_twin_id = Column(Integer, nullable=True)

    external_uuid = Column(String(64), nullable=True)

    environment = Column(String(20), nullable=True)

    ip_address = Column(String(50), nullable=True)

    network = Column(String(100), nullable=True)

    twin_image = Column(String(255), nullable=True)

    vm_name = Column(String(255), nullable=True)

    health = Column(String(30), nullable=True)

    legacy_flag = Column(String(30), nullable=True)

    destroy_at = Column(DateTime(timezone=True), nullable=True)

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    asset = relationship(
        "Asset",
        back_populates="twins",
    )

    validations = relationship(
        "Validation",
        back_populates="twin",
    )