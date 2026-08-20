from sqlalchemy import Boolean, Column, Date, DateTime, Float, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from database.base import Base


class LegacyProfile(Base):
    __tablename__ = "legacy_profiles"
    id = Column(Integer, primary_key=True)

    asset_id = Column(Integer)

    vendor = Column(String(255))

    product = Column(String(255))

    version = Column(String(64))

    fingerprint = Column(String)

    unsupported = Column(Boolean)

    eol = Column(Date)

    support_status = Column(String)

    legacy_penalty = Column(Float)

    compensating_controls = Column(Text)

    route_to_specialist = Column(Boolean)

    metadata_json = Column(JSON)

    created_at = Column(DateTime)


class SpecialistQueue(Base):
    """Manual review queue for legacy assets that need specialist handling."""

    __tablename__ = "specialist_queue"

    id = Column(Integer, primary_key=True, index=True)
    legacy_profile_id = Column(Integer, ForeignKey("legacy_profiles.id"), nullable=True, index=True)
    queue_type = Column(String(80), nullable=False)
    status = Column(String(40), default="pending", nullable=False)
    reason = Column(Text, nullable=False)
    payload = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    legacy_profile = relationship("LegacyProfile")
