from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from database.base import Base


class LegacyProfile(Base):
    """Software legacy/EOL risk profile.

    Column types below intentionally match the schema created by migration
    ``0002_trust_legacy_extensions`` (eol=Boolean, compensating_controls=JSON).
    A previous revision of this ORM model declared ``eol`` as Date and
    ``compensating_controls`` as Text, which mismatched both the actual
    database schema and the values LegacyProfiler assigns to them.
    """

    __tablename__ = "legacy_profiles"
    id = Column(Integer, primary_key=True)

    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=True)

    vendor = Column(String(120), nullable=False)

    product = Column(String(160), nullable=False)

    version = Column(String(80), nullable=True)

    fingerprint = Column(String(255), nullable=False)

    unsupported = Column(Boolean, nullable=False, default=False)

    eol = Column(Boolean, nullable=False, default=False)

    support_status = Column(String(80), nullable=False)

    legacy_penalty = Column(Float, nullable=False)

    compensating_controls = Column(JSON, nullable=False)

    route_to_specialist = Column(Boolean, nullable=False, default=False)

    metadata_json = Column(JSON, nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


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
