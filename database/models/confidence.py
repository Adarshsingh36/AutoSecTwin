from sqlalchemy import Column, DateTime, Float, ForeignKey, Integer, JSON
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from database.base import Base


class Confidence(Base):
    """Confidence fusion result C(v)."""

    __tablename__ = "confidences"

    id = Column(Integer, primary_key=True, index=True)
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id"), nullable=False, index=True)
    exploitability_probability = Column(Float, nullable=False)
    validation_score = Column(Float, nullable=False)
    exposure_score = Column(Float, nullable=False)
    threat_intelligence_score = Column(Float, nullable=False)
    asset_criticality = Column(Float, nullable=False)
    fused_confidence = Column(Float, nullable=False)
    weights = Column(JSON, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    vulnerability = relationship("Vulnerability", back_populates="confidences")
