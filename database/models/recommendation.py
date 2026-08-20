from sqlalchemy import Column, DateTime, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from database.base import Base


class Recommendation(Base):
    """Patch, code, or configuration recommendation."""

    __tablename__ = "recommendations"

    id = Column(Integer, primary_key=True, index=True)
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id"), nullable=False, index=True)
    recommendation_type = Column(String(50), nullable=False)
    title = Column(String(255), nullable=False)
    content = Column(Text, nullable=False)
    provider = Column(String(80), default="rule_based", nullable=False)
    metadata_json = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    vulnerability = relationship("Vulnerability", back_populates="recommendations")
