from sqlalchemy import Column, DateTime, Float, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from database.base import Base


class Validation(Base):
    """Result of exploit validation inside the digital twin."""

    __tablename__ = "validations"

    id = Column(Integer, primary_key=True, index=True)
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id"), nullable=False, index=True)
    exploit_id = Column(Integer, ForeignKey("exploits.id"), nullable=True, index=True)
    twin_id = Column(Integer, ForeignKey("twins.id"), nullable=True, index=True)
    status = Column(String(40), default="pending", nullable=False)
    validation_score = Column(Float, default=0.0, nullable=False)
    evidence = Column(JSON, nullable=True)
    analysis = Column(Text, nullable=True)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    vulnerability = relationship("Vulnerability", back_populates="validations")
    exploit = relationship("Exploit", back_populates="validations")
    twin = relationship("Twin", back_populates="validations")
