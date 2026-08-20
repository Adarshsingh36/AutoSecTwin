from sqlalchemy import Column, DateTime, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from database.base import Base


class Approval(Base):
    """Human approval decision for remediation or validation actions."""

    __tablename__ = "approvals"

    id = Column(Integer, primary_key=True, index=True)
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id"), nullable=False, index=True)
    requested_action = Column(String(120), nullable=False)
    status = Column(String(40), default="pending", nullable=False)
    requested_by = Column(String(120), nullable=True)
    decided_by = Column(String(120), nullable=True)
    decision_reason = Column(Text, nullable=True)
    context = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    decided_at = Column(DateTime(timezone=True), nullable=True)

    vulnerability = relationship("Vulnerability", back_populates="approvals")
