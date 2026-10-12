from sqlalchemy import Column, DateTime, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from database.base import Base


class Approval(Base):
    """
    Human approval decision for remediation or validation actions.

    recommendation_id/target_twin_id are set when the approval request
    concerns a specific proposed remediation (the normal case this project
    is built around); remediation_id is filled in afterward, once an
    approved request actually produces a Remediation row to execute --
    it cannot be known at request-creation time. All three are nullable so
    this model keeps working for approval requests that are about
    something other than a twin-targeted remediation (kept for backward
    compatibility with existing rows and callers).
    """

    __tablename__ = "approvals"

    id = Column(Integer, primary_key=True, index=True)
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id"), nullable=False, index=True)
    recommendation_id = Column(Integer, ForeignKey("recommendations.id"), nullable=True, index=True)
    target_twin_id = Column(Integer, ForeignKey("twins.id"), nullable=True, index=True)
    remediation_id = Column(Integer, ForeignKey("remediations.id"), nullable=True, index=True)

    requested_action = Column(String(120), nullable=False)
    status = Column(String(40), default="pending", nullable=False)
    requested_by = Column(String(120), nullable=True)
    decided_by = Column(String(120), nullable=True)
    decision_reason = Column(Text, nullable=True)
    context = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    decided_at = Column(DateTime(timezone=True), nullable=True)

    vulnerability = relationship("Vulnerability", back_populates="approvals")
    recommendation = relationship("Recommendation")
    target_twin = relationship("Twin")
    remediation = relationship("Remediation")
