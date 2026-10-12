from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from database.base import Base


class Remediation(Base):
    """
    Remediation action and verification state.

    target_twin_id is the field this project's remediation work centers
    on: every automatic remediation must be traceable to the exact
    AutoSecTwin-managed Twin it modified (or replaced). It is nullable at
    the database level only for backward compatibility with any rows
    written before this column existed -- the execution layer refuses to
    run against a remediation that has no target_twin_id set.

    executor/handler/execution_authorized/target_modified are kept as
    first-class columns (not buried in `evidence`) because they are
    exactly the facts this project's safety rules are about -- "the
    database status must always reflect reality" is easiest to audit
    when those specific facts are directly queryable, not JSON-encoded.
    Everything else that's handler-specific and variable in shape (old/new
    image, container id, endpoint, health, etc.) stays in `evidence`.
    """

    __tablename__ = "remediations"

    id = Column(Integer, primary_key=True, index=True)
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id"), nullable=False, index=True)
    recommendation_id = Column(Integer, ForeignKey("recommendations.id"), nullable=True)
    target_twin_id = Column(Integer, ForeignKey("twins.id"), nullable=True, index=True)

    status = Column(String(40), default="planned", nullable=False, index=True)
    action = Column(Text, nullable=False)
    applied_by = Column(String(120), nullable=True)

    executor = Column(String(120), nullable=True)
    handler = Column(String(120), nullable=True)
    execution_authorized = Column(Boolean, nullable=False, default=False)
    target_modified = Column(Boolean, nullable=False, default=False)

    verification_score = Column(Float, default=0.0, nullable=False)
    evidence = Column(JSON, nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    execution_started_at = Column(DateTime(timezone=True), nullable=True)
    execution_completed_at = Column(DateTime(timezone=True), nullable=True)
    applied_at = Column(DateTime(timezone=True), nullable=True)
    verified_at = Column(DateTime(timezone=True), nullable=True)

    vulnerability = relationship("Vulnerability", back_populates="remediations")
    recommendation = relationship("Recommendation")
    target_twin = relationship("Twin")
