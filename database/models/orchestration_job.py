from sqlalchemy import Column, DateTime, Integer, JSON, String, Text, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from database.base import Base


class OrchestrationJob(Base):
    """
    Tracks a single dispatch of the closed-loop orchestrator for one
    vulnerability: Twin provisioning -> exploit validation -> recommendation
    generation, then stopping at the human-approval gate.

    This is a job-tracking record only. It never itself decides whether a
    finding is exploitable, remediated, or verified -- those facts live on
    Validation/Remediation rows. `result_summary` is a pointer to those rows
    (ids), not a restatement of their content.
    """

    __tablename__ = "orchestration_jobs"

    id = Column(Integer, primary_key=True, index=True)

    vulnerability_id = Column(
        Integer, ForeignKey("vulnerabilities.id"), nullable=False, index=True
    )

    job_type = Column(String(80), nullable=False, default="closed_loop_validation")

    # queued -> running -> completed | failed
    status = Column(String(20), nullable=False, default="queued", index=True)

    dispatch_backend = Column(String(20), nullable=True)  # "celery" | "inline"
    celery_task_id = Column(String(255), nullable=True)

    result_summary = Column(JSON, nullable=True)
    error_message = Column(Text, nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)

    vulnerability = relationship("Vulnerability")
