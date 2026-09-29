from sqlalchemy import Column, DateTime, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from database.base import Base


class OrchestrationJob(Base):
    """Tracks a single closed-loop AutoSecTwin workflow run.

    A row is created immediately when ``POST /orchestration/run`` is called
    (status="queued") so the HTTP request never has to block on twin
    provisioning, Metasploit execution, remediation, or revalidation. The
    background task updates ``status``/``stage``/``progress``/``message`` as
    it proceeds so the client can poll ``GET /orchestration/{job_id}``.
    """

    __tablename__ = "orchestration_jobs"

    id = Column(Integer, primary_key=True, index=True)
    job_id = Column(String(64), unique=True, index=True, nullable=False)

    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id"), nullable=False, index=True)

    # queued | running | completed | failed | cancelled
    status = Column(String(20), default="queued", nullable=False)

    # assessment | exploit_selection | twin_provisioning | twin_ready |
    # module_inspection | validation | analysis | remediation |
    # revalidation | report_generation | cleanup | completed | failed
    stage = Column(String(40), default="assessment", nullable=False)

    progress = Column(Integer, default=0, nullable=False)
    message = Column(Text, nullable=True)

    mock_mode = Column(String(10), default="false", nullable=False)
    # "celery" or "inline" -- which dispatch mechanism actually ran this
    # job. Recorded even when TASK_QUEUE_BACKEND requested Celery but the
    # broker was unreachable and the API route fell back to BackgroundTasks.
    queue_backend = Column(String(20), default="inline", nullable=False)

    result_json = Column(JSON, nullable=True)
    error = Column(Text, nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), onupdate=func.now(), nullable=True)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)

    vulnerability = relationship("Vulnerability")
