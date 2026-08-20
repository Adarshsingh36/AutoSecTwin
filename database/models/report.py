from sqlalchemy import Column, DateTime, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from database.base import Base


class Report(Base):
    """Generated technical or executive report."""

    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True)
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id"), nullable=True, index=True)
    report_type = Column(String(60), nullable=False)
    title = Column(String(255), nullable=False)
    content = Column(Text, nullable=False)
    format = Column(String(30), default="json", nullable=False)
    metadata_json = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    vulnerability = relationship("Vulnerability")
