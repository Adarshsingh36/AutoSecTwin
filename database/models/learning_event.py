from sqlalchemy import Column, DateTime, Float, Integer, JSON, String, Text
from sqlalchemy.sql import func

from database.base import Base


class LearningEvent(Base):
    """Feedback event used by continuous learning."""

    __tablename__ = "learning_events"

    id = Column(Integer, primary_key=True, index=True)
    event_type = Column(String(80), nullable=False)
    source = Column(String(120), nullable=False)
    label = Column(String(80), nullable=True)
    confidence_before = Column(Float, nullable=True)
    confidence_after = Column(Float, nullable=True)
    payload = Column(JSON, nullable=True)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
