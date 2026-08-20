from sqlalchemy import Column, DateTime, Integer, JSON, String
from sqlalchemy.sql import func

from database.base import Base


class Audit(Base):
    """Immutable audit event."""

    __tablename__ = "audits"

    id = Column(Integer, primary_key=True, index=True)
    actor = Column(String(120), nullable=True)
    action = Column(String(120), nullable=False)
    entity_type = Column(String(80), nullable=False)
    entity_id = Column(Integer, nullable=True)
    details = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
