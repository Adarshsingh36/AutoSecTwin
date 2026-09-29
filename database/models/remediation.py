from sqlalchemy import (
    Column,
    Integer,
    String,
    Text,
    Float,
    JSON,
    ForeignKey,
    DateTime,
)
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from database.base import Base



class Remediation(Base):
    __tablename__ = "remediations"

    id = Column(Integer, primary_key=True, index=True)

    vulnerability_id = Column(
        Integer,
        ForeignKey("vulnerabilities.id"),
        nullable=False,
        index=True,
    )

    recommendation_id = Column(
        Integer,
        ForeignKey("recommendations.id"),
        nullable=True,
    )

    # Lifecycle:
    # planned -> approved -> queued -> executing -> executed
    # -> revalidating -> verified
    # Failed/manual paths are also supported.
    status = Column(
        String(40),
        default="planned",
        nullable=False,
    )

    action = Column(Text, nullable=False)

    applied_by = Column(String(120), nullable=True)

    verification_score = Column(
        Float,
        default=0.0,
        nullable=False,
    )

    evidence = Column(JSON, nullable=True)

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    applied_at = Column(
        DateTime(timezone=True),
        nullable=True,
    )

    verified_at = Column(
        DateTime(timezone=True),
        nullable=True,
    )

    vulnerability = relationship(
        "Vulnerability",
        back_populates="remediations",
    )

    recommendation = relationship(
        "Recommendation",
    )