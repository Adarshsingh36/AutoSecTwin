from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from database.base import Base


class TrustMetric(Base):
    """Persisted trust score produced by comparing AI prediction with validation."""

    __tablename__ = "trust_metrics"

    id = Column(Integer, primary_key=True, index=True)
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id"), nullable=True, index=True)
    prediction_score = Column(Float, nullable=False)
    validation_score = Column(Float, nullable=False)
    agreement = Column(Boolean, nullable=False)
    trust_score = Column(Float, nullable=False)
    shap_explanation = Column(JSON, nullable=True)
    metadata_json = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    vulnerability = relationship("Vulnerability", back_populates="trust_metrics")


class HallucinationLog(Base):
    """Evidence that a model prediction was not supported by validation results."""

    __tablename__ = "hallucination_logs"

    id = Column(Integer, primary_key=True, index=True)
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id"), nullable=True, index=True)
    prediction_score = Column(Float, nullable=False)
    validation_score = Column(Float, nullable=False)
    severity = Column(String(40), nullable=False)
    reason = Column(Text, nullable=False)
    review_status = Column(String(40), default="pending", nullable=False)
    metadata_json = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    vulnerability = relationship("Vulnerability", back_populates="hallucination_logs")


class ModelDrift(Base):
    """Historical model drift signal derived from classifier agreement changes."""

    __tablename__ = "model_drift"

    id = Column(Integer, primary_key=True, index=True)
    model_name = Column(String(120), default="exploitability", nullable=False)
    drift_score = Column(Float, nullable=False)
    baseline_agreement = Column(Float, nullable=False)
    current_agreement = Column(Float, nullable=False)
    retraining_recommended = Column(Boolean, default=False, nullable=False)
    metadata_json = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class AgreementHistory(Base):
    """Point-in-time agreement statistic for the exploitability classifier."""

    __tablename__ = "agreement_history"

    id = Column(Integer, primary_key=True, index=True)
    model_name = Column(String(120), default="exploitability", nullable=False)
    agreement_rate = Column(Float, nullable=False)
    sample_size = Column(Integer, nullable=False)
    metadata_json = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
