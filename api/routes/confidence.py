import logging

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from api.dependencies import get_db
from api.schemas.autosectwin import ConfidenceCalculateResponse, ConfidenceRequest, ConfidenceResponse
from database.models.confidence import Confidence
from services.confidence.fusion import ConfidenceFusionEngine, FusionInputs

router = APIRouter()
logger = logging.getLogger(__name__)
engine = ConfidenceFusionEngine()


@router.post("/", response_model=ConfidenceResponse)
def create_confidence(payload: ConfidenceRequest, db: Session = Depends(get_db)) -> Confidence:
    """Compute and persist confidence fusion C(v)."""

    classifier_uncertainty = payload.classifier_uncertainty
    if classifier_uncertainty is None:
        classifier_uncertainty = 1.0 - float(payload.exploitability_probability or 0.0)
    inputs = FusionInputs(
        classifier_uncertainty=classifier_uncertainty,
        twin_exploit_success_rate=payload.twin_exploit_success_rate
        if payload.twin_exploit_success_rate is not None
        else float(payload.validation_score or 0.0),
        network_exposure=payload.network_exposure
        if payload.network_exposure is not None
        else float(payload.exposure_score or 0.0),
        historical_ai_agreement=payload.historical_ai_agreement
        if payload.historical_ai_agreement is not None
        else 0.0,
        legacy_penalty=payload.legacy_penalty,
    )
    score, weights = engine.fuse(inputs)
    confidence = Confidence(
        vulnerability_id=payload.vulnerability_id,
        exploitability_probability=1.0 - classifier_uncertainty,
        validation_score=inputs.twin_exploit_success_rate,
        exposure_score=inputs.network_exposure,
        threat_intelligence_score=payload.threat_intelligence_score or inputs.historical_ai_agreement,
        asset_criticality=payload.asset_criticality or 0.0,
        fused_confidence=score,
        weights=weights,
    )
    db.add(confidence)
    db.commit()
    db.refresh(confidence)
    logger.info("Computed confidence %.3f for vulnerability %s", score, payload.vulnerability_id)
    return confidence


@router.post("/calculate", response_model=ConfidenceCalculateResponse)
def calculate_confidence(payload: ConfidenceRequest) -> ConfidenceCalculateResponse:
    """Calculate confidence without persisting a database row."""

    classifier_uncertainty = payload.classifier_uncertainty
    if classifier_uncertainty is None:
        classifier_uncertainty = 1.0 - float(payload.exploitability_probability or 0.0)
    inputs = FusionInputs(
        classifier_uncertainty=classifier_uncertainty,
        twin_exploit_success_rate=payload.twin_exploit_success_rate
        if payload.twin_exploit_success_rate is not None
        else float(payload.validation_score or 0.0),
        network_exposure=payload.network_exposure
        if payload.network_exposure is not None
        else float(payload.exposure_score or 0.0),
        historical_ai_agreement=payload.historical_ai_agreement
        if payload.historical_ai_agreement is not None
        else 0.0,
        legacy_penalty=payload.legacy_penalty,
    )
    breakdown = engine.generate_confidence_breakdown(inputs)
    return ConfidenceCalculateResponse(
        vulnerability_id=payload.vulnerability_id,
        confidence=breakdown.confidence,
        weights=breakdown.weights,
        components=breakdown.components,
        explanation=breakdown.explanation,
    )


@router.get("/", response_model=list[ConfidenceResponse])
def list_confidences(db: Session = Depends(get_db)) -> list[Confidence]:
    """List confidence results."""

    return db.query(Confidence).order_by(Confidence.id.desc()).all()
