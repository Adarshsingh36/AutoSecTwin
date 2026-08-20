from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from api.dependencies import get_db
from api.schemas.autosectwin import DriftResponse, TrustCompareRequest, TrustCompareResponse, TrustStatisticsResponse
from database.models.trust import ModelDrift
from services.trust import PredictionComparison, TrustService

router = APIRouter()


@router.post("/compare", response_model=TrustCompareResponse)
def compare_prediction(payload: TrustCompareRequest, db: Session = Depends(get_db)) -> TrustCompareResponse:
    """Compare an ML prediction against exploit validation."""

    result = TrustService(db).compare_prediction(
        PredictionComparison(
            vulnerability_id=payload.vulnerability_id,
            prediction_score=payload.prediction_score,
            validation_score=payload.validation_score,
            shap_explanation=payload.shap_explanation,
            metadata=payload.metadata or {},
        )
    )
    return TrustCompareResponse(**result.__dict__)


@router.get("/statistics", response_model=TrustStatisticsResponse)
def get_statistics(db: Session = Depends(get_db)) -> dict[str, float | int]:
    """Return aggregate trust statistics."""

    return TrustService(db).get_trust_metrics()


@router.get("/drift", response_model=list[DriftResponse])
def get_drift(db: Session = Depends(get_db)) -> list[ModelDrift]:
    """Return model drift history."""

    return db.query(ModelDrift).order_by(ModelDrift.id.desc()).all()
