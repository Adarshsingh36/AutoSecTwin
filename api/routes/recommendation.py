from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from api.dependencies import get_db
from api.schemas.autosectwin import RecommendationGenerateRequest, RecommendationResponse
from database.models.recommendation import Recommendation
from services.recommendation.recommendation_engine import RecommendationEngine

router = APIRouter()


@router.post("/generate", response_model=RecommendationResponse)
def generate_recommendation(payload: RecommendationGenerateRequest, db: Session = Depends(get_db)) -> Recommendation:
    """Generate a remediation recommendation."""

    return RecommendationEngine(db).generate(
        vulnerability_id=payload.vulnerability_id,
        recommendation_type=payload.recommendation_type,
        context=payload.context,
    )
