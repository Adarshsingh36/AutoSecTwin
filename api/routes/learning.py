import logging

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from api.dependencies import get_db
from api.schemas.autosectwin import LearningEventCreate, LearningEventResponse
from database.models.learning_event import LearningEvent
from services.learning import ContinuousLearningEngine

router = APIRouter()
logger = logging.getLogger(__name__)
engine = ContinuousLearningEngine()


@router.post("/", response_model=LearningEventResponse)
def create_learning_event(payload: LearningEventCreate, db: Session = Depends(get_db)) -> LearningEvent:
    """Persist a continuous learning feedback event."""

    data = payload.model_dump()
    data["payload"] = engine.normalize_event(data.get("payload"))
    event = LearningEvent(**data)
    db.add(event)
    db.commit()
    db.refresh(event)
    logger.info("Created learning event %s", event.id)
    return event


@router.get("/", response_model=list[LearningEventResponse])
def list_learning_events(db: Session = Depends(get_db)) -> list[LearningEvent]:
    """List continuous learning events."""

    return db.query(LearningEvent).order_by(LearningEvent.id.desc()).all()
