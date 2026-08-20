from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from api.dependencies import get_db
from api.schemas.autosectwin import LegacyProfileRequest, LegacyProfileResponse
from database.models.legacy import LegacyProfile
from services.legacy import LegacyProfiler

router = APIRouter()


@router.post("/profile", response_model=LegacyProfileResponse)
def profile_system(payload: LegacyProfileRequest, db: Session = Depends(get_db)) -> LegacyProfile:
    """Profile a system for legacy software risk."""

    data = payload.model_dump(exclude_none=True)
    data.update(data.pop("metadata", {}) or {})
    return LegacyProfiler(db).profile_system(data)


@router.get("/{profile_id}", response_model=LegacyProfileResponse)
def get_profile(profile_id: int, db: Session = Depends(get_db)) -> LegacyProfile:
    """Fetch a legacy profile."""

    profile = db.get(LegacyProfile, profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Legacy profile not found")
    return profile
