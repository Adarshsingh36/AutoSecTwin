"""
FastAPI router: Legacy Profiler.

Endpoint (exactly as specified):
    POST /legacy/check

Classification is metadata only -- this endpoint never rejects a request or
implies a twin should not be created; it just tells the caller (normally the
Twin Orchestrator) whether the software/version is Legacy, Supported, or
Unknown so that can be recorded on the twin.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from twin_generator.api.deps import get_legacy_service
from twin_generator.legacy.service import LegacyProfilerService
from twin_generator.schemas.legacy_profile import LegacyCheckRequest, LegacyCheckResponse

router = APIRouter(prefix="/legacy", tags=["Legacy Profiler"])


@router.post("/check", response_model=LegacyCheckResponse)
def check_legacy_status(
    payload: LegacyCheckRequest,
    service: LegacyProfilerService = Depends(get_legacy_service),
) -> LegacyCheckResponse:
    """Classify a detected (software, version) pair as Legacy/Supported/Unknown."""
    return  service.check(payload.software, payload.version)
