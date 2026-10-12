"""FastAPI router: Twin Orchestrator (POST/GET /twins*)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List

import structlog
from fastapi import APIRouter, Depends, HTTPException, status

from twin_generator.api.deps import get_orchestrator
from twin_generator.schemas.twin_instance import (
    TwinCreateRequest,
    TwinDestroyResponse,
    TwinHealthResponse,
    TwinListItem,
    TwinRead,
)
from twin_generator.services.orchestrator import TwinOrchestrator
from twin_generator.utils.enums import TwinStatus
from twin_generator.utils.exceptions import TwinNotFoundError, TwinProvisioningError

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/twins", tags=["Twin Orchestrator"])


@router.post("/create", response_model=TwinRead, status_code=status.HTTP_201_CREATED)
def create_twin(
    payload: TwinCreateRequest, orchestrator: TwinOrchestrator = Depends(get_orchestrator)
) -> TwinRead:
    try:
        twin = orchestrator.create_twin(payload)
        logger.info("twin_create_succeeded", twin_id=twin.id, cve=payload.cve)
    except Exception as exc:
        logger.exception("twin_create_failed", cve=payload.cve, error=str(exc))
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)) from exc
    return TwinRead.model_validate(twin)


@router.get("", response_model=List[TwinListItem])
def list_twins(orchestrator: TwinOrchestrator = Depends(get_orchestrator)) -> List[TwinListItem]:
    twins = orchestrator.list_twins()
    return [TwinListItem.model_validate(t) for t in twins]


@router.get("/{twin_id}", response_model=TwinRead)
def get_twin(twin_id: int, orchestrator: TwinOrchestrator = Depends(get_orchestrator)) -> TwinRead:
    try:
        twin = orchestrator.get_twin(twin_id)
    except TwinNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return TwinRead.model_validate(twin)


@router.get("/{twin_id}/health", response_model=TwinHealthResponse)
def get_twin_health(
    twin_id: int, orchestrator: TwinOrchestrator = Depends(get_orchestrator)
) -> TwinHealthResponse:
    try:
        twin, inspection = orchestrator.refresh_twin_health(twin_id)
    except TwinNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except TwinProvisioningError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc
    return TwinHealthResponse(
        id=twin.id,
        uuid=twin.uuid,
        status=twin.status,
        health=twin.health,
        checked_at=datetime.now(timezone.utc),
        source="live_docker" if inspection is not None else "stored_state",
        container_status=(
            inspection["container_status"] if inspection is not None else None
        ),
        image=inspection["image"] if inspection is not None else None,
    )


@router.post("/{twin_id}/destroy", response_model=TwinDestroyResponse)
def destroy_twin(
    twin_id: int, orchestrator: TwinOrchestrator = Depends(get_orchestrator)
) -> TwinDestroyResponse:
    try:
        twin = orchestrator.destroy_twin(twin_id)
    except TwinNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return TwinDestroyResponse(
        id=twin.id, uuid=twin.uuid, status=TwinStatus(twin.status), destroyed_at=datetime.now(timezone.utc)
    )
