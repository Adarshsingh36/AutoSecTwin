import logging

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from services.twin_provisioning_service import TwinProvisioningService
from api.dependencies import get_db
from api.schemas.autosectwin import (
    TwinCreate,
    TwinResponse,
    TwinProvisionRequest,
    TwinProvisionResponse,
    TwinDestroyResponse,
)
from database.models.twin import Twin

router = APIRouter()
logger = logging.getLogger(__name__)


@router.post("/", response_model=TwinProvisionResponse)
@router.post("/provision", response_model=TwinProvisionResponse)
async def provision_twin(
    payload: TwinProvisionRequest,
    db: Session = Depends(get_db),
) -> Twin:

    service = TwinProvisioningService(db)

    twin = await service.provision(
        vulnerability_id=payload.vulnerability_id,
        ttl_seconds=payload.ttl_seconds,
    )

    logger.info("Provisioned twin %s", twin.id)

    return twin


@router.get("/", response_model=list[TwinResponse])
def list_twins(db: Session = Depends(get_db)) -> list[Twin]:
    """List digital twins."""

    return db.query(Twin).order_by(Twin.id.desc()).all()


@router.get("/{twin_id}", response_model=TwinResponse)
def get_twin(twin_id: int, db: Session = Depends(get_db)) -> Twin:
    """Fetch a digital twin."""

    twin = db.get(Twin, twin_id)
    if not twin:
        raise HTTPException(status_code=404, detail="Twin not found")
    return twin

@router.delete("/{twin_id}", response_model=TwinDestroyResponse)
@router.post("/{twin_id}/destroy", response_model=TwinDestroyResponse)
async def destroy_twin(
    twin_id: int,
    db: Session = Depends(get_db),
) -> TwinDestroyResponse:
    """
    Destroy a provisioned digital twin.

    Exposed as both ``DELETE /twins/{id}`` (REST-conventional) and
    ``POST /twins/{id}/destroy`` (kept for backward compatibility with
    existing clients/tests).
    """

    service = TwinProvisioningService(db)

    twin = await service.destroy(twin_id)

    logger.info("Destroyed twin %s", twin_id)

    return TwinDestroyResponse(
        id=twin.id,
        status=twin.status,
        destroyed=twin.status == "destroyed",
        message="Twin destroyed successfully",
    )