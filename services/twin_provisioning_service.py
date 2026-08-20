import logging
from fastapi import HTTPException
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from database.models.asset import Asset
from database.models.twin import Twin
from database.models.vulnerability import Vulnerability

from integrations.digital_twin.twin_client import DigitalTwinClient
from sqlalchemy.exc import SQLAlchemyError

logger = logging.getLogger(__name__)


class TwinProvisioningService:
    """
    Handles provisioning and destruction of Digital Twins.
    """

    def __init__(
        self,
        db: Session,
        twin_client: DigitalTwinClient | None = None,
    ):
        self.db = db
        self.twin_client = twin_client or DigitalTwinClient()

    async def provision(
        self,
        vulnerability_id: int,
        ttl_seconds: int | None = None,
    ) -> Twin:

        # ---------------------------------------------------
        # Lookup Vulnerability
        # ---------------------------------------------------

        vulnerability = (
            self.db.query(Vulnerability)
            .filter(Vulnerability.id == vulnerability_id)
            .first()
        )

        if vulnerability is None:
            raise HTTPException(
                status_code=404,
                detail=f"Vulnerability {vulnerability_id} not found.",
            )

        # ---------------------------------------------------
        # Lookup Asset
        # ---------------------------------------------------

        asset = (
            self.db.query(Asset)
            .filter(Asset.id == vulnerability.asset_id)
            .first()
        )

        if asset is None:
            raise HTTPException(
                status_code=404,
                detail=f"Asset {vulnerability.asset_id} not found.",
            )

        logger.info(
            "Provisioning Twin for %s",
            vulnerability.cve_id,
        )

        # ---------------------------------------------------
        # Call Twin Generator
        # ---------------------------------------------------

        try:

            twin_data = await self.twin_client.create_twin(
                cve=vulnerability.cve_id,
                host=asset.hostname,
                software=asset.software,
                version=asset.version,
                environment=asset.environment,
                ttl_seconds=ttl_seconds,
            )

        except RuntimeError as exc:

            logger.exception("Twin Generator failed.")

            raise HTTPException(
                status_code=502,
                detail=str(exc),
            )

        # ---------------------------------------------------
        # Persist Twin
        # ---------------------------------------------------

        twin = Twin(
            asset_id=asset.id,
            name=f"{asset.name}-{vulnerability.cve_id}",
            provider="TwinGenerator",
            status=twin_data.get("status", "requested"),
            endpoint=twin_data.get("ip_address"),
            topology=twin_data,
            notes=f"Provisioned for {vulnerability.cve_id}",

            external_twin_id=twin_data.get("id"),
            external_uuid=twin_data.get("uuid"),

            environment=twin_data.get("environment"),

            ip_address=twin_data.get("ip_address"),

            network=twin_data.get("network"),

            twin_image=twin_data.get("twin_image"),

            vm_name=twin_data.get("vm_name"),

            health=twin_data.get("health"),

            legacy_flag=twin_data.get("legacy_flag"),

            destroy_at=twin_data.get("destroy_at"),
        )

        try:

            self.db.add(twin)

            self.db.commit()

            self.db.refresh(twin)
        except Exception as exc:

            self.db.rollback()

            logger.exception(exc)

            raise HTTPException(
                status_code=500,
                detail="Failed to save Twin.",
            )
        logger.info(
            "Twin %s provisioned successfully.",
            twin.id,
        )

        return twin

    async def destroy(
        self,
        twin_id: int,
    ) -> Twin:

        twin = (
        self.db.query(Twin)
        .filter(Twin.id == twin_id)
        .first()
        )

        if twin is None:

            raise HTTPException(
                status_code=404,
                detail="Twin not found.",
            )

        if twin.external_twin_id is not None:

            try:

                await self.twin_client.destroy_twin(
                    str(twin.external_twin_id)
                )

            except RuntimeError as exc:

                raise HTTPException(
                    status_code=502,
                    detail=str(exc),
                )

        twin.status = "destroyed"

        try:

            self.db.commit()

            self.db.refresh(twin)

        except SQLAlchemyError:

            self.db.rollback()

            raise HTTPException(
                status_code=500,
                detail="Failed to update Twin.",
            )

        logger.info(
            "Twin %s destroyed.",
            twin.id,
        )

        return twin