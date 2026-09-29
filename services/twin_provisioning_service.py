import asyncio
import logging
import time
from fastapi import HTTPException
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from core.config import settings
from database.models.asset import Asset
from database.models.twin import Twin
from database.models.vulnerability import Vulnerability

from integrations.digital_twin.twin_client import DigitalTwinClient

logger = logging.getLogger(__name__)

READY_HEALTH_VALUES = {"healthy", "ready", "running"}
FAILED_HEALTH_VALUES = {"failed", "error", "unhealthy"}


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
            endpoint=twin_data.get("endpoint") or twin_data.get("ip_address"),
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

    async def wait_until_ready(
        self,
        twin: Twin,
        timeout_seconds: float | None = None,
        poll_interval_seconds: float | None = None,
    ) -> Twin:
        """Poll the Digital Twin Generator until the twin reports healthy.

        If the twin already reports a ready health value, returns
        immediately. Never blocks indefinitely -- raises ``HTTPException``
        (502) if the timeout elapses or the twin reports a failed state.
        """

        timeout_seconds = timeout_seconds or settings.TWIN_HEALTH_TIMEOUT_SECONDS
        poll_interval_seconds = poll_interval_seconds or settings.TWIN_HEALTH_POLL_INTERVAL_SECONDS

        if (twin.health or "").lower() in READY_HEALTH_VALUES:
            return twin

        if twin.external_twin_id is None:
            # No external reference to poll -- trust the initial status.
            return twin

        deadline = time.monotonic() + timeout_seconds

        while time.monotonic() < deadline:
            try:
                health_data = await self.twin_client.get_twin_health(str(twin.external_twin_id))
            except RuntimeError as exc:
                logger.warning("Twin health check failed for twin %s: %s", twin.id, exc)
                await asyncio.sleep(poll_interval_seconds)
                continue

            health = str(health_data.get("health") or health_data.get("status") or "").lower()

            if health in READY_HEALTH_VALUES:
                twin.health = health
                twin.status = "ready"
                self.db.commit()
                self.db.refresh(twin)
                return twin

            if health in FAILED_HEALTH_VALUES:
                twin.health = health
                twin.status = "failed"
                self.db.commit()
                self.db.refresh(twin)
                raise HTTPException(
                    status_code=502,
                    detail=f"Twin {twin.id} reported failed health state: {health}",
                )

            await asyncio.sleep(poll_interval_seconds)

        raise HTTPException(
            status_code=504,
            detail=f"Timed out waiting for Twin {twin.id} to become healthy.",
        )

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