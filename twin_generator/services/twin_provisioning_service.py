import logging
from typing import Any

from sqlalchemy.orm import Session

from database.models.asset import Asset
from database.models.twin import Twin
from database.models.vulnerability import Vulnerability
from integrations.digital_twin.twin_client import DigitalTwinClient

logger = logging.getLogger(__name__)


class TwinProvisioningService:
    """
    Service responsible for provisioning Digital Twin environments.

    Flow:
        Vulnerability
            ↓
        Asset
            ↓
        DigitalTwinClient
            ↓
        Twin Generator
            ↓
        Docker / VM
            ↓
        Persist Twin metadata
    """

    def __init__(
        self,
        db: Session,
        twin_client: DigitalTwinClient | None = None,
    ) -> None:
        self.db = db
        self.twin_client = twin_client or DigitalTwinClient()

    def provision(
        self,
        vulnerability_id: int,
        ttl_seconds: int | None = None,
    ) -> Twin:
        """
        Provision a Digital Twin for a vulnerability.
        """

        # ------------------------------------------------------------------
        # Load Vulnerability
        # ------------------------------------------------------------------

        vulnerability = (
            self.db.query(Vulnerability)
            .filter(Vulnerability.id == vulnerability_id)
            .first()
        )

        if vulnerability is None:
            raise ValueError(
                f"Vulnerability {vulnerability_id} not found."
            )

        # ------------------------------------------------------------------
        # Load Asset
        # ------------------------------------------------------------------

        asset = (
            self.db.query(Asset)
            .filter(Asset.id == vulnerability.asset_id)
            .first()
        )

        if asset is None:
            raise ValueError(
                f"Asset {vulnerability.asset_id} not found."
            )

        logger.info(
            "Provisioning Twin for CVE %s",
            vulnerability.cve_id,
        )

        # ------------------------------------------------------------------
        # Call Twin Generator
        # ------------------------------------------------------------------

        twin_response: dict[str, Any] = self.twin_client.create_twin(
            cve=vulnerability.cve_id,
            host=asset.hostname,
            software=asset.software,
            version=asset.version,
            environment=asset.environment,
            ttl_seconds=ttl_seconds,
        )

        # ------------------------------------------------------------------
        # Persist Twin
        # ------------------------------------------------------------------

        twin = Twin(
            asset_id=asset.id,

            name=f"{asset.name}-{vulnerability.cve_id}",

            provider="TwinGenerator",

            status=str(twin_response.get("status")),

            endpoint=twin_response.get("ip_address"),

            topology={
                "uuid": str(twin_response.get("uuid")),
                "environment": str(
                    twin_response.get("environment")
                ),
                "network": twin_response.get("network"),
                "image": twin_response.get("twin_image"),
                "vm_name": twin_response.get("vm_name"),
                "health": str(
                    twin_response.get("health")
                ),
                "legacy_flag": str(
                    twin_response.get("legacy_flag")
                ),
                "destroy_at": twin_response.get("destroy_at"),
            },

            notes=f"Provisioned for {vulnerability.cve_id}",
        )

        self.db.add(twin)
        self.db.commit()
        self.db.refresh(twin)

        logger.info(
            "Twin %s successfully provisioned.",
            twin.id,
        )

        return twin

    def destroy(
        self,
        twin: Twin,
    ) -> None:
        """
        Destroy a Twin through the Twin Generator.
        """

        topology = twin.topology or {}

        twin_uuid = topology.get("uuid")

        if not twin_uuid:
            raise ValueError(
                "Twin UUID missing."
            )

        self.twin_client.destroy_twin(
            twin_uuid
        )

        twin.status = "destroyed"

        self.db.commit()

        logger.info(
            "Twin %s destroyed.",
            twin.id,
        )