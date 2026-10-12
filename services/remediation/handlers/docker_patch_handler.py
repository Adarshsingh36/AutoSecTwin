"""
DockerPatchHandler.

Models remediation the way it actually has to work for a Docker-based
Digital Twin: there is no "patch the running container" -- the Twin
Generator doesn't expose one, and pretending to patch a running Java
process inside a container that was never designed to be mutated in place
would be exactly the kind of fake remediation this project exists to
eliminate. Instead:

    OLD TWIN (vulnerable image)
        -> destroy the managed twin (TwinProvisioningService.destroy)
        -> provision a new twin requesting the fixed version explicitly
           (TwinProvisioningService.provision(version_override=...), which
           Phase 2 made possible via the CVE Image Registry's per-version
           lookup)
        -> wait for the new twin to report healthy
    NEW TWIN (fixed image)

Reuses TwinProvisioningService end to end -- this is not a second Docker
orchestration layer, it's the same one remediation now drives too.
"""

from __future__ import annotations

import logging

from database.models.twin import Twin
from database.models.vulnerability import Vulnerability
from services.common.version_utils import detect_version_from_image_tag
from services.remediation.handlers.base import PartialRemediationFailure, PatchResult
from services.twin_provisioning_service import TwinProvisioningService

logger = logging.getLogger(__name__)

_HEALTHY_VALUES = {"healthy", "ready", "running"}


class DockerPatchHandler:
    """Destroys the vulnerable Docker twin and redeploys it at a fixed version."""

    def __init__(self, provisioning_service: TwinProvisioningService) -> None:
        self.provisioning_service = provisioning_service

    async def apply(
        self,
        twin: Twin,
        vulnerability: Vulnerability,
        fixed_version: str,
    ) -> PatchResult:
        old_twin_id = twin.id
        old_image = twin.twin_image
        old_endpoint = twin.endpoint
        old_container_id = twin.external_uuid
        old_version = detect_version_from_image_tag(old_image)
        original_destroyed = False

        logger.info(
            "DockerPatchHandler: destroying twin %s (image=%s) for vulnerability %s",
            old_twin_id,
            old_image,
            vulnerability.id,
        )

        try:
            # Raises on failure -- PatchExecutor treats that as a genuine
            # execution failure (status=FAILED), not a silent no-op.
            await self.provisioning_service.destroy(old_twin_id)
            original_destroyed = True

            logger.info(
                "DockerPatchHandler: provisioning replacement twin for vulnerability %s "
                "requesting version=%s",
                vulnerability.id,
                fixed_version,
            )

            new_twin = await self.provisioning_service.provision(
                vulnerability_id=vulnerability.id,
                version_override=fixed_version,
            )
            new_twin = await self.provisioning_service.wait_until_ready(
                new_twin,
                expected_version=fixed_version,
            )

            actual_version = detect_version_from_image_tag(getattr(new_twin, "twin_image", None))
            if actual_version != fixed_version:
                raise PartialRemediationFailure(
                    (
                        f"Replacement twin {getattr(new_twin, 'id', None)} did not match the approved "
                        f"fixed_version {fixed_version!r} (actual {actual_version!r})."
                    ),
                    target_modified=True,
                    old_twin_id=old_twin_id,
                    new_twin_id=getattr(new_twin, "id", None),
                    evidence={
                        "partial_failure": True,
                        "replacement_ready": False,
                        "approved_fixed_version": fixed_version,
                        "actual_version": actual_version,
                    },
                )

            healthy = (new_twin.health or "").lower() in _HEALTHY_VALUES

            return PatchResult(
                target_modified=True,
                healthy=healthy,
                old_twin_id=old_twin_id,
                new_twin_id=new_twin.id,
                old_image=old_image,
                new_image=new_twin.twin_image,
                old_version=old_version,
                new_version=fixed_version,
                old_endpoint=old_endpoint,
                new_endpoint=new_twin.endpoint,
                old_container_id=old_container_id,
                new_container_id=new_twin.external_uuid,
                health=new_twin.health,
            )
        except PartialRemediationFailure:
            raise
        except Exception as exc:  # noqa: BLE001
            if original_destroyed:
                raise PartialRemediationFailure(
                    (
                        f"Replacement provisioning failed after destroying original twin {old_twin_id}: "
                        f"{exc}"
                    ),
                    target_modified=True,
                    old_twin_id=old_twin_id,
                    new_twin_id=None,
                    evidence={
                        "partial_failure": True,
                        "replacement_ready": False,
                        "original_destroyed": True,
                        "error": str(exc),
                    },
                ) from exc
            raise
