"""
PatchExecutor.

This is the file the "DRY RUN" problem was about. It replaces
RemediationEngine.apply()'s real-mode no-op with an executor that:

  1. Verifies every precondition explicitly (approval exists, target twin
     exists and is AutoSecTwin-managed, vulnerability/twin/asset agree,
     fixed_version is specified and actually different from the current
     one, a recommendation backs this remediation).
  2. Delegates the actual work to a handler selected by twin environment
     (only DockerPatchHandler exists today -- see handlers/base.py for why
     that's deliberate, not an oversight).
  3. Never marks target_modified=True or status=EXECUTED unless the
     handler itself performed and confirmed the modification.
  4. Never marks status=VERIFIED -- that only ever happens as the result
     of a real revalidation run (Phase 5), never from execution alone.

A precondition failure routes to MANUAL_ACTION_REQUIRED (a human needs to
fix the setup -- wrong twin, no approval, etc.). A failure *during*
execution (the handler's destroy/provision calls themselves failing)
routes to FAILED (an execution-level problem). The two are kept distinct
because they call for different follow-up action.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session

from core.exceptions import ASDEError
from database.models.approval import Approval
from database.models.remediation import Remediation
from database.models.twin import Twin
from database.models.vulnerability import Vulnerability
from services.common.version_utils import detect_version_from_image_tag
from services.remediation import status as remediation_status
from services.remediation.handlers.base import PartialRemediationFailure, PatchHandler, PatchResult
from services.remediation.handlers.docker_patch_handler import DockerPatchHandler
from services.twin_provisioning_service import TwinProvisioningService

logger = logging.getLogger(__name__)

# Must match TwinProvisioningService.provision()'s Twin.provider value --
# this is how PatchExecutor confirms a twin is actually one AutoSecTwin
# itself provisioned, not an arbitrary row someone inserted by hand.
MANAGED_TWIN_PROVIDER = "TwinGenerator"

_ENVIRONMENT_TO_HANDLER_KEY = {"docker": "docker"}


class RemediationExecutionError(ASDEError):
    """Raised when a remediation cannot be executed as requested.

    Caught internally by PatchExecutor.execute() and converted into a
    MANUAL_ACTION_REQUIRED remediation rather than propagating raw -- the
    caller always gets back the (updated) Remediation row, not an
    exception, so the API layer has one consistent response shape.
    """


class PatchExecutor:
    """Verifies preconditions, then delegates real remediation to a handler."""

    def __init__(
        self,
        db: Session,
        provisioning_service: Optional[TwinProvisioningService] = None,
        handlers: Optional[dict[str, PatchHandler]] = None,
    ) -> None:
        self.db = db
        self.provisioning_service = provisioning_service or TwinProvisioningService(db)
        self.handlers: dict[str, PatchHandler] = handlers or {
            "docker": DockerPatchHandler(self.provisioning_service)
        }

    async def execute(self, remediation_id: int, fixed_version: str) -> Remediation:
        """Execute a remediation. Always returns the (updated) Remediation
        row -- never raises for an ordinary precondition failure, since
        that's recorded as MANUAL_ACTION_REQUIRED on the row itself.
        """

        remediation = self._get_remediation(remediation_id)

        try:
            twin, vulnerability = self._verify_preconditions(remediation, fixed_version)
        except RemediationExecutionError as exc:
            self._mark_manual_action_required(remediation, str(exc))
            return remediation

        handler_key = _ENVIRONMENT_TO_HANDLER_KEY.get((twin.environment or "").lower())
        handler = self.handlers.get(handler_key) if handler_key else None

        if handler is None:
            self._mark_manual_action_required(
                remediation,
                f"No remediation handler available for twin environment {twin.environment!r}.",
            )
            return remediation

        try:
            approved_approval = (
                self.db.query(Approval)
                .filter(
                    Approval.remediation_id == remediation.id,
                    Approval.status == "approved",
                )
                .first()
            )
            if approved_approval is None:
                raise RemediationExecutionError(
                    f"Remediation {remediation.id} has no approved Approval record; "
                    "refusing to execute without human approval."
                )

            if approved_approval.target_twin_id != twin.id:
                raise RemediationExecutionError(
                    "Approved target_twin_id does not match the remediation target."
                )

            approved_version = (approved_approval.context or {}).get("fixed_version")
            if approved_version != fixed_version:
                raise RemediationExecutionError(
                    "Approved fixed_version does not match the requested fixed version."
                )

            if approved_approval.vulnerability_id != remediation.vulnerability_id:
                raise RemediationExecutionError(
                    "Approval vulnerability does not match the remediation."
                )

            if approved_approval.recommendation_id != remediation.recommendation_id:
                raise RemediationExecutionError(
                    "Approval recommendation does not match the remediation."
                )
        except RemediationExecutionError as exc:
            self._mark_manual_action_required(remediation, str(exc))
            return remediation

        remediation.status = remediation_status.QUEUED
        remediation.executor = "PatchExecutor"
        remediation.handler = handler.__class__.__name__
        remediation.execution_authorized = True
        self._save(remediation)

        remediation.status = remediation_status.EXECUTING
        remediation.execution_started_at = datetime.now(timezone.utc)
        self._save(remediation)

        result: PatchResult | None = None
        try:
            result = await handler.apply(
                twin=twin, vulnerability=vulnerability, fixed_version=fixed_version
            )
            actual_version = detect_version_from_image_tag(getattr(result, "new_image", None))
            if result.new_image is not None and actual_version is not None and actual_version != fixed_version:
                raise PartialRemediationFailure(
                    (
                        f"Replacement twin image version mismatch: approved fixed_version "
                        f"{fixed_version!r}, actual {actual_version!r}."
                    ),
                    target_modified=bool(result.target_modified),
                    old_twin_id=result.old_twin_id,
                    new_twin_id=result.new_twin_id,
                    evidence={
                        "approved_fixed_version": fixed_version,
                        "actual_version": actual_version,
                    },
                )
            if result.new_image is not None and actual_version is None:
                raise PartialRemediationFailure(
                    (
                        f"Replacement twin image version could not be established for approved "
                        f"fixed_version {fixed_version!r}; refusing to treat the running application "
                        "as verified."
                    ),
                    target_modified=bool(result.target_modified),
                    old_twin_id=result.old_twin_id,
                    new_twin_id=result.new_twin_id,
                    evidence={
                        "approved_fixed_version": fixed_version,
                        "actual_version": None,
                    },
                )
        except PartialRemediationFailure as exc:  # noqa: BLE001 - partial execution recorded faithfully
            logger.warning(
                "Remediation %s partially failed after original target change: %s",
                remediation_id,
                exc,
            )
            remediation.status = remediation_status.FAILED
            remediation.target_modified = bool(exc.target_modified or exc.new_twin_id is not None)
            remediation.target_twin_id = None
            remediation.evidence = {
                **(remediation.evidence or {}),
                **(exc.evidence or {}),
                "error": str(exc),
                "partial_failure": True,
                "replacement_ready": False,
                "old_twin_id": exc.old_twin_id,
                "replacement_twin_id": exc.new_twin_id,
            }
            remediation.execution_completed_at = datetime.now(timezone.utc)
            self._save(remediation)
            return remediation
        except Exception as exc:  # noqa: BLE001 - execution-level failure, recorded not re-raised
            logger.exception("Remediation %s execution failed", remediation_id)
            remediation.status = remediation_status.FAILED
            remediation.target_modified = bool(
                result is not None and (result.target_modified or result.new_twin_id is not None)
            )
            remediation.target_twin_id = None
            remediation.evidence = {
                **(remediation.evidence or {}),
                "error": str(exc),
                **(
                    {
                        "partial_failure": True,
                        "replacement_ready": False,
                        "old_twin_id": result.old_twin_id,
                        "replacement_twin_id": result.new_twin_id,
                    }
                    if result is not None
                    else {}
                ),
            }
            remediation.execution_completed_at = datetime.now(timezone.utc)
            self._save(remediation)
            return remediation

        remediation.status = remediation_status.EXECUTED
        remediation.target_modified = result.target_modified

        # From here on, the remediation's target IS the new (fixed) twin --
        # that's what Phase 5's revalidation must run against. The old
        # twin's identity is preserved in evidence for the audit trail.
        remediation.target_twin_id = result.new_twin_id if result.new_twin_id is not None else None

        remediation.evidence = result.to_evidence_dict()
        remediation.execution_completed_at = datetime.now(timezone.utc)
        self._save(remediation)

        logger.info(
            "Remediation %s executed: target_modified=%s new_twin_id=%s",
            remediation_id,
            result.target_modified,
            result.new_twin_id,
        )

        return remediation

    # -- preconditions -----------------------------------------------------

    def _verify_preconditions(
        self, remediation: Remediation, fixed_version: str
    ) -> tuple[Twin, Vulnerability]:
        if not fixed_version:
            raise RemediationExecutionError("fixed_version must be explicitly specified.")

        if remediation.target_twin_id is None:
            raise RemediationExecutionError(
                f"Remediation {remediation.id} has no target_twin_id; "
                "cannot determine what to modify."
            )

        twin = self.db.query(Twin).filter(Twin.id == remediation.target_twin_id).first()
        if twin is None:
            raise RemediationExecutionError(
                f"Target twin {remediation.target_twin_id} does not exist."
            )

        if twin.provider != MANAGED_TWIN_PROVIDER or twin.external_twin_id is None:
            raise RemediationExecutionError(
                f"Twin {twin.id} is not managed by AutoSecTwin's Twin Generator "
                f"(provider={twin.provider!r}); refusing to modify an unmanaged host."
            )

        if twin.status == "destroyed":
            raise RemediationExecutionError(
                f"Twin {twin.id} has already been destroyed; refusing to re-modify it."
            )

        vulnerability = (
            self.db.query(Vulnerability)
            .filter(Vulnerability.id == remediation.vulnerability_id)
            .first()
        )
        if vulnerability is None:
            raise RemediationExecutionError(
                f"Vulnerability {remediation.vulnerability_id} not found."
            )

        if (
            twin.asset_id is not None
            and vulnerability.asset_id is not None
            and twin.asset_id != vulnerability.asset_id
        ):
            raise RemediationExecutionError(
                f"Target twin {twin.id} (asset {twin.asset_id}) does not match the "
                f"remediation's vulnerability asset {vulnerability.asset_id}; refusing."
            )

        current_version = detect_version_from_image_tag(twin.twin_image)
        if current_version and current_version == fixed_version:
            raise RemediationExecutionError(
                f"Requested fixed_version {fixed_version!r} matches the twin's current "
                f"version {current_version!r}; nothing to remediate."
            )

        approved_approval = (
            self.db.query(Approval)
            .filter(
                Approval.remediation_id == remediation.id,
                Approval.status == "approved",
            )
            .first()
        )
        if approved_approval is None:
            raise RemediationExecutionError(
                f"Remediation {remediation.id} has no approved Approval record; "
                "refusing to execute without human approval."
            )

        if remediation.recommendation_id is None:
            raise RemediationExecutionError(
                f"Remediation {remediation.id} has no backing recommendation_id; "
                "refusing to execute an action with no recommendation behind it."
            )

        return twin, vulnerability

    # -- persistence helpers ------------------------------------------------

    def _get_remediation(self, remediation_id: int) -> Remediation:
        remediation = (
            self.db.query(Remediation).filter(Remediation.id == remediation_id).first()
        )
        if remediation is None:
            raise RemediationExecutionError(f"Remediation {remediation_id} not found.")
        return remediation

    def _mark_manual_action_required(self, remediation: Remediation, reason: str) -> None:
        remediation.status = remediation_status.MANUAL_ACTION_REQUIRED
        remediation.execution_authorized = False
        remediation.target_modified = False
        remediation.evidence = {
            **(remediation.evidence or {}),
            "manual_action_reason": reason,
        }
        self._save(remediation)
        logger.warning("Remediation %s requires manual action: %s", remediation.id, reason)

    def _save(self, remediation: Remediation) -> None:
        self.db.add(remediation)
        self.db.commit()
        self.db.refresh(remediation)
