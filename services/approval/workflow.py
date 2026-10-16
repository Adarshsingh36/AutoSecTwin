"""
Human approval workflow.

    Recommendation -> Review Package -> Human Approval -> Remediation Queue

A rejection prevents remediation outright -- no Remediation row is ever
created for a rejected approval. An approval creates the Remediation row
(status=APPROVED, "queued" in the sense that it now exists and is waiting
to be executed -- see queue_manager.py) but does NOT execute anything
itself; dispatching execution is the API route's job (api/routes/approvals.py),
governed by settings.REMEDIATION_AUTO_APPLY.
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import update
from sqlalchemy.orm import Session

from core.exceptions import ASDEError
from database.models.approval import Approval
from database.models.asset import Asset
from database.models.recommendation import Recommendation
from database.models.twin import Twin
from database.models.validation import Validation
from database.models.vulnerability import Vulnerability
from services.common.version_utils import detect_version_from_image_tag
from services.remediation import status as remediation_status
from database.models.remediation import Remediation

logger = logging.getLogger(__name__)


class ApprovalWorkflowError(ASDEError):
    """Raised when an approval request or decision cannot proceed as asked."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="APPROVAL_WORKFLOW_ERROR", status_code=422)


@dataclass
class RemediationReviewPackage:
    """Everything a human reviewer needs to actually make this decision --
    not just IDs, but the evidence and the specific change being proposed.
    """

    vulnerability_id: int
    cve_id: str
    asset_name: Optional[str]

    recommendation_id: Optional[int]
    recommendation_title: Optional[str]
    recommendation_content: Optional[str]

    target_twin_id: int
    target_twin_name: Optional[str]
    current_version: Optional[str]
    fixed_version: str

    validation_id: Optional[int]
    validation_status: Optional[str]
    validation_score: Optional[float]
    exploit_evidence: Optional[dict[str, Any]]

    limitations: list[str]


def build_review_package(
    db: Session,
    vulnerability_id: int,
    target_twin_id: int,
    fixed_version: str,
    recommendation_id: Optional[int] = None,
) -> RemediationReviewPackage:
    """Assemble the package a human approves or rejects against. Never
    fabricates a field it can't find -- missing evidence shows up as an
    explicit limitation, not a silently blank/default value.
    """

    if target_twin_id is None:
        raise ApprovalWorkflowError("target_twin_id must be specified.")

    limitations: list[str] = []

    vulnerability = db.query(Vulnerability).filter(Vulnerability.id == vulnerability_id).first()
    if vulnerability is None:
        raise ApprovalWorkflowError(f"Vulnerability {vulnerability_id} not found.")

    asset = (
        db.query(Asset).filter(Asset.id == vulnerability.asset_id).first()
        if vulnerability.asset_id is not None
        else None
    )

    twin = db.query(Twin).filter(Twin.id == target_twin_id).first()
    if twin is None:
        raise ApprovalWorkflowError(f"Target twin {target_twin_id} not found.")

    recommendation = None
    if recommendation_id is not None:
        recommendation = (
            db.query(Recommendation).filter(Recommendation.id == recommendation_id).first()
        )
        if recommendation is None:
            raise ApprovalWorkflowError(f"Recommendation {recommendation_id} not found.")
    else:
        limitations.append("No recommendation_id supplied; this request is not backed by a recorded recommendation.")

    current_version = detect_version_from_image_tag(twin.twin_image)
    if current_version is None:
        limitations.append("Could not determine the twin's current version from its image tag.")

    if not fixed_version:
        raise ApprovalWorkflowError("fixed_version must be explicitly specified.")

    if current_version == fixed_version:
        limitations.append(
            f"Requested fixed_version ({fixed_version!r}) is identical to the twin's "
            "current version -- there may be nothing to remediate."
        )

    initial_validation = (
        db.query(Validation)
        .filter(Validation.vulnerability_id == vulnerability_id, Validation.phase == "initial")
        .order_by(Validation.created_at.desc())
        .first()
    )
    if initial_validation is None:
        limitations.append(
            "No initial validation record found for this vulnerability -- this approval "
            "is not backed by confirmed exploit evidence."
        )

    limitations.append(
        "Whether the requested fixed_version is actually registered in the CVE Image "
        "Registry is verified at execution time, not at approval time."
    )

    return RemediationReviewPackage(
        vulnerability_id=vulnerability_id,
        cve_id=vulnerability.cve_id,
        asset_name=asset.name if asset else None,
        recommendation_id=recommendation.id if recommendation else None,
        recommendation_title=recommendation.title if recommendation else None,
        recommendation_content=recommendation.content if recommendation else None,
        target_twin_id=twin.id,
        target_twin_name=twin.name,
        current_version=current_version,
        fixed_version=fixed_version,
        validation_id=initial_validation.id if initial_validation else None,
        validation_status=initial_validation.status if initial_validation else None,
        validation_score=initial_validation.validation_score if initial_validation else None,
        exploit_evidence=initial_validation.evidence if initial_validation else None,
        limitations=limitations,
    )


def request_approval(
    db: Session,
    vulnerability_id: int,
    target_twin_id: int,
    fixed_version: str,
    recommendation_id: Optional[int] = None,
    requested_by: Optional[str] = None,
) -> Approval:
    """Build the review package and create a pending Approval carrying it."""

    package = build_review_package(
        db,
        vulnerability_id=vulnerability_id,
        target_twin_id=target_twin_id,
        fixed_version=fixed_version,
        recommendation_id=recommendation_id,
    )

    approval = Approval(
        vulnerability_id=vulnerability_id,
        recommendation_id=recommendation_id,
        target_twin_id=target_twin_id,
        requested_action="apply_patch",
        requested_by=requested_by,
        status="pending",
        context={"fixed_version": fixed_version, "review_package": asdict(package)},
    )
    db.add(approval)
    db.commit()
    db.refresh(approval)

    logger.info(
        "Approval %s requested: vulnerability=%s twin=%s fixed_version=%s",
        approval.id,
        vulnerability_id,
        target_twin_id,
        fixed_version,
    )

    return approval


def request_recommendation_review(
    db: Session,
    vulnerability_id: int,
    recommendation_id: int | None,
    report_id: int,
    review_package: dict[str, Any],
    requested_by: Optional[str] = None,
) -> Approval:
    """Request human review of a recommendation without authorizing a deploy."""

    approval = Approval(
        vulnerability_id=vulnerability_id,
        recommendation_id=recommendation_id,
        target_twin_id=None,
        requested_action="recommend_only",
        requested_by=requested_by,
        status="pending",
        context={
            "review_mode": "recommendation_only",
            "report_id": report_id,
            "review_package": review_package,
        },
    )
    db.add(approval)
    db.commit()
    db.refresh(approval)
    return approval



def decide(
    db: Session,
    approval_id: int,
    decision: str,
    decided_by: str,
    decision_reason: Optional[str] = None,
) -> Approval:
    """Record a human decision and atomically create/link remediation."""

    if decision not in ("approved", "rejected"):
        raise ApprovalWorkflowError(
            f"decision must be 'approved' or 'rejected', got {decision!r}."
        )

    if not decided_by or not decided_by.strip():
        raise ApprovalWorkflowError("decided_by must identify the human reviewer.")

    try:
        decided_at = datetime.now(timezone.utc)

        updated = db.execute(
            update(Approval)
            .where(
                Approval.id == approval_id,
                Approval.status == "pending",
            )
            .values(
                status=decision,
                decided_by=decided_by,
                decision_reason=decision_reason,
                decided_at=decided_at,
            )
            .execution_options(synchronize_session=False)
        )

        if updated.rowcount != 1:
            db.rollback()
            existing = (
                db.query(Approval)
                .filter(Approval.id == approval_id)
                .first()
            )
            if existing is None:
                raise ApprovalWorkflowError(
                    f"Approval {approval_id} not found."
                )
            raise ApprovalWorkflowError(
                f"Approval {approval_id} has already been decided "
                f"(status={existing.status!r})."
            )

        approval = (
            db.query(Approval)
            .filter(Approval.id == approval_id)
            .populate_existing()
            .first()
        )

        if approval is None:
            raise ApprovalWorkflowError(
                f"Approval {approval_id} not found."
            )

        # Rejection is final: no remediation is created.
        if decision == "rejected":
            db.commit()
            db.refresh(approval)
            logger.info(
                "Approval %s rejected by %s: %s",
                approval_id,
                decided_by,
                decision_reason,
            )
            return approval

        # An approved action must have a recorded target and fixed version.
        context = approval.context or {}
        fixed_version = context.get("fixed_version")

        if approval.requested_action == "recommend_only":
            if approval.recommendation_id is not None:
                recommendation = (
                    db.query(Recommendation)
                    .filter(Recommendation.id == approval.recommendation_id)
                    .first()
                )
                if recommendation is None or recommendation.vulnerability_id != approval.vulnerability_id:
                    raise ApprovalWorkflowError(
                        "The linked recommendation does not match the approval vulnerability."
                    )
            db.commit()
            db.refresh(approval)
            logger.info(
                "Recommendation %s accepted by %s; no deployment was authorized.",
                approval.recommendation_id,
                decided_by,
            )
            return approval

        if approval.target_twin_id is None:
            raise ApprovalWorkflowError(
                "Cannot approve remediation without a target twin."
            )

        if not isinstance(fixed_version, str) or not fixed_version.strip():
            raise ApprovalWorkflowError(
                "Cannot approve remediation without a fixed version."
            )

        recommendation_title = None
        if approval.recommendation_id is not None:
            recommendation = (
                db.query(Recommendation)
                .filter(
                    Recommendation.id == approval.recommendation_id
                )
                .first()
            )
            if recommendation is None:
                raise ApprovalWorkflowError(
                    "The linked recommendation no longer exists."
                )
            if recommendation.vulnerability_id != approval.vulnerability_id:
                raise ApprovalWorkflowError(
                    "The recommendation does not match the approval vulnerability."
                )
            recommendation_title = recommendation.title

        action_description = (
            f"Upgrade to {fixed_version}"
            if fixed_version
            else (recommendation_title or "Apply recommended remediation")
        )

        remediation = Remediation(
            vulnerability_id=approval.vulnerability_id,
            recommendation_id=approval.recommendation_id,
            target_twin_id=approval.target_twin_id,
            action=action_description,
            status=remediation_status.APPROVED,
            applied_by=decided_by,
        )
        db.add(remediation)

        # Obtain the generated ID without committing yet.
        db.flush()

        approval.remediation_id = remediation.id

        # One transaction: decision + remediation + linkage.
        db.commit()
        db.refresh(approval)

        logger.info(
            "Approval %s approved by %s: remediation=%s twin=%s version=%s",
            approval_id,
            decided_by,
            remediation.id,
            approval.target_twin_id,
            fixed_version,
        )
        return approval

    except Exception:
        db.rollback()
        raise
