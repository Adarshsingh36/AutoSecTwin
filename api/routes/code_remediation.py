import logging
from dataclasses import asdict
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from api.dependencies import get_db
from api.schemas.autosectwin import (
    CodeChangeApplyRequest,
    CodeChangeApplyResponse,
    CodeChangeProposalResponse,
    CodeChangeProposeRequest,
)
from database.models.approval import Approval
from database.models.vulnerability import Vulnerability
from services.remediation.code_remediation import (
    CodeChangeExecutor,
    CodeChangeProposal,
    CodeRemediationError,
    propose_code_change,
)

router = APIRouter()
logger = logging.getLogger(__name__)


@router.post("/propose", response_model=CodeChangeProposalResponse)
def propose_change(payload: CodeChangeProposeRequest, db: Session = Depends(get_db)) -> CodeChangeProposalResponse:
    """Propose a code-level fix for one function/class.

    Never writes anything. Returns the current code, proposed code, and
    diff for human review, and creates a pending Approval carrying the
    full proposal -- nothing is applied until that approval is granted
    and POST /code-remediation/{approval_id}/apply is called with the
    exact content hash shown here.
    """

    vulnerability = db.query(Vulnerability).filter(Vulnerability.id == payload.vulnerability_id).first()
    if vulnerability is None:
        raise HTTPException(status_code=404, detail=f"Vulnerability {payload.vulnerability_id} not found")

    try:
        proposal = propose_code_change(payload.file_path, payload.function_name, vulnerability)
    except CodeRemediationError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc))

    approval = Approval(
        vulnerability_id=payload.vulnerability_id,
        requested_action="apply_code_change",
        requested_by=payload.requested_by,
        status="pending",
        context={"code_proposal": asdict(proposal)},
    )
    db.add(approval)
    db.commit()
    db.refresh(approval)

    logger.info(
        "Code change proposed for vulnerability %s: approval=%s file=%s requires_manual_authoring=%s",
        payload.vulnerability_id,
        approval.id,
        payload.file_path,
        proposal.requires_manual_authoring,
    )

    return CodeChangeProposalResponse(approval_id=approval.id, **asdict(proposal))


@router.post("/{approval_id}/apply", response_model=CodeChangeApplyResponse)
def apply_change(
    approval_id: int, payload: CodeChangeApplyRequest, db: Session = Depends(get_db)
) -> CodeChangeApplyResponse:
    """Apply a previously-proposed code change.

    Requires: the approval to exist, be decided "approved", carry a
    code_proposal in its context, and the caller to supply the exact
    content_hash shown in the original proposal (confirming they're
    applying the specific diff that was reviewed, not something swapped
    in since). Runs tests after writing the change; rolls back to the
    original file content if they fail.
    """

    approval = db.query(Approval).filter(Approval.id == approval_id).first()
    if approval is None:
        raise HTTPException(status_code=404, detail=f"Approval {approval_id} not found")

    if approval.status != "approved":
        raise HTTPException(
            status_code=409,
            detail=f"Approval {approval_id} is not approved (status={approval.status}).",
        )

    proposal_data = (approval.context or {}).get("code_proposal")
    if proposal_data is None:
        raise HTTPException(status_code=422, detail=f"Approval {approval_id} has no code_proposal in its context.")

    proposal = CodeChangeProposal(**proposal_data)

    try:
        result = CodeChangeExecutor().apply(proposal, approved_content_hash=payload.confirmed_content_hash)
    except CodeRemediationError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc))

    approval.context = {
        **(approval.context or {}),
        "apply_result": {
            "applied": result.applied,
            "tests_passed": result.tests_passed,
            "rolled_back": result.rolled_back,
            "applied_at": result.applied_at.isoformat() if result.applied_at else None,
        },
    }
    db.commit()

    logger.info(
        "Code change apply result for approval %s: applied=%s tests_passed=%s rolled_back=%s",
        approval_id,
        result.applied,
        result.tests_passed,
        result.rolled_back,
    )

    return CodeChangeApplyResponse(
        approval_id=approval_id,
        applied=result.applied,
        tests_passed=result.tests_passed,
        test_output=result.test_output,
        rolled_back=result.rolled_back,
        file_path=result.file_path,
    )
