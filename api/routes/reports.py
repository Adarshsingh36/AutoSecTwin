import json
import logging

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse, Response
from sqlalchemy.orm import Session

from api.dependencies import get_db
from api.schemas.autosectwin import ReportCreate, ReportResponse
from database.models.remediation import Remediation
from database.models.report import Report
from database.models.vulnerability import Vulnerability
from services.reporting.closed_loop_report_service import build_closed_loop_report
from services.reporting.report_generator import ReportGenerator

router = APIRouter()
logger = logging.getLogger(__name__)


@router.post("/closed-loop/{remediation_id}", response_model=ReportResponse)
def create_closed_loop_report(remediation_id: int, db: Session = Depends(get_db)) -> Report:
    """Build and persist the full technical closed-loop report for a
    remediation: vulnerability technical analysis, exploit execution
    evidence, validation scoring, approval, remediation execution,
    revalidation, and before/after comparison -- all pulled from real
    persisted rows, nothing supplied by the caller.

    Once persisted, use the existing GET /reports/{id}/html and
    GET /reports/{id}/pdf routes to render it -- they're generic over any
    report's JSON content, closed-loop included.
    """

    remediation = db.query(Remediation).filter(Remediation.id == remediation_id).first()
    if remediation is None:
        raise HTTPException(status_code=404, detail=f"Remediation {remediation_id} not found")

    try:
        content = build_closed_loop_report(db, remediation_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))

    body = json.loads(content)

    report = Report(
        vulnerability_id=remediation.vulnerability_id,
        report_type="closed_loop",
        title=body.get("title", f"Closed-Loop Report: Remediation {remediation_id}"),
        content=content,
        format="json",
        metadata_json={"remediation_id": remediation_id},
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    logger.info("Generated closed-loop report %s for remediation %s", report.id, remediation_id)
    return report


@router.post("/", response_model=ReportResponse)
def create_report(payload: ReportCreate, db: Session = Depends(get_db)) -> Report:
    """Generate a technical or executive report."""

    vulnerability = db.get(Vulnerability, payload.vulnerability_id) if payload.vulnerability_id else None
    content = ReportGenerator().generate(
        payload.report_type,
        payload.title,
        {
            "vulnerability": vulnerability.cve_id if vulnerability else None,
            "confidence_inputs": {
                "exploitability_probability": getattr(vulnerability, "exploitability_probability", None),
                "threat_intelligence_score": getattr(vulnerability, "threat_intelligence_score", None),
                "exposure_score": getattr(vulnerability, "exposure_score", None),
                "asset_criticality": getattr(vulnerability, "asset_criticality", None),
            },
            "metadata": payload.metadata_json or {},
        },
    )
    report = Report(**payload.model_dump(), content=content)
    db.add(report)
    db.commit()
    db.refresh(report)
    logger.info("Generated report %s", report.id)
    return report


@router.get("/", response_model=list[ReportResponse])
def list_reports(db: Session = Depends(get_db)) -> list[Report]:
    """List generated reports."""

    return db.query(Report).order_by(Report.id.desc()).all()


@router.get("/{report_id}", response_model=ReportResponse)
def get_report(report_id: int, db: Session = Depends(get_db)) -> Report:
    """Fetch a report."""

    report = db.get(Report, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report


@router.get("/{report_id}/html", response_class=HTMLResponse)
def get_report_html(report_id: int, db: Session = Depends(get_db)) -> HTMLResponse:
    """Render a persisted report (technical, executive, or closed-loop) as
    a human-readable HTML page, per the reporting requirement for at least
    a structured JSON report and, where practical, a human-readable
    rendering of it.
    """

    report = db.get(Report, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    html = ReportGenerator().render_html(report.content, title=report.title)
    return HTMLResponse(content=html)


@router.get("/{report_id}/pdf")
def get_report_pdf(report_id: int, db: Session = Depends(get_db)) -> Response:
    """Render a persisted report as a downloadable PDF document."""

    report = db.get(Report, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    pdf_bytes = ReportGenerator().render_pdf(report.content, title=report.title)
    filename = f"report-{report_id}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
