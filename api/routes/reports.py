import logging

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse, Response
from sqlalchemy.orm import Session

from api.dependencies import get_db
from api.schemas.autosectwin import ReportCreate, ReportResponse
from database.models.report import Report
from database.models.vulnerability import Vulnerability
from services.reporting.report_generator import ReportGenerator

router = APIRouter()
logger = logging.getLogger(__name__)


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
