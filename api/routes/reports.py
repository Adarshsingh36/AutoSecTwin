import logging

from fastapi import APIRouter, Depends, HTTPException
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
