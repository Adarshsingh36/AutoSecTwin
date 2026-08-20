import logging

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from api.dependencies import get_db
from api.schemas.autosectwin import VulnerabilityCreate, VulnerabilityResponse
from database.models.vulnerability import Vulnerability
from services.exploitability.predictor import ExploitabilityPredictionEngine
from services.threat_intelligence import ThreatIntelligenceEngine

router = APIRouter()
logger = logging.getLogger(__name__)
predictor = ExploitabilityPredictionEngine()
threat_engine = ThreatIntelligenceEngine()


@router.post(
    "/",
    response_model=VulnerabilityResponse
)
def create_vulnerability(
    payload: VulnerabilityCreate,
    db: Session = Depends(get_db)
) -> Vulnerability:
    """Create a vulnerability and compute initial P(e) and TI(v)."""

    vuln = Vulnerability(**payload.model_dump())
    vuln.threat_intelligence_score = threat_engine.score(vuln)
    vuln.exploitability_probability = predictor.predict(vuln, vuln.threat_intelligence_score)
    db.add(vuln)
    db.commit()
    db.refresh(vuln)
    logger.info("Created vulnerability %s", vuln.cve_id)
    return vuln


@router.get("/", response_model=list[VulnerabilityResponse])
def list_vulnerabilities(db: Session = Depends(get_db)) -> list[Vulnerability]:
    """List vulnerabilities."""

    return db.query(Vulnerability).order_by(Vulnerability.id.desc()).all()


@router.get("/{vulnerability_id}", response_model=VulnerabilityResponse)
def get_vulnerability(vulnerability_id: int, db: Session = Depends(get_db)) -> Vulnerability:
    """Fetch a vulnerability by id."""

    vuln = db.get(Vulnerability, vulnerability_id)
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return vuln
