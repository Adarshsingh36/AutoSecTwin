import logging

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from api.dependencies import get_db
from api.schemas.autosectwin import VulnerabilityCreate, VulnerabilityResponse
from database.models.vulnerability import Vulnerability
from integrations.epss.client import EPSSClient
from services.exploitability.predictor import ExploitabilityPredictionEngine
from services.threat_intelligence import ThreatIntelligenceEngine

router = APIRouter()
logger = logging.getLogger(__name__)

predictor = ExploitabilityPredictionEngine()
threat_engine = ThreatIntelligenceEngine()
epss_client = EPSSClient()


@router.post(
    "/",
    response_model=VulnerabilityResponse
)
async def create_vulnerability(
    payload: VulnerabilityCreate,
    db: Session = Depends(get_db)
) -> Vulnerability:
    """Create a vulnerability and compute initial P(e) and TI(v)."""

    vuln = Vulnerability(**payload.model_dump())

    # ---------------------------------------------------------
    # Fetch EPSS intelligence
    # ---------------------------------------------------------

    try:
        epss_response = await epss_client.fetch_score(vuln.cve_id)

        epss_data = epss_response.get("data", [])

        if epss_data:
            epss_record = epss_data[0]

            if epss_record.get("epss") is not None:
                vuln.epss_score = float(epss_record["epss"])

            metadata = vuln.metadata_json or {}

            if epss_record.get("percentile") is not None:
                metadata["epss_percentile"] = float(
                    epss_record["percentile"]
                )

            vuln.metadata_json = metadata

            logger.info(
                "EPSS intelligence loaded for %s: score=%s percentile=%s",
                vuln.cve_id,
                epss_record.get("epss"),
                epss_record.get("percentile"),
            )

    except RuntimeError:
        logger.exception(
            "Failed to fetch EPSS intelligence for %s",
            vuln.cve_id,
        )

        raise HTTPException(
            status_code=502,
            detail=f"Failed to retrieve EPSS intelligence for {vuln.cve_id}.",
        )

    # ---------------------------------------------------------
    # Threat intelligence
    # ---------------------------------------------------------

    vuln.threat_intelligence_score = threat_engine.score(vuln)

    # ---------------------------------------------------------
    # ML exploitability prediction
    # ---------------------------------------------------------

    vuln.exploitability_probability = predictor.predict(vuln)

    # ---------------------------------------------------------
    # Persist vulnerability
    # ---------------------------------------------------------

    db.add(vuln)
    db.commit()
    db.refresh(vuln)

    logger.info(
        "Created vulnerability %s with exploitability probability %.4f",
        vuln.cve_id,
        vuln.exploitability_probability,
    )

    return vuln


@router.get("/", response_model=list[VulnerabilityResponse])
def list_vulnerabilities(
    db: Session = Depends(get_db)
) -> list[Vulnerability]:
    """List vulnerabilities."""

    return (
        db.query(Vulnerability)
        .order_by(Vulnerability.id.desc())
        .all()
    )


@router.get(
    "/{vulnerability_id}",
    response_model=VulnerabilityResponse
)
def get_vulnerability(
    vulnerability_id: int,
    db: Session = Depends(get_db)
) -> Vulnerability:

    """Fetch a vulnerability by id."""

    vuln = db.get(Vulnerability, vulnerability_id)

    if not vuln:
        raise HTTPException(
            status_code=404,
            detail="Vulnerability not found"
        )

    return vuln