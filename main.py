import logging

from fastapi import FastAPI
from sqlalchemy import text

from api.routes import approvals, exploits, legacy, recommendation, remediation, reports, trust, validations, vulnerabilities
from api.routes import confidence, learning, twins
from core.config import settings
from core.exceptions import ASDEError, asde_exception_handler, not_found_handler
from database.session import SessionLocal

logger = logging.getLogger(__name__)

app = FastAPI(title=settings.APP_NAME, version=settings.APP_VERSION)

app.add_exception_handler(ASDEError, asde_exception_handler)
app.add_exception_handler(404, not_found_handler)

app.include_router(vulnerabilities.router, prefix="/vulnerabilities", tags=["Vulnerabilities"])
app.include_router(exploits.router, prefix="/exploits", tags=["Exploits"])
app.include_router(validations.router, prefix="/validations", tags=["Validations"])
app.include_router(confidence.router, prefix="/confidence", tags=["Confidence"])
app.include_router(approvals.router, prefix="/approvals", tags=["Approvals"])
app.include_router(approvals.router, prefix="/approval", tags=["Approvals"])
app.include_router(trust.router, prefix="/trust", tags=["Trust"])
app.include_router(legacy.router, prefix="/legacy", tags=["Legacy"])
app.include_router(recommendation.router, prefix="/recommendation", tags=["Recommendations"])
app.include_router(remediation.router, prefix="/remediations", tags=["Remediations"])
app.include_router(reports.router, prefix="/reports", tags=["Reports"])
app.include_router(twins.router, prefix="/twins",tags=["Twins"])
app.include_router(learning.router, prefix="/learning", tags=["Continuous Learning"])


def check_database_connection() -> bool:
    """Return database health without failing app startup."""

    try:
        with SessionLocal() as db:
            db.execute(text("SELECT 1"))
        return True
    except Exception as exc:
        logger.warning("Database health check failed: %s", exc)
        return False


@app.get("/")
@app.get("/health")
def health() -> dict[str, object]:
    """Service health endpoint."""

    return {
        "status": "ok",
        "app_name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT,
        "database_connected": check_database_connection(),
    }
