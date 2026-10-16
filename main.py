import logging

from fastapi import Depends, FastAPI
from sqlalchemy import text

from api.routes import approvals, auth, exploits, legacy, recommendation, remediation, reports, trust, validations, vulnerabilities
from api.routes import confidence, learning, orchestration, twins, workflow_ui
from api.routes import code_remediation
from core.config import settings
from core.exceptions import ASDEError, asde_exception_handler, not_found_handler
from core.security import require_role
from database.session import SessionLocal

logger = logging.getLogger(__name__)

app = FastAPI(title=settings.APP_NAME, version=settings.APP_VERSION)

app.add_exception_handler(ASDEError, asde_exception_handler)
app.add_exception_handler(404, not_found_handler)

read_access = [Depends(require_role("viewer", "analyst", "operator", "approver", "admin"))]

app.include_router(auth.router, prefix="/auth", tags=["Auth"])
app.include_router(vulnerabilities.router, prefix="/vulnerabilities", tags=["Vulnerabilities"], dependencies=read_access)
app.include_router(exploits.router, prefix="/exploits", tags=["Exploits"], dependencies=read_access)
app.include_router(validations.router, prefix="/validations", tags=["Validations"], dependencies=read_access)
app.include_router(confidence.router, prefix="/confidence", tags=["Confidence"], dependencies=read_access)
app.include_router(approvals.router, prefix="/approvals", tags=["Approvals"], dependencies=read_access)
app.include_router(approvals.router, prefix="/approval", tags=["Approvals"], dependencies=read_access)
app.include_router(trust.router, prefix="/trust", tags=["Trust"], dependencies=read_access)
app.include_router(legacy.router, prefix="/legacy", tags=["Legacy"], dependencies=read_access)
app.include_router(recommendation.router, prefix="/recommendation", tags=["Recommendations"], dependencies=read_access)
app.include_router(remediation.router, prefix="/remediations", tags=["Remediations"], dependencies=read_access)
app.include_router(reports.router, prefix="/reports", tags=["Reports"], dependencies=read_access)
app.include_router(twins.router, prefix="/twins",tags=["Twins"], dependencies=read_access)
app.include_router(learning.router, prefix="/learning", tags=["Continuous Learning"], dependencies=read_access)
app.include_router(orchestration.router, prefix="/orchestration", tags=["Orchestration"], dependencies=read_access)
app.include_router(code_remediation.router, prefix="/code-remediation", tags=["Code Remediation"], dependencies=read_access)
app.include_router(workflow_ui.router, prefix="/workflow", tags=["Workflow UI"], dependencies=read_access)


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
