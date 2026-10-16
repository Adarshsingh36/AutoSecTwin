from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import FileResponse

router = APIRouter()
_STATIC_DIR = Path(__file__).resolve().parents[1] / "static"


@router.get("/intake", response_class=FileResponse)
def assessment_intake_page() -> FileResponse:
    return FileResponse(_STATIC_DIR / "assessment_intake.html", media_type="text/html")