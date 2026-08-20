from fastapi import Request
from fastapi.responses import JSONResponse


class ASDEError(Exception):
    """Base domain exception for AutoSecTwin."""

    def __init__(self, message: str, code: str = "ASDE_ERROR", status_code: int = 400) -> None:
        self.message = message
        self.code = code
        self.status_code = status_code
        super().__init__(message)


async def asde_exception_handler(_: Request, exc: ASDEError) -> JSONResponse:
    """Render domain exceptions as a consistent API envelope."""

    return JSONResponse(
        status_code=exc.status_code,
        content={"error": {"code": exc.code, "message": exc.message}},
    )


async def not_found_handler(_: Request, exc: Exception) -> JSONResponse:
    """Render unknown routes as a consistent API envelope."""

    return JSONResponse(
        status_code=404,
        content={"error": {"code": "NOT_FOUND", "message": "Resource not found"}},
    )
