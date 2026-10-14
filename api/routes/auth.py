from fastapi import APIRouter, HTTPException, status

from api.schemas.autosectwin import AuthTokenRequest, AuthTokenResponse
from core.config import settings
from core.security import authenticate_user, create_access_token

router = APIRouter()


@router.post("/token", response_model=AuthTokenResponse)
def issue_token(payload: AuthTokenRequest) -> AuthTokenResponse:
    principal = authenticate_user(payload.username, payload.password)
    if principal is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
        )

    return AuthTokenResponse(
        access_token=create_access_token(principal.subject, principal.roles),
        expires_in=settings.AUTH_TOKEN_TTL_SECONDS,
        roles=sorted(principal.roles),
    )
