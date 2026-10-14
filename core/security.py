from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from typing import Iterable

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from core.config import settings

_bearer = HTTPBearer(auto_error=False)
_HASH_ALGORITHM = "pbkdf2_sha256"
_HASH_ITERATIONS = 210_000


@dataclass(frozen=True)
class Principal:
    subject: str
    roles: frozenset[str]

    def has_any_role(self, allowed_roles: Iterable[str]) -> bool:
        return bool(self.roles.intersection(allowed_roles)) or "admin" in self.roles


def hash_password(password: str, salt: str | None = None) -> str:
    """Return a PBKDF2-SHA256 password hash suitable for AUTH_USERS_JSON."""

    salt = salt or secrets.token_urlsafe(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        _HASH_ITERATIONS,
    )
    return (
        f"{_HASH_ALGORITHM}${_HASH_ITERATIONS}${salt}$"
        f"{base64.urlsafe_b64encode(digest).decode('ascii').rstrip('=')}"
    )


def verify_password(password: str, password_hash: str) -> bool:
    try:
        algorithm, iterations, salt, digest = password_hash.split("$", 3)
        if algorithm != _HASH_ALGORITHM:
            return False
        expected = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            int(iterations),
        )
        expected_digest = base64.urlsafe_b64encode(expected).decode("ascii").rstrip("=")
        return hmac.compare_digest(expected_digest, digest)
    except (TypeError, ValueError):
        return False


def create_access_token(subject: str, roles: Iterable[str]) -> str:
    if not settings.AUTH_SECRET_KEY:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Token signing is not configured.",
        )

    now = int(time.time())
    payload = {
        "sub": subject,
        "roles": sorted(set(roles)),
        "iat": now,
        "exp": now + int(settings.AUTH_TOKEN_TTL_SECONDS),
    }
    header = {"alg": "HS256", "typ": "JWT"}
    signing_input = ".".join(
        [_b64_json(header), _b64_json(payload)]
    ).encode("ascii")
    signature = hmac.new(
        settings.AUTH_SECRET_KEY.encode("utf-8"),
        signing_input,
        hashlib.sha256,
    ).digest()
    return (
        signing_input.decode("ascii")
        + "."
        + base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    )


def authenticate_user(username: str, password: str) -> Principal | None:
    users = json.loads(settings.AUTH_USERS_JSON or "{}")
    user = users.get(username)
    if not isinstance(user, dict):
        return None
    password_hash = user.get("password_hash")
    if not isinstance(password_hash, str) or not verify_password(password, password_hash):
        return None
    roles = user.get("roles") or []
    if not isinstance(roles, list) or not all(isinstance(role, str) for role in roles):
        return None
    return Principal(subject=username, roles=frozenset(roles))


def get_current_principal(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> Principal:
    if not settings.AUTH_ENABLED:
        return Principal(subject="auth-disabled", roles=frozenset({"admin"}))

    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required.")

    token = credentials.credentials
    principal = _principal_from_static_token(token) or _principal_from_signed_token(token)
    if principal is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token.")
    return principal


def require_role(*roles: str):
    allowed_roles = frozenset(roles)

    def dependency(principal: Principal = Depends(get_current_principal)) -> Principal:
        if not principal.has_any_role(allowed_roles):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions.")
        return principal

    return dependency


def _principal_from_static_token(token: str) -> Principal | None:
    if settings.AUTH_DEV_ADMIN_TOKEN and settings.ENVIRONMENT.lower() != "production":
        if hmac.compare_digest(token, settings.AUTH_DEV_ADMIN_TOKEN):
            return Principal(subject="dev-admin", roles=frozenset({"admin"}))

    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    token_roles = json.loads(settings.AUTH_STATIC_TOKEN_HASHES_JSON or "{}")
    roles = token_roles.get(token_hash)
    if isinstance(roles, list) and all(isinstance(role, str) for role in roles):
        return Principal(subject="service-token", roles=frozenset(roles))
    return None


def _principal_from_signed_token(token: str) -> Principal | None:
    if not settings.AUTH_SECRET_KEY:
        return None
    try:
        header_b64, payload_b64, signature_b64 = token.split(".", 2)
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        expected = hmac.new(
            settings.AUTH_SECRET_KEY.encode("utf-8"),
            signing_input,
            hashlib.sha256,
        ).digest()
        received = _b64_decode(signature_b64)
        if not hmac.compare_digest(expected, received):
            return None
        payload = json.loads(_b64_decode(payload_b64))
        if int(payload.get("exp", 0)) < int(time.time()):
            return None
        roles = payload.get("roles")
        subject = payload.get("sub")
        if not isinstance(subject, str):
            return None
        if not isinstance(roles, list) or not all(isinstance(role, str) for role in roles):
            return None
        return Principal(subject=subject, roles=frozenset(roles))
    except (TypeError, ValueError, json.JSONDecodeError):
        return None


def _b64_json(value: dict[str, object]) -> str:
    encoded = json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return base64.urlsafe_b64encode(encoded).decode("ascii").rstrip("=")


def _b64_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)
