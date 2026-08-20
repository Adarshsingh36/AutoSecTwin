import logging
from typing import Any

import httpx

from core.config import settings

logger = logging.getLogger(__name__)


class MetasploitRPCClient:
    """Minimal Metasploit RPC client for exploit orchestration."""

    def __init__(
        self,
        url: str = settings.METASPLOIT_RPC_URL,
        username: str = settings.METASPLOIT_RPC_USERNAME,
        password: str = settings.METASPLOIT_RPC_PASSWORD,
        timeout: float = 30.0,
    ) -> None:
        self.url = url
        self.username = username
        self.password = password
        self.timeout = timeout
        self._token: str | None = None

    async def login(self) -> str:
        """Authenticate with Metasploit RPC and cache the token."""

        payload = ["auth.login", self.username, self.password]
        result = await self._call_raw(payload)
        token = result.get("token")
        if not token:
            raise RuntimeError("Metasploit RPC authentication did not return a token")
        self._token = token
        return token

    async def run_module(self, module_type: str, module_name: str, options: dict[str, Any]) -> dict[str, Any]:
        """Execute a Metasploit module."""

        token = self._token or await self.login()
        return await self._call_raw(["module.execute", token, module_type, module_name, options])

    async def _call_raw(self, payload: list[Any]) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(self.url, json=payload)
                response.raise_for_status()
                data = response.json()
                if data.get("error"):
                    raise RuntimeError(str(data["error"]))
                return data
        except httpx.HTTPError as exc:
            logger.exception("Metasploit RPC request failed")
            raise RuntimeError("Metasploit RPC request failed") from exc
