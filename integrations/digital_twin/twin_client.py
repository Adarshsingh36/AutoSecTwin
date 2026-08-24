import logging

import httpx
from typing import Any


from core.config import settings

logger = logging.getLogger(__name__)


class DigitalTwinClient:
    """Client for digital twin environment orchestration."""

    def __init__(self, base_url: str = settings.DIGITAL_TWIN_BASE_URL, timeout: float = 30.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    async def create_twin(
        self,
        cve: str,
        host: str | None = None,
        software: str | None = None,
        version: str | None = None,
        environment: str | None = None,
        ttl_seconds: int | None = None,
    ) -> dict[str, Any]:
        """Request a twin environment from the configured provider."""
        
        payload = {
            "cve": cve,
            "host": host,
            "software": software,
            "version": version,
            "environment": environment,
            "ttl_seconds": ttl_seconds,
        }
        print("=" * 60)
        print("Payload to Twin Generator")
        print("cve        :", cve)
        print("host       :", host)
        print("software   :", software)
        print("version    :", version)
        print("environment:", environment)
        print("ttl        :", ttl_seconds)
        print("=" * 60)
        
        payload = {k: v for k, v in payload.items() if v is not None}

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{self.base_url}/twins/create",
                    json=payload,
                )

                print("Status:", response.status_code)
                print("Response:", response.text)

                response.raise_for_status()

                print("=" * 80)
                print("STATUS:", response.status_code)
                print("BODY:")
                print(response.text)
                print("=" * 80)

                response.raise_for_status()

                return response.json()

        except httpx.HTTPError as exc:
            logger.exception("Digital twin creation failed")
            raise RuntimeError("Digital twin creation failed") from exc

    async def destroy_twin(self, twin_external_id: str) -> dict[str, Any]:
        """Destroy a twin environment."""

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.delete(f"{self.base_url}/twins/{twin_external_id}")
                response.raise_for_status()
                return response.json()
        except httpx.HTTPError as exc:
            logger.exception("Digital twin destruction failed for %s", twin_external_id)
            raise RuntimeError(f"Digital twin destruction failed for {twin_external_id}") from exc
