import logging
import uuid
from typing import Any

import httpx

from core.config import settings

logger = logging.getLogger(__name__)


class DigitalTwinClient:
    """Client for the Digital Twin Generator service.

    When ``settings.MOCK_MODE`` is enabled, no network calls are made and a
    deterministic, clearly-labelled simulated twin is returned instead. This
    lets the closed-loop orchestrator (and its tests) run end-to-end without
    the Twin Generator / Docker / VM infrastructure available. Real and
    simulated results are always distinguishable via the ``simulated`` key.
    """

    def __init__(self, base_url: str = settings.DIGITAL_TWIN_BASE_URL, timeout: float = 30.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.mock_mode = settings.MOCK_MODE

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

        if self.mock_mode:
            return self._mock_twin(cve=cve, environment=environment)

        payload = {
            "cve": cve,
            "host": host,
            "software": software,
            "version": version,
            "environment": environment,
            "ttl_seconds": ttl_seconds,
        }
        payload = {k: v for k, v in payload.items() if v is not None}

        logger.info("Requesting Digital Twin for %s (host=%s, software=%s)", cve, host, software)

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(f"{self.base_url}/twins/create", json=payload)
                response.raise_for_status()
                data = response.json()
                data.setdefault("simulated", False)
                return data

        except httpx.HTTPError as exc:
            logger.exception("Digital twin creation failed")
            raise RuntimeError("Digital twin creation failed") from exc

    async def get_twin_health(self, twin_external_id: str) -> dict[str, Any]:
        """Return current health/status for a provisioned twin."""

        if self.mock_mode:
            return {"id": twin_external_id, "health": "healthy", "status": "running", "simulated": True}

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(f"{self.base_url}/twins/{twin_external_id}")
                response.raise_for_status()
                data = response.json()
                data.setdefault("simulated", False)
                return data

        except httpx.HTTPError as exc:
            logger.exception("Digital twin health check failed for %s", twin_external_id)
            raise RuntimeError(f"Digital twin health check failed for {twin_external_id}") from exc

    async def destroy_twin(self, twin_external_id: str) -> dict[str, Any]:
        """Destroy a twin environment."""

        if self.mock_mode:
            return {"id": twin_external_id, "status": "destroyed", "simulated": True}

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.delete(f"{self.base_url}/twins/{twin_external_id}")
                response.raise_for_status()
                data = response.json()
                data.setdefault("simulated", False)
                return data
        except httpx.HTTPError as exc:
            logger.exception("Digital twin destruction failed for %s", twin_external_id)
            raise RuntimeError(f"Digital twin destruction failed for {twin_external_id}") from exc

    @staticmethod
    def _mock_twin(cve: str, environment: str | None) -> dict[str, Any]:
        """Deterministic simulated twin used for MOCK_MODE / offline demos."""

        token = uuid.uuid4().hex[:8]
        return {
            "id": abs(hash((cve, token))) % 100000,
            "uuid": f"mock-{token}",
            "status": "running",
            "environment": environment or "docker",
            "ip_address": "10.99.0.10",
            "network": "autosectwin-mock-net",
            "twin_image": "autosectwin/mock-target:latest",
            "vm_name": f"mock-twin-{token}",
            "health": "healthy",
            "legacy_flag": "false",
            "simulated": True,
        }
