import logging
from typing import Any

import httpx

from core.config import settings

logger = logging.getLogger(__name__)


class EPSSClient:
    """Client for FIRST EPSS API."""

    def __init__(self, base_url: str = settings.EPSS_API_BASE_URL, timeout: float = 20.0) -> None:
        self.base_url = base_url
        self.timeout = timeout

    async def fetch_score(self, cve_id: str) -> dict[str, Any]:
        """Fetch EPSS probability for a CVE."""

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(self.base_url, params={"cve": cve_id})
                response.raise_for_status()
                return response.json()
        except httpx.HTTPError as exc:
            logger.exception("EPSS request failed for %s", cve_id)
            raise RuntimeError(f"EPSS request failed for {cve_id}") from exc
