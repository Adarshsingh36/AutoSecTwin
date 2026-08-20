import logging
from typing import Any

import httpx

from core.config import settings

logger = logging.getLogger(__name__)


class ThreatIntelligenceClient:
    """Aggregates external threat intelligence sources."""

    def __init__(self, timeout: float = 20.0) -> None:
        self.timeout = timeout

    async def fetch_cisa_kev(self) -> dict[str, Any]:
        """Fetch CISA KEV catalog."""

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(settings.CISA_KEV_URL)
                response.raise_for_status()
                return response.json()
        except httpx.HTTPError as exc:
            logger.exception("CISA KEV request failed")
            raise RuntimeError("CISA KEV request failed") from exc

    async def search_exploitdb(self, cve_id: str) -> dict[str, Any]:
        """Prepare ExploitDB lookup metadata for the CVE."""

        return {"source": "exploitdb", "cve_id": cve_id, "search_url": f"{settings.EXPLOITDB_BASE_URL}/search?cve={cve_id}"}
