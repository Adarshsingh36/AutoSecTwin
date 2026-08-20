from typing import Any

from services.legacy.models import SoftwareFingerprint


class FingerprintEngine:
    """Fingerprints software names and versions from metadata."""

    def fingerprint(self, payload: dict[str, Any]) -> SoftwareFingerprint:
        """Extract vendor, product, and version from request metadata.

        Args:
            payload: Asset or service metadata.

        Returns:
            Normalized software fingerprint.
        """

        vendor = str(payload.get("vendor") or payload.get("publisher") or "unknown").strip().lower()
        product = str(payload.get("product") or payload.get("service") or payload.get("name") or "unknown").strip().lower()
        version = payload.get("version")
        return SoftwareFingerprint(vendor=vendor, product=product, version=str(version) if version else None, raw=payload)
