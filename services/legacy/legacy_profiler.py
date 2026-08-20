from __future__ import annotations

from sqlalchemy.orm import Session

from database.models.legacy import LegacyProfile, SpecialistQueue
from services.legacy.eol_lookup import EOLLookup
from services.legacy.fingerprint import FingerprintEngine
from services.legacy.models import LegacyProfileResult, SoftwareFingerprint


class LegacyProfiler:
    """Profiles assets for unsupported and end-of-life software risk."""

    def __init__(self, db: Session, lookup: EOLLookup | None = None) -> None:
        self.db = db
        self.fingerprinter = FingerprintEngine()
        self.lookup = lookup or EOLLookup()

    def profile_system(self, payload: dict[str, object]) -> LegacyProfile:
        """Fingerprint software, apply penalties, and persist the profile.

        Args:
            payload: Asset and software metadata.

        Returns:
            Persisted legacy profile row.
        """

        fingerprint = self.fingerprinter.fingerprint(payload)
        support = self.lookup_vendor_support(fingerprint)
        penalty = self.calculate_legacy_penalty(bool(support["unsupported"]), bool(support["eol"]))
        controls = self._recommend_controls(fingerprint, bool(support["eol"]))
        route_to_specialist = penalty >= 0.35
        profile = LegacyProfile(
            asset_id=payload.get("asset_id") if isinstance(payload.get("asset_id"), int) else None,
            vendor=fingerprint.vendor,
            product=fingerprint.product,
            version=fingerprint.version,
            fingerprint=f"{fingerprint.vendor}:{fingerprint.product}:{fingerprint.version or 'unknown'}",
            unsupported=bool(support["unsupported"]),
            eol=bool(support["eol"]),
            support_status=str(support["support_status"]),
            legacy_penalty=penalty,
            compensating_controls=controls,
            route_to_specialist=route_to_specialist,
            metadata_json=fingerprint.raw,
        )
        self.db.add(profile)
        self.db.flush()
        if route_to_specialist:
            self.db.add(
                SpecialistQueue(
                    legacy_profile_id=profile.id,
                    queue_type="legacy",
                    reason="Legacy risk exceeds automated remediation threshold.",
                    payload=fingerprint.raw,
                )
            )
        self.db.commit()
        self.db.refresh(profile)
        return profile

    def lookup_vendor_support(self, fingerprint: SoftwareFingerprint) -> dict[str, object]:
        """Return vendor support metadata for a fingerprint."""

        return self.lookup.lookup_vendor_support(fingerprint)

    def calculate_legacy_penalty(self, unsupported: bool, eol: bool) -> float:
        """Calculate confidence penalty for unsupported software.

        Args:
            unsupported: Whether vendor support is unavailable or unknown.
            eol: Whether the product is known end-of-life.

        Returns:
            Penalty from 0.0 to 0.5.
        """

        penalty = 0.0
        if unsupported:
            penalty += 0.20
        if eol:
            penalty += 0.25
        return min(0.5, penalty)

    @staticmethod
    def _recommend_controls(fingerprint: SoftwareFingerprint, eol: bool) -> list[str]:
        controls = [
            "Restrict network exposure with firewall rules.",
            "Increase monitoring for exploit attempts.",
            "Prioritize migration to a supported release.",
        ]
        if eol:
            controls.append("Apply virtual patching or WAF rules until replacement is complete.")
        return controls
