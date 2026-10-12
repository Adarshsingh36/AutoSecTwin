import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from core.config import settings
from database.models.remediation import Remediation
from database.models.twin import Twin
from database.models.vulnerability import Vulnerability

logger = logging.getLogger(__name__)

# Remediation types the engine can reason about. The concrete "action" text
# is always generated, but the type informs how ``apply`` behaves.
REMEDIATION_TYPES = (
    "patch_update",
    "configuration_change",
    "service_configuration",
    "firewall_network_restriction",
    "disable_vulnerable_service",
    "credential_hardening",
    "virtual_patch",
)


class RemediationEngine:
    """Builds remediation recommendations/plans and applies them to a Twin.

    Covers non-Docker remediation types (config changes, firewall rules,
    credential hardening, etc.) that don't have a real automated handler
    yet -- see services/remediation/handlers/ for the one that does exist
    (Docker). For those, this class's honest behavior is: recommend/plan
    freely, and only ever claim "applied" when MOCK_MODE is on or a real
    application channel exists; otherwise it stays "planned" and says so.

    This class does NOT verify anything -- there is no mark_verified()
    here on purpose. "Verified" is only ever set by
    services/remediation/pipeline.py, as the direct result of a real
    RevalidationEngine.run() call. Transitions this class does manage::

        recommended -> planned -> applied
                              \\-> failed

    "Applying" a remediation never silently pretends success. In
    ``MOCK_MODE`` the compensating control is *simulated* against the mock
    Digital Twin and clearly tagged as such. Outside mock mode, without a
    Digital Twin Generator endpoint that exposes a configuration-management
    API, the engine records the action as ``planned`` with an explanation
    that manual/out-of-band application is required -- it does not claim an
    action was applied when it was not.
    """

    def build_action(self, vulnerability: Vulnerability) -> str:
        """Return a concrete remediation action description."""

        cve_id = getattr(vulnerability, "cve_id", "the vulnerability")
        severity = str(getattr(vulnerability, "severity", "UNKNOWN")).lower()
        return (
            f"Patch or upgrade affected components for {cve_id}; prioritize {severity} exposure, "
            "apply vendor guidance, disable vulnerable service paths where feasible, and schedule revalidation."
        )

    def classify_remediation_type(self, vulnerability: Vulnerability) -> str:
        """Pick a remediation type based on vulnerability metadata.

        Falls back to "patch_update", the most broadly applicable option,
        when there isn't enough signal to be more specific.
        """

        metadata = getattr(vulnerability, "metadata_json", None) or {}
        hinted = metadata.get("remediation_type")
        if hinted in REMEDIATION_TYPES:
            return hinted

        title = f"{getattr(vulnerability, 'title', '') or ''} {getattr(vulnerability, 'description', '') or ''}".lower()
        if "credential" in title or "default password" in title or "auth" in title:
            return "credential_hardening"
        if "service" in title and "disable" in title:
            return "disable_vulnerable_service"
        if "smb" in title or "rdp" in title or "port" in title:
            return "firewall_network_restriction"
        return "patch_update"

    def recommend(self, db: Session, vulnerability: Vulnerability, recommendation_id: int | None = None) -> Remediation:
        """Create a Remediation row in the "recommended" state."""

        remediation = Remediation(
            vulnerability_id=vulnerability.id,
            recommendation_id=recommendation_id,
            status="recommended",
            action=self.build_action(vulnerability),
            evidence={
                "remediation_type": self.classify_remediation_type(vulnerability),
                "recommended_at": datetime.now(timezone.utc).isoformat(),
            },
        )
        db.add(remediation)
        db.commit()
        db.refresh(remediation)
        logger.info("Remediation %s recommended for vulnerability %s", remediation.id, vulnerability.id)
        return remediation

    def plan(self, db: Session, remediation: Remediation) -> Remediation:
        """Move a remediation from recommended -> planned."""

        remediation.status = "planned"
        evidence = dict(remediation.evidence or {})
        evidence["planned_at"] = datetime.now(timezone.utc).isoformat()
        remediation.evidence = evidence
        db.commit()
        db.refresh(remediation)
        return remediation

    def apply(
        self,
        db: Session,
        remediation: Remediation,
        twin: Twin,
        applied_by: str = "autosectwin-orchestrator",
    ) -> Remediation:
        """Apply (or, outside MOCK_MODE without a config-mgmt API, honestly
        decline to fabricate application of) the remediation against the
        Digital Twin.
        """

        evidence = dict(remediation.evidence or {})
        remediation_type = evidence.get("remediation_type", "patch_update")

        if settings.MOCK_MODE:
            evidence.update(
                {
                    "applied_at": datetime.now(timezone.utc).isoformat(),
                    "target_twin_id": twin.id,
                    "target_ip": twin.ip_address,
                    "simulated": True,
                    "detail": (
                        f"Simulated {remediation_type} applied to Digital Twin {twin.id} "
                        f"({twin.ip_address}). No production system was modified."
                    ),
                }
            )
            remediation.status = "applied"
            remediation.applied_by = applied_by
            remediation.applied_at = datetime.now(timezone.utc)
            remediation.evidence = evidence
            db.commit()
            db.refresh(remediation)
            logger.info("Remediation %s simulated-applied to twin %s (mock mode)", remediation.id, twin.id)
            return remediation

        # Outside mock mode: AutoSecTwin does not currently have a
        # configuration-management channel into the Twin Generator, so it
        # must not claim the control was applied. Record the honest state.
        evidence.update(
            {
                "target_twin_id": twin.id,
                "target_ip": twin.ip_address,
                "simulated": False,
                "detail": (
                    f"{remediation_type} plan is ready for {twin.ip_address or twin.id}, but "
                    "AutoSecTwin has no configuration-management integration to apply it "
                    "automatically. Apply manually or via the Twin Generator's own tooling, "
                    "then re-run revalidation."
                ),
            }
        )
        remediation.status = "planned"
        remediation.evidence = evidence
        db.commit()
        db.refresh(remediation)
        logger.warning(
            "Remediation %s requires manual application outside MOCK_MODE (twin %s)",
            remediation.id,
            twin.id,
        )
        return remediation

    def mark_failed(self, db: Session, remediation: Remediation, reason: str) -> Remediation:
        """Mark a remediation attempt as failed with an audit reason."""

        evidence = dict(remediation.evidence or {})
        evidence["failure_reason"] = reason
        evidence["failed_at"] = datetime.now(timezone.utc).isoformat()
        remediation.status = "failed"
        remediation.evidence = evidence
        db.commit()
        db.refresh(remediation)
        logger.error("Remediation %s failed: %s", remediation.id, reason)
        return remediation

    # Note: there is deliberately no mark_verified()/similar method here.
    # "Verified" may only ever be set as the result of a real revalidation
    # run -- see services/remediation/pipeline.py:run_revalidation_only(),
    # which is the sole place that assigns remediation_status.VERIFIED,
    # and only when RevalidationEngine.run() returns result="resolved".
