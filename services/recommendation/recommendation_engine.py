from __future__ import annotations

from sqlalchemy.orm import Session

from database.models.recommendation import Recommendation
from database.models.vulnerability import Vulnerability
from services.llm.client import LLMClient


class RecommendationEngine:
    """Generates patch, configuration, code, and compensating-control recommendations."""

    def __init__(self, db: Session, llm_client: LLMClient | None = None) -> None:
        self.db = db
        self.llm_client = llm_client or LLMClient()

    def generate(self, vulnerability_id: int, recommendation_type: str, context: dict[str, object] | None = None) -> Recommendation:
        """Generate and persist a recommendation for a vulnerability."""

        vulnerability = self.db.get(Vulnerability, vulnerability_id)
        cve_id = vulnerability.cve_id if vulnerability else f"vulnerability-{vulnerability_id}"
        context = context or {}
        rec_type = recommendation_type.lower().replace("_", " ")
        title, content, provider = self._build(cve_id, rec_type, context)
        row = Recommendation(
            vulnerability_id=vulnerability_id,
            recommendation_type=rec_type.title(),
            title=title,
            content=content,
            provider=provider,
            metadata_json=context,
        )
        self.db.add(row)
        self.db.commit()
        self.db.refresh(row)
        return row

    def _build(self, cve_id: str, rec_type: str, context: dict[str, object]) -> tuple[str, str, str]:
        if rec_type in {"patch", "vendor patch"}:
            vendor = context.get("vendor") or "vendor"
            product = context.get("product") or "affected product"
            return (
                f"Apply vendor patch for {cve_id}",
                f"Check {vendor} advisories for {product}, deploy the fixed release, and revalidate in the twin.",
                "vendor_lookup",
            )
        if rec_type in {"configuration", "configuration fix"}:
            return (
                f"Harden configuration for {cve_id}",
                "Disable exposed vulnerable services, restrict management access, and enforce least privilege.",
                "rule_based",
            )
        if rec_type in {"code", "code fix"}:
            prompt = f"Generate concise secure coding guidance for {cve_id}: {context}"
            return (f"Code fix for {cve_id}", self.llm_client.generate("code_recommendation", prompt), "llm")
        if rec_type in {"compensating controls", "legacy"}:
            return (
                f"Compensating controls for {cve_id}",
                "Segment the asset, add detection coverage, enable virtual patching, and queue specialist review.",
                "legacy_controls",
            )
        prompt = f"Generate remediation recommendation for {cve_id}: {context}"
        return (f"Recommendation for {cve_id}", self.llm_client.generate("patch_recommendation", prompt), "llm")
