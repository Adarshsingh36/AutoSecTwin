from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from database.models.recommendation import Recommendation
from database.models.vulnerability import Vulnerability
from services.llm.client import LLMClient


class RecommendationEngine:
    """
    Generates remediation recommendations together with a structured
    explanation that can be consumed by the human-approval and reporting
    stages of AutoSecTwin.
    """

    def __init__(
        self,
        db: Session,
        llm_client: LLMClient | None = None,
    ) -> None:
        self.db = db
        self.llm_client = llm_client or LLMClient()

    def generate(
        self,
        vulnerability_id: int,
        recommendation_type: str,
        context: dict[str, object] | None = None,
    ) -> Recommendation:
        """Generate and persist a structured remediation recommendation."""

        vulnerability = self.db.get(Vulnerability, vulnerability_id)
        context = context or {}

        cve_id = (
            vulnerability.cve_id
            if vulnerability
            else f"vulnerability-{vulnerability_id}"
        )

        rec_type = recommendation_type.lower().replace("_", " ")

        title, content, provider = self._build(
            cve_id=cve_id,
            rec_type=rec_type,
            context=context,
            vulnerability=vulnerability,
        )

        explanation = self._build_explanation(
            cve_id=cve_id,
            rec_type=rec_type,
            context=context,
            vulnerability=vulnerability,
        )

        metadata = {
            **context,
            "explanation": explanation,
        }

        row = Recommendation(
            vulnerability_id=vulnerability_id,
            recommendation_type=rec_type.title(),
            title=title,
            content=content,
            provider=provider,
            metadata_json=metadata,
        )

        self.db.add(row)
        self.db.commit()
        self.db.refresh(row)

        return row

    def _build(
        self,
        cve_id: str,
        rec_type: str,
        context: dict[str, object],
        vulnerability: Vulnerability | None,
    ) -> tuple[str, str, str]:
        """Build the actual remediation recommendation."""

        if rec_type in {"patch", "vendor patch"}:
            vendor = context.get("vendor") or "vendor"
            product = context.get("product") or "affected product"

            return (
                f"Apply vendor patch for {cve_id}",
                (
                    f"Check {vendor} security advisories for {product}, "
                    "deploy the fixed release, and revalidate the vulnerability "
                    "in the Digital Twin."
                ),
                "vendor_lookup",
            )

        if rec_type in {"configuration", "configuration fix"}:
            return (
                f"Harden configuration for {cve_id}",
                (
                    "Disable or restrict the vulnerable service, reduce unnecessary "
                    "network exposure, enforce least privilege, and revalidate "
                    "the resulting configuration."
                ),
                "rule_based",
            )

        if rec_type in {"code", "code fix"}:
            prompt = (
                f"Generate concise secure coding guidance for {cve_id}. "
                f"Vulnerability: {self._vulnerability_description(vulnerability)}. "
                f"Context: {context}"
            )

            return (
                f"Code fix for {cve_id}",
                self.llm_client.generate(
                    "code_recommendation",
                    prompt,
                ),
                "llm",
            )

        if rec_type in {"compensating controls", "legacy"}:
            return (
                f"Compensating controls for {cve_id}",
                (
                    "Segment the affected asset, restrict exposure, add detection "
                    "coverage, consider virtual patching where appropriate, and "
                    "queue specialist review."
                ),
                "legacy_controls",
            )

        prompt = (
            f"Generate remediation guidance for {cve_id}. "
            f"Vulnerability: {self._vulnerability_description(vulnerability)}. "
            f"Context: {context}"
        )

        return (
            f"Recommendation for {cve_id}",
            self.llm_client.generate(
                "patch_recommendation",
                prompt,
            ),
            "llm",
        )

    def _build_explanation(
        self,
        cve_id: str,
        rec_type: str,
        context: dict[str, object],
        vulnerability: Vulnerability | None,
    ) -> dict[str, Any]:
        """
        Build the structured explanation consumed by approval/reporting.

        The explanation intentionally separates:
        - vulnerability explanation
        - exploitation evidence
        - remediation
        - code-change requirements
        - human approval
        - limitations
        """

        category = self._remediation_category(rec_type, context)

        vulnerability_description = self._vulnerability_description(
            vulnerability
        )

        evidence = self._extract_evidence(context)

        explanation: dict[str, Any] = {
            "remediation_category": category,

            "why_vulnerable": vulnerability_description,

            "how_it_can_be_exploited": self._exploitation_explanation(
                cve_id=cve_id,
                context=context,
                vulnerability=vulnerability,
            ),

            "validation_evidence": evidence,

            "recommended_fix": self._recommended_fix(
                cve_id=cve_id,
                category=category,
                context=context,
                vulnerability=vulnerability,
            ),

            "why_fix_works": self._why_fix_works(
                category=category,
                context=context,
            ),

            "code_change_required": category == "CODE_CHANGE",

            "proposed_code_change": self._proposed_code_change(
                category=category,
                context=context,
            ),

            "human_approval_required": True,

            "approval_reason": (
                "The recommendation must be reviewed and explicitly approved "
                "by a human before remediation is applied."
            ),

            "limitations": self._limitations(
                category=category,
                context=context,
            ),
        }

        return explanation

    @staticmethod
    def _remediation_category(
        rec_type: str,
        context: dict[str, object],
    ) -> str:
        """Normalize recommendation types into reportable categories."""

        explicit_category = context.get("remediation_category")

        if explicit_category:
            return str(explicit_category).upper()

        if rec_type in {"patch", "vendor patch"}:
            return "PATCH"

        if rec_type in {"configuration", "configuration fix"}:
            return "CONFIGURATION_CHANGE"

        if rec_type in {"code", "code fix"}:
            return "CODE_CHANGE"

        if rec_type in {"compensating controls", "legacy"}:
            return "COMPENSATING_CONTROL"

        return "PATCH"

    @staticmethod
    def _vulnerability_description(
        vulnerability: Vulnerability | None,
    ) -> str:
        if vulnerability is None:
            return (
                "The vulnerability record could not be retrieved. "
                "A complete vulnerability explanation requires the vulnerability "
                "description and affected product information."
            )

        description = getattr(vulnerability, "description", None)

        if description:
            return str(description)

        title = getattr(vulnerability, "title", None)

        if title:
            return str(title)

        return (
            "The vulnerability record does not contain a detailed description."
        )

    @staticmethod
    def _exploitation_explanation(
        cve_id: str,
        context: dict[str, object],
        vulnerability: Vulnerability | None,
    ) -> str:
        """
        Explain exploitation using supplied project evidence.

        We do not invent exploit details when the context does not contain them.
        """

        explicit = context.get("exploitation_explanation")

        if explicit:
            return str(explicit)

        exploit_module = context.get("exploit_module")
        validation_status = context.get("validation_status")
        session_id = context.get("session_id")

        if exploit_module and validation_status:
            result = (
                f"The vulnerability can be investigated using the validated "
                f"exploit path associated with {cve_id}. "
                f"AutoSecTwin recorded validation status '{validation_status}' "
                f"using exploit module '{exploit_module}'."
            )

            if session_id:
                result += (
                    f" The validation produced session/evidence identifier "
                    f"{session_id}."
                )

            return result

        return (
            f"Exploitation details for {cve_id} require validated exploit "
            "evidence. The current recommendation context does not contain "
            "enough evidence to describe a specific exploitation sequence."
        )

    @staticmethod
    def _extract_evidence(
        context: dict[str, object],
    ) -> dict[str, object]:
        """Extract only evidence relevant to the recommendation explanation."""

        evidence_keys = (
            "validation_id",
            "validation_status",
            "validation_score",
            "validation_analysis",
            "exploit_module",
            "exploit_status",
            "session_id",
            "stdout",
            "proof",
            "evidence",
            "target",
            "endpoint",
            "detected_version",
        )

        return {
            key: context[key]
            for key in evidence_keys
            if key in context
        }

    @staticmethod
    def _recommended_fix(
        cve_id: str,
        category: str,
        context: dict[str, object],
        vulnerability: Vulnerability | None,
    ) -> str:
        """Generate a human-readable remediation instruction."""

        explicit = context.get("recommended_fix")

        if explicit:
            return str(explicit)

        if category == "PATCH":
            current_version = context.get("current_version")
            fixed_version = context.get("fixed_version")
            product = context.get("product") or "the affected software"

            if current_version and fixed_version:
                return (
                    f"Upgrade {product} from version {current_version} "
                    f"to version {fixed_version} or a later vendor-fixed release."
                )

            return (
                f"Upgrade the affected software to a vendor-fixed release "
                f"addressing {cve_id}, then revalidate the vulnerability."
            )

        if category == "CONFIGURATION_CHANGE":
            return (
                "Modify the affected configuration to remove unnecessary "
                "exposure or disable the vulnerable functionality, then "
                "revalidate the resulting configuration."
            )

        if category == "CODE_CHANGE":
            return (
                "Modify the affected source code according to the proposed "
                "secure-code change, review and test the change, obtain human "
                "approval, then deploy and revalidate."
            )

        if category == "COMPENSATING_CONTROL":
            return (
                "Apply compensating controls such as network segmentation, "
                "access restrictions, monitoring, or virtual patching while "
                "a permanent fix is unavailable."
            )

        return (
            f"Apply the appropriate vendor or engineering remediation for "
            f"{cve_id} and revalidate the result."
        )

    @staticmethod
    def _why_fix_works(
        category: str,
        context: dict[str, object],
    ) -> str:
        """Explain the expected security effect of the remediation."""

        explicit = context.get("why_fix_works")

        if explicit:
            return str(explicit)

        if category == "PATCH":
            return (
                "A vendor-fixed release is expected to contain the security "
                "changes that address the vulnerable behavior. AutoSecTwin "
                "must independently revalidate the affected condition after "
                "the upgrade rather than treating the version change alone "
                "as proof of remediation."
            )

        if category == "CONFIGURATION_CHANGE":
            return (
                "The configuration change is intended to remove or restrict "
                "the vulnerable attack surface. Revalidation is required to "
                "confirm that the vulnerable condition is no longer reachable."
            )

        if category == "CODE_CHANGE":
            return (
                "The proposed source-code change is intended to remove the "
                "unsafe behavior identified during vulnerability analysis. "
                "Code review, testing, human approval, and revalidation are "
                "required before the change can be considered effective."
            )

        if category == "COMPENSATING_CONTROL":
            return (
                "The controls reduce exposure or the likelihood of successful "
                "exploitation but may not remove the underlying vulnerability. "
                "They should therefore be treated as compensating protection "
                "until a permanent fix is available."
            )

        return (
            "The effectiveness of the recommendation must be established "
            "through post-remediation validation."
        )

    @staticmethod
    def _proposed_code_change(
        category: str,
        context: dict[str, object],
    ) -> dict[str, object] | None:
        """
        Return proposed code-change information without applying it.

        The system deliberately does not modify source code here.
        """

        if category != "CODE_CHANGE":
            return None

        return {
            "file": context.get("affected_file"),
            "function": context.get("affected_function"),
            "current_code": context.get("current_code"),
            "proposed_code": context.get("proposed_code"),
            "diff": context.get("code_diff"),
            "reason": context.get(
                "code_change_reason",
                "The affected code requires modification to remove "
                "the vulnerable behavior.",
            ),
            "human_review_required": True,
            "automatic_application": False,
        }

    @staticmethod
    def _limitations(
        category: str,
        context: dict[str, object],
    ) -> list[str]:
        """Record limitations that should appear in the final report."""

        limitations: list[str] = []

        supplied_limitations = context.get("limitations")

        if isinstance(supplied_limitations, list):
            limitations.extend(str(item) for item in supplied_limitations)

        if category == "CODE_CHANGE":
            limitations.append(
                "AutoSecTwin does not automatically apply source-code changes. "
                "The proposed change must be reviewed and approved by a human."
            )

        limitations.append(
            "A recommendation is not evidence that remediation has been "
            "successfully applied. Effectiveness requires post-remediation "
            "revalidation."
        )

        return limitations