from typing import Any


class RemediationEngine:
    """Creates remediation actions and recommendation text."""

    def build_action(self, vulnerability: Any) -> str:
        """Return a concrete remediation action for the vulnerability."""

        cve_id = getattr(vulnerability, "cve_id", "the vulnerability")
        severity = str(getattr(vulnerability, "severity", "UNKNOWN")).lower()
        return (
            f"Patch or upgrade affected components for {cve_id}; prioritize {severity} exposure, "
            "apply vendor guidance, disable vulnerable service paths where feasible, and schedule revalidation."
        )
