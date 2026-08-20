from typing import Any


class ThreatIntelligenceEngine:
    """Compute TI(v) from NVD, EPSS, ExploitDB, CISA KEV, and ATT&CK signals."""

    def score(self, vulnerability: Any, intelligence: dict[str, Any] | None = None) -> float:
        """Return normalized threat intelligence score TI(v)."""

        intelligence = intelligence or {}
        epss = float(intelligence.get("epss_score", getattr(vulnerability, "epss_score", 0.0)) or 0.0)
        exploit_count = min(1.0, float(intelligence.get("exploit_count", 0) or 0) / 5.0)
        kev = 1.0 if intelligence.get("kev_listed", getattr(vulnerability, "kev_listed", False)) else 0.0
        attack = 1.0 if intelligence.get("mitre_attack_techniques") else 0.0
        cvss = float(getattr(vulnerability, "cvss_score", 0.0) or 0.0) / 10.0
        return max(0.0, min(1.0, 0.30 * epss + 0.25 * exploit_count + 0.25 * kev + 0.10 * attack + 0.10 * cvss))
