"""
Curated technical explanations for specific CVEs, used by the closed-loop
technical report.

Per the explicit instruction this was built against: explain the
technical chain accurately and conservatively, and where AutoSecTwin does
not have enough information for a given CVE, say so plainly rather than
inventing implementation details. Only CVE-2023-46604 is populated here
today -- extend this dict with the same level of care (and the same
sourcing discipline) before relying on it for another CVE in a report.
"""

from __future__ import annotations

from typing import Any

CVE_TECHNICAL_EXPLANATIONS: dict[str, dict[str, Any]] = {
    "CVE-2023-46604": {
        "title": "Apache ActiveMQ OpenWire Protocol Unauthenticated Remote Code Execution",
        "affected_component": "Apache ActiveMQ broker -- OpenWire transport connector",
        "affected_versions": (
            "Apache ActiveMQ 5.18.0 and earlier, 5.17.5 and earlier, "
            "5.16.6 and earlier, 5.15.16 and earlier"
        ),
        "protocol_port": "OpenWire protocol, default TCP port 61616",
        "attack_chain": [
            "An unauthenticated attacker connects to the broker's OpenWire transport "
            "connector (default TCP/61616) and sends a crafted OpenWire protocol message.",
            "The OpenWire wire-format marshaller deserializes the message, including an "
            "embedded class name the attacker controls, and instantiates that class via "
            "reflection as part of normal message handling.",
            "The attacker supplies org.springframework.context.support.ClassPathXmlApplicationContext "
            "(a class already present on ActiveMQ's classpath) as the type to instantiate, "
            "with a constructor argument pointing at an attacker-hosted XML file (typically "
            "served over HTTP from attacker-controlled infrastructure).",
            "ClassPathXmlApplicationContext's constructor fetches and parses that remote XML "
            "as a Spring application context definition.",
            "The attacker's XML defines a bean whose construction (constructor-arg, "
            "factory-method, or init-method) invokes process-execution APIs such as "
            "java.lang.ProcessBuilder, running an OS command chosen by the attacker with "
            "the privileges of the ActiveMQ broker process.",
        ],
        "root_cause": (
            "An unsafe-deserialization-to-RCE chain: the OpenWire marshaller does not "
            "restrict which classes an inbound message may instantiate, and a "
            "classpath-available class (ClassPathXmlApplicationContext) that can be coerced "
            "into fetching and executing attacker-controlled remote configuration is reachable "
            "from that unrestricted instantiation path."
        ),
        "source": (
            "NVD CVE-2023-46604; Apache ActiveMQ Security Advisory (October 2023); "
            "Metasploit module exploit/multi/misc/apache_activemq_rce_cve_2023_46604."
        ),
    }
}

VALIDATION_SCORE_EXPLANATION = (
    "The validation score is not the CVSS score. CVSS is a vendor/NVD-assigned severity "
    "rating based on the vulnerability's theoretical characteristics (attack vector, "
    "complexity, privileges required, impact) and is the same number regardless of whether "
    "the vulnerability was ever actually exploited. The validation score below is computed "
    "by AutoSecTwin's ValidationEngine from real evidence collected during an actual exploit "
    "attempt against an isolated Digital Twin: +0.25 if the Metasploit RPC execution itself "
    "completed without error, up to +0.60 for confirmed success markers (a session actually "
    "opened, verification commands actually returned output, the target's deployed version "
    "was independently corroborated), and +0.15 if no failure was reported. A score of 0.70 "
    "or higher is reported as 'validated' (the exploit demonstrably worked against this "
    "twin); 0.35-0.69 as 'inconclusive'; below 0.35 as 'failed'. A timeout or RPC failure "
    "during execution is always force-classified as 'inconclusive' regardless of the number "
    "it happens to compute to -- an absence of evidence is never treated as evidence of "
    "absence."
)


def get_cve_technical_explanation(cve_id: str | None) -> dict[str, Any]:
    """Return the curated explanation for `cve_id`, or an honest
    "not available" record naming where to look instead. Never fabricates
    a plausible-sounding attack chain for a CVE this module doesn't
    actually have researched information about.
    """

    explanation = CVE_TECHNICAL_EXPLANATIONS.get(cve_id or "")

    if explanation is None:
        return {
            "available": False,
            "cve_id": cve_id,
            "note": (
                f"AutoSecTwin's report generator does not have a curated technical "
                f"explanation for {cve_id or '(unknown CVE)'}. Consult the NVD entry, the "
                "vendor security advisory, and/or the Metasploit module's own documentation "
                "for the authoritative attack chain rather than relying on a generated "
                "explanation here."
            ),
        }

    return {"available": True, **explanation}
