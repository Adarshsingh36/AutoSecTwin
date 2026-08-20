from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class SoftwareFingerprint:
    """Identified software tuple extracted from asset or service metadata."""

    vendor: str
    product: str
    version: str | None
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class LegacyProfileResult:
    """Legacy profiling decision for a software component."""

    vendor: str
    product: str
    version: str | None
    fingerprint: str
    unsupported: bool
    eol: bool
    support_status: str
    legacy_penalty: float
    compensating_controls: list[str]
    route_to_specialist: bool
