"""
PatchHandler abstraction.

Only DockerPatchHandler is implemented right now -- per the current
repository and Digital Twin architecture, that's the one remediation path
that actually exists end to end (the Digital Twin Generator only supports
Docker and VM twins, and only Docker twins are version-selectable via the
CVE Image Registry today, per Phase 2). PackagePatchHandler /
ConfigPatchHandler / CodePatchHandler are not stubbed out here -- empty
placeholder classes that do nothing would be exactly the kind of fake
module this project is explicitly trying to eliminate. Add a real handler
here, implementing this same Protocol, when there's a real remediation
mechanism for it to drive.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional, Protocol

from database.models.twin import Twin
from database.models.vulnerability import Vulnerability


class PartialRemediationFailure(RuntimeError):
    """Raised when a remediation has already changed state but cannot be
    completed to a valid replacement twin.

    The `target_modified` flag preserves the real partial execution record:
    if the original twin was destroyed before the replacement failed, that is
    still a genuine modification and must not be re-labeled as a no-op.
    """

    def __init__(
        self,
        message: str,
        *,
        target_modified: bool,
        old_twin_id: Optional[int] = None,
        new_twin_id: Optional[int] = None,
        evidence: Optional[dict[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        self.target_modified = target_modified
        self.old_twin_id = old_twin_id
        self.new_twin_id = new_twin_id
        self.evidence = evidence or {}


@dataclass(frozen=True)
class PatchResult:
    """What a handler reports back after actually attempting remediation.

    `target_modified` must only ever be True when the handler itself
    performed and confirmed the modification/replacement -- never set
    optimistically before the work is actually done.
    """

    target_modified: bool
    healthy: bool

    old_twin_id: Optional[int] = None
    new_twin_id: Optional[int] = None
    old_image: Optional[str] = None
    new_image: Optional[str] = None
    old_version: Optional[str] = None
    new_version: Optional[str] = None
    old_endpoint: Optional[str] = None
    new_endpoint: Optional[str] = None
    old_container_id: Optional[str] = None
    new_container_id: Optional[str] = None
    health: Optional[str] = None
    notes: Optional[str] = None

    extra: dict[str, Any] = field(default_factory=dict)

    def to_evidence_dict(self) -> dict[str, Any]:
        """Flatten into the Phase 7 evidence shape persisted on
        Remediation.evidence. target_modified/execution_authorized are
        intentionally NOT included here -- those live as first-class
        Remediation columns (see database/models/remediation.py), set by
        PatchExecutor itself, not duplicated into the JSON blob.
        """

        return {
            "old_twin_id": self.old_twin_id,
            "new_twin_id": self.new_twin_id,
            "old_image": self.old_image,
            "new_image": self.new_image,
            "old_version": self.old_version,
            "new_version": self.new_version,
            "old_endpoint": self.old_endpoint,
            "new_endpoint": self.new_endpoint,
            "old_container_id": self.old_container_id,
            "new_container_id": self.new_container_id,
            "health": self.health,
            "notes": self.notes,
            **self.extra,
        }


class PatchHandler(Protocol):
    """Contract every remediation handler implements."""

    async def apply(
        self,
        twin: Twin,
        vulnerability: Vulnerability,
        fixed_version: str,
    ) -> PatchResult:
        """Actually perform the remediation against `twin`. Must raise on
        failure (never return a result claiming target_modified=True for
        a modification that didn't actually happen or wasn't confirmed).
        """
        ...
