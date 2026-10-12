"""
Valid values for Remediation.status.

Defined here (rather than as a DB-level enum) so the column stays a plain
portable String across Postgres/SQLite, matching the rest of this
project's convention. The transition rules that enforce which moves
between these states are legal are implemented separately once the real
executor exists (so "manual_action_required -> verified" without an
actual revalidation can never happen) -- this module is only the
vocabulary both that engine and these schema/migration files share.

"verified" must never be set except as the direct result of a
revalidation that actually ran and showed the vulnerability is no longer
exploitable -- see services/remediation/ once the executor lands.
"""

from __future__ import annotations

# Legacy/pre-existing values, kept for backward compatibility with rows
# written before this state machine existed.
PLANNED = "planned"
APPLIED = "applied"
VERIFIED_LEGACY = "verified"  # pre-existing meaning: "verify() was called"

# Real lifecycle, introduced alongside target_twin_id.
APPROVED = "approved"
QUEUED = "queued"
EXECUTING = "executing"
EXECUTED = "executed"
REVALIDATING = "revalidating"
VERIFIED = "verified"
FAILED = "failed"
MANUAL_ACTION_REQUIRED = "manual_action_required"

ALL_STATUSES = frozenset(
    {
        PLANNED,
        APPLIED,
        APPROVED,
        QUEUED,
        EXECUTING,
        EXECUTED,
        REVALIDATING,
        VERIFIED,
        FAILED,
        MANUAL_ACTION_REQUIRED,
    }
)

# States from which a remediation is considered resolved (no further
# automatic action expected without a new approval).
TERMINAL_STATUSES = frozenset({VERIFIED, FAILED, MANUAL_ACTION_REQUIRED})
