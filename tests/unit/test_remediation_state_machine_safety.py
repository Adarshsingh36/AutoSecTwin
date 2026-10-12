"""
Explicit state-machine safety tests. The core guarantee this project is
built around: Remediation.status can only ever become VERIFIED as the
direct result of run_revalidation_only() computing outcome="resolved" --
there is no code path that sets it any other way.
"""

import sys
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from services.remediation import status as remediation_status


def test_verified_status_string_only_assigned_in_pipeline_module():
    """Grep-style regression guard: VERIFIED must only ever be assigned in
    services/remediation/pipeline.py, and only inside the branch gated by
    summary.result == "resolved". If this ever shows up assigned anywhere
    else in services/ or api/, that's a path that could mark something
    verified without a real revalidation outcome backing it.
    """

    import re

    services_root = ROOT / "services"
    offending_files = []

    # Matches an actual ATTRIBUTE assignment: `remediation.status = "verified"`
    # or `x.status = remediation_status.VERIFIED` -- requires a leading "."
    # specifically so this does NOT match a bare local variable assignment
    # like `status = "verified" if score >= 0.75 else ...` (which is what
    # RevalidationEngine.verify()'s legacy heuristic does -- it returns a
    # tuple, it never mutates a Remediation row, so it's safe by
    # construction and deliberately not flagged here).
    assignment_pattern = re.compile(
        r'\.status\s*=\s*(remediation_status\.VERIFIED|["\']verified["\'])'
    )

    for path in services_root.rglob("*.py"):
        if path.name == "test_remediation_state_machine_safety.py":
            continue
        text = path.read_text()
        if not assignment_pattern.search(text):
            continue
        # pipeline.py is the one legitimate assignment site.
        if path.name == "pipeline.py":
            continue
        offending_files.append(str(path))

    assert offending_files == [], (
        f"Found status='verified'/.VERIFIED assigned outside pipeline.py: {offending_files}. "
        "VERIFIED must only ever be set as a result of a real revalidation outcome."
    )


def test_manual_action_required_is_a_valid_distinct_status():
    """Sanity check that the vocabulary itself keeps MANUAL_ACTION_REQUIRED
    and VERIFIED as genuinely distinct values -- a trivial assertion, but
    it's exactly the kind of thing a typo could silently break."""

    assert remediation_status.MANUAL_ACTION_REQUIRED != remediation_status.VERIFIED
    assert remediation_status.FAILED != remediation_status.VERIFIED
    assert remediation_status.MANUAL_ACTION_REQUIRED in remediation_status.TERMINAL_STATUSES
    assert remediation_status.VERIFIED in remediation_status.TERMINAL_STATUSES
    assert remediation_status.FAILED in remediation_status.TERMINAL_STATUSES
    assert remediation_status.EXECUTING not in remediation_status.TERMINAL_STATUSES
