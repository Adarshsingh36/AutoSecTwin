"""
VM-side cleanup: old VirtualBox snapshots.

Caveat (documented here and surfaced to the caller): VBoxManage does not
reliably expose snapshot creation timestamps across versions, so this
cannot do true age-based deletion. Instead it deletes every snapshot NOT
in `keep_snapshot_names` -- i.e. every snapshot other than the clean
baseline(s) the VM Twin Engine restores from. Disabled by default
(`enable_snapshot_cleanup=False`) until that trade-off is reviewed.
"""

from __future__ import annotations

import re
from typing import List

from twin_generator.cleanup.config import CleanupSettings
from twin_generator.utils.exceptions import SnapshotCleanupError
from twin_generator.vm_engine.config import VMEngineSettings
from twin_generator.vm_engine.subprocess_runner import run_command

_SNAPSHOT_NAME_RE = re.compile(r'^SnapshotName(?:-\d+)?="(.+)"$', re.MULTILINE)


def list_snapshot_names(vm_name: str, vm_settings: VMEngineSettings) -> List[str]:
    args = [vm_settings.vboxmanage_path, "snapshot", vm_name, "list", "--machinereadable"]
    result = run_command(args, timeout_seconds=vm_settings.command_timeout_seconds)
    if result.returncode != 0:
        raise SnapshotCleanupError(vm_name, result.stderr)
    return _SNAPSHOT_NAME_RE.findall(result.stdout)


def prune_non_baseline_snapshots(
    vm_name: str,
    vm_settings: VMEngineSettings,
    cleanup_settings: CleanupSettings,
) -> int:
    """Delete every snapshot for `vm_name` except those in keep_snapshot_names."""
    names = list_snapshot_names(vm_name, vm_settings)
    removed = 0

    for name in names:
        if name in cleanup_settings.keep_snapshot_names:
            continue
        args = [vm_settings.vboxmanage_path, "snapshot", vm_name, "delete", name]
        result = run_command(args, timeout_seconds=vm_settings.command_timeout_seconds)
        if result.returncode == 0:
            removed += 1
        else:
            raise SnapshotCleanupError(vm_name, f"failed to delete snapshot {name!r}: {result.stderr}")

    return removed
