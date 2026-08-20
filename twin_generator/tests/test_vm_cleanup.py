"""
Unit tests for cleanup/vm_cleanup.py. `run_command` is patched, so no real
VirtualBox is needed.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from twin_generator.cleanup.config import CleanupSettings
from twin_generator.cleanup.vm_cleanup import (
    list_snapshot_names,
    prune_non_baseline_snapshots,
)
from twin_generator.utils.exceptions import SnapshotCleanupError
from twin_generator.vm_engine.config import VMEngineSettings
from twin_generator.vm_engine.subprocess_runner import CommandResult


MACHINEREADABLE_SNAPSHOTS = (
    'SnapshotName="clean-snapshot"\n'
    'SnapshotUUID="abc-123"\n'
    'SnapshotName-1="post-exploit"\n'
    'SnapshotUUID-1="def-456"\n'
)


def test_list_snapshot_names_parses_machinereadable_output() -> None:
    settings = VMEngineSettings()

    with patch(
        "twin_generator.cleanup.vm_cleanup.run_command",
        new=MagicMock(
            return_value=CommandResult(
                0,
                MACHINEREADABLE_SNAPSHOTS,
                "",
            )
        ),
    ):
        names = list_snapshot_names("vuln-vm-1", settings)

    assert names == ["clean-snapshot", "post-exploit"]


def test_list_snapshot_names_raises_on_command_failure() -> None:
    settings = VMEngineSettings()

    with patch(
        "twin_generator.cleanup.vm_cleanup.run_command",
        new=MagicMock(
            return_value=CommandResult(
                1,
                "",
                "vm not found",
            )
        ),
    ):
        with pytest.raises(SnapshotCleanupError):
            list_snapshot_names("missing-vm", settings)


def test_prune_non_baseline_snapshots_keeps_baseline() -> None:
    vm_settings = VMEngineSettings()
    cleanup_settings = CleanupSettings(
        keep_snapshot_names=("clean-snapshot",)
    )

    responses = [
        CommandResult(
            0,
            MACHINEREADABLE_SNAPSHOTS,
            "",
        ),  # list
        CommandResult(
            0,
            "",
            "",
        ),  # delete "post-exploit"
    ]

    with patch(
        "twin_generator.cleanup.vm_cleanup.run_command",
        new=MagicMock(side_effect=responses),
    ) as mocked:
        removed = prune_non_baseline_snapshots(
            "vuln-vm-1",
            vm_settings,
            cleanup_settings,
        )

    assert removed == 1

    # Second call (the delete) must target "post-exploit", not the baseline.
    delete_args = mocked.call_args_list[1].args[0]

    assert "post-exploit" in delete_args
    assert "clean-snapshot" not in delete_args


def test_prune_non_baseline_snapshots_raises_on_delete_failure() -> None:
    vm_settings = VMEngineSettings()
    cleanup_settings = CleanupSettings(
        keep_snapshot_names=("clean-snapshot",)
    )

    responses = [
        CommandResult(
            0,
            MACHINEREADABLE_SNAPSHOTS,
            "",
        ),
        CommandResult(
            1,
            "",
            "snapshot busy",
        ),
    ]

    with patch(
        "twin_generator.cleanup.vm_cleanup.run_command",
        new=MagicMock(side_effect=responses),
    ):
        with pytest.raises(SnapshotCleanupError):
            prune_non_baseline_snapshots(
                "vuln-vm-1",
                vm_settings,
                cleanup_settings,
            )