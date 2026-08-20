"""
Unit tests for VMTwinEngine. `run_command` (the only place that shells out
to VBoxManage) is patched, so these tests run without VirtualBox installed.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from twin_generator.utils.exceptions import (
    VMBootError,
    VMHeartbeatTimeoutError,
    VMNetworkConfigError,
    VMSnapshotRestoreError,
)
from twin_generator.vm_engine.config import VMEngineSettings
from twin_generator.vm_engine.manager import VMTwinEngine
from twin_generator.vm_engine.subprocess_runner import CommandResult


@pytest.fixture
def fast_settings() -> VMEngineSettings:
    return VMEngineSettings(
        heartbeat_timeout_seconds=1,
        heartbeat_poll_interval_seconds=0.01,
        command_timeout_seconds=5,
    )


def _ok(stdout: str = "") -> CommandResult:
    return CommandResult(
        returncode=0,
        stdout=stdout,
        stderr="",
    )


def _fail(stderr: str = "boom") -> CommandResult:
    return CommandResult(
        returncode=1,
        stdout="",
        stderr=stderr,
    )


def test_provision_twin_happy_path(
    fast_settings: VMEngineSettings,
) -> None:
    engine = VMTwinEngine(fast_settings)

    responses = [
        _ok(),  # snapshot restore
        _ok(),  # modifyvm network config
        _ok(),  # startvm
        _ok("Value: 10.10.0.5"),  # guestproperty get
        _ok('VMState="running"'),  # showvminfo --machinereadable
    ]

    with patch(
        "twin_generator.vm_engine.manager.run_command",
        new=MagicMock(side_effect=responses),
    ) as mocked:
        result = engine.provision_twin(
            vm_name="vuln-vm-1"
        )

    assert result.status == "running"
    assert result.ip_address == "10.10.0.5"
    assert result.healthy is True
    assert mocked.call_count == 5


def test_snapshot_restore_failure_raises(
    fast_settings: VMEngineSettings,
) -> None:
    engine = VMTwinEngine(fast_settings)

    with patch(
        "twin_generator.vm_engine.manager.run_command",
        new=MagicMock(
            return_value=_fail("no snapshot")
        ),
    ):
        with pytest.raises(VMSnapshotRestoreError):
            engine.provision_twin(
                vm_name="vuln-vm-1"
            )


def test_network_config_failure_raises(
    fast_settings: VMEngineSettings,
) -> None:
    engine = VMTwinEngine(fast_settings)

    responses = [
        _ok(),
        _fail("nic error"),
    ]

    with patch(
        "twin_generator.vm_engine.manager.run_command",
        new=MagicMock(side_effect=responses),
    ):
        with pytest.raises(VMNetworkConfigError):
            engine.provision_twin(
                vm_name="vuln-vm-1"
            )


def test_boot_failure_raises(
    fast_settings: VMEngineSettings,
) -> None:
    engine = VMTwinEngine(fast_settings)

    responses = [
        _ok(),
        _ok(),
        _fail("start error"),
    ]

    with patch(
        "twin_generator.vm_engine.manager.run_command",
        new=MagicMock(side_effect=responses),
    ):
        with pytest.raises(VMBootError):
            engine.provision_twin(
                vm_name="vuln-vm-1"
            )


def test_heartbeat_timeout_raises(
    fast_settings: VMEngineSettings,
) -> None:
    engine = VMTwinEngine(fast_settings)

    setup_steps_remaining = [3]

    def _side_effect(*args, **kwargs) -> CommandResult:
        if setup_steps_remaining[0] > 0:
            setup_steps_remaining[0] -= 1
            return _ok()

        return _ok("No value set!")

    with patch(
        "twin_generator.vm_engine.manager.run_command",
        new=MagicMock(side_effect=_side_effect),
    ):
        with pytest.raises(VMHeartbeatTimeoutError):
            engine.provision_twin(
                vm_name="vuln-vm-1"
            )