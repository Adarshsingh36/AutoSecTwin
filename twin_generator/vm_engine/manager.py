from __future__ import annotations

import time
from typing import Optional

import structlog

from twin_generator.utils.exceptions import (
    VMBootError,
    VMCommandError,
    VMHeartbeatTimeoutError,
    VMNetworkConfigError,
    VMSnapshotRestoreError,
)
from twin_generator.vm_engine.config import VMEngineSettings
from twin_generator.vm_engine.schemas import VMProvisionResult
from twin_generator.vm_engine.subprocess_runner import CommandResult, run_command

logger = structlog.get_logger(__name__)


def _parse_machinereadable(output: str) -> dict[str, str]:
    """Parse VBoxManage --machinereadable `key="value"` / `key=value` lines."""
    parsed: dict[str, str] = {}

    for line in output.splitlines():
        if "=" not in line:
            continue

        key, _, value = line.partition("=")
        parsed[key.strip()] = value.strip().strip('"')

    return parsed


class VMTwinEngine:
    """Provisions an isolated, running VM replica of a vulnerable target via VirtualBox."""

    def __init__(self, settings: Optional[VMEngineSettings] = None) -> None:
        self._settings = settings or VMEngineSettings()

    def provision_twin(
        self,
        *,
        vm_name: str,
        snapshot_name: Optional[str] = None,
        network_name: Optional[str] = None,
    ) -> VMProvisionResult:
        """Bring up a fully isolated, responsive VM twin from a clean snapshot."""

        snapshot_name = snapshot_name or self._settings.default_snapshot_name
        network_name = network_name or self._settings.default_isolated_intnet

        # 1. Restore snapshot
        self.restore_snapshot(vm_name, snapshot_name)

        # 2. Configure network
        self.configure_network(vm_name, network_name)

        # 3. Boot VM
        self.boot_vm(vm_name)

        # 4. Check heartbeat
        ip_address = self.wait_for_heartbeat(vm_name)

        # 5. Return status
        status = self.get_vm_status(vm_name)
        healthy = status == "running" and ip_address is not None

        logger.info(
            "vm_twin_provisioned",
            vm_name=vm_name,
            network=network_name,
            ip_address=ip_address,
            status=status,
            healthy=healthy,
        )

        return VMProvisionResult(
            vm_name=vm_name,
            snapshot_name=snapshot_name,
            network_name=network_name,
            ip_address=ip_address,
            status=status,
            healthy=healthy,
        )

    def restore_snapshot(
        self,
        vm_name: str,
        snapshot_name: str,
    ) -> None:
        args = [
            self._settings.vboxmanage_path,
            "snapshot",
            vm_name,
            "restore",
            snapshot_name,
        ]

        result = self._run(args)

        if result.returncode != 0:
            raise VMSnapshotRestoreError(
                vm_name,
                snapshot_name,
                result.stderr,
            )

    def configure_network(
        self,
        vm_name: str,
        network_name: str,
    ) -> None:
        args = [
            self._settings.vboxmanage_path,
            "modifyvm",
            vm_name,
            "--nic1",
            "intnet",
            "--intnet1",
            network_name,
            "--cableconnected1",
            "on",
        ]

        result = self._run(args)

        if result.returncode != 0:
            raise VMNetworkConfigError(
                vm_name,
                result.stderr,
            )

    def boot_vm(self, vm_name: str) -> None:
        args = [
            self._settings.vboxmanage_path,
            "startvm",
            vm_name,
            "--type",
            self._settings.boot_type,
        ]

        result = self._run(args)

        if result.returncode != 0:
            raise VMBootError(
                vm_name,
                result.stderr,
            )

    def wait_for_heartbeat(
        self,
        vm_name: str,
    ) -> Optional[str]:
        timeout = self._settings.heartbeat_timeout_seconds
        poll_interval = self._settings.heartbeat_poll_interval_seconds

        deadline = time.monotonic() + timeout

        args = [
            self._settings.vboxmanage_path,
            "guestproperty",
            "get",
            vm_name,
            "/VirtualBox/GuestInfo/Net/0/V4/IP",
        ]

        while time.monotonic() < deadline:
            result = self._run(args)

            if (
                result.returncode == 0
                and result.stdout.strip().startswith("Value:")
            ):
                ip_address = result.stdout.split(
                    "Value:",
                    1,
                )[1].strip()

                if ip_address:
                    return ip_address

            time.sleep(poll_interval)

        raise VMHeartbeatTimeoutError(
            vm_name,
            timeout,
        )

    def get_vm_status(
        self,
        vm_name: str,
    ) -> str:
        args = [
            self._settings.vboxmanage_path,
            "showvminfo",
            vm_name,
            "--machinereadable",
        ]

        result = self._run(args)

        if result.returncode != 0:
            raise VMCommandError(
                args,
                result.returncode,
                result.stderr,
            )

        info = _parse_machinereadable(result.stdout)

        return info.get(
            "VMState",
            "unknown",
        )

    def power_off(
        self,
        vm_name: str,
    ) -> None:
        """Used by the Twin Cleanup Manager to tear down an expired VM twin."""

        args = [
            self._settings.vboxmanage_path,
            "controlvm",
            vm_name,
            "poweroff",
        ]

        result = self._run(args)

        if result.returncode != 0:
            logger.warning(
                "vm_poweroff_failed",
                vm_name=vm_name,
                stderr=result.stderr,
            )

    def _run(
        self,
        args: list[str],
    ) -> CommandResult:
        return run_command(
            args,
            timeout_seconds=self._settings.command_timeout_seconds,
        )