"""
VM resource metrics collection, via VBoxManage's built-in metrics
subsystem (same subprocess-exec-only approach as the VM Twin Engine --
see vm_engine/subprocess_runner.py for why no shell string is used).

Output parsing here is intentionally lenient: VBoxManage's `metrics query`
table format has drifted across VirtualBox versions, so this extracts the
first numeric token per named metric line rather than assuming fixed
column positions.
"""

from __future__ import annotations

import time
import re
from typing import Optional

from twin_generator.monitor.config import MonitorSettings
from twin_generator.monitor.schemas import TwinMetrics
from twin_generator.utils.enums import HealthStatus
from twin_generator.vm_engine.config import VMEngineSettings
from twin_generator.vm_engine.subprocess_runner import run_command

METRICS = ("CPU/Load", "RAM/Usage/Used", "Disk/Usage/Used", "Net/Rate/Rx", "Net/Rate/Tx")

_NUMBER_RE = re.compile(r"-?\d+(?:\.\d+)?")


def _parse_metrics_query(output: str) -> dict[str, float]:
    """Parse lines like `<vm>: CPU/Load  %  12` into {'CPU/Load': 12.0, ...}."""
    parsed: dict[str, float] = {}
    for line in output.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        _, _, rest = line.partition(":")
        rest = rest.strip()
        for metric_name in METRICS:
            if rest.startswith(metric_name):
                remainder = rest[len(metric_name):]
                match = _NUMBER_RE.search(remainder)
                if match:
                    parsed[metric_name] = float(match.group())
                break
    return parsed


class VMStatsCollector:
    """Collects a one-shot resource snapshot for a running VM twin."""

    def __init__(
        self,
        vm_settings: Optional[VMEngineSettings] = None,
        monitor_settings: Optional[MonitorSettings] = None,
    ) -> None:
        self._vm_settings = vm_settings or VMEngineSettings()
        self._monitor_settings = monitor_settings or MonitorSettings()

    def collect(self, vm_name: str, twin_uuid: str, vm_status: str) -> TwinMetrics:
        metric_list = ",".join(METRICS)
        vboxmanage = self._vm_settings.vboxmanage_path
        timeout = self._vm_settings.command_timeout_seconds

        run_command(
            [
                vboxmanage,
                "metrics",
                "setup",
                vm_name,
                metric_list,
                "--period",
                str(self._monitor_settings.vm_metrics_period_seconds),
                "--samples",
                "1",
            ],
            timeout_seconds=timeout,
        )
        time.sleep(self._monitor_settings.vm_metrics_settle_seconds)
        result = run_command(
            [vboxmanage, "metrics", "query", vm_name, metric_list], timeout_seconds=timeout
        )
        values = _parse_metrics_query(result.stdout) if result.returncode == 0 else {}

        health = HealthStatus.HEALTHY if vm_status == "running" else HealthStatus.UNHEALTHY

        return TwinMetrics(
            twin_uuid=twin_uuid,
            environment="vm",
            container_or_vm_status=vm_status,
            health=health,
            cpu_percent=values.get("CPU/Load"),
            memory_usage_bytes=(
                int(values["RAM/Usage/Used"] * 1024) if "RAM/Usage/Used" in values else None
            ),  # VBoxManage reports RAM in kB
            disk_io_bytes=(
                int(values["Disk/Usage/Used"]) if "Disk/Usage/Used" in values else None
            ),
            network_rx_bytes=int(values["Net/Rate/Rx"]) if "Net/Rate/Rx" in values else None,
            network_tx_bytes=int(values["Net/Rate/Tx"]) if "Net/Rate/Tx" in values else None,
        )
