"""
Unit tests for VMStatsCollector. `run_command` is patched, so no VirtualBox
installation is required.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from twin_generator.monitor.config import MonitorSettings
from twin_generator.monitor.vm_collector import VMStatsCollector
from twin_generator.utils.enums import HealthStatus
from twin_generator.vm_engine.config import VMEngineSettings
from twin_generator.vm_engine.subprocess_runner import CommandResult


@pytest.fixture
def fast_settings() -> MonitorSettings:
    return MonitorSettings(vm_metrics_settle_seconds=0.1)


def test_collect_parses_metrics_table(
    fast_settings: MonitorSettings,
) -> None:
    metrics_output = (
        "vuln-vm-1: CPU/Load %   17\n"
        "vuln-vm-1: RAM/Usage/Used kB  524288\n"
        "vuln-vm-1: Disk/Usage/Used B  10485760\n"
        "vuln-vm-1: Net/Rate/Rx B/s  100\n"
        "vuln-vm-1: Net/Rate/Tx B/s  200\n"
    )

    responses = [
        CommandResult(
            returncode=0,
            stdout="",
            stderr="",
        ),  # metrics setup
        CommandResult(
            returncode=0,
            stdout=metrics_output,
            stderr="",
        ),  # metrics query
    ]

    collector = VMStatsCollector(
        VMEngineSettings(),
        fast_settings,
    )

    with patch(
        "twin_generator.monitor.vm_collector.run_command",
        new=MagicMock(side_effect=responses),
    ):
        metrics = collector.collect(
            "vuln-vm-1",
            "abc-uuid",
            "running",
        )

    assert metrics.environment == "vm"
    assert metrics.health == HealthStatus.HEALTHY
    assert metrics.cpu_percent == 17.0
    assert metrics.memory_usage_bytes == 524288 * 1024
    assert metrics.disk_io_bytes == 10485760
    assert metrics.network_rx_bytes == 100
    assert metrics.network_tx_bytes == 200


def test_collect_reports_unhealthy_when_not_running(
    fast_settings: MonitorSettings,
) -> None:
    responses = [
        CommandResult(
            returncode=0,
            stdout="",
            stderr="",
        ),
        CommandResult(
            returncode=1,
            stdout="",
            stderr="metrics unavailable",
        ),
    ]

    collector = VMStatsCollector(
        VMEngineSettings(),
        fast_settings,
    )

    with patch(
        "twin_generator.monitor.vm_collector.run_command",
        new=MagicMock(side_effect=responses),
    ):
        metrics = collector.collect(
            "vuln-vm-1",
            "abc-uuid",
            "poweroff",
        )

    assert metrics.health == HealthStatus.UNHEALTHY
    assert metrics.cpu_percent is None