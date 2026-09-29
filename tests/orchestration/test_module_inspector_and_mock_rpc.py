import pytest

from core.config import settings
from integrations.metasploit.rpc_client import MetasploitRPCClient
from services.orchestration.module_inspector import MetasploitModuleInspector


class _RaisingRPCClient:
    """Simulates an RPC client whose module.info call fails (module
    missing, Metasploit unreachable, auth failure, etc.)."""

    async def get_module_info(self, module_type, module_name):
        raise RuntimeError("module not found")


class _WorkingRPCClient:
    async def get_module_info(self, module_type, module_name):
        return {
            "type": module_type,
            "fullname": f"{module_type}/{module_name}",
            "rank": "excellent",
            "platform": "windows",
            "arch": "x64",
            "privileged": True,
            "check": True,
            "targets": ["Automatic"],
            "default_target": 0,
            "options": {},
            "default_options": {},
            "references": [],
        }


@pytest.mark.asyncio
async def test_module_inspector_marks_unavailable_on_rpc_failure():
    """Previously this always returned available=True even when the RPC
    call raised, which meant a missing/unreachable module would incorrectly
    pass the exploit readiness gate."""

    inspector = MetasploitModuleInspector(_RaisingRPCClient())

    inspection = await inspector.inspect("exploit", "windows/smb/does_not_exist")

    assert inspection.available is False
    assert inspection.check_supported is False
    assert inspection.options == {}


@pytest.mark.asyncio
async def test_module_inspector_marks_available_on_success():
    inspector = MetasploitModuleInspector(_WorkingRPCClient())

    inspection = await inspector.inspect("exploit", "windows/smb/ms17_010_eternalblue")

    assert inspection.available is True
    assert inspection.platform == "windows"


@pytest.mark.asyncio
async def test_rpc_client_mock_mode_returns_deterministic_module_info(monkeypatch):
    monkeypatch.setattr(settings, "MOCK_MODE", True)

    client = MetasploitRPCClient()
    info = await client.get_module_info("exploit", "windows/smb/ms17_010_eternalblue")

    assert info["simulated"] is True
    assert info["platform"] == "windows"


@pytest.mark.asyncio
async def test_rpc_client_mock_mode_run_module_success_then_fails_after_remediation(monkeypatch):
    monkeypatch.setattr(settings, "MOCK_MODE", True)

    client = MetasploitRPCClient()

    success = await client.run_module(
        "exploit", "windows/smb/ms17_010_eternalblue", {"RHOSTS": "10.0.0.5"}
    )
    assert success["exit_code"] == 0
    assert "shell_opened" in success["markers"]

    after_remediation = await client.run_module(
        "exploit",
        "windows/smb/ms17_010_eternalblue",
        {"RHOSTS": "10.0.0.5", "_simulated_remediated": "true"},
    )
    assert after_remediation["exit_code"] != 0
    assert after_remediation["markers"] == []
