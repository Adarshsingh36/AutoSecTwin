"""
Tests for services/orchestration/session_evidence.py -- real parsing of
Metasploit meterpreter/shell command output, and the overall
gather_session_proof orchestration (RPC client mocked).
"""

import asyncio
from unittest.mock import AsyncMock

import pytest

from services.orchestration.session_evidence import (
    _extract_arch_from_uname,
    _parse_getuid,
    _parse_sysinfo,
    gather_session_proof,
)


# ---------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------


def test_parse_sysinfo_extracts_all_fields():
    raw = (
        "Computer        : TWIN-ACTIVEMQ\n"
        "OS              : Linux twin-activemq 5.15.0 #1 SMP x86_64\n"
        "Architecture    : x64\n"
        "Meterpreter     : java/linux\n"
    )
    hostname, os_, arch = _parse_sysinfo(raw)
    assert hostname == "TWIN-ACTIVEMQ"
    assert os_ == "Linux twin-activemq 5.15.0 #1 SMP x86_64"
    assert arch == "x64"


def test_parse_sysinfo_tolerates_missing_fields():
    hostname, os_, arch = _parse_sysinfo("Computer        : HOST-ONLY\n")
    assert hostname == "HOST-ONLY"
    assert os_ is None
    assert arch is None


def test_parse_sysinfo_handles_empty_input():
    assert _parse_sysinfo("") == (None, None, None)


def test_parse_getuid_with_prefix():
    assert _parse_getuid("Server username: root") == "root"


def test_parse_getuid_without_prefix():
    assert _parse_getuid("root") == "root"


def test_parse_getuid_empty_returns_none():
    assert _parse_getuid("   ") is None


def test_extract_arch_from_uname_finds_x86_64():
    uname = "Linux twin-activemq 5.15.0-91-generic #101-Ubuntu SMP x86_64 x86_64 x86_64 GNU/Linux"
    assert _extract_arch_from_uname(uname) == "x86_64"


def test_extract_arch_from_uname_returns_none_when_absent():
    assert _extract_arch_from_uname("some unparseable output") is None


# ---------------------------------------------------------
# gather_session_proof
# ---------------------------------------------------------


@pytest.mark.asyncio
async def test_gather_session_proof_meterpreter():
    rpc_client = AsyncMock()
    rpc_client.session_meterpreter_run_single.side_effect = [
        {"result": "Computer        : TWIN-HOST\nOS              : Linux\nArchitecture    : x64\n"},
        {"result": "Server username: root"},
        {"result": "/opt/activemq"},
    ]

    proof = await gather_session_proof(rpc_client, session_id=1, session_type="meterpreter")

    assert proof.hostname == "TWIN-HOST"
    assert proof.operating_system == "Linux"
    assert proof.architecture == "x64"
    assert proof.user == "root"
    assert proof.working_directory == "/opt/activemq"


@pytest.mark.asyncio
async def test_gather_session_proof_shell():
    rpc_client = AsyncMock()
    rpc_client.session_shell_write = AsyncMock(return_value={})
    rpc_client.session_shell_read = AsyncMock(
        side_effect=[
            {"data": "root\n"},
            {"data": "twin-activemq\n"},
            {"data": "/opt/activemq\n"},
            {"data": "Linux twin-activemq 5.15.0 x86_64 GNU/Linux\n"},
        ]
    )

    proof = await gather_session_proof(rpc_client, session_id=2, session_type="shell")

    assert proof.user == "root"
    assert proof.hostname == "twin-activemq"
    assert proof.working_directory == "/opt/activemq"
    assert "Linux" in proof.operating_system
    assert proof.architecture == "x86_64"


@pytest.mark.asyncio
async def test_gather_session_proof_never_raises_on_rpc_failure():
    rpc_client = AsyncMock()
    rpc_client.session_meterpreter_run_single.side_effect = RuntimeError("RPC connection lost")

    proof = await gather_session_proof(rpc_client, session_id=1, session_type="meterpreter")

    assert proof.user is None
    assert proof.hostname is None


@pytest.mark.asyncio
async def test_gather_session_proof_handles_timeout(monkeypatch):
    from core.config import settings

    monkeypatch.setattr(settings, "SESSION_VERIFICATION_TIMEOUT_SECONDS", 0.01)

    async def _hangs(*args, **kwargs):
        await asyncio.sleep(5)
        return {"result": "never"}

    rpc_client = AsyncMock()
    rpc_client.session_meterpreter_run_single.side_effect = _hangs

    proof = await gather_session_proof(rpc_client, session_id=1, session_type="meterpreter")

    assert proof.user is None
    assert proof.raw_outputs is None
