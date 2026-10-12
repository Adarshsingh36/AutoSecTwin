"""
Tests for the new session.*/console.destroy RPC primitives added for real
exploit evidence gathering. _call_raw (the actual HTTP/msgpack transport)
is patched -- these tests verify the correct RPC method name and
parameters are sent, not real Metasploit connectivity.
"""

from unittest.mock import AsyncMock, patch

import pytest

from integrations.metasploit.rpc_client import MetasploitRPCClient


@pytest.fixture
def client():
    c = MetasploitRPCClient()
    c.mock_mode = False
    c._token = "test-token"
    return c


@pytest.mark.asyncio
async def test_session_list_sends_correct_rpc_call(client):
    with patch.object(client, "_call_raw", new=AsyncMock(return_value={1: {"type": "shell"}})) as mock_call:
        result = await client.session_list()

    mock_call.assert_awaited_once_with(["session.list", "test-token"])
    assert result == {1: {"type": "shell"}}


@pytest.mark.asyncio
async def test_session_meterpreter_run_single_sends_correct_rpc_call(client):
    with patch.object(
        client, "_call_raw", new=AsyncMock(return_value={"result": "Computer: HOST"})
    ) as mock_call:
        result = await client.session_meterpreter_run_single(1, "sysinfo")

    mock_call.assert_awaited_once_with(
        ["session.meterpreter_run_single", "test-token", 1, "sysinfo"]
    )
    assert result == {"result": "Computer: HOST"}


@pytest.mark.asyncio
async def test_session_shell_write_sends_correct_rpc_call(client):
    with patch.object(client, "_call_raw", new=AsyncMock(return_value={"write_count": 7})) as mock_call:
        await client.session_shell_write(2, "whoami\n")

    mock_call.assert_awaited_once_with(["session.shell_write", "test-token", 2, "whoami\n"])


@pytest.mark.asyncio
async def test_session_shell_read_sends_correct_rpc_call(client):
    with patch.object(client, "_call_raw", new=AsyncMock(return_value={"data": "root\n"})) as mock_call:
        result = await client.session_shell_read(2)

    mock_call.assert_awaited_once_with(["session.shell_read", "test-token", 2])
    assert result["data"] == "root\n"


@pytest.mark.asyncio
async def test_destroy_console_sends_correct_rpc_call(client):
    with patch.object(client, "_call_raw", new=AsyncMock(return_value={"result": "success"})) as mock_call:
        await client.destroy_console("5")

    mock_call.assert_awaited_once_with(["console.destroy", "test-token", "5"])


@pytest.mark.asyncio
async def test_destroy_console_mock_mode_never_calls_rpc():
    client = MetasploitRPCClient()
    client.mock_mode = True

    with patch.object(client, "_call_raw", new=AsyncMock()) as mock_call:
        result = await client.destroy_console("5")

    mock_call.assert_not_called()
    assert result["simulated"] is True


@pytest.mark.asyncio
async def test_session_list_mock_mode_returns_empty_without_rpc_call():
    client = MetasploitRPCClient()
    client.mock_mode = True

    with patch.object(client, "_call_raw", new=AsyncMock()) as mock_call:
        result = await client.session_list()

    mock_call.assert_not_called()
    assert result == {}
