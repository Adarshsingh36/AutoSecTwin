"""
Given a live Metasploit session, actually run verification commands on it
and parse real output -- this module is what turns "a session exists" into
the kind of proof a human reviewer can read (user, hostname, OS,
architecture, working directory).

Deliberately separate from ExploitExecutor: that module owns the
console-driving control flow (launching the module, deciding whether a
session appeared, timeouts); this one only knows "given a session_id and
its type, what did the target actually say back".
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Optional

from core.config import settings
from integrations.metasploit.rpc_client import MetasploitRPCClient

logger = logging.getLogger(__name__)


@dataclass
class SessionProof:
    user: Optional[str] = None
    hostname: Optional[str] = None
    working_directory: Optional[str] = None
    operating_system: Optional[str] = None
    architecture: Optional[str] = None
    raw_outputs: dict[str, str] | None = None


async def gather_session_proof(
    rpc_client: MetasploitRPCClient,
    session_id: int,
    session_type: str,
) -> SessionProof:
    """Run verification commands appropriate to the session type.

    Never raises -- a verification command failing (session died mid-check,
    RPC hiccup, unparseable output) is recorded as missing proof, not as an
    exploit-execution failure. The session already being established is
    itself real evidence; this is best-effort enrichment on top of it.
    """

    try:
        if session_type == "meterpreter":
            return await asyncio.wait_for(
                _gather_meterpreter_proof(rpc_client, session_id),
                timeout=settings.SESSION_VERIFICATION_TIMEOUT_SECONDS,
            )
        return await asyncio.wait_for(
            _gather_shell_proof(rpc_client, session_id),
            timeout=settings.SESSION_VERIFICATION_TIMEOUT_SECONDS,
        )
    except asyncio.TimeoutError:
        logger.warning("Session verification timed out for session %s", session_id)
        return SessionProof()
    except Exception:  # noqa: BLE001 - verification is always best-effort
        logger.exception("Session verification failed for session %s", session_id)
        return SessionProof()


async def _gather_meterpreter_proof(
    rpc_client: MetasploitRPCClient, session_id: int
) -> SessionProof:
    sysinfo_raw = await _meterpreter_command(rpc_client, session_id, "sysinfo")
    uid_raw = await _meterpreter_command(rpc_client, session_id, "getuid")
    pwd_raw = await _meterpreter_command(rpc_client, session_id, "pwd")

    hostname, operating_system, architecture = _parse_sysinfo(sysinfo_raw)
    user = _parse_getuid(uid_raw)
    working_directory = pwd_raw.strip() or None

    return SessionProof(
        user=user,
        hostname=hostname,
        working_directory=working_directory,
        operating_system=operating_system,
        architecture=architecture,
        raw_outputs={"sysinfo": sysinfo_raw, "getuid": uid_raw, "pwd": pwd_raw},
    )


async def _gather_shell_proof(rpc_client: MetasploitRPCClient, session_id: int) -> SessionProof:
    user = (await _shell_command(rpc_client, session_id, "whoami")).strip() or None
    hostname = (await _shell_command(rpc_client, session_id, "hostname")).strip() or None
    working_directory = (await _shell_command(rpc_client, session_id, "pwd")).strip() or None
    uname = (await _shell_command(rpc_client, session_id, "uname -a")).strip()

    return SessionProof(
        user=user,
        hostname=hostname,
        working_directory=working_directory,
        operating_system=uname or None,
        architecture=_extract_arch_from_uname(uname),
        raw_outputs={"whoami": user or "", "hostname": hostname or "", "pwd": working_directory or "", "uname -a": uname},
    )


async def _meterpreter_command(rpc_client: MetasploitRPCClient, session_id: int, command: str) -> str:
    result = await rpc_client.session_meterpreter_run_single(session_id, command)
    return str(result.get("result") or result.get("data") or "")


async def _shell_command(rpc_client: MetasploitRPCClient, session_id: int, command: str) -> str:
    await rpc_client.session_shell_write(session_id, command + "\n")
    await asyncio.sleep(settings.SESSION_SHELL_COMMAND_SETTLE_SECONDS)
    result = await rpc_client.session_shell_read(session_id)
    return str(result.get("data") or "")


def _parse_sysinfo(raw: str) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """Parse meterpreter's `sysinfo` output.

    Typical shape:
        Computer        : TWIN-HOST
        OS              : Linux twin-host 5.15.0 #1 SMP x86_64
        Architecture    : x64
        ...
    Tolerant of extra/missing lines -- only pulls out what it can find.
    """

    hostname = operating_system = architecture = None

    for line in raw.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()
        if not value:
            continue
        if key == "computer":
            hostname = value
        elif key == "os":
            operating_system = value
        elif key == "architecture":
            architecture = value

    return hostname, operating_system, architecture


def _parse_getuid(raw: str) -> Optional[str]:
    """Parse meterpreter's `getuid` output, e.g. "Server username: root"."""

    raw = raw.strip()
    if not raw:
        return None
    if ":" in raw:
        return raw.rsplit(":", 1)[-1].strip() or None
    return raw


def _extract_arch_from_uname(uname_output: str) -> Optional[str]:
    """Best-effort architecture extraction from `uname -a` output -- the
    last whitespace-separated token before the OS name is conventionally
    the machine hardware name (x86_64, aarch64, etc.) on Linux.
    """

    tokens = uname_output.split()
    for token in reversed(tokens):
        if token in ("x86_64", "aarch64", "arm64", "i686", "i386"):
            return token
    return None
