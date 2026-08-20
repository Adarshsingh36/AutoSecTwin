"""
Centralized sync runner for VBoxManage/vagrant invocations.

Unlike the Docker Twin Engine (which has docker-sdk-python as an official
Python SDK), no comparable maintained Python SDK exists for VirtualBox or
Vagrant automation -- VBoxManage/vagrant CLIs are the standard tooling
implied by the tech stack. Every invocation uses subprocess execution with
an explicit argument list -- never a shell string, never shell=True -- so
there is no shell parsing or injection surface, only direct process
execution.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


def run_command(
    args: list[str],
    timeout_seconds: int,
) -> CommandResult:
    """
    Run `args[0] args[1:]` as a direct process (no shell),
    returning captured output.
    """

    process = subprocess.Popen(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    try:
        stdout_bytes, stderr_bytes = process.communicate(
            timeout=timeout_seconds,
        )

    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        raise

    return CommandResult(
        returncode=(
            process.returncode
            if process.returncode is not None
            else -1
        ),
        stdout=stdout_bytes.decode(errors="replace"),
        stderr=stderr_bytes.decode(errors="replace"),
    )