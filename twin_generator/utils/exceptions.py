"""
Custom exception hierarchy for the Digital Twin Generator module.

Routers catch these and translate them to HTTP responses; service/repository
layers only ever raise subclasses of TwinGeneratorError so error handling
stays consistent across the module.
"""

from __future__ import annotations


class TwinGeneratorError(Exception):
    """Base class for all errors raised within the Digital Twin Generator module."""


# --- Registry -----------------------------------------------------------


class RegistryEntryNotFoundError(TwinGeneratorError):
    """Raised when a twin_registry row does not exist for the given id."""

    def __init__(self, entry_id: int) -> None:
        self.entry_id = entry_id
        super().__init__(f"Registry entry {entry_id} not found.")


class DuplicateRegistryEntryError(TwinGeneratorError):
    """Raised when a (cve, image, version) combination already exists."""

    def __init__(self, cve: str, image: str, version: str | None) -> None:
        self.cve = cve
        self.image = image
        self.version = version
        super().__init__(
            f"Registry entry already exists for cve={cve!r}, image={image!r}, version={version!r}."
        )


class NoRegistryEntryForCveError(TwinGeneratorError):
    """Raised when the Twin Orchestrator requests a CVE with no registry mapping."""

    def __init__(self, cve: str) -> None:
        self.cve = cve
        super().__init__(f"No registry entry found for cve={cve!r}. Cannot select a Docker image.")


class NoRegistryEntryForVersionError(TwinGeneratorError):
    """Raised when a CVE IS registered, but not for the specific version
    requested. Deliberately distinct from NoRegistryEntryForCveError: that
    one means "Docker can't reproduce this CVE at all, fall back to VM";
    this one means "Docker can reproduce this CVE, but not the exact
    version asked for" -- falling back to VM here would silently provision
    something unrelated to what was requested (e.g. a remediation asking
    for the fixed version getting the vulnerable one back, or vice versa),
    so this is intentionally NOT caught by the orchestrator's VM-fallback
    logic and is left to propagate as a clear, actionable error instead.
    """

    def __init__(self, cve: str, version: str, available_versions: list[str]) -> None:
        self.cve = cve
        self.version = version
        self.available_versions = available_versions
        super().__init__(
            f"Registry has cve={cve!r} but no entry for version={version!r}. "
            f"Available versions for this CVE: {available_versions or '(none recorded)'}. "
            "Register the requested version via POST /registry before provisioning it."
        )


# --- Twin lifecycle (used by later phases) -------------------------------


class TwinNotFoundError(TwinGeneratorError):
    def __init__(self, twin_id: int) -> None:
        self.twin_id = twin_id
        super().__init__(f"Twin instance {twin_id} not found.")


class TwinProvisioningError(TwinGeneratorError):
    """Raised when the Docker or VM Twin Engine fails to bring up a twin."""


class TwinHealthCheckError(TwinGeneratorError):
    """Raised when a twin fails its health check."""


class HealthCheckTimeoutError(TwinHealthCheckError):
    """Raised when a twin does not become healthy within the configured timeout."""

    def __init__(self, container_id: str, timeout_seconds: int) -> None:
        self.container_id = container_id
        self.timeout_seconds = timeout_seconds
        super().__init__(
            f"Container {container_id} did not become healthy within {timeout_seconds}s."
        )


# --- Docker Twin Engine ---------------------------------------------------


class DockerTwinEngineError(TwinGeneratorError):
    """Base class for Docker Twin Engine failures."""


class DockerImagePullError(DockerTwinEngineError):
    def __init__(self, image: str, reason: str) -> None:
        self.image = image
        self.reason = reason
        super().__init__(f"Failed to pull Docker image {image!r}: {reason}")


class DockerProvisioningError(DockerTwinEngineError):
    """Raised when container creation, network attach, or start fails."""


# --- Network Isolation ----------------------------------------------------


class NetworkIsolationError(TwinGeneratorError):
    """Raised when an isolated Docker network cannot be created or torn down."""


# --- VM Twin Engine --------------------------------------------------------


class VMTwinEngineError(TwinGeneratorError):
    """Base class for VM Twin Engine failures."""


class VMCommandError(VMTwinEngineError):
    """Raised when a VBoxManage/vagrant invocation exits non-zero."""

    def __init__(self, command: list[str], returncode: int, stderr: str) -> None:
        self.command = command
        self.returncode = returncode
        self.stderr = stderr
        super().__init__(
            f"Command {' '.join(command)!r} failed with exit code {returncode}: {stderr.strip()}"
        )


class VMSnapshotRestoreError(VMTwinEngineError):
    def __init__(self, vm_name: str, snapshot_name: str, reason: str) -> None:
        self.vm_name = vm_name
        self.snapshot_name = snapshot_name
        super().__init__(
            f"Failed to restore snapshot {snapshot_name!r} for VM {vm_name!r}: {reason}"
        )


class VMBootError(VMTwinEngineError):
    def __init__(self, vm_name: str, reason: str) -> None:
        self.vm_name = vm_name
        super().__init__(f"Failed to boot VM {vm_name!r}: {reason}")


class VMNetworkConfigError(VMTwinEngineError):
    def __init__(self, vm_name: str, reason: str) -> None:
        self.vm_name = vm_name
        super().__init__(f"Failed to configure network for VM {vm_name!r}: {reason}")


class VMHeartbeatTimeoutError(VMTwinEngineError):
    def __init__(self, vm_name: str, timeout_seconds: int) -> None:
        self.vm_name = vm_name
        self.timeout_seconds = timeout_seconds
        super().__init__(f"VM {vm_name!r} did not respond to heartbeat within {timeout_seconds}s.")


# --- Twin Monitor ----------------------------------------------------------


class TwinMonitorError(TwinGeneratorError):
    """Base class for Twin Monitor failures."""


class MetricsCollectionError(TwinMonitorError):
    """Raised when CPU/RAM/disk/network stats cannot be retrieved for a
    Docker container or VM."""

    def __init__(self, target: str, reason: str) -> None:
        self.target = target
        super().__init__(f"Failed to collect metrics for {target!r}: {reason}")


class ContainerRestartError(TwinMonitorError):
    """Raised when an auto-restart attempt on a failed container fails."""

    def __init__(self, container_name: str, reason: str) -> None:
        self.container_name = container_name
        super().__init__(f"Failed to auto-restart container {container_name!r}: {reason}")


# --- Twin Cleanup Manager ---------------------------------------------------


class TwinCleanupError(TwinGeneratorError):
    """Base class for Twin Cleanup Manager failures."""


class SnapshotCleanupError(TwinCleanupError):
    def __init__(self, vm_name: str, reason: str) -> None:
        self.vm_name = vm_name
        super().__init__(f"Failed to clean up snapshots for VM {vm_name!r}: {reason}")
