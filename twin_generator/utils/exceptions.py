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
    """Raised when neither status nor resource metrics could be collected for a twin."""

    def __init__(self, identifier: str, reason: str) -> None:
        self.identifier = identifier
        self.reason = reason
        super().__init__(f"Failed to collect metrics for {identifier!r}: {reason}")


class ContainerRestartError(TwinMonitorError):
    def __init__(self, container_name: str, reason: str) -> None:
        self.container_name = container_name
        super().__init__(f"Failed to auto-restart container {container_name!r}: {reason}")


# --- Twin Monitor ----------------------------------------------------------


class TwinMonitorError(TwinGeneratorError):
    """Base class for Twin Monitor failures."""


class MetricsCollectionError(TwinMonitorError):
    """Raised when CPU/RAM/disk/network stats cannot be retrieved, or a
    restart attempt fails, for a Docker container or VM."""

    def __init__(self, target_name: str, reason: str) -> None:
        self.target_name = target_name
        super().__init__(f"Metrics/restart operation failed for {target_name!r}: {reason}")


# --- Twin Cleanup Manager ---------------------------------------------------


class TwinCleanupError(TwinGeneratorError):
    """Base class for Twin Cleanup Manager failures."""


class SnapshotCleanupError(TwinCleanupError):
    def __init__(self, vm_name: str, reason: str) -> None:
        self.vm_name = vm_name
        super().__init__(f"Failed to clean up snapshots for VM {vm_name!r}: {reason}")


# --- Twin Monitor ----------------------------------------------------------


class TwinMonitorError(TwinGeneratorError):
    """Base class for Twin Monitor failures."""


class MetricsCollectionError(TwinMonitorError):
    def __init__(self, target: str, reason: str) -> None:
        self.target = target
        super().__init__(f"Failed to collect metrics for {target!r}: {reason}")
