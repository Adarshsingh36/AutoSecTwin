"""
Shared enumerations for the Digital Twin Generator module.

These enums back the SQLAlchemy models and Pydantic schemas for
twin_instances, twin_registry, legacy_profiles, and twin_logs.
"""

from __future__ import annotations

import enum


class EnvironmentType(str, enum.Enum):
    """Which twin backend produced/hosts a given twin instance."""

    DOCKER = "docker"
    VM = "vm"


class TwinStatus(str, enum.Enum):
    """Lifecycle status of a twin instance, driven by the Twin Orchestrator."""

    PENDING = "pending"
    CREATING = "creating"
    RUNNING = "running"
    DEGRADED = "degraded"
    FAILED = "failed"
    DESTROYING = "destroying"
    DESTROYED = "destroyed"


class HealthStatus(str, enum.Enum):
    """Result of the most recent health check performed on a twin."""

    UNKNOWN = "unknown"
    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"


class LegacyFlag(str, enum.Enum):
    """Classification produced by the Legacy Profiler for a twin's stack."""

    LEGACY = "legacy"
    SUPPORTED = "supported"
    UNKNOWN = "unknown"


class TwinLogEvent(str, enum.Enum):
    """Canonical event names recorded in twin_logs."""

    CREATED = "created"
    NETWORK_ASSIGNED = "network_assigned"
    STARTED = "started"
    HEALTH_CHECK_PASSED = "health_check_passed"
    HEALTH_CHECK_FAILED = "health_check_failed"
    AUTO_RESTARTED = "auto_restarted"
    REGISTERED = "registered"
    LEGACY_FLAGGED = "legacy_flagged"
    DESTROY_REQUESTED = "destroy_requested"
    DESTROYED = "destroyed"
    ERROR = "error"
