"""
Twin Orchestrator.

Ties the CVE Image Registry, Docker Twin Engine, VM Twin Engine, and Legacy
Profiler together. Implements the workflow exactly as specified:

    Twin Generator receives CVE -> search registry -> Docker available?
      YES -> pull image -> create isolated bridge -> create container ->
             health check -> register twin -> return Twin ID
      NO  -> VirtualBox snapshot -> restore -> boot VM -> health check ->
             register twin -> return Twin ID
    -> Legacy Profiler -> flag if EOL
    -> Exploit Engine receives Twin ID (out of scope: whichever module
       orchestrates the Exploit Engine reads the returned twin id/uuid)
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, Sequence

import structlog
from sqlalchemy.orm import Session
from twin_generator.docker_engine.manager import DockerTwinEngine
from twin_generator.legacy.service import LegacyProfilerService
from twin_generator.models.twin_instance import TwinInstance
from twin_generator.registry.service import RegistryService
from twin_generator.schemas.twin_instance import TwinCreateRequest
from twin_generator.services.twin_repository import TwinRepository
from twin_generator.utils.enums import EnvironmentType, HealthStatus, TwinLogEvent, TwinStatus
from twin_generator.utils.exceptions import (
    NoRegistryEntryForCveError,
    TwinNotFoundError,
    TwinProvisioningError,
)
from twin_generator.vm_engine.config import VMEngineSettings
from twin_generator.vm_engine.manager import VMTwinEngine

logger = structlog.get_logger(__name__)

DEFAULT_TTL_SECONDS = 3600


class TwinOrchestrator:
    """Coordinates twin creation, lookup, health reporting, and on-demand destruction."""

    def __init__(
        self,
        session: Session,
        registry_service: RegistryService,
        docker_engine: DockerTwinEngine,
        vm_engine: Optional[VMTwinEngine] = None,
        legacy_service: Optional[LegacyProfilerService] = None,
    ) -> None:
        self._session = session
        self._repo = TwinRepository(session)
        self._registry = registry_service
        self._docker_engine = docker_engine
        self._vm_engine = vm_engine or VMTwinEngine(VMEngineSettings())
        self._legacy_service = legacy_service

    # -- create ---------------------------------------------------------

    def create_twin(self, payload: TwinCreateRequest) -> TwinInstance:
        twin_uuid = uuid.uuid4()
        ttl = payload.ttl_seconds or DEFAULT_TTL_SECONDS

        twin = TwinInstance(
            uuid=twin_uuid,
            host=payload.host,
            cve=payload.cve,
            status=TwinStatus.PENDING.value,
            environment=(payload.environment or EnvironmentType.DOCKER).value,
            health=HealthStatus.UNKNOWN.value,
            created_at=datetime.now(timezone.utc),
            destroy_at=datetime.now(timezone.utc) + timedelta(seconds=ttl),
        )
        twin = self._repo.create(twin)
        self._repo.add_log(twin.id, TwinLogEvent.CREATED, f"cve={payload.cve}")

        try:
            if payload.environment == EnvironmentType.VM:
                self._provision_vm(twin)
            else:
                self._provision_docker_with_fallback(twin, payload)

            if payload.software:
                self._apply_legacy_check(
                    twin,
                    payload.software,
                    payload.version,
                )

            twin.status = (
                TwinStatus.RUNNING
                if twin.health == HealthStatus.HEALTHY.value
                else TwinStatus.DEGRADED
            ).value
            self._repo.save(twin)

            self._repo.add_log(
                twin.id,
                TwinLogEvent.REGISTERED,
                f"twin_uuid={twin.uuid}",
            )
        except Exception as exc:
            twin.status = TwinStatus.FAILED.value
            self._repo.save(twin)
            self._repo.add_log(twin.id, TwinLogEvent.ERROR, str(exc))
            raise TwinProvisioningError(str(exc)) from exc

        return twin

    def _provision_docker_with_fallback(
        self, twin: TwinInstance, payload: TwinCreateRequest
    ) -> None:
        try:
            image_entry = self._registry.resolve_image_for_cve(payload.cve)
        except NoRegistryEntryForCveError:
            logger.info("no_docker_image_falling_back_to_vm", cve=payload.cve)
            self._repo.add_log(
                twin.id, TwinLogEvent.ERROR, "No registry image for CVE; falling back to VM."
            )
            twin.environment = EnvironmentType.VM.value
            self._provision_vm(twin)
            return

        twin.status = TwinStatus.CREATING.value
        twin.environment = EnvironmentType.DOCKER.value
        self._repo.save(twin)

        result = self._docker_engine.provision_twin(
            twin_uuid=str(twin.uuid), image=image_entry.image
        )

        twin.twin_image = result.image
        twin.ip_address = result.ip_address
        twin.network = result.network_name
        twin.health = (HealthStatus.HEALTHY if result.healthy else HealthStatus.UNHEALTHY).value
        self._repo.save(twin)

        self._repo.add_log(twin.id, TwinLogEvent.NETWORK_ASSIGNED, result.network_name)
        self._repo.add_log(twin.id, TwinLogEvent.STARTED, f"container_id={result.container_id}")
        self._repo.add_log(
            twin.id,
            TwinLogEvent.HEALTH_CHECK_PASSED if result.healthy else TwinLogEvent.HEALTH_CHECK_FAILED,
            f"container_id={result.container_id}",
        )

    def _provision_vm(self, twin: TwinInstance) -> None:
        twin.status = TwinStatus.CREATING.value
        vm_name = twin.vm_name or f"twin-vm-{twin.uuid}"
        network_name = f"twin-vm-net-{twin.uuid}"
        twin.vm_name = vm_name
        self._repo.save(twin)

        result = self._vm_engine.provision_twin(vm_name=vm_name, network_name=network_name)

        twin.network = result.network_name
        twin.ip_address = result.ip_address
        twin.health = (HealthStatus.HEALTHY if result.healthy else HealthStatus.UNHEALTHY).value
        self._repo.save(twin)

        self._repo.add_log(twin.id, TwinLogEvent.NETWORK_ASSIGNED, result.network_name)
        self._repo.add_log(twin.id, TwinLogEvent.STARTED, f"vm_name={vm_name}")
        self._repo.add_log(
            twin.id,
            TwinLogEvent.HEALTH_CHECK_PASSED if result.healthy else TwinLogEvent.HEALTH_CHECK_FAILED,
            f"vm_name={vm_name}",
        )

    def _apply_legacy_check(
        self, twin: TwinInstance, software: str, version: Optional[str]
    ) -> None:
        if self._legacy_service is None or not version:
            return
        result = self._legacy_service.check(software, version)
        twin.legacy_flag = result.classification.value
        self._repo.save(twin)
        self._repo.add_log(
            twin.id,
            TwinLogEvent.LEGACY_FLAGGED,
            f"software={software} version={version} classification={result.classification.value}",
        )

    # -- read -------------------------------------------------------------

    def get_twin(self, twin_id: int) -> TwinInstance:
        twin = self._repo.get_by_id(twin_id)
        if twin is None:
            raise TwinNotFoundError(twin_id)
        return twin

    def list_twins(self) -> Sequence[TwinInstance]:
        return self._repo.list_all()

    # -- destroy ------------------------------------------------------------

    def destroy_twin(self, twin_id: int) -> TwinInstance:
        twin = self.get_twin(twin_id)
        self._repo.add_log(twin.id, TwinLogEvent.DESTROY_REQUESTED, None)
        twin.status = TwinStatus.DESTROYING.value
        self._repo.save(twin)

        try:
            if twin.environment == EnvironmentType.DOCKER.value and twin.network:
                self._docker_engine.destroy_twin(str(twin.uuid), twin.network)
            elif twin.environment == EnvironmentType.VM.value and twin.vm_name:
                self._vm_engine.power_off(twin.vm_name)
        except Exception as exc:  # pragma: no cover - best-effort teardown
            logger.warning("twin_teardown_failed", twin_id=twin_id, error=str(exc))
            self._repo.add_log(twin.id, TwinLogEvent.ERROR, f"teardown_warning={exc}")

        twin.status = TwinStatus.DESTROYED.value
        self._repo.save(twin)
        self._repo.add_log(twin.id, TwinLogEvent.DESTROYED, None)
        return twin
