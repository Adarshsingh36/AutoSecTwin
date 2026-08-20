"""
Shared FastAPI dependencies for the Digital Twin Generator.
"""

from fastapi import Depends
from sqlalchemy.orm import Session

from database.session import get_db
from twin_generator.docker_engine.client import get_docker_client
from twin_generator.docker_engine.manager import DockerTwinEngine
from twin_generator.legacy.service import LegacyProfilerService
from twin_generator.network.docker_network_manager import IsolatedNetworkManager
from twin_generator.registry.service import RegistryService
from twin_generator.services.orchestrator import TwinOrchestrator
from twin_generator.vm_engine.manager import VMTwinEngine

def get_session():
    yield from get_db()

def get_registry_service(
    db: Session = Depends(get_db),
):
    return RegistryService(db)


def get_legacy_service(
    db: Session = Depends(get_db),
):
    return LegacyProfilerService(db)


def get_orchestrator(
    db: Session = Depends(get_db),
    registry_service=Depends(get_registry_service),
    legacy_service=Depends(get_legacy_service),
):
    docker_client = get_docker_client()

    docker_engine = DockerTwinEngine(
        docker_client,
        IsolatedNetworkManager(docker_client),
    )

    return TwinOrchestrator(
        db,
        registry_service,
        docker_engine,
        VMTwinEngine(),
        legacy_service=legacy_service,
    )