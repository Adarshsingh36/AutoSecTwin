"""Digital Twin Generator - FastAPI routers."""

from twin_generator.api.legacy import router as legacy_router
from twin_generator.api.registry import router as registry_router
from twin_generator.api.twins import router as twins_router

__all__ = [
    "legacy_router",
    "registry_router",
    "twins_router",
]