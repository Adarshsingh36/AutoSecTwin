import logging

from fastapi import FastAPI

from twin_generator.api import (
    legacy_router,
    registry_router,
    twins_router,
)

logging.basicConfig(level=logging.INFO)

app = FastAPI(
    title="AutoSecTwin Digital Twin Generator",
    version="1.0.0",
)

app.include_router(twins_router)
app.include_router(registry_router)
app.include_router(legacy_router)


@app.get("/")
def root():
    return {
        "service": "Digital Twin Generator",
        "status": "running",
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
    }