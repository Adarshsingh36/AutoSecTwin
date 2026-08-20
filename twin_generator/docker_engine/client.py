"""
Docker client factory.

A single place that constructs the docker-sdk-python client, so every
consumer (Docker Twin Engine, Network Isolation Manager, Twin Monitor,
Twin Cleanup Manager) shares one configuration path.
"""

from __future__ import annotations

from functools import lru_cache

import docker
from docker import DockerClient


@lru_cache(maxsize=1)
def get_docker_client() -> DockerClient:
    """Return a process-wide Docker client built from the environment
    (DOCKER_HOST, TLS config, etc.), matching `docker-sdk-python`'s
    standard `from_env()` behavior. No shell commands are used anywhere
    in this module -- all Docker interaction goes through this SDK client.
    """
    return docker.from_env()
