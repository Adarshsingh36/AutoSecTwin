"""
Unit tests for RegistryService: business rules only, repository is mocked
out so these tests run without touching any database.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from twin_generator.models.twin_registry import TwinRegistry
from twin_generator.registry.service import RegistryService
from twin_generator.schemas.twin_registry import (
    RegistryEntryCreate,
    RegistryEntryUpdate,
)
from twin_generator.utils.enums import EnvironmentType
from twin_generator.utils.exceptions import (
    DuplicateRegistryEntryError,
    NoRegistryEntryForCveError,
    NoRegistryEntryForVersionError,
    RegistryEntryNotFoundError,
)


@pytest.fixture
def service() -> RegistryService:
    svc = RegistryService(session=MagicMock())
    svc._repo = MagicMock()  # bypass the real repository entirely
    return svc


class TestCreateEntry:
    def test_creates_when_no_duplicate(self, service: RegistryService) -> None:
        service._repo.find_duplicate.return_value = None

        created = TwinRegistry(
            id=1,
            cve="CVE-2021-44228",
            image="vulhub/log4j",
            version="2.15.0",
        )
        service._repo.create.return_value = created

        payload = RegistryEntryCreate(
            cve="CVE-2021-44228",
            image="vulhub/log4j",
            environment=EnvironmentType.DOCKER,
            version="2.15.0",
        )

        result = service.create_entry(payload)

        assert result.id == 1
        service._repo.create.assert_called_once()

    def test_rejects_duplicate(self, service: RegistryService) -> None:
        service._repo.find_duplicate.return_value = TwinRegistry(
            id=1,
            cve="CVE-2021-44228",
            image="vulhub/log4j",
            version="2.15.0",
        )

        payload = RegistryEntryCreate(
            cve="CVE-2021-44228",
            image="vulhub/log4j",
            version="2.15.0",
        )

        with pytest.raises(DuplicateRegistryEntryError):
            service.create_entry(payload)

        service._repo.create.assert_not_called()


class TestGetEntry:
    def test_returns_entry_when_found(self, service: RegistryService) -> None:
        service._repo.get_by_id.return_value = TwinRegistry(
            id=5,
            cve="CVE-X",
            image="img",
        )

        result = service.get_entry(5)

        assert result.id == 5

    def test_raises_when_missing(self, service: RegistryService) -> None:
        service._repo.get_by_id.return_value = None

        with pytest.raises(RegistryEntryNotFoundError):
            service.get_entry(999)


class TestUpdateEntry:
    def test_updates_only_provided_fields(self, service: RegistryService) -> None:
        existing = TwinRegistry(
            id=1,
            cve="CVE-1",
            image="old/image",
            version="1.0",
            notes="old notes",
        )

        service._repo.get_by_id.return_value = existing

        payload = RegistryEntryUpdate(image="new/image")

        result = service.update_entry(1, payload)

        assert result.image == "new/image"
        assert result.version == "1.0"
        assert result.notes == "old notes"

    def test_raises_when_missing(self, service: RegistryService) -> None:
        service._repo.get_by_id.return_value = None

        with pytest.raises(RegistryEntryNotFoundError):
            service.update_entry(
                999,
                RegistryEntryUpdate(image="x"),
            )


class TestDeleteEntry:
    def test_deletes_existing(self, service: RegistryService) -> None:
        existing = TwinRegistry(
            id=1,
            cve="CVE-1",
            image="img",
        )

        service._repo.get_by_id.return_value = existing

        service.delete_entry(1)

        service._repo.delete.assert_called_once_with(existing)

    def test_raises_when_missing(self, service: RegistryService) -> None:
        service._repo.get_by_id.return_value = None

        with pytest.raises(RegistryEntryNotFoundError):
            service.delete_entry(999)


class TestResolveImageForCve:
    def test_returns_most_recent_mapping(self, service: RegistryService) -> None:
        older = TwinRegistry(
            id=1,
            cve="CVE-1",
            image="old/image",
        )

        newer = TwinRegistry(
            id=2,
            cve="CVE-1",
            image="new/image",
        )

        service._repo.list_for_cve.return_value = [
            older,
            newer,
        ]

        result = service.resolve_image_for_cve("CVE-1")

        assert result.image == "new/image"

    def test_returns_most_recent_mapping_when_version_omitted(
        self, service: RegistryService
    ) -> None:
        vulnerable = TwinRegistry(id=1, cve="CVE-2023-46604", image="autosectwin/activemq", version="5.17.3")
        fixed = TwinRegistry(id=2, cve="CVE-2023-46604", image="apache/activemq-classic", version="5.17.6")
        service._repo.list_for_cve.return_value = [vulnerable, fixed]

        result = service.resolve_image_for_cve("CVE-2023-46604")

        assert result.image == "apache/activemq-classic"

    def test_selects_vulnerable_version_explicitly(self, service: RegistryService) -> None:
        vulnerable = TwinRegistry(id=1, cve="CVE-2023-46604", image="autosectwin/activemq", version="5.17.3")
        fixed = TwinRegistry(id=2, cve="CVE-2023-46604", image="apache/activemq-classic", version="5.17.6")
        service._repo.list_for_cve.return_value = [vulnerable, fixed]

        result = service.resolve_image_for_cve("CVE-2023-46604", version="5.17.3")

        assert result.image == "autosectwin/activemq"
        assert result.version == "5.17.3"

    def test_selects_fixed_version_explicitly(self, service: RegistryService) -> None:
        vulnerable = TwinRegistry(id=1, cve="CVE-2023-46604", image="autosectwin/activemq", version="5.17.3")
        fixed = TwinRegistry(id=2, cve="CVE-2023-46604", image="apache/activemq-classic", version="5.17.6")
        service._repo.list_for_cve.return_value = [vulnerable, fixed]

        result = service.resolve_image_for_cve("CVE-2023-46604", version="5.17.6")

        assert result.image == "apache/activemq-classic"
        assert result.version == "5.17.6"

    def test_requesting_vulnerable_version_never_returns_fixed_image(
        self, service: RegistryService
    ) -> None:
        """Regression guard: picking a specific version must never
        silently fall through to a different one, in either direction."""
        vulnerable = TwinRegistry(id=1, cve="CVE-2023-46604", image="autosectwin/activemq", version="5.17.3")
        fixed = TwinRegistry(id=2, cve="CVE-2023-46604", image="apache/activemq-classic", version="5.17.6")
        service._repo.list_for_cve.return_value = [vulnerable, fixed]

        result = service.resolve_image_for_cve("CVE-2023-46604", version="5.17.3")

        assert result.image != "apache/activemq-classic"

    def test_raises_specific_error_when_cve_known_but_version_unregistered(
        self, service: RegistryService
    ) -> None:
        vulnerable = TwinRegistry(id=1, cve="CVE-2023-46604", image="autosectwin/activemq", version="5.17.3")
        service._repo.list_for_cve.return_value = [vulnerable]

        with pytest.raises(NoRegistryEntryForVersionError) as exc_info:
            service.resolve_image_for_cve("CVE-2023-46604", version="5.17.6")

        assert exc_info.value.available_versions == ["5.17.3"]

    def test_raises_when_no_mapping(self, service: RegistryService) -> None:
        service._repo.list_for_cve.return_value = []

        with pytest.raises(NoRegistryEntryForCveError):
            service.resolve_image_for_cve("CVE-UNKNOWN")