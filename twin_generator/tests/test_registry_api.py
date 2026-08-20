"""
Integration tests for the CVE Image Registry endpoints, run against a real
(in-memory SQLite) database through the actual FastAPI router -- no mocks.
"""

from __future__ import annotations

import pytest
from httpx import Client


def test_create_and_get_registry_entry(client: Client) -> None:
    response = client.post(
        "/registry",
        json={
            "cve": "CVE-2021-44228",
            "image": "vulhub/log4j",
            "version": "2.15.0",
        },
    )

    assert response.status_code == 201

    body = response.json()
    assert body["cve"] == "CVE-2021-44228"
    assert body["image"] == "vulhub/log4j"
    assert "id" in body


def test_create_duplicate_returns_409(client: Client) -> None:
    payload = {
        "cve": "CVE-2021-44228",
        "image": "vulhub/log4j",
        "version": "2.15.0",
    }

    first = client.post("/registry", json=payload)
    assert first.status_code == 201

    second = client.post("/registry", json=payload)
    assert second.status_code == 409


def test_list_registry_entries_filters_by_cve(client: Client) -> None:
    client.post(
        "/registry",
        json={"cve": "CVE-A", "image": "img/a"},
    )
    client.post(
        "/registry",
        json={"cve": "CVE-B", "image": "img/b"},
    )

    response = client.get(
        "/registry",
        params={"cve": "CVE-A"},
    )

    assert response.status_code == 200

    body = response.json()
    assert len(body) == 1
    assert body[0]["cve"] == "CVE-A"


def test_update_registry_entry(client: Client) -> None:
    created = client.post(
        "/registry",
        json={"cve": "CVE-C", "image": "img/old"},
    )

    entry_id = created.json()["id"]

    response = client.put(
        f"/registry/{entry_id}",
        json={"image": "img/new"},
    )

    assert response.status_code == 200
    assert response.json()["image"] == "img/new"


def test_update_missing_entry_returns_404(client: Client) -> None:
    response = client.put(
        "/registry/999999",
        json={"image": "img/x"},
    )

    assert response.status_code == 404


def test_delete_registry_entry(client: Client) -> None:
    created = client.post(
        "/registry",
        json={"cve": "CVE-D", "image": "img/d"},
    )

    entry_id = created.json()["id"]

    delete_response = client.delete(
        f"/registry/{entry_id}"
    )

    assert delete_response.status_code == 204

    list_response = client.get("/registry")

    assert all(
        item["id"] != entry_id
        for item in list_response.json()
    )


def test_delete_missing_entry_returns_404(client: Client) -> None:
    response = client.delete("/registry/999999")

    assert response.status_code == 404