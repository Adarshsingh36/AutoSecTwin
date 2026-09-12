from unittest.mock import AsyncMock, patch

from database.models.asset import Asset
from database.models.exploit import Exploit
from database.models.remediation import Remediation
from database.models.twin import Twin
from database.models.validation import Validation
from database.models.vulnerability import Vulnerability


def _seed_asset(db) -> Asset:
    asset = Asset(name="Legacy File Server", asset_type="Server", hostname="fileserver01", environment="production")
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset


def _seed_vulnerability(db, asset: Asset) -> Vulnerability:
    vuln = Vulnerability(
        asset_id=asset.id,
        cve_id="CVE-2017-0144",
        title="EternalBlue",
        cvss_score=9.8,
        epss_score=0.9,
        severity="CRITICAL",
        kev_listed=True,
    )
    db.add(vuln)
    db.commit()
    db.refresh(vuln)
    return vuln


# ---------------------------------------------------------------------
# Vulnerabilities
# ---------------------------------------------------------------------


def test_create_vulnerability_persists_and_scores(client, db):
    asset = _seed_asset(db)

    with patch(
        "api.routes.vulnerabilities.EPSSClient.fetch_score",
        new_callable=AsyncMock,
    ) as mock_epss:
        mock_epss.return_value = {"data": [{"epss": "0.87", "percentile": "0.95"}]}

        response = client.post(
            "/vulnerabilities/",
            json={
                "asset_id": asset.id,
                "cve_id": "CVE-2021-44228",
                "title": "Log4Shell",
                "cvss_score": 10.0,
                "severity": "CRITICAL",
                "kev_listed": True,
            },
        )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["cve_id"] == "CVE-2021-44228"
    assert 0.0 <= body["exploitability_probability"] <= 1.0
    assert db.query(Vulnerability).filter(Vulnerability.cve_id == "CVE-2021-44228").count() == 1


def test_list_vulnerabilities_returns_seeded_rows(client, db):
    asset = _seed_asset(db)
    _seed_vulnerability(db, asset)

    response = client.get("/vulnerabilities/")

    assert response.status_code == 200
    body = response.json()
    assert len(body) == 1
    assert body[0]["cve_id"] == "CVE-2017-0144"


def test_get_vulnerability_404_for_missing_id(client):
    response = client.get("/vulnerabilities/999999")
    assert response.status_code == 404


# ---------------------------------------------------------------------
# Exploits
# ---------------------------------------------------------------------


def test_create_exploit_persists(client, db):
    asset = _seed_asset(db)
    vuln = _seed_vulnerability(db, asset)

    response = client.post(
        "/exploits/",
        json={
            "vulnerability_id": vuln.id,
            "source": "metasploit",
            "module_name": "windows/smb/ms17_010_eternalblue",
            "title": "MS17-010 EternalBlue",
            "reliability_score": 0.9,
            "requires_auth": False,
        },
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["module_name"] == "windows/smb/ms17_010_eternalblue"
    assert db.query(Exploit).filter(Exploit.vulnerability_id == vuln.id).count() == 1


def test_list_exploits_filters_by_vulnerability(client, db):
    asset = _seed_asset(db)
    vuln = _seed_vulnerability(db, asset)
    other_vuln = Vulnerability(asset_id=asset.id, cve_id="CVE-2020-0001", title="Other", severity="LOW")
    db.add(other_vuln)
    db.commit()
    db.refresh(other_vuln)

    db.add(Exploit(vulnerability_id=vuln.id, source="metasploit", title="Exploit A", module_name="a/b/c"))
    db.add(Exploit(vulnerability_id=other_vuln.id, source="metasploit", title="Exploit B", module_name="x/y/z"))
    db.commit()

    response = client.get("/exploits/", params={"vulnerability_id": vuln.id})

    assert response.status_code == 200
    body = response.json()
    assert len(body) == 1
    assert body[0]["title"] == "Exploit A"


def test_list_exploits_without_filter_returns_all(client, db):
    asset = _seed_asset(db)
    vuln = _seed_vulnerability(db, asset)
    db.add(Exploit(vulnerability_id=vuln.id, source="metasploit", title="Exploit A", module_name="a/b/c"))
    db.commit()

    response = client.get("/exploits/")

    assert response.status_code == 200
    assert len(response.json()) == 1


# ---------------------------------------------------------------------
# Validations
# ---------------------------------------------------------------------


def test_create_validation_persists_with_vulnerability_id(client, db):
    asset = _seed_asset(db)
    vuln = _seed_vulnerability(db, asset)
    exploit = Exploit(vulnerability_id=vuln.id, source="metasploit", title="Exploit A", module_name="a/b/c")
    db.add(exploit)
    db.commit()
    db.refresh(exploit)

    response = client.post(
        "/validations/",
        json={
            "vulnerability_id": vuln.id,
            "exploit_id": exploit.id,
            "evidence": {"exit_code": 0, "markers": ["proof_obtained"]},
        },
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["vulnerability_id"] == vuln.id
    assert body["phase"] == "initial"
    assert body["status"] in {"validated", "failed", "inconclusive"}

    stored = db.query(Validation).first()
    assert stored is not None
    assert stored.vulnerability_id == vuln.id  # regression check for the NOT NULL bug fixed earlier


def test_get_validation_404_for_missing_id(client):
    response = client.get("/validations/999999")
    assert response.status_code == 404


# ---------------------------------------------------------------------
# Remediation
# ---------------------------------------------------------------------


def test_create_remediation_persists(client, db):
    asset = _seed_asset(db)
    vuln = _seed_vulnerability(db, asset)

    response = client.post(
        "/remediations/",
        json={
            "vulnerability_id": vuln.id,
            "action": "Patch SMBv1 and disable the vulnerable service.",
        },
    )

    assert response.status_code == 200, response.text
    body = response.json()
    # Manual creation via this CRUD endpoint bypasses RemediationEngine's
    # recommend() step (the action was already decided by a human), so it
    # starts at the model's "planned" default rather than "recommended".
    assert body["status"] == "planned"
    assert db.query(Remediation).filter(Remediation.vulnerability_id == vuln.id).count() == 1


def test_list_remediations(client, db):
    asset = _seed_asset(db)
    vuln = _seed_vulnerability(db, asset)
    db.add(Remediation(vulnerability_id=vuln.id, action="Patch it", status="recommended"))
    db.commit()

    response = client.get("/remediations/")

    assert response.status_code == 200
    assert len(response.json()) == 1


# ---------------------------------------------------------------------
# Twins (list/get -- provisioning itself is covered by
# tests/test_twin_provision.py)
# ---------------------------------------------------------------------


def test_list_twins_returns_seeded_rows(client, db):
    db.add(Twin(name="test-twin", provider="TwinGenerator", status="running", ip_address="10.0.0.5"))
    db.commit()

    response = client.get("/twins/")

    assert response.status_code == 200
    body = response.json()
    assert len(body) == 1
    assert body[0]["status"] == "running"


def test_get_twin_404_for_missing_id(client):
    response = client.get("/twins/999999")
    assert response.status_code == 404
