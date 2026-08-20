from types import SimpleNamespace

from services.confidence.fusion import ConfidenceFusionEngine, FusionInputs
from services.exploitability.predictor import ExploitabilityPredictionEngine
from services.threat_intelligence import ThreatIntelligenceEngine
from services.validation.validation_engine import ValidationEngine


def test_vulnerability_to_confidence_flow():
    vulnerability = SimpleNamespace(
        cvss_score=9.1,
        epss_score=0.64,
        exposure_score=0.75,
        asset_criticality=0.85,
        kev_listed=True,
        severity="CRITICAL",
    )

    threat_score = ThreatIntelligenceEngine().score(vulnerability, {"exploit_count": 2, "kev_listed": True})
    exploitability = ExploitabilityPredictionEngine(model_path="missing.pkl").predict(vulnerability, threat_score)
    _, validation_score, _ = ValidationEngine().analyze({"exit_code": 0, "markers": ["proof_obtained"]})
    confidence, weights = ConfidenceFusionEngine().fuse(
        FusionInputs(
            exploitability,
            validation_score,
            vulnerability.exposure_score,
            threat_score,
            vulnerability.asset_criticality,
        )
    )

    assert confidence > 0.5
    assert round(sum(weights.values()), 6) == 1.0
