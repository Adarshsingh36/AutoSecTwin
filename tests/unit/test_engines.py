from types import SimpleNamespace

import pytest

from services.confidence.fusion import ConfidenceFusionEngine, FusionInputs
from services.exploitability.feature_builder import FeatureEngineeringEngine
from services.exploitability.predictor import ExploitabilityPredictionEngine
from services.revalidation.revalidation_engine import RevalidationEngine
from services.threat_intelligence import ThreatIntelligenceEngine
from services.validation.validation_engine import ValidationEngine


def test_feature_engineering_normalizes_values():
    vuln = SimpleNamespace(
        cvss_score=9.8,
        epss_score=0.72,
        exposure_score=0.8,
        asset_criticality=0.9,
        kev_listed=True,
        severity="CRITICAL",
    )

    features = FeatureEngineeringEngine().build(vuln, threat_intel_score=0.6)

    assert features["cvss"] == pytest.approx(0.98)
    assert features["kev"] == 1.0
    assert all(0.0 <= value <= 1.0 for value in features.values())


def test_exploitability_predictor_heuristic_returns_probability():
    vuln = SimpleNamespace(
        cvss_score=9.8,
        epss_score=0.8,
        exposure_score=0.7,
        asset_criticality=0.9,
        kev_listed=True,
        severity="CRITICAL",
    )

    score = ExploitabilityPredictionEngine(model_path="missing.pkl").predict(vuln, 0.7)

    assert 0.0 <= score <= 1.0
    assert score > 0.5


def test_threat_intelligence_score_uses_external_signals():
    vuln = SimpleNamespace(cvss_score=8.0, epss_score=0.2, kev_listed=False)

    score = ThreatIntelligenceEngine().score(
        vuln,
        {"epss_score": 0.9, "exploit_count": 4, "kev_listed": True, "mitre_attack_techniques": ["T1190"]},
    )

    assert score > 0.7


def test_validation_engine_scores_success_markers():
    status, score, analysis = ValidationEngine().analyze(
        {"exit_code": 0, "markers": ["shell_opened", "proof_obtained"], "stderr": ""}
    )

    assert status == "validated"
    assert score >= 0.7
    assert "marker_hits=2" in analysis


def test_confidence_fusion_normalizes_weights():
    engine = ConfidenceFusionEngine()
    score, weights = engine.fuse(
        FusionInputs(0.9, 0.8, 0.7, 0.6, 0.5),
        {"exploitability_probability": 2, "validation_score": 1},
    )

    assert 0.0 <= score <= 1.0
    assert round(sum(weights.values()), 6) == 1.0


def test_revalidation_engine_inverts_residual_validation():
    status, score, evidence = RevalidationEngine().verify(0.1)

    assert status == "verified"
    assert score == 0.9
    assert evidence["residual_validation_score"] == 0.1
