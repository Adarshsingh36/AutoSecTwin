from types import SimpleNamespace

import pytest

from services.confidence.fusion import ConfidenceFusionEngine, FusionInputs
from services.exploitability.feature_builder import FeatureEngineeringEngine
from services.exploitability.predictor import ExploitabilityPredictionEngine
from services.revalidation.revalidation_engine import RevalidationEngine
from services.threat_intelligence import ThreatIntelligenceEngine
from services.validation.validation_engine import ValidationEngine


def test_feature_engineering_builds_model_feature_set():
    vuln = SimpleNamespace(
        cvss_score=9.8,
        epss_score=0.72,
        kev_listed=True,
        metadata_json={"epss_percentile": 0.95},
    )

    features = FeatureEngineeringEngine().build(vuln)

    assert features["CVSS_SCORE"] == pytest.approx(9.8)
    assert features["EPSS_SCORE"] == pytest.approx(0.72)
    assert features["EPSS_PERCENTILE"] == pytest.approx(0.95)
    assert features["KEV_STATUS"] == 1.0


def test_feature_engineering_preserves_missing_values_as_nan():
    import math

    vuln = SimpleNamespace(cvss_score=None, epss_score=None, kev_listed=False, metadata_json=None)

    features = FeatureEngineeringEngine().build(vuln)

    assert math.isnan(features["CVSS_SCORE"])
    assert math.isnan(features["EPSS_PERCENTILE"])
    assert features["KEV_STATUS"] == 0.0


def test_exploitability_predictor_uses_trained_model():
    """No heuristic fallback: the predictor must use the trained XGBoost
    artifact shipped in the repo (ml/models/exploitability_xgb.joblib)."""

    vuln = SimpleNamespace(
        cvss_score=9.8,
        epss_score=0.8,
        kev_listed=True,
        metadata_json={"epss_percentile": 0.95},
    )

    score = ExploitabilityPredictionEngine().predict(vuln)

    assert 0.0 <= score <= 1.0


def test_exploitability_predictor_propagates_model_failure():
    """Model failures must be raised, not silently papered over with a fake
    heuristic score -- the orchestration layer is responsible for handling
    the failure cleanly (see ClosedLoopOrchestrator._predict_exploitability).
    """

    with pytest.raises(FileNotFoundError):
        ExploitabilityPredictionEngine(model_path="missing.joblib")


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
