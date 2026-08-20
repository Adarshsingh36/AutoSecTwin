from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import pytest

from database.base import Base
from database.models import *  # noqa: F403
from services.confidence.fusion import ConfidenceFusionEngine, FusionInputs
from services.features import FeatureEngineeringService
from services.legacy import LegacyProfiler
from services.trust import PredictionComparison, TrustService


def session_factory():
    """Create an isolated in-memory database session for service tests."""

    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def test_feature_engineering_combines_external_and_asset_signals():
    features = FeatureEngineeringService().build_feature_vector(
        nvd={"cvss_score": 9.8, "severity": "CRITICAL", "kev_listed": True},
        epss={"epss_score": 0.8},
        threat_intel={"exploit_count": 4},
        asset_metadata={"exposure": 0.7, "criticality": 0.9},
        service_metadata={"privilege_level": 0.5},
    )

    assert features["cvss"] == pytest.approx(0.98)
    assert features["severity"] == 1.0
    assert all(0.0 <= value <= 1.0 for value in features.values())


def test_confidence_breakdown_uses_new_signals_without_cvss():
    breakdown = ConfidenceFusionEngine().generate_confidence_breakdown(
        FusionInputs(
            classifier_uncertainty=0.1,
            twin_exploit_success_rate=0.8,
            network_exposure=0.7,
            historical_ai_agreement=0.9,
            legacy_penalty=0.2,
        )
    )

    assert breakdown.confidence > 0.6
    assert "classifier_certainty" in breakdown.components
    assert "Confidence=" in breakdown.explanation


def test_trust_service_logs_hallucination_and_metrics():
    db = session_factory()

    result = TrustService(db).compare_prediction(
        PredictionComparison(prediction_score=0.95, validation_score=0.05, metadata={"source": "unit"})
    )
    metrics = TrustService(db).get_trust_metrics()

    assert result.hallucination is True
    assert metrics["hallucinations"] == 1
    assert metrics["total_comparisons"] == 1


def test_legacy_profiler_routes_eol_software_to_specialist_queue():
    db = session_factory()

    profile = LegacyProfiler(db).profile_system(
        {"vendor": "microsoft", "product": "windows 7", "version": "6.1"}
    )

    assert profile.eol is True
    assert profile.legacy_penalty >= 0.35
    assert profile.route_to_specialist is True
