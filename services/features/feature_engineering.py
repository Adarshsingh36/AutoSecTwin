from typing import Any

from services.features.encoders import CategoricalEncoder
from services.features.preprocessing import FeaturePreprocessor


class FeatureEngineeringService:
    """Builds ML feature vectors from NVD, EPSS, threat, asset, and service data."""

    def __init__(self) -> None:
        self.encoder = CategoricalEncoder()
        self.preprocessor = FeaturePreprocessor()

    def build_feature_vector(
        self,
        nvd: dict[str, Any] | None = None,
        epss: dict[str, Any] | None = None,
        threat_intel: dict[str, Any] | None = None,
        asset_metadata: dict[str, Any] | None = None,
        service_metadata: dict[str, Any] | None = None,
    ) -> dict[str, float]:
        """Generate a normalized feature vector for exploitability inference."""

        nvd = nvd or {}
        epss = epss or {}
        threat_intel = threat_intel or {}
        asset_metadata = asset_metadata or {}
        service_metadata = service_metadata or {}
        return {
            "cvss": self.preprocessor.normalize(nvd.get("cvss_score"), 10.0),
            "epss": self.preprocessor.normalize(epss.get("epss_score")),
            "kev": self.encoder.encode_bool(bool(threat_intel.get("kev_listed") or nvd.get("kev_listed"))),
            "exploit_count": self.preprocessor.normalize(threat_intel.get("exploit_count"), 20.0),
            "asset_exposure": self.preprocessor.normalize(asset_metadata.get("exposure")),
            "asset_criticality": self.preprocessor.normalize(asset_metadata.get("criticality")),
            "service_privilege": self.preprocessor.normalize(service_metadata.get("privilege_level")),
            "severity": self.encoder.encode_severity(nvd.get("severity")),
        }
