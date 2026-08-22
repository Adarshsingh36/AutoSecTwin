from pathlib import Path

import joblib
import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[2]

MODEL_PATH = (
    PROJECT_ROOT
    / "ml"
    / "models"
    / "exploitability_xgb.joblib"
)


class ExploitabilityModel:

    def __init__(self, model_path: Path | None = None):

        path = model_path or MODEL_PATH

        if not path.exists():
            raise FileNotFoundError(
                f"Exploitability model not found: {path}"
            )

        artifact = joblib.load(path)

        required_keys = {
            "model",
            "imputer",
            "features",
        }

        missing = required_keys - artifact.keys()

        if missing:
            raise ValueError(
                f"Invalid exploitability model artifact. "
                f"Missing keys: {sorted(missing)}"
            )

        self.model = artifact["model"]
        self.imputer = artifact["imputer"]
        self.features = artifact["features"]

    def predict(
        self,
        cvss_score,
        epss_score,
        epss_percentile,
        kev_status,
    ):

        data = pd.DataFrame([{
            "CVSS_SCORE": cvss_score,
            "EPSS_SCORE": epss_score,
            "EPSS_PERCENTILE": epss_percentile,
            "KEV_STATUS": kev_status,
        }])

        X = self.imputer.transform(
            data[self.features]
        )

        probability = float(
            self.model.predict_proba(X)[0][1]
        )

        if probability >= 0.90:
            decision = "VALIDATE"
            risk = "HIGH"

        elif probability >= 0.50:
            decision = "REVIEW"
            risk = "MEDIUM"

        else:
            decision = "MONITOR"
            risk = "LOW"

        return {
            "exploitability_probability": round(
                probability,
                4
            ),
            "risk_level": risk,
            "recommendation": decision,
        }