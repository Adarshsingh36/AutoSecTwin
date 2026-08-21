from pathlib import Path

import joblib
import pandas as pd


MODEL_PATH = Path(
    "ml/models/exploitability_xgb.joblib"
)


class ExploitabilityModel:

    def __init__(self):
        artifact = joblib.load(MODEL_PATH)

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