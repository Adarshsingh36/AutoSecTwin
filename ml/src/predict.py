import argparse
from pathlib import Path

import joblib
import numpy as np
import pandas as pd


MODEL_PATH = Path("ml/models/exploitability_xgb.joblib")


def parse_args():
    parser = argparse.ArgumentParser(
        description="AutoSecTwin exploitability prediction"
    )

    parser.add_argument(
        "--cvss",
        type=float,
        required=True,
        help="CVSS base score"
    )

    parser.add_argument(
        "--epss",
        type=float,
        required=True,
        help="EPSS score"
    )

    parser.add_argument(
        "--percentile",
        type=float,
        required=True,
        help="EPSS percentile"
    )

    parser.add_argument(
        "--kev",
        type=int,
        choices=[0, 1],
        required=True,
        help="Whether CVE is present in CISA KEV"
    )

    return parser.parse_args()


def get_risk_level(probability):
    if probability >= 0.90:
        return "HIGH"
    elif probability >= 0.50:
        return "MEDIUM"
    else:
        return "LOW"


def get_recommendation(probability):
    if probability >= 0.90:
        return "VALIDATE"
    elif probability >= 0.50:
        return "REVIEW"
    else:
        return "MONITOR"


def main():

    args = parse_args()

    if not 0 <= args.cvss <= 10:
        raise ValueError("CVSS must be between 0 and 10.")

    if not 0 <= args.epss <= 1:
        raise ValueError("EPSS must be between 0 and 1.")

    if not 0 <= args.percentile <= 1:
        raise ValueError(
            "EPSS percentile must be between 0 and 1."
        )

    artifact = joblib.load(MODEL_PATH)

    model = artifact["model"]
    imputer = artifact["imputer"]
    features = artifact["features"]

    input_data = pd.DataFrame([{
        "CVSS_SCORE": args.cvss,
        "EPSS_SCORE": args.epss,
        "EPSS_PERCENTILE": args.percentile,
        "KEV_STATUS": args.kev,
    }])

    X = imputer.transform(
        input_data[features]
    )

    probability = float(
        model.predict_proba(X)[0][1]
    )

    risk = get_risk_level(probability)
    recommendation = get_recommendation(probability)

    print()
    print("=" * 50)
    print("AutoSecTwin Exploitability Prediction")
    print("=" * 50)

    print(
        f"CVSS Score       : {args.cvss:.2f}"
    )

    print(
        f"EPSS Score       : {args.epss:.4f}"
    )

    print(
        f"EPSS Percentile  : {args.percentile:.4f}"
    )

    print(
        f"KEV Status       : {args.kev}"
    )

    print("-" * 50)

    print(
        f"Probability      : {probability:.4f}"
    )

    print(
        f"Probability (%)  : {probability * 100:.2f}%"
    )

    print(
        f"Risk Level       : {risk}"
    )

    print(
        f"Recommendation   : {recommendation}"
    )

    print("=" * 50)
    print()


if __name__ == "__main__":
    main()