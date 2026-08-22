from pathlib import Path

import numpy as np
import pandas as pd

from sklearn.calibration import calibration_curve
from sklearn.impute import SimpleImputer
from sklearn.metrics import brier_score_loss
from xgboost import XGBClassifier


DATA_PATH = Path(
    "data/processed/vulnerability_dataset.csv"
)

OUTPUT_PATH = Path(
    "data/processed/calibration_results.csv"
)

FEATURES = [
    "CVSS_SCORE",
    "EPSS_SCORE",
    "EPSS_PERCENTILE",
    "KEV_STATUS",
]

TARGET = "EXPLOIT_AVAILABLE"


def main():

    print("Loading dataset...")

    df = pd.read_csv(DATA_PATH)

    df["PUBLISHED_DATE"] = pd.to_datetime(
        df["PUBLISHED_DATE"]
    )

    # Exact production split
    train = df[
        df["PUBLISHED_DATE"].dt.year <= 2024
    ].copy()

    test = df[
        df["PUBLISHED_DATE"].dt.year >= 2025
    ].copy()

    X_train = train[FEATURES]
    y_train = train[TARGET]

    X_test = test[FEATURES]
    y_test = test[TARGET]

    # Same imputation
    imputer = SimpleImputer(
        strategy="median"
    )

    X_train = imputer.fit_transform(X_train)
    X_test = imputer.transform(X_test)

    # Same class balancing
    positives = y_train.sum()
    negatives = len(y_train) - positives

    scale_pos_weight = negatives / positives

    # Same production model
    model = XGBClassifier(
        n_estimators=400,
        max_depth=5,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        objective="binary:logistic",
        eval_metric="aucpr",
        scale_pos_weight=scale_pos_weight,
        random_state=42,
        n_jobs=-1,
    )

    print("Training model...")

    model.fit(
        X_train,
        y_train
    )

    probabilities = model.predict_proba(
        X_test
    )[:, 1]

    # --------------------------------------------------
    # Brier score
    # --------------------------------------------------

    brier = brier_score_loss(
        y_test,
        probabilities
    )

    print()
    print("=" * 70)
    print("CALIBRATION ANALYSIS")
    print("=" * 70)

    print(
        f"Test samples : {len(y_test):,}"
    )

    print(
        f"Actual positives : {int(y_test.sum()):,}"
    )

    print(
        f"Brier score : {brier:.6f}"
    )

    # --------------------------------------------------
    # Reliability bins
    # --------------------------------------------------

    fraction_positive, mean_predicted = calibration_curve(
        y_test,
        probabilities,
        n_bins=10,
        strategy="quantile"
    )

    results = []

    for i, (predicted, actual) in enumerate(
        zip(mean_predicted, fraction_positive),
        start=1
    ):
        results.append(
            {
                "Bin": i,
                "Mean Predicted Probability": predicted,
                "Observed Positive Rate": actual,
                "Calibration Error": abs(
                    predicted - actual
                ),
            }
        )

    results_df = pd.DataFrame(results)

    print()
    print("RELIABILITY BINS")
    print("-" * 70)

    print(
        results_df.to_string(
            index=False
        )
    )

    print()
    print(
        f"Mean absolute calibration error: "
        f"{results_df['Calibration Error'].mean():.6f}"
    )

    OUTPUT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    results_df.to_csv(
        OUTPUT_PATH,
        index=False
    )

    print()
    print(
        f"Saved: {OUTPUT_PATH}"
    )


if __name__ == "__main__":
    main()