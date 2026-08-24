from pathlib import Path

import joblib
import pandas as pd
from sklearn.impute import SimpleImputer


DATA_PATH = Path("data/processed/vulnerability_dataset.csv")
MODEL_PATH = Path("ml/models/exploitability_xgb.joblib")
OUTPUT_PATH = Path("data/processed/error_analysis.csv")


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

    df["PUBLISHED_DATE"] = pd.to_datetime(df["PUBLISHED_DATE"])

    # Same temporal split used during model training/evaluation
    test = df[
        df["PUBLISHED_DATE"].dt.year >= 2025
    ].copy()

    print()
    print("=" * 70)
    print("MODEL ERROR ANALYSIS")
    print("=" * 70)

    print(f"Test samples:     {len(test):,}")
    print(f"Actual positives: {int(test[TARGET].sum()):,}")

    # --------------------------------------------------
    # Load trained artifact
    # --------------------------------------------------

    artifact = joblib.load(MODEL_PATH)

    model = artifact["model"]
    imputer = artifact["imputer"]

    # --------------------------------------------------
    # Generate predictions
    # --------------------------------------------------

    X_test = test[FEATURES]

    X_test_imp = imputer.transform(X_test)

    probabilities = model.predict_proba(
        X_test_imp
    )[:, 1]

    test["MODEL_PROBABILITY"] = probabilities

    # --------------------------------------------------
    # Error analysis at selected thresholds
    # --------------------------------------------------

    thresholds = [
        0.30,
        0.50,
        0.70,
        0.80,
        0.90,
    ]

    for threshold in thresholds:

        predictions = (
            probabilities >= threshold
        ).astype(int)

        test[f"PRED_{threshold:.2f}"] = predictions

        fp = (
            (test[TARGET] == 0)
            & (predictions == 1)
        ).sum()

        fn = (
            (test[TARGET] == 1)
            & (predictions == 0)
        ).sum()

        tp = (
            (test[TARGET] == 1)
            & (predictions == 1)
        ).sum()

        tn = (
            (test[TARGET] == 0)
            & (predictions == 0)
        ).sum()

        print()
        print("-" * 70)
        print(f"THRESHOLD: {threshold:.2f}")
        print("-" * 70)

        print(f"True positives : {tp:,}")
        print(f"False positives: {fp:,}")
        print(f"True negatives : {tn:,}")
        print(f"False negatives: {fn:,}")

    # --------------------------------------------------
    # Detailed errors at 0.90
    # --------------------------------------------------

    threshold = 0.90

    predictions = (
        probabilities >= threshold
    ).astype(int)

    false_positives = test[
        (test[TARGET] == 0)
        & (predictions == 1)
    ].copy()

    false_negatives = test[
        (test[TARGET] == 1)
        & (predictions == 0)
    ].copy()

    print()
    print("=" * 70)
    print("FALSE NEGATIVES @ 0.90")
    print("=" * 70)

    fn_columns = [
        "CVE_ID",
        "PUBLISHED_DATE",
        "CVSS_SCORE",
        "EPSS_SCORE",
        "EPSS_PERCENTILE",
        "KEV_STATUS",
        "MODEL_PROBABILITY",
        TARGET,
    ]

    print(
        false_negatives[
            fn_columns
        ]
        .sort_values(
            "MODEL_PROBABILITY",
            ascending=False
        )
        .head(30)
        .to_string(index=False)
    )

    print()
    print("=" * 70)
    print("FALSE POSITIVES @ 0.90")
    print("=" * 70)

    print(
        false_positives[
            fn_columns
        ]
        .sort_values(
            "MODEL_PROBABILITY",
            ascending=False
        )
        .head(30)
        .to_string(index=False)
    )

    # --------------------------------------------------
    # Save all error-analysis records
    # --------------------------------------------------

    test["ERROR_TYPE_0.90"] = "TRUE_NEGATIVE"

    test.loc[
        (test[TARGET] == 1)
        & (predictions == 1),
        "ERROR_TYPE_0.90"
    ] = "TRUE_POSITIVE"

    test.loc[
        (test[TARGET] == 0)
        & (predictions == 1),
        "ERROR_TYPE_0.90"
    ] = "FALSE_POSITIVE"

    test.loc[
        (test[TARGET] == 1)
        & (predictions == 0),
        "ERROR_TYPE_0.90"
    ] = "FALSE_NEGATIVE"

    OUTPUT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    test.to_csv(
        OUTPUT_PATH,
        index=False
    )

    print()
    print("=" * 70)
    print("ERROR ANALYSIS COMPLETE")
    print("=" * 70)

    print(
        f"Saved: {OUTPUT_PATH}"
    )


if __name__ == "__main__":
    main()