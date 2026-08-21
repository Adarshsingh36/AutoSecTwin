from pathlib import Path

import joblib
import pandas as pd


DATA_PATH = Path(
    "data/processed/vulnerability_dataset.csv"
)

MODEL_PATH = Path(
    "ml/models/exploitability_xgb.joblib"
)

OUTPUT_PATH = Path(
    "data/processed/real_cve_predictions.csv"
)


def main():

    print("Loading dataset...")
    df = pd.read_csv(DATA_PATH)

    df["PUBLISHED_DATE"] = pd.to_datetime(
        df["PUBLISHED_DATE"]
    )

    print("Loading trained model...")
    artifact = joblib.load(MODEL_PATH)

    model = artifact["model"]
    imputer = artifact["imputer"]
    features = artifact["features"]

    # --------------------------------------------------
    # IMPORTANT:
    # Reproduce the temporal test period used during
    # model evaluation.
    #
    # The model was trained on earlier vulnerabilities
    # and evaluated on 2025-2026 vulnerabilities.
    # --------------------------------------------------

    test = df[
        df["PUBLISHED_DATE"].dt.year >= 2025
    ].copy()

    print()
    print("=" * 70)
    print("TEMPORAL REAL-CVE INFERENCE SAMPLE")
    print("=" * 70)

    print(
        f"Available test rows: {len(test):,}"
    )

    print(
        f"Available positives: "
        f"{test['EXPLOIT_AVAILABLE'].sum():,}"
    )

    print()

    # --------------------------------------------------
    # Representative sampling
    #
    # We sample independently from the actual temporal
    # test population.
    #
    # Selection is based ONLY on ground truth, not
    # model predictions.
    # --------------------------------------------------

    positives = (
        test[
            test["EXPLOIT_AVAILABLE"] == 1
        ]
        .sample(
            n=min(
                10,
                len(
                    test[
                        test["EXPLOIT_AVAILABLE"] == 1
                    ]
                )
            ),
            random_state=42
        )
    )

    negatives = (
        test[
            test["EXPLOIT_AVAILABLE"] == 0
        ]
        .sample(
            n=min(
                10,
                len(
                    test[
                        test["EXPLOIT_AVAILABLE"] == 0
                    ]
                )
            ),
            random_state=42
        )
    )

    selected = pd.concat(
        [positives, negatives]
    )

    # Shuffle only for presentation.
    selected = selected.sample(
        frac=1,
        random_state=42
    ).reset_index(drop=True)

    # --------------------------------------------------
    # Model inference
    # --------------------------------------------------

    X = imputer.transform(
        selected[features]
    )

    probabilities = model.predict_proba(
        X
    )[:, 1]

    selected["MODEL_PROBABILITY"] = probabilities

    # Current operational threshold.
    #
    # This is a decision policy, NOT a hardcoded
    # prediction.
    selected["MODEL_DECISION"] = (
        selected["MODEL_PROBABILITY"]
        .apply(
            lambda x:
                "VALIDATE"
                if x >= 0.90
                else (
                    "REVIEW"
                    if x >= 0.50
                    else "MONITOR"
                )
        )
    )

    selected["GROUND_TRUTH"] = (
        selected["EXPLOIT_AVAILABLE"]
    )

    selected["VALIDATION_STATUS"] = (
        "NOT_TESTED"
    )

    # --------------------------------------------------
    # Output
    # --------------------------------------------------

    output = selected[
        [
            "CVE_ID",
            "PUBLISHED_DATE",
            "CVSS_SCORE",
            "EPSS_SCORE",
            "EPSS_PERCENTILE",
            "KEV_STATUS",
            "EXPLOIT_AVAILABLE",
            "EXPLOIT_COUNT",
            "GROUND_TRUTH",
            "MODEL_PROBABILITY",
            "MODEL_DECISION",
            "VALIDATION_STATUS",
        ]
    ].copy()

    output["MODEL_PROBABILITY"] = (
        output["MODEL_PROBABILITY"]
        .round(4)
    )

    OUTPUT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    output.to_csv(
        OUTPUT_PATH,
        index=False
    )

    # --------------------------------------------------
    # Display results
    # --------------------------------------------------

    print(
        f"Sample size: {len(output)}"
    )

    print(
        f"Positive samples: "
        f"{(output.GROUND_TRUTH == 1).sum()}"
    )

    print(
        f"Negative samples: "
        f"{(output.GROUND_TRUTH == 0).sum()}"
    )

    print()
    print(output.to_string(index=False))

    print()
    print(
        f"Saved: {OUTPUT_PATH}"
    )


if __name__ == "__main__":
    main()