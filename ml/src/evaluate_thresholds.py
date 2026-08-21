import joblib
import pandas as pd

from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
    average_precision_score,
)


DATA_PATH = "data/processed/vulnerability_dataset.csv"
MODEL_PATH = "ml/models/exploitability_xgb.joblib"


def main():

    df = pd.read_csv(DATA_PATH)

    df["PUBLISHED_DATE"] = pd.to_datetime(
        df["PUBLISHED_DATE"]
    )

    test = df[
        df["PUBLISHED_DATE"].dt.year >= 2025
    ].copy()

    artifact = joblib.load(MODEL_PATH)

    model = artifact["model"]
    imputer = artifact["imputer"]
    features = artifact["features"]

    X_test = imputer.transform(
        test[features]
    )

    y_test = test["EXPLOIT_AVAILABLE"]

    probabilities = model.predict_proba(
        X_test
    )[:, 1]

    print("=" * 70)
    print("THRESHOLD ANALYSIS")
    print("=" * 70)

    print(
        f"Test samples: {len(test):,}"
    )

    print(
        f"Actual positives: {y_test.sum():,}"
    )

    print()

    results = []

    for threshold in [
        0.10,
        0.15,
        0.20,
        0.25,
        0.30,
        0.35,
        0.40,
        0.45,
        0.50,
        0.55,
        0.60,
        0.65,
        0.70,
        0.75,
        0.80,
        0.85,
        0.90,
    ]:

        predictions = (
            probabilities >= threshold
        ).astype(int)

        precision = precision_score(
            y_test,
            predictions,
            zero_division=0
        )

        recall = recall_score(
            y_test,
            predictions,
            zero_division=0
        )

        f1 = f1_score(
            y_test,
            predictions,
            zero_division=0
        )

        results.append({
            "threshold": threshold,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "predicted_positive": predictions.sum(),
        })

    result_df = pd.DataFrame(results)

    print(
        result_df.to_string(
            index=False,
            formatters={
                "precision": "{:.4f}".format,
                "recall": "{:.4f}".format,
                "f1": "{:.4f}".format,
            }
        )
    )

    print()

    best = result_df.loc[
        result_df["f1"].idxmax()
    ]

    print("=" * 70)
    print("BEST F1 THRESHOLD")
    print("=" * 70)

    print(best.to_string())


if __name__ == "__main__":
    main()