from pathlib import Path

import joblib
import pandas as pd
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    average_precision_score,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from xgboost import XGBClassifier


DATA_PATH = Path("data/processed/vulnerability_dataset.csv")
OUTPUT_PATH = Path("data/processed/kev_target_results.csv")

FEATURES = [
    "CVSS_SCORE",
    "EPSS_SCORE",
    "EPSS_PERCENTILE",
    "KEV_STATUS",
]


def evaluate_target(df, target_name):
    train = df[df["PUBLISHED_DATE"].dt.year <= 2024].copy()
    test = df[df["PUBLISHED_DATE"].dt.year >= 2025].copy()

    X_train = train[FEATURES]
    X_test = test[FEATURES]

    y_train = train[target_name]
    y_test = test[target_name]

    imputer = SimpleImputer(strategy="median")

    X_train = imputer.fit_transform(X_train)
    X_test = imputer.transform(X_test)

    positives = y_train.sum()
    negatives = len(y_train) - positives

    model = XGBClassifier(
        n_estimators=400,
        max_depth=5,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        objective="binary:logistic",
        eval_metric="aucpr",
        scale_pos_weight=negatives / positives,
        random_state=42,
        n_jobs=-1,
    )

    model.fit(X_train, y_train)

    probabilities = model.predict_proba(X_test)[:, 1]

    predictions = (probabilities >= 0.5).astype(int)

    return {
        "Target": target_name,
        "Train Rows": len(train),
        "Test Rows": len(test),
        "Train Positives": int(y_train.sum()),
        "Test Positives": int(y_test.sum()),
        "ROC-AUC": roc_auc_score(y_test, probabilities),
        "PR-AUC": average_precision_score(y_test, probabilities),
        "Precision": precision_score(
            y_test,
            predictions,
            zero_division=0,
        ),
        "Recall": recall_score(
            y_test,
            predictions,
            zero_division=0,
        ),
        "F1": f1_score(
            y_test,
            predictions,
            zero_division=0,
        ),
    }


def main():
    print("Loading dataset...")

    df = pd.read_csv(DATA_PATH)

    df["PUBLISHED_DATE"] = pd.to_datetime(
        df["PUBLISHED_DATE"]
    )

    # --------------------------------------------------
    # Current production target
    # --------------------------------------------------

    df["CURRENT_TARGET"] = (
        df["EXPLOIT_COUNT"] > 0
    ).astype(int)

    # --------------------------------------------------
    # Experimental KEV-aware target
    # --------------------------------------------------

    df["KEV_AWARE_TARGET"] = (
        (df["EXPLOIT_COUNT"] > 0)
        | (df["KEV_STATUS"] == 1)
    ).astype(int)

    print()
    print("=" * 70)
    print("KEV-AWARE TARGET EXPERIMENT")
    print("=" * 70)

    print()
    print("Current target:")
    print(
        df["CURRENT_TARGET"]
        .value_counts()
        .sort_index()
        .to_string()
    )

    print()
    print("KEV-aware target:")
    print(
        df["KEV_AWARE_TARGET"]
        .value_counts()
        .sort_index()
        .to_string()
    )

    results = []

    print()
    print("=" * 70)
    print("CURRENT TARGET")
    print("=" * 70)

    result = evaluate_target(
        df,
        "CURRENT_TARGET",
    )

    results.append(result)

    for key, value in result.items():
        if key != "Target":
            print(f"{key}: {value}")

    print()
    print("=" * 70)
    print("KEV-AWARE TARGET")
    print("=" * 70)

    result = evaluate_target(
        df,
        "KEV_AWARE_TARGET",
    )

    results.append(result)

    for key, value in result.items():
        if key != "Target":
            print(f"{key}: {value}")

    results_df = pd.DataFrame(results)

    OUTPUT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    results_df.to_csv(
        OUTPUT_PATH,
        index=False,
    )

    print()
    print("=" * 70)
    print("EXPERIMENT COMPLETE")
    print("=" * 70)

    print(results_df.to_string(index=False))

    print()
    print(f"Saved: {OUTPUT_PATH}")


if __name__ == "__main__":
    main()