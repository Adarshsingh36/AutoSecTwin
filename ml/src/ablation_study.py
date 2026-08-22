from pathlib import Path

import pandas as pd

from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    average_precision_score,
    roc_auc_score,
)
from xgboost import XGBClassifier


DATA_PATH = Path(
    "data/processed/vulnerability_dataset.csv"
)

OUTPUT_PATH = Path(
    "data/processed/ablation_results.csv"
)


TARGET = "EXPLOIT_AVAILABLE"


FEATURE_SETS = {
    "CVSS only": [
        "CVSS_SCORE",
    ],
    "EPSS only": [
        "EPSS_SCORE",
    ],
    "CVSS + EPSS": [
        "CVSS_SCORE",
        "EPSS_SCORE",
    ],
    "CVSS + EPSS + Percentile": [
        "CVSS_SCORE",
        "EPSS_SCORE",
        "EPSS_PERCENTILE",
    ],
    "All features": [
        "CVSS_SCORE",
        "EPSS_SCORE",
        "EPSS_PERCENTILE",
        "KEV_STATUS",
    ],
}


def main():

    print("Loading dataset...")

    df = pd.read_csv(DATA_PATH)

    df["PUBLISHED_DATE"] = pd.to_datetime(
        df["PUBLISHED_DATE"]
    )

    # --------------------------------------------------
    # EXACT SAME TEMPORAL SPLIT AS PRODUCTION MODEL
    # --------------------------------------------------

    train = df[
        df["PUBLISHED_DATE"].dt.year <= 2024
    ].copy()

    test = df[
        df["PUBLISHED_DATE"].dt.year >= 2025
    ].copy()

    print()
    print("=" * 75)
    print("CONTROLLED FEATURE ABLATION STUDY")
    print("=" * 75)

    print()
    print(
        f"Training rows: {len(train):,}"
    )

    print(
        f"Test rows:     {len(test):,}"
    )

    print(
        f"Training positives: {int(train[TARGET].sum()):,}"
    )

    print(
        f"Test positives:     {int(test[TARGET].sum()):,}"
    )

    results = []

    # --------------------------------------------------
    # SAME MODEL CONFIGURATION AS PRODUCTION
    # --------------------------------------------------

    for name, features in FEATURE_SETS.items():

        print()
        print("-" * 75)
        print(f"Training: {name}")
        print(f"Features: {features}")

        X_train = train[features]
        y_train = train[TARGET]

        X_test = test[features]
        y_test = test[TARGET]

        # --------------------------------------------------
        # SAME IMPUTATION STRATEGY
        # --------------------------------------------------

        imputer = SimpleImputer(
            strategy="median"
        )

        X_train_imp = imputer.fit_transform(
            X_train
        )

        X_test_imp = imputer.transform(
            X_test
        )

        # --------------------------------------------------
        # SAME CLASS WEIGHT CALCULATION
        # --------------------------------------------------

        positives = y_train.sum()
        negatives = len(y_train) - positives

        scale_pos_weight = (
            negatives / positives
        )

        # --------------------------------------------------
        # SAME XGBOOST CONFIGURATION
        # --------------------------------------------------

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

        model.fit(
            X_train_imp,
            y_train
        )

        # --------------------------------------------------
        # PROBABILITY PREDICTIONS
        # --------------------------------------------------

        probabilities = model.predict_proba(
            X_test_imp
        )[:, 1]

        # --------------------------------------------------
        # METRICS
        # --------------------------------------------------

        roc_auc = roc_auc_score(
            y_test,
            probabilities
        )

        pr_auc = average_precision_score(
            y_test,
            probabilities
        )

        results.append(
            {
                "Feature Set": name,
                "Features": ", ".join(features),
                "ROC-AUC": roc_auc,
                "PR-AUC": pr_auc,
                "Train Rows": len(train),
                "Test Rows": len(test),
                "Train Positives": int(y_train.sum()),
                "Test Positives": int(y_test.sum()),
            }
        )

        print(
            f"ROC-AUC: {roc_auc:.4f}"
        )

        print(
            f"PR-AUC : {pr_auc:.4f}"
        )

    # --------------------------------------------------
    # FINAL RESULTS
    # --------------------------------------------------

    results_df = pd.DataFrame(results)

    print()
    print("=" * 75)
    print("CONTROLLED ABLATION RESULTS")
    print("=" * 75)

    print(
        results_df[
            [
                "Feature Set",
                "ROC-AUC",
                "PR-AUC",
                "Train Rows",
                "Test Rows",
                "Train Positives",
                "Test Positives",
            ]
        ].to_string(index=False)
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