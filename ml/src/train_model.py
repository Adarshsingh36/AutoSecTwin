from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    average_precision_score,
    classification_report,
    confusion_matrix,
    precision_recall_curve,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier


DATA_PATH = Path(
    "data/processed/vulnerability_dataset.csv"
)

MODEL_PATH = Path(
    "ml/models/exploitability_xgb.joblib"
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

    # --------------------------------------------------
    # Time-aware split
    # --------------------------------------------------

    train = df[
        df["PUBLISHED_DATE"].dt.year <= 2024
    ].copy()

    test = df[
        df["PUBLISHED_DATE"].dt.year >= 2025
    ].copy()

    print()
    print("=" * 60)
    print("TIME-AWARE SPLIT")
    print("=" * 60)

    print(
        f"Training rows: {len(train):,}"
    )

    print(
        f"Test rows:     {len(test):,}"
    )

    print()

    print(
        "Training positives:",
        int(train[TARGET].sum())
    )

    print(
        "Test positives:",
        int(test[TARGET].sum())
    )

    # --------------------------------------------------
    # Features / target
    # --------------------------------------------------

    X_train = train[FEATURES]
    y_train = train[TARGET]

    X_test = test[FEATURES]
    y_test = test[TARGET]

    # --------------------------------------------------
    # Handle missing values
    # --------------------------------------------------

    # Median imputation keeps the model pipeline
    # reproducible and avoids dropping thousands of CVEs.

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
    # Class imbalance
    # --------------------------------------------------

    positives = y_train.sum()
    negatives = len(y_train) - positives

    scale_pos_weight = negatives / positives

    print()
    print(
        f"scale_pos_weight: "
        f"{scale_pos_weight:.2f}"
    )

    # --------------------------------------------------
    # XGBoost
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

    print()
    print("Training XGBoost...")

    model.fit(
        X_train_imp,
        y_train
    )

    # --------------------------------------------------
    # Predictions
    # --------------------------------------------------

    probabilities = model.predict_proba(
        X_test_imp
    )[:, 1]

    predictions = (
        probabilities >= 0.5
    ).astype(int)

    # --------------------------------------------------
    # Metrics
    # --------------------------------------------------

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

    roc_auc = roc_auc_score(
        y_test,
        probabilities
    )

    pr_auc = average_precision_score(
        y_test,
        probabilities
    )

    print()
    print("=" * 60)
    print("MODEL RESULTS")
    print("=" * 60)

    print(
        f"Precision : {precision:.4f}"
    )

    print(
        f"Recall    : {recall:.4f}"
    )

    print(
        f"F1        : {f1:.4f}"
    )

    print(
        f"ROC-AUC   : {roc_auc:.4f}"
    )

    print(
        f"PR-AUC    : {pr_auc:.4f}"
    )

    print()
    print("Classification report:")
    print(
        classification_report(
            y_test,
            predictions,
            digits=4,
            zero_division=0
        )
    )

    print("Confusion matrix:")
    print(
        confusion_matrix(
            y_test,
            predictions
        )
    )

    # --------------------------------------------------
    # Feature importance
    # --------------------------------------------------

    importance = pd.Series(
        model.feature_importances_,
        index=FEATURES
    ).sort_values(
        ascending=False
    )

    print()
    print("Feature importance:")
    print(
        importance.to_string()
    )

    # --------------------------------------------------
    # Save model + imputer together
    # --------------------------------------------------

    MODEL_PATH.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    artifact = {
        "model": model,
        "imputer": imputer,
        "features": FEATURES,
        "target": TARGET,
        "train_years": "2020-2024",
        "test_years": "2025-2026",
    }

    joblib.dump(
        artifact,
        MODEL_PATH
    )

    print()
    print(
        f"Saved model: {MODEL_PATH}"
    )


if __name__ == "__main__":
    main()