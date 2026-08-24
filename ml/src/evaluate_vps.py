import pandas as pd
from sklearn.metrics import roc_auc_score, average_precision_score


INPUT = "data/processed/vulnerability_dataset_vps.csv"


def main():
    df = (
        pd.read_csv(INPUT, low_memory=False)
        .sort_values("VPS", ascending=False)
        .reset_index(drop=True)
    )

    total_kev = int(df["KEV_STATUS"].sum())
    total_exploit = int(df["EXPLOIT_AVAILABLE"].sum())

    print("=" * 60)
    print("VPS TOP-K EVALUATION")
    print("=" * 60)

    print(f"Total KEV:       {total_kev}")
    print(f"Total ExploitDB: {total_exploit}")
    print()

    print(
        f"{'K':<8}"
        f"{'KEV Captured':<18}"
        f"{'KEV Recall':<15}"
        f"{'Exploit Captured':<20}"
        f"{'Exploit Recall':<15}"
    )

    print("-" * 76)

    for k in [10, 25, 50, 100, 250, 500, 1000, 2000, 5000]:

        top_k = df.head(k)

        kev_captured = int(top_k["KEV_STATUS"].sum())
        exploit_captured = int(top_k["EXPLOIT_AVAILABLE"].sum())

        kev_recall = kev_captured / total_kev if total_kev else 0
        exploit_recall = (
            exploit_captured / total_exploit
            if total_exploit
            else 0
        )

        print(
            f"{k:<8}"
            f"{kev_captured:<18}"
            f"{kev_recall:<15.2%}"
            f"{exploit_captured:<20}"
            f"{exploit_recall:<15.2%}"
        )

    print()
    print("=" * 60)
    print("VPS RANKING METRICS")
    print("=" * 60)

    y_kev = df["KEV_STATUS"].astype(int)
    y_exploit = df["EXPLOIT_AVAILABLE"].astype(int)

    print(
        "KEV ROC-AUC:",
        round(roc_auc_score(y_kev, df["VPS"]), 4)
    )

    print(
        "KEV PR-AUC:",
        round(average_precision_score(y_kev, df["VPS"]), 4)
    )

    print(
        "ExploitDB ROC-AUC:",
        round(roc_auc_score(y_exploit, df["VPS"]), 4)
    )

    print(
        "ExploitDB PR-AUC:",
        round(average_precision_score(y_exploit, df["VPS"]), 4)
    )


if __name__ == "__main__":
    main()