import pandas as pd


# ============================================================
# CONFIGURATION
# ============================================================

INPUT = "data/processed/vulnerability_dataset_vps.csv"
OUTPUT = "data/processed/validation_candidates.csv"

TOP_K = 100

MIN_VPS = 40.0


# ============================================================
# LOAD DATA
# ============================================================

df = pd.read_csv(INPUT, low_memory=False)

print("=" * 60)
print("VALIDATION CANDIDATE SELECTION")
print("=" * 60)

print(f"Input vulnerabilities: {len(df):,}")


# ============================================================
# ELIGIBILITY FILTER
# ============================================================

eligible = df[df["VPS"] >= MIN_VPS].copy()

print(f"Eligible VPS >= {MIN_VPS}: {len(eligible):,}")


# ============================================================
# RANK BY VPS
# ============================================================

eligible = eligible.sort_values(
    by=["VPS", "CVSS_SCORE", "EPSS_SCORE"],
    ascending=[False, False, False]
).reset_index(drop=True)


# ============================================================
# TOP-K SELECTION
# ============================================================

candidates = eligible.head(TOP_K).copy()

candidates.insert(
    0,
    "VALIDATION_RANK",
    range(1, len(candidates) + 1)
)


# ============================================================
# VALIDATION STATUS
# ============================================================

candidates["VALIDATION_STATUS"] = "PENDING"


# ============================================================
# SAVE
# ============================================================

candidates.to_csv(
    OUTPUT,
    index=False
)


# ============================================================
# REPORT
# ============================================================

print()
print("Selection configuration:")
print(f"Minimum VPS: {MIN_VPS}")
print(f"TOP_K:       {TOP_K}")

print()
print("Selected candidates:")
print(f"{len(candidates):,}")

print()
print("Priority distribution:")
print(
    candidates["VPS_PRIORITY"]
    .value_counts()
    .sort_index()
    .to_string()
)

print()
print("VPS statistics:")
print(
    candidates["VPS"]
    .describe()
    .round(3)
    .to_string()
)

print()
print("Top candidates:")
print(
    candidates[
        [
            "VALIDATION_RANK",
            "CVE_ID",
            "VPS",
            "VPS_PRIORITY",
            "CVSS_SCORE",
            "EPSS_SCORE",
            "KEV_STATUS",
            "EXPLOIT_AVAILABLE",
            "EXPLOIT_COUNT",
            "VALIDATION_STATUS",
        ]
    ]
    .head(20)
    .to_string(index=False)
)

print()
print("=" * 60)
print("VALIDATION CANDIDATE DATASET CREATED")
print("=" * 60)
print(f"Saved: {OUTPUT}")