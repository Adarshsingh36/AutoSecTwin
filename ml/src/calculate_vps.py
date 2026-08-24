import pandas as pd
import numpy as np

INPUT = "data/processed/vulnerability_dataset.csv"
OUTPUT = "data/processed/vulnerability_dataset_vps.csv"


# ============================================================
# VPS CONFIGURATION
# ============================================================

W_CVSS = 0.25
W_EPSS = 0.35
W_KEV = 0.25
W_EXPLOIT = 0.15


# ============================================================
# LOAD DATA
# ============================================================

df = pd.read_csv(INPUT, low_memory=False)

print("=" * 60)
print("VALIDATION PRIORITY SCORE")
print("=" * 60)

print(f"Input rows: {len(df):,}")


# ============================================================
# NORMALIZE EVIDENCE SIGNALS
# ============================================================

# CVSS: 0-10 -> 0-1
df["CVSS_NORMALIZED"] = (
    df["CVSS_SCORE"]
    .fillna(0)
    .clip(0, 10)
    / 10
)

# EPSS: already 0-1
df["EPSS_NORMALIZED"] = (
    df["EPSS_SCORE"]
    .fillna(0)
    .clip(0, 1)
)

# CISA KEV: binary evidence
df["KEV_SIGNAL"] = (
    df["KEV_STATUS"]
    .fillna(0)
    .clip(0, 1)
)

# ExploitDB:
# logarithmic saturation prevents exploit-count domination
df["EXPLOIT_SIGNAL"] = np.minimum(
    1,
    np.log2(
        1 + df["EXPLOIT_COUNT"].fillna(0)
    )
)


# ============================================================
# VALIDATION PRIORITY SCORE
# ============================================================

df["VPS"] = 100 * (
    W_CVSS * df["CVSS_NORMALIZED"]
    + W_EPSS * df["EPSS_NORMALIZED"]
    + W_KEV * df["KEV_SIGNAL"]
    + W_EXPLOIT * df["EXPLOIT_SIGNAL"]
)


# ============================================================
# PRIORITY CLASS
# ============================================================

def priority_class(score):

    if score >= 80:
        return "CRITICAL"

    elif score >= 60:
        return "HIGH"

    elif score >= 40:
        return "MEDIUM"

    elif score >= 20:
        return "LOW"

    else:
        return "INFORMATIONAL"


df["VPS_PRIORITY"] = df["VPS"].apply(priority_class)


# ============================================================
# SAVE
# ============================================================

df.to_csv(OUTPUT, index=False)


# ============================================================
# REPORT
# ============================================================

print()
print("VPS configuration:")
print(f"CVSS weight:     {W_CVSS}")
print(f"EPSS weight:     {W_EPSS}")
print(f"KEV weight:      {W_KEV}")
print(f"ExploitDB weight:{W_EXPLOIT}")

print()
print("VPS statistics:")
print(
    df["VPS"]
    .describe(
        percentiles=[
            0.50,
            0.75,
            0.90,
            0.95,
            0.99
        ]
    )
    .round(3)
    .to_string()
)

print()
print("Priority distribution:")
print(
    df["VPS_PRIORITY"]
    .value_counts()
    .to_string()
)

print()
print("Mean VPS by evidence class:")

df["EVIDENCE_CLASS"] = (
    df["KEV_STATUS"].astype(str)
    + df["EXPLOIT_AVAILABLE"].astype(str)
)

print(
    df.groupby("EVIDENCE_CLASS")
    .agg(
        ROWS=("CVE_ID", "size"),
        MEAN_VPS=("VPS", "mean"),
        MEDIAN_VPS=("VPS", "median"),
        MAX_VPS=("VPS", "max")
    )
    .round(3)
    .to_string()
)

print()
print("=" * 60)
print("VPS DATASET CREATED")
print("=" * 60)
print(f"Saved: {OUTPUT}")