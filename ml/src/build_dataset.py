import re
from pathlib import Path

import pandas as pd


NVD_PATH = Path("data/processed/nvd.csv")
EPSS_PATH = Path("data/raw/epss/epss_scores-2026-08-12.csv")
KEV_PATH = Path("data/raw/kev/known_exploited_vulnerabilities.csv")
EXPLOITDB_PATH = Path("data/raw/exploitdb/files_exploits.csv")

OUTPUT_PATH = Path(
    "data/processed/vulnerability_dataset.csv"
)


def load_nvd():
    print("Loading NVD...")
    df = pd.read_csv(NVD_PATH)

    df["CVE_ID"] = df["CVE_ID"].str.upper().str.strip()

    return df


def load_epss():
    print("Loading EPSS...")
    df = pd.read_csv(
        EPSS_PATH,
        comment="#"
    )

    df = df.rename(
        columns={
            "cve": "CVE_ID",
            "epss": "EPSS_SCORE",
            "percentile": "EPSS_PERCENTILE",
        }
    )

    df["CVE_ID"] = (
        df["CVE_ID"]
        .astype(str)
        .str.upper()
        .str.strip()
    )

    return df[
        [
            "CVE_ID",
            "EPSS_SCORE",
            "EPSS_PERCENTILE",
        ]
    ]


def load_kev():
    print("Loading CISA KEV...")
    df = pd.read_csv(KEV_PATH)

    df = df.rename(
        columns={
            "cveID": "CVE_ID"
        }
    )

    df["CVE_ID"] = (
        df["CVE_ID"]
        .astype(str)
        .str.upper()
        .str.strip()
    )

    # Every CVE appearing in KEV is known to have
    # real-world exploitation evidence.
    df["KEV_STATUS"] = 1

    return df[
        [
            "CVE_ID",
            "KEV_STATUS"
        ]
    ].drop_duplicates("CVE_ID")


def extract_cves(value):
    """
    Extract CVE identifiers from ExploitDB's
    semicolon-separated codes field.
    """

    if pd.isna(value):
        return []

    return re.findall(
        r"CVE-\d{4}-\d{4,7}",
        str(value).upper()
    )


def load_exploitdb():
    print("Loading ExploitDB...")

    df = pd.read_csv(
        EXPLOITDB_PATH,
        low_memory=False
    )

    records = []

    for codes in df["codes"]:
        cves = extract_cves(codes)

        for cve in cves:
            records.append(cve)

    exploit_cves = pd.Series(
        records,
        name="CVE_ID"
    )

    exploit_counts = (
        exploit_cves
        .value_counts()
        .rename("EXPLOIT_COUNT")
        .reset_index()
    )

    exploit_counts = exploit_counts.rename(
        columns={
            "index": "CVE_ID"
        }
    )

    exploit_counts["CVE_ID"] = (
        exploit_counts["CVE_ID"]
        .astype(str)
        .str.upper()
        .str.strip()
    )

    exploit_counts["EXPLOIT_AVAILABLE"] = 1

    return exploit_counts[
        [
            "CVE_ID",
            "EXPLOIT_AVAILABLE",
            "EXPLOIT_COUNT",
        ]
    ]


def main():

    nvd = load_nvd()
    epss = load_epss()
    kev = load_kev()
    exploitdb = load_exploitdb()

    print()
    print("NVD rows:", len(nvd))
    print("EPSS rows:", len(epss))
    print("KEV rows:", len(kev))
    print("ExploitDB CVEs:", len(exploitdb))

    print()
    print("Merging datasets...")

    # Start from NVD because it is our
    # vulnerability universe.
    df = nvd.merge(
        epss,
        on="CVE_ID",
        how="left"
    )

    df = df.merge(
        kev,
        on="CVE_ID",
        how="left"
    )

    df = df.merge(
        exploitdb,
        on="CVE_ID",
        how="left"
    )

    # Missing KEV means the vulnerability
    # is not currently listed in KEV.
    df["KEV_STATUS"] = (
        df["KEV_STATUS"]
        .fillna(0)
        .astype(int)
    )

    # Missing ExploitDB evidence means
    # no matching public exploit was found.
    df["EXPLOIT_AVAILABLE"] = (
        df["EXPLOIT_AVAILABLE"]
        .fillna(0)
        .astype(int)
    )

    df["EXPLOIT_COUNT"] = (
        df["EXPLOIT_COUNT"]
        .fillna(0)
        .astype(int)
    )

    OUTPUT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    df.to_csv(
        OUTPUT_PATH,
        index=False
    )

    print()
    print("=" * 60)
    print("UNIFIED DATASET COMPLETE")
    print("=" * 60)

    print("Rows:", f"{len(df):,}")
    print("Columns:", len(df.columns))
    print()

    print(
        "ExploitDB positive:",
        int(df["EXPLOIT_AVAILABLE"].sum())
    )

    print(
        "KEV positive:",
        int(df["KEV_STATUS"].sum())
    )

    print(
        "EPSS available:",
        int(df["EPSS_SCORE"].notna().sum())
    )

    print()

    print(
        "Saved:",
        OUTPUT_PATH
    )


if __name__ == "__main__":
    main()