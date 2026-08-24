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

    df["CVE_ID"] = (
        df["CVE_ID"]
        .astype(str)
        .str.upper()
        .str.strip()
    )

    df["PUBLISHED_DATE"] = pd.to_datetime(
        df["PUBLISHED_DATE"],
        errors="coerce"
    )

    df["LAST_MODIFIED"] = pd.to_datetime(
        df["LAST_MODIFIED"],
        errors="coerce"
    )

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

    # EPSS file is a point-in-time snapshot.
    # The date is stored separately so that the
    # temporal nature of this intelligence is explicit.
    df["EPSS_SNAPSHOT_DATE"] = pd.Timestamp(
        "2026-08-12"
    )

    return df[
        [
            "CVE_ID",
            "EPSS_SCORE",
            "EPSS_PERCENTILE",
            "EPSS_SNAPSHOT_DATE",
        ]
    ]


def load_kev():
    print("Loading CISA KEV...")

    df = pd.read_csv(KEV_PATH)

    df = df.rename(
        columns={
            "cveID": "CVE_ID",
            "dateAdded": "KEV_DATE_ADDED",
        }
    )

    df["CVE_ID"] = (
        df["CVE_ID"]
        .astype(str)
        .str.upper()
        .str.strip()
    )

    df["KEV_DATE_ADDED"] = pd.to_datetime(
        df["KEV_DATE_ADDED"],
        errors="coerce"
    )

    # Presence in KEV means CISA has identified the
    # vulnerability as known exploited.
    df["KEV_STATUS"] = 1

    return df[
        [
            "CVE_ID",
            "KEV_STATUS",
            "KEV_DATE_ADDED",
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

    df["date_published"] = pd.to_datetime(
        df["date_published"],
        errors="coerce"
    )

    records = []

    for _, row in df.iterrows():

        cves = extract_cves(row["codes"])

        for cve in cves:
            records.append(
                {
                    "CVE_ID": cve,
                    "EXPLOIT_DATE": row["date_published"],
                }
            )

    if not records:
        return pd.DataFrame(
            columns=[
                "CVE_ID",
                "EXPLOIT_COUNT",
                "FIRST_EXPLOIT_DATE",
                "LATEST_EXPLOIT_DATE",
            ]
        )

    exploit_records = pd.DataFrame(records)

    exploit_records["CVE_ID"] = (
        exploit_records["CVE_ID"]
        .astype(str)
        .str.upper()
        .str.strip()
    )

    exploit_counts = (
        exploit_records
        .groupby("CVE_ID")
        .agg(
            EXPLOIT_COUNT=("CVE_ID", "size"),
            FIRST_EXPLOIT_DATE=("EXPLOIT_DATE", "min"),
            LATEST_EXPLOIT_DATE=("EXPLOIT_DATE", "max"),
        )
        .reset_index()
    )

    return exploit_counts


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

    # NVD remains the vulnerability universe.
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

    # Missing KEV means the CVE is not present
    # in the downloaded KEV snapshot.
    df["KEV_STATUS"] = (
        df["KEV_STATUS"]
        .fillna(0)
        .astype(int)
    )

    # Missing ExploitDB evidence means no matching
    # ExploitDB record was found.
    df["EXPLOIT_COUNT"] = (
        df["EXPLOIT_COUNT"]
        .fillna(0)
        .astype(int)
    )

    # Derived convenience indicator.
    # This is NOT treated as ground-truth exploitability.
    df["EXPLOIT_AVAILABLE"] = (
        df["EXPLOIT_COUNT"] > 0
    ).astype(int)

    # Explicitly calculate temporal relationships.
    df["KEV_DAYS_AFTER_PUBLICATION"] = (
        df["KEV_DATE_ADDED"] -
        df["PUBLISHED_DATE"]
    ).dt.total_seconds() / 86400

    df["FIRST_EXPLOIT_DAYS_AFTER_PUBLICATION"] = (
        df["FIRST_EXPLOIT_DATE"] -
        df["PUBLISHED_DATE"]
    ).dt.total_seconds() / 86400

    df["LATEST_EXPLOIT_DAYS_AFTER_PUBLICATION"] = (
        df["LATEST_EXPLOIT_DATE"] -
        df["PUBLISHED_DATE"]
    ).dt.total_seconds() / 86400

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

    print(
        "KEV dates available:",
        int(df["KEV_DATE_ADDED"].notna().sum())
    )

    print(
        "Exploit dates available:",
        int(df["FIRST_EXPLOIT_DATE"].notna().sum())
    )

    print()
    print("Saved:", OUTPUT_PATH)


if __name__ == "__main__":
    main()