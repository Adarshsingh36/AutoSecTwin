import gzip
import json
from pathlib import Path

import pandas as pd


NVD_DIR = Path("data/raw/nvd")
OUTPUT = Path("data/processed/nvd.csv")


def get_cvss(metrics):
    """
    Extract the preferred CVSS v3.x score/vector.
    Prefer v3.1, then v3.0.
    """
    for version in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(version, [])
        if entries:
            data = entries[0].get("cvssData", {})
            return (
                data.get("baseScore"),
                data.get("vectorString"),
            )

    return None, None


def get_cwes(problem_types):
    cwes = []

    for problem in problem_types or []:
        for desc in problem.get("descriptions", []):
            value = desc.get("value")

            if value and value.startswith("CWE-"):
                cwes.append(value)

    return ";".join(sorted(set(cwes))) if cwes else None


def get_cpe_products(configurations):
    vendors = []
    products = []
    versions = []

    for config in configurations or []:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                criteria = match.get("criteria", "")

                parts = criteria.split(":")

                # cpe:2.3:a:vendor:product:version:...
                if len(parts) >= 6 and parts[0] == "cpe" and parts[1] == "2.3":
                    vendors.append(parts[3])
                    products.append(parts[4])
                    versions.append(parts[5])

    return (
        ";".join(sorted(set(vendors))) if vendors else None,
        ";".join(sorted(set(products))) if products else None,
        ";".join(sorted(set(versions))) if versions else None,
    )


def parse_file(path):
    print(f"Processing {path.name}...")

    with gzip.open(path, "rt", encoding="utf-8") as f:
        data = json.load(f)

    rows = []

    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})

        cve_id = cve.get("id")

        if not cve_id:
            continue

        cvss_score, cvss_vector = get_cvss(
            cve.get("metrics", {})
        )

        cwe_id = get_cwes(
            cve.get("weaknesses", [])
        )

        vendor, product, version = get_cpe_products(
            cve.get("configurations", [])
        )

        rows.append({
            "CVE_ID": cve_id,
            "CVSS_SCORE": cvss_score,
            "CVSS_VECTOR": cvss_vector,
            "CWE_ID": cwe_id,
            "PUBLISHED_DATE": cve.get("published"),
            "LAST_MODIFIED": cve.get("lastModified"),
            "VENDOR": vendor,
            "PRODUCT": product,
            "VERSION": version,
        })

    return rows


def main():
    files = sorted(
        NVD_DIR.glob("nvdcve-2.0-*.json.gz")
    )

    if not files:
        raise FileNotFoundError(
            f"No NVD feeds found in {NVD_DIR}"
        )

    all_rows = []

    for path in files:
        all_rows.extend(parse_file(path))

    df = pd.DataFrame(all_rows)

    # One CVE should correspond to one row.
    df = df.drop_duplicates(
        subset=["CVE_ID"],
        keep="last"
    )

    OUTPUT.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    df.to_csv(
        OUTPUT,
        index=False
    )

    print()
    print("NVD parsing complete.")
    print(f"Rows: {len(df):,}")
    print(f"Columns: {df.columns.tolist()}")
    print(f"Saved: {OUTPUT}")


if __name__ == "__main__":
    main()