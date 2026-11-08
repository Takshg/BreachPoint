"""Convert the raw CSVs to Parquet once, then load them fast.

Usage:
    uv run python -m src.load          # convert all CSVs (skips ones already done)
    uv run python -m src.load --force  # reconvert everything

    from src.load import load
    vulns = load("vulnerabilities")
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data"
PQ = ROOT / "data" / "parquet"

# Row counts from data/README.md, used as a sanity check.
EXPECTED_ROWS = {
    "vulnerabilities": 401_082,
    "affected_products": 3_155_934,
    "references": 1_360_487,
    "known_exploited": 1_484,
    "exploit_signals": 6_463_734,  # 2024 + 2025 combined
    "weakness_types": 1_374,
    "scoreboard_2026": 72_670,
}

# Only keep the columns we need from the two big files.
KEEP_COLS = {
    "affected_products": ["cve_id", "type", "vendor", "product", "vulnerable"],
    "references": ["cve_id", "url", "domain", "tags"],
}

DATE_COLS = {
    "vulnerabilities": ["published", "last_modified"],
    "known_exploited": ["date_added", "due_date"],
    "scoreboard_2026": ["published"],
}

FLOAT_COLS = {
    "vulnerabilities": [
        "cvss3_score", "cvss3_exploitability_score", "cvss3_impact_score",
        "cvss4_score", "cvss2_score",
    ],
    "exploit_signals": ["epss"],
    "scoreboard_2026": ["epss"],
}

INT_COLS = {
    "vulnerabilities": ["n_references", "n_affected_cpes"],
    "exploit_signals": ["in_kev", "exploitdb", "metasploit", "nuclei", "poc_github"],
    "scoreboard_2026": ["exploitdb", "metasploit", "nuclei", "poc_github"],
}

CATEGORY_COLS = {
    "vulnerabilities": [
        "nvd_status", "assigner", "cvss3_version", "cvss3_severity", "attack_vector",
        "attack_complexity", "privileges_required", "user_interaction", "scope",
        "confidentiality_impact", "integrity_impact", "availability_impact",
        "cvss3_source", "cvss4_severity", "cvss2_severity",
    ],
    "affected_products": ["type", "vendor", "vulnerable"],
    "references": ["domain"],
    "exploit_signals": ["month"],
}


def _read_csv(path: Path, usecols=None) -> pd.DataFrame:
    # Read everything as text first (version strings, IDs), then cast known columns.
    return pd.read_csv(
        path, dtype=str, keep_default_na=False, na_values=[""],
        quotechar='"', usecols=usecols, low_memory=False,
    )


def _cast(name: str, df: pd.DataFrame) -> pd.DataFrame:
    for c in DATE_COLS.get(name, []):
        df[c] = pd.to_datetime(df[c], errors="coerce")
    for c in FLOAT_COLS.get(name, []):
        df[c] = pd.to_numeric(df[c], errors="coerce").astype("float32")
    for c in INT_COLS.get(name, []):
        df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0).astype("int8" if name != "vulnerabilities" else "int32")
    for c in CATEGORY_COLS.get(name, []):
        df[c] = df[c].astype("category")
    return df


def convert(force: bool = False) -> None:
    PQ.mkdir(parents=True, exist_ok=True)
    jobs = {
        "vulnerabilities": ["vulnerabilities.csv"],
        "affected_products": ["affected_products.csv"],
        "references": ["references.csv"],
        "known_exploited": ["known_exploited.csv"],
        "exploit_signals": ["exploit_signals_2024.csv", "exploit_signals_2025.csv"],
        "weakness_types": ["weakness_types.csv"],
        "scoreboard_2026": ["scoreboard_2026.csv"],
    }
    for name, files in jobs.items():
        out = PQ / f"{name}.parquet"
        if out.exists() and not force:
            print(f"skip {name} (exists)")
            continue
        t = time.time()
        df = pd.concat([_read_csv(RAW / f, KEEP_COLS.get(name)) for f in files], ignore_index=True)
        df = _cast(name, df)
        df.to_parquet(out, index=False)
        print(f"wrote {name}: {len(df):,} rows in {time.time() - t:.1f}s")


def load(name: str, columns: list[str] | None = None) -> pd.DataFrame:
    return pd.read_parquet(PQ / f"{name}.parquet", columns=columns)


def check() -> bool:
    ok = True
    for name, n in EXPECTED_ROWS.items():
        t = time.time()
        df = load(name)
        dt = time.time() - t
        good = len(df) == n and dt < 10
        ok &= good
        print(f"{'OK ' if good else 'BAD'} {name:18s} rows={len(df):>10,} expected={n:>10,} load={dt:.2f}s")
    return ok


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--force", action="store_true")
    args = p.parse_args()
    convert(force=args.force)
    sys.exit(0 if check() else 1)
