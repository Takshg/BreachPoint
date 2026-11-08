"""Phase 2: build the train / validate / score sets the same way as the benchmark.

For cohort year Y (2024, 2025):
  - vulnerabilities published Jan-Sep of Y
  - snapshot = end of the publish month; June -> end of July (decision C1)
  - drop rows already on KEV at the snapshot
  - label = KEV date_added after the snapshot and on or before Nov 4 of Y
  - EPSS and exploit flags from that snapshot month; missing -> blank EPSS, 0 flags
    (the scoreboard's convention; no missing flag, decision C3)
For 2026: the scoreboard rows as given (label unknown).

Usage: uv run python -m src.cohort
"""
from __future__ import annotations

import pandas as pd

from src.load import PQ, load

OUT = PQ.parent.parent / "outputs"
FLAGS = ["exploitdb", "metasploit", "nuclei", "poc_github"]
COLUMNS = ["cve_id", "published", "cohort_year", "snapshot_month", "snapshot_end", "cutoff",
           "window_days", "epss", *FLAGS, "kev_date_added", "label"]


def snapshot_end(published: pd.Series) -> pd.Series:
    """End of the publish month; June -> end of July (matches the scoreboard)."""
    p = published.dt.to_period("M")
    p = p.where(published.dt.month != 6, p + 1)
    return p.dt.to_timestamp(how="end").dt.normalize()


def cutoff(year: int) -> pd.Timestamp:
    return pd.Timestamp(f"{year}-11-04")


def build_year(year: int, vulns: pd.DataFrame, kev: pd.DataFrame, sig: pd.DataFrame) -> pd.DataFrame:
    c = vulns[(vulns.published.dt.year == year) & (vulns.published.dt.month <= 9)][["cve_id", "published"]].copy()
    c["cohort_year"] = year
    c["snapshot_end"] = snapshot_end(c.published)
    c["snapshot_month"] = c.snapshot_end.dt.strftime("%Y-%m")
    c["cutoff"] = cutoff(year)
    c = c.merge(kev[["cve_id", "date_added"]].rename(columns={"date_added": "kev_date_added"}),
                on="cve_id", how="left")
    c = c[~(c.kev_date_added <= c.snapshot_end)]  # NaN compares False -> kept
    c["label"] = ((c.kev_date_added > c.snapshot_end) & (c.kev_date_added <= c.cutoff)).astype("int8")

    s = sig[sig.month.astype(str).str.startswith(str(year))].drop(columns="in_kev").copy()
    s["month"] = s.month.astype(str)
    c = c.merge(s, left_on=["cve_id", "snapshot_month"], right_on=["cve_id", "month"], how="left").drop(columns="month")
    return _finish(c)


def build_2026(board: pd.DataFrame) -> pd.DataFrame:
    c = board.copy()
    c["cohort_year"] = 2026
    c["snapshot_end"] = pd.PeriodIndex(c.snapshot_month, freq="M").to_timestamp(how="end").normalize()
    c["cutoff"] = cutoff(2026)
    c["kev_date_added"] = pd.NaT
    c["label"] = pd.NA
    return _finish(c)


def _finish(c: pd.DataFrame) -> pd.DataFrame:
    c["window_days"] = (c.cutoff - c.snapshot_end).dt.days.astype("int16")
    c[FLAGS] = c[FLAGS].fillna(0).astype("int8")
    c["epss"] = c.epss.astype("float32")
    c["label"] = c.label.astype("Int8")
    return c[COLUMNS].sort_values(["published", "cve_id"]).reset_index(drop=True)


def build_all() -> dict[str, pd.DataFrame]:
    vulns = load("vulnerabilities", ["cve_id", "published"])
    kev = load("known_exploited", ["cve_id", "date_added"])
    sig = load("exploit_signals")
    board = load("scoreboard_2026")
    return {
        "train_2024": build_year(2024, vulns, kev, sig),
        "val_2025": build_year(2025, vulns, kev, sig),
        "score_2026": build_2026(board),
    }


if __name__ == "__main__":
    OUT.mkdir(exist_ok=True)
    for name, df in build_all().items():
        df.to_parquet(OUT / f"{name}.parquet", index=False)
        pos = df.label.sum() if df.label.notna().any() else "unknown"
        print(f"{name}: {len(df):,} rows, positives={pos}, epss missing={df.epss.isna().mean():.3f}")
