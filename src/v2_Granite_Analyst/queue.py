"""Build the Granite job queue: every description in the three cohorts (~137k), plus history.

History rows (cohort_year = 0): all KEV vulns and a random sample of 25,000 vulns published
2018-2025, so stage 2 can estimate each category's KEV rate from hundreds of KEV examples
instead of the cohorts' 24-45 positives (frozen per cohort year, D13).

Rows are ordered so an interrupted run is still useful: by stage-1 score percentile within each
cohort (v1 logistic core), so the most likely vulns in every cohort are done first.
Also writes a 60-row pilot set (20 positives + 40 random, from 2024-25) for checking the prompt.

Usage: uv run python -m src.v2_Granite_Analyst.queue
"""
from __future__ import annotations

import pandas as pd

from src.cohort import OUT
from src.load import load
from src.v1_LightGBM.train import CORE, LogReg, load_sets

JOB = OUT / "v2_Granite_Analyst"


def main():
    JOB.mkdir(parents=True, exist_ok=True)
    sets = load_sets()
    both = pd.concat([sets[2024], sets[2025]], ignore_index=True)
    stage1 = LogReg(CORE).fit(both, both.label.to_numpy(int))  # used for ordering only
    desc = load("vulnerabilities", ["cve_id", "description"]).set_index("cve_id").description
    parts = []
    for year, df in sets.items():
        d = df[["cve_id", "label"]].copy()
        d["cohort_year"] = year
        d["stage1_pct"] = pd.Series(stage1.predict(df)).rank(ascending=False, pct=True).to_numpy()
        parts.append(d)
    q = pd.concat(parts, ignore_index=True)
    # History rows: all KEV vulns + 25k random vulns published 2018-2025, spread evenly through the queue
    v = load("vulnerabilities", ["cve_id", "published"])
    kev_ids = load("known_exploited", ["cve_id"]).cve_id
    pool = v[v.published.between("2018-01-01", "2025-12-31") & ~v.cve_id.isin(q.cve_id)].cve_id
    hist = pd.concat([kev_ids[~kev_ids.isin(q.cve_id)], pool.sample(25_000, random_state=0)]).drop_duplicates()
    h = pd.DataFrame({"cve_id": hist.to_numpy(), "label": pd.NA, "cohort_year": 0})
    h["stage1_pct"] = (pd.Series(range(len(h))).sample(frac=1, random_state=1).to_numpy() + 0.5) / len(h)
    h.loc[h.cve_id.isin(kev_ids), "stage1_pct"] = 0.0  # KEV examples first: small and essential
    q = pd.concat([q, h], ignore_index=True)
    q["description"] = q.cve_id.map(desc)
    q = q[q.description.notna()]
    q = q.drop_duplicates("cve_id").sort_values(["stage1_pct", "cohort_year"]).reset_index(drop=True)
    q["priority"] = range(len(q))
    q[["cve_id", "cohort_year", "priority", "description"]].to_parquet(JOB / "queue.parquet", index=False)

    lab = q[q.cohort_year.isin([2024, 2025])]
    pilot = pd.concat([lab[lab.label == 1].sample(20, random_state=0),
                       lab[lab.label == 0].sample(40, random_state=0)]).sample(frac=1, random_state=0)
    pilot.assign(priority=range(len(pilot)))[["cve_id", "cohort_year", "priority", "description"]] \
        .to_parquet(JOB / "pilot_queue.parquet", index=False)
    print(f"queue: {len(q):,} rows ({q.cohort_year.value_counts().sort_index().to_dict()}); "
          f"median description {q.description.str.len().median():.0f} chars; pilot: {len(pilot)} rows")


if __name__ == "__main__":
    main()
