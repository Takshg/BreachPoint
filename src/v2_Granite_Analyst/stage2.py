"""Phase 5 v2, stage 2: add the Granite analyst fields to the v1 core features.

Granite fields per vulnerability: category, internet_facing, pre_auth, attack_type, server_product.

Turning them into features without overfitting 24-45 positives:
- "History lift" for each field value, estimated from KEV history, not from the cohort labels.
  For cohort year Y (frozen, D13): KEV vulns published 2018..Y-1 and added by Dec 31 of Y-1,
  compared with a random sample of all vulns published 2018..Y-1 (history rows in the queue).
  lift = (share of KEV in this group) / (share of all vulns in this group), smoothed; feature = log lift.
  Groups: category, category x pre_auth, attack_type, attack_type x pre_auth.
- yes / unclear / no fields as 1 / 0.5 / 0.

Evaluation as in v1: both directions, paired bootstrap vs the best baseline and vs v1 logistic core.

Usage: uv run python -m src.v2_Granite_Analyst.stage2 [--fields outputs/v2_Granite_Analyst/granite_fields]
"""
from __future__ import annotations

import argparse
import glob
import json
from pathlib import Path

import numpy as np
import pandas as pd

from src.cohort import OUT
from src.evaluate import baseline_scores, bootstrap, hits_at_k, paired_bootstrap, scaled_k
from src.load import load
from src.v1_LightGBM.train import CORE, LGBM, MONOTONE_UP, LogReg, load_sets

JOB = OUT / "v2_Granite_Analyst"
YN = {"yes": 1.0, "unclear": 0.5, "no": 0.0}
GROUPS = {"lift_category": ["category"], "lift_category_preauth": ["category", "pre_auth"],
          "lift_attack": ["attack_type"], "lift_attack_preauth": ["attack_type", "pre_auth"]}
LIFTS = list(GROUPS)
ORDINAL = ["g_internet_facing", "g_pre_auth", "g_server_product"]
V2 = CORE + LIFTS + ORDINAL
SMOOTH = 20


def load_fields(path) -> pd.DataFrame:
    """Granite results from Colab (granite_fields/) and/or the local run (granite_fields_local/)."""
    parts = glob.glob(str(path / "part-*.parquet")) + glob.glob(str(path) + "_local/part-*.parquet")
    f = pd.concat([pd.read_parquet(p) for p in parts], ignore_index=True)
    f = f[f.ok].drop_duplicates("cve_id", keep="last")
    return f.set_index("cve_id")


def history_lifts(fields: pd.DataFrame, year: int) -> dict[str, pd.Series]:
    """Log lift of each group value: KEV (published 2018..Y-1, added <= Dec 31 Y-1) vs random history sample."""
    cut = pd.Timestamp(f"{year - 1}-12-31")
    v = load("vulnerabilities", ["cve_id", "published"]).set_index("cve_id").published
    kev = load("known_exploited", ["cve_id", "date_added"]).set_index("cve_id").date_added
    q = pd.read_parquet(JOB / "queue.parquet", columns=["cve_id", "cohort_year"]).set_index("cve_id").cohort_year
    f = fields.join(v.rename("published"), how="left")
    in_window = f.published.between("2018-01-01", cut)
    kev_rows = f[in_window & f.index.isin(kev[kev <= cut].index)]
    background = f[in_window & (q.reindex(f.index) == 0) & ~f.index.isin(kev.index)]
    out = {}
    for name, cols in GROUPS.items():
        kc = kev_rows.groupby(cols).size()
        bc = background.groupby(cols).size()
        idx = kc.index.union(bc.index)
        kc, bc = kc.reindex(idx, fill_value=0), bc.reindex(idx, fill_value=0)
        p_bg = (bc + 1) / (bc.sum() + len(idx))
        p_kev = (kc + SMOOTH * p_bg) / (kc.sum() + SMOOTH)
        out[name] = np.log(p_kev / p_bg)
    return out


def add_granite(df: pd.DataFrame, fields: pd.DataFrame, year: int) -> pd.DataFrame:
    df = df.copy()
    g = fields.reindex(df.cve_id)
    g.index = df.index
    for c in ("category", "attack_type", "internet_facing", "pre_auth", "server_product"):
        df[f"g_{c}"] = g[c]
    for c in ("internet_facing", "pre_auth", "server_product"):
        df[f"g_{c}"] = g[c].map(YN)
    lifts = history_lifts(fields, year)
    for name, cols in GROUPS.items():
        key = pd.MultiIndex.from_frame(g[cols]) if len(cols) > 1 else pd.Index(g[cols[0]])
        df[name] = lifts[name].reindex(key).to_numpy()
    df["granite_coverage"] = g.category.notna().astype("int8")
    return df


class LogRegV2(LogReg):
    def _X(self, df):
        X = super()._X(df)
        return X.fillna(0)  # missing Granite fields -> neutral (log lift 0, ordinal 0)


def evaluate(make, train, test, ref_scores, label):
    m = make().fit(train, train.label.to_numpy(int))
    s = m.predict(test)
    y = test.label.to_numpy(int)
    k = scaled_k(len(test))
    base = baseline_scores(test)["Exploit code, then EPSS"]
    lo, hi = bootstrap(y, s, k)
    d, (dlo, dhi) = paired_bootstrap(y, s, base, k)
    dv, (dvlo, dvhi) = paired_bootstrap(y, s, ref_scores, k)
    return {"model": label[0], "direction": label[1], "K": k, "hits@K": hits_at_k(y, s, k),
            "95% CI": f"[{lo:.0f}-{hi:.0f}]", "baseline": hits_at_k(y, base, k),
            "vs baseline": f"{d:+.1f} [{dlo:+.0f} to {dhi:+.0f}]",
            "v1 logistic": hits_at_k(y, ref_scores, k), "vs v1": f"{dv:+.1f} [{dvlo:+.0f} to {dvhi:+.0f}]",
            "hits@500": hits_at_k(y, s, 500)}, m, s


def main(fields_dir):
    fields = load_fields(fields_dir)
    sets = load_sets()
    for y in sets:
        sets[y] = add_granite(sets[y], fields, y)
        print(f"{y}: Granite coverage {sets[y].granite_coverage.mean():.1%}")

    # Phase 6 #2: later-exploited rate by Granite field (2024 + 2025 cohorts)
    both = pd.concat([sets[2024], sets[2025]], ignore_index=True)
    for c in ("g_category", "g_attack_type"):
        t = both.groupby(c).agg(n=("label", "size"), later_exploited=("label", "sum"))
        t["per_10k"] = (t.later_exploited / t.n * 1e4).round(1)
        print(f"\n{c}:\n{t.sort_values('per_10k', ascending=False).to_string()}")
        t.to_csv(JOB / f"rate_by_{c}.csv")

    models = {"v2 logistic": lambda: LogRegV2(V2),
              "v2 LightGBM": lambda: LGBM(V2)}
    rows = []
    for tr, te in ((2024, 2025), (2025, 2024)):
        ref = LogReg(CORE).fit(sets[tr], sets[tr].label.to_numpy(int)).predict(sets[te])
        for name, make in models.items():
            rows.append(evaluate(make, sets[tr], sets[te], ref, (name, f"{tr} -> {te}"))[0])
    res = pd.DataFrame(rows)
    pd.set_option("display.width", 240)
    print("\n" + res.to_string(index=False))
    res.to_csv(JOB / "results.csv", index=False)

    # Final: train on 2024 + 2025, score 2026
    s26 = sets[2026]
    for name, fname in (("v2 logistic", "logreg_v2"), ("v2 LightGBM", "lgbm_v2")):
        m = models[name]().fit(both, both.label.to_numpy(int))
        sc = pd.DataFrame({"cve_id": s26.cve_id, "score": m.predict(s26)})
        sc["rank"] = sc.score.rank(ascending=False, method="first").astype(int)
        sc.sort_values("rank").to_parquet(JOB / f"scores_2026_{fname}.parquet", index=False)
        sc.sort_values("rank").head(500)[["cve_id"]].to_csv(JOB / f"top500_{fname}.csv", index=False)
    json.dump({"features": V2, "smooth": SMOOTH}, open(JOB / "config.json", "w"), indent=1)


if __name__ == "__main__":
    MONOTONE_UP.update(LIFTS)  # a riskier group per KEV history never lowers the score
    p = argparse.ArgumentParser()
    p.add_argument("--fields", default=str(JOB / "granite_fields"))
    main(Path(p.parse_args().fields))
