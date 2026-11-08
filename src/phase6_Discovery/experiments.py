"""Phase 6 discovery experiments that don't need the Granite analyst labels.

exp1  Leakage inflation: core features vs core + leaky NIST columns (plus the "exploited" keyword, C14).
exp3  KEV blind spot: KEV features frozen at Dec 31 of Y-1 vs kept current to each snapshot.
exp4  Vendor-history effect: later-exploited rate by vendor/assigner history vs by CVSS.

These measure effects; they are not used to pick the submitted model.
Usage: uv run python -m src.phase6_Discovery.experiments [exp1 exp3 exp4]
"""
from __future__ import annotations

import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score
from statsmodels.stats.proportion import proportion_confint

from src.cohort import OUT
from src.evaluate import baseline_scores, bootstrap, hits_at_k, paired_bootstrap, scaled_k
from src.features import Builder
from src.v1_LightGBM.train import CORE, LGBM, LogReg, PARAMS, load_sets

PARAMS["num_threads"] = 4  # other jobs are running on this machine
RES = OUT / "phase6_Discovery"
DIRECTIONS = ((2024, 2025), (2025, 2024))
pd.set_option("display.width", 220)


def score_row(y, s, ref, k, **tags):
    lo, hi = bootstrap(y, s, k)
    d, (dl, dh) = paired_bootstrap(y, s, ref, k)
    return {**tags, "K": k, "hits@K": hits_at_k(y, s, k), "95% range": f"{lo:.0f}-{hi:.0f}",
            "diff vs reference": f"{d:+.1f} [{dl:+.0f} to {dh:+.0f}]", "AP": round(average_precision_score(y, s), 4)}


# ---------- exp 1: leakage inflation
LEAK = ["leak_analyzed", "leak_has_cpes", "leak_refs", "leak_cvss_nist", "leak_cvss_any", "leak_has_cwe"]


def add_leak(df):
    df = df.copy()
    df["leak_analyzed"] = df.leak_nvd_status.astype(str).isin(["Analyzed", "Modified"]).astype(int)
    df["leak_has_cpes"] = (df.leak_n_affected_cpes > 0).astype(int)
    df["leak_refs"] = np.log1p(df.leak_n_references)
    df["leak_cvss_nist"] = (df.leak_cvss3_source.astype(str) == "nist").astype(int)
    df["leak_cvss_any"] = df.leak_cvss3_any
    return df


def exp1(sets):
    sets = {y: add_leak(d) for y, d in sets.items()}
    variants = {"core (clean)": CORE, "core + all leaky columns": CORE + LEAK,
                **{f"core + {c}": CORE + [c] for c in LEAK}, "core + kw_exploited": CORE + ["kw_exploited"]}
    rows = []
    for tr, te in DIRECTIONS:
        y = sets[te].label.to_numpy(int)
        k = scaled_k(len(y))
        for cls, names in ((LogReg, list(variants)), (LGBM, ["core (clean)", "core + all leaky columns"])):
            ref = cls(CORE).fit(sets[tr], sets[tr].label.to_numpy(int)).predict(sets[te])
            for n in names:
                s = ref if n == "core (clean)" else cls(variants[n]).fit(sets[tr], sets[tr].label.to_numpy(int)).predict(sets[te])
                rows.append(score_row(y, s, ref, k, model=cls.__name__, variant=n, direction=f"{tr}->{te}"))
    r = pd.DataFrame(rows)
    print("\n=== EXP 1: leakage (reference = same model, clean core)\n" + r.to_string(index=False))
    r.to_csv(RES / "exp1_leakage.csv", index=False)

    # What a leaky model would submit for 2026: the half of 2026 NIST hasn't reviewed disappears
    both = pd.concat([sets[2024], sets[2025]], ignore_index=True)
    yb, s26 = both.label.to_numpy(int), sets[2026]
    out = {}
    for n, cols in (("clean", CORE), ("leaky", CORE + LEAK)):
        p = LogReg(cols).fit(both, yb).predict(s26)
        out[n] = s26.assign(p=p).nlargest(500, "p")
    a, b = set(out["clean"].cve_id), set(out["leaky"].cve_id)
    print(f"\n2026 scoreboard overall: NIST-analysed {s26.leak_analyzed.mean():.0%}, has product list {s26.leak_has_cpes.mean():.0%}")
    for n, t in out.items():
        print(f"2026 top 500 {n}: NIST-analysed {t.leak_analyzed.mean():.0%}, has product list {t.leak_has_cpes.mean():.0%}")
    print(f"overlap of clean and leaky top 500: {len(a & b)}")


# ---------- exp 3: KEV blind spot
KEV_COLS = ["assigner_kev_hist", "assigner_kev_rate", "vendor_kev_hist", "vendor_kev_recent", "vendor_kev_rate", "kev_product_named"]


def current_features(builder, df, year):
    """Same rows, KEV features recomputed with KEV known at each row's own snapshot."""
    parts = []
    for end, g in df.groupby("snapshot_end"):
        base = g.drop(columns=[c for c in g.columns if c not in COHORT_COLS])
        parts.append(builder.build(base, year, kev_cutoff=pd.Timestamp(end)))
    return pd.concat(parts).set_index("cve_id").loc[df.cve_id].reset_index()


COHORT_COLS = ["cve_id", "published", "cohort_year", "snapshot_month", "snapshot_end", "cutoff", "window_days",
               "epss", "exploitdb", "metasploit", "nuclei", "poc_github", "kev_date_added", "label"]


def exp3(sets):
    b = Builder()
    cur = {y: current_features(b, sets[y], y) for y in (2024, 2025)}
    for y in cur:
        for c in KEV_COLS:
            print(f"{y} {c}: mean frozen {sets[y][c].mean():.4f}, current {cur[y][c].mean():.4f}, "
                  f"rows changed {(sets[y][c].to_numpy() != cur[y][c].to_numpy()).mean():.0%}")
    rows = []
    for tr, te in DIRECTIONS:
        y = sets[te].label.to_numpy(int)
        k = scaled_k(len(y))
        yt = sets[tr].label.to_numpy(int)
        for cls in (LogReg, LGBM):
            frozen = cls(CORE).fit(sets[tr], yt)
            fresh = cls(CORE).fit(cur[tr], yt)
            ref = frozen.predict(sets[te])
            for n, s in (("A frozen train, frozen test (ours; matches 2026)", ref),
                         ("B current train, current test (what a naive check reports)", fresh.predict(cur[te])),
                         ("C current train, frozen test (what the naive model gets in 2026)", fresh.predict(sets[te]))):
                rows.append(score_row(y, s, ref, k, model=cls.__name__, setup=n, direction=f"{tr}->{te}"))
    r = pd.DataFrame(rows)
    print("\n=== EXP 3: KEV blind spot (reference = A)\n" + r.to_string(index=False))
    r.to_csv(RES / "exp3_blind_spot.csv", index=False)


# ---------- exp 4: vendor-history effect
def rate_table(df, group, name):
    t = df.groupby(group, observed=True).agg(n=("label", "size"), later_exploited=("label", "sum"))
    t["per_10k"] = (t.later_exploited / t.n * 1e4).round(1)
    lo, hi = proportion_confint(t.later_exploited.astype(int), t.n, method="wilson")
    t["95% range per 10k"] = [f"{a * 1e4:.1f}-{b * 1e4:.1f}" for a, b in zip(lo, hi)]
    t["lift"] = (t.later_exploited / t.n / df.label.mean()).round(1)
    print(f"\n{name}\n{t.to_string()}")
    t.to_csv(RES / f"exp4_{name.replace(' ', '_')}.csv")
    return t


def exp4(sets):
    d = pd.concat([sets[2024], sets[2025]], ignore_index=True)
    d["label"] = d.label.astype(int)
    d["vendor_hist"] = pd.cut(d.vendor_kev_hist, [-1, 0, 4, 19, 1e9], labels=["0", "1-4", "5-19", "20+"])
    d["vendor_named"] = np.where(d.vendor_matched > 0, "KEV vendor named", "no KEV vendor named")
    d["cvss_band"] = pd.cut(d.baseline_cvss3, [-1, 6.99, 8.99, 10], labels=["<7", "7-8.9", "9+"]).astype(object).fillna("none")
    d["assigner_q"] = pd.qcut(d.assigner_kev_rate.rank(method="first"), 4, labels=["Q1 low", "Q2", "Q3", "Q4 high"])
    print(f"\n=== EXP 4: {len(d):,} rows, {d.label.sum()} later-exploited, base rate {d.label.mean() * 1e4:.1f} per 10k")
    v = rate_table(d, "vendor_hist", "by vendor KEV count")
    rate_table(d, "assigner_q", "by assigner KEV rate quartile")
    c = rate_table(d, "cvss_band", "by CVSS band")
    rate_table(d, ["cvss_band", "vendor_named"], "by CVSS band and vendor")
    no_flag = d[d.any_flag == 0]
    print(f"\nNo public exploit code: {len(no_flag):,} rows, {no_flag.label.sum()} later-exploited")
    rate_table(no_flag, "vendor_hist", "no exploit code by vendor KEV count")

    fig, ax = plt.subplots(1, 2, figsize=(9, 3.4), sharey=True)
    ax[0].bar(c.index.astype(str), c.per_10k, color="#999999"); ax[0].set_title("By CVSS 3 band")
    ax[1].bar(v.index.astype(str), v.per_10k, color="#4c72b0"); ax[1].set_title("By vendor's past KEV count (frozen)")
    ax[0].set_ylabel("later-exploited per 10k")
    fig.tight_layout(); fig.savefig(OUT / "figures" / "p6_vendor_history.png")


if __name__ == "__main__":
    RES.mkdir(parents=True, exist_ok=True)
    which = sys.argv[1:] or ["exp1", "exp3", "exp4"]
    sets = load_sets()
    for e in which:
        globals()[e](sets)
