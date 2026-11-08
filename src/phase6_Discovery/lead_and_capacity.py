"""Phase 6 experiments 5-7: where severity misses, early warning, patch-capacity curve.

Model = v1 logistic core, out-of-year scores only (fit 2024 -> score 2025; fit 2025 -> score 2024).
"CVSS first" uses `baseline_cvss3`: the score as given in vulnerabilities.csv, as the README baseline
does. It includes NIST-added scores, so it is a benchmark, never a model feature.

exp5  Later-exploited vulns outside the top K of CVSS first AND EPSS first, inside the model's top K.
exp6  Lead time: model in its top K at the snapshot vs the first month-end EPSS >= 0.1 / 0.5 before listing.
exp7  A team fixes N new vulns per snapshot month: later-exploited caught by each ranking.

Usage: uv run python -m src.phase6_Discovery.lead_and_capacity
"""
from __future__ import annotations

import os

for v in ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "VECLIB_MAXIMUM_CONCURRENT_THREADS", "MKL_NUM_THREADS"):
    os.environ[v] = "2"  # several jobs share this machine

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from src.cohort import OUT
from src.evaluate import SEED, baseline_scores, rank_order, scaled_k
from src.load import PQ, load
from src.v1_LightGBM.train import CORE, LogReg, load_sets

RES = OUT / "phase6_Discovery"
DIRECTIONS = {2025: 2024, 2024: 2025}  # test year -> training year
THRESHOLDS = (0.1, 0.5)
CAPACITIES = [25, 50, 100, 200, 500]
N_BOOT = 1000
METHODS = ["Model (v1 logistic)", "Exploit code, then EPSS", "EPSS first", "CVSS 3 first"]
COLORS = dict(zip(METHODS, ["#2a78d6", "#eb6834", "#1baf7a", "#eda100"]))  # default palette, slots 1-4
SAFE_TRAITS = ["any_flag", "poc_github", "nuclei", "kev_product_named", "kw_rce", "kw_cmd_injection", "kw_auth_bypass",
               "kw_unauth", "kw_sqli", "kw_path_traversal", "kw_file_upload", "kw_deserialization", "kw_edge"]
pd.set_option("display.width", 240)


def scored_sets() -> dict[int, tuple[pd.DataFrame, dict[str, np.ndarray]]]:
    sets = load_sets()
    out = {}
    for te, tr in DIRECTIONS.items():
        df = sets[te].reset_index(drop=True)
        m = LogReg(CORE).fit(sets[tr], sets[tr].label.to_numpy(int))
        out[te] = (df, {"Model (v1 logistic)": m.predict(df), **baseline_scores(df)})
    return out


def ranks(score: np.ndarray) -> np.ndarray:
    r = np.empty(len(score), dtype=np.int64)
    r[rank_order(score)] = np.arange(1, len(score) + 1)
    return r


# ---------- exp 5
def exp5(scored):
    kev = load("known_exploited", ["cve_id", "vendor", "product"]).set_index("cve_id")
    listed, summary, traits = [], [], []
    for year, (df, sc) in scored.items():
        k = scaled_k(len(df))
        r = {m: ranks(s) for m, s in sc.items()}
        y = df.label.to_numpy(int) == 1
        rescued = y & (r["Model (v1 logistic)"] <= k) & (r["CVSS 3 first"] > k) & (r["EPSS first"] > k)
        also_code = rescued & (r["Exploit code, then EPSS"] <= k)
        summary.append({"year": year, "K": k, "later_exploited": int(y.sum()), "model_hits": int((y & (r["Model (v1 logistic)"] <= k)).sum()),
                        "outside_CVSS_and_EPSS_top_K_inside_model": int(rescued.sum()),
                        "of_those_also_in_exploit_code_baseline_top_K": int(also_code.sum()),
                        "model_only_vs_all_three_baselines": int((rescued & ~also_code).sum())})
        t = df.loc[rescued, ["cve_id", "baseline_cvss3", "epss", "exploitdb", "metasploit", "nuclei", "poc_github",
                             "vendor_kev_hist", "assigner_kev_rate"]].copy()
        t.insert(1, "year", year)
        t.insert(2, "kev_vendor", t.cve_id.map(kev.vendor))
        t.insert(3, "kev_product", t.cve_id.map(kev["product"]))
        for m, col in (("Model (v1 logistic)", "rank_model"), ("CVSS 3 first", "rank_cvss"), ("EPSS first", "rank_epss"),
                       ("Exploit code, then EPSS", "rank_exploit_code")):
            t[col] = r[m][rescued]
        listed.append(t)
        d = df.assign(group=np.select([rescued, y], ["rescued", "other later-exploited"], "not exploited"))
        d["has_kev_vendor"] = (d.vendor_matched > 0).astype(int)
        d["vendor_kev_5plus"] = (d.vendor_kev_hist >= 5).astype(int)
        traits.append(d[["group", *SAFE_TRAITS, "has_kev_vendor", "vendor_kev_5plus"]].assign(year=year))
    out = pd.concat(listed).sort_values(["year", "rank_model"])
    out.to_csv(RES / "exp5_missed_by_severity.csv", index=False)
    s = pd.DataFrame(summary)
    s.to_csv(RES / "exp5_summary.csv", index=False)
    all_t = pd.concat(traits)
    cols = [*SAFE_TRAITS, "has_kev_vendor", "vendor_kev_5plus"]
    common = all_t.groupby("group")[cols].mean().T.round(2)
    common.loc["n rows"] = all_t.groupby("group").size()
    common.to_csv(RES / "exp5_common_traits.csv")
    print("\n=== EXP 5\n" + s.to_string(index=False))
    print("\n" + out.to_string(index=False))
    print("\nShare with each trait (safe columns, both years):\n" + common.to_string())


# ---------- exp 6
def month_end(m: pd.Series) -> pd.Series:
    return pd.PeriodIndex(m.astype(str), freq="M").to_timestamp(how="end").normalize()


def exp6(scored):
    high = pd.read_parquet(PQ / "exploit_signals.parquet", columns=["month", "cve_id", "epss"], filters=[("epss", ">=", min(THRESHOLDS))])
    high["month_end"] = month_end(high.month)
    rows, summary = [], []
    for year, (df, sc) in scored.items():
        k, cutoff = scaled_k(len(df)), pd.Timestamp(f"{year}-11-04")
        r = ranks(sc["Model (v1 logistic)"])
        h = high[high.cve_id.isin(df.cve_id) & (high.month_end <= cutoff)]
        pos = df.assign(rank_model=r)[df.label == 1]
        row = pos[["cve_id", "snapshot_end", "kev_date_added", "rank_model"]].assign(year=year)
        row["model_flagged"] = row.rank_model <= k
        row["model_lead_days"] = (row.kev_date_added - row.snapshot_end).dt.days.where(row.model_flagged)
        added = pos.set_index("cve_id").kev_date_added
        for t in THRESHOLDS:
            hh = h[h.epss >= t]
            first = hh[hh.month_end < hh.cve_id.map(added)].groupby("cve_id").month_end.min()
            row[f"epss_{t}_first_month_end"] = row.cve_id.map(first)
            row[f"epss_{t}_lead_days"] = (row.kev_date_added - row[f"epss_{t}_first_month_end"]).dt.days
        rows.append(row)
        methods = [("Model top K at snapshot", row.model_lead_days, k)]
        methods += [(f"EPSS >= {t} at a month-end", row[f"epss_{t}_lead_days"], h[h.epss >= t].cve_id.nunique()) for t in THRESHOLDS]
        for name, lead, alerts in methods:
            w = lead.notna()
            summary.append({"year": year, "method": name, "later_exploited": len(row), "warned": int(w.sum()),
                            "median_lead_days": lead[w].median() if w.any() else np.nan,
                            "cohort_rows_alerted": alerts, "precision": round(w.sum() / alerts, 3) if alerts else np.nan})
    pd.concat(rows).to_csv(RES / "exp6_early_warning.csv", index=False)
    s = pd.DataFrame(summary)
    s.to_csv(RES / "exp6_summary.csv", index=False)
    print("\n=== EXP 6\n" + s.to_string(index=False))


# ---------- exp 7
def monthly_orders(df, sc):
    """For each method and snapshot month: row positions best to worst, plus each row's within-month rank."""
    groups = {m: np.asarray(ix) for m, ix in df.groupby("snapshot_month").indices.items()}
    pos_rank = {}
    for name, s in sc.items():
        pr = np.empty(len(df), dtype=np.int64)
        for ix in groups.values():
            pr[ix[rank_order(s[ix])]] = np.arange(len(ix))
        pos_rank[name] = pr
    return groups, pos_rank


def caught(y, groups_idx, pr, caps):
    """Later-exploited in each month's top N, for each N, given row positions per month."""
    out = np.zeros(len(caps), dtype=np.int64)
    for ix in groups_idx:
        hit = y[ix[np.argsort(pr[ix], kind="stable")]].cumsum()
        out += hit[np.minimum(caps, len(hit)) - 1]
    return out


def exp7(scored):
    caps = np.array(CAPACITIES)
    rows, curves = [], {}
    rng = np.random.default_rng(SEED)
    for year, (df, sc) in scored.items():
        y = df.label.to_numpy(int)
        groups, pr = monthly_orders(df, sc)
        ix_all = list(groups.values())
        point = {m: caught(y, ix_all, pr[m], caps) for m in METHODS}
        boot = {m: np.empty((N_BOOT, len(caps)), dtype=np.int64) for m in METHODS}
        for b in range(N_BOOT):
            resample = [ix[rng.integers(0, len(ix), len(ix))] for ix in ix_all]  # within each snapshot month
            for m in METHODS:
                boot[m][b] = caught(y, resample, pr[m], caps)
        curves[year] = point
        diff = boot[METHODS[0]] - boot[METHODS[1]]
        for j, n in enumerate(caps):
            for m in METHODS:
                lo, hi = np.percentile(boot[m][:, j], [2.5, 97.5])
                rows.append({"year": year, "fixes_per_snapshot_month": int(n), "total_fixes": int(np.minimum(n, [len(i) for i in ix_all]).sum()),
                             "method": m, "caught": int(point[m][j]), "95% range": f"{lo:.0f}-{hi:.0f}", "later_exploited": int(y.sum()),
                             "model_minus_best_baseline": (f"{diff[:, j].mean():+.1f} [{np.percentile(diff[:, j], 2.5):+.0f} to {np.percentile(diff[:, j], 97.5):+.0f}]"
                                                           if m == METHODS[0] else "")})
    r = pd.DataFrame(rows)
    r["note"] = np.where(r.method == "CVSS 3 first", "uses baseline_cvss3 as given in vulnerabilities.csv, as the README baseline does", "")
    r.to_csv(RES / "exp7_capacity.csv", index=False)
    print("\n=== EXP 7\n" + r.pivot_table(index=["year", "fixes_per_snapshot_month"], columns="method", values="caught")[METHODS].astype(int).to_string())
    print("\nModel minus exploit-code baseline:\n" + r[r.method == METHODS[0]][["year", "fixes_per_snapshot_month", "model_minus_best_baseline"]].to_string(index=False))
    chart(curves, {y: int(d.label.sum()) for y, (d, _) in scored.items()})


def chart(curves, positives):
    ink, muted, grid, surface = "#0b0b0b", "#52514e", "#e6e5e0", "#fcfcfb"
    fig, axes = plt.subplots(1, 2, figsize=(10.5, 4.3), sharey=True, facecolor=surface)
    for ax, year in zip(axes, sorted(curves)):
        ax.set_facecolor(surface)
        ends = []
        for m in METHODS:
            ax.plot(CAPACITIES, curves[year][m], color=COLORS[m], lw=2, solid_capstyle="round", solid_joinstyle="round",
                    marker="o", ms=8, mec=surface, mew=2, label=m, zorder=3)
            ends.append((int(curves[year][m][-1]), m))
        ax.set_xscale("log")
        ax.set_xticks(CAPACITIES, [str(c) for c in CAPACITIES])
        ax.minorticks_off()
        ax.set_xlim(20, 1300)
        ax.set_xlabel("New vulnerabilities fixed per snapshot month", color=muted, fontsize=9)
        ax.set_title(f"{year} (out-of-year model): {positives[year]} later exploited", color=ink, fontsize=11, loc="left")
        ax.grid(axis="y", color=grid, lw=1)
        ax.set_axisbelow(True)
        for s in ("top", "right", "left"):
            ax.spines[s].set_visible(False)
        ax.spines["bottom"].set_color(grid)
        ax.tick_params(colors=muted, length=0, labelsize=9)
        # End labels, spread apart with thin leaders so converging lines stay readable.
        ends.sort()
        gap = max(positives.values()) * 0.075
        placed = []
        for value, m in ends:
            placed.append(max(value, placed[-1] + gap) if placed else value)
        for (value, m), yy in zip(ends, placed):
            ax.annotate(f"{m.split(' (')[0]}: {value}", xy=(500, value), xytext=(560, yy), color=ink, fontsize=8, va="center",
                        arrowprops=dict(arrowstyle="-", color=COLORS[m], lw=1, shrinkA=0, shrinkB=5))
    axes[0].set_ylabel("Later-exploited vulnerabilities caught", color=muted, fontsize=9)
    h, l = axes[0].get_legend_handles_labels()
    fig.legend(h, l, loc="upper center", ncol=4, frameon=False, fontsize=9, labelcolor=muted)
    fig.text(0.01, 0.01, "CVSS 3 first uses baseline_cvss3, the score as given in vulnerabilities.csv (as the README baseline does); it includes NIST-added scores.\n"
             "Monthly top N; 8 snapshot months (June and July share one).", color=muted, fontsize=7.5)
    fig.tight_layout(rect=(0, 0.07, 1, 0.93))
    fig.savefig(OUT / "figures" / "p6_patch_capacity.png", dpi=160, facecolor=surface)


if __name__ == "__main__":
    RES.mkdir(parents=True, exist_ok=True)
    scored = scored_sets()
    exp5(scored)
    exp6(scored)
    exp7(scored)
