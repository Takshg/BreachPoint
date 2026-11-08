"""Phase 5 v3: does vendor-supplied severity help, or leak? (plan v3, decisions D2, C4, C4a)

Variants on top of the v1 core features, with logistic regression and LightGBM:
  cna_score    vendor (CNA) CVSS 3 score
  cna_fields   vendor CVSS 3 attack fields: network vector, no privileges, no user interaction
  cvss4        CVSS 4 score
  has_cna / has_cvss4   presence only (diagnostics: is any gain from the value or from presence?)

Blank values: LightGBM handles them natively. Logistic regression fills them with the training
mean, so the value columns carry no presence signal there.

Also: presence by label and year, 2026 coverage by month, and top-500 month shares for 2026.

Usage: uv run python -m src.v3_Vendor_CVSS.train
"""
from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score

import src.v1_LightGBM.train as v1
from src.cohort import OUT
from src.evaluate import baseline_scores, bootstrap, hits_at_k, paired_bootstrap, scaled_k
from src.load import load
from src.v1_LightGBM.train import BEST_BASELINE, CORE, LGBM, LogReg, load_sets

RESULTS = OUT / "v3_Vendor_CVSS"
v1.PARAMS["num_threads"] = 4  # the Granite pilot is using this machine too (this process only)

FIELDS = ["cna_net", "cna_no_priv", "cna_no_ui"]
VARIANTS = {
    "core + cna_score": ["cna_cvss3"],
    "core + cna_fields": FIELDS,
    "core + cvss4": ["cvss4_score"],
    "core + has_cna (presence)": ["has_cna"],
    "core + has_cvss4 (presence)": ["has_cvss4"],
}
IMPUTE = ["cna_cvss3", "cvss4_score", *FIELDS]


class LogRegMean(LogReg):
    """Logistic regression that fills blank severity columns with the training mean."""

    def fit(self, df, y):
        self.means_ = df[[c for c in self.cols if c in IMPUTE]].mean()
        return super().fit(df, y)

    def _X(self, df):
        d = df[self.cols].copy()
        for c, m in self.means_.items():
            d[c] = d[c].fillna(m)
        return super()._X(d)


def add_severity(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    v4 = load("vulnerabilities", ["cve_id", "cvss4_score"]).set_index("cve_id").cvss4_score
    df["cvss4_score"] = df.cve_id.map(v4).astype(float)
    df["has_cvss4"] = df.cvss4_score.notna().astype("int8")
    df["has_cna"] = df.cna_cvss3.notna().astype("int8")
    has = df.has_cna == 1
    for name, col, val in (("cna_net", "cna_attack_vector", "NETWORK"),
                           ("cna_no_priv", "cna_privileges_required", "NONE"),
                           ("cna_no_ui", "cna_user_interaction", "NONE")):
        df[name] = (df[col].astype(str) == val).astype(float).where(has)
    return df


def result_row(name, kind, direction, y, s, base, ref, k):
    lo, hi = bootstrap(y, s, k)
    d, (dlo, dhi) = paired_bootstrap(y, s, base, k)
    dr, (drlo, drhi) = paired_bootstrap(y, s, ref, k)
    return {"variant": name, "model": kind, "direction": direction, "K": k, "hits@K": hits_at_k(y, s, k),
            "95% range": f"{lo:.0f}-{hi:.0f}", "baseline": hits_at_k(y, base, k),
            "vs baseline": f"{d:+.1f} [{dlo:+.0f},{dhi:+.0f}]", "v1 logistic": hits_at_k(y, ref, k),
            "vs v1 logistic": f"{dr:+.1f} [{drlo:+.0f},{drhi:+.0f}]", "AP": round(average_precision_score(y, s), 4)}


def run_variants(train_test, variants, logreg_cls, results_path):
    """train_test: list of (direction label, train df, test df). variants: name -> extra columns."""
    rows = []
    for direction, tr, te in train_test:
        ytr, y = tr.label.to_numpy(int), te.label.to_numpy(int)
        k = scaled_k(len(te))
        base = baseline_scores(te)[BEST_BASELINE]
        ref = LogReg(CORE).fit(tr, ytr).predict(te)
        rows.append(result_row("v1 core", "logistic", direction, y, ref, base, ref, k))
        rows.append(result_row("v1 core", "LightGBM", direction, y, LGBM(CORE).fit(tr, ytr).predict(te), base, ref, k))
        for name, extra in variants.items():
            cols = CORE + extra
            rows.append(result_row(name, "logistic", direction, y, logreg_cls(cols).fit(tr, ytr).predict(te), base, ref, k))
            rows.append(result_row(name, "LightGBM", direction, y, LGBM(cols).fit(tr, ytr).predict(te), base, ref, k))
            print(direction, name, "done", flush=True)
    res = pd.DataFrame(rows)
    res.to_csv(results_path, index=False)
    return res


def leak_check(sets) -> None:
    rows = []
    for y in (2024, 2025):
        d = sets[y]
        pos, neg = d[d.label == 1], d[d.label == 0]
        for c, val in (("has_cna", "cna_cvss3"), ("has_cvss4", "cvss4_score")):
            rows.append({"year": y, "column": c, "positives": len(pos),
                         "present, positives": round(pos[c].mean(), 3), "present, others": round(neg[c].mean(), 3),
                         "sign": "+" if pos[c].mean() > neg[c].mean() else "-",
                         "mean value, positives": round(pos[val].mean(), 2), "mean value, others": round(neg[val].mean(), 2)})
    t = pd.DataFrame(rows)
    print("\nPresence and value by label (sign should be the same in both years if it is real):")
    print(t.to_string(index=False))
    t.to_csv(RESULTS / "leak_check.csv", index=False)


def final_2026(sets) -> None:
    both = pd.concat([sets[2024], sets[2025]], ignore_index=True)
    yb, s26 = both.label.to_numpy(int), sets[2026]
    board = s26.snapshot_month.value_counts(normalize=True)
    cov = s26.groupby("snapshot_month")[["has_cna", "has_cvss4"]].mean().round(3)
    print("\n2026 coverage by snapshot month:\n" + cov.T.to_string())
    print("Training coverage has_cna:", {y: round(sets[y].has_cna.mean(), 3) for y in sets},
          "has_cvss4:", {y: round(sets[y].has_cvss4.mean(), 3) for y in sets})
    rows, tops = [], {}
    configs = {"v1 core": (LogReg, []), "core + cna_score": (LogRegMean, ["cna_cvss3"]),
               "core + cvss4": (LogRegMean, ["cvss4_score"]), "core + cna_fields": (LogRegMean, FIELDS)}
    for name, (cls, extra) in configs.items():
        for kind, make in (("logistic", cls), ("LightGBM", LGBM)):
            m = make(CORE + extra).fit(both, yb)
            top = s26.assign(score=m.predict(s26)).sort_values("score", ascending=False).head(500)
            tops[(name, kind)] = set(top.cve_id)
            share = (top.snapshot_month.value_counts(normalize=True) / board).reindex(board.index).fillna(0).sort_index()
            rows.append({"variant": name, "model": kind, **share.round(2).to_dict(),
                         "has_cna in top 500": round(top.has_cna.mean(), 2), "has_cvss4 in top 500": round(top.has_cvss4.mean(), 2),
                         "overlap with v1 logistic": len(tops[(name, kind)] & tops[("v1 core", "logistic")])})
    t = pd.DataFrame(rows)
    print("\nTop 500: each month's share / its share of the scoreboard:\n" + t.to_string(index=False))
    t.to_csv(RESULTS / "top500_month_shares.csv", index=False)


def main():
    RESULTS.mkdir(parents=True, exist_ok=True)
    pd.set_option("display.width", 260)
    sets = {y: add_severity(d) for y, d in load_sets().items()}
    leak_check(sets)
    res = run_variants([("2024 -> 2025", sets[2024], sets[2025]), ("2025 -> 2024", sets[2025], sets[2024])],
                       VARIANTS, LogRegMean, RESULTS / "results.csv")
    print("\n" + res.to_string(index=False))
    final_2026(sets)
    print("\nscoreboard rows by month, has_cna mean:", sets[2026].groupby("snapshot_month").has_cna.size().to_dict())


if __name__ == "__main__":
    main()
