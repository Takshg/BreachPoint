"""Phase 5 v1: LightGBM on exploit signals + assigner and vendor KEV history (no text).

What we learned building it (decisions C19-C21)
- Raw EPSS jumps ~8x from July 2026 and CVE volume triples, so raw values and counts drift.
  Only within-month EPSS rank and history rates are used.
- With 24 / 45 positives, the timing and batch-size features (days to snapshot, weekday,
  same-day batch size) let the trees fit noise: v1 with all 21 features lost to the baseline.
  v1 now uses the 11 "core" features. The 21-feature model is kept as a reference row.
- A logistic regression on the same core features is reported alongside as a check on
  whether the trees add anything.

Steps
1. Both directions (D14): train 2024 -> test 2025 (main) and 2025 -> 2024 (check).
   Boosting rounds picked by 5-fold CV inside the training year only.
2. Paired bootstrap against the best README baseline (exploit code, then EPSS).
3. C3 check: 2025 results without Jan-Feb 2025.
4. Final models on 2024 + 2025 -> score 2026 -> top 500 files; outputs/top500.csv = backup.

Usage: uv run python -m src.v1_LightGBM.train
"""
from __future__ import annotations

import json

import lightgbm as lgb
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score
from sklearn.model_selection import StratifiedKFold
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from src.cohort import OUT
from src.evaluate import baseline_scores, bootstrap, hits_at_k, paired_bootstrap, scaled_k

RESULTS = OUT / "v1_LightGBM"

SIGNALS = ["epss_pct", "exploitdb", "metasploit", "nuclei", "poc_github", "n_flags", "any_flag"]
HISTORY = ["assigner_kev_rate", "vendor_kev_rate", "vendor_kev_hist", "kev_product_named"]
CORE = SIGNALS + HISTORY
# Reference only: the first v1 feature set, which overfit.
ALL21 = SIGNALS + ["window_days", "days_pub_to_snapshot", "pub_dow", "id_year_lag",
                   "assigner_share_hist", "assigner_share_recent", "assigner_kev_hist", "assigner_kev_rate",
                   "assigner_same_day_pct", "vendor_matched", "vendor_kev_hist", "vendor_kev_recent",
                   "vendor_kev_rate", "kev_product_named"]

# More exploit code, a higher EPSS rank or more KEV history should never lower the score.
MONOTONE_UP = set(SIGNALS) | {"assigner_kev_hist", "assigner_kev_rate", "vendor_kev_hist",
                              "vendor_kev_recent", "vendor_kev_rate", "kev_product_named"}

# Few positives -> small, heavily regularised trees.
PARAMS = dict(
    objective="binary", learning_rate=0.03, num_leaves=7, max_depth=4, min_child_samples=40,
    min_sum_hessian_in_leaf=1e-3, feature_fraction=0.7, bagging_fraction=0.8, bagging_freq=1,
    lambda_l2=5.0, scale_pos_weight=20.0, verbose=-1, seed=0, deterministic=True, num_threads=8,
)
MAX_ROUNDS = 1000
BEST_BASELINE = "Exploit code, then EPSS"


def params_for(cols: list[str]) -> dict:
    return {**PARAMS, "monotone_constraints": [1 if c in MONOTONE_UP else 0 for c in cols],
            "monotone_constraints_method": "advanced"}


def load_sets():
    return {y: pd.read_parquet(OUT / f) for y, f in
            ((2024, "features_train_2024.parquet"), (2025, "features_val_2025.parquet"),
             (2026, "features_score_2026.parquet"))}


# ---------- models: each has fit(X, y) -> predict(X)

class LGBM:
    name = "LightGBM"

    def __init__(self, cols):
        self.cols = cols

    def _cv_rounds(self, X, y):
        curves = []
        for tr, va in StratifiedKFold(5, shuffle=True, random_state=0).split(X, y):
            ev = {}
            lgb.train(params_for(self.cols), lgb.Dataset(X.iloc[tr], y[tr]), MAX_ROUNDS,
                      valid_sets=[lgb.Dataset(X.iloc[va], y[va])], valid_names=["va"],
                      feval=lambda p, d: ("ap", average_precision_score(d.get_label(), p), True),
                      callbacks=[lgb.record_evaluation(ev)])
            curves.append(ev["va"]["ap"])
        smooth = pd.Series(np.mean(curves, axis=0)).rolling(50, min_periods=1, center=True).mean()
        return int(np.argmax(smooth.to_numpy()) + 1)

    def fit(self, df, y):
        X = df[self.cols]
        self.rounds = self._cv_rounds(X, y)
        self.model = lgb.train(params_for(self.cols), lgb.Dataset(X, y), self.rounds)
        return self

    def predict(self, df):
        return self.model.predict(df[self.cols])


class LogReg:
    name = "Logistic regression"

    def __init__(self, cols):
        self.cols = cols

    def _X(self, df):
        X = df[self.cols].astype(float).copy()
        for c in ("assigner_kev_rate", "vendor_kev_rate"):
            if c in X:
                X[c] = np.log(X[c].fillna(self.fill_[c]))
        if "vendor_kev_hist" in X:
            X["vendor_kev_hist"] = np.log1p(X["vendor_kev_hist"])
        return X.fillna(0)

    def fit(self, df, y):
        self.fill_ = {c: df[c].median() for c in ("assigner_kev_rate", "vendor_kev_rate") if c in self.cols}
        self.rounds = None
        self.model = make_pipeline(StandardScaler(),
                                   LogisticRegression(C=0.1, class_weight="balanced", max_iter=2000))
        self.model.fit(self._X(df), y)
        return self

    def predict(self, df):
        return self.model.predict_proba(self._X(df))[:, 1]


MODELS = {
    "v1 LightGBM core": lambda: LGBM(CORE),
    "v1 logistic core": lambda: LogReg(CORE),
    "ref: LightGBM all 21": lambda: LGBM(ALL21),
}


def evaluate_direction(make, train, test, label):
    m = make().fit(train, train.label.to_numpy(int))
    s = m.predict(test)
    y = test.label.to_numpy(int)
    k = scaled_k(len(test))
    base = baseline_scores(test)[BEST_BASELINE]
    lo, hi = bootstrap(y, s, k)
    d, (dlo, dhi) = paired_bootstrap(y, s, base, k)
    row = {"model": label[0], "direction": label[1], "rounds": m.rounds, "K": k,
           "hits@K": hits_at_k(y, s, k), "95% CI": f"[{lo:.0f}-{hi:.0f}]",
           "baseline": hits_at_k(y, base, k), "diff vs baseline": f"{d:+.1f} [{dlo:+.0f} to {dhi:+.0f}]",
           "hits@500": hits_at_k(y, s, 500), "AP": round(average_precision_score(y, s), 4),
           "AP baseline": round(average_precision_score(y, np.nan_to_num(base, nan=-1)), 4)}
    return row, m, s


def main():
    RESULTS.mkdir(parents=True, exist_ok=True)
    sets = load_sets()
    rows, extra = [], []
    for name, make in MODELS.items():
        r, m, s25 = evaluate_direction(make, sets[2024], sets[2025], (name, "2024 -> 2025"))
        rows.append(r)
        rows.append(evaluate_direction(make, sets[2025], sets[2024], (name, "2025 -> 2024"))[0])
        # C3: without Jan-Feb 2025
        t = sets[2025]
        keep = (t.published.dt.month > 2).to_numpy()
        kk = scaled_k(int(keep.sum()))
        extra.append({"model": name, "test": "2025 Mar-Sep", "K": kk,
                      "hits@K": hits_at_k(t.label.to_numpy(int)[keep], s25[keep], kk),
                      "baseline": hits_at_k(t.label.to_numpy(int)[keep], baseline_scores(t[keep])[BEST_BASELINE], kk),
                      "positives": int(t.label[keep].sum())})
        if name == "v1 LightGBM core":
            imp = pd.Series(m.model.feature_importance("gain"), index=m.cols).sort_values(ascending=False)
            imp.round(1).to_csv(RESULTS / "importance_2024_model.csv")
    pd.set_option("display.width", 220)
    res = pd.DataFrame(rows)
    print(res.to_string(index=False))
    print("\nC3 check (no Jan-Feb 2025):")
    print(pd.DataFrame(extra).to_string(index=False))
    print("\nLightGBM core, top features (gain, trained on 2024):")
    print(imp.round(1).to_string())
    res.to_csv(RESULTS / "results.csv", index=False)
    pd.DataFrame(extra).to_csv(RESULTS / "results_c3.csv", index=False)

    # ---------- final models on 2024 + 2025 -> 2026
    both = pd.concat([sets[2024], sets[2025]], ignore_index=True)
    yb = both.label.to_numpy(int)
    s26 = sets[2026]
    cfg = {}
    for name, fname in (("v1 LightGBM core", "lgbm_core"), ("v1 logistic core", "logreg_core")):
        m = MODELS[name]().fit(both, yb)
        sc = pd.DataFrame({"cve_id": s26.cve_id, "score": m.predict(s26)})
        sc["rank"] = sc.score.rank(ascending=False, method="first").astype(int)
        sc = sc.sort_values("rank")
        sc.to_parquet(RESULTS / f"scores_2026_{fname}.parquet", index=False)
        top = sc.head(500)[["cve_id"]]
        assert len(top) == 500 and top.cve_id.is_unique and top.cve_id.isin(s26.cve_id).all()
        top.to_csv(RESULTS / f"top500_{fname}.csv", index=False)
        cfg[fname] = {"features": m.cols, "rounds": m.rounds}
        t = s26.set_index("cve_id").loc[top.cve_id]
        share = t.snapshot_month.value_counts(normalize=True) / s26.snapshot_month.value_counts(normalize=True)
        print(f"\n{name}: top 500 month share vs scoreboard {share.round(2).sort_index().to_dict()}; "
              f"exploit code {t.any_flag.mean():.2f}; KEV vendor named {(t.vendor_matched > 0).mean():.2f}")
        if name == "v1 LightGBM core":
            m.model.save_model(str(RESULTS / "model_lgbm_core.txt"))
    cfg["params"] = params_for(CORE)
    json.dump(cfg, open(RESULTS / "config.json", "w"), indent=1, default=str)
    a = set(pd.read_csv(RESULTS / "top500_lgbm_core.csv").cve_id)
    b = set(pd.read_csv(RESULTS / "top500_logreg_core.csv").cve_id)
    print(f"\noverlap of the two top 500s: {len(a & b)}")


if __name__ == "__main__":
    main()
