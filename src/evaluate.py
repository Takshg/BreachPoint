"""Phase 4: evaluation and the three README baselines.

Main metric (D8): hits@K with K = 500 x cohort size / 72,670 (198 for 2024, 243 for 2025).
Uncertainty (D14): bootstrap intervals, both directions, paired bootstrap for model differences.
Ties (many vulns share the same EPSS) are broken with a fixed random order, so results are repeatable.

Usage: uv run python -m src.evaluate
"""
from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score

from src.cohort import OUT

BOARD_SIZE = 72_670
SEED = 0


def scaled_k(n: int) -> int:
    return int(round(500 * n / BOARD_SIZE))


def rank_order(score: np.ndarray, seed: int = SEED) -> np.ndarray:
    """Indices from best to worst; NaN scores last; ties in a fixed random order."""
    s = np.where(np.isnan(score), -np.inf, score)
    tie = np.random.default_rng(seed).random(len(s))
    return np.lexsort((tie, -s))


def hits_at_k(y: np.ndarray, score: np.ndarray, k: int) -> int:
    return int(y[rank_order(score)[:k]].sum())


def average_precision(y: np.ndarray, score: np.ndarray) -> float:
    s = np.where(np.isnan(score), -np.inf, score)
    s = np.where(np.isinf(s), np.nanmin(s[np.isfinite(s)]) - 1 if np.isfinite(s).any() else 0, s)
    return float(average_precision_score(y, s))


def bootstrap(y, score, k, n_boot=1000, seed=SEED):
    """95% interval for hits@K by resampling vulnerabilities with replacement."""
    rng = np.random.default_rng(seed)
    order = rank_order(score)
    pos_rank = np.empty(len(y), dtype=np.int64); pos_rank[order] = np.arange(len(y))
    out = np.empty(n_boot)
    for b in range(n_boot):
        idx = rng.integers(0, len(y), len(y))
        # top-K of the resample = the K resampled rows with the best original rank
        top = idx[np.argsort(pos_rank[idx], kind="stable")[:k]]
        out[b] = y[top].sum()
    return np.percentile(out, [2.5, 97.5])


def paired_bootstrap(y, score_a, score_b, k, n_boot=1000, seed=SEED):
    """Interval for hits@K(A) - hits@K(B) on the same resamples."""
    rng = np.random.default_rng(seed)
    ra = np.empty(len(y), dtype=np.int64); ra[rank_order(score_a)] = np.arange(len(y))
    rb = np.empty(len(y), dtype=np.int64); rb[rank_order(score_b)] = np.arange(len(y))
    diff = np.empty(n_boot)
    for b in range(n_boot):
        idx = rng.integers(0, len(y), len(y))
        ta = idx[np.argsort(ra[idx], kind="stable")[:k]]
        tb = idx[np.argsort(rb[idx], kind="stable")[:k]]
        diff[b] = y[ta].sum() - y[tb].sum()
    return float(np.mean(diff)), np.percentile(diff, [2.5, 97.5])


def baseline_scores(df: pd.DataFrame) -> dict[str, np.ndarray]:
    flags = df[["exploitdb", "metasploit", "nuclei", "poc_github"]].sum(axis=1).gt(0).to_numpy()
    epss = df.epss.to_numpy(dtype=float)
    return {
        "CVSS 3 first": df.baseline_cvss3.to_numpy(dtype=float),
        "EPSS first": epss,
        # Any exploit code first, then EPSS (EPSS < 1, so +1 puts flagged rows on top)
        "Exploit code, then EPSS": np.where(flags, 1.0, 0.0) + np.nan_to_num(epss, nan=-1e-6),
    }


def report(df: pd.DataFrame, scores: dict[str, np.ndarray], name: str, n_boot: int = 1000) -> pd.DataFrame:
    y = df.label.to_numpy(dtype=int)
    k = scaled_k(len(df))
    rows = []
    for m, s in scores.items():
        lo, hi = bootstrap(y, s, k, n_boot)
        rows.append({"cohort": name, "method": m, "K": k, f"hits@K": hits_at_k(y, s, k),
                     "95% CI": f"[{lo:.0f}-{hi:.0f}]", "hits@500": hits_at_k(y, s, 500),
                     "AP": round(average_precision(y, s), 4), "positives": int(y.sum())})
    return pd.DataFrame(rows)


def hits_curve(df: pd.DataFrame, scores: dict[str, np.ndarray], ks=None) -> pd.DataFrame:
    y = df.label.to_numpy(dtype=int)
    ks = ks or list(range(25, 2001, 25))
    out = {}
    for m, s in scores.items():
        cum = np.cumsum(y[rank_order(s)])
        out[m] = [int(cum[k - 1]) for k in ks]
    return pd.DataFrame(out, index=pd.Index(ks, name="K"))


if __name__ == "__main__":
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    res = []
    fig, axes = plt.subplots(1, 2, figsize=(11, 3.6))
    for ax, (name, f) in zip(axes, (("2024", "features_train_2024"), ("2025", "features_val_2025"))):
        df = pd.read_parquet(OUT / f"{f}.parquet")
        sc = baseline_scores(df)
        res.append(report(df, sc, name))
        hits_curve(df, sc).plot(ax=ax)
        ax.axvline(scaled_k(len(df)), ls="--", c="grey", lw=0.8)
        ax.set_title(f"{name} cohort: hits vs K (dashed = scaled K)"); ax.set_ylabel("later-exploited found")
    fig.tight_layout(); fig.savefig(OUT / "figures" / "p4_baselines_hits_curve.png")
    out = pd.concat(res)
    print(out.to_string(index=False))
    out.to_csv(OUT / "baselines.csv", index=False)
