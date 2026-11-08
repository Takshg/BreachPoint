"""Phase 5 v2b: Granite embeddings as the backup to the Granite analyst (no Colab needed).

Variants on the v1 core features, logistic regression and LightGBM:
  core + kev_similarity   one feature: mean cosine similarity to the 10 nearest frozen KEV descriptions
  core + svd8             8 SVD components of the embeddings, fit on the training year only

Usage: uv run python -m src.v2b_Granite_Embeddings.train   (needs embed.py to have finished)
"""
from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.decomposition import TruncatedSVD

import src.v1_LightGBM.train as v1
from src.cohort import OUT
from src.load import load
from src.v1_LightGBM.train import CORE, LGBM, LogReg, load_sets
from src.v2b_Granite_Embeddings.similarity import kev_similarity
from src.v3_Vendor_CVSS.train import run_variants  # also sets LightGBM to 4 threads

JOB = OUT / "v2b_Granite_Embeddings"
SVD = [f"svd_{i}" for i in range(8)]
v1.MONOTONE_UP.add("kev_similarity")  # closer to known-exploited descriptions never lowers the score


def main():
    pd.set_option("display.width", 260)
    E = np.load(JOB / "embeddings.npy")
    ids = pd.read_parquet(JOB / "ids.parquet").cve_id
    pos = pd.Series(np.arange(len(ids)), index=ids.to_numpy())
    kev = load("known_exploited", ["cve_id", "date_added"])
    published = load("vulnerabilities", ["cve_id", "published"]).set_index("cve_id").published
    sets = load_sets()
    for y, d in sets.items():
        d["kev_similarity"] = kev_similarity(d.cve_id.to_numpy(), ids, E, kev, published, y)
        print(f"{y}: kev_similarity median {d.kev_similarity.median():.3f}", flush=True)

    print("\nMedian kev_similarity by snapshot month:")
    for y, d in sets.items():
        print(y, d.groupby("snapshot_month").kev_similarity.median().round(3).to_dict())
    for y in (2024, 2025):
        d = sets[y]
        print(f"{y}: median positives {d[d.label == 1].kev_similarity.median():.3f}, "
              f"others {d[d.label == 0].kev_similarity.median():.3f}; "
              f"positives in top 10%: {(d[d.label == 1].kev_similarity >= d.kev_similarity.quantile(.9)).mean():.2f}")

    def with_svd(tr, te):
        svd = TruncatedSVD(8, random_state=0).fit(E[pos.loc[tr.cve_id].to_numpy()])
        out = []
        for d in (tr, te):
            d = d.copy()
            d[SVD] = svd.transform(E[pos.loc[d.cve_id].to_numpy()])
            out.append(d)
        return out

    pairs = [("2024 -> 2025", *with_svd(sets[2024], sets[2025])), ("2025 -> 2024", *with_svd(sets[2025], sets[2024]))]
    variants = {"core + kev_similarity": ["kev_similarity"], "core + svd8": SVD}
    res = run_variants(pairs, variants, LogReg, JOB / "results.csv")
    print("\n" + res.to_string(index=False))

    # Backup 2026 list from the single-feature logistic model (not the submission file).
    both = pd.concat([sets[2024], sets[2025]], ignore_index=True)
    s26 = sets[2026]
    m = LogReg(CORE + ["kev_similarity"]).fit(both, both.label.to_numpy(int))
    sc = s26.assign(score=m.predict(s26)).sort_values("score", ascending=False)
    sc[["cve_id", "score"]].to_parquet(JOB / "scores_2026_logreg_kevsim.parquet", index=False)
    sc.head(500)[["cve_id"]].to_csv(JOB / "top500_logreg_kevsim.csv", index=False)
    board = s26.snapshot_month.value_counts(normalize=True)
    print("\ntop 500 month share / scoreboard share:",
          (sc.head(500).snapshot_month.value_counts(normalize=True) / board).round(2).sort_index().to_dict())
    v1top = set(pd.read_csv(OUT / "v1_LightGBM" / "top500_logreg_core.csv").cve_id)
    print("overlap with v1 logistic top 500:", len(v1top & set(sc.head(500).cve_id)))


if __name__ == "__main__":
    main()
