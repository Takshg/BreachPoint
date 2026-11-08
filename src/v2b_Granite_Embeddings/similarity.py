"""kev_similarity: how close a description is to known-exploited ones, under the D13 freeze."""
from __future__ import annotations

import numpy as np
import pandas as pd


def kev_similarity(cohort_ids, ids: pd.Series, E: np.ndarray, kev: pd.DataFrame, published: pd.Series,
                   year: int, top: int = 10, batch: int = 5000) -> np.ndarray:
    """Mean cosine similarity to the `top` nearest KEV descriptions known by Dec 31 of year-1.

    Reference set: KEV entries with date_added <= cut and published <= cut. A row's own entry is
    never counted. E must be unit length and aligned with `ids`.
    """
    cut = pd.Timestamp(f"{year - 1}-12-31")
    pos = pd.Series(np.arange(len(ids)), index=ids.to_numpy())
    known = kev[(kev.date_added <= cut) & (kev.cve_id.map(published) <= cut) & kev.cve_id.isin(pos.index)]
    refs = known.cve_id.drop_duplicates().to_numpy()
    ref_pos = pos.loc[refs].to_numpy()
    ref_E = E[ref_pos]
    ref_of = {c: i for i, c in enumerate(refs)}
    cohort_ids = np.asarray(cohort_ids)
    out = np.empty(len(cohort_ids), dtype="float32")
    row_pos = pos.loc[cohort_ids].to_numpy()
    for start in range(0, len(cohort_ids), batch):
        sims = E[row_pos[start:start + batch]] @ ref_E.T
        for j, c in enumerate(cohort_ids[start:start + batch]):
            if c in ref_of:
                sims[j, ref_of[c]] = -np.inf
        n = min(top, sims.shape[1] - 1)
        out[start:start + batch] = np.partition(sims, -n, axis=1)[:, -n:].mean(axis=1)
    return out
