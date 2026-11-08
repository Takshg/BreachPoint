"""Embed cohort and KEV descriptions with IBM Granite's 30M embedding model, once.

Falls back to CPU if MPS fails. Resumable: writes one part per 5,000 descriptions.
Output: outputs/v2b_Granite_Embeddings/embeddings.npy (float32, unit length), ids.parquet.

Usage: uv run python -m src.v2b_Granite_Embeddings.embed
"""
from __future__ import annotations

import numpy as np
import pandas as pd
import torch
from sentence_transformers import SentenceTransformer

from src.cohort import OUT
from src.load import load

JOB = OUT / "v2b_Granite_Embeddings"
PARTS = JOB / "parts"
MODEL = "ibm-granite/granite-embedding-30m-english"
CHUNK = 5000


def target_ids() -> pd.Series:
    ids = [pd.read_parquet(OUT / f, columns=["cve_id"]).cve_id
           for f in ("train_2024.parquet", "val_2025.parquet", "score_2026.parquet")]
    ids.append(load("known_exploited", ["cve_id"]).cve_id)
    return pd.concat(ids).drop_duplicates().sort_values(ignore_index=True)


def main():
    PARTS.mkdir(parents=True, exist_ok=True)
    ids = target_ids()
    desc = load("vulnerabilities", ["cve_id", "description"]).set_index("cve_id").description.reindex(ids)
    assert desc.notna().all()
    device = "mps" if torch.backends.mps.is_available() else "cpu"
    model = SentenceTransformer(MODEL, device=device)
    n_parts = (len(ids) + CHUNK - 1) // CHUNK
    print(f"{len(ids):,} descriptions, {n_parts} parts, device {device}", flush=True)
    for p in range(n_parts):
        f = PARTS / f"part-{p:04d}.npy"
        if f.exists():
            continue
        batch = desc.iloc[p * CHUNK:(p + 1) * CHUNK].tolist()
        try:
            e = model.encode(batch, batch_size=64, normalize_embeddings=True, convert_to_numpy=True, show_progress_bar=False)
        except RuntimeError as err:
            if device == "cpu":
                raise
            print(f"MPS failed ({err}); falling back to CPU", flush=True)
            device = "cpu"
            model = SentenceTransformer(MODEL, device=device)
            e = model.encode(batch, batch_size=64, normalize_embeddings=True, convert_to_numpy=True, show_progress_bar=False)
        np.save(f, e.astype("float32"))
        print(f"part {p + 1}/{n_parts} done on {device}", flush=True)
    E = np.concatenate([np.load(PARTS / f"part-{p:04d}.npy") for p in range(n_parts)])
    assert len(E) == len(ids)
    np.save(JOB / "embeddings.npy", E)
    pd.DataFrame({"cve_id": ids}).to_parquet(JOB / "ids.parquet", index=False)
    print("wrote", E.shape, flush=True)


if __name__ == "__main__":
    main()
