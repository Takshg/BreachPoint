import numpy as np

from src.v2_Granite_Analyst.stage2 import pool_order


def test_pool_is_reranked_and_stays_on_top():
    v1 = np.arange(100.0)  # rows 90-99 form the top 10%
    v2 = -np.arange(100.0)  # v2 reverses the order
    order = np.argsort(-pool_order(v1, v2, share=0.10))
    assert order[:10].tolist() == list(range(90, 100))  # lowest v1 in the pool now leads
    assert order[10:].tolist() == list(range(89, -1, -1))  # the rest keep v1 order
