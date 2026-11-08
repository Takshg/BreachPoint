import numpy as np

from src.evaluate import bootstrap, hits_at_k, paired_bootstrap, rank_order, scaled_k


def test_scaled_k():
    assert scaled_k(72_670) == 500 and scaled_k(35_278) == 243 and scaled_k(28_836) == 198


def test_rank_order_nan_last_and_repeatable():
    s = np.array([0.1, np.nan, 0.9, 0.1])
    o = rank_order(s)
    assert o[0] == 2 and o[-1] == 1
    assert (o == rank_order(s)).all()


def test_hits_and_intervals():
    y = np.array([1, 0, 0, 1, 0, 0, 0, 0, 0, 0])
    s = np.arange(10, 0, -1, dtype=float)  # row 0 best
    assert hits_at_k(y, s, 2) == 1 and hits_at_k(y, s, 4) == 2
    lo, hi = bootstrap(y, s, 4, n_boot=200)
    assert lo <= 2 <= hi
    mean, (dlo, dhi) = paired_bootstrap(y, s, s, 4, n_boot=200)
    assert mean == 0 and dlo == 0 and dhi == 0
