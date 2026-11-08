import numpy as np
import pandas as pd

from src.v2b_Granite_Embeddings.similarity import kev_similarity


def setup():
    rng = np.random.default_rng(0)
    E = rng.normal(size=(40, 8)).astype("float32")
    E /= np.linalg.norm(E, axis=1, keepdims=True)
    ids = pd.Series([f"CVE-X-{i}" for i in range(40)])
    pub = pd.Series(pd.Timestamp("2020-06-01"), index=ids.to_numpy())
    kev = pd.DataFrame({"cve_id": ids[:20].to_numpy(), "date_added": pd.Timestamp("2021-06-01")})
    return ids, E, pub, kev, ids[25:35].to_numpy()


def test_fake_kev_inside_year_changes_nothing():
    ids, E, pub, kev, cohort = setup()
    before = kev_similarity(cohort, ids, E, kev, pub, 2024, top=3)
    fake = pd.DataFrame({"cve_id": cohort[:5], "date_added": pd.Timestamp("2024-03-01")})
    after = kev_similarity(cohort, ids, E, pd.concat([kev, fake], ignore_index=True), pub, 2024, top=3)
    assert np.array_equal(before, after)


def test_kev_before_the_year_does_change_it():
    ids, E, pub, kev, cohort = setup()
    before = kev_similarity(cohort, ids, E, kev, pub, 2024, top=3)
    earlier = pd.DataFrame({"cve_id": ids[35:40].to_numpy(), "date_added": pd.Timestamp("2023-03-01")})
    after = kev_similarity(cohort, ids, E, pd.concat([kev, earlier], ignore_index=True), pub, 2024, top=3)
    assert not np.array_equal(before, after)


def test_own_entry_is_excluded():
    ids, E, pub, kev, _ = setup()
    me = ids[:1].to_numpy()  # a row that is itself in the reference set
    assert kev_similarity(me, ids, E, kev, pub, 2024, top=1)[0] < 0.999


def test_published_after_the_cut_is_not_a_reference():
    ids, E, pub, kev, cohort = setup()
    before = kev_similarity(cohort, ids, E, kev, pub, 2024, top=3)
    late = pub.copy()
    extra = ids[35:40].to_numpy()
    late.loc[extra] = pd.Timestamp("2024-02-01")
    added = pd.DataFrame({"cve_id": extra, "date_added": pd.Timestamp("2023-01-01")})
    after = kev_similarity(cohort, ids, E, pd.concat([kev, added], ignore_index=True), late, 2024, top=3)
    assert np.array_equal(before, after)
