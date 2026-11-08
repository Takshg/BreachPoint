import pandas as pd
import pytest

from src.cohort import OUT
from src.features import Builder, feature_columns


@pytest.fixture(scope="module")
def builder():
    return Builder()


@pytest.fixture(scope="module")
def train():
    return pd.read_parquet(OUT / "train_2024.parquet")


def test_kev_frozen_at_end_of_previous_year(builder, train):
    """D13: a KEV entry added during 2024 must not change any 2024 feature."""
    sample = train.sample(3000, random_state=0)
    before = builder.build(sample, 2024)
    # Fake: list Fortinet and Microsoft vulns on KEV in March 2024, plus every 2024 positive.
    fake = builder.v[builder.v.description.str.contains("Fortinet|Microsoft", na=False)].cve_id.head(200)
    extra = pd.DataFrame({"cve_id": list(fake) + list(train[train.label == 1].cve_id),
                          "vendor": "Fortinet", "product": "FortiOS", "date_added": pd.Timestamp("2024-03-01")})
    original = builder.kev
    builder.kev = pd.concat([original, extra], ignore_index=True)
    try:
        after = builder.build(sample, 2024)
    finally:
        builder.kev = original
    cols = feature_columns(before)
    pd.testing.assert_frame_equal(before[cols], after[cols])


def test_no_leaky_columns_in_safe_features(train, builder):
    f = builder.build(train.head(500), 2024)
    cols = feature_columns(f)
    banned = {"label", "kev_date_added", "baseline_cvss3"}
    assert not any(c.startswith("leak_") for c in cols)
    assert not banned & set(cols)
