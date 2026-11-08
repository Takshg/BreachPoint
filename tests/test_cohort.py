import pandas as pd
import pytest

from src.cohort import COLUMNS, FLAGS, build_all, snapshot_end
from src.load import load


@pytest.fixture(scope="module")
def sets():
    return build_all()


@pytest.fixture(scope="module")
def kev():
    return load("known_exploited", ["cve_id", "date_added"]).set_index("cve_id").date_added


def test_same_columns(sets):
    for df in sets.values():
        assert list(df.columns) == COLUMNS


def test_snapshot_rule():
    d = pd.Series(pd.to_datetime(["2024-01-15", "2024-06-03", "2024-06-30", "2024-07-01", "2024-09-30"]))
    assert snapshot_end(d).dt.strftime("%Y-%m-%d").tolist() == [
        "2024-01-31", "2024-07-31", "2024-07-31", "2024-07-31", "2024-09-30"]


@pytest.mark.parametrize("name,year", [("train_2024", 2024), ("val_2025", 2025)])
def test_cohort_rules(sets, kev, name, year):
    df = sets[name]
    assert df.cve_id.is_unique
    assert (df.published.dt.year == year).all() and (df.published.dt.month <= 9).all()
    # No row was on KEV at its snapshot.
    added = df.cve_id.map(kev)
    assert not (added <= df.snapshot_end).any()
    # Every positive was added after the snapshot and on or before Nov 4 of Y; no label uses later data.
    pos = df[df.label == 1]
    assert (pos.kev_date_added > pos.snapshot_end).all()
    assert (pos.kev_date_added <= pd.Timestamp(f"{year}-11-04")).all()
    # Every KEV addition inside the window is labelled positive.
    inside = (added > df.snapshot_end) & (added <= pd.Timestamp(f"{year}-11-04"))
    assert (df.label == inside.astype(int)).all()


def test_positive_counts(sets):
    # Matches Phase 1 exploration.
    assert sets["train_2024"].label.sum() == 24
    assert sets["val_2025"].label.sum() == 45


def test_score_set_matches_scoreboard(sets):
    board = load("scoreboard_2026")
    s = sets["score_2026"]
    assert len(s) == 72_670 and set(s.cve_id) == set(board.cve_id)
    assert s.label.isna().all()
    # June 2026 rows are snapshotted in July, like the training sets.
    june = s[s.published.dt.month == 6]
    assert (june.snapshot_month == "2026-07").all()


def test_missing_signals_convention(sets):
    for df in sets.values():
        assert df[FLAGS].notna().all().all()
        assert df[FLAGS].isin([0, 1]).all().all()


def test_hand_checked_rows(sets):
    """A few rows checked by hand against known_exploited.csv and the signals."""
    df = pd.concat([sets["train_2024"], sets["val_2025"]]).set_index("cve_id")
    pos = df[df.label == 1]
    for cve, r in pos.head(3).iterrows():
        print(cve, r.published.date(), r.snapshot_month, r.kev_date_added.date(), r.epss, r[FLAGS].tolist())
    assert len(pos) == 69
