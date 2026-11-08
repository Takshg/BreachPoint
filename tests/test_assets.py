from itertools import product

import pandas as pd
import pytest

from src.assets import (DATA_VALUES, DEFER, ENVIRONMENTS, EXPOSURES, LEVELS, NOW, TRACK, decide, exploitation_tier,
                        highest_per_vulnerability, assess, load_sample, match, validate_inventory)

TIERS = ["active", "likely", "possible", "unlikely"]
ALL = list(product(TIERS, EXPOSURES, ENVIRONMENTS, DATA_VALUES))


@pytest.mark.parametrize("env,data", list(product(ENVIRONMENTS, DATA_VALUES)))
def test_g1_kev_on_internet_is_always_act_now(env, data):
    assert decide("active", "internet", env, data)[0] == NOW


@pytest.mark.parametrize("exposure,data", list(product(EXPOSURES, DATA_VALUES)))
def test_g1_kev_in_production_is_always_act_now(exposure, data):
    assert decide("active", exposure, "production", data)[0] == NOW


@pytest.mark.parametrize("tier,env,data", list(product(TIERS, ENVIRONMENTS, DATA_VALUES)))
def test_g2_isolation_lowers_by_at_most_two_levels(tier, env, data):
    assert decide(tier, "internet", env, data)[0] - decide(tier, "isolated", env, data)[0] <= 2


def test_g2_actually_fires():
    """Top-10% vuln on an isolated production box with sensitive data would otherwise fall three levels."""
    assert decide("possible", "isolated", "production", "high") == (TRACK, "G2")


@pytest.mark.parametrize("tier,exposure,env,data", ALL)
def test_every_combination_gives_a_valid_level(tier, exposure, env, data):
    assert DEFER <= decide(tier, exposure, env, data)[0] <= NOW


@pytest.mark.parametrize("tier,env,data", list(product(TIERS, ENVIRONMENTS, DATA_VALUES)))
def test_more_exposure_never_lowers_priority(tier, env, data):
    a, b, c = (decide(tier, x, env, data)[0] for x in ("isolated", "internal", "internet"))
    assert a <= b <= c


@pytest.mark.parametrize("exposure,env,data", list(product(EXPOSURES, ENVIRONMENTS, DATA_VALUES)))
def test_higher_exploitation_never_lowers_priority(exposure, env, data):
    levels = [decide(t, exposure, env, data)[0] for t in ("unlikely", "possible", "likely", "active")]
    assert levels == sorted(levels)


def test_the_motivating_case_is_deferred():
    """Top-ranked vuln on an isolated dev sandbox with no data shouldn't take an engineer's morning."""
    assert LEVELS[decide("likely", "isolated", "dev/test", "none")[0]] == "Defer"


def test_tiers():
    assert exploitation_tier(1, 10_000) == "likely" and exploitation_tier(100, 10_000) == "likely"
    assert exploitation_tier(101, 10_000) == "possible" and exploitation_tier(1001, 10_000) == "unlikely"
    assert exploitation_tier(9_999, 10_000, on_kev=True) == "active"


LOOKUP = pd.DataFrame({"cve_id": ["A", "B", "C"], "rank": [1, 2, 3],
                       "text": ["rce in apache tomcat 9", "bug in acme widget", "tomcatish thing"],
                       "products": ["", "fortinet fortios", ""], "on_kev": [False, False, False]})


def inv(rows):
    return pd.DataFrame(rows, columns=["asset", "owner", "software", "exposure", "environment", "data_value"])


def test_matching_uses_description_and_product_list_and_whole_words():
    m = match(inv([["a", "x", "Apache Tomcat; FortiOS", "internal", "production", "high"]]), LOOKUP)
    assert set(m.cve_id) == {"A", "B"}  # "tomcatish" must not match


def test_g3_highest_priority_across_assets():
    i = inv([["dev", "x", "Apache Tomcat", "isolated", "dev/test", "none"],
             ["prod", "x", "Apache Tomcat", "internet", "production", "high"]])
    filler = pd.DataFrame({"cve_id": [f"F{n}" for n in range(1000)], "rank": range(4, 1004), "text": "x", "products": "", "on_kev": False})
    v = highest_per_vulnerability(assess(i, pd.concat([LOOKUP, filler], ignore_index=True)))  # rank 1 of ~1000 = top 1%
    r = v[v.cve_id == "A"].iloc[0]
    assert r.asset == "prod" and r.priority == "Act now" and r.n_assets == 2


def test_validation_reports_problems():
    assert validate_inventory(pd.DataFrame({"asset": ["a"]}))
    bad = inv([["a", "x", "s", "public", "production", "high"]])
    assert any("exposure" in p for p in validate_inventory(bad))
    assert not validate_inventory(load_sample())
