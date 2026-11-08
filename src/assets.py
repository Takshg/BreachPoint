"""Phase 8a: turn "how likely is an attack anywhere" into "what should THIS client fix first".

Two questions stay separate. The model ranks each vulnerability for everyone; this module adds
where it runs in one client's environment. It never affects top500.csv.

Fix order is an explicit decision table in the style of CISA's SSVC, not a weighted score:
exploitation x exposure gives a base level, impact moves it, and guardrails stop asset context
from hiding real danger:
  G1  KEV-listed on an internet-facing or production asset is always Act now.
  G2  Being isolated lowers priority by at most two levels (isolation is often wrong in practice).
  G3  A vulnerability on several assets takes its highest priority.

Usage: uv run python -m src.assets    # builds outputs/app/asset_lookup.parquet (after src.app_data)
"""
from __future__ import annotations

import re
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "outputs" / "app"
SAMPLE = ROOT / "app" / "sample_assets_MADE_UP.csv"

LEVELS = ["Defer", "Track", "Act soon", "Act now"]
DEFER, TRACK, SOON, NOW = range(4)
COLUMNS = ["asset", "owner", "software", "exposure", "environment", "data_value"]
EXPOSURES = ["internet", "internal", "isolated"]
ENVIRONMENTS = ["production", "staging", "dev/test"]
DATA_VALUES = ["high", "medium", "none"]

BASE = {
    ("active", "internet"): NOW, ("active", "internal"): NOW, ("active", "isolated"): SOON,
    ("likely", "internet"): NOW, ("likely", "internal"): SOON, ("likely", "isolated"): TRACK,
    ("possible", "internet"): SOON, ("possible", "internal"): TRACK, ("possible", "isolated"): DEFER,
    ("unlikely", "internet"): TRACK, ("unlikely", "internal"): DEFER, ("unlikely", "isolated"): DEFER,
}

# Names that appear differently in descriptions than in an inventory
ALIASES = {
    "microsoft windows server": ["windows kernel", "windows smb", "windows ntlm", "windows tcp ip", "windows server"],
    "microsoft windows 11": ["windows 11"],
    "microsoft exchange server": ["exchange server"],
    "microsoft sharepoint": ["sharepoint server"],
    "fortios": ["fortigate"],
    "fortra goanywhere": ["goanywhere"],
    "pan os": ["palo alto networks pan os"],
    "ivanti epmm": ["endpoint manager mobile"],
    "sharefile": ["storage zones controller"],
}


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", str(s).lower()).strip()


# ---------- the decision
def impact_of(environment: str, data_value: str) -> str:
    if environment == "production":
        return "high" if data_value == "high" else "medium"
    return "medium" if data_value == "high" else "low"


def exploitation_tier(rank: int, n: int, on_kev: bool = False) -> str:
    if on_kev:
        return "active"
    return "likely" if rank <= round(n * 0.01) else "possible" if rank <= round(n * 0.10) else "unlikely"


def _table(exploitation: str, exposure: str, impact: str) -> int:
    level = BASE[(exploitation, exposure)]
    if impact == "low":
        level -= 1
    elif impact == "high" and exposure != "isolated" and exploitation != "unlikely":
        level += 1
    return max(DEFER, min(NOW, level))


def decide(exploitation: str, exposure: str, environment: str, data_value: str) -> tuple[int, str | None]:
    """Priority level and which guardrail changed it, if any."""
    impact = impact_of(environment, data_value)
    level = _table(exploitation, exposure, impact)
    if exploitation == "active" and (exposure == "internet" or environment == "production"):  # G1
        return NOW, ("G1" if level != NOW else None)
    if exposure == "isolated":  # G2: at most two levels below the same asset if it were exposed
        floor = decide(exploitation, "internet", environment, data_value)[0] - 2
        if level < floor:
            return floor, "G2"
    return level, None


def explain(rank: int, exploitation: str, a: dict, level: int, guardrail: str | None) -> str:
    why = {"active": "on CISA's KEV list", "likely": f"in the top 1% of our ranking (#{rank:,})",
           "possible": f"in the top 10% of our ranking (#{rank:,})",
           "unlikely": f"outside the top 10% of our ranking (#{rank:,})"}[exploitation]
    place = {"internet": "internet-facing", "internal": "internal", "isolated": "isolated"}[a["exposure"]]
    data = {"high": "sensitive data", "medium": "some business data", "none": "no sensitive data"}[a["data_value"]]
    text = f"{LEVELS[level]}: {why}, and it runs on {a['asset']} ({place}, {a['environment']}, {data})."
    if guardrail == "G1":
        text += " Kept at Act now because it is confirmed exploited and exposed or in production."
    if guardrail == "G2":
        text += " Not lowered further: isolation is often wrong in practice."
    return text


# ---------- the inventory
def validate_inventory(df: pd.DataFrame) -> list[str]:
    """Plain-English problems with an inventory; empty when it's usable."""
    missing = [c for c in COLUMNS if c not in df.columns]
    if missing:
        return ["Missing column(s): " + ", ".join(missing)]
    problems = []
    for col, allowed in (("exposure", EXPOSURES), ("environment", ENVIRONMENTS), ("data_value", DATA_VALUES)):
        bad = sorted(set(df[col].fillna("(blank)").astype(str)) - set(allowed))
        if bad:
            problems.append(f"`{col}` must be one of {', '.join(allowed)}. Found: {', '.join(bad)}")
    if df.asset.isna().any() or df.software.isna().any():
        problems.append("Every row needs an `asset` and `software`.")
    if df.asset.duplicated().any():
        problems.append("Asset names must be unique.")
    return problems


def load_sample() -> pd.DataFrame:
    return pd.read_csv(SAMPLE)


# ---------- matching vulnerabilities to assets
def build_lookup() -> pd.DataFrame:
    """One row per vulnerability in the queue: normalised description, product list and KEV status."""
    from src.load import load  # only needed at build time
    q = pd.read_parquet(APP / "queue.parquet", columns=["cve_id", "rank", "description"])
    cp = load("affected_products", ["cve_id", "vendor", "product", "vulnerable"])
    cp = cp[cp.cve_id.isin(q.cve_id) & (cp.vulnerable == "Y")]
    names = (cp.vendor.astype(str) + " " + cp["product"].astype(str)).map(_norm)
    cpe = names.groupby(cp.cve_id).agg(lambda s: " | ".join(sorted(set(s))))
    kev = load("known_exploited", ["cve_id"]).cve_id
    out = q.assign(text=q.description.map(_norm), products=q.cve_id.map(cpe).fillna(""), on_kev=q.cve_id.isin(kev))
    return out[["cve_id", "rank", "text", "products", "on_kev"]]


def software_items(software: str) -> list[str]:
    return [x.strip() for x in str(software).split(";") if x.strip()]


def match(inventory: pd.DataFrame, lookup: pd.DataFrame) -> pd.DataFrame:
    """Every (vulnerability, asset, software) that matches, on the product list or in the description."""
    frames = []
    cache: dict[str, pd.Series] = {}
    for a in inventory.to_dict("records"):
        for item in software_items(a["software"]):
            key = _norm(item)
            if key not in cache:
                terms = [key] + ALIASES.get(key, [])
                pat = re.compile(r"\b(?:" + "|".join(re.escape(t) for t in terms) + r")\b")
                cache[key] = lookup.text.str.contains(pat) | lookup.products.str.contains(pat)
            hit = lookup.loc[cache[key], ["cve_id"]]
            if len(hit):
                frames.append(hit.assign(asset=a["asset"], software=item))
    if not frames:
        return pd.DataFrame(columns=["cve_id", "asset", "software"])
    return pd.concat(frames, ignore_index=True).drop_duplicates(["cve_id", "asset"])


def assess(inventory: pd.DataFrame, lookup: pd.DataFrame) -> pd.DataFrame:
    """Priority for every vulnerability-asset pair."""
    n = len(lookup)
    m = match(inventory, lookup)
    if m.empty:
        return m.assign(rank=[], level=[], priority=[], guardrail=[], reason=[])
    info = lookup.set_index("cve_id")
    assets = inventory.set_index("asset").to_dict("index")
    rows = []
    for r in m.itertuples(index=False):
        rank, kev = int(info.at[r.cve_id, "rank"]), bool(info.at[r.cve_id, "on_kev"])
        a = {**assets[r.asset], "asset": r.asset}
        tier = exploitation_tier(rank, n, kev)
        level, guard = decide(tier, a["exposure"], a["environment"], a["data_value"])
        rows.append({"cve_id": r.cve_id, "asset": r.asset, "software": r.software, "rank": rank, "exploitation": tier,
                     "exposure": a["exposure"], "environment": a["environment"], "data_value": a["data_value"],
                     "level": level, "priority": LEVELS[level], "guardrail": guard,
                     "reason": explain(rank, tier, a, level, guard)})
    return pd.DataFrame(rows)


def highest_per_vulnerability(pairs: pd.DataFrame) -> pd.DataFrame:
    """G3: one row per vulnerability, at its highest priority; ties go to the first-listed asset."""
    if pairs.empty:
        return pairs.assign(n_assets=[])
    counts = pairs.groupby("cve_id").asset.nunique().rename("n_assets")
    top = pairs.sort_values(["level", "asset"], ascending=[False, True]).drop_duplicates("cve_id")
    return top.join(counts, on="cve_id").sort_values(["level", "rank"], ascending=[False, True]).reset_index(drop=True)


if __name__ == "__main__":
    lk = build_lookup()
    lk.to_parquet(APP / "asset_lookup.parquet", index=False)
    inv = load_sample()
    assert not validate_inventory(inv), validate_inventory(inv)
    p = assess(inv, lk)
    v = highest_per_vulnerability(p)
    print(f"{len(p):,} vulnerability-asset pairs, {len(v):,} vulnerabilities, {p.guardrail.notna().sum()} guardrail changes")
    print(v.priority.value_counts().to_dict())
