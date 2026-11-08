"""Phase 3: features, built only from what was known at each row's snapshot.

Rule (decision D13): every KEV-based feature for cohort year Y uses KEV entries added on or
before Dec 31 of Y-1, and history counts use vulnerabilities published on or before Dec 31 of Y-1.
That gives training the same blind spot the 2026 scoring has (our KEV file ends Dec 31, 2025).

Safe feature groups: exploit signals, timing, who (assigner), vendor history, description text,
vendor (CNA) CVSS 3. Leaky columns are built separately with a `leak_` prefix, only for the
leakage experiment (Phase 6 #1). Never train the submitted model on them.

Usage: uv run python -m src.features
"""
from __future__ import annotations

import re

import numpy as np
import pandas as pd

from src.cohort import FLAGS, OUT
from src.load import load

NIST = "nvd@nist.gov"
CISA = "134c704f-9b21-4f2e-91b3-4a467353bcc0"

KEYWORDS = {
    "kw_rce": r"remote code execution|execute arbitrary code|arbitrary code execution|code execution",
    "kw_cmd_injection": r"command injection|os command|arbitrary (?:os |system |shell )?commands?",
    "kw_auth_bypass": r"authentication bypass|bypass(?:es|ing)? (?:the )?authentication|auth(?:entication)? bypass|missing authentication",
    "kw_unauth": r"unauthenticated|without authentication|remote,? unauthenticated|no authentication",
    "kw_sqli": r"sql injection",
    "kw_deserialization": r"deserializ",
    "kw_path_traversal": r"path traversal|directory traversal|arbitrary file (?:read|write|deletion)",
    "kw_file_upload": r"file upload|upload arbitrary",
    "kw_ssrf": r"server-side request forgery|\bssrf\b",
    "kw_priv_esc": r"privilege escalation|elevat(?:e|ion of|ed) privileges?|escalate privileges",
    "kw_xss": r"cross-site scripting|\bxss\b",
    "kw_csrf": r"cross-site request forgery|\bcsrf\b",
    "kw_dos": r"denial of service|\bdos\b",
    "kw_memory": r"use-after-free|use after free|buffer overflow|out-of-bounds write|heap overflow|type confusion|memory corruption",
    "kw_info_leak": r"information disclosure|sensitive information|information exposure",
    "kw_edge": r"\bvpn\b|firewall|gateway|router|appliance|load balancer|ssl-vpn|remote access",
    "kw_wordpress": r"wordpress|\bplugin\b",
    "kw_remote_attacker": r"remote attackers?|remotely",
    "kw_exploited": r"exploited in the wild|may have been exploited|actively exploited|has been exploited|being exploited",
    "kw_zero_click": r"zero-click|no user interaction",
    "kw_kernel": r"linux kernel|kernel",
    "kw_browser": r"chrome|chromium|webkit|firefox|safari|v8\b",
}

CNA_CVSS_CATS = ["attack_vector", "attack_complexity", "privileges_required", "user_interaction",
                 "scope", "confidentiality_impact", "integrity_impact", "availability_impact"]

# Vendor names that are also ordinary words; skip them when matching descriptions.
VENDOR_STOP = {"progress", "elastic", "n a", "multiple", "unknown", "ds", "php", "wordpress", "git", "meta", "arm"}


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", str(s).lower()).strip()


def _kev_vendor_patterns(kev: pd.DataFrame) -> dict[str, re.Pattern]:
    """One word-boundary pattern per KEV vendor, matched against normalised (lower-case) descriptions."""
    pats = {}
    for v in kev.vendor.dropna().unique():
        n = _norm(v)
        if not n or n in VENDOR_STOP:
            continue
        pats[v] = re.compile(r"\b" + re.escape(n) + r"\b")
    return pats


def _match_vendors(desc_norm: pd.Series, pats: dict[str, re.Pattern]) -> pd.Series:
    """List of KEV vendors named in each description."""
    out = [[] for _ in range(len(desc_norm))]
    for vendor, pat in pats.items():
        hit = desc_norm.str.contains(pat, na=False).to_numpy()
        for i in np.flatnonzero(hit):
            out[i].append(vendor)
    return pd.Series(out, index=desc_norm.index)


def _assigner_domain(a: pd.Series) -> pd.Series:
    a = a.astype(str)
    dom = a.str.extract(r"@([^@]+)$")[0].fillna(a)
    return dom.str.lower()


class Builder:
    """Loads the big tables once; builds features for any cohort year."""

    def __init__(self):
        cols = ["cve_id", "published", "assigner", "description", "cvss3_score", "cvss3_source",
                "cvss3_exploitability_score", "cvss3_impact_score", *CNA_CVSS_CATS,
                "nvd_status", "n_references", "n_affected_cpes", "cwe_ids"]
        self.v = load("vulnerabilities", cols)
        self.v["desc_norm"] = self.v.description.map(_norm)
        self.v["assigner_dom"] = _assigner_domain(self.v.assigner)
        self.kev = load("known_exploited", ["cve_id", "vendor", "product", "date_added"])
        self.pats = _kev_vendor_patterns(self.kev)
        self.sig = load("exploit_signals")
        self._vendor_cache: pd.Series | None = None

    def vendors(self) -> pd.Series:
        """KEV vendors named in each vulnerability's description (computed once for all rows)."""
        if self._vendor_cache is None:
            m = _match_vendors(self.v.desc_norm, self.pats)
            m.index = self.v.cve_id.to_numpy()
            self._vendor_cache = m
        return self._vendor_cache

    def build(self, cohort: pd.DataFrame, year: int, kev_cutoff: pd.Timestamp | None = None) -> pd.DataFrame:
        kev_cutoff = kev_cutoff if kev_cutoff is not None else pd.Timestamp(f"{year - 1}-12-31")
        hist_cutoff = pd.Timestamp(f"{year - 1}-12-31")
        v = self.v.set_index("cve_id")
        df = cohort.copy()
        info = v.loc[df.cve_id]
        info.index = df.index

        # --- exploit signals
        df["epss_pct"] = df.groupby("snapshot_month").epss.rank(pct=True)
        df["epss_log"] = np.log10(df.epss.clip(lower=1e-5))
        df["n_flags"] = df[FLAGS].sum(axis=1)
        df["any_flag"] = (df.n_flags > 0).astype("int8")

        # --- timing
        df["pub_month"] = df.published.dt.month
        df["days_pub_to_snapshot"] = (df.snapshot_end - df.published).dt.days
        df["pub_dow"] = df.published.dt.day_of_week
        id_year = df.cve_id.str.extract(r"CVE-(\d{4})-")[0].astype(int)
        df["id_year_lag"] = df.published.dt.year - id_year

        # --- who: assigner history (published <= Dec 31 Y-1, KEV <= kev_cutoff)
        kev_known = self.kev[self.kev.date_added <= kev_cutoff]
        hist = self.v[self.v.published <= hist_cutoff][["cve_id", "assigner_dom", "published"]].copy()
        hist["is_kev"] = hist.cve_id.isin(kev_known.cve_id)
        hist["recent"] = hist.published > hist_cutoff - pd.Timedelta(days=365)
        a = hist.groupby("assigner_dom").agg(a_n=("is_kev", "size"), a_kev=("is_kev", "sum"),
                                             a_n_recent=("recent", "sum"))
        prior = len(kev_known) / len(hist)
        a["a_kev_rate"] = (a.a_kev + 20 * prior) / (a.a_n + 20)  # smoothed
        dom = info.assigner_dom
        df["assigner_n_hist"] = dom.map(a.a_n).fillna(0).to_numpy()
        df["assigner_n_recent"] = dom.map(a.a_n_recent).fillna(0).to_numpy()
        df["assigner_kev_hist"] = dom.map(a.a_kev).fillna(0).to_numpy()
        df["assigner_kev_rate"] = dom.map(a.a_kev_rate).fillna(prior).to_numpy()
        # Batch size: same assigner, same publish day (Patch Tuesday-style releases). Known by the snapshot.
        same_day = self.v.groupby([self.v.assigner_dom, self.v.published.dt.normalize()]).size()
        key = pd.MultiIndex.from_arrays([dom.to_numpy(), df.published.dt.normalize().to_numpy()])
        df["assigner_same_day"] = same_day.reindex(key).fillna(1).to_numpy()
        # Shift-robust versions: CVE volume roughly triples from July 2026, so raw counts drift.
        # Use shares of the history window and ranks within the snapshot month instead.
        df["assigner_share_hist"] = df.assigner_n_hist / len(hist)
        df["assigner_share_recent"] = df.assigner_n_recent / max(int(hist.recent.sum()), 1)
        df["assigner_same_day_pct"] = df.groupby("snapshot_month").assigner_same_day.rank(pct=True)

        # --- vendor history: KEV vendors named in the description
        vend_all = self.vendors()
        vend = pd.Series(vend_all.loc[df.cve_id].to_numpy(), index=df.index)
        kv_count = kev_known.groupby("vendor").size()
        kv_recent = kev_known[kev_known.date_added > kev_cutoff - pd.Timedelta(days=365)].groupby("vendor").size()
        # vendor CVE volume in history (descriptions naming the vendor)
        hist_mask = (self.v.published <= hist_cutoff).to_numpy()
        vol = pd.Series([x for xs, h in zip(vend_all.to_numpy(), hist_mask) if h for x in xs]).value_counts()
        df["vendor_matched"] = vend.map(len).astype("int8")
        df["vendor_kev_hist"] = vend.map(lambda xs: max((kv_count.get(x, 0) for x in xs), default=0))
        df["vendor_kev_recent"] = vend.map(lambda xs: max((kv_recent.get(x, 0) for x in xs), default=0))
        df["vendor_kev_rate"] = vend.map(
            lambda xs: max(((kv_count.get(x, 0) + 20 * prior) / (vol.get(x, 0) + 20) for x in xs), default=np.nan))
        # KEV product named too (e.g. "FortiOS", "Exchange Server")
        prods = kev_known.assign(p=kev_known["product"].map(_norm)).query("p.str.len() >= 4").groupby("p").size()
        prod_pat = re.compile(r"\b(?:" + "|".join(re.escape(p) for p in prods.index) + r")\b") if len(prods) else None
        dn = info.desc_norm
        df["kev_product_named"] = dn.str.contains(prod_pat, na=False).astype("int8") if prod_pat else 0

        # --- description text
        for name, pat in KEYWORDS.items():
            df[name] = info.description.str.contains(pat, case=False, regex=True, na=False).astype("int8").to_numpy()
        df["desc_len"] = info.description.str.len().fillna(0).to_numpy()

        # --- vendor (CNA) CVSS 3 only (decisions D2, C4)
        src = info.cvss3_source.astype(str)
        cna = info.cvss3_score.notna() & ~src.isin([NIST, CISA])
        df["cna_cvss3"] = info.cvss3_score.where(cna).to_numpy()
        df["cna_cvss3_exploitability"] = info.cvss3_exploitability_score.where(cna).to_numpy()
        df["cna_cvss3_impact"] = info.cvss3_impact_score.where(cna).to_numpy()
        for c in CNA_CVSS_CATS:
            df[f"cna_{c}"] = info[c].astype(str).where(cna, "NA").astype("category").to_numpy()

        # --- leaky columns (Phase 6 #1 only)
        df["leak_nvd_status"] = info.nvd_status.astype(str).astype("category").to_numpy()
        df["leak_n_references"] = info.n_references.to_numpy()
        df["leak_n_affected_cpes"] = info.n_affected_cpes.to_numpy()
        df["leak_cvss3_any"] = info.cvss3_score.to_numpy()
        df["leak_cvss3_source"] = np.select([src == NIST, src == CISA, info.cvss3_score.isna()],
                                            ["nist", "cisa", "none"], "cna")
        df["leak_cvss3_source"] = df.leak_cvss3_source.astype("category")
        df["leak_has_cwe"] = info.cwe_ids.notna().astype("int8").to_numpy()

        # Baseline helper: CVSS 3 as given in vulnerabilities.csv (what the README baseline uses)
        df["baseline_cvss3"] = info.cvss3_score.to_numpy()
        return df


def feature_columns(df: pd.DataFrame, leaky: bool = False) -> list[str]:
    drop = {"cve_id", "published", "cohort_year", "snapshot_month", "snapshot_end", "cutoff",
            "kev_date_added", "label", "baseline_cvss3", "epss_log"}
    cols = [c for c in df.columns if c not in drop]
    return cols if leaky else [c for c in cols if not c.startswith("leak_")]


if __name__ == "__main__":
    b = Builder()
    for name, year in (("train_2024", 2024), ("val_2025", 2025), ("score_2026", 2026)):
        c = pd.read_parquet(OUT / f"{name}.parquet")
        f = b.build(c, year)
        f.to_parquet(OUT / f"features_{name}.parquet", index=False)
        print(f"{name}: {f.shape}, vendor matched {(f.vendor_matched > 0).mean():.2f}, "
              f"CNA CVSS {f.cna_cvss3.notna().mean():.2f}")
    print("safe features:", len(feature_columns(f)))
