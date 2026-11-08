"""Build everything the triage app reads, so the app itself needs no model and no network.

Writes to outputs/app/:
  queue.parquet       one row per 2026 vulnerability: rank, score, ranks under EPSS and CVSS, and reasons
  validation.parquet  hits vs K for the model and the 3 baselines, on years the model did not train on
  meta.json           model name, the numbers behind the Evidence tab

The app knows nothing about the model: it renders `reasons` (plain English + signed weight) and
`reason_line`. When v2 is chosen, only this file changes.

Usage: uv run python -m src.app_data
"""
from __future__ import annotations

import json

import numpy as np
import pandas as pd

from src.cohort import OUT
from src.evaluate import baseline_scores, bootstrap, hits_at_k, hits_curve, scaled_k
from src.features import _assigner_domain, _kev_vendor_patterns, _match_vendors, _norm
from src.load import load
from src.v1_LightGBM.train import CORE, LogReg, load_sets

APP = OUT / "app"
MODEL_NAME = "v1 logistic regression on 11 core features, trained on 2024 + 2025"
FLAG_NAMES = {"poc_github": "GitHub proof of concept", "nuclei": "Nuclei template",
              "metasploit": "Metasploit module", "exploitdb": "Exploit-DB entry"}
GROUPS = {"exploit": ["any_flag", "n_flags", "poc_github", "nuclei", "metasploit", "exploitdb"],
          "epss": ["epss_pct"], "assigner": ["assigner_kev_rate"],
          "vendor": ["vendor_kev_rate", "vendor_kev_hist"], "product": ["kev_product_named"]}


def contributions(m: LogReg, df: pd.DataFrame) -> pd.DataFrame:
    """Each feature's push on the log-odds: for a linear model this is the exact SHAP-style attribution."""
    scaler, lr = m.model[0], m.model[-1]
    z = scaler.transform(m._X(df))
    c = pd.DataFrame(z * lr.coef_[0], columns=m.cols, index=df.index)
    return pd.DataFrame({g: c[cols].sum(axis=1) for g, cols in GROUPS.items()})


def reason_text(group: str, r, avg_rate: float) -> str:
    if group == "exploit":
        found = [n for c, n in FLAG_NAMES.items() if r[c] == 1]
        return "Public exploit code exists: " + ", ".join(found) if found else "No public exploit code yet"
    if group == "epss":
        return "No EPSS score yet" if pd.isna(r.epss_pct) else \
            f"EPSS is in the top {max(1 - r.epss_pct, 0.01):.0%} of vulnerabilities in its month"
    if group == "assigner":
        return f"Assigner's past KEV rate is {r.assigner_kev_rate / avg_rate:.1f}× the average"
    if group == "vendor":
        return f"{r.vendor} had {r.vendor_kev_hist:.0f} vulnerabilities on KEV by Dec 31, 2025" if r.vendor \
            else "No vendor with KEV history named in the description"
    return "Names a product already on KEV" if r.kev_product_named else "Names no product already on KEV"


def main():
    APP.mkdir(parents=True, exist_ok=True)
    sets = load_sets()
    both = pd.concat([sets[2024], sets[2025]], ignore_index=True)
    model = LogReg(CORE).fit(both, both.label.to_numpy(int))

    q = sets[2026].copy()
    info = load("vulnerabilities", ["cve_id", "description", "assigner", "attack_vector"]).set_index("cve_id")
    info = info.loc[q.cve_id]
    q["description"] = info.description.to_numpy()
    q["attack_vector"] = info.attack_vector.astype(object).where(info.attack_vector.notna(), "Unknown").to_numpy()
    dom = _assigner_domain(info.assigner).to_numpy()
    q["assigned_by"] = [d if "." in d else "" for d in dom]

    # Vendor shown = the KEV vendor named in the description with the longest KEV record
    kev = load("known_exploited", ["cve_id", "vendor", "date_added"])
    pats = _kev_vendor_patterns(kev)
    counts = kev.groupby("vendor").size()
    names = _match_vendors(q.description.map(_norm), pats)
    q["vendor"] = [max(n, key=lambda v: counts.get(v, 0)) if n else "" for n in names]

    q["score"] = model.predict(q)
    q["rank"] = q.score.rank(ascending=False, method="first").astype(int)
    q["epss_rank"] = q.epss.rank(ascending=False, method="min", na_option="bottom").astype(int)
    q["cvss_rank"] = q.baseline_cvss3.rank(ascending=False, method="min", na_option="bottom").astype(int)
    q["exploit_code"] = [", ".join(n for c, n in FLAG_NAMES.items() if r[c] == 1)
                         for r in q[list(FLAG_NAMES)].to_dict("records")]

    c = contributions(model, q)
    avg = q.assigner_kev_rate.mean()
    reasons, lines = [], []
    for i, r in enumerate(q.itertuples(index=False)):
        rs = sorted(((abs(c[g].iat[i]), g) for g in GROUPS), reverse=True)
        items = []
        for _, g in rs:
            d = {k: getattr(r, k) for k in ("epss_pct", "assigner_kev_rate", "vendor", "vendor_kev_hist",
                                              "kev_product_named", *FLAG_NAMES)}
            items.append({"text": reason_text(g, pd.Series(d), avg), "weight": round(float(c[g].iat[i]), 3)})
        reasons.append(json.dumps(items))
        ups = [x["text"] for x in items if x["weight"] > 0][:2]
        lines.append(("Ranked here mainly because: " + "; ".join(ups) + ".") if ups else
                     "Nothing in this vulnerability's signals stands out.")
    q["reasons"], q["reason_line"] = reasons, lines

    keep = ["rank", "cve_id", "score", "published", "vendor", "assigned_by", "attack_vector", "description",
            "exploit_code", "epss", "epss_rank", "baseline_cvss3", "cvss_rank", "reasons", "reason_line"]
    q[keep].rename(columns={"baseline_cvss3": "cvss"}).sort_values("rank").to_parquet(APP / "queue.parquet", index=False)

    # Evidence: only years the model did not train on
    frames, summary = [], {}
    for tr, te in ((2024, 2025), (2025, 2024)):
        t = sets[te]
        m = LogReg(CORE).fit(sets[tr], sets[tr].label.to_numpy(int))
        sc = {"BreachPoint": m.predict(t), **baseline_scores(t)}
        frames.append(hits_curve(t, sc).reset_index().assign(year=te, trained_on=tr))
        y = t.label.to_numpy(int)
        k = scaled_k(len(t))
        summary[str(te)] = {"trained_on": tr, "k": k, "rows": len(t), "positives": int(y.sum()),
                            "hits": {n: hits_at_k(y, s, k) for n, s in sc.items()},
                            "ranges": {n: [int(v) for v in bootstrap(y, s, k)] for n, s in sc.items()}}
    pd.concat(frames, ignore_index=True).to_parquet(APP / "validation.parquet", index=False)
    json.dump({"model": MODEL_NAME, "rows": len(q), "kev_through": "Dec 31, 2025", "years": summary},
              open(APP / "meta.json", "w"), indent=1)
    print("wrote", APP, summary)


if __name__ == "__main__":
    main()
