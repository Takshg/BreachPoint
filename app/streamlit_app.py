"""BreachPoint triage app.

Run from the repo root:  uv run streamlit run app/streamlit_app.py
Reads only outputs/app/ (built by `uv run python -m src.app_data`), so it works offline.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))
from splash import splash_html  # noqa: E402

DATA = ROOT / "outputs" / "app"
st.set_page_config(page_title="BreachPoint", page_icon="🛡️", layout="wide")

# Same grid, glow and type as the opening screen (app/splash.py)
st.markdown("""<style>
  .stApp { background:
      radial-gradient(circle at 50% -8%, rgba(60,190,230,.17), transparent 55%),
      linear-gradient(rgba(111,233,255,.045) 1px, transparent 1px) 0 0/100% 34px,
      linear-gradient(90deg, rgba(111,233,255,.045) 1px, transparent 1px) 0 0/34px 100%,
      #04070d; }
  header[data-testid="stHeader"] { background:transparent; }
  h1 { font-family:"Avenir Next","Helvetica Neue",Arial,sans-serif !important; font-weight:300 !important; letter-spacing:.14em;
       color:#effcff; text-shadow:0 0 14px rgba(111,233,255,.85),0 0 42px rgba(111,233,255,.45); }
  [data-testid="stMetric"] { background:rgba(12,22,34,.72); border:1px solid rgba(111,233,255,.2); border-radius:8px; padding:10px 16px; }
  [data-testid="stMetricLabel"] p { font-family:ui-monospace,"SF Mono",Menlo,Consolas,monospace; font-size:11px; letter-spacing:.14em; text-transform:uppercase; color:#7fa9b8; }
  .stButton button[kind="primary"], .stButton button[kind="primary"] p { color:#04070d; font-weight:600; }
</style>""", unsafe_allow_html=True)


@st.cache_data
def load_queue() -> pd.DataFrame:
    return pd.read_parquet(DATA / "queue.parquet")


@st.cache_data
def load_validation() -> pd.DataFrame:
    return pd.read_parquet(DATA / "validation.parquet")


@st.cache_data
def load_meta() -> dict:
    return json.loads((DATA / "meta.json").read_text())


if not (DATA / "queue.parquet").exists():
    st.error("App data not found. Build it first: `uv run python -m src.app_data`")
    st.stop()

queue, validation, meta = load_queue(), load_validation(), load_meta()
N = len(queue)
TOP1, TOP10 = round(N * 0.01), round(N * 0.10)


# ---------- opening screen
def show_splash() -> None:
    st.markdown("""<style>
      .stApp { background:#04070d; }
      header[data-testid="stHeader"] { display:none; }
      .block-container { padding:0 0 12px; max-width:100%; }
      iframe { display:block; border:0; }
      .stButton { display:flex; justify-content:center; }
    </style>""", unsafe_allow_html=True)
    ring = f"VULNERABILITY TRIAGE ENGINE  ///  {N:,} RANKED  ///  WHAT TO FIX FIRST  ///  "
    st.iframe(splash_html(ring), height=680)
    _, mid, _ = st.columns([2, 1, 2])
    if mid.button("Enter the fix queue", type="primary", width="stretch"):
        st.session_state.entered = True
        st.rerun()


if not st.session_state.get("entered"):
    show_splash()
    st.stop()


# ---------- shared helpers
def tier(rank: int) -> str:
    return "Top 1%" if rank <= TOP1 else "Top 10%" if rank <= TOP10 else "Rest"


def show_detail(r: pd.Series) -> None:
    st.subheader(r.cve_id)
    st.badge(f"{tier(r['rank'])} · #{r['rank']:,}", color="orange" if r["rank"] <= TOP1 else "blue" if r["rank"] <= TOP10 else "gray")
    st.write(r.reason_line)
    a, b, c = st.columns(3)
    a.metric("Our rank", f"{r['rank']:,}")
    b.metric("EPSS rank", f"{r.epss_rank:,}")
    c.metric("CVSS rank", f"{r.cvss_rank:,}")
    st.markdown("**Why it's ranked here**")
    for x in json.loads(r.reasons):
        if abs(x["weight"]) < 0.05:  # no real effect on this model's score
            continue
        arrow = "▲ raises" if x["weight"] > 0 else "▼ lowers"
        st.markdown(f"- **{arrow}:** {x['text']}")
    st.markdown("**Description**")
    st.write(r.description)
    meta_bits = [f"Published {r.published:%b %d, %Y}", f"Attack vector: {r.attack_vector.title()}"]
    if r.assigned_by:
        meta_bits.append(f"Assigned by {r.assigned_by}")
    st.caption(" · ".join(meta_bits))
    st.link_button("Open in NVD", f"https://nvd.nist.gov/vuln/detail/{r.cve_id}")


# ---------- main app
st.title("BreachPoint")
st.caption(f"{N:,} new 2026 vulnerabilities, ranked by how likely they are to be attacked, using only what was known "
           f"at each one's monthly snapshot. Model: {meta['model']}.")

tab_queue, tab_evidence = st.tabs(["Fix queue", "Evidence"])

with tab_queue:
    f1, f2, f3, f4, f5 = st.columns([2.2, 1.1, 1.8, 1.3, 1.3])
    search = f1.text_input("Search", placeholder="CVE ID or a word in the description")
    scope = f2.selectbox("Show", ["Top 500", "Top 1%", "Top 10%", "All"])
    vendors = f3.multiselect("Vendor", sorted(v for v in queue.vendor.unique() if v))
    months = f4.multiselect("Published", sorted(queue.published.dt.strftime("%Y-%m").unique()))
    vectors = f5.multiselect("Attack vector", sorted(queue.attack_vector.unique()))
    only_code = st.toggle("Only vulnerabilities with public exploit code")

    limit = {"Top 500": 500, "Top 1%": TOP1, "Top 10%": TOP10, "All": N}[scope]
    view = queue[queue["rank"] <= limit]
    if search:
        s = search.strip()
        view = view[view.cve_id.str.contains(s, case=False, regex=False) | view.description.str.contains(s, case=False, regex=False)]
    if vendors:
        view = view[view.vendor.isin(vendors)]
    if months:
        view = view[view.published.dt.strftime("%Y-%m").isin(months)]
    if vectors:
        view = view[view.attack_vector.isin(vectors)]
    if only_code:
        view = view[view.exploit_code != ""]
    view = view.reset_index(drop=True)

    m1, m2, m3 = st.columns(3)
    m1.metric("In this view", f"{len(view):,}")
    m2.metric("With public exploit code", f"{(view.exploit_code != '').sum():,}")
    m3.metric("Outside CVSS's top 5,000", f"{(view.cvss_rank > 5000).sum():,}",
              help="Vulnerabilities in this view that a highest-CVSS-first queue would place below 5,000.")

    if view.empty:
        st.info("Nothing matches these filters.")
    else:
        left, right = st.columns([3, 2], gap="large")
        with left:
            table = view.assign(what=view.description.str.slice(0, 110))
            event = st.dataframe(
                table[["rank", "cve_id", "vendor", "what", "exploit_code", "epss_rank", "cvss_rank"]],
                hide_index=True, width="stretch", height=560, on_select="rerun", selection_mode="single-row", key="queue_table",
                column_config={
                    "rank": st.column_config.NumberColumn("Rank", format="%d", width="small"),
                    "cve_id": st.column_config.TextColumn("CVE", width="medium"),
                    "vendor": st.column_config.TextColumn("Vendor", width="small"),
                    "what": st.column_config.TextColumn("What it is", width="medium"),
                    "exploit_code": st.column_config.TextColumn("Exploit code", width="small"),
                    "epss_rank": st.column_config.NumberColumn("EPSS rank", format="%d", width="small"),
                    "cvss_rank": st.column_config.NumberColumn("CVSS rank", format="%d", width="small"),
                })
            st.caption("Select a row to see why it's ranked there. Vendor is blank when no vendor with KEV history is named in the description.")
        with right:
            picked = event.selection.rows
            i = picked[0] if picked and picked[0] < len(view) else 0
            show_detail(view.iloc[i])

with tab_evidence:
    st.subheader("Does the ranking find what attackers actually hit?")
    year = st.segmented_control("Test year", ["2025", "2024"], default="2025") or "2025"
    y = meta["years"][year]
    st.write(f"Model trained on {y['trained_on']} only, then tested on {int(y['rows']):,} vulnerabilities from {year}, "
             f"of which {y['positives']} were added to CISA's KEV list after their snapshot.")

    wide = validation[validation.year == int(year)].drop(columns=["year", "trained_on"])
    ORDER = ["BreachPoint", "Exploit code, then EPSS", "EPSS first", "CVSS 3 first"]
    dark = st.context.theme.type == "dark"
    PAL = ["#3987e5", "#d95926", "#199e70", "#c98500"] if dark else ["#2a78d6", "#eb6834", "#1baf7a", "#eda100"]
    long = wide.melt(id_vars="K", var_name="Method", value_name="Found")
    x = alt.X("K:Q", title="Vulnerabilities fixed, highest ranked first", axis=alt.Axis(grid=False))
    yy = alt.Y("Found:Q", title="Later-exploited found", axis=alt.Axis(gridOpacity=0.25, domain=False, ticks=False))
    color = alt.Color("Method:N", scale=alt.Scale(domain=ORDER, range=PAL), legend=alt.Legend(orient="top", title=None))
    nearest = alt.selection_point(nearest=True, on="pointerover", fields=["K"], empty=False, clear="pointerout")
    lines = alt.Chart(long).mark_line(strokeWidth=2).encode(x=x, y=yy, color=color)
    hover = alt.Chart(wide).mark_rule(color="#898781").encode(
        x="K:Q", opacity=alt.condition(nearest, alt.value(0.7), alt.value(0)),
        tooltip=[alt.Tooltip("K:Q", title="Fixed")] + [alt.Tooltip(f"{m}:Q") for m in ORDER]).add_params(nearest)
    points = alt.Chart(long).mark_circle(size=70, stroke="#04070d" if dark else "white", strokeWidth=2, opacity=1).encode(x=x, y=yy, color=color).transform_filter(nearest)
    k_line = alt.Chart(pd.DataFrame({"K": [y["k"]], "t": ["Same share as the top 500"]}))
    rule = k_line.mark_rule(strokeDash=[4, 4], color="#898781").encode(x="K:Q")
    rule_text = k_line.mark_text(align="left", dx=6, baseline="top", y=6, color="#898781", fontSize=12).encode(x="K:Q", text="t:N")
    st.altair_chart((lines + rule + rule_text + hover + points).properties(height=360), width="stretch")

    rows = [{"Method": m, f"Found in top {y['k']}": y["hits"][m], "95% range": f"{y['ranges'][m][0]}–{y['ranges'][m][1]}"} for m in ORDER]
    st.dataframe(pd.DataFrame(rows), hide_index=True, width="content")
    st.caption("CVSS 3 first uses the score as published, including NIST-added scores, like the challenge's baseline. "
               "With this few real attacks, the ranges overlap: a difference of a few hits can be luck.")
