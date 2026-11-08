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
sys.path[:0] = [str(ROOT), str(ROOT / "app")]
from splash import splash_html  # noqa: E402
from src.assets import (DATA_VALUES, DEFER, ENVIRONMENTS, EXPOSURES, LEVELS, assess,  # noqa: E402
                        highest_per_vulnerability, load_sample, validate_inventory)

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


@st.cache_data
def load_lookup() -> pd.DataFrame:
    return pd.read_parquet(DATA / "asset_lookup.parquet")


@st.cache_data(show_spinner="Matching vulnerabilities to your assets...")
def assess_inventory(inventory: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    pairs = assess(inventory, load_lookup())
    return pairs, highest_per_vulnerability(pairs)


@st.cache_resource(show_spinner="Starting Ask the Data...")
def get_asker():
    """None when the database isn't running; the rest of the app still works."""
    try:
        from src.ask_the_data.ask import Asker
        asker = Asker()
        asker.embed("warm up")  # so the first real question is fast
        return asker
    except Exception:
        return None


if not (DATA / "queue.parquet").exists() or not (DATA / "asset_lookup.parquet").exists():
    st.error("App data not found. Build it first: `uv run python -m src.app_data`, then `uv run python -m src.assets`")
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
    if r.granite:
        st.caption(f"Read by IBM Granite: **{r.granite}**. Context only, not used in the rank.")
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

tab_queue, tab_env, tab_ask, tab_evidence = st.tabs(["Fix queue", "My environment", "Ask the data", "Evidence"])

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
                table[["rank", "cve_id", "vendor", "granite", "exploit_code", "epss_rank", "cvss_rank", "what"]],
                hide_index=True, width="stretch", height=560, on_select="rerun", selection_mode="single-row", key="queue_table",
                column_config={
                    "rank": st.column_config.NumberColumn("Rank", format="%d", width="small"),
                    "cve_id": st.column_config.TextColumn("CVE", width="small"),
                    "vendor": st.column_config.TextColumn("Vendor", width="small"),
                    "granite": st.column_config.TextColumn("Type (Granite)", width="medium", help="Product and attack type IBM Granite read from the description. Context only, not used in the rank."),
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

with tab_env:
    st.subheader("What should this environment fix first?")
    st.write("The Fix queue says how likely an attack is anywhere. This view adds where each vulnerability runs in your environment.")
    upload = st.file_uploader("Upload an asset inventory (CSV)", type="csv",
                              help="Columns: asset, owner, software (separated by ;), exposure, environment, data_value")
    inventory = pd.read_csv(upload) if upload else load_sample()
    problems = validate_inventory(inventory)
    if not upload:
        st.info("Showing a **made-up sample inventory**, for demonstration only. Upload your own to replace it.")
    if problems:
        for p in problems:
            st.error(p)
    else:
        with st.expander(f"Asset inventory ({len(inventory)} assets): change a value to see the effect"):
            inventory = st.data_editor(
                inventory, hide_index=True, width="stretch", disabled=["asset"], key=f"inventory_{upload.name if upload else 'sample'}",
                column_config={"exposure": st.column_config.SelectboxColumn("Exposure", options=EXPOSURES, required=True),
                               "environment": st.column_config.SelectboxColumn("Environment", options=ENVIRONMENTS, required=True),
                               "data_value": st.column_config.SelectboxColumn("Data value", options=DATA_VALUES, required=True)})
        pairs, vulns = assess_inventory(inventory)
        if vulns.empty:
            st.warning("None of this inventory's software matches a vulnerability in the queue. Check the software names.")
        else:
            counts = vulns.priority.value_counts()
            tiles = st.columns(5)
            for tile, name in zip(tiles, reversed(LEVELS)):
                tile.metric(name, f"{counts.get(name, 0):,}")
            tiles[4].metric("Not in your inventory", f"{N - len(vulns):,}", help="Still ranked in the Fix queue. Nothing is hidden.")

            capacity = st.slider("How many can your team fix next?", 5, 100, 20, 5)
            before = vulns.sort_values("rank").head(capacity)
            after = vulns.head(capacity)  # already sorted by priority, then rank
            left_out = before[~before.cve_id.isin(after.cve_id)]
            moved_up = after[~after.cve_id.isin(before.cve_id)]
            deferred = int((before.level == DEFER).sum())
            summary = f"**Asset context changes {len(moved_up)} of your next {capacity} fixes.**"
            if deferred:
                summary += f" {deferred} of the highest-ranked {'is' if deferred == 1 else 'are'} deferred because {'it only touches' if deferred == 1 else 'they only touch'} isolated, low-value systems."
            if len(moved_up):
                summary += f" {len(moved_up)} lower-ranked {'vulnerability moves' if len(moved_up) == 1 else 'vulnerabilities move'} up because of where {'it runs' if len(moved_up) == 1 else 'they run'}."
            st.markdown(summary)

            desc = queue.set_index("cve_id").description
            def fix_table(df: pd.DataFrame) -> pd.DataFrame:
                return df.assign(what=df.cve_id.map(desc).str.slice(0, 90))[["priority", "rank", "cve_id", "asset", "n_assets", "what", "reason"]]
            config = {"priority": st.column_config.TextColumn("Priority", width="small"),
                      "rank": st.column_config.NumberColumn("Rank", format="%d", width="small"),
                      "cve_id": st.column_config.TextColumn("CVE", width="medium"),
                      "asset": st.column_config.TextColumn("Most exposed asset", width="medium"),
                      "n_assets": st.column_config.NumberColumn("Assets", format="%d", width="small"),
                      "what": st.column_config.TextColumn("What it is", width="medium"),
                      "reason": st.column_config.TextColumn("Why", width="large")}
            st.markdown(f"**Your next {capacity} fixes, with your environment**")
            st.dataframe(fix_table(after), hide_index=True, width="stretch", column_config=config)
            st.markdown(f"**For comparison: the next {capacity} by attack ranking alone**")
            st.dataframe(fix_table(before), hide_index=True, width="stretch", column_config=config)
            st.caption("Priority uses an SSVC-style decision table. A vulnerability confirmed on KEV and exposed or in production is always Act now, "
                       "and being isolated lowers priority by at most two levels. Vulnerabilities on several assets take the highest priority.")

with tab_ask:
    st.subheader("Ask about the top 500 and your assets")
    st.caption("Answers come from SQL written by IBM Granite and run read-only on Tiger Data. Assets are the made-up sample inventory.")
    asker = get_asker()
    if asker is None:
        st.warning("The database isn't running. Start Docker and the `breachpoint-db` container, then reload.")
    else:
        examples = ["How many vulnerabilities in the top 500 have public exploit code?", "Which vendor has the most vulnerabilities?",
                    "What should the IT team fix first?", "Which asset has the most findings?"]
        picked = st.pills("Try one", examples, key="ask_example")
        with st.form("ask_form", clear_on_submit=True):
            typed = st.text_input("Your question", placeholder="For example: which assets are internet-facing?")
            sent = st.form_submit_button("Ask", type="primary")
        new_pick = picked if picked != st.session_state.get("ask_last_pick") else None  # a selected pill counts once
        st.session_state.ask_last_pick = picked
        question = typed.strip() if sent and typed.strip() else new_pick
        history = st.session_state.setdefault("ask_history", [])
        if question:
            with st.spinner("Thinking..."):
                try:
                    history.insert(0, {"question": question, **asker.ask(question)})
                except Exception as e:
                    reason = "Granite isn't reachable, so only questions already answered can be used." \
                        if type(e).__name__ in ("APIConnectionError", "APITimeoutError") else "I couldn't write working SQL for that. Try rephrasing it."
                    history.insert(0, {"question": question, "error": reason})
        for item in history[:10]:
            st.markdown(f"**{item['question']}**")
            if "error" in item:
                st.warning(item["error"])
                continue
            st.write(item["answer"])
            how = f"From cache ({item['latency_ms']:.0f} ms, similar to: {item['matched']})" if item["source"] == "cache" \
                else f"Written by Granite ({item['latency_ms'] / 1000:.1f} s)"
            st.caption(how)
            with st.expander("Show the SQL and data"):
                st.code(item["sql"], language="sql")
                st.dataframe(pd.DataFrame(item["rows"], columns=item["columns"]), hide_index=True, width="stretch")

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

    granite = meta.get("granite")
    if granite:
        st.divider()
        st.subheader("Did IBM Granite's reading of the descriptions improve the ranking?")
        st.write("No. Granite read about 32,000 descriptions, highest priority first, and we used its fields to re-rank the top 10% of each "
                 "test year. That found no more than the simpler model, so the submitted ranking doesn't use them.")
        compare = [{"Method": "BreachPoint (submitted)", f"Found in top {y['k']}": y["hits"]["BreachPoint"],
                    "95% range": f"{y['ranges']['BreachPoint'][0]}–{y['ranges']['BreachPoint'][1]}"}]
        compare += [{"Method": f"Re-ranked with Granite ({r['model'].removeprefix('v2 ')})", f"Found in top {y['k']}": r["hits"], "95% range": r["range"]}
                    for r in granite["years"][year]]
        st.dataframe(pd.DataFrame(compare), hide_index=True, width="content")

        st.markdown("**Where attacks landed, by what Granite read**")
        rate_config = {"name": st.column_config.TextColumn("Group", width="medium"), "read": st.column_config.NumberColumn("Read", format="%d"),
                       "later_exploited": st.column_config.NumberColumn("Later exploited", format="%d"),
                       "per_10k": st.column_config.NumberColumn("Per 10,000", format="%.0f")}
        left, right = st.columns(2, gap="large")
        for col, key, title in ((left, "category", "Product type"), (right, "attack", "Attack type")):
            col.markdown(f"*{title}*")
            col.dataframe(pd.DataFrame(granite["rates"][key]), hide_index=True, width="stretch", height=35 * (len(granite["rates"][key]) + 1) + 3, column_config=rate_config)
        st.caption("2024–25 vulnerabilities Granite read, which are the higher-scoring 19% of each year. Groups of at least 100 shown. "
                   "Counts are small, so treat these as description, not prediction.")
