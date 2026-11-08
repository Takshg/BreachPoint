"""Evaluate Ask the Data: SQL accuracy against hand-written answers, cache behaviour, and safety.

  uv run python -m src.ask_the_data.evaluate           # full report to outputs/ask_the_data/report.md
  uv run python -m src.ask_the_data.evaluate --prefill # load the verified demo questions into the cache

The test questions are not the prompt's examples. Accuracy runs with the cache off.
Prefilled answers use the hand-written SQL, so cached demo answers are verified.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

import pandas as pd

from src.ask_the_data.ask import Asker, UnsafeSQL, entities, validate_sql
from src.ask_the_data.db import ADMIN_DSN

OUT = Path(__file__).resolve().parents[2] / "outputs" / "ask_the_data"
PO = "CASE f.priority WHEN 'Act now' THEN 1 WHEN 'Act soon' THEN 2 WHEN 'Track' THEN 3 ELSE 4 END"
V = "(vendor ILIKE '%{0}%' OR description ILIKE '%{0}%')"

# (question, hand-written SQL, how to compare: "all" = same rows; "first" = gold row is the first answer)
QUESTIONS = [
    ("How many vulnerabilities in the top 500 have public exploit code?", "SELECT count(*) FROM top500 WHERE has_exploit_code", "all"),
    ("How many have a GitHub proof of concept?", "SELECT count(*) FROM top500 WHERE github_poc", "all"),
    ("How many vulnerabilities have no public exploit code?", "SELECT count(*) FROM top500 WHERE NOT has_exploit_code", "all"),
    ("What is the highest CVSS score in the list?", "SELECT max(cvss) FROM top500", "all"),
    ("What are the top 3 ranked CVEs?", "SELECT cve_id FROM top500 WHERE rank <= 3", "all"),
    ("How many Microsoft vulnerabilities are there?", f"SELECT count(*) FROM top500 WHERE {V.format('microsoft')}", "all"),
    ("Which vendor has the most vulnerabilities?", "SELECT vendor FROM top500 WHERE vendor IS NOT NULL GROUP BY vendor ORDER BY count(*) DESC LIMIT 1", "first"),
    ("How many vulnerabilities were published in May 2026?", "SELECT count(*) FROM top500 WHERE published >= '2026-05-01' AND published < '2026-06-01'", "all"),
    ("Which month had the most vulnerabilities published?", "SELECT to_char(published,'YYYY-MM') FROM top500 GROUP BY 1 ORDER BY count(*) DESC LIMIT 1", "first"),
    ("What is the average EPSS rank of Ivanti vulnerabilities?", f"SELECT avg(epss_rank) FROM top500 WHERE {V.format('ivanti')}", "all"),
    ("How many vulnerabilities can be attacked over the network?", "SELECT count(*) FROM top500 WHERE attack_vector = 'NETWORK'", "all"),
    ("How many local vulnerabilities have public exploit code?", "SELECT count(*) FROM top500 WHERE attack_vector = 'LOCAL' AND has_exploit_code", "all"),
    ("Which vulnerabilities have a Metasploit module?", "SELECT cve_id FROM top500 WHERE metasploit", "all"),
    ("How many of the top 100 are outside the top 5000 by CVSS?", "SELECT count(*) FROM top500 WHERE rank <= 100 AND cvss_rank > 5000", "all"),
    ("What rank is CVE-2026-6875?", "SELECT rank FROM top500 WHERE cve_id = 'CVE-2026-6875'", "all"),
    ("Which organisation assigned the most CVEs?", "SELECT assigned_by FROM top500 WHERE assigned_by IS NOT NULL GROUP BY 1 ORDER BY count(*) DESC LIMIT 1", "first"),
    ("How many Act now findings are there?", "SELECT count(*) FROM asset_findings WHERE priority = 'Act now'", "all"),
    ("Which asset has the most findings?", "SELECT asset FROM asset_findings GROUP BY asset ORDER BY count(*) DESC LIMIT 1", "first"),
    ("Which assets are internet-facing?", "SELECT asset FROM assets WHERE exposure = 'internet'", "all"),
    ("How many findings on isolated assets are deferred?", "SELECT count(*) FROM asset_findings WHERE exposure = 'isolated' AND priority = 'Defer'", "all"),
    ("What should the IT team fix first?", f"SELECT f.cve_id FROM asset_findings f JOIN assets a ON a.asset = f.asset WHERE a.owner = 'IT' ORDER BY {PO}, f.rank LIMIT 1", "first"),
    ("Which CVEs affect edge-fw-01?", "SELECT cve_id FROM asset_findings WHERE asset = 'edge-fw-01'", "all"),
    ("Which isolated assets have findings?", "SELECT DISTINCT asset FROM asset_findings WHERE exposure = 'isolated'", "all"),
    ("How many distinct vulnerabilities affect production assets?", "SELECT count(DISTINCT cve_id) FROM asset_findings WHERE environment = 'production'", "all"),
    ("Which team has the most Act now findings?", "SELECT a.owner FROM asset_findings f JOIN assets a ON a.asset = f.asset WHERE f.priority = 'Act now' GROUP BY a.owner ORDER BY count(*) DESC LIMIT 1", "first"),
    ("How many findings involve Apache Camel?", "SELECT count(*) FROM asset_findings WHERE software ILIKE '%apache camel%'", "all"),
]

# Written after the prompt was tuned on QUESTIONS, and never used for tuning.
HOLDOUT = [
    ("How many vulnerabilities have both a Nuclei template and a GitHub proof of concept?", "SELECT count(*) FROM top500 WHERE nuclei AND github_poc", "all"),
    ("What is the lowest EPSS rank among SonicWall vulnerabilities?", f"SELECT min(epss_rank) FROM top500 WHERE {V.format('sonicwall')}", "all"),
    ("How many vulnerabilities were published in the first quarter of 2026?", "SELECT count(*) FROM top500 WHERE published >= '2026-01-01' AND published < '2026-04-01'", "all"),
    ("How many vulnerabilities have no CVSS score?", "SELECT count(*) FROM top500 WHERE cvss IS NULL", "all"),
    ("Which CVEs in the top 10 have no exploit code?", "SELECT cve_id FROM top500 WHERE rank <= 10 AND NOT has_exploit_code", "all"),
    ("How many vulnerabilities need physical access?", "SELECT count(*) FROM top500 WHERE attack_vector = 'PHYSICAL'", "all"),
    ("How many findings are on staging assets?", "SELECT count(*) FROM asset_findings WHERE environment = 'staging'", "all"),
    ("Which internal assets hold sensitive data?", "SELECT asset FROM assets WHERE exposure = 'internal' AND data_value = 'high'", "all"),
    ("How many Defer findings does the Data team have?", "SELECT count(*) FROM asset_findings f JOIN assets a ON a.asset = f.asset WHERE a.owner = 'Data' AND f.priority = 'Defer'", "all"),
    ("Which software appears in the most findings?", "SELECT software FROM asset_findings GROUP BY software ORDER BY count(*) DESC LIMIT 1", "first"),
    ("How many internal assets does IT own?", "SELECT count(*) FROM assets WHERE owner = 'IT' AND exposure = 'internal'", "all"),
    ("What is the most urgent finding on web-store-01?", f"SELECT f.cve_id FROM asset_findings f WHERE f.asset = 'web-store-01' ORDER BY {PO}, f.rank LIMIT 1", "first"),
    ("How many dev/test assets are there?", "SELECT count(*) FROM assets WHERE environment = 'dev/test'", "all"),
    ("Which CVE has the highest EPSS score?", "SELECT cve_id FROM top500 ORDER BY epss DESC NULLS LAST LIMIT 1", "first"),
]

# Written before any result on them was seen, after the last change to the prompt. Never used for tuning.
FRESH = [
    ("How many vulnerabilities have an Exploit-DB entry?", "SELECT count(*) FROM top500 WHERE exploitdb", "all"),
    ("What are the 4 most urgent CVEs?", "SELECT cve_id FROM top500 WHERE rank <= 4", "all"),
    ("How many Google vulnerabilities have public exploit code?", f"SELECT count(*) FROM top500 WHERE {V.format('google')} AND has_exploit_code", "all"),
    ("What is the average CVSS score in the top 100?", "SELECT avg(cvss) FROM top500 WHERE rank <= 100", "all"),
    ("How many vulnerabilities were published in July or August 2026?", "SELECT count(*) FROM top500 WHERE published >= '2026-07-01' AND published < '2026-09-01'", "all"),
    ("Which CVE published in January 2026 is ranked highest?", "SELECT cve_id FROM top500 WHERE published >= '2026-01-01' AND published < '2026-02-01' ORDER BY rank LIMIT 1", "first"),
    ("How many assets are internet-facing and in production?", "SELECT count(*) FROM assets WHERE exposure = 'internet' AND environment = 'production'", "all"),
    ("Which production assets have a data value of none?", "SELECT asset FROM assets WHERE environment = 'production' AND data_value = 'none'", "all"),
    ("Which teams own isolated assets?", "SELECT DISTINCT owner FROM assets WHERE exposure = 'isolated'", "all"),
    ("How many Act soon findings are on internal assets?", "SELECT count(*) FROM asset_findings WHERE priority = 'Act soon' AND exposure = 'internal'", "all"),
    ("Which asset has the most Act now findings?", "SELECT asset FROM asset_findings WHERE priority = 'Act now' GROUP BY asset ORDER BY count(*) DESC LIMIT 1", "first"),
    ("How many findings does the Web team have?", "SELECT count(*) FROM asset_findings f JOIN assets a ON a.asset = f.asset WHERE a.owner = 'Web'", "all"),
    ("What is the lowest CVSS score?", "SELECT min(cvss) FROM top500", "all"),
    ("List the findings on mft-prod-01", "SELECT cve_id FROM asset_findings WHERE asset = 'mft-prod-01'", "all"),
]

# Written after the last prompt change, aimed at the known weakness of picking the wrong table. Never used for tuning.
FRESH_CROSS_TABLE = [
    ("Which Microsoft vulnerabilities in the top 150 have a GitHub proof of concept?", f"SELECT cve_id FROM top500 WHERE rank <= 150 AND {V.format('microsoft')} AND github_poc", "all"),
    ("How many Fortinet vulnerabilities have no exploit code?", f"SELECT count(*) FROM top500 WHERE {V.format('fortinet')} AND NOT has_exploit_code", "all"),
    ("What is the highest CVSS score among Apache vulnerabilities?", f"SELECT max(cvss) FROM top500 WHERE {V.format('apache')}", "all"),
    ("Which Ivanti vulnerabilities can be attacked over the network?", f"SELECT cve_id FROM top500 WHERE {V.format('ivanti')} AND attack_vector = 'NETWORK'", "all"),
    ("How many of the top 50 were assigned by github.com?", "SELECT count(*) FROM top500 WHERE rank <= 50 AND assigned_by = 'github.com'", "all"),
    ("How many Apache findings are on production assets?", "SELECT count(*) FROM asset_findings WHERE software ILIKE '%apache%' AND environment = 'production'", "all"),
    ("Which assets are affected by Microsoft Exchange Server?", "SELECT DISTINCT asset FROM asset_findings WHERE software ILIKE '%exchange%'", "all"),
    ("How many assets does the Integration team own?", "SELECT count(*) FROM assets WHERE owner = 'Integration'", "all"),
    ("Which team owns edge-fw-01?", "SELECT owner FROM assets WHERE asset = 'edge-fw-01'", "all"),
    ("How many Track findings are on staging assets?", "SELECT count(*) FROM asset_findings WHERE priority = 'Track' AND environment = 'staging'", "all"),
]

# Written after owner was added to asset_findings, for the failure that change targets. Never used for tuning.
FRESH_TEAMS = [
    ("How many Act soon findings does the Network team have?", "SELECT count(*) FROM asset_findings WHERE owner = 'Network' AND priority = 'Act soon'", "all"),
    ("Which CVEs does the Integration team have on production assets?", "SELECT DISTINCT cve_id FROM asset_findings WHERE owner = 'Integration' AND environment = 'production'", "all"),
    ("How many findings does each team have?", "SELECT owner, count(*) FROM asset_findings GROUP BY owner", "all"),
    ("Which team has the fewest findings?", "SELECT owner FROM asset_findings GROUP BY owner ORDER BY count(*) ASC LIMIT 1", "first"),
    ("How many isolated assets are there?", "SELECT count(*) FROM assets WHERE exposure = 'isolated'", "all"),
    ("How many assets have high data value?", "SELECT count(*) FROM assets WHERE data_value = 'high'", "all"),
]

# (a question in the cache, a rewording that should reuse it)
SHOULD_HIT = [
    ("How many Act now findings are there?", "How many findings are Act now?"),
    ("Which assets are internet-facing?", "Which of the assets are internet-facing?"),
    ("Which asset has the most findings?", "Which asset has the most findings overall?"),
    ("What is the highest CVSS score in the list?", "What is the highest CVSS score on the list?"),
    ("How many vulnerabilities were published in May 2026?", "How many of the vulnerabilities were published in May 2026?"),
]
# Harder, natural rewordings: measured, not required. A miss only costs a Granite call.
NATURAL = [
    ("How many vulnerabilities in the top 500 have public exploit code?", "What number of the top 500 have public exploit code available?"),
    ("Which vendor has the most vulnerabilities?", "Which vendor shows up the most in the list?"),
    ("Which assets are internet-facing?", "List the assets exposed to the internet"),
    ("How many Act now findings are there?", "Count the findings marked Act now"),
    ("What should the IT team fix first?", "What is the first thing the IT team should patch?"),
    ("Which asset has the most findings?", "What asset is affected by the most vulnerabilities?"),
    ("How many vulnerabilities have no public exploit code?", "How many vulnerabilities are missing exploit code?"),
    ("Which month had the most vulnerabilities published?", "In which month were the most vulnerabilities published?"),
]
# (a question in the cache, a similar question that needs a DIFFERENT answer)
MUST_MISS = [
    ("How many have a GitHub proof of concept?", "How many have a Nuclei template?"),
    ("How many vulnerabilities were published in May 2026?", "How many vulnerabilities were published in June 2026?"),
    ("What are the top 3 ranked CVEs?", "What are the top 5 ranked CVEs?"),
    ("How many Microsoft vulnerabilities are there?", "How many Apache vulnerabilities are there?"),
    ("How many findings on isolated assets are deferred?", "How many findings on internal assets are deferred?"),
    ("How many vulnerabilities have no public exploit code?", "How many vulnerabilities have public exploit code?"),
    ("What rank is CVE-2026-6875?", "What rank is CVE-2026-39808?"),
    ("How many Act now findings are there?", "How many Act soon findings are there?"),
    ("Which asset has the most findings?", "Which asset has the fewest findings?"),
    ("What should the IT team fix first?", "What should the Web team fix first?"),
]
ATTACKS = ["DROP TABLE top500", "DELETE FROM top500", "UPDATE top500 SET rank = 1", "INSERT INTO assets VALUES ('a')",
           "SELECT * FROM qa_cache", "SELECT * FROM pg_shadow", "SELECT * FROM pg_catalog.pg_roles",
           "SELECT pg_sleep(60)", "SELECT pg_read_file('/etc/passwd')", "SELECT 1; DROP TABLE top500",
           "CREATE TABLE x (a int)", "SELECT * INTO x FROM top500", "COPY top500 TO '/tmp/x'",
           "WITH d AS (DELETE FROM top500 RETURNING *) SELECT * FROM d"]


def norm(v):
    if v is None:
        return None
    if isinstance(v, bool):
        return v
    try:
        return round(float(v), 2)
    except (TypeError, ValueError):
        return str(v).strip().lower()


def matches(gold_cols, gold_rows, rows, mode) -> bool:
    """Right if every gold column appears in the answer with the same values. Extra columns are fine."""
    if not rows or not gold_rows:
        return not rows and not gold_rows
    if mode == "first":
        return all(norm(g) in {norm(c) for c in rows[0]} for g in gold_rows[0])
    if len(rows) != len(gold_rows):
        return False
    pred = [sorted((norm(r[i]) for r in rows), key=str) for i in range(len(rows[0]))]
    return all(sorted((norm(r[i]) for r in gold_rows), key=str) in pred for i in range(len(gold_rows[0])))


def prefill(a: Asker) -> int:
    import psycopg
    with psycopg.connect(ADMIN_DSN, autocommit=True) as c:
        c.execute("TRUNCATE qa_cache")
    for q, sql, _ in QUESTIONS + HOLDOUT + FRESH + FRESH_CROSS_TABLE + FRESH_TEAMS:
        safe = validate_sql(sql)
        cols, rows = a.run(safe)
        v = a.embed(q)
        a.cache_put(q, v, entities(q, a.names), safe, cols, rows, a.word_answer(q, cols, rows), source="verified")
    return len(QUESTIONS)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    a = Asker()
    print("prefilled", prefill(a), flush=True)

    # 1. SQL accuracy, cache off
    rows = []
    for group, q, sql, mode in [("tuned", *x) for x in QUESTIONS + HOLDOUT] + [("earlier fresh", *x) for x in FRESH + FRESH_CROSS_TABLE] + [("held out", *x) for x in FRESH_TEAMS]:
        gc, gr = a.run(validate_sql(sql))
        t = time.perf_counter()
        try:
            psql, pc, pr = a.generate_and_run(q)
            ok, err = matches(gc, gr, pr, mode), ""
        except Exception as e:
            psql, pr, ok, err = "", [], False, str(e)[:160]
        rows.append({"set": group, "question": q, "correct": ok, "seconds": round(time.perf_counter() - t, 1), "generated_sql": psql,
                     "expected": str(gr[:3])[:90], "got": str(pr[:3])[:90], "error": err})
        print(("OK  " if ok else "FAIL"), q, flush=True)
    acc = pd.DataFrame(rows)

    # 2. Cache behaviour (prefilled cache; Granite is not called for hits)
    cache_rows = []
    for kind, pairs, want in (("should reuse", SHOULD_HIT, True), ("natural rewording", NATURAL, True), ("must not reuse", MUST_MISS, False)):
        for cached, q in pairs:
            ents, v = entities(q, a.names), a.embed(q)
            sim = float(a.admin.execute("SELECT 1 - (embedding <=> %s) FROM qa_cache WHERE question = %s", (v, cached)).fetchone()[0])
            hit = a.cache_lookup(v, ents)
            reused = hit is not None and hit["matched"] == cached
            wrong = hit is not None and hit["matched"] != cached
            cache_rows.append({"check": kind, "question": q, "cached_question": cached, "similarity": round(sim, 3), "reused": reused,
                               "reused_other": hit["matched"] if wrong else "", "passed": (reused == want) and not (wrong and not want)})
    cache = pd.DataFrame(cache_rows)
    timings = []
    for q, _, _ in QUESTIONS + HOLDOUT + FRESH + FRESH_CROSS_TABLE + FRESH_TEAMS:
        r = a.ask(q)
        assert r["source"] == "cache", q
        timings.append(r["latency_ms"])

    # 3. Safety
    safe_rows = []
    for s in ATTACKS:
        try:
            validate_sql(s)
            blocked = False
        except UnsafeSQL:
            blocked = True
        db_blocked = None
        if not blocked:  # the validator let it through: the database role must still stop it
            try:
                a.run(s); db_blocked = False
            except Exception:
                db_blocked = True
        safe_rows.append({"attempt": s, "validator_blocked": blocked, "database_blocked": db_blocked, "stopped": blocked or bool(db_blocked)})
    safe = pd.DataFrame(safe_rows)
    role = []
    for s in ("DELETE FROM top500", "SELECT pg_sleep(60)", "SELECT * FROM qa_cache"):  # straight to the DB, skipping the validator
        t = time.perf_counter()
        try:
            a.run(s); role.append(f"NOT STOPPED: {s}")
        except Exception as e:
            role.append(f"stopped in {time.perf_counter() - t:.1f}s: `{s}` ({str(e).splitlines()[0][:70]})")

    tuned, earlier, held = acc[acc.set == "tuned"], acc[acc.set == "earlier fresh"], acc[acc.set == "held out"]
    lines = ["# Ask the Data: evaluation", "",
             f"Model: Granite 4.2-3B through LM Studio (local). Scope: top 500 and the made-up sample inventory.", "",
             "| Check | Result | Target |", "| --- | --- | --- |",
             f"| SQL correct, questions the prompt was tuned on | {int(tuned.correct.sum())} of {len(tuned)} | |",
             f"| SQL correct, earlier fresh sets (each scored before later changes) | {int(earlier.correct.sum())} of {len(earlier)} | |",
             f"| **SQL correct, newest questions never used for tuning (teams and assets)** | **{int(held.correct.sum())} of {len(held)}** | 80% |",
             f"| All {len(acc)} questions together | {int(acc.correct.sum())} of {len(acc)} ({acc.correct.mean():.0%}) | |",
             f"| Median time for a new question | {acc.seconds.median():.1f} s | |",
             f"| Cached answer time | median {pd.Series(timings).median():.0f} ms, slowest {max(timings):.0f} ms | under 200 ms |",
             f"| Easy rewordings that reused the cache | {int(cache[cache.check == 'should reuse'].passed.sum())} of {len(SHOULD_HIT)} | |",
             f"| Natural rewordings that reused the cache | {int(cache[cache.check == 'natural rewording'].passed.sum())} of {len(NATURAL)} | none set |",
             f"| Different questions kept out of the cache | {int(cache[cache.check == 'must not reuse'].passed.sum())} of {len(MUST_MISS)} | all |",
             f"| Harmful SQL stopped | {int(safe.stopped.sum())} of {len(safe)} | all |", "",
             "## SQL accuracy", "", acc.drop(columns=["generated_sql"]).to_markdown(index=False), "",
             "## Generated SQL", ""] + [f"- {'✅' if r.correct else '❌'} {r.question}\n  `{r.generated_sql or r.error}`" for r in acc.itertuples()] + \
            ["", "## Cache", "", cache.to_markdown(index=False), "", "## Safety", "", safe.to_markdown(index=False), "",
             "Straight to the database, skipping the validator:", ""] + [f"- {x}" for x in role]
    (OUT / "report.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines[:12]))
    print(acc[~acc.correct][["set", "question", "generated_sql", "error"]].to_string(index=False))
    print(cache[cache.check == "natural rewording"].to_string(index=False)); print(int(safe.stopped.sum()), "of", len(safe), "stopped"); print("\n".join(role))


if __name__ == "__main__":
    if "--prefill" in sys.argv:
        print("prefilled", prefill(Asker()))
    else:
        main()
