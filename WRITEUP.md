# BreachPoint: what to fix before the breach

## What it does

Thousands of vulnerabilities are published each week, and most teams rank them by severity. Severity says how bad an attack could be, not whether anyone will attack.

BreachPoint ranks new vulnerabilities by how likely they are to be added to CISA's Known Exploited Vulnerabilities list (KEV), using only what was known at each one's monthly snapshot. A triage app shows the queue, the plain-English reasons behind each rank, and the evidence that the ranking works.

## The main finding

**Who shipped a vulnerability says more about whether it will be attacked than how severe it is.**

- Among vulnerabilities with CVSS 9 or higher, those naming a vendor with KEV history were later exploited at **193 per 10,000**. Those without one: **10 per 10,000**, about 19 times lower.
- The bottom half of CVE assigners, ranked by past KEV rate, held **1 of the 69** later-exploited vulnerabilities.
- Public exploit code is the strongest single signal: 33–44% of later-exploited vulnerabilities had it at the snapshot, against 2.2% of the rest. But 56–67% had none, so a ranking built on exploit code alone misses most of them.
- EPSS barely separated them at the snapshot (median 0.0004 for both groups in 2024).

## What others would miss

- **Most exploited vulnerabilities aren't in the benchmark.** Of those reaching KEV by Nov 4 of their publish year, 73% (2024) and 66% (2025) were already listed by their snapshot. The scoreboard holds only the later ones, so we trained on exactly that population.
- **The 2026 data shifts in July.** Median EPSS jumps about 8× and monthly CVE volume roughly triples. A first model using raw EPSS put 352 of its top 500 in July–September for that reason alone, and validation on past years could not show it. We use EPSS rank within each month instead.
- **More features made the model worse.** With 21 features, LightGBM found 6 where the best baseline found 14. With so few positives, trees fit noise in timing and batch size. Cutting to 11 core features fixed it.
- **Some results went against what we expected, and we report them.**
  - Leaky NIST columns did not inflate validation hits (14 against 16, and 7 against 7). The damage shows in the 2026 list: a leaky model's top 500 is 100% NIST-reviewed, against 50% of the scoreboard, and shares only 136 entries with the clean list.
  - Freezing KEV history to match the 2026 blind spot did not change results much either way (16 / 7 frozen, 14 / 5 kept current).

## Results

Each model was trained on one year and tested on the other. K is the same share of the cohort as the scoreboard's top 500.

| Ranking | 2025 test (K = 243, 45 to find) | 2024 test (K = 198, 24 to find) |
| --- | --- | --- |
| Highest CVSS 3 first | 4 (1–8) | 0 (0–3) |
| EPSS first | 8 (3–14) | 1 (0–3) |
| Public exploit code, then EPSS | 14 (7–22) | 4 (1–8) |
| **BreachPoint v1** | **16 (8–23)** | **7 (2–12)** |

Ranges are 95% bootstrap intervals. BreachPoint leads in both years, but by +1.2 (−6 to +9) and +3.1 (−2 to +8), so at the top of the list the margin isn't statistically clear. Its ranking of the whole list is better: average precision is 1.4–2.3× the best baseline.

**At equal patching capacity**, fixing N new vulnerabilities a month, BreachPoint never trailed any baseline. At 100 a month it caught 20 against 18 (2025) and 14 against 8 (2024). The gain is statistically clear only in 2024, at 100 or more a month.

**Early warning:** the model flagged 16 (2025) and 7 (2024) before they were listed, against 10 and 4 for EPSS crossing 0.1. Lead time was mixed, and EPSS alerts were more precise in 2024.

**Adding Granite's fields made the ranking worse, so `top500.csv` comes from v1.** Granite read about 32,000 of 162,985 descriptions before the GPU session ended, highest-priority first. We used it only to re-rank the top 10% of each set by v1 score, which was over 99% covered. Results at the same K:

| Re-ranked with Granite fields | 2025 test (K = 243) | 2024 test (K = 198) |
| --- | --- | --- |
| Logistic regression | 12 (6–19) | 3 (0–7) |
| LightGBM | 13 (7–20) | 7 (2–12) |
| *v1, for comparison* | *16 (8–23)* | *7 (2–12)* |

The differences from v1 are within the noise, but none is a gain, so we kept the simpler model and did not tune further on the test years.

**Granite's fields still describe where attacks land.** Among the vulnerabilities it read in 2024–25, which were the higher-scoring 19% of each year:

- Remote-management tools were later exploited at 251 per 10,000 (8 of 319). Browsers: 0 of 739.
- File read or path traversal: 201 per 10,000 (7 of 348). Authentication bypass: 179 (9 of 502). Memory corruption: 12 (2 of 1,649). Denial of service: 0 of 692.

These counts are small and cover only rows the model already ranked highly, so they are descriptive.

## How we validated it

- **Copied the benchmark.** Vulnerabilities published Jan–Sep of each year, snapshot at the end of the publish month (June moved to July, as in the scoreboard), label = added to KEV after the snapshot and by Nov 4. Applying the same rule to 2026 gives exactly the scoreboard: 72,794 published, minus 124 = 72,670.
- **Both directions.** Train 2024 → test 2025, and train 2025 → test 2024.
- **Bootstrap ranges** on every result, with paired bootstrap for differences. There are only 24 and 45 positives, so a gap of a few hits can be luck.
- **Matched the KEV blind spot.** Our KEV file ends Dec 31, 2025. KEV-based features for year Y use only KEV entries from before that year, as 2026 scoring must. A unit test confirms that fake KEV entries inside the year change nothing.
- **Honest limits.** Model variants were compared on these test years, so margins are somewhat optimistic. KEV is a lower bound: a vulnerability not on it may still have been attacked.

## Columns used and excluded

**Used by the model**

- `epss` (only as a rank within the snapshot month), `exploitdb`, `metasploit`, `nuclei`, `poc_github`
- `published`, `assigner`
- `description` (KEV vendor and product names; Granite's input)
- `known_exploited.csv`: `vendor`, `product`, `date_added`, frozen to before each cohort year

**Excluded from the model**

- `nvd_status`, `n_affected_cpes`, `n_references`, `last_modified`
- Flags for blank scores, CVSS scores and their source, CWE
- Everything in `affected_products.csv` and `references.csv`
- Raw EPSS values

**Shown in the app only, never used for ranking:** `attack_vector` (as a filter) and `cvss3_score` (to compare ranks). These may include NIST-added values.

**Why excluded:** among 2024–25 vulnerabilities, 100% of KEV entries were NIST-analysed and had product lists, against 74% of the rest. NIST scored 61% of KEV entries against 48% of others, so even the source of a score leaks.

## How a team would use it

The queue shows each vulnerability's rank next to its EPSS and CVSS ranks, with the reasons in plain language. In the current top 500, 390 sit outside the top 5,000 by CVSS: a severity-first team would not reach them.

**My environment** adds where each vulnerability runs, from an uploaded asset inventory, and sorts it into Act now, Act soon, Track or Defer using an SSVC-style decision table. Guardrails stop it hiding real danger: being isolated can lower priority by at most two levels, and a vulnerability on several assets takes its highest priority. In the demo's made-up inventory, four of the next 20 fixes only run on isolated sandboxes and are deferred, and five lower-ranked ones move up.

**Ask the data** answers plain-English questions about the top 500 and the inventory. Granite writes SQL, which runs read-only on Tiger Data (Postgres with pgvector). On 70 test questions with hand-written answers it got 63 right (90%), though about 80–90% is a fairer expectation for new questions. A query that ignores part of the question is rejected rather than answered. Similar questions reuse cached answers in milliseconds, but only when years, vendors and other key terms match exactly: "May 2026" and "June 2026" are 95.5% similar as embeddings, so similarity alone would give wrong answers.

Scores are shown as ranks, not probabilities. They aren't calibrated, and only a small share of even the top slice is confirmed exploited later.

## IBM technology

- **Granite 4.2-3B** writes the SQL and the plain-English answers in Ask the data.
- **Granite 4.2-3B on vLLM** read about 32,000 descriptions and filled in fixed fields: product category, internet-facing, login needed, attack type, server software. It sees only the description, never the CVE ID, and is never asked about exploitation, which limits any knowledge of later attacks. These fields did not improve the ranking, so they do not affect `top500.csv`.
- **granite-embedding-30m-english** powers the semantic cache in Ask the data. We also tested similarity to past KEV descriptions as a ranking feature. It added nothing, so it wasn't adopted for that.

## Sources

- [NVD data feeds mirror](https://github.com/fkie-cad/nvd-json-data-feeds) (fkie-cad), Nov 6, 2026
- [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), to Dec 31, 2025
- [FIRST EPSS](https://www.first.org/epss/), and exploit flags from [t0sche/cvss-bt](https://github.com/t0sche/cvss-bt)
- [MITRE CWE](https://cwe.mitre.org/), version 4.14
- [IBM Granite models](https://huggingface.co/ibm-granite)
- [vLLM](https://docs.vllm.ai)
- No outside data was added beyond the challenge's `data.zip`.
