# BreachPoint

Predicts which newly published vulnerabilities attackers will go on to exploit, and shows engineers what to fix first and why. Built for the IBM "Before the Breach" track at Sheridan Datathon 2026.

BreachPoint ranks the 72,670 vulnerabilities in the challenge scoreboard using only what was known at each one's monthly snapshot. The target is CISA's Known Exploited Vulnerabilities list (KEV). A Streamlit triage app shows the ranked queue, the reasons behind each rank, and the evidence that the ranking works.

The full method and findings are in [WRITEUP.md](WRITEUP.md).

## Results

Later-exploited vulnerabilities found in a top list the same share of the cohort as the scoreboard's top 500. Each model was trained on one year and tested on the other.

| Ranking | 2025 test (K = 243, 45 to find) | 2024 test (K = 198, 24 to find) |
| --- | --- | --- |
| Highest CVSS 3 first | 4 | 0 |
| EPSS first | 8 | 1 |
| Public exploit code, then EPSS | 14 | 4 |
| **BreachPoint v1 (logistic regression)** | **16** (range 8–23) | **7** (range 2–12) |

There are very few real attacks to find, so the 95% ranges overlap. BreachPoint is ahead in both years, but that margin alone is not statistically clear.

Adding Granite's analyst fields did not help: re-ranking the top 10% gave 13 and 7 at best (LightGBM), so `outputs/top500.csv` comes from v1 logistic regression. Granite read about 32,000 of 162,985 descriptions before the GPU session ended. See [WRITEUP.md](WRITEUP.md).

## Set up

Needs Python 3.12 and [uv](https://docs.astral.sh/uv/).

```bash
uv sync
```

The challenge data isn't in this repo. Put `data.zip` in `data/` and unzip it from the repo root:

```bash
unzip data/data.zip -d .
```

## Reproduce the results

Run these from the repo root, in order:

```bash
uv run python -m src.load               # convert the CSVs to Parquet and check row counts
uv run python -m src.cohort             # build the 2024, 2025 and 2026 sets with labels
uv run python -m src.features           # build leakage-safe features
uv run python -m src.evaluate           # rebuild the three baselines
uv run python -m src.v1_LightGBM.train  # train v1 and write the top 500 lists
uv run pytest -q                        # unit tests
```

`outputs/top500.csv` is the submission file.

Phase 6 experiments:

```bash
uv run python -m src.phase6_Discovery.experiments       # leakage, KEV blind spot, vendor history
uv run python -m src.phase6_Discovery.lead_and_capacity # severity misses, early warning, patch capacity
```

## Run the app

```bash
uv run python -m src.app_data              # build the app's data (run the steps above first)
uv run python -m src.assets                # match vulnerabilities to asset software
uv run streamlit run app/streamlit_app.py
```

The app runs on your machine only (`127.0.0.1:8501`) and reads local files. Only the "Open in NVD" link needs the internet.

The tabs:

- **Fix queue:** every vulnerability ranked, with the reasons behind each rank.
- **My environment:** adds where each vulnerability runs, using an asset inventory you upload. It sorts them into Act now, Act soon, Track or Defer. The bundled `app/sample_assets_MADE_UP.csv` is invented for demonstration. Your inventory needs these columns: `asset`, `owner`, `software` (separated by `;`), `exposure` (`internet`, `internal`, `isolated`), `environment` (`production`, `staging`, `dev/test`) and `data_value` (`high`, `medium`, `none`).
- **Ask the data:** plain-English questions about the top 500 and the sample inventory (setup below).
- **Evidence:** how the ranking performed on years it wasn't trained on.

## Ask the data

Granite turns a question into one read-only SQL query on Tiger Data (TimescaleDB with pgvector). Similar questions are answered instantly from a semantic cache, but only if their years, vendors, CVE IDs and other key terms match exactly.

It needs Docker and a Granite server. Start the database once, then load it (re-run the load whenever the top 500 changes):

```bash
docker run -d --name breachpoint-db -p 127.0.0.1:5433:5432 -e POSTGRES_PASSWORD=breachpoint-local \
    -v breachpoint-pg:/home/postgres/pgdata/data timescale/timescaledb-ha:pg17
uv run python -m src.ask_the_data.db                 # load the tables
uv run python -m src.ask_the_data.evaluate --prefill # load verified answers into the cache
```

For Granite, load `granite-4.2-3b` in LM Studio with its server on (context length 16384), or point `BREACHPOINT_LLM_URL` and `BREACHPOINT_LLM_MODEL` at a vLLM server. Questions already in the cache work without Granite.

To measure it: `uv run python -m src.ask_the_data.evaluate` writes `outputs/ask_the_data/report.md`.

## Granite analyst

IBM Granite 4.2-3B reads each description and fills in fixed fields: product category, internet-facing, login needed, attack type and server software. It sees only the description, never the CVE ID, and is never asked whether something was exploited.

```bash
uv run python -m src.v2_Granite_Analyst.queue    # build the job queue and pilot set
```

Then run the batch on a GPU with vLLM:

1. Copy `outputs/v2_Granite_Analyst/granite_job.zip` to `MyDrive/breachpoint_granite/` on Google Drive. To create it, zip `queue.parquet`, `pilot_queue.parquet` and the `prompt.py` and `extract.py` files from `src/v2_Granite_Analyst/`.
2. Run `notebooks/02_granite_vllm_colab.ipynb` on a T4 GPU. Re-running resumes where it stopped.
3. Unzip the results into `outputs/v2_Granite_Analyst/`, then:

```bash
uv run python -m src.v2_Granite_Analyst.stage2
```

To run on a Mac instead, load Granite in LM Studio and use `src/v2_Granite_Analyst/run_local.sh`. It is much slower.

## Project layout

| Path | What it holds |
| --- | --- |
| `src/load.py`, `cohort.py`, `features.py`, `evaluate.py` | Data loading, benchmark-matched sets, features, metrics |
| `src/v1_LightGBM/` | v1: LightGBM and logistic regression on 11 core features |
| `src/v2_Granite_Analyst/` | Granite prompt, batch extraction and stage-2 model |
| `src/v2b_Granite_Embeddings/` | Granite embeddings backup (not adopted) |
| `src/v3_Vendor_CVSS/` | Vendor CVSS test (paused; see its `STATUS.md`) |
| `src/phase6_Discovery/` | Discovery experiments |
| `src/app_data.py`, `app/` | App data build and the Streamlit app |
| `src/assets.py` | Asset matching and the fix-order decision table |
| `src/ask_the_data/` | Plain-English to SQL, semantic cache and evaluation |
| `notebooks/` | Data exploration and the Colab vLLM run |
| `tests/` | Unit tests, including the no-future-data checks |
| `outputs/` | Result tables, figures and `top500.csv` |

## IBM technology

- **Granite 4.2-3B** for Ask the data (SQL and answers), and served with **vLLM** for the analyst fields, which are not used in the final ranking
- **granite-embedding-30m-english** for the semantic cache in Ask the data
