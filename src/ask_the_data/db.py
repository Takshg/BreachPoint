"""Phase 8b database: the top 500, the asset inventory and the semantic cache, on Tiger Data.

One Postgres (TimescaleDB image, local Docker) holds the tables the chatbot may query and its
pgvector cache. Generated SQL runs as a read-only role with a 5-second limit.

Start the database once:
  docker run -d --name breachpoint-db -p 127.0.0.1:5433:5432 -e POSTGRES_PASSWORD=breachpoint-local \
      -v breachpoint-pg:/home/postgres/pgdata/data timescale/timescaledb-ha:pg17
Then:  uv run python -m src.ask_the_data.db      (re-run whenever the top 500 changes)

Point at Tiger Cloud or elsewhere by setting BREACHPOINT_ADMIN_DSN and BREACHPOINT_READER_DSN.
The passwords below only protect a container bound to localhost.
"""
from __future__ import annotations

import os

import pandas as pd
import psycopg

from src.assets import APP, assess, load_sample

ADMIN_DSN = os.environ.get("BREACHPOINT_ADMIN_DSN", "postgresql://postgres:breachpoint-local@127.0.0.1:5433/postgres")
READER_DSN = os.environ.get("BREACHPOINT_READER_DSN", "postgresql://breachpoint_reader:breachpoint-read@127.0.0.1:5433/postgres")
EMBED_DIM = 384
QUERY_TABLES = {"top500", "assets", "asset_findings"}

SCHEMA = f"""
CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS timescaledb;
DROP TABLE IF EXISTS asset_findings, assets, top500;
CREATE TABLE top500 (
    rank int PRIMARY KEY, cve_id text UNIQUE NOT NULL, published date NOT NULL, vendor text, assigned_by text,
    attack_vector text, description text NOT NULL, exploit_code text,
    has_exploit_code boolean NOT NULL, github_poc boolean NOT NULL, nuclei boolean NOT NULL,
    metasploit boolean NOT NULL, exploitdb boolean NOT NULL,
    epss real, epss_rank int NOT NULL, cvss real, cvss_rank int NOT NULL);
CREATE TABLE assets (asset text PRIMARY KEY, owner text, software text NOT NULL, exposure text NOT NULL,
    environment text NOT NULL, data_value text NOT NULL);
CREATE TABLE asset_findings (cve_id text NOT NULL REFERENCES top500(cve_id), asset text NOT NULL REFERENCES assets(asset),
    owner text, software text NOT NULL, rank int NOT NULL, priority text NOT NULL, exposure text NOT NULL, environment text NOT NULL,
    data_value text NOT NULL, reason text NOT NULL, PRIMARY KEY (cve_id, asset));
CREATE TABLE IF NOT EXISTS qa_cache (id bigserial PRIMARY KEY, question text NOT NULL, entities jsonb NOT NULL,
    embedding vector({EMBED_DIM}) NOT NULL, sql text NOT NULL, columns jsonb NOT NULL, rows jsonb NOT NULL,
    answer text NOT NULL, source text NOT NULL, created_at timestamptz NOT NULL DEFAULT now());
DO $$ BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'breachpoint_reader') THEN
        CREATE ROLE breachpoint_reader LOGIN PASSWORD 'breachpoint-read';
    END IF;
END $$;
ALTER ROLE breachpoint_reader SET statement_timeout = '5s';
ALTER ROLE breachpoint_reader SET default_transaction_read_only = on;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM breachpoint_reader;
GRANT USAGE ON SCHEMA public TO breachpoint_reader;
GRANT SELECT ON top500, assets, asset_findings TO breachpoint_reader;
"""


def load_tables(clear_cache: bool = True) -> dict[str, int]:
    q = pd.read_parquet(APP / "queue.parquet").sort_values("rank").head(500)
    q["vendor"] = q.vendor.where(q.vendor != "")
    q["assigned_by"] = q.assigned_by.where(q.assigned_by != "")
    flag = {c: q.exploit_code.str.contains(t, regex=False) for c, t in
            (("github_poc", "GitHub"), ("nuclei", "Nuclei"), ("metasploit", "Metasploit"), ("exploitdb", "Exploit-DB"))}
    t = q.assign(has_exploit_code=q.exploit_code != "", published=q.published.dt.date, **flag)
    cols = ["rank", "cve_id", "published", "vendor", "assigned_by", "attack_vector", "description", "exploit_code",
            "has_exploit_code", "github_poc", "nuclei", "metasploit", "exploitdb", "epss", "epss_rank", "cvss", "cvss_rank"]
    inv = load_sample()
    lookup = pd.read_parquet(APP / "asset_lookup.parquet")
    pairs = assess(inv, lookup)
    pairs = pairs[pairs.cve_id.isin(t.cve_id)]
    pairs = pairs.assign(owner=pairs.asset.map(inv.set_index("asset").owner))
    pcols = ["cve_id", "asset", "owner", "software", "rank", "priority", "exposure", "environment", "data_value", "reason"]
    with psycopg.connect(ADMIN_DSN, autocommit=False) as c:
        c.execute(SCHEMA)
        if clear_cache:
            c.execute("TRUNCATE qa_cache")
        with c.cursor() as cur:
            for table, df, names in (("top500", t, cols), ("assets", inv, list(inv.columns)), ("asset_findings", pairs, pcols)):
                recs = df[names].astype(object).where(df[names].notna(), None).values.tolist()
                ph = ",".join(["%s"] * len(names))
                cur.executemany(f"INSERT INTO {table} ({','.join(names)}) VALUES ({ph})", recs)
    return {"top500": len(t), "assets": len(inv), "asset_findings": len(pairs)}


if __name__ == "__main__":
    print(load_tables())
