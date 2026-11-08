"""Run the Granite analyst over a queue of descriptions through any OpenAI-compatible server.

Works the same against vLLM (Colab GPU, the main path) and LM Studio (local Mac, backup/pilot).
Resumable: results are written in parts; rows already done are skipped on restart.
No project imports, so this file and prompt.py can be copied to Colab as is.

Usage:
  python extract.py --queue queue.parquet --out granite_fields \
      --base-url http://localhost:8000/v1 --model granite-4.2-3b --concurrency 128 [--limit N]
"""
from __future__ import annotations

import argparse
import asyncio
import glob
import os
import time

import pandas as pd
from openai import AsyncOpenAI

try:
    from prompt import FIELDS, PROMPT_VERSION, SCHEMA, messages, parse
except ImportError:  # running inside the project
    from src.v2_Granite_Analyst.prompt import FIELDS, PROMPT_VERSION, SCHEMA, messages, parse


def done_ids(out: str) -> set[str]:
    parts = glob.glob(os.path.join(out, "part-*.parquet"))
    if not parts:
        return set()
    done = pd.concat([pd.read_parquet(p, columns=["cve_id", "ok"]) for p in parts])
    return set(done[done.ok].cve_id)  # failed rows are retried on the next run


def raw_prompt(description: str) -> str:
    """Granite chat format built by hand; the empty think block turns reasoning off (model card).
    Used with servers that ignore chat_template_kwargs, e.g. LM Studio."""
    body = "".join(f"<|im_start|>{m['role']}\n{m['content']}<|im_end|>\n" for m in messages(description))
    return body + "<|im_start|>assistant\n<think></think>"


async def one(client, model, sem, row, args):
    async with sem:
        for attempt in range(3):
            try:
                if args.raw:
                    r = await client.completions.create(model=model, prompt=raw_prompt(row.description),
                                                        temperature=0, max_tokens=args.max_tokens,
                                                        stop=["<|im_end|>"])
                    d = parse(r.choices[0].text or "")
                    if d is not None:
                        return {"cve_id": row.cve_id, **d, "ok": True, "raw": None}
                    text = r.choices[0].text or ""
                    continue
                kw = dict(model=model, messages=messages(row.description), temperature=0,
                          max_tokens=args.max_tokens)
                if args.schema:
                    kw["response_format"] = {"type": "json_schema",
                                             "json_schema": {"name": "vuln_fields", "schema": SCHEMA, "strict": True}}
                if args.no_think:
                    kw["extra_body"] = {"chat_template_kwargs": {"enable_thinking": False}}
                r = await client.chat.completions.create(**kw)
                text = r.choices[0].message.content or ""
                d = parse(text)
                if d is not None:
                    return {"cve_id": row.cve_id, **d, "ok": True, "raw": None}
            except Exception as e:  # network or server error: retry
                text = f"ERROR: {e}"
                await asyncio.sleep(2 * (attempt + 1))
        return {"cve_id": row.cve_id, **{k: None for k in FIELDS}, "ok": False, "raw": text[:500]}


async def main(args):
    os.makedirs(args.out, exist_ok=True)
    q = pd.read_parquet(args.queue).sort_values("priority")
    skip = done_ids(args.out)
    q = q[~q.cve_id.isin(skip)]
    if args.limit:
        q = q.head(args.limit)
    print(f"{len(skip):,} already done; {len(q):,} to go", flush=True)
    client = AsyncOpenAI(base_url=args.base_url, api_key=os.environ.get("OPENAI_API_KEY", "unused"), timeout=120)
    sem = asyncio.Semaphore(args.concurrency)
    n_part = len(glob.glob(os.path.join(args.out, "part-*.parquet")))
    t0, total = time.time(), 0
    rows = list(q.itertuples(index=False))
    for i in range(0, len(rows), args.chunk):
        chunk = rows[i:i + args.chunk]
        res = await asyncio.gather(*(one(client, args.model, sem, r, args) for r in chunk))
        df = pd.DataFrame(res).assign(prompt_version=PROMPT_VERSION, model=args.model)
        df.to_parquet(os.path.join(args.out, f"part-{n_part:05d}.parquet"), index=False)
        n_part += 1
        total += len(chunk)
        rate = total / (time.time() - t0)
        print(f"{total:,}/{len(rows):,} done, {df.ok.mean():.1%} valid, {rate:.1f}/s, "
              f"~{(len(rows) - total) / max(rate, 1e-9) / 60:.0f} min left", flush=True)


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--queue", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--base-url", default="http://localhost:8000/v1")
    p.add_argument("--model", default="granite-4.2-3b")
    p.add_argument("--concurrency", type=int, default=64)
    p.add_argument("--chunk", type=int, default=2000)
    p.add_argument("--limit", type=int, default=0)
    p.add_argument("--max-tokens", type=int, default=160)
    p.add_argument("--no-schema", dest="schema", action="store_false", help="if the server lacks json_schema")
    p.add_argument("--think", dest="no_think", action="store_false", help="allow thinking mode (slower)")
    p.add_argument("--raw", action="store_true",
                   help="hand-built prompt via /completions (for servers that ignore enable_thinking, e.g. LM Studio)")
    asyncio.run(main(p.parse_args()))
