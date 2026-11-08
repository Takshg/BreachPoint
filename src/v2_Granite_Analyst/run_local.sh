#!/bin/zsh
# Local backup for the Granite analyst run: LM Studio serves Granite 4.2-3B (OpenAI-compatible API)
# and extract.py works through the queue in priority order. Resumable: re-run to continue.
#
# Usage (from the repo root):
#   src/v2_Granite_Analyst/run_local.sh pilot     # the 60-row pilot only
#   src/v2_Granite_Analyst/run_local.sh full      # the whole queue (slow on a laptop; stop any time)
set -e
LMS=~/.lmstudio/bin/lms
JOB=outputs/v2_Granite_Analyst
MODEL=granite-4.2-3b

$LMS server start >/dev/null 2>&1 || true
if ! $LMS ps 2>/dev/null | grep -q "$MODEL"; then
  $LMS load granite-4.2-3b --identifier $MODEL --context-length 16384 --parallel 4 --gpu max -y
fi

case "${1:-pilot}" in
  pilot) uv run python -m src.v2_Granite_Analyst.extract --queue $JOB/pilot_queue.parquet \
           --out $JOB/pilot_run_local --base-url http://localhost:1234/v1 --model $MODEL --raw --concurrency 4 --chunk 60 ;;
  full)  uv run python -m src.v2_Granite_Analyst.extract --queue $JOB/queue.parquet \
           --out $JOB/granite_fields_local --base-url http://localhost:1234/v1 --model $MODEL --raw --concurrency 4 --chunk 200 ;;
esac
