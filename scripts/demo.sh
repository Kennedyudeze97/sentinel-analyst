#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ ! -d ".venv" ]]; then
  python3 -m venv .venv
fi

source .venv/bin/activate
pip -q install -r requirements.txt

python3 -m sentinel.cli --history data/history.jsonl --today data/today.jsonl

echo ""
echo "Artifacts:"
ls -lh incidents | tail || true
ls -lh tickets | tail || true
