#!/usr/bin/env bash
# Start the SealedEval backend on http://localhost:8000 (Mac/Linux).
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/.venv/bin/activate"
cd "$ROOT/backend"
python -m uvicorn app.api.main:app --reload --port 8000
