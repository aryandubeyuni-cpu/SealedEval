#!/usr/bin/env bash
# Start the SealedEval backend on http://localhost:8001 for a live demo: no auto-reload (Mac/Linux).
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/.venv/bin/activate"
cd "$ROOT/backend"
python -m uvicorn app.api.main:app --port 8001
