#!/usr/bin/env bash
# Start the SealedEval backend on http://localhost:8001 with auto-reload (Mac/Linux).
# Only backend/app is watched: runs write files (including a decoy grader.py) into backend/data/,
# and watching that would restart the server in the middle of a run.
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/.venv/bin/activate"
cd "$ROOT/backend"
python -m uvicorn app.api.main:app --reload --reload-dir app --port 8001
