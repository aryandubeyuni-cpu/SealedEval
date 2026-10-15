#!/usr/bin/env bash
# Serve the SealedEval dashboard on http://localhost:5500 (Mac/Linux).
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
python3 -m http.server 5500 --directory "$ROOT/frontend"
