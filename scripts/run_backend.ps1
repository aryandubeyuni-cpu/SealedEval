# Start the SealedEval backend on http://localhost:8001 with auto-reload (Windows PowerShell).
# Only backend/app is watched: runs write files (including a decoy grader.py) into backend/data/,
# and watching that would restart the server in the middle of a run.
$Root = Split-Path -Parent $PSScriptRoot
& "$Root\.venv\Scripts\Activate.ps1"
Set-Location "$Root\backend"
python -m uvicorn app.api.main:app --reload --reload-dir app --port 8001
