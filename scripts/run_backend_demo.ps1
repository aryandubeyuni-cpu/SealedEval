# Start the SealedEval backend on http://localhost:8001 for a live demo: no auto-reload (Windows PowerShell).
$Root = Split-Path -Parent $PSScriptRoot
& "$Root\.venv\Scripts\Activate.ps1"
Set-Location "$Root\backend"
python -m uvicorn app.api.main:app --port 8001
