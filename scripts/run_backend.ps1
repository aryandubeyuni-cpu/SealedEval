# Start the SealedEval backend on http://localhost:8000 (Windows PowerShell).
$Root = Split-Path -Parent $PSScriptRoot
& "$Root\.venv\Scripts\Activate.ps1"
Set-Location "$Root\backend"
python -m uvicorn app.api.main:app --reload --port 8000
