# Serve the SealedEval dashboard on http://localhost:5500 (Windows PowerShell).
$Root = Split-Path -Parent $PSScriptRoot
python -m http.server 5500 --directory "$Root\frontend"
