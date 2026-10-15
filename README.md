# SealedEval

SealedEval makes adversarial AI safety tests leak-proof and verifiable.
An attacker (RED), a defense filter (BLUE) and the model under test talk only through a broker that hides timing, length and refusal reasons, after both sides commit to their attacks and defense up front.
Every run produces a signed, hash-chained log and an evidence bundle that anyone can check for tampering.

This is a hackathon prototype: pure Python plus a plain HTML dashboard, no Docker, no GPU, no real LLM.

## Setup (once)

Requires Python 3.10+.

**Windows (PowerShell)**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r backend\requirements.txt
```

**Mac / Linux**
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
```

## Run

Start the backend and the frontend in two terminals, then open http://localhost:5500.
The header should show **Backend connected**.

**Windows (PowerShell)**
```powershell
.\scripts\run_backend.ps1     # API on http://localhost:8001
.\scripts\run_frontend.ps1    # dashboard on http://localhost:5500
```
If PowerShell refuses to run scripts, run this once: `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`.

For a live demo, start the backend with `.\scripts\run_backend_demo.ps1` (or `./scripts/run_backend_demo.sh`) instead: same port, no auto-reload.

**Mac / Linux**
```bash
./scripts/run_backend.sh      # API on http://localhost:8001
./scripts/run_frontend.sh     # dashboard on http://localhost:5500
```

## Tests

```bash
cd backend
python -m tests.test_core
```

## Project layout

- `backend/app/`: Python packages (core, zones, broker, safety, evidence, demo, api)
- `frontend/`: static dashboard
- `docs/API.md`: the API contract between frontend and backend
- `scripts/`: run scripts for Windows and Mac/Linux
