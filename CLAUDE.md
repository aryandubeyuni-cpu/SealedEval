# SealedEval

A 2-hour hackathon **prototype**.

## Context

SealedEval makes adversarial AI safety tests leak-proof and verifiable. Three parties run at once: **RED** (attacker), **BLUE** (defense filter), **MODEL** (AI under test). Today they share one environment, so tests can leak, the defender can adapt mid-test, and agents can escape. SealedEval fixes this with:

1. **Two-sided freeze:** red and blue commit SHA-256 hashes of their attacks/defense before the run; blue is stateless and read-only during the run.
2. **A BROKER** that is the only communication path and enforces an information-flow contract: fixed-time response release, fixed-size padded messages, one unified refusal message, per-tenant cache salt.
3. **A pre-flight self-test** that runs escape probes and aborts the run if any succeeds, plus tripwire decoy files.
4. **A signed, hash-chained event log** and an evidence bundle where every claim is labelled `ENFORCED`, `VERIFIED`, `MONITORED` or `NOT_COVERED`, plus a verifier that detects tampering.

## Prototype rules (keep it simple)

- Pure Python 3.10+, standard library where possible. Allowed extra packages only: `fastapi`, `uvicorn`, `cryptography`, `requests`.
- No Docker, no GPU, no real LLM. Zones are simulated as separate Python modules/processes. The MODEL is a simple rule-based mock.
- Must run on Windows, Mac and Linux.
- Every module must be small, readable and demo-friendly.
- Frontend is plain HTML/CSS/JS (no build step, no framework).

## Architecture rules

- **The frontend talks to the backend ONLY through the endpoints in [docs/API.md](docs/API.md).** Every fetch lives in `frontend/js/api.js`.
- `backend/app/api/main.py` only wires routes. Business logic lives in the other `app/` packages.
- Adding or changing an endpoint means updating `docs/API.md`, `api/main.py` and `js/api.js` together.
- Backend Python runs from inside `backend/`, so imports look like `from app.core.log import HashChainLog`.
- Runtime outputs (keys, logs, bundles) go in `backend/data/` (git-ignored). `app.core.crypto.DATA_DIR` points there.

## Layout

```
SealedEval/
  backend/
    app/
      core/      crypto.py, log.py, contract.py      (proof core, done)
      zones/     red.py, blue.py, model.py
      broker/    broker.py
      safety/    preflight.py, tripwires.py
      evidence/  bundle.py, verify.py
      demo/      naive_run.py, sealed_run.py, attacks.json
      api/       main.py   (FastAPI routes only)
    tests/       test_core.py   (run: cd backend && python -m tests.test_core)
    data/        runtime outputs (git-ignored)
    requirements.txt
  frontend/
    index.html, css/style.css, js/api.js, js/app.js
  docs/API.md    API contract between frontend and backend
  scripts/       run_backend.ps1/.sh (port 8000), run_frontend.ps1/.sh (port 5500)
  .venv/         virtual environment (repo root)
```

## Build order

1. Proof core (`core/`: crypto, log, contract) ✅
2. Zones (`zones/`: red, blue, model)
3. Broker (`broker/`)
4. Preflight + tripwires (`safety/`)
5. Naive vs sealed demo (`demo/`)
6. Evidence bundle + verifier (`evidence/`)
7. Web dashboard (`api/main.py` routes + `frontend/`)
8. README
