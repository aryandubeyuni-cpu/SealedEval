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

## Layout

```
sealedeval/
  core/      crypto.py, log.py, contract.py
  zones/     red.py, blue.py, model.py
  broker/    broker.py
  safety/    preflight.py, tripwires.py
  evidence/  bundle.py, verify.py
  demo/      naive_run.py, sealed_run.py, attacks.json
  web/       app.py, static/index.html
  data/      runtime outputs (git-ignored)
```

## Build order

1. Proof core (`core/`: crypto, log, contract)
2. Zones (`zones/`: red, blue, model)
3. Broker (`broker/`)
4. Preflight + tripwires (`safety/`)
5. Naive vs sealed demo (`demo/`)
6. Evidence bundle + verifier (`evidence/`)
7. Web dashboard (`web/`)
8. README
