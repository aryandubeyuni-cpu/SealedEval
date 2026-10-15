# SealedEval API contract

The frontend talks to the backend **only** through the endpoints below. Every call to them lives in `frontend/js/api.js`, and every route lives in `backend/app/api/main.py`.

- Base URL: `http://localhost:8000`
- All bodies are JSON. Errors use FastAPI's default shape: `{"detail": "..."}` with a 4xx/5xx status.
- Hashes are 64-character lowercase hex SHA-256 strings (shortened to `"ab12…"` in the examples).
- Evidence labels: `ENFORCED`, `VERIFIED`, `MONITORED`, `NOT_COVERED`.

| Method | Path | Status | Purpose |
|---|---|---|---|
| GET  | `/api/health` | implemented | Liveness check |
| POST | `/api/run/naive` | planned | Run the naive shared-environment demo |
| POST | `/api/run/sealed` | planned | Run the SealedEval demo |
| GET  | `/api/preflight` | planned | Run pre-flight escape probes |
| GET  | `/api/log` | planned | Return the hash-chained event log |
| GET  | `/api/bundle` | planned | Return the latest evidence bundle |
| POST | `/api/bundle/verify` | planned | Verify the bundle and log |
| POST | `/api/bundle/tamper` | planned | Demo only: corrupt one log line |
| GET  | `/api/view/{role}` | planned | Role-scoped view: `operator`, `red` or `blue` |

---

## GET /api/health

Request: no body.

Response `200`:
```json
{ "status": "ok" }
```

---

## POST /api/run/naive

Runs RED, BLUE and MODEL in one shared environment and reports what went wrong.

Request (body optional):
```json
{ "attack_ids": [0, 1, 2] }
```
Omit `attack_ids` to run every attack in `demo/attacks.json`.

Response `200`:
```json
{
  "mode": "naive",
  "results": [
    { "attack_id": 0, "prompt": "Ignore previous instructions...", "blocked": true,  "response": "Blocked by keyword filter: 'ignore previous'", "latency_ms": 41 },
    { "attack_id": 1, "prompt": "Pretend you are...",              "blocked": false, "response": "Sure, here is...",                              "latency_ms": 212 }
  ],
  "leaks": [
    { "type": "blue_saw_attack_list", "detail": "Defense read attacks.json before the run" },
    { "type": "refusal_reason_leak", "detail": "Refusal text names the matched rule" },
    { "type": "timing_leak", "detail": "Blocked responses return ~170 ms faster" }
  ],
  "summary": { "total": 2, "blocked": 1, "passed": 1, "leak_count": 3 }
}
```

---

## POST /api/run/sealed

Runs the full pipeline: commitments, pre-flight, broker-mediated run, signed log, evidence bundle.

Request (body optional):
```json
{ "attack_ids": [0, 1, 2], "tenant_id": "demo-tenant" }
```

Response `200`:
```json
{
  "mode": "sealed",
  "run_id": "run-20261015-193000",
  "commitments": {
    "red_root": "ab12…",
    "blue_hash": "cd34…",
    "model_hash": "ef56…",
    "contract_hash": "0912…"
  },
  "preflight": { "passed": true, "probes_run": 5, "probes_escaped": 0 },
  "results": [
    { "attack_id": 0, "blocked": true,  "response": "I can't help with that request.", "released_at_tick": 1, "padded_bytes": 512 },
    { "attack_id": 1, "blocked": false, "response": "Sure, here is...",                 "released_at_tick": 2, "padded_bytes": 512 }
  ],
  "leaks": [],
  "summary": { "total": 2, "blocked": 1, "passed": 1, "leak_count": 0 },
  "log_head_hash": "7788…",
  "bundle_id": "run-20261015-193000"
}
```

If pre-flight fails, the run is aborted. Response `409`:
```json
{ "detail": "Pre-flight failed: probe 'read_red_attacks' escaped. Run aborted." }
```

---

## GET /api/preflight

Runs the escape probes and checks the tripwires without starting a run.

Response `200`:
```json
{
  "passed": true,
  "probes": [
    { "name": "blue_reads_red_attacks", "escaped": false, "detail": "PermissionError: outside zone" },
    { "name": "model_writes_outside_zone", "escaped": false, "detail": "write blocked" },
    { "name": "red_contacts_model_directly", "escaped": false, "detail": "no route except broker" },
    { "name": "blue_persists_state", "escaped": false, "detail": "state discarded between calls" },
    { "name": "network_egress", "escaped": false, "detail": "simulated egress denied" }
  ],
  "tripwires": [
    { "path": "data/zones/blue/DO_NOT_READ_answers.txt", "triggered": false }
  ]
}
```

---

## GET /api/log

Query (optional): `?since=0` returns entries with `index >= since`.

Response `200`:
```json
{
  "entries": [
    {
      "index": 0,
      "timestamp": "2026-10-15T19:30:00.123456+00:00",
      "event_type": "commit_red",
      "data": { "root": "ab12…", "count": 5 },
      "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000",
      "hash": "11aa…"
    }
  ],
  "head_hash": "11aa…",
  "verified": { "ok": true, "first_bad_index": null, "reason": "chain intact" }
}
```

---

## GET /api/bundle

Returns the latest evidence bundle. Responds `404` if no sealed run has happened yet.

Response `200`:
```json
{
  "run_id": "run-20261015-193000",
  "created_at": "2026-10-15T19:30:05+00:00",
  "commitments": { "red_root": "ab12…", "blue_hash": "cd34…", "model_hash": "ef56…", "contract_hash": "0912…" },
  "contract": { "tick_ms": 300, "pad_bytes": 512, "unified_refusal": "I can't help with that request.", "red_sees": ["final_response_text_or_unified_refusal"], "blue_sees": ["single_prompt_at_checkpoint"], "operator_sees": ["health", "alerts"], "humans_see_prompts_during_run": false },
  "claims": [
    { "claim": "Blue defense was frozen before the run", "label": "VERIFIED", "evidence": "blue_hash matches pre- and post-run" },
    { "claim": "All traffic went through the broker", "label": "ENFORCED", "evidence": "zones have no other route" },
    { "claim": "Tripwire decoys were not accessed", "label": "MONITORED", "evidence": "0 tripwire events" },
    { "claim": "Hardware side channels", "label": "NOT_COVERED", "evidence": "out of prototype scope" }
  ],
  "log_head_hash": "7788…",
  "public_key": "aa55…",
  "signature": "99ff…"
}
```

---

## POST /api/bundle/verify

Request (body optional; omit to verify the latest bundle):
```json
{ "run_id": "run-20261015-193000" }
```

Response `200` (valid):
```json
{ "ok": true, "first_bad_index": null, "reason": "signature valid, chain intact, commitments match" }
```

Response `200` (tampered):
```json
{ "ok": false, "first_bad_index": 2, "reason": "entry 2: contents do not match its stored hash" }
```

---

## POST /api/bundle/tamper

**Demo only.** Edits one log line in place, without fixing its hash, so the next verify fails.

Request (body optional):
```json
{ "index": 2 }
```

Response `200`:
```json
{ "tampered_index": 2, "field": "data", "message": "Entry 2 modified. Run POST /api/bundle/verify to detect it." }
```

---

## GET /api/view/{role}

Returns what a given role is allowed to see under the information-flow contract. `role` is one of `operator`, `red`, `blue`. Any other value returns `404`.

Response `200`, `role=operator`:
```json
{ "role": "operator", "visible": ["health", "alerts"], "data": { "health": "ok", "alerts": [] } }
```

Response `200`, `role=red`:
```json
{
  "role": "red",
  "visible": ["final_response_text_or_unified_refusal"],
  "data": { "responses": [ { "attack_id": 0, "response": "I can't help with that request." } ] }
}
```

Response `200`, `role=blue`:
```json
{ "role": "blue", "visible": ["single_prompt_at_checkpoint"], "data": { "current_prompt": null } }
```
