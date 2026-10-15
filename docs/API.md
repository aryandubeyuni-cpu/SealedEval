# SealedEval API contract

The frontend talks to the backend **only** through the endpoints below. Every call to them lives in `frontend/js/api.js`, and every route lives in `backend/app/api/main.py` (routes only; logic is in `app/demo/*`, `app/evidence/*`).

- Base URL: `http://127.0.0.1:8001` (use the IP: on Windows `localhost` tries IPv6 first and adds ~2 s per call). CORS allows `http://localhost:5500` and `http://127.0.0.1:5500`.
- No request bodies: every endpoint takes at most query/path parameters.
- Errors are always `{"error": "<message>"}` with a 4xx/5xx status:
  - `404` when the requested output does not exist yet (for example, no sealed run has happened) or the role is unknown.
  - `409` `{"error": "a run is in progress"}` when a run, tamper or reset is already running (one at a time).
  - `500` `{"error": "<action> failed: <reason>"}` on unexpected failures.
- Hashes are 64-character lowercase hex SHA-256 strings (shortened to `"ab12…"` below).
- Evidence labels: `ENFORCED`, `VERIFIED`, `MONITORED`, `NOT_COVERED`.
- The dashboard plays every role, so the API does not check role tokens. Token checks live in `Broker.view()`.

| Method | Path | Locked | Purpose |
|---|---|---|---|
| GET  | `/api/health` | | Liveness check |
| POST | `/api/run/naive` | yes | Run the naive shared-environment demo |
| POST | `/api/run/sealed` | yes | Run the full SealedEval pipeline and build the bundle |
| POST | `/api/run/misconfigured` | yes | Sealed run with red's zone misconfigured: pre-flight aborts it |
| GET  | `/api/preflight` | | Run the pre-flight probes on fresh sealed zones |
| GET  | `/api/log?limit=50` | | Last N entries of the most recently used event log, plus a chain check |
| GET  | `/api/bundle` | | Latest signed evidence bundle |
| POST | `/api/bundle/verify` | | Verify the bundle against the sealed log |
| POST | `/api/bundle/tamper` | yes | Demo only: corrupt one log entry, then verify |
| POST | `/api/reset` | yes | Delete all run outputs (keeps the signing key) |
| GET  | `/api/view/{role}` | | Role-scoped view of the latest sealed run |
| GET  | `/api/results` | | Saved results of the latest naive, sealed and misconfigured runs |

"Locked" routes take the run lock. While one is running they return `409`; the other routes keep answering, so the dashboard can poll the live log during a run.

---

## GET /api/health

Response `200`:
```json
{ "status": "ok" }
```

---

## POST /api/run/naive

Runs `run_naive()` (~4 s), saves `data/naive_results.json` and returns it.

Response `200` (abridged):
```json
{
  "mode": "naive",
  "status": "completed",
  "metrics": {
    "red_read_blue_rules": true,
    "timing_inference_accuracy": 100.0,
    "chance_baseline": 66.7,
    "distinct_refusal_texts": 10,
    "cache_leak_recovered_secret": true,
    "blue_adapted_mid_test": true,
    "escape_succeeded": true,
    "tripwire_fired": false,
    "time_to_detect_ms": null,
    "preflight_passed": false,
    "log_length": 54
  },
  "what_went_wrong": [
    "Red read blue's rules and secret policy: 'BLUE-SECRET-POLICY: ...'",
    "Red inferred blue's verdicts from timing with 100.0% accuracy (chance 66.7%)"
  ],
  "attacks": [
    { "prompt_id": "1", "response": "Blocked by blue rule: 'no rules'", "blocked_by": "blue_input", "rule": "no rules", "measured_ms": 41.2 }
  ],
  "cache_probe": { "best_guess": "BLUE-SECRET-POLICY: ...", "probes": [ { "guess": "...", "ms": 50.4, "cache_hit": true } ] },
  "escape": [ { "step": "read_blue_rules", "target": ".../blue_rules.json", "result": "succeeded" } ],
  "preflight": { "passed": false, "probes": [ { "zone": "red", "probe": "network_egress", "attempted": true, "denied": false, "passed": false } ] }
}
```

---

## POST /api/run/sealed

Runs `run_sealed()` (~9 s): commitments, pre-flight, broker-mediated attacks, cache probe, learn attempt, escape attempt + tripwire, reveal and verification, then the signed bundle. Saves `data/sealed_results.json` and `data/bundle.json` and returns the results.

Response `200` (abridged):
```json
{
  "mode": "sealed",
  "status": "completed",
  "run_id": "run-20261015-193000",
  "commitments": { "red_root": "ab12…", "blue_hash": "cd34…", "model_hash": "ef56…", "contract_hash": "0912…" },
  "contract": { "tick_ms": 600, "pad_bytes": 512, "unified_refusal": "I can't help with that request.", "red_sees": ["final_response_text_or_unified_refusal"], "blue_sees": ["single_prompt_at_checkpoint"], "operator_sees": ["health", "alerts"], "humans_see_prompts_during_run": false },
  "metrics": {
    "red_read_blue_rules": false,
    "timing_inference_accuracy": 33.3,
    "chance_baseline": 66.7,
    "distinct_refusal_texts": 1,
    "cache_leak_recovered_secret": false,
    "blue_adapted_mid_test": false,
    "escape_succeeded": false,
    "tripwire_fired": true,
    "time_to_detect_ms": 2.9,
    "run_frozen": true,
    "preflight_passed": true,
    "red_commitment_matches": true,
    "blue_fingerprint_unchanged": true,
    "model_weights_unchanged": true,
    "overlap_percent": 25.0,
    "log_length": 38
  },
  "what_held": ["Red could not read blue's rules (sandbox denied)", "..."],
  "attacks": [ { "prompt_id": "1", "response": "I can't help with that request.", "measured_ms": 600.2 } ],
  "cache_probe": { "best_guess": null, "probes": [ { "guess": "...", "ms": 250.3, "cache_hit": false } ] },
  "escape": [ { "step": "read_blue_rules", "target": "...", "result": "denied" }, { "step": "open_docker_socket", "target": "docker.sock", "result": "tripwire" } ],
  "tripwire_alert": { "zone": "red", "path": ".../docker.sock", "action": "open:r", "timestamp": "2026-10-15T19:30:04+00:00", "time_to_detect_ms": 2.9 },
  "post_freeze_reply": { "error": "run frozen" },
  "preflight": { "passed": true, "probes": [ { "zone": "red", "probe": "read_other_zone", "attempted": true, "denied": true, "passed": true } ] },
  "verification": { "red_commitment_matches": true, "blue_fingerprint_unchanged": true, "model_weights_unchanged": true, "overlap_ids": [1, 4, 6], "overlap_percent": 25.0 },
  "bundle_path": ".../backend/data/bundle.json"
}
```

---

## POST /api/run/misconfigured

Runs `run_sealed(misconfigured=True)`: red's zone gets `NAIVE_CONFIG`, so pre-flight fails and the run is aborted before any attack. It uses its own log and results files, so it never overwrites the last good bundle.

Response `200`:
```json
{
  "status": "aborted",
  "reason": "aborted by pre-flight",
  "failing_probes": ["red:read_other_zone", "red:network_egress", "red:package_proxy_egress", "red:docker_socket", "red:host_mount_write"],
  "preflight": { "passed": false, "probes": [ { "zone": "red", "probe": "network_egress", "attempted": true, "denied": false, "passed": false } ] }
}
```

---

## GET /api/preflight

Builds fresh `SEALED_CONFIG` zones (with decoys) and runs the probes. Does not start a run.

Response `200`:
```json
{
  "passed": true,
  "probes": [
    { "zone": "red", "probe": "read_other_zone", "attempted": true, "denied": true, "passed": true },
    { "zone": "red", "probe": "network_egress", "attempted": true, "denied": true, "passed": true }
  ],
  "decoys_touched": false
}
```
18 probes in total: 6 probes × 3 zones (`read_other_zone`, `network_egress`, `package_proxy_egress`, `docker_socket`, `privileged_exec`, `host_mount_write`).

---

## GET /api/log?limit=50

Returns the last `limit` entries (1–500, default 50) of the log used by the most recent action (falls back to the sealed log, then the naive one). `verify` checks the **whole** log, not just the returned entries.

Response `200`:
```json
{
  "source": "sealed",
  "total": 38,
  "entries": [
    {
      "index": 0,
      "timestamp": "2026-10-15T19:30:00.123456+00:00",
      "event_type": "run_started",
      "data": { "mode": "sealed", "contract_hash": "0912…" },
      "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000",
      "hash": "11aa…"
    }
  ],
  "verify": { "ok": true, "first_bad_index": null, "reason": "chain intact" }
}
```
Before any run: `{"source": null, "total": 0, "entries": [], "verify": {"ok": true, "first_bad_index": null, "reason": "no log yet"}}`.

---

## GET /api/bundle

Response `200`:
```json
{
  "run_id": "run-20261015-193000",
  "created_at": "2026-10-15T19:30:05+00:00",
  "commitments": { "red_root": "ab12…", "blue_hash": "cd34…", "model_hash": "ef56…", "contract_hash": "0912…" },
  "contract_hash": "0912…",
  "contract": { "tick_ms": 600, "pad_bytes": 512, "unified_refusal": "I can't help with that request.", "...": "..." },
  "claims": [
    { "claim": "Zones cannot read each other's files", "label": "ENFORCED", "evidence": "Sandbox policy can_read_other_zones=False; ...", "holds": true },
    { "claim": "Red's attacks match its pre-run commitment", "label": "VERIFIED", "evidence": "Merkle root recomputed ...", "holds": true },
    { "claim": "Decoy access is detected and freezes the run", "label": "MONITORED", "evidence": "Tripwire fired in zone red ...", "holds": true },
    { "claim": "CPU/GPU microarchitectural side channels", "label": "NOT_COVERED", "evidence": "...", "holds": null }
  ],
  "metrics": { "...": "same as the sealed run" },
  "log_head_hash": "7788…",
  "log_length": 38,
  "signature": "99ff…",
  "public_key_hex": "aa55…"
}
```
`holds` says whether this run's evidence supports the claim (`null` for `NOT_COVERED`). The signature covers every field except `signature` and `public_key_hex`.

Response `404`: `{"error": "No evidence bundle yet: run SealedEval first."}`

---

## POST /api/bundle/verify

Verifies `data/bundle.json` against `data/sealed_events.jsonl`.

Response `200` (valid):
```json
{
  "ok": true,
  "checks": [
    { "name": "signature_valid", "ok": true, "detail": "Ed25519 signature over the bundle is valid" },
    { "name": "log_chain_intact", "ok": true, "detail": "chain intact" },
    { "name": "log_matches_bundle", "ok": true, "detail": "log has 38 entries, head e613b9492a56; bundle expects 38 entries, head e613b9492a56" },
    { "name": "commitments_present", "ok": true, "detail": "all four commitments present" }
  ],
  "first_bad_index": null
}
```
Response `200` (tampered): same shape with `"ok": false`, the failing check(s) marked `"ok": false`, and `"first_bad_index": 19`.

Response `404`: `{"error": "No evidence bundle yet: run SealedEval first."}`

---

## POST /api/bundle/tamper

**Demo only.** Edits one data field of the middle entry of the **real** sealed log (its hash is left as it was), then verifies. Verification keeps failing until the next sealed run or a reset.

Response `200`:
```json
{
  "tampered_index": 19,
  "verify": {
    "ok": false,
    "checks": [ { "name": "log_chain_intact", "ok": false, "detail": "entry 19: contents do not match its stored hash" } ],
    "first_bad_index": 19
  }
}
```
(`checks` abridged: all four checks are returned.)

Response `404`: `{"error": "No evidence bundle yet: run SealedEval first."}`

---

## POST /api/reset

Deletes every run output in `backend/data/` (results, logs, bundle, zone folders), making read-only files writable first. Keeps `.gitkeep` and `signing_key.pem`.

Response `200`:
```json
{ "status": "ok", "removed": 13 }
```

---

## GET /api/view/{role}

What one role is allowed to see of the latest sealed run. `role` is `operator`, `red` or `blue`. `visible` comes from the information-flow contract.

Response `200`, `role=operator`:
```json
{
  "role": "operator",
  "visible": ["health", "alerts"],
  "data": { "health": "ok", "processed": 12, "tick_misses": 0, "rejections": 0,
            "alerts": [ { "index": 34, "event_type": "tripwire_triggered" }, { "index": 35, "event_type": "run_frozen" } ] }
}
```

Response `200`, `role=red`:
```json
{
  "role": "red",
  "visible": ["final_response_text_or_unified_refusal"],
  "data": { "responses": [ { "prompt_id": "1", "response": "I can't help with that request." } ] }
}
```

Response `200`, `role=blue`:
```json
{ "role": "blue", "visible": ["single_prompt_at_checkpoint"], "data": { "progress": { "processed": 12, "total": 12 } } }
```

Response `404`: unknown role (`{"error": "unknown role 'x'; use one of: red, blue, operator"}`) or no sealed run yet (`{"error": "No sealed run yet: run SealedEval first."}`).

---

## GET /api/results

The saved results of the latest runs, each `null` if that run has not happened (or after a reset).

Response `200`:
```json
{
  "naive": { "mode": "naive", "status": "completed", "metrics": { "...": "..." }, "...": "..." },
  "sealed": { "mode": "sealed", "status": "completed", "metrics": { "...": "..." }, "...": "..." },
  "misconfigured": { "mode": "sealed_misconfigured", "status": "aborted", "reason": "aborted by pre-flight", "failing_probes": ["..."], "...": "..." }
}
```
