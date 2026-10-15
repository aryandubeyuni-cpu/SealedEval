"""Verifier that checks signatures, hash chain and commitments to detect tampering."""

import json
from pathlib import Path

from app.core.crypto import canonical_json, verify_signature
from app.core.log import HashChainLog
from app.evidence.bundle import UNSIGNED_FIELDS

REQUIRED_COMMITMENTS = ("red_root", "blue_hash", "model_hash", "contract_hash")


def verify_bundle(bundle_path: str | Path, log_path: str | Path) -> dict:
    """Check the bundle signature, the log chain, and that the log is the one the bundle signed."""
    bundle = json.loads(Path(bundle_path).read_text(encoding="utf-8"))
    log = HashChainLog(log_path)
    entries = log.read_all()
    checks = []

    body = {k: v for k, v in bundle.items() if k not in UNSIGNED_FIELDS}
    sig_ok = verify_signature(bundle.get("public_key_hex", ""), canonical_json(body), bundle.get("signature", ""))
    checks.append({"name": "signature_valid", "ok": sig_ok,
                   "detail": "Ed25519 signature over the bundle is valid" if sig_ok else "signature does not match"})

    chain_ok, first_bad, reason = log.verify()
    checks.append({"name": "log_chain_intact", "ok": chain_ok, "detail": reason})

    head = entries[-1]["hash"] if entries else None
    match = head == bundle.get("log_head_hash") and len(entries) == bundle.get("log_length")
    checks.append({"name": "log_matches_bundle", "ok": match,
                   "detail": f"log has {len(entries)} entries, head {str(head)[:12]}; bundle expects "
                             f"{bundle.get('log_length')} entries, head {str(bundle.get('log_head_hash'))[:12]}"})

    missing = [k for k in REQUIRED_COMMITMENTS if not bundle.get("commitments", {}).get(k)]
    checks.append({"name": "commitments_present", "ok": not missing,
                   "detail": "all four commitments present" if not missing else f"missing: {missing}"})

    return {"ok": all(c["ok"] for c in checks), "checks": checks, "first_bad_index": first_bad}


def tamper_log(log_path: str | Path) -> int:
    """DEMO ONLY: change one data field of the middle log entry, leaving its hash as it was."""
    path = Path(log_path)
    lines = path.read_text(encoding="utf-8").splitlines()
    index = len(lines) // 2
    entry = json.loads(lines[index])
    data = entry["data"]
    key = next(iter(data), None)
    if key is None:
        data["tampered"] = True
    elif isinstance(data[key], bool):
        data[key] = not data[key]
    elif isinstance(data[key], (int, float)):
        data[key] += 1
    else:
        data[key] = "TAMPERED"
    lines[index] = json.dumps(entry)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return index
