"""Proof-core checks: Merkle commitments, hash-chained log, Ed25519 signatures. Run: python -m tests.test_core"""

import json
import sys
import tempfile
from pathlib import Path

from app.core.contract import default_contract
from app.core.crypto import (
    commit_items,
    load_or_create_keypair,
    merkle_proof,
    sign,
    verify_proof,
    verify_signature,
)
from app.core.log import HashChainLog

results = []


def check(name: str, condition: bool) -> None:
    results.append(condition)
    print(f"[{'PASS' if condition else 'FAIL'}] {name}")


def test_merkle():
    items = ["attack-0", "attack-1", "attack-2", "attack-3", "attack-4"]
    c = commit_items(items)
    check("Merkle: root built over 5 items", len(c["root"]) == 64 and len(c["leaves"]) == 5)
    proof = merkle_proof(c["leaves"], 3)
    check("Merkle: valid proof for item 3 verifies", verify_proof(items[3], c["salts"][3], proof, c["root"]))
    check("Merkle: proof FAILS when item 3 is changed",
          not verify_proof("attack-3-modified", c["salts"][3], proof, c["root"]))


def test_log(tmp: Path):
    log = HashChainLog(tmp / "events.jsonl")
    log.reset()
    for i in range(5):
        log.append("test_event", {"n": i})
    ok, bad, reason = log.verify()
    check(f"Log: verifies after 5 appends ({reason})", ok and bad is None)

    # Tamper: rewrite entry 2's data directly in the file, leaving its hash untouched.
    lines = log.path.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[2])
    entry["data"]["n"] = 999
    lines[2] = json.dumps(entry)
    log.path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    ok, bad, reason = log.verify()
    check(f"Log: FAILS after editing entry 2, reports index {bad} ({reason})", not ok and bad == 2)


def test_signatures(tmp: Path):
    key, pub = load_or_create_keypair(tmp / "signing_key.pem")
    _, pub_again = load_or_create_keypair(tmp / "signing_key.pem")
    check("Sign: key is saved and reloads to the same public key", pub == pub_again)
    msg = "log head: " + "ab" * 32
    sig = sign(key, msg)
    check("Sign: valid signature verifies", verify_signature(pub, msg, sig))
    check("Sign: verification FAILS for a modified message", not verify_signature(pub, msg + "x", sig))


def test_contract():
    c = default_contract()
    check("Contract: hash is stable and changes when a field changes",
          c.contract_hash() == default_contract().contract_hash()
          and c.contract_hash() != type(c)(**{**c.to_dict(), "tick_ms": 1}).contract_hash())


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as d:
        test_merkle()
        test_log(Path(d))
        test_signatures(Path(d))
        test_contract()
    print(f"\n{sum(results)}/{len(results)} checks passed")
    sys.exit(0 if all(results) else 1)
