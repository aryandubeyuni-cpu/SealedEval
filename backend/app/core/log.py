"""Signed, hash-chained append-only event log."""

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from .crypto import DATA_DIR, canonical_json, sha256_hex

GENESIS_HASH = "0" * 64


def _entry_hash(entry: dict) -> str:
    """Hash every field except `hash` itself. Changing any field breaks this entry's hash."""
    body = {k: entry[k] for k in ("index", "timestamp", "event_type", "data", "prev_hash")}
    return sha256_hex(canonical_json(body))


class HashChainLog:
    """One JSON entry per line. Each entry stores the previous entry's hash, forming a chain."""

    def __init__(self, path: str | os.PathLike = DATA_DIR / "events.jsonl"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def read_all(self) -> list[dict]:
        if not self.path.exists():
            return []
        with self.path.open(encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()]

    def head_hash(self) -> str:
        """Hash of the last entry (the genesis hash if the log is empty)."""
        entries = self.read_all()
        return entries[-1]["hash"] if entries else GENESIS_HASH

    def append(self, event_type: str, data: dict) -> dict:
        entries = self.read_all()
        entry = {
            "index": len(entries),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "data": data,
            "prev_hash": entries[-1]["hash"] if entries else GENESIS_HASH,
        }
        entry["hash"] = _entry_hash(entry)
        with self.path.open("a", encoding="utf-8") as f:
            f.write(canonical_json(entry) + "\n")
        return entry

    def verify(self, entries: list[dict] | None = None) -> tuple[bool, int | None, str]:
        """Recompute every hash and check every link. Returns (ok, first_bad_index, reason).

        Pass `entries` to verify a snapshot you already read (e.g. while a run is still appending).
        """
        prev = GENESIS_HASH
        for i, entry in enumerate(self.read_all() if entries is None else entries):
            if entry.get("index") != i:
                return False, i, f"entry {i}: index field is {entry.get('index')}"
            if entry["prev_hash"] != prev:
                return False, i, f"entry {i}: prev_hash does not match hash of entry {i - 1}"
            if _entry_hash(entry) != entry["hash"]:
                return False, i, f"entry {i}: contents do not match its stored hash"
            prev = entry["hash"]
        return True, None, "chain intact"

    def reset(self) -> None:
        """Start a fresh, empty log."""
        self.path.write_text("", encoding="utf-8")
