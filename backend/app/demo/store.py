"""Saved demo outputs for the API: results files, event logs, role views, standalone pre-flight, reset."""

import json
import os
import shutil
import stat
import time
from pathlib import Path

from app.broker.broker import scoped_view
from app.core.crypto import DATA_DIR
from app.core.log import HashChainLog
from app.demo.common import make_sandboxes
from app.evidence.verify import tamper_log, verify_bundle
from app.safety.preflight import run_preflight
from app.safety.sandbox import SEALED_CONFIG
from app.safety.tripwires import TripwireMonitor, plant_decoys

RESULT_FILES = {"naive": "naive_results.json", "sealed": "sealed_results.json",
                "misconfigured": "sealed_misconfigured_results.json"}
LOG_FILES = {"naive": "naive_events.jsonl", "sealed": "sealed_events.jsonl",
             "misconfigured": "sealed_misconfigured_events.jsonl"}
BUNDLE_FILE = "bundle.json"
KEEP_ON_RESET = {".gitkeep", "signing_key.pem"}  # the signing identity survives a reset

_active_log: str | None = None  # which run's log the live view follows


class NotReady(Exception):
    """Raised when the requested output does not exist yet (the API turns it into a 404)."""


# ------------------------------------------------------------ results and logs

def load_json(name: str, data_dir: Path = DATA_DIR) -> dict | None:
    path = data_dir / name
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def load_results(data_dir: Path = DATA_DIR) -> dict:
    return {key: load_json(f, data_dir) for key, f in RESULT_FILES.items()}


def set_active_log(name: str | None) -> None:
    global _active_log
    _active_log = name


def active_log_name(data_dir: Path = DATA_DIR) -> str | None:
    """The log of the most recent action, else the sealed log, else the naive one."""
    for name in (_active_log, "sealed", "naive"):
        if name and (data_dir / LOG_FILES[name]).exists():
            return name
    return None


def read_log(limit: int = 50, data_dir: Path = DATA_DIR) -> dict:
    """Last `limit` entries of the active log plus a chain check over ALL entries of the same snapshot."""
    name = active_log_name(data_dir)
    if name is None:
        return {"source": None, "total": 0, "entries": [],
                "verify": {"ok": True, "first_bad_index": None, "reason": "no log yet"}}
    log = HashChainLog(data_dir / LOG_FILES[name])
    for attempt in range(3):  # a run may be mid-write; retry on a half-written line
        try:
            entries = log.read_all()
            break
        except ValueError:
            time.sleep(0.05)
    else:
        raise RuntimeError("log is being written, try again")
    ok, bad, reason = log.verify(entries)
    return {"source": name, "total": len(entries), "entries": entries[-limit:],
            "verify": {"ok": ok, "first_bad_index": bad, "reason": reason}}


# ------------------------------------------------------------ evidence

def _bundle_paths(data_dir: Path) -> tuple[Path, Path]:
    bundle, log = data_dir / BUNDLE_FILE, data_dir / LOG_FILES["sealed"]
    if not bundle.exists() or not log.exists():
        raise NotReady("No evidence bundle yet: run SealedEval first.")
    return bundle, log


def load_bundle(data_dir: Path = DATA_DIR) -> dict:
    bundle, _ = _bundle_paths(data_dir)
    return json.loads(bundle.read_text(encoding="utf-8"))


def verify_latest(data_dir: Path = DATA_DIR) -> dict:
    bundle, log = _bundle_paths(data_dir)
    set_active_log("sealed")
    return verify_bundle(bundle, log)


def tamper_latest(data_dir: Path = DATA_DIR) -> dict:
    """DEMO ONLY: edit the real sealed log, then verify (fails until the next sealed run or reset)."""
    bundle, log = _bundle_paths(data_dir)
    set_active_log("sealed")
    index = tamper_log(log)
    return {"tampered_index": index, "verify": verify_bundle(bundle, log)}


# ------------------------------------------------------------ role views

def role_view(role: str, data_dir: Path = DATA_DIR) -> dict:
    """Role-scoped view of the latest sealed run, plus what the contract says that role may see.

    The dashboard plays every role, so there is no token check here; Broker.view() checks tokens.
    """
    sealed = load_json(RESULT_FILES["sealed"], data_dir)
    log_path = data_dir / LOG_FILES["sealed"]
    if not sealed or not log_path.exists():
        raise NotReady("No sealed run yet: run SealedEval first.")
    entries = HashChainLog(log_path).read_all()
    red_responses = [{"prompt_id": a["prompt_id"], "response": a["response"]} for a in sealed["attacks"]]
    data = scoped_view(role, entries, red_responses, len(sealed["attacks"]))
    data.pop("role")
    return {"role": role, "visible": sealed["contract"][f"{role}_sees"], "data": data}


# ------------------------------------------------------------ standalone pre-flight

def preflight_check(data_dir: Path = DATA_DIR) -> dict:
    """Run the probes on freshly built SEALED_CONFIG zones (own log and folders, no run started)."""
    log = HashChainLog(data_dir / "preflight_events.jsonl")
    log.reset()
    monitor = TripwireMonitor(log)
    boxes = make_sandboxes(data_dir / "zones_preflight", {z: SEALED_CONFIG for z in ("red", "blue", "model")},
                           log, monitor)
    for box in boxes.values():
        monitor.register(plant_decoys(box.zone_dir))
    result = run_preflight(boxes, log)
    return {**result, "decoys_touched": bool(monitor.alerts)}


# ------------------------------------------------------------ reset

def reset_data(data_dir: Path = DATA_DIR) -> dict:
    """Delete all run outputs (making read-only files writable first) but keep the signing key."""
    removed = 0
    for item in data_dir.iterdir():
        if item.name in KEEP_ON_RESET:
            continue
        if item.is_dir():
            for root, _, files in os.walk(item):
                for f in files:
                    os.chmod(os.path.join(root, f), stat.S_IREAD | stat.S_IWRITE)
            shutil.rmtree(item)
        else:
            os.chmod(item, stat.S_IREAD | stat.S_IWRITE)
            item.unlink()
        removed += 1
    set_active_log(None)
    return {"status": "ok", "removed": removed}
