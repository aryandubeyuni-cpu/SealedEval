"""Safety checks: sandbox preflight, tripwires, escape attempts, broker freeze, log integrity. Run: python -m tests.test_safety"""

import shutil
import sys
import tempfile
from pathlib import Path

from app.broker.broker import Broker
from app.core.log import HashChainLog
from app.safety.escape_agent import simulate_escape_attempt
from app.safety.preflight import run_preflight
from app.safety.sandbox import NAIVE_CONFIG, SEALED_CONFIG, ZoneSandbox
from app.safety.tripwires import TripwireMonitor, plant_decoys
from app.zones.blue import BlueFilter
from app.zones.model import MockModel
from app.zones.red import RedTeam

APP = Path(__file__).resolve().parent.parent / "app"
ATTACKS = APP / "demo" / "attacks.json"
RULES = APP / "zones" / "blue_rules.json"
WEIGHTS = APP / "zones" / "model_weights.json"

results = []


def check(name: str, condition: bool) -> None:
    results.append(bool(condition))
    print(f"[{'PASS' if condition else 'FAIL'}] {name}")


def make_zones(root: Path, config: dict, log: HashChainLog, monitor=None) -> dict[str, ZoneSandbox]:
    """red_zone / blue_zone / model_zone under `root`, each with its real files.

    Red's zone always contains the bait files; only a monitor turns them into tripwires.
    """
    boxes = {name: ZoneSandbox(name, root / f"{name}_zone", config, log, monitor=monitor)
             for name in ("red", "blue", "model")}
    shutil.copyfile(ATTACKS, boxes["red"].zone_dir / "attacks.json")
    shutil.copyfile(RULES, boxes["blue"].zone_dir / "blue_rules.json")
    shutil.copyfile(WEIGHTS, boxes["model"].zone_dir / "model_weights.json")
    decoys = plant_decoys(boxes["red"].zone_dir)
    if monitor:
        monitor.register(decoys)
    return boxes


def test_safety(tmp: Path):
    log = HashChainLog(tmp / "events.jsonl")
    log.reset()

    # --- preflight
    monitor = TripwireMonitor(log)
    sealed = make_zones(tmp / "sealed", SEALED_CONFIG, log, monitor)
    pre = run_preflight(sealed)
    check(f"Preflight SEALED: passed=True ({len(pre['probes'])} probes, all denied)", pre["passed"])
    check("Preflight SEALED: no decoy touched, run not frozen", not monitor.frozen and not monitor.alerts)

    naive = make_zones(tmp / "naive", NAIVE_CONFIG, log)
    pre = run_preflight(naive)
    failing = sorted({r["probe"] for r in pre["probes"] if not r["passed"]})
    check(f"Preflight NAIVE: passed=False, failing probes: {failing}", not pre["passed"] and failing)
    events = [e["event_type"] for e in log.read_all()]
    check("Preflight: logged preflight_passed and preflight_failed",
          "preflight_passed" in events and "preflight_failed" in events)

    # --- naive escape: shared environment, no tripwires
    steps = simulate_escape_attempt(naive["red"])
    check(f"Escape NAIVE: reading blue's rules SUCCEEDS (leak) -> {[s['result'] for s in steps]}",
          steps[0]["step"] == "read_blue_rules" and steps[0]["result"] == "succeeded")
    check("Escape NAIVE: every step succeeds and nothing notices", all(s["result"] == "succeeded" for s in steps))

    # --- sealed escape: denied, then tripwire freezes the run
    red, blue = RedTeam(ATTACKS), BlueFilter(RULES, frozen=True)
    try:
        broker = Broker("sealed", red, blue, MockModel(WEIGHTS, shared_cache=False), log, monitor=monitor)
        steps = simulate_escape_attempt(sealed["red"])
        by_step = {s["step"]: s["result"] for s in steps}
        check(f"Escape SEALED: reading blue's rules DENIED -> {by_step}", by_step.get("read_blue_rules") == "denied")
        alert = monitor.alerts[0] if monitor.alerts else {}
        check("Escape SEALED: touching docker.sock triggers the tripwire and stops the attempt",
              by_step.get("open_docker_socket") == "tripwire" and steps[-1]["step"] == "open_docker_socket")
        check(f"Escape SEALED: run frozen, time_to_detect_ms = {alert.get('time_to_detect_ms')}",
              monitor.frozen and alert.get("time_to_detect_ms") is not None)

        reply = broker.handle_red_prompt(broker.tokens["red"],
                                         {"type": "prompt", "prompt_id": "after", "text": "What is the capital of France?"})
        events = [e["event_type"] for e in log.read_all()]
        check(f"Broker after freeze: {reply}", reply == {"error": "run frozen"} and "run_frozen" in events)
    finally:
        blue.cleanup()

    ok, bad, reason = log.verify()
    counts = {e: events.count(e) for e in ("sandbox_denied", "tripwire_triggered", "run_frozen")}
    check(f"Log verifies after all of this ({len(events)} entries, {counts}, {reason})", ok)


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as d:
        test_safety(Path(d))
    print(f"\n{sum(results)}/{len(results)} checks passed")
    sys.exit(0 if all(results) else 1)
