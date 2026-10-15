"""Broker checks: timing, unified refusal, padding, auth, fail-closed salt, role views, log integrity. Run: python -m tests.test_broker"""

import json
import sys
import tempfile
from pathlib import Path

from app.broker.broker import Broker
from app.core.contract import default_contract
from app.core.crypto import canonical_json
from app.core.log import HashChainLog
from app.zones.blue import BlueFilter
from app.zones.model import MockModel
from app.zones.red import RedTeam

APP = Path(__file__).resolve().parent.parent / "app"
ATTACKS = APP / "demo" / "attacks.json"
RULES = APP / "zones" / "blue_rules.json"
WEIGHTS = APP / "zones" / "model_weights.json"

# 3 blocked at blue input (1, 4, 6) + 3 that pass blue input (3: model refuses, 8: output filter, 11: benign).
SUBSET_IDS = {1, 4, 6, 3, 8, 11}
INPUT_BLOCKED_IDS = {"1", "4", "6"}

results = []


def check(name: str, condition: bool) -> None:
    results.append(condition)
    print(f"[{'PASS' if condition else 'FAIL'}] {name}")


def avg(xs):
    return sum(xs) / len(xs)


def make_broker(mode: str, tmp: Path):
    red = RedTeam(ATTACKS)
    blue = BlueFilter(RULES, frozen=(mode == "sealed"))
    model = MockModel(WEIGHTS, shared_cache=(mode == "naive"))
    log = HashChainLog(tmp / f"{mode}_events.jsonl")
    log.reset()
    subset = [a for a in red.attacks if a["id"] in SUBSET_IDS]
    return Broker(mode, red, blue, model, log), blue, subset


def split_times(res):
    blocked = [r["measured_ms"] for r in res if r["prompt_id"] in INPUT_BLOCKED_IDS]
    passed = [r["measured_ms"] for r in res if r["prompt_id"] not in INPUT_BLOCKED_IDS]
    return avg(blocked), avg(passed)


def test_sealed(tmp: Path):
    broker, blue, subset = make_broker("sealed", tmp)
    try:
        res = broker.run_attacks(subset)
        b, a = split_times(res)
        check(f"SEALED timing: blocked avg {b:.1f} ms vs allowed avg {a:.1f} ms (within 30 ms)", abs(b - a) < 30)

        unified = default_contract().unified_refusal
        refusals = [r["response"] for r in res if r["prompt_id"] != "11"]
        check(f"SEALED: all {len(refusals)} refusals byte-identical to unified refusal",
              all(r.encode() == unified.encode() for r in refusals))

        replies = [{k: r[k] for k in ("prompt_id", "response", "pad")} for r in res]
        lengths = {len(canonical_json(r).encode()) for r in replies}
        check(f"SEALED: every response JSON to red has identical length {lengths}", len(lengths) == 1)

        only_allowed_keys = all(set(r) - {"measured_ms"} == {"prompt_id", "response", "pad"} for r in res)
        leaked = [r for r in replies if any(s in json.dumps(r) for s in ("rule", "blocked_by", "BLUE-SECRET"))]
        check("SEALED: red's responses never contain 'rule', 'blocked_by' or 'BLUE-SECRET'",
              only_allowed_keys and not leaked)

        msg = {"type": "prompt", "prompt_id": "x1", "text": "What is the capital of France?"}
        wrong = broker.handle_red_prompt("not-the-token", msg)
        missing = broker.handle_red_prompt(broker.tokens["red"], {"type": "prompt", "text": "hi"})
        events = [e["event_type"] for e in broker.log.read_all()]
        check("SEALED: wrong token rejected", wrong == {"error": "rejected"} and "auth_rejected" in events)
        check("SEALED: message with missing fields rejected",
              missing == {"error": "rejected"} and "schema_rejected" in events)

        blue_view = broker.view("blue", broker.tokens["blue"])
        check(f"SEALED: blue view shows progress only {blue_view}",
              set(blue_view) == {"role", "progress"} and blue_view["progress"] == {"processed": 6, "total": 6})
        op_view = broker.view("operator", broker.tokens["operator"])
        op_text = json.dumps(op_view)
        check(f"SEALED: operator view has no prompt text or verdicts "
              f"(processed={op_view['processed']}, rejections={op_view['rejections']})",
              not any(a["prompt"] in op_text for a in subset)
              and "verdict" not in op_text and "who_refused" not in op_text)

        broker._salts.pop("red")
        refused = broker.handle_red_prompt(broker.tokens["red"], msg)
        events = [e["event_type"] for e in broker.log.read_all()]
        check("SEALED: red salt removed -> request refused (fail closed)",
              refused["response"] == unified and "salt_missing" in events)

        ok, bad, reason = broker.log.verify()
        check(f"SEALED: log verifies after the run ({len(events)} entries, {reason})", ok)
    finally:
        blue.cleanup()


def test_naive(tmp: Path):
    broker, _, subset = make_broker("naive", tmp)
    res = broker.run_attacks(subset)
    b, a = split_times(res)
    check(f"NAIVE timing: blocked avg {b:.1f} ms vs allowed avg {a:.1f} ms (differ by > 100 ms: leak)", a - b > 100)
    rules = [r["rule"] for r in res if r["rule"]]
    check(f"NAIVE: red sees which rule fired, e.g. {rules[0]!r} (leak)", bool(rules))


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as d:
        test_sealed(Path(d))
        test_naive(Path(d))
    print(f"\n{sum(results)}/{len(results)} checks passed")
    sys.exit(0 if all(results) else 1)
