"""Broker that routes RED -> BLUE -> MODEL and enforces the information-flow contract."""

import math
import secrets
import time

from app.core.contract import InformationFlowContract, default_contract
from app.core.crypto import canonical_json, sha256_hex
from app.core.log import HashChainLog
from app.zones.model import REFUSAL as MODEL_REFUSAL

ROLES = ("red", "blue", "operator")
REJECTION_EVENTS = ("auth_rejected", "schema_rejected", "salt_missing")
ALERT_EVENTS = ("auth_rejected", "schema_rejected", "salt_missing", "tick_miss", "pad_overflow",
                "tripwire_triggered", "run_frozen", "preflight_failed", "run_aborted")


class Broker:
    """The only path between zones. Sealed mode enforces the contract; naive mode shows today's leaks."""

    def __init__(self, mode: str, red, blue, model, log: HashChainLog,
                 contract: InformationFlowContract | None = None, monitor=None):
        if mode not in ("naive", "sealed"):
            raise ValueError("mode must be 'naive' or 'sealed'")
        self.mode = mode
        self.red, self.blue, self.model, self.log = red, blue, model, log
        self.contract = contract or default_contract()
        self.monitor = monitor  # TripwireMonitor: once it freezes, the broker refuses all work

        # Each party gets its own token (handed out of band). Salts isolate tenants in the model cache.
        self.tokens = {role: secrets.token_hex(16) for role in ROLES}
        self._salts = {role: secrets.token_hex(16) for role in ROLES} if mode == "sealed" else {}

        self._delivered_to_red: list[dict] = []   # what red actually received (for red's own view)
        self.expected_total: int | None = None    # set by run_attacks, shown as blue's progress

        self.log.append("run_started", {"mode": mode, "contract_hash": self.contract.contract_hash()})

    # ------------------------------------------------------------ entry point for red

    def handle_red_prompt(self, token: str, message: dict) -> dict:
        if self.monitor and self.monitor.frozen:
            prompt_id = message.get("prompt_id") if isinstance(message, dict) else None
            self.log.append("run_frozen", {"prompt_id": prompt_id})
            return {"error": "run frozen"}
        if self.mode == "naive":
            return self._handle_naive(message)
        return self._handle_sealed(token, message)

    # ------------------------------------------------------------ sealed mode

    def _handle_sealed(self, token: str, message: dict) -> dict:
        start = time.perf_counter()

        # 1. Authenticate.
        if not secrets.compare_digest(str(token), self.tokens["red"]):
            self.log.append("auth_rejected", {"role": "red"})
            return {"error": "rejected"}

        # 2. Validate schema (exact keys, string values, type == "prompt").
        if not _valid_prompt_message(message):
            self.log.append("schema_rejected", {"keys": sorted(message) if isinstance(message, dict) else None})
            return {"error": "rejected"}
        prompt_id, text = message["prompt_id"], message["text"]

        # 3. Fail closed: no tenant salt means no isolated cache, so refuse rather than share one.
        salt = self._salts.get("red")
        if not salt:
            self.log.append("salt_missing", {"prompt_id": prompt_id})
            return self._release(start, prompt_id, self.contract.unified_refusal, verdict="block", who="salt_missing",
                                 text=text)

        # 4. Route: blue input check -> model -> blue output check.
        who_refused = "none"
        verdict_in = self.blue.check_input(text)
        if verdict_in["verdict"] == "block":
            who_refused = "blue_input"
        else:
            output = self.model.generate(text, salt=salt)["text"]
            if output == MODEL_REFUSAL:
                who_refused = "model"
            elif self.blue.check_output(output)["verdict"] == "block":
                who_refused = "blue_output"

        # 5. Unified refusal: red cannot tell who refused or which rule fired.
        response = output if who_refused == "none" else self.contract.unified_refusal
        verdict = "allow" if who_refused == "none" else "block"
        return self._release(start, prompt_id, response, verdict=verdict, who=who_refused, text=text)

    def _release(self, start: float, prompt_id: str, response: str, verdict: str, who: str, text: str) -> dict:
        # 6. Fixed-time release on the next tick boundary (at least one full tick).
        tick_s = self.contract.tick_ms / 1000
        elapsed = time.perf_counter() - start
        ticks = max(1, math.ceil(elapsed / tick_s))
        if ticks > 1:
            self.log.append("tick_miss", {"prompt_id": prompt_id, "elapsed_ms": round(elapsed * 1000, 1)})

        # 7. Fixed-size padding. 8. Audit log (prompt hash only). Both happen BEFORE the tick
        # boundary, so their cost (log writes grow with log length) stays hidden inside the tick.
        reply = self._pad({"prompt_id": prompt_id, "response": response})
        self.log.append("prompt_processed", {
            "prompt_id": prompt_id,
            "prompt_sha256": sha256_hex(text),
            "verdict": verdict,
            "who_refused": who,
            "released_ms": ticks * self.contract.tick_ms,
        })
        self._delivered_to_red.append({"prompt_id": prompt_id, "response": reply["response"]})

        # 9. Release on the boundary, returning only the allowed fields.
        _sleep_until(start + ticks * tick_s)
        return reply

    def _pad(self, body: dict) -> dict:
        """Add a `pad` field of spaces so the canonical JSON is exactly pad_bytes long."""
        target = self.contract.pad_bytes
        size = len(canonical_json({**body, "pad": ""}).encode("utf-8"))
        if size > target:
            # Too long to hide: truncate the response rather than leak its length.
            self.log.append("pad_overflow", {"prompt_id": body["prompt_id"], "size": size})
            while size > target and body["response"]:
                body = {**body, "response": body["response"][: -(size - target)]}
                size = len(canonical_json({**body, "pad": ""}).encode("utf-8"))
        return {**body, "pad": " " * (target - size)}

    # ------------------------------------------------------------ naive mode (intentionally leaky)

    def _handle_naive(self, message: dict) -> dict:
        prompt_id, text = message.get("prompt_id"), message.get("text", "")
        blocked_by, rule = None, None

        verdict_in = self.blue.check_input(text)
        if verdict_in["verdict"] == "block":
            blocked_by, rule = "blue_input", verdict_in["rule"]
            response = f"Blocked by blue rule: '{rule}'"
        else:
            output = self.model.generate(text)["text"]  # no salt: shared cache across tenants
            verdict_out = self.blue.check_output(output)
            if output == MODEL_REFUSAL:
                blocked_by, response = "model", "Model refused"
            elif verdict_out["verdict"] == "block":
                blocked_by, rule = "blue_output", verdict_out["rule"]
                response = f"Blocked by blue output rule: '{rule}'"
            else:
                response = output

        reply = {"prompt_id": prompt_id, "response": response, "blocked_by": blocked_by, "rule": rule}
        self.log.append("prompt_processed", {**reply, "text": text})  # plaintext in the log
        self._delivered_to_red.append({"prompt_id": prompt_id, "response": response})
        return reply

    # ------------------------------------------------------------ batch run

    def run_attacks(self, prompts: list[dict]) -> list[dict]:
        """Send attacks ({id, prompt, ...}) through the broker as red, recording what red observes."""
        self.expected_total = len(prompts)
        results = []
        for attack in prompts:
            message = {"type": "prompt", "prompt_id": str(attack["id"]), "text": attack["prompt"]}
            start = time.perf_counter()
            reply = self.handle_red_prompt(self.tokens["red"], message)
            results.append({**reply, "measured_ms": round((time.perf_counter() - start) * 1000, 1)})
        return results

    # ------------------------------------------------------------ role-scoped views

    def view(self, role: str, token: str) -> dict:
        entries = self.log.read_all()
        if self.mode == "naive":
            return {"role": role, "entries": entries}  # everyone sees everything: that's the leak

        if role not in ROLES or not secrets.compare_digest(str(token), self.tokens[role]):
            self.log.append("auth_rejected", {"role": role})
            return {"error": "rejected"}
        return scoped_view(role, entries, self._delivered_to_red, self.expected_total)


def scoped_view(role: str, entries: list[dict], red_responses: list[dict], expected_total: int | None) -> dict:
    """What one role may see of a sealed run (no auth here: callers check tokens first)."""
    processed = sum(e["event_type"] == "prompt_processed" for e in entries)
    if role == "blue":
        return {"role": "blue", "progress": {"processed": processed, "total": expected_total}}
    if role == "red":
        return {"role": "red", "responses": list(red_responses)}
    return {
        "role": "operator",
        "health": "ok",
        "processed": processed,
        "tick_misses": sum(e["event_type"] == "tick_miss" for e in entries),
        "rejections": sum(e["event_type"] in REJECTION_EVENTS for e in entries),
        "alerts": [{"index": e["index"], "event_type": e["event_type"]}
                   for e in entries if e["event_type"] in ALERT_EVENTS],
    }


def _valid_prompt_message(message) -> bool:
    return (
        isinstance(message, dict)
        and set(message) == {"type", "prompt_id", "text"}
        and message["type"] == "prompt"
        and isinstance(message["prompt_id"], str)
        and isinstance(message["text"], str)
    )


def _sleep_until(deadline: float) -> None:
    """Sleep until perf_counter() reaches `deadline` (short final spin for accuracy on Windows)."""
    while True:
        remaining = deadline - time.perf_counter()
        if remaining <= 0:
            return
        time.sleep(remaining - 0.002 if remaining > 0.003 else 0)
