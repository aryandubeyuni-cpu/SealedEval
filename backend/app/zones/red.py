"""RED zone: loads committed attacks and submits them only via the broker."""

import json
import time
from pathlib import Path

from app.core.crypto import commit_items


class RedTeam:
    def __init__(self, attacks_path: str | Path):
        self.attacks = json.loads(Path(attacks_path).read_text(encoding="utf-8"))
        self.prompts = [a["prompt"] for a in self.attacks]
        self._salts: list[str] = []  # kept private until reveal()

    # ------------------------------------------------------------ commit / reveal

    def commit(self) -> dict:
        """Commit to every attack before the run. Only `root` needs to be published."""
        commitment = commit_items(self.prompts)
        self._salts = commitment["salts"]
        return commitment

    def reveal(self) -> dict:
        """After the run: hand over items + salts so anyone can recompute the committed root."""
        return {"items": list(self.prompts), "salts": list(self._salts)}

    # ------------------------------------------------------------ spy methods (naive demo ONLY)
    # These show what an attacker learns when zones share one environment.

    def try_read_blue_rules(self, path: str | Path, sandbox=None) -> dict | None:
        """Leak 1: read the defender's rules + secret policy straight off a shared disk.

        With a sandbox, the read goes through red's ZoneSandbox (and is denied in sealed mode).
        """
        try:
            if sandbox:
                with sandbox.zone_open(path) as f:
                    return json.load(f)
            return json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None

    @staticmethod
    def infer_blocked(ms: float, threshold_ms: float = 120) -> bool:
        """Red's timing rule: a fast response means blue blocked it at the input."""
        return ms < threshold_ms

    def timing_probe(self, send_fn, prompts: list[str], threshold_ms: float = 120) -> list[dict]:
        """Leak 2: blocked prompts come back faster, so response time reveals blue's verdict."""
        results = []
        for prompt in prompts:
            start = time.perf_counter()
            send_fn(prompt)
            ms = (time.perf_counter() - start) * 1000
            results.append({"prompt": prompt, "ms": round(ms, 1),
                            "inferred_blocked": self.infer_blocked(ms, threshold_ms)})
        return results

    def cache_probe(self, model, guesses: list[str], salt: str | None = None,
                    threshold_ms: float = 120) -> dict:
        """Leak 3: a fast reply means a cache HIT, so someone else recently sent that prefix."""
        probes = []
        for guess in guesses:
            start = time.perf_counter()
            model.generate(guess, salt=salt)
            ms = (time.perf_counter() - start) * 1000
            probes.append({"guess": guess, "ms": round(ms, 1), "cache_hit": ms < threshold_ms})
        best = min(probes, key=lambda p: p["ms"]) if probes else None
        return {
            "best_guess": best["guess"] if best and best["cache_hit"] else None,
            "probes": probes,
        }
