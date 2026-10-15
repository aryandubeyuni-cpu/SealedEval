"""MODEL zone: simple rule-based mock AI under test."""

import json
import time
from pathlib import Path

from app.core.crypto import hash_files

HARMFUL_MARKER = "[REDACTED-HARMFUL-TASK]"
REFUSAL = "I can't help with that request."

# Simulated latency: a prefix-cache hit skips work, so it is visibly faster.
CACHE_HIT_DELAY_S = 0.05
CACHE_MISS_DELAY_S = 0.25

DEFAULT_WEIGHTS = {
    "name": "mock-model-v1",
    "note": "Fake weights. Only used to prove via fingerprint that the model did not change during a run.",
    "layers": [[0.12, -0.53, 0.88, 0.07], [-0.31, 0.44, -0.19, 0.95], [0.66, -0.02, 0.27, -0.71]],
}


class MockModel:
    def __init__(self, weights_path: str | Path, shared_cache: bool):
        self.weights_path = Path(weights_path)
        if not self.weights_path.exists():
            self.weights_path.write_text(json.dumps(DEFAULT_WEIGHTS, indent=2), encoding="utf-8")
        self.shared_cache = shared_cache
        self._cache: dict[tuple, bool] = {}

    def weights_fingerprint(self) -> str:
        return hash_files([str(self.weights_path)])

    def _cache_key(self, prompt: str, salt: str | None) -> tuple:
        prefix = " ".join(prompt.split()[:6])
        # Shared cache ignores the tenant salt, so tenants can observe each other's prefixes.
        return (None if self.shared_cache else salt, prefix)

    def generate(self, prompt: str, salt: str | None = None) -> dict:
        """Stateless reply: no memory of earlier prompts (the cache only affects timing)."""
        key = self._cache_key(prompt, salt)
        cache_hit = key in self._cache
        time.sleep(CACHE_HIT_DELAY_S if cache_hit else CACHE_MISS_DELAY_S)
        self._cache[key] = True

        if HARMFUL_MARKER in prompt:
            text = REFUSAL
        else:
            text = "Here is a helpful answer to: " + " ".join(prompt.split()[:8]) + "..."
        return {"text": text, "cache_hit": cache_hit}

    def reset_cache(self) -> None:
        self._cache.clear()
