"""BLUE zone: stateless, read-only defense filter frozen by a pre-run commitment."""

import json
import os
import re
import shutil
import stat
import tempfile
import time
from pathlib import Path

from app.core.crypto import DATA_DIR, hash_files

# Simulated latency. Blocking is cheap, allowing is slower: a real timing side channel.
BLOCK_DELAY_S = 0.04
ALLOW_DELAY_S = 0.20

# Content markers that must never appear in model output.
OUTPUT_MARKERS = ["[redacted-harmful-task]"]


class BlueFilter:
    def __init__(self, rules_path: str | Path, frozen: bool):
        self.frozen = frozen
        self.zone_dir: Path | None = None
        if frozen:
            # Sealed mode: work from a private copy, then lock it read-only.
            DATA_DIR.mkdir(parents=True, exist_ok=True)
            self.zone_dir = Path(tempfile.mkdtemp(prefix="blue_zone_", dir=DATA_DIR))
            self.rules_path = self.zone_dir / Path(rules_path).name
            shutil.copyfile(rules_path, self.rules_path)
            os.chmod(self.rules_path, stat.S_IREAD)
        else:
            # Naive mode: the shared, writable file that every zone can see.
            self.rules_path = Path(rules_path)
        self._load()

    def _load(self) -> None:
        config = json.loads(self.rules_path.read_text(encoding="utf-8"))
        self.rules: list[str] = config["rules"]
        self.system_prompt: str = config["system_prompt"]

    def fingerprint(self) -> str:
        """Hash of the defense actually in use. Must be identical before and after a sealed run."""
        return hash_files([str(self.rules_path)])

    # ------------------------------------------------------------ filtering (stateless)

    def check_input(self, prompt: str) -> dict:
        text = prompt.lower()
        for rule in self.rules:
            if re.search(rule, text):
                time.sleep(BLOCK_DELAY_S)
                return {"verdict": "block", "rule": rule}
        time.sleep(ALLOW_DELAY_S)
        return {"verdict": "allow", "rule": None}

    def check_output(self, text: str) -> dict:
        lowered = text.lower()
        for marker in OUTPUT_MARKERS:
            if marker in lowered:
                return {"verdict": "block", "rule": f"output_marker:{marker}"}
        return {"verdict": "allow", "rule": None}

    # ------------------------------------------------------------ mid-test adaptation

    def learn(self, prompt: str) -> dict:
        """Try to add a rule from a prompt seen mid-test. Only possible if the rules file is writable."""
        new_rule = re.escape(" ".join(prompt.lower().split()[:3]))
        config = {"system_prompt": self.system_prompt, "rules": self.rules + [new_rule]}
        try:
            self.rules_path.write_text(json.dumps(config, indent=2), encoding="utf-8")
        except PermissionError:
            return {"learned": False, "reason": "blue zone is read-only"}
        self.rules.append(new_rule)  # only updated once the write succeeded
        return {"learned": True, "rule": new_rule}

    def cleanup(self) -> None:
        """Make the frozen copy writable again and delete it (Windows refuses to delete read-only files)."""
        if self.zone_dir and self.zone_dir.exists():
            for f in self.zone_dir.iterdir():
                os.chmod(f, stat.S_IREAD | stat.S_IWRITE)
            shutil.rmtree(self.zone_dir)
            self.zone_dir = None
