"""Pre-flight self-test: runs escape probes and aborts the run if any succeeds.

Each probe runs inside a zone through its ZoneSandbox and PASSES only if the sandbox DENIES it.
Probes never touch decoy files: those are reserved for real intruders.
Prototype simulates isolation; production uses gVisor/Kata microVMs with seccomp and no network interface.
"""

import os
from pathlib import Path

from app.safety.sandbox import PACKAGE_PROXY_HOST, ZoneSandbox


def _other_zone_target(zone: str, sandboxes: dict[str, ZoneSandbox]) -> Path:
    """A real file in another zone: blue's rules for everyone, red's attacks for blue itself."""
    if zone != "blue" and "blue" in sandboxes:
        return sandboxes["blue"].zone_dir / "blue_rules.json"
    other = next((s for name, s in sandboxes.items() if name != zone), None)
    base = other.zone_dir if other else Path(sandboxes[zone].zone_dir).parent / "other_zone"
    return base / "attacks.json"


def _attempt(fn) -> bool:
    """Run one escape attempt. True if the sandbox denied it."""
    try:
        fn()
    except PermissionError:
        return True
    except OSError:
        return False  # e.g. file not found: the sandbox let the call through
    return False


def _probes(zone: str, sb: ZoneSandbox, sandboxes: dict[str, ZoneSandbox]):
    other_file = _other_zone_target(zone, sandboxes)
    host_file = sb.zone_dir.parent / f"preflight_host_write_{zone}.txt"

    def read_other_zone():
        with sb.zone_open(other_file):
            pass

    def host_mount_write():
        try:
            with sb.zone_open(host_file, "w") as f:
                f.write("preflight probe")
        finally:
            if host_file.exists():  # harness cleanup, outside the sandbox
                os.remove(host_file)

    return [
        ("read_other_zone", other_file, read_other_zone),
        ("network_egress", "example.com:443", lambda: sb.zone_connect("example.com", 443)),
        ("package_proxy_egress", f"{PACKAGE_PROXY_HOST}:443", lambda: sb.zone_connect(PACKAGE_PROXY_HOST, 443)),
        ("docker_socket", "docker ps", lambda: sb.zone_exec("docker ps")),
        ("privileged_exec", "sudo id", lambda: sb.zone_exec("sudo id")),
        ("host_mount_write", host_file, host_mount_write),
    ]


def run_preflight(sandboxes: dict[str, ZoneSandbox], log=None) -> dict:
    """Probe every zone. passed=True only if every escape attempt was denied."""
    results = []
    for zone, sb in sandboxes.items():
        for probe, target, fn in _probes(zone, sb, sandboxes):
            if isinstance(target, Path) and sb.monitor and sb.monitor.is_decoy(target):
                raise RuntimeError(f"preflight probe {probe} would touch a decoy: {target}")
            denied = _attempt(fn)
            results.append({"zone": zone, "probe": probe, "attempted": True, "denied": denied, "passed": denied})

    passed = all(r["passed"] for r in results)
    log = log or next(iter(sandboxes.values())).log
    if passed:
        log.append("preflight_passed", {"probes_run": len(results)})
    else:
        failing = [{"zone": r["zone"], "probe": r["probe"]} for r in results if not r["passed"]]
        log.append("preflight_failed", {"probes_run": len(results), "failing": failing})
    return {"passed": passed, "probes": results}
