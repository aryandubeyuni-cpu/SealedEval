"""Simulated per-zone sandbox: the only way a zone may touch files, the network or run commands.

Prototype simulates isolation; production uses gVisor/Kata microVMs with seccomp and no network interface.
Nothing here opens real sockets or runs real commands: allowed network/exec calls are only simulated.
"""

import shlex
import time
from pathlib import Path

PACKAGE_PROXY_HOST = "package-proxy.local"
EXEC_ALLOWLIST = {"python", "echo"}

# Locked down: no shared disk, no network, no docker socket, no privileges.
SEALED_CONFIG = {
    "network_enabled": False,
    "docker_socket_exposed": False,
    "host_mount_writable": False,
    "privileged": False,
    "can_read_other_zones": False,
    "egress_proxy_enabled": False,
}

# Today's typical shared Docker setup: everything a curious agent needs to escape.
NAIVE_CONFIG = {
    "network_enabled": True,
    "docker_socket_exposed": True,
    "host_mount_writable": True,
    "privileged": False,
    "can_read_other_zones": True,
    "egress_proxy_enabled": True,
}


class ZoneSandbox:
    def __init__(self, zone_name: str, zone_dir: str | Path, config: dict, log,
                 alert_callback=None, monitor=None):
        """`alert_callback(event: dict)` is told about every denial; `monitor` is a TripwireMonitor (or None)."""
        self.zone = zone_name
        self.zone_dir = Path(zone_dir).resolve()
        self.zone_dir.mkdir(parents=True, exist_ok=True)
        self.config = {**SEALED_CONFIG, **config}  # anything unspecified defaults to locked down
        self.log = log
        self.alert_callback = alert_callback
        self.monitor = monitor
        self.attempt_started_at: float | None = None  # set by an escape attempt, for time-to-detect

    # ------------------------------------------------------------ helpers

    def _resolve(self, path: str | Path) -> Path:
        """Relative paths are relative to the zone dir (the zone's working directory)."""
        p = Path(path)
        return (p if p.is_absolute() else self.zone_dir / p).resolve()

    def _inside_zone(self, path: Path) -> bool:
        return path == self.zone_dir or path.is_relative_to(self.zone_dir)

    def _deny(self, action: str, target: str, reason: str):
        event = {"zone": self.zone, "action": action, "target": target}
        self.log.append("sandbox_denied", event)
        if self.alert_callback:
            self.alert_callback({**event, "reason": reason})
        raise PermissionError(f"sandbox: {reason}")

    # ------------------------------------------------------------ files

    def zone_open(self, path: str | Path, mode: str = "r"):
        target = self._resolve(path)

        # Tripwire first: touching a decoy is an alarm even if the read itself would be allowed.
        if self.monitor and self.monitor.is_decoy(target):
            self.monitor.trigger(self.zone, str(target), f"open:{mode}", started_at=self.attempt_started_at)
            raise PermissionError("sandbox: tripwire triggered, run frozen")

        if not self._inside_zone(target):
            writing = any(c in mode for c in "wax+")
            allowed = self.config["host_mount_writable"] if writing else self.config["can_read_other_zones"]
            if not allowed:
                self._deny(f"open:{mode}", str(target), "path outside zone")
        return open(target, mode, encoding=None if "b" in mode else "utf-8")

    # ------------------------------------------------------------ network (simulated)

    def zone_connect(self, host: str, port: int) -> dict:
        via_proxy = self.config["egress_proxy_enabled"] and host == PACKAGE_PROXY_HOST
        if not (self.config["network_enabled"] or via_proxy):
            self._deny("connect", f"{host}:{port}", "no network")
        return {"connected": True, "host": host, "port": port, "simulated": True}

    # ------------------------------------------------------------ exec (simulated)

    def zone_exec(self, command: str) -> dict:
        program = shlex.split(command)[0] if command.strip() else ""
        allowed = (
            program in EXEC_ALLOWLIST
            or self.config["privileged"]
            or (program == "docker" and self.config["docker_socket_exposed"])
        )
        if not allowed:
            self._deny("exec", command, f"command '{program}' not allowed")
        return {"executed": True, "command": command, "simulated": True}

    def begin_attempt(self) -> None:
        """Mark the start of an (escape) attempt so tripwires can report time-to-detect."""
        self.attempt_started_at = time.perf_counter()
