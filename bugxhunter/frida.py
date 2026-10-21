"""Frida server lifecycle and script execution.

Two modes, and the distinction matters:

*local*  — a frida-server is running on this machine; this class starts
           and stops it. This is the operator workstation, or a phone
           with root.

*remote* — a frida-server is running on a *different* machine and this
           class reaches it over the network. This is what a bugXhunter
           server running inside a PRoot VM must use: PRoot already
           occupies the ptrace slot, so a frida-server spawned inside
           the guest cannot instrument anything. The server has to talk
           to a frida-server running natively on the target instead.

The remote mode is selected by passing a host that is not localhost.
"""

import json
import socket
import subprocess
import time

FRIDA_PORT = 27042
FRIDA_SOCKET = "/data/local/tmp/frida.sock"
LOCAL_HOSTS = ("127.0.0.1", "localhost", "::1")


class FridaClient:
    """Control a Frida server and execute scripts against it."""

    def __init__(self, socket_path=FRIDA_SOCKET, port=FRIDA_PORT,
                 host="127.0.0.1"):
        self.socket_path = socket_path
        self.port = port
        self.host = host

    # ------------------------------------------------------------------
    # Mode
    # ------------------------------------------------------------------
    @property
    def is_local(self) -> bool:
        """True when the Frida server lives on this machine."""
        return self.host in LOCAL_HOSTS

    def _endpoint(self):
        """The address to connect to, as (host, port)."""
        return (self.host, self.port)

    def _cli_target(self):
        """The -H argument for the frida CLI, or None for local mode."""
        if self.is_local:
            return None
        return "{}:{}".format(self.host, self.port)

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------
    def status(self):
        """Return whether a Frida server is reachable."""
        host, port = self._endpoint()
        try:
            with socket.create_connection((host, port), timeout=2):
                return {"running": True, "host": host, "port": port,
                        "mode": "local" if self.is_local else "remote"}
        except OSError:
            return {
                "running": False,
                "host": host,
                "port": port,
                "mode": "local" if self.is_local else "remote",
                "reason": "{}:{} closed".format(host, port),
            }

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def start(self, binary="/data/local/tmp/frida-server"):
        """Start a frida-server locally.

        Refused in remote mode: a Frida server belongs on the target,
        not on whatever is running this client. Spawning one inside a
        PRoot guest fails anyway, because PRoot already holds the
        ptrace slot and the guest server cannot instrument a host
        process.
        """
        if not self.is_local:
            return {
                "started": False,
                "reason": (
                    "remote Frida mode: frida-server must be started on "
                    "the target, not on {}".format(self.host)
                ),
            }
        try:
            proc = subprocess.Popen(
                [binary, "--no-pause"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            time.sleep(1)
            return {"started": True, "pid": proc.pid}
        except OSError as exc:
            return {"started": False, "reason": str(exc)}

    def stop(self):
        """Kill any running frida-server on this machine."""
        if not self.is_local:
            return {
                "stopped": False,
                "reason": (
                    "remote Frida mode: stop frida-server on the target, "
                    "not on {}".format(self.host)
                ),
            }
        try:
            subprocess.run(["pkill", "-f", "frida-server"], check=False)
            return {"stopped": True}
        except OSError as exc:
            return {"stopped": False, "reason": str(exc)}

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------
    def _run_frida(self, args, timeout=15):
        """Run the frida CLI, adding -H when in remote mode."""
        cmd = ["frida"]
        endpoint = self._cli_target()
        if endpoint:
            cmd.extend(["-H", endpoint])
        cmd.extend(args)
        try:
            out = subprocess.run(cmd, capture_output=True, text=True,
                                 timeout=timeout)
            return out
        except OSError as exc:
            return None
        except subprocess.TimeoutExpired:
            return None

    def list_devices(self):
        """List devices visible to the Frida server."""
        out = self._run_frida(["ls"])
        if out is None or out.returncode != 0:
            return []
        try:
            return json.loads(out.stdout) if out.stdout.strip() else []
        except json.JSONDecodeError:
            return []

    def list_processes(self, device="local"):
        """List processes on a device."""
        out = self._run_frida(["-D", device, "ls"])
        if out is None or out.returncode != 0:
            return []
        try:
            return json.loads(out.stdout) if out.stdout.strip() else []
        except json.JSONDecodeError:
            return []

    def execute(self, target, script_path, device="local"):
        """Execute a Frida script against a target process."""
        out = self._run_frida(
            ["-D", device, "-n", target, "-l", script_path], timeout=30)
        if out is None:
            return {"ok": False, "reason": "frida CLI unavailable or timed out"}
        return {
            "ok": out.returncode == 0,
            "stdout": out.stdout,
            "stderr": out.stderr,
        }
