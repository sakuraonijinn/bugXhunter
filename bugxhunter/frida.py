"""Frida server lifecycle and script execution.

Talks to a Frida server running on the target device over its local socket.
The server must be started first (see termux.py for the Termux-based launch).
"""

import json
import os
import socket
import subprocess
import time

FRIDA_PORT = 27042
FRIDA_SOCKET = "/data/local/tmp/frida.sock"


class FridaClient:
    """Control a Frida server and execute scripts against it."""

    def __init__(self, socket_path=FRIDA_SOCKET, port=FRIDA_PORT):
        self.socket_path = socket_path
        self.port = port

    def status(self):
        """Return whether a Frida server is reachable."""
        try:
            with socket.create_connection(("127.0.0.1", self.port), timeout=2):
                return {"running": True}
        except OSError:
            return {"running": False, "reason": "port {} closed".format(self.port)}

    def start(self, binary="/data/local/tmp/frida-server"):
        """Start the Frida server in the background."""
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
        """Kill any running Frida server."""
        try:
            subprocess.run(["pkill", "-f", "frida-server"], check=False)
            return {"stopped": True}
        except OSError as exc:
            return {"stopped": False, "reason": str(exc)}

    def list_devices(self):
        """List devices visible to the local Frida server."""
        try:
            out = subprocess.run(
                ["frida", "ls"], capture_output=True, text=True, timeout=10
            )
            if out.returncode == 0:
                return json.loads(out.stdout) if out.stdout.strip() else []
            return []
        except (OSError, json.JSONDecodeError):
            return []

    def list_processes(self, device="local"):
        """List processes on a device."""
        try:
            out = subprocess.run(
                ["frida", "-D", device, "ls"],
                capture_output=True, text=True, timeout=10,
            )
            if out.returncode == 0:
                return json.loads(out.stdout) if out.stdout.strip() else []
            return []
        except (OSError, json.JSONDecodeError):
            return []

    def execute(self, target, script_path, device="local"):
        """Execute a Frida script against a target process."""
        try:
            out = subprocess.run(
                ["frida", "-D", device, "-n", target, "-l", script_path],
                capture_output=True, text=True, timeout=30,
            )
            return {
                "ok": out.returncode == 0,
                "stdout": out.stdout,
                "stderr": out.stderr,
            }
        except OSError as exc:
            return {"ok": False, "reason": str(exc)}
