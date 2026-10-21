"""Reverse SSH tunnel support.

Establishes a reverse tunnel from the target device back to the operator's
machine so the bugXhunter server (running on the operator host) can reach
services on the target without opening inbound ports on the target's network.

Usage:
    tunnel = ReverseSSH(host="operator.example.com", port=22,
                        user="operator", key="/path/to/key")
    tunnel.connect(remote_port=7080)
    # now localhost:7080 on the operator host forwards to the target
    tunnel.close()
"""

import os
import shutil
import subprocess
import time


class ReverseSSH:
    """Manage a reverse SSH tunnel from the target to the operator host."""

    def __init__(self, host, port=22, user=None, key=None,
                 password=None, proxy_command=None):
        self.host = host
        self.port = port
        self.user = user or "operator"
        self.key = key
        self.password = password
        self.proxy_command = proxy_command
        self._proc = None
        self._tunnels = []

    # ------------------------------------------------------------------
    # Connection
    # ------------------------------------------------------------------
    def _build_base_args(self):
        args = ["ssh"]
        if self.key:
            args.extend(["-i", self.key])
        if self.password:
            # Use sshpass if available, else fall back to key-only.
            if shutil.which("sshpass"):
                args = ["sshpass", "-p", self.password] + args
        args.extend([
            "-p", str(self.port),
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "LogLevel=ERROR",
            "-o", "ServerAliveInterval=30",
            "-o", "ServerAliveCountMax=3",
            "-N",  # no command, just tunnel
        ])
        if self.proxy_command:
            args.extend(["-o", "ProxyCommand=" + self.proxy_command])
        args.append("{}@{}".format(self.user, self.host))
        return args

    def connect(self, remote_port=7080, local_port=None):
        """Open a reverse tunnel: operator:remote_port -> target:local_port.

        Uses SSH RemoteForward so the operator host's remote_port is
        forwarded back to the target's local_port.
        """
        if local_port is None:
            local_port = remote_port  # symmetric by default

        args = self._build_base_args()
        # -R remote_port:localhost:local_port
        args.insert(-1, "-R {}:localhost:{}".format(remote_port, local_port))

        self._proc = subprocess.Popen(args, stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL)
        self._tunnels.append((remote_port, local_port))

        # Give the tunnel a moment to establish.
        time.sleep(1)
        return self._proc.poll() is None

    def connect_dynamic(self, remote_port=7080):
        """Open a dynamic SOCKS proxy via reverse tunnel.

        The operator host's remote_port becomes a SOCKS proxy that routes
        through the target's network.
        """
        args = self._build_base_args()
        args.insert(-1, "-R {}:127.0.0.1:1080".format(remote_port))

        self._proc = subprocess.Popen(args, stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL)
        self._tunnels.append((remote_port, "socks"))
        time.sleep(1)
        return self._proc.poll() is None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def is_alive(self):
        return self._proc is not None and self._proc.poll() is None

    def close(self):
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        self._proc = None
        self._tunnels = []

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def test_connectivity(self):
        """Quick check that the SSH host is reachable."""
        args = ["ssh"]
        if self.key:
            args.extend(["-i", self.key])
        args.extend([
            "-p", str(self.port),
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "LogLevel=ERROR",
            "-o", "ConnectTimeout=5",
            "-o", "BatchMode=yes",
            "{}@{}".format(self.user, self.host),
            "echo", "ok",
        ])
        try:
            out = subprocess.run(args, capture_output=True, text=True, timeout=10)
            return out.returncode == 0 and "ok" in out.stdout
        except (OSError, subprocess.TimeoutExpired):
            return False
