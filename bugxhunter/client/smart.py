"""Smart bugXhunter client.

Takes a goal (not a command list) and figures out the rest:

    client = SmartClient(host="operator.example.com", token="secret")
    client.ensure_ready()
    findings = client.diagnose()
    client.frida_attach("com.example.app")

Under the hood this:
  1. Tests SSH connectivity and opens a reverse tunnel if needed
  2. Auto-starts the Frida server on the target if not running
  3. Waits for the Frida server to become ready
  4. Returns high-level results, not raw JSON
"""

import json
import time

from .reverse_ssh import ReverseSSH
from ..frida import FridaClient
from ..posture import PostureCheck


class SmartClient:
    """High-level client that auto-provisions Frida and tunnels traffic."""

    def __init__(self, host, token=None, ssh_host=None, ssh_port=22,
                 ssh_user=None, ssh_key=None, timeout_ms=8000):
        self.host = host
        self.token = token
        self.ssh_host = ssh_host
        self.ssh_port = ssh_port
        self.ssh_user = ssh_user
        self.ssh_key = ssh_key
        self.timeout_ms = timeout_ms

        self.frida = FridaClient()
        self.tunnel = None
        self._ready = False

    # ------------------------------------------------------------------
    # Provisioning
    # ------------------------------------------------------------------
    def ensure_ready(self, max_wait=30):
        """Ensure the server is reachable and Frida is running.

        Returns True on success, False on failure.
        """
        # Step 1: open reverse SSH tunnel if configured.
        if self.ssh_host and not self.tunnel:
            self.tunnel = ReverseSSH(
                host=self.ssh_host, port=self.ssh_port,
                user=self.ssh_user, key=self.ssh_key,
            )
            if not self.tunnel.test_connectivity():
                return False
            # Tunnel the server's port back to the operator host.
            self.tunnel.connect(remote_port=7080, local_port=7080)

        # Step 2: wait for the server to respond.
        deadline = time.time() + max_wait
        while time.time() < deadline:
            if self._ping():
                break
            time.sleep(1)
        else:
            return False

        # Step 3: auto-start Frida if not running.
        status = self.frida.status()
        if not status.get("running"):
            self.frida.start()

        # Step 4: wait for Frida to become ready.
        deadline = time.time() + max_wait
        while time.time() < deadline:
            status = self.frida.status()
            if status.get("running"):
                self._ready = True
                break
            time.sleep(1)

        return self._ready

    def _ping(self):
        """Check whether the server is reachable."""
        import urllib.request
        try:
            req = urllib.request.Request(self.host + "/health")
            if self.token:
                req.add_header("X-Auth-Token", self.token)
            with urllib.request.urlopen(req, timeout=3) as resp:
                return resp.status == 200
        except Exception:
            return False

    # ------------------------------------------------------------------
    # High-level API
    # ------------------------------------------------------------------
    def diagnose(self):
        """Run posture checks and return findings as a list of dicts."""
        if not self._ready:
            if not self.ensure_ready():
                return [{"level": "HIGH", "category": "posture.unreachable",
                         "detail": "Server not reachable"}]
        posture = PostureCheck()
        return posture.run()

    def frida_attach(self, process_name):
        """Attach Frida to a process and return a session handle.

        Returns a dict with the process info, or None on failure.
        """
        if not self._ready:
            if not self.ensure_ready():
                return None
        processes = self.frida.list_processes()
        for proc in processes:
            name = proc.get("name", "")
            pid = str(proc.get("pid", ""))
            if name == process_name or pid == str(process_name):
                return proc
        return None

    def frida_execute(self, process_name, script_path):
        """Execute a Frida script against a process.

        Returns the result dict, or None on failure.
        """
        if not self._ready:
            if not self.ensure_ready():
                return None
        return self.frida.execute(process_name, script_path)

    def scan_web(self, base_url):
        """Run web posture checks against a target URL."""
        from ..scanners.web import WebScanner
        from ..scanners.network import NetworkScan
        scanner = WebScanner(NetworkScan())
        return scanner.scan(base_url)

    def scan_vuln(self, url):
        """Run vulnerability probes against a target URL."""
        from ..scanners.vuln import VulnScanner
        from ..scanners.network import NetworkScan
        scanner = VulnScanner(NetworkScan())
        return scanner.scan(url)

    def scan_credentials(self, path):
        """Scan a directory for exposed credentials."""
        from ..scanners.credential import CredentialScanner
        return CredentialScanner().scan_dir(path)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def close(self):
        """Tear down the tunnel and stop Frida."""
        if self.tunnel:
            self.tunnel.close()
            self.tunnel = None
        self._ready = False
