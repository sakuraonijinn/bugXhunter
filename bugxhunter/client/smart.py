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
from ..frida import FridaClient, FRIDA_PORT
from ..posture import PostureCheck
from ..vpn import status as vpn_status


class SmartClient:
    """High-level client that auto-provisions Frida and tunnels traffic."""

    # Ports that have to be reachable for the suite to work at all.
    FRIDA_PORT = 27042
    SERVER_PORT = 7080

    def __init__(self, host, token=None, ssh_host=None, ssh_port=22,
                 ssh_user=None, ssh_key=None, timeout_ms=8000,
                 frida_host="127.0.0.1", frida_port=FRIDA_PORT):
        self.host = host
        self.token = token
        self.ssh_host = ssh_host
        self.ssh_port = ssh_port
        self.ssh_user = ssh_user
        self.ssh_key = ssh_key
        self.timeout_ms = timeout_ms

        self.frida = FridaClient(host=frida_host, port=frida_port)
        self.tunnel = None
        self._ready = False
        self._server_ready = False
        self.last_error = None

    # ------------------------------------------------------------------
    # Provisioning
    # ------------------------------------------------------------------
    def ensure_ready(self, max_wait=30):
        """Ensure the server is reachable and Frida is running.

        Returns True on success, False on failure.
        """
    def ensure_ready(self, max_wait=30):
        """Ensure the server is reachable and Frida is running.

        Returns True on success, False on failure. On failure, last_error
        explains why rather than leaving the caller guessing.
        """
        if not self.ensure_server(max_wait=max_wait):
            return False
        return self.ensure_frida(max_wait=max_wait)

    def ensure_server(self, max_wait=15):
        """Ensure the server host is reachable. Does not touch Frida.

        Posture checks and web scans do not need Frida, so they must not
        pay for Frida's readiness wait.
        """
        if self._server_ready:
            return True

        # Open the reverse tunnel if configured.
        #
        # Two forwards are needed, not one. FridaClient binds 127.0.0.1 on
        # the operator, so without a forward for 27042 it can never see the
        # target's frida-server no matter how healthy the tunnel looks.
        if self.ssh_host and not self.tunnel:
            self.tunnel = ReverseSSH(
                host=self.ssh_host, port=self.ssh_port,
                user=self.ssh_user, key=self.ssh_key,
            )
            if not self.tunnel.test_connectivity():
                self.last_error = "ssh to {} unreachable".format(self.ssh_host)
                return False
            # One SSH process carrying both forwards.
            self.tunnel.connect_multi([
                (self.SERVER_PORT, self.SERVER_PORT),
                (self.FRIDA_PORT, self.FRIDA_PORT),
            ])

        # Wait for the server to respond.
        deadline = time.time() + max_wait
        while time.time() < deadline:
            if self._ping():
                self._server_ready = True
                self.last_error = None
                return True
            time.sleep(1)

        self.last_error = "server {} did not respond".format(self.host)
        return False

    def ensure_frida(self, max_wait=30):
        """Ensure a Frida server is reachable, starting it if needed."""
        if self._ready:
            return True

        # frida-server has to run on the target, not here. Starting it
        # locally is the one move that looks right and silently does
        # nothing, because /data/local/tmp/frida-server does not exist on
        # the operator's filesystem.
        if not self.frida.status().get("running"):
            self._start_frida_on_target()

        deadline = time.time() + max_wait
        while time.time() < deadline:
            if self.frida.status().get("running"):
                self._ready = True
                self.last_error = None
                return True
            time.sleep(1)

        self.last_error = (
            "frida-server not reachable on port {}".format(self.FRIDA_PORT)
        )
        return False

    def _start_frida_on_target(self):
        """Start frida-server on the target device over SSH.

        Falls back to a local start when there is no tunnel, which is the
        right behaviour when the operator and the target are the same box.
        """
        if not self.tunnel:
            return self.frida.start()

        # Try root first, then unprivileged. On a rooted device the su
        # path is the one that works; on a Termux-hosted frida-server the
        # plain path is.
        return self.tunnel.run_command(
            "su -c '/data/local/tmp/frida-server --no-pause &' "
            "|| /data/local/tmp/frida-server --no-pause &"
        )

    def set_frida_host(self, host, port=None):
        """Point the Frida client at a different host.

        Needed when the bugXhunter server runs in a PRoot VM: the VM
        cannot host a frida-server, so it drives one running natively
        on the target.
        """
        self.frida = FridaClient(host=host, port=port or self.FRIDA_PORT)
        return self.frida.status()

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
        if not self._server_ready:
            if not self.ensure_server():
                return [{"level": "HIGH", "category": "posture.unreachable",
                         "detail": self.last_error or "Server not reachable"}]
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
        return WebScanner().scan(base_url)

    def scan_vuln(self, url):
        """Run vulnerability probes against a target URL."""
        from ..scanners.vuln import VulnScanner
        return VulnScanner().scan(url)

    def scan_credentials(self, path):
        """Scan a directory for exposed credentials."""
        from ..scanners.credential import CredentialScanner
        return CredentialScanner().scan_dir(path)

    def bug_steps(self):
        """Fetch the operator field guide from the server.

        Hidden endpoint, token-gated like everything else. Works without
        the server being up: the guide is bundled locally too, so the
        operator can always read it.
        """
        import urllib.request
        url = self.host.rstrip("/") + "/bugSteps"
        req = urllib.request.Request(url)
        if self.token:
            req.add_header("X-Auth-Token", self.token)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_ms / 1000) as resp:
                return json.loads(resp.read().decode("utf-8", "replace"))
        except Exception:
            from ..steps import guide
            return guide()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def close(self):
        """Tear down the tunnel and stop Frida."""
        if self.tunnel:
            self.tunnel.close()
            self.tunnel = None
        self._ready = False
        self._server_ready = False
