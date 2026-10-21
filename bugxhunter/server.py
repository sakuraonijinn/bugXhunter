"""bugXhunter HTTP server.

Exposes a small API for remote posture checks and Frida control, and serves
the Frida web UI. Designed to run under Termux on the same device as the
Android app, or on a separate VPS.

Usage:
    python3 -m bugxhunter.server --host 0.0.0.0 --port 7080
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path

from .config import Config
from .frida import FridaClient
from .posture import PostureCheck
from .scanners.credential import CredentialScanner
from .scanners.config_audit import ConfigAudit
from .scanners.network import NetworkScan
from .scanners.vuln import VulnScanner
from .scanners.web import WebScanner
from .termux import Termux
from .vpn import VPN


class Server:
    """Minimal HTTP server using only the standard library."""

    def __init__(self, config: Config):
        self.config = config
        self.frida = FridaClient()
        self._handlers = {
            "GET": {
                "/health": self._health,
                "/status": self._status,
                "/diagnose": self._diagnose,
                "/frida/status": self._frida_status,
                "/frida/devices": self._frida_devices,
                "/frida/processes": self._frida_processes,
                "/frida/results": self._frida_results,
            },
            "POST": {
                "/frida/start": self._frida_start,
                "/frida/stop": self._frida_stop,
                "/frida/script": self._frida_script,
            },
        }

    # ------------------------------------------------------------------
    # Auth
    # ------------------------------------------------------------------
    def _check_auth(self, headers):
        if not self.config.token:
            return True
        return headers.get("X-Auth-Token", "") == self.config.token

    def _send(self, handler, status, payload, content_type="application/json"):
        body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        handler.send_response(status)
        handler.send_header("Content-Type", content_type)
        handler.send_header("Content-Length", str(len(body)))
        handler.send_header("Access-Control-Allow-Origin", "*")
        handler.end_headers()
        handler.wfile.write(body)

    def _read_body(self, handler):
        length = int(handler.headers.get("Content-Length", 0))
        return handler.rfile.read(length) if length else b""

    # ------------------------------------------------------------------
    # Route dispatch
    # ------------------------------------------------------------------
    def dispatch(self, handler):
        method = handler.command
        path = handler.path.split("?", 1)[0]

        if not self._check_auth(handler.headers):
            self._send(handler, 401, {"error": "unauthorized"})
            return

        route = self._handlers.get(method, {}).get(path)
        if route is None:
            self._send(handler, 404, {"error": "not found"})
            return

        try:
            body = self._read_body(handler)
            result = route(handler, body)
            self._send(handler, 200, result)
        except Exception as exc:
            self._send(handler, 500, {"error": str(exc)})

    # ------------------------------------------------------------------
    # Endpoints
    # ------------------------------------------------------------------
    def _health(self, handler, body):
        return {"ok": True, "version": self.config.version}

    def _status(self, handler, body):
        return {
            "version": self.config.version,
            "frida": self.frida.status(),
            "vpn": self.config.vpn_enabled,
            "termux": Termux.available(),
        }

    def _diagnose(self, handler, body):
        """Run posture checks and return findings."""
        posture = PostureCheck()
        findings = posture.run()
        return {"findings": findings}

    def _frida_status(self, handler, body):
        return self.frida.status()

    def _frida_start(self, handler, body):
        return self.frida.start()

    def _frida_stop(self, handler, body):
        return self.frida.stop()

    def _frida_devices(self, handler, body):
        return {"devices": self.frida.list_devices()}

    def _frida_processes(self, handler, body):
        return {"processes": self.frida.list_processes()}

    def _frida_script(self, handler, body):
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            return {"ok": False, "reason": "invalid JSON"}
        return self.frida.execute(
            payload.get("target", ""),
            payload.get("script", ""),
            payload.get("device", "local"),
        )

    def _frida_results(self, handler, body):
        return {"ok": True, "results": []}


def make_server(config: Config):
    """Build a configured Server instance."""
    return Server(config)


def main():
    parser = argparse.ArgumentParser(description="bugXhunter server")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=7080)
    parser.add_argument("--config", default=None)
    parser.add_argument("--token", default=None)
    parser.add_argument("--vpn", action="store_true")
    args = parser.parse_args()

    config = Config.load(args.config)
    if args.token:
        config.token = args.token
    config.vpn_enabled = args.vpn

    server = make_server(config)

    # Start VPN tunnel if requested.
    if config.vpn_enabled:
        vpn = VPN(config)
        vpn.start()

    # Start Frida server if not running.
    if not server.frida.status().get("running"):
        server.frida.start()

    # Serve Frida web UI at /frida/page.
    from http.server import HTTPServer, BaseHTTPRequestHandler

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path.startswith("/frida/page"):
                self._serve_frida_page()
            else:
                server.dispatch(self)

        def do_POST(self):
            server.dispatch(self)

        def _serve_frida_page(self):
            try:
                page = Path(__file__).parent / "templates" / "frida.html"
                data = page.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            except OSError:
                server._send(self, 500, {"error": "frida page not found"})

        def log_message(self, fmt, *args):
            sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    httpd = HTTPServer((args.host, args.port), Handler)
    print("bugXhunter listening on {}:{} (token={})".format(
        args.host, args.port, "set" if config.token else "unset"))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down")
        httpd.shutdown()


if __name__ == "__main__":
    main()
