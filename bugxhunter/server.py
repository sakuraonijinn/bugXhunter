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

from .config import Config, load as load_config
from .frida import FridaClient
from .posture import PostureCheck
from .scanners.credential import CredentialScanner
from .steps import guide as bug_steps_guide
from .scanners.config_audit import ConfigAudit
from .scanners.network import NetworkScan
from .scanners.vuln import VulnScanner
from .scanners.web import WebScanner
from .termux import termux_available
from .vpn import status as vpn_status, active_mode, proxy_url

from starlette.applications import Starlette
from starlette.routing import Route
from starlette.responses import JSONResponse, FileResponse
from starlette.middleware.cors import CORSMiddleware


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
                # Not advertised in /status and not in the route list. This
                # is the operator's field guide; it is token-gated like the
                # rest, but it is deliberately off the beaten path.
                "/bugSteps": self._bug_steps,
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
        if not self.config.auth_token:
            return True
        return headers.get("X-Auth-Token", "") == self.config.auth_token

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
        return {"ok": True, "version": "1.0.0"}

    def _status(self, handler, body):
        return {
            "version": "1.0.0",
            "frida": self.frida.status(),
            "vpn": vpn_status(),
            "termux": termux_available(),
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

    def _bug_steps(self, handler, body):
        """Return the operator field guide. Hidden from route listings."""
        return bug_steps_guide()


def make_server(config: Config):
    """Build a configured Server instance."""
    return Server(config)


# Module-level config + server, used by the ASGI `app` below.
_config = load_config()
_server = make_server(_config)


async def _health_route(request):
    return JSONResponse(_server._health(None, b""))


async def _status_route(request):
    return JSONResponse(_server._status(None, b""))


async def _diagnose_route(request):
    return JSONResponse(_server._diagnose(None, b""))


async def _frida_status_route(request):
    return JSONResponse(_server._frida_status(None, b""))


async def _frida_devices_route(request):
    return JSONResponse(_server._frida_devices(None, b""))


async def _frida_processes_route(request):
    return JSONResponse(_server._frida_processes(None, b""))


async def _frida_results_route(request):
    return JSONResponse(_server._frida_results(None, b""))


async def _frida_start_route(request):
    body = await request.body()
    return JSONResponse(_server._frida_start(None, body))


async def _frida_stop_route(request):
    body = await request.body()
    return JSONResponse(_server._frida_stop(None, body))


async def _frida_script_route(request):
    body = await request.body()
    return JSONResponse(_server._frida_script(None, body))


async def _frida_page_route(request):
    token = request.query_params.get("token", "")
    if _config.auth_token and token != _config.auth_token:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    page = Path(__file__).parent / "templates" / "frida.html"
    return FileResponse(page)


async def _bug_steps_route(request):
    """Hidden endpoint: the operator field guide."""
    return JSONResponse(_server._bug_steps(None, b""))


routes = [
    Route("/health", _health_route, methods=["GET"]),
    Route("/status", _status_route, methods=["GET"]),
    Route("/diagnose", _diagnose_route, methods=["GET"]),
    Route("/frida/status", _frida_status_route, methods=["GET"]),
    Route("/frida/devices", _frida_devices_route, methods=["GET"]),
    Route("/frida/processes", _frida_processes_route, methods=["GET"]),
    Route("/frida/results", _frida_results_route, methods=["GET"]),
    Route("/frida/start", _frida_start_route, methods=["POST"]),
    Route("/frida/stop", _frida_stop_route, methods=["POST"]),
    Route("/frida/script", _frida_script_route, methods=["POST"]),
    Route("/frida/page", _frida_page_route, methods=["GET"]),
    # Hidden: the operator field guide. Deliberately last in the list and
    # absent from /status, so a casual endpoint sweep will not find it.
    Route("/bugSteps", _bug_steps_route, methods=["GET", "POST"]),
]


class AuthMiddleware:
    """Reject requests without a valid X-Auth-Token (except /health)."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        if path == "/health":
            await self.app(scope, receive, send)
            return
        headers = dict(scope.get("headers") or [])
        token = headers.get(b"x-auth-token", b"").decode()
        if _config.auth_token and token != _config.auth_token:
            await send({
                "type": "http.response.start",
                "status": 401,
                "headers": [(b"content-type", b"application/json")],
            })
            await send({
                "type": "http.response.body",
                "body": b'{"error": "unauthorized"}',
            })
            return
        await self.app(scope, receive, send)


app = Starlette(routes=routes)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"],
                   allow_headers=["*"])
app.add_middleware(AuthMiddleware)


def main():
    parser = argparse.ArgumentParser(description="bugXhunter server")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=7080)
    parser.add_argument("--config", default=None)
    parser.add_argument("--token", default=None)
    parser.add_argument("--vpn", action="store_true")
    args = parser.parse_args()

    config = load_config(args.config)
    if args.token:
        config.auth_token = args.token
    config.vpn_enabled = args.vpn

    server = make_server(config)

    # Start VPN tunnel if requested.
    if config.vpn_enabled:
        from .vpn import route_all_through_tunnel
        route_all_through_tunnel()

    # Start Frida server if not running.
    if not server.frida.status().get("running"):
        server.frida.start()

    import uvicorn
    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
