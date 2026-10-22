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
import tempfile
import threading
import time
from collections import OrderedDict
from pathlib import Path

from .config import Config, PLACEHOLDER_TOKENS, load as load_config
from .frida import FridaClient
from .hooks import HookLibrary
from .posture import PostureCheck, under_proot
from .privileges import Privileges
from .scanners.credential import CredentialScanner
from .steps import guide as bug_steps_guide
from .scanners.config_audit import ConfigAudit
from .scanners.network import NetworkScan
from .scanners.vuln import VulnScanner
from .scanners.web import WebScanner
from .termux import termux_available
from .tools import ToolBridge
from .vpn import apply as vpn_apply
from .vpn import status as vpn_status
from .vpn import active_mode, proxy_url

from starlette.applications import Starlette
from starlette.routing import Route
from starlette.responses import JSONResponse, FileResponse
from starlette.middleware.cors import CORSMiddleware


class Server:
    """Minimal HTTP server using only the standard library."""

    def __init__(self, config: Config):
        self.config = config
        self.frida = FridaClient(host=config.frida_host, port=config.frida_port)
        self.tools = ToolBridge()
        self.priv = Privileges()
        self.hooks = HookLibrary()
        # Script results, keyed by id, newest last. Bounded so a long
        # running server cannot grow without limit.
        self._results = OrderedDict()
        self._result_lock = threading.Lock()
        self._result_seq = 0
        self._result_limit = 100
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
                "/tools": self._tools,
                "/hooks": self._hooks,
                "/hooks/run": self._hooks_run,
                "/vpn": self._vpn,
                "/termux": self._termux,
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
        if route is None and path.startswith("/frida/results/"):
            # Parameterised result lookup.
            route = self._handlers.get(method, {}).get("/frida/results")
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
            "vpn": vpn_status(),
            "termux": termux_available(),
            "emulated": under_proot(),
            "privileges": self.priv.detect(),
            "frida_mode": self.config.frida_mode,
        }

    def _diagnose(self, handler, body):
        """Run posture checks and return findings."""
        posture = PostureCheck(priv=self.priv)
        findings = posture.run()
        return {"findings": findings, "privileges": self.priv.detect()}

    def _frida_status(self, handler, body):
        return self.frida.status()

    def _frida_start(self, handler, body):
        return self.frida.start()

    def _frida_stop(self, handler, body):
        return self.frida.stop()

    def _frida_devices(self, handler, body):
        return {"devices": self.frida.list_devices()}

    def _frida_processes(self, handler, body, device=None):
        """List processes on a device.

        The device comes from the ?device= query parameter, which the
        Android app sends. It is ignored when absent.

        In gadget mode the target loads Frida Gadget inside its own
        process, so the process list shows the app under the name
        "Gadget" rather than its package name.
        """
        if not device:
            device = self._query_param(handler, "device") or "local"
        result = {"processes": self.frida.list_processes(device), "device": device}
        if self.config.frida_mode == "gadget":
            result["mode"] = "gadget"
            result["target_name"] = self.config.gadget_target
        return result

    def _frida_script(self, handler, body):
        """Run a script against a process and keep the result.

        The script may be given as source text or as a path to a file on
        the server. The Android app sends source text; the CLI sends a
        path.
        """
        try:
            payload = json.loads(body or b"{}")
        except json.JSONDecodeError:
            return {"ok": False, "reason": "invalid JSON"}

        target = payload.get("target") or payload.get("process") or ""
        script = payload.get("script") or ""
        device = payload.get("device") or "local"

        if not target:
            return {"ok": False, "reason": "target is required"}
        if not script:
            return {"ok": False, "reason": "script is required"}

        script_path, cleanup = self._resolve_script(script)
        if script_path is None:
            return {"ok": False, "reason": "script could not be resolved"}

        try:
            result = self.frida.execute(target, script_path, device)
        finally:
            if cleanup:
                try:
                    os.unlink(script_path)
                except OSError:
                    pass

        result["target"] = target
        result["device"] = device
        result_id = self._store_result(target, device, result)
        result["result_id"] = result_id
        return result

    @staticmethod
    def _resolve_script(script):
        """Return (path, should_delete) for a script given as text or a path."""
        # A path that exists on the server is used as-is.
        if "\n" not in script and len(script) < 4096:
            try:
                if os.path.isfile(script):
                    return script, False
            except OSError:
                pass
        # Otherwise it is source text, so it goes to a temporary file.
        try:
            handle = tempfile.NamedTemporaryFile(
                mode="w", suffix=".js", prefix="bugxhunter-", delete=False)
            with handle:
                handle.write(script)
            return handle.name, True
        except OSError:
            return None, False

    def _store_result(self, target, device, result):
        """Keep a script result and return its id."""
        with self._result_lock:
            self._result_seq += 1
            result_id = "r{0:06d}".format(self._result_seq)
            self._results[result_id] = {
                "result_id": result_id,
                "target": target,
                "device": device,
                "created": time.time(),
                "ok": bool(result.get("ok")),
                "stdout": result.get("stdout", ""),
                "stderr": result.get("stderr", ""),
            }
            while len(self._results) > self._result_limit:
                self._results.popitem(last=False)
        return result_id

    def _get_result(self, result_id):
        with self._result_lock:
            return self._results.get(result_id)

    def _frida_results(self, handler, body, result_id=None):
        """Serve a stored script result."""
        if not result_id:
            path = handler.path.split("?", 1)[0] if handler is not None else ""
            parts = path.strip("/").split("/")
            result_id = parts[2] if len(parts) > 2 else ""
        if not result_id:
            return {"ok": True, "results": []}
        stored = self._get_result(result_id)
        if stored is None:
            return {"ok": False, "reason": "no such result: {}".format(result_id)}
        return stored

    @staticmethod
    def _query_param(handler, name):
        """Read a query parameter from the request path."""
        if handler is None:
            return None
        path = getattr(handler, "path", "") or ""
        if "?" not in path:
            return None
        query = path.split("?", 1)[1]
        for pair in query.split("&"):
            key, _, value = pair.partition("=")
            if key == name:
                return value
        return None

    def _bug_steps(self, handler, body):
        """Return the operator field guide. Hidden from route listings."""
        return bug_steps_guide()

    def _tools(self, handler, body):
        """Report which Kali tools are reachable."""
        report = self.tools.available()
        return {
            "kali_root": self.tools.kali_root,
            "nethunter": self.tools._nethunter_path() is not None,
            "available": [name for name, meta in report.items()
                          if meta["available"]],
            "tools": report,
        }

    def _vpn(self, handler, body):
        """Report the live VPN state, and optionally change it."""
        mode = (body or b"").decode("utf-8", "replace").strip() or "auto"
        if mode not in ("auto", "off", "proxy", "tun"):
            return {"ok": False, "reason": "mode must be auto, off, proxy or tun"}
        result = vpn_apply(mode)
        result["status"] = vpn_status()
        return result

    def _termux(self, handler, body):
        """Termux device state: location, battery, wifi, clipboard, sms."""
        from . import termux
        if not termux.termux_available():
            return {
                "available": False,
                "reason": "the Termux:API add-on is not installed",
            }
        limit = 20
        if handler is not None:
            value = self._query_param(handler, "limit")
            if value and value.isdigit():
                limit = max(1, min(200, int(value)))
        return {
            "available": True,
            "api_path": termux.api_path(),
            "location": termux.location(),
            "battery": termux.battery(),
            "wifi": termux.wifi_info(),
            "clipboard": termux.clipboard_get(),
            "sms": termux.sms_inbox(limit=limit),
        }

    def _hooks(self, handler, body, name=""):
        """List the Frida hook library, or return one script.

        The stdlib dispatcher reaches this with a real handler, so the
        hook name is taken from the path.
        """
        name = ""
        if handler is not None:
            parts = handler.path.split("?", 1)[0].strip("/").split("/")
            if len(parts) > 1 and parts[1]:
                name = parts[1]
        return self._hooks_named(name)

    def _hooks_named(self, name):
        """Return the library manifest, or one hook's script."""
        if name:
            meta = self.hooks.get(name)
            if not meta:
                return {"error": "no such hook: {}".format(name)}
            return {
                "name": meta["name"],
                "sha256": meta["sha256"],
                "version": self.hooks.version(),
                "git_commit": self.hooks.git_commit(),
                "script": self.hooks.read(name),
            }
        return self.hooks.manifest()

    def _hooks_run(self, handler, body):
        """Run a named hook against a target process."""
        try:
            payload = json.loads(body or b"{}")
        except json.JSONDecodeError:
            return {"ok": False, "reason": "invalid JSON"}

        name = payload.get("hook", "")
        target = payload.get("target", "")
        device = payload.get("device", "local")
        args = payload.get("args", [])

        meta = self.hooks.get(name)
        if not meta:
            return {"ok": False, "reason": "no such hook: {}".format(name)}
        if not target:
            return {"ok": False, "reason": "target is required"}

        result = self.frida.execute(target, meta["path"], device)
        result["hook"] = meta["name"]
        result["sha256"] = meta["sha256"]
        result["version"] = self.hooks.version()
        return result


def make_server(config: Config):
    """Build a configured Server instance."""
    return Server(config)


def _json_route(method, *args, **kwargs):
    """Run a handler and turn a failure into a JSON error.

    Without this an exception in a handler becomes an opaque 500 with
    no body, and the operator cannot tell what went wrong.
    """
    try:
        return JSONResponse(method(*args, **kwargs))
    except Exception as exc:
        return JSONResponse(
            {"error": type(exc).__name__ + ": " + str(exc)},
            status_code=500,
        )


def make_app(config: Config):
    """Build the ASGI application for a given config.

    The app is built from the config rather than reading a module global,
    so that command-line overrides actually take effect. Previously the
    routes closed over a module-level config loaded at import time, and
    main() then served that app instead of the one it had just built,
    which meant --token and --frida-host were silently ignored.
    """
    server = make_server(config)

    # A placeholder token is a well-known credential. Refusing to serve is
    # better than serving an API that anyone can read.
    #
    # This is not raised here, because the module is imported by tooling
    # and by the ASGI app factory. The app answers every request with 503
    # and says why, so an operator who started it by mistake finds out
    # immediately. The command line entry point refuses to start at all.
    if config.auth_token in PLACEHOLDER_TOKENS:
        async def _refuse(request):
            return JSONResponse({
                "error": "the auth token is a placeholder; refusing to serve",
                "fix": ("set a real token with AUTH_TOKEN, --token, or the "
                        '"token" key in config.json'),
            }, status_code=503)

        refusing = Starlette(routes=[
            Route("/{path:path}", _refuse, methods=["GET", "POST"]),
        ])
        refusing.add_middleware(CORSMiddleware, allow_origins=["*"],
                                allow_methods=["*"], allow_headers=["*"])
        return refusing

    async def _health_route(request):
        return _json_route(server._health, None, b"")

    async def _status_route(request):
        return _json_route(server._status, None, b"")

    async def _diagnose_route(request):
        return _json_route(server._diagnose, None, b"")

    async def _frida_status_route(request):
        return _json_route(server._frida_status, None, b"")

    async def _frida_devices_route(request):
        return _json_route(server._frida_devices, None, b"")

    async def _frida_processes_route(request):
        device = request.query_params.get("device") or None
        return _json_route(server._frida_processes, None, b"", device)

    async def _frida_results_route(request):
        return _json_route(server._frida_results, None, b"")

    async def _frida_result_route(request):
        result_id = request.path_params.get("result_id", "")
        return _json_route(server._frida_results, None, b"", result_id)

    async def _frida_start_route(request):
        body = await request.body()
        return _json_route(server._frida_start, None, body)

    async def _frida_stop_route(request):
        body = await request.body()
        return _json_route(server._frida_stop, None, body)

    async def _frida_script_route(request):
        body = await request.body()
        return _json_route(server._frida_script, None, body)

    async def _frida_page_route(request):
        token = request.query_params.get("token", "")
        if config.auth_token and token != config.auth_token:
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        page = Path(__file__).parent / "templates" / "frida.html"
        return FileResponse(page)

    async def _bug_steps_route(request):
        """Hidden endpoint: the operator field guide."""
        return _json_route(server._bug_steps, None, b"")

    async def _tools_route(request):
        """Report which Kali tools are reachable."""
        return _json_route(server._tools, None, b"")

    async def _hooks_route(request):
        """List the Frida hook library."""
        return _json_route(server._hooks, None, b"")

    async def _hooks_name_route(request):
        """Return one hook's script, so a target can pull it."""
        return _json_route(server._hooks_named,
                           request.path_params["name"])

    async def _hooks_run_route(request):
        """Run a hook against a target process."""
        body = await request.body()
        return _json_route(server._hooks_run, None, body)

    async def _vpn_route(request):
        """Report or change the VPN routing mode."""
        body = await request.body()
        return _json_route(server._vpn, None, body)

    async def _termux_route(request):
        """Report the Termux device state."""
        return _json_route(server._termux, None, b"")

    routes = [
        Route("/health", _health_route, methods=["GET"]),
        Route("/status", _status_route, methods=["GET"]),
        Route("/diagnose", _diagnose_route, methods=["GET"]),
        Route("/frida/status", _frida_status_route, methods=["GET"]),
        Route("/frida/devices", _frida_devices_route, methods=["GET"]),
        Route("/frida/processes", _frida_processes_route, methods=["GET"]),
        Route("/frida/results", _frida_results_route, methods=["GET"]),
        Route("/frida/results/{result_id}", _frida_result_route, methods=["GET"]),
        Route("/frida/start", _frida_start_route, methods=["POST"]),
        Route("/frida/stop", _frida_stop_route, methods=["POST"]),
        Route("/frida/script", _frida_script_route, methods=["POST"]),
        Route("/frida/page", _frida_page_route, methods=["GET"]),
        # Hidden: the operator field guide. Deliberately last in the list
        # and absent from /status, so a casual endpoint sweep will not
        # find it.
        Route("/bugSteps", _bug_steps_route, methods=["GET", "POST"]),
        Route("/tools", _tools_route, methods=["GET"]),
        Route("/hooks", _hooks_route, methods=["GET"]),
        # /hooks/run must come before /hooks/{name} so "run" is not
        # captured as a hook name.
        Route("/hooks/run", _hooks_run_route, methods=["POST"]),
        Route("/hooks/{name}", _hooks_name_route, methods=["GET"]),
        Route("/vpn", _vpn_route, methods=["GET", "POST"]),
        Route("/termux", _termux_route, methods=["GET"]),
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
            if config.auth_token and token != config.auth_token:
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

    application = Starlette(routes=routes)
    application.add_middleware(CORSMiddleware, allow_origins=["*"],
                                allow_methods=["*"], allow_headers=["*"])
    application.add_middleware(AuthMiddleware)
    return application


# Module-level config + app, for `uvicorn bugxhunter.server:app`.
_config = load_config()
_server = make_server(_config)
app = make_app(_config)


def main():
    parser = argparse.ArgumentParser(description="bugXhunter server")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=7080)
    parser.add_argument("--config", default=None)
    parser.add_argument("--token", default=None)
    parser.add_argument("--vpn", action="store_true",
                        help="route outbound traffic through a VPN tunnel")
    parser.add_argument("--vpn-mode", default=None,
                        choices=("auto", "off", "proxy", "tun"),
                        help="how to route outbound traffic")
    parser.add_argument("--frida-host", default=None,
                        help="frida-server host (default: this machine)")
    args = parser.parse_args()

    config = load_config(args.config)
    if args.token:
        config.auth_token = args.token
    if args.frida_host:
        config.frida_host = args.frida_host
    if args.vpn_mode:
        config.vpn_mode = args.vpn_mode
    if args.vpn:
        config.vpn_enabled = True
        if config.vpn_mode == "off":
            config.vpn_mode = "auto"

    # A placeholder token is a well-known credential. The command line
    # entry point refuses to start rather than serving one.
    if config.auth_token in PLACEHOLDER_TOKENS:
        print("refusing to start: the auth token is a placeholder.")
        print("set a real token with AUTH_TOKEN, --token, or the "
              '"token" key in config.json')
        raise SystemExit(2)

    server = make_server(config)

    # Put the traffic routing into the requested mode.
    #
    # The result is reported, not discarded. A requested mode that could
    # not be applied says so, rather than the server quietly running in
    # the clear and looking protected.
    vpn_result = vpn_apply(config.vpn_mode or "auto")
    if vpn_result.get("note"):
        print("vpn: {} (requested {})".format(
            vpn_result.get("applied"), vpn_result.get("requested")))
        print("vpn: " + vpn_result["note"])
    else:
        print("vpn: mode {}".format(vpn_result.get("applied")))

    # Start Frida server if not running.
    #
    # Only in local mode. A remote frida-server belongs on the target,
    # and a PRoot guest cannot host one at all.
    if server.frida.is_local and not server.frida.status().get("running"):
        server.frida.start()

    import uvicorn
    # Serve an app built from THIS config, so --token, --frida-host and
    # --vpn actually take effect.
    uvicorn.run(make_app(config), host=args.host, port=args.port)


if __name__ == "__main__":
    main()
