#!/usr/bin/env python3
"""
BugXhunter Frida + Xhunter control plane.

Runs on the Android host (no root, no VM) and binds 0.0.0.0:7080 so it is
reachable over a VPN (WireGuard/Tailscale) without port forwarding.

  /frida/*    — drives the frida-server binary (Android arm64) over its
                control port, plus process/app discovery via adb.
  /xhunter/*  — manages the Xhunter SSH reverse tunnel, keeps a device
                roster, and proxies module commands to enrolled clients.

Why Starlette and not FastAPI: FastAPI requires pydantic v2, whose
pydantic-core is a Rust extension with no Android/aarch64 wheel. Starlette
has no compiled dependency, so the whole server runs natively here.

Why no frida-python: PyPI ships only glibc aarch64 wheels for frida, and
Android uses Bionic. The native binding cannot be loaded here (it needs
libc.so.6 / libpthread.so.0 / libdl.so.2 plus glibc symbol versioning; even
after repointing NEEDED and stripping the version tables it fails on a TLS
relocation model mismatch). frida-server is a native Android binary and
works fine, so we drive that instead.

Auth: every HTTP request needs the X-Auth-Token header, unless
ALLOW_UNAUTHENTICATED=1 is set (the server refuses to start otherwise).
"""

import asyncio
import json
import os
import hmac
import hashlib
import shutil
import socket
import subprocess
import time
import uuid
from dataclasses import dataclass, field, asdict
from pathlib import Path
from shutil import which
from typing import Any, Dict, List, Optional

from starlette.applications import Starlette
from starlette.responses import HTMLResponse, JSONResponse, PlainTextResponse
from starlette.routing import Route, WebSocketRoute
from starlette.websockets import WebSocket, WebSocketDisconnect

# ─────────────────────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────────────────────

HERE = Path(__file__).resolve().parent
CONFIG_PATH = Path(os.environ.get("BUGXHUNTER_CONFIG", HERE / "config.json"))
STATE_DIR = Path(os.environ.get("BUGXHUNTER_STATE", HERE / "state"))
STATE_DIR.mkdir(parents=True, exist_ok=True)

FRIDA_SERVER_BIN = os.environ.get("FRIDA_SERVER_BIN", "frida-server")
FRIDA_HOST = os.environ.get("FRIDA_HOST", "127.0.0.1")
FRIDA_PORT = int(os.environ.get("FRIDA_PORT", "27042"))
RESULT_TTL_SECONDS = int(os.environ.get("RESULT_TTL_SECONDS", "1800"))
MAX_BUFFERED_MESSAGES = 5000
# Remote SSH probe. An emulated guest (QEMU/TCG) can take ~90s just to send a
# banner, so the old hardcoded 15s/5s timeouts were unusable there. Both are
# now overridable per-deployment via xhunter.probe_timeout in config.json.
PROBE_TIMEOUT_SECONDS = int(os.environ.get("PROBE_TIMEOUT_SECONDS", "20"))
PROBE_CACHE_SECONDS = float(os.environ.get("PROBE_CACHE_SECONDS", "30"))
# How long start() waits to see whether the -R forward actually established.
# Must exceed the remote handshake, which is ~90s on an emulated guest.
START_GRACE_SECONDS = float(os.environ.get("START_GRACE_SECONDS", "20"))


def load_config() -> Dict[str, Any]:
    if CONFIG_PATH.exists():
        try:
            return json.loads(CONFIG_PATH.read_text())
        except json.JSONDecodeError as exc:
            raise SystemExit(f"Bad config at {CONFIG_PATH}: {exc}")
    return {
        "auth_token": "",
        "frida": {"host": FRIDA_HOST, "port": FRIDA_PORT, "remotes": []},
        "xhunter": {
            "vps_host": "",
            "vps_user": "root",
            "vps_port": 22,
            "vps_key": "",
            "listen_port": 8080,
            "gateway_ports": True,
            "probe_timeout": PROBE_TIMEOUT_SECONDS,
            "start_grace": START_GRACE_SECONDS,
        },
    }


CONFIG = load_config()


def auth_token() -> str:
    return os.environ.get("AUTH_TOKEN") or CONFIG.get("auth_token", "")


def auth_enabled() -> bool:
    return bool(auth_token()) or os.environ.get("ALLOW_UNAUTHENTICATED") == "1"


def unauthorized() -> bool:
    return not auth_enabled() and os.environ.get("ALLOW_UNAUTHENTICATED") != "1"


# ─────────────────────────────────────────────────────────────────────────────
# Small helpers
# ─────────────────────────────────────────────────────────────────────────────


class ApiError(Exception):
    def __init__(self, status: int, detail: str) -> None:
        self.status = status
        self.detail = detail


def find_api_error(exc: BaseException) -> Optional[ApiError]:
    """
    Starlette runs handlers inside an anyio task group, so a raised ApiError
    reaches us wrapped in an ExceptionGroup. Unwrap to find it.
    """
    if isinstance(exc, ApiError):
        return exc
    nested = getattr(exc, "exceptions", None)
    if nested:
        for sub in nested:
            found = find_api_error(sub)
            if found is not None:
                return found
    return None


def run(cmd: List[str], timeout: int = 30) -> Dict[str, Any]:
    """Run a command and capture its output."""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, errors="replace")
    except FileNotFoundError:
        raise ApiError(404, f"Command not found: {cmd[0]}")
    except subprocess.TimeoutExpired:
        raise ApiError(504, f"Command timed out after {timeout}s: {' '.join(cmd)}")
    return {"rc": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}


def adb(*args: str, timeout: int = 20) -> Dict[str, Any]:
    return run(["adb", *args], timeout=timeout)


def try_run(cmd: List[str], timeout: int = 20) -> Optional[Dict[str, Any]]:
    """Like run(), but returns None instead of raising when cmd[0] is missing."""
    try:
        return run(cmd, timeout=timeout)
    except ApiError as exc:
        if exc.status == 404:
            return None
        raise


def port_open(host: str, port: int, timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


SCRATCH = Path(os.environ.get("HARNESS_SCRATCH", "/data/local/tmp/androidharness-scratch"))


def stage_executable(source: Path) -> Optional[str]:
    """Copy a binary into scratch (exec-capable) and chmod it, if we can."""
    try:
        target_dir = SCRATCH / "bugxhunter-server-bin"
        target_dir.mkdir(parents=True, exist_ok=True)
        target = target_dir / source.name
        if not target.exists() or target.stat().st_size != source.stat().st_size:
            shutil.copyfile(source, target)
        target.chmod(0o755)
        return str(target)
    except OSError:
        return None


def body_json(request) -> Dict[str, Any]:
    raw = request.state.raw_body or b""
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ApiError(400, f"Invalid JSON body: {exc}")
    return parsed if isinstance(parsed, dict) else {"value": parsed}


# ─────────────────────────────────────────────────────────────────────────────
# Result store
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class ResultBuffer:
    id: str
    kind: str
    target: str
    created: float = field(default_factory=time.time)
    messages: List[Dict[str, Any]] = field(default_factory=list)
    meta: Dict[str, Any] = field(default_factory=dict)

    def append(self, message: Dict[str, Any]) -> None:
        self.messages.append(message)
        if len(self.messages) > MAX_BUFFERED_MESSAGES:
            del self.messages[: len(self.messages) - MAX_BUFFERED_MESSAGES]


class ResultStore:
    def __init__(self) -> None:
        self._items: Dict[str, ResultBuffer] = {}

    def create(self, kind: str, target: str, **meta: Any) -> ResultBuffer:
        self._sweep()
        buf = ResultBuffer(id=uuid.uuid4().hex[:16], kind=kind, target=target, meta=meta)
        self._items[buf.id] = buf
        return buf

    def get(self, result_id: str) -> ResultBuffer:
        buf = self._items.get(result_id)
        if buf is None:
            raise ApiError(404, f"No such result id: {result_id}")
        return buf

    def _sweep(self) -> None:
        cutoff = time.time() - RESULT_TTL_SECONDS
        for rid in [r.id for r in self._items.values() if r.created < cutoff]:
            del self._items[rid]

    def all(self) -> List[ResultBuffer]:
        self._sweep()
        return sorted(self._items.values(), key=lambda b: b.created, reverse=True)

    def drop(self, result_id: str) -> None:
        self._items.pop(result_id, None)


RESULTS = ResultStore()
SUBSCRIBERS: Dict[str, List[WebSocket]] = {}


async def emit(buf: ResultBuffer, message: Dict[str, Any]) -> None:
    buf.append(message)
    for ws in list(SUBSCRIBERS.get(buf.id, [])):
        try:
            await ws.send_text(json.dumps(message))
        except Exception:
            try:
                SUBSCRIBERS[buf.id].remove(ws)
            except ValueError:
                pass


# ─────────────────────────────────────────────────────────────────────────────
# Frida module
# ─────────────────────────────────────────────────────────────────────────────


class FridaManager:
    """Owns the frida-server binary lifecycle and process discovery."""

    def __init__(self) -> None:
        self.proc: Optional[subprocess.Popen] = None
        self.host = CONFIG.get("frida", {}).get("host", FRIDA_HOST)
        self.port = int(CONFIG.get("frida", {}).get("port", FRIDA_PORT))
        self.started_at: Optional[float] = None

    def binary_path(self) -> str:
        """
        Locate an executable frida-server. Shared storage has no exec bit, so
        a copy placed next to this script is staged into the harness scratch
        dir and chmod +x'd there before being used.
        """
        for candidate in (FRIDA_SERVER_BIN, str(HERE / "frida-server")):
            path = Path(candidate)
            if not path.is_file():
                continue
            if os.access(path, os.X_OK):
                return str(path)
            staged = stage_executable(path)
            if staged:
                return staged
        found = which("frida-server")
        if found:
            return found
        raise ApiError(
            500,
            "frida-server binary not found. Set FRIDA_SERVER_BIN or place the binary next to this script.",
        )

    def is_running(self) -> bool:
        if self.proc and self.proc.poll() is None:
            return True
        return port_open(self.host, self.port)

    async def start(self) -> Dict[str, Any]:
        if self.is_running():
            return {"status": "already-running", "host": self.host, "port": self.port}
        path = self.binary_path()
        cmd = [path, "-l", f"0.0.0.0:{self.port}"]
        self.proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.started_at = time.time()
        await asyncio.sleep(1.0)
        alive = self.proc.poll() is None
        if not alive:
            self.proc = None
        return {
            "status": "started" if alive else "exited-immediately",
            "pid": self.proc.pid if alive else None,
            "host": self.host,
            "port": self.port,
            "cmd": cmd,
        }

    def stop(self) -> Dict[str, Any]:
        stopped = False
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
            stopped = True
        self.proc = None
        self.started_at = None
        return {"status": "stopped" if stopped else "not-running"}

    def status(self) -> Dict[str, Any]:
        version = None
        try:
            version = run([self.binary_path(), "--version"], timeout=10)["stdout"].strip()
        except ApiError:
            pass
        return {
            "running": self.is_running(),
            "host": self.host,
            "port": self.port,
            "port_open": port_open(self.host, self.port),
            "pid": self.proc.pid if self.proc and self.proc.poll() is None else None,
            "uptime_seconds": round(time.time() - self.started_at, 1) if self.started_at else None,
            "version": version,
        }

    def list_processes(self) -> List[Dict[str, Any]]:
        """
        On-device we call ps directly; adb is the fallback when this server is
        pointed at a remote device. Toybox ps -A prints "PID TTY TIME CMD", so
        the command line is the last field — and toybox rejects the -o format
        specifiers, hence the plain fallback.
        """
        result = self._device_cmd(["ps", "-A", "-o", "PID,NAME,ARGS"])
        lines = result["stdout"].splitlines()
        if "PID" not in result["stdout"]:
            result = self._device_cmd(["ps", "-A"])
            lines = result["stdout"].splitlines()

        header = lines[0].split() if lines else []
        cmd_index = header.index("CMD") if "CMD" in header else None

        processes: List[Dict[str, Any]] = []
        for line in lines[1:]:
            parts = line.split(None, 4 if cmd_index == 4 else 3)
            if len(parts) < 2 or not parts[0].isdigit():
                continue
            pid = int(parts[0])
            if cmd_index is not None and len(parts) > cmd_index:
                command = parts[cmd_index]
                name = command.rsplit("/", 1)[-1]
            else:
                # "PID NAME" style output (adb shell ps -A -o PID,NAME)
                command = parts[-1]
                name = parts[1] if len(parts) > 2 else command
            processes.append({"pid": pid, "name": name, "args": command})
        return processes
    def list_applications(self) -> List[Dict[str, Any]]:
        result = self._device_cmd(["pm", "list", "packages", "-3"])
        packages = []
        for line in result["stdout"].splitlines():
            line = line.strip()
            if line.startswith("package:"):
                packages.append(line[len("package:") :])
        return [{"package": p} for p in packages]

    def _device_cmd(self, argv: List[str]) -> Dict[str, Any]:
        """Run a command on the target: locally, or over adb for a remote device."""
        local = try_run(argv)
        if local is not None:
            return local
        try:
            return adb("shell", *argv)
        except ApiError as exc:
            raise ApiError(500, f"Cannot run {argv[0]}: not available locally and adb is missing ({exc.detail})")

    async def run_script(self, target: str, script: str, mode: str = "attach") -> ResultBuffer:
        """
        Inject a JS script into a target. Uses the frida CLI, which talks to
        frida-server over USB/TCP without needing the Python bindings.
        """
        cli = which("frida")
        if not cli:
            raise ApiError(
                501,
                "frida CLI not found. The Python bindings cannot load on Android/Bionic — "
                "install frida-tools on a Linux host and point it at this device instead.",
            )
        buf = RESULTS.create("frida", target, mode=mode)
        host_flag = ["-H", f"{self.host}:{self.port}"] if not port_open("127.0.0.1", 27042) else ["-U"]
        cmd = [cli, *host_flag, "-q", "-f", target] if mode == "spawn" else [cli, *host_flag, "-q", "-n", target]
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
        )
        try:
            proc.stdin.write(script.encode() + b"\n%exit\n")
            await proc.stdin.drain()
            proc.stdin.close()
        except Exception:
            pass
        await emit(buf, {"type": "started", "target": target, "mode": mode, "cmd": cmd})
        try:
            async for line in proc.stdout:
                await emit(buf, {"type": "log", "line": line.decode(errors="replace").rstrip()})
        finally:
            await proc.wait()
        await emit(buf, {"type": "done", "rc": proc.returncode})
        return buf


FRIDA = FridaManager()


# ─────────────────────────────────────────────────────────────────────────────
# Xhunter module
# ─────────────────────────────────────────────────────────────────────────────


class XhunterManager:
    """
    Xhunter's server side is an SSH gateway: the operator app and the enrolled
    clients both connect out to a VPS, so the VPS only needs sshd with
    GatewayPorts enabled. This manages that tunnel and the device roster.
    """

    def __init__(self) -> None:
        self.proc: Optional[subprocess.Popen] = None
        self.config: Dict[str, Any] = dict(CONFIG.get("xhunter", {}))
        self.started_at: Optional[float] = None
        self.devices: Dict[str, Dict[str, Any]] = {}
        self.log_path = STATE_DIR / "xhunter-tunnel.log"
        # Cache for the remote sshd probe; see remote_status().
        self._probe_at: float = 0.0
        self._probe_result: Optional[str] = None

    def _key_flag(self) -> List[str]:
        return ["-i", self.config["vps_key"]] if self.config.get("vps_key") else []

    def is_running(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def start(self, overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if overrides:
            self.config.update({k: v for k, v in overrides.items() if v is not None})
        if not self.config.get("vps_host"):
            raise ApiError(400, "vps_host is required to start the tunnel")
        if self.is_running():
            return {"status": "already-running"}
        ssh = which("ssh")
        if not ssh:
            raise ApiError(500, "ssh client not found on PATH")
        listen = int(self.config.get("listen_port", 8080))
        cmd = [
            ssh, "-N", *self._key_flag(),
            "-o", "StrictHostKeyChecking=no",
            "-o", "ServerAliveInterval=30",
            "-o", f"ConnectTimeout={self._probe_timeout()}",
            "-o", "ExitOnForwardFailure=yes",
            "-R", f"0.0.0.0:{listen}:localhost:{listen}",
            "-p", str(self.config.get("vps_port", 22)),
            f"{self.config.get('vps_user', 'root')}@{self.config['vps_host']}",
        ]
        self.proc = subprocess.Popen(cmd, stdout=self.log_path.open("ab"), stderr=subprocess.STDOUT)
        self.started_at = time.time()

        # 1.5s was never enough to tell success from failure. ExitOnForwardFailure
        # means ssh exits non-zero as soon as the remote refuses the -R, but a
        # slow guest may not have finished the handshake at all by then, so the
        # old check reported "started" for a tunnel that had already died. Poll
        # until the process settles one way or the other.
        grace = float(self.config.get("start_grace", START_GRACE_SECONDS))
        deadline = time.time() + grace
        alive = True
        while time.time() < deadline:
            alive = self.proc.poll() is None
            if not alive:
                break
            await_sleep(0.25)

        tail = self.log_tail(20)
        if not alive:
            self.proc = None
        return {
            "status": "started" if alive else "exited-immediately",
            "pid": self.proc.pid if alive else None,
            "cmd": cmd,
            "log": str(self.log_path),
            "log_tail": tail,
            # Both are actionable: a refused -R usually means the remote sshd
            # lacks GatewayPorts, and -R needs AllowTcpForwarding remote.
            "hint": None if alive else (
                "ssh exited before the forward was established. On the remote, "
                "sshd needs 'GatewayPorts yes' and 'AllowTcpForwarding remote'; "
                "dropbear uses -g / etc/ssh/dropbear_config instead. "
                f"Log: {tail.strip() or '(empty)'}"
            ),
        }

    def stop(self) -> Dict[str, Any]:
        stopped = False
        if self.is_running():
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
            stopped = True
        self.proc = None
        self.started_at = None
        return {"status": "stopped" if stopped else "not-running"}

    def status(self) -> Dict[str, Any]:
        """Local state only. Deliberately synchronous and instant.

        The remote GatewayPorts probe used to run here, which meant every
        /xhunter/status call shelled out to ssh and blocked the event loop for
        up to 15s. Against an emulated guest that needs ~90s just to send a
        banner, that stalled every concurrent request. Callers that want the
        remote probe should await self.remote_status().
        """
        return {
            "tunnel_running": self.is_running(),
            "pid": self.proc.pid if self.is_running() else None,
            "uptime_seconds": round(time.time() - self.started_at, 1) if self.started_at else None,
            "config": self.config,
            "device_count": len(self.devices),
        }

    async def remote_status(self) -> Dict[str, Any]:
        """Local status plus a remote probe, with the SSH call off the loop.

        The probe runs in a thread because subprocess.run is blocking. Cached
        briefly, because it is slow against an emulated VM and a client that
        polls it would otherwise pay that cost on every request.
        """
        state = self.status()
        if not self.config.get("vps_host"):
            state["remote_sshd"] = None
            state["remote_sshd_note"] = "no vps_host configured"
            return state

        now = time.time()
        if now - self._probe_at < PROBE_CACHE_SECONDS:
            state["remote_sshd"] = self._probe_result
            state["remote_sshd_cached"] = round(PROBE_CACHE_SECONDS - (now - self._probe_at), 1)
            return state

        loop = asyncio.get_event_loop()
        try:
            result = await asyncio.wait_for(
                loop.run_in_executor(None, self._probe_remote_sshd),
                timeout=self._probe_timeout() + 5,
            )
        except asyncio.TimeoutError:
            result = f"error: probe exceeded {self._probe_timeout()}s budget"
        except Exception as exc:  # noqa: BLE001 - report, never crash the server
            result = f"error: {exc}"

        self._probe_at = now
        self._probe_result = result
        state["remote_sshd"] = result
        return state

    def _probe_remote_sshd(self) -> str:
        """Blocking; always called via run_in_executor. Detects sshd flavour."""
        timeout = self._probe_timeout()
        script = (
            # Dropbear and OpenSSH keep their settings in different places, and
            # NixOS generates /etc/ssh/sshd_config rather than shipping one, so
            # check every plausible source before declaring it unset.
            "{ "
            "for f in /etc/ssh/sshd_config /etc/ssh/dropbear_config "
            "/run/current-system/etc/ssh/sshd_config; do "
            "  [ -r \"$f\" ] && grep -ihE '^\\s*GatewayPorts' \"$f\"; "
            "done; "
            "} | head -3"
        )
        out = run(
            [which("ssh") or "ssh",
             "-o", "BatchMode=yes",
             "-o", f"ConnectTimeout={timeout}",
             "-o", "ServerAliveInterval=15",
             *self._key_flag(),
             "-p", str(self.config.get("vps_port", 22)),
             f"{self.config.get('vps_user', 'root')}@{self.config['vps_host']}",
             script],
            timeout=timeout + 5,
        )
        text = out["stdout"].strip()
        return text or "GatewayPorts not set (no readable config found)"

    def _probe_timeout(self) -> int:
        return int(self.config.get("probe_timeout", PROBE_TIMEOUT_SECONDS))

    def log_tail(self, lines: int = 200) -> str:
        if not self.log_path.exists():
            return ""
        return "\n".join(self.log_path.read_text(errors="replace").splitlines()[-lines:])

    def register_device(self, device_id: str, info: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        entry = {"id": device_id, "first_seen": time.time(), "last_seen": time.time(), **(info or {})}
        self.devices[device_id] = entry
        return entry

    def roster(self) -> List[Dict[str, Any]]:
        return sorted(self.devices.values(), key=lambda d: d.get("last_seen", 0), reverse=True)

    def send_command(self, device: str, module: str, args: Dict[str, Any]) -> Dict[str, Any]:
        if device not in self.devices:
            raise ApiError(404, f"Unknown device: {device}")
        self.devices[device]["last_seen"] = time.time()
        payload = {"device": device, "module": module, "args": args}
        buf = RESULTS.create("xhunter", device, module=module)
        asyncio.get_event_loop().create_task(emit(buf, {"type": "dispatch", "payload": payload}))
        return {"result_id": buf.id, "payload": payload}


def await_sleep(seconds: float) -> None:
    time.sleep(seconds)


XHUNTER = XhunterManager()


# ─────────────────────────────────────────────────────────────────────────────
# Auth middleware
# ─────────────────────────────────────────────────────────────────────────────


# Paths reachable without a token. /health is a bare liveness probe; the
# detailed view lives on the authenticated /status.
PUBLIC_PATHS = {"/health"}


class AuthMiddleware:
    """
    Pure-ASGI auth + body capture. Replays the body to the app afterwards.

    PUBLIC_PATHS are reachable without a token so liveness probes work without
    carrying a secret. They must only return non-sensitive data.
    """

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] not in ("http", "websocket"):
            return await self.app(scope, receive, send)

        scope.setdefault("state", {})

        if scope["type"] == "websocket":
            token = auth_token()
            if token:
                query = scope.get("query_string", b"").decode()
                supplied = None
                for pair in query.split("&"):
                    if pair.startswith("token="):
                        supplied = pair[len("token="):]
                        break
                if supplied != token:
                    await send({"type": "websocket.close", "code": 4401})
                    return
            return await self.app(scope, receive, send)

        token = auth_token()
        if token and scope.get("path") not in PUBLIC_PATHS:
            supplied = None
            for key, value in scope.get("headers", []):
                if key == b"x-auth-token":
                    supplied = value.decode()
                    break
            if supplied != token:
                response = JSONResponse({"error": "Invalid or missing X-Auth-Token"}, status_code=401)
                return await response(scope, receive, send)

        # Buffer the body so handlers can re-read it from scope["state"].
        body = b""
        more = True
        while more:
            message = await receive()
            body += message.get("body", b"")
            more = message.get("more_body", False)
        scope["state"]["raw_body"] = body

        sent = False

        async def replay() -> Dict[str, Any]:
            nonlocal sent
            if sent:
                return {"type": "http.disconnect"}
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}

        return await self.app(scope, replay, send)


# ─────────────────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────────────────

INDEX_HTML = """<!doctype html>
<title>BugXhunter Frida + Xhunter</title>
<h1>BugXhunter Frida + Xhunter server</h1>
<p>Running. Endpoints:</p>
<ul>
  <li><code>GET  /health</code> &mdash; liveness probe, no auth needed</li>
  <li><code>GET  /status</code> &mdash; frida + xhunter detail (auth)</li>
  <li><code>GET  /frida/status</code> &middot; <code>POST /frida/start</code> &middot; <code>POST /frida/stop</code></li>
  <li><code>GET  /frida/devices</code> &middot; <code>GET /frida/processes</code> &middot; <code>GET /frida/applications</code></li>
  <li><code>POST /frida/script</code> &middot; <code>GET /frida/results</code> &middot; <code>GET /frida/results/{id}</code></li>
  <li><code>GET  /xhunter/status</code> &middot; <code>POST /xhunter/tunnel</code></li>
  <li><code>GET  /xhunter/devices</code> &middot; <code>POST /xhunter/enroll</code></li>
  <li><code>POST /xhunter/command</code> &middot; <code>GET /xhunter/logs</code></li>
</ul>
<p>WebSocket streams: <code>/frida/stream/{id}</code>, <code>/xhunter/stream/{id}</code></p>
"""


async def index(request) -> HTMLResponse:
    return HTMLResponse(INDEX_HTML)


async def health(request) -> JSONResponse:
    """
    Deliberately unauthenticated and deliberately minimal: monitors need a
    liveness probe that requires no secret. Anything interesting belongs on
    /status, which is authenticated.
    """
    return JSONResponse({"ok": True})


async def status(request) -> JSONResponse:
    """The detailed view that /health used to carry, now behind auth."""
    return JSONResponse(
        {
            "ok": True,
            "frida": FRIDA.status(),
            "xhunter": {"tunnel_running": XHUNTER.is_running(), "devices": len(XHUNTER.devices)},
            "results": len(RESULTS.all()),
        }
    )


# -- Frida routes -------------------------------------------------------------


async def frida_status(request) -> JSONResponse:
    return JSONResponse(FRIDA.status())


async def frida_start(request) -> JSONResponse:
    payload = body_json(request)
    if payload.get("host"):
        FRIDA.host = payload["host"]
    if payload.get("port"):
        FRIDA.port = int(payload["port"])
    return JSONResponse(await FRIDA.start())


async def frida_stop(request) -> JSONResponse:
    return JSONResponse(FRIDA.stop())


async def frida_devices(request) -> JSONResponse:
    return JSONResponse(
        {
            "local": {
                "id": "local",
                "type": "socket",
                "name": f"{FRIDA.host}:{FRIDA.port}",
                "online": port_open(FRIDA.host, FRIDA.port),
            },
            "remotes": CONFIG.get("frida", {}).get("remotes", []),
        }
    )


async def frida_processes(request) -> JSONResponse:
    return JSONResponse({"processes": FRIDA.list_processes()})


async def frida_applications(request) -> JSONResponse:
    return JSONResponse({"applications": FRIDA.list_applications()})


async def frida_script(request) -> JSONResponse:
    payload = body_json(request)
    target = payload.get("target")
    if not target:
        raise ApiError(400, "'target' is required (package name, process name, or pid)")
    buf = await FRIDA.run_script(
        target=target,
        script=payload.get("script", ""),
        mode=payload.get("mode", "attach"),
    )
    return JSONResponse(
        {"result_id": buf.id, "target": buf.target, "mode": payload.get("mode", "attach"),
         "messages": buf.messages}
    )


async def frida_results(request) -> JSONResponse:
    return JSONResponse(
        {
            "results": [
                {"id": b.id, "kind": b.kind, "target": b.target, "created": b.created, "count": len(b.messages)}
                for b in RESULTS.all()
            ]
        }
    )


async def frida_result(request) -> JSONResponse:
    since = int(request.query_params.get("since", 0))
    buf = RESULTS.get(request.path_params["result_id"])
    return JSONResponse(
        {"id": buf.id, "kind": buf.kind, "target": buf.target, "created": buf.created,
         "meta": buf.meta, "messages": buf.messages[since:]}
    )


async def frida_result_delete(request) -> JSONResponse:
    rid = request.path_params["result_id"]
    RESULTS.drop(rid)
    return JSONResponse({"status": "deleted", "id": rid})


# -- Xhunter routes -----------------------------------------------------------


async def xhunter_status(request) -> JSONResponse:
    return JSONResponse(await XHUNTER.remote_status())


async def xhunter_tunnel(request) -> JSONResponse:
    payload = body_json(request)
    action = payload.get("action", "status")
    if action == "start":
        return JSONResponse(XHUNTER.start(payload.get("config")))
    if action == "stop":
        return JSONResponse(XHUNTER.stop())
    if action == "status":
        return JSONResponse(await XHUNTER.remote_status())
    raise ApiError(400, "action must be 'start', 'stop', or 'status'")


async def xhunter_devices(request) -> JSONResponse:
    return JSONResponse({"devices": XHUNTER.roster()})


async def xhunter_enroll(request) -> JSONResponse:
    payload = body_json(request)
    device_id = payload.get("device_id")
    if not device_id:
        raise ApiError(400, "'device_id' is required")
    return JSONResponse(XHUNTER.register_device(device_id, payload.get("info", {})))


async def xhunter_command(request) -> JSONResponse:
    payload = body_json(request)
    device = payload.get("device")
    module = payload.get("module")
    if not device or not module:
        raise ApiError(400, "'device' and 'module' are required")
    return JSONResponse(XHUNTER.send_command(device, module, payload.get("args", {})))


async def xhunter_logs(request) -> PlainTextResponse:
    return PlainTextResponse(XHUNTER.log_tail(int(request.query_params.get("lines", 200))))


# -- Drop chain routes --------------------------------------------------------

async def drop_receive(request) -> JSONResponse:
    body = await request.body()
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        return JSONResponse({"ok": False, "reason": "invalid JSON"})
    
    # Validate HMAC using the shared PSK
    psk = (CONFIG.get("drop_psk", "") or os.environ.get("DROP_PSK", "")).encode()
    if not psk:
        return JSONResponse({"ok": False, "reason": "drop_psk not configured"})
    
    # body format: nonce(8) + ciphertext + mac(8)
    if len(body) < 16:
        return JSONResponse({"ok": False, "reason": "payload too short"})
    
    nonce = body[:8]
    mac = body[-8:]
    ciphertext = body[8:-8]
    
    # Calculate expected HMAC
    expected_mac = hmac.new(psk, nonce + ciphertext, hashlib.sha256).digest()[:8]
    if not hmac.compare_digest(mac, expected):
        return JSONResponse({"ok": False, "reason": "MAC mismatch"})
    
    # Store the payload
    store_dir = CONFIG.get("drop_store_dir", "/data/local/tmp/drops")
    os.makedirs(store_dir, exist_ok=True)
    
    timestamp = int(time.time())
    path = os.path.join(store_dir, f"{timestamp}.bin")
    with open(path, "wb") as f:
        f.write(ciphertext)
    
    return JSONResponse({
        "ok": True,
        "path": path,
        "size": len(ciphertext),
        "timestamp": timestamp
    })


async def frida_control(request) -> JSONResponse:
    body = await request.body()
    try:
        payload = json.loads(body or b"{}")
    except json.JSONDecodeError:
        return JSONResponse({"ok": False, "reason": "invalid JSON"})
    
    # Forward command to C:7080 (reverse tunnel established by bootstrapper)
    import socket
    try:
        sock = socket.create_connection(("127.0.0.1", 7080), timeout=5)
        sock.sendall(json.dumps(payload).encode())
        
        # Receive response
        resp = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            resp += chunk
        
        sock.close()
        try:
            result = json.loads(resp)
            return JSONResponse(result)
        except:
            return JSONResponse({"ok": True, "raw": resp.decode("utf-8", "replace")})
    except Exception as e:
        return JSONResponse({"ok": False, "reason": str(e)})


# -- WebSockets ---------------------------------------------------------------


async def stream(websocket: WebSocket) -> None:
    token = websocket.query_params.get("token") or websocket.headers.get("x-auth-token")
    if auth_token() and token != auth_token():
        await websocket.close(code=4401)
        return
    result_id = websocket.path_params["result_id"]
    try:
        buf = RESULTS.get(result_id)
    except ApiError:
        await websocket.close(code=4404)
        return
    await websocket.accept()
    SUBSCRIBERS.setdefault(result_id, []).append(websocket)
    try:
        for message in buf.messages:
            await websocket.send_text(json.dumps(message))
        while True:
            raw = await websocket.receive_text()
            try:
                cmd = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if "since" in cmd:
                for message in buf.messages[int(cmd["since"]):]:
                    await websocket.send_text(json.dumps(message))
    except WebSocketDisconnect:
        pass
    finally:
        if websocket in SUBSCRIBERS.get(result_id, []):
            SUBSCRIBERS[result_id].remove(websocket)


# ─────────────────────────────────────────────────────────────────────────────
# App
# ─────────────────────────────────────────────────────────────────────────────

routes = [
    Route("/", index, methods=["GET"]),
    Route("/health", health, methods=["GET"]),
    Route("/status", status, methods=["GET"]),
    Route("/frida/status", frida_status, methods=["GET"]),
    Route("/frida/start", frida_start, methods=["POST"]),
    Route("/frida/stop", frida_stop, methods=["POST"]),
    Route("/frida/devices", frida_devices, methods=["GET"]),
    Route("/frida/processes", frida_processes, methods=["GET"]),
    Route("/frida/applications", frida_applications, methods=["GET"]),
    Route("/frida/script", frida_script, methods=["POST"]),
    Route("/frida/results", frida_results, methods=["GET"]),
    Route("/frida/results/{result_id}", frida_result, methods=["GET"]),
    Route("/frida/results/{result_id}", frida_result_delete, methods=["DELETE"]),
    WebSocketRoute("/frida/stream/{result_id}", stream),
    Route("/xhunter/status", xhunter_status, methods=["GET"]),
    Route("/xhunter/tunnel", xhunter_tunnel, methods=["POST"]),
    Route("/xhunter/devices", xhunter_devices, methods=["GET"]),
    Route("/xhunter/enroll", xhunter_enroll, methods=["POST"]),
    Route("/xhunter/command", xhunter_command, methods=["POST"]),
    Route("/xhunter/logs", xhunter_logs, methods=["GET"]),
    WebSocketRoute("/xhunter/stream/{result_id}", stream),
    # ── Drop chain routes ───────────────────────────────────────────────
    # POST /drop/receive — C posts decoded payload blobs; server validates HMAC
    Route("/drop/receive", drop_receive, methods=["POST"]),
    # POST /frida/control — forward a control command to C:7080 over the
    # reverse tunnel established by the bootstrapper on Phone C.
    Route("/frida/control", frida_control, methods=["POST"]),
]


async def on_shutdown() -> None:
    FRIDA.stop()
    XHUNTER.stop()


from contextlib import asynccontextmanager  # noqa: E402


@asynccontextmanager
async def lifespan(_app):
    yield
    FRIDA.stop()
    XHUNTER.stop()


class ErrorHandling:
    """
    Fallback for ApiErrors that escape the exception_handlers registry — for
    example ones raised inside a Starlette task group and re-raised wrapped in
    an ExceptionGroup. Only responds if nothing has been sent yet.
    """

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        started = False

        async def tracking_send(message):
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, receive, tracking_send)
        except BaseException as exc:
            api_error = find_api_error(exc)
            if api_error is None or started:
                raise
            response = JSONResponse({"error": api_error.detail}, status_code=api_error.status)
            await response(scope, receive, send)


async def api_error_handler(request, exc: ApiError) -> JSONResponse:
    return JSONResponse({"error": exc.detail}, status_code=exc.status)


app = Starlette(
    routes=routes,
    lifespan=lifespan,
    # Register here rather than in outer middleware: Starlette's own
    # ServerErrorMiddleware would otherwise swallow ApiError into a plain 500.
    exception_handlers={ApiError: api_error_handler},
)

# Auth + body capture wrap the app so the token is checked before routing.
app = AuthMiddleware(app)


if __name__ == "__main__":
    import sys

    import uvicorn

    if unauthorized():
        print(
            "Refusing to start: no auth token.\n"
            "  Set AUTH_TOKEN=<secret>  (recommended)\n"
            "  or ALLOW_UNAUTHENTICATED=1  (anyone on the VPN can drive Frida)",
            file=sys.stderr,
        )
        raise SystemExit(2)

    uvicorn.run(
        app,
        host=os.environ.get("BIND_HOST", "0.0.0.0"),
        port=int(os.environ.get("BIND_PORT", "7080")),
        log_level=os.environ.get("LOG_LEVEL", "info"),
    )
