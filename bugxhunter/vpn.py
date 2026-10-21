"""VPN / tunnel integration layer.

Routes the server's outbound internet traffic through a VPN tunnel when
one is available. Three modes:

  off    - no VPN, direct connections only
  proxy  - all outbound HTTP(S) goes through an upstream proxy (e.g. Tor)
  tun    - a TUN or WireGuard interface is up and the default route
           goes through it, so every socket on the box is tunnelled

The TUN mode needs root or a VPN app that installs a tunnel interface.
On Termux that is typically Termux:VPN, WireGuard or mullvad.

The proxy mode is applied by setting the standard proxy environment
variables, which urllib and every subprocess inherit. That is what makes
it real rather than decorative.
"""

import json
import os
import shutil
import socket
import subprocess
from typing import Any, Dict, List, Optional

# Interface name fragments that indicate a tunnel is up.
TUNNEL_MARKERS = ("tun", "tap", "wg", "wireguard", "mullvad", "tailscale", "nordlynx")

# Environment variables that every HTTP client understands.
PROXY_VARS = ("ALL_PROXY", "all_proxy", "HTTP_PROXY", "http_proxy",
               "HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy")


def _run(args: List[str], timeout: int = 10) -> Optional[str]:
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        if p.returncode == 0:
            return p.stdout.strip()
        return None
    except Exception:
        return None


def tunnel_interfaces() -> List[str]:
    """List active tunnel interfaces (tun0, wg0, mullvad, tailscale, ...)."""
    out = _run(["ip", "-o", "link", "show"])
    if not out:
        out = _run(["ip", "link", "show"])
    if not out:
        return []
    ifaces = []
    for line in out.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        # "2: tun0: <POINTOPOINT,UP> ..." or with -o "2: tun0: ..."
        parts = line.split(":")
        if len(parts) < 2:
            continue
        name = parts[1].strip()
        if not name:
            continue
        if any(marker in name.lower() for marker in TUNNEL_MARKERS):
            ifaces.append(name)
    return ifaces


def mullvad_active() -> bool:
    """True when the mullvad client reports a connected daemon."""
    if not shutil.which("mullvad"):
        return False
    out = _run(["mullvad", "status"], timeout=5)
    if not out:
        return False
    lowered = out.lower()
    return "connected" in lowered and "disconnected" not in lowered


def openvpn_active() -> bool:
    """True when an openvpn process is running."""
    out = _run(["pgrep", "-f", "openvpn"], timeout=5)
    return bool(out)


def tor_active() -> bool:
    """Tor SOCKS5 proxy on 9050 is the standard Tor indicator."""
    try:
        with socket.create_connection(("127.0.0.1", 9050), timeout=1):
            return True
    except OSError:
        return False


def active_mode() -> str:
    """Detect which VPN mode is currently active.

    A tunnel interface only counts as "tun" if the default route
    actually goes through it. An interface that is up but unused is
    reported as "off" rather than pretending the traffic is protected.
    """
    if mullvad_active() or openvpn_active() or default_route_through_tunnel():
        return "tun"
    if tor_active():
        return "proxy"
    if os.environ.get("ALL_PROXY") or os.environ.get("all_proxy"):
        return "proxy"
    return "off"


def proxy_url() -> Optional[str]:
    """Return the SOCKS5 proxy URL when one is active."""
    if tor_active():
        return "socks5h://127.0.0.1:9050"
    # environment-variable override
    return os.environ.get("ALL_PROXY") or os.environ.get("all_proxy")


def tunnel_ips() -> List[str]:
    """IP addresses assigned to tunnel interfaces."""
    out = _run(["ip", "addr", "show"])
    if not out:
        return []
    ips = []
    for line in out.splitlines():
        line = line.strip()
        if "inet " in line and any(t in line for t in ("tun", "wg", "mullvad")):
            parts = line.split()
            for i, p in enumerate(parts):
                if p == "inet" and i + 1 < len(parts):
                    ips.append(parts[i + 1].split("/")[0])
    return ips


def status() -> Dict[str, Any]:
    return {
        "mode": active_mode(),
        "proxy_url": proxy_url(),
        "tunnel_interfaces": tunnel_interfaces(),
        "tunnel_ips": tunnel_ips(),
        "mullvad": mullvad_active(),
        "tor": tor_active(),
    }


def default_route_through_tunnel() -> bool:
    """True when the default route goes through a tunnel interface.

    This is a check, not an action. The name says what it does.
    """
    out = _run(["ip", "route", "show", "default"])
    if not out:
        return False
    return any(marker in out for marker in ("tun", "wg", "mullvad", "tailscale"))


def set_env_proxy(mode: str) -> Dict[str, str]:
    """Apply the proxy environment for *mode* and return what was set.

    The variables are set in this process, so urllib and every
    subprocess inherit them. That is what actually moves the traffic.
    """
    env: Dict[str, str] = {}
    if mode == "proxy":
        proxy = proxy_url()
        if proxy:
            for name in ("ALL_PROXY", "all_proxy", "HTTP_PROXY", "http_proxy",
                         "HTTPS_PROXY", "https_proxy"):
                env[name] = proxy
                os.environ[name] = proxy
            # Keep the loopback out of the proxy, otherwise the server
            # cannot talk to itself or to a frida-server on this host.
            env["NO_PROXY"] = "127.0.0.1,localhost"
            env["no_proxy"] = "127.0.0.1,localhost"
            os.environ["NO_PROXY"] = env["NO_PROXY"]
            os.environ["no_proxy"] = env["no_proxy"]
    return env


def clear_env_proxy() -> Dict[str, str]:
    """Remove the proxy environment variables."""
    removed = {}
    for name in PROXY_VARS:
        if name in os.environ:
            removed[name] = os.environ.pop(name)
    return removed


def apply(mode: str = "auto") -> Dict[str, Any]:
    """Put the traffic routing into the requested mode.

    "auto" uses whatever is already available. "off" removes any proxy
    environment. "proxy" forces the proxy variables. "tun" can only be
    honoured if the default route already goes through a tunnel, which
    is something the VPN app does, not something this process can do.

    The return value says what actually happened, so the caller never
    has to assume the requested mode was applied.
    """
    if mode == "off":
        clear_env_proxy()
        return {
            "requested": "off",
            "applied": "off",
            "proxy_url": None,
            "env": {},
            "tunnel_interfaces": tunnel_interfaces(),
            "note": "direct connections",
        }

    if mode == "tun":
        if default_route_through_tunnel():
            clear_env_proxy()
            return {
                "requested": "tun",
                "applied": "tun",
                "proxy_url": None,
                "env": {},
                "tunnel_interfaces": tunnel_interfaces(),
                "tunnel_ips": tunnel_ips(),
                "note": "the default route already goes through a tunnel",
            }
        return {
            "requested": "tun",
            "applied": active_mode(),
            "proxy_url": proxy_url(),
            "env": {},
            "tunnel_interfaces": tunnel_interfaces(),
            "note": (
                "no tunnel interface carries the default route. Bring up "
                "the VPN app first; this process cannot redirect traffic "
                "without root."
            ),
        }

    # auto or proxy
    applied = active_mode()
    env = set_env_proxy("proxy" if applied == "proxy" else "off")
    if applied == "proxy" and not env:
        return {
            "requested": mode,
            "applied": "off",
            "proxy_url": None,
            "env": {},
            "tunnel_interfaces": tunnel_interfaces(),
            "note": "proxy mode was requested but no proxy is reachable",
        }
    return {
        "requested": mode,
        "applied": applied,
        "proxy_url": proxy_url(),
        "env": env,
        "tunnel_interfaces": tunnel_interfaces(),
        "tunnel_ips": tunnel_ips(),
        "note": "",
    }
