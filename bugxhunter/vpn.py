"""VPN / tunnel integration layer.

Routes the server's outbound internet traffic through a VPN tunnel when
one is available. Three modes:

  off    - no VPN, direct connections only
  proxy  - all outbound HTTP(S) goes through an upstream proxy (e.g. Tor)
  tun    - full TUN tunnel; every socket on the box is redirected

The TUN mode requires root or a VPN app with a tunnel interface. On
Termux this is typically provided by "Termux:VPN" or mullvad-vpn.
"""

import json
import os
import shutil
import subprocess
from typing import Any, Dict, List, Optional


def _run(args: List[str], timeout: int = 10) -> Optional[str]:
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        if p.returncode == 0:
            return p.stdout.strip()
        return None
    except Exception:
        return None


def tunnel_interfaces() -> List[str]:
    """List active tunnel interfaces (tun0, wg0, mullvad, etc)."""
    out = _run(["ip", "link", "show", "type", "tun"])
    if not out:
        out = _run(["ip", "link", "show"])
    if not out:
        return []
    ifaces = []
    for line in out.splitlines():
        line = line.strip()
        if line and "tun" in line.lower():
            # lines look like "2: tun0: <POINTOPOINT,UP> ..."
            parts = line.split(":")
            if len(parts) >= 2:
                ifaces.append(parts[1].strip())
    return ifaces


def mullvad_active() -> bool:
    return shutil.which("mullvad") is not None and \
           _run(["mullvad", "status"], timeout=5) == "Mullvad VPN is connected."


def openvpn_active() -> bool:
    return any("tun" in i for i in tunnel_interfaces())


def tor_active() -> bool:
    """Tor SOCKS5 proxy on 9050 is the standard Tor indicator."""
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect(("127.0.0.1", 9050))
        s.close()
        return True
    except Exception:
        return False


def active_mode() -> str:
    """Detect which VPN mode is currently active."""
    if mullvad_active():
        return "tun"
    if openvpn_active():
        return "tun"
    if tor_active():
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


def route_all_through_tunnel() -> bool:
    """Check whether the default route goes through the tunnel."""
    out = _run(["ip", "route", "show", "default"])
    if not out:
        return False
    return any(t in out for t in ("tun", "wg", "mullvad"))


def set_env_proxy(mode: str) -> Dict[str, str]:
    """Export proxy env vars so subprocesses inherit them."""
    env = {}
    if mode == "proxy":
        proxy = proxy_url()
        if proxy:
            env["ALL_PROXY"] = proxy
            env["all_proxy"] = proxy
            env["HTTP_PROXY"] = proxy
            env["http_proxy"] = proxy
    return env
