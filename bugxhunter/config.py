"""bugXhunter server configuration.

Loads from config.json if present, else falls back to defaults. The
config file is meant to live next to the server on the host machine
(Termux, Pi, VPS, NixOS VM) and is world-readable-safe because secrets
live in environment variables, not in this file.
"""

import json
import os
from dataclasses import dataclass, field
from typing import List, Dict, Any


DEFAULT_CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")


@dataclass
class Config:
    # ---- server ----
    host: str = "0.0.0.0"
    port: int = 7080
    auth_token: str = ""          # from env AUTH_TOKEN if not set here
    log_level: str = "info"

    # ---- termux ----
    termux_enabled: bool = True
    termux_api_path: str = ""     # auto-detected if empty

    # ---- vpn ----
    vpn_enabled: bool = False
    vpn_mode: str = "tun"         # tun | proxy | off
    vpn_tunnel_if: str = ""       # auto-detected
    vpn_route_all: bool = True    # route all internet through VPN
    vpn_dns: List[str] = field(default_factory=lambda: ["1.1.1.1", "8.8.8.8"])

    # ---- frida ----
    frida_enabled: bool = True
    frida_port: int = 27042
    frida_web_ui: bool = True

    # ---- scanners ----
    scanner_threads: int = 4
    scanner_timeout_ms: int = 8000
    scanner_user_agent: str = (
        "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"
    )

    # ---- enrolled targets ----
    targets: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    # ---- rate limiting ----
    rate_limit_per_minute: int = 60

    # ---- logging ----
    log_file: str = ""            # empty = stderr


def _load_json(path: str) -> Dict[str, Any]:
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def load(path: str = DEFAULT_CONFIG_PATH) -> Config:
    raw = _load_json(path)
    cfg = Config()

    # scalar overrides
    for k in (
        "host", "port", "log_level",
        "termux_api_path",
        "vpn_mode", "vpn_tunnel_if",
        "frida_port",
        "scanner_user_agent",
        "log_file",
    ):
        if k in raw:
            setattr(cfg, k, raw[k])

    # bool overrides
    for k in (
        "termux_enabled", "vpn_enabled", "vpn_route_all",
        "frida_enabled", "frida_web_ui",
    ):
        if k in raw:
            setattr(cfg, k, bool(raw[k]))

    # int overrides
    for k in (
        "scanner_threads", "scanner_timeout_ms",
        "rate_limit_per_minute",
    ):
        if k in raw:
            try:
                setattr(cfg, k, int(raw[k]))
            except Exception:
                pass

    # list overrides
    if "vpn_dns" in raw and isinstance(raw["vpn_dns"], list):
        cfg.vpn_dns = list(raw["vpn_dns"])

    # targets
    if "targets" in raw and isinstance(raw["targets"], dict):
        cfg.targets = raw["targets"]

    # auth_token from env wins over file
    env_token = os.environ.get("AUTH_TOKEN", "")
    if env_token:
        cfg.auth_token = env_token
    elif "auth_token" in raw:
        cfg.auth_token = str(raw["auth_token"])

    return cfg


# Module-level singleton, loaded at import time.
config: Config = load()
