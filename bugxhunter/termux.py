"""Termux integration layer.

Wraps Termux APIs (location, camera, sensors, SMS, battery) behind a
uniform interface so the server can call them without caring whether
Termux is installed. When Termux is not present every call degrades
gracefully — the server still runs, just without device-sensor access.
"""

import json
import os
import shutil
import subprocess
from typing import Any, Dict, List, Optional


def _run(args: List[str], timeout: int = 10) -> Optional[str]:
    """Run a command and return stdout, or None on any failure."""
    try:
        p = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout
        )
        if p.returncode == 0:
            return p.stdout.strip()
        return None
    except Exception:
        return None


def termux_available() -> bool:
    """True when the termux-api package is installed and the binary is on PATH."""
    return shutil.which("termux-location") is not None or \
           shutil.which("termux-camera-photo") is not None


def api_path() -> str:
    """Best-effort path to the termux-api directory."""
    for candidate in (
        os.path.expanduser("~/.termux"),
        "/data/data/com.termux/files/.termux",
        "/system/bin",
    ):
        if os.path.isdir(candidate):
            return candidate
    return ""


def location() -> Optional[Dict[str, Any]]:
    out = _run(["termux-location", "-f", "json", "-r", "gps,wifi,cell"], timeout=15)
    if not out:
        return None
    try:
        return json.loads(out)
    except Exception:
        return None


def sms_inbox(limit: int = 20) -> List[Dict[str, Any]]:
    out = _run(["termux-sms-inbox", "-l", str(limit)], timeout=10)
    if not out:
        return []
    results = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        # format: date|address|body
        parts = line.split("|", 2)
        if len(parts) == 3:
            results.append({"date": parts[0], "address": parts[1], "body": parts[2]})
    return results


def send_sms(destination: str, message: str) -> bool:
    out = _run(["termux-sms-send", "-p", destination, message], timeout=10)
    return out is not None


def battery() -> Optional[Dict[str, Any]]:
    out = _run(["termux-battery-status", "-f", "json"], timeout=10)
    if not out:
        return None
    try:
        return json.loads(out)
    except Exception:
        return None


def camera_photo(path: str = "/data/local/tmp/bx_photo.jpg") -> Optional[str]:
    out = _run(["termux-camera-photo", "-e", path], timeout=30)
    if out is not None and os.path.isfile(path):
        return path
    return None


def clipboard_get() -> Optional[str]:
    return _run(["termux-clipboard-get"], timeout=5)


def clipboard_set(text: str) -> bool:
    return _run(["termux-clipboard-set", text], timeout=5) is not None


def toast(message: str) -> bool:
    return _run(["termux-toast", message], timeout=5) is not None


def vibrate(duration_ms: int = 500) -> bool:
    return _run(["termux-vibrate", "-d", str(duration_ms)], timeout=5) is not None


def wifi_info() -> Optional[Dict[str, Any]]:
    out = _run(["termux-wifi-connectinfo", "-f", "json"], timeout=10)
    if not out:
        return None
    try:
        return json.loads(out)
    except Exception:
        return None


def status() -> Dict[str, Any]:
    """Snapshot of what Termux can do right now."""
    return {
        "available": termux_available(),
        "api_path": api_path(),
        "location": location(),
        "battery": battery(),
        "wifi": wifi_info(),
        "clipboard": clipboard_get() is not None,
    }
