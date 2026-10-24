"""Android hardware driver shim client.

Talks to DropShim.kt over a localhost socket so the pure-Python protocol
stack can drive a real phone's vibrator motor and magnetometer.
"""

from __future__ import annotations

import json
import socket
from typing import Optional

from .driver import CoilDriver, Magnetometer


class AndroidCoil:
    def __init__(self, host: str = "127.0.0.1", port: int = 8765):
        self.host = host
        self.port = port

    def _send(self, obj: dict) -> dict:
        with socket.create_connection((self.host, self.port), timeout=5) as s:
            s.sendall((json.dumps(obj) + "\n").encode())
            f = s.makefile()
            return json.loads(f.readline())

    def pulse(self, duration_ms: float) -> None:
        self._send({"cmd": "pulse", "ms": duration_ms})

    def idle(self) -> None:
        self._send({"cmd": "idle"})

    def close(self) -> None:
        pass


class AndroidMagnetometer:
    def __init__(self, host: str = "127.0.0.1", port: int = 8765):
        self.host = host
        self.port = port

    def _send(self, obj: dict) -> dict:
        with socket.create_connection((self.host, self.port), timeout=5) as s:
            s.sendall((json.dumps(obj) + "\n").encode())
            f = s.makefile()
            return json.loads(f.readline())

    def sample(self) -> float:
        return float(self._send({"cmd": "sample"})["value"])

    def close(self) -> None:
        pass


# Make them satisfy the protocols structurally.
_: CoilDriver = AndroidCoil()  # type: ignore
__: Magnetometer = AndroidMagnetometer()  # type: ignore
del _, __
EOF
echo done
