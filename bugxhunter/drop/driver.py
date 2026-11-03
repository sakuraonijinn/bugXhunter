"""Driver layer: abstract coil / magnetometer access.

Hardware is hidden behind small interfaces so the protocol code never
depends on a specific transmitter (coil vs. vibrator motor) or sensor.
"""

from __future__ import annotations

import time
from typing import Iterable, Protocol


class CoilDriver(Protocol):
    """Transmitter capable of emitting a magnetic pulse."""

    def pulse(self, duration_ms: float) -> None:
        """Emit a single pulse of the given duration."""

    def idle(self) -> None:
        """Return the transmitter to idle (no field)."""

    def close(self) -> None:
        """Release hardware resources."""


class Magnetometer(Protocol):
    """Sensor capable of sampling the ambient magnetic field."""

    def sample(self) -> float:
        """Return one scalar field-strength reading (arbitrary units)."""

    def close(self) -> None:
        """Release hardware resources."""


class VibratorDriver:
    """CoilDriver backed by an Android vibrator motor via DropShim.

    Delegates pulse/idle to an AndroidCoil instance, which talks to
    DropShim.kt over a localhost socket. Falls back to in-memory logging
    when no shim is reachable (useful for tests / dry runs).
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 8765):
        self._coil = None
        try:
            from .android_driver import AndroidCoil
            self._coil = AndroidCoil(host, port)
        except Exception:
            pass
        self.pulses: list[float] = []
        self.idle_calls = 0

    def pulse(self, duration_ms: float) -> None:
        if duration_ms < 0:
            raise ValueError("duration_ms must be >= 0")
        self.pulses.append(duration_ms)
        if self._coil is not None:
            self._coil.pulse(duration_ms)

    def idle(self) -> None:
        self.idle_calls += 1
        if self._coil is not None:
            self._coil.idle()

    def close(self) -> None:
        self.idle_calls += 1
        if self._coil is not None:
            self._coil.close()
            self._coil = None


class NullMagnetometer:
    """Magnetometer that always reads zero (useful for tests / dry runs)."""

    def __init__(self, value: float = 0.0):
        self.value = value
        self.samples: list[float] = []

    def sample(self) -> float:
        self.samples.append(self.value)
        return self.value

    def close(self) -> None:
        pass


class SimulatedCoil:
    """In-memory CoilDriver for tests and simulation."""

    def __init__(self):
        self.pulses: list[float] = []

    def pulse(self, duration_ms: float) -> None:
        if duration_ms < 0:
            raise ValueError("duration_ms must be >= 0")
        self.pulses.append(duration_ms)

    def idle(self) -> None:
        pass

    def close(self) -> None:
        pass


def sleep_ms(ms: float) -> None:
    """Thin wrapper around time.sleep for symbol timing."""
    if ms > 0:
        time.sleep(ms / 1000.0)


def emit_pulses(driver: CoilDriver, durations: Iterable[float]) -> None:
    """Emit a sequence of pulses with the given durations."""
    for d in durations:
        driver.pulse(d)
    driver.idle()
