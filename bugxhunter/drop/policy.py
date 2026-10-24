"""Policy layer: rate limits, proximity triggers, kill-switch, self-wipe.

Keeps operational safety checks out of the protocol code.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, Optional


class PolicyViolation(Exception):
    pass


@dataclass
class Policy:
    max_transmits_per_hour: int = 4
    proximity_threshold: float = 1.0  # min field delta to consider "nearby"
    kill_switch: bool = False
    self_wipe_armed: bool = False
    _transmit_times: list[float] = field(default_factory=list, repr=False)
    _wiped: bool = field(default=False, repr=False)
    on_wipe: Optional[Callable[[], None]] = None

    def check_proximity(self, field_delta: float) -> bool:
        if self.kill_switch:
            raise PolicyViolation("kill switch engaged")
        return field_delta >= self.proximity_threshold

    def allow_transmit(self, now: Optional[float] = None) -> bool:
        if self.kill_switch:
            raise PolicyViolation("kill switch engaged")
        if self._wiped:
            raise PolicyViolation("device wiped")
        now = time.time() if now is None else now
        window = now - 3600.0
        self._transmit_times = [t for t in self._transmit_times if t > window]
        if len(self._transmit_times) >= self.max_transmits_per_hour:
            return False
        self._transmit_times.append(now)
        return True

    def engage_kill_switch(self) -> None:
        self.kill_switch = True

    def disarm_kill_switch(self) -> None:
        self.kill_switch = False

    def tamper_detected(self) -> None:
        """Trigger self-wipe on tamper."""
        self.self_wipe_armed = True
        self._wiped = True
        if self.on_wipe is not None:
            self.on_wipe()

    @property
    def wiped(self) -> bool:
        return self._wiped

    def reset(self) -> None:
        self._transmit_times.clear()
        self._wiped = False
        self.self_wipe_armed = False
        self.kill_switch = False
