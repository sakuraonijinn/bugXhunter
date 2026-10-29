"""AudioCoilDriver: emit FSK tones via speaker on Phone B (Termux available)."""

import math
import struct
import subprocess
import tempfile
import os
from bugxhunter.drop.driver import CoilDriver


class AudioCoilDriver(CoilDriver):
    """CoilDriver that emits mark/space tones through the speaker."""

    def __init__(self, mark_freq: int = 18500, space_freq: int = 19500,
                 sample_rate: int = 44100, amplitude: float = 0.8):
        super().__init__()
        self.mark_freq = mark_freq
        self.space_freq = space_freq
        self.sample_rate = sample_rate
        self.amplitude = amplitude
        self._playing = False

    def _tone(self, freq: float, duration_ms: float) -> bytes:
        n = int(self.sample_rate * duration_ms / 1000.0)
        pcm = bytearray()
        for i in range(n):
            t = i / self.sample_rate
            val = int(self.amplitude * 32767 * math.sin(2 * math.pi * freq * t))
            pcm += struct.pack("<h", val)
        return bytes(pcm)

    def pulse(self, duration_ms: float, bit: int = 1) -> None:
        freq = self.mark_freq if bit else self.space_freq
        if duration_ms <= 0:
            self.idle()
            return
        pcm = self._tone(freq, duration_ms)
        with tempfile.NamedTemporaryFile(suffix=".pcm", delete=False) as f:
            f.write(pcm)
            path = f.name
        try:
            subprocess.run(
                ["termux-media-player", "play", path],
                check=False, capture_output=True,
            )
        finally:
            os.unlink(path)
        self._playing = True

    def idle(self) -> None:
        subprocess.run(
            ["termux-media-player", "stop"],
            check=False, capture_output=True,
        )
        self._playing = False
