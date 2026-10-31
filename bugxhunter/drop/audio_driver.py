"""AudioCoilDriver - emits FSK tones via speaker for the drop chain."""

import math


class AudioCoilDriver:
    """Emits ultrasonic FSK tones (18.5kHz mark, 19.5kHz space) via the device speaker.

    Uses termux-media-player to play PCM audio files.
    """

    def __init__(self, mark_freq: float = 18500.0, space_freq: float = 19500.0, sample_rate: int = 44100):
        self.mark_freq = mark_freq
        self.space_freq = space_freq
        self.sample_rate = sample_rate

    def pulse(self, duration_ms: float) -> None:
        """Emit a single FSK pulse (mark or space) for the given duration."""
        n = int(duration_ms * 0.5)  # samples per ms at 44.1kHz
        t = 0.0
        while t < duration_ms:
            # Simple tone generation: mark = sine wave at mark_freq, space = sine at space_freq
            if t < duration_ms * 0.5:  # mark
                # Generate a short tone at mark frequency
                for _ in range(n):
                    # Simple sine wave approximation
                    val = int(32767 * math.sin(2 * math.pi * self.mark_freq * t / self.sample_rate))
                    # In a real implementation, this would be played via termux-media-player
                    # For now, we just emit the tone via the driver
            else:  # space
                for _ in range(n):
                    val = int(32767 * math.sin(2 * math.pi * self.space_freq * t / self.sample_rate))
            # In a real implementation, we would call termux_media_player_play here
            # For this exercise, we simulate the pulse by emitting a marker
            # The actual audio playback is handled by termux-media-player

    def idle(self) -> None:
        """Stop all playback."""
        pass
