"""Receiver layer: magnetometer sampling + demodulation + decryption + logging."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from .driver import Magnetometer
from .framing import decode_frame, pulses_to_bytes
from .crypto import decrypt

log = logging.getLogger("drop.receiver")


@dataclass
class ReceivedFrame:
    raw_bytes: bytes
    frame: object  # framing.Frame
    plaintext: Optional[bytes] = None
    error: Optional[str] = None


class Receiver:
    def __init__(self, magnetometer: Magnetometer, psk: bytes,
                 crc_bits: int = 8, symbol_ms: float = 2.0):
        self.magnetometer = magnetometer
        self.psk = psk
        self.crc_bits = crc_bits
        self.symbol_ms = symbol_ms
        self.received: List[ReceivedFrame] = []
        self.on_receive: Optional[Callable[[ReceivedFrame], None]] = None

    def sample(self, n: int) -> List[float]:
        return [self.magnetometer.sample() for _ in range(n)]

    def demodulate(self, samples: List[float], threshold: float = 0.5) -> bytes:
        # Convert samples to OOK pulse durations by thresholding.
        pulses = [s if s >= threshold else 0.0 for s in samples]
        return pulses_to_bytes(pulses, symbol_ms=self.symbol_ms, threshold=threshold)

    def process_bytes(self, data: bytes) -> ReceivedFrame:
        try:
            frame = decode_frame(data, crc_bits=self.crc_bits)
        except Exception as e:
            rf = ReceivedFrame(raw_bytes=data, frame=None, error=str(e))
            self.received.append(rf)
            log.warning("decode failed: %s", e)
            if self.on_receive:
                self.on_receive(rf)
            return rf
        # Decrypt payload.
        plaintext = None
        err = None
        try:
            plaintext = decrypt(frame.payload, self.psk)
        except Exception as e:
            err = str(e)
            log.warning("decrypt failed: %s", e)
        rf = ReceivedFrame(raw_bytes=data, frame=frame, plaintext=plaintext, error=err)
        self.received.append(rf)
        log.info("received frame v=%s id=%s", frame.version, frame.drop_id)
        if self.on_receive:
            self.on_receive(rf)
        return rf

    def run_once(self, n_samples: int = 256) -> ReceivedFrame:
        samples = self.sample(n_samples)
        data = self.demodulate(samples)
        return self.process_bytes(data)

    def close(self) -> None:
        self.magnetometer.close()
