"""Physical-layer "drop" communication package.

Modular implementation of the magnetic-field pulse carrier stack described
in the drop design document:

* ``driver``   - abstract coil / magnetometer access
* ``framing``  - sync, header, payload, CRC, postamble (pure functions)
* ``crypto``   - pre-shared-key encryption for the payload
* ``policy``   - rate limits, proximity triggers, kill-switch, self-wipe
* ``receiver`` - magnetometer sampling + demodulation + decryption + logging

All modules are stdlib-only so they can run on a bare Python 3 target.
"""

from .driver import (
    CoilDriver,
    Magnetometer,
    VibratorDriver,
    NullMagnetometer,
    SimulatedCoil,
)
from .framing import Frame, encode_frame, decode_frame, crc8, crc16, frame_to_pulses, pulses_to_bytes
from .crypto import encrypt, decrypt
from .policy import Policy, PolicyViolation
from .receiver import Receiver, ReceivedFrame

__all__ = [
    "CoilDriver",
    "Magnetometer",
    "VibratorDriver",
    "NullMagnetometer",
    "SimulatedCoil",
    "Frame",
    "encode_frame",
    "decode_frame",
    "crc8",
    "crc16",
    "frame_to_pulses",
    "pulses_to_bytes",
    "encrypt",
    "decrypt",
    "Policy",
    "PolicyViolation",
    "Receiver",
    "ReceivedFrame",
]

__version__ = "0.1.0"
