"""Framing layer: sync, header, payload, CRC, postamble.

All functions are pure and operate on bytes / lists of ints, so they are
straightforward to unit-test without hardware.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional

# Sync pattern: alternating long/short pulse durations (in ms) for clock recovery.
PREAMBLE = [3, 1, 3, 1, 3, 1]
POSTAMBLE = [1, 1, 1]

VERSION = 1
MAX_PAYLOAD_BYTES = 64  # a few hundred bits


def crc8(data: bytes, poly: int = 0x07, init: int = 0x00) -> int:
    crc = init
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 0x80:
                crc = ((crc << 1) ^ poly) & 0xFF
            else:
                crc = (crc << 1) & 0xFF
    return crc


def crc16(data: bytes, poly: int = 0x8005, init: int = 0x0000) -> int:
    crc = init
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ poly) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc


@dataclass
class Frame:
    version: int
    drop_id: Optional[int]  # None means "no tag"
    payload: bytes
    crc: int = 0
    crc_bits: int = 8

    def __post_init__(self):
        if self.version < 0 or self.version > 255:
            raise ValueError("version must fit in one byte")
        if self.drop_id is not None and not (0 <= self.drop_id <= 0xFFFF):
            raise ValueError("drop_id must fit in two bytes or be None")
        if len(self.payload) > MAX_PAYLOAD_BYTES:
            raise ValueError("payload too large")
        if self.crc_bits not in (8, 16):
            raise ValueError("crc_bits must be 8 or 16")


def _header_bytes(frame: Frame) -> bytes:
    drop_id = 0 if frame.drop_id is None else frame.drop_id
    tag_flag = 0 if frame.drop_id is None else 1
    return struct.pack(">BBH", frame.version, tag_flag, drop_id) + struct.pack(">B", len(frame.payload))


def encode_frame(frame: Frame) -> bytes:
    """Encode a frame into a byte stream: header + payload + CRC."""
    header = _header_bytes(frame)
    crc_input = header + frame.payload
    if frame.crc_bits == 16:
        crc = crc16(crc_input)
        crc_bytes = struct.pack(">H", crc)
    else:
        crc = crc8(crc_input)
        crc_bytes = struct.pack(">B", crc)
    frame.crc = crc
    return header + frame.payload + crc_bytes


def decode_frame(data: bytes, crc_bits: int = 8) -> Frame:
    """Decode a frame from a byte stream. Raises ValueError on bad CRC / truncation."""
    if len(data) < 5:
        raise ValueError("frame too short")
    version, tag_flag, drop_id = struct.unpack(">BBH", data[:4])
    (plen,) = struct.unpack(">B", data[4:5])
    if len(data) < 5 + plen + (2 if crc_bits == 16 else 1):
        raise ValueError("truncated frame")
    payload = data[5:5 + plen]
    off = 5 + plen
    if crc_bits == 16:
        (crc,) = struct.unpack(">H", data[off:off + 2])
        off += 2
    else:
        (crc,) = struct.unpack(">B", data[off:off + 1])
        off += 1
    crc_input = data[:5 + plen]
    expected = crc16(crc_input) if crc_bits == 16 else crc8(crc_input)
    if expected != crc:
        raise ValueError(f"CRC mismatch: got {crc}, expected {expected}")
    did = drop_id if tag_flag else None
    return Frame(version=version, drop_id=did, payload=payload, crc=crc, crc_bits=crc_bits)


def frame_to_pulses(frame_bytes: bytes, symbol_ms: float = 2.0) -> list[float]:
    """Convert encoded frame bytes into OOK pulse durations (ms).

    Each byte becomes 8 symbols; a '1' bit is a pulse of symbol_ms, a '0'
    bit is silence (0 ms). Preamble/postamble are prepended/appended.
    """
    durations: list[float] = list(PREAMBLE)
    for b in frame_bytes:
        for i in range(7, -1, -1):
            durations.append(symbol_ms if (b >> i) & 1 else 0.0)
    durations.extend(POSTAMBLE)
    return durations


def pulses_to_bytes(pulses: list[float], symbol_ms: float = 2.0,
                    threshold: float = 0.5) -> bytes:
    """Demodulate OOK pulse durations back into bytes (best-effort)."""
    # Strip preamble/postamble by length.
    body = pulses[len(PREAMBLE):]
    if len(body) >= len(POSTAMBLE):
        body = body[:-len(POSTAMBLE)] if len(POSTAMBLE) else body
    out = bytearray()
    i = 0
    while i + 8 <= len(body):
        byte = 0
        for j in range(8):
            if body[i + j] >= symbol_ms * threshold:
                byte = (byte << 1) | 1
            else:
                byte = byte << 1
        out.append(byte)
        i += 8
    return bytes(out)
