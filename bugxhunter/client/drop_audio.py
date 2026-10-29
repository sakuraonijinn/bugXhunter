"""CLI + frame emitter: transmit an ELF over ultrasonic FSK audio."""

import argparse
import os
import struct
import subprocess
import time

from bugxhunter.drop.audio_driver import AudioCoilDriver
from bugxhunter.drop.crypto import encrypt
from bugxhunter.drop.framing import Frame, encode_frame, frame_to_pulses, MAX_PAYLOAD_BYTES


def transmit_elf(elf_path: str, psk: bytes, mark_freq: int = 18500,
                 space_freq: int = 19500, symbol_ms: float = 10.0) -> None:
    with open(elf_path, "rb") as f:
        data = f.read()

    driver = AudioCoilDriver(mark_freq=mark_freq, space_freq=space_freq)

    seq = 0
    offset = 0
    while offset < len(data):
        chunk = data[offset:offset + MAX_PAYLOAD_BYTES]
        frame = Frame(version=1, drop_id=seq, payload=chunk, crc_bits=16)
        frame_bytes = encode_frame(frame)
        blob = encrypt(frame_bytes, psk)
        pulses = frame_to_pulses(blob, symbol_ms=symbol_ms)

        for p in pulses:
            if p > 0:
                driver.pulse(p, bit=1)
            else:
                driver.idle()
                time.sleep(symbol_ms / 1000.0)

        # magnetic sync pulse between frames
        subprocess.run(["termux-vibrator", "vibrate", "-t", "10"],
                       check=False, capture_output=True)
        seq += 1
        offset += MAX_PAYLOAD_BYTES

    driver.idle()


def main():
    parser = argparse.ArgumentParser(description="Transmit ELF over audio drop")
    parser.add_argument("--elf", required=True)
    parser.add_argument("--psk", required=True, help="hex-encoded PSK")
    parser.add_argument("--mark", type=int, default=18500)
    parser.add_argument("--space", type=int, default=19500)
    parser.add_argument("--symbol-ms", type=float, default=10.0)
    args = parser.parse_args()

    psk = bytes.fromhex(args.psk)
    transmit_elf(args.elf, psk, mark_freq=args.mark,
                 space_freq=args.space, symbol_ms=args.symbol_ms)


if __name__ == "__main__":
    main()
