"""CLI + frame emitter: transmit an ELF over ultrasonic FSK audio."""

import argparse
import os
import struct
import subprocess
import time


def transmit_elf(elf_path: str, psk: bytes, mark_freq: int = 18500,
                 space_freq: int = 19500, symbol_ms: float = 10.0) -> None:
    with open(elf_path, "rb") as f:
        data = f.read()

    # Split into ≤64-byte chunks
    MAX_PAYLOAD = 64
    seq = 0
    offset = 0
    
    while offset < len(data):
        chunk = data[offset:offset + MAX_PAYLOAD]
        frame = chunk  # In real implementation, this would be a Frame object
        
        # Build frame (version=1, drop_id=seq, payload=chunk, crc=16)
        frame_bytes = bytearray()
        # Header: version (1 byte), drop_id (2 bytes), payload length (1 byte), crc_bits (1 byte)
        frame_bytes.append(1)  # version
        frame_bytes.append(seq >> 8)  # drop_id high byte
        frame_bytes.append(seq & 0xFF)  # drop_id low byte
        frame_bytes.append(len(chunk))  # payload length
        frame_bytes.append(16)  # crc_bits
        
        # Add payload
        frame_bytes.extend(chunk)
        
        # Add CRC16 (big endian)
        crc = 0
        for b in frame_bytes[:-2]:  # exclude last 2 bytes (crc)
            crc = ((crc << 8) & 0xFFFF) ^ (b & 0xFF)
        for b in frame_bytes[-2:]:  # include CRC bytes in calculation
            crc = ((crc << 8) & 0xFFFF) ^ b
        crc_bytes = struct.pack('>H', crc)
        frame_bytes.extend(crc_bytes)
        
        # Convert to pulses (simplified - in real implementation, this would use frame_to_pulses)
        pulses = []
        for byte in frame_bytes:
            for i in range(7, -1, -1):
                if byte & (1 << i):
                    pulses.append(symbol_ms)  # '1' bit = pulse
                else:
                    pulses.append(0.0)  # '0' bit = silence
        # Add preamble and postamble (simplified)
        pulses.extend([3, 1, 3, 1, 3, 1])  # preamble
        pulses.extend([1, 1, 1])  # postamble
        
        # Emit pulses
        for pulse in pulses:
            if pulse > 0:
                # Simulate termux-media-player play
                subprocess.run(["termux-media-player", "play", "/dev/null"], 
                             check=False, capture_output=True)
            time.sleep(pulse / 1000.0)
            
        # Magnetic sync pulse between frames
        subprocess.run(["termux-vibrator", "vibrate", "-t", "10"], 
                      check=False, capture_output=True)
        
        seq += 1
        offset += MAX_PAYLOAD

    # Final idle
    subprocess.run(["termux-media-player", "stop"], check=False, capture_output=True)


def main():
    parser = argparse.ArgumentParser(description="Transmit ELF over audio drop")
    parser.add_argument("--elf", required=True)
    parser.add_argument("--psk", required=True, help="hex-encoded PSK")
    parser.add_argument("--mark", type=int, default=18500)
    parser.add_argument("--space", type=int, default=19500)
    parser.add_argument("--symbol-ms", type=float, default=10.0)
    args = parser.parse_args()

    psk = bytes.fromhex(args.psk)
    transmit_elf(args.elf, psk, mark_freq=args.mark, space_freq=args.space, symbol_ms=args.symbol_ms)


if __name__ == "__main__":
    main()
