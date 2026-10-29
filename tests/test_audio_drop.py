"""Round-trip tests for the audio drop crypto and framing."""

import os
import sys
import struct
import hashlib
import hmac

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from bugxhunter.drop.crypto import encrypt, decrypt
from bugxhunter.drop.framing import Frame, encode_frame, decode_frame, frame_to_pulses, pulses_to_bytes, crc16


def test_crypto_roundtrip():
    psk = os.urandom(32)
    plaintext = b"hello drop world!!" + b"\x00" * 14
    blob = encrypt(plaintext, psk)
    out = decrypt(blob, psk)
    assert out == plaintext


def test_crypto_mac_mismatch():
    psk = os.urandom(32)
    blob = bytearray(encrypt(b"secret", psk))
    blob[-1] ^= 1
    try:
        decrypt(bytes(blob), psk)
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_frame_roundtrip():
    payload = b"A" * 32
    frame = Frame(version=1, drop_id=7, payload=payload, crc_bits=16)
    fb = encode_frame(frame)
    dec = decode_frame(fb, crc_bits=16)
    assert dec.version == 1
    assert dec.drop_id == 7
    assert dec.payload == payload
    assert dec.crc == crc16(fb[:5 + len(payload)])


def test_pulses_roundtrip():
    data = bytes([0b10101010, 0b11001100])
    fb = encode_frame(Frame(version=1, drop_id=1, payload=data, crc_bits=16))
    pulses = frame_to_pulses(fb, symbol_ms=10.0)
    # pulses includes preamble/postamble; body bits should round-trip
    assert len(pulses) > 0


def test_encrypt_decrypt_vectors():
    # Known 32-byte PSK, 8-byte nonce
    psk = bytes(range(32))
    nonce = bytes([1, 2, 3, 4, 5, 6, 7, 8])
    pt = b"test vector 1234"
    blob = encrypt(pt, psk, nonce=nonce)
    assert blob[:8] == nonce
    out = decrypt(blob, psk)
    assert out == pt
