import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from bugxhunter.drop.framing import (
    Frame, encode_frame, decode_frame, crc8, crc16,
    frame_to_pulses, pulses_to_bytes, PREAMBLE, POSTAMBLE,
)


def test_crc8_deterministic():
    data = b"hello"
    assert crc8(data) == crc8(data)
    assert 0 <= crc8(data) <= 255


def test_crc16_deterministic():
    data = b"hello"
    assert crc16(data) == crc16(data)


def test_encode_decode_roundtrip():
    f = Frame(version=1, drop_id=42, payload=b"secret", crc_bits=8)
    enc = encode_frame(f)
    dec = decode_frame(enc, crc_bits=8)
    assert dec.version == 1
    assert dec.drop_id == 42
    assert dec.payload == b"secret"


def test_encode_decode_no_tag():
    f = Frame(version=1, drop_id=None, payload=b"hi", crc_bits=16)
    enc = encode_frame(f)
    dec = decode_frame(enc, crc_bits=16)
    assert dec.drop_id is None
    assert dec.payload == b"hi"


def test_bad_crc_raises():
    f = Frame(version=1, drop_id=1, payload=b"x", crc_bits=8)
    enc = bytearray(encode_frame(f))
    enc[-1] ^= 0xFF
    try:
        decode_frame(bytes(enc), crc_bits=8)
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_pulses_roundtrip():
    f = Frame(version=1, drop_id=7, payload=b"ab", crc_bits=8)
    enc = encode_frame(f)
    pulses = frame_to_pulses(enc)
    assert pulses[:len(PREAMBLE)] == PREAMBLE
    # pulses count should be multiple of 8 for body
    body = pulses[len(PREAMBLE):len(pulses)-len(POSTAMBLE)]
    assert len(body) % 8 == 0
    recovered = pulses_to_bytes(pulses)
    assert recovered == enc
