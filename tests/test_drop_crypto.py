import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from bugxhunter.drop.crypto import encrypt, decrypt


def test_roundtrip():
    psk = b"shared-secret-key"
    pt = b"top secret payload"
    blob = encrypt(pt, psk)
    assert decrypt(blob, psk) == pt


def test_wrong_key_fails():
    blob = encrypt(b"hi", b"key1")
    try:
        decrypt(blob, b"key2")
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_tamper_fails():
    blob = bytearray(encrypt(b"hi", b"key"))
    blob[-1] ^= 0xFF
    try:
        decrypt(bytes(blob), b"key")
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_nonce_randomness():
    a = encrypt(b"hi", b"key")
    b = encrypt(b"hi", b"key")
    assert a != b  # random nonce
    assert decrypt(a, b"key") == b"hi"


if __name__ == "__main__":
    test_roundtrip()
    print("✓ test_roundtrip passed")
    test_wrong_key_fails()
    print("✓ test_wrong_key_fails passed")
    test_tamper_fails()
    print("✓ test_tamper_fails passed")
    test_nonce_randomness()
    print("✓ test_nonce_randomness passed")
    print("\nAll crypto tests passed!")
