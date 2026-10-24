"""Crypto layer: encrypt payload with a pre-shared key.

Stdlib-only: derives a keystream from the PSK + nonce using SHA-256 in
counter mode, then XORs. Not a substitute for audited crypto, but keeps
plaintext secrets off the drop and is unit-testable.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct


def _keystream(psk: bytes, nonce: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        block = hashlib.sha256(psk + nonce + struct.pack(">I", counter)).digest()
        out.extend(block)
        counter += 1
    return bytes(out[:length])


def encrypt(plaintext: bytes, psk: bytes, nonce: bytes = None) -> bytes:
    """Return nonce (8 bytes) + ciphertext. PSK must be non-empty."""
    if not psk:
        raise ValueError("psk must not be empty")
    if nonce is None:
        nonce = os.urandom(8)
    if len(nonce) != 8:
        raise ValueError("nonce must be 8 bytes")
    ks = _keystream(psk, nonce, len(plaintext))
    ct = bytes(p ^ k for p, k in zip(plaintext, ks))
    # Append a short HMAC for integrity of the ciphertext.
    mac = hmac.new(psk, nonce + ct, hashlib.sha256).digest()[:8]
    return nonce + ct + mac


def decrypt(blob: bytes, psk: bytes) -> bytes:
    """Inverse of encrypt. Raises ValueError on bad MAC / truncation."""
    if not psk:
        raise ValueError("psk must not be empty")
    if len(blob) < 8 + 8:
        raise ValueError("ciphertext too short")
    nonce = blob[:8]
    mac = blob[-8:]
    ct = blob[8:-8]
    expected = hmac.new(psk, nonce + ct, hashlib.sha256).digest()[:8]
    if not hmac.compare_digest(mac, expected):
        raise ValueError("MAC mismatch")
    ks = _keystream(psk, nonce, len(ct))
    return bytes(c ^ k for c, k in zip(ct, ks))
