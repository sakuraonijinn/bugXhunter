"""Crypto module for drop chain."""

import os
import struct
import hashlib
import hmac
from typing import Optional


def _keystream(psk: bytes, nonce: bytes, length: int) -> bytes:
    """Generate keystream using SHA256 counter mode."""
    out = bytearray()
    counter = 0
    while len(out) < length:
        block = hashlib.sha256(psk + nonce + struct.pack(">I", counter)).digest()
        out.extend(block)
        counter += 1
    return bytes(out[:length])


def encrypt(plaintext: bytes, psk: bytes, nonce: bytes = None) -> bytes:
    if not psk:
        raise ValueError("psk must not be empty")
    if nonce is None:
        nonce = os.urandom(8)
    if len(nonce) != 8:
        raise ValueError("nonce must be 8 bytes")
    
    ks = _keystream(psk, nonce, len(plaintext))
    ct = bytes(p ^ k for p, k in zip(plaintext, ks))
    
    mac = hmac.new(psk, nonce + ct, hashlib.sha256).digest()[:8]
    return nonce + ct + mac


def decrypt(blob: bytes, psk: bytes) -> bytes:
    if not psk:
        raise ValueError("psk must not be empty")
    if len(blob) < 16:  # 8 nonce + 8 mac minimum
        raise ValueError("ciphertext too short")
    
    nonce = blob[:8]
    mac = blob[-8:]
    ct = blob[8:-8]
    
    expected = hmac.new(psk, nonce + ct, hashlib.sha256).digest()[:8]
    if not hmac.compare_digest(mac, expected):
        raise ValueError("MAC mismatch")
    
    ks = _keystream(psk, nonce, len(ct))
    return bytes(c ^ k for c, k in zip(ct, ks))
