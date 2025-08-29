# src/modules/rng.py
"""
Centralized CSPRNG and constant-time comparison for AnswerChain.

Policy:
- All randomness must originate from Python's OS-backed CSPRNG only.
- Do not obtain randomness via the Node bridge (noble) or any other source.
- Import from this module wherever random bytes/tokens are needed.

References:
- Python secrets and os.urandom are suitable for cryptographic use.
"""

from __future__ import annotations

import hmac
import os
import secrets
from typing import Union

BytesLike = Union[bytes, bytearray, memoryview]

__all__ = [
    "random_bytes",
    "token_bytes",
    "token_hex",
    "token_urlsafe",
    "secure_compare",
]


def random_bytes(n: int) -> bytes:
    """
    Return n cryptographically secure random bytes from the OS CSPRNG.

    Raises:
        ValueError: if n is negative
        TypeError: if n is not an int
    """
    if not isinstance(n, int):
        raise TypeError("n must be int")
    if n < 0:
        raise ValueError("n must be non-negative")
    # os.urandom is explicitly intended for crypto-quality randomness.
    return os.urandom(n)


def token_bytes(n: int) -> bytes:
    """
    Return n random bytes suitable for secrets (via secrets.token_bytes).

    Raises:
        ValueError: if n is negative
        TypeError: if n is not an int
    """
    if not isinstance(n, int):
        raise TypeError("n must be int")
    if n < 0:
        raise ValueError("n must be non-negative")
    return secrets.token_bytes(n)


def token_hex(n: int) -> str:
    """
    Return a secure random text token with 2*n hex characters.
    """
    if not isinstance(n, int):
        raise TypeError("n must be int")
    if n < 0:
        raise ValueError("n must be non-negative")
    return secrets.token_hex(n)


def token_urlsafe(n: int) -> str:
    """
    Return a secure random URL-safe text token (base64url-like).
    """
    if not isinstance(n, int):
        raise TypeError("n must be int")
    if n < 0:
        raise ValueError("n must be non-negative")
    return secrets.token_urlsafe(n)


def secure_compare(a: BytesLike, b: BytesLike) -> bool:
    """
    Constant-time equality check using hmac.compare_digest.

    Both inputs must be bytes-like.
    """
    if not isinstance(a, (bytes, bytearray, memoryview)):
        raise TypeError("a must be bytes-like")
    if not isinstance(b, (bytes, bytearray, memoryview)):
        raise TypeError("b must be bytes-like")
    return hmac.compare_digest(a, b)
