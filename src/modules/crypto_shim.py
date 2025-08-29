# File: src/modules/crypto_shim.py
# Purpose: Test-friendly shim for Argon2id derivation, leaving production defaults intact.
#          When SECQ_ARGON2_TEST=1 and default-like parameters are requested, we lighten them.

from typing import Union
import os as _os
from modules.crypto_backend import argon2id as _argon2id  # delegate to backend/bridge

BytesLike = Union[bytes, bytearray]
_ARGON2_TEST = _os.environ.get("SECQ_ARGON2_TEST", "0") == "1"

def derive_key_argon2id(
    password: Union[str, BytesLike],
    salt: BytesLike,
    time_cost: int = 2,
    memory_cost: int = 65536,
    parallelism: int = 1,
    key_length: int = 32,
) -> bytes:
    """
    Derive a key with Argon2id. In test mode (SECQ_ARGON2_TEST=1), if the caller
    requests the default-like (2, 65536, 1), automatically downshift to (1, 8192, 1)
    to speed up CI/dev while keeping production parameters unchanged.
    """
    pw_bytes = password.encode("utf-8") if isinstance(password, str) else bytes(password)
    if _ARGON2_TEST and (time_cost, memory_cost, parallelism) == (2, 65536, 1):
        time_cost, memory_cost, parallelism = (1, 8192, 1)
    return _argon2id(
        pw_bytes, bytes(salt),
        t=time_cost, m=memory_cost, p=parallelism,
        dkLen=key_length, version=19
    )
