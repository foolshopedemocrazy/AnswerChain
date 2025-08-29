# File: tests/test_backend_argon2.py
import os, secrets, pytest
os.environ["CRYPTO_BACKEND"] = "noble"
from modules import crypto_backend as cb

def test_argon2_smoke_fast():
    # Very fast parameters for default runs (correctness only)
    salt = secrets.token_bytes(16)
    dk = cb.argon2id(b"password", salt, t=1, m=8192, p=1, dkLen=32, version=19)
    assert isinstance(dk, (bytes, bytearray)) and len(dk) == 32

@pytest.mark.slow
def test_argon2_realistic_profile():
    # More realistic but slower parameters; run only with -m slow
    salt = secrets.token_bytes(16)
    dk = cb.argon2id(b"password", salt, t=2, m=65536, p=1, dkLen=32, version=19)
    assert isinstance(dk, (bytes, bytearray)) and len(dk) == 32
