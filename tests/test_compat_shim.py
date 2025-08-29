# tests/test_compat_shim.py
import os, secrets
os.environ["CRYPTO_BACKEND"] = "noble"

from modules.crypto_shim import (
    encrypt_aes256gcm, decrypt_aes256gcm,
    encrypt_chacha20poly1305, decrypt_chacha20poly1305,
    encrypt_xchacha20poly1305, decrypt_xchacha20poly1305,
    derive_key_argon2id, ct_equal
)

def test_shim_parity():
    key = secrets.token_bytes(32)
    aad = b"hdr"
    msg = b"ping"

    n1 = secrets.token_bytes(12)
    ct1 = encrypt_aes256gcm(msg, key, n1, aad)
    assert decrypt_aes256gcm(ct1, key, n1, aad) == msg

    n2 = secrets.token_bytes(12)
    ct2 = encrypt_chacha20poly1305(msg, key, n2, aad)
    assert decrypt_chacha20poly1305(ct2, key, n2, aad) == msg

    n3 = secrets.token_bytes(24)
    ct3 = encrypt_xchacha20poly1305(msg, key, n3, aad)
    assert decrypt_xchacha20poly1305(ct3, key, n3, aad) == msg

    salt = secrets.token_bytes(16)
    dk = derive_key_argon2id("password", salt, time_cost=2, memory_cost=65536, parallelism=1, key_length=32)
    assert len(dk) == 32 and not ct_equal(dk, b"\x00"*32)
