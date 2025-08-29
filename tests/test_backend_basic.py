# File: tests/test_backend_basic.py
import os, secrets
os.environ["CRYPTO_BACKEND"] = "noble"

from modules import crypto_backend as cb

def test_round_trips_and_primitives():
    key = secrets.token_bytes(32)
    aad = b"header"
    msg = b"hello world"

    # AES-GCM (96-bit nonce)
    n1 = secrets.token_bytes(12)
    ct = cb.aes_gcm_encrypt(key, n1, msg, aad)
    assert cb.aes_gcm_decrypt(key, n1, ct, aad) == msg

    # ChaCha20-Poly1305 (96-bit nonce)
    n2 = secrets.token_bytes(12)
    ct2 = cb.chacha20poly1305_encrypt(key, n2, msg, aad)
    assert cb.chacha20poly1305_decrypt(key, n2, ct2, aad) == msg

    # XChaCha20-Poly1305 (192-bit nonce)
    n3 = secrets.token_bytes(24)
    ct3 = cb.xchacha20poly1305_encrypt(key, n3, msg, aad)
    assert cb.xchacha20poly1305_decrypt(key, n3, ct3, aad) == msg

    # Hash / HMAC / HKDF lengths
    h = cb.sha3_256(b"data");            assert len(h) == 32
    mac = cb.hmac_sha256(key, b"data");  assert len(mac) == 32
    okm = cb.hkdf_sha256(key, secrets.token_bytes(16), b"context", 42)
    assert len(okm) == 42

    # Constant-time compare
    assert cb.ct_equal(mac, mac)
    assert not cb.ct_equal(mac, b"\x00" * len(mac))
