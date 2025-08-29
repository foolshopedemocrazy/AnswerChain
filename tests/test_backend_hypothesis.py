# File: tests/test_backend_hypothesis.py
import os
os.environ["CRYPTO_BACKEND"] = "noble"

from modules import crypto_backend as cb
from hypothesis import given, settings, strategies as st

# Fixed-size keys/nonces; variable AAD/msg (kept small for speed)
key32   = st.binary(min_size=32, max_size=32)
nonce12 = st.binary(min_size=12, max_size=12)
nonce24 = st.binary(min_size=24, max_size=24)
aad     = st.binary(min_size=0,  max_size=64)
msg     = st.binary(min_size=0,  max_size=1024)

@settings(max_examples=12, deadline=None)
@given(key32, nonce12, aad, msg)
def test_aes_gcm_roundtrip(key, n, a, m):
    ct = cb.aes_gcm_encrypt(key, n, m, a)
    assert cb.aes_gcm_decrypt(key, n, ct, a) == m

@settings(max_examples=12, deadline=None)
@given(key32, nonce12, aad, msg)
def test_chacha20poly1305_roundtrip(key, n, a, m):
    ct = cb.chacha20poly1305_encrypt(key, n, m, a)
    assert cb.chacha20poly1305_decrypt(key, n, ct, a) == m

@settings(max_examples=12, deadline=None)
@given(key32, nonce24, aad, msg)
def test_xchacha20poly1305_roundtrip(key, n, a, m):
    ct = cb.xchacha20poly1305_encrypt(key, n, m, a)
    assert cb.xchacha20poly1305_decrypt(key, n, ct, a) == m

@settings(max_examples=6, deadline=None)
@given(key32, nonce12, aad, msg)
def test_tamper_detects(key, n, a, m):
    ct = cb.aes_gcm_encrypt(key, n, m, a)
    tampered = ct[:-1] + bytes([ct[-1] ^ 0x01]) if len(ct) else ct + b"\x01"
    failed = False
    try:
        _ = cb.aes_gcm_decrypt(key, n, tampered, a)
    except Exception:
        failed = True
    assert failed, "Tampering must be detected (decrypt should fail)"
