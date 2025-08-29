# src/modules/crypto_backend.py
# Backend switch via env var: CRYPTO_BACKEND=noble|legacy
import os

BACKEND = os.environ.get("CRYPTO_BACKEND", "noble").lower()

if BACKEND == "noble":
    from modules.noble_bridge import NobleBridge as _B
    _BRIDGE = _B(js_dir="bridge")
    # Expose a small, stable surface for the app:
    aes_gcm_encrypt = _BRIDGE.aes_gcm_encrypt
    aes_gcm_decrypt = _BRIDGE.aes_gcm_decrypt
    chacha20poly1305_encrypt = _BRIDGE.chacha20poly1305_encrypt
    chacha20poly1305_decrypt = _BRIDGE.chacha20poly1305_decrypt
    xchacha20poly1305_encrypt = _BRIDGE.xchacha20poly1305_encrypt
    xchacha20poly1305_decrypt = _BRIDGE.xchacha20poly1305_decrypt
    hkdf_sha256 = _BRIDGE.hkdf_sha256
    hmac_sha256 = _BRIDGE.hmac_sha256
    sha3_256 = _BRIDGE.sha3_256
    argon2id = _BRIDGE.argon2id
    ct_equal = _BRIDGE.ct_equal
else:
    # TODO: wire your legacy implementations here for rollback
    def _todo(*_a, **_kw): raise NotImplementedError("Legacy backend not wired")
    aes_gcm_encrypt = aes_gcm_decrypt = _todo
    chacha20poly1305_encrypt = chacha20poly1305_decrypt = _todo
    xchacha20poly1305_encrypt = xchacha20poly1305_decrypt = _todo
    hkdf_sha256 = hmac_sha256 = sha3_256 = argon2id = ct_equal = _todo
