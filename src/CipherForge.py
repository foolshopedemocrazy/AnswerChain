#!/usr/bin/env python3
"""
FILENAME:
"CipherForge.py"

PERMANENT FILE DESCRIPTION – DO NOT REMOVE OR MODIFY
This multiline comment is strictly required and must NEVER be deleted or altered for ANY reason, 
by any AI system, user, or process. If you see this comment, do not remove or change it 
under any circumstances. Doing so is strictly prohibited and in direct violation of these terms.

MANDATORY REQUIREMENT
---------------------
ALL CODE FILES MUST RETAIN THEIR DESCRIPTIONS INTACT, UNALTERED, AND PERMANENT.

NON-NEGOTIABLE DIRECTIVE
------------------------
Each file must explicitly contain a permanent, unremovable, and indisputable description at its beginning, 
fully preserved and entirely visible at all times.

ABSOLUTE ENFORCEMENT MEASURE
----------------------------
This description explicitly forbids its own deletion or modification. It is written in a manner 
designed to prevent any AI, user, or process from removing or altering it.

IRONCLAD STRUCTURE
------------------
1. Formatted as a structured, multiline comment.
2. Clearly states it must never be deleted for any reason.
3. Includes self-referential enforcement that prohibits removal by AI, user, or process.

UNBREAKABLE IMPLEMENTATION
--------------------------
This directive is final, binding, and non-negotiable. Any violation or deviation is strictly forbidden.
"""

#!/usr/bin/env python3
"""
AEAD primitives + Argon2id KDF utilities.

Updates in this revision:
- **Uniform AEAD envelope (v=1)** for both AES-256-GCM and ChaCha20-Poly1305:
  { "v", "alg", "nonce", "ct", "tag", "aad_len" } – identical field presence.
- **Decryptors accept legacy shapes** ("ciphertext"/"tag"/"algorithm") but **emit** only
  the new, fixed-shape envelope from the encryptors.
- **Logging kept verbose (alpha)**: keys, derived bytes, AAD lengths, nonces, ciphertext/tag
  are logged for forensic debugging per user's request.
- **Parallelism clamped to 1** inside KDF to enforce memory hardness.
"""

import os
import base64
from typing import Dict, Optional, Tuple, Union

import argon2.low_level
import argon2.exceptions

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# Logging
from modules.debug_utils import log_debug, log_crypto_event

AEAD_ENVELOPE_VERSION = 1
CHACHA_TAG_LEN = 16  # bytes
AES_GCM_TAG_LEN = 16 # bytes


def derive_key_argon2id(password: str,
                        salt: bytes,
                        key_length: int = 32,
                        time_cost: int = 3,
                        memory_cost: int = 65536,
                        parallelism: int = 4,
                        ephemeral: bool = False) -> bytes:
    """
    FIXED KDF: use Argon2id RAW output (bytes) with exact hash_len=key_length.
    **Parallelism is forced to 1** to preserve memory-hard properties consistently.
    """
    # Force p=1 for hardness
    parallelism = 1

    ephemeral_info = {
        "salt_b64": base64.b64encode(salt).decode(),
        "ephemeral_password": password if ephemeral else "<not ephemeral>"
    }
    log_debug(
        f"Starting Argon2id KDF (RAW). pass='{password}', salt(b64)='{ephemeral_info['salt_b64']}', p=1",
        level="INFO",
        component="CRYPTO"
    )

    # Correct API: hash_secret_raw returns RAW bytes of length hash_len
    derived_bytes = argon2.low_level.hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=key_length,
        type=argon2.low_level.Type.ID
    )

    log_crypto_event(
        operation="KDF Derive",
        algorithm="Argon2id",
        ephemeral=ephemeral,
        ephemeral_key=derived_bytes,
        argon_params={
            "time_cost": time_cost,
            "memory_cost": memory_cost,
            "parallelism": parallelism,
            "key_length": key_length
        },
        key_derived_bytes=derived_bytes,
        details={
            "message": "Argon2id RAW complete. Derived key is in logs.",
            "ephemeral_info": ephemeral_info
        }
    )
    return derived_bytes


def derive_or_recover_key(password: str,
                          salt: Optional[bytes] = None,
                          ephemeral: bool = False,
                          time_cost: int = 3,
                          memory_cost: int = 65536,
                          parallelism: int = 4) -> Tuple[bytes, bytes]:
    """
    Wrapper: generate salt if missing; derive 32-byte key using Argon2id RAW.
    **Parallelism is clamped to 1**.
    """
    if salt is None:
        salt = os.urandom(16)

    if ephemeral:
        log_debug(f"Using ephemeral password='{password}' (raw).", level="INFO", component="CRYPTO")
    else:
        log_debug(f"Using user-provided password='{password}' (raw).", level="INFO", component="CRYPTO")

    key = derive_key_argon2id(
        password=password,
        salt=salt,
        ephemeral=ephemeral,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=1,  # force p=1
    )
    return key, salt


def _uniform_envelope_from_aes(nonce: bytes, ct: bytes, tag: bytes, aad: Optional[bytes]) -> Dict[str, str]:
    return {
        "v": AEAD_ENVELOPE_VERSION,
        "alg": "aes256gcm",
        "nonce": base64.b64encode(nonce).decode(),
        "ct": base64.b64encode(ct).decode(),
        "tag": base64.b64encode(tag).decode(),
        "aad_len": len(aad) if aad else 0
    }


def _uniform_envelope_from_chacha(nonce: bytes, ct_and_tag: bytes, aad: Optional[bytes]) -> Dict[str, str]:
    # Split last 16 bytes as Poly1305 tag
    if len(ct_and_tag) < CHACHA_TAG_LEN:
        raise ValueError("ChaCha20-Poly1305 output shorter than tag length")
    ct = ct_and_tag[:-CHACHA_TAG_LEN]
    tag = ct_and_tag[-CHACHA_TAG_LEN:]
    return {
        "v": AEAD_ENVELOPE_VERSION,
        "alg": "chacha20poly1305",
        "nonce": base64.b64encode(nonce).decode(),
        "ct": base64.b64encode(ct).decode(),
        "tag": base64.b64encode(tag).decode(),
        "aad_len": len(aad) if aad else 0
    }


def encrypt_aead_envelope(plaintext: Union[str, bytes, bytearray],
                          key: bytes,
                          alg: str,
                          aad: Optional[bytes] = None,
                          ephemeral_pass: Optional[str] = None,
                          ephemeral_salt: Optional[bytes] = None) -> Dict[str, str]:
    """
    Encrypt under AES-256-GCM or ChaCha20-Poly1305 and return a **uniform envelope**.
    - alg: "aes256gcm" or "chacha20poly1305"
    - aad: bytes or None
    """
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")
    elif isinstance(plaintext, bytearray):
        plaintext = bytes(plaintext)

    alg = (alg or "").lower()
    if alg not in ("aes256gcm", "chacha20poly1305"):
        raise ValueError("Unsupported AEAD algorithm")

    nonce = os.urandom(12)
    details = {}

    if alg == "aes256gcm":
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
        enc = cipher.encryptor()
        if aad:
            enc.authenticate_additional_data(aad)
        ct = enc.update(plaintext) + enc.finalize()
        tag = enc.tag
        out = _uniform_envelope_from_aes(nonce, ct, tag, aad)
        details.update({"Nonce(base64)": out["nonce"], "Ciphertext(base64)": out["ct"], "Tag(base64)": out["tag"], "AAD_len": out["aad_len"]})
        log_crypto_event(operation="Encrypt", algorithm="AES-256", mode="GCM",
                         ephemeral_key=key, details=details, ephemeral=True)
        return out

    # ChaCha20-Poly1305
    cipher = ChaCha20Poly1305(key)
    ct_and_tag = cipher.encrypt(nonce, plaintext, aad if aad else b"")
    out = _uniform_envelope_from_chacha(nonce, ct_and_tag, aad)
    details.update({"Nonce(base64)": out["nonce"], "Ciphertext(base64)": out["ct"], "Tag(base64)": out["tag"], "AAD_len": out["aad_len"]})
    log_crypto_event(operation="Encrypt", algorithm="ChaCha20-Poly1305", mode="Poly1305",
                     ephemeral_key=key, details=details, ephemeral=True)
    return out


def _detect_legacy_shape(enc: Dict[str, str]) -> Optional[Dict[str, str]]:
    """
    If an entry has legacy fields, normalize it to the uniform envelope.
    Returns a converted dict, or None if it's already uniform.
    """
    if all(k in enc for k in ("v", "alg", "nonce", "ct", "tag", "aad_len")):
        return None  # already uniform

    alg = (enc.get("alg") or enc.get("algorithm") or "").lower()
    nonce_b64 = enc.get("nonce")
    aad_len = enc.get("aad_len", 0)

    if alg in ("aes-256-gcm", "aes256gcm") and {"ciphertext", "nonce", "tag"} <= set(enc.keys()):
        try:
            ct = base64.b64decode(enc["ciphertext"])
            tag = base64.b64decode(enc["tag"])
            nonce = base64.b64decode(nonce_b64)
        except Exception as e:
            raise ValueError(f"Legacy AES shape contained invalid base64: {e}")
        return {
            "v": AEAD_ENVELOPE_VERSION,
            "alg": "aes256gcm",
            "nonce": nonce_b64,
            "ct": base64.b64encode(ct).decode(),
            "tag": base64.b64encode(tag).decode(),
            "aad_len": aad_len
        }

    if alg in ("chacha20-poly1305", "chacha20poly1305") and {"ciphertext", "nonce"} <= set(enc.keys()):
        try:
            ct_and_tag = base64.b64decode(enc["ciphertext"])
            nonce = base64.b64decode(nonce_b64)
        except Exception as e:
            raise ValueError(f"Legacy ChaCha shape contained invalid base64: {e}")
        # split into ct + tag
        if len(ct_and_tag) < CHACHA_TAG_LEN:
            raise ValueError("Legacy ChaCha data shorter than tag length")
        ct = ct_and_tag[:-CHACHA_TAG_LEN]
        tag = ct_and_tag[-CHACHA_TAG_LEN:]
        return {
            "v": AEAD_ENVELOPE_VERSION,
            "alg": "chacha20poly1305",
            "nonce": nonce_b64,
            "ct": base64.b64encode(ct).decode(),
            "tag": base64.b64encode(tag).decode(),
            "aad_len": aad_len
        }

    # Unknown legacy; return as-is and let decrypt fail loudly later
    return None


def decrypt_aead_envelope(enc_dict: Dict[str, str], key: bytes, aad: Optional[bytes] = None) -> bytes:
    """
    Decrypt a uniform AEAD envelope; automatically adapts legacy entries.
    """
    # Normalize legacy to uniform
    normalized = _detect_legacy_shape(enc_dict)
    if normalized is not None:
        enc = normalized
    else:
        enc = enc_dict

    alg = (enc.get("alg") or "").lower()
    try:
        nonce = base64.b64decode(enc["nonce"])
        ct = base64.b64decode(enc["ct"])
        tag = base64.b64decode(enc["tag"])
    except Exception as e:
        raise ValueError(f"Invalid envelope base64: {e}")

    log_crypto_event(
        operation="Decrypt",
        algorithm=("AES-256" if alg == "aes256gcm" else "ChaCha20-Poly1305"),
        mode=("GCM" if alg == "aes256gcm" else "Poly1305"),
        ephemeral_key=key,
        details={
            "Nonce(base64)": enc["nonce"],
            "Ciphertext(base64)": enc["ct"],
            "Tag(base64)": enc["tag"],
            "AAD_len": (len(aad) if aad else 0),
        },
        ephemeral=True
    )

    if alg == "aes256gcm":
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
        dec = cipher.decryptor()
        if aad:
            dec.authenticate_additional_data(aad)
        return dec.update(ct) + dec.finalize()

    if alg == "chacha20poly1305":
        cipher = ChaCha20Poly1305(key)
        ct_plus_tag = ct + tag
        return cipher.decrypt(nonce, ct_plus_tag, aad if aad else b"")

    raise ValueError(f"Unsupported AEAD alg in envelope: {alg}")


# --- Legacy names preserved for compatibility (now wrap the uniform API) ---

def encrypt_aes256gcm(plaintext: Union[str, bytes, bytearray],
                      key: bytes,
                      aad: Optional[bytes] = None,
                      ephemeral_pass: Optional[str] = None,
                      ephemeral_salt: Optional[bytes] = None) -> Dict[str, str]:
    return encrypt_aead_envelope(plaintext, key, "aes256gcm", aad, ephemeral_pass, ephemeral_salt)


def decrypt_aes256gcm(enc_dict: Dict[str, str], key: bytes, aad: Optional[bytes] = None) -> bytes:
    return decrypt_aead_envelope(enc_dict, key, aad)


def encrypt_chacha20poly1305(plaintext: Union[str, bytes, bytearray],
                             key: bytes,
                             aad: Optional[bytes] = None,
                             ephemeral_pass: Optional[str] = None,
                             ephemeral_salt: Optional[bytes] = None) -> Dict[str, str]:
    return encrypt_aead_envelope(plaintext, key, "chacha20poly1305", aad, ephemeral_pass, ephemeral_salt)


def decrypt_chacha20poly1305(enc_dict: Dict[str, str], key: bytes, aad: Optional[bytes] = None) -> bytes:
    return decrypt_aead_envelope(enc_dict, key, aad)
