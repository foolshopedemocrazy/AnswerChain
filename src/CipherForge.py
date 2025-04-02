################################################################################
# START OF FILE: "CipherForge.py"
################################################################################

"""
FILENAME:
"CipherForge.py"

PERMANENT FILE DESCRIPTION – DO NOT REMOVE OR MODIFY
...
(unmodified large multiline comment preserved)
"""

import os
import base64
from typing import Dict, Optional, Tuple

import argon2.low_level
import argon2.exceptions

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# Logging
from modules.debug_utils import log_debug, log_crypto_event


def derive_key_argon2id(password: str,
                        salt: bytes,
                        key_length: int = 32,
                        time_cost: int = 3,
                        memory_cost: int = 65536,
                        parallelism: int = 4,
                        ephemeral: bool = False) -> bytes:
    ephemeral_info = {
        "salt_b64": base64.b64encode(salt).decode(),
        "ephemeral_password": password if ephemeral else "<not ephemeral>"
    }
    log_debug(
        f"Starting Argon2id KDF: pass='{password}', salt(b64)='{ephemeral_info['salt_b64']}'",
        level="INFO",
        component="CRYPTO"
    )

    derived_bytes = argon2.low_level.hash_secret(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=key_length,
        type=argon2.low_level.Type.ID
    )
    if len(derived_bytes) > key_length:
        derived_bytes = derived_bytes[:key_length]

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
            "message": "Argon2id complete. Derived key is in logs.",
            "ephemeral_info": ephemeral_info
        }
    )
    return derived_bytes


def encrypt_aes256gcm(plaintext: bytes,
                      key: bytes,
                      ephemeral_pass: Optional[str] = None,
                      ephemeral_salt: Optional[bytes] = None) -> Dict[str, str]:
    if not isinstance(plaintext, bytes):
        plaintext = plaintext.encode("utf-8")

    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag

    out = {
        "alg": "AES-256-GCM",
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "tag": base64.b64encode(tag).decode()
    }

    details = {
        "Nonce(base64)": out["nonce"],
        "Ciphertext(base64)": out["ciphertext"],
        "Tag(base64)": out["tag"]
    }
    if ephemeral_pass is not None:
        details["ephemeral_password"] = ephemeral_pass
    if ephemeral_salt is not None:
        details["ephemeral_salt_b64"] = base64.b64encode(ephemeral_salt).decode()

    log_crypto_event(
        operation="Encrypt",
        algorithm="AES-256",
        mode="GCM",
        ephemeral_key=key,
        details=details,
        ephemeral=True
    )
    return out


def decrypt_aes256gcm(enc_dict: Dict[str, str], key: bytes) -> bytes:
    ciphertext = base64.b64decode(enc_dict["ciphertext"])
    nonce = base64.b64decode(enc_dict["nonce"])
    tag = base64.b64decode(enc_dict["tag"])

    log_crypto_event(
        operation="Decrypt",
        algorithm="AES-256",
        mode="GCM",
        ephemeral_key=key,
        details={
            "Nonce(base64)": enc_dict["nonce"],
            "Ciphertext(base64)": enc_dict["ciphertext"],
            "Tag(base64)": enc_dict["tag"]
        },
        ephemeral=True
    )

    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext


def encrypt_chacha20poly1305(plaintext: bytes,
                             key: bytes,
                             ephemeral_pass: Optional[str] = None,
                             ephemeral_salt: Optional[bytes] = None) -> Dict[str, str]:
    if not isinstance(plaintext, bytes):
        plaintext = plaintext.encode("utf-8")

    nonce = os.urandom(12)
    cipher = ChaCha20Poly1305(key)
    ciphertext = cipher.encrypt(nonce, plaintext, b"")

    out = {
        "alg": "ChaCha20-Poly1305",
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "nonce": base64.b64encode(nonce).decode()
    }
    details = {
        "Nonce(base64)": out["nonce"],
        "Ciphertext(base64)": out["ciphertext"]
    }
    if ephemeral_pass is not None:
        details["ephemeral_password"] = ephemeral_pass
    if ephemeral_salt is not None:
        details["ephemeral_salt_b64"] = base64.b64encode(ephemeral_salt).decode()

    log_crypto_event(
        operation="Encrypt",
        algorithm="ChaCha20-Poly1305",
        mode="Poly1305",
        ephemeral_key=key,
        details=details,
        ephemeral=True
    )
    return out


def decrypt_chacha20poly1305(enc_dict: Dict[str, str], key: bytes) -> bytes:
    import base64
    nonce = base64.b64decode(enc_dict["nonce"])
    ciphertext = base64.b64decode(enc_dict["ciphertext"])

    log_crypto_event(
        operation="Decrypt",
        algorithm="ChaCha20-Poly1305",
        mode="Poly1305",
        ephemeral_key=key,
        details={
            "Nonce(base64)": enc_dict["nonce"],
            "Ciphertext(base64)": enc_dict["ciphertext"]
        },
        ephemeral=True
    )

    cipher = ChaCha20Poly1305(key)
    plaintext = cipher.decrypt(nonce, ciphertext, b"")
    return plaintext


def derive_or_recover_key(password: str,
                          salt: Optional[bytes] = None,
                          ephemeral: bool = False,
                          time_cost: int = 3,
                          memory_cost: int = 65536,
                          parallelism: int = 4) -> Tuple[bytes, bytes]:
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
        parallelism=parallelism
    )
    return key, salt

################################################################################
# END OF FILE: "CipherForge.py"
################################################################################
