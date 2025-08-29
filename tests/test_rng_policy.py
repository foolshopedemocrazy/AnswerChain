# tests/test_rng_policy.py
import pytest

from modules.rng import random_bytes, token_bytes, token_hex, token_urlsafe, secure_compare
from modules.noble_bridge import NobleBridge, BridgeError


def test_python_rng_basic_properties():
    b1 = random_bytes(32)
    b2 = random_bytes(32)
    assert isinstance(b1, (bytes, bytearray)) and isinstance(b2, (bytes, bytearray))
    assert len(b1) == 32 and len(b2) == 32
    # Extremely likely to differ
    assert b1 != b2

    t_bytes = token_bytes(16)
    t_hex = token_hex(16)
    t_url = token_urlsafe(16)

    assert isinstance(t_bytes, (bytes, bytearray)) and len(t_bytes) == 16
    assert isinstance(t_hex, str) and len(t_hex) == 32  # 2 chars per byte
    assert isinstance(t_url, str) and len(t_url) > 0


def test_secure_compare_constant_time_semantics():
    a = token_bytes(32)
    b = bytes(a)
    c = b"\x00" * len(a)
    assert secure_compare(a, b) is True
    assert secure_compare(a, c) is False


def test_bridge_has_no_random_op():
    # The Node bridge must not expose randomness.
    with NobleBridge(js_dir="bridge") as nb:
        # Attempt to invoke a non-existent op; should raise BridgeError.
        with pytest.raises(BridgeError):
            nb._rpc("random_bytes", {"len": 32})
