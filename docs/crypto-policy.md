# Cryptography Policy: Randomness Boundary

**Decision**: All randomness must originate from Python’s OS-backed CSPRNG (`secrets`/`os.urandom`). The Node bridge (noble) must not be used to generate random bytes or tokens.

**Rationale**:
1. Python’s `secrets` module and `os.urandom` are designed for cryptographic use and draw from the operating system’s CSPRNG.  
2. A single, centralized RNG reduces attack surface and avoids inconsistent seeding, platform drift, or mockability issues.  
3. This aligns with industry guidance on randomness and secure design.

**Usage**:
- Import **only** from `modules.rng`:
  - `random_bytes(n)` for raw bytes
  - `token_bytes(n)`, `token_hex(n)`, `token_urlsafe(n)` for tokens
  - `secure_compare(a, b)` for constant-time equality

**Prohibitions**:
- Do not add any RNG operation to the Node bridge.
- Do not call Node/JS APIs for randomness.

**Testing**:
- `test_rng_policy.py` verifies Python RNG behavior and that the bridge rejects RNG calls.

**References**:
- Python docs: `os.urandom`, `secrets`  
- PEP 506 (introducing `secrets`)  
- RFC 4086, NIST SP 800-90B guidance on randomness  
- OWASP guidance (Random Number Generation, Cryptographic Storage)
