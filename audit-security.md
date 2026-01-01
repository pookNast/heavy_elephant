# Security Audit Report: heavy_elephant

**Audit Date:** 2025-12-31
**Auditor:** Security Auditor Agent
**Project:** PS5 Security Research Toolkit
**Status:** Pre-Implementation Design Review

---

## Executive Summary

This audit reviews the **planned architecture** outlined in the design document (`encapsulated-stargazing-biscuit.md`). The project directory exists but contains only empty scaffolding with no implementation code. This report identifies security concerns in the proposed design and provides recommendations before development begins.

**Overall Risk Assessment:** HIGH - Multiple critical and high-severity issues in the planned design require remediation before implementation.

---

## 1. Key Storage Security

### Finding 1.1: Hardcoded Keys in Plan Document
**Severity:** CRITICAL

**Description:** The plan document contains cryptographic keys in plaintext:
- EMC IPL Header Key: `F0332357C8CFAE7E7E26E52BE9E3AED4`
- EMC IPL Cipher Key: `D5C92E39759A3E5CE954E772B1C2B651`
- EAP KBL Key: `262555E3CF062B070B5AA2CDDF3A5D0E`
- SELF Cipher Key: `32D00F27AE38FE4AC88A352313A2BFB4`
- M.2 Keys: `012345678901234567890123456789AB` (clearly placeholder/test values)

**Risk:** Keys stored in plaintext in design documents or source code can be:
- Leaked through version control history
- Exposed in logs, crash dumps, or memory analysis
- Compromised if the repository is accessed by unauthorized parties

**Recommendations:**
1. Never store keys in plaintext in documents or source code
2. Use environment variables or secure key management systems
3. Consider using a Hardware Security Module (HSM) or secure enclave
4. If keys must be in files, encrypt them with a master key derived from user input

---

### Finding 1.2: JSON Key Files Without Encryption
**Severity:** HIGH

**Description:** The planned `keys/` directory structure stores keys in plain JSON files:
```
keys/
├── boot_chain.json
├── pkg_rsa.json
├── self_keys.json
├── m2_keys.json
└── ucmd_keys.json
```

**Risk:**
- Filesystem access grants key access
- No access control beyond filesystem permissions
- Keys remain in plaintext on disk

**Recommendations:**
1. Encrypt key files at rest using age, gpg, or AEAD ciphers
2. Implement key derivation from passphrase using Argon2id
3. Use `secrecy` crate's `SecretBox<T>` for in-memory key handling
4. Add file permission validation (0600) on key file access

---

### Finding 1.3: No Key Rotation or Versioning
**Severity:** MEDIUM

**Description:** The design shows no mechanism for key versioning or rotation.

**Risk:** If a key is compromised, there's no clear path to recovery or key replacement.

**Recommendations:**
1. Add key version identifiers in JSON schema
2. Implement key validation/integrity checks (HMAC or signature)
3. Document key provenance and update procedures

---

## 2. Crypto Implementation Vulnerabilities

### Finding 2.1: AES-128-CBC with IV=0 (Zero IV)
**Severity:** CRITICAL

**Description:** The plan specifies:
> "Mode: AES-128-CBC, IV=0"

Using a zero (or constant) IV with CBC mode is a severe cryptographic weakness.

**Risk:**
- Identical plaintext blocks at the start of messages produce identical ciphertext
- Enables known-plaintext attacks
- Breaks semantic security of encryption
- CBC with predictable IV is vulnerable to BEAST-style attacks

**Recommendations:**
1. **For decryption of existing PS5 data:** Document this as a known weakness of the target system; add warnings in code comments and output
2. **For any new encryption operations:** Generate cryptographically random IVs using `rand::rngs::OsRng`
3. Consider using authenticated encryption (AES-GCM) for any new data the tools generate

---

### Finding 2.2: No Ciphertext Authentication
**Severity:** HIGH

**Description:** AES-CBC provides confidentiality but not integrity. The plan mentions HMAC-SHA1 for MAC verification on some components but not all:
- EAP KBL: Has MAC verification
- EAP Kernel: Has MAC verification
- EMC IPL Header/Body: No MAC mentioned
- M.2 Storage: No authentication mentioned

**Risk:**
- Ciphertext manipulation attacks (padding oracle, bit-flipping)
- Malicious firmware injection if decrypted content is re-encrypted and deployed

**Recommendations:**
1. Always verify MAC/signature BEFORE decrypting (Encrypt-then-MAC)
2. Use HMAC-SHA256 instead of HMAC-SHA1 (SHA1 is deprecated)
3. For new data, use authenticated encryption (AES-GCM or ChaCha20-Poly1305)

---

### Finding 2.3: HMAC-SHA1 Deprecation
**Severity:** MEDIUM

**Description:** The plan uses HMAC-SHA1 for MAC verification:
> "MAC: 1EE22F6A189E7E... (HMAC-SHA1)"

**Risk:** While HMAC-SHA1 is not yet broken for HMAC purposes, SHA1 is deprecated. This creates:
- Compliance issues
- Future security debt
- Perception problems in security-conscious contexts

**Recommendations:**
1. Document SHA1 usage as a requirement of the PS5 protocol (can't change)
2. For any tool-generated signatures, use HMAC-SHA256 or HMAC-SHA3
3. Add deprecation warnings in code documentation

---

## 3. Memory Safety for AES-CBC

### Finding 3.1: No Secure Memory Handling Specified
**Severity:** HIGH

**Description:** The plan does not specify secure memory handling for cryptographic operations.

**Risk:**
- Keys may remain in memory after use
- Swap files may contain key material
- Core dumps expose secrets
- Memory scanning attacks

**Recommendations:**
1. Use the `secrecy` crate with `SecretBox<T>` for all key material
2. Implement `Zeroize` trait for all structs holding sensitive data
3. Use `ZeroizeOnDrop` to ensure automatic cleanup
4. Consider `mlock()` to prevent swapping (via `memsec` or `secrets` crates)

Example pattern:
```rust
use secrecy::{SecretBox, ExposeSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
struct AesKey([u8; 16]);

fn decrypt(key: &SecretBox<AesKey>, ciphertext: &[u8]) -> Vec<u8> {
    let key_bytes = key.expose_secret();
    // ... perform decryption
    // Key automatically zeroized when SecretBox drops
}
```

---

### Finding 3.2: Buffer Handling for CBC Padding
**Severity:** MEDIUM

**Description:** CBC mode requires proper PKCS#7 padding handling. No padding strategy is specified.

**Risk:**
- Padding oracle attacks if error messages leak padding validity
- Buffer overflows if padding is not validated correctly
- Panic on malformed input

**Recommendations:**
1. Use `block-padding` crate from RustCrypto for PKCS#7
2. Implement constant-time padding validation
3. Return generic errors, never leak whether padding failed vs. decryption failed
4. Handle `UnpadError` gracefully without exposing details

---

## 4. RSA Handling

### Finding 4.1: Full RSA Private Key Components Exposed
**Severity:** CRITICAL

**Description:** The plan mentions storing "Full RSA private key (N, D, P, Q, DP, DQ, QP)" in `pkg_rsa.json`.

**Risk:**
- Complete private key exposure allows signing arbitrary packages
- CRT parameters (DP, DQ, QP) enable optimized attacks if partially leaked
- No key protection mechanism specified

**Recommendations:**
1. Encrypt RSA key file at rest with passphrase-derived key
2. Validate RSA key consistency on load (check P*Q = N, etc.)
3. Use the `rsa` crate's safe key loading with validation
4. Consider storing only minimal required components

---

### Finding 4.2: No RSA Key Size Validation
**Severity:** HIGH

**Description:** No minimum RSA key size is specified in the design.

**Risk:**
- Small keys (< 2048 bits) are factorizable
- No validation could allow loading weak test keys

**Recommendations:**
1. Validate RSA key size >= 2048 bits on load
2. Reject keys that don't meet minimum security requirements
3. Log warnings for keys between 2048-3072 bits (recommend 4096)

---

### Finding 4.3: RSA Padding Scheme Not Specified
**Severity:** HIGH

**Description:** The plan doesn't specify RSA padding (PKCS#1 v1.5, OAEP, PSS).

**Risk:**
- PKCS#1 v1.5 is vulnerable to Bleichenbacher attacks
- Wrong padding can break signature verification
- Interoperability issues

**Recommendations:**
1. Document which padding PS5 PKG signing uses
2. For signing: Use PSS (RSASSA-PSS) if possible
3. For encryption: Use OAEP with SHA-256
4. If legacy PKCS#1 v1.5 required, implement constant-time operations

---

## 5. Rust Crypto Patterns

### Finding 5.1: Correct Crate Selection
**Severity:** INFORMATIONAL (Positive)

**Description:** The plan correctly identifies RustCrypto ecosystem crates:
- `aes` - Pure Rust AES implementation
- `cbc` - CBC mode operations
- `rsa` - RSA operations
- `sha1`/`hmac` - MAC verification

**Assessment:** These are appropriate choices from the well-audited RustCrypto project.

**Recommendations:**
1. Pin exact versions in `Cargo.toml` (avoid `*` or loose ranges)
2. Run `cargo audit` regularly
3. Enable `#![deny(unsafe_code)]` where possible
4. Consider `#![forbid(unsafe_code)]` for `he-crypto` crate

---

### Finding 5.2: Missing Error Handling Pattern
**Severity:** MEDIUM

**Description:** No error handling strategy is defined for crypto operations.

**Risk:**
- Panics expose internal state
- Inconsistent error handling across tools
- Potential for timing side-channels in error paths

**Recommendations:**
1. Define a unified `CryptoError` enum using `thiserror`
2. Never use `.unwrap()` on crypto operations
3. Implement constant-time error comparison where applicable
4. Use `subtle::ConstantTimeEq` for MAC verification

Example:
```rust
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("invalid key length")]
    InvalidKeyLength,
    #[error("MAC verification failed")]
    MacVerificationFailed,
    // Never include the actual expected/received values
}
```

---

### Finding 5.3: No Timing Attack Mitigations
**Severity:** MEDIUM

**Description:** The design doesn't address timing attacks.

**Risk:**
- Variable-time comparisons leak secret data
- Early-return on failures enables timing analysis

**Recommendations:**
1. Use `subtle::ConstantTimeEq` for all secret comparisons
2. Use `subtle::Choice` for conditional operations on secrets
3. Verify constant-time behavior with tools like `dudect`
4. The RustCrypto crates handle this internally, but wrapper code must not introduce timing leaks

---

### Finding 5.4: Parallel Agent Architecture Security
**Severity:** MEDIUM

**Description:** The plan proposes 5 parallel tmux sessions working on different tools, each potentially handling key material.

**Risk:**
- Key material may be shared insecurely between sessions
- Race conditions in key file access
- Log files from multiple sessions may contain secrets

**Recommendations:**
1. Use file locking (flock) for key file access
2. Clear environment variables containing secrets after use
3. Redirect sensitive output away from logs
4. Consider process isolation for key operations

---

## 6. Additional Security Concerns

### Finding 6.1: Debug Logging Risk
**Severity:** MEDIUM

**Description:** CLI tools using `clap` often enable verbose/debug output.

**Risk:** Debug output may inadvertently log key material or plaintext.

**Recommendations:**
1. Implement `Debug` trait carefully - use `secrecy::SecretBox` which redacts debug output
2. Never log key bytes, even in hex
3. Use structured logging with secret redaction
4. Add `#[cfg(not(debug_assertions))]` guards for sensitive debug code

---

### Finding 6.2: Test Data Handling
**Severity:** LOW

**Description:** The plan mentions "synthetic test data" but doesn't specify handling.

**Risk:** Test keys left in production builds.

**Recommendations:**
1. Use separate key files for tests (`keys/test/`)
2. Add compile-time assertions to prevent test keys in release
3. Mark test keys clearly: `TEST_KEY_DO_NOT_USE_IN_PRODUCTION`

---

## Summary of Findings

| ID | Finding | Severity | Status |
|----|---------|----------|--------|
| 1.1 | Hardcoded keys in plan document | CRITICAL | Open |
| 1.2 | JSON key files without encryption | HIGH | Open |
| 1.3 | No key rotation/versioning | MEDIUM | Open |
| 2.1 | AES-128-CBC with IV=0 | CRITICAL | Open |
| 2.2 | No ciphertext authentication | HIGH | Open |
| 2.3 | HMAC-SHA1 deprecation | MEDIUM | Open |
| 3.1 | No secure memory handling | HIGH | Open |
| 3.2 | Buffer handling for CBC padding | MEDIUM | Open |
| 4.1 | Full RSA private key exposed | CRITICAL | Open |
| 4.2 | No RSA key size validation | HIGH | Open |
| 4.3 | RSA padding scheme not specified | HIGH | Open |
| 5.1 | Correct crate selection | INFO | OK |
| 5.2 | Missing error handling pattern | MEDIUM | Open |
| 5.3 | No timing attack mitigations | MEDIUM | Open |
| 5.4 | Parallel agent architecture security | MEDIUM | Open |
| 6.1 | Debug logging risk | MEDIUM | Open |
| 6.2 | Test data handling | LOW | Open |

---

## Recommendations Priority

### Immediate (Before Implementation)

1. **Remove keys from plan document** - Store keys in encrypted vault
2. **Define secure memory handling** - Use `secrecy` + `zeroize` crates
3. **Document IV=0 limitation** - Add warnings for PS5 protocol constraints
4. **Encrypt key files at rest** - Use age or GPG encryption

### High Priority (During Implementation)

5. **Implement SecretBox for all key material**
6. **Add RSA key validation** (size, consistency)
7. **Use constant-time comparisons** for MAC verification
8. **Define unified error handling** with `thiserror`

### Medium Priority (Before Release)

9. **Add `cargo audit` to CI**
10. **Implement key file locking**
11. **Review debug output for leaks**
12. **Create test key isolation**

---

## Conclusion

The heavy_elephant project design shows appropriate technology choices (Rust, RustCrypto ecosystem) but requires significant security hardening before implementation. The most critical issues are:

1. Plaintext key storage
2. Zero IV usage (PS5 protocol limitation - document and warn)
3. Lack of secure memory handling
4. Unencrypted RSA private key storage

Addressing these issues during the design phase will be significantly less costly than retrofitting security after implementation.

---

*Report generated by Security Auditor Agent*
*Review cycle: Initial Design Audit*
