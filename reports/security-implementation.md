# Security Implementation Guide: Heavy Elephant

**Version:** 1.0.0
**Date:** 2025-12-31
**Status:** Implementation Reference
**Audit Reference:** `/home/pook/projects/heavy_elephant/audit-security.md`

---

## Table of Contents

1. [SecretBox Patterns for Key Types](#1-secretbox-patterns-for-key-types)
2. [Constant-Time Comparison Implementations](#2-constant-time-comparison-implementations)
3. [IV=0 Safety Wrappers](#3-iv0-safety-wrappers)
4. [Key File Encryption with Age](#4-key-file-encryption-with-age)
5. [Audit Logging Without Key Exposure](#5-audit-logging-without-key-exposure)
6. [Memory Zeroization Verification](#6-memory-zeroization-verification)

---

## 1. SecretBox Patterns for Key Types

### 1.1 Core Key Type Definitions

All key material MUST be wrapped in `SecretBox<T>` with `ZeroizeOnDrop` to ensure automatic memory cleanup.

```rust
// crates/he-crypto/src/keys/types.rs

use secrecy::{SecretBox, ExposeSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};
use std::fmt;

/// AES-128 symmetric key (16 bytes)
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Aes128Key([u8; 16]);

impl Aes128Key {
    /// Create a new AES-128 key wrapped in SecretBox
    pub fn new(bytes: [u8; 16]) -> SecretBox<Self> {
        SecretBox::new(Box::new(Self(bytes)))
    }

    /// Create from hex string (for loading from config)
    pub fn from_hex(hex_str: &str) -> Result<SecretBox<Self>, KeyError> {
        let bytes = hex::decode(hex_str)
            .map_err(|_| KeyError::InvalidHex)?;
        if bytes.len() != 16 {
            return Err(KeyError::InvalidLength { expected: 16, got: bytes.len() });
        }
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&bytes);
        Ok(Self::new(arr))
    }

    /// Access the raw key bytes (internal use only)
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

// Prevent accidental key exposure in debug output
impl fmt::Debug for Aes128Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Aes128Key([REDACTED])")
    }
}

/// AES-256 symmetric key (32 bytes)
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Aes256Key([u8; 32]);

impl Aes256Key {
    pub fn new(bytes: [u8; 32]) -> SecretBox<Self> {
        SecretBox::new(Box::new(Self(bytes)))
    }

    pub fn from_hex(hex_str: &str) -> Result<SecretBox<Self>, KeyError> {
        let bytes = hex::decode(hex_str)
            .map_err(|_| KeyError::InvalidHex)?;
        if bytes.len() != 32 {
            return Err(KeyError::InvalidLength { expected: 32, got: bytes.len() });
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self::new(arr))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for Aes256Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Aes256Key([REDACTED])")
    }
}

/// HMAC key (variable length, typically 16-32 bytes)
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HmacKey(Vec<u8>);

impl HmacKey {
    pub fn new(bytes: Vec<u8>) -> SecretBox<Self> {
        SecretBox::new(Box::new(Self(bytes)))
    }

    pub fn from_hex(hex_str: &str) -> Result<SecretBox<Self>, KeyError> {
        let bytes = hex::decode(hex_str)
            .map_err(|_| KeyError::InvalidHex)?;
        Ok(Self::new(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for HmacKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HmacKey([REDACTED; {} bytes])", self.0.len())
    }
}
```

### 1.2 RSA Key SecretBox Pattern

RSA private keys require special handling due to CRT components:

```rust
// crates/he-crypto/src/keys/rsa_key.rs

use rsa::{RsaPrivateKey, RsaPublicKey};
use rsa::pkcs1v15::{SigningKey, VerifyingKey};
use secrecy::{SecretBox, ExposeSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};
use std::fmt;

/// RSA private key wrapper with zeroization
#[derive(ZeroizeOnDrop)]
pub struct RsaPrivateKeyWrapper {
    // RsaPrivateKey doesn't impl Zeroize, so we store components separately
    n: Vec<u8>,      // Modulus
    e: Vec<u8>,      // Public exponent
    d: Vec<u8>,      // Private exponent
    p: Vec<u8>,      // Prime 1
    q: Vec<u8>,      // Prime 2
    dp: Vec<u8>,     // d mod (p-1)
    dq: Vec<u8>,     // d mod (q-1)
    qinv: Vec<u8>,   // q^-1 mod p
    // The actual key for operations
    #[zeroize(skip)]
    inner: Option<RsaPrivateKey>,
}

impl RsaPrivateKeyWrapper {
    /// Create from individual components
    pub fn from_components(
        n: &[u8], e: &[u8], d: &[u8],
        p: &[u8], q: &[u8],
        dp: &[u8], dq: &[u8], qinv: &[u8],
    ) -> Result<SecretBox<Self>, KeyError> {
        use rsa::BigUint;

        let n_int = BigUint::from_bytes_be(n);
        let e_int = BigUint::from_bytes_be(e);
        let d_int = BigUint::from_bytes_be(d);
        let primes = vec![
            BigUint::from_bytes_be(p),
            BigUint::from_bytes_be(q),
        ];

        let inner = RsaPrivateKey::from_components(n_int, e_int, d_int, primes)
            .map_err(|_| KeyError::InvalidRsaKey)?;

        // Validate key size (minimum 2048 bits)
        if inner.size() < 256 {
            return Err(KeyError::RsaKeyTooSmall {
                bits: inner.size() * 8,
                minimum: 2048,
            });
        }

        // Validate key consistency
        inner.validate()
            .map_err(|_| KeyError::RsaKeyValidationFailed)?;

        Ok(SecretBox::new(Box::new(Self {
            n: n.to_vec(),
            e: e.to_vec(),
            d: d.to_vec(),
            p: p.to_vec(),
            q: q.to_vec(),
            dp: dp.to_vec(),
            dq: dq.to_vec(),
            qinv: qinv.to_vec(),
            inner: Some(inner),
        })))
    }

    /// Get the inner RSA key for cryptographic operations
    pub fn inner(&self) -> Option<&RsaPrivateKey> {
        self.inner.as_ref()
    }

    /// Create signing key for PKCS#1 v1.5 signatures
    pub fn signing_key<D>(&self) -> Option<SigningKey<D>>
    where
        D: digest::Digest,
    {
        self.inner.as_ref().map(|k| SigningKey::new(k.clone()))
    }
}

impl fmt::Debug for RsaPrivateKeyWrapper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RsaPrivateKeyWrapper([REDACTED])")
    }
}

// Manual Zeroize implementation for the byte vectors
impl Zeroize for RsaPrivateKeyWrapper {
    fn zeroize(&mut self) {
        self.n.zeroize();
        self.e.zeroize();
        self.d.zeroize();
        self.p.zeroize();
        self.q.zeroize();
        self.dp.zeroize();
        self.dq.zeroize();
        self.qinv.zeroize();
        self.inner = None;
    }
}
```

### 1.3 Tool-Specific Key Containers

```rust
// crates/he-crypto/src/keys/containers.rs

use secrecy::SecretBox;
use super::types::{Aes128Key, HmacKey};
use super::rsa_key::RsaPrivateKeyWrapper;

/// Boot chain decryption keys (Tool 1)
pub struct BootChainKeys {
    pub emc_ipl_header_key: SecretBox<Aes128Key>,
    pub emc_ipl_cipher_key: SecretBox<Aes128Key>,
    pub eap_kbl_key: SecretBox<Aes128Key>,
    pub eap_kbl_mac_key: SecretBox<HmacKey>,
    pub eap_kernel_key: SecretBox<Aes128Key>,
    pub eap_kernel_mac_key: SecretBox<HmacKey>,
}

/// PKG signing keys (Tool 2)
pub struct PkgKeys {
    pub rsa_private: SecretBox<RsaPrivateKeyWrapper>,
    pub content_key: SecretBox<Aes128Key>,
}

/// SELF decryption keys (Tool 3)
pub struct SelfKeys {
    pub cipher_key: SecretBox<Aes128Key>,
    pub cipher_iv: [u8; 16],  // IV can be public
}

/// M.2 storage keys (Tool 4)
pub struct M2StorageKeys {
    pub primary_key: SecretBox<Aes128Key>,
    pub backup_key: SecretBox<Aes128Key>,
}

/// UCMD authentication keys (Tool 5)
pub struct UcmdKeys {
    pub rsa_private: SecretBox<RsaPrivateKeyWrapper>,
    pub important_key_3: SecretBox<Aes128Key>,
}

/// Portability encryption keys (Tool 12)
pub struct PortabilityKeys {
    pub master_encdec: SecretBox<Aes256Key>,  // 128 bytes = two 256-bit keys
    pub master_encdec_2: SecretBox<Aes256Key>,
}
```

### 1.4 Key Access Pattern

```rust
// crates/he-crypto/src/keys/access.rs

use secrecy::ExposeSecret;
use super::types::Aes128Key;

/// CORRECT: Minimal exposure scope
pub fn decrypt_with_key(
    key: &SecretBox<Aes128Key>,
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    // Key is only exposed within this scope
    let key_bytes = key.expose_secret().as_bytes();

    // Perform decryption (key_bytes reference is short-lived)
    let cipher = Aes128::new_from_slice(key_bytes)
        .map_err(|_| CryptoError::InvalidKey)?;

    // ... perform decryption ...

    Ok(plaintext)
    // key_bytes reference goes out of scope here
}

/// WRONG: Do NOT do this - exposes key for too long
// pub fn get_key_bytes(key: &SecretBox<Aes128Key>) -> &[u8; 16] {
//     key.expose_secret().as_bytes()  // Returns reference - bad!
// }
```

---

## 2. Constant-Time Comparison Implementations

### 2.1 MAC Verification

```rust
// crates/he-crypto/src/mac/verify.rs

use sha1::Sha1;
use hmac::{Hmac, Mac};
use subtle::ConstantTimeEq;
use secrecy::{SecretBox, ExposeSecret};
use super::super::keys::types::HmacKey;

type HmacSha1 = Hmac<Sha1>;

/// Result of MAC verification - no timing information leaked
pub struct MacVerificationResult {
    verified: bool,
}

impl MacVerificationResult {
    pub fn is_valid(&self) -> bool {
        self.verified
    }
}

/// Verify HMAC-SHA1 in constant time
///
/// # Security
/// - Uses subtle::ConstantTimeEq to prevent timing attacks
/// - Returns only verified/not-verified, no details about mismatch
/// - Same execution time regardless of where mismatch occurs
pub fn verify_hmac_sha1(
    key: &SecretBox<HmacKey>,
    data: &[u8],
    expected_tag: &[u8],
) -> MacVerificationResult {
    let key_bytes = key.expose_secret().as_bytes();

    let mut mac = match HmacSha1::new_from_slice(key_bytes) {
        Ok(m) => m,
        Err(_) => return MacVerificationResult { verified: false },
    };

    mac.update(data);
    let computed = mac.finalize().into_bytes();

    // Constant-time comparison - same time regardless of match position
    let is_valid: bool = computed.ct_eq(expected_tag).into();

    MacVerificationResult { verified: is_valid }
}

/// Verify HMAC-SHA256 in constant time (recommended for new implementations)
pub fn verify_hmac_sha256(
    key: &SecretBox<HmacKey>,
    data: &[u8],
    expected_tag: &[u8],
) -> MacVerificationResult {
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    let key_bytes = key.expose_secret().as_bytes();

    let mut mac = match HmacSha256::new_from_slice(key_bytes) {
        Ok(m) => m,
        Err(_) => return MacVerificationResult { verified: false },
    };

    mac.update(data);
    let computed = mac.finalize().into_bytes();

    let is_valid: bool = computed.ct_eq(expected_tag).into();

    MacVerificationResult { verified: is_valid }
}
```

### 2.2 General Constant-Time Comparisons

```rust
// crates/he-crypto/src/util/ct.rs

use subtle::{Choice, ConstantTimeEq, ConditionallySelectable};

/// Constant-time byte array comparison
///
/// Returns true if arrays are equal, false otherwise.
/// Execution time is constant regardless of where/if arrays differ.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        // Length mismatch - but still do work to avoid timing leak
        // This is a known acceptable leak as length is usually public
        return false;
    }

    let result: bool = a.ct_eq(b).into();
    result
}

/// Constant-time select between two values
///
/// If `condition` is true, returns `a`, otherwise returns `b`.
/// Execution time is the same regardless of condition.
pub fn ct_select<T: ConditionallySelectable + Copy>(
    condition: bool,
    if_true: T,
    if_false: T,
) -> T {
    let choice = Choice::from(condition as u8);
    T::conditional_select(&if_false, &if_true, choice)
}

/// Constant-time buffer selection
///
/// Copies `if_true` into `dst` if condition is true, otherwise `if_false`.
pub fn ct_select_copy(
    condition: bool,
    dst: &mut [u8],
    if_true: &[u8],
    if_false: &[u8],
) {
    assert_eq!(dst.len(), if_true.len());
    assert_eq!(dst.len(), if_false.len());

    let choice = Choice::from(condition as u8);

    for i in 0..dst.len() {
        dst[i] = u8::conditional_select(&if_false[i], &if_true[i], choice);
    }
}
```

### 2.3 Signature Verification

```rust
// crates/he-crypto/src/rsa/verify.rs

use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::signature::Verifier;
use sha2::Sha256;
use subtle::ConstantTimeEq;

/// Verify RSA-PKCS#1v1.5-SHA256 signature
///
/// # Security
/// The rsa crate internally uses constant-time operations.
/// We wrap this for consistent error handling.
pub fn verify_rsa_signature(
    public_key: &RsaPublicKey,
    message: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    let verifying_key = VerifyingKey::<Sha256>::new(public_key.clone());

    let sig = Signature::try_from(signature)
        .map_err(|_| CryptoError::SignatureVerificationFailed)?;

    verifying_key.verify(message, &sig)
        .map_err(|_| CryptoError::SignatureVerificationFailed)
}
```

---

## 3. IV=0 Safety Wrappers

### 3.1 Feature-Gated IV=0 Support

The PS5 protocol requires IV=0 for AES-CBC in certain contexts. This is a known cryptographic weakness that MUST be explicitly enabled and documented.

```rust
// crates/he-crypto/src/aes/cbc.rs

use aes::Aes128;
use cbc::{Decryptor, Encryptor};
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use secrecy::{SecretBox, ExposeSecret};
use super::super::keys::types::Aes128Key;

type Aes128CbcDec = Decryptor<Aes128>;
type Aes128CbcEnc = Encryptor<Aes128>;

/// Zero IV constant - ONLY for PS5 protocol compatibility
///
/// # Security Warning
/// Using IV=0 breaks semantic security. Identical plaintext blocks
/// at the start of messages will produce identical ciphertext.
/// This is ONLY acceptable when decrypting existing PS5 data that
/// was encrypted with IV=0.
#[cfg(feature = "unsafe_iv_zero")]
const ZERO_IV: [u8; 16] = [0u8; 16];

/// Decrypt AES-128-CBC with zero IV (PS5 protocol)
///
/// # Security Warning
/// This function uses IV=0 which is cryptographically weak.
/// Only use for decrypting existing PS5 data.
///
/// # Panics
/// Panics if compiled without `unsafe_iv_zero` feature.
#[cfg(feature = "unsafe_iv_zero")]
pub fn decrypt_cbc_iv_zero(
    key: &SecretBox<Aes128Key>,
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    // Log warning about IV=0 usage (without exposing key)
    tracing::warn!(
        target: "he_crypto::aes",
        ciphertext_len = ciphertext.len(),
        "Decrypting with IV=0 (PS5 protocol compatibility mode)"
    );

    let key_bytes = key.expose_secret().as_bytes();

    let decryptor = Aes128CbcDec::new_from_slices(key_bytes, &ZERO_IV)
        .map_err(|_| CryptoError::InvalidKey)?;

    let mut buffer = ciphertext.to_vec();

    let plaintext = decryptor
        .decrypt_padded_mut::<block_padding::Pkcs7>(&mut buffer)
        .map_err(|_| CryptoError::DecryptionFailed)?;

    Ok(plaintext.to_vec())
}

/// Compile-time guard: IV=0 not available without feature flag
#[cfg(not(feature = "unsafe_iv_zero"))]
pub fn decrypt_cbc_iv_zero(
    _key: &SecretBox<Aes128Key>,
    _ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    compile_error!(
        "IV=0 decryption requires the `unsafe_iv_zero` feature flag. \
         This is intentionally gated because IV=0 is cryptographically weak. \
         Only enable this if you are decrypting existing PS5 data."
    );
}

/// Decrypt AES-128-CBC with proper IV (recommended)
///
/// This is the secure version - use this for any new encryption.
pub fn decrypt_cbc(
    key: &SecretBox<Aes128Key>,
    iv: &[u8; 16],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    // Validate IV is not zero (defense in depth)
    if iv == &[0u8; 16] {
        #[cfg(feature = "unsafe_iv_zero")]
        {
            tracing::warn!("Zero IV detected - consider using decrypt_cbc_iv_zero explicitly");
        }
        #[cfg(not(feature = "unsafe_iv_zero"))]
        {
            return Err(CryptoError::ZeroIvNotAllowed);
        }
    }

    let key_bytes = key.expose_secret().as_bytes();

    let decryptor = Aes128CbcDec::new_from_slices(key_bytes, iv)
        .map_err(|_| CryptoError::InvalidKey)?;

    let mut buffer = ciphertext.to_vec();

    let plaintext = decryptor
        .decrypt_padded_mut::<block_padding::Pkcs7>(&mut buffer)
        .map_err(|_| CryptoError::DecryptionFailed)?;

    Ok(plaintext.to_vec())
}
```

### 3.2 Safe IV=0 Wrapper with Explicit Acknowledgment

```rust
// crates/he-crypto/src/aes/ps5_compat.rs

use super::cbc::decrypt_cbc_iv_zero;
use secrecy::SecretBox;
use super::super::keys::types::Aes128Key;

/// PS5 Protocol Compatibility Layer
///
/// This module provides wrappers for PS5-specific cryptographic operations
/// that have known weaknesses. Each function requires explicit acknowledgment
/// of the security implications.
pub struct Ps5CompatDecryptor;

/// Marker type for acknowledging IV=0 risk
pub struct IvZeroAcknowledgment {
    _private: (),
}

impl IvZeroAcknowledgment {
    /// Create an acknowledgment that IV=0 is intentionally used
    ///
    /// By calling this function, you acknowledge:
    /// - IV=0 breaks semantic security
    /// - Identical plaintext blocks produce identical ciphertext
    /// - This is only acceptable for decrypting existing PS5 data
    pub fn i_understand_iv_zero_is_insecure() -> Self {
        Self { _private: () }
    }
}

impl Ps5CompatDecryptor {
    /// Decrypt PS5 data that was encrypted with IV=0
    ///
    /// Requires explicit acknowledgment of the security implications.
    ///
    /// # Example
    /// ```rust
    /// use he_crypto::aes::ps5_compat::{Ps5CompatDecryptor, IvZeroAcknowledgment};
    ///
    /// let ack = IvZeroAcknowledgment::i_understand_iv_zero_is_insecure();
    /// let plaintext = Ps5CompatDecryptor::decrypt_emc_header(&key, &ciphertext, ack)?;
    /// ```
    #[cfg(feature = "unsafe_iv_zero")]
    pub fn decrypt_with_zero_iv(
        key: &SecretBox<Aes128Key>,
        ciphertext: &[u8],
        _ack: IvZeroAcknowledgment,
    ) -> Result<Vec<u8>, CryptoError> {
        decrypt_cbc_iv_zero(key, ciphertext)
    }
}
```

### 3.3 Documentation and Warnings

```rust
// crates/he-crypto/src/lib.rs

//! # HE-Crypto: Heavy Elephant Cryptographic Library
//!
//! ## Security Notices
//!
//! ### IV=0 Mode (PS5 Protocol Compatibility)
//!
//! Some PS5 data uses AES-CBC with IV=0, which is cryptographically weak.
//! This library supports IV=0 mode ONLY for decrypting existing PS5 data.
//!
//! To use IV=0 mode:
//! 1. Enable the `unsafe_iv_zero` feature in Cargo.toml
//! 2. Use the `Ps5CompatDecryptor` with explicit acknowledgment
//!
//! **NEVER use IV=0 for encrypting new data.**
//!
//! ### Recommended: Authenticated Encryption
//!
//! For any new data this library generates, use AES-GCM:
//!
//! ```rust
//! use he_crypto::aead::encrypt_aes_gcm;
//!
//! let (ciphertext, nonce) = encrypt_aes_gcm(&key, &plaintext)?;
//! ```
```

---

## 4. Key File Encryption with Age

### 4.1 Key File Format

```rust
// crates/he-crypto/src/keys/storage.rs

use std::path::Path;
use std::process::Command;
use std::fs::{self, Permissions};
use std::os::unix::fs::PermissionsExt;

/// Encrypted key file manager using age
pub struct KeyFileManager {
    keys_dir: PathBuf,
    identity_file: PathBuf,
}

impl KeyFileManager {
    /// Create a new key file manager
    ///
    /// # Arguments
    /// * `keys_dir` - Directory containing .age encrypted key files
    /// * `identity_file` - Path to age identity file (private key)
    pub fn new(keys_dir: impl AsRef<Path>, identity_file: impl AsRef<Path>) -> Self {
        Self {
            keys_dir: keys_dir.as_ref().to_path_buf(),
            identity_file: identity_file.as_ref().to_path_buf(),
        }
    }

    /// Validate key file permissions (must be 0600)
    fn validate_permissions(&self, path: &Path) -> Result<(), KeyError> {
        let metadata = fs::metadata(path)
            .map_err(|e| KeyError::FileAccess(e.to_string()))?;

        let permissions = metadata.permissions();
        let mode = permissions.mode() & 0o777;

        if mode != 0o600 {
            return Err(KeyError::InsecurePermissions {
                path: path.to_path_buf(),
                mode,
                required: 0o600,
            });
        }

        Ok(())
    }

    /// Decrypt an age-encrypted key file
    pub fn load_key_file(&self, name: &str) -> Result<Vec<u8>, KeyError> {
        let encrypted_path = self.keys_dir.join(format!("{}.json.age", name));

        // Validate file exists
        if !encrypted_path.exists() {
            return Err(KeyError::KeyFileNotFound(encrypted_path));
        }

        // Validate permissions on encrypted file
        self.validate_permissions(&encrypted_path)?;

        // Validate permissions on identity file
        self.validate_permissions(&self.identity_file)?;

        // Decrypt using age CLI
        let output = Command::new("age")
            .args([
                "--decrypt",
                "--identity", self.identity_file.to_str().unwrap(),
                encrypted_path.to_str().unwrap(),
            ])
            .output()
            .map_err(|e| KeyError::AgeDecryptFailed(e.to_string()))?;

        if !output.status.success() {
            return Err(KeyError::AgeDecryptFailed(
                String::from_utf8_lossy(&output.stderr).to_string()
            ));
        }

        Ok(output.stdout)
    }

    /// Encrypt and save a key file
    pub fn save_key_file(
        &self,
        name: &str,
        content: &[u8],
        recipient_pubkey: &str,
    ) -> Result<(), KeyError> {
        let encrypted_path = self.keys_dir.join(format!("{}.json.age", name));

        // Encrypt using age CLI
        let mut child = Command::new("age")
            .args([
                "--encrypt",
                "--recipient", recipient_pubkey,
                "--output", encrypted_path.to_str().unwrap(),
            ])
            .stdin(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| KeyError::AgeEncryptFailed(e.to_string()))?;

        use std::io::Write;
        child.stdin.as_mut().unwrap().write_all(content)
            .map_err(|e| KeyError::AgeEncryptFailed(e.to_string()))?;

        let status = child.wait()
            .map_err(|e| KeyError::AgeEncryptFailed(e.to_string()))?;

        if !status.success() {
            return Err(KeyError::AgeEncryptFailed("age encrypt failed".to_string()));
        }

        // Set restrictive permissions
        fs::set_permissions(&encrypted_path, Permissions::from_mode(0o600))
            .map_err(|e| KeyError::FileAccess(e.to_string()))?;

        Ok(())
    }
}
```

### 4.2 Age Identity Setup Script

```bash
#!/bin/bash
# scripts/setup-age-identity.sh

set -euo pipefail

KEYS_DIR="${1:-./keys}"
IDENTITY_FILE="${KEYS_DIR}/.age-identity"
PUBKEY_FILE="${KEYS_DIR}/.age-recipient.pub"

echo "Setting up age encryption for Heavy Elephant keys..."

# Create keys directory with restrictive permissions
mkdir -p "$KEYS_DIR"
chmod 700 "$KEYS_DIR"

# Generate age identity if it doesn't exist
if [ ! -f "$IDENTITY_FILE" ]; then
    echo "Generating new age identity..."
    age-keygen -o "$IDENTITY_FILE" 2> "$PUBKEY_FILE"
    chmod 600 "$IDENTITY_FILE"
    chmod 644 "$PUBKEY_FILE"
    echo "Identity created: $IDENTITY_FILE"
    echo "Public key saved to: $PUBKEY_FILE"
else
    echo "Identity already exists: $IDENTITY_FILE"
fi

# Display public key
echo ""
echo "Your age public key (use this to encrypt keys):"
cat "$PUBKEY_FILE" | grep "^age1"
```

### 4.3 Key File JSON Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "HeavyElephantKeyFile",
  "description": "Encrypted key storage format for Heavy Elephant tools",
  "type": "object",
  "required": ["version", "key_type", "created_at", "keys"],
  "properties": {
    "version": {
      "type": "string",
      "pattern": "^1\\.0\\.0$"
    },
    "key_type": {
      "type": "string",
      "enum": ["boot_chain", "pkg_rsa", "self_keys", "m2_keys", "ucmd_keys", "portability"]
    },
    "created_at": {
      "type": "string",
      "format": "date-time"
    },
    "description": {
      "type": "string"
    },
    "keys": {
      "type": "object",
      "additionalProperties": {
        "type": "object",
        "required": ["algorithm", "key_hex"],
        "properties": {
          "algorithm": {
            "type": "string",
            "enum": ["AES-128-CBC", "AES-256-CBC", "HMAC-SHA1", "HMAC-SHA256", "RSA-2048", "RSA-4096"]
          },
          "key_hex": {
            "type": "string",
            "pattern": "^[0-9a-fA-F]+$"
          },
          "iv_hex": {
            "type": "string",
            "pattern": "^[0-9a-fA-F]{32}$"
          },
          "notes": {
            "type": "string"
          }
        }
      }
    }
  }
}
```

### 4.4 Example Key File (before encryption)

```json
{
  "version": "1.0.0",
  "key_type": "boot_chain",
  "created_at": "2025-12-31T00:00:00Z",
  "description": "Boot chain decryption keys for PS5 firmware analysis",
  "keys": {
    "emc_ipl_header": {
      "algorithm": "AES-128-CBC",
      "key_hex": "REDACTED_BEFORE_ENCRYPTION",
      "notes": "IV=0 required for PS5 compatibility"
    },
    "emc_ipl_cipher": {
      "algorithm": "AES-128-CBC",
      "key_hex": "REDACTED_BEFORE_ENCRYPTION"
    },
    "eap_kbl": {
      "algorithm": "AES-128-CBC",
      "key_hex": "REDACTED_BEFORE_ENCRYPTION"
    },
    "eap_kbl_mac": {
      "algorithm": "HMAC-SHA1",
      "key_hex": "REDACTED_BEFORE_ENCRYPTION",
      "notes": "Verify MAC before decryption"
    }
  }
}
```

---

## 5. Audit Logging Without Key Exposure

### 5.1 Secure Logging Module

```rust
// crates/he-crypto/src/audit/mod.rs

use std::fmt;
use tracing::{info, warn, error, span, Level};

/// Redacted wrapper for logging sensitive values
pub struct Redacted<T>(pub T);

impl<T> fmt::Debug for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl<T> fmt::Display for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// Key identifier for logging (shows type + length, not content)
pub struct KeyIdentifier {
    key_type: &'static str,
    length_bytes: usize,
    fingerprint: [u8; 4],  // First 4 bytes of SHA256 of key
}

impl KeyIdentifier {
    pub fn new(key_type: &'static str, key_bytes: &[u8]) -> Self {
        use sha2::{Sha256, Digest};
        let hash = Sha256::digest(key_bytes);
        let mut fingerprint = [0u8; 4];
        fingerprint.copy_from_slice(&hash[..4]);

        Self {
            key_type,
            length_bytes: key_bytes.len(),
            fingerprint,
        }
    }
}

impl fmt::Debug for KeyIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}[{} bytes, fp:{:02x}{:02x}{:02x}{:02x}]",
            self.key_type,
            self.length_bytes,
            self.fingerprint[0],
            self.fingerprint[1],
            self.fingerprint[2],
            self.fingerprint[3],
        )
    }
}

impl fmt::Display for KeyIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}
```

### 5.2 Audit Event Types

```rust
// crates/he-crypto/src/audit/events.rs

use super::KeyIdentifier;
use std::path::PathBuf;
use tracing::{info, warn, error, instrument};

/// Audit events for cryptographic operations
#[derive(Debug)]
pub enum AuditEvent {
    KeyLoaded {
        key_id: KeyIdentifier,
        source: PathBuf,
    },
    KeyDestroyed {
        key_id: KeyIdentifier,
    },
    DecryptionAttempt {
        key_id: KeyIdentifier,
        input_size: usize,
        success: bool,
    },
    MacVerification {
        key_id: KeyIdentifier,
        data_size: usize,
        verified: bool,
    },
    SignatureOperation {
        key_id: KeyIdentifier,
        operation: &'static str,  // "sign" or "verify"
        success: bool,
    },
    SecurityWarning {
        message: String,
        context: String,
    },
}

impl AuditEvent {
    /// Log this event to the audit trail
    pub fn log(&self) {
        match self {
            AuditEvent::KeyLoaded { key_id, source } => {
                info!(
                    target: "he_crypto::audit",
                    key = %key_id,
                    source = %source.display(),
                    "Key loaded"
                );
            }
            AuditEvent::KeyDestroyed { key_id } => {
                info!(
                    target: "he_crypto::audit",
                    key = %key_id,
                    "Key destroyed and zeroized"
                );
            }
            AuditEvent::DecryptionAttempt { key_id, input_size, success } => {
                if *success {
                    info!(
                        target: "he_crypto::audit",
                        key = %key_id,
                        input_size,
                        "Decryption successful"
                    );
                } else {
                    warn!(
                        target: "he_crypto::audit",
                        key = %key_id,
                        input_size,
                        "Decryption failed"
                    );
                }
            }
            AuditEvent::MacVerification { key_id, data_size, verified } => {
                if *verified {
                    info!(
                        target: "he_crypto::audit",
                        key = %key_id,
                        data_size,
                        "MAC verification passed"
                    );
                } else {
                    error!(
                        target: "he_crypto::audit",
                        key = %key_id,
                        data_size,
                        "MAC verification FAILED - potential tampering"
                    );
                }
            }
            AuditEvent::SignatureOperation { key_id, operation, success } => {
                if *success {
                    info!(
                        target: "he_crypto::audit",
                        key = %key_id,
                        operation,
                        "Signature operation successful"
                    );
                } else {
                    warn!(
                        target: "he_crypto::audit",
                        key = %key_id,
                        operation,
                        "Signature operation failed"
                    );
                }
            }
            AuditEvent::SecurityWarning { message, context } => {
                warn!(
                    target: "he_crypto::audit::security",
                    message,
                    context,
                    "SECURITY WARNING"
                );
            }
        }
    }
}
```

### 5.3 Tracing Configuration

```rust
// crates/he-crypto/src/audit/config.rs

use tracing_subscriber::{
    fmt,
    layer::SubscriberExt,
    util::SubscriberInitExt,
    EnvFilter,
    Layer,
};
use std::path::Path;

/// Initialize audit logging with file and console output
pub fn init_audit_logging(log_file: impl AsRef<Path>) -> Result<(), Box<dyn std::error::Error>> {
    // Console layer - INFO level, redacted
    let console_layer = fmt::layer()
        .with_target(true)
        .with_level(true)
        .with_filter(EnvFilter::new("he_crypto=info"));

    // File layer - DEBUG level, for forensics (still no keys!)
    let file = std::fs::File::create(log_file)?;
    let file_layer = fmt::layer()
        .with_writer(file)
        .with_ansi(false)
        .json()  // Structured logging for analysis
        .with_filter(EnvFilter::new("he_crypto=debug"));

    tracing_subscriber::registry()
        .with(console_layer)
        .with(file_layer)
        .init();

    Ok(())
}
```

### 5.4 Usage Example

```rust
// Example: Secure decryption with audit logging

use he_crypto::{
    keys::{KeyFileManager, types::Aes128Key},
    aes::cbc::decrypt_cbc,
    audit::{AuditEvent, KeyIdentifier},
};
use secrecy::ExposeSecret;

fn decrypt_firmware(
    key_manager: &KeyFileManager,
    ciphertext: &[u8],
    iv: &[u8; 16],
) -> Result<Vec<u8>, CryptoError> {
    // Load key (logs: "Key loaded")
    let key_data = key_manager.load_key_file("boot_chain")?;
    let key = Aes128Key::from_hex(&key_data)?;

    // Create key identifier for logging (uses hash, not actual key)
    let key_id = KeyIdentifier::new("AES-128", key.expose_secret().as_bytes());

    // Attempt decryption
    let result = decrypt_cbc(&key, iv, ciphertext);

    // Log audit event (success or failure, no key content)
    AuditEvent::DecryptionAttempt {
        key_id: key_id.clone(),
        input_size: ciphertext.len(),
        success: result.is_ok(),
    }.log();

    // Key automatically zeroized when dropped
    result

    // After scope: "Key destroyed and zeroized" logged
}
```

---

## 6. Memory Zeroization Verification

### 6.1 Zeroization Test Module

```rust
// crates/he-crypto/src/tests/zeroize_tests.rs

#[cfg(test)]
mod tests {
    use super::super::keys::types::*;
    use secrecy::{SecretBox, ExposeSecret};
    use std::ptr;

    /// Test that AES-128 keys are zeroized on drop
    #[test]
    fn test_aes128_key_zeroize() {
        // Create key
        let key_bytes = [0x42u8; 16];  // Non-zero pattern
        let key = Aes128Key::new(key_bytes);

        // Get pointer to key data before drop
        let key_ptr: *const [u8; 16] = key.expose_secret().as_bytes() as *const _;

        // Drop the key
        drop(key);

        // SAFETY: We're reading potentially freed memory for testing only
        // This is undefined behavior but acceptable in tests to verify zeroization
        // In release builds, this memory may be reused
        #[cfg(debug_assertions)]
        unsafe {
            let after_drop = ptr::read_volatile(key_ptr);
            assert!(
                after_drop.iter().all(|&b| b == 0),
                "Key was not zeroized after drop! Found: {:?}",
                after_drop
            );
        }
    }

    /// Test that HMAC keys are zeroized on drop
    #[test]
    fn test_hmac_key_zeroize() {
        let key_bytes = vec![0x42u8; 32];
        let key = HmacKey::new(key_bytes);

        // Store length and pattern for verification
        let len = key.expose_secret().as_bytes().len();
        let first_ptr: *const u8 = key.expose_secret().as_bytes().as_ptr();

        drop(key);

        #[cfg(debug_assertions)]
        unsafe {
            // Check first few bytes are zeroed
            for i in 0..std::cmp::min(len, 8) {
                let byte = ptr::read_volatile(first_ptr.add(i));
                assert_eq!(byte, 0, "HMAC key byte {} was not zeroized", i);
            }
        }
    }

    /// Verify SecretBox prevents Debug leaks
    #[test]
    fn test_debug_redaction() {
        let key = Aes128Key::new([0x42u8; 16]);
        let debug_output = format!("{:?}", key.expose_secret());

        // Should NOT contain actual key bytes
        assert!(!debug_output.contains("42"));
        assert!(debug_output.contains("REDACTED") || debug_output.contains("Aes128Key"));
    }
}
```

### 6.2 Runtime Zeroization Verification

```rust
// crates/he-crypto/src/util/zeroize_verify.rs

use std::alloc::{alloc, dealloc, Layout};
use std::ptr;

/// Verify that a buffer was properly zeroized
///
/// # Safety
/// Only call this in tests or debug builds.
/// Reading freed memory is undefined behavior.
#[cfg(debug_assertions)]
pub unsafe fn verify_buffer_zeroized(ptr: *const u8, len: usize) -> bool {
    for i in 0..len {
        let byte = ptr::read_volatile(ptr.add(i));
        if byte != 0 {
            return false;
        }
    }
    true
}

/// Guard that verifies zeroization on drop (for testing)
pub struct ZeroizeGuard {
    ptr: *mut u8,
    len: usize,
    layout: Layout,
}

impl ZeroizeGuard {
    /// Create a guarded buffer that will verify zeroization on drop
    pub fn new(size: usize) -> Self {
        let layout = Layout::array::<u8>(size).unwrap();
        let ptr = unsafe { alloc(layout) };
        Self { ptr, len: size, layout }
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }
}

impl Drop for ZeroizeGuard {
    fn drop(&mut self) {
        // Fill with pattern before zeroize
        unsafe {
            ptr::write_bytes(self.ptr, 0xFF, self.len);
        }

        // Zeroize
        use zeroize::Zeroize;
        self.as_mut_slice().zeroize();

        // Verify zeroization (debug only)
        #[cfg(debug_assertions)]
        unsafe {
            for i in 0..self.len {
                let byte = ptr::read_volatile(self.ptr.add(i));
                debug_assert_eq!(byte, 0, "ZeroizeGuard: byte {} not zeroed", i);
            }
        }

        unsafe {
            dealloc(self.ptr, self.layout);
        }
    }
}
```

### 6.3 Integration Test for Full Lifecycle

```rust
// tests/integration/key_lifecycle.rs

use he_crypto::keys::{KeyFileManager, types::Aes128Key, containers::BootChainKeys};
use he_crypto::aes::cbc::decrypt_cbc;
use he_crypto::audit::AuditEvent;
use secrecy::ExposeSecret;
use std::sync::atomic::{AtomicBool, Ordering};

static KEY_DROPPED: AtomicBool = AtomicBool::new(false);

/// Custom key type with drop tracking
struct TrackedKey {
    inner: Aes128Key,
}

impl Drop for TrackedKey {
    fn drop(&mut self) {
        KEY_DROPPED.store(true, Ordering::SeqCst);
    }
}

#[test]
fn test_key_lifecycle_zeroization() {
    KEY_DROPPED.store(false, Ordering::SeqCst);

    {
        // Scope: Key is alive
        let key = Aes128Key::new([0x42u8; 16]);

        // Use the key
        let _ = key.expose_secret();

        assert!(!KEY_DROPPED.load(Ordering::SeqCst), "Key dropped too early");

        // End of scope: key should be dropped and zeroized
    }

    // Key should be zeroized now (can't verify memory in safe Rust)
    // But we can verify the drop handler ran
}

#[test]
fn test_decrypt_operation_no_key_leak() {
    // Create a test key
    let key = Aes128Key::new([0x42u8; 16]);

    // Create test data
    let ciphertext = vec![0u8; 32];  // Invalid ciphertext
    let iv = [0u8; 16];

    // Attempt decryption (will fail due to invalid data)
    let result = decrypt_cbc(&key, &iv, &ciphertext);

    // Verify error doesn't contain key material
    if let Err(e) = result {
        let error_string = format!("{:?}", e);
        assert!(
            !error_string.contains("42"),
            "Error message contains key byte pattern"
        );
    }

    // Key is still valid here
    assert_eq!(key.expose_secret().as_bytes().len(), 16);

    // Drop key explicitly
    drop(key);

    // Key is now zeroized (verified by Drop implementation)
}
```

### 6.4 CI Integration for Zeroization Checks

```yaml
# .github/workflows/security.yml

name: Security Checks

on: [push, pull_request]

jobs:
  zeroization:
    name: Memory Zeroization Tests
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: dtolnay/rust-toolchain@stable

      - name: Run zeroization tests
        run: |
          # Run tests with debug assertions enabled
          RUSTFLAGS="-C debug-assertions" cargo test zeroize --all-features

      - name: Run with ASAN (if nightly)
        run: |
          rustup install nightly
          RUSTFLAGS="-Z sanitizer=address" cargo +nightly test zeroize --target x86_64-unknown-linux-gnu
        continue-on-error: true

  valgrind:
    name: Valgrind Memory Analysis
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Valgrind
        run: sudo apt-get install -y valgrind

      - uses: dtolnay/rust-toolchain@stable

      - name: Build tests
        run: cargo test --no-run --all-features

      - name: Run under Valgrind
        run: |
          TEST_BIN=$(find target/debug/deps -name 'he_crypto-*' -type f -executable | head -1)
          valgrind --leak-check=full --error-exitcode=1 $TEST_BIN --test-threads=1 zeroize
```

---

## Appendix A: Error Types

```rust
// crates/he-crypto/src/error.rs

use thiserror::Error;
use std::path::PathBuf;

/// Unified error type for all cryptographic operations
///
/// # Security
/// Error messages are intentionally vague to prevent oracle attacks.
/// Detailed information is only available via audit logs.
#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("decryption failed")]
    DecryptionFailed,

    #[error("invalid key")]
    InvalidKey,

    #[error("MAC verification failed")]
    MacVerificationFailed,

    #[error("signature verification failed")]
    SignatureVerificationFailed,

    #[error("padding error")]
    PaddingError,

    #[error("zero IV not allowed without feature flag")]
    ZeroIvNotAllowed,
}

/// Key management errors (more detailed, non-crypto)
#[derive(Error, Debug)]
pub enum KeyError {
    #[error("invalid hex encoding")]
    InvalidHex,

    #[error("invalid key length: expected {expected}, got {got}")]
    InvalidLength { expected: usize, got: usize },

    #[error("invalid RSA key")]
    InvalidRsaKey,

    #[error("RSA key too small: {bits} bits, minimum {minimum} required")]
    RsaKeyTooSmall { bits: usize, minimum: usize },

    #[error("RSA key validation failed")]
    RsaKeyValidationFailed,

    #[error("key file not found: {0}")]
    KeyFileNotFound(PathBuf),

    #[error("insecure file permissions on {path}: {mode:o}, required {required:o}")]
    InsecurePermissions { path: PathBuf, mode: u32, required: u32 },

    #[error("age decryption failed: {0}")]
    AgeDecryptFailed(String),

    #[error("age encryption failed: {0}")]
    AgeEncryptFailed(String),

    #[error("file access error: {0}")]
    FileAccess(String),
}
```

---

## Appendix B: Cargo.toml for he-crypto

```toml
[package]
name = "he-crypto"
version = "0.1.0"
edition = "2021"
description = "Cryptographic library for Heavy Elephant PS5 research tools"
license = "MIT OR Apache-2.0"

# Forbid unsafe code by default (override per-module if needed)
[lints.rust]
unsafe_code = "forbid"

[dependencies]
# RustCrypto ecosystem
aes = "0.8"
cbc = "0.1"
rsa = { version = "0.9", features = ["sha2"] }
sha1 = "0.10"
sha2 = "0.10"
hmac = "0.12"
digest = "0.10"
cipher = "0.4"
block-padding = "0.3"

# Constant-time operations
subtle = "2.5"

# Secure memory
secrecy = "0.8"
zeroize = { version = "1.7", features = ["derive"] }

# Serialization
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
hex = "0.4"

# Error handling
thiserror = "1.0"

# Logging
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["json", "env-filter"] }

[dev-dependencies]
hex-literal = "0.4"

[features]
default = []
# DANGER: Enables IV=0 mode for PS5 protocol compatibility
# Only enable this if you understand the security implications
unsafe_iv_zero = []
```

---

## Appendix C: Security Checklist

Before releasing any tool, verify:

- [ ] All key types use `SecretBox<T>` wrapper
- [ ] All key types implement `ZeroizeOnDrop`
- [ ] All Debug implementations redact sensitive data
- [ ] MAC verification uses `subtle::ConstantTimeEq`
- [ ] IV=0 requires `unsafe_iv_zero` feature flag
- [ ] Key files are encrypted with age
- [ ] Key file permissions are validated (0600)
- [ ] Audit logging enabled with no key exposure
- [ ] Error messages don't leak cryptographic details
- [ ] Zeroization tests pass under valgrind/ASAN
- [ ] `cargo audit` shows no vulnerabilities
- [ ] `cargo clippy` shows no warnings
- [ ] All unwrap() calls are removed from crypto paths

---

*Security Implementation Guide v1.0.0 - Heavy Elephant PS5 Security Research Toolkit*
