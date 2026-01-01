# heavy_elephant Architecture Audit Report

**Date:** 2025-12-31
**Auditor:** Claude (Architecture Reviewer)
**Plan Reference:** `/home/pook/.claude/plans/encapsulated-stargazing-biscuit.md`
**Project Status:** Pre-implementation (structure created, no code)

---

## Executive Summary

This report audits the proposed architecture for `heavy_elephant`, a PS5 security research toolkit. The plan specifies a Rust workspace with 6 crates (1 shared library + 5 tools). Overall assessment: **Well-designed with minor recommendations**.

---

## 1. Rust Workspace Structure Audit

### Proposed Structure
```
heavy_elephant/
├── Cargo.toml              # Workspace manifest
├── crates/
│   ├── he-crypto/          # Shared crypto library
│   ├── boot-decryptor/     # Tool 1
│   ├── pkg-manager/        # Tool 2
│   ├── self-patcher/       # Tool 3
│   ├── m2-analyzer/        # Tool 4
│   └── ucmd-auth/          # Tool 5
├── keys/                   # Key material (JSON)
└── tests/integration/      # Integration tests
```

### Assessment: GOOD

| Aspect | Status | Notes |
|--------|--------|-------|
| Workspace layout | ✅ | Standard `crates/` pattern is idiomatic |
| Shared library separation | ✅ | `he-crypto` centralizes crypto ops |
| Key material isolation | ✅ | Separate `keys/` directory is secure |
| Integration test location | ✅ | Standard Rust convention |

### Recommendations

1. **Add `Cargo.lock` to version control** - For reproducible builds in security tooling
2. **Consider `xtask` pattern** - Add `crates/xtask/` for build automation scripts
3. **Add `.cargo/config.toml`** - Configure default target, linker optimizations

### Suggested Cargo.toml (Workspace Root)
```toml
[workspace]
resolver = "2"
members = [
    "crates/he-crypto",
    "crates/boot-decryptor",
    "crates/pkg-manager",
    "crates/self-patcher",
    "crates/m2-analyzer",
    "crates/ucmd-auth",
]

[workspace.package]
version = "0.1.0"
edition = "2021"
license = "MIT"
authors = ["heavy_elephant contributors"]
rust-version = "1.75"

[workspace.dependencies]
# Crypto
aes = "0.8"
cbc = "0.1"
rsa = "0.9"
sha1 = "0.10"
hmac = "0.12"

# Utilities
hex = "0.4"
clap = { version = "4", features = ["derive"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
thiserror = "1"
anyhow = "1"

# Testing
proptest = "1"
```

---

## 2. he-crypto Library Design Audit

### Proposed Modules
```
he-crypto/src/
├── lib.rs
├── aes_ops.rs
├── rsa_ops.rs
└── keys.rs
```

### Assessment: NEEDS EXPANSION

The current design is minimal. For a comprehensive crypto library, recommend:

```
he-crypto/src/
├── lib.rs              # Public API re-exports
├── error.rs            # Custom error types
├── keys/
│   ├── mod.rs          # Key management
│   ├── loader.rs       # JSON key loading
│   ├── types.rs        # Key type definitions
│   └── validate.rs     # Key validation
├── aes/
│   ├── mod.rs          # AES operations
│   ├── cbc.rs          # AES-128-CBC (zeroed IV)
│   └── modes.rs        # Other modes if needed
├── rsa/
│   ├── mod.rs          # RSA operations
│   ├── sign.rs         # Signing (CRT params)
│   ├── verify.rs       # Signature verification
│   └── encrypt.rs      # RSA encryption
├── hmac_sha1.rs        # HMAC-SHA1 for MAC verification
└── traits.rs           # Common traits (Decrypt, Verify)
```

### Critical Design Recommendations

1. **Error Handling**
```rust
// he-crypto/src/error.rs
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Key loading failed: {0}")]
    KeyLoad(#[from] std::io::Error),

    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("MAC verification failed")]
    MacVerificationFailed,

    #[error("RSA operation failed: {0}")]
    RsaError(#[from] rsa::Error),
}

pub type Result<T> = std::result::Result<T, CryptoError>;
```

2. **Zero-IV AES-CBC Abstraction**
```rust
// he-crypto/src/aes/cbc.rs
use aes::Aes128;
use cbc::{Decryptor, cipher::BlockDecryptMut, cipher::KeyIvInit};

pub struct Aes128CbcZeroIv {
    key: [u8; 16],
}

impl Aes128CbcZeroIv {
    pub fn new(key: &[u8]) -> Result<Self> {
        if key.len() != 16 {
            return Err(CryptoError::InvalidKeyLength {
                expected: 16,
                actual: key.len()
            });
        }
        let mut k = [0u8; 16];
        k.copy_from_slice(key);
        Ok(Self { key: k })
    }

    pub fn decrypt(&self, data: &mut [u8]) -> Result<()> {
        let iv = [0u8; 16];
        let decryptor = Decryptor::<Aes128>::new(&self.key.into(), &iv.into());
        decryptor.decrypt_padded_mut::<NoPadding>(data)
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
        Ok(())
    }
}
```

3. **Key Type Safety**
```rust
// he-crypto/src/keys/types.rs
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AesKey {
    #[serde(with = "hex")]
    pub key: [u8; 16],
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RsaPrivateKey {
    #[serde(with = "hex")]
    pub n: Vec<u8>,
    #[serde(with = "hex")]
    pub d: Vec<u8>,
    #[serde(with = "hex")]
    pub p: Vec<u8>,
    #[serde(with = "hex")]
    pub q: Vec<u8>,
    #[serde(with = "hex")]
    pub dp: Vec<u8>,
    #[serde(with = "hex")]
    pub dq: Vec<u8>,
    #[serde(with = "hex")]
    pub qp: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootChainKeys {
    pub emc_ipl_header: AesKey,
    pub emc_ipl_cipher: AesKey,
    pub eap_kbl: AesKey,
    pub eap_kbl_mac: AesKey,
    pub eap_kernel: AesKey,
    pub eap_kernel_mac: AesKey,
}
```

---

## 3. Interface Consistency Audit

### Recommended Trait Hierarchy

All tools should implement consistent traits for interoperability:

```rust
// he-crypto/src/traits.rs

/// Core decryption trait
pub trait Decrypt {
    type Input;
    type Output;
    type Error;

    fn decrypt(&self, input: Self::Input) -> Result<Self::Output, Self::Error>;
}

/// MAC verification trait
pub trait VerifyMac {
    fn verify_mac(&self, data: &[u8], expected: &[u8]) -> bool;
}

/// Key loading trait
pub trait KeyLoader {
    type Keys;
    fn load_from_path(path: &Path) -> Result<Self::Keys>;
}
```

### CLI Interface Consistency

Each tool should follow the same CLI pattern:

```
<tool> [OPTIONS] <COMMAND>

Commands:
  decrypt    Decrypt input file
  verify     Verify MAC/signature only
  info       Display file structure info

Options:
  -k, --keys <PATH>    Path to keys directory [default: ./keys]
  -o, --output <PATH>  Output path
  -v, --verbose        Verbose output
  --json               Output as JSON
```

### Recommended: Shared CLI Crate

Consider adding `crates/he-cli-common/` for shared CLI utilities:
- Common argument parsing
- Progress bars
- Error formatting
- JSON output helpers

---

## 4. CI/CD Recommendations

### GitHub Actions Workflow

```yaml
# .github/workflows/ci.yml
name: CI

on:
  push:
    branches: [main]
  pull_request:

env:
  CARGO_TERM_COLOR: always
  RUSTFLAGS: -D warnings

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: clippy, rustfmt
      - uses: Swatinem/rust-cache@v2

      - name: Format check
        run: cargo fmt --all -- --check

      - name: Clippy
        run: cargo clippy --all-targets --all-features -- -D warnings

      - name: Build
        run: cargo build --all-targets

      - name: Test
        run: cargo test --all-targets

  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable

      - name: Install cargo-audit
        run: cargo install cargo-audit

      - name: Security audit
        run: cargo audit

  coverage:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable

      - name: Install cargo-llvm-cov
        uses: taiki-e/install-action@cargo-llvm-cov

      - name: Generate coverage
        run: cargo llvm-cov --all-features --lcov --output-path lcov.info

      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          files: lcov.info
```

### Pre-commit Hooks

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: cargo-fmt
        name: cargo fmt
        entry: cargo fmt --all --
        language: system
        types: [rust]
        pass_filenames: false

      - id: cargo-clippy
        name: cargo clippy
        entry: cargo clippy --all-targets -- -D warnings
        language: system
        types: [rust]
        pass_filenames: false
```

### Release Workflow

```yaml
# .github/workflows/release.yml
name: Release

on:
  push:
    tags: ['v*']

jobs:
  build:
    strategy:
      matrix:
        include:
          - target: x86_64-unknown-linux-gnu
            os: ubuntu-latest
          - target: x86_64-apple-darwin
            os: macos-latest
          - target: x86_64-pc-windows-msvc
            os: windows-latest

    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          targets: ${{ matrix.target }}

      - name: Build release
        run: cargo build --release --target ${{ matrix.target }}

      - name: Upload artifacts
        uses: actions/upload-artifact@v4
        with:
          name: heavy_elephant-${{ matrix.target }}
          path: target/${{ matrix.target }}/release/
```

---

## 5. Integration Test Strategy

### Test File Structure

```
tests/
├── integration/
│   ├── mod.rs
│   ├── boot_chain_test.rs
│   ├── pkg_test.rs
│   ├── self_test.rs
│   ├── m2_test.rs
│   └── ucmd_test.rs
└── fixtures/
    ├── README.md           # Describes how to generate test data
    ├── synthetic/          # Generated test data
    │   ├── boot_sample.bin
    │   ├── pkg_sample.pkg
    │   └── self_sample.self
    └── expected/           # Expected outputs
        ├── boot_decrypted.bin
        └── pkg_decrypted.bin
```

### Integration Test Patterns

```rust
// tests/integration/boot_chain_test.rs
use he_crypto::keys::BootChainKeys;
use boot_decryptor::BootChainDecryptor;

#[test]
fn test_emc_ipl_header_decrypt() {
    let keys = BootChainKeys::load_test_keys();
    let decryptor = BootChainDecryptor::new(keys);

    let encrypted = include_bytes!("../fixtures/synthetic/emc_ipl_header.bin");
    let expected = include_bytes!("../fixtures/expected/emc_ipl_header_dec.bin");

    let mut buffer = encrypted.to_vec();
    decryptor.decrypt_emc_ipl_header(&mut buffer).unwrap();

    assert_eq!(&buffer[..], expected);
}

#[test]
fn test_full_boot_chain_pipeline() {
    let keys = BootChainKeys::load_test_keys();
    let decryptor = BootChainDecryptor::new(keys);

    let input = include_bytes!("../fixtures/synthetic/full_boot.bin");
    let result = decryptor.decrypt_full_chain(input).unwrap();

    assert!(result.emc_ipl_header.is_some());
    assert!(result.emc_ipl_body.is_some());
    assert!(result.eap_kbl.is_some());
    assert!(result.eap_kernel.is_some());
}
```

### Test Data Generation Strategy

Since real PS5 firmware cannot be distributed, use synthetic test data:

1. **Known Answer Tests (KAT)** - Encrypt known plaintext with the keys, verify decryption
2. **Round-trip Tests** - Encrypt then decrypt, verify equality
3. **Edge Cases** - Empty input, malformed headers, corrupted MAC

```rust
// tests/fixtures/generate_test_data.rs
//! Run with: cargo run --bin generate-test-data

fn main() {
    // Generate synthetic test data by encrypting known plaintext
    let plaintext = b"KNOWN_PLAINTEXT_FOR_TESTING_1234";
    let key = hex::decode("F0332357C8CFAE7E7E26E52BE9E3AED4").unwrap();

    let encrypted = aes_128_cbc_zero_iv_encrypt(&key, plaintext);
    std::fs::write("tests/fixtures/synthetic/emc_ipl_header.bin", &encrypted).unwrap();
    std::fs::write("tests/fixtures/expected/emc_ipl_header_dec.bin", plaintext).unwrap();
}
```

### Coverage Requirements

| Component | Minimum Coverage |
|-----------|------------------|
| he-crypto | 90% |
| boot-decryptor | 80% |
| pkg-manager | 80% |
| self-patcher | 80% |
| m2-analyzer | 80% |
| ucmd-auth | 80% |

---

## 6. Dependency Graph

```
                          ┌─────────────────────────────────────────────┐
                          │          External Dependencies             │
                          │  aes, cbc, rsa, sha1, hmac, hex, clap      │
                          │  serde, serde_json, thiserror, anyhow      │
                          └─────────────────────────────────────────────┘
                                              │
                                              ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                              he-crypto (v0.1.0)                              │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌───────────────┐  │
│  │  keys/   │  │   aes/   │  │   rsa/   │  │hmac_sha1 │  │   traits.rs   │  │
│  │loader.rs │  │  cbc.rs  │  │ sign.rs  │  │          │  │Decrypt,Verify │  │
│  │types.rs  │  │ modes.rs │  │verify.rs │  │          │  │               │  │
│  │validate  │  │          │  │encrypt.rs│  │          │  │               │  │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘  └───────────────┘  │
└──────────────────────────────────────────────────────────────────────────────┘
                                              │
              ┌───────────────────────────────┼───────────────────────────────┐
              │                               │                               │
              ▼                               ▼                               ▼
┌─────────────────────┐         ┌─────────────────────┐         ┌─────────────────────┐
│  boot-decryptor     │         │    pkg-manager      │         │   self-patcher      │
│  (v0.1.0)           │         │    (v0.1.0)         │         │   (v0.1.0)          │
│                     │         │                     │         │                     │
│  Dependencies:      │         │  Dependencies:      │         │  Dependencies:      │
│  - he-crypto        │         │  - he-crypto        │         │  - he-crypto        │
│  - clap             │         │  - clap             │         │  - clap             │
│                     │         │                     │         │                     │
│  Uses:              │         │  Uses:              │         │  Uses:              │
│  - AES-128-CBC      │         │  - RSA (full CRT)   │         │  - AES-128-CBC      │
│  - HMAC-SHA1        │         │  - AES-128-CBC      │         │  - RSA verify       │
└─────────────────────┘         └─────────────────────┘         └─────────────────────┘
              │                               │                               │
              └───────────────────────────────┴───────────────────────────────┘
                                              │
              ┌───────────────────────────────┼───────────────────────────────┐
              │                               │                               │
              ▼                               ▼                               ▼
┌─────────────────────┐         ┌─────────────────────┐         ┌─────────────────────┐
│  m2-analyzer        │         │    ucmd-auth        │         │ tests/integration/  │
│  (v0.1.0)           │         │    (v0.1.0)         │         │                     │
│                     │         │                     │         │  All crates         │
│  Dependencies:      │         │  Dependencies:      │         │  + proptest         │
│  - he-crypto        │         │  - he-crypto        │         │                     │
│  - clap             │         │  - clap             │         │                     │
│                     │         │                     │         │                     │
│  Uses:              │         │  Uses:              │         │                     │
│  - AES-128          │         │  - RSA auth         │         │                     │
│  - (simple keys)    │         │  - Key3 ops         │         │                     │
└─────────────────────┘         └─────────────────────┘         └─────────────────────┘
```

### Dependency Summary Table

| Crate | Direct Dependencies | Dev Dependencies |
|-------|---------------------|------------------|
| he-crypto | aes, cbc, rsa, sha1, hmac, hex, serde, serde_json, thiserror | proptest |
| boot-decryptor | he-crypto, clap, anyhow | proptest |
| pkg-manager | he-crypto, clap, anyhow | proptest |
| self-patcher | he-crypto, clap, anyhow | proptest |
| m2-analyzer | he-crypto, clap, anyhow | proptest |
| ucmd-auth | he-crypto, clap, anyhow | proptest |

---

## 7. Security Considerations

### Key Material Handling

1. **Never log keys** - Ensure keys are not printed in error messages or debug output
2. **Secure key loading** - Use `secrecy` crate for in-memory key protection
3. **Memory zeroization** - Clear sensitive data from memory after use

```rust
// Add to he-crypto/Cargo.toml
secrecy = "0.8"
zeroize = { version = "1", features = ["derive"] }
```

```rust
// he-crypto/src/keys/types.rs
use secrecy::{ExposeSecret, SecretVec};
use zeroize::Zeroize;

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct SecureAesKey {
    key: SecretVec<u8>,
}
```

### Crypto Implementation Review

- Prefer high-level `aes`/`cbc` crate abstractions over raw implementations
- Use constant-time comparison for MAC verification (`subtle` crate)
- Validate all input lengths before crypto operations

---

## 8. Recommendations Summary

### High Priority

| # | Recommendation | Effort |
|---|----------------|--------|
| 1 | Expand he-crypto module structure | Medium |
| 2 | Add `thiserror` error types | Low |
| 3 | Implement consistent CLI interface | Medium |
| 4 | Set up GitHub Actions CI | Low |

### Medium Priority

| # | Recommendation | Effort |
|---|----------------|--------|
| 5 | Add `secrecy`/`zeroize` for key handling | Low |
| 6 | Create synthetic test data generator | Medium |
| 7 | Add `xtask` for build automation | Low |
| 8 | Set up pre-commit hooks | Low |

### Low Priority

| # | Recommendation | Effort |
|---|----------------|--------|
| 9 | Add shared `he-cli-common` crate | Medium |
| 10 | Configure code coverage reporting | Low |
| 11 | Add release workflow | Low |

---

## 9. Implementation Order

Based on dependencies and priority:

```
Phase 1: Foundation
  1. Create workspace Cargo.toml with workspace.dependencies
  2. Implement he-crypto with full module structure
  3. Add key loading and validation

Phase 2: Priority Tool
  4. Implement boot-decryptor (uses he-crypto)
  5. Create synthetic test data
  6. Write integration tests

Phase 3: Remaining Tools (Parallelizable)
  7. pkg-manager
  8. self-patcher
  9. m2-analyzer
  10. ucmd-auth

Phase 4: Polish
  11. Unified CLI experience
  12. Documentation
  13. CI/CD setup
```

---

## Appendix A: Suggested Cargo.toml Files

### Workspace Root
```toml
[workspace]
resolver = "2"
members = ["crates/*"]

[workspace.package]
version = "0.1.0"
edition = "2021"
license = "MIT"
rust-version = "1.75"

[workspace.dependencies]
# Internal
he-crypto = { path = "crates/he-crypto" }

# Crypto
aes = "0.8"
cbc = "0.1"
rsa = "0.9"
sha1 = "0.10"
hmac = "0.12"
subtle = "2.5"

# Utilities
hex = "0.4"
clap = { version = "4", features = ["derive"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
thiserror = "1"
anyhow = "1"
secrecy = "0.8"
zeroize = { version = "1", features = ["derive"] }

# Testing
proptest = "1"
```

### he-crypto/Cargo.toml
```toml
[package]
name = "he-crypto"
version.workspace = true
edition.workspace = true

[dependencies]
aes.workspace = true
cbc.workspace = true
rsa.workspace = true
sha1.workspace = true
hmac.workspace = true
subtle.workspace = true
hex.workspace = true
serde.workspace = true
serde_json.workspace = true
thiserror.workspace = true
secrecy.workspace = true
zeroize.workspace = true

[dev-dependencies]
proptest.workspace = true
```

### boot-decryptor/Cargo.toml
```toml
[package]
name = "boot-decryptor"
version.workspace = true
edition.workspace = true

[[bin]]
name = "boot-decryptor"
path = "src/main.rs"

[dependencies]
he-crypto.workspace = true
clap.workspace = true
anyhow.workspace = true
hex.workspace = true

[dev-dependencies]
proptest.workspace = true
```

---

**Report Generated:** 2025-12-31
**Next Steps:** Implement recommendations in priority order, beginning with workspace Cargo.toml and he-crypto module structure.
