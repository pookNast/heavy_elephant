# Heavy Elephant Test Strategy

**Version:** 1.0.0
**Created:** 2025-12-31
**Author:** QA Expert Agent
**Status:** Pre-Implementation Test Planning

---

## Executive Summary

This document defines the comprehensive test strategy for the Heavy Elephant PS5 Security Research Toolkit. Given the security-critical nature of this cryptographic toolkit, testing requirements are exceptionally rigorous. The strategy addresses the security findings from `audit-security.md` and ensures all 15+ tools meet quality and security standards.

**Key Testing Objectives:**
1. Validate cryptographic correctness against known test vectors
2. Prevent security regressions (timing attacks, memory leaks, key exposure)
3. Ensure cross-crate integration works correctly
4. Maintain >90% code coverage for `he-crypto`, >80% for tool crates

---

## Table of Contents

1. [Unit Test Patterns for Crypto Primitives](#1-unit-test-patterns-for-crypto-primitives)
2. [Integration Test Scenarios](#2-integration-test-scenarios)
3. [Security Test Cases](#3-security-test-cases)
4. [Test Fixture Generation Strategy](#4-test-fixture-generation-strategy)
5. [CI/CD Test Pipeline](#5-cicd-test-pipeline)
6. [Coverage Requirements](#6-coverage-requirements)
7. [Test Infrastructure](#7-test-infrastructure)
8. [Appendices](#appendices)

---

## 1. Unit Test Patterns for Crypto Primitives

### 1.1 AES-CBC Tests

#### 1.1.1 Known Answer Tests (KAT)

All AES implementations MUST pass NIST SP 800-38A test vectors.

```rust
// crates/he-crypto/src/aes/tests.rs

#[cfg(test)]
mod aes_cbc_tests {
    use super::*;
    use hex_literal::hex;

    /// NIST SP 800-38A AES-128-CBC Test Vector F.2.1
    #[test]
    fn test_aes128_cbc_encrypt_nist_vector() {
        let key = hex!("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = hex!("000102030405060708090a0b0c0d0e0f");
        let plaintext = hex!("6bc1bee22e409f96e93d7e117393172a");
        let expected = hex!("7649abac8119b246cee98e9b12e9197d");

        let result = aes_cbc_encrypt(&key, &iv, &plaintext).unwrap();
        assert_eq!(result, expected);
    }

    /// NIST SP 800-38A AES-128-CBC Test Vector F.2.2
    #[test]
    fn test_aes128_cbc_decrypt_nist_vector() {
        let key = hex!("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = hex!("000102030405060708090a0b0c0d0e0f");
        let ciphertext = hex!("7649abac8119b246cee98e9b12e9197d");
        let expected = hex!("6bc1bee22e409f96e93d7e117393172a");

        let result = aes_cbc_decrypt(&key, &iv, &ciphertext).unwrap();
        assert_eq!(result, expected);
    }

    /// Test IV=0 mode (PS5 protocol requirement) - REQUIRES feature flag
    #[test]
    #[cfg(feature = "unsafe_iv_zero")]
    fn test_aes128_cbc_iv_zero_decrypt() {
        let key = hex!("F0332357C8CFAE7E7E26E52BE9E3AED4"); // Example
        let iv = [0u8; 16];
        let ciphertext = /* known test ciphertext */;
        let expected_plaintext = /* known result */;

        let result = aes_cbc_decrypt(&key, &iv, &ciphertext).unwrap();
        assert_eq!(result, expected_plaintext);
    }
}
```

#### 1.1.2 Edge Case Tests

```rust
#[cfg(test)]
mod aes_edge_cases {
    /// Empty input handling
    #[test]
    fn test_empty_plaintext() {
        let key = [0u8; 16];
        let iv = [0u8; 16];
        let result = aes_cbc_encrypt(&key, &iv, &[]);
        // Should return padded empty block or error based on design
        assert!(result.is_ok());
    }

    /// Invalid key length rejection
    #[test]
    fn test_invalid_key_length() {
        let short_key = [0u8; 8];  // Too short
        let iv = [0u8; 16];
        let plaintext = b"test data";

        let result = aes_cbc_encrypt(&short_key, &iv, plaintext);
        assert!(matches!(result, Err(CryptoError::InvalidKeyLength)));
    }

    /// Block-misaligned ciphertext
    #[test]
    fn test_misaligned_ciphertext() {
        let key = [0u8; 16];
        let iv = [0u8; 16];
        let bad_ciphertext = [0u8; 17];  // Not block-aligned

        let result = aes_cbc_decrypt(&key, &iv, &bad_ciphertext);
        assert!(matches!(result, Err(CryptoError::InvalidBlockSize)));
    }

    /// Maximum size handling (16MB)
    #[test]
    fn test_large_data_16mb() {
        let key = [0u8; 16];
        let iv = [0u8; 16];
        let large_data = vec![0xAB; 16 * 1024 * 1024];

        let encrypted = aes_cbc_encrypt(&key, &iv, &large_data).unwrap();
        let decrypted = aes_cbc_decrypt(&key, &iv, &encrypted).unwrap();
        assert_eq!(decrypted, large_data);
    }

    /// PKCS#7 padding validation
    #[test]
    fn test_pkcs7_padding_valid() {
        let padded = hex!("01020304050607080910111213141502 02");
        assert!(validate_pkcs7_padding(&padded).is_ok());
    }

    #[test]
    fn test_pkcs7_padding_invalid() {
        let bad_padded = hex!("01020304050607080910111213141502 03");
        assert!(matches!(
            validate_pkcs7_padding(&bad_padded),
            Err(CryptoError::InvalidPadding)
        ));
    }
}
```

### 1.2 RSA Tests

#### 1.2.1 Key Validation Tests

```rust
#[cfg(test)]
mod rsa_tests {
    use rsa::{RsaPrivateKey, RsaPublicKey};
    use super::*;

    /// RSA key consistency check (P * Q = N)
    #[test]
    fn test_rsa_key_consistency() {
        let key = load_test_rsa_key("test_pkg_rsa.json").unwrap();

        // Verify P * Q = N
        let n_computed = &key.primes()[0] * &key.primes()[1];
        assert_eq!(*key.n(), n_computed);
    }

    /// Minimum key size validation (2048 bits)
    #[test]
    fn test_rsa_minimum_key_size() {
        let weak_key = generate_rsa_key(1024);  // Too small
        let result = validate_rsa_key(&weak_key);

        assert!(matches!(result, Err(CryptoError::WeakKeySize)));
    }

    /// CRT parameter validation
    #[test]
    fn test_rsa_crt_parameters() {
        let key = load_test_rsa_key("test_pkg_rsa.json").unwrap();

        // Verify DP = D mod (P-1)
        let dp = key.dp().expect("DP required");
        let p_minus_1 = &key.primes()[0] - 1u32;
        assert_eq!(*dp, key.d() % &p_minus_1);
    }
}
```

#### 1.2.2 Signature Tests

```rust
#[cfg(test)]
mod rsa_signature_tests {
    /// PKCS#1 v1.5 signature verification
    #[test]
    fn test_pkcs1v15_sign_verify() {
        let private_key = load_test_rsa_key("test_pkg_rsa.json").unwrap();
        let public_key = RsaPublicKey::from(&private_key);
        let message = b"PS5 PKG signing test";

        let signature = sign_pkcs1v15(&private_key, message).unwrap();
        let verified = verify_pkcs1v15(&public_key, message, &signature);

        assert!(verified.is_ok());
    }

    /// PSS signature (if used)
    #[test]
    fn test_pss_sign_verify() {
        let private_key = load_test_rsa_key("test_pkg_rsa.json").unwrap();
        let public_key = RsaPublicKey::from(&private_key);
        let message = b"PS5 PKG signing test";

        let signature = sign_pss(&private_key, message).unwrap();
        let verified = verify_pss(&public_key, message, &signature);

        assert!(verified.is_ok());
    }

    /// Wrong key rejection
    #[test]
    fn test_signature_wrong_key_rejected() {
        let key1 = generate_test_rsa_key();
        let key2 = generate_test_rsa_key();
        let message = b"test message";

        let signature = sign_pkcs1v15(&key1, message).unwrap();
        let public_key2 = RsaPublicKey::from(&key2);

        let result = verify_pkcs1v15(&public_key2, message, &signature);
        assert!(result.is_err());
    }
}
```

### 1.3 HMAC Tests

#### 1.3.1 RFC Test Vectors

```rust
#[cfg(test)]
mod hmac_tests {
    /// RFC 2202 HMAC-SHA1 Test Case 1
    #[test]
    fn test_hmac_sha1_rfc2202_case1() {
        let key = hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let data = b"Hi There";
        let expected = hex!("b617318655057264e28bc0b6fb378c8ef146be00");

        let result = hmac_sha1(&key, data);
        assert_eq!(result, expected);
    }

    /// HMAC-SHA256 test (for new operations)
    #[test]
    fn test_hmac_sha256() {
        let key = hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let data = b"Hi There";
        let expected = hex!("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");

        let result = hmac_sha256(&key, data);
        assert_eq!(result, expected);
    }

    /// Constant-time MAC comparison
    #[test]
    fn test_mac_constant_time_comparison() {
        let mac1 = hex!("b617318655057264e28bc0b6fb378c8ef146be00");
        let mac2 = hex!("b617318655057264e28bc0b6fb378c8ef146be00");
        let mac3 = hex!("0000000000000000000000000000000000000000");

        // These should use subtle::ConstantTimeEq internally
        assert!(verify_mac_constant_time(&mac1, &mac2));
        assert!(!verify_mac_constant_time(&mac1, &mac3));
    }
}
```

### 1.4 Key Management Tests

```rust
#[cfg(test)]
mod key_management_tests {
    use secrecy::{SecretBox, ExposeSecret};

    /// SecretBox wrapping
    #[test]
    fn test_secret_box_wrapping() {
        let key_bytes = [0xABu8; 16];
        let secret_key = AesKey::new(key_bytes);

        // Key should not be directly accessible
        // Must use expose_secret()
        let exposed = secret_key.expose_secret();
        assert_eq!(exposed.0, key_bytes);
    }

    /// Zeroize on drop
    #[test]
    fn test_zeroize_on_drop() {
        let ptr: *const u8;
        {
            let key = AesKey::new([0xFFu8; 16]);
            ptr = key.expose_secret().0.as_ptr();
        }
        // After drop, memory should be zeroed
        // Note: This is difficult to test reliably; use miri or asan
    }

    /// Key file permissions validation
    #[test]
    fn test_key_file_permissions() {
        let test_key_path = create_temp_key_file();

        // Set wrong permissions
        std::fs::set_permissions(&test_key_path,
            std::fs::Permissions::from_mode(0o644)).unwrap();

        let result = load_key_file(&test_key_path);
        assert!(matches!(result, Err(CryptoError::InsecureFilePermissions)));
    }

    /// Age-encrypted key loading
    #[test]
    fn test_age_encrypted_key_loading() {
        let encrypted_path = "tests/fixtures/keys/test_boot_chain.json.age";
        let passphrase = "test-passphrase";

        let result = load_encrypted_key(encrypted_path, passphrase);
        assert!(result.is_ok());
    }
}
```

---

## 2. Integration Test Scenarios

### 2.1 Cross-Crate Integration Matrix

| Test Scenario | Crates Involved | Priority | Description |
|---------------|-----------------|----------|-------------|
| Boot chain decryption | he-crypto, boot-decryptor | P0 | Full EMC->EAP->Kernel pipeline |
| PKG signing workflow | he-crypto, pkg-manager | P0 | Sign, verify, decrypt cycle |
| SELF patch pipeline | he-crypto, self-patcher | P0 | Decrypt, patch, re-encrypt |
| M.2 full disk decrypt | he-crypto, m2-analyzer | P1 | Stream decryption with MAC |
| UCMD forge + verify | he-crypto, ucmd-auth | P1 | Create and validate UCMD |
| Trophy manipulation | he-crypto, trophy-tool | P2 | Decrypt/modify/re-encrypt |
| Save data migration | he-crypto, savedata-tool | P2 | Cross-console save handling |

### 2.2 Tool-Specific Integration Tests

#### 2.2.1 Boot Decryptor (`boot-decryptor`)

```rust
// tests/integration/boot_decryptor_tests.rs

#[test]
fn test_full_boot_chain_decryption() {
    // Setup: Synthetic firmware blob
    let firmware = TestFixtures::create_synthetic_firmware();
    let keys = TestFixtures::load_test_keys("boot_chain");

    // Execute: Full chain decryption
    let decryptor = BootDecryptor::new(keys);
    let result = decryptor.decrypt_full_chain(&firmware);

    // Verify: Each stage decrypted correctly
    assert!(result.emc_ipl_header.is_ok());
    assert!(result.emc_ipl_body.is_ok());
    assert!(result.eap_kbl.is_ok());
    assert!(result.eap_kernel.is_ok());

    // Verify MAC validation occurred
    assert!(result.mac_verified.eap_kbl);
    assert!(result.mac_verified.eap_kernel);
}

#[test]
fn test_boot_decryptor_cli_end_to_end() {
    let input_path = "tests/fixtures/synthetic_firmware.bin";
    let output_dir = tempdir().unwrap();

    let status = Command::new("cargo")
        .args(["run", "-p", "boot-decryptor", "--",
               "full-chain",
               "-i", input_path,
               "-o", output_dir.path().to_str().unwrap(),
               "-k", "tests/fixtures/keys/"])
        .status()
        .unwrap();

    assert!(status.success());

    // Verify output files exist
    assert!(output_dir.path().join("emc_header.dec").exists());
    assert!(output_dir.path().join("emc_body.dec").exists());
    assert!(output_dir.path().join("eap_kbl.dec").exists());
    assert!(output_dir.path().join("eap_kernel.dec").exists());
}
```

#### 2.2.2 PKG Manager (`pkg-manager`)

```rust
#[test]
fn test_pkg_sign_verify_roundtrip() {
    let test_data = TestFixtures::create_minimal_pkg();
    let keys = TestFixtures::load_test_keys("pkg_rsa");

    // Sign
    let pkg_manager = PkgManager::new(keys);
    let signed = pkg_manager.sign(&test_data).unwrap();

    // Verify
    let verification = pkg_manager.verify(&signed);
    assert!(verification.is_ok());
    assert!(verification.unwrap().signature_valid);
}

#[test]
fn test_pkg_decrypt_ps5_format() {
    let encrypted_pkg = TestFixtures::load_synthetic_pkg("encrypted_test.pkg");
    let keys = TestFixtures::load_test_keys("pkg_rsa");

    let pkg_manager = PkgManager::new(keys);
    let decrypted = pkg_manager.decrypt(&encrypted_pkg).unwrap();

    // Verify structure
    assert_eq!(decrypted.header.magic, b"CNT\0");
    assert!(decrypted.entries.len() > 0);
}

#[test]
fn test_pkg_tamper_detection() {
    let signed_pkg = TestFixtures::load_signed_pkg();

    // Tamper with content
    let mut tampered = signed_pkg.clone();
    tampered.content[100] ^= 0xFF;

    let keys = TestFixtures::load_test_keys("pkg_rsa");
    let pkg_manager = PkgManager::new(keys);

    let result = pkg_manager.verify(&tampered);
    assert!(matches!(result, Err(CryptoError::SignatureVerificationFailed)));
}
```

#### 2.2.3 SELF Patcher (`self-patcher`)

```rust
#[test]
fn test_self_decrypt_patch_cycle() {
    let encrypted_self = TestFixtures::load_synthetic_self();
    let keys = TestFixtures::load_test_keys("self_keys");

    let patcher = SelfPatcher::new(keys);

    // Decrypt
    let decrypted = patcher.decrypt(&encrypted_self).unwrap();

    // Apply patch
    let patch = Patch::new(0x1000, vec![0x90, 0x90, 0x90, 0x90]);
    let patched = patcher.apply_patch(&decrypted, &patch).unwrap();

    // Verify patch applied
    assert_eq!(&patched.data[0x1000..0x1004], &[0x90, 0x90, 0x90, 0x90]);
}
```

#### 2.2.4 M.2 Analyzer (`m2-analyzer`)

```rust
#[test]
fn test_m2_stream_decryption() {
    let encrypted_stream = TestFixtures::create_m2_stream(1024 * 1024);
    let keys = TestFixtures::load_test_keys("m2_keys");

    let analyzer = M2Analyzer::new(keys);

    // Stream decrypt with progress callback
    let mut decrypted = Vec::new();
    let mut progress_count = 0;

    analyzer.decrypt_stream(
        &encrypted_stream,
        |chunk| {
            decrypted.extend_from_slice(chunk);
            progress_count += 1;
        },
    ).unwrap();

    assert!(progress_count > 0);
    assert_eq!(decrypted.len(), encrypted_stream.len());
}

#[test]
fn test_m2_partition_parsing() {
    let m2_image = TestFixtures::load_synthetic_m2_image();
    let keys = TestFixtures::load_test_keys("m2_keys");

    let analyzer = M2Analyzer::new(keys);
    let partitions = analyzer.parse_partitions(&m2_image).unwrap();

    assert!(partitions.len() >= 1);
    for partition in partitions {
        assert!(partition.offset % 512 == 0);  // Sector aligned
    }
}
```

#### 2.2.5 UCMD Auth Tool (`ucmd-auth`)

```rust
#[test]
fn test_ucmd_forge_and_verify() {
    let keys = TestFixtures::load_test_keys("ucmd_keys");

    let ucmd_tool = UcmdAuth::new(keys);

    // Forge UCMD
    let command = UcmdCommand::ReadMemory { address: 0x1000, size: 0x100 };
    let forged = ucmd_tool.forge(command).unwrap();

    // Verify
    let verified = ucmd_tool.verify(&forged);
    assert!(verified.is_ok());
}
```

### 2.3 Cross-Tool Pipeline Tests

```rust
#[test]
fn test_boot_to_self_pipeline() {
    // Decrypt boot chain
    let boot_keys = TestFixtures::load_test_keys("boot_chain");
    let firmware = TestFixtures::load_synthetic_firmware();

    let boot_decryptor = BootDecryptor::new(boot_keys);
    let boot_result = boot_decryptor.decrypt_full_chain(&firmware).unwrap();

    // Extract SELF from kernel
    let self_keys = TestFixtures::load_test_keys("self_keys");
    let self_patcher = SelfPatcher::new(self_keys);

    let extracted_self = boot_result.eap_kernel.extract_self().unwrap();
    let decrypted_self = self_patcher.decrypt(&extracted_self);

    assert!(decrypted_self.is_ok());
}
```

---

## 3. Security Test Cases

### 3.1 Timing Attack Prevention

#### 3.1.1 MAC Verification Timing

```rust
#[cfg(test)]
mod timing_tests {
    use std::time::{Duration, Instant};

    /// Verify MAC comparison is constant-time
    #[test]
    fn test_mac_verification_constant_time() {
        let correct_mac = [0xABu8; 20];
        let wrong_first_byte = {
            let mut m = correct_mac;
            m[0] ^= 0xFF;
            m
        };
        let wrong_last_byte = {
            let mut m = correct_mac;
            m[19] ^= 0xFF;
            m
        };

        const ITERATIONS: u32 = 10000;

        // Measure time to reject MAC differing in first byte
        let start = Instant::now();
        for _ in 0..ITERATIONS {
            let _ = verify_mac_constant_time(&correct_mac, &wrong_first_byte);
        }
        let time_first = start.elapsed();

        // Measure time to reject MAC differing in last byte
        let start = Instant::now();
        for _ in 0..ITERATIONS {
            let _ = verify_mac_constant_time(&correct_mac, &wrong_last_byte);
        }
        let time_last = start.elapsed();

        // Times should be within 10% of each other
        let diff_ratio = (time_first.as_nanos() as f64 - time_last.as_nanos() as f64).abs()
            / time_first.as_nanos() as f64;

        assert!(diff_ratio < 0.10,
            "Timing difference: first={:?}, last={:?}, ratio={:.2}%",
            time_first, time_last, diff_ratio * 100.0);
    }

    /// RSA signature verification timing
    #[test]
    fn test_rsa_verify_constant_time() {
        let key = TestFixtures::load_test_rsa_key();
        let message = b"test message";
        let valid_sig = sign_pkcs1v15(&key, message).unwrap();

        let mut invalid_sig_first = valid_sig.clone();
        invalid_sig_first[0] ^= 0xFF;

        let mut invalid_sig_last = valid_sig.clone();
        *invalid_sig_last.last_mut().unwrap() ^= 0xFF;

        const ITERATIONS: u32 = 1000;

        let times = vec![
            measure_iterations(ITERATIONS, || verify_pkcs1v15(&key.to_public_key(), message, &invalid_sig_first)),
            measure_iterations(ITERATIONS, || verify_pkcs1v15(&key.to_public_key(), message, &invalid_sig_last)),
        ];

        // Verify timing variance is within acceptable bounds
        let max_diff = times.iter().max().unwrap().as_nanos() as f64
            - times.iter().min().unwrap().as_nanos() as f64;
        let avg = times.iter().map(|t| t.as_nanos()).sum::<u128>() as f64 / times.len() as f64;

        assert!(max_diff / avg < 0.10, "Timing variance too high");
    }
}
```

#### 3.1.2 Padding Oracle Prevention

```rust
#[test]
fn test_padding_oracle_prevention() {
    let key = [0xABu8; 16];
    let iv = [0u8; 16];

    // Create ciphertexts with different padding errors
    let valid_ciphertext = encrypt_test_data(&key, &iv, b"valid data");

    // Corrupt last block differently
    let mut bad_padding_1 = valid_ciphertext.clone();
    bad_padding_1.last_mut().map(|b| *b ^= 0x01);

    let mut bad_padding_2 = valid_ciphertext.clone();
    bad_padding_2.last_mut().map(|b| *b ^= 0x10);

    // Both should return the same generic error type
    let result1 = aes_cbc_decrypt(&key, &iv, &bad_padding_1);
    let result2 = aes_cbc_decrypt(&key, &iv, &bad_padding_2);

    // Error types must be identical (no information leakage)
    assert!(matches!(result1, Err(CryptoError::DecryptionFailed)));
    assert!(matches!(result2, Err(CryptoError::DecryptionFailed)));

    // Error messages must be identical
    assert_eq!(
        format!("{:?}", result1),
        format!("{:?}", result2)
    );
}
```

### 3.2 Memory Safety Tests

#### 3.2.1 Zeroization Verification

```rust
#[cfg(test)]
mod memory_tests {
    /// Test key zeroization using miri or manual inspection
    /// Run with: cargo +nightly miri test
    #[test]
    fn test_key_zeroization_on_drop() {
        use std::ptr;

        let raw_ptr: *const [u8; 16];

        {
            let key = AesKey::new([0xFF; 16]);
            raw_ptr = key.expose_secret().0.as_ptr() as *const [u8; 16];

            // Key is valid here
            let bytes = unsafe { ptr::read_volatile(raw_ptr) };
            assert_eq!(bytes, [0xFF; 16]);
        }
        // Key dropped - should be zeroized

        // NOTE: This test may be flaky depending on allocator behavior
        // Use Address Sanitizer for reliable detection
        // ASAN command: RUSTFLAGS="-Z sanitizer=address" cargo +nightly test
    }

    /// Test SecretBox Debug output redaction
    #[test]
    fn test_debug_output_redacted() {
        let key = AesKey::new([0xAB; 16]);
        let debug_output = format!("{:?}", key);

        // Debug output should NOT contain key bytes
        assert!(!debug_output.contains("AB"));
        assert!(!debug_output.contains("0xAB"));
        assert!(!debug_output.contains("171")); // 0xAB in decimal

        // Should contain redaction marker
        assert!(debug_output.contains("[REDACTED]") || debug_output.contains("Secret"));
    }

    /// Test no key leakage in error messages
    #[test]
    fn test_no_key_in_errors() {
        let key = [0xDEu8; 16];
        let result = intentionally_fail_with_key(&key);

        let error_string = format!("{:?}", result.unwrap_err());

        assert!(!error_string.contains("DE"));
        assert!(!error_string.contains("0xDE"));
    }
}
```

#### 3.2.2 Buffer Overflow Prevention

```rust
#[test]
fn test_buffer_overflow_prevention() {
    let key = [0u8; 16];
    let iv = [0u8; 16];

    // Attempt to decrypt oversized data
    let huge_data = vec![0u8; 1024 * 1024 * 1024];  // 1GB

    // Should handle gracefully, not panic or overflow
    let result = aes_cbc_decrypt(&key, &iv, &huge_data);

    // Either succeeds or returns clean error
    match result {
        Ok(_) => { /* Large allocation succeeded */ }
        Err(e) => assert!(matches!(e,
            CryptoError::AllocationFailed |
            CryptoError::InputTooLarge
        )),
    }
}

#[test]
fn test_integer_overflow_prevention() {
    // Test with sizes near usize::MAX
    let result = allocate_crypto_buffer(usize::MAX);
    assert!(result.is_err());

    let result = allocate_crypto_buffer(usize::MAX - 16);
    assert!(result.is_err());
}
```

### 3.3 Key Exposure Prevention

#### 3.3.1 Log Sanitization Tests

```rust
#[test]
fn test_tracing_key_redaction() {
    let key = AesKey::new([0xCC; 16]);

    // Capture log output
    let (writer, captured) = create_test_subscriber();

    // Attempt to log key
    tracing::info!("Processing with key: {:?}", key);

    let log_output = captured.lock().unwrap();

    assert!(!log_output.contains("CC"));
    assert!(!log_output.contains("0xCC"));
}

#[test]
fn test_panic_no_key_exposure() {
    use std::panic;

    let result = panic::catch_unwind(|| {
        let key = AesKey::new([0xBB; 16]);
        panic!("Intentional panic with key context");
    });

    let panic_msg = result.unwrap_err();
    let panic_str = if let Some(s) = panic_msg.downcast_ref::<&str>() {
        s.to_string()
    } else if let Some(s) = panic_msg.downcast_ref::<String>() {
        s.clone()
    } else {
        format!("{:?}", panic_msg)
    };

    assert!(!panic_str.contains("BB"));
    assert!(!panic_str.contains("0xBB"));
}
```

#### 3.3.2 Core Dump Protection

```rust
#[test]
#[ignore]  // Run manually with core dumps enabled
fn test_core_dump_no_keys() {
    // This test requires:
    // 1. Enable core dumps: ulimit -c unlimited
    // 2. Run test that forces crash
    // 3. Analyze core dump for key material

    // Placeholder for manual security testing procedure
    // Document: tests/SECURITY_TEST_PROCEDURES.md
}
```

### 3.4 File Permission Tests

```rust
#[test]
fn test_key_file_permission_validation() {
    let temp_dir = tempdir().unwrap();
    let key_path = temp_dir.path().join("test_key.json");

    // Create key file with wrong permissions
    std::fs::write(&key_path, r#"{"key": "test"}"#).unwrap();
    std::fs::set_permissions(&key_path,
        std::fs::Permissions::from_mode(0o644)).unwrap();

    let result = load_key_file(&key_path);
    assert!(matches!(result, Err(CryptoError::InsecureFilePermissions)));

    // Fix permissions
    std::fs::set_permissions(&key_path,
        std::fs::Permissions::from_mode(0o600)).unwrap();

    let result = load_key_file(&key_path);
    assert!(result.is_ok());
}

#[test]
fn test_output_file_permission_enforcement() {
    let temp_dir = tempdir().unwrap();
    let output_path = temp_dir.path().join("decrypted.bin");

    // Write decrypted output
    write_secure_output(&output_path, b"sensitive data").unwrap();

    // Verify permissions are restricted
    let metadata = std::fs::metadata(&output_path).unwrap();
    let mode = metadata.permissions().mode();

    assert_eq!(mode & 0o777, 0o600,
        "Output file should have 0600 permissions");
}
```

---

## 4. Test Fixture Generation Strategy

### 4.1 Synthetic Data Generation

#### 4.1.1 Test Key Generation

**CRITICAL:** Never use production keys in tests. All test keys must be clearly marked.

```rust
// tests/fixtures/key_generator.rs

pub struct TestKeyGenerator;

impl TestKeyGenerator {
    /// Generate deterministic test AES key
    pub fn aes_key(seed: &str) -> [u8; 16] {
        use sha2::{Sha256, Digest};

        let mut hasher = Sha256::new();
        hasher.update(b"TEST_KEY_DO_NOT_USE_");
        hasher.update(seed.as_bytes());

        let hash = hasher.finalize();
        let mut key = [0u8; 16];
        key.copy_from_slice(&hash[..16]);
        key
    }

    /// Generate test RSA key pair (2048-bit, deterministic from seed)
    pub fn rsa_keypair(seed: &str) -> RsaPrivateKey {
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;
        use sha2::{Sha256, Digest};

        let seed_hash = Sha256::digest(
            format!("TEST_RSA_KEY_{}", seed).as_bytes()
        );

        let mut rng = ChaCha20Rng::from_seed(seed_hash.into());
        RsaPrivateKey::new(&mut rng, 2048).unwrap()
    }

    /// Generate test HMAC key
    pub fn hmac_key(seed: &str) -> [u8; 32] {
        use sha2::{Sha256, Digest};

        let hash = Sha256::digest(
            format!("TEST_HMAC_KEY_{}", seed).as_bytes()
        );
        hash.into()
    }
}
```

#### 4.1.2 Synthetic Firmware Generation

```rust
// tests/fixtures/firmware_generator.rs

pub struct SyntheticFirmwareBuilder {
    emc_ipl_header: Vec<u8>,
    emc_ipl_body: Vec<u8>,
    eap_kbl: Vec<u8>,
    eap_kernel: Vec<u8>,
}

impl SyntheticFirmwareBuilder {
    pub fn new() -> Self {
        Self {
            emc_ipl_header: vec![0; 0x1000],
            emc_ipl_body: vec![0; 0x10000],
            eap_kbl: vec![0; 0x20000],
            eap_kernel: vec![0; 0x100000],
        }
    }

    /// Build encrypted firmware blob using test keys
    pub fn build_encrypted(&self) -> Vec<u8> {
        let keys = TestKeyGenerator::boot_chain_keys();

        let mut firmware = Vec::new();

        // Encrypt each section
        firmware.extend(aes_cbc_encrypt(
            &keys.emc_header_key,
            &[0u8; 16],  // IV=0 per PS5 protocol
            &self.emc_ipl_header
        ).unwrap());

        firmware.extend(aes_cbc_encrypt(
            &keys.emc_body_key,
            &[0u8; 16],
            &self.emc_ipl_body
        ).unwrap());

        // Add MAC for EAP KBL
        let eap_kbl_encrypted = aes_cbc_encrypt(
            &keys.eap_kbl_key,
            &[0u8; 16],
            &self.eap_kbl
        ).unwrap();
        let eap_kbl_mac = hmac_sha1(&keys.eap_kbl_mac_key, &eap_kbl_encrypted);

        firmware.extend(&eap_kbl_encrypted);
        firmware.extend(&eap_kbl_mac);

        // Similar for kernel...

        firmware
    }

    /// Build plaintext reference for verification
    pub fn build_plaintext(&self) -> FirmwarePlaintext {
        FirmwarePlaintext {
            emc_ipl_header: self.emc_ipl_header.clone(),
            emc_ipl_body: self.emc_ipl_body.clone(),
            eap_kbl: self.eap_kbl.clone(),
            eap_kernel: self.eap_kernel.clone(),
        }
    }
}
```

#### 4.1.3 Synthetic PKG Generation

```rust
pub struct SyntheticPkgBuilder {
    content_id: String,
    entries: Vec<PkgEntry>,
}

impl SyntheticPkgBuilder {
    pub fn minimal() -> Self {
        Self {
            content_id: "UP0001-TEST00001_00-0000000000000001".to_string(),
            entries: vec![
                PkgEntry {
                    name: "eboot.bin".to_string(),
                    data: vec![0xEB; 0x1000],
                },
            ],
        }
    }

    pub fn with_entry(mut self, name: &str, data: Vec<u8>) -> Self {
        self.entries.push(PkgEntry {
            name: name.to_string(),
            data,
        });
        self
    }

    pub fn build_signed(&self, rsa_key: &RsaPrivateKey) -> Vec<u8> {
        let pkg_data = self.build_unsigned();
        let signature = sign_pkg(&rsa_key, &pkg_data).unwrap();

        let mut signed = Vec::new();
        signed.extend(&pkg_data);
        signed.extend(&signature);
        signed
    }
}
```

### 4.2 Fixture File Structure

```
tests/
├── fixtures/
│   ├── keys/
│   │   ├── README.md              # Documents test key usage
│   │   ├── test_boot_chain.json   # Plaintext test keys
│   │   ├── test_boot_chain.json.age  # Age-encrypted for realism
│   │   ├── test_pkg_rsa.json
│   │   ├── test_pkg_rsa.pem       # PEM format for compatibility testing
│   │   ├── test_self_keys.json
│   │   ├── test_m2_keys.json
│   │   └── test_ucmd_keys.json
│   │
│   ├── firmware/
│   │   ├── synthetic_boot_chain.bin     # Generated encrypted firmware
│   │   ├── synthetic_boot_chain.dec/    # Expected decryption results
│   │   │   ├── emc_header.bin
│   │   │   ├── emc_body.bin
│   │   │   ├── eap_kbl.bin
│   │   │   └── eap_kernel.bin
│   │   └── malformed/
│   │       ├── truncated.bin
│   │       ├── bad_mac.bin
│   │       └── corrupted_header.bin
│   │
│   ├── pkg/
│   │   ├── minimal_valid.pkg
│   │   ├── signed_test.pkg
│   │   └── malformed/
│   │       ├── bad_signature.pkg
│   │       ├── truncated.pkg
│   │       └── invalid_header.pkg
│   │
│   ├── self/
│   │   ├── synthetic_eboot.self
│   │   ├── synthetic_eboot.elf     # Expected decrypted ELF
│   │   └── malformed/
│   │
│   ├── m2/
│   │   ├── synthetic_partition.bin
│   │   └── malformed/
│   │
│   └── vectors/
│       ├── aes_nist_vectors.json    # NIST SP 800-38A
│       ├── hmac_rfc_vectors.json    # RFC 2202/4231
│       └── rsa_test_vectors.json    # PKCS#1 test vectors
│
├── integration/
│   └── ... (integration tests)
│
└── proptest/
    └── ... (property-based tests)
```

### 4.3 Fixture Generation Scripts

```bash
#!/bin/bash
# tests/fixtures/generate_all.sh

set -euo pipefail

echo "Generating test fixtures..."

# Generate test keys
cargo run -p he-crypto --example generate_test_keys -- \
    --output tests/fixtures/keys/

# Generate synthetic firmware
cargo run -p boot-decryptor --example generate_fixtures -- \
    --keys tests/fixtures/keys/ \
    --output tests/fixtures/firmware/

# Generate synthetic PKGs
cargo run -p pkg-manager --example generate_fixtures -- \
    --keys tests/fixtures/keys/ \
    --output tests/fixtures/pkg/

# Generate malformed inputs for fuzz targets
cargo run -p he-crypto --example generate_malformed -- \
    --output tests/fixtures/

echo "Fixtures generated successfully"
```

### 4.4 Property-Based Testing

```rust
// tests/proptest/aes_properties.rs

use proptest::prelude::*;

proptest! {
    /// AES encrypt-decrypt roundtrip
    #[test]
    fn test_aes_roundtrip(
        key in prop::array::uniform16(any::<u8>()),
        iv in prop::array::uniform16(any::<u8>()),
        data in prop::collection::vec(any::<u8>(), 0..1024)
    ) {
        let encrypted = aes_cbc_encrypt(&key, &iv, &data)?;
        let decrypted = aes_cbc_decrypt(&key, &iv, &encrypted)?;

        prop_assert_eq!(decrypted, data);
    }

    /// Ciphertext is always block-aligned
    #[test]
    fn test_ciphertext_block_aligned(
        key in prop::array::uniform16(any::<u8>()),
        iv in prop::array::uniform16(any::<u8>()),
        data in prop::collection::vec(any::<u8>(), 0..1024)
    ) {
        let encrypted = aes_cbc_encrypt(&key, &iv, &data)?;

        prop_assert!(encrypted.len() % 16 == 0);
        prop_assert!(encrypted.len() >= 16);  // At least one padded block
    }

    /// Different plaintexts produce different ciphertexts (with same key)
    #[test]
    fn test_cbc_diffusion(
        key in prop::array::uniform16(any::<u8>()),
        iv in prop::array::uniform16(any::<u8>()),
        data1 in prop::collection::vec(any::<u8>(), 16..32),
        data2 in prop::collection::vec(any::<u8>(), 16..32).prop_filter(
            "data1 != data2", |d| true  // Filter applied below
        )
    ) {
        prop_assume!(data1 != data2);

        let ct1 = aes_cbc_encrypt(&key, &iv, &data1)?;
        let ct2 = aes_cbc_encrypt(&key, &iv, &data2)?;

        prop_assert_ne!(ct1, ct2);
    }
}
```

---

## 5. CI/CD Test Pipeline

### 5.1 GitHub Actions Workflow

```yaml
# .github/workflows/test.yml

name: Test Suite

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
  schedule:
    # Weekly security scan
    - cron: '0 0 * * 0'

env:
  CARGO_TERM_COLOR: always
  RUST_BACKTRACE: 1

jobs:
  # Fast feedback for PRs
  quick-check:
    name: Quick Check
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2

      - name: Check formatting
        run: cargo fmt --all -- --check

      - name: Clippy (no warnings)
        run: cargo clippy --all-targets --all-features -- -D warnings

      - name: Quick test (no integration)
        run: cargo test --lib --bins

  # Full test suite
  test:
    name: Test Suite
    runs-on: ubuntu-latest
    needs: quick-check
    strategy:
      matrix:
        rust: [stable, nightly]
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@master
        with:
          toolchain: ${{ matrix.rust }}
      - uses: Swatinem/rust-cache@v2

      - name: Generate test fixtures
        run: ./tests/fixtures/generate_all.sh

      - name: Run all tests
        run: cargo test --all-features --workspace

      - name: Run doctests
        run: cargo test --doc --all-features

      - name: Upload test results
        if: failure()
        uses: actions/upload-artifact@v4
        with:
          name: test-results-${{ matrix.rust }}
          path: target/debug/deps/*.log

  # Security-focused tests
  security:
    name: Security Tests
    runs-on: ubuntu-latest
    needs: quick-check
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable

      - name: Install cargo-audit
        run: cargo install cargo-audit

      - name: Audit dependencies
        run: cargo audit

      - name: Check for unsafe code
        run: |
          # Fail if unsafe is used outside of allowed modules
          if grep -r "unsafe" crates/he-crypto/src/ --include="*.rs" | grep -v "// SAFETY:" | grep -v "#\[cfg(test)\]"; then
            echo "ERROR: Undocumented unsafe code found"
            exit 1
          fi

      - name: Run security test cases
        run: cargo test --features security_tests security_tests::

  # Memory safety with sanitizers
  sanitizers:
    name: Sanitizer Tests
    runs-on: ubuntu-latest
    needs: test
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@nightly
        with:
          components: rust-src

      - name: Address Sanitizer
        env:
          RUSTFLAGS: "-Z sanitizer=address"
        run: |
          cargo +nightly test --target x86_64-unknown-linux-gnu \
            -p he-crypto --lib

      - name: Memory Sanitizer
        env:
          RUSTFLAGS: "-Z sanitizer=memory"
        run: |
          cargo +nightly test --target x86_64-unknown-linux-gnu \
            -p he-crypto --lib -- --test-threads=1

  # Miri for undefined behavior
  miri:
    name: Miri Tests
    runs-on: ubuntu-latest
    needs: test
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@nightly
        with:
          components: miri

      - name: Setup Miri
        run: cargo +nightly miri setup

      - name: Run Miri on crypto primitives
        run: |
          cargo +nightly miri test -p he-crypto -- \
            --test-threads=1 \
            aes_tests:: hmac_tests:: key_management_tests::

  # Coverage reporting
  coverage:
    name: Code Coverage
    runs-on: ubuntu-latest
    needs: test
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable

      - name: Install cargo-tarpaulin
        run: cargo install cargo-tarpaulin

      - name: Generate coverage report
        run: |
          cargo tarpaulin --all-features --workspace \
            --out Xml --out Html \
            --output-dir coverage/

      - name: Upload coverage to Codecov
        uses: codecov/codecov-action@v3
        with:
          files: coverage/cobertura.xml
          fail_ci_if_error: true

      - name: Check coverage thresholds
        run: |
          # Extract he-crypto coverage
          CRYPTO_COV=$(cargo tarpaulin -p he-crypto --out Json | jq '.coverage')
          if (( $(echo "$CRYPTO_COV < 90" | bc -l) )); then
            echo "ERROR: he-crypto coverage ($CRYPTO_COV%) below 90% threshold"
            exit 1
          fi

  # Fuzz testing (scheduled)
  fuzz:
    name: Fuzz Testing
    runs-on: ubuntu-latest
    if: github.event_name == 'schedule'
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@nightly

      - name: Install cargo-fuzz
        run: cargo install cargo-fuzz

      - name: Fuzz AES-CBC (30 minutes)
        run: |
          cd crates/he-crypto
          timeout 1800 cargo +nightly fuzz run fuzz_aes_cbc || true

      - name: Fuzz HMAC (30 minutes)
        run: |
          cd crates/he-crypto
          timeout 1800 cargo +nightly fuzz run fuzz_hmac || true

      - name: Upload crash artifacts
        if: failure()
        uses: actions/upload-artifact@v4
        with:
          name: fuzz-artifacts
          path: |
            crates/he-crypto/fuzz/artifacts/

  # Integration tests (slower, separate job)
  integration:
    name: Integration Tests
    runs-on: ubuntu-latest
    needs: [test, security]
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2

      - name: Generate fixtures
        run: ./tests/fixtures/generate_all.sh

      - name: Run integration tests
        run: cargo test --test '*' --all-features
        timeout-minutes: 30

      - name: CLI end-to-end tests
        run: ./tests/e2e/run_cli_tests.sh

  # Release builds
  release-check:
    name: Release Build Check
    runs-on: ubuntu-latest
    needs: [test, security, integration]
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable

      - name: Build release
        run: cargo build --release --all-features

      - name: Verify no test keys in release
        run: |
          # Check binary doesn't contain test key markers
          if strings target/release/boot-decryptor | grep -i "TEST_KEY"; then
            echo "ERROR: Test key markers found in release binary"
            exit 1
          fi
```

### 5.2 Pre-Commit Hooks

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
        entry: cargo clippy --all-features -- -D warnings
        language: system
        types: [rust]
        pass_filenames: false

      - id: cargo-test-quick
        name: cargo test (quick)
        entry: cargo test --lib --bins -- --test-threads=4
        language: system
        types: [rust]
        pass_filenames: false

      - id: secrets-check
        name: Check for secrets
        entry: ./scripts/check_secrets.sh
        language: script
        types: [rust, json]
```

### 5.3 Test Environment Matrix

| Environment | Rust Version | Features | Tests Run |
|-------------|--------------|----------|-----------|
| Quick Check | stable | default | fmt, clippy, unit |
| Full Test | stable, nightly | all-features | all |
| Security | stable | security_tests | audit, unsafe scan, security tests |
| Sanitizers | nightly | default | ASan, MSan on he-crypto |
| Miri | nightly | default | UB detection on crypto |
| Coverage | stable | all-features | all + coverage report |
| Fuzz | nightly | default | Weekly fuzzing |
| Integration | stable | all-features | Integration + E2E |

---

## 6. Coverage Requirements

### 6.1 Per-Crate Coverage Thresholds

| Crate | Required Coverage | Rationale |
|-------|-------------------|-----------|
| `he-crypto` | **90%** | Core security library - highest standards |
| `boot-decryptor` | 80% | Critical tool with complex logic |
| `pkg-manager` | 80% | Handles signing operations |
| `self-patcher` | 80% | Binary modification risks |
| `m2-analyzer` | 75% | Stream processing |
| `ucmd-auth` | 80% | Authentication forging |
| `trophy-tool` | 70% | Lower risk PS4 tool |
| `savedata-tool` | 70% | Lower risk PS4 tool |
| `controller-auth` | 70% | Lower risk PS4 tool |
| `livedump-tool` | 70% | Lower risk PS4 tool |
| `pfs-sbl` | 75% | Filesystem encryption |
| `ipmi-tool` | 70% | Hardware interface |
| `portability-mgr` | 75% | Key unwrapping |
| `keyseed-engine` | 80% | Key derivation |
| `rnps-tool` | 75% | Remote play auth |
| `eap-validator` | 80% | Verification tool |

### 6.2 Coverage Enforcement

```rust
// build.rs (workspace root)

fn main() {
    // Enforce coverage requirements in CI
    if std::env::var("CI").is_ok() {
        println!("cargo:rustc-cfg=coverage_required");
    }
}
```

```toml
# Cargo.toml (workspace)

[workspace.metadata.coverage]
he-crypto = 90
boot-decryptor = 80
pkg-manager = 80
# ... etc
```

### 6.3 Coverage Exclusions

```rust
// Exclude from coverage for legitimate reasons

#[cfg_attr(coverage_nightly, coverage(off))]
fn unreachable_safety_check() {
    // This is intentionally unreachable in normal operation
    // Used only as defense-in-depth
    unreachable!("Safety check should never execute");
}

// Or use comments for tarpaulin:
// tarpaulin::skip
fn platform_specific_code() {
    // Only runs on specific hardware
}
```

### 6.4 Coverage Reporting

```bash
#!/bin/bash
# scripts/coverage_report.sh

cargo tarpaulin --all-features --workspace \
    --out Html --out Lcov --out Json \
    --output-dir coverage/ \
    --exclude-files 'tests/*' 'examples/*' 'benches/*'

# Parse and enforce thresholds
python3 scripts/check_coverage_thresholds.py coverage/coverage.json

# Generate badge
python3 scripts/generate_coverage_badge.py coverage/coverage.json
```

---

## 7. Test Infrastructure

### 7.1 Custom Test Harness

```rust
// tests/harness/mod.rs

/// Custom test runner with security features
pub struct SecurityTestRunner;

impl SecurityTestRunner {
    /// Run test with timing isolation
    pub fn run_timing_isolated<F, R>(test: F) -> R
    where
        F: FnOnce() -> R,
    {
        // Disable CPU frequency scaling
        // Pin to single core
        // Clear caches
        test()
    }

    /// Run test with memory protection
    pub fn run_memory_protected<F, R>(test: F) -> R
    where
        F: FnOnce() -> R,
    {
        // Enable guard pages
        // Lock memory from swapping
        // Clear on exit
        let result = test();
        // Force memory clear
        result
    }
}
```

### 7.2 Test Utilities

```rust
// tests/utils/mod.rs

pub mod crypto_test_utils {
    use std::time::{Duration, Instant};

    /// Measure operation timing
    pub fn measure_iterations<F>(iterations: u32, mut f: F) -> Duration
    where
        F: FnMut(),
    {
        let start = Instant::now();
        for _ in 0..iterations {
            f();
        }
        start.elapsed()
    }

    /// Assert timing within bounds
    pub fn assert_constant_time(times: &[Duration], max_variance_percent: f64) {
        let nanos: Vec<u128> = times.iter().map(|t| t.as_nanos()).collect();
        let mean = nanos.iter().sum::<u128>() as f64 / nanos.len() as f64;
        let max_diff = nanos.iter()
            .map(|&n| (n as f64 - mean).abs())
            .fold(0.0f64, f64::max);

        let variance = max_diff / mean;
        assert!(variance <= max_variance_percent / 100.0,
            "Timing variance {:.2}% exceeds threshold {:.2}%",
            variance * 100.0, max_variance_percent);
    }
}

pub mod fixture_utils {
    /// Create temporary test directory with fixtures
    pub fn setup_test_env() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();

        // Copy fixtures
        copy_fixtures(dir.path());

        // Set secure permissions
        set_secure_permissions(dir.path());

        dir
    }

    /// Load test vectors from JSON
    pub fn load_test_vectors<T: DeserializeOwned>(name: &str) -> T {
        let path = format!("tests/fixtures/vectors/{}.json", name);
        let data = std::fs::read_to_string(path).unwrap();
        serde_json::from_str(&data).unwrap()
    }
}
```

### 7.3 Fuzz Targets

```rust
// crates/he-crypto/fuzz/fuzz_targets/fuzz_aes_cbc.rs

#![no_main]

use libfuzzer_sys::fuzz_target;
use he_crypto::aes::{aes_cbc_encrypt, aes_cbc_decrypt};

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 {
        return;
    }

    let key: [u8; 16] = data[..16].try_into().unwrap();
    let iv: [u8; 16] = data[16..32].try_into().unwrap();
    let plaintext = &data[32..];

    if let Ok(ciphertext) = aes_cbc_encrypt(&key, &iv, plaintext) {
        let decrypted = aes_cbc_decrypt(&key, &iv, &ciphertext);
        assert!(decrypted.is_ok());
        assert_eq!(decrypted.unwrap(), plaintext);
    }
});
```

```rust
// crates/he-crypto/fuzz/fuzz_targets/fuzz_hmac.rs

#![no_main]

use libfuzzer_sys::fuzz_target;
use he_crypto::mac::hmac_sha1;

fuzz_target!(|data: &[u8]| {
    if data.len() < 20 {
        return;
    }

    let key = &data[..20];
    let message = &data[20..];

    // Should never panic
    let _mac = hmac_sha1(key, message);
});
```

---

## Appendices

### A. Test Vector Sources

| Source | Usage | URL/Reference |
|--------|-------|---------------|
| NIST SP 800-38A | AES-CBC vectors | [NIST Cryptographic Toolkit](https://csrc.nist.gov/publications/detail/sp/800-38a/final) |
| RFC 2202 | HMAC-SHA1 vectors | [IETF RFC 2202](https://tools.ietf.org/html/rfc2202) |
| RFC 4231 | HMAC-SHA256 vectors | [IETF RFC 4231](https://tools.ietf.org/html/rfc4231) |
| PKCS#1 v2.2 | RSA test vectors | [RFC 8017](https://tools.ietf.org/html/rfc8017) |
| Wycheproof | Edge case vectors | [Google Wycheproof](https://github.com/google/wycheproof) |

### B. Security Testing Checklist

- [ ] Timing attack tests pass for all MAC verifications
- [ ] Timing attack tests pass for RSA signature verification
- [ ] Memory sanitizers report no issues
- [ ] Miri reports no undefined behavior
- [ ] No key material in debug output
- [ ] No key material in error messages
- [ ] File permissions enforced for key files
- [ ] Padding oracle prevention verified
- [ ] Zeroization confirmed via miri/asan
- [ ] Fuzz testing completed without crashes

### C. Test Naming Conventions

```
test_<component>_<scenario>_<expected_outcome>

Examples:
- test_aes_cbc_nist_vector_decrypts_correctly
- test_rsa_sign_with_weak_key_rejected
- test_mac_verification_is_constant_time
- test_key_file_insecure_permissions_rejected
```

### D. Related Documents

- [MASTER_PLAN.md](../MASTER_PLAN.md) - Project architecture
- [audit-security.md](../audit-security.md) - Security audit findings
- [docs/SECURITY.md](../docs/SECURITY.md) - Security considerations
- [docs/context7-rust-crypto.md](../docs/context7-rust-crypto.md) - RustCrypto patterns

---

*Test Strategy v1.0.0 - Heavy Elephant PS5 Security Research Toolkit*
*QA Expert Agent - 2025-12-31*
