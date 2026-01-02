#!/usr/bin/env python3
"""
Security Tests for PS5 M.2 Tool

Focus on security-critical aspects:
- Key validation and bounds checking
- Constant-time comparison protection against timing attacks
- Input validation and error handling
- Cryptographic operation security
"""
import sys
from pathlib import Path
import pytest
import json
import time

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from he.crypto import (
    aes_ecb_decrypt,
    aes_ecb_encrypt,
    constant_time_compare,
    aes_cbc_decrypt,
    aes_cbc_encrypt,
)
from he.keys import load_m2_keys


# ============================================================================
# Key Loading Security Tests
# ============================================================================

def test_load_m2_keys_valid():
    """Test loading valid M.2 keys."""
    keys_path = Path(__file__).parent.parent / 'keys' / 'm2_keys.json'

    if not keys_path.exists():
        pytest.skip("M.2 keys file not found")

    keys = load_m2_keys(str(keys_path))

    assert 'metadata_key' in keys
    assert 'encryption_key' in keys
    assert len(keys['metadata_key']) == 16, "Metadata key must be 16 bytes (AES-128)"
    assert len(keys['encryption_key']) == 16, "Encryption key must be 16 bytes (AES-128)"


def test_load_m2_keys_wrong_length(tmp_path):
    """Test that keys with wrong length are rejected."""
    # Create key file with wrong-length keys
    invalid_keys = {
        "metadata_verification_key": "0123456789ABCDEF",  # Only 8 bytes
        "default_encryption_key": "0123456789ABCDEF0123456789ABCDEF"  # 16 bytes
    }

    key_file = tmp_path / "invalid_keys.json"
    key_file.write_text(json.dumps(invalid_keys))

    with pytest.raises(ValueError, match="Invalid metadata key length"):
        load_m2_keys(str(key_file))


def test_load_m2_keys_invalid_hex(tmp_path):
    """Test that invalid hex strings are rejected."""
    invalid_keys = {
        "metadata_verification_key": "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",  # Invalid hex
        "default_encryption_key": "0123456789ABCDEF0123456789ABCDEF"
    }

    key_file = tmp_path / "invalid_hex.json"
    key_file.write_text(json.dumps(invalid_keys))

    with pytest.raises(ValueError):
        load_m2_keys(str(key_file))


def test_load_m2_keys_missing_fields(tmp_path):
    """Test that missing required fields are detected."""
    incomplete_keys = {
        "metadata_verification_key": "0123456789ABCDEF0123456789ABCDEF"
        # Missing default_encryption_key
    }

    key_file = tmp_path / "incomplete_keys.json"
    key_file.write_text(json.dumps(incomplete_keys))

    with pytest.raises(KeyError):
        load_m2_keys(str(key_file))


# ============================================================================
# AES ECB Security Tests
# ============================================================================

def test_aes_ecb_decrypt_valid():
    """Test AES-ECB decryption with valid input."""
    key = b'0123456789ABCDEF'  # 16 bytes
    plaintext = b'Hello World!!!!!'  # 16 bytes

    # Encrypt then decrypt
    ciphertext = aes_ecb_encrypt(key, plaintext)
    decrypted = aes_ecb_decrypt(key, ciphertext)

    assert decrypted == plaintext


def test_aes_ecb_invalid_key_length():
    """Test that invalid key lengths are rejected."""
    short_key = b'short'
    data = b'0123456789ABCDEF'

    with pytest.raises(ValueError, match="Key must be 16 bytes"):
        aes_ecb_encrypt(short_key, data)

    with pytest.raises(ValueError, match="Key must be 16 bytes"):
        aes_ecb_decrypt(short_key, data)


def test_aes_ecb_misaligned_data():
    """Test that misaligned data is rejected."""
    key = b'0123456789ABCDEF'
    misaligned_data = b'Not 16-byte aligned!'

    with pytest.raises(ValueError, match="Data must be 16-byte aligned"):
        aes_ecb_encrypt(key, misaligned_data)

    with pytest.raises(ValueError, match="Data must be 16-byte aligned"):
        aes_ecb_decrypt(key, misaligned_data)


def test_aes_ecb_multiple_blocks():
    """Test AES-ECB with multiple blocks."""
    key = b'0123456789ABCDEF'
    plaintext = b'Block 1 here!!!!' b'Block 2 here!!!!'  # 32 bytes (2 blocks)

    ciphertext = aes_ecb_encrypt(key, plaintext)
    assert len(ciphertext) == 32

    decrypted = aes_ecb_decrypt(key, ciphertext)
    assert decrypted == plaintext


def test_aes_ecb_pattern_leakage():
    """
    Security test: Verify ECB mode pattern leakage (educational).

    ECB mode encrypts identical plaintext blocks to identical ciphertext blocks.
    This is a known weakness - this test documents it for educational purposes.
    """
    key = b'0123456789ABCDEF'

    # Two identical blocks
    plaintext = b'AAAAAAAAAAAAAAAA' b'AAAAAAAAAAAAAAAA'
    ciphertext = aes_ecb_encrypt(key, plaintext)

    # First and second blocks should be identical (demonstrating ECB weakness)
    block1 = ciphertext[0:16]
    block2 = ciphertext[16:32]

    assert block1 == block2, "ECB mode encrypts identical blocks identically (known weakness)"


# ============================================================================
# Constant-Time Comparison Tests (Timing Attack Protection)
# ============================================================================

def test_constant_time_compare_equal():
    """Test constant-time comparison with equal values."""
    a = b'secret_value_123'
    b = b'secret_value_123'

    assert constant_time_compare(a, b) is True


def test_constant_time_compare_different():
    """Test constant-time comparison with different values."""
    a = b'secret_value_123'
    b = b'secret_value_456'

    assert constant_time_compare(a, b) is False


def test_constant_time_compare_different_lengths():
    """Test that different lengths return False immediately."""
    a = b'short'
    b = b'much_longer_value'

    assert constant_time_compare(a, b) is False


def test_constant_time_compare_single_bit_difference():
    """Test with single-bit difference (most sensitive timing case)."""
    a = b'secret_value_123'
    b = b'secret_value_124'  # Last character differs by 1

    assert constant_time_compare(a, b) is False


def test_constant_time_compare_empty():
    """Test constant-time comparison with empty values."""
    assert constant_time_compare(b'', b'') is True
    assert constant_time_compare(b'', b'x') is False


def test_constant_time_timing_consistency():
    """
    Security test: Verify timing consistency (basic check).

    This test attempts to verify that comparison time doesn't leak
    information about where the difference occurs. Note: this is a
    basic check and not a rigorous timing attack analysis.
    """
    key = b'0123456789ABCDEF'

    # Test cases: difference at start vs end
    early_diff = b'X123456789ABCDEF'  # First byte differs
    late_diff = b'0123456789ABCDEX'   # Last byte differs

    # Measure timing for early difference
    iterations = 1000
    start = time.perf_counter()
    for _ in range(iterations):
        constant_time_compare(key, early_diff)
    early_time = time.perf_counter() - start

    # Measure timing for late difference
    start = time.perf_counter()
    for _ in range(iterations):
        constant_time_compare(key, late_diff)
    late_time = time.perf_counter() - start

    # Times should be similar (within 50% for this basic test)
    # Note: This is a weak check - proper timing attack analysis requires
    # sophisticated statistical methods
    time_ratio = max(early_time, late_time) / min(early_time, late_time)
    assert time_ratio < 1.5, f"Timing ratio {time_ratio} suggests potential timing leak"


# ============================================================================
# Input Validation Security Tests
# ============================================================================

def test_aes_operations_with_null_bytes():
    """Test that null bytes in data don't cause issues."""
    key = b'0123456789ABCDEF'
    data = b'\x00' * 16  # All null bytes

    ciphertext = aes_ecb_encrypt(key, data)
    decrypted = aes_ecb_decrypt(key, ciphertext)

    assert decrypted == data


def test_aes_operations_with_high_bytes():
    """Test with high byte values (0xFF)."""
    key = b'0123456789ABCDEF'
    data = b'\xFF' * 16  # All 0xFF bytes

    ciphertext = aes_ecb_encrypt(key, data)
    decrypted = aes_ecb_decrypt(key, ciphertext)

    assert decrypted == data


def test_key_immutability():
    """Test that encryption doesn't modify the key."""
    key = bytearray(b'0123456789ABCDEF')
    key_copy = bytes(key)
    data = b'Test data here!!'

    aes_ecb_encrypt(bytes(key), data)

    assert bytes(key) == key_copy, "Encryption should not modify key"


# ============================================================================
# Known Answer Tests (KAT) for Regression Detection
# ============================================================================

def test_aes_ecb_known_answer():
    """
    Known Answer Test: Verify AES-ECB produces expected output.

    This helps detect regressions in crypto implementation.
    Test vector from NIST AES test suite.
    """
    # NIST test vector
    key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
    plaintext = bytes.fromhex('6bc1bee22e409f96e93d7e117393172a')
    expected_ciphertext = bytes.fromhex('3ad77bb40d7a3660a89ecaf32466ef97')

    ciphertext = aes_ecb_encrypt(key, plaintext)

    assert ciphertext == expected_ciphertext, "AES-ECB output doesn't match NIST test vector"


def test_aes_ecb_decrypt_known_answer():
    """Known Answer Test for AES-ECB decryption."""
    key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
    ciphertext = bytes.fromhex('3ad77bb40d7a3660a89ecaf32466ef97')
    expected_plaintext = bytes.fromhex('6bc1bee22e409f96e93d7e117393172a')

    plaintext = aes_ecb_decrypt(key, ciphertext)

    assert plaintext == expected_plaintext, "AES-ECB decryption doesn't match NIST test vector"


# ============================================================================
# Security Boundary Tests
# ============================================================================

def test_maximum_size_data():
    """Test encryption with large data (boundary test)."""
    key = b'0123456789ABCDEF'
    # Test with 1MB of data
    data = b'A' * (1024 * 1024)

    # Ensure it's 16-byte aligned
    if len(data) % 16 != 0:
        data += b'\x00' * (16 - len(data) % 16)

    ciphertext = aes_ecb_encrypt(key, data)
    decrypted = aes_ecb_decrypt(key, ciphertext)

    assert decrypted == data


def test_wrong_key_produces_garbage():
    """Security test: Verify that wrong key produces unusable output."""
    correct_key = b'0123456789ABCDEF'
    wrong_key = b'FEDCBA9876543210'
    plaintext = b'Secret message!!'

    ciphertext = aes_ecb_encrypt(correct_key, plaintext)
    wrong_decryption = aes_ecb_decrypt(wrong_key, ciphertext)

    # Decryption with wrong key should NOT produce original plaintext
    assert wrong_decryption != plaintext, "Wrong key must not decrypt correctly"


# ============================================================================
# Integration Security Tests
# ============================================================================

def test_m2_key_format_validation():
    """
    Security test: Verify M.2 keys match expected hardcoded values.

    Per PSDevWiki research, these keys are hardcoded across all
    PS5 firmware versions (1.00-12.20).
    """
    keys_path = Path(__file__).parent.parent / 'keys' / 'm2_keys.json'

    if not keys_path.exists():
        pytest.skip("M.2 keys file not found")

    keys = load_m2_keys(str(keys_path))

    # Verify expected values from PSDevWiki
    expected_metadata = bytes.fromhex('012345678901234567890123456789AB')
    expected_encryption = bytes.fromhex('01234567890123456789012345678901')

    assert constant_time_compare(keys['metadata_key'], expected_metadata), \
        "Metadata key doesn't match PSDevWiki documented value"
    assert constant_time_compare(keys['encryption_key'], expected_encryption), \
        "Encryption key doesn't match PSDevWiki documented value"


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
