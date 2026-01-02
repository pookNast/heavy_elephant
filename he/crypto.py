"""
Heavy Elephant - Core Crypto Functions

AES-128-CBC, HMAC-SHA1, RSA operations for PS5 security research.
"""
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA1, SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from typing import Tuple


def aes_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    """AES-128-CBC decryption with PKCS7 unpadding."""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(data)
    # Remove PKCS7 padding
    pad_len = decrypted[-1]
    return decrypted[:-pad_len]


def aes_cbc_decrypt_no_pad(key: bytes, iv: bytes, data: bytes) -> bytes:
    """AES-128-CBC decryption without unpadding (for raw blocks)."""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(data)


def aes_cbc_decrypt_iv_zero(key: bytes, data: bytes) -> bytes:
    """
    AES-128-CBC with IV=0 (PS5 protocol requirement).

    WARNING: IV=0 is cryptographically weak but required by PS5 boot chain.
    """
    iv = b'\x00' * 16
    return aes_cbc_decrypt_no_pad(key, iv, data)


def aes_cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    """AES-128-CBC encryption with PKCS7 padding."""
    # PKCS7 padding
    pad_len = 16 - (len(data) % 16)
    padded = data + bytes([pad_len] * pad_len)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(padded)


def aes_cbc_encrypt_no_pad(key: bytes, iv: bytes, data: bytes) -> bytes:
    """AES-128-CBC encryption without padding (data must be block-aligned)."""
    assert len(data) % 16 == 0, "Data must be 16-byte aligned"
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(data)


def aes_cbc_encrypt_iv_zero(key: bytes, data: bytes) -> bytes:
    """AES-128-CBC encryption with IV=0."""
    iv = b'\x00' * 16
    return aes_cbc_encrypt_no_pad(key, iv, data)


def hmac_sha1(key: bytes, data: bytes) -> bytes:
    """Compute HMAC-SHA1."""
    h = HMAC.new(key, data, digestmod=SHA1)
    return h.digest()


def hmac_sha1_verify(key: bytes, data: bytes, expected_mac: bytes) -> bool:
    """
    Verify HMAC-SHA1 tag using constant-time comparison.

    Returns True if MAC is valid, False otherwise.
    """
    h = HMAC.new(key, data, digestmod=SHA1)
    try:
        h.verify(expected_mac)
        return True
    except ValueError:
        return False


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    """Compute HMAC-SHA256."""
    h = HMAC.new(key, data, digestmod=SHA256)
    return h.digest()


def hmac_sha256_verify(key: bytes, data: bytes, expected_mac: bytes) -> bool:
    """Verify HMAC-SHA256 tag."""
    h = HMAC.new(key, data, digestmod=SHA256)
    try:
        h.verify(expected_mac)
        return True
    except ValueError:
        return False


def rsa_sign_pkcs1v15(private_key: RSA.RsaKey, data: bytes) -> bytes:
    """Sign data with RSA PKCS#1 v1.5 using SHA-256."""
    h = SHA256.new(data)
    return pkcs1_15.new(private_key).sign(h)


def rsa_verify_pkcs1v15(public_key: RSA.RsaKey, data: bytes, signature: bytes) -> bool:
    """Verify RSA PKCS#1 v1.5 signature."""
    h = SHA256.new(data)
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False


def rsa_construct_from_crt(n: int, e: int, d: int, p: int, q: int) -> RSA.RsaKey:
    """Construct RSA key from CRT parameters."""
    return RSA.construct((n, e, d, p, q))


def aes_ecb_decrypt(key: bytes, data: bytes) -> bytes:
    """
    AES-128-ECB decryption (no IV).

    WARNING: ECB mode is cryptographically weak as it doesn't use an IV.
    Identical plaintext blocks produce identical ciphertext blocks.
    Only use when required by protocol specification (e.g., M.2 metadata).

    Args:
        key: 16-byte AES-128 key
        data: Data to decrypt (must be 16-byte aligned)

    Returns:
        Decrypted data

    Raises:
        ValueError: If data is not 16-byte aligned
    """
    if len(data) % 16 != 0:
        raise ValueError(f"Data must be 16-byte aligned, got {len(data)} bytes")
    if len(key) != 16:
        raise ValueError(f"Key must be 16 bytes for AES-128, got {len(key)} bytes")

    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(data)


def aes_ecb_encrypt(key: bytes, data: bytes) -> bytes:
    """
    AES-128-ECB encryption (no IV).

    WARNING: ECB mode is cryptographically weak. Use only when required
    by protocol specification.

    Args:
        key: 16-byte AES-128 key
        data: Data to encrypt (must be 16-byte aligned)

    Returns:
        Encrypted data

    Raises:
        ValueError: If data is not 16-byte aligned
    """
    if len(data) % 16 != 0:
        raise ValueError(f"Data must be 16-byte aligned, got {len(data)} bytes")
    if len(key) != 16:
        raise ValueError(f"Key must be 16 bytes for AES-128, got {len(key)} bytes")

    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(data)


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """
    Constant-time byte comparison to prevent timing attacks.

    This function compares two byte sequences in constant time,
    preventing timing side-channel attacks when comparing secrets
    like HMACs, passwords, or verification keys.

    Args:
        a: First byte sequence
        b: Second byte sequence

    Returns:
        True if sequences are equal, False otherwise

    Security Note:
        Always use this function when comparing cryptographic values
        to prevent timing-based information leakage.
    """
    if len(a) != len(b):
        return False

    result = 0
    for x, y in zip(a, b):
        result |= x ^ y

    return result == 0
