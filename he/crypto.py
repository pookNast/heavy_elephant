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
