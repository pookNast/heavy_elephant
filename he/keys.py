"""
Heavy Elephant - Key Loading Utilities

Load cryptographic keys from JSON files.
"""
import json
from pathlib import Path
from typing import Dict, Any


def load_boot_chain_keys(path: str) -> Dict[str, bytes]:
    """
    Load boot chain decryption keys.

    Expected JSON format:
    {
        "emc_ipl_header": "hex...",
        "emc_ipl_cipher": "hex...",
        "eap_kbl": "hex...",
        "eap_kbl_mac": "hex...",
        "eap_kernel": "hex...",
        "eap_kernel_mac": "hex..."
    }
    """
    data = json.loads(Path(path).read_text())
    return {
        'emc_ipl_header': bytes.fromhex(data['emc_ipl_header']),
        'emc_ipl_cipher': bytes.fromhex(data['emc_ipl_cipher']),
        'eap_kbl': bytes.fromhex(data['eap_kbl']),
        'eap_kbl_mac': bytes.fromhex(data['eap_kbl_mac']),
        'eap_kernel': bytes.fromhex(data['eap_kernel']),
        'eap_kernel_mac': bytes.fromhex(data['eap_kernel_mac']),
    }


def load_pkg_keys(path: str) -> Dict[str, Any]:
    """
    Load PKG RSA keys.

    Expected JSON format:
    {
        "rsa_private_pem": "-----BEGIN RSA PRIVATE KEY-----...",
        "rsa_public_pem": "-----BEGIN PUBLIC KEY-----...",
        "content_key": "hex..."
    }

    OR for CRT format:
    {
        "n": "hex...",
        "e": "hex...",
        "d": "hex...",
        "p": "hex...",
        "q": "hex..."
    }
    """
    data = json.loads(Path(path).read_text())

    # Check if PEM format
    if 'rsa_private_pem' in data:
        return {
            'rsa_private': data['rsa_private_pem'],
            'rsa_public': data.get('rsa_public_pem', ''),
            'content_key': data.get('content_key', ''),
        }

    # CRT format - return raw hex for conversion
    return {
        'n': data.get('n', ''),
        'e': data.get('e', ''),
        'd': data.get('d', ''),
        'p': data.get('p', ''),
        'q': data.get('q', ''),
    }


def load_self_keys(path: str) -> Dict[str, str]:
    """
    Load SELF decryption keys.

    Expected JSON format:
    {
        "cipher_key": "hex...",
        "cipher_iv": "hex..."
    }
    """
    data = json.loads(Path(path).read_text())
    return {
        'cipher_key': data['cipher_key'],
        'cipher_iv': data['cipher_iv'],
    }


def load_raw_key(path: str) -> bytes:
    """Load a raw binary key file."""
    return Path(path).read_bytes()


def load_hex_key(path: str) -> bytes:
    """Load a key stored as hex string."""
    hex_str = Path(path).read_text().strip()
    return bytes.fromhex(hex_str)
