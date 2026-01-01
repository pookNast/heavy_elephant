# Heavy Elephant: PS5 Security Research Toolkit - Master Plan

**Version:** 3.0.0 (Python Rewrite)
**Created:** 2025-12-31
**Last Updated:** 2025-12-31
**Status:** READY FOR IMPLEMENTATION

---

## Executive Summary

Heavy Elephant is a focused Python toolkit for PS5 security research, consisting of 3 high-utility tools for firmware decryption, package management, and executable analysis.

**Language:** Python 3.11+
**Crypto Library:** pycryptodome
**Philosophy:** Fast iteration, research-friendly, community-compatible

---

## Tool Inventory (3 High-Utility Tools)

| # | Tool | Script | Purpose | Key Material |
|---|------|--------|---------|--------------|
| 1 | **Boot Chain Decryptor** | `ps5_boot_decrypt.py` | Decrypt PS5 boot sequence | EMC IPL, EAP KBL, Kernel keys |
| 2 | **PKG Manager** | `ps5_pkg_tool.py` | Sign/decrypt/forge PKG files | Full RSA private key (CRT) |
| 3 | **SELF Decryptor** | `ps5_self_tool.py` | Decrypt/patch SELF executables | SELF cipher key + IV |

### Why These 3?

- **Boot Chain Decryptor**: Gateway to ALL firmware analysis - nothing works without this
- **PKG Manager**: Required for homebrew deployment and package research
- **SELF Decryptor**: Essential for usermode executable analysis

---

## Project Structure

```
heavy_elephant/
├── README.md
├── requirements.txt
├── setup.py                      # Optional pip install
├── keys/
│   ├── boot_chain.json           # Boot chain keys
│   ├── pkg_rsa.json              # PKG RSA keys (CRT format)
│   └── self_keys.json            # SELF cipher keys
├── he/                           # Main package
│   ├── __init__.py
│   ├── crypto.py                 # Shared crypto functions
│   ├── keys.py                   # Key loading utilities
│   └── utils.py                  # Common utilities
├── tools/
│   ├── ps5_boot_decrypt.py       # Tool 1: Boot chain decryptor
│   ├── ps5_pkg_tool.py           # Tool 2: PKG manager
│   └── ps5_self_tool.py          # Tool 3: SELF decryptor
├── docs/
│   ├── ps5-keys.md               # Key documentation
│   └── file-formats.md           # PS5 file format notes
└── tests/
    ├── test_crypto.py
    ├── test_boot_decrypt.py
    ├── test_pkg_tool.py
    └── test_self_tool.py
```

---

## Dependencies

### requirements.txt

```
pycryptodome>=3.19.0
click>=8.1.0
rich>=13.0.0
```

### Why These?

| Package | Purpose |
|---------|---------|
| `pycryptodome` | AES, RSA, HMAC - well-audited, widely used |
| `click` | CLI interface - cleaner than argparse |
| `rich` | Pretty output, progress bars, hex dumps |

---

## Core Library: `he/crypto.py`

```python
"""
Heavy Elephant - Core Crypto Functions
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
    """AES-128-CBC with IV=0 (PS5 protocol requirement)."""
    iv = b'\x00' * 16
    return aes_cbc_decrypt_no_pad(key, iv, data)

def hmac_sha1_verify(key: bytes, data: bytes, expected_mac: bytes) -> bool:
    """Verify HMAC-SHA1 tag."""
    h = HMAC.new(key, data, digestmod=SHA1)
    try:
        h.verify(expected_mac)
        return True
    except ValueError:
        return False

def hmac_sha1(key: bytes, data: bytes) -> bytes:
    """Compute HMAC-SHA1."""
    h = HMAC.new(key, data, digestmod=SHA1)
    return h.digest()

def rsa_sign_pkcs1v15(private_key: RSA.RsaKey, data: bytes) -> bytes:
    """Sign with RSA PKCS#1 v1.5."""
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
```

---

## Tool 1: Boot Chain Decryptor

### `tools/ps5_boot_decrypt.py`

```python
#!/usr/bin/env python3
"""
PS5 Boot Chain Decryptor

Decrypts: EMC IPL Header -> EMC IPL Body -> EAP KBL -> EAP Kernel

Usage:
    python ps5_boot_decrypt.py firmware.bin -o output/
    python ps5_boot_decrypt.py firmware.bin --stage eap-kbl -o eap_kbl.dec
"""
import click
from pathlib import Path
from rich.console import Console
from rich.progress import Progress

from he.crypto import aes_cbc_decrypt_iv_zero, hmac_sha1_verify
from he.keys import load_boot_chain_keys

console = Console()

@click.command()
@click.argument('firmware', type=click.Path(exists=True))
@click.option('-o', '--output', required=True, help='Output file or directory')
@click.option('-k', '--keys', default='keys/boot_chain.json', help='Keys file')
@click.option('--stage', type=click.Choice(['all', 'emc-header', 'emc-body', 'eap-kbl', 'eap-kernel']),
              default='all', help='Stage to decrypt')
def main(firmware: str, output: str, keys: str, stage: str):
    """Decrypt PS5 boot chain components."""
    console.print(f"[bold blue]PS5 Boot Chain Decryptor[/]")

    # Load keys
    k = load_boot_chain_keys(keys)

    # Read firmware
    data = Path(firmware).read_bytes()
    console.print(f"Loaded {len(data):,} bytes from {firmware}")

    if stage in ('all', 'emc-header'):
        decrypt_emc_header(data, k, output)

    if stage in ('all', 'emc-body'):
        decrypt_emc_body(data, k, output)

    if stage in ('all', 'eap-kbl'):
        decrypt_eap_kbl(data, k, output)

    if stage in ('all', 'eap-kernel'):
        decrypt_eap_kernel(data, k, output)

def decrypt_emc_header(data: bytes, keys: dict, output: str):
    """Decrypt EMC IPL header."""
    # Extract header region (adjust offsets based on format)
    header_offset = 0x0
    header_size = 0x1000

    encrypted = data[header_offset:header_offset + header_size]
    decrypted = aes_cbc_decrypt_iv_zero(keys['emc_ipl_header'], encrypted)

    out_path = Path(output) / 'emc_header.dec' if Path(output).is_dir() else output
    Path(out_path).write_bytes(decrypted)
    console.print(f"[green]EMC Header -> {out_path}[/]")

def decrypt_emc_body(data: bytes, keys: dict, output: str):
    """Decrypt EMC IPL body."""
    body_offset = 0x1000
    body_size = 0x10000

    encrypted = data[body_offset:body_offset + body_size]
    decrypted = aes_cbc_decrypt_iv_zero(keys['emc_ipl_cipher'], encrypted)

    out_path = Path(output) / 'emc_body.dec' if Path(output).is_dir() else output
    Path(out_path).write_bytes(decrypted)
    console.print(f"[green]EMC Body -> {out_path}[/]")

def decrypt_eap_kbl(data: bytes, keys: dict, output: str):
    """Decrypt EAP KBL with MAC verification."""
    kbl_offset = 0x20000  # Adjust based on format
    kbl_size = 0x20000
    mac_size = 20  # HMAC-SHA1

    encrypted = data[kbl_offset:kbl_offset + kbl_size]
    expected_mac = data[kbl_offset + kbl_size:kbl_offset + kbl_size + mac_size]

    # Verify MAC first
    if not hmac_sha1_verify(keys['eap_kbl_mac'], encrypted, expected_mac):
        console.print("[red]EAP KBL MAC verification FAILED[/]")
        return

    console.print("[green]EAP KBL MAC verified[/]")

    decrypted = aes_cbc_decrypt_iv_zero(keys['eap_kbl'], encrypted)

    out_path = Path(output) / 'eap_kbl.dec' if Path(output).is_dir() else output
    Path(out_path).write_bytes(decrypted)
    console.print(f"[green]EAP KBL -> {out_path}[/]")

def decrypt_eap_kernel(data: bytes, keys: dict, output: str):
    """Decrypt EAP Kernel."""
    kernel_offset = 0x50000  # Adjust based on format
    kernel_size = 0x100000

    encrypted = data[kernel_offset:kernel_offset + kernel_size]
    decrypted = aes_cbc_decrypt_iv_zero(keys['eap_kernel'], encrypted)

    out_path = Path(output) / 'eap_kernel.dec' if Path(output).is_dir() else output
    Path(out_path).write_bytes(decrypted)
    console.print(f"[green]EAP Kernel -> {out_path}[/]")

if __name__ == '__main__':
    main()
```

---

## Tool 2: PKG Manager

### `tools/ps5_pkg_tool.py`

```python
#!/usr/bin/env python3
"""
PS5 PKG Manager

Sign, decrypt, and forge PS5 PKG files.

Usage:
    python ps5_pkg_tool.py decrypt package.pkg -o decrypted/
    python ps5_pkg_tool.py sign package.pkg -o signed.pkg
    python ps5_pkg_tool.py info package.pkg
"""
import click
import struct
from pathlib import Path
from rich.console import Console
from rich.table import Table

from Crypto.PublicKey import RSA
from he.crypto import aes_cbc_decrypt, rsa_sign_pkcs1v15, rsa_verify_pkcs1v15
from he.keys import load_pkg_keys

console = Console()

# PKG Header structure
PKG_MAGIC = b'\x7FCNT'
PKG_HEADER_SIZE = 0x1000

@click.group()
def cli():
    """PS5 PKG Manager"""
    pass

@cli.command()
@click.argument('pkg_file', type=click.Path(exists=True))
def info(pkg_file: str):
    """Display PKG information."""
    data = Path(pkg_file).read_bytes()

    if data[:4] != PKG_MAGIC:
        console.print(f"[red]Not a valid PKG file (magic: {data[:4].hex()})[/]")
        return

    # Parse header
    table = Table(title="PKG Info")
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Magic", data[:4].hex())
    table.add_row("File Size", f"{len(data):,} bytes")
    # Add more fields based on PKG format

    console.print(table)

@cli.command()
@click.argument('pkg_file', type=click.Path(exists=True))
@click.option('-o', '--output', required=True, help='Output directory')
@click.option('-k', '--keys', default='keys/pkg_rsa.json', help='Keys file')
def decrypt(pkg_file: str, output: str, keys: str):
    """Decrypt PKG file."""
    console.print(f"[bold blue]Decrypting {pkg_file}[/]")

    k = load_pkg_keys(keys)
    data = Path(pkg_file).read_bytes()

    # Extract and decrypt content
    # (Implementation depends on PKG format specifics)

    out_dir = Path(output)
    out_dir.mkdir(parents=True, exist_ok=True)

    console.print(f"[green]Decrypted to {output}[/]")

@cli.command()
@click.argument('pkg_file', type=click.Path(exists=True))
@click.option('-o', '--output', required=True, help='Output PKG file')
@click.option('-k', '--keys', default='keys/pkg_rsa.json', help='Keys file')
def sign(pkg_file: str, output: str, keys: str):
    """Sign PKG file with RSA key."""
    console.print(f"[bold blue]Signing {pkg_file}[/]")

    k = load_pkg_keys(keys)
    data = Path(pkg_file).read_bytes()

    # Sign with RSA private key
    private_key = RSA.import_key(k['rsa_private'])
    signature = rsa_sign_pkcs1v15(private_key, data)

    # Append/embed signature
    signed_data = data + signature  # Simplified - actual format may differ

    Path(output).write_bytes(signed_data)
    console.print(f"[green]Signed PKG -> {output}[/]")

if __name__ == '__main__':
    cli()
```

---

## Tool 3: SELF Decryptor

### `tools/ps5_self_tool.py`

```python
#!/usr/bin/env python3
"""
PS5 SELF Decryptor/Patcher

Decrypt and patch PS5 SELF (Signed ELF) executables.

Usage:
    python ps5_self_tool.py decrypt eboot.self -o eboot.elf
    python ps5_self_tool.py patch eboot.self --offset 0x1000 --bytes "90909090"
    python ps5_self_tool.py info eboot.self
"""
import click
import struct
from pathlib import Path
from rich.console import Console
from rich.table import Table

from he.crypto import aes_cbc_decrypt
from he.keys import load_self_keys

console = Console()

# SELF Header
SELF_MAGIC = b'\x4F\x15\x3D\x1D'  # PS5 SELF magic

@click.group()
def cli():
    """PS5 SELF Decryptor/Patcher"""
    pass

@cli.command()
@click.argument('self_file', type=click.Path(exists=True))
def info(self_file: str):
    """Display SELF information."""
    data = Path(self_file).read_bytes()

    table = Table(title="SELF Info")
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Magic", data[:4].hex())
    table.add_row("File Size", f"{len(data):,} bytes")
    # Parse SELF header fields

    console.print(table)

@cli.command()
@click.argument('self_file', type=click.Path(exists=True))
@click.option('-o', '--output', required=True, help='Output ELF file')
@click.option('-k', '--keys', default='keys/self_keys.json', help='Keys file')
def decrypt(self_file: str, output: str, keys: str):
    """Decrypt SELF to ELF."""
    console.print(f"[bold blue]Decrypting {self_file}[/]")

    k = load_self_keys(keys)
    data = Path(self_file).read_bytes()

    # Parse SELF header to find encrypted segments
    # Decrypt each segment with SELF cipher key

    key = bytes.fromhex(k['cipher_key'])
    iv = bytes.fromhex(k['cipher_iv'])

    # Simplified - actual SELF format has multiple segments
    encrypted_offset = 0x1000  # Adjust based on header
    encrypted_size = len(data) - encrypted_offset

    encrypted = data[encrypted_offset:encrypted_offset + encrypted_size]
    decrypted = aes_cbc_decrypt(key, iv, encrypted)

    # Write ELF (strip SELF header, add ELF header)
    Path(output).write_bytes(decrypted)
    console.print(f"[green]Decrypted ELF -> {output}[/]")

@cli.command()
@click.argument('self_file', type=click.Path(exists=True))
@click.option('-o', '--output', required=True, help='Output patched SELF')
@click.option('--offset', required=True, type=str, help='Patch offset (hex)')
@click.option('--bytes', 'patch_bytes', required=True, help='Patch bytes (hex)')
def patch(self_file: str, output: str, offset: str, patch_bytes: str):
    """Patch SELF file at offset."""
    console.print(f"[bold blue]Patching {self_file}[/]")

    data = bytearray(Path(self_file).read_bytes())

    patch_offset = int(offset, 16)
    patch_data = bytes.fromhex(patch_bytes)

    console.print(f"Patching {len(patch_data)} bytes at 0x{patch_offset:X}")
    console.print(f"  Before: {data[patch_offset:patch_offset+len(patch_data)].hex()}")

    data[patch_offset:patch_offset + len(patch_data)] = patch_data

    console.print(f"  After:  {data[patch_offset:patch_offset+len(patch_data)].hex()}")

    Path(output).write_bytes(bytes(data))
    console.print(f"[green]Patched SELF -> {output}[/]")

if __name__ == '__main__':
    cli()
```

---

## Key Loading: `he/keys.py`

```python
"""
Heavy Elephant - Key Loading Utilities
"""
import json
from pathlib import Path
from typing import Dict

def load_boot_chain_keys(path: str) -> Dict[str, bytes]:
    """Load boot chain decryption keys."""
    data = json.loads(Path(path).read_text())
    return {
        'emc_ipl_header': bytes.fromhex(data['emc_ipl_header']),
        'emc_ipl_cipher': bytes.fromhex(data['emc_ipl_cipher']),
        'eap_kbl': bytes.fromhex(data['eap_kbl']),
        'eap_kbl_mac': bytes.fromhex(data['eap_kbl_mac']),
        'eap_kernel': bytes.fromhex(data['eap_kernel']),
        'eap_kernel_mac': bytes.fromhex(data['eap_kernel_mac']),
    }

def load_pkg_keys(path: str) -> Dict[str, str]:
    """Load PKG RSA keys."""
    data = json.loads(Path(path).read_text())
    return {
        'rsa_private': data['rsa_private_pem'],
        'rsa_public': data.get('rsa_public_pem', ''),
        'content_key': data.get('content_key', ''),
    }

def load_self_keys(path: str) -> Dict[str, str]:
    """Load SELF decryption keys."""
    data = json.loads(Path(path).read_text())
    return {
        'cipher_key': data['cipher_key'],
        'cipher_iv': data['cipher_iv'],
    }
```

---

## Key File Format

### `keys/boot_chain.json`

```json
{
  "emc_ipl_header": "F0332357C8CFAE7E7E26E52BE9E3AED4",
  "emc_ipl_cipher": "D5C92E39759A3E5CE954E772B1C2B651",
  "eap_kbl": "262555E3CF062B070B5AA2CDDF3A5D0E",
  "eap_kbl_mac": "1EE22F6A189E7D99A28B9A96D3C4DBA2",
  "eap_kernel": "CBCC1E53F42C1CB44D965E233CD792A8",
  "eap_kernel_mac": "683D6E2E496687CB5B831DA12BCB001B"
}
```

### `keys/self_keys.json`

```json
{
  "cipher_key": "32D00F27AE38FE4AC88A352313A2BFB4",
  "cipher_iv": "08FEA1ACC37A63099974538616881EC"
}
```

---

## Implementation Timeline

| Phase | Task | Effort |
|-------|------|--------|
| 1 | Set up project structure + `he/crypto.py` | 2h |
| 2 | `ps5_boot_decrypt.py` | 4h |
| 3 | `ps5_pkg_tool.py` | 6h |
| 4 | `ps5_self_tool.py` | 4h |
| 5 | Testing + documentation | 4h |
| **Total** | | **20h** |

---

## Comparison: Python vs Rust (Previous Plan)

| Metric | Python (v3.0) | Rust (v2.0) |
|--------|---------------|-------------|
| Tools | 3 focused | 15 sprawling |
| Effort | ~20h | ~140h |
| Dependencies | 3 packages | 20+ crates |
| Lines of code | ~500 | ~10,000+ |
| Time to first result | Hours | Weeks |

---

## Quick Start

```bash
# Setup
cd heavy_elephant
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Decrypt boot chain
python tools/ps5_boot_decrypt.py firmware.bin -o output/

# Decrypt PKG
python tools/ps5_pkg_tool.py decrypt package.pkg -o decrypted/

# Decrypt SELF
python tools/ps5_self_tool.py decrypt eboot.self -o eboot.elf
```

---

## References

- PS5 Keys: `/home/pook/documents/ps5-keys.txt`
- pycryptodome docs: https://pycryptodome.readthedocs.io/

---

## Change Log

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2025-12-31 | Initial Rust master plan |
| 2.0.0 | 2025-12-31 | Integrated agent reviews (Rust) |
| 3.0.0 | 2025-12-31 | **Python rewrite** - 3 focused tools |

---

*Master Plan v3.0.0 - Heavy Elephant PS5 Security Research Toolkit*
*Python Edition - Fast, Focused, Research-Friendly*
