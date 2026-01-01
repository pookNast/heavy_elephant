# Heavy Elephant - PS5 Security Research Toolkit

A Python toolkit for PS5 security research, providing tools for firmware analysis, package management, and executable decryption.

## Overview

Heavy Elephant consists of three high-utility tools for PS5 security research:

| Tool | Purpose | Key Features |
|------|---------|--------------|
| **Boot Chain Decryptor** | Decrypt PS5 boot sequence | Firmware detection, auto-offset, MAC verification |
| **PKG Manager** | Analyze and extract PKG files | Header parsing, XTS-AES decrypt, entry extraction |
| **SELF Decryptor** | Decrypt SELF executables | Segment parsing, ELF reconstruction |

## Requirements

- Python 3.11+
- pycryptodome >= 3.19.0
- click >= 8.1.0
- rich >= 13.0.0

## Installation

### From Source

```bash
git clone https://github.com/yourusername/heavy_elephant.git
cd heavy_elephant
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### As Package

```bash
pip install -e .
```

## Quick Start

### 1. Set Up Keys

Copy the example key files and add your research keys:

```bash
cp keys/example_boot_chain.json keys/boot_chain.json
cp keys/example_pkg_rsa.json keys/pkg_rsa.json
cp keys/example_self_keys.json keys/self_keys.json
# Edit the JSON files with actual keys
```

### 2. Boot Chain Decryption

```bash
# Analyze firmware
python tools/ps5_boot_decrypt.py firmware.bin --info

# Decrypt all stages
python tools/ps5_boot_decrypt.py firmware.bin -o output/

# Decrypt specific stage
python tools/ps5_boot_decrypt.py firmware.bin --stage eap-kbl -o eap_kbl.dec

# With verbose output
python tools/ps5_boot_decrypt.py firmware.bin -o output/ --verbose
```

### 3. PKG Analysis

```bash
# Display PKG information
python tools/ps5_pkg_tool.py info package.pkg

# Verbose with digests
python tools/ps5_pkg_tool.py info package.pkg -v

# Extract all entries
python tools/ps5_pkg_tool.py decrypt package.pkg -o extracted/

# Extract specific entry
python tools/ps5_pkg_tool.py extract package.pkg -e param.sfo -o param.sfo

# Verify PKG integrity
python tools/ps5_pkg_tool.py verify package.pkg
```

### 4. SELF Decryption

```bash
# Display SELF information
python tools/ps5_self_tool.py info eboot.self

# Decrypt to ELF
python tools/ps5_self_tool.py decrypt eboot.self -o eboot.elf

# Extract raw segment
python tools/ps5_self_tool.py extract-segment eboot.self --index 0 -o segment0.bin

# Patch SELF at offset
python tools/ps5_self_tool.py patch eboot.self --offset 0x1000 --bytes "90909090" -o patched.self
```

## Project Structure

```
heavy_elephant/
├── he/                          # Core library
│   ├── __init__.py
│   ├── crypto.py               # AES, HMAC, RSA operations
│   ├── keys.py                 # Key loading utilities
│   └── utils.py                # Hex dump, alignment helpers
├── tools/                       # CLI tools
│   ├── ps5_boot_decrypt.py     # Boot chain decryptor (662 lines)
│   ├── ps5_pkg_tool.py         # PKG manager (348 lines)
│   └── ps5_self_tool.py        # SELF decryptor (279 lines)
├── keys/                        # Key files (gitignored)
│   ├── example_boot_chain.json # Example boot chain keys
│   ├── example_pkg_rsa.json    # Example PKG RSA keys
│   └── example_self_keys.json  # Example SELF cipher keys
├── tests/                       # Unit tests (95 tests)
│   ├── test_boot_decrypt.py    # 39 tests
│   ├── test_pkg_tool.py        # 33 tests
│   └── test_self_tool.py       # 23 tests
├── docs/                        # Documentation
├── requirements.txt
├── setup.py
└── README.md
```

## Tool Details

### Boot Chain Decryptor

Decrypts the PS5 boot sequence:
- **EMC IPL Header** - Initial program loader header
- **EMC IPL Body** - Main bootloader code (EMC revision c0)
- **EAP KBL** - Kernel boot loader with HMAC-SHA1 verification
- **EAP Kernel** - Main kernel with HMAC-SHA256 verification

Features:
- Auto-detection of firmware format (ELF, PKG, PUP, EMC IPL, EAP blob)
- Entropy analysis for encrypted data identification
- Automatic segment offset detection
- Firmware version detection

### PKG Manager

Analyzes and extracts PS4/PS5 PKG files:
- Full header parsing (big-endian PS3/PS4/PS5 format)
- Entry table with 50+ known entry types
- XTS-AES decryption for PFS images
- Content ID, DRM type, and content flags parsing

Supported entry types:
- `param.sfo`, `icon0.png`, `pic0.png`, `pic1.png`
- `playgo-chunk.dat`, `playgo-manifest.xml`
- `license.dat`, `npbind.dat`
- PFS image extraction
- And many more...

### SELF Decryptor

Decrypts PS4/PS5 SELF (Signed ELF) executables:
- SELF header parsing with version detection
- Segment table with encryption/compression flags
- AES-CBC segment decryption
- ZLIB decompression for compressed segments
- ELF reconstruction from decrypted segments

Supports program types:
- NPDRM Executable/Dynamic Library
- System Executable/Dynamic Library
- Host Kernel
- Secure Module/Kernel

## Testing

Run all tests:

```bash
python -m pytest tests/ -v
```

Run specific test file:

```bash
python -m pytest tests/test_boot_decrypt.py -v
python -m pytest tests/test_pkg_tool.py -v
python -m pytest tests/test_self_tool.py -v
```

## Key File Format

### boot_chain.json

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

### pkg_rsa.json

```json
{
  "n": "RSA_MODULUS_HEX",
  "e": "010001",
  "d": "RSA_PRIVATE_EXPONENT_HEX",
  "p": "RSA_PRIME_P_HEX",
  "q": "RSA_PRIME_Q_HEX",
  "ekpfs": "EKPFS_KEY_HEX",
  "content_key": "CONTENT_KEY_HEX"
}
```

### self_keys.json

```json
{
  "cipher_key": "32D00F27AE38FE4AC88A352313A2BFB4",
  "cipher_iv": "08FEA1ACC37A63099974538616881EC0"
}
```

## Security Notes

- **Keys are gitignored** - Never commit actual cryptographic keys
- **Research purposes only** - This toolkit is for security research
- **IV=0 limitation** - PS5 boot chain uses AES-CBC with zeroed IV (protocol requirement)
- **MAC verification** - Always verify MAC before decryption (encrypt-then-MAC pattern)

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

MIT License - See [LICENSE](LICENSE) for details.

## Disclaimer

This toolkit is provided for security research and educational purposes only. Use responsibly and in accordance with applicable laws and regulations.

## Acknowledgments

- PS4/PS5 security research community
- [psdevwiki.com](https://www.psdevwiki.com) for format documentation
- pycryptodome developers for excellent crypto library
