# PS4-Compatible Tools Implementation Specification

**Version:** 1.0.0
**Created:** 2025-12-31
**Status:** Implementation Ready
**Tools Covered:** trophy-tool, savedata-tool, controller-auth, livedump-tool, pfs-sbl, ipmi-tool

---

## Executive Summary

This document specifies implementation details for the 6 PS4-compatible tools in the Heavy Elephant toolkit. These tools leverage PS4 cryptographic keys that are reused on PS5 for backward compatibility, making them valuable for cross-platform security research.

---

## Table of Contents

1. [Key Material Overview](#1-key-material-overview)
2. [Tool 6: Trophy Decryptor (trophy-tool)](#2-tool-6-trophy-decryptor-trophy-tool)
3. [Tool 7: Save Data Tool (savedata-tool)](#3-tool-7-save-data-tool-savedata-tool)
4. [Tool 8: Controller Auth (controller-auth)](#4-tool-8-controller-auth-controller-auth)
5. [Tool 9: Crash Dump Analyzer (livedump-tool)](#5-tool-9-crash-dump-analyzer-livedump-tool)
6. [Tool 10: PFS SBL Tool (pfs-sbl)](#6-tool-10-pfs-sbl-tool-pfs-sbl)
7. [Tool 11: IPMI Manager (ipmi-tool)](#7-tool-11-ipmi-manager-ipmi-tool)
8. [Shared Code Patterns](#8-shared-code-patterns)
9. [he-crypto Extensions](#9-he-crypto-extensions)
10. [Testing Strategy](#10-testing-strategy)

---

## 1. Key Material Overview

### 1.1 Key Source Files

| Tool | Primary Key Source | Key Slot |
|------|-------------------|----------|
| trophy-tool | ps4-trophy-hid-keys.md | 0x0 (pfsSKKey) |
| savedata-tool | ps4-save-auth-keys.md | 0x58 (pfs_sd_auth) |
| controller-auth | ps4-trophy-hid-keys.md | 0x48 (SceHidAuth) |
| livedump-tool | ps4-save-auth-keys.md | 0x44 (livedump_secure) |
| pfs-sbl | ps4-save-auth-keys.md | 0x54 (pfs_sbl) |
| ipmi-tool | ps4-save-auth-keys.md | 0x50 (IPMI) |

### 1.2 Common Key Types

All PS4-compatible tools use these key structures:

```rust
/// Dual AES key structure (256-bit total via two 128-bit keys)
pub struct DualAesKey {
    pub key1: [u8; 16],  // First 128-bit AES key
    pub key2: [u8; 16],  // Second 128-bit AES key
}

/// HMAC authentication key
pub struct HmacKey {
    pub key: [u8; 16],   // 128-bit HMAC key
}

/// Console type for key selection
#[derive(Clone, Copy)]
pub enum ConsoleType {
    Retail,   // Type E keys
    DevKit,   // Type I keys
}
```

### 1.3 Key Storage Structure

```
keys/
├── ps4/
│   ├── trophy.json.age          # Trophy encryption keys
│   ├── pfs_sealed.json.age      # PFS sealed key material
│   ├── hid_auth.json.age        # Controller auth keys
│   ├── save_auth.json.age       # Save data auth keys
│   ├── livedump.json.age        # Crash dump keys
│   ├── pfs_sbl.json.age         # SBL filesystem keys
│   └── ipmi.json.age            # IPMI management keys
└── portability/
    └── sealed_key_iv.json.age   # Shared IV material
```

---

## 2. Tool 6: Trophy Decryptor (trophy-tool)

### 2.1 Purpose

Decrypt and manipulate PS4/PS5 trophy data (Trophy.trp files) for research purposes.

### 2.2 Key Mapping

| Key Name | Hex Value | Size | Algorithm |
|----------|-----------|------|-----------|
| Trophy Key (Full) | `9EA5CD89DA8DAB6E66CE6D345752639D9A4EE51EEAF084D970FEFC2850F7604E` | 256-bit | AES-256-CBC |
| Trophy Key Part 1 | `9EA5CD89DA8DAB6E66CE6D345752639D` | 128-bit | - |
| Trophy Key Part 2 | `9A4EE51EEAF084D970FEFC2850F7604E` | 128-bit | - |
| PFS Sealed HMAC (E) | `D8808616FA98B0BF50A499D5FA5DCCA7` | 128-bit | HMAC-SHA1 |
| PFS Sealed HMAC (I) | `096459F1A0C8C5DDDD404E40A4CEBF6C` | 128-bit | HMAC-SHA1 |

### 2.3 Algorithm Specification

#### 2.3.1 Trophy.trp Decryption

```
Algorithm: AES-256-CBC
Key: Trophy Key (256-bit combined)
IV: First 16 bytes of encrypted block (or file-specific)
Padding: PKCS7

Decrypt Flow:
1. Read Trophy.trp header
2. Extract IV from header offset
3. Decrypt trophy data with AES-256-CBC
4. Verify HMAC over decrypted content
5. Parse internal trophy structure
```

#### 2.3.2 Trophy Data Structure

```rust
#[repr(C)]
pub struct TrophyHeader {
    pub magic: [u8; 4],      // "TRPF" or version marker
    pub version: u32,
    pub file_size: u64,
    pub entry_count: u32,
    pub entry_size: u32,
    pub dev_flag: u32,       // 0=retail, 1=devkit
    pub digest: [u8; 20],    // SHA-1 of entries
    pub padding: [u8; 36],
}

#[repr(C)]
pub struct TrophyEntry {
    pub name: [u8; 32],
    pub offset: u64,
    pub size: u64,
    pub flags: u32,
    pub padding: [u8; 12],
}
```

### 2.4 CLI Interface

```
trophy-tool <COMMAND>

COMMANDS:
    decrypt     Decrypt Trophy.trp file
    list        List trophy entries without decrypting
    extract     Extract individual trophy assets
    info        Display trophy metadata
    verify      Verify HMAC integrity

OPTIONS:
    -k, --keys <PATH>       Key file path [default: ./keys/ps4/trophy.json.age]
    -t, --type <TYPE>       Console type [retail|devkit] [default: retail]
    -v, --verbose           Enable verbose output

EXAMPLES:
    trophy-tool decrypt -i trophy.trp -o trophy.dec
    trophy-tool list -i trophy.trp
    trophy-tool extract -i trophy.trp --entry "TROP.SFM" -o trop.sfm
```

### 2.5 Implementation Notes

```rust
// Key structure for trophy-tool
pub struct TrophyKeys {
    pub aes_key: SecretBox<[u8; 32]>,     // Combined 256-bit key
    pub hmac_key: SecretBox<[u8; 16]>,    // HMAC verification
}

impl TrophyKeys {
    pub fn load(console: ConsoleType, path: &Path) -> Result<Self, KeyError> {
        let json = age_decrypt(path)?;
        let keys: TrophyKeyJson = serde_json::from_str(&json)?;

        // Combine two 128-bit keys into one 256-bit key
        let mut combined = [0u8; 32];
        combined[..16].copy_from_slice(&keys.key1);
        combined[16..].copy_from_slice(&keys.key2);

        Ok(Self {
            aes_key: SecretBox::new(Box::new(combined)),
            hmac_key: SecretBox::new(Box::new(keys.hmac)),
        })
    }
}
```

---

## 3. Tool 7: Save Data Tool (savedata-tool)

### 3.1 Purpose

Encrypt/decrypt PS4/PS5 save data using `pfs_sd_auth` (slot 0x58) keys.

### 3.2 Key Mapping

| Type | Key Name | Hex Value | Purpose |
|------|----------|-----------|---------|
| E | AES Key 1 | `85BF3C5FBB76D849FEE56AB0A91FFAE0` | Primary encryption |
| E | AES Key 2 | `E5D1B6A41A95BE06DBAC56D1AE1DDD39` | Secondary encryption |
| E | HMAC | `ADAE46C988E4C9F7DA8CA68F05F6F1E2` | Integrity |
| I | AES Key 1 | `65E8B9FD9876A0FD6FA056C34EDFE850` | Primary (DevKit) |
| I | AES Key 2 | `C3BA2A09B8D49FB4EF8AC90A7CEE29C7` | Secondary (DevKit) |
| I | HMAC | `D02CFD9DA3B4784172F98FADA2D206DB` | Integrity (DevKit) |

### 3.3 Algorithm Specification

#### 3.3.1 Save Data Encryption (ENCDEC)

```
Algorithm: AES-128-CBC (dual-key ENCDEC)
Mode: Encrypt with Key1, Decrypt with Key2 (or vice versa)
IV: Derived from sealed key IV or file-specific

ENCDEC Flow:
1. Input plaintext
2. Encrypt with AES-CBC using Key1
3. Decrypt result with AES-CBC using Key2 (XOR chain)
4. Output ciphertext

Verify Flow:
1. Compute HMAC-SHA1 over ciphertext
2. Compare with stored tag (constant-time)
3. If valid, proceed with decryption
```

#### 3.3.2 Sealed Key Structure

```rust
#[repr(C)]
pub struct SealedKey {
    pub version: u16,
    pub type_flag: u16,        // 0=retail, 1=devkit
    pub key_id: [u8; 16],      // Key identifier
    pub wrapped_key: [u8; 32], // Encrypted data key
    pub hmac: [u8; 20],        // HMAC-SHA1 tag
    pub padding: [u8; 10],
}

// IV for sealed key operations
pub const SEALED_KEY_IV: [u8; 16] = hex!("F60016BACD42AD21C70D9B075CB51983");
```

### 3.4 CLI Interface

```
savedata-tool <COMMAND>

COMMANDS:
    decrypt     Decrypt save data container
    encrypt     Encrypt save data container
    unseal      Unseal encrypted key material
    reseal      Re-seal key material for different console
    verify      Verify save data integrity

OPTIONS:
    -k, --keys <PATH>       Key file path [default: ./keys/ps4/save_auth.json.age]
    -t, --type <TYPE>       Console type [retail|devkit]
    --sealed-iv <PATH>      Custom sealed key IV

EXAMPLES:
    savedata-tool decrypt -i save.dat -o save.dec
    savedata-tool unseal -i sealedkey -o unwrapped.key
    savedata-tool verify -i save.dat
```

### 3.5 ENCDEC Implementation

```rust
use aes::Aes128;
use cbc::{Encryptor, Decryptor};
use cipher::{BlockEncryptMut, BlockDecryptMut, KeyIvInit};

pub struct EncDec {
    key1: [u8; 16],
    key2: [u8; 16],
}

impl EncDec {
    /// PS4 ENCDEC: Encrypt with key1, decrypt with key2
    pub fn process(&self, data: &mut [u8], iv: &[u8; 16]) -> Result<(), CryptoError> {
        // Phase 1: Encrypt with key1
        let enc = Encryptor::<Aes128>::new(&self.key1.into(), iv.into());
        enc.encrypt_padded_mut::<NoPadding>(data, data.len())?;

        // Phase 2: Decrypt with key2 (using zero IV for chain)
        let zero_iv = [0u8; 16];
        let dec = Decryptor::<Aes128>::new(&self.key2.into(), &zero_iv.into());
        dec.decrypt_padded_mut::<NoPadding>(data)?;

        Ok(())
    }
}
```

---

## 4. Tool 8: Controller Auth (controller-auth)

### 4.1 Purpose

Analyze and research DualShock 4/DualSense controller authentication using SceHidAuth (slot 0x48) keys.

### 4.2 Key Mapping

| Type | Key Name | Hex Value | Purpose |
|------|----------|-----------|---------|
| E | AES Key 1 | `BDA98742518157C4634A21FBB47C8311` | Challenge encryption |
| E | AES Key 2 | `D21CE6016404D8CB2EF0C24462C42C38` | Response decryption |
| E | HMAC | `AED0BCC3264D91A698E4D7D8CA428E52` | Auth verification |
| I | AES Key 1 | `8FC2405D96B41290DF62525E536E37B6` | Challenge (DevKit) |
| I | AES Key 2 | `42D798F0538B7FB42829C05ECBB00B08` | Response (DevKit) |
| I | HMAC | `A43C5B248AEF15C4CEFAEA170F6F31F7` | Auth (DevKit) |

### 4.3 Algorithm Specification

#### 4.3.1 HID Authentication Protocol

```
Protocol: Challenge-Response Authentication
Transport: USB HID / Bluetooth

Authentication Flow:
1. Console generates 32-byte random challenge
2. Challenge encrypted with AES-128-CBC (Key1)
3. Sent to controller via HID report
4. Controller decrypts, generates response
5. Response encrypted and returned
6. Console decrypts with Key2
7. HMAC verified over session

Challenge Structure:
  [4 bytes] Nonce
  [4 bytes] Counter
  [8 bytes] Random
  [16 bytes] Reserved
```

#### 4.3.2 HID Report Structure

```rust
#[repr(C)]
pub struct HidAuthChallenge {
    pub report_id: u8,       // 0xF0 for auth
    pub sub_type: u8,        // Challenge type
    pub nonce: [u8; 4],
    pub counter: u32,
    pub random: [u8; 8],
    pub reserved: [u8; 16],
    pub hmac: [u8; 20],      // HMAC-SHA1
}

#[repr(C)]
pub struct HidAuthResponse {
    pub report_id: u8,       // 0xF1 for response
    pub status: u8,
    pub response: [u8; 32],
    pub signature: [u8; 20], // HMAC-SHA1
}
```

### 4.4 CLI Interface

```
controller-auth <COMMAND>

COMMANDS:
    analyze     Analyze captured HID auth traffic
    generate    Generate challenge packet
    verify      Verify response packet
    dump        Dump controller certificate info

OPTIONS:
    -k, --keys <PATH>       Key file path [default: ./keys/ps4/hid_auth.json.age]
    -t, --type <TYPE>       Console type [retail|devkit]
    --report-file <PATH>    USB/BT capture file (pcap)

EXAMPLES:
    controller-auth analyze -i capture.pcap
    controller-auth generate --challenge-out challenge.bin
    controller-auth verify -i response.bin --challenge challenge.bin
```

### 4.5 Implementation Notes

```rust
pub struct HidAuth {
    enc_key: SecretBox<[u8; 16]>,
    dec_key: SecretBox<[u8; 16]>,
    hmac_key: SecretBox<[u8; 16]>,
}

impl HidAuth {
    pub fn verify_response(
        &self,
        challenge: &HidAuthChallenge,
        response: &HidAuthResponse,
    ) -> Result<bool, CryptoError> {
        // 1. Decrypt response
        let decrypted = self.decrypt_response(&response.response)?;

        // 2. Verify counter matches
        if decrypted.counter != challenge.counter {
            return Ok(false);
        }

        // 3. Verify HMAC
        let computed_hmac = self.compute_hmac(&decrypted)?;
        Ok(computed_hmac.ct_eq(&response.signature).into())
    }
}
```

---

## 5. Tool 9: Crash Dump Analyzer (livedump-tool)

### 5.1 Purpose

Decrypt and analyze PS4/PS5 crash dump (livedump) data for debugging research.

### 5.2 Key Mapping

| Type | Key Name | Hex Value | Purpose |
|------|----------|-----------|---------|
| Static | Slot 0x44 | `505E2D39EB32E5FCE9DEE1F80D9EED26` | Livedump base key |
| E | AES Key 1 | `9AB969E2A0DB234C0A2B0C1B3F2A4B5C` | Dump encryption |
| E | AES Key 2 | `D8E7F6A5B4C3D2E1F0A9B8C7D6E5F4A3` | Dump decryption |
| I | AES Key 1 | `1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D` | Dump enc (DevKit) |
| I | AES Key 2 | `7E8F9A0B1C2D3E4F5A6B7C8D9E0F1A2B` | Dump dec (DevKit) |

### 5.3 Algorithm Specification

#### 5.3.1 Livedump File Structure

```rust
#[repr(C)]
pub struct LivedumpHeader {
    pub magic: [u8; 8],       // "LIVEDUMP" or version
    pub version: u32,
    pub flags: u32,
    pub dump_size: u64,
    pub timestamp: u64,
    pub console_id: [u8; 16],
    pub encryption_iv: [u8; 16],
    pub hmac: [u8; 32],
    pub reserved: [u8; 64],
}

#[repr(C)]
pub struct LivedumpSegment {
    pub segment_type: u32,    // Memory, registers, etc.
    pub offset: u64,
    pub size: u64,
    pub flags: u32,
    pub padding: [u8; 12],
}
```

#### 5.3.2 Decryption Process

```
Algorithm: AES-128-CBC with dual-key processing
IV: Extracted from header (encryption_iv field)

Decrypt Flow:
1. Read livedump header (128 bytes, unencrypted)
2. Verify header magic and version
3. Compute HMAC over encrypted segments
4. If HMAC valid, decrypt each segment:
   a. Use segment-specific IV (derived from offset)
   b. Apply ENCDEC with Key1/Key2
5. Parse segment contents (memory, registers, etc.)
```

### 5.4 CLI Interface

```
livedump-tool <COMMAND>

COMMANDS:
    decrypt     Decrypt livedump file
    info        Display dump metadata
    extract     Extract specific segments
    analyze     Perform basic crash analysis

OPTIONS:
    -k, --keys <PATH>       Key file path [default: ./keys/ps4/livedump.json.age]
    -t, --type <TYPE>       Console type [retail|devkit]
    --segment <TYPE>        Segment to extract [memory|registers|threads]

EXAMPLES:
    livedump-tool decrypt -i crash.dmp -o crash.dec
    livedump-tool info -i crash.dmp
    livedump-tool extract -i crash.dmp --segment registers -o regs.bin
```

---

## 6. Tool 10: PFS SBL Tool (pfs-sbl)

### 6.1 Purpose

Handle PFS (PlayStation File System) encryption at the SBL (Secure Boot Loader) level using slot 0x54 keys.

### 6.2 Key Mapping

| Type | Key Name | Hex Value | Purpose |
|------|----------|-----------|---------|
| E | AES Key 1 | `42E66FA0A4D1E41A29FD96E7D19FB85E` | PFS encryption |
| E | AES Key 2 | `1E0DAEAE658A87AAFB44C59BD51A33A6` | PFS decryption |
| E | HMAC | `9D67B99B7BEC6F61C3D3C0A6AA2CB65C` | Integrity |
| I | AES Key 1 | `4BE2F42A48EE7F8A5627C8F6286FF989` | PFS enc (DevKit) |
| I | AES Key 2 | `C0F880CD84F6D84B70FC4D2FBD41EDCC` | PFS dec (DevKit) |
| I | HMAC | `B8BA3ACFA85FF6999F3EF2F03CD00DF7` | Integrity (DevKit) |
| Shared | OpenPSID IV | `57D6270D982E21532F776EF4800F27B6` | CMAC / SBL IV |

### 6.3 Algorithm Specification

#### 6.3.1 PFS Image Structure

```rust
#[repr(C)]
pub struct PfsImageHeader {
    pub magic: u32,           // 0x31534650 ("PFS1")
    pub version: u16,
    pub flags: u16,
    pub block_size: u32,
    pub block_count: u64,
    pub inode_size: u32,
    pub inode_count: u32,
    pub root_inode: u32,
    pub signature: [u8; 32],  // HMAC-SHA256
}

#[repr(C)]
pub struct PfsSuperblock {
    pub header: PfsImageHeader,
    pub key_table_offset: u64,
    pub key_table_size: u32,
    pub encryption_type: u32,  // 1=AES-CBC, 2=AES-XTS
    pub reserved: [u8; 48],
}
```

#### 6.3.2 Block Encryption

```
Block Encryption: AES-128-CBC (ENCDEC mode)
Block Size: 0x10000 (64KB) standard
IV Derivation: CMAC(block_index || OpenPSID_IV)

Per-Block Process:
1. Compute block IV: AES-CMAC(block_index, OpenPSID_IV)
2. Read 64KB block
3. Apply ENCDEC(Key1, Key2, block, iv)
4. Output decrypted block
```

### 6.4 CLI Interface

```
pfs-sbl <COMMAND>

COMMANDS:
    decrypt     Decrypt PFS image
    encrypt     Encrypt PFS image
    mount       Virtual mount for analysis (read-only)
    info        Display PFS metadata
    verify      Verify PFS integrity

OPTIONS:
    -k, --keys <PATH>       Key file path [default: ./keys/ps4/pfs_sbl.json.age]
    -t, --type <TYPE>       Console type [retail|devkit]
    --block-size <SIZE>     Override block size [default: 65536]

EXAMPLES:
    pfs-sbl decrypt -i system.pfs -o system.dec
    pfs-sbl mount -i system.pfs --mountpoint /mnt/pfs
    pfs-sbl verify -i system.pfs
```

### 6.5 IV Derivation Implementation

```rust
use aes::Aes128;
use cmac::{Cmac, Mac};

pub fn derive_block_iv(block_index: u64, base_iv: &[u8; 16]) -> [u8; 16] {
    let mut mac = Cmac::<Aes128>::new_from_slice(base_iv)
        .expect("Valid key size");

    // Input: 8-byte block index (little-endian)
    mac.update(&block_index.to_le_bytes());

    let result = mac.finalize().into_bytes();
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&result);
    iv
}
```

---

## 7. Tool 11: IPMI Manager (ipmi-tool)

### 7.1 Purpose

Handle IPMI (Intelligent Platform Management Interface) communications for PS4/PS5 hardware management research.

### 7.2 Key Mapping

| Type | Key Name | Hex Value | Purpose |
|------|----------|-----------|---------|
| Static | Slot 0x50 | `507E2C5877B3A0F3DE7B96A4F38EFEFF` | IPMI base key |
| E | AES Key 1 | `9D60FF0DAE47CC8BA5255B71A6B27CB7` | Command encryption |
| E | AES Key 2 | `66C72FF8C4F6297BEA50778B1413368C` | Response decryption |
| E | HMAC | `C7E8DB6A3C3D1FB94AA0CB2F36F7E53D` | Message auth |
| I | AES Key 1 | `68A1FB4DE4D15A75BC35CD4476AE7FC3` | Cmd enc (DevKit) |
| I | AES Key 2 | `7C4FC7C7CCAEC4D85048AC2A9FF1DB1D` | Resp dec (DevKit) |
| I | HMAC | `6DA12F2F43CA4D0CE8AEAD85FBED7D64` | Auth (DevKit) |

### 7.3 Algorithm Specification

#### 7.3.1 IPMI Message Structure

```rust
#[repr(C)]
pub struct IpmiHeader {
    pub version: u8,         // Protocol version
    pub msg_type: u8,        // Request/Response/Event
    pub seq_num: u16,        // Sequence number
    pub target: u8,          // Target subsystem
    pub cmd: u8,             // Command ID
    pub data_len: u16,       // Payload length
}

#[repr(C)]
pub struct IpmiMessage {
    pub header: IpmiHeader,
    pub data: Vec<u8>,       // Variable payload
    pub hmac: [u8; 20],      // HMAC-SHA1 authentication
}

// Known IPMI targets
pub enum IpmiTarget {
    Bmc = 0x01,              // Baseboard Management Controller
    Psu = 0x02,              // Power Supply Unit
    Fan = 0x03,              // Fan controller
    Thermal = 0x04,          // Thermal management
    Ssd = 0x05,              // SSD controller
}
```

#### 7.3.2 Secure IPMI Protocol

```
Protocol: Encrypted IPMI over internal bus
Encryption: AES-128-CBC (ENCDEC)
Authentication: HMAC-SHA1

Message Flow:
1. Construct IPMI header + payload
2. Compute HMAC-SHA1 over (header || payload)
3. Append HMAC to message
4. Encrypt entire message with ENCDEC
5. Send to target subsystem
6. Receive encrypted response
7. Decrypt and verify HMAC
8. Parse response payload
```

### 7.4 CLI Interface

```
ipmi-tool <COMMAND>

COMMANDS:
    decode      Decode captured IPMI traffic
    forge       Create IPMI message
    replay      Replay captured message
    info        Display IPMI subsystem info

OPTIONS:
    -k, --keys <PATH>       Key file path [default: ./keys/ps4/ipmi.json.age]
    -t, --type <TYPE>       Console type [retail|devkit]
    --target <TARGET>       IPMI target [bmc|psu|fan|thermal|ssd]

EXAMPLES:
    ipmi-tool decode -i capture.bin
    ipmi-tool forge --target fan --cmd 0x10 --data "01 02 03"
    ipmi-tool info -i dump.bin
```

---

## 8. Shared Code Patterns

### 8.1 Common Traits

All PS4-compatible tools implement these shared traits from `he-crypto`:

```rust
/// Dual-key encryption/decryption (ENCDEC pattern)
pub trait EncDecCipher {
    fn encdec(&self, data: &mut [u8], iv: &[u8; 16]) -> Result<(), CryptoError>;
    fn dedenc(&self, data: &mut [u8], iv: &[u8; 16]) -> Result<(), CryptoError>;
}

/// MAC verification with constant-time comparison
pub trait MacVerifier {
    fn compute_mac(&self, data: &[u8]) -> [u8; 20];
    fn verify_mac(&self, data: &[u8], expected: &[u8; 20]) -> bool;
}

/// Key loading with console type selection
pub trait KeyLoader {
    type Keys;
    fn load(console: ConsoleType, path: &Path) -> Result<Self::Keys, KeyError>;
}

/// Secure memory handling
pub trait SecureWipe: Sized {
    fn secure_wipe(&mut self);
}
```

### 8.2 Key Loading Pattern

```rust
use secrecy::{SecretBox, ExposeSecret};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct DualKeyJson {
    #[serde(deserialize_with = "hex_deserialize")]
    pub aes_key1: [u8; 16],
    #[serde(deserialize_with = "hex_deserialize")]
    pub aes_key2: [u8; 16],
    #[serde(deserialize_with = "hex_deserialize")]
    pub hmac: [u8; 16],
}

#[derive(Deserialize)]
pub struct KeyFileJson {
    pub retail: DualKeyJson,
    pub devkit: DualKeyJson,
}

pub fn load_keys(console: ConsoleType, path: &Path) -> Result<DualKeySet, KeyError> {
    // 1. Decrypt age-encrypted file
    let decrypted = age_decrypt(path)?;

    // 2. Parse JSON
    let keys: KeyFileJson = serde_json::from_str(&decrypted)?;

    // 3. Select appropriate keyset
    let selected = match console {
        ConsoleType::Retail => keys.retail,
        ConsoleType::DevKit => keys.devkit,
    };

    // 4. Wrap in SecretBox
    Ok(DualKeySet {
        key1: SecretBox::new(Box::new(selected.aes_key1)),
        key2: SecretBox::new(Box::new(selected.aes_key2)),
        hmac: SecretBox::new(Box::new(selected.hmac)),
    })
}
```

### 8.3 ENCDEC Implementation (Shared)

```rust
use aes::Aes128;
use cbc::{Encryptor, Decryptor};
use cipher::{BlockEncryptMut, BlockDecryptMut, KeyIvInit};
use block_padding::NoPadding;

/// PS4/PS5 dual-key ENCDEC cipher
pub struct EncDecCipher {
    key1: SecretBox<[u8; 16]>,
    key2: SecretBox<[u8; 16]>,
}

impl EncDecCipher {
    pub fn new(key1: [u8; 16], key2: [u8; 16]) -> Self {
        Self {
            key1: SecretBox::new(Box::new(key1)),
            key2: SecretBox::new(Box::new(key2)),
        }
    }

    /// Encrypt with key1, then decrypt with key2
    pub fn encdec(&self, data: &mut [u8], iv: &[u8; 16]) -> Result<(), CryptoError> {
        let key1 = self.key1.expose_secret();
        let key2 = self.key2.expose_secret();

        // Encrypt with key1
        type Aes128CbcEnc = Encryptor<Aes128>;
        let enc = Aes128CbcEnc::new(key1.into(), iv.into());
        enc.encrypt_padded_mut::<NoPadding>(data, data.len())
            .map_err(|_| CryptoError::EncryptionFailed)?;

        // Decrypt with key2 (zero IV for second pass)
        type Aes128CbcDec = Decryptor<Aes128>;
        let zero_iv = [0u8; 16];
        let dec = Aes128CbcDec::new(key2.into(), &zero_iv.into());
        dec.decrypt_padded_mut::<NoPadding>(data)
            .map_err(|_| CryptoError::DecryptionFailed)?;

        Ok(())
    }

    /// Decrypt with key2, then encrypt with key1 (reverse)
    pub fn dedenc(&self, data: &mut [u8], iv: &[u8; 16]) -> Result<(), CryptoError> {
        // Inverse of encdec for decryption
        let key1 = self.key1.expose_secret();
        let key2 = self.key2.expose_secret();

        // Encrypt with key2
        type Aes128CbcEnc = Encryptor<Aes128>;
        let zero_iv = [0u8; 16];
        let enc = Aes128CbcEnc::new(key2.into(), &zero_iv.into());
        enc.encrypt_padded_mut::<NoPadding>(data, data.len())
            .map_err(|_| CryptoError::EncryptionFailed)?;

        // Decrypt with key1
        type Aes128CbcDec = Decryptor<Aes128>;
        let dec = Aes128CbcDec::new(key1.into(), iv.into());
        dec.decrypt_padded_mut::<NoPadding>(data)
            .map_err(|_| CryptoError::DecryptionFailed)?;

        Ok(())
    }
}
```

### 8.4 MAC Verification Pattern

```rust
use hmac::{Hmac, Mac};
use sha1::Sha1;
use subtle::ConstantTimeEq;

type HmacSha1 = Hmac<Sha1>;

pub struct MacVerifier {
    key: SecretBox<[u8; 16]>,
}

impl MacVerifier {
    pub fn new(key: [u8; 16]) -> Self {
        Self { key: SecretBox::new(Box::new(key)) }
    }

    pub fn compute(&self, data: &[u8]) -> [u8; 20] {
        let key = self.key.expose_secret();
        let mut mac = HmacSha1::new_from_slice(key)
            .expect("HMAC key size is valid");
        mac.update(data);

        let result = mac.finalize().into_bytes();
        let mut output = [0u8; 20];
        output.copy_from_slice(&result);
        output
    }

    /// Constant-time MAC verification
    pub fn verify(&self, data: &[u8], expected: &[u8; 20]) -> bool {
        let computed = self.compute(data);
        computed.ct_eq(expected).into()
    }
}
```

### 8.5 Error Types

```rust
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Ps4ToolError {
    #[error("Key loading failed")]
    KeyError(#[from] KeyError),

    #[error("Cryptographic operation failed")]
    CryptoError(#[from] CryptoError),

    #[error("Invalid file format")]
    InvalidFormat,

    #[error("MAC verification failed")]
    MacVerificationFailed,

    #[error("Unsupported version: {0}")]
    UnsupportedVersion(u32),

    #[error("IO error")]
    IoError(#[from] std::io::Error),
}

#[derive(Error, Debug)]
pub enum KeyError {
    #[error("Key file not found: {0}")]
    NotFound(PathBuf),

    #[error("Age decryption failed")]
    DecryptionFailed,

    #[error("Invalid key format")]
    InvalidFormat,

    #[error("Console type mismatch")]
    ConsoleMismatch,
}

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Encryption failed")]
    EncryptionFailed,

    #[error("Decryption failed")]
    DecryptionFailed,

    #[error("Invalid key length")]
    InvalidKeyLength,

    #[error("Invalid IV")]
    InvalidIv,
}
```

---

## 9. he-crypto Extensions

### 9.1 New Modules for PS4 Tools

```rust
// crates/he-crypto/src/ps4/mod.rs
pub mod encdec;      // ENCDEC cipher implementation
pub mod sealed;      // Sealed key handling
pub mod pfs;         // PFS-specific crypto
pub mod hid;         // HID authentication
pub mod ipmi;        // IPMI message crypto
```

### 9.2 Key Type Definitions

```rust
// crates/he-crypto/src/ps4/keys.rs

/// PS4 key slot identifiers
pub enum KeySlot {
    PfsSealedKey = 0x00,
    BlurayAacs = 0x05,
    CrashReport = 0x0C,
    RootParam = 0x14,
    LivedumpSecure = 0x44,
    HidAuth = 0x48,
    IpmiMgr = 0x50,
    PfsSbl = 0x54,
    PfsSdAuth = 0x58,
}

/// Complete PS4 keyset for a tool
pub struct Ps4KeySet {
    pub slot: KeySlot,
    pub console: ConsoleType,
    pub aes_key1: SecretBox<[u8; 16]>,
    pub aes_key2: SecretBox<[u8; 16]>,
    pub hmac_key: SecretBox<[u8; 16]>,
    pub iv: Option<[u8; 16]>,
}
```

### 9.3 Feature Flags

```toml
# crates/he-crypto/Cargo.toml

[features]
default = []
ps4-tools = ["encdec", "sealed-keys", "pfs-crypto"]
encdec = []              # ENCDEC cipher support
sealed-keys = []         # Sealed key handling
pfs-crypto = []          # PFS encryption support
hid-auth = []            # HID authentication
ipmi = []                # IPMI message crypto
unsafe_iv_zero = []      # Allow IV=0 (required by some operations)
```

---

## 10. Testing Strategy

### 10.1 Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    // Test vector from known PS4 dump
    const TEST_ENCDEC_PLAINTEXT: [u8; 16] = hex!("00112233445566778899aabbccddeeff");
    const TEST_ENCDEC_KEY1: [u8; 16] = hex!("9EA5CD89DA8DAB6E66CE6D345752639D");
    const TEST_ENCDEC_KEY2: [u8; 16] = hex!("9A4EE51EEAF084D970FEFC2850F7604E");
    const TEST_ENCDEC_IV: [u8; 16] = hex!("F60016BACD42AD21C70D9B075CB51983");

    #[test]
    fn test_encdec_roundtrip() {
        let cipher = EncDecCipher::new(TEST_ENCDEC_KEY1, TEST_ENCDEC_KEY2);
        let mut data = TEST_ENCDEC_PLAINTEXT;

        // Encrypt
        cipher.encdec(&mut data, &TEST_ENCDEC_IV).unwrap();
        assert_ne!(data, TEST_ENCDEC_PLAINTEXT);

        // Decrypt
        cipher.dedenc(&mut data, &TEST_ENCDEC_IV).unwrap();
        assert_eq!(data, TEST_ENCDEC_PLAINTEXT);
    }

    #[test]
    fn test_mac_verification() {
        let hmac_key = hex!("D8808616FA98B0BF50A499D5FA5DCCA7");
        let verifier = MacVerifier::new(hmac_key);

        let data = b"test data";
        let mac = verifier.compute(data);

        assert!(verifier.verify(data, &mac));

        // Tampered MAC should fail
        let mut bad_mac = mac;
        bad_mac[0] ^= 0xFF;
        assert!(!verifier.verify(data, &bad_mac));
    }

    #[test]
    fn test_constant_time_comparison() {
        // Verify timing is consistent regardless of where mismatch occurs
        let hmac_key = hex!("D8808616FA98B0BF50A499D5FA5DCCA7");
        let verifier = MacVerifier::new(hmac_key);

        let data = b"test";
        let correct_mac = verifier.compute(data);

        // Test with mismatches at different positions
        for i in 0..20 {
            let mut bad_mac = correct_mac;
            bad_mac[i] ^= 0xFF;
            assert!(!verifier.verify(data, &bad_mac));
        }
    }
}
```

### 10.2 Integration Tests

```rust
// tests/integration/ps4_tools.rs

#[test]
fn test_trophy_decrypt_sample() {
    let keys = TrophyKeys::load(ConsoleType::Retail, test_key_path()).unwrap();
    let mut trophy = std::fs::read(fixture_path("sample.trp")).unwrap();

    let decrypted = trophy_decrypt(&mut trophy, &keys).unwrap();

    // Verify magic bytes
    assert_eq!(&decrypted[0..4], b"TRPF");
}

#[test]
fn test_savedata_unseal() {
    let keys = SaveDataKeys::load(ConsoleType::Retail, test_key_path()).unwrap();
    let sealed = std::fs::read(fixture_path("sealedkey.bin")).unwrap();

    let unsealed = unseal_key(&sealed, &keys).unwrap();

    assert_eq!(unsealed.len(), 32);
}

#[test]
fn test_pfs_block_decrypt() {
    let keys = PfsSblKeys::load(ConsoleType::Retail, test_key_path()).unwrap();
    let block = std::fs::read(fixture_path("pfs_block_0.bin")).unwrap();

    let iv = derive_block_iv(0, &PFS_SBL_IV);
    let mut data = block.clone();

    pfs_decrypt_block(&mut data, &keys, &iv).unwrap();

    // Verify decrypted content has valid structure
    assert!(data.iter().any(|&b| b != 0));
}
```

### 10.3 Security Tests

```rust
#[test]
fn test_key_zeroization() {
    let mut key = [0x42u8; 16];
    {
        let _cipher = EncDecCipher::new(key, key);
        // Key should be zeroized when cipher is dropped
    }
    // Verify key is still in scope (for testing)
    // In real code, SecretBox handles this automatically
}

#[test]
fn test_no_key_in_error_messages() {
    let result = load_keys(ConsoleType::Retail, Path::new("/nonexistent"));
    let err = result.unwrap_err();
    let msg = format!("{:?}", err);

    // Ensure no hex key material in error
    assert!(!msg.contains("9EA5CD"));
    assert!(!msg.contains("D88086"));
}
```

---

## Appendix A: Key Slot Quick Reference

| Slot | Name | Tool | Algorithm |
|------|------|------|-----------|
| 0x00 | pfsSKKey__SecKey | trophy-tool, savedata-tool | AES-256-CBC + HMAC-SHA1 |
| 0x44 | livedump_secure | livedump-tool | AES-128-CBC ENCDEC |
| 0x48 | SceHidAuth | controller-auth | AES-128-CBC + HMAC-SHA1 |
| 0x50 | SIEIPMISceIpmiMgrEQSx | ipmi-tool | AES-128-CBC ENCDEC |
| 0x54 | pfs_sbl | pfs-sbl | AES-128-CBC ENCDEC + CMAC |
| 0x58 | pfs_sd_auth | savedata-tool | AES-128-CBC ENCDEC |

---

## Appendix B: File Format Summary

| Tool | Input Format | Output Format | Magic Bytes |
|------|--------------|---------------|-------------|
| trophy-tool | Trophy.trp | Decrypted TRP | `TRPF` / `PSF` |
| savedata-tool | .sav, sealedkey | Decrypted data | Variable |
| controller-auth | HID capture | Analysis report | `0xF0`/`0xF1` |
| livedump-tool | .dmp | Decrypted dump | `LIVEDUMP` |
| pfs-sbl | .pfs | Decrypted image | `PFS1` |
| ipmi-tool | Binary capture | Decoded messages | Version byte |

---

## Appendix C: Implementation Checklist

### Per-Tool Checklist

- [ ] Key loading with console type selection
- [ ] SecretBox wrapper for all key material
- [ ] MAC verification before decryption
- [ ] Constant-time MAC comparison
- [ ] ENCDEC cipher with zero IV option
- [ ] CLI interface matching specification
- [ ] Unit tests with known vectors
- [ ] Integration tests with fixtures
- [ ] ZeroizeOnDrop for all secrets
- [ ] No key material in logs/errors

### Cross-Tool Checklist

- [ ] Shared `he-crypto::ps4` module
- [ ] Common error types
- [ ] Consistent key file format
- [ ] Unified CLI pattern
- [ ] Feature flags for optional components

---

*PS4-Compatible Tools Specification v1.0.0 - Heavy Elephant Project*
