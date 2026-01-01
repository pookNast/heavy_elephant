# PS4/PS5 Trophy and HID Authentication Keys

> **Source:** https://www.psdevwiki.com/ps4/Keys
> **Purpose:** PS5 Security Research - These keys are shared between PS4 and PS5 systems
> **Date:** 2025-12-31

---

## Table of Contents

1. [SceHidAuth - Controller Authentication Keys](#scehidauth---controller-authentication-keys)
2. [Trophy Encryption Keys](#trophy-encryption-keys)
3. [PFS Sealed Key Keys (Used by Trophy System)](#pfs-sealed-key-keys)
4. [SceShellCore Keys](#sceshellcore-keys)
5. [Static KeySlots](#static-keyslots)
6. [Additional Kernel Keys](#additional-kernel-keys)
7. [Key Slot Reference Table](#key-slot-reference-table)

---

## SceHidAuth - Controller Authentication Keys

**Key Slot:** `0x48`
**Purpose:** Human Interface Device (HID) authentication for DualShock 4/DualSense controllers
**Component:** Kernel

### AES Keys (128-bit)

#### Type E (External/Retail)
```
BDA98742518157C4634A21FBB47C8311
D21CE6016404D8CB2EF0C24462C42C38
```

#### Type I (Internal/DevKit)
```
8FC2405D96B41290DF62525E536E37B6
42D798F0538B7FB42829C05ECBB00B08
```

### HMAC Keys (128-bit)

#### Type E (External/Retail)
```
AED0BCC3264D91A698E4D7D8CA428E52
```

#### Type I (Internal/DevKit)
```
A43C5B248AEF15C4CEFAEA170F6F31F7
```

---

## Trophy Encryption Keys

**Component:** SceShellCore
**Purpose:** Trophy data encryption/decryption
**Algorithm:** AES-256 (two 128-bit key components)

### Trophy Key (Combined 256-bit)
```
9EA5CD89DA8DAB6E66CE6D345752639D9A4EE51EEAF084D970FEFC2850F7604E
```

#### Key Components (128-bit each)
```
Part 1: 9EA5CD89DA8DAB6E66CE6D345752639D
Part 2: 9A4EE51EEAF084D970FEFC2850F7604E
```

---

## PFS Sealed Key Keys

**Key Slot:** `0x0` (pfsSKKey__SecKey)
**Purpose:** PFS encryption/decryption for save data and trophies
**Component:** Kernel

### AES Keys (128-bit)

#### Type E (External/Retail)
```
9EA5CD89DA8DAB6E66CE6D345752639D
9A4EE51EEAF084D970FEFC2850F7604E
```

#### Type I (Internal/DevKit)
```
6CEDCF30A30306F3AAE52B51B93726FD
E18CE3B2B1ED8BB74BDE51D712349314
```

### HMAC Keys (128-bit)

#### Type E (External/Retail)
```
D8808616FA98B0BF50A499D5FA5DCCA7
```

#### Type I (Internal/DevKit)
```
096459F1A0C8C5DDDD404E40A4CEBF6C
```

---

## SceShellCore Keys

### param.sfo OpenPSID HMAC-SHA256 Key
**Purpose:** HMAC-SHA256 Key for Sealedkey / pfsSKKey verification
**Note:** Consistent across PS4 system software from 1.01+
```
8707960A53468D6C843B3DC9624E22AF
```

### RSA-2048 HID Config Service Keys
**Purpose:** HID configuration service signature verification
**Type:** RSA-2048 public key with P, Q components

> Note: Complete RSA modulus and private key components documented in wiki sections 13.3.1-13.3.4

---

## Static KeySlots

These keys have unknown usage but appear consistently across multiple PS4 firmware dumps:

| Slot | Hex Value |
|------|-----------|
| 0x43 | `6B9818FF35167D3090090AA422D68057` |
| 0x44 | `505E2D39EB32E5FCE9DEE1F80D9EED26` |
| 0x50 | `507E2C5877B3A0F3DE7B96A4F38EFEFF` |
| 0x52 | `F4E620AEEE5337738503D364017DAA29` |
| 0x67 | `B2EBABD92C2D12BE12C11EBDC72D9036` |
| 0x71 | `87DB4C5C56291F3D4D602EC409503AFE` |
| 0x15A | `1AF9223E6CC0A3C87ECCC65274191372` |
| 0x15B | `2DD77FD038BF674CFC6073A9E7B61776` |

---

## Additional Kernel Keys

### Crash Report Key (0xC - CFK1)
**Purpose:** Crash report encryption

#### AES Type E
```
36902DC7BD1EC112BE122D2CD9ABEBB2
29AA7D0164D30385733753EEAE20E6F4
```

### Bluray AACS Key (0x5)
**Purpose:** Blu-ray disc authentication

#### AES Key
```
21E474E20845F868B1EADBC90C7BE001
CF7FBB1A479716EA02F8A30B23C577BB
```

### Rootparam Key (0x14 - SCEROOTPARAM_KEY)
**Purpose:** Rootparam SFO/JSON verification by SceShellCore

#### AES Type E
```
3A9980C60B2752B1E5C9437C8BE0730E
057683371B0207B1B63D32412D41AAC3
```

---

## Key Slot Reference Table

### Kernel Keys

| Slot | Name | Purpose |
|------|------|---------|
| 0x0 | pfsSKKey__SecKey | PFS encryption for save data & trophies |
| 0x5 | Bluray AACS | Blu-ray disc authentication |
| 0xC | CFK1 | Crash report encryption |
| 0x14 | SCEROOTPARAM_KEY | Rootparam verification |
| 0x1C | SCECloudSD___KEY | Cloud save data encryption |
| 0x20 | sbl_srv_ioctl | SBL service I/O control |
| 0x24 | SCE_LwUtoken_Key | Lightweight user token |
| 0x28 | SCE_SBL_BAR_KEY1 | Backup and restore |
| 0x44 | livedump_secure | Live dump security |
| 0x48 | SceHidAuth | Controller/HID authentication |
| 0x4C | SCE_KDF_NCDT_PSK | Network key derivation |
| 0x50 | SIEIPMISceIpmiMgrEQSx | IPMI management (v7.55+) |
| 0x54 | pfs_sbl | PFS SBL encryption (v7.55+) |
| 0x58 | pfs_sd_auth | SD auth update (v7.55+) |

### SceShellCore Keys

| Slot | Name | Purpose |
|------|------|---------|
| 0x8 | Index.dat | Game index database encryption |
| 0xD | Hostnames | Connection hostname encryption |
| 0x10 | SystemLogger | System logging encryption |
| 0x3C | GetOpenPsIdHash | OpenPSID hash encryption |
| 0x40 | Envelope Files | Patch envelope message encryption |

---

## DualShock 4 / DualSense Controller Keys

The PS4 wiki documents additional DS4-specific keys:

- **Jedi Master Key V1:** Used for all V1 DS4 controller models
- **Jedi Master Key V2:** Used for JDM-030 and JDM-040 models
- **DS4 Bootloader Key:** Controller firmware bootloader
- **DS4 App 0/1 Keys:** Application-level controller keys
- **DS4 Certificate Authority Modulus:** CA for controller certificates

> Note: Complete hex values for DS4 keys are documented in wiki sections 14.1-14.3

---

## Notes for PS5 Research

1. **Key Compatibility:** Many PS4 keys are reused in PS5 for backward compatibility
2. **Trophy System:** PS5 uses the same trophy encryption mechanism for PS4 games
3. **Controller Auth:** SceHidAuth keys are relevant for DualSense authentication research
4. **PFS Keys:** Protected File System keys apply to both platforms

---

## References

- Primary Source: https://www.psdevwiki.com/ps4/Keys
- Trophy Structure: https://www.psdevwiki.com/ps4/Trophy
- DualShock 4 Info: https://www.psdevwiki.com/ps4/DualShock_4
