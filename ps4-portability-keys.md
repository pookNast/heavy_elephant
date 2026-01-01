# PS4 Portability Keys Reference

> **Source**: PSDevWiki PS4/Keys
> **Purpose**: PS5 security research - PS5 documentation references these as "same as PS4"
> **Last Updated**: 2025-12-31

---

## Master Portability Keys

### Type E (Retail) - pfsSKKey__SecKey

| Key Type | Hex Value |
|----------|-----------|
| AES Key 1 | `9EA5CD89DA8DAB6E66CE6D345752639D` |
| AES Key 2 | `9A4EE51EEAF084D970FEFC2850F7604E` |
| HMAC | `D8808616FA98B0BF50A499D5FA5DCCA7` |

### Type I (Internal/DevKit) - pfsSKKey__SecKey

| Key Type | Hex Value |
|----------|-----------|
| AES Key 1 | `6CEDCF30A30306F3AAE52B51B93726FD` |
| AES Key 2 | `E18CE3B2B1ED8BB74BDE51D712349314` |
| HMAC | `096459F1A0C8C5DDDD404E40A4CEBF6C` |

---

## Sealed Key Material (Subsystem 0x0)

### Shared IV
```
sealedkey_key_IV: F6 00 16 BA CD 42 AD 21 C7 0D 9B 07 5C B5 19 83
```

### Type E (Retail)
```
sealedkey_key: AC 81 12 EC 4B B2 E1 4D... (256-byte key)
sealedkey_key_sign: E0 B8 33 73 96 0E F4 46 C2 C7 04 BB 25 9B 27 DA 39 70 D0 AE EF 3E 72 62 7C D1 5E FF 8B FC FC F0
```

### Type I (Internal/DevKit)
```
sealedkey_key: 7D 72 D3 AD 98 30 8C 5B... (256-byte key)
sealedkey_key_sign: 2A E5 A0 FB C1 4F C7 34 F5 3B EB B7 13 CE B7 2D 7E 62 06 E6 09 05 AE 28 E3 5B FB D2 8E E1 EC 78
```

---

## Indexed Portability Subsystem Keys

### 0x4 - Generic Subsystem

| Key Type | Hex Value |
|----------|-----------|
| AES Key 1 | `231D69F73D12C55164D5A40A10DB5170` |
| AES Key 2 | `4DF980998A155CE381966E6521C572C6` |
| HMAC | `B3547B179154B3C9AC96304B4F9AEA73` |

---

### 0x5 - AACS Blu-ray

| Key Type | Hex Value |
|----------|-----------|
| AES Key 1 | `21E474E20845F868B1EADBC90C7BE001` |
| AES Key 2 | `CF7FBB1A479716EA02F8A30B23C577BB` |
| HMAC | `94CA4FDC575C812E9E0432459E30DB75` |

---

### 0x6 - CSS Blu-ray

| Key Type | Hex Value |
|----------|-----------|
| AES Key 1 | `A48932A314C75ED5321764638B7A2FE8` |
| AES Key 2 | `9EF8ADB044C01302936910C25FD7410E` |
| HMAC | `6E30BD54F52053CA6B68F9F23B7FD216` |

---

### 0x7 - BdPlus Blu-ray

| Key Type | Hex Value |
|----------|-----------|
| AES Key 1 | `7B626924420F5F8D7BC5CBF7BC803C27` |
| AES Key 2 | `DAFA0EA507083AF6D91033548BCFB216` |
| HMAC | `8FAA08823BF7354F0999D0D8A7F0A893` |

---

### 0x8 - index.dat

#### Type E (Retail)
| Key Type | Hex Value |
|----------|-----------|
| AES Key 1 | `CC3C6CD60871591A5A6C6347B2100CA2` |
| AES Key 2 | `FC286633A4D9482B9313FEE574E04338` |

#### Type I (Internal/DevKit)
| Key Type | Hex Value |
|----------|-----------|
| AES Key 1 | `331BDC5EF45CA0CADEB210DDC309C1D2` |
| AES Key 2 | `4E0059E82E1626F24A1855696BE324B2` |

#### Shared IV
```
310CC1BD68FA39AF74FB07A6C67B6CBF
```

---

### 0xC - CFK1 Crash Report

#### Type E (Retail)
| Key Type | Hex Value |
|----------|-----------|
| AES Key 1 | `36902DC7BD1EC112BE122D2CD9ABEBB2` |
| AES Key 2 | `29AA7D0164D30385733753EEAE20E6F4` |

#### Type I (Internal/DevKit)
| Key Type | Hex Value |
|----------|-----------|
| AES Key 1 | `16BC4CCEABEA9F03D2EB670BD29630A1` |
| AES Key 2 | `882D16F707FD33FA2ABFEC130F60EEFF` |

---

### 0xD - Hostnames

#### Type E (Retail)
| Key Type | Hex Value |
|----------|-----------|
| AES Key 1 | `BDA98742518157C4634A21FBB47C8311` |
| AES Key 2 | `D21CE6016404D8CB2EF0C24462C42C38` |

#### Type I (Internal/DevKit)
| Key Type | Hex Value |
|----------|-----------|
| AES Key 1 | `8FC2405D96B41290DF62525E536E37B6` |
| AES Key 2 | `42D798F0538B7FB42829C05ECBB00B08` |

---

### 0x10 - Logger

#### Type E (Retail)
| Key Type | Hex Value |
|----------|-----------|
| AES Key 1 | `32AF1AE6A8B408ACA7072C9364BF8A36` |
| AES Key 2 | `BA19E55263F00585EA2653311747A1E4` |

#### Type I (Internal/DevKit)
| Key Type | Hex Value |
|----------|-----------|
| AES Key 1 | `05E051FEDB737FEEA2FFA6D78AAC1613` |
| AES Key 2 | `2ABAE36253F2A291C2EF0A1ACADAE1D1` |

#### Shared IV
```
A1D989B020185024F4C448283537540B
```

---

### 0x14 - SCEROOTPARAM_KEY

#### Type E (Retail)
| Key Type | Hex Value |
|----------|-----------|
| AES Key 1 | `3A9980C60B2752B1E5C9437C8BE0730E` |
| AES Key 2 | `057683371B0207B1B63D32412D41AAC3` |

#### Type I (Internal/DevKit)
| Key Type | Hex Value |
|----------|-----------|
| AES Key 1 | `190C5FD353B619FFE1CEE8DEB9F828DA` |
| AES Key 2 | `60F0ADA572E1C5CB30BC259BD0818C66` |

#### Shared IV
```
95 69 82 9C D4 B1 5F F8 43 30 54 5A 34 EC 1B C5
```

---

## Additional Subsystem Keys (Indices 0x18-0x5C)

The following subsystem indices are documented on PSDevWiki but require direct page access for full hex values:

| Index | Purpose | Notes |
|-------|---------|-------|
| 0x18 | TBD | AES/HMAC keys documented |
| 0x1C | TBD | AES/HMAC keys documented |
| 0x20 | TBD | AES/HMAC keys documented |
| 0x24 | TBD | AES/HMAC keys documented |
| 0x28 | TBD | AES/HMAC keys documented |
| 0x3C | TBD | AES/HMAC keys documented |
| 0x40 | TBD | AES/HMAC keys documented |
| 0x44 | TBD | AES/HMAC keys documented |
| 0x48 | TBD | AES/HMAC keys documented |
| 0x4C | TBD | AES/HMAC keys documented |
| 0x50 | TBD | AES/HMAC keys documented |
| 0x54 | TBD | AES/HMAC keys documented |
| 0x58 | TBD | AES/HMAC keys documented |
| 0x5C | TBD | AES/HMAC keys documented |

---

## Key Architecture Notes

### Key Types
- **AES**: 128-bit symmetric encryption keys (used in pairs for ENCDEC operations)
- **HMAC**: Message authentication codes for integrity verification
- **IV**: Initialization vectors for cipher block chaining

### Type Classification
- **Type E**: Retail/consumer hardware keys
- **Type I**: Internal/DevKit hardware keys

### PFS (PlayStation File System) Keys
- `pfsSKKey__SecKey` is the master key for PFS encryption
- Used for save data, trophy data, and system file encryption
- Two AES keys used together for ENCDEC (encrypt-decrypt) operations

### Sealed Keys
- 256-byte keys used for securing sensitive data at rest
- Requires corresponding sign keys for authentication
- Shared IV used across retail and devkit variants

---

## References

- PSDevWiki PS4/Keys: https://www.psdevwiki.com/ps4/Keys
- PS5 uses "same as PS4" for portability subsystem compatibility
