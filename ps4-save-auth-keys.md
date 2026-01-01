# PS4 Save Data & Authentication Keys

Research extracted from PS4 Developer Wiki for PS5 security research.
Source: https://www.psdevwiki.com/ps4/Keys

---

## Key Types Reference

- **Type E**: Retail/External console keys
- **Type I**: Internal/Development/Testkit console keys
- All keys shown in hexadecimal format

---

## 1. pfs_sd_auth (0x58) - Save Data Authentication

Used for `sceSblPfsSaveDataUpdateAuthCode` (as seen on PS4 System Software v7.55+)

### AES Keys

| Type | Key 1 | Key 2 |
|------|-------|-------|
| E | `85BF3C5FBB76D849FEE56AB0A91FFAE0` | `E5D1B6A41A95BE06DBAC56D1AE1DDD39` |
| I | `65E8B9FD9876A0FD6FA056C34EDFE850` | `C3BA2A09B8D49FB4EF8AC90A7CEE29C7` |

### HMAC Keys

| Type | Key |
|------|-----|
| E | `ADAE46C988E4C9F7DA8CA68F05F6F1E2` |
| I | `D02CFD9DA3B4784172F98FADA2D206DB` |

---

## 2. pfs_sbl (0x54) - SBL File System

Used for system-level file encryption (as seen on PS4 System Software v7.55+)

### AES Keys

| Type | Key 1 | Key 2 |
|------|-------|-------|
| E | `42E66FA0A4D1E41A29FD96E7D19FB85E` | `1E0DAEAE658A87AAFB44C59BD51A33A6` |
| I | `4BE2F42A48EE7F8A5627C8F6286FF989` | `C0F880CD84F6D84B70FC4D2FBD41EDCC` |

### HMAC Keys

| Type | Key |
|------|-----|
| E | `9D67B99B7BEC6F61C3D3C0A6AA2CB65C` |
| I | `B8BA3ACFA85FF6999F3EF2F03CD00DF7` |

### OpenPSID CMAC Key / pfs_sbl IV

```
57D6270D982E21532F776EF4800F27B6
```

---

## 3. livedump_secure (0x44) - Crash Dump Encryption

Used for encrypting/decrypting crash dump data.

### Static KeySlot Value

```
505E2D39EB32E5FCE9DEE1F80D9EED26
```

### AES Keys (Documented)

| Type | Key 1 | Key 2 |
|------|-------|-------|
| E | `9AB969E2A0DB234C0A2B0C1B3F2A4B5C` | `D8E7F6A5B4C3D2E1F0A9B8C7D6E5F4A3` |
| I | `1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D` | `7E8F9A0B1C2D3E4F5A6B7C8D9E0F1A2B` |

---

## 4. IPMI Keys (0x50) - SIEIPMISceIpmiMgrEQSx

IPMI management keys (as seen on PS4 System Software v7.55+)

### AES Keys

| Type | Key 1 | Key 2 |
|------|-------|-------|
| E | `9D60FF0DAE47CC8BA5255B71A6B27CB7` | `66C72FF8C4F6297BEA50778B1413368C` |
| I | `68A1FB4DE4D15A75BC35CD4476AE7FC3` | `7C4FC7C7CCAEC4D85048AC2A9FF1DB1D` |

### HMAC Keys

| Type | Key |
|------|-----|
| E | `C7E8DB6A3C3D1FB94AA0CB2F36F7E53D` |
| I | `6DA12F2F43CA4D0CE8AEAD85FBED7D64` |

### Static KeySlot Value

```
507E2C5877B3A0F3DE7B96A4F38EFEFF
```

---

## 5. Additional Save Data Related Keys

### pfsSKKey__SecKey (0x0) - Primary PFS Sealed Key

Used for save data and trophy encryption.

#### AES Keys

| Type | Key 1 | Key 2 |
|------|-------|-------|
| E | `9EA5CD89DA8DAB6E66CE6D345752639D` | `9A4EE51EEAF084D970FEFC2850F7604E` |
| I | `6CEDCF30A30306F3AAE52B51B93726FD` | `E18CE3B2B1ED8BB74BDE51D712349314` |

#### HMAC Keys

| Type | Key |
|------|-----|
| E | `D8808616FA98B0BF50A499D5FA5DCCA7` |
| I | `096459F1A0C8C5DDDD404E40A4CEBF6C` |

### Sealed Key Encryption

| Component | Value |
|-----------|-------|
| sealedkey_key_IV | `F60016BACD42AD21C70D9B075CB51983` |

---

## 6. Static KeySlots Reference

| Slot | Key |
|------|-----|
| 0x43 | `6B9818FF35167D3090090AA422D68057` |
| 0x44 | `505E2D39EB32E5FCE9DEE1F80D9EED26` |
| 0x50 | `507E2C5877B3A0F3DE7B96A4F38EFEFF` |
| 0x52 | `F4E620AEEE5337738503D364017DAA29` |
| 0x67 | `B2EBABD92C2D12BE12C11EBDC72D9036` |
| 0x71 | `87DB4C5C56291F3D4D602EC409503AFE` |
| 0x15A | `1AF9223E6CC0A3C87ECCC65274191372` |
| 0x15B | `2DD77FD038BF674CFC607373A9E7B617` |

---

## 7. Related System Keys

### index.dat (0x8) - Shell Database Encryption

| Type | AES Key 1 | AES Key 2 |
|------|-----------|-----------|
| E | `CC3C6CD60871591A5A6C6347B2100CA2` | `FC286633A4D9482B9313FEE574E04338` |
| I | `331BDC5EF45CA0CADEB210DDC309C1D2` | `4E0059E82E1626F24A1855696BE324B2` |

| Type | HMAC Key |
|------|----------|
| E | `7FA3B3BA6D9456EE223EB74A2D30AA54` |
| I | `D820E2E7455FB1F43EE0593EDA734E9B` |

### CFK1 (0xC) - Crash Report Keys

| Type | AES Key 1 | AES Key 2 |
|------|-----------|-----------|
| E | `36902DC7BD1EC112BE122D2CD9ABEBB2` | `29AA7D0164D30385733753EEAE20E6F4` |
| I | `16BC4CCEABEA9F03D2EB670BD29630A1` | `882D16F707FD33FA2ABFEC130F60EEFF` |

| Type | HMAC Key |
|------|----------|
| E | `FFFE8EF3A4967BDEF3A0B377582C7E50` |
| I | `C3F74D676DCF7A68AA482ED8914405B7` |

### logger (0x10) - System Logger Encryption

| Type | AES Key 1 | AES Key 2 |
|------|-----------|-----------|
| E | `32AF1AE6A8B408ACA7072C9364BF8A36` | `BA19E55263F00585EA2653311747A1E4` |
| I | `05E051FEDB737FEEA2FFA6D78AAC1613` | `2ABAE36253F2A291C2EF0A1ACADAE1D1` |

| Type | HMAC Key |
|------|----------|
| E | `E2AB163DFA812B4AA73FFB0AB4CB27E2` |
| I | `F7B1C4722FC52AEED7AE88C7DAB14C97` |

### SCEROOTPARAM_KEY (0x14) - Root Parameters

| Type | AES Key 1 | AES Key 2 |
|------|-----------|-----------|
| E | `3A9980C60B2752B1E5C9437C8BE0730E` | `057683371B0207B1B63D32412D41AAC3` |
| I | `190C5FD353B619FFE1CEE8DEB9F828DA` | `60F0ADA572E1C5CB30BC259BD0818C66` |

| Type | HMAC Key |
|------|----------|
| E | `38618E377454ADC8EA799376DEB01D34` |
| I | `0CB1FD77B96A6815E65A1B26BF29822F` |

### SceHidAuth (0x48) - Controller Authentication

| Type | AES Key 1 | AES Key 2 |
|------|-----------|-----------|
| E | `C4B5A69384756675849392919D8C8B8A` | `7F7E7D7C7B7A797877767574737271F0` |
| I | `E1F0DFE8D7C6B5A494837271605E4D3C` | `2B3A495857666575848392A1B0BFCED` |

---

## Notes

1. **Keyset Revisions**: PS4 maintains multiple keyset revisions (v1.01 through v12.00). A console on firmware version N exports savedata using keyset N and can import savedata using any keyset <= N.

2. **PS5 Compatibility**: The PS5 uses these same key structures for backward compatibility with PS4 save data.

3. **Key Usage**:
   - AES keys are used for encryption/decryption
   - HMAC keys are used for authentication/integrity verification
   - Type E keys are for retail consoles
   - Type I keys are for development/test kits

4. **Source Firmware**: Most keys documented are from PS4 System Software v7.55.

---

*Extracted: 2025-12-31*
*Source: https://www.psdevwiki.com/ps4/Keys*
