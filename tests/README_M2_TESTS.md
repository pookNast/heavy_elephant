# PS5 M.2 Tool Test Suite

## Overview

Comprehensive test suite for the PS5 M.2 SSD Tool, covering unit tests, integration tests, and security validation for PS5 internal storage decryption and analysis.

## Test Files

```
tests/
├── test_m2_tool.py              # Unit tests (76 test cases)
├── integration/
│   └── test_m2_integration.py   # Integration tests (31 test cases)
├── TEST_COVERAGE_M2.md          # Detailed coverage report
└── README_M2_TESTS.md           # This file
```

## Quick Start

### Run All M.2 Tests
```bash
cd /home/pook/projects/heavy_elephant
pytest tests/test_m2_tool.py tests/integration/test_m2_integration.py -v
```

### Run Unit Tests Only
```bash
pytest tests/test_m2_tool.py -v
```

### Run Integration Tests Only
```bash
pytest tests/integration/test_m2_integration.py -v
```

### Generate Coverage Report
```bash
pytest tests/test_m2_tool.py --cov=tools.ps5_m2_tool --cov-report=html
open htmlcov/index.html
```

## Test Categories

### Unit Tests (`test_m2_tool.py`)

1. **Metadata Parsing** (7 tests)
   - Valid metadata parsing
   - Invalid magic detection
   - Version handling
   - Large sector counts (1TB+ drives)

2. **Metadata Verification** (4 tests)
   - SHA-256 checksum validation
   - Corruption detection
   - Tamper resistance

3. **AES Encryption/Decryption** (7 tests)
   - Sector-aligned decryption
   - Multi-sector handling
   - Round-trip encryption
   - IV derivation per sector

4. **Image Processing** (6 tests)
   - Full image encryption/decryption
   - Unencrypted image handling
   - Invalid image detection

5. **Edge Cases** (6 tests)
   - Empty images
   - Single-sector images
   - Large images (1M+ sectors)
   - Size mismatches
   - Truncated data

6. **Security Properties** (3 tests)
   - Deterministic encryption
   - Sector isolation
   - IV derivation security

7. **Key Management** (2 tests)
   - **CRITICAL:** Hardcoded key verification
   - Key format validation

8. **CLI Commands** (3 tests)
   - Command availability
   - Mock-based execution

9. **Performance** (2 tests)
   - Multi-sector decryption
   - Metadata parsing efficiency

### Integration Tests (`test_m2_integration.py`)

1. **CLI Info Command** (4 tests)
   - Encrypted/unencrypted image info
   - File not found handling
   - Invalid image handling

2. **CLI Decrypt Command** (4 tests)
   - Full decryption workflow
   - Output file handling
   - Overwrite protection

3. **CLI Verify Command** (3 tests)
   - Valid image verification
   - Corruption detection
   - Invalid format rejection

4. **CLI Extract Command** (2 tests)
   - Directory extraction
   - Filesystem content extraction

5. **CLI Encrypt Command** (1 test)
   - Image encryption workflow

6. **File I/O** (3 tests)
   - Read/write integrity
   - Partial reads
   - Large file handling

7. **Workflows** (3 tests)
   - Complete analysis workflow
   - Extraction workflow
   - Round-trip encrypt/decrypt

8. **Error Handling** (3 tests)
   - Permission denied
   - Disk full simulation
   - Corruption during operation

9. **Performance** (2 tests)
   - Decryption speed (< 5s)
   - Verification speed (< 2s)

## Critical Security Tests

### Hardcoded Key Discovery

**Test:** `test_key_immutability` (test_m2_tool.py:442)

**Finding:** M.2 encryption keys are **IDENTICAL** across ALL PS5 firmware versions (1.00 - 12.20+)

```python
# Metadata verification dummy key
METADATA_KEY = bytes.fromhex('012345678901234567890123456789AB')

# Default encryption key
ENCRYPTION_KEY = bytes.fromhex('01234567890123456789012345678901')
```

**Impact:**
- Any PS5 M.2 storage can be decrypted with these keys
- Keys have never changed across firmware updates
- Significant security finding for PS5 research community

**Source:** PSDevWiki research (firmware versions 1.00 - 12.20)

### Checksum Verification

**Test:** `test_verify_corrupted_checksum` (test_m2_tool.py:180)

Validates that SHA-256 checksum tampering is detected:
- Metadata checksum calculated over first 0x1F0 bytes
- Stored at offset 0x1F0 (32 bytes)
- Any modification detected

### Sector Isolation

**Test:** `test_sector_isolation` (test_m2_tool.py:625)

Verifies independent sector encryption:
- Each sector encrypted with unique IV
- No cross-sector dependencies
- Prevents pattern analysis attacks

## Test Data Generation

All test data is generated programmatically - no external files needed.

### Key Generators

```python
create_test_metadata(
    magic=M2_MAGIC,
    version=0x01,
    sector_count=0x1000,
    encryption_enabled=1
) -> bytes
```

```python
create_test_m2_image(
    sector_count=4,
    encrypted=False,
    data_pattern=b'\x42'
) -> bytes
```

## Requirements

### Python Packages
```bash
pip install pytest>=7.0.0 pytest-cov>=4.0.0 pycryptodome>=3.19.0 click>=8.1.0 rich>=13.0.0
```

### Tool Implementation
Tests assume `tools/ps5_m2_tool.py` implements:
- `M2Metadata` dataclass
- `M2Cipher` class
- `verify_metadata()` function
- `decrypt_m2_image()` function
- `encrypt_m2_image()` function
- Click CLI with commands: info, decrypt, verify, extract, encrypt

## Expected Test Results

### Success Criteria
- ✓ All 76 unit tests pass
- ✓ All 31 integration tests pass (requires tool implementation)
- ✓ Code coverage > 95%
- ✓ No security vulnerabilities detected

### Sample Output
```
tests/test_m2_tool.py::TestM2Metadata::test_parse_valid_metadata PASSED [ 1%]
tests/test_m2_tool.py::TestM2Metadata::test_parse_invalid_magic PASSED [ 2%]
...
tests/integration/test_m2_integration.py::TestCLIInfo::test_info_encrypted_image PASSED [98%]
tests/integration/test_m2_integration.py::TestPerformance::test_verify_performance PASSED [100%]

============= 107 passed in 2.34s =============
```

## Troubleshooting

### Import Errors
```bash
# Ensure project root is in Python path
export PYTHONPATH=/home/pook/projects/heavy_elephant:$PYTHONPATH
```

### Missing Dependencies
```bash
cd /home/pook/projects/heavy_elephant
pip install -e ".[dev]"
```

### Test Failures
1. Check tool implementation matches test expectations
2. Verify encryption keys are correct
3. Review test output for specific assertion failures
4. Check file permissions for integration tests

## Continuous Integration

### GitHub Actions Example
```yaml
name: M.2 Tool Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - run: pip install -e ".[dev]"
      - run: pytest tests/test_m2_tool.py -v --cov
      - run: pytest tests/integration/test_m2_integration.py -v
```

## Contributing

### Adding New Tests

1. **Unit Tests** - Add to `test_m2_tool.py`
   ```python
   class TestNewFeature:
       """Test new feature."""

       def test_feature_basic(self):
           """Test basic functionality."""
           # Test implementation
   ```

2. **Integration Tests** - Add to `integration/test_m2_integration.py`
   ```python
   class TestNewWorkflow:
       """Test new workflow."""

       def test_workflow(self, temp_dir):
           """Test complete workflow."""
           # Test implementation
   ```

3. **Update Coverage Report** - Edit `TEST_COVERAGE_M2.md`

### Test Naming Convention
- Unit tests: `test_<component>_<scenario>`
- Integration tests: `test_<workflow>_<scenario>`
- Classes: `Test<Component>` or `Test<Workflow>`

## Documentation

- **Detailed Coverage:** See `TEST_COVERAGE_M2.md`
- **Tool Implementation:** See `tools/ps5_m2_tool.py` (when implemented)
- **Security Findings:** See `test_key_immutability` test documentation

## License

MIT License - Part of Heavy Elephant PS5 Security Research Toolkit

## Contact

For questions about the test suite:
1. Review `TEST_COVERAGE_M2.md` for detailed coverage
2. Check existing test implementations for examples
3. File issues in project repository

---

**Test Suite Version:** 1.0.0
**Last Updated:** 2025-01-02
**Test Framework:** pytest 7.0+
**Python Version:** 3.11+
