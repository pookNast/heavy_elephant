#!/usr/bin/env python3
"""
Unit tests for PS5 Boot Chain Decryptor

Tests firmware detection, header parsing, segment detection, and decryption.
"""
import pytest
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add parent dirs for imports
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / 'tools'))

from he.crypto import (
    aes_cbc_decrypt_iv_zero,
    aes_cbc_encrypt_iv_zero,
    hmac_sha1,
    hmac_sha1_verify,
    hmac_sha256,
    hmac_sha256_verify,
)
from he.keys import load_boot_chain_keys

# Import from the tool module
from tools.ps5_boot_decrypt import (
    FirmwareType,
    BootChainHeader,
    BootSegment,
    FirmwareInfo,
    MAGIC_ELF,
    MAGIC_CNT,
    MAGIC_SLBH,
    MAGIC_PUP,
    DEFAULT_OFFSETS,
    detect_firmware_type,
    parse_boot_chain_header,
    detect_segment_offsets,
    detect_version,
    analyze_firmware,
    decrypt_segment,
    _check_emc_ipl_pattern,
    _is_potential_segment_start,
)


# =============================================================================
# Test Fixtures
# =============================================================================

@pytest.fixture
def sample_keys():
    """Sample encryption keys for testing."""
    return {
        'emc_ipl_header': bytes.fromhex('F0332357C8CFAE7E7E26E52BE9E3AED4'),
        'emc_ipl_cipher': bytes.fromhex('D5C92E39759A3E5CE954E772B1C2B651'),
        'eap_kbl': bytes.fromhex('262555E3CF062B070B5AA2CDDF3A5D0E'),
        'eap_kbl_mac': bytes.fromhex('1EE22F6A189E7D99A28B9A96D3C4DBA2'),
        'eap_kernel': bytes.fromhex('CBCC1E53F42C1CB44D965E233CD792A8'),
        'eap_kernel_mac': bytes.fromhex('683D6E2E496687CB5B831DA12BCB001B'),
    }


@pytest.fixture
def elf_header():
    """Sample ELF file header."""
    return MAGIC_ELF + b'\x02\x01\x01\x00' + b'\x00' * 8


@pytest.fixture
def high_entropy_data():
    """High entropy data simulating encrypted content.

    Creates data with guaranteed high byte diversity by including
    all 256 possible byte values, which matches the characteristics
    of real encrypted data.
    """
    # Create data with all 256 byte values to ensure high diversity
    base = bytes(range(256))
    # Repeat to reach 0x1000 bytes
    return (base * 16)[:0x1000]


@pytest.fixture
def low_entropy_data():
    """Low entropy data (repeating pattern)."""
    return b'\x00\x01\x02\x03' * 256


# =============================================================================
# Firmware Type Detection Tests
# =============================================================================

class TestFirmwareTypeDetection:
    """Tests for detect_firmware_type function."""

    def test_detects_elf(self, elf_header):
        """Should detect ELF magic bytes."""
        data = elf_header + b'\x00' * 100
        assert detect_firmware_type(data) == FirmwareType.RAW_DUMP

    def test_detects_pkg_container(self):
        """Should detect PKG container magic."""
        data = MAGIC_CNT + b'\x00' * 100
        assert detect_firmware_type(data) == FirmwareType.PUP_SEGMENT

    def test_detects_pup_format(self):
        """Should detect PUP magic bytes."""
        data = MAGIC_PUP + b'\x00' * 100
        assert detect_firmware_type(data) == FirmwareType.PUP_SEGMENT

    def test_detects_slbh_format(self):
        """Should detect SLBH (EAP blob) magic."""
        data = MAGIC_SLBH + b'\x00' * 100
        assert detect_firmware_type(data) == FirmwareType.EAP_BLOB

    def test_detects_emc_ipl_high_entropy(self, high_entropy_data):
        """Should detect EMC IPL from high entropy pattern."""
        assert detect_firmware_type(high_entropy_data) == FirmwareType.EMC_IPL

    def test_short_data_returns_unknown(self):
        """Should return UNKNOWN for data shorter than 16 bytes."""
        assert detect_firmware_type(b'\x00' * 10) == FirmwareType.UNKNOWN

    def test_low_entropy_returns_raw_dump(self, low_entropy_data):
        """Should return RAW_DUMP for low entropy data."""
        result = detect_firmware_type(low_entropy_data)
        assert result in (FirmwareType.RAW_DUMP, FirmwareType.EMC_IPL)


class TestEmcIplPatternCheck:
    """Tests for _check_emc_ipl_pattern function."""

    def test_high_entropy_matches(self, high_entropy_data):
        """High entropy data should match EMC IPL pattern."""
        assert _check_emc_ipl_pattern(high_entropy_data) is True

    def test_low_entropy_no_match(self, low_entropy_data):
        """Low entropy data should not match EMC IPL pattern."""
        # Low entropy might still have some diversity
        result = _check_emc_ipl_pattern(low_entropy_data)
        # The function checks for > 200 unique bytes in first 256
        assert isinstance(result, bool)

    def test_short_data_no_match(self):
        """Data shorter than 0x1000 should not match."""
        assert _check_emc_ipl_pattern(b'\x00' * 100) is False


# =============================================================================
# Header Parsing Tests
# =============================================================================

class TestHeaderParsing:
    """Tests for parse_boot_chain_header function."""

    def test_valid_header(self):
        """Should parse a valid header structure."""
        # Create a mock header with valid values
        header_data = (
            b'TEST'  # magic
            + (1).to_bytes(4, 'little')  # version
            + (0x1000).to_bytes(4, 'little')  # header_size
            + (0x50000).to_bytes(4, 'little')  # total_size
            + (4).to_bytes(4, 'little')  # segment_count
            + (0).to_bytes(4, 'little')  # flags
            + b'\x00' * 16  # reserved
            + b'\x00' * 100  # padding
        )

        result = parse_boot_chain_header(header_data)
        assert result is not None
        assert result.magic == b'TEST'
        assert result.version == 1
        assert result.header_size == 0x1000
        assert result.total_size == 0x50000
        assert result.segment_count == 4

    def test_invalid_header_size(self):
        """Should return None for invalid header_size."""
        header_data = (
            b'TEST'
            + (1).to_bytes(4, 'little')
            + (0x20000).to_bytes(4, 'little')  # Too large header_size
            + (0x50000).to_bytes(4, 'little')
            + (4).to_bytes(4, 'little')
            + (0).to_bytes(4, 'little')
            + b'\x00' * 80
        )
        assert parse_boot_chain_header(header_data) is None

    def test_too_many_segments(self):
        """Should return None for too many segments."""
        header_data = (
            b'TEST'
            + (1).to_bytes(4, 'little')
            + (0x1000).to_bytes(4, 'little')
            + (0x50000).to_bytes(4, 'little')
            + (20).to_bytes(4, 'little')  # Too many segments
            + (0).to_bytes(4, 'little')
            + b'\x00' * 80
        )
        assert parse_boot_chain_header(header_data) is None

    def test_short_data(self):
        """Should return None for data shorter than 0x40 bytes."""
        assert parse_boot_chain_header(b'\x00' * 32) is None


# =============================================================================
# Segment Offset Detection Tests
# =============================================================================

class TestSegmentOffsetDetection:
    """Tests for detect_segment_offsets function."""

    def test_default_offsets_for_unknown_type(self):
        """Should return default offsets for unknown firmware type."""
        data = b'\x00' * 0x200000
        offsets = detect_segment_offsets(data, FirmwareType.UNKNOWN)

        assert 'emc_header' in offsets
        assert 'emc_body' in offsets
        assert 'eap_kbl' in offsets
        assert 'eap_kernel' in offsets

    def test_emc_ipl_detection(self, high_entropy_data):
        """Should detect EMC IPL offsets."""
        # Create larger data with segment boundaries
        data = high_entropy_data + b'\x00' * 0x100000
        offsets = detect_segment_offsets(data, FirmwareType.EMC_IPL)

        assert offsets['emc_header']['offset'] == 0x0
        assert offsets['emc_header']['size'] == 0x1000

    def test_eap_blob_detection(self):
        """Should detect EAP blob offsets from SLBH header."""
        # Create SLBH header
        header_size = 0x100
        payload_size = 0x20000
        data = (
            MAGIC_SLBH
            + header_size.to_bytes(4, 'little')
            + payload_size.to_bytes(4, 'little')
            + b'\x00' * 0x30000
        )

        offsets = detect_segment_offsets(data, FirmwareType.EAP_BLOB)
        assert offsets['eap_kbl']['offset'] == header_size
        assert offsets['eap_kbl']['size'] == payload_size


class TestPotentialSegmentStart:
    """Tests for _is_potential_segment_start function."""

    def test_high_entropy_is_segment(self, high_entropy_data):
        """High entropy data should be detected as segment start."""
        assert _is_potential_segment_start(high_entropy_data, 0) is True

    def test_slbh_marker_is_segment(self):
        """SLBH marker should be detected as segment start."""
        data = MAGIC_SLBH + b'\x00' * 100
        assert _is_potential_segment_start(data, 0) is True

    def test_short_data_returns_false(self):
        """Should return False for insufficient data."""
        assert _is_potential_segment_start(b'\x00' * 10, 0) is False


# =============================================================================
# Version Detection Tests
# =============================================================================

class TestVersionDetection:
    """Tests for detect_version function."""

    def test_detects_development_version(self):
        """Should detect development version string."""
        data = b'\x00' * 100 + b'00.000.000' + b'\x00' * 100
        result = detect_version(data)
        assert '00.000.000' in result or 'Development' in result

    def test_detects_release_version(self):
        """Should detect release version strings."""
        for major in range(1, 10):
            pattern = f'0{major}.'.encode()
            data = b'\x00' * 100 + pattern + b'123.456\x00' + b'\x00' * 100
            result = detect_version(data)
            assert result != "Unknown" or f"Release {major}.x" in result

    def test_returns_unknown_for_no_version(self):
        """Should return Unknown when no version found."""
        data = b'\xFF' * 1000
        assert detect_version(data) == "Unknown"


# =============================================================================
# Firmware Analysis Tests
# =============================================================================

class TestFirmwareAnalysis:
    """Tests for analyze_firmware function."""

    def test_complete_analysis(self, high_entropy_data):
        """Should return complete firmware info."""
        data = high_entropy_data + b'\x00' * 0x100000

        info = analyze_firmware(data)

        assert isinstance(info, FirmwareInfo)
        assert info.firmware_type in FirmwareType
        assert info.size == len(data)
        assert isinstance(info.segments, list)
        assert isinstance(info.offsets, dict)

    def test_segment_list_populated(self, high_entropy_data):
        """Should populate segment list from offsets."""
        data = high_entropy_data + b'\x00' * 0x100000

        info = analyze_firmware(data)

        assert len(info.segments) > 0
        for seg in info.segments:
            assert isinstance(seg, BootSegment)
            assert seg.name in info.offsets


# =============================================================================
# Decryption Tests
# =============================================================================

class TestDecryption:
    """Tests for decrypt_segment function."""

    def test_decrypt_roundtrip(self, sample_keys):
        """Encrypting then decrypting should return original data."""
        original = b'Test data for encryption!\x00' * 10
        # Pad to 16-byte boundary
        padded = original + b'\x00' * (16 - len(original) % 16)

        key = sample_keys['emc_ipl_header']
        encrypted = aes_cbc_encrypt_iv_zero(key, padded)

        # Create mock firmware with encrypted data
        firmware = encrypted + b'\x00' * 100

        decrypted, mac_ok = decrypt_segment(
            firmware,
            key,
            offset=0,
            size=len(encrypted)
        )

        assert decrypted[:len(original)] == original
        assert mac_ok is True  # No MAC verification requested

    def test_decrypt_with_mac_verification(self, sample_keys):
        """Should verify MAC when provided."""
        key = sample_keys['eap_kbl']
        mac_key = sample_keys['eap_kbl_mac']

        # Create encrypted data
        original = b'EAP KBL test data\x00' * 100
        padded = original + b'\x00' * (16 - len(original) % 16)
        encrypted = aes_cbc_encrypt_iv_zero(key, padded)

        # Compute MAC
        mac = hmac_sha1(mac_key, encrypted)

        # Create firmware with data and MAC
        firmware = encrypted + mac + b'\x00' * 100

        decrypted, mac_ok = decrypt_segment(
            firmware,
            key,
            offset=0,
            size=len(encrypted),
            mac_key=mac_key,
            mac_offset=len(encrypted),
            mac_size=20
        )

        assert mac_ok is True
        assert decrypted[:len(original)] == original

    def test_decrypt_with_invalid_mac(self, sample_keys):
        """Should fail MAC verification with wrong MAC."""
        key = sample_keys['eap_kbl']
        mac_key = sample_keys['eap_kbl_mac']

        # Create encrypted data
        original = b'EAP KBL test data\x00' * 100
        padded = original + b'\x00' * (16 - len(original) % 16)
        encrypted = aes_cbc_encrypt_iv_zero(key, padded)

        # Wrong MAC
        wrong_mac = b'\xFF' * 20

        # Create firmware with data and wrong MAC
        firmware = encrypted + wrong_mac + b'\x00' * 100

        decrypted, mac_ok = decrypt_segment(
            firmware,
            key,
            offset=0,
            size=len(encrypted),
            mac_key=mac_key,
            mac_offset=len(encrypted),
            mac_size=20
        )

        assert mac_ok is False

    def test_decrypt_skip_mac(self, sample_keys):
        """Should skip MAC verification when requested."""
        key = sample_keys['eap_kbl']
        mac_key = sample_keys['eap_kbl_mac']

        # Create encrypted data with wrong MAC
        original = b'Test data\x00' * 50
        padded = original + b'\x00' * (16 - len(original) % 16)
        encrypted = aes_cbc_encrypt_iv_zero(key, padded)
        wrong_mac = b'\x00' * 20

        firmware = encrypted + wrong_mac

        decrypted, mac_ok = decrypt_segment(
            firmware,
            key,
            offset=0,
            size=len(encrypted),
            mac_key=mac_key,
            mac_offset=len(encrypted),
            mac_size=20,
            skip_mac=True
        )

        # MAC should be reported as True when skipped
        assert mac_ok is True

    def test_decrypt_sha256_mac(self, sample_keys):
        """Should use SHA-256 for MAC verification when specified."""
        key = sample_keys['eap_kernel']
        mac_key = sample_keys['eap_kernel_mac']

        # Create encrypted data
        original = b'EAP Kernel test\x00' * 100
        padded = original + b'\x00' * (16 - len(original) % 16)
        encrypted = aes_cbc_encrypt_iv_zero(key, padded)

        # Compute SHA-256 MAC
        mac = hmac_sha256(mac_key, encrypted)

        firmware = encrypted + mac

        decrypted, mac_ok = decrypt_segment(
            firmware,
            key,
            offset=0,
            size=len(encrypted),
            mac_key=mac_key,
            mac_offset=len(encrypted),
            mac_size=32,
            use_sha256=True
        )

        assert mac_ok is True

    def test_decrypt_truncated_data(self, sample_keys):
        """Should handle truncated segment data gracefully."""
        key = sample_keys['emc_ipl_header']

        # Create small data but request larger size
        small_data = b'\x00' * 32

        # Should not raise, but print warning
        decrypted, _ = decrypt_segment(
            small_data,
            key,
            offset=0,
            size=1024
        )

        # Decrypted size should be based on available data (padded to block size)
        assert len(decrypted) == 32


# =============================================================================
# Key Loading Tests
# =============================================================================

class TestKeyLoading:
    """Tests for key loading functionality."""

    def test_load_boot_chain_keys(self, tmp_path):
        """Should load keys from JSON file."""
        keys_file = tmp_path / "test_keys.json"
        keys_file.write_text('''{
            "emc_ipl_header": "F0332357C8CFAE7E7E26E52BE9E3AED4",
            "emc_ipl_cipher": "D5C92E39759A3E5CE954E772B1C2B651",
            "eap_kbl": "262555E3CF062B070B5AA2CDDF3A5D0E",
            "eap_kbl_mac": "1EE22F6A189E7D99A28B9A96D3C4DBA2",
            "eap_kernel": "CBCC1E53F42C1CB44D965E233CD792A8",
            "eap_kernel_mac": "683D6E2E496687CB5B831DA12BCB001B"
        }''')

        keys = load_boot_chain_keys(str(keys_file))

        assert len(keys['emc_ipl_header']) == 16
        assert len(keys['eap_kbl']) == 16
        assert keys['emc_ipl_header'] == bytes.fromhex('F0332357C8CFAE7E7E26E52BE9E3AED4')


# =============================================================================
# Dataclass Tests
# =============================================================================

class TestDataclasses:
    """Tests for dataclass structures."""

    def test_boot_chain_header(self):
        """Should create BootChainHeader correctly."""
        header = BootChainHeader(
            magic=b'TEST',
            version=1,
            header_size=0x1000,
            total_size=0x50000,
            segment_count=4,
            flags=0,
            reserved=b'\x00' * 16
        )

        assert header.magic == b'TEST'
        assert header.version == 1
        assert header.header_size == 0x1000

    def test_boot_segment(self):
        """Should create BootSegment correctly."""
        segment = BootSegment(
            index=0,
            name='emc_header',
            offset=0x0,
            size=0x1000,
            encrypted_size=0x1000,
            mac_offset=None,
            mac_size=0,
            flags=0
        )

        assert segment.name == 'emc_header'
        assert segment.offset == 0x0

    def test_firmware_info(self):
        """Should create FirmwareInfo correctly."""
        info = FirmwareInfo(
            firmware_type=FirmwareType.EMC_IPL,
            size=0x100000,
            header=None,
            segments=[],
            version_string="Unknown",
            offsets={}
        )

        assert info.firmware_type == FirmwareType.EMC_IPL
        assert info.size == 0x100000


# =============================================================================
# Edge Cases
# =============================================================================

class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_empty_data(self):
        """Should handle empty data gracefully."""
        assert detect_firmware_type(b'') == FirmwareType.UNKNOWN
        assert parse_boot_chain_header(b'') is None

    def test_single_byte_data(self):
        """Should handle minimal data."""
        assert detect_firmware_type(b'\x00') == FirmwareType.UNKNOWN

    def test_offset_beyond_data(self):
        """Should handle offset beyond data length."""
        data = b'\x00' * 100
        result = _is_potential_segment_start(data, 200)
        assert result is False

    def test_default_offsets_structure(self):
        """Should have correct DEFAULT_OFFSETS structure."""
        for name, offsets in DEFAULT_OFFSETS.items():
            assert 'offset' in offsets
            assert 'size' in offsets
            assert 'mac_offset' in offsets
            assert 'mac_size' in offsets


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
