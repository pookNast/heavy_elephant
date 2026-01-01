#!/usr/bin/env python3
"""
Unit tests for PS5 SELF Tool

Tests SELF header parsing, segment handling, and decryption functionality.
"""
import struct
import sys
from pathlib import Path

import pytest

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from tools.ps5_self_tool import (
    SELF_MAGIC,
    ELF_MAGIC,
    SegmentFlags,
    SELFHeader,
    SELFSegment,
    ELF64Header,
    ELF64ProgramHeader,
    SELFParser,
    SELFDecryptor,
    PROGRAM_TYPE_NPDRM_EXEC,
    PROGRAM_TYPE_SYSTEM_EXEC,
)
from he.crypto import aes_cbc_encrypt_no_pad


# ============================================================================
# Test Data Generators
# ============================================================================

def create_self_header(
    num_segments: int = 2,
    header_size: int = 0x100,
    file_size: int = 0x1000,
    category: int = 1,
    program_type: int = PROGRAM_TYPE_NPDRM_EXEC,
) -> bytes:
    """Create a minimal SELF header for testing."""
    header = bytearray(0x20)

    # Magic
    header[0:4] = SELF_MAGIC

    # Version (0x00010112)
    struct.pack_into('<I', header, 0x04, 0x00010112)

    # Category
    header[0x08] = category

    # Program type
    header[0x09] = program_type

    # Header size
    struct.pack_into('<H', header, 0x0C, header_size)

    # Signature size
    struct.pack_into('<H', header, 0x0E, 0x100)

    # File size (low 32 bits)
    struct.pack_into('<I', header, 0x10, file_size & 0xFFFFFFFF)

    # File size (high 32 bits)
    struct.pack_into('<I', header, 0x14, file_size >> 32)

    # Number of segments
    struct.pack_into('<H', header, 0x18, num_segments)

    # Flags
    struct.pack_into('<H', header, 0x1A, 0x22)

    return bytes(header)


def create_segment_entry(
    flags: int = 0x000006,  # ENCRYPTED | SIGNED
    offset: int = 0x1000,
    compressed_size: int = 0x100,
    decompressed_size: int = 0x100,
) -> bytes:
    """Create a segment table entry for testing."""
    entry = bytearray(0x20)

    struct.pack_into('<Q', entry, 0x00, flags)
    struct.pack_into('<Q', entry, 0x08, offset)
    struct.pack_into('<Q', entry, 0x10, compressed_size)
    struct.pack_into('<Q', entry, 0x18, decompressed_size)

    return bytes(entry)


def create_elf_header(
    entry: int = 0x400000,
    phoff: int = 0x40,
    phnum: int = 4,
) -> bytes:
    """Create a minimal ELF64 header for testing."""
    header = bytearray(0x40)

    # Magic
    header[0:4] = ELF_MAGIC

    # Class (64-bit)
    header[4] = 2

    # Endian (little)
    header[5] = 1

    # Version
    header[6] = 1

    # OS ABI (FreeBSD/PS4)
    header[7] = 9

    # Type (executable)
    struct.pack_into('<H', header, 0x10, 2)

    # Machine (x86-64)
    struct.pack_into('<H', header, 0x12, 0x3E)

    # Version
    struct.pack_into('<I', header, 0x14, 1)

    # Entry point
    struct.pack_into('<Q', header, 0x18, entry)

    # Program header offset
    struct.pack_into('<Q', header, 0x20, phoff)

    # Section header offset (0 = none)
    struct.pack_into('<Q', header, 0x28, 0)

    # ELF header size
    struct.pack_into('<H', header, 0x34, 0x40)

    # Program header entry size
    struct.pack_into('<H', header, 0x36, 0x38)

    # Number of program headers
    struct.pack_into('<H', header, 0x38, phnum)

    # Section header entry size
    struct.pack_into('<H', header, 0x3A, 0x40)

    return bytes(header)


def create_program_header(
    p_type: int = 1,  # PT_LOAD
    p_flags: int = 5,  # PF_R | PF_X
    p_offset: int = 0x1000,
    p_vaddr: int = 0x400000,
    p_filesz: int = 0x100,
    p_memsz: int = 0x100,
) -> bytes:
    """Create an ELF64 program header for testing."""
    header = bytearray(0x38)

    struct.pack_into('<I', header, 0x00, p_type)
    struct.pack_into('<I', header, 0x04, p_flags)
    struct.pack_into('<Q', header, 0x08, p_offset)
    struct.pack_into('<Q', header, 0x10, p_vaddr)
    struct.pack_into('<Q', header, 0x18, p_vaddr)  # paddr = vaddr
    struct.pack_into('<Q', header, 0x20, p_filesz)
    struct.pack_into('<Q', header, 0x28, p_memsz)
    struct.pack_into('<Q', header, 0x30, 0x1000)  # alignment

    return bytes(header)


def create_test_self(
    include_elf: bool = True,
    encrypted_segments: bool = False,
) -> bytes:
    """Create a complete test SELF file."""
    # SELF header
    self_header = create_self_header(num_segments=2, header_size=0x100, file_size=0x2000)

    # Segment table
    seg1_flags = 0x000006 if encrypted_segments else 0x000004  # ENC|SGN or just SGN
    seg1 = create_segment_entry(flags=seg1_flags, offset=0x1000, compressed_size=0x100)
    seg2 = create_segment_entry(flags=0x000004, offset=0x1100, compressed_size=0x100)  # SGN only

    # Build file
    data = bytearray(0x2000)
    data[0:0x20] = self_header
    data[0x20:0x40] = seg1
    data[0x40:0x60] = seg2

    # Add ELF header at header_size offset
    if include_elf:
        elf_header = create_elf_header()
        data[0x100:0x140] = elf_header

    # Add segment data
    data[0x1000:0x1100] = b'\x41' * 0x100  # Segment 1 data
    data[0x1100:0x1200] = b'\x42' * 0x100  # Segment 2 data

    return bytes(data)


# ============================================================================
# Test Cases: SELF Header Parsing
# ============================================================================

class TestSELFHeader:
    """Tests for SELFHeader parsing."""

    def test_parse_valid_header(self):
        """Test parsing a valid SELF header."""
        header_data = create_self_header(num_segments=3, header_size=0x200)
        header = SELFHeader.parse(header_data)

        assert header.magic == SELF_MAGIC
        assert header.version == 0x00010112
        assert header.category == 1
        assert header.num_segments == 3
        assert header.header_size == 0x200

    def test_parse_invalid_magic(self):
        """Test that invalid magic raises error."""
        bad_header = b'\x00\x00\x00\x00' + b'\x00' * 28

        with pytest.raises(ValueError, match="Invalid SELF magic"):
            SELFHeader.parse(bad_header)

    def test_parse_too_short(self):
        """Test that short data raises error."""
        short_data = SELF_MAGIC + b'\x00' * 10

        with pytest.raises(ValueError, match="Data too short"):
            SELFHeader.parse(short_data)

    def test_program_type_name(self):
        """Test program type name property."""
        header_data = create_self_header(program_type=PROGRAM_TYPE_SYSTEM_EXEC)
        header = SELFHeader.parse(header_data)

        assert header.program_type_name == "System Executable"

    def test_total_file_size_64bit(self):
        """Test 64-bit file size calculation."""
        header = bytearray(create_self_header(file_size=0x100))
        # Set high bits
        struct.pack_into('<I', header, 0x14, 0x1)

        parsed = SELFHeader.parse(bytes(header))
        assert parsed.total_file_size == 0x100000100


class TestSELFSegment:
    """Tests for SELFSegment parsing."""

    def test_parse_segment(self):
        """Test parsing a segment entry."""
        seg_data = create_segment_entry(
            flags=0x110006,
            offset=0x2000,
            compressed_size=0x500,
            decompressed_size=0x800,
        )
        segment = SELFSegment.parse(seg_data, index=1)

        assert segment.offset == 0x2000
        assert segment.compressed_size == 0x500
        assert segment.decompressed_size == 0x800
        assert segment.index == 1

    def test_segment_flags(self):
        """Test segment flag properties."""
        # Flags: ORDERED | ENCRYPTED | SIGNED | COMPRESSED
        flags = SegmentFlags.ORDERED | SegmentFlags.ENCRYPTED | SegmentFlags.SIGNED | SegmentFlags.COMPRESSED
        seg_data = create_segment_entry(flags=int(flags))
        segment = SELFSegment.parse(seg_data)

        assert segment.is_ordered is True
        assert segment.is_encrypted is True
        assert segment.is_signed is True
        assert segment.is_compressed is True
        assert segment.is_blocked is False

    def test_segment_id(self):
        """Test segment ID extraction from flags."""
        # ID is bits 20-31
        flags = (0x11 << 20) | 0x06
        seg_data = create_segment_entry(flags=flags)
        segment = SELFSegment.parse(seg_data)

        assert segment.segment_id == 0x11

    def test_flags_str(self):
        """Test flags string representation."""
        flags = SegmentFlags.ENCRYPTED | SegmentFlags.SIGNED
        seg_data = create_segment_entry(flags=int(flags))
        segment = SELFSegment.parse(seg_data)

        assert "ENC" in segment.flags_str
        assert "SGN" in segment.flags_str
        assert "CMP" not in segment.flags_str


class TestELF64Header:
    """Tests for ELF64Header parsing."""

    def test_parse_valid_elf(self):
        """Test parsing a valid ELF header."""
        elf_data = create_elf_header(entry=0x401000, phnum=8)
        elf = ELF64Header.parse(elf_data)

        assert elf.magic == ELF_MAGIC
        assert elf.elf_class == 2
        assert elf.endian == 1
        assert elf.osabi == 9
        assert elf.entry == 0x401000
        assert elf.phnum == 8
        assert elf.machine == 0x3E

    def test_parse_invalid_magic(self):
        """Test that invalid ELF magic raises error."""
        bad_elf = b'\x00\x00\x00\x00' + b'\x00' * 60

        with pytest.raises(ValueError, match="Invalid ELF magic"):
            ELF64Header.parse(bad_elf)


class TestELF64ProgramHeader:
    """Tests for ELF64ProgramHeader parsing."""

    def test_parse_program_header(self):
        """Test parsing a program header."""
        ph_data = create_program_header(
            p_type=1,  # PT_LOAD
            p_offset=0x2000,
            p_vaddr=0x800000,
            p_filesz=0x1000,
        )
        ph = ELF64ProgramHeader.parse(ph_data)

        assert ph.p_type == 1
        assert ph.p_offset == 0x2000
        assert ph.p_vaddr == 0x800000
        assert ph.p_filesz == 0x1000


# ============================================================================
# Test Cases: SELF Parser
# ============================================================================

class TestSELFParser:
    """Tests for SELFParser."""

    def test_parse_complete_self(self):
        """Test parsing a complete SELF file."""
        self_data = create_test_self(include_elf=True)
        parser = SELFParser(self_data)

        assert parser.header is not None
        assert parser.header.num_segments == 2
        assert len(parser.segments) == 2

    def test_parse_with_embedded_elf(self):
        """Test that embedded ELF is detected."""
        self_data = create_test_self(include_elf=True)
        parser = SELFParser(self_data)

        assert parser.elf_header is not None
        assert parser.elf_header.magic == ELF_MAGIC

    def test_parse_without_embedded_elf(self):
        """Test parsing SELF without visible ELF (encrypted)."""
        self_data = create_test_self(include_elf=False)
        parser = SELFParser(self_data)

        assert parser.header is not None
        assert parser.elf_header is None

    def test_get_segment_data(self):
        """Test extracting segment data."""
        self_data = create_test_self()
        parser = SELFParser(self_data)

        seg_data = parser.get_segment_data(parser.segments[0])
        assert len(seg_data) == 0x100
        assert seg_data == b'\x41' * 0x100

        seg_data = parser.get_segment_data(parser.segments[1])
        assert seg_data == b'\x42' * 0x100


# ============================================================================
# Test Cases: SELF Decryptor
# ============================================================================

class TestSELFDecryptor:
    """Tests for SELFDecryptor."""

    @pytest.fixture
    def test_key_iv(self):
        """Test key and IV."""
        key = bytes.fromhex('32D00F27AE38FE4AC88A352313A2BFB4')
        iv = bytes.fromhex('08FEA1ACC37A63099974538616881EC0')
        return key, iv

    def test_decrypt_unencrypted_segment(self, test_key_iv):
        """Test decrypting a segment that's not encrypted."""
        key, iv = test_key_iv

        # Create SELF with unencrypted segment
        self_data = bytearray(create_test_self())
        # Modify segment 1 to be unencrypted (clear ENCRYPTED flag)
        struct.pack_into('<Q', self_data, 0x20, 0x000004)  # SGN only

        parser = SELFParser(bytes(self_data))
        decryptor = SELFDecryptor(parser, key, iv)

        result = decryptor.decrypt_segment(parser.segments[0])
        assert result == b'\x41' * 0x100

    def test_decrypt_encrypted_segment(self, test_key_iv):
        """Test decrypting an encrypted segment."""
        key, iv = test_key_iv

        # Create plaintext
        plaintext = b'\x41' * 0x100  # 256 bytes, block aligned

        # Encrypt it
        ciphertext = aes_cbc_encrypt_no_pad(key, iv, plaintext)

        # Build SELF with encrypted segment
        self_data = bytearray(0x2000)
        self_data[0:0x20] = create_self_header(num_segments=1, file_size=0x2000)
        self_data[0x20:0x40] = create_segment_entry(
            flags=int(SegmentFlags.ENCRYPTED | SegmentFlags.SIGNED),
            offset=0x1000,
            compressed_size=0x100,
        )
        self_data[0x1000:0x1100] = ciphertext

        parser = SELFParser(bytes(self_data))
        decryptor = SELFDecryptor(parser, key, iv)

        result = decryptor.decrypt_segment(parser.segments[0])
        assert result == plaintext

    def test_decrypt_all_segments(self, test_key_iv):
        """Test decrypting all segments."""
        key, iv = test_key_iv
        self_data = create_test_self()

        parser = SELFParser(self_data)
        decryptor = SELFDecryptor(parser, key, iv)

        results = decryptor.decrypt_all_segments()
        assert len(results) == 2

        for segment, data in results:
            assert len(data) > 0


# ============================================================================
# Test Cases: Segment Flags
# ============================================================================

class TestSegmentFlags:
    """Tests for SegmentFlags enum."""

    def test_flag_values(self):
        """Test flag constant values."""
        assert SegmentFlags.ORDERED == 0x1
        assert SegmentFlags.ENCRYPTED == 0x2
        assert SegmentFlags.SIGNED == 0x4
        assert SegmentFlags.COMPRESSED == 0x8
        assert SegmentFlags.BLOCKED == 0x800

    def test_flag_combinations(self):
        """Test combining flags."""
        combined = SegmentFlags.ENCRYPTED | SegmentFlags.SIGNED
        assert combined == 0x6

        assert combined & SegmentFlags.ENCRYPTED
        assert combined & SegmentFlags.SIGNED
        assert not (combined & SegmentFlags.COMPRESSED)


# ============================================================================
# Integration Tests
# ============================================================================

class TestIntegration:
    """Integration tests for complete workflows."""

    def test_parse_and_extract_workflow(self):
        """Test complete parse and extract workflow."""
        self_data = create_test_self()

        # Parse
        parser = SELFParser(self_data)
        assert parser.header.num_segments == 2

        # Verify segments
        for i, seg in enumerate(parser.segments):
            data = parser.get_segment_data(seg)
            assert len(data) == seg.compressed_size

    def test_empty_segment_handling(self):
        """Test handling of empty segments."""
        self_data = bytearray(create_test_self())

        # Set segment 0 to have zero size
        struct.pack_into('<Q', self_data, 0x20 + 0x10, 0)  # compressed_size = 0

        parser = SELFParser(bytes(self_data))
        seg_data = parser.get_segment_data(parser.segments[0])

        assert len(seg_data) == 0


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
