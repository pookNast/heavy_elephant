#!/usr/bin/env python3
"""
Unit tests for PS5 PKG Tool.

Tests PKG header parsing, entry table parsing, XTS-AES decryption,
and CLI commands.
"""
import struct
import pytest
from pathlib import Path
from io import BytesIO
from unittest.mock import patch, MagicMock

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from tools.ps5_pkg_tool import (
    PKG_MAGIC, PKG_HEADER_SIZE, PKG_ENTRY_SIZE,
    PKGHeader, PKGEntry, PKGEntryID, PKGContentType, PKGDRMType,
    PKGContentFlags, ENTRY_ID_NAMES,
    parse_entry_table, xts_aes_decrypt, derive_pfs_keys
)


class TestPKGConstants:
    """Test PKG format constants."""

    def test_pkg_magic(self):
        """Test PKG magic bytes."""
        assert PKG_MAGIC == b'\x7FCNT'
        assert len(PKG_MAGIC) == 4

    def test_pkg_header_size(self):
        """Test PKG header size is 4KB."""
        assert PKG_HEADER_SIZE == 0x1000
        assert PKG_HEADER_SIZE == 4096

    def test_pkg_entry_size(self):
        """Test PKG entry size is 32 bytes."""
        assert PKG_ENTRY_SIZE == 0x20
        assert PKG_ENTRY_SIZE == 32


class TestPKGEntry:
    """Test PKG entry parsing."""

    def test_entry_from_bytes_basic(self):
        """Test basic entry parsing."""
        # Create a 32-byte entry (big-endian)
        entry_data = struct.pack('>IIIIIIQ',
            0x00001000,  # id: PARAM_SFO
            0x00000000,  # filename_offset
            0x00000000,  # flags1 (not encrypted)
            0x00001000,  # flags2 (key index 1)
            0x00002000,  # offset
            0x00000100,  # size: 256 bytes
            0x0000000000000000  # padding
        )

        entry = PKGEntry.from_bytes(entry_data)

        assert entry.id == 0x00001000
        assert entry.id == PKGEntryID.PARAM_SFO
        assert entry.offset == 0x2000
        assert entry.size == 0x100
        assert entry.key_index == 1
        assert not entry.encrypted
        assert entry.filename == "param.sfo"

    def test_entry_from_bytes_encrypted(self):
        """Test parsing encrypted entry."""
        # flags1 with bit 31 set = encrypted
        entry_data = struct.pack('>IIIIIIQ',
            0x00001200,  # id: ICON0_PNG
            0x00000000,  # filename_offset
            0x80000000,  # flags1 (encrypted)
            0x00002000,  # flags2 (key index 2)
            0x00010000,  # offset
            0x00008000,  # size: 32KB
            0x0000000000000000  # padding
        )

        entry = PKGEntry.from_bytes(entry_data)

        assert entry.id == PKGEntryID.ICON0_PNG
        assert entry.encrypted
        assert entry.key_index == 2
        assert entry.filename == "icon0.png"

    def test_entry_to_bytes(self):
        """Test entry serialization."""
        entry = PKGEntry(
            id=0x00001000,
            filename_offset=0,
            flags1=0,
            flags2=0x1000,
            offset=0x2000,
            size=256,
            padding=0
        )

        data = entry.to_bytes()
        assert len(data) == 32

        # Parse it back
        parsed = PKGEntry.from_bytes(data)
        assert parsed.id == entry.id
        assert parsed.offset == entry.offset
        assert parsed.size == entry.size

    def test_entry_type_name_known(self):
        """Test known entry type name."""
        entry = PKGEntry(
            id=PKGEntryID.PARAM_SFO,
            filename_offset=0, flags1=0, flags2=0,
            offset=0, size=0
        )
        assert entry.get_type_name() == "PARAM_SFO"

    def test_entry_type_name_unknown(self):
        """Test unknown entry type name."""
        entry = PKGEntry(
            id=0xDEADBEEF,
            filename_offset=0, flags1=0, flags2=0,
            offset=0, size=0
        )
        assert "UNKNOWN" in entry.get_type_name()

    def test_entry_from_bytes_too_short(self):
        """Test entry parsing with insufficient data."""
        with pytest.raises(ValueError, match="too short"):
            PKGEntry.from_bytes(b'\x00' * 16)


class TestPKGHeader:
    """Test PKG header parsing."""

    def _create_test_header(self, **overrides) -> bytes:
        """Create a minimal valid PKG header for testing."""
        header = bytearray(PKG_HEADER_SIZE)

        # Magic
        header[0:4] = PKG_MAGIC

        # PKG type (big-endian)
        struct.pack_into('>I', header, 0x04, overrides.get('pkg_type', 0x00000004))

        # Entry count
        struct.pack_into('>I', header, 0x10, overrides.get('entry_count', 5))

        # Table offset
        struct.pack_into('>I', header, 0x18, overrides.get('table_offset', 0x1000))

        # Body offset
        struct.pack_into('>Q', header, 0x20, overrides.get('body_offset', 0x2000))

        # Body size
        struct.pack_into('>Q', header, 0x28, overrides.get('body_size', 0x10000))

        # Content ID
        content_id = overrides.get('content_id', b'UP0001-TEST00001_00-TESTPACKAGE00001')
        header[0x40:0x40 + len(content_id)] = content_id

        # DRM type
        struct.pack_into('>I', header, 0x70, overrides.get('drm_type', 1))

        # Content type
        struct.pack_into('>I', header, 0x74, overrides.get('content_type', 0x1A))

        # Content flags
        struct.pack_into('>I', header, 0x78, overrides.get('content_flags', 0))

        # PKG size (at 0x430)
        struct.pack_into('>Q', header, 0x430, overrides.get('pkg_size', 0x100000))

        return bytes(header)

    def test_header_parsing_basic(self):
        """Test basic header parsing."""
        header_data = self._create_test_header()

        header = PKGHeader.from_bytes(header_data)

        assert header.magic == PKG_MAGIC
        assert header.pkg_entry_count == 5
        assert header.pkg_table_offset == 0x1000
        assert header.pkg_body_offset == 0x2000
        assert header.pkg_body_size == 0x10000
        assert "TEST00001" in header.pkg_content_id

    def test_header_parsing_content_id(self):
        """Test content ID parsing."""
        header_data = self._create_test_header(
            content_id=b'EP0002-GAME12345_00-MYCOOLPACKAGE001'
        )

        header = PKGHeader.from_bytes(header_data)

        assert header.pkg_content_id == 'EP0002-GAME12345_00-MYCOOLPACKAGE001'

    def test_header_invalid_magic(self):
        """Test header with invalid magic."""
        header_data = bytearray(self._create_test_header())
        header_data[0:4] = b'BAAD'

        with pytest.raises(ValueError, match="Invalid PKG magic"):
            PKGHeader.from_bytes(bytes(header_data))

    def test_header_too_short(self):
        """Test header parsing with insufficient data."""
        with pytest.raises(ValueError, match="too short"):
            PKGHeader.from_bytes(b'\x00' * 100)

    def test_content_type_name_game(self):
        """Test content type name for game."""
        header_data = self._create_test_header(content_type=0x1A)
        header = PKGHeader.from_bytes(header_data)

        assert header.get_content_type_name() == "GAME"

    def test_content_type_name_dlc(self):
        """Test content type name for DLC."""
        header_data = self._create_test_header(content_type=0x1C)
        header = PKGHeader.from_bytes(header_data)

        assert header.get_content_type_name() == "DLC"

    def test_drm_type_name(self):
        """Test DRM type name."""
        header_data = self._create_test_header(drm_type=1)
        header = PKGHeader.from_bytes(header_data)

        assert header.get_drm_type_name() == "PS4"

    def test_content_flags_str(self):
        """Test content flags string."""
        header_data = self._create_test_header(
            content_flags=PKGContentFlags.VR | PKGContentFlags.NON_GAME
        )
        header = PKGHeader.from_bytes(header_data)

        flags_str = header.get_content_flags_str()
        assert "VR" in flags_str or "NON_GAME" in flags_str


class TestEntryTable:
    """Test entry table parsing."""

    def _create_test_pkg_with_entries(self, entries: list) -> bytes:
        """Create a test PKG with given entries."""
        # Create header
        header = bytearray(PKG_HEADER_SIZE)
        header[0:4] = PKG_MAGIC

        # Set entry count and table offset
        table_offset = PKG_HEADER_SIZE
        struct.pack_into('>I', header, 0x10, len(entries))
        struct.pack_into('>I', header, 0x18, table_offset)
        struct.pack_into('>Q', header, 0x20, table_offset + len(entries) * PKG_ENTRY_SIZE)
        struct.pack_into('>Q', header, 0x28, 0x10000)

        # Build entry table
        entry_table = bytearray()
        for entry in entries:
            entry_data = struct.pack('>IIIIIIQ',
                entry['id'],
                entry.get('filename_offset', 0),
                entry.get('flags1', 0),
                entry.get('flags2', 0),
                entry['offset'],
                entry['size'],
                0
            )
            entry_table.extend(entry_data)

        return bytes(header) + bytes(entry_table)

    def test_parse_entry_table_basic(self):
        """Test basic entry table parsing."""
        pkg_data = self._create_test_pkg_with_entries([
            {'id': 0x1000, 'offset': 0x2000, 'size': 256},
            {'id': 0x1200, 'offset': 0x3000, 'size': 1024},
        ])

        header = PKGHeader.from_bytes(pkg_data)
        entries = parse_entry_table(pkg_data, header)

        assert len(entries) == 2
        assert entries[0].id == 0x1000
        assert entries[0].filename == "param.sfo"
        assert entries[1].id == 0x1200
        assert entries[1].filename == "icon0.png"

    def test_parse_entry_table_empty(self):
        """Test parsing empty entry table."""
        pkg_data = self._create_test_pkg_with_entries([])

        header = PKGHeader.from_bytes(pkg_data)
        entries = parse_entry_table(pkg_data, header)

        assert len(entries) == 0

    def test_parse_entry_table_truncated(self):
        """Test parsing truncated entry table."""
        pkg_data = self._create_test_pkg_with_entries([
            {'id': 0x1000, 'offset': 0x2000, 'size': 256},
        ])

        # Truncate the data
        truncated = pkg_data[:PKG_HEADER_SIZE + 16]

        header = PKGHeader.from_bytes(truncated)
        # Should not crash, just return fewer entries
        entries = parse_entry_table(truncated, header)
        assert len(entries) == 0  # Entry table is incomplete


class TestXTSAESDecrypt:
    """Test XTS-AES decryption."""

    def test_xts_decrypt_aligned(self):
        """Test XTS decryption with aligned data."""
        # Test with known aligned data (0x1000 bytes)
        key_tweak = b'\x00' * 16
        key_data = b'\x00' * 16
        data = b'\x00' * 0x1000

        # Should not raise
        result = xts_aes_decrypt(data, key_tweak, key_data)
        assert len(result) == 0x1000

    def test_xts_decrypt_unaligned(self):
        """Test XTS decryption with unaligned data."""
        key_tweak = b'\x00' * 16
        key_data = b'\x00' * 16
        data = b'\x00' * 100  # Not sector-aligned

        # Should pad and decrypt
        result = xts_aes_decrypt(data, key_tweak, key_data)
        assert len(result) == 0x1000  # Padded to sector size

    def test_xts_decrypt_multiple_sectors(self):
        """Test XTS decryption with multiple sectors."""
        key_tweak = b'\x01' * 16
        key_data = b'\x02' * 16
        data = b'\x00' * (0x1000 * 3)  # 3 sectors

        result = xts_aes_decrypt(data, key_tweak, key_data)
        assert len(result) == 0x1000 * 3


class TestPFSKeyDerivation:
    """Test PFS key derivation."""

    def test_derive_pfs_keys_basic(self):
        """Test basic key derivation."""
        ekpfs = b'\xAB' * 16
        crypt_seed = b'\xCD' * 32

        tweak_key, data_key = derive_pfs_keys(ekpfs, crypt_seed)

        assert len(tweak_key) == 16
        assert len(data_key) == 16
        assert tweak_key != data_key

    def test_derive_pfs_keys_deterministic(self):
        """Test that key derivation is deterministic."""
        ekpfs = b'\x12\x34' * 8
        crypt_seed = b'\x56\x78' * 16

        tweak1, data1 = derive_pfs_keys(ekpfs, crypt_seed)
        tweak2, data2 = derive_pfs_keys(ekpfs, crypt_seed)

        assert tweak1 == tweak2
        assert data1 == data2

    def test_derive_pfs_keys_different_inputs(self):
        """Test that different inputs produce different keys."""
        ekpfs1 = b'\x00' * 16
        ekpfs2 = b'\x01' * 16
        crypt_seed = b'\xFF' * 32

        tweak1, data1 = derive_pfs_keys(ekpfs1, crypt_seed)
        tweak2, data2 = derive_pfs_keys(ekpfs2, crypt_seed)

        assert tweak1 != tweak2
        assert data1 != data2


class TestPKGEntryIDs:
    """Test PKG entry ID mappings."""

    def test_known_entry_ids(self):
        """Test known entry ID mappings."""
        assert ENTRY_ID_NAMES[PKGEntryID.PARAM_SFO] == "param.sfo"
        assert ENTRY_ID_NAMES[PKGEntryID.ICON0_PNG] == "icon0.png"
        assert ENTRY_ID_NAMES[PKGEntryID.PIC0_PNG] == "pic0.png"
        assert ENTRY_ID_NAMES[PKGEntryID.SND0_AT9] == "snd0.at9"

    def test_meta_entry_ids(self):
        """Test meta entry IDs."""
        assert PKGEntryID.DIGEST_TABLE == 0x00000001
        assert PKGEntryID.ENTRY_KEYS == 0x00000010
        assert PKGEntryID.IMAGE_KEY == 0x00000020
        assert PKGEntryID.METADATA_TABLE == 0x00000100
        assert PKGEntryID.ENTRY_NAMES == 0x00000200


class TestPKGContentTypes:
    """Test PKG content type enum."""

    def test_content_types(self):
        """Test content type values."""
        assert PKGContentType.GAME == 0x1A
        assert PKGContentType.DLC == 0x1C
        assert PKGContentType.PATCH == 0x1E


class TestPKGContentFlags:
    """Test PKG content flags."""

    def test_content_flags_values(self):
        """Test content flag values."""
        assert PKGContentFlags.FIRST_PATCH == 0x00100000
        assert PKGContentFlags.VR == 0x10000000
        assert PKGContentFlags.DELTA_PATCH == 0x40000000

    def test_content_flags_combination(self):
        """Test combining content flags."""
        combined = PKGContentFlags.VR | PKGContentFlags.NON_GAME
        assert combined & PKGContentFlags.VR
        assert combined & PKGContentFlags.NON_GAME


class TestCLI:
    """Test CLI commands (mock-based)."""

    def test_cli_import(self):
        """Test that CLI can be imported."""
        from tools.ps5_pkg_tool import cli
        assert cli is not None

    def test_cli_has_commands(self):
        """Test that CLI has expected commands."""
        from tools.ps5_pkg_tool import cli
        assert 'info' in cli.commands
        assert 'decrypt' in cli.commands
        assert 'sign' in cli.commands
        assert 'verify' in cli.commands
        assert 'extract' in cli.commands


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
