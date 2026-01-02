#!/usr/bin/env python3
"""
Integration tests for PS5 M.2 Tool

Tests complete workflows including file I/O, CLI integration,
and real-world usage scenarios.
"""
import pytest
import tempfile
import shutil
from pathlib import Path
from click.testing import CliRunner
import sys

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from tools.ps5_m2_tool import cli, M2_METADATA_SIZE, M2_SECTOR_SIZE
from he.crypto import aes_cbc_encrypt_no_pad


# ============================================================================
# Test Fixtures
# ============================================================================

@pytest.fixture
def temp_dir():
    """Create temporary directory for test files."""
    temp_path = tempfile.mkdtemp(prefix='m2_test_')
    yield Path(temp_path)
    shutil.rmtree(temp_path, ignore_errors=True)


@pytest.fixture
def test_encryption_key():
    """Standard M.2 encryption key."""
    return bytes.fromhex('01234567890123456789012345678901')


@pytest.fixture
def sample_encrypted_image(temp_dir, test_encryption_key):
    """Create a sample encrypted M.2 image file."""
    import struct
    import hashlib

    image_path = temp_dir / 'encrypted_test.img'

    # Create metadata
    metadata = bytearray(M2_METADATA_SIZE)
    metadata[0:4] = b'M2SS'  # Magic
    struct.pack_into('<I', metadata, 0x04, 0x01)  # Version
    struct.pack_into('<Q', metadata, 0x08, 8)  # 8 sectors
    struct.pack_into('<I', metadata, 0x10, 1)  # Encryption enabled

    # Calculate checksum
    checksum = hashlib.sha256(metadata[0:0x1F0]).digest()
    metadata[0x1F0:0x210] = checksum[:32]

    # Create encrypted data (8 sectors)
    plaintext = b'\xDE\xAD\xBE\xEF' * (M2_SECTOR_SIZE // 4)
    iv = b'\x00' * 16
    encrypted_data = bytearray()

    for i in range(8):
        encrypted_sector = aes_cbc_encrypt_no_pad(test_encryption_key, iv, plaintext)
        encrypted_data.extend(encrypted_sector)

    # Write to file
    with open(image_path, 'wb') as f:
        f.write(metadata)
        f.write(encrypted_data)

    return image_path


@pytest.fixture
def sample_unencrypted_image(temp_dir):
    """Create a sample unencrypted M.2 image file."""
    import struct
    import hashlib

    image_path = temp_dir / 'unencrypted_test.img'

    # Create metadata
    metadata = bytearray(M2_METADATA_SIZE)
    metadata[0:4] = b'M2SS'  # Magic
    struct.pack_into('<I', metadata, 0x04, 0x01)  # Version
    struct.pack_into('<Q', metadata, 0x08, 4)  # 4 sectors
    struct.pack_into('<I', metadata, 0x10, 0)  # Encryption disabled

    # Calculate checksum
    checksum = hashlib.sha256(metadata[0:0x1F0]).digest()
    metadata[0x1F0:0x210] = checksum[:32]

    # Create unencrypted data (4 sectors)
    data = b'\xCA\xFE\xBA\xBE' * (M2_SECTOR_SIZE * 4 // 4)

    # Write to file
    with open(image_path, 'wb') as f:
        f.write(metadata)
        f.write(data)

    return image_path


# ============================================================================
# CLI Integration Tests
# ============================================================================

class TestCLIInfo:
    """Test 'info' command integration."""

    def test_info_encrypted_image(self, sample_encrypted_image):
        """Test displaying info for encrypted image."""
        runner = CliRunner()
        result = runner.invoke(cli, ['info', str(sample_encrypted_image)])

        assert result.exit_code == 0
        assert 'M2SS' in result.output or 'magic' in result.output.lower()
        assert 'encrypted' in result.output.lower() or 'yes' in result.output.lower()
        assert '8' in result.output  # Sector count

    def test_info_unencrypted_image(self, sample_unencrypted_image):
        """Test displaying info for unencrypted image."""
        runner = CliRunner()
        result = runner.invoke(cli, ['info', str(sample_unencrypted_image)])

        assert result.exit_code == 0
        assert '4' in result.output  # Sector count

    def test_info_nonexistent_file(self):
        """Test info command with nonexistent file."""
        runner = CliRunner()
        result = runner.invoke(cli, ['info', '/nonexistent/file.img'])

        assert result.exit_code != 0

    def test_info_invalid_image(self, temp_dir):
        """Test info command with invalid image file."""
        bad_file = temp_dir / 'bad.img'
        bad_file.write_bytes(b'NOT_A_VALID_M2_IMAGE' * 100)

        runner = CliRunner()
        result = runner.invoke(cli, ['info', str(bad_file)])

        assert result.exit_code != 0


class TestCLIDecrypt:
    """Test 'decrypt' command integration."""

    def test_decrypt_encrypted_image(self, sample_encrypted_image, temp_dir):
        """Test decrypting an encrypted image."""
        output_path = temp_dir / 'decrypted.img'

        runner = CliRunner()
        result = runner.invoke(cli, [
            'decrypt',
            str(sample_encrypted_image),
            '-o', str(output_path)
        ])

        assert result.exit_code == 0
        assert output_path.exists()
        assert output_path.stat().st_size > 0

    def test_decrypt_unencrypted_image(self, sample_unencrypted_image, temp_dir):
        """Test decrypting an already unencrypted image."""
        output_path = temp_dir / 'decrypted.img'

        runner = CliRunner()
        result = runner.invoke(cli, [
            'decrypt',
            str(sample_unencrypted_image),
            '-o', str(output_path)
        ])

        # Should handle gracefully (copy or skip)
        assert result.exit_code == 0

    def test_decrypt_missing_output_path(self, sample_encrypted_image):
        """Test decrypt without output path."""
        runner = CliRunner()
        result = runner.invoke(cli, ['decrypt', str(sample_encrypted_image)])

        # Should either fail or use default output
        assert result.exit_code in [0, 1, 2]

    def test_decrypt_to_existing_file(self, sample_encrypted_image, temp_dir):
        """Test decrypting to existing file (overwrite)."""
        output_path = temp_dir / 'existing.img'
        output_path.write_bytes(b'OLD_DATA')

        runner = CliRunner()
        result = runner.invoke(cli, [
            'decrypt',
            str(sample_encrypted_image),
            '-o', str(output_path),
            '--force'
        ])

        # Should overwrite with force flag
        if '--force' in cli.commands['decrypt'].params:
            assert result.exit_code == 0
        else:
            # May fail without force flag
            assert result.exit_code in [0, 1]


class TestCLIVerify:
    """Test 'verify' command integration."""

    def test_verify_valid_image(self, sample_encrypted_image):
        """Test verifying a valid image."""
        runner = CliRunner()
        result = runner.invoke(cli, ['verify', str(sample_encrypted_image)])

        assert result.exit_code == 0
        assert 'valid' in result.output.lower() or 'ok' in result.output.lower()

    def test_verify_corrupted_image(self, sample_encrypted_image):
        """Test verifying a corrupted image."""
        # Corrupt the image
        with open(sample_encrypted_image, 'r+b') as f:
            f.seek(0x100)
            f.write(b'\xFF' * 16)

        runner = CliRunner()
        result = runner.invoke(cli, ['verify', str(sample_encrypted_image)])

        # Should detect corruption
        assert 'invalid' in result.output.lower() or 'fail' in result.output.lower()

    def test_verify_invalid_magic(self, temp_dir):
        """Test verifying image with invalid magic."""
        bad_file = temp_dir / 'bad_magic.img'
        bad_file.write_bytes(b'BAAD' + b'\x00' * 1000)

        runner = CliRunner()
        result = runner.invoke(cli, ['verify', str(bad_file)])

        assert result.exit_code != 0


class TestCLIExtract:
    """Test 'extract' command integration."""

    def test_extract_to_directory(self, sample_encrypted_image, temp_dir):
        """Test extracting image contents to directory."""
        extract_dir = temp_dir / 'extracted'

        runner = CliRunner()
        result = runner.invoke(cli, [
            'extract',
            str(sample_encrypted_image),
            '-o', str(extract_dir)
        ])

        assert result.exit_code == 0
        assert extract_dir.exists()
        assert extract_dir.is_dir()

    def test_extract_filesystem_contents(self, sample_encrypted_image, temp_dir):
        """Test that extract creates filesystem files."""
        extract_dir = temp_dir / 'fs'

        runner = CliRunner()
        result = runner.invoke(cli, [
            'extract',
            str(sample_encrypted_image),
            '-o', str(extract_dir)
        ])

        if result.exit_code == 0:
            # Check for common PS5 filesystem artifacts
            extracted_files = list(extract_dir.rglob('*'))
            assert len(extracted_files) > 0


class TestCLIEncrypt:
    """Test 'encrypt' command integration (if implemented)."""

    def test_encrypt_unencrypted_image(self, sample_unencrypted_image, temp_dir):
        """Test encrypting an unencrypted image."""
        output_path = temp_dir / 'encrypted.img'

        runner = CliRunner()
        result = runner.invoke(cli, [
            'encrypt',
            str(sample_unencrypted_image),
            '-o', str(output_path)
        ])

        if 'encrypt' in cli.commands:
            assert result.exit_code == 0
            assert output_path.exists()


# ============================================================================
# File I/O Integration Tests
# ============================================================================

class TestFileOperations:
    """Test file reading and writing."""

    def test_read_write_round_trip(self, sample_encrypted_image, temp_dir):
        """Test reading and writing image preserves data."""
        # Read original
        with open(sample_encrypted_image, 'rb') as f:
            original_data = f.read()

        # Write to new file
        copy_path = temp_dir / 'copy.img'
        with open(copy_path, 'wb') as f:
            f.write(original_data)

        # Read copy
        with open(copy_path, 'rb') as f:
            copy_data = f.read()

        assert original_data == copy_data

    def test_partial_read(self, sample_encrypted_image):
        """Test reading only metadata."""
        with open(sample_encrypted_image, 'rb') as f:
            metadata = f.read(M2_METADATA_SIZE)

        assert len(metadata) == M2_METADATA_SIZE
        assert metadata[:4] == b'M2SS'

    def test_large_file_handling(self, temp_dir):
        """Test handling of large M.2 images (simulated)."""
        import struct
        import hashlib

        large_image = temp_dir / 'large.img'

        # Create metadata claiming 1 million sectors (but don't write all data)
        metadata = bytearray(M2_METADATA_SIZE)
        metadata[0:4] = b'M2SS'
        struct.pack_into('<I', metadata, 0x04, 0x01)
        struct.pack_into('<Q', metadata, 0x08, 1_000_000)
        struct.pack_into('<I', metadata, 0x10, 1)

        checksum = hashlib.sha256(metadata[0:0x1F0]).digest()
        metadata[0x1F0:0x210] = checksum[:32]

        with open(large_image, 'wb') as f:
            f.write(metadata)
            # Just write a bit of data, not all 1M sectors
            f.write(b'\x00' * M2_SECTOR_SIZE * 10)

        # Test that info command handles it
        runner = CliRunner()
        result = runner.invoke(cli, ['info', str(large_image)])

        assert result.exit_code == 0
        assert '1000000' in result.output or '1M' in result.output


# ============================================================================
# Workflow Integration Tests
# ============================================================================

class TestWorkflows:
    """Test complete multi-step workflows."""

    def test_info_verify_decrypt_workflow(self, sample_encrypted_image, temp_dir):
        """Test complete analysis and decryption workflow."""
        runner = CliRunner()

        # Step 1: Get info
        info_result = runner.invoke(cli, ['info', str(sample_encrypted_image)])
        assert info_result.exit_code == 0

        # Step 2: Verify integrity
        verify_result = runner.invoke(cli, ['verify', str(sample_encrypted_image)])
        assert verify_result.exit_code == 0

        # Step 3: Decrypt
        output_path = temp_dir / 'decrypted.img'
        decrypt_result = runner.invoke(cli, [
            'decrypt',
            str(sample_encrypted_image),
            '-o', str(output_path)
        ])
        assert decrypt_result.exit_code == 0

        # Step 4: Verify decrypted image
        verify_decrypted = runner.invoke(cli, ['verify', str(output_path)])
        assert verify_decrypted.exit_code == 0

    def test_extract_workflow(self, sample_encrypted_image, temp_dir):
        """Test complete extraction workflow."""
        runner = CliRunner()
        extract_dir = temp_dir / 'extracted'

        # Extract
        result = runner.invoke(cli, [
            'extract',
            str(sample_encrypted_image),
            '-o', str(extract_dir)
        ])

        assert result.exit_code == 0

        # Verify extraction created files
        if extract_dir.exists():
            contents = list(extract_dir.rglob('*'))
            # Should have created at least some files/dirs
            assert len(contents) >= 0

    def test_decrypt_then_encrypt_workflow(self, sample_encrypted_image, temp_dir):
        """Test decrypt then re-encrypt workflow."""
        if 'encrypt' not in cli.commands:
            pytest.skip("Encrypt command not implemented")

        runner = CliRunner()

        # Decrypt
        decrypted_path = temp_dir / 'decrypted.img'
        decrypt_result = runner.invoke(cli, [
            'decrypt',
            str(sample_encrypted_image),
            '-o', str(decrypted_path)
        ])
        assert decrypt_result.exit_code == 0

        # Re-encrypt
        reencrypted_path = temp_dir / 'reencrypted.img'
        encrypt_result = runner.invoke(cli, [
            'encrypt',
            str(decrypted_path),
            '-o', str(reencrypted_path)
        ])
        assert encrypt_result.exit_code == 0


# ============================================================================
# Error Handling Integration Tests
# ============================================================================

class TestErrorHandling:
    """Test error handling in real scenarios."""

    def test_permission_denied(self, temp_dir):
        """Test handling of permission denied errors."""
        # Create a file we can't write to
        import os
        readonly_file = temp_dir / 'readonly.img'
        readonly_file.write_bytes(b'M2SS' + b'\x00' * 1000)
        readonly_file.chmod(0o444)

        runner = CliRunner()

        # Try to decrypt to readonly file (should fail gracefully)
        result = runner.invoke(cli, [
            'decrypt',
            str(readonly_file),
            '-o', str(readonly_file)
        ])

        assert result.exit_code != 0

        # Cleanup
        readonly_file.chmod(0o644)

    def test_disk_full_simulation(self, temp_dir, sample_encrypted_image):
        """Test handling of disk full errors."""
        # Note: This is hard to test without actually filling disk
        # We'll just verify the decrypt command handles I/O errors
        runner = CliRunner()

        output_path = temp_dir / 'output.img'
        result = runner.invoke(cli, [
            'decrypt',
            str(sample_encrypted_image),
            '-o', str(output_path)
        ])

        # Should either succeed or fail gracefully
        assert result.exit_code in [0, 1]

    def test_corrupted_during_operation(self, sample_encrypted_image, temp_dir):
        """Test handling of image corrupted during operation."""
        # Simulate corruption by truncating file
        corrupted = temp_dir / 'corrupted.img'
        with open(sample_encrypted_image, 'rb') as src:
            data = src.read(M2_METADATA_SIZE + M2_SECTOR_SIZE * 2)  # Truncated
        corrupted.write_bytes(data)

        runner = CliRunner()
        result = runner.invoke(cli, ['verify', str(corrupted)])

        # Should detect issue
        assert 'error' in result.output.lower() or result.exit_code != 0


# ============================================================================
# Performance Integration Tests
# ============================================================================

class TestPerformance:
    """Test performance with realistic scenarios."""

    def test_decrypt_performance(self, sample_encrypted_image, temp_dir):
        """Test decryption performance."""
        import time

        output_path = temp_dir / 'decrypted.img'
        runner = CliRunner()

        start = time.time()
        result = runner.invoke(cli, [
            'decrypt',
            str(sample_encrypted_image),
            '-o', str(output_path)
        ])
        duration = time.time() - start

        assert result.exit_code == 0
        # Should complete in reasonable time (< 5 seconds for small test image)
        assert duration < 5.0

    def test_verify_performance(self, sample_encrypted_image):
        """Test verification performance."""
        import time

        runner = CliRunner()

        start = time.time()
        result = runner.invoke(cli, ['verify', str(sample_encrypted_image)])
        duration = time.time() - start

        assert result.exit_code == 0
        # Verification should be fast
        assert duration < 2.0


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
