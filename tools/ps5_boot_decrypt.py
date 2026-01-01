#!/usr/bin/env python3
"""
PS5 Boot Chain Decryptor

Decrypts: EMC IPL Header -> EMC IPL Body -> EAP KBL -> EAP Kernel

Usage:
    python ps5_boot_decrypt.py firmware.bin -o output/
    python ps5_boot_decrypt.py firmware.bin --stage eap-kbl -o eap_kbl.dec
    python ps5_boot_decrypt.py firmware.bin --info
"""
import struct
import sys
from dataclasses import dataclass
from enum import Enum, auto
from pathlib import Path
from typing import Optional, Dict, List, Tuple

# Add parent dir to path for he package
sys.path.insert(0, str(Path(__file__).parent.parent))

import click
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
from rich.panel import Panel

from he.crypto import aes_cbc_decrypt_iv_zero, hmac_sha1_verify, hmac_sha256_verify
from he.keys import load_boot_chain_keys
from he.utils import hexdump, read_u32_le, read_u64_le

console = Console()


# =============================================================================
# Firmware Format Definitions
# =============================================================================

class FirmwareType(Enum):
    """Known PS5 firmware container types."""
    UNKNOWN = auto()
    RAW_DUMP = auto()
    EMC_IPL = auto()
    EAP_BLOB = auto()
    PUP_SEGMENT = auto()


@dataclass
class BootChainHeader:
    """Parsed boot chain header structure."""
    magic: bytes
    version: int
    header_size: int
    total_size: int
    segment_count: int
    flags: int
    reserved: bytes


@dataclass
class BootSegment:
    """A segment within the boot chain."""
    index: int
    name: str
    offset: int
    size: int
    encrypted_size: int
    mac_offset: Optional[int]
    mac_size: int
    flags: int


@dataclass
class FirmwareInfo:
    """Complete firmware analysis result."""
    firmware_type: FirmwareType
    size: int
    header: Optional[BootChainHeader]
    segments: List[BootSegment]
    version_string: str
    offsets: Dict[str, Dict[str, int]]


# =============================================================================
# Magic Bytes and Constants
# =============================================================================

# Known magic bytes for different firmware types
MAGIC_ELF = b'\x7FELF'
MAGIC_CNT = b'\x7FCNT'  # PS5 PKG container
MAGIC_EMC = b'\x00\x00\x00\x00'  # EMC IPL starts with zeros (encrypted)
MAGIC_PUP = b'\x4F\x15\x3D\x1D'  # PUP format
MAGIC_SLBH = b'SLBH'  # Secure loader blob header

# EMC IPL header structure constants
EMC_HEADER_MAGIC_OFFSET = 0x0
EMC_HEADER_VERSION_OFFSET = 0x4
EMC_HEADER_SIZE_OFFSET = 0x8
EMC_HEADER_FLAGS_OFFSET = 0xC
EMC_HEADER_BODY_OFFSET_OFFSET = 0x10
EMC_HEADER_BODY_SIZE_OFFSET = 0x18

# Default segment sizes (fallback when header parsing fails)
DEFAULT_OFFSETS = {
    'emc_header': {'offset': 0x0, 'size': 0x1000, 'mac_offset': None, 'mac_size': 0},
    'emc_body': {'offset': 0x1000, 'size': 0x10000, 'mac_offset': None, 'mac_size': 0},
    'eap_kbl': {'offset': 0x20000, 'size': 0x20000, 'mac_offset': 0x40000, 'mac_size': 20},
    'eap_kernel': {'offset': 0x50000, 'size': 0x100000, 'mac_offset': 0x150000, 'mac_size': 32},
}

# Version patterns for detection
VERSION_PATTERNS = [
    (b'00.000.000', 'Development'),
    (b'01.', 'Release 1.x'),
    (b'02.', 'Release 2.x'),
    (b'03.', 'Release 3.x'),
    (b'04.', 'Release 4.x'),
    (b'05.', 'Release 5.x'),
    (b'06.', 'Release 6.x'),
    (b'07.', 'Release 7.x'),
    (b'08.', 'Release 8.x'),
    (b'09.', 'Release 9.x'),
]


# =============================================================================
# Header Parsing Functions
# =============================================================================

def detect_firmware_type(data: bytes) -> FirmwareType:
    """Detect the type of firmware based on magic bytes and structure."""
    if len(data) < 16:
        return FirmwareType.UNKNOWN

    # Check for known magic bytes
    if data[:4] == MAGIC_ELF:
        return FirmwareType.RAW_DUMP  # ELF might be a raw kernel dump

    if data[:4] == MAGIC_CNT:
        return FirmwareType.PUP_SEGMENT  # PKG container format

    if data[:4] == MAGIC_PUP:
        return FirmwareType.PUP_SEGMENT

    if data[:4] == MAGIC_SLBH:
        return FirmwareType.EAP_BLOB

    # Check for EMC IPL characteristics
    # EMC IPL typically starts with encrypted data (high entropy)
    # and has specific size patterns
    if _check_emc_ipl_pattern(data):
        return FirmwareType.EMC_IPL

    return FirmwareType.RAW_DUMP


def _check_emc_ipl_pattern(data: bytes) -> bool:
    """Check if data matches EMC IPL pattern."""
    if len(data) < 0x1000:
        return False

    # EMC IPL header is 0x1000 bytes, encrypted
    # Check for high entropy in first block (encrypted data characteristic)
    first_block = data[:256]
    unique_bytes = len(set(first_block))

    # Encrypted data typically has high byte diversity
    return unique_bytes > 200


def parse_boot_chain_header(data: bytes) -> Optional[BootChainHeader]:
    """
    Parse the boot chain header structure.

    Returns None if header cannot be parsed (encrypted or unknown format).
    """
    if len(data) < 0x40:
        return None

    try:
        magic = data[:4]
        version = read_u32_le(data, 4)
        header_size = read_u32_le(data, 8)
        total_size = read_u32_le(data, 12)
        segment_count = read_u32_le(data, 16)
        flags = read_u32_le(data, 20)
        reserved = data[24:40]

        # Validate parsed values
        if header_size > 0x10000 or header_size == 0:
            return None
        if segment_count > 16:
            return None

        return BootChainHeader(
            magic=magic,
            version=version,
            header_size=header_size,
            total_size=total_size,
            segment_count=segment_count,
            flags=flags,
            reserved=reserved
        )
    except (struct.error, IndexError):
        return None


def detect_segment_offsets(data: bytes, firmware_type: FirmwareType) -> Dict[str, Dict[str, int]]:
    """
    Auto-detect segment offsets based on firmware analysis.

    Attempts to find segment boundaries by scanning for:
    - Size fields in headers
    - Alignment patterns
    - Known marker sequences
    """
    offsets = DEFAULT_OFFSETS.copy()

    if firmware_type == FirmwareType.EMC_IPL:
        offsets = _detect_emc_offsets(data)
    elif firmware_type == FirmwareType.EAP_BLOB:
        offsets = _detect_eap_offsets(data)

    return offsets


def _detect_emc_offsets(data: bytes) -> Dict[str, Dict[str, int]]:
    """Detect offsets for EMC IPL format."""
    offsets = DEFAULT_OFFSETS.copy()

    # EMC header is always at offset 0, size 0x1000
    offsets['emc_header'] = {'offset': 0x0, 'size': 0x1000, 'mac_offset': None, 'mac_size': 0}

    # Try to find EMC body size from decrypted header hints
    # In encrypted form, we use heuristics
    data_len = len(data)

    # EMC body typically follows immediately after header
    emc_body_offset = 0x1000

    # Look for segment boundaries (often aligned to 0x1000 or 0x10000)
    # EAP KBL usually starts at 0x20000 or similar aligned offset
    for potential_offset in [0x11000, 0x20000, 0x30000, 0x40000]:
        if potential_offset < data_len:
            # Check for potential header/marker at this offset
            if _is_potential_segment_start(data, potential_offset):
                emc_body_size = potential_offset - emc_body_offset
                offsets['emc_body'] = {
                    'offset': emc_body_offset,
                    'size': emc_body_size,
                    'mac_offset': None,
                    'mac_size': 0
                }
                offsets['eap_kbl'] = {
                    'offset': potential_offset,
                    'size': min(0x20000, data_len - potential_offset),
                    'mac_offset': potential_offset + 0x20000,
                    'mac_size': 20
                }
                break

    # EAP kernel follows EAP KBL
    eap_kbl_end = offsets['eap_kbl']['offset'] + offsets['eap_kbl']['size'] + offsets['eap_kbl']['mac_size']
    if eap_kbl_end < data_len:
        # Align to next boundary
        eap_kernel_offset = (eap_kbl_end + 0xFFF) & ~0xFFF
        offsets['eap_kernel'] = {
            'offset': eap_kernel_offset,
            'size': min(0x100000, data_len - eap_kernel_offset),
            'mac_offset': eap_kernel_offset + 0x100000,
            'mac_size': 32
        }

    return offsets


def _detect_eap_offsets(data: bytes) -> Dict[str, Dict[str, int]]:
    """Detect offsets for standalone EAP blob format."""
    offsets = DEFAULT_OFFSETS.copy()

    # EAP blob format: SLBH header followed by encrypted payload
    if data[:4] == MAGIC_SLBH:
        header_size = read_u32_le(data, 4)
        payload_size = read_u32_le(data, 8)

        offsets['eap_kbl'] = {
            'offset': header_size,
            'size': payload_size,
            'mac_offset': header_size + payload_size,
            'mac_size': 20
        }

    return offsets


def _is_potential_segment_start(data: bytes, offset: int) -> bool:
    """Check if offset looks like a segment boundary."""
    if offset + 16 > len(data):
        return False

    chunk = data[offset:offset + 16]

    # Check for high entropy (encrypted segment start)
    unique_bytes = len(set(chunk))
    if unique_bytes > 12:
        return True

    # Check for known markers
    if chunk[:4] in (MAGIC_SLBH, b'\x00\x00\x00\x00'):
        return True

    return False


def detect_version(data: bytes) -> str:
    """Attempt to detect firmware version from binary data."""
    # Search for version strings
    for pattern, description in VERSION_PATTERNS:
        idx = data.find(pattern)
        if idx != -1:
            # Try to extract full version string
            version_bytes = data[idx:idx + 16]
            try:
                # Find null terminator or non-printable
                end = 0
                for i, b in enumerate(version_bytes):
                    if b == 0 or b < 0x20 or b > 0x7E:
                        end = i
                        break
                else:
                    end = len(version_bytes)

                if end > 0:
                    return version_bytes[:end].decode('ascii')
            except (UnicodeDecodeError, ValueError):
                pass
            return description

    return "Unknown"


def analyze_firmware(data: bytes) -> FirmwareInfo:
    """Perform complete firmware analysis."""
    firmware_type = detect_firmware_type(data)
    header = parse_boot_chain_header(data)
    offsets = detect_segment_offsets(data, firmware_type)
    version = detect_version(data)

    # Build segment list
    segments = []
    for idx, (name, info) in enumerate(offsets.items()):
        segments.append(BootSegment(
            index=idx,
            name=name,
            offset=info['offset'],
            size=info['size'],
            encrypted_size=info['size'],
            mac_offset=info.get('mac_offset'),
            mac_size=info.get('mac_size', 0),
            flags=0
        ))

    return FirmwareInfo(
        firmware_type=firmware_type,
        size=len(data),
        header=header,
        segments=segments,
        version_string=version,
        offsets=offsets
    )


# =============================================================================
# Decryption Functions
# =============================================================================

def decrypt_segment(
    data: bytes,
    key: bytes,
    offset: int,
    size: int,
    mac_key: Optional[bytes] = None,
    mac_offset: Optional[int] = None,
    mac_size: int = 20,
    skip_mac: bool = False,
    use_sha256: bool = False
) -> Tuple[bytes, bool]:
    """
    Decrypt a firmware segment with optional MAC verification.

    Returns:
        Tuple of (decrypted_data, mac_verified)
    """
    # Extract encrypted data
    encrypted = data[offset:offset + size]

    if len(encrypted) < size:
        console.print(f"[yellow]Warning: Segment truncated ({len(encrypted)} < {size})[/]")

    # Align to AES block size
    if len(encrypted) % 16 != 0:
        padding_needed = 16 - (len(encrypted) % 16)
        encrypted = encrypted + b'\x00' * padding_needed

    # Verify MAC if requested
    mac_verified = True
    if mac_key and mac_offset and not skip_mac:
        expected_mac = data[mac_offset:mac_offset + mac_size]
        if len(expected_mac) >= mac_size:
            if use_sha256:
                mac_verified = hmac_sha256_verify(mac_key, encrypted, expected_mac)
            else:
                mac_verified = hmac_sha1_verify(mac_key, encrypted, expected_mac)

    # Decrypt
    decrypted = aes_cbc_decrypt_iv_zero(key, encrypted)

    return decrypted, mac_verified


def decrypt_emc_header(data: bytes, keys: dict, offsets: dict, output: Path, is_dir: bool):
    """Decrypt EMC IPL header."""
    off = offsets['emc_header']
    decrypted, _ = decrypt_segment(
        data,
        keys['emc_ipl_header'],
        off['offset'],
        off['size']
    )

    out_file = output / 'emc_header.dec' if is_dir else output
    Path(out_file).write_bytes(decrypted)
    console.print(f"[green]EMC Header ({len(decrypted)} bytes) -> {out_file}[/]")

    return decrypted


def decrypt_emc_body(data: bytes, keys: dict, offsets: dict, output: Path, is_dir: bool):
    """Decrypt EMC IPL body (only works on EMC revision c0)."""
    off = offsets['emc_body']
    decrypted, _ = decrypt_segment(
        data,
        keys['emc_ipl_cipher'],
        off['offset'],
        off['size']
    )

    out_file = output / 'emc_body.dec' if is_dir else output
    Path(out_file).write_bytes(decrypted)
    console.print(f"[green]EMC Body ({len(decrypted)} bytes) -> {out_file}[/]")

    return decrypted


def decrypt_eap_kbl(data: bytes, keys: dict, offsets: dict, output: Path, is_dir: bool, skip_mac: bool):
    """Decrypt EAP KBL with MAC verification."""
    off = offsets['eap_kbl']

    decrypted, mac_verified = decrypt_segment(
        data,
        keys['eap_kbl'],
        off['offset'],
        off['size'],
        mac_key=keys['eap_kbl_mac'],
        mac_offset=off.get('mac_offset'),
        mac_size=off.get('mac_size', 20),
        skip_mac=skip_mac
    )

    if not skip_mac:
        if off.get('mac_offset') is None:
            console.print("[yellow]Warning: No MAC offset configured, skipping verification[/]")
        elif not mac_verified:
            console.print("[red]EAP KBL MAC verification FAILED - data may be corrupted[/]")
            console.print("[yellow]Use --skip-mac to force decryption (dangerous)[/]")
            return None
        else:
            console.print("[green]EAP KBL MAC verified ✓[/]")

    out_file = output / 'eap_kbl.dec' if is_dir else output
    Path(out_file).write_bytes(decrypted)
    console.print(f"[green]EAP KBL ({len(decrypted)} bytes) -> {out_file}[/]")

    return decrypted


def decrypt_eap_kernel(data: bytes, keys: dict, offsets: dict, output: Path, is_dir: bool, skip_mac: bool = False):
    """Decrypt EAP Kernel with MAC verification."""
    off = offsets['eap_kernel']

    decrypted, mac_verified = decrypt_segment(
        data,
        keys['eap_kernel'],
        off['offset'],
        off['size'],
        mac_key=keys.get('eap_kernel_mac'),
        mac_offset=off.get('mac_offset'),
        mac_size=off.get('mac_size', 32),
        skip_mac=skip_mac,
        use_sha256=True  # EAP kernel uses SHA-256
    )

    if not skip_mac and keys.get('eap_kernel_mac'):
        if off.get('mac_offset') is None:
            console.print("[yellow]Warning: No MAC offset configured for kernel, skipping verification[/]")
        elif not mac_verified:
            console.print("[red]EAP Kernel MAC verification FAILED - data may be corrupted[/]")
        else:
            console.print("[green]EAP Kernel MAC verified ✓[/]")

    out_file = output / 'eap_kernel.dec' if is_dir else output
    Path(out_file).write_bytes(decrypted)
    console.print(f"[green]EAP Kernel ({len(decrypted)} bytes) -> {out_file}[/]")

    return decrypted


# =============================================================================
# Display Functions
# =============================================================================

def show_firmware_info(data: bytes):
    """Display comprehensive firmware analysis."""
    info = analyze_firmware(data)

    # Main info table
    table = Table(title="Firmware Analysis")
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Size", f"{info.size:,} bytes ({info.size / 1024 / 1024:.2f} MB)")
    table.add_row("Type", info.firmware_type.name)
    table.add_row("Version", info.version_string)
    table.add_row("Magic (first 16 bytes)", data[:16].hex())

    console.print(table)

    # Segment table
    if info.segments:
        seg_table = Table(title="Detected Segments")
        seg_table.add_column("#", style="dim")
        seg_table.add_column("Name", style="cyan")
        seg_table.add_column("Offset", style="yellow")
        seg_table.add_column("Size", style="green")
        seg_table.add_column("MAC Offset", style="magenta")
        seg_table.add_column("MAC Size", style="blue")

        for seg in info.segments:
            mac_off_str = f"0x{seg.mac_offset:X}" if seg.mac_offset else "N/A"
            seg_table.add_row(
                str(seg.index),
                seg.name,
                f"0x{seg.offset:X}",
                f"0x{seg.size:X} ({seg.size:,})",
                mac_off_str,
                str(seg.mac_size) if seg.mac_size else "N/A"
            )

        console.print(seg_table)

    # Hex dump
    console.print("\n[dim]First 256 bytes:[/]")
    console.print(hexdump(data, length=256))

    # Check data at segment boundaries
    console.print("\n[dim]Segment boundary samples:[/]")
    for seg in info.segments:
        if seg.offset < len(data):
            sample = data[seg.offset:seg.offset + 32]
            console.print(f"[cyan]{seg.name}[/] @ 0x{seg.offset:X}: {sample.hex()}")


# =============================================================================
# CLI Entry Point
# =============================================================================

@click.command()
@click.argument('firmware', type=click.Path(exists=True))
@click.option('-o', '--output', required=False, help='Output file or directory')
@click.option('-k', '--keys', default='keys/boot_chain.json', help='Keys file')
@click.option('--stage', type=click.Choice(['all', 'emc-header', 'emc-body', 'eap-kbl', 'eap-kernel']),
              default='all', help='Stage to decrypt')
@click.option('--info', is_flag=True, help='Show firmware info only')
@click.option('--skip-mac', is_flag=True, help='Skip MAC verification (dangerous)')
@click.option('--auto-detect/--no-auto-detect', default=True, help='Auto-detect offsets from firmware')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def main(firmware: str, output: str, keys: str, stage: str, info: bool, skip_mac: bool, auto_detect: bool, verbose: bool):
    """Decrypt PS5 boot chain components."""
    console.print(Panel.fit(
        "[bold blue]PS5 Boot Chain Decryptor[/]\n"
        "[dim]Heavy Elephant Security Research Toolkit[/]",
        border_style="blue"
    ))
    console.print(f"Firmware: {firmware}")

    # Read firmware
    data = Path(firmware).read_bytes()
    console.print(f"Loaded {len(data):,} bytes")

    # Analyze firmware
    fw_info = analyze_firmware(data)
    if verbose:
        console.print(f"[dim]Detected type: {fw_info.firmware_type.name}[/]")
        console.print(f"[dim]Detected version: {fw_info.version_string}[/]")

    if info:
        show_firmware_info(data)
        return

    if not output:
        console.print("[red]Error: --output required for decryption[/]")
        return

    # Load keys
    keys_path = Path(__file__).parent.parent / keys
    if not keys_path.exists():
        keys_path = Path(keys)

    if not keys_path.exists():
        console.print(f"[red]Error: Keys file not found: {keys_path}[/]")
        return

    k = load_boot_chain_keys(str(keys_path))
    console.print(f"[green]Loaded keys from {keys_path}[/]")

    # Use detected or default offsets
    offsets = fw_info.offsets if auto_detect else DEFAULT_OFFSETS

    if verbose:
        console.print("[dim]Using offsets:[/]")
        for name, off in offsets.items():
            console.print(f"[dim]  {name}: offset=0x{off['offset']:X}, size=0x{off['size']:X}[/]")

    # Ensure output directory exists
    out_path = Path(output)
    if stage == 'all':
        out_path.mkdir(parents=True, exist_ok=True)

    with Progress() as progress:
        task = progress.add_task("[cyan]Decrypting...", total=4)

        if stage in ('all', 'emc-header'):
            decrypt_emc_header(data, k, offsets, out_path, stage == 'all')
            progress.update(task, advance=1)

        if stage in ('all', 'emc-body'):
            decrypt_emc_body(data, k, offsets, out_path, stage == 'all')
            progress.update(task, advance=1)

        if stage in ('all', 'eap-kbl'):
            decrypt_eap_kbl(data, k, offsets, out_path, stage == 'all', skip_mac)
            progress.update(task, advance=1)

        if stage in ('all', 'eap-kernel'):
            decrypt_eap_kernel(data, k, offsets, out_path, stage == 'all', skip_mac)
            progress.update(task, advance=1)

    console.print("[bold green]Done![/]")


if __name__ == '__main__':
    main()
