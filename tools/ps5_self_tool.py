#!/usr/bin/env python3
"""
PS5 SELF Decryptor/Patcher

Decrypt and patch PS5 SELF (Signed ELF) executables.

Usage:
    python ps5_self_tool.py info eboot.self
    python ps5_self_tool.py decrypt eboot.self -o eboot.elf
    python ps5_self_tool.py patch eboot.self --offset 0x1000 --bytes "90909090" -o patched.self

Reference:
    - PS4/PS5 SELF format: https://www.psdevwiki.com/ps4/SELF_File_Format
    - Segment flags and structure based on public documentation
"""
import sys
import struct
import zlib
from dataclasses import dataclass
from enum import IntFlag
from pathlib import Path
from typing import List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).parent.parent))

import click
from rich.console import Console
from rich.table import Table

from he.crypto import aes_cbc_decrypt_no_pad
from he.keys import load_self_keys
from he.utils import hexdump, read_u32_le, read_u64_le, align_up

console = Console()


# ============================================================================
# SELF Format Constants
# ============================================================================

SELF_MAGIC = b'\x4F\x15\x3D\x1D'
ELF_MAGIC = b'\x7FELF'

# SELF Category
SELF_CATEGORY_SELF = 1
SELF_CATEGORY_PUP_ENTRY = 4

# Program types (low nibble)
PROGRAM_TYPE_FAKE = 0x1
PROGRAM_TYPE_NPDRM_EXEC = 0x4
PROGRAM_TYPE_NPDRM_DYNLIB = 0x5
PROGRAM_TYPE_SYSTEM_EXEC = 0x8
PROGRAM_TYPE_SYSTEM_DYNLIB = 0x9
PROGRAM_TYPE_HOST_KERNEL = 0xC
PROGRAM_TYPE_SECURE_MODULE = 0xE
PROGRAM_TYPE_SECURE_KERNEL = 0xF


class SegmentFlags(IntFlag):
    """SELF segment property flags."""
    ORDERED = 0x1      # SF_ORDR - ordered segment
    ENCRYPTED = 0x2    # SF_ENCR - encrypted segment
    SIGNED = 0x4       # SF_SIGN - signed segment
    COMPRESSED = 0x8   # SF_DFLG - deflated/compressed
    BLOCKED = 0x800    # SF_BFLG - block segment


# ============================================================================
# SELF Data Structures
# ============================================================================

@dataclass
class SELFHeader:
    """SELF file header (0x20 bytes)."""
    magic: bytes           # 0x00: 4 bytes - 0x4F153D1D
    version: int           # 0x04: 4 bytes - usually 0x00010112
    category: int          # 0x08: 1 byte - 1=SELF, 4=PUP
    program_type: int      # 0x09: 1 byte - high nibble=version, low=type
    padding1: int          # 0x0A: 2 bytes
    header_size: int       # 0x0C: 2 bytes - total header size
    signature_size: int    # 0x0E: 2 bytes - metadata signature size
    file_size: int         # 0x10: 4 bytes - complete file size (lower 32 bits)
    file_size_hi: int      # 0x14: 4 bytes - file size high bits
    num_segments: int      # 0x18: 2 bytes - segment count
    flags: int             # 0x1A: 2 bytes - usually 0x22
    padding2: int          # 0x1C: 4 bytes

    @classmethod
    def parse(cls, data: bytes) -> 'SELFHeader':
        """Parse SELF header from bytes."""
        if len(data) < 0x20:
            raise ValueError(f"Data too short for SELF header: {len(data)} < 32")

        if data[:4] != SELF_MAGIC:
            raise ValueError(f"Invalid SELF magic: {data[:4].hex()}")

        return cls(
            magic=data[0:4],
            version=read_u32_le(data, 0x04),
            category=data[0x08],
            program_type=data[0x09],
            padding1=struct.unpack('<H', data[0x0A:0x0C])[0],
            header_size=struct.unpack('<H', data[0x0C:0x0E])[0],
            signature_size=struct.unpack('<H', data[0x0E:0x10])[0],
            file_size=read_u32_le(data, 0x10),
            file_size_hi=read_u32_le(data, 0x14),
            num_segments=struct.unpack('<H', data[0x18:0x1A])[0],
            flags=struct.unpack('<H', data[0x1A:0x1C])[0],
            padding2=read_u32_le(data, 0x1C),
        )

    @property
    def total_file_size(self) -> int:
        """Get full 64-bit file size."""
        return self.file_size | (self.file_size_hi << 32)

    @property
    def program_type_name(self) -> str:
        """Get human-readable program type."""
        type_val = self.program_type & 0x0F
        types = {
            PROGRAM_TYPE_FAKE: "Fake SELF",
            PROGRAM_TYPE_NPDRM_EXEC: "NPDRM Executable",
            PROGRAM_TYPE_NPDRM_DYNLIB: "NPDRM Dynamic Library",
            PROGRAM_TYPE_SYSTEM_EXEC: "System Executable",
            PROGRAM_TYPE_SYSTEM_DYNLIB: "System Dynamic Library",
            PROGRAM_TYPE_HOST_KERNEL: "Host Kernel",
            PROGRAM_TYPE_SECURE_MODULE: "Secure Module",
            PROGRAM_TYPE_SECURE_KERNEL: "Secure Kernel",
        }
        return types.get(type_val, f"Unknown (0x{type_val:X})")

    @property
    def program_version(self) -> int:
        """Get program version from high nibble."""
        return (self.program_type >> 4) & 0x0F


@dataclass
class SELFSegment:
    """SELF segment table entry (0x20 bytes)."""
    flags: int             # 0x00: 8 bytes - segment properties
    offset: int            # 0x08: 8 bytes - file offset
    compressed_size: int   # 0x10: 8 bytes - encrypted/compressed size
    decompressed_size: int # 0x18: 8 bytes - decrypted/decompressed size
    index: int = 0         # Segment index for reference

    @classmethod
    def parse(cls, data: bytes, index: int = 0) -> 'SELFSegment':
        """Parse segment entry from 0x20 bytes."""
        if len(data) < 0x20:
            raise ValueError(f"Data too short for segment: {len(data)} < 32")

        return cls(
            flags=read_u64_le(data, 0x00),
            offset=read_u64_le(data, 0x08),
            compressed_size=read_u64_le(data, 0x10),
            decompressed_size=read_u64_le(data, 0x18),
            index=index,
        )

    @property
    def segment_id(self) -> int:
        """Get segment ID from flags."""
        return (self.flags >> 20) & 0xFFF

    @property
    def is_ordered(self) -> bool:
        return bool(self.flags & SegmentFlags.ORDERED)

    @property
    def is_encrypted(self) -> bool:
        return bool(self.flags & SegmentFlags.ENCRYPTED)

    @property
    def is_signed(self) -> bool:
        return bool(self.flags & SegmentFlags.SIGNED)

    @property
    def is_compressed(self) -> bool:
        return bool(self.flags & SegmentFlags.COMPRESSED)

    @property
    def is_blocked(self) -> bool:
        return bool(self.flags & SegmentFlags.BLOCKED)

    @property
    def flags_str(self) -> str:
        """Get human-readable flags string."""
        parts = []
        if self.is_ordered:
            parts.append("ORD")
        if self.is_encrypted:
            parts.append("ENC")
        if self.is_signed:
            parts.append("SGN")
        if self.is_compressed:
            parts.append("CMP")
        if self.is_blocked:
            parts.append("BLK")
        return "|".join(parts) if parts else "NONE"


@dataclass
class ELF64Header:
    """ELF64 header structure (0x40 bytes)."""
    magic: bytes           # 0x00: 4 bytes - 0x7F ELF
    elf_class: int         # 0x04: 1 byte - 2 for 64-bit
    endian: int            # 0x05: 1 byte - 1 for little-endian
    version: int           # 0x06: 1 byte
    osabi: int             # 0x07: 1 byte - 9 for FreeBSD/PS4
    abiversion: int        # 0x08: 1 byte
    padding: bytes         # 0x09: 7 bytes
    elf_type: int          # 0x10: 2 bytes
    machine: int           # 0x12: 2 bytes - 0x3E for x86-64
    elf_version: int       # 0x14: 4 bytes
    entry: int             # 0x18: 8 bytes - entry point
    phoff: int             # 0x20: 8 bytes - program header offset
    shoff: int             # 0x28: 8 bytes - section header offset
    flags: int             # 0x30: 4 bytes
    ehsize: int            # 0x34: 2 bytes - ELF header size
    phentsize: int         # 0x36: 2 bytes - program header entry size
    phnum: int             # 0x38: 2 bytes - program header count
    shentsize: int         # 0x3A: 2 bytes - section header entry size
    shnum: int             # 0x3C: 2 bytes - section header count
    shstrndx: int          # 0x3E: 2 bytes - section string table index

    @classmethod
    def parse(cls, data: bytes) -> 'ELF64Header':
        """Parse ELF64 header from bytes."""
        if len(data) < 0x40:
            raise ValueError(f"Data too short for ELF header: {len(data)} < 64")

        if data[:4] != ELF_MAGIC:
            raise ValueError(f"Invalid ELF magic: {data[:4].hex()}")

        return cls(
            magic=data[0:4],
            elf_class=data[4],
            endian=data[5],
            version=data[6],
            osabi=data[7],
            abiversion=data[8],
            padding=data[9:16],
            elf_type=struct.unpack('<H', data[0x10:0x12])[0],
            machine=struct.unpack('<H', data[0x12:0x14])[0],
            elf_version=read_u32_le(data, 0x14),
            entry=read_u64_le(data, 0x18),
            phoff=read_u64_le(data, 0x20),
            shoff=read_u64_le(data, 0x28),
            flags=read_u32_le(data, 0x30),
            ehsize=struct.unpack('<H', data[0x34:0x36])[0],
            phentsize=struct.unpack('<H', data[0x36:0x38])[0],
            phnum=struct.unpack('<H', data[0x38:0x3A])[0],
            shentsize=struct.unpack('<H', data[0x3A:0x3C])[0],
            shnum=struct.unpack('<H', data[0x3C:0x3E])[0],
            shstrndx=struct.unpack('<H', data[0x3E:0x40])[0],
        )


@dataclass
class ELF64ProgramHeader:
    """ELF64 program header entry (0x38 bytes)."""
    p_type: int            # 0x00: 4 bytes
    p_flags: int           # 0x04: 4 bytes
    p_offset: int          # 0x08: 8 bytes
    p_vaddr: int           # 0x10: 8 bytes
    p_paddr: int           # 0x18: 8 bytes
    p_filesz: int          # 0x20: 8 bytes
    p_memsz: int           # 0x28: 8 bytes
    p_align: int           # 0x30: 8 bytes

    @classmethod
    def parse(cls, data: bytes) -> 'ELF64ProgramHeader':
        """Parse ELF64 program header from 0x38 bytes."""
        if len(data) < 0x38:
            raise ValueError(f"Data too short for program header: {len(data)} < 56")

        return cls(
            p_type=read_u32_le(data, 0x00),
            p_flags=read_u32_le(data, 0x04),
            p_offset=read_u64_le(data, 0x08),
            p_vaddr=read_u64_le(data, 0x10),
            p_paddr=read_u64_le(data, 0x18),
            p_filesz=read_u64_le(data, 0x20),
            p_memsz=read_u64_le(data, 0x28),
            p_align=read_u64_le(data, 0x30),
        )


# ============================================================================
# SELF Parser
# ============================================================================

class SELFParser:
    """Parser for PS4/PS5 SELF files."""

    def __init__(self, data: bytes):
        self.data = data
        self.header: Optional[SELFHeader] = None
        self.segments: List[SELFSegment] = []
        self.elf_header: Optional[ELF64Header] = None
        self.elf_program_headers: List[ELF64ProgramHeader] = []
        self._parse()

    def _parse(self):
        """Parse SELF file structure."""
        # Parse SELF header
        self.header = SELFHeader.parse(self.data)

        # Parse segment table (starts at 0x20)
        segment_table_offset = 0x20
        for i in range(self.header.num_segments):
            offset = segment_table_offset + (i * 0x20)
            seg = SELFSegment.parse(self.data[offset:offset + 0x20], index=i)
            self.segments.append(seg)

        # Calculate where ELF header should be (after SELF header + segments)
        # The ELF header is typically embedded after the segment certifications
        elf_offset = self._find_elf_header()
        if elf_offset is not None:
            try:
                self.elf_header = ELF64Header.parse(self.data[elf_offset:])
                self._parse_program_headers(elf_offset)
            except ValueError:
                pass  # ELF header might be encrypted

    def _find_elf_header(self) -> Optional[int]:
        """Find embedded ELF header offset."""
        # ELF is usually after SELF header + segment table + extended info
        # Try common offsets
        for offset in [self.header.header_size, 0x100, 0x200, 0x400, 0x1000]:
            if offset < len(self.data) - 4:
                if self.data[offset:offset + 4] == ELF_MAGIC:
                    return offset
        return None

    def _parse_program_headers(self, elf_offset: int):
        """Parse ELF program headers."""
        if self.elf_header is None:
            return

        phoff = elf_offset + self.elf_header.phoff
        for i in range(self.elf_header.phnum):
            offset = phoff + (i * self.elf_header.phentsize)
            if offset + 0x38 <= len(self.data):
                ph = ELF64ProgramHeader.parse(self.data[offset:offset + 0x38])
                self.elf_program_headers.append(ph)

    def get_segment_data(self, segment: SELFSegment) -> bytes:
        """Get raw segment data from file."""
        if segment.offset + segment.compressed_size > len(self.data):
            raise ValueError(f"Segment {segment.index} extends beyond file")
        return self.data[segment.offset:segment.offset + segment.compressed_size]


# ============================================================================
# SELF Decryptor
# ============================================================================

class SELFDecryptor:
    """Decryptor for PS4/PS5 SELF files."""

    def __init__(self, parser: SELFParser, key: bytes, iv: bytes):
        self.parser = parser
        self.key = key
        self.iv = iv

    def decrypt_segment(self, segment: SELFSegment) -> bytes:
        """
        Decrypt a single segment.

        Returns decrypted (and decompressed if applicable) data.
        """
        raw_data = self.parser.get_segment_data(segment)

        if len(raw_data) == 0:
            return b''

        # Handle encryption
        if segment.is_encrypted:
            # Align data to AES block size
            aligned_size = len(raw_data) & ~15
            if aligned_size == 0:
                # Data too small to decrypt
                return raw_data

            aligned_data = raw_data[:aligned_size]
            decrypted = aes_cbc_decrypt_no_pad(self.key, self.iv, aligned_data)

            # Append any remaining bytes (shouldn't happen with proper alignment)
            if len(raw_data) > aligned_size:
                decrypted += raw_data[aligned_size:]
        else:
            decrypted = raw_data

        # Handle compression
        if segment.is_compressed:
            try:
                # ZLIB decompression
                decompressed = zlib.decompress(decrypted)
                return decompressed
            except zlib.error as e:
                # May fail if decryption was wrong
                console.print(f"[yellow]Warning: Decompression failed for segment {segment.index}: {e}[/]")
                return decrypted

        return decrypted

    def decrypt_all_segments(self) -> List[Tuple[SELFSegment, bytes]]:
        """Decrypt all segments and return list of (segment, data) tuples."""
        results = []
        for segment in self.parser.segments:
            try:
                data = self.decrypt_segment(segment)
                results.append((segment, data))
            except Exception as e:
                console.print(f"[yellow]Warning: Failed to decrypt segment {segment.index}: {e}[/]")
                results.append((segment, b''))
        return results

    def reconstruct_elf(self) -> bytes:
        """
        Reconstruct ELF from decrypted segments.

        This attempts to rebuild a valid ELF file from the decrypted
        segment data, mapping SELF segments to ELF program headers.
        """
        decrypted_segments = self.decrypt_all_segments()

        # Find the segment containing the ELF header
        elf_data = None
        for segment, data in decrypted_segments:
            if len(data) >= 4 and data[:4] == ELF_MAGIC:
                elf_data = data
                break

        if elf_data is not None and len(elf_data) >= 0x40:
            # We found a decrypted ELF header
            try:
                elf_header = ELF64Header.parse(elf_data)

                # Build ELF from decrypted segments
                # Calculate required file size
                max_offset = elf_header.ehsize
                if elf_header.phoff > 0:
                    max_offset = max(max_offset, elf_header.phoff +
                                    (elf_header.phnum * elf_header.phentsize))

                # Parse program headers to find segment offsets
                phoff = elf_header.phoff
                for i in range(elf_header.phnum):
                    ph_start = phoff + (i * elf_header.phentsize)
                    if ph_start + 0x38 <= len(elf_data):
                        ph = ELF64ProgramHeader.parse(elf_data[ph_start:ph_start + 0x38])
                        if ph.p_filesz > 0:
                            max_offset = max(max_offset, ph.p_offset + ph.p_filesz)

                # Create output buffer
                output = bytearray(max_offset)

                # Copy ELF header and program headers
                header_end = elf_header.phoff + (elf_header.phnum * elf_header.phentsize)
                output[:min(header_end, len(elf_data))] = elf_data[:min(header_end, len(elf_data))]

                # Map decrypted segments to ELF program headers
                for i, (segment, data) in enumerate(decrypted_segments):
                    if i < elf_header.phnum:
                        ph_start = phoff + (i * elf_header.phentsize)
                        if ph_start + 0x38 <= len(elf_data):
                            ph = ELF64ProgramHeader.parse(elf_data[ph_start:ph_start + 0x38])
                            if ph.p_offset > 0 and ph.p_filesz > 0:
                                # Ensure output buffer is large enough
                                end_offset = ph.p_offset + ph.p_filesz
                                if end_offset > len(output):
                                    output.extend(b'\x00' * (end_offset - len(output)))
                                # Copy segment data
                                copy_size = min(len(data), ph.p_filesz)
                                output[ph.p_offset:ph.p_offset + copy_size] = data[:copy_size]

                return bytes(output)

            except ValueError as e:
                console.print(f"[yellow]Warning: ELF reconstruction failed: {e}[/]")

        # Fallback: concatenate all decrypted data
        all_data = b''.join(data for _, data in decrypted_segments)
        return all_data


# ============================================================================
# CLI Commands
# ============================================================================

@click.group()
def cli():
    """PS5 SELF Decryptor/Patcher - Security Research Tool"""
    pass


@cli.command()
@click.argument('self_file', type=click.Path(exists=True))
@click.option('-v', '--verbose', is_flag=True, help='Show detailed segment info')
def info(self_file: str, verbose: bool):
    """Display SELF file information."""
    data = Path(self_file).read_bytes()

    # Header info table
    table = Table(title=f"SELF Info: {Path(self_file).name}")
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("File Size", f"{len(data):,} bytes ({len(data) / 1024:.2f} KB)")

    # Check file type
    if data[:4] == SELF_MAGIC:
        table.add_row("Format", "Signed ELF (SELF)")

        try:
            parser = SELFParser(data)
            hdr = parser.header

            table.add_row("Magic", hdr.magic.hex())
            table.add_row("Version", f"0x{hdr.version:08X}")
            table.add_row("Category", f"{hdr.category} ({'SELF' if hdr.category == 1 else 'PUP Entry'})")
            table.add_row("Program Type", f"{hdr.program_type_name} (v{hdr.program_version})")
            table.add_row("Header Size", f"0x{hdr.header_size:X} ({hdr.header_size} bytes)")
            table.add_row("Signature Size", f"0x{hdr.signature_size:X} ({hdr.signature_size} bytes)")
            table.add_row("Declared Size", f"0x{hdr.total_file_size:X} ({hdr.total_file_size:,} bytes)")
            table.add_row("Segments", str(hdr.num_segments))
            table.add_row("Flags", f"0x{hdr.flags:04X}")

            # Check for embedded ELF
            if parser.elf_header:
                elf = parser.elf_header
                table.add_row("ELF Embedded", "Yes (found)")
                table.add_row("ELF Entry", f"0x{elf.entry:X}")
                table.add_row("ELF Programs", str(elf.phnum))
            else:
                table.add_row("ELF Embedded", "Not found (encrypted?)")

            console.print(table)

            # Segment table
            if parser.segments:
                seg_table = Table(title="Segment Table")
                seg_table.add_column("#", style="dim")
                seg_table.add_column("ID", style="cyan")
                seg_table.add_column("Flags", style="yellow")
                seg_table.add_column("Offset", style="green")
                seg_table.add_column("Comp Size", style="blue")
                seg_table.add_column("Decomp Size", style="magenta")

                for seg in parser.segments:
                    seg_table.add_row(
                        str(seg.index),
                        f"0x{seg.segment_id:03X}",
                        seg.flags_str,
                        f"0x{seg.offset:08X}",
                        f"0x{seg.compressed_size:X}",
                        f"0x{seg.decompressed_size:X}",
                    )

                console.print(seg_table)

            # ELF program headers
            if verbose and parser.elf_program_headers:
                ph_table = Table(title="ELF Program Headers")
                ph_table.add_column("#", style="dim")
                ph_table.add_column("Type", style="cyan")
                ph_table.add_column("Offset", style="green")
                ph_table.add_column("VAddr", style="blue")
                ph_table.add_column("FileSz", style="magenta")
                ph_table.add_column("MemSz", style="yellow")

                PT_TYPES = {
                    0: "NULL", 1: "LOAD", 2: "DYNAMIC", 3: "INTERP",
                    4: "NOTE", 6: "PHDR", 7: "TLS",
                    0x61000000: "SCE_RELA", 0x61000001: "SCE_DYNLIBDATA",
                    0x61000002: "SCE_PROCPARAM", 0x61000010: "SCE_RELRO",
                }

                for i, ph in enumerate(parser.elf_program_headers):
                    type_name = PT_TYPES.get(ph.p_type, f"0x{ph.p_type:X}")
                    ph_table.add_row(
                        str(i),
                        type_name,
                        f"0x{ph.p_offset:X}",
                        f"0x{ph.p_vaddr:X}",
                        f"0x{ph.p_filesz:X}",
                        f"0x{ph.p_memsz:X}",
                    )

                console.print(ph_table)

        except Exception as e:
            table.add_row("Parse Error", str(e))
            console.print(table)

    elif data[:4] == ELF_MAGIC:
        table.add_row("Format", "Plain ELF (already decrypted)")
        try:
            elf = ELF64Header.parse(data)
            table.add_row("Class", "64-bit" if elf.elf_class == 2 else "32-bit")
            table.add_row("Entry Point", f"0x{elf.entry:X}")
            table.add_row("Program Headers", str(elf.phnum))
            table.add_row("Section Headers", str(elf.shnum))
        except Exception as e:
            table.add_row("Parse Error", str(e))
        console.print(table)
    else:
        table.add_row("Format", f"Unknown (magic: {data[:4].hex()})")
        console.print(table)

    # Show header hexdump
    if verbose:
        console.print("\n[dim]Header (first 256 bytes):[/]")
        console.print(hexdump(data, length=256))


@cli.command()
@click.argument('self_file', type=click.Path(exists=True))
@click.option('-o', '--output', required=True, help='Output ELF file')
@click.option('-k', '--keys', default='keys/self_keys.json', help='Keys file')
@click.option('--raw', is_flag=True, help='Output raw decrypted segments (no ELF reconstruction)')
@click.option('--segment', type=int, default=None, help='Decrypt specific segment only')
def decrypt(self_file: str, output: str, keys: str, raw: bool, segment: Optional[int]):
    """Decrypt SELF to ELF."""
    console.print(f"[bold blue]Decrypting {self_file}[/]")

    # Load keys
    keys_path = Path(__file__).parent.parent / keys
    if not keys_path.exists():
        keys_path = Path(keys)

    try:
        k = load_self_keys(str(keys_path))
    except Exception as e:
        console.print(f"[red]Failed to load keys: {e}[/]")
        return

    data = Path(self_file).read_bytes()

    # Check if already decrypted ELF
    if data[:4] == ELF_MAGIC:
        console.print("[yellow]File is already a plain ELF[/]")
        Path(output).write_bytes(data)
        console.print(f"[green]Copied to {output}[/]")
        return

    if data[:4] != SELF_MAGIC:
        console.print(f"[red]Not a valid SELF file (magic: {data[:4].hex()})[/]")
        return

    key = bytes.fromhex(k['cipher_key'])
    iv = bytes.fromhex(k['cipher_iv'])

    console.print(f"[dim]Using cipher key: {k['cipher_key'][:16]}...[/]")

    try:
        parser = SELFParser(data)
        decryptor = SELFDecryptor(parser, key, iv)

        console.print(f"[dim]Parsed {len(parser.segments)} segments[/]")

        if segment is not None:
            # Decrypt specific segment
            if segment < 0 or segment >= len(parser.segments):
                console.print(f"[red]Invalid segment index: {segment} (0-{len(parser.segments)-1})[/]")
                return

            seg = parser.segments[segment]
            console.print(f"[dim]Decrypting segment {segment}: flags={seg.flags_str}[/]")

            decrypted = decryptor.decrypt_segment(seg)
            Path(output).write_bytes(decrypted)
            console.print(f"[green]Segment {segment} ({len(decrypted):,} bytes) -> {output}[/]")
            return

        if raw:
            # Output concatenated raw decrypted segments
            all_segments = decryptor.decrypt_all_segments()
            all_data = b''.join(data for _, data in all_segments)
            Path(output).write_bytes(all_data)
            console.print(f"[green]Raw decrypted data ({len(all_data):,} bytes) -> {output}[/]")
            return

        # Reconstruct ELF
        elf_data = decryptor.reconstruct_elf()

        # Verify result
        if len(elf_data) >= 4 and elf_data[:4] == ELF_MAGIC:
            console.print("[green]Decryption successful - valid ELF header found[/]")
        else:
            console.print(f"[yellow]Warning: Output doesn't start with ELF magic[/]")
            console.print(f"[dim]Got: {elf_data[:16].hex() if len(elf_data) >= 16 else elf_data.hex()}[/]")
            console.print("[yellow]File may need different keys or manual extraction[/]")

        Path(output).write_bytes(elf_data)
        console.print(f"[green]Decrypted ELF ({len(elf_data):,} bytes) -> {output}[/]")

    except Exception as e:
        console.print(f"[red]Decryption failed: {e}[/]")
        raise


@cli.command()
@click.argument('self_file', type=click.Path(exists=True))
@click.option('-o', '--output', required=True, help='Output patched SELF')
@click.option('--offset', required=True, type=str, help='Patch offset (hex, e.g., 0x1000)')
@click.option('--bytes', 'patch_bytes', required=True, help='Patch bytes (hex, e.g., 90909090)')
def patch(self_file: str, output: str, offset: str, patch_bytes: str):
    """Patch SELF file at offset."""
    console.print(f"[bold blue]Patching {self_file}[/]")

    data = bytearray(Path(self_file).read_bytes())

    # Parse offset (support 0x prefix)
    try:
        if offset.lower().startswith('0x'):
            patch_offset = int(offset, 16)
        else:
            patch_offset = int(offset)
    except ValueError:
        console.print(f"[red]Invalid offset: {offset}[/]")
        return

    # Parse patch bytes
    try:
        patch_data = bytes.fromhex(patch_bytes.replace(' ', ''))
    except ValueError:
        console.print(f"[red]Invalid hex bytes: {patch_bytes}[/]")
        return

    # Validate offset
    if patch_offset < 0 or patch_offset + len(patch_data) > len(data):
        console.print(f"[red]Offset 0x{patch_offset:X} + {len(patch_data)} bytes exceeds file size ({len(data)})[/]")
        return

    # Show before
    before = data[patch_offset:patch_offset + len(patch_data)]
    console.print(f"\n[cyan]Patching {len(patch_data)} bytes at offset 0x{patch_offset:X}[/]")
    console.print(f"  Before: {before.hex()}")
    console.print(f"  After:  {patch_data.hex()}")

    # Apply patch
    data[patch_offset:patch_offset + len(patch_data)] = patch_data

    Path(output).write_bytes(bytes(data))
    console.print(f"\n[green]Patched SELF -> {output}[/]")


@cli.command()
@click.argument('self_file', type=click.Path(exists=True))
@click.option('--offset', type=str, default='0', help='Offset to dump from (hex)')
@click.option('--length', type=int, default=256, help='Number of bytes to dump')
def dump(self_file: str, offset: str, length: int):
    """Dump bytes from SELF file."""
    data = Path(self_file).read_bytes()

    # Parse offset
    try:
        if offset.lower().startswith('0x'):
            dump_offset = int(offset, 16)
        else:
            dump_offset = int(offset)
    except ValueError:
        console.print(f"[red]Invalid offset: {offset}[/]")
        return

    if dump_offset >= len(data):
        console.print(f"[red]Offset 0x{dump_offset:X} exceeds file size ({len(data)})[/]")
        return

    console.print(f"[cyan]Dumping {length} bytes from offset 0x{dump_offset:X}[/]\n")
    console.print(hexdump(data[dump_offset:dump_offset + length], offset=dump_offset))


@cli.command()
@click.argument('self_file', type=click.Path(exists=True))
@click.option('-o', '--output', required=True, help='Output file for segment data')
@click.option('--index', required=True, type=int, help='Segment index to extract')
def extract_segment(self_file: str, output: str, index: int):
    """Extract raw segment data (without decryption)."""
    data = Path(self_file).read_bytes()

    if data[:4] != SELF_MAGIC:
        console.print(f"[red]Not a valid SELF file[/]")
        return

    try:
        parser = SELFParser(data)

        if index < 0 or index >= len(parser.segments):
            console.print(f"[red]Invalid segment index: {index} (0-{len(parser.segments)-1})[/]")
            return

        segment = parser.segments[index]
        segment_data = parser.get_segment_data(segment)

        Path(output).write_bytes(segment_data)
        console.print(f"[green]Extracted segment {index} ({len(segment_data):,} bytes)[/]")
        console.print(f"[dim]  Flags: {segment.flags_str}[/]")
        console.print(f"[dim]  Offset: 0x{segment.offset:X}[/]")
        console.print(f"[green]  -> {output}[/]")

    except Exception as e:
        console.print(f"[red]Extraction failed: {e}[/]")


if __name__ == '__main__':
    cli()
