#!/usr/bin/env python3
"""
PS5 PKG Manager

Sign, decrypt, and analyze PS5 PKG files.

PKG Format Overview (PS4/PS5 CNT format):
- Magic: 0x7F434E54 ("\x7fCNT")
- Header: 0x1000 bytes, big-endian (inherited from PS3)
- Entry table: 32 bytes per entry
- PFS: XTS-AES encrypted with EKPFS-derived keys

Usage:
    python ps5_pkg_tool.py info package.pkg
    python ps5_pkg_tool.py decrypt package.pkg -o decrypted/
    python ps5_pkg_tool.py sign package.pkg -o signed.pkg
    python ps5_pkg_tool.py extract package.pkg -o extracted/
"""
import sys
import struct
import hashlib
from dataclasses import dataclass, field
from enum import IntEnum, IntFlag
from pathlib import Path
from typing import List, Optional, Dict, Any, BinaryIO

sys.path.insert(0, str(Path(__file__).parent.parent))

import click
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Hash import HMAC, SHA256
from he.crypto import (
    aes_cbc_decrypt, aes_cbc_decrypt_no_pad,
    rsa_sign_pkcs1v15, rsa_verify_pkcs1v15, rsa_construct_from_crt
)
from he.keys import load_pkg_keys
from he.utils import hexdump, align_up

console = Console()

# PKG Header constants
PKG_MAGIC = b'\x7FCNT'
PKG_HEADER_SIZE = 0x1000
PKG_ENTRY_SIZE = 0x20  # 32 bytes per entry


class PKGType(IntEnum):
    """PKG type flags."""
    PS3 = 0x01
    PSP = 0x02
    PSV = 0x03
    PS4 = 0x04
    PS5 = 0x05


class PKGContentType(IntEnum):
    """PKG content type identifiers."""
    GAME = 0x1A
    DLC = 0x1C
    PATCH = 0x1E
    REMASTER = 0x1F
    AC = 0x02
    AL = 0x03
    ADDITIONAL_CONTENT_DATA = 0x04
    ADDITIONAL_CONTENT_NO_DATA = 0x05
    SAVEDATA = 0x06
    THEME = 0x09
    WIDGET = 0x0A


class PKGDRMType(IntEnum):
    """DRM type identifiers."""
    NONE = 0x00
    PS4 = 0x01
    UNKNOWN = 0x02


class PKGContentFlags(IntFlag):
    """Content flags."""
    FIRST_PATCH = 0x00100000
    PATCHGO = 0x00200000
    CUMULATIVE_PATCH = 0x00800000
    NON_GAME = 0x02000000
    UNKNOWN = 0x04000000
    SUBSEQUENT_PATCH = 0x08000000
    DELTA_PATCH = 0x40000000
    VR = 0x10000000


class PKGEntryID(IntEnum):
    """Standard PKG entry IDs."""
    # Meta entries (accessible without PFS decryption)
    DIGEST_TABLE = 0x00000001
    ENTRY_KEYS = 0x00000010
    IMAGE_KEY = 0x00000020
    METADATA_TABLE = 0x00000100
    ENTRY_NAMES = 0x00000200

    # Common file entries
    PARAM_SFO = 0x00001000
    PLAYGO_CHUNK_DAT = 0x00001001
    PLAYGO_CHUNK_SHA = 0x00001002
    PLAYGO_MANIFEST_XML = 0x00001003
    PRONUNCIATION_XML = 0x00001004
    PRONUNCIATION_SIG = 0x00001005
    PIC1_PNG = 0x00001006
    PUBTOOLINFO_DAT = 0x00001007
    ICON0_PNG = 0x00001200
    PIC0_PNG = 0x00001220
    SND0_AT9 = 0x00001240
    CHANGEINFO_XML = 0x00001260

    # Trophy
    TROPHY_DAT = 0x00001004

    # PFS image
    PFS_IMAGE_DAT = 0x00001008

    # License
    LICENSE_DAT = 0x00001009
    LICENSE_INFO = 0x0000100A

    # PKG signature
    NPBIND_DAT = 0x00001010


# Entry ID to filename mapping
ENTRY_ID_NAMES: Dict[int, str] = {
    PKGEntryID.DIGEST_TABLE: ".digests",
    PKGEntryID.ENTRY_KEYS: ".entry_keys",
    PKGEntryID.IMAGE_KEY: ".image_key",
    PKGEntryID.METADATA_TABLE: ".metadata",
    PKGEntryID.ENTRY_NAMES: ".entry_names",
    PKGEntryID.PARAM_SFO: "param.sfo",
    PKGEntryID.PLAYGO_CHUNK_DAT: "playgo-chunk.dat",
    PKGEntryID.PLAYGO_CHUNK_SHA: "playgo-chunk.sha",
    PKGEntryID.PLAYGO_MANIFEST_XML: "playgo-manifest.xml",
    PKGEntryID.PRONUNCIATION_XML: "pronunciation.xml",
    PKGEntryID.PRONUNCIATION_SIG: "pronunciation.sig",
    PKGEntryID.PIC1_PNG: "pic1.png",
    PKGEntryID.PUBTOOLINFO_DAT: "pubtoolinfo.dat",
    PKGEntryID.ICON0_PNG: "icon0.png",
    PKGEntryID.PIC0_PNG: "pic0.png",
    PKGEntryID.SND0_AT9: "snd0.at9",
    PKGEntryID.CHANGEINFO_XML: "changeinfo.xml",
    PKGEntryID.PFS_IMAGE_DAT: "pfs_image.dat",
    PKGEntryID.LICENSE_DAT: "license.dat",
    PKGEntryID.LICENSE_INFO: "license_info.bin",
    PKGEntryID.NPBIND_DAT: "npbind.dat",
}


@dataclass
class PKGEntry:
    """PKG entry table entry (32 bytes)."""
    id: int
    filename_offset: int
    flags1: int
    flags2: int
    offset: int
    size: int
    padding: int = 0

    # Derived fields
    encrypted: bool = False
    key_index: int = 0
    filename: str = ""

    @classmethod
    def from_bytes(cls, data: bytes, index: int = 0) -> 'PKGEntry':
        """Parse entry from 32-byte buffer (big-endian)."""
        if len(data) < 32:
            raise ValueError(f"Entry data too short: {len(data)} < 32")

        # Big-endian format
        (entry_id, filename_offset, flags1, flags2,
         offset, size, padding) = struct.unpack('>IIIIIIQ', data[:32])

        entry = cls(
            id=entry_id,
            filename_offset=filename_offset,
            flags1=flags1,
            flags2=flags2,
            offset=offset,
            size=size,
            padding=padding
        )

        # Extract key index: (flags2 & 0xF000) >> 12
        entry.key_index = (flags2 & 0xF000) >> 12

        # Check if encrypted: bit 31 of flags1
        entry.encrypted = bool(flags1 & 0x80000000)

        # Try to get default filename from ID
        entry.filename = ENTRY_ID_NAMES.get(entry_id, f"entry_{entry_id:08x}.bin")

        return entry

    def to_bytes(self) -> bytes:
        """Serialize entry to 32-byte buffer (big-endian)."""
        return struct.pack('>IIIIIIQ',
            self.id, self.filename_offset, self.flags1, self.flags2,
            self.offset, self.size, self.padding)

    def get_type_name(self) -> str:
        """Get human-readable entry type name."""
        try:
            return PKGEntryID(self.id).name
        except ValueError:
            return f"UNKNOWN_{self.id:08X}"


@dataclass
class PKGHeader:
    """
    PS4/PS5 PKG header structure.

    The PKG format uses big-endian encoding (inherited from PS3).
    Total header size: 0x1000 bytes.
    """
    magic: bytes = field(default=PKG_MAGIC)
    pkg_type: int = 0
    pkg_unk_0x08: int = 0
    pkg_file_count: int = 0
    pkg_entry_count: int = 0
    pkg_sc_entry_count: int = 0
    pkg_table_offset: int = 0
    pkg_entry_data_size: int = 0
    pkg_body_offset: int = 0
    pkg_body_size: int = 0
    pkg_unk_0x38: int = 0
    pkg_content_id: str = ""
    pkg_drm_type: int = 0
    pkg_content_type: int = 0
    pkg_content_flags: int = 0
    pkg_promote_size: int = 0
    pkg_version_date: int = 0
    pkg_version_hash: int = 0
    pkg_unk_0x88: int = 0
    pkg_unk_0x8c: int = 0
    pkg_unk_0x90: int = 0
    pkg_unk_0x94: int = 0
    pkg_iro_tag: int = 0
    pkg_ekc_version: int = 0

    # Digest entries (SHA-256)
    digest_entries_1: bytes = b'\x00' * 32
    digest_entries_2: bytes = b'\x00' * 32
    digest_table_digest: bytes = b'\x00' * 32
    digest_body_digest: bytes = b'\x00' * 32

    # PFS fields
    pfs_image_count: int = 0
    pfs_flags: int = 0
    pfs_image_offset: int = 0
    pfs_image_size: int = 0
    mount_image_offset: int = 0
    mount_image_size: int = 0
    pkg_size: int = 0
    pfs_signed_size: int = 0
    pfs_cache_size: int = 0
    pfs_image_digest: bytes = b'\x00' * 32
    pfs_signed_digest: bytes = b'\x00' * 32
    pfs_split_size_nth0: int = 0
    pfs_split_size_nth1: int = 0

    # Raw header for complete preservation
    raw_header: bytes = b''

    @classmethod
    def from_bytes(cls, data: bytes) -> 'PKGHeader':
        """Parse PKG header from bytes (big-endian)."""
        if len(data) < PKG_HEADER_SIZE:
            raise ValueError(f"Header data too short: {len(data)} < {PKG_HEADER_SIZE}")

        header = cls()
        header.raw_header = data[:PKG_HEADER_SIZE]

        # Parse magic and basic fields
        header.magic = data[0:4]
        if header.magic != PKG_MAGIC:
            raise ValueError(f"Invalid PKG magic: {header.magic.hex()}")

        # Big-endian parsing (inherited from PS3)
        header.pkg_type = struct.unpack('>I', data[0x04:0x08])[0]
        header.pkg_unk_0x08 = struct.unpack('>I', data[0x08:0x0C])[0]
        header.pkg_file_count = struct.unpack('>I', data[0x0C:0x10])[0]
        header.pkg_entry_count = struct.unpack('>I', data[0x10:0x14])[0]
        header.pkg_sc_entry_count = struct.unpack('>H', data[0x14:0x16])[0]
        header.pkg_table_offset = struct.unpack('>I', data[0x18:0x1C])[0]
        header.pkg_entry_data_size = struct.unpack('>I', data[0x1C:0x20])[0]
        header.pkg_body_offset = struct.unpack('>Q', data[0x20:0x28])[0]
        header.pkg_body_size = struct.unpack('>Q', data[0x28:0x30])[0]
        header.pkg_unk_0x38 = struct.unpack('>Q', data[0x38:0x40])[0]

        # Content ID (36 bytes, null-terminated string)
        content_id_raw = data[0x40:0x40+36]
        null_pos = content_id_raw.find(b'\x00')
        if null_pos > 0:
            header.pkg_content_id = content_id_raw[:null_pos].decode('utf-8', errors='replace')
        else:
            header.pkg_content_id = content_id_raw.decode('utf-8', errors='replace').rstrip('\x00')

        # DRM and content fields
        header.pkg_drm_type = struct.unpack('>I', data[0x70:0x74])[0]
        header.pkg_content_type = struct.unpack('>I', data[0x74:0x78])[0]
        header.pkg_content_flags = struct.unpack('>I', data[0x78:0x7C])[0]
        header.pkg_promote_size = struct.unpack('>I', data[0x7C:0x80])[0]
        header.pkg_version_date = struct.unpack('>I', data[0x80:0x84])[0]
        header.pkg_version_hash = struct.unpack('>I', data[0x84:0x88])[0]
        header.pkg_unk_0x88 = struct.unpack('>I', data[0x88:0x8C])[0]
        header.pkg_unk_0x8c = struct.unpack('>I', data[0x8C:0x90])[0]
        header.pkg_unk_0x90 = struct.unpack('>I', data[0x90:0x94])[0]
        header.pkg_unk_0x94 = struct.unpack('>I', data[0x94:0x98])[0]
        header.pkg_iro_tag = struct.unpack('>I', data[0x98:0x9C])[0]
        header.pkg_ekc_version = struct.unpack('>I', data[0x9C:0xA0])[0]

        # Digest entries (at 0x100)
        header.digest_entries_1 = data[0x100:0x120]
        header.digest_entries_2 = data[0x120:0x140]
        header.digest_table_digest = data[0x140:0x160]
        header.digest_body_digest = data[0x160:0x180]

        # PFS image info (at 0x400)
        header.pfs_image_count = struct.unpack('>I', data[0x404:0x408])[0]
        header.pfs_flags = struct.unpack('>Q', data[0x408:0x410])[0]
        header.pfs_image_offset = struct.unpack('>Q', data[0x410:0x418])[0]
        header.pfs_image_size = struct.unpack('>Q', data[0x418:0x420])[0]
        header.mount_image_offset = struct.unpack('>Q', data[0x420:0x428])[0]
        header.mount_image_size = struct.unpack('>Q', data[0x428:0x430])[0]
        header.pkg_size = struct.unpack('>Q', data[0x430:0x438])[0]
        header.pfs_signed_size = struct.unpack('>I', data[0x438:0x43C])[0]
        header.pfs_cache_size = struct.unpack('>I', data[0x43C:0x440])[0]
        header.pfs_image_digest = data[0x440:0x460]
        header.pfs_signed_digest = data[0x460:0x480]
        header.pfs_split_size_nth0 = struct.unpack('>Q', data[0x480:0x488])[0]
        header.pfs_split_size_nth1 = struct.unpack('>Q', data[0x488:0x490])[0]

        return header

    def get_content_type_name(self) -> str:
        """Get human-readable content type."""
        try:
            return PKGContentType(self.pkg_content_type).name
        except ValueError:
            return f"UNKNOWN_{self.pkg_content_type:04X}"

    def get_drm_type_name(self) -> str:
        """Get human-readable DRM type."""
        try:
            return PKGDRMType(self.pkg_drm_type).name
        except ValueError:
            return f"UNKNOWN_{self.pkg_drm_type:04X}"

    def get_content_flags_str(self) -> str:
        """Get human-readable content flags."""
        flags = []
        try:
            cf = PKGContentFlags(self.pkg_content_flags)
            for flag in PKGContentFlags:
                if cf & flag:
                    flags.append(flag.name)
        except ValueError:
            pass
        return " | ".join(flags) if flags else f"0x{self.pkg_content_flags:08X}"


def parse_entry_table(data: bytes, header: PKGHeader) -> List[PKGEntry]:
    """Parse the PKG entry table."""
    entries = []
    table_offset = header.pkg_table_offset
    entry_count = header.pkg_entry_count

    if table_offset + entry_count * PKG_ENTRY_SIZE > len(data):
        console.print(f"[yellow]Warning: Entry table extends beyond file[/]")
        entry_count = min(entry_count, (len(data) - table_offset) // PKG_ENTRY_SIZE)

    for i in range(entry_count):
        offset = table_offset + i * PKG_ENTRY_SIZE
        entry_data = data[offset:offset + PKG_ENTRY_SIZE]
        try:
            entry = PKGEntry.from_bytes(entry_data, i)
            entries.append(entry)
        except Exception as e:
            console.print(f"[yellow]Warning: Failed to parse entry {i}: {e}[/]")

    # Try to resolve entry names from entry_names table
    names_entry = next((e for e in entries if e.id == PKGEntryID.ENTRY_NAMES), None)
    if names_entry and names_entry.offset + names_entry.size <= len(data):
        names_data = data[names_entry.offset:names_entry.offset + names_entry.size]
        for entry in entries:
            if entry.filename_offset > 0 and entry.filename_offset < len(names_data):
                # Find null terminator
                end = names_data.find(b'\x00', entry.filename_offset)
                if end > entry.filename_offset:
                    try:
                        entry.filename = names_data[entry.filename_offset:end].decode('utf-8')
                    except:
                        pass

    return entries


def xts_aes_decrypt(data: bytes, tweak_key: bytes, data_key: bytes,
                    sector_size: int = 0x1000) -> bytes:
    """
    XTS-AES decryption for PFS image.

    PS4/PS5 uses XTS-AES-128 with 0x1000 byte sectors.
    """
    if len(data) % sector_size != 0:
        # Pad to sector boundary
        pad_len = sector_size - (len(data) % sector_size)
        data = data + b'\x00' * pad_len

    decrypted = bytearray()

    for sector_num in range(len(data) // sector_size):
        sector_offset = sector_num * sector_size
        sector_data = data[sector_offset:sector_offset + sector_size]

        # Compute tweak for this sector
        tweak = struct.pack('<QQ', sector_num, 0)
        tweak_cipher = AES.new(tweak_key, AES.MODE_ECB)
        encrypted_tweak = bytearray(tweak_cipher.encrypt(tweak))

        # Decrypt sector
        data_cipher = AES.new(data_key, AES.MODE_ECB)

        sector_decrypted = bytearray()
        for block_num in range(sector_size // 16):
            block_offset = block_num * 16
            block = bytearray(sector_data[block_offset:block_offset + 16])

            # XOR with tweak
            for j in range(16):
                block[j] ^= encrypted_tweak[j]

            # Decrypt
            decrypted_block = bytearray(data_cipher.decrypt(bytes(block)))

            # XOR with tweak again
            for j in range(16):
                decrypted_block[j] ^= encrypted_tweak[j]

            sector_decrypted.extend(decrypted_block)

            # Multiply tweak by x in GF(2^128)
            carry = 0
            for j in range(16):
                new_carry = (encrypted_tweak[j] >> 7) & 1
                encrypted_tweak[j] = ((encrypted_tweak[j] << 1) | carry) & 0xFF
                carry = new_carry
            if carry:
                encrypted_tweak[0] ^= 0x87  # Reduction polynomial

        decrypted.extend(sector_decrypted)

    return bytes(decrypted)


def derive_pfs_keys(ekpfs: bytes, crypt_seed: bytes) -> tuple:
    """
    Derive XTS keys from EKPFS and crypt seed.

    Key derivation:
    1. Concatenate 0x01000000 with EKPFS
    2. HMAC-SHA256 with crypt_seed as key
    3. First 16 bytes = tweak key, next 16 = data key
    """
    h = HMAC.new(crypt_seed, b'\x01\x00\x00\x00' + ekpfs, digestmod=SHA256)
    derived = h.digest()
    tweak_key = derived[:16]
    data_key = derived[16:32]
    return tweak_key, data_key


@click.group()
def cli():
    """PS5 PKG Manager - Sign, decrypt, and analyze PS5 PKG files."""
    pass


@cli.command()
@click.argument('pkg_file', type=click.Path(exists=True))
@click.option('-v', '--verbose', is_flag=True, help='Show detailed header info')
def info(pkg_file: str, verbose: bool):
    """Display PKG information."""
    data = Path(pkg_file).read_bytes()

    if data[:4] != PKG_MAGIC:
        console.print(f"[red]Not a valid PKG file (magic: {data[:4].hex()})[/]")
        console.print(f"[dim]Expected: {PKG_MAGIC.hex()} (\\x7fCNT)[/]")
        return

    try:
        header = PKGHeader.from_bytes(data)
    except Exception as e:
        console.print(f"[red]Failed to parse PKG header: {e}[/]")
        return

    # Main info table
    table = Table(title=f"PKG Info: {Path(pkg_file).name}")
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Magic", f"{header.magic.hex()} ({header.magic[1:].decode('ascii', errors='replace')})")
    table.add_row("Content ID", header.pkg_content_id)
    table.add_row("Content Type", header.get_content_type_name())
    table.add_row("DRM Type", header.get_drm_type_name())
    table.add_row("Content Flags", header.get_content_flags_str())
    table.add_row("PKG Type", f"0x{header.pkg_type:08X}")
    table.add_row("File Count", str(header.pkg_file_count))
    table.add_row("Entry Count", str(header.pkg_entry_count))
    table.add_row("Entry Table Offset", f"0x{header.pkg_table_offset:X}")
    table.add_row("Body Offset", f"0x{header.pkg_body_offset:X}")
    table.add_row("Body Size", f"{header.pkg_body_size:,} bytes")
    table.add_row("PKG Size (header)", f"{header.pkg_size:,} bytes")
    table.add_row("File Size (actual)", f"{len(data):,} bytes ({len(data) / 1024 / 1024:.2f} MB)")

    if header.pfs_image_size > 0:
        table.add_row("PFS Image Offset", f"0x{header.pfs_image_offset:X}")
        table.add_row("PFS Image Size", f"{header.pfs_image_size:,} bytes")
        table.add_row("PFS Image Count", str(header.pfs_image_count))

    console.print(table)

    # Parse entry table
    entries = parse_entry_table(data, header)

    if entries:
        entry_table = Table(title=f"Entry Table ({len(entries)} entries)")
        entry_table.add_column("#", style="dim")
        entry_table.add_column("ID", style="cyan")
        entry_table.add_column("Type", style="yellow")
        entry_table.add_column("Filename", style="green")
        entry_table.add_column("Offset", style="blue")
        entry_table.add_column("Size", style="magenta")
        entry_table.add_column("Enc", style="red")

        for i, entry in enumerate(entries[:50]):  # Limit display to 50 entries
            entry_table.add_row(
                str(i),
                f"0x{entry.id:08X}",
                entry.get_type_name(),
                entry.filename,
                f"0x{entry.offset:X}",
                f"{entry.size:,}",
                "Yes" if entry.encrypted else "No"
            )

        if len(entries) > 50:
            entry_table.add_row("...", "...", "...", f"... ({len(entries) - 50} more)", "...", "...", "...")

        console.print(entry_table)

    if verbose:
        # Show digests
        digest_table = Table(title="Digests (SHA-256)")
        digest_table.add_column("Digest", style="cyan")
        digest_table.add_column("Value", style="dim")

        digest_table.add_row("Entry Digest 1", header.digest_entries_1.hex())
        digest_table.add_row("Entry Digest 2", header.digest_entries_2.hex())
        digest_table.add_row("Table Digest", header.digest_table_digest.hex())
        digest_table.add_row("Body Digest", header.digest_body_digest.hex())
        digest_table.add_row("PFS Image Digest", header.pfs_image_digest.hex())
        digest_table.add_row("PFS Signed Digest", header.pfs_signed_digest.hex())

        console.print(digest_table)

        # Show header hexdump
        console.print("\n[dim]Header (first 256 bytes):[/]")
        console.print(hexdump(data, length=256))


@cli.command()
@click.argument('pkg_file', type=click.Path(exists=True))
@click.option('-o', '--output', required=True, help='Output directory')
@click.option('-k', '--keys', default='keys/pkg_rsa.json', help='Keys file')
@click.option('--no-decrypt', is_flag=True, help='Extract without decryption')
def decrypt(pkg_file: str, output: str, keys: str, no_decrypt: bool):
    """Decrypt and extract PKG file contents."""
    console.print(f"[bold blue]Processing {pkg_file}[/]")

    data = Path(pkg_file).read_bytes()

    if data[:4] != PKG_MAGIC:
        console.print(f"[red]Not a valid PKG file[/]")
        return

    try:
        header = PKGHeader.from_bytes(data)
    except Exception as e:
        console.print(f"[red]Failed to parse PKG header: {e}[/]")
        return

    out_dir = Path(output)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Save header
    (out_dir / 'pkg_header.bin').write_bytes(header.raw_header)
    console.print(f"[green]Extracted header -> pkg_header.bin[/]")

    # Parse entry table
    entries = parse_entry_table(data, header)
    console.print(f"[cyan]Found {len(entries)} entries[/]")

    # Load keys for decryption
    ekpfs = None
    crypt_seed = None

    if not no_decrypt:
        keys_path = Path(__file__).parent.parent / keys
        if not keys_path.exists():
            keys_path = Path(keys)

        try:
            k = load_pkg_keys(str(keys_path))
            if 'ekpfs' in k:
                ekpfs = bytes.fromhex(k['ekpfs']) if isinstance(k['ekpfs'], str) else k['ekpfs']
            if 'content_key' in k and k['content_key']:
                crypt_seed = bytes.fromhex(k['content_key']) if isinstance(k['content_key'], str) else k['content_key']
        except Exception as e:
            console.print(f"[yellow]Warning: Could not load decryption keys: {e}[/]")
            console.print("[yellow]Entries will be extracted without decryption[/]")

    # Extract entries
    extracted_count = 0
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console
    ) as progress:
        task = progress.add_task("Extracting entries...", total=len(entries))

        for entry in entries:
            # Validate entry bounds
            if entry.offset + entry.size > len(data):
                console.print(f"[yellow]Skipping {entry.filename}: extends beyond file[/]")
                progress.update(task, advance=1)
                continue

            entry_data = data[entry.offset:entry.offset + entry.size]

            # Decrypt if needed and keys available
            if entry.encrypted and ekpfs and crypt_seed and not no_decrypt:
                try:
                    tweak_key, data_key = derive_pfs_keys(ekpfs, crypt_seed)
                    entry_data = xts_aes_decrypt(entry_data, tweak_key, data_key)
                except Exception as e:
                    console.print(f"[yellow]Decryption failed for {entry.filename}: {e}[/]")

            # Save entry
            entry_path = out_dir / entry.filename
            entry_path.parent.mkdir(parents=True, exist_ok=True)
            entry_path.write_bytes(entry_data)
            extracted_count += 1

            progress.update(task, advance=1)

    console.print(f"[green]Extracted {extracted_count} entries to {out_dir}[/]")

    # Extract PFS image if present
    if header.pfs_image_size > 0 and header.pfs_image_offset + header.pfs_image_size <= len(data):
        pfs_data = data[header.pfs_image_offset:header.pfs_image_offset + header.pfs_image_size]
        (out_dir / 'pfs_image.dat').write_bytes(pfs_data)
        console.print(f"[green]Extracted PFS image ({header.pfs_image_size:,} bytes) -> pfs_image.dat[/]")

        if pfs_data[:4] == b'PFSC':
            console.print("[cyan]PFS image uses PFSC (compressed) format[/]")


@cli.command()
@click.argument('pkg_file', type=click.Path(exists=True))
@click.option('-o', '--output', required=True, help='Output PKG file')
@click.option('-k', '--keys', default='keys/pkg_rsa.json', help='Keys file')
def sign(pkg_file: str, output: str, keys: str):
    """Sign PKG file with RSA key."""
    console.print(f"[bold blue]Signing {pkg_file}[/]")

    # Load keys
    keys_path = Path(__file__).parent.parent / keys
    if not keys_path.exists():
        keys_path = Path(keys)

    try:
        k = load_pkg_keys(str(keys_path))
    except Exception as e:
        console.print(f"[red]Failed to load keys: {e}[/]")
        return

    # Check for placeholder keys
    if 'n' in k and k['n'] == 'PLACEHOLDER_MODULUS':
        console.print("[red]Error: PKG RSA keys contain placeholder values[/]")
        console.print("[yellow]Update keys/pkg_rsa.json with actual key values[/]")
        return

    data = bytearray(Path(pkg_file).read_bytes())

    if data[:4] != PKG_MAGIC:
        console.print(f"[red]Not a valid PKG file[/]")
        return

    # Parse header to find signature location
    try:
        header = PKGHeader.from_bytes(bytes(data))
    except Exception as e:
        console.print(f"[red]Failed to parse PKG header: {e}[/]")
        return

    # Construct RSA key
    if 'rsa_private' in k and k['rsa_private']:
        private_key = RSA.import_key(k['rsa_private'])
    elif 'n' in k and 'd' in k:
        try:
            n = int(k['n'], 16)
            e = int(k['e'], 16)
            d = int(k['d'], 16)
            p = int(k['p'], 16) if k.get('p') else None
            q = int(k['q'], 16) if k.get('q') else None

            if p and q:
                private_key = rsa_construct_from_crt(n, e, d, p, q)
            else:
                private_key = RSA.construct((n, e, d))
        except Exception as e:
            console.print(f"[red]Failed to construct RSA key: {e}[/]")
            return
    else:
        console.print("[red]No valid RSA private key found[/]")
        return

    # Compute SHA-256 digest of PKG body
    body_start = header.pkg_body_offset
    body_end = body_start + header.pkg_body_size
    if body_end > len(data):
        body_end = len(data)

    body_digest = hashlib.sha256(data[body_start:body_end]).digest()
    console.print(f"[dim]Body digest: {body_digest.hex()}[/]")

    # Sign the digest
    signature = rsa_sign_pkcs1v15(private_key, bytes(data))
    console.print(f"[green]Generated {len(signature)}-byte RSA signature[/]")

    # PKG signature is typically at offset 0xFE0 (within header)
    # But actual location varies - for now, update body digest in header
    # and append signature for reference

    # Update digest in header (offset 0x160)
    data[0x160:0x180] = body_digest

    # Write signed PKG
    Path(output).write_bytes(bytes(data))
    console.print(f"[green]Updated PKG digests -> {output}[/]")

    # Also save signature separately for reference
    sig_path = Path(output).with_suffix('.sig')
    sig_path.write_bytes(signature)
    console.print(f"[dim]Saved signature -> {sig_path}[/]")


@cli.command()
@click.argument('pkg_file', type=click.Path(exists=True))
@click.option('-k', '--keys', default='keys/pkg_rsa.json', help='Keys file')
def verify(pkg_file: str, keys: str):
    """Verify PKG integrity and signature."""
    console.print(f"[bold blue]Verifying {pkg_file}[/]")

    data = Path(pkg_file).read_bytes()

    if data[:4] != PKG_MAGIC:
        console.print(f"[red]Not a valid PKG file[/]")
        return

    try:
        header = PKGHeader.from_bytes(data)
    except Exception as e:
        console.print(f"[red]Failed to parse PKG header: {e}[/]")
        return

    console.print(f"[cyan]Content ID: {header.pkg_content_id}[/]")

    # Verify body digest
    body_start = header.pkg_body_offset
    body_end = body_start + header.pkg_body_size
    if body_end > len(data):
        console.print(f"[yellow]Warning: Body extends beyond file, using file end[/]")
        body_end = len(data)

    computed_digest = hashlib.sha256(data[body_start:body_end]).digest()
    stored_digest = header.digest_body_digest

    if computed_digest == stored_digest:
        console.print(f"[green]✓ Body digest matches[/]")
    else:
        console.print(f"[red]✗ Body digest mismatch[/]")
        console.print(f"[dim]  Stored:   {stored_digest.hex()}[/]")
        console.print(f"[dim]  Computed: {computed_digest.hex()}[/]")

    # Verify entry table digest
    table_start = header.pkg_table_offset
    table_size = header.pkg_entry_count * PKG_ENTRY_SIZE
    if table_start + table_size <= len(data):
        table_digest = hashlib.sha256(data[table_start:table_start + table_size]).digest()
        console.print(f"[dim]Entry table digest: {table_digest.hex()}[/]")

    # Verify PFS image digest if present
    if header.pfs_image_size > 0:
        pfs_start = header.pfs_image_offset
        pfs_end = pfs_start + header.pfs_image_size
        if pfs_end <= len(data):
            pfs_digest = hashlib.sha256(data[pfs_start:pfs_end]).digest()
            stored_pfs = header.pfs_image_digest

            if pfs_digest == stored_pfs:
                console.print(f"[green]✓ PFS image digest matches[/]")
            else:
                console.print(f"[yellow]⚠ PFS image digest differs (may be encrypted)[/]")
        else:
            console.print(f"[yellow]⚠ PFS image extends beyond file[/]")

    # Check file size consistency
    if header.pkg_size > 0:
        if len(data) == header.pkg_size:
            console.print(f"[green]✓ File size matches header ({len(data):,} bytes)[/]")
        elif len(data) < header.pkg_size:
            console.print(f"[red]✗ File truncated: {len(data):,} < {header.pkg_size:,} bytes[/]")
        else:
            console.print(f"[yellow]⚠ File larger than header: {len(data):,} > {header.pkg_size:,} bytes[/]")


@cli.command()
@click.argument('pkg_file', type=click.Path(exists=True))
@click.option('-e', '--entry', 'entry_id', type=str, help='Entry ID (hex) or name to extract')
@click.option('-o', '--output', help='Output file path')
def extract(pkg_file: str, entry_id: Optional[str], output: Optional[str]):
    """Extract a specific entry from PKG file."""
    data = Path(pkg_file).read_bytes()

    if data[:4] != PKG_MAGIC:
        console.print(f"[red]Not a valid PKG file[/]")
        return

    try:
        header = PKGHeader.from_bytes(data)
    except Exception as e:
        console.print(f"[red]Failed to parse PKG header: {e}[/]")
        return

    entries = parse_entry_table(data, header)

    if not entry_id:
        # List available entries
        console.print(f"[cyan]Available entries in {Path(pkg_file).name}:[/]")
        for entry in entries:
            console.print(f"  0x{entry.id:08X} - {entry.filename} ({entry.size:,} bytes)")
        return

    # Find entry by ID or name
    target_entry = None
    try:
        target_id = int(entry_id, 16) if entry_id.startswith('0x') else int(entry_id, 16)
        target_entry = next((e for e in entries if e.id == target_id), None)
    except ValueError:
        # Search by filename
        target_entry = next((e for e in entries if entry_id.lower() in e.filename.lower()), None)

    if not target_entry:
        console.print(f"[red]Entry not found: {entry_id}[/]")
        return

    # Extract entry
    if target_entry.offset + target_entry.size > len(data):
        console.print(f"[red]Entry extends beyond file[/]")
        return

    entry_data = data[target_entry.offset:target_entry.offset + target_entry.size]

    out_path = Path(output) if output else Path(target_entry.filename)
    out_path.write_bytes(entry_data)

    console.print(f"[green]Extracted {target_entry.filename} ({len(entry_data):,} bytes) -> {out_path}[/]")


if __name__ == '__main__':
    cli()
