"""
Heavy Elephant - Utility Functions

Common utilities for PS5 tools.
"""
from pathlib import Path
from typing import Optional


def hexdump(data: bytes, offset: int = 0, length: Optional[int] = None) -> str:
    """
    Format bytes as hex dump.

    Args:
        data: Bytes to dump
        offset: Starting offset for display
        length: Max bytes to display (None = all)

    Returns:
        Formatted hex dump string
    """
    if length:
        data = data[:length]

    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f'{offset + i:08x}  {hex_part:<48}  |{ascii_part}|')

    return '\n'.join(lines)


def align_up(value: int, alignment: int) -> int:
    """Align value up to nearest alignment boundary."""
    return (value + alignment - 1) & ~(alignment - 1)


def align_down(value: int, alignment: int) -> int:
    """Align value down to nearest alignment boundary."""
    return value & ~(alignment - 1)


def read_u32_le(data: bytes, offset: int) -> int:
    """Read 32-bit unsigned little-endian integer."""
    return int.from_bytes(data[offset:offset + 4], 'little')


def read_u64_le(data: bytes, offset: int) -> int:
    """Read 64-bit unsigned little-endian integer."""
    return int.from_bytes(data[offset:offset + 8], 'little')


def write_u32_le(value: int) -> bytes:
    """Write 32-bit unsigned little-endian integer."""
    return value.to_bytes(4, 'little')


def write_u64_le(value: int) -> bytes:
    """Write 64-bit unsigned little-endian integer."""
    return value.to_bytes(8, 'little')


def ensure_dir(path: str) -> Path:
    """Ensure directory exists, create if needed."""
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p
