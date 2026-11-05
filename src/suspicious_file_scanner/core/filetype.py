"""File type detection via magic bytes."""

from __future__ import annotations

import os

# (magic bytes, offset, label)
_SIGNATURES: list[tuple[bytes, int, str]] = [
    (b"MZ", 0, "PE (Windows executable)"),
    (b"\x7fELF", 0, "ELF (Linux/Unix executable)"),
    (b"PK\x03\x04", 0, "ZIP archive"),
    (b"PK\x05\x06", 0, "ZIP archive (empty)"),
    (b"\x89PNG\r\n\x1a\n", 0, "PNG image"),
    (b"\xff\xd8\xff", 0, "JPEG image"),
    (b"GIF87a", 0, "GIF image"),
    (b"GIF89a", 0, "GIF image"),
    (b"%PDF", 0, "PDF document"),
    (b"7z\xbc\xaf\x27\x1c", 0, "7-Zip archive"),
    (b"Rar!\x1a\x07", 0, "RAR archive"),
    (b"\x1f\x8b", 0, "GZIP archive"),
]


def detect_file_type(path: str) -> str:
    """Return a human-readable file type label based on magic bytes."""
    try:
        with open(path, "rb") as fh:
            header = fh.read(64)
    except OSError:
        return "unknown (unreadable)"

    for magic, offset, label in _SIGNATURES:
        if header[offset : offset + len(magic)] == magic:
            return label

    # Fallback: extension-based hint
    ext = os.path.splitext(path)[1].lower()
    if ext:
        return f"unknown (ext: {ext})"
    return "unknown (no signature)"